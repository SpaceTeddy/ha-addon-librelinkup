#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import hashlib
import json
import logging
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import requests

try:
    import paho.mqtt.client as mqtt
except Exception:
    mqtt = None

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None


# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------

def _parse_log_level(s: str) -> int:
    return {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "WARN": logging.WARNING,
        "ERROR": logging.ERROR,
    }.get((s or "").upper(), logging.INFO)


class TZFormatter(logging.Formatter):
    def __init__(self, fmt: str, tz):
        super().__init__(fmt)
        self.tz = tz

    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created, tz=self.tz) if self.tz else datetime.fromtimestamp(record.created)
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def setup_logger(level: str, tz):
    log = logging.getLogger("librelinkup")
    log.setLevel(_parse_log_level(level))
    log.handlers.clear()
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(TZFormatter("%(asctime)s [%(levelname)s] %(message)s", tz))
    log.addHandler(h)
    return log


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def json_compact(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def parse_ll_ts_utc(ts: Optional[str]) -> Optional[float]:
    """
    Parse LibreLinkUp FactoryTimestamp as UTC epoch seconds.
    This is timezone-robust and MUST be used for scheduling.
    """
    if not ts:
        return None
    try:
        dt = datetime.strptime(ts, "%m/%d/%Y %I:%M:%S %p")
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return None


def parse_ll_ts_local(ts: Optional[str], tz) -> Optional[datetime]:
    if not ts:
        return None
    try:
        dt = datetime.strptime(ts, "%m/%d/%Y %I:%M:%S %p")
        return dt.replace(tzinfo=tz) if tz else dt
    except Exception:
        return None


# -------------------------------------------------------------------
# LibreLinkUp Client
# -------------------------------------------------------------------

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/json",
    "version": "4.16.0",
    "product": "llu.ios",
}


@dataclass
class LoginResult:
    user_id: str
    token: str
    expires: int
    account_id: str


class LibreLinkUpClient:
    def __init__(self, api_base: str, logger):
        self.base = api_base.rstrip("/")
        self.session = requests.Session()
        self.log = logger

    def login(self, email: str, password: str) -> LoginResult:
        r = self.session.post(
            f"{self.base}/llu/auth/login",
            headers=DEFAULT_HEADERS,
            json={"email": email, "password": password},
            timeout=15,
        )
        r.raise_for_status()
        d = r.json()["data"]
        user = d["user"]
        ticket = d["authTicket"]
        return LoginResult(
            user_id=user["id"],
            token=ticket["token"],
            expires=int(ticket["expires"]),
            account_id=sha256_hex(user["id"]),
        )

    def graph(self, login: LoginResult) -> Dict[str, Any]:
        r = self.session.get(
            f"{self.base}/llu/connections/{login.user_id}/graph",
            headers={
                **DEFAULT_HEADERS,
                "Authorization": f"Bearer {login.token}",
                "Account-ID": login.account_id,
            },
            timeout=15,
        )
        r.raise_for_status()
        return r.json()


# -------------------------------------------------------------------
# MQTT
# -------------------------------------------------------------------

class MqttPub:
    def __init__(self, host, port, user, password, base, master, logger):
        self.log = logger
        self.base = base.strip("/")
        self.master = master.strip("/")
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)
        if user:
            self.client.username_pw_set(user, password)
        self.client.connect(host, port, 30)
        self.client.loop_start()

    def publish(self, topic, payload, retain=True):
        self.client.publish(topic, payload, retain=retain)


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--interval", type=int, default=60)
    ap.add_argument("--fetch-offset-target-lag", type=float, default=5.0)
    ap.add_argument("--poll-seconds", type=float, default=10.0)
    ap.add_argument("--tz", default="Europe/Berlin")
    ap.add_argument("--log-level", default="INFO")

    ap.add_argument("--mqtt-publish", action="store_true")
    ap.add_argument("--mqtt-host", default="localhost")
    ap.add_argument("--mqtt-port", type=int, default=1883)
    ap.add_argument("--mqtt-user", default="")
    ap.add_argument("--mqtt-password", default="")
    ap.add_argument("--mqtt-base-topic", default="librelinkup")
    ap.add_argument("--master-id", default="MASTER")

    args = ap.parse_args()

    tz = ZoneInfo(args.tz) if ZoneInfo else None
    log = setup_logger(args.log_level, tz)

    client = LibreLinkUpClient("https://api.libreview.io", log)

    mqtt_pub = None
    if args.mqtt_publish:
        mqtt_pub = MqttPub(
            args.mqtt_host,
            args.mqtt_port,
            args.mqtt_user,
            args.mqtt_password,
            args.mqtt_base_topic,
            args.master_id,
            log,
        )

    login: Optional[LoginResult] = None
    last_meas_epoch: Optional[float] = None
    last_meas_change = time.time()

    def ensure_login():
        nonlocal login
        if not login or login.expires - time.time() < 60:
            log.info("=== LOGIN ===")
            login = client.login(args.email, args.password)
        return login

    next_run = time.time() + 5

    while True:
        time.sleep(max(0, next_run - time.time()))

        login = ensure_login()
        log.debug("=== FETCH GRAPH ===")
        raw = client.graph(login)

        gm = raw["data"]["connection"]["glucoseMeasurement"]
        ts = gm.get("Timestamp")
        fts = gm.get("FactoryTimestamp")

        meas_epoch = parse_ll_ts_utc(fts)
        meas_local = parse_ll_ts_local(ts, tz)

        now = time.time()
        lag = now - meas_epoch if meas_epoch else None

        log.debug("[sync] lag=%.2fs desired=%.2fs", lag or -1, args.fetch_offset_target_lag)

        if mqtt_pub:
            mqtt_pub.publish(
                f"{args.mqtt_base_topic}/{args.master_id}/data",
                json_compact(raw),
                retain=True,
            )

        if meas_epoch and meas_epoch != last_meas_epoch:
            last_meas_epoch = meas_epoch
            last_meas_change = now

        if last_meas_epoch:
            expected = last_meas_epoch + args.interval + args.fetch_offset_target_lag
            if now < expected:
                next_run = expected
                log.debug("[schedule] last_meas=%s expected_next=%s",
                          meas_local, datetime.fromtimestamp(expected, tz))
            else:
                if now - last_meas_change < 120:
                    next_run = now + args.poll_seconds
                    log.debug("[schedule] POLL next_run=%s",
                              datetime.fromtimestamp(next_run, tz))
                else:
                    next_run = now + args.interval
        else:
            next_run = now + args.interval

        if not args.loop:
            break


if __name__ == "__main__":
    main()
