#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import hashlib
import json
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

import requests

try:
    import paho.mqtt.client as mqtt
except Exception:
    mqtt = None  # optional

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None  # py<3.9


# -----------------------------
# Helpers
# -----------------------------

def eprint(*a, **k):
    print(*a, file=sys.stderr, **k)

def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def json_dumps_compact(obj: Any) -> str:
    # garantiert JSON-konform (dumps wirft Exception, wenn nicht serialisierbar)
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)

def now_ts(tz) -> datetime:
    return datetime.now(tz) if tz else datetime.now()

def parse_libreview_ts(ts: str, tz) -> Optional[datetime]:
    # Example: "1/9/2026 10:41:01 AM"
    if not ts:
        return None
    try:
        dt = datetime.strptime(ts, "%m/%d/%Y %I:%M:%S %p")
        return dt.replace(tzinfo=tz) if tz else dt
    except Exception:
        return None

def align_next_run(epoch_now: float, period_s: int, offset_s: float) -> float:
    # next multiple of period + offset
    base = (int(epoch_now) // period_s + 1) * period_s
    return base + offset_s


# -----------------------------
# LibreLinkUp minimal client
# -----------------------------

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/json",
    "version": "4.16.0",
    "product": "llu.ios",
    "Pragma": "no-cache",
    "Cache-Control": "no-cache",
}

@dataclass
class LoginResult:
    status: int
    country: str
    user_id: str
    token: str
    expires: int          # unix seconds
    account_id: str

class LibreLinkUpClient:
    def __init__(
        self,
        api_base: str,
        auth_path: str,
        tou_path: str,
        graph_template: str,
        timeout_s: int = 15,
        verify_tls: bool = True,
        connection_close: bool = False,
        debug: bool = False,
    ):
        self.api_base = api_base.rstrip("/")
        self.auth_url = self.api_base + auth_path
        self.tou_url = self.api_base + tou_path
        self.graph_template = graph_template
        self.timeout_s = timeout_s
        self.verify_tls = verify_tls
        self.connection_close = connection_close
        self.debug = debug
        self.session = requests.Session()

    def _headers(self) -> Dict[str, str]:
        h = dict(DEFAULT_HEADERS)
        if self.connection_close:
            h["Connection"] = "close"
        return h

    def auth_user(self, email: str, password: str) -> LoginResult:
        payload = {"email": email, "password": password}
        if self.debug:
            eprint(f"[http] POST {self.auth_url}")

        r = self.session.post(
            self.auth_url,
            headers=self._headers(),
            json=payload,
            timeout=self.timeout_s,
            verify=self.verify_tls,
        )
        if self.debug:
            eprint(f"[http] status={r.status_code} len={len(r.content)}")
        r.raise_for_status()

        data = r.json()
        status = int(data.get("status", -1))
        user = (data.get("data") or {}).get("user") or {}
        ticket = (data.get("data") or {}).get("authTicket") or {}

        user_id = str(user.get("id", ""))
        token = str(ticket.get("token", ""))
        expires = int(ticket.get("expires", 0))
        country = str(user.get("country", ""))

        if not user_id or not token:
            raise RuntimeError(f"Login response missing user_id/token (status={status})")

        account_id = sha256_hex(user_id)

        return LoginResult(
            status=status,
            country=country,
            user_id=user_id,
            token=token,
            expires=expires,
            account_id=account_id,
        )

    def tou_user(self, token: str) -> Dict[str, Any]:
        if self.debug:
            eprint(f"[http] POST {self.tou_url}")

        h = self._headers()
        h["Authorization"] = f"Bearer {token}"

        r = self.session.post(
            self.tou_url,
            headers=h,
            data=b"",
            timeout=self.timeout_s,
            verify=self.verify_tls,
        )
        if self.debug:
            eprint(f"[http] status={r.status_code} len={len(r.content)}")
        r.raise_for_status()
        return r.json()

    def get_graph(self, user_id: str, token: str, account_id: str) -> Dict[str, Any]:
        url = self.api_base + self.graph_template.format(user_id=user_id)

        if self.debug:
            eprint(f"[http] GET {url}")

        h = self._headers()
        h["Authorization"] = f"Bearer {token}"
        h["Account-ID"] = account_id

        r = self.session.get(
            url,
            headers=h,
            timeout=self.timeout_s,
            verify=self.verify_tls,
        )

        if self.debug:
            eprint(f"[http] status={r.status_code} len={len(r.content)}")

        if r.status_code == 401:
            raise PermissionError("Unauthorized (401)")

        r.raise_for_status()
        return r.json()


# -----------------------------
# Filtering (ESP32 compatible)
# -----------------------------

def filter_graph_json(raw: Dict[str, Any], graph_limit: int = 0) -> Dict[str, Any]:
    data = raw.get("data") or {}
    conn = data.get("connection") or {}
    active = data.get("activeSensors") or []
    gdata = data.get("graphData") or []

    if graph_limit and isinstance(gdata, list):
        gdata = gdata[-graph_limit:]

    out = {
        "data": {
            "connection": {
                "country": conn.get("country"),
                "status": conn.get("status"),
                "targetLow": conn.get("targetLow"),
                "targetHigh": conn.get("targetHigh"),
                "sensor": {
                    "deviceId": (conn.get("sensor") or {}).get("deviceId"),
                    "sn": (conn.get("sensor") or {}).get("sn"),
                    "a": (conn.get("sensor") or {}).get("a"),
                },
                "glucoseMeasurement": {
                    "Timestamp": (conn.get("glucoseMeasurement") or {}).get("Timestamp"),
                    "ValueInMgPerDl": (conn.get("glucoseMeasurement") or {}).get("ValueInMgPerDl"),
                    "TrendArrow": (conn.get("glucoseMeasurement") or {}).get("TrendArrow"),
                    "TrendMessage": (conn.get("glucoseMeasurement") or {}).get("TrendMessage"),
                    "MeasurementColor": (conn.get("glucoseMeasurement") or {}).get("MeasurementColor"),
                },
                "patientDevice": {
                    "ll": (conn.get("patientDevice") or {}).get("ll"),
                    "hl": (conn.get("patientDevice") or {}).get("hl"),
                    "fixedLowAlarmValues": {
                        "mgdl": ((conn.get("patientDevice") or {}).get("fixedLowAlarmValues") or {}).get("mgdl")
                    },
                },
            },
            "activeSensors": [],
            "graphData": [],
        }
    }

    if isinstance(active, list):
        for item in active:
            s = (item or {}).get("sensor") or {}
            out["data"]["activeSensors"].append({
                "sensor": {
                    "deviceId": s.get("deviceId"),
                    "sn": s.get("sn"),
                    "a": s.get("a"),
                    "pt": s.get("pt"),
                }
            })

    if isinstance(gdata, list):
        for item in gdata:
            out["data"]["graphData"].append({
                "Timestamp": (item or {}).get("Timestamp"),
                "ValueInMgPerDl": (item or {}).get("ValueInMgPerDl"),
            })

    return out


# -----------------------------
# Sync / adaptive fetch offset
# -----------------------------

def adapt_offset(
    current_offset: float,
    meas_timestamp_str: Optional[str],
    tz,
    desired_lag_s: float,
    gain: float,
    max_step_s: float,
    offset_min_s: float,
    offset_max_s: float,
    debug: bool,
) -> float:
    meas_ts = parse_libreview_ts(meas_timestamp_str or "", tz)
    if meas_ts is None:
        return current_offset

    now = now_ts(tz)
    lag_s = (now - meas_ts).total_seconds()
    err = lag_s - desired_lag_s

    step = clamp(gain * err, -max_step_s, +max_step_s)
    new_offset = clamp(current_offset - step, offset_min_s, offset_max_s)

    if debug:
        eprint(
            f"[sync] lag={lag_s:.2f}s desired={desired_lag_s:.2f}s err={err:.2f}s "
            f"step={step:+.2f}s offset={current_offset:.2f}->{new_offset:.2f}"
        )
    return new_offset


# -----------------------------
# MQTT persistent publisher
# -----------------------------

class MqttPublisher:
    def __init__(
        self,
        host: str,
        port: int,
        user: str,
        password: str,
        keepalive: int,
        debug: bool,
    ):
        if mqtt is None:
            raise RuntimeError("paho-mqtt not installed. Try: pip install paho-mqtt")

        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.keepalive = keepalive
        self.debug = debug

        self._connected = False
        self.client = mqtt.Client()
        if user:
            self.client.username_pw_set(user, password=password)

        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect

    def _on_connect(self, client, userdata, flags, rc):
        self._connected = (rc == 0)
        if self.debug:
            eprint(f"[mqtt] on_connect rc={rc} connected={self._connected}")

    def _on_disconnect(self, client, userdata, rc):
        self._connected = False
        if self.debug:
            eprint(f"[mqtt] on_disconnect rc={rc}")

    def connect(self):
        if self.debug:
            eprint(f"[mqtt] connect {self.host}:{self.port} user={self.user!r}")
        self.client.connect(self.host, self.port, keepalive=self.keepalive)
        # background network loop
        self.client.loop_start()

        # kurz warten bis on_connect kommt
        t0 = time.time()
        while not self._connected and (time.time() - t0) < 5:
            time.sleep(0.05)

        if not self._connected:
            raise RuntimeError("MQTT connect timeout (no CONNACK within 5s)")

    def ensure_connected(self):
        if self._connected:
            return
        # reconnect
        if self.debug:
            eprint("[mqtt] reconnecting…")
        try:
            self.client.reconnect()
        except Exception:
            # fallback: hard reconnect
            try:
                self.client.loop_stop()
            except Exception:
                pass
            self.client = None
            raise

    def publish(self, topic: str, payload: str, retain: bool, qos: int):
        if not self._connected:
            self.ensure_connected()

        if self.debug:
            eprint(f"[mqtt] publish topic={topic} retain={retain} qos={qos} bytes={len(payload)}")

        info = self.client.publish(topic, payload=payload, qos=qos, retain=retain)
        info.wait_for_publish(timeout=10)

    def close(self):
        try:
            self.client.loop_stop()
        except Exception:
            pass
        try:
            self.client.disconnect()
        except Exception:
            pass
        self._connected = False


# -----------------------------
# Token/session cache
# -----------------------------

@dataclass
class AuthCache:
    login: Optional[LoginResult] = None
    last_login_epoch: float = 0.0

def token_is_valid(login: Optional[LoginResult], min_valid_for_s: int) -> bool:
    if not login:
        return False
    # expires ist unix seconds (laut API)
    now = int(time.time())
    return (login.expires - now) > min_valid_for_s


# -----------------------------
# Main flow
# -----------------------------

def main():
    p = argparse.ArgumentParser(
        description="LibreLinkUp CLI: reuse token/session + optional MQTT persistent publish, ESP32-like filtered JSON + sync offset."
    )

    # credentials
    p.add_argument("--email", required=True, help="LibreLinkUp email")
    p.add_argument("--password", required=True, help="LibreLinkUp password (quote it in the shell!)")

    # output/debug
    p.add_argument("--debug", action="store_true", help="Verbose debug logging to stderr")
    p.add_argument("--print-raw", action="store_true", help="Print raw /graph JSON")
    p.add_argument("--print-filtered", action="store_true", help="Print ESP32-compatible filtered JSON")

    # API tweaks
    p.add_argument("--api-base", default="https://api.libreview.io", help="API base URL")
    p.add_argument("--auth-path", default="/llu/auth/login", help="Auth path")
    p.add_argument("--tou-path", default="/llu/user/consent", help="ToU/consent path")
    p.add_argument("--graph-template", default="/llu/connections/{user_id}/graph", help="Graph path template")
    p.add_argument("--timeout", type=int, default=15, help="HTTP timeout seconds")
    p.add_argument("--no-verify-tls", action="store_true", help="Disable TLS verification (not recommended)")
    p.add_argument("--connection-close", action="store_true", help="Send Connection: close header")

    # filtering
    p.add_argument("--graph-limit", type=int, default=0, help="Limit graphData points (0 = keep all)")

    # loop/sync
    p.add_argument("--loop", action="store_true", help="Run forever, fetching periodically")
    p.add_argument("--interval", type=int, default=60, help="Fetch interval seconds (default 60)")

    p.add_argument("--fetch-offset", type=float, default=5.0, help="Initial fetch offset seconds (default 5)")
    p.add_argument("--fetch-offset-target-lag", type=float, default=5.0, help="Target lag seconds vs measurement timestamp (default 5)")
    p.add_argument("--fetch-offset-min", type=float, default=1.0, help="Min adaptive offset (default 1)")
    p.add_argument("--fetch-offset-max", type=float, default=20.0, help="Max adaptive offset (default 20)")
    p.add_argument("--fetch-offset-gain", type=float, default=0.3, help="Adaptive gain (default 0.3)")
    p.add_argument("--fetch-offset-max-step", type=float, default=1.0, help="Max offset change per loop in seconds (default 1.0)")
    p.add_argument("--tz", default="Europe/Berlin", help="Timezone for local comparison (default Europe/Berlin)")

    # token reuse
    p.add_argument("--token-min-valid", type=int, default=90,
                   help="If token expires in less than this many seconds, do relogin (default 90)")

    # MQTT
    p.add_argument("--mqtt-publish", action="store_true", help="Publish to MQTT")
    p.add_argument("--mqtt-host", default="localhost", help="MQTT host")
    p.add_argument("--mqtt-port", type=int, default=1883, help="MQTT port")
    p.add_argument("--mqtt-user", default="", help="MQTT username")
    p.add_argument("--mqtt-password", default="", help="MQTT password")
    p.add_argument("--mqtt-keepalive", type=int, default=30, help="MQTT keepalive seconds (default 30)")

    p.add_argument("--mqtt-base-topic", default="librelinkup", help="Base topic (default librelinkup)")
    p.add_argument("--master-id", default="MASTER", help="Master id segment (default MASTER)")
    p.add_argument("--mqtt-topic-raw-suffix", default="data_raw", help="Raw topic suffix (default data_raw)")
    p.add_argument("--mqtt-topic-filtered-suffix", default="data", help="Filtered topic suffix (default data)")

    p.add_argument("--mqtt-publish-raw", action="store_true", help="Publish raw JSON")
    p.add_argument("--mqtt-publish-filtered", action="store_true", help="Publish filtered JSON")
    p.add_argument("--mqtt-retain", action="store_true", help="MQTT retain flag")
    p.add_argument("--mqtt-qos", type=int, default=0, choices=[0, 1, 2], help="MQTT QoS (0/1/2)")

    args = p.parse_args()

    tz = None
    if ZoneInfo is not None:
        try:
            tz = ZoneInfo(args.tz)
        except Exception:
            tz = None

    client = LibreLinkUpClient(
        api_base=args.api_base,
        auth_path=args.auth_path,
        tou_path=args.tou_path,
        graph_template=args.graph_template,
        timeout_s=args.timeout,
        verify_tls=not args.no_verify_tls,
        connection_close=args.connection_close,
        debug=args.debug,
    )

    # MQTT persistent setup (optional)
    mqtt_pub: Optional[MqttPublisher] = None
    if args.mqtt_publish:
        mqtt_pub = MqttPublisher(
            host=args.mqtt_host,
            port=args.mqtt_port,
            user=args.mqtt_user,
            password=args.mqtt_password,
            keepalive=args.mqtt_keepalive,
            debug=args.debug,
        )
        mqtt_pub.connect()

    auth = AuthCache()

    def ensure_login() -> LoginResult:
        # Reuse token while valid
        if token_is_valid(auth.login, args.token_min_valid):
            return auth.login  # type: ignore

        if args.debug:
            eprint("=== LOGIN (new/refresh) ===")

        login = client.auth_user(args.email, args.password)
        auth.login = login
        auth.last_login_epoch = time.time()

        if args.debug:
            eprint(f"user_id        : {login.user_id}")
            eprint(f"country        : {login.country}")
            eprint(f"status         : {login.status}")
            eprint(f"token (short)  : {login.token[:18]}…")
            eprint(f"expires (unix) : {login.expires}")
            eprint(f"account_id     : {login.account_id}")

        if login.status == 4:
            eprint("[info] ToU/consent required -> trying tou_user()")
            try:
                client.tou_user(login.token)
            except Exception as ex:
                eprint(f"[warn] tou_user failed: {ex}")

        return login

    def mqtt_topics() -> Tuple[str, str]:
        base = args.mqtt_base_topic.strip("/")
        mid = args.master_id.strip("/")
        topic_raw = f"{base}/{mid}/{args.mqtt_topic_raw_suffix}"
        topic_filtered = f"{base}/{mid}/{args.mqtt_topic_filtered_suffix}"
        return topic_raw, topic_filtered

    def one_cycle(fetch_offset_s: float) -> float:
        # 1) login reuse
        login = ensure_login()

        # 2) fetch graph (if 401 -> relogin once and retry)
        if args.debug:
            eprint("=== FETCH GRAPH ===")

        raw: Dict[str, Any]
        try:
            raw = client.get_graph(login.user_id, login.token, login.account_id)
        except PermissionError:
            # token invalid -> relogin and retry once
            if args.debug:
                eprint("[auth] 401 -> relogin and retry once")
            auth.login = None
            login = ensure_login()
            raw = client.get_graph(login.user_id, login.token, login.account_id)

        filtered = filter_graph_json(raw, graph_limit=args.graph_limit)

        # 3) print
        if args.print_raw:
            print("=== RAW GRAPH JSON ===")
            print(json.dumps(raw, indent=2, ensure_ascii=False))

        if args.print_filtered:
            print("=== FILTERED GRAPH JSON (ESP32 compatible) ===")
            print(json.dumps(filtered, indent=2, ensure_ascii=False))

        # 4) sync adapt offset based on measurement timestamp
        meas_ts_str = (
            ((filtered.get("data") or {}).get("connection") or {})
            .get("glucoseMeasurement", {})
            .get("Timestamp")
        )
        fetch_offset_s = adapt_offset(
            current_offset=fetch_offset_s,
            meas_timestamp_str=meas_ts_str,
            tz=tz,
            desired_lag_s=args.fetch_offset_target_lag,
            gain=args.fetch_offset_gain,
            max_step_s=args.fetch_offset_max_step,
            offset_min_s=args.fetch_offset_min,
            offset_max_s=args.fetch_offset_max,
            debug=args.debug,
        )

        # 5) mqtt publish (persistent connection)
        if args.mqtt_publish and mqtt_pub is not None:
            pub_raw = args.mqtt_publish_raw or (not args.mqtt_publish_filterered_and_raw_flags_set(args))
            pub_filtered = args.mqtt_publish_filtered or (not args.mqtt_publish_filterered_and_raw_flags_set(args))

            topic_raw, topic_filtered = mqtt_topics()

            if pub_raw:
                payload_raw = json_dumps_compact(raw)  # full API JSON
                mqtt_pub.publish(topic_raw, payload_raw, retain=args.mqtt_retain, qos=args.mqtt_qos)

            if pub_filtered:
                payload_f = json_dumps_compact(filtered)  # ESP32-format
                mqtt_pub.publish(topic_filtered, payload_f, retain=args.mqtt_retain, qos=args.mqtt_qos)

        return fetch_offset_s

    # helper: decide defaults if user didn't specify raw/filtered flags
    def mqtt_publish_filterered_and_raw_flags_set(args) -> bool:
        return bool(args.mqtt_publish_raw or args.mqtt_publish_filtered)

    # attach helper into args namespace (so above can call it without extra state)
    args.mqtt_publish_filterered_and_raw_flags_set = mqtt_publish_filterered_and_raw_flags_set  # type: ignore

    # single-shot
    if not args.loop:
        _ = one_cycle(args.fetch_offset)
        if mqtt_pub:
            mqtt_pub.close()
        print("✔ Done")
        return

    # loop mode
    fetch_offset_s = float(args.fetch_offset)
    eprint(f"[loop] interval={args.interval}s initial_offset={fetch_offset_s:.2f}s tz={args.tz}")

    next_run = align_next_run(time.time(), args.interval, fetch_offset_s)

    try:
        while True:
            sleep_s = next_run - time.time()
            if sleep_s > 0:
                time.sleep(sleep_s)

            try:
                fetch_offset_s = one_cycle(fetch_offset_s)
            except Exception as ex:
                eprint(f"[error] cycle failed: {ex}")

            next_run = align_next_run(time.time(), args.interval, fetch_offset_s)
    finally:
        if mqtt_pub:
            mqtt_pub.close()


if __name__ == "__main__":
    main()
