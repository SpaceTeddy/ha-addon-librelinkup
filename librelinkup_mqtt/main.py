#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import hashlib
import json
import logging
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
# Logging (timestamp + levels)
# -----------------------------

def _parse_log_level(s: str) -> int:
    s = (s or "").strip().upper()
    return {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "WARN": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }.get(s, logging.INFO)


class TZFormatter(logging.Formatter):
    """Formatter mit lokaler TZ (zoneinfo) + Millisekunden."""

    def __init__(self, fmt: str, tz):
        super().__init__(fmt=fmt, datefmt=None)
        self._tz = tz

    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created, tz=self._tz) if self._tz else datetime.fromtimestamp(record.created)
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def setup_logger(log_level: str, tz):
    logger = logging.getLogger("librelinkup")
    logger.setLevel(_parse_log_level(log_level))
    logger.handlers.clear()
    logger.propagate = False

    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(TZFormatter("%(asctime)s [%(levelname)s] %(message)s", tz))
    logger.addHandler(h)

    return logger


# -----------------------------
# Helpers
# -----------------------------

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def json_dumps_compact(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def now_ts(tz) -> datetime:
    return datetime.now(tz) if tz else datetime.now()


def iso_now(tz) -> str:
    return now_ts(tz).isoformat()


def iso_dt(dt: Optional[datetime]) -> str:
    return dt.isoformat() if dt else ""


def parse_libreview_ts(ts: str, tz) -> Optional[datetime]:
    # Example: "1/27/2026 1:29:49 PM"
    if not ts:
        return None
    try:
        dt = datetime.strptime(ts, "%m/%d/%Y %I:%M:%S %p")
        return dt.replace(tzinfo=tz) if tz else dt
    except Exception:
        return None


def parse_libreview_ts_naive(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.strptime(ts, "%m/%d/%Y %I:%M:%S %p")
    except Exception:
        return None


def compute_factory_offset(
    ts_local: Optional[str],
    ts_factory: Optional[str],
) -> Tuple[Optional[int], Optional[int], Optional[int], Optional[str]]:
    """
    Compute offset between localized Timestamp and FactoryTimestamp.

    Returns:
      offset_s: seconds (local - factory)
      offset_h: rounded hours
      residual_s: abs(offset_s - offset_h*3600)
      quality: "high" if residual<=120s else "low"
    """
    dl = parse_libreview_ts_naive(ts_local or "")
    df = parse_libreview_ts_naive(ts_factory or "")
    if not dl or not df:
        return None, None, None, None

    offset_s = int((dl - df).total_seconds())
    offset_h = int(round(offset_s / 3600.0))
    residual_s = abs(offset_s - offset_h * 3600)

    quality = "high" if residual_s <= 120 else "low"
    return offset_s, offset_h, residual_s, quality


def compute_cloud_lag_s(cloud_ts_str: Optional[str], tz) -> Optional[float]:
    dt = parse_libreview_ts(cloud_ts_str or "", tz)
    if not dt:
        return None
    return (now_ts(tz) - dt).total_seconds()


def region_to_base_url(region: str) -> str:
    if not region:
        return "https://api.libreview.io"
    r = region.strip().lower()
    if r in ("de", "eu"):
        return "https://api-de.libreview.io"
    return f"https://api-{r}.libreview.io"


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
        logger: Optional[logging.Logger] = None,
    ):
        self.api_base = api_base.rstrip("/")
        self.auth_url = self.api_base + auth_path
        self.tou_url = self.api_base + tou_path
        self.graph_template = graph_template
        self.timeout_s = timeout_s
        self.verify_tls = verify_tls
        self.connection_close = connection_close
        self.session = requests.Session()
        self.log = logger or logging.getLogger("librelinkup")

    def _headers(self) -> Dict[str, str]:
        h = dict(DEFAULT_HEADERS)
        if self.connection_close:
            h["Connection"] = "close"
        return h

    def auth_user(self, email: str, password: str) -> LoginResult:
        payload = {"email": email, "password": password}

        for attempt in (1, 2):
            self.log.debug("[http] POST %s (attempt %d)", self.auth_url, attempt)

            r = self.session.post(
                self.auth_url,
                headers=self._headers(),
                json=payload,
                timeout=self.timeout_s,
                verify=self.verify_tls,
            )

            self.log.debug("[http] status=%s len=%s", r.status_code, len(r.content))
            r.raise_for_status()

            try:
                data = r.json()
            except Exception:
                raise RuntimeError(
                    f"Login response is not JSON (status_code={r.status_code}, body={r.text[:200]!r})"
                )

            d = (data.get("data") or {})
            redirect = bool(d.get("redirect", False))
            region = str(d.get("region", "") or "").strip()

            if redirect and region and attempt == 1:
                new_base = region_to_base_url(region).rstrip("/")
                old_base = self.api_base.rstrip("/")
                if new_base != old_base:
                    self.log.info("[auth] redirect requested: region=%s -> api_base=%s", region, new_base)
                    self.api_base = new_base
                    self.auth_url = self.api_base + "/llu/auth/login"
                    self.tou_url = self.api_base + "/llu/user/consent"
                    continue
                body_short = json.dumps(data, ensure_ascii=False)[:300]
                raise RuntimeError(f"Redirect loop detected: body={body_short}")

            status = int(data.get("status", -1))
            user = d.get("user") or {}
            ticket = d.get("authTicket") or {}

            user_id = str(user.get("id", "")) if user else ""
            token = str(ticket.get("token", "")) if ticket else ""
            expires = int(ticket.get("expires", 0)) if ticket else 0
            country = str(user.get("country", "")) if user else ""

            if not user_id or not token:
                err = data.get("error") or data.get("message") or data.get("reason") or ""
                body_short = json.dumps(data, ensure_ascii=False)[:300]
                raise RuntimeError(
                    f"Login response missing user_id/token (status={status})"
                    + (f" error={err!r}" if err else "")
                    + f" body={body_short}"
                )

            account_id = sha256_hex(user_id)
            return LoginResult(status=status, country=country, user_id=user_id, token=token, expires=expires, account_id=account_id)

        raise RuntimeError("Login failed after redirect retry")

    def tou_user(self, token: str) -> Dict[str, Any]:
        self.log.debug("[http] POST %s", self.tou_url)

        h = self._headers()
        h["Authorization"] = f"Bearer {token}"

        r = self.session.post(
            self.tou_url,
            headers=h,
            data=b"",
            timeout=self.timeout_s,
            verify=self.verify_tls,
        )
        self.log.debug("[http] status=%s len=%s", r.status_code, len(r.content))
        r.raise_for_status()
        return r.json()

    def get_graph(self, user_id: str, token: str, account_id: str) -> Dict[str, Any]:
        url = self.api_base + self.graph_template.format(user_id=user_id)
        self.log.debug("[http] GET %s", url)

        h = self._headers()
        h["Authorization"] = f"Bearer {token}"
        h["Account-ID"] = account_id

        r = self.session.get(
            url,
            headers=h,
            timeout=self.timeout_s,
            verify=self.verify_tls,
        )
        self.log.debug("[http] status=%s len=%s", r.status_code, len(r.content))

        if r.status_code == 401:
            raise PermissionError("Unauthorized (401)")

        r.raise_for_status()
        return r.json()


# -----------------------------
# Filtering (ESP32 compatible) + FactoryTimestamp
# -----------------------------

def filter_graph_json(raw: Dict[str, Any], graph_limit: int = 0) -> Dict[str, Any]:
    data = raw.get("data") or {}
    conn = data.get("connection") or {}
    active = data.get("activeSensors") or []
    gdata = data.get("graphData") or []

    if graph_limit and isinstance(gdata, list):
        gdata = gdata[-graph_limit:]

    gm = (conn.get("glucoseMeasurement") or {})
    sensor = (conn.get("sensor") or {})
    pd = (conn.get("patientDevice") or {})

    out = {
        "data": {
            "connection": {
                "country": conn.get("country"),
                "status": conn.get("status"),
                "targetLow": conn.get("targetLow"),
                "targetHigh": conn.get("targetHigh"),
                "sensor": {
                    "deviceId": sensor.get("deviceId"),
                    "sn": sensor.get("sn"),
                    "a": sensor.get("a"),
                },
                "glucoseMeasurement": {
                    "FactoryTimestamp": gm.get("FactoryTimestamp"),
                    "Timestamp": gm.get("Timestamp"),
                    "ValueInMgPerDl": gm.get("ValueInMgPerDl"),
                    "TrendArrow": gm.get("TrendArrow"),
                    "TrendMessage": gm.get("TrendMessage"),
                    "MeasurementColor": gm.get("MeasurementColor"),
                },
                "patientDevice": {
                    "ll": pd.get("ll"),
                    "hl": pd.get("hl"),
                    "fixedLowAlarmValues": {
                        "mgdl": (pd.get("fixedLowAlarmValues") or {}).get("mgdl")
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
            it = (item or {})
            out["data"]["graphData"].append({
                "FactoryTimestamp": it.get("FactoryTimestamp"),
                "Timestamp": it.get("Timestamp"),
                "ValueInMgPerDl": it.get("ValueInMgPerDl"),
            })

    return out


# -----------------------------
# MQTT persistent publisher (+ status/health + LWT)
# -----------------------------

class MqttPublisher:
    def __init__(
        self,
        host: str,
        port: int,
        user: str,
        password: str,
        keepalive: int,
        base_topic: str,
        master_id: str,
        tz,
        logger: logging.Logger,
    ):
        if mqtt is None:
            raise RuntimeError("paho-mqtt not installed. Try: pip install paho-mqtt")

        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.keepalive = keepalive
        self.base_topic = (base_topic or "").strip("/")
        self.master_id = (master_id or "").strip("/")
        self.tz = tz
        self.log = logger

        self._connected = False
        self.reconnects = 0

        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)

        if user:
            self.client.username_pw_set(user, password=password)

        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect

        self.topic_status = f"{self.base_topic}/{self.master_id}/status"
        self.topic_health = f"{self.base_topic}/{self.master_id}/health"

        lwt_payload = json_dumps_compact({
            "state": "offline",
            "ts_local": iso_now(self.tz),
            "reason": "lwt",
        })
        self.client.will_set(self.topic_status, payload=lwt_payload, qos=0, retain=True)

    def _on_connect(self, client, userdata, flags, rc):
        self._connected = (rc == 0)
        self.log.debug("[mqtt] on_connect rc=%s connected=%s", rc, self._connected)

        if self._connected:
            try:
                self.publish_json(self.topic_status, {
                    "state": "online",
                    "ts_local": iso_now(self.tz),
                }, retain=True, qos=0)
            except Exception as ex:
                self.log.warning("[mqtt] failed to publish online status: %s", ex)

    def _on_disconnect(self, client, userdata, rc):
        self._connected = False
        self.log.debug("[mqtt] on_disconnect rc=%s", rc)

    def connect(self):
        self.log.info("[mqtt] connect %s:%s user=%r", self.host, self.port, self.user)
        self.client.connect(self.host, self.port, keepalive=self.keepalive)
        self.client.loop_start()

        t0 = time.time()
        while not self._connected and (time.time() - t0) < 5:
            time.sleep(0.05)

        if not self._connected:
            raise RuntimeError("MQTT connect timeout (no CONNACK within 5s)")

    def ensure_connected(self):
        if self._connected:
            return
        self.reconnects += 1
        self.log.warning("[mqtt] not connected -> reconnecting… (count=%s)", self.reconnects)

        self.client.reconnect()

        t0 = time.time()
        while not self._connected and (time.time() - t0) < 5:
            time.sleep(0.05)

        if not self._connected:
            raise RuntimeError("MQTT reconnect timeout")

    def publish(self, topic: str, payload: str, retain: bool, qos: int):
        self.ensure_connected()
        self.log.debug("[mqtt] publish topic=%s retain=%s qos=%s bytes=%s", topic, retain, qos, len(payload))
        info = self.client.publish(topic, payload=payload, qos=qos, retain=retain)
        info.wait_for_publish(timeout=10)

    def publish_json(self, topic: str, obj: Dict[str, Any], retain: bool, qos: int):
        self.publish(topic, json_dumps_compact(obj), retain=retain, qos=qos)

    def publish_health(self, obj: Dict[str, Any], retain: bool = True, qos: int = 0):
        self.publish_json(self.topic_health, obj, retain=retain, qos=qos)

    def close(self):
        try:
            if self._connected:
                self.publish_json(self.topic_status, {
                    "state": "offline",
                    "ts_local": iso_now(self.tz),
                    "reason": "shutdown",
                }, retain=True, qos=0)
        except Exception:
            pass

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
    now = int(time.time())
    return (login.expires - now) > min_valid_for_s


# -----------------------------
# Health state
# -----------------------------

@dataclass
class HealthState:
    start_epoch: float = 0.0

    last_fetch_start: Optional[datetime] = None
    last_fetch_ok: Optional[datetime] = None
    last_fetch_fail: Optional[datetime] = None

    fetch_ok_count: int = 0
    fetch_err_count: int = 0
    last_error: str = ""

    last_fetch_duration_ms: Optional[int] = None

    last_cloud_ts: str = ""
    last_cloud_lag_s: Optional[float] = None

    last_factory_ts: str = ""
    last_local_ts: str = ""
    last_tz_offset_s: Optional[int] = None
    last_tz_offset_h: Optional[int] = None
    last_tz_offset_residual_s: Optional[int] = None
    last_tz_offset_quality: str = ""

    relogin_count: int = 0
    last_meas_dt: Optional[datetime] = None


# -----------------------------
# Main
# -----------------------------

def main():
    p = argparse.ArgumentParser(
        description="LibreLinkUp CLI: token reuse + optional MQTT publish + filtered JSON + robust scheduler (poll-window)."
    )

    # credentials
    p.add_argument("--email", required=True, help="LibreLinkUp email")
    p.add_argument("--password", required=True, help="LibreLinkUp password (quote it in the shell!)")

    # logging
    p.add_argument("--debug", action="store_true", help="Enable debug logging (compat)")
    p.add_argument("--log-level", default="INFO", help="Log level: DEBUG, INFO, WARNING, ERROR (default INFO)")

    # output
    p.add_argument("--print-raw", action="store_true", help="Print raw /graph JSON")
    p.add_argument("--print-filtered", action="store_true", help="Print filtered JSON")

    # API
    p.add_argument("--api-base", default="https://api.libreview.io", help="API base URL")
    p.add_argument("--auth-path", default="/llu/auth/login", help="Auth path")
    p.add_argument("--tou-path", default="/llu/user/consent", help="ToU/consent path")
    p.add_argument("--graph-template", default="/llu/connections/{user_id}/graph", help="Graph path template")
    p.add_argument("--timeout", type=int, default=15, help="HTTP timeout seconds")
    p.add_argument("--no-verify-tls", action="store_true", help="Disable TLS verification (not recommended)")
    p.add_argument("--connection-close", action="store_true", help="Send Connection: close")

    # filtering
    p.add_argument("--graph-limit", type=int, default=0, help="Limit graphData points (0 = keep all)")

    # loop/sync
    p.add_argument("--loop", action="store_true", help="Run forever")
    p.add_argument("--interval", type=int, default=60, help="Expected sensor cadence seconds (default 60)")
    p.add_argument("--fetch-offset", type=float, default=5.0, help="Initial delay before first fetch (default 5s)")
    p.add_argument("--fetch-offset-target-lag", type=float, default=5.0, help="Target lag after measurement (default 5s)")
    p.add_argument("--tz", default="Europe/Berlin", help="Timezone (default Europe/Berlin)")

    # token reuse
    p.add_argument("--token-min-valid", type=int, default=90,
                   help="If token expires in less than this many seconds, do relogin (default 90)")

    # scheduler knobs (IMPORTANT)
    p.add_argument("--poll-seconds", type=float, default=10.0,
                   help="When no new measurement appears around expected time, poll every N seconds (default 10)")
    p.add_argument("--poll-max-seconds", type=float, default=120.0,
                   help="Maximum time to stay in poll-mode without a new measurement before falling back to interval (default 120)")

    # MQTT
    p.add_argument("--mqtt-publish", action="store_true", help="Publish to MQTT")
    p.add_argument("--mqtt-host", default="localhost", help="MQTT host")
    p.add_argument("--mqtt-port", type=int, default=1883, help="MQTT port")
    p.add_argument("--mqtt-user", default="", help="MQTT username")
    p.add_argument("--mqtt-password", default="", help="MQTT password")
    p.add_argument("--mqtt-keepalive", type=int, default=30, help="MQTT keepalive seconds (default 30)")

    p.add_argument("--mqtt-base-topic", default="librelinkup", help="Base topic")
    p.add_argument("--master-id", default="MASTER", help="Master id segment")
    p.add_argument("--mqtt-topic-raw-suffix", default="data_raw", help="Raw topic suffix")
    p.add_argument("--mqtt-topic-filtered-suffix", default="data", help="Filtered topic suffix")

    p.add_argument("--mqtt-publish-raw", action="store_true", help="Publish raw JSON")
    p.add_argument("--mqtt-publish-filtered", action="store_true", help="Publish filtered JSON")
    p.add_argument("--mqtt-retain", action="store_true", help="MQTT retain")
    p.add_argument("--mqtt-qos", type=int, default=0, choices=[0, 1, 2], help="MQTT QoS")

    # health
    p.add_argument("--mqtt-publish-health", action="store_true", help="Publish health JSON to .../health")
    p.add_argument("--mqtt-health-retain", action="store_true", help="Retain health topic")

    args = p.parse_args()

    # timezone
    tz = None
    if ZoneInfo is not None:
        try:
            tz = ZoneInfo(args.tz)
        except Exception:
            tz = None

    if args.debug and (args.log_level or "").upper() == "INFO":
        args.log_level = "DEBUG"

    logger = setup_logger(args.log_level, tz)

    if args.interval <= 0:
        logger.warning("[cfg] interval=%s invalid, forcing 60", args.interval)
        args.interval = 60
    if args.poll_seconds <= 0:
        logger.warning("[cfg] poll_seconds=%s invalid, forcing 10", args.poll_seconds)
        args.poll_seconds = 10.0

    client = LibreLinkUpClient(
        api_base=args.api_base,
        auth_path=args.auth_path,
        tou_path=args.tou_path,
        graph_template=args.graph_template,
        timeout_s=args.timeout,
        verify_tls=not args.no_verify_tls,
        connection_close=args.connection_close,
        logger=logger,
    )

    mqtt_pub: Optional[MqttPublisher] = None
    if args.mqtt_publish:
        mqtt_pub = MqttPublisher(
            host=args.mqtt_host,
            port=args.mqtt_port,
            user=args.mqtt_user,
            password=args.mqtt_password,
            keepalive=args.mqtt_keepalive,
            base_topic=args.mqtt_base_topic,
            master_id=args.master_id,
            tz=tz,
            logger=logger,
        )
        mqtt_pub.connect()

    auth = AuthCache()
    health = HealthState(start_epoch=time.time())

    # Scheduler state
    last_meas_epoch: Optional[float] = None
    last_meas_changed_epoch: float = time.time()  # last time we observed a NEW meas timestamp

    def ensure_login() -> LoginResult:
        if token_is_valid(auth.login, args.token_min_valid):
            return auth.login  # type: ignore

        logger.info("=== LOGIN (new/refresh) ===")
        login = client.auth_user(args.email, args.password)
        auth.login = login
        auth.last_login_epoch = time.time()

        logger.debug("user_id        : %s", login.user_id)
        logger.debug("country        : %s", login.country)
        logger.debug("status         : %s", login.status)
        logger.debug("token (short)  : %s…", (login.token[:18] if login.token else ""))
        logger.debug("expires (unix) : %s", login.expires)
        logger.debug("account_id     : %s", login.account_id)

        if login.status == 4:
            logger.info("[info] ToU/consent required -> trying tou_user()")
            try:
                client.tou_user(login.token)
            except Exception as ex:
                logger.warning("[warn] tou_user failed: %s", ex)

        return login

    def mqtt_topics() -> Tuple[str, str]:
        base = args.mqtt_base_topic.strip("/")
        mid = args.master_id.strip("/")
        topic_raw = f"{base}/{mid}/{args.mqtt_topic_raw_suffix}"
        topic_filtered = f"{base}/{mid}/{args.mqtt_topic_filtered_suffix}"
        return topic_raw, topic_filtered

    def resolve_publish_modes() -> Tuple[bool, bool]:
        any_flag = bool(args.mqtt_publish_raw or args.mqtt_publish_filtered)
        if any_flag:
            return bool(args.mqtt_publish_raw), bool(args.mqtt_publish_filtered)
        return False, True  # default: filtered only

    def token_valid_for_s() -> Optional[int]:
        if not auth.login:
            return None
        return max(0, int(auth.login.expires - time.time()))

    def publish_health():
        if not (args.mqtt_publish and mqtt_pub):
            return
        if not args.mqtt_publish_health:
            return

        payload = {
            "ts_local": iso_now(tz),
            "uptime_s": int(time.time() - health.start_epoch),

            "fetch": {
                "ok": (health.last_error == ""),
                "last_start": iso_dt(health.last_fetch_start),
                "last_ok": iso_dt(health.last_fetch_ok),
                "last_fail": iso_dt(health.last_fetch_fail),
                "duration_ms": health.last_fetch_duration_ms,
                "ok_count": health.fetch_ok_count,
                "err_count": health.fetch_err_count,
                "last_error": health.last_error,
            },

            "cloud": {
                "ts": health.last_cloud_ts,
                "lag_s": health.last_cloud_lag_s,
                "target_lag_s": float(args.fetch_offset_target_lag),
                "meas_dt": iso_dt(health.last_meas_dt),

                "local_ts": health.last_local_ts,
                "factory_ts": health.last_factory_ts,
                "tz_offset_s": health.last_tz_offset_s,
                "tz_offset_h": health.last_tz_offset_h,
                "tz_offset_residual_s": health.last_tz_offset_residual_s,
                "tz_offset_quality": health.last_tz_offset_quality,
            },

            "auth": {
                "token_valid_for_s": token_valid_for_s(),
                "relogin_count": health.relogin_count,
            },

            "mqtt": {
                "connected": bool(mqtt_pub._connected),
                "reconnects": int(mqtt_pub.reconnects),
            },

            "scheduler": {
                "interval_s": int(args.interval),
                "poll_s": float(args.poll_seconds),
                "last_meas_epoch": last_meas_epoch,
            }
        }

        mqtt_pub.publish_health(payload, retain=bool(args.mqtt_health_retain), qos=0)

    def one_cycle() -> Optional[datetime]:
        """
        One fetch/publish cycle.
        Returns the parsed measurement datetime (or None).
        """
        health.last_fetch_start = now_ts(tz)
        t0 = time.time()

        meas_dt: Optional[datetime] = None

        try:
            login = ensure_login()

            logger.debug("=== FETCH GRAPH ===")
            try:
                raw = client.get_graph(login.user_id, login.token, login.account_id)
            except PermissionError:
                logger.warning("[auth] 401 -> relogin and retry once")
                auth.login = None
                health.relogin_count += 1
                login = ensure_login()
                raw = client.get_graph(login.user_id, login.token, login.account_id)

            filtered = filter_graph_json(raw, graph_limit=args.graph_limit)

            gm = (((filtered.get("data") or {}).get("connection") or {}).get("glucoseMeasurement") or {})
            cloud_ts_str = gm.get("Timestamp")
            cloud_factory_ts_str = gm.get("FactoryTimestamp")

            health.last_cloud_ts = cloud_ts_str or ""
            health.last_meas_dt = parse_libreview_ts(cloud_ts_str or "", tz)
            meas_dt = health.last_meas_dt

            health.last_cloud_lag_s = compute_cloud_lag_s(cloud_ts_str, tz)

            off_s, off_h, resid_s, qual = compute_factory_offset(cloud_ts_str, cloud_factory_ts_str)
            health.last_local_ts = cloud_ts_str or ""
            health.last_factory_ts = cloud_factory_ts_str or ""
            health.last_tz_offset_s = off_s
            health.last_tz_offset_h = off_h
            health.last_tz_offset_residual_s = resid_s
            health.last_tz_offset_quality = qual or ""

            if args.print_raw:
                print("=== RAW GRAPH JSON ===")
                print(json.dumps(raw, indent=2, ensure_ascii=False))

            if args.print_filtered:
                print("=== FILTERED GRAPH JSON ===")
                print(json.dumps(filtered, indent=2, ensure_ascii=False))

            # publish MQTT
            if args.mqtt_publish and mqtt_pub is not None:
                pub_raw, pub_filtered = resolve_publish_modes()
                topic_raw, topic_filtered = mqtt_topics()

                if pub_raw:
                    mqtt_pub.publish(topic_raw, json_dumps_compact(raw), retain=args.mqtt_retain, qos=args.mqtt_qos)
                if pub_filtered:
                    mqtt_pub.publish(topic_filtered, json_dumps_compact(filtered), retain=args.mqtt_retain, qos=args.mqtt_qos)

            health.last_fetch_ok = now_ts(tz)
            health.fetch_ok_count += 1
            health.last_error = ""

            # log sync info (purely informational)
            if health.last_cloud_lag_s is not None:
                logger.debug("[sync] lag=%.2fs desired=%.2fs", float(health.last_cloud_lag_s), float(args.fetch_offset_target_lag))

            return meas_dt

        except Exception as ex:
            health.last_fetch_fail = now_ts(tz)
            health.fetch_err_count += 1
            health.last_error = str(ex)[:300]
            raise

        finally:
            health.last_fetch_duration_ms = int((time.time() - t0) * 1000)
            try:
                publish_health()
            except Exception as ex:
                logger.warning("[health] publish failed: %s", ex)

    # -----------------------------
    # single-shot
    # -----------------------------
    if not args.loop:
        try:
            _ = one_cycle()
            logger.info("✔ Done")
        finally:
            if mqtt_pub:
                mqtt_pub.close()
        return

    # -----------------------------
    # LOOP: robust scheduler (poll-window)
    # -----------------------------
    interval_s = float(args.interval)
    target_lag = float(args.fetch_offset_target_lag)
    poll_s = float(args.poll_seconds)
    poll_max_s = float(args.poll_max_seconds)

    logger.info(
        "[loop] interval=%ss initial_delay=%.2fs tz=%s target_lag=%.2fs poll=%.1fs poll_max=%.0fs",
        args.interval, float(args.fetch_offset), args.tz, target_lag, poll_s, poll_max_s
    )

    next_run = time.time() + float(args.fetch_offset)

    try:
        while True:
            sleep_s = next_run - time.time()
            if sleep_s > 0:
                time.sleep(sleep_s)

            # run cycle
            try:
                meas_dt = one_cycle()
            except KeyboardInterrupt:
                raise
            except Exception as ex:
                logger.error("cycle failed: %s", ex)
                meas_dt = None

            # update scheduler state (detect new measurement timestamp)
            now_e = time.time()
            meas_epoch = meas_dt.timestamp() if meas_dt is not None else None

            if meas_epoch is not None:
                if last_meas_epoch is None or meas_epoch != last_meas_epoch:
                    last_meas_epoch = meas_epoch
                    last_meas_changed_epoch = now_e

            # compute next_run
            if last_meas_epoch is None:
                # still nothing valid -> just retry at interval
                next_run = now_e + interval_s
                logger.debug(
                    "[schedule] no last_meas -> next_run=%s",
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(next_run))
                )
                continue

            # The earliest time we *expect* a new measurement to be visible:
            # last_meas + interval + target_lag
            expected_next = last_meas_epoch + interval_s + target_lag

            if now_e < expected_next:
                # wait until expected_next (this avoids your previous :51 pattern)
                next_run = expected_next
                logger.debug(
                    "[schedule] last_meas=%s expected_next=%s sleep=%.3fs",
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_meas_epoch)),
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expected_next)),
                    max(0.0, next_run - time.time())
                )
                continue

            # We are past expected_next but measurement may still not have updated (cloud caching).
            # => Poll mode, but with a cap.
            poll_age = now_e - last_meas_changed_epoch
            if poll_age <= poll_max_s:
                next_run = now_e + poll_s
                logger.debug(
                    "[schedule] expected_next=%s is past; meas_still=%s; POLL next_run=%s (poll_age=%.1fs)",
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expected_next)),
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_meas_epoch)),
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(next_run)),
                    poll_age
                )
            else:
                # If we have polled long enough without a new meas timestamp, fall back to interval
                next_run = now_e + interval_s
                logger.debug(
                    "[schedule] poll_max exceeded (%.1fs) -> fallback next_run=%s",
                    poll_age,
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(next_run))
                )

    finally:
        if mqtt_pub:
            mqtt_pub.close()


if __name__ == "__main__":
    main()
