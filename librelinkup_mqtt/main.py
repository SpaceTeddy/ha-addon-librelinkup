#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LibreLinkUp -> MQTT Add-on main.py (Drop-in, CLI-kompatibel)

Ziele:
- 1:1 kompatibel zu deiner "meist lauffähigen" Version (Args, Topics, Publish-Modi, Health).
- Zeitzonen-robustes Scheduling/Lag via FactoryTimestamp (UTC epoch) -> kein negativer lag, kein 7h sleep.
- Stabiler Scheduler: expected_next = last_meas + interval + target_lag, Poll-Window bei Cloud-Caching.

Hinweis:
- Timestamp wird weiter geloggt/health-ausgegeben (zur Anzeige).
- Scheduling + lag basieren primär auf FactoryTimestamp.
"""

import argparse
import hashlib
import json
import logging
import math
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
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

def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


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


def parse_libreview_ts_local(ts: str, tz) -> Optional[datetime]:
    """Parse Timestamp (Anzeige). NICHT fürs Scheduling verwenden."""
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


def parse_factory_epoch(ts_factory: Optional[str]) -> Optional[float]:
    """
    FactoryTimestamp wird als UTC Referenz behandelt.
    Ergebnis: epoch seconds (UTC), stabil über alle Zeitzonen.
    """
    if not ts_factory:
        return None
    try:
        dt = datetime.strptime(ts_factory, "%m/%d/%Y %I:%M:%S %p")
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return None


def factory_epoch_to_local_dt(epoch_s: float, tz) -> datetime:
    dt_utc = datetime.fromtimestamp(epoch_s, tz=timezone.utc)
    return dt_utc.astimezone(tz) if tz else dt_utc.replace(tzinfo=None)


# Nach so vielen aufeinanderfolgenden "aelteren" Messungen wird der Rueckwaerts-
# sprung als dauerhaft angesehen und neu verankert, statt ewig zu blockieren.
MAX_CONSECUTIVE_OLDER = 10


def next_grid_run(
    last_meas_epoch: float,
    interval_s: float,
    lag_s: float,
    now_e: float,
    min_step: float = 1.0,
) -> float:
    """
    Nächster Zeitpunkt auf dem Messraster des Sensors:
        last_meas_epoch + k * interval_s + lag_s     (k >= 1)
    Es wird der kleinste solche Zeitpunkt gewählt, der echt in der Zukunft liegt.

    Dadurch bleibt die Phasenlage zum Sensor auch nach Fehlern, Aussetzern oder
    langen Cloud-Pausen erhalten — im Gegensatz zu "now + interval", das die
    Phaseninformation verwirft.

    min_step verhindert einen Floating-Point-Grenzfall: liegt das Raster exakt
    auf now_e, würde ohne diese Korrektur ein Zeitschritt von ~0s entstehen und
    der Loop die API in einer Endlosschleife abfragen.
    """
    k = math.floor((now_e - last_meas_epoch - lag_s) / interval_s) + 1
    if k < 1:
        k = 1
    t = last_meas_epoch + k * interval_s + lag_s
    if t < now_e + min_step:
        t = last_meas_epoch + (k + 1) * interval_s + lag_s
    return t


def compute_factory_offset(
    ts_local: Optional[str],
    ts_factory: Optional[str],
) -> Tuple[Optional[int], Optional[int], Optional[int], Optional[str]]:
    """
    Debug/Health: Differenz zwischen Timestamp und FactoryTimestamp (beide "naive" geparst).
    Nur Info, nicht fürs Scheduling.
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


def region_to_base_url(region: str) -> str:
    if not region:
        return "https://api.libreview.io"
    r = region.strip().lower()
    if r in ("de", "eu"):
        return "https://api-de.libreview.io"
    return f"https://api-{r}.libreview.io"


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
                raise RuntimeError(f"Login response not JSON (status={r.status_code}, body={r.text[:200]!r})")

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
                    f"Login missing user_id/token (status={status})"
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
                    "dtid": pd.get("dtid"),
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
            d = (item or {}).get("device") or {}
            out["data"]["activeSensors"].append({
                "device": {
                    "dtid": d.get("dtid"),
                },
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

        # Keep v1 for backwards compatibility with your container image
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

    # Cloud timestamps
    last_cloud_update_epoch: float = 0.0   # wann die cloud-Felder zuletzt frisch waren
    last_cloud_ts: str = ""               # Timestamp (string)
    last_cloud_factory_ts: str = ""       # FactoryTimestamp (string)
    last_cloud_lag_s: Optional[float] = None  # lag vs FactoryTimestamp (seconds)

    # Timecode info
    last_local_ts: str = ""
    last_factory_ts: str = ""
    last_tz_offset_s: Optional[int] = None
    last_tz_offset_h: Optional[int] = None
    last_tz_offset_residual_s: Optional[int] = None
    last_tz_offset_quality: str = ""

    # measurement dt for display
    last_meas_local_dt: Optional[datetime] = None
    last_meas_epoch: Optional[float] = None

    relogin_count: int = 0
    last_publish_reason: str = ""


# -----------------------------
# Runtime state
# -----------------------------

@dataclass
class PublishState:
    last_published_meas_epoch: Optional[float] = None
    last_filtered_payload_sig: str = ""
    last_raw_payload_sig: str = ""
    last_publish_epoch: float = 0.0


@dataclass
class SchedulerState:
    last_meas_epoch: Optional[float] = None
    last_meas_changed_epoch: float = 0.0

    # Adaptives Modell der Cloud-Verzögerung (wann taucht eine Messung wirklich auf)
    delay_ema: Optional[float] = None       # gleitender Mittelwert der Ankunftsverzögerung
    delay_dev: Optional[float] = None       # gleitende mittlere Abweichung davon
    effective_lag: float = 0.0              # daraus abgeleiteter Weckversatz

    # Poll-Fenster
    poll_deadline: Optional[float] = None
    consecutive_missed: int = 0
    stale: bool = False

    # Fehler-Backoff
    consecutive_errors: int = 0

    # Cloud liefert zeitweise eine ältere Messung aus
    consecutive_older: int = 0

    # Zähler für /health
    missed_count: int = 0
    resync_count: int = 0
    stale_meas_count: int = 0


def update_delay_model(
    sched: SchedulerState,
    observed_delay_s: float,
    args: argparse.Namespace,
    interval_s: float,
) -> None:
    """
    Lernt, wie lange die Cloud typischerweise braucht, bis eine Messung sichtbar ist.

    Statt stur bei meas + target_lag zu wecken (und dann minutenlang zu pollen),
    weckt der Scheduler kurz vor der erwarteten Ankunft. Der Vorlauf richtet sich
    nach der beobachteten Streuung, damit wir zuverlässig knapp davor liegen.
    """
    if not (0.0 <= observed_delay_s <= interval_s * 3):
        return  # Ausreißer (z.B. Cloud-Nachlauf nach Aussetzer) nicht einlernen

    alpha = clamp(float(args.lag_ema_alpha), 0.01, 1.0)
    poll_s = float(args.poll_seconds)

    if sched.delay_ema is None or sched.delay_dev is None:
        sched.delay_ema = observed_delay_s
        sched.delay_dev = poll_s
    else:
        sched.delay_dev = (1.0 - alpha) * sched.delay_dev + alpha * abs(observed_delay_s - sched.delay_ema)
        sched.delay_ema = (1.0 - alpha) * sched.delay_ema + alpha * observed_delay_s

    lead = max(poll_s, float(args.lag_lead_factor) * sched.delay_dev)
    sched.effective_lag = clamp(
        sched.delay_ema - lead,
        float(args.fetch_offset_target_lag),
        interval_s * 2.0,
    )


# -----------------------------
# Main workflow helpers
# -----------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="LibreLinkUp CLI: token reuse + MQTT publish + filtered JSON + TZ-robust scheduling via FactoryTimestamp."
    )

    # credentials
    p.add_argument("--email", required=True, help="LibreLinkUp email")
    p.add_argument("--password", required=True, help="LibreLinkUp password")

    # output/debug/logging
    p.add_argument("--debug", action="store_true", help="Enable debug logging (kept for compatibility)")
    p.add_argument("--log-level", default="INFO", help="Log level: DEBUG, INFO, WARNING, ERROR (default INFO)")
    p.add_argument("--print-raw", action="store_true", help="Print raw /graph JSON")
    p.add_argument("--print-filtered", action="store_true", help="Print filtered JSON")

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
    p.add_argument("--interval", type=int, default=60, help="Expected sensor cadence seconds (default 60)")

    # keep compatibility flags
    p.add_argument("--fetch-offset", type=float, default=5.0, help="Initial delay before first scheduled run")
    p.add_argument("--fetch-offset-target-lag", type=float, default=5.0, help="Target lag after measurement (seconds)")
    p.add_argument("--fetch-offset-min", type=float, default=1.0, help="(compat) unused in this stable scheduler")
    p.add_argument("--fetch-offset-max", type=float, default=20.0, help="(compat) unused in this stable scheduler")
    p.add_argument("--fetch-offset-gain", type=float, default=0.3, help="(compat) unused in this stable scheduler")
    p.add_argument("--fetch-offset-max-step", type=float, default=1.0, help="(compat) unused in this stable scheduler")
    p.add_argument("--tz", default="Europe/Berlin", help="Timezone for display/logs (default Europe/Berlin)")

    # scheduler knobs
    p.add_argument("--poll-seconds", type=float, default=10.0, help="Poll interval when cloud caches (default 10s)")
    p.add_argument("--poll-max-seconds", type=float, default=120.0, help="Max poll window (default 120s)")
    p.add_argument("--no-adaptive-lag", action="store_true",
                   help="Disable learning of the cloud arrival delay; always wake at meas + target lag")
    p.add_argument("--lag-ema-alpha", type=float, default=0.3,
                   help="Smoothing factor for the arrival-delay model (default 0.3)")
    p.add_argument("--lag-lead-factor", type=float, default=1.5,
                   help="Wake this many mean-deviations before the expected arrival (default 1.5)")
    p.add_argument("--stale-after", type=int, default=2,
                   help="Enter stale mode after this many consecutive skipped measurements (default 2)")
    p.add_argument("--stale-poll-seconds", type=float, default=30.0,
                   help="Check interval while the cloud is stale (default 30s)")
    p.add_argument("--error-retry-seconds", type=float, default=10.0,
                   help="Base retry delay after a failed cycle, grows linearly up to interval (default 10s)")

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

    p.add_argument("--mqtt-base-topic", default="librelinkup", help="Base topic")
    p.add_argument("--master-id", default="MASTER", help="Master id segment")
    p.add_argument("--mqtt-topic-raw-suffix", default="data_raw", help="Raw topic suffix")
    p.add_argument("--mqtt-topic-filtered-suffix", default="data", help="Filtered topic suffix")

    p.add_argument("--mqtt-publish-raw", action="store_true", help="Publish raw JSON")
    p.add_argument("--mqtt-publish-filtered", action="store_true", help="Publish filtered JSON")
    p.add_argument("--mqtt-retain", action="store_true", help="MQTT retain flag")
    p.add_argument("--mqtt-qos", type=int, default=0, choices=[0, 1, 2], help="MQTT QoS (0/1/2)")
    p.add_argument("--mqtt-publish-on-change", action="store_true",
                   help="Publish only when measurement timestamp changes (recommended)")
    p.add_argument("--mqtt-force-publish-seconds", type=float, default=0.0,
                   help="Force republish after this many seconds even if unchanged (0=disabled)")

    # Health publishing
    p.add_argument("--mqtt-publish-health", action="store_true", help="Publish health JSON to .../health")
    p.add_argument("--mqtt-health-retain", action="store_true", help="Retain health topic")
    return p


def resolve_timezone(tz_name: str):
    tz = None
    if ZoneInfo is not None:
        try:
            tz = ZoneInfo(tz_name)
        except Exception:
            tz = None
    return tz


def create_client(args: argparse.Namespace, logger: logging.Logger) -> LibreLinkUpClient:
    return LibreLinkUpClient(
        api_base=args.api_base,
        auth_path=args.auth_path,
        tou_path=args.tou_path,
        graph_template=args.graph_template,
        timeout_s=args.timeout,
        verify_tls=not args.no_verify_tls,
        connection_close=args.connection_close,
        logger=logger,
    )


def create_mqtt_publisher(args: argparse.Namespace, tz, logger: logging.Logger) -> Optional[MqttPublisher]:
    if not args.mqtt_publish:
        return None

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
    return mqtt_pub


def ensure_login(
    args: argparse.Namespace,
    client: LibreLinkUpClient,
    auth: AuthCache,
    health: HealthState,
    logger: logging.Logger,
) -> LoginResult:
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


def mqtt_topics(args: argparse.Namespace) -> Tuple[str, str]:
    base = args.mqtt_base_topic.strip("/")
    mid = args.master_id.strip("/")
    topic_raw = f"{base}/{mid}/{args.mqtt_topic_raw_suffix}"
    topic_filtered = f"{base}/{mid}/{args.mqtt_topic_filtered_suffix}"
    return topic_raw, topic_filtered


def resolve_publish_modes(args: argparse.Namespace) -> Tuple[bool, bool]:
    any_flag = bool(args.mqtt_publish_raw or args.mqtt_publish_filtered)
    if any_flag:
        return bool(args.mqtt_publish_raw), bool(args.mqtt_publish_filtered)
    return False, True  # default: filtered only


def token_valid_for_s(auth: AuthCache) -> Optional[int]:
    if not auth.login:
        return None
    return max(0, int(auth.login.expires - time.time()))


def publish_health(
    args: argparse.Namespace,
    tz,
    health: HealthState,
    auth: AuthCache,
    mqtt_pub: Optional[MqttPublisher],
    sched: Optional["SchedulerState"] = None,
):
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
            # Bei einem fehlgeschlagenen Zyklus wird /health weiterhin publiziert,
            # die cloud-Felder stammen dann aber noch vom letzten Erfolg. age_s macht
            # das sichtbar: waechst der Wert ueber ein Intervall hinaus, sind ts/lag_s
            # veraltet und kein aktueller Messwert.
            "age_s": (round(time.time() - health.last_cloud_update_epoch, 1)
                      if health.last_cloud_update_epoch > 0 else None),
            "ts": health.last_cloud_ts,
            "factory_ts": health.last_cloud_factory_ts,
            "lag_s": health.last_cloud_lag_s,
            "target_lag_s": float(args.fetch_offset_target_lag),

            # display
            "meas_local_dt": iso_dt(health.last_meas_local_dt),
            "meas_epoch": health.last_meas_epoch,

            # debug offset info
            "local_ts": health.last_local_ts,
            "factory_ts_dbg": health.last_factory_ts,
            "tz_offset_s": health.last_tz_offset_s,
            "tz_offset_h": health.last_tz_offset_h,
            "tz_offset_residual_s": health.last_tz_offset_residual_s,
            "tz_offset_quality": health.last_tz_offset_quality,
        },

        "auth": {
            "token_valid_for_s": token_valid_for_s(auth),
            "relogin_count": health.relogin_count,
        },

        "mqtt": {
            "connected": bool(mqtt_pub._connected),
            "reconnects": int(mqtt_pub.reconnects),
            "last_publish_reason": health.last_publish_reason,
        }
    }

    if sched is not None:
        payload["sched"] = {
            "effective_lag_s": round(sched.effective_lag, 1),
            "delay_ema_s": round(sched.delay_ema, 1) if sched.delay_ema is not None else None,
            "delay_dev_s": round(sched.delay_dev, 1) if sched.delay_dev is not None else None,
            "stale": bool(sched.stale),
            "consecutive_missed": int(sched.consecutive_missed),
            "missed_total": int(sched.missed_count),
            "resync_count": int(sched.resync_count),
            "consecutive_errors": int(sched.consecutive_errors),
            "stale_meas_total": int(sched.stale_meas_count),
            "consecutive_older": int(sched.consecutive_older),
        }

    mqtt_pub.publish_health(payload, retain=bool(args.mqtt_health_retain), qos=0)


def should_publish(
    args: argparse.Namespace,
    publish_state: PublishState,
    payload: str,
    meas_epoch: Optional[float],
    payload_sig_last: str,
) -> Tuple[bool, str, str]:
    sig = sha256_hex(payload)
    if not args.mqtt_publish_on_change:
        return True, "always", sig

    now_e = time.time()
    if publish_state.last_publish_epoch <= 0:
        return True, "first", sig

    if meas_epoch is not None:
        last_pub = publish_state.last_published_meas_epoch
        if last_pub is None or meas_epoch > last_pub:
            return True, "new_meas_epoch", sig
        # Die LibreLinkUp-Cloud liefert zeitweise eine ÄLTERE Messung aus
        # (verschiedene Backend-Knoten mit unterschiedlichem Cache-Stand).
        # Die darf nicht als aktueller Wert veröffentlicht werden, sonst zeigt
        # Home Assistant einen minutenalten Glukosewert als aktuell an.
        if meas_epoch < last_pub:
            return False, "stale_meas_epoch", sig
        # LibreLinkUp can change data fields without advancing FactoryTimestamp.
        # In that case, keep /data in sync instead of suppressing the publish.
        if sig != payload_sig_last:
            return True, "payload_changed_same_meas_epoch", sig
        if args.mqtt_force_publish_seconds > 0 and (now_e - publish_state.last_publish_epoch) >= args.mqtt_force_publish_seconds:
            return True, "forced_interval", sig
        return False, "same_meas_epoch", sig

    if sig != payload_sig_last:
        return True, "payload_changed_no_meas_epoch", sig
    if args.mqtt_force_publish_seconds > 0 and (now_e - publish_state.last_publish_epoch) >= args.mqtt_force_publish_seconds:
        return True, "forced_interval_no_meas_epoch", sig
    return False, "same_payload_no_meas_epoch", sig


def publish_mqtt_payloads(
    args: argparse.Namespace,
    mqtt_pub: Optional[MqttPublisher],
    publish_state: PublishState,
    raw: Dict[str, Any],
    filtered: Dict[str, Any],
    meas_epoch: Optional[float],
    logger: logging.Logger,
) -> str:
    if not (args.mqtt_publish and mqtt_pub is not None):
        return "not_published"

    pub_raw, pub_filtered = resolve_publish_modes(args)
    topic_raw, topic_filtered = mqtt_topics(args)
    published_any = False
    publish_reason = "not_published"

    if pub_raw:
        raw_payload = json_dumps_compact(raw)
        do_pub, reason, sig = should_publish(args, publish_state, raw_payload, meas_epoch, publish_state.last_raw_payload_sig)
        if do_pub:
            mqtt_pub.publish(topic_raw, raw_payload, retain=args.mqtt_retain, qos=args.mqtt_qos)
            published_any = True
            publish_reason = f"raw:{reason}"
        else:
            logger.debug("[mqtt] skip raw publish: %s", reason)
        publish_state.last_raw_payload_sig = sig

    if pub_filtered:
        filtered_payload = json_dumps_compact(filtered)
        do_pub, reason, sig = should_publish(args, publish_state, filtered_payload, meas_epoch, publish_state.last_filtered_payload_sig)
        if do_pub:
            mqtt_pub.publish(topic_filtered, filtered_payload, retain=args.mqtt_retain, qos=args.mqtt_qos)
            published_any = True
            publish_reason = f"filtered:{reason}"
        else:
            logger.debug("[mqtt] skip filtered publish: %s", reason)
        publish_state.last_filtered_payload_sig = sig

    if published_any:
        publish_state.last_publish_epoch = time.time()
        if meas_epoch is not None:
            publish_state.last_published_meas_epoch = meas_epoch

    return publish_reason


def one_cycle(
    args: argparse.Namespace,
    tz,
    client: LibreLinkUpClient,
    mqtt_pub: Optional[MqttPublisher],
    auth: AuthCache,
    health: HealthState,
    publish_state: PublishState,
    logger: logging.Logger,
    sched: Optional[SchedulerState] = None,
) -> Tuple[Optional[float], Optional[datetime]]:
    """
    One fetch/publish cycle.
    Returns:
      meas_epoch (UTC epoch via FactoryTimestamp if possible)
      meas_local_dt (for logs/health display)
    """
    health.last_fetch_start = now_ts(tz)
    t0 = time.time()

    meas_epoch: Optional[float] = None
    meas_local_dt: Optional[datetime] = None
    publish_reason = "not_published"

    try:
        login = ensure_login(args, client, auth, health, logger)

        logger.debug("=== FETCH GRAPH ===")
        try:
            raw = client.get_graph(login.user_id, login.token, login.account_id)
        except PermissionError:
            logger.warning("[auth] 401 -> relogin and retry once")
            auth.login = None
            health.relogin_count += 1
            login = ensure_login(args, client, auth, health, logger)
            raw = client.get_graph(login.user_id, login.token, login.account_id)

        filtered = filter_graph_json(raw, graph_limit=args.graph_limit)

        gm = (((filtered.get("data") or {}).get("connection") or {}).get("glucoseMeasurement") or {})
        cloud_ts_str = gm.get("Timestamp") or ""
        cloud_factory_ts_str = gm.get("FactoryTimestamp") or ""

        health.last_cloud_ts = cloud_ts_str
        health.last_cloud_factory_ts = cloud_factory_ts_str
        health.last_cloud_update_epoch = time.time()

        # --- Measurement time (robust): FactoryTimestamp -> epoch
        meas_epoch = parse_factory_epoch(cloud_factory_ts_str)
        if meas_epoch is not None:
            meas_local_dt = factory_epoch_to_local_dt(meas_epoch, tz)
            lag = time.time() - meas_epoch
            if lag < -10:
                logger.warning(
                    "[sync] meas_epoch liegt %.1fs in der Zukunft — "
                    "FactoryTimestamp UTC-Annahme prüfen! (factory_ts=%r)",
                    -lag, cloud_factory_ts_str,
                )
            health.last_cloud_lag_s = lag
        else:
            # fallback: use Timestamp only for display; lag is unknown/unstable
            meas_local_dt = parse_libreview_ts_local(cloud_ts_str, tz)
            health.last_cloud_lag_s = None

        health.last_meas_epoch = meas_epoch
        health.last_meas_local_dt = meas_local_dt

        # Debug offset info (optional)
        off_s, off_h, resid_s, qual = compute_factory_offset(cloud_ts_str, cloud_factory_ts_str)
        health.last_local_ts = cloud_ts_str
        health.last_factory_ts = cloud_factory_ts_str
        health.last_tz_offset_s = off_s
        health.last_tz_offset_h = off_h
        health.last_tz_offset_residual_s = resid_s
        health.last_tz_offset_quality = qual or ""

        # prints
        if args.print_raw:
            print("=== RAW GRAPH JSON ===")
            print(json.dumps(raw, indent=2, ensure_ascii=False))
        if args.print_filtered:
            print("=== FILTERED GRAPH JSON ===")
            print(json.dumps(filtered, indent=2, ensure_ascii=False))

        publish_reason = publish_mqtt_payloads(args, mqtt_pub, publish_state, raw, filtered, meas_epoch, logger)

        # ok counters
        health.last_fetch_ok = now_ts(tz)
        health.fetch_ok_count += 1
        health.last_error = ""
        health.last_publish_reason = publish_reason

        # sync log (epoch-based)
        if meas_epoch is not None:
            lag = time.time() - meas_epoch
            logger.debug("[sync] lag=%.2fs desired=%.2fs", lag, float(args.fetch_offset_target_lag))

        return meas_epoch, meas_local_dt

    except Exception as ex:
        health.last_fetch_fail = now_ts(tz)
        health.fetch_err_count += 1
        health.last_error = str(ex)[:300]
        raise

    finally:
        health.last_fetch_duration_ms = int((time.time() - t0) * 1000)
        try:
            publish_health(args, tz, health, auth, mqtt_pub, sched)
        except Exception as ex:
            logger.warning("[health] publish failed: %s", ex)


def run_single_cycle(
    args: argparse.Namespace,
    tz,
    client: LibreLinkUpClient,
    mqtt_pub: Optional[MqttPublisher],
    auth: AuthCache,
    health: HealthState,
    publish_state: PublishState,
    logger: logging.Logger,
):
    try:
        _ = one_cycle(args, tz, client, mqtt_pub, auth, health, publish_state, logger)
        logger.info("✔ Done")
    finally:
        if mqtt_pub:
            mqtt_pub.close()


def run_loop(
    args: argparse.Namespace,
    tz,
    client: LibreLinkUpClient,
    mqtt_pub: Optional[MqttPublisher],
    auth: AuthCache,
    health: HealthState,
    publish_state: PublishState,
    scheduler_state: SchedulerState,
    logger: logging.Logger,
):
    sched = scheduler_state

    interval_s = float(args.interval)
    target_lag = float(args.fetch_offset_target_lag)
    poll_s = float(args.poll_seconds)
    poll_max_s = float(args.poll_max_seconds)
    stale_poll_s = float(args.stale_poll_seconds)
    stale_after = max(1, int(args.stale_after))
    err_retry_s = float(args.error_retry_seconds)
    adaptive = not args.no_adaptive_lag

    if sched.effective_lag <= 0.0:
        sched.effective_lag = target_lag

    logger.info("[loop] interval=%ss initial_delay=%.1fs tz=%s target_lag=%.1fs "
                "poll=%.0fs poll_max=%.0fs adaptive_lag=%s",
                args.interval, float(args.fetch_offset), args.tz, target_lag,
                poll_s, poll_max_s, "on" if adaptive else "off")

    def hhmmss(epoch_s: float) -> str:
        dt = factory_epoch_to_local_dt(epoch_s, tz) if tz else datetime.fromtimestamp(epoch_s)
        return dt.strftime("%H:%M:%S")

    def capped(target_epoch: float, now_e: float) -> float:
        """Schutz gegen absurd weite Zielzeiten (z.B. falsche FactoryTimestamp-Zeitzone)."""
        limit = now_e + interval_s + poll_max_s
        if target_epoch > limit:
            logger.warning("[schedule] Zielzeit liegt %.0fs in der Zukunft — begrenzt auf %.0fs. "
                           "FactoryTimestamp/UTC prüfen!",
                           target_epoch - now_e, limit - now_e)
            return limit
        return target_epoch

    # initial delay
    next_run = time.time() + float(args.fetch_offset)

    try:
        while True:
            sleep_s = next_run - time.time()
            if sleep_s > 0:
                time.sleep(sleep_s)

            try:
                meas_epoch, _ = one_cycle(
                    args, tz, client, mqtt_pub, auth, health, publish_state, logger, sched
                )
                sched.consecutive_errors = 0
            except KeyboardInterrupt:
                raise
            except Exception as ex:
                # Fehler lassen das Messraster unangetastet — nach Erholung
                # rastet der Scheduler ohne Phasenverlust wieder ein.
                sched.consecutive_errors += 1
                backoff = min(err_retry_s * sched.consecutive_errors, interval_s)
                logger.error("cycle failed (%dx): %s -> retry in %.0fs (Raster bleibt erhalten)",
                             sched.consecutive_errors, ex, backoff)
                next_run = time.time() + backoff
                continue

            now_e = time.time()

            # --- Nur echt neuere Messungen duerfen den Anker bewegen ---
            # Die Cloud liefert zeitweise eine aeltere Messung aus. Wuerde die
            # als "neu" gelten, ruckelte das Raster rueckwaerts und ein alter
            # Glukosewert erschiene als aktueller.
            is_new = False
            if meas_epoch is not None:
                last = sched.last_meas_epoch
                if last is None or meas_epoch > last:
                    is_new = True
                    sched.consecutive_older = 0
                elif meas_epoch < last:
                    sched.consecutive_older += 1
                    sched.stale_meas_count += 1
                    if sched.consecutive_older >= MAX_CONSECUTIVE_OLDER:
                        # Dauerhafter Rueckwaertssprung (Uhrumstellung, API-Wechsel,
                        # Sensortausch): nicht ewig blockieren, neu verankern.
                        logger.warning("[cloud] seit %d Abfragen nur aeltere Messungen — "
                                       "%s wird neuer Anker",
                                       sched.consecutive_older, hhmmss(meas_epoch))
                        is_new = True
                        sched.consecutive_older = 0
                        publish_state.last_published_meas_epoch = None
                    else:
                        logger.warning("[cloud] aeltere Messung geliefert: %s statt %s "
                                       "(%.0fs rueckwaerts) — ignoriert, Raster bleibt",
                                       hhmmss(meas_epoch), hhmmss(last), last - meas_epoch)
                else:
                    sched.consecutive_older = 0

            # --- Neue Messung: Raster nachführen und Ankunftsmodell lernen ---
            if is_new:
                observed_delay = now_e - meas_epoch
                if adaptive:
                    update_delay_model(sched, observed_delay, args, interval_s)

                if sched.stale:
                    logger.info("[schedule] Cloud liefert wieder — zurück auf Raster (meas=%s)",
                                hhmmss(meas_epoch))
                    sched.stale = False
                    sched.resync_count += 1

                sched.last_meas_epoch = meas_epoch
                sched.last_meas_changed_epoch = now_e
                sched.poll_deadline = None
                sched.consecutive_missed = 0

                next_run = capped(
                    next_grid_run(meas_epoch, interval_s, sched.effective_lag, now_e), now_e
                )
                logger.debug("[schedule] meas=%s ankunft=+%.1fs eff_lag=%.1fs -> next=%s (in %.1fs)",
                             hhmmss(meas_epoch), observed_delay, sched.effective_lag,
                             hhmmss(next_run), next_run - now_e)
                continue

            # --- Keine neue Messung ---
            if sched.last_meas_epoch is None:
                next_run = now_e + interval_s
                logger.debug("[schedule] noch keine gültige Messung -> next=%s", hhmmss(next_run))
                continue

            if sched.stale:
                next_run = now_e + stale_poll_s
                logger.debug("[schedule] stale — nächster Check in %.0fs", stale_poll_s)
                continue

            if sched.poll_deadline is None:
                # Poll-Fenster beginnt JETZT (nicht ab der letzten Messung), damit
                # das volle Fenster fürs Warten auf die Cloud zur Verfügung steht.
                sched.poll_deadline = now_e + poll_max_s

            if now_e < sched.poll_deadline:
                next_run = now_e + poll_s
                logger.debug("[schedule] warte auf neue Messung (Fenster noch %.0fs) -> next=%s",
                             sched.poll_deadline - now_e, hhmmss(next_run))
                continue

            # --- Fenster ausgeschöpft: Messung übersprungen, Raster bleibt erhalten ---
            sched.consecutive_missed += 1
            sched.missed_count += 1
            sched.poll_deadline = None
            next_run = capped(
                next_grid_run(sched.last_meas_epoch, interval_s, sched.effective_lag, now_e), now_e
            )

            if sched.consecutive_missed >= stale_after and not sched.stale:
                sched.stale = True
                logger.warning("[schedule] Cloud liefert seit %d Intervallen nichts Neues — "
                               "Stale-Modus (Check alle %.0fs)",
                               sched.consecutive_missed, stale_poll_s)
            else:
                logger.info("[schedule] Messung übersprungen (%dx) — bleibe auf Raster, next=%s",
                            sched.consecutive_missed, hhmmss(next_run))
    finally:
        if mqtt_pub:
            mqtt_pub.close()


def main():
    parser = build_parser()
    args = parser.parse_args()

    tz = resolve_timezone(args.tz)

    # debug flag compatibility
    if args.debug and (args.log_level or "").upper() == "INFO":
        args.log_level = "DEBUG"

    logger = setup_logger(args.log_level, tz)
    client = create_client(args, logger)
    mqtt_pub = create_mqtt_publisher(args, tz, logger)

    auth = AuthCache()
    health = HealthState(start_epoch=time.time())
    publish_state = PublishState()
    scheduler_state = SchedulerState(last_meas_changed_epoch=time.time())

    if not args.loop:
        run_single_cycle(args, tz, client, mqtt_pub, auth, health, publish_state, logger)
        return

    run_loop(args, tz, client, mqtt_pub, auth, health, publish_state, scheduler_state, logger)


if __name__ == "__main__":
    main()
