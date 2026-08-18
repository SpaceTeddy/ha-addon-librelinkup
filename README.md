# LibreLinkUp MQTT – Home Assistant Add-on & CLI

This project provides a **Home Assistant add-on** and a **CLI tool (`main.py`)** to fetch data from the **LibreLinkUp / LibreView cloud** and publish it via **MQTT**.

The focus is on:
- Stable token/session reuse
- Time-aligned fetching (offset + sync)
- Clear logging with **timestamps & log levels**

---

## Features

- ⏱️ Fetch interval every **60 seconds** (configurable)
- 🕒 **Fetch offset** (e.g. 5 seconds after app upload)
- 🔁 **Token reuse** (login only when required)
- 📡 **Persistent MQTT connection**
- 📦 Two data formats:
  - **Filtered JSON**
  - **Raw JSON** (full API response, optional)
- 🧾 **Timestamped logging with log levels**
- 🧪 CLI and add-on share the **same code base**

---

## Installation (Home Assistant Add-on)

### Add the repository
1. Home Assistant → **Settings**
2. **Add-ons** → **Add-on Store**
3. Top right (⋮) → **Repositories**
4. Add repository:
   ```
   https://github.com/SpaceTeddy/ha-addon-librelinkup
   ```

### Install the add-on
- Select **LibreLinkUp MQTT**
- Install
- Configure (see below)
- Start

> ℹ️ The add-on uses a prebuilt GHCR image  
> (`ghcr.io/spaceteddy/ha-addon-librelinkup`, lowercase)

---

## Configuration (Home Assistant)

### Example configuration

```yaml
email: "user@example.com"
password: "myPassword#withSpecialChars"

interval: 60
fetch_offset: 5.0
fetch_offset_target_lag: 5.0
tz: "Europe/Berlin"

mqtt_host: "core-mosquitto"
mqtt_port: 1883
mqtt_user: "mqtt"
mqtt_password: "mqttpass"
mqtt_base_topic: "librelinkup"
master_id: "MASTER"

publish_raw: false
publish_filtered: true
mqtt_retain: true
mqtt_qos: 0
mqtt_publish_on_change: true
mqtt_force_publish_seconds: 0

log_level: INFO
debug: false
```

### Important notes
- **Passwords containing special characters (`#`, `$`, `!`, etc.) are fully supported**
- No YAML quoting tricks required
- `publish_raw` can produce very large MQTT messages → usually **keep disabled**

---

## Configuration options explained

### General
| Option | Description |
|------|-------------|
| `email` | LibreLinkUp login email |
| `password` | LibreLinkUp password |
| `interval` | Expected sensor cadence in seconds (default 60) |
| `fetch_offset` | Delay in seconds before the first fetch after start |
| `fetch_offset_target_lag` | Minimum lag after a measurement before fetching |
| `tz` | Timezone for timestamp comparison |

### Scheduler
| Option | Description |
|------|-------------|
| `adaptive_lag` | Learn how long the cloud takes to publish a measurement and wake up just before it arrives (recommended, default `true`) |
| `poll_seconds` | Poll interval while waiting for a new measurement (default `10`) |
| `poll_max_seconds` | How long to wait for a measurement before skipping it (default `120`) |
| `stale_poll_seconds` | Check interval while the cloud is stale, e.g. the phone is offline (default `30`) |

### MQTT
| Option | Description |
|------|-------------|
| `mqtt_host` | MQTT broker host |
| `mqtt_port` | MQTT broker port |
| `mqtt_user` | MQTT username (optional) |
| `mqtt_password` | MQTT password (optional) |
| `mqtt_base_topic` | Base MQTT topic |
| `master_id` | Instance / device identifier |
| `mqtt_retain` | MQTT retain flag |
| `mqtt_qos` | QoS level (0–2) |
| `mqtt_publish_on_change` | Publish only on new `FactoryTimestamp` (reduces duplicate messages) |
| `mqtt_force_publish_seconds` | Force republish after N seconds even if unchanged (`0` = disabled) |

### Publish
| Option | Description |
|------|-------------|
| `publish_filtered` | Reduced JSON for Home Assistant / ESP32 (default) |
| `publish_raw` | Full API JSON (debug / analysis) |

### Logging
| Option | Description |
|------|-------------|
| `log_level` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `debug` | Legacy flag (internally sets DEBUG) |

All logs include **timestamps with millisecond precision**.

---

## MQTT Topics

Base:
```
<mqtt_base_topic>/<master_id>/
```

Example (`mqtt_base_topic=librelinkup`, `master_id=MASTER`):

| Topic | Payload |
|------|---------|
| `librelinkup/MASTER/data` | Filtered JSON |
| `librelinkup/MASTER/data_raw` | Raw API JSON (optional) |
| `librelinkup/MASTER/health` | Health / diagnostics JSON |
| `librelinkup/MASTER/status` | `online` / `offline` (retained, with LWT) |

---

## How the scheduler stays in sync

A Libre sensor produces a reading every 60 seconds, but the LibreLinkUp cloud
only shows it once the master's phone has uploaded it. That upload delay is
variable — often 10 seconds, sometimes over a minute.

The scheduler therefore works on the **sensor's measurement grid**:

```
next fetch = last_measurement + k × interval + lag        (k ≥ 1)
```

Because every fetch time is derived from the last measurement's
`FactoryTimestamp`, the phase relationship to the sensor is never lost — not
after a failed request, not after a skipped measurement, and not after the
cloud has been stale for an hour.

**Adaptive lag** (`adaptive_lag: true`): the add-on measures how long the cloud
actually takes and wakes up shortly before the expected arrival, instead of
waking early and polling repeatedly. On a cloud that consistently delivers at
measurement + 45 s, it settles on waking at measurement + 35 s and catches the
value on the first or second try.

**When a measurement does not arrive**, it is polled every `poll_seconds` for
up to `poll_max_seconds`. After that the measurement is skipped — but the grid
is kept, so the next one is still expected at the right time. Two consecutive
skips switch to stale mode (`stale_poll_seconds`), which keeps log noise and
API load low while the phone is offline.

**Request errors** never touch the grid. They are retried with a linearly
growing backoff, capped at one `interval`.

### Relevant log lines

| Message | Meaning |
|------|---------|
| `Messung übersprungen (Nx) — bleibe auf Raster` | Cloud was late; grid intact |
| `Cloud liefert seit N Intervallen nichts Neues — Stale-Modus` | Phone likely offline |
| `Cloud liefert wieder — zurück auf Raster` | Recovered |
| `cycle failed (Nx): … retry in Xs (Raster bleibt erhalten)` | Request error, grid intact |
| `meas_epoch liegt Xs in der Zukunft` | `FactoryTimestamp` is not UTC — needs investigation |

### Health fields (`.../health`)

The `sched` block reports what the scheduler is doing:

| Field | Meaning |
|------|---------|
| `effective_lag_s` | Current wake-up offset after a measurement |
| `delay_ema_s` | Learned mean cloud delay |
| `delay_dev_s` | Learned variation of that delay |
| `stale` | Currently in stale mode |
| `consecutive_missed` | Consecutive skipped measurements |
| `missed_total` / `resync_count` | Totals since start |
| `consecutive_errors` | Consecutive failed requests |

---

## CLI usage (outside Home Assistant)

The add-on internally runs **`main.py`**, which can also be used standalone.

### Single fetch
```bash
python3 main.py \
  --email "user@example.com" \
  --password "myPassword#withSpecialChars" \
  --print-filtered
```

### Loop mode with MQTT
```bash
python3 main.py \
  --email "user@example.com" \
  --password "myPassword#withSpecialChars" \
  --loop \
  --interval 60 \
  --fetch-offset 5 \
  --tz "Europe/Berlin" \
  --mqtt-publish \
  --mqtt-host 192.168.0.x \
  --mqtt-port 1883 \
  --mqtt-user mqtt \
  --mqtt-password mqttpass \
  --mqtt-base-topic librelinkup \
  --master-id MASTER \
  --log-level DEBUG
```

---

## Logging & Debugging

Example log output:
```
2026-01-10 13:22:05.104 [INFO] === LOGIN (new/refresh) ===
2026-01-10 13:22:05.412 [DEBUG] user_id : ...
2026-01-10 13:22:06.031 [INFO] [mqtt] connect core-mosquitto:1883
```

Recommended:
- Normal operation: `log_level: INFO`
- Troubleshooting: `log_level: DEBUG`

---

## Troubleshooting

### Login fails (`status=2`)
- Verify credentials
- Test CLI with `--log-level DEBUG`
- Account may be locked or require ToU acceptance

### No MQTT data
- Broker reachable?
- Credentials correct?
- `publish_filtered` enabled?
- Enable `log_level: DEBUG` for diagnostics

---

## Disclaimer

This project is **unofficial** and not affiliated with Abbott.  
The LibreLinkUp / LibreView API may change at any time.

Use at your own risk.

---

## Status

✅ Add-on stable  
✅ CLI stable  
✅ Safe handling of special characters  
✅ Timestamped logging  

LWT and health topics are implemented. HA MQTT discovery is still open.
