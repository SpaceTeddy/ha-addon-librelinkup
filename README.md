# LibreLinkUp MQTT – Home Assistant Add-on & CLI

This project provides a **Home Assistant add-on** and a **CLI tool (`main.py`)** to fetch data from the **LibreLinkUp / LibreView cloud** and publish it via **MQTT**.

The focus is on:
- Stable token/session reuse
- Time-aligned fetching (offset + sync)
- Clear logging with **timestamps & log levels**
- Compatibility with existing **ESP32-based setups**

---

## Features

- ⏱️ Fetch interval every **60 seconds** (configurable)
- 🕒 **Fetch offset** (e.g. 5 seconds after app upload)
- 🔁 **Token reuse** (login only when required)
- 📡 **Persistent MQTT connection**
- 📦 Two data formats:
  - **Filtered JSON** (ESP32-compatible, recommended)
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
| `interval` | Fetch interval in seconds |
| `fetch_offset` | Offset in seconds after app upload |
| `tz` | Timezone for timestamp comparison |

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

### Publish
| Option | Description |
|------|-------------|
| `publish_filtered` | ESP32-compatible JSON (recommended) |
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
| `librelinkup/MASTER/data` | Filtered JSON (ESP32 format) |
| `librelinkup/MASTER/data_raw` | Raw API JSON (optional) |

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

Future improvements (LWT, health topics, HA MQTT discovery) are possible but optional.
