#!/bin/sh
set -eu

# Home Assistant Add-on Options liegen in /data/options.json
OPTIONS="/data/options.json"

# Minimaler JSON-Getter ohne jq (HA Add-ons haben oft kein jq)
# Erwartet einfache String/Number/Boolean Felder auf Top-Level.
json_get() {
  key="$1"
  default="${2:-}"
  if [ ! -f "$OPTIONS" ]; then
    echo "$default"
    return
  fi

  # String
  val="$(python3 - <<PY
import json,sys
p="$OPTIONS"
k="$key"
d="$default"
try:
    o=json.load(open(p,'r',encoding='utf-8'))
    v=o.get(k, d)
    if isinstance(v, bool):
        print("true" if v else "false")
    else:
        print(v)
except Exception:
    print(d)
PY
)"
  echo "$val"
}

EMAIL="$(json_get email "")"
PASSWORD="$(json_get password "")"

MQTT_HOST="$(json_get mqtt_host "core-mosquitto")"
MQTT_PORT="$(json_get mqtt_port "1883")"
MQTT_USER="$(json_get mqtt_user "")"
MQTT_PASSWORD="$(json_get mqtt_password "")"

MQTT_BASE_TOPIC="$(json_get mqtt_base_topic "librelinkup")"
MASTER_ID="$(json_get master_id "MASTER")"

# Topic-Suffixe (du hattest da Anpassungen)
TOPIC_RAW_SUFFIX="$(json_get mqtt_topic_raw_suffix "data_raw")"
TOPIC_FILTERED_SUFFIX="$(json_get mqtt_topic_filtered_suffix "data")"

PUBLISH_RAW="$(json_get publish_raw "false")"
PUBLISH_FILTERED="$(json_get publish_filtered "true")"

RETAIN="$(json_get mqtt_retain "true")"
QOS="$(json_get mqtt_qos "0")"

INTERVAL="$(json_get interval "60")"
FETCH_OFFSET="$(json_get fetch_offset "5.0")"
TZ="$(json_get tz "Europe/Berlin")"

DEBUG="$(json_get debug "false")"
PRINT_RAW="$(json_get print_raw "false")"
PRINT_FILTERED="$(json_get print_filtered "false")"

# Pflichtwerte prüfen
if [ -z "$EMAIL" ] || [ -z "$PASSWORD" ]; then
  echo "[fatal] Bitte in den Add-on Optionen 'email' und 'password' setzen." >&2
  exit 1
fi

# CLI args bauen
ARGS="--email \"$EMAIL\" --password \"$PASSWORD\" --loop --interval $INTERVAL --fetch-offset $FETCH_OFFSET --tz \"$TZ\""

if [ "$DEBUG" = "true" ]; then
  ARGS="$ARGS --debug"
fi
if [ "$PRINT_RAW" = "true" ]; then
  ARGS="$ARGS --print-raw"
fi
if [ "$PRINT_FILTERED" = "true" ]; then
  ARGS="$ARGS --print-filtered"
fi

# MQTT aktivieren
ARGS="$ARGS --mqtt-publish --mqtt-host \"$MQTT_HOST\" --mqtt-port $MQTT_PORT --mqtt-base-topic \"$MQTT_BASE_TOPIC\" --master-id \"$MASTER_ID\" --mqtt-qos $QOS"

if [ -n "$MQTT_USER" ]; then
  ARGS="$ARGS --mqtt-user \"$MQTT_USER\""
fi
if [ -n "$MQTT_PASSWORD" ]; then
  ARGS="$ARGS --mqtt-password \"$MQTT_PASSWORD\""
fi

# retain
if [ "$RETAIN" = "true" ]; then
  ARGS="$ARGS --mqtt-retain"
fi

# Topic-Suffixe
ARGS="$ARGS --mqtt-topic-raw-suffix \"$TOPIC_RAW_SUFFIX\" --mqtt-topic-filtered-suffix \"$TOPIC_FILTERED_SUFFIX\""

# Raw/Filtered publish toggles
if [ "$PUBLISH_RAW" = "true" ]; then
  ARGS="$ARGS --mqtt-publish-raw"
fi
if [ "$PUBLISH_FILTERED" = "true" ]; then
  ARGS="$ARGS --mqtt-publish-filtered"
fi

echo "[info] Starting LibreLinkUp MQTT add-on..."
echo "[info] mqtt=${MQTT_HOST}:${MQTT_PORT} base_topic=${MQTT_BASE_TOPIC} master_id=${MASTER_ID} interval=${INTERVAL}s offset=${FETCH_OFFSET}s tz=${TZ}"
echo "[info] publish_raw=${PUBLISH_RAW} publish_filtered=${PUBLISH_FILTERED} retain=${RETAIN} qos=${QOS}"

# shellcheck disable=SC2086
exec sh -c "python3 /app/main.py $ARGS"