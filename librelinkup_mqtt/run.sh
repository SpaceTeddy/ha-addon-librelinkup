#!/bin/sh
set -eu

OPTIONS="/data/options.json"

EMAIL="$(jq -r '.email // ""' "$OPTIONS")"
PASSWORD="$(jq -r '.password // ""' "$OPTIONS")"

if [ -z "$EMAIL" ] || [ -z "$PASSWORD" ]; then
  echo "[fatal] Bitte in den Add-on Optionen 'email' und 'password' setzen."
  exit 1
fi

INTERVAL="$(jq -r '.interval // 60' "$OPTIONS")"
FETCH_OFFSET="$(jq -r '.fetch_offset // 5.0' "$OPTIONS")"
TZ="$(jq -r '.tz // "Europe/Berlin"' "$OPTIONS")"

MQTT_HOST="$(jq -r '.mqtt_host // "core-mosquitto"' "$OPTIONS")"
MQTT_PORT="$(jq -r '.mqtt_port // 1883' "$OPTIONS")"
MQTT_USER="$(jq -r '.mqtt_user // ""' "$OPTIONS")"
MQTT_PASSWORD="$(jq -r '.mqtt_password // ""' "$OPTIONS")"
MQTT_BASE_TOPIC="$(jq -r '.mqtt_base_topic // "librelinkup"' "$OPTIONS")"
MASTER_ID="$(jq -r '.master_id // "MASTER"' "$OPTIONS")"

PUBLISH_RAW="$(jq -r '.publish_raw // false' "$OPTIONS")"
PUBLISH_FILTERED="$(jq -r '.publish_filtered // true' "$OPTIONS")"
RETAIN="$(jq -r '.mqtt_retain // true' "$OPTIONS")"
QOS="$(jq -r '.mqtt_qos // 0' "$OPTIONS")"
DEBUG="$(jq -r '.debug // false' "$OPTIONS")"

ARGS="--email \"$EMAIL\" --password \"$PASSWORD\" --loop --interval $INTERVAL --fetch-offset $FETCH_OFFSET --tz \"$TZ\""

[ "$DEBUG" = "true" ] && ARGS="$ARGS --debug"

ARGS="$ARGS --mqtt-publish --mqtt-host \"$MQTT_HOST\" --mqtt-port $MQTT_PORT"
ARGS="$ARGS --mqtt-base-topic \"$MQTT_BASE_TOPIC\" --master-id \"$MASTER_ID\" --mqtt-qos $QOS"

[ -n "$MQTT_USER" ] && ARGS="$ARGS --mqtt-user \"$MQTT_USER\""
[ -n "$MQTT_PASSWORD" ] && ARGS="$ARGS --mqtt-password \"$MQTT_PASSWORD\""
[ "$RETAIN" = "true" ] && ARGS="$ARGS --mqtt-retain"
[ "$PUBLISH_RAW" = "true" ] && ARGS="$ARGS --mqtt-publish-raw"
[ "$PUBLISH_FILTERED" = "true" ] && ARGS="$ARGS --mqtt-publish-filtered"

echo "[info] Starting LibreLinkUp MQTT add-on"
exec sh -c "python3 /main.py $ARGS"