#!/bin/sh
set -eu

OPTIONS="/data/options.json"

# --- Required ---
EMAIL="$(jq -r '.email // ""' "$OPTIONS")"
PASSWORD="$(jq -r '.password // ""' "$OPTIONS")"

if [ -z "$EMAIL" ] || [ -z "$PASSWORD" ]; then
  echo "[fatal] Bitte in den Add-on Optionen 'email' und 'password' setzen."
  exit 1
fi

# --- Optional / Defaults ---
INTERVAL="$(jq -r '.interval // 60' "$OPTIONS")"
FETCH_OFFSET="$(jq -r '.fetch_offset // 5.0' "$OPTIONS")"
FETCH_OFFSET_TARGET_LAG="$(jq -r '.fetch_offset_target_lag // 5.0' "$OPTIONS")"
TZ="$(jq -r '.tz // "Europe/Berlin"' "$OPTIONS")"

# Scheduler
ADAPTIVE_LAG="$(jq -r 'if .adaptive_lag == null then true else .adaptive_lag end' "$OPTIONS")"
POLL_SECONDS="$(jq -r '.poll_seconds // 10.0' "$OPTIONS")"
POLL_MAX_SECONDS="$(jq -r '.poll_max_seconds // 120.0' "$OPTIONS")"
STALE_POLL_SECONDS="$(jq -r '.stale_poll_seconds // 30.0' "$OPTIONS")"

MQTT_HOST="$(jq -r '.mqtt_host // "core-mosquitto"' "$OPTIONS")"
MQTT_PORT="$(jq -r '.mqtt_port // 1883' "$OPTIONS")"
MQTT_USER="$(jq -r '.mqtt_user // ""' "$OPTIONS")"
MQTT_PASSWORD="$(jq -r '.mqtt_password // ""' "$OPTIONS")"
MQTT_BASE_TOPIC="$(jq -r '.mqtt_base_topic // "librelinkup"' "$OPTIONS")"
MASTER_ID="$(jq -r '.master_id // "MASTER"' "$OPTIONS")"

PUBLISH_RAW="$(jq -r '.publish_raw // false' "$OPTIONS")"
PUBLISH_FILTERED="$(jq -r 'if .publish_filtered == null then true else .publish_filtered end' "$OPTIONS")"
RETAIN="$(jq -r 'if .mqtt_retain == null then true else .mqtt_retain end' "$OPTIONS")"
QOS="$(jq -r '.mqtt_qos // 0' "$OPTIONS")"
MQTT_PUBLISH_ON_CHANGE="$(jq -r 'if .mqtt_publish_on_change == null then true else .mqtt_publish_on_change end' "$OPTIONS")"
MQTT_FORCE_PUBLISH_SECONDS="$(jq -r '.mqtt_force_publish_seconds // 0' "$OPTIONS")"

# Logging
DEBUG="$(jq -r '.debug // false' "$OPTIONS")"
LOG_LEVEL="$(jq -r '.log_level // "INFO"' "$OPTIONS")"

# Health / Status topics
MQTT_PUBLISH_HEALTH="$(jq -r 'if .mqtt_publish_health == null then true else .mqtt_publish_health end' "$OPTIONS")"
MQTT_HEALTH_RETAIN="$(jq -r 'if .mqtt_health_retain == null then true else .mqtt_health_retain end' "$OPTIONS")"

# Build a real argv list (NO string building, NO eval, NO sh -c)
set -- python3 /main.py \
  --email "$EMAIL" \
  --password "$PASSWORD" \
  --loop \
  --interval "$INTERVAL" \
  --fetch-offset "$FETCH_OFFSET" \
  --fetch-offset-target-lag "$FETCH_OFFSET_TARGET_LAG" \
  --tz "$TZ" \
  --log-level "$LOG_LEVEL" \
  --mqtt-publish \
  --mqtt-host "$MQTT_HOST" \
  --mqtt-port "$MQTT_PORT" \
  --mqtt-base-topic "$MQTT_BASE_TOPIC" \
  --master-id "$MASTER_ID" \
  --mqtt-qos "$QOS" \
  --mqtt-force-publish-seconds "$MQTT_FORCE_PUBLISH_SECONDS" \
  --poll-seconds "$POLL_SECONDS" \
  --poll-max-seconds "$POLL_MAX_SECONDS" \
  --stale-poll-seconds "$STALE_POLL_SECONDS"

# Optional flags
[ "$DEBUG" = "true" ] && set -- "$@" --debug
[ "$ADAPTIVE_LAG" = "false" ] && set -- "$@" --no-adaptive-lag
[ "$RETAIN" = "true" ] && set -- "$@" --mqtt-retain
[ "$PUBLISH_RAW" = "true" ] && set -- "$@" --mqtt-publish-raw
[ "$PUBLISH_FILTERED" = "true" ] && set -- "$@" --mqtt-publish-filtered
[ "$MQTT_PUBLISH_ON_CHANGE" = "true" ] && set -- "$@" --mqtt-publish-on-change

# Health flags
[ "$MQTT_PUBLISH_HEALTH" = "true" ] && set -- "$@" --mqtt-publish-health
[ "$MQTT_HEALTH_RETAIN" = "true" ] && set -- "$@" --mqtt-health-retain

# Optional MQTT credentials
[ -n "$MQTT_USER" ] && set -- "$@" --mqtt-user "$MQTT_USER"
[ -n "$MQTT_PASSWORD" ] && set -- "$@" --mqtt-password "$MQTT_PASSWORD"

echo "[info] Starting LibreLinkUp MQTT add-on"
echo "[info] mqtt=$MQTT_HOST:$MQTT_PORT base_topic=$MQTT_BASE_TOPIC master_id=$MASTER_ID"
echo "[info] publish_raw=$PUBLISH_RAW publish_filtered=$PUBLISH_FILTERED retain=$RETAIN qos=$QOS"
echo "[info] mqtt_publish_on_change=$MQTT_PUBLISH_ON_CHANGE mqtt_force_publish_seconds=$MQTT_FORCE_PUBLISH_SECONDS"
echo "[info] publish_health=$MQTT_PUBLISH_HEALTH health_retain=$MQTT_HEALTH_RETAIN"
echo "[info] log_level=$LOG_LEVEL debug=$DEBUG interval=${INTERVAL}s offset=${FETCH_OFFSET}s target_lag=${FETCH_OFFSET_TARGET_LAG}s tz=$TZ"
echo "[info] adaptive_lag=$ADAPTIVE_LAG poll=${POLL_SECONDS}s poll_max=${POLL_MAX_SECONDS}s stale_poll=${STALE_POLL_SECONDS}s"

exec "$@"
