#!/usr/bin/with-contenv sh
set -e

EMAIL="$(jq -r '.email' /data/options.json)"
PASSWORD="$(jq -r '.password' /data/options.json)"
MQTT_HOST="$(jq -r '.mqtt_host' /data/options.json)"
MQTT_PORT="$(jq -r '.mqtt_port' /data/options.json)"
MQTT_USER="$(jq -r '.mqtt_user // ""' /data/options.json)"
MQTT_PASSWORD="$(jq -r '.mqtt_password // ""' /data/options.json)"
BASE_TOPIC="$(jq -r '.mqtt_base_topic' /data/options.json)"
MASTER_ID="$(jq -r '.master_id' /data/options.json)"
INTERVAL="$(jq -r '.interval' /data/options.json)"
FETCH_OFFSET="$(jq -r '.fetch_offset' /data/options.json)"

exec python3 /app/main.py \
  --email "$EMAIL" \
  --password "$PASSWORD" \
  --loop \
  --interval "$INTERVAL" \
  --fetch-offset "$FETCH_OFFSET" \
  --mqtt-publish \
  --mqtt-host "$MQTT_HOST" --mqtt-port "$MQTT_PORT" \
  --mqtt-user "$MQTT_USER" --mqtt-password "$MQTT_PASSWORD" \
  --mqtt-base-topic "$BASE_TOPIC" --master-id "$MASTER_ID" \
  --mqtt-retain