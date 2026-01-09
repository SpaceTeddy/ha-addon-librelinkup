#!/usr/bin/with-contenv sh
set -eu

CONFIG_PATH="/data/options.json"

get() {
  python3 -c "import json; print(json.load(open('$CONFIG_PATH')).get('$1',''))"
}

EMAIL="$(get email)"
PASSWORD="$(get password)"

if [ -z "$EMAIL" ] || [ -z "$PASSWORD" ]; then
  echo "[fatal] email/password not set in add-on configuration"
  exit 1
fi

INTERVAL="$(get interval)"

DEBUG="$(get debug)"
API_BASE="$(get api_base)"
TIMEOUT="$(get timeout)"
CONNECTION_CLOSE="$(get connection_close)"
VERIFY_TLS="$(get verify_tls)"
GRAPH_LIMIT="$(get graph_limit)"

FETCH_OFFSET="$(get fetch_offset)"
FETCH_TARGET_LAG="$(get fetch_offset_target_lag)"
FETCH_MIN="$(get fetch_offset_min)"
FETCH_MAX="$(get fetch_offset_max)"
FETCH_GAIN="$(get fetch_offset_gain)"
FETCH_MAX_STEP="$(get fetch_offset_max_step)"
TZ="$(get tz)"

MQTT_PUBLISH="$(get mqtt_publish)"
MQTT_HOST="$(get mqtt_host)"
MQTT_PORT="$(get mqtt_port)"
MQTT_USER="$(get mqtt_user)"
MQTT_PASSWORD="$(get mqtt_password)"
MQTT_BASE_TOPIC="$(get mqtt_base_topic)"
MASTER_ID="$(get master_id)"
MQTT_RAW_SUFFIX="$(get mqtt_topic_raw_suffix)"
MQTT_FILTERED_SUFFIX="$(get mqtt_topic_filtered_suffix)"
MQTT_PUB_RAW="$(get mqtt_publish_raw)"
MQTT_PUB_FILTERED="$(get mqtt_publish_filtered)"
MQTT_RETAIN="$(get mqtt_retain)"
MQTT_QOS="$(get mqtt_qos)"

ARGS="--email $EMAIL --password $PASSWORD --loop --interval $INTERVAL"
ARGS="$ARGS --api-base $API_BASE --timeout $TIMEOUT --tz $TZ"
ARGS="$ARGS --fetch-offset $FETCH_OFFSET --fetch-offset-target-lag $FETCH_TARGET_LAG"
ARGS="$ARGS --fetch-offset-min $FETCH_MIN --fetch-offset-max $FETCH_MAX"
ARGS="$ARGS --fetch-offset-gain $FETCH_GAIN --fetch-offset-max-step $FETCH_MAX_STEP"
ARGS="$ARGS --graph-limit $GRAPH_LIMIT"

if [ "$DEBUG" = "True" ] || [ "$DEBUG" = "true" ]; then
  ARGS="$ARGS --debug"
fi

if [ "$CONNECTION_CLOSE" = "True" ] || [ "$CONNECTION_CLOSE" = "true" ]; then
  ARGS="$ARGS --connection-close"
fi

if [ "$VERIFY_TLS" = "False" ] || [ "$VERIFY_TLS" = "false" ]; then
  ARGS="$ARGS --no-verify-tls"
fi

if [ "$MQTT_PUBLISH" = "True" ] || [ "$MQTT_PUBLISH" = "true" ]; then
  ARGS="$ARGS --mqtt-publish --mqtt-host $MQTT_HOST --mqtt-port $MQTT_PORT"
  ARGS="$ARGS --mqtt-user $MQTT_USER --mqtt-password $MQTT_PASSWORD"
  ARGS="$ARGS --mqtt-base-topic $MQTT_BASE_TOPIC --master-id $MASTER_ID"
  ARGS="$ARGS --mqtt-topic-raw-suffix $MQTT_RAW_SUFFIX --mqtt-topic-filtered-suffix $MQTT_FILTERED_SUFFIX"
  ARGS="$ARGS --mqtt-qos $MQTT_QOS"
  if [ "$MQTT_RETAIN" = "True" ] || [ "$MQTT_RETAIN" = "true" ]; then
    ARGS="$ARGS --mqtt-retain"
  fi
  if [ "$MQTT_PUB_RAW" = "True" ] || [ "$MQTT_PUB_RAW" = "true" ]; then
    ARGS="$ARGS --mqtt-publish-raw"
  fi
  if [ "$MQTT_PUB_FILTERED" = "True" ] || [ "$MQTT_PUB_FILTERED" = "true" ]; then
    ARGS="$ARGS --mqtt-publish-filtered"
  fi
fi

echo "[info] starting LibreLinkUp service"
exec python3 /app/main.py $ARGS