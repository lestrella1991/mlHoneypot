#!/bin/sh
set -e

echo "[kibana-init] Esperando Kibana..."

until curl -fsS http://kibana:5601/api/status >/dev/null; do
    sleep 3
done

echo "[kibana-init] Kibana disponible"

create_index_pattern() {
    TITLE="$1"
    ID="$3"

    echo "[kibana-init] Creando $NAME..."

    curl -fsS -X POST \
      "http://kibana:5601/api/index_patterns/index_pattern" \
      -H "kbn-xsrf: true" \
      -H "Content-Type: application/json" \
      -d "{
        \"index_pattern\": {
          \"id\": \"$ID\",
          \"title\": \"$TITLE\",
          \"timeFieldName\": \"@timestamp\"
        },
        \"override\": true
      }"
}

create_index_pattern \
  "honeypot-sites-*" \
  "honeypot-sites"

echo "[kibana-init] Index patterns creados"

curl -f \
  -X POST \
  "http://kibana:5601/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" \
  --form file=@/dashboard.ndjson

echo "[kibana-init] Dashboard creado"