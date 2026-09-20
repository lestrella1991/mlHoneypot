#!/bin/sh

set -e

echo "[elasticsearch-init] Esperando Elasticsearch..."

until curl -fsS http://elasticsearch:9200 >/dev/null; do
    sleep 3
done

echo "[elasticsearch-init] Instalando templates..."

curl -fsS -X  PUT \
  http://elasticsearch:9200/_index_template/honeypot-nginx \
  -H 'Content-Type: application/json' \
  --data-binary "@/templates/honeypot-nginx.json"

echo "[+] honeypot-nginx"

curl -fsS -X  PUT \
  http://elasticsearch:9200/_index_template/honeypot-detections \
  -H 'Content-Type: application/json' \
  --data-binary "@/templates/honeypot-detections.json"

echo "[+] honeypot-detections"

curl -fsS -X  PUT \
  http://elasticsearch:9200/_index_template/honeypot-network \
  -H 'Content-Type: application/json' \
  --data-binary "@/templates/honeypot-network.json"

echo "[+] honeypot-network"

curl -fsS -X  PUT \
  http://elasticsearch:9200/_index_template/honeypot-sites \
  -H 'Content-Type: application/json' \
  --data-binary "@/templates/honeypot-sites.json"

echo "[+] honeypot-sites"

echo "[elasticsearch-init] Templates instalados"