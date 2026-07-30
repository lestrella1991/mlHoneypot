#!/usr/bin/env bash
set -Eeuo pipefail

: "${TARGET_DOMAIN:?TARGET_DOMAIN es obligatorio}"
: "${RECON_OUTPUT:=/work/recon/active-sites.txt}"
: "${SITES_DIR:=/work/sites}"
: "${GENERATED_OUTPUT:=/work/generated}"
: "${MAX_DEPTH:=4}"

mkdir -p "$(dirname "$RECON_OUTPUT")" "$SITES_DIR" "$GENERATED_OUTPUT"

tmp_assets="$(mktemp)"
tmp_hosts="$(mktemp)"
trap 'rm -f "$tmp_assets" "$tmp_hosts"' EXIT

assetfinder --subs-only "$TARGET_DOMAIN" | sed '/^[[:space:]]*$/d' | sort -u > "$tmp_assets"
printf '%s\n' "$TARGET_DOMAIN" >> "$tmp_assets"
sort -u "$tmp_assets" -o "$tmp_assets"

cat "$tmp_assets" | httprobe | sed '/^[[:space:]]*$/d' | sort -u > "$tmp_hosts"

count="$(wc -l < "$tmp_hosts" | tr -d ' ')"
if [ "$count" -eq 0 ]; then
  echo "No se encontraron sitios HTTP/HTTPS activos" >&2
  exit 20
fi

cp "$tmp_hosts" "$RECON_OUTPUT"

rm -rf "${SITES_DIR:?}/"*
rm -rf "${GENERATED_OUTPUT}/"*

python /app/honeypot_cloner.py \
  --recon-file "$RECON_OUTPUT" \
  --output "$SITES_DIR" \
  --mode isolated \
  --max-depth "$MAX_DEPTH"

python /app/generate_nginx.py \
  --recon-summary "$SITES_DIR/recon_summary.json" \
  --sites-root "$SITES_DIR" \
  --output "$GENERATED_OUTPUT" \
  --listen-port 8080

test -f "$GENERATED_OUTPUT/nginx.conf" || {
  echo "[recon] nginx.conf no fue generado" >&2
  exit 21
}


