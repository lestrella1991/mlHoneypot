#!/bin/bash
set -e

/etc/init.d/nordvpn start

sleep 5

if [ -z "$NORDVPN_TOKEN" ]; then
    echo "[nordvpn] NORDVPN_TOKEN no configurado"
    exit 1
fi

echo "[nordvpn] Deshabilitando analytics..."

nordvpn set analytics off || true

echo "[nordvpn] Autenticando..."

nordvpn login --token "$NORDVPN_TOKEN" 

echo "[nordvpn] Configurando NordLynx..."

nordvpn set technology nordlynx

echo "[nordvpn] Conectando..."

if [ -n "$NORDVPN_COUNTRY" ]; then
    nordvpn connect "$NORDVPN_COUNTRY"
else
    nordvpn connect
fi

echo "[nordvpn] Estado:"
nordvpn status

echo "[nordvpn] Exit IP:"
curl -fsS https://api.ipify.org
echo

# Mantiene vivo el contenedor.
tail -f /dev/null