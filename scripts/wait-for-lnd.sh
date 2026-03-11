#!/bin/sh
set -eu

LND_HOST="${LND_HOST:-192.168.188.39}"
LND_PORT="${LND_PORT:-10009}"

echo "[wait-for-lnd] checking secrets..."
until [ -f /secrets/tls.cert ] && [ -f /secrets/admin.macaroon ]; do
  echo "[wait-for-lnd] secrets not ready yet..."
  sleep 5
done

echo "[wait-for-lnd] secrets found."

echo "[wait-for-lnd] waiting for LND gRPC at ${LND_HOST}:${LND_PORT} ..."
until nc -z "$LND_HOST" "$LND_PORT"; do
  echo "[wait-for-lnd] LND not reachable yet..."
  sleep 5
done

echo "[wait-for-lnd] LND is reachable. Starting lndk..."
exec "$@"
