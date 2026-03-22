#!/bin/sh
set -e

mkdir -p /data/config

[ -f /data/config.json ] || cp /app/data/config.runtime.default.json /data/config.json
[ -f /data/config/config.json ] || cp /app/data/config/config.default.json /data/config/config.json
[ -f /data/config/secrets.json ] || cp /app/data/config/secrets.default.json /data/config/secrets.json

exec uvicorn backend.app:app --host 0.0.0.0 --port 8081
