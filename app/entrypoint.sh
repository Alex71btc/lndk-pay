#!/usr/bin/env sh
set -eu

APP_DATA_DIR="${APP_DATA_DIR:-/data}"
DEFAULTS_DIR="/app/defaults"

mkdir -p "${APP_DATA_DIR}"
mkdir -p "${APP_DATA_DIR}/config"

copy_if_missing() {
  src="$1"
  dst="$2"

  if [ -f "$src" ] && [ ! -f "$dst" ]; then
    cp "$src" "$dst"
    echo "Initialized $(basename "$dst") from defaults"
  fi
}

# Main runtime config
copy_if_missing "${DEFAULTS_DIR}/config.default.json" "${APP_DATA_DIR}/config.json"
copy_if_missing "${DEFAULTS_DIR}/config.runtime.default.json" "${APP_DATA_DIR}/config.runtime.default.json"

# Nested config defaults
copy_if_missing "${DEFAULTS_DIR}/config/secrets.default.json" "${APP_DATA_DIR}/config/secrets.default.json"

exec uvicorn backend.app:app --host 0.0.0.0 --port 8081
