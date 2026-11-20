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

if [ "${BOLT12_PAY_INITIAL_PASSWORD+x}" = x ]; then
  python - <<'PYTHON'
import os

from backend.config import initialize_ui_password

legacy_password = os.getenv("PAY_UI_PASSWORD", "").strip()
initialize_ui_password(legacy_password or os.environ["BOLT12_PAY_INITIAL_PASSWORD"])
PYTHON
  unset BOLT12_PAY_INITIAL_PASSWORD
fi

exec uvicorn backend.app:app --host 0.0.0.0 --port 8081
