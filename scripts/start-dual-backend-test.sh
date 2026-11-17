#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
override_file=$(mktemp /tmp/bolt12-dual-backend.XXXXXX.json)
trap 'rm -f "$override_file"' EXIT
python3 scripts/prepare-dual-backend-test.py "${1:-bolt12-pay}" > "$override_file"
if [[ -z "${PHOENIX_TEST_UI_PASSWORD:-}" ]]; then
  read -rsp 'Admin password for the existing isolated test UI: ' PHOENIX_TEST_UI_PASSWORD
  printf '\n'
fi
if [[ -z "$PHOENIX_TEST_UI_PASSWORD" ]]; then
  printf 'A non-empty admin password is required.\n' >&2
  exit 1
fi
export PHOENIX_TEST_UI_PASSWORD
docker compose -f deploy/docker-compose.phoenixd-test.yml -f "$override_file" config --quiet
docker compose -f deploy/docker-compose.phoenixd-test.yml -f "$override_file" up --build -d pay
printf 'Dual BOLT11 test: http://phoenixd.localhost:8092/app?setup=1\n'
printf 'Existing Phoenixd settings and test history are retained. Source container unchanged.\n'
