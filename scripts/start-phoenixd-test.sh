#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -z "${PHOENIX_TEST_UI_PASSWORD:-}" ]]; then
  read -rsp 'Admin password for the isolated Phoenixd test UI: ' PHOENIX_TEST_UI_PASSWORD
  printf '\n'
fi
if [[ -z "$PHOENIX_TEST_UI_PASSWORD" ]]; then
  printf 'A non-empty admin password is required.\n' >&2
  exit 1
fi
export PHOENIX_TEST_UI_PASSWORD
docker compose -f deploy/docker-compose.phoenixd-test.yml up --build -d
printf 'Phoenixd test UI: http://phoenixd.localhost:8092/app?setup=1\n'
