#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
override_file=$(mktemp /tmp/bolt12-dual-backend.XXXXXX.json)
trap 'rm -f "$override_file"' EXIT
python3 scripts/prepare-dual-backend-test.py "${1:-bolt12-pay}" --full > "$override_file"
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
# Start only the existing LNDK sidecar, not the old web application.
source_project=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "${1:-bolt12-pay}")
if [[ -z "$source_project" || "$source_project" == '<no value>' ]]; then
  printf 'Cannot identify the source Compose project.\n' >&2
  exit 1
fi
mapfile -t lndk_ids < <(docker ps -aq --filter "label=com.docker.compose.project=$source_project" --filter 'label=com.docker.compose.service=lndk')
if [[ "${#lndk_ids[@]}" != 1 ]]; then
  printf 'Expected one existing LNDK sidecar in source project %s; found %s.\n' "$source_project" "${#lndk_ids[@]}" >&2
  exit 1
fi
docker start "${lndk_ids[0]}" >/dev/null
docker compose -f deploy/docker-compose.phoenixd-test.yml -f "$override_file" up --build -d pay
printf 'Full LND + LNDK / Phoenixd test: http://phoenixd.localhost:8092/app?setup=1\n'
printf 'Existing Phoenixd settings and test history are retained. Source container unchanged.\n'
