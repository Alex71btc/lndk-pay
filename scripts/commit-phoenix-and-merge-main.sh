#!/usr/bin/env bash
# Run manually on the host: this Work session cannot write Git metadata.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

commit_only=false
if [[ "$#" -eq 1 && "$1" == "--commit-only" ]]; then
  commit_only=true
elif [[ "$#" -ne 0 ]]; then
  echo 'Aufruf: scripts/commit-phoenix-and-merge-main.sh [--commit-only]' >&2
  exit 1
fi

if [[ "$(git branch --show-current)" != "codex/phoenixd-prototype" ]]; then
  echo 'Abbruch: Bitte zuerst codex/phoenixd-prototype auswählen.' >&2
  exit 1
fi
if git rev-parse -q --verify MERGE_HEAD >/dev/null; then
  echo 'Ein Merge läuft bereits. Bitte dessen Konflikte zuerst auflösen.' >&2
  exit 1
fi
if ! git diff --cached --quiet; then
  echo 'Abbruch: Es sind bereits Änderungen vorgemerkt. Bitte zuerst prüfen.' >&2
  exit 1
fi

# Stage only the implementation and its tests/docs, never generated_images.
git add -u -- app android-companion
git add -- app/Dockerfile.phoenixd-test \
  app/Dockerfile.dual-backend-test \
  app/backend/local_secret_key.py app/backend/upgrade_backup.py \
  app/tests/test_upgrade_backup.py app/tests/test_bip353_alias_resolution.py \
  app/tests/test_console_alias_addresses.py \
  app/tests/test_setup_bip353_domain.py \
  app/tests/test_alias_dns_repair.py app/tests/test_alias_dns_warning.py \
  app/tests/test_nwc_key_bootstrap.py app/tests/test_lnurl_metadata_response.py \
  app/backend/offer_preview.py app/tests/test_offer_amount_preview.py \
  tests/test_pwa_handoff_assets.py \
  app/assets/backend-icons app/assets/lightning-backend.js \
  app/backend/lightning_backends.py app/backend/lnurl_actions.py \
  app/tests/test_backend_ui.py app/tests/test_dual_backend_test_config.py \
  app/tests/test_lightning_backends.py app/tests/test_lnurl_actions.py \
  deploy/docker-compose.phoenixd-test.yml docs/phoenixd-prototype-test.md \
  scripts/prepare-dual-backend-test.py scripts/start-dual-backend-test.sh \
  scripts/start-phoenixd-test.sh scripts/commit-phoenix-and-merge-main.sh \
  scripts/diagnose-bip353.sh
git add -- CHANGELOG.md README.md docs/release-0.3.26-status.md \
  docs/phoenixd-test-checkliste.md
git diff --cached --check
git diff --cached --stat
if [[ "$commit_only" == true ]]; then
  git commit -m 'WIP: checkpoint Phoenixd integration before live NWC validation'
  git status --short --branch
  exit 0
fi
git commit -m 'Complete Phoenixd receiving, NWC and automatic upgrade backups'
git fetch origin
if git merge --no-commit --no-ff origin/main; then
  if git rev-parse -q --verify MERGE_HEAD >/dev/null; then
    echo 'Merge vorbereitet. Noch nicht committen; zuerst Integration prüfen.'
  else
    echo 'Aktueller main-Stand ist bereits integriert. Änderungen wurden committet.'
  fi
else
  echo 'Merge angehalten. Bitte diese Ausgabe zur Konfliktauflösung weitergeben.'
fi
git status --short --branch
