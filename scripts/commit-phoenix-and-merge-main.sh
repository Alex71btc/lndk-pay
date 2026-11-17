#!/usr/bin/env bash
# Run manually on the host: this Work session cannot write Git metadata.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

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
git add -u -- app
git add -- app/Dockerfile.phoenixd-test \
  app/assets/backend-icons app/assets/lightning-backend.js \
  app/backend/lightning_backends.py app/backend/lnurl_actions.py \
  app/tests/test_backend_ui.py app/tests/test_dual_backend_test_config.py \
  app/tests/test_lightning_backends.py app/tests/test_lnurl_actions.py \
  deploy/docker-compose.phoenixd-test.yml docs/phoenixd-prototype-test.md \
  scripts/prepare-dual-backend-test.py scripts/start-dual-backend-test.sh \
  scripts/start-phoenixd-test.sh scripts/commit-phoenix-and-merge-main.sh
git diff --cached --check
git diff --cached --stat
git commit -m 'Integrate Phoenixd backend and LNURL auth and withdraw'
git fetch origin
if git merge --no-commit --no-ff origin/main; then
  echo 'Merge vorbereitet. Noch nicht committen; zuerst Integration prüfen.'
else
  echo 'Merge angehalten. Bitte diese Ausgabe zur Konfliktauflösung weitergeben.'
fi
git status --short --branch
