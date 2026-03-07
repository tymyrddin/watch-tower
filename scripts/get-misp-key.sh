#!/usr/bin/env bash
# Quick helper: print the MISP admin API key
# Usage: bash scripts/get-misp-key.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ -f "$REPO_ROOT/.env" ]]; then
  # shellcheck disable=SC2046
  export $(grep -v '^#' "$REPO_ROOT/.env" | xargs)
fi

CAKE_OUT=$(docker exec misp-core \
  /var/www/MISP/app/Console/cake user change_authkey "${MISP_ADMIN_EMAIL}" \
  2>/dev/null)
KEY=$(echo "$CAKE_OUT" | grep -oP '(?<=new key created: )\S+')

if [[ -z "$KEY" ]]; then
  echo "Could not generate key — is misp-core running and initialised?"
  exit 1
fi

echo "$KEY"