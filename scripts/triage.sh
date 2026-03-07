#!/usr/bin/env bash
# triage.sh — run ICS triage on all Firmware research events in MISP
#
# Usage:
#   bash scripts/triage.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

HOOK_FILE="$REPO_ROOT/.shuffle-triage-webhook-id"
if [[ ! -f "$HOOK_FILE" ]]; then
  echo "ERROR: .shuffle-triage-webhook-id not found."
  echo "Run:   bash scripts/init-lab.sh"
  exit 1
fi

if [[ -f "$REPO_ROOT/.env" ]]; then
  # shellcheck disable=SC2046
  export $(grep -v '^#' "$REPO_ROOT/.env" | xargs)
fi

HOOK_ID=$(cat "$HOOK_FILE")
SHUFFLE_BASE="${SHUFFLE_URL:-http://localhost:5001}"
HOOK_URL="${SHUFFLE_BASE}/api/v1/hooks/webhook_${HOOK_ID}"

echo "[*] Triggering triage on all Firmware research events in MISP..."
curl -sf -X POST "$HOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{}' > /dev/null
echo "[+] Triage triggered."
echo ""
echo "    Workflow runs: http://localhost:${SHUFFLE_PORT:-3001}"
echo "    MISP events:   http://localhost:${MISP_PORT:-8080}"
echo ""
echo "    Triage summaries appear in MISP events within ~60 seconds."