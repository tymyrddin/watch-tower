#!/usr/bin/env bash
# import.sh — import firmware vulnerability findings into MISP via Shuffle
#
# Usage:
#   bash scripts/import.sh --example
#   bash scripts/import.sh --file findings.json
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

usage() {
  echo "Usage:"
  echo "  bash scripts/import.sh --example"
  echo "  bash scripts/import.sh --file <findings.json>"
  exit 1
}

case "${1:-}" in
  --example) FILE="$REPO_ROOT/examples/findings.json" ;;
  --file)
    [[ -z "${2:-}" ]] && usage
    FILE="$2"
    ;;
  *) usage ;;
esac

python3 "$REPO_ROOT/ingestion/ingest_findings.py" "$FILE"