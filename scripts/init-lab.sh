#!/usr/bin/env bash
# ============================================================
#  init-lab.sh — post docker compose up initialisation
#
#  1. Retrieves the MISP admin API key
#  2. Enables OT/ICS taxonomies (ics, tlp, circl, mitre-ics-attack)
#  3. Updates MISP galaxies (mitre-ics-attack-pattern, ICS malware groups)
#  4. Imports the firmware triage + responsible disclosure workflow
#  5. Patches MISP_API_KEY into the workflow
#  6. Saves the webhook ID for scripts/triage.sh
#
#  Run from the repo root:
#    bash scripts/init-lab.sh
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ -f "$REPO_ROOT/.env" ]]; then
  # shellcheck disable=SC2046
  export $(grep -v '^#' "$REPO_ROOT/.env" | xargs)
else
  echo "ERROR: .env not found. Run: cp .env.example .env  then edit it."
  exit 1
fi

MISP_URL="http://localhost:${MISP_PORT:-8080}"
SHUFFLE_URL="http://localhost:5001"

# Create reports directory (bind-mounted into shuffle-backend)
mkdir -p "$REPO_ROOT/reports"

# ── helpers ──────────────────────────────────────────────────
wait_for() {
  local name="$1" url="$2"
  echo -n "[*] Waiting for $name "
  until curl -sf --max-time 3 "$url" > /dev/null 2>&1; do
    echo -n "."
    sleep 5
  done
  echo " ready"
}

wait_for_misp_seeded() {
  echo -n "[*] Waiting for MISP API ready (first boot can take 3-5 min) "
  local attempts=0 count=0
  while [[ $attempts -lt 72 ]]; do   # 6 min max
    count=$(misp_api "/taxonomies" 2>/dev/null | python3 -c "
import json,sys
try: print(len(json.load(sys.stdin)))
except: print(0)
" 2>/dev/null) || true
    count=${count:-0}
    if [[ "$count" -gt 0 ]]; then
      echo " ready ($count taxonomies)"
      return 0
    fi
    echo -n "."
    sleep 5
    attempts=$((attempts + 1))
  done
  echo " timed out — proceeding anyway"
}

misp_api() {
  local path="$1"; shift
  curl -sf \
    -H "Authorization: $MISP_API_KEY" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    "$@" "$MISP_URL$path"
}

# ── 1. Wait ───────────────────────────────────────────────────
wait_for "MISP"    "$MISP_URL"
wait_for "Shuffle" "$SHUFFLE_URL/api/v1/health/stats"

# ── 2. MISP admin API key ─────────────────────────────────────
echo "[*] Generating MISP admin API key..."
MISP_API_KEY=""
for attempt in $(seq 1 24); do   # retry up to 2 min
  CAKE_OUT=$(docker exec misp-core \
    /var/www/MISP/app/Console/cake user change_authkey "${MISP_ADMIN_EMAIL}" \
    2>/dev/null) || true
  MISP_API_KEY=$(echo "$CAKE_OUT" | grep -oP '(?<=new key created: )\S+') || true
  [[ -n "$MISP_API_KEY" ]] && break
  echo -n "."
  sleep 5
done

if [[ -z "$MISP_API_KEY" ]]; then
  echo "ERROR: Could not generate API key after 2 min. Check MISP logs: docker logs misp-core"
  exit 1
fi
echo "[+] MISP API key: ${MISP_API_KEY:0:8}..."

wait_for_misp_seeded

# ── 3. OT/ICS taxonomies ──────────────────────────────────────
# These taxonomies let you tag events with ICS-specific labels
# and use them in the restSearch query from Shuffle.
#
#  ics           — ICS/SCADA asset categories and sectors
#  tlp           — Traffic Light Protocol (sharing rules)
#  circl         — CIRCL incident taxonomy
#  mitre-attack  — ATT&CK Enterprise (base, needed by mitre-ics-attack)
#
echo "[*] Enabling OT/ICS taxonomies..."

# Import all bundled taxonomy files from disk into the DB before enabling.
# Without this, only a handful are present on a fresh instance.
misp_api "/taxonomies/update" -X POST > /dev/null 2>&1 && \
  echo "    [+] Taxonomy index updated" || \
  echo "    [-] Taxonomy update failed (non-fatal)"

TAXA_JSON=$(misp_api "/taxonomies" 2>/dev/null || echo "[]")

enable_taxonomy() {
  local name="$1"
  local tid
  tid=$(echo "$TAXA_JSON" | python3 -c "
import json, sys
for t in json.load(sys.stdin):
    tx = t.get('Taxonomy', t)
    if tx.get('namespace','').lower() == '$name'.lower():
        print(tx.get('id',''))
        break
" 2>/dev/null || true)

  if [[ -n "$tid" ]]; then
    misp_api "/taxonomies/enable/$tid" -X POST > /dev/null 2>&1 && \
      echo "    [+] $name (id=$tid)" || \
      echo "    [-] $name — already enabled or error"
  else
    echo "    [?] $name — not found in this MISP instance"
  fi
}

for tax in ics tlp circl; do
  enable_taxonomy "$tax"
done

# ── 4. OT/ICS galaxy data ─────────────────────────────────────
# Galaxies are different from feeds:
#  - A galaxy is a curated knowledge base shipped with MISP
#    (e.g. MITRE ATT&CK for ICS, ICS malware families)
#  - A feed is an external source of live indicators (IPs, hashes, etc.)
#
# For OT/ICS threat intel, galaxies are the primary free resource.
# MITRE ATT&CK for ICS galaxies ship with MISP under generic names
# (Techniques, Tactics, Groups…) identified only by their type field —
# NOT by their display name. We search by type to find them reliably.
#
# There are NO meaningful free public MISP feeds dedicated to OT/ICS
# indicators. Real OT/ICS feeds come from:
#   - Dragos WorldView (commercial)
#   - Claroty / Nozomi feeds (commercial)
#   - Sector ISACs (E-ISAC, WaterISAC — membership required)
#   - CISA ICS advisories (no native MISP feed, import manually)
#
echo "[*] Updating MISP galaxies (pulls latest ICS attack patterns + malware)..."
misp_api "/galaxies/update" -X POST > /dev/null 2>&1 && \
  echo "    [+] Galaxy update triggered" || \
  echo "    [-] Galaxy update failed (non-fatal, galaxies ship with MISP)"

# Enable the ICS-relevant galaxies so they appear in event tagging
GALAXY_JSON=$(misp_api "/galaxies" 2>/dev/null || echo "[]")

enable_galaxy() {
  local type_exact="$1"
  local label="$2"
  local gid
  gid=$(echo "$GALAXY_JSON" | python3 -c "
import json, sys
for g in json.load(sys.stdin):
    gx = g.get('Galaxy', g)
    if gx.get('type','').lower() == '$type_exact'.lower():
        print(gx.get('id',''))
        break
" 2>/dev/null || true)

  if [[ -n "$gid" ]]; then
    echo "    [+] $label (type=$type_exact, id=$gid)"
  else
    echo "    [?] $label — not found"
  fi
}

# MITRE ATT&CK for ICS galaxies ship with MISP under generic names
# (Techniques, Tactics, Groups, etc.) but are identified by their type field.
for args in \
    "mitre-ics-techniques|MITRE ATT&CK for ICS — Techniques" \
    "mitre-ics-tactics|MITRE ATT&CK for ICS — Tactics" \
    "mitre-ics-groups|MITRE ATT&CK for ICS — Groups" \
    "mitre-ics-software|MITRE ATT&CK for ICS — Software" \
    "mitre-attack-pattern|Enterprise ATT&CK — Attack Patterns"; do
  enable_galaxy "${args%%|*}" "${args##*|}"
done

# ── 5. Import Shuffle workflows ───────────────────────────────
echo "[*] Logging into Shuffle..."
SHUFFLE_SESSION=$(python3 - <<PYEOF
import json, urllib.request, urllib.error, sys
body = json.dumps({"username": "${SHUFFLE_ADMIN_EMAIL}", "password": "${SHUFFLE_ADMIN_PASSWORD}"}).encode()
req = urllib.request.Request("${SHUFFLE_URL}/api/v1/login",
    data=body, headers={"Content-Type": "application/json"})
try:
    r = urllib.request.urlopen(req)
    d = json.loads(r.read().decode())
    if d.get("success"):
        cookies = d.get("cookies", [])
        token = next((c["value"] for c in cookies if c["key"] == "session_token"), "")
        print(token)
except Exception as e:
    sys.stderr.write(str(e) + "\n")
PYEOF
)

shuffle_api() {
  local method="${1:-GET}" path="$2"; shift 2
  python3 - "$@" <<PYEOF
import json, urllib.request, urllib.error, sys
url = "${SHUFFLE_URL}${path}"
data = sys.argv[1].encode() if len(sys.argv) > 1 else None
req = urllib.request.Request(url, data=data, method="${method}",
    headers={"Cookie": "session_token=${SHUFFLE_SESSION}",
             "Content-Type": "application/json"})
try:
    r = urllib.request.urlopen(req)
    print(r.read().decode())
except urllib.error.HTTPError as e:
    sys.stderr.write(f"HTTP {e.code}: {e.read().decode()}\n")
    print("{}")
except Exception as e:
    sys.stderr.write(str(e) + "\n")
    print("{}")
PYEOF
}

# Imports one workflow (idempotent), patches credentials, activates webhook trigger.
# Args: <display-name> <json-file> <webhook-label> <id-output-file>
import_workflow() {
  local wf_name="$1" wf_file="$2" hook_label="$3" id_file="$4"
  local wf_id=""

  wf_id=$(shuffle_api GET /api/v1/workflows | python3 -c "
import json, sys
wfs = json.load(sys.stdin)
for wf in (wfs if isinstance(wfs, list) else []):
    if wf.get('name') == '$wf_name':
        print(wf.get('id', ''))
        break
" 2>/dev/null || true)

  if [[ -n "$wf_id" ]]; then
    echo "    [*] Already imported (id=$wf_id) — skipping"
  else
    local resp
    resp=$(shuffle_api POST /api/v1/workflows "$(cat "$wf_file")")
    wf_id=$(echo "$resp" | python3 -c "
import json, sys
print(json.load(sys.stdin).get('id', ''))
" 2>/dev/null || true)
    if [[ -z "$wf_id" ]]; then
      echo "    [-] Import returned no id. Response: $(echo "$resp" | head -c 200)"
      return
    fi
    echo "    [+] Imported — id=$wf_id"
  fi

  # Shuffle worker containers are spawned by Orborus outside the ot-triage
  # network, so they cannot reach misp-core by hostname. host.docker.internal
  # resolves to the Docker host, where MISP is exposed on MISP_PORT.
  local misp_worker_url="http://host.docker.internal:${MISP_PORT:-8080}"

  local updated
  updated=$(
    shuffle_api GET "/api/v1/workflows/$wf_id" | \
    python3 -c "
import json, sys
wf = json.load(sys.stdin)
for v in wf.get('workflow_variables', []):
    if v.get('name') == 'MISP_API_KEY':
        v['value'] = '${MISP_API_KEY}'
    elif v.get('name') == 'MISP_URL':
        v['value'] = '${misp_worker_url}'
print(json.dumps(wf))
" 2>/dev/null || true
  )
  if [[ -n "$updated" ]]; then
    shuffle_api PUT "/api/v1/workflows/$wf_id" "$updated" > /dev/null && \
      echo "    [+] MISP_API_KEY and MISP_URL patched" || \
      echo "    [-] PATCH failed — paste the key and URL manually in Shuffle workflow variables"
  fi

  local hook_id
  hook_id=$(
    shuffle_api GET "/api/v1/workflows/$wf_id" | \
    python3 -c "
import json, sys
wf = json.load(sys.stdin)
for t in wf.get('triggers', []):
    if t.get('name', '').lower() == 'webhook':
        print(t.get('id', ''))
        break
" 2>/dev/null || true
  )
  if [[ -z "$hook_id" ]]; then
    echo "    [-] Webhook trigger not found in workflow"
    return
  fi

  echo "$hook_id" > "$id_file"
  echo "    [+] Webhook ID saved → $(basename "$id_file")"

  shuffle_api POST /api/v1/hooks/new \
    "{\"type\":\"webhook\",\"id\":\"${hook_id}\",\"name\":\"${hook_label}\",\"workflow\":\"${wf_id}\",\"start\":\"${hook_id}\"}" \
    > /dev/null 2>&1 && echo "    [+] Webhook trigger activated" || \
    echo "    [-] Webhook activation failed (may already be running)"
}

IMPORT_WEBHOOK_URL=""
TRIAGE_WEBHOOK_URL=""

if [[ -z "$SHUFFLE_SESSION" ]]; then
  echo "[-] Could not log into Shuffle — check credentials in .env"
  echo "    Import manually: http://localhost:${SHUFFLE_PORT:-3001} > Workflows > Import"
else
  echo "[+] Shuffle login OK"

  echo "[*] Importing OT/ICS Firmware Findings Import workflow..."
  import_workflow \
    "OT/ICS Firmware Findings Import" \
    "$REPO_ROOT/shuffle/workflows/ot-ics-import.json" \
    "Firmware Findings Input" \
    "$REPO_ROOT/.shuffle-import-webhook-id"

  echo "[*] Importing OT/ICS Firmware Triage workflow..."
  import_workflow \
    "OT/ICS Firmware Triage" \
    "$REPO_ROOT/shuffle/workflows/ot-ics-triage.json" \
    "Run Triage" \
    "$REPO_ROOT/.shuffle-triage-webhook-id"

  if [[ -f "$REPO_ROOT/.shuffle-import-webhook-id" ]]; then
    local_id=$(cat "$REPO_ROOT/.shuffle-import-webhook-id")
    IMPORT_WEBHOOK_URL="$SHUFFLE_URL/api/v1/hooks/webhook_${local_id}"
  fi
  if [[ -f "$REPO_ROOT/.shuffle-triage-webhook-id" ]]; then
    local_id=$(cat "$REPO_ROOT/.shuffle-triage-webhook-id")
    TRIAGE_WEBHOOK_URL="$SHUFFLE_URL/api/v1/hooks/webhook_${local_id}"
  fi
fi

# ── Done ──────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  OT/ICS Firmware Triage Lab — ready"
echo "============================================================"
echo ""
echo "  MISP     http://localhost:${MISP_PORT:-8080}"
echo "           ${MISP_ADMIN_EMAIL} / ${MISP_ADMIN_PASSPHRASE}"
echo "           API key: ${MISP_API_KEY}"
echo ""
echo "  Shuffle  http://localhost:${SHUFFLE_PORT:-3001}"
echo "           ${SHUFFLE_ADMIN_EMAIL} / ${SHUFFLE_ADMIN_PASSWORD}"
echo ""
echo "  HOW TO USE"
echo ""
echo "  Step 1 — import findings into MISP:"
echo "    bash scripts/import.sh --file examples/findings.json"
echo ""
echo "  Step 2 — review events in MISP, then run triage:"
echo "    bash scripts/triage.sh"
echo ""
echo "  Input format: {\"research_batch\":{...}, \"firmware\":[{\"vendor\", \"product\","
echo "    \"version\", \"vulnerabilities\":[{\"research_id\", \"cvss_score\", ...}]}]}"
echo "  See README for the full schema."
echo ""
if [[ -n "${IMPORT_WEBHOOK_URL:-}" ]]; then
echo "  Import webhook URL:"
echo "    ${IMPORT_WEBHOOK_URL}"
echo ""
fi
if [[ -n "${TRIAGE_WEBHOOK_URL:-}" ]]; then
echo "  Triage webhook URL:"
echo "    ${TRIAGE_WEBHOOK_URL}"
echo ""
fi
echo "  Enrichment: CIRCL CVE Search (cve.circl.lu, Luxembourg, EU)"
echo "  CVD framework: ENISA — 30/60/90 day disclosure deadlines"
echo "  ICS coordinator: cert@vde.com (VDE CERT, DE/EU)"
echo "============================================================"