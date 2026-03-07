# Getting started

This tutorial walks through a complete triage run using the example findings.
By the end you will know what each stage does, what to look for in MISP, and
how to interpret KEV and EPSS signals.

## Prerequisites

- Docker and Docker Compose installed
- Ports 8080, 3001, 5001 free on your machine
- The repo cloned and `.env` configured:

```bash
cp .env.example .env
# open .env
# Change MYSQL_ROOT_PASSWORD, MYSQL_PASSWORD, MISP_ADMIN_PASSPHRASE, 
# SHUFFLE_ADMIN_PASSWORD to something non-default
```

## Start the stack

```bash
make start
```

This starts all eight services. First boot takes 2–5 minutes while MISP
initialises its database. You can watch its progress:

```bash
docker compose logs -f misp-core
# wait for: "MISP is ready"
```

## Initialise the lab

```bash
make init
```

`init-lab.sh` does the following automatically:

| Step                      | What happens                                       |
|---------------------------|----------------------------------------------------|
| Wait for MISP and Shuffle | Polls both services until they respond             |
| Generate MISP API key     | Generated via MISP console, no manual login needed |
| Enable taxonomies         | Enables `ics`, `tlp`, `circl`                      |
| Update galaxies           | Pulls latest ATT&CK for ICS, ICS malware groups    |
| Import Shuffle workflows  | Imports `ot-ics-import.json` and `ot-ics-triage.json` |
| Patch MISP_API_KEY        | Injects the live key into both workflow variables     |
| Save webhook IDs          | Writes `.shuffle-import-webhook-id` and `.shuffle-triage-webhook-id` |

At the end it prints credentials and the webhook URL. It is safe to run again, it detects an existing workflow and skips re-import.

If the automatic key patch fails, the script tells you. The simplest fix is to
re-run `make init`, which generates a fresh key and patches it again. If the
patch still fails, open `http://localhost:3001`, go to Workflows, open the
workflow, go to Variables, and paste the printed API key into `MISP_API_KEY`.

## Verify the cve module is available

The triage pipeline relies on the MISP `cve` enrichment module. Confirm it is
loaded:

```bash
docker exec misp-modules \
  curl -s http://localhost:6666/modules \
  | python3 -c "
import json, sys
modules = json.load(sys.stdin)
names = [m['name'] for m in modules]
print('cve module:', 'FOUND' if 'cve' in names else 'MISSING')
"
```

Expected: `cve module: FOUND`

If missing, restart misp-modules:

```bash
docker compose restart misp-modules
```

## Import the example findings

```bash
bash scripts/import.sh --example
```

Output:

```
[*] 3 firmware image(s), 6 finding(s)
[*] Posting to Shuffle...
[+] Accepted, pipeline running.

    MISP events:   http://localhost:8080
    Workflow runs: http://localhost:3001

    Results appear in MISP within ~30 seconds.
```

The ingestion script normalised the findings, validated CVE formats, and
posted the batch to the Shuffle webhook. The import workflow is now running.

## What the import workflow does (while you wait)

The import workflow runs a single Python action (`act_import`) that processes
the batch sequentially:

### For each firmware image

1. Creates a MISP event: `Firmware research -- <vendor> <product> <version>`
2. Adds a `software` object (vendor, product, version, architecture)
3. Adds `sha256` and `filename` attributes for the firmware image
4. For each vulnerability:
   - Adds a `vulnerability` object with all research fields and ICS scoring fields
   - Adds a `file` object if `affected_binary` is set
   - Adds a `port` attribute if `trigger_port` is set

### CVE enrichment (in MISP)

After adding all objects, the workflow calls:

```
POST /events/enrichEvent/{event_id}   body: {"cve": true}
```

The MISP `cve` module queries `cve.circl.lu` for each CVE attribute and
creates additional MISP objects inside the event:

- `vulnerability` object, CVSS score, description, references from CIRCL
- `weakness` object, CWE description and category

The workflow waits 10 seconds for this to complete.

After the import has run, analysts can review the events in MISP and make
changes before running triage.

## Run triage

```bash
bash scripts/triage.sh
```

This triggers the triage workflow, which reads all `Firmware research --` events
from MISP, scores each vulnerability, and writes a summary back to each event.

## What the triage workflow does

The triage workflow runs a single Python action (`act_triage`). It does not
receive findings data and does not re-trigger enrichment.

### CISA KEV check

The triage workflow fetches the CISA Known Exploited Vulnerabilities catalogue once
per run and checks every CVE against it. A match adds +2 to the ICS triage score.

In the example: CVE-2021-44228 (Log4Shell) is in the KEV catalogue.

### EPSS check

For each CVE the workflow queries `api.first.org/data/v1/epss`. A probability
above 50 % adds +1 to the ICS triage score.

Log4Shell has EPSS > 0.94, well above the threshold.

### Triage scoring

```
ICS score = CVSS
           + exploit_complexity bonus   (low = +2, high = -2)
           + operational_impact bonus   (safety hazard = +3, process halt = +2)
           + exposure bonus             (internet = +2, internal network = +1)
           + PoC bonus                  (+1 if poc_available)
           + KEV bonus                  (+2 if in CISA KEV)
           + EPSS bonus                 (+1 if EPSS > 0.5)
```

### Possible triage decisions

| Score                      | Decision                |
|----------------------------|-------------------------|
| ≥ 9                        | DISCLOSE NOW (30 days)  |
| 7–8.9                      | DISCLOSE WITHIN 60 DAYS |
| 4–6.9                      | DISCLOSE WITHIN 90 DAYS |
| > 0                        | MONITOR                 |
| 0                          | MANUAL REVIEW           |
| disclosure_status = public | ALREADY PUBLIC          |


## Review results in MISP

Open `http://localhost:8080` and log in:

```
<your MISP_ADMIN_EMAIL from .env>  /  <your MISP_ADMIN_PASSPHRASE from .env>
```

Go to Event List. You should see three new events:

```
Firmware research -- ABB RTU560 11.7.1
Firmware research -- Siemens SCALANCE X308-2 4.1.3
Firmware research -- Schneider Electric Modicon M340 3.10
```

### Open the Schneider Electric event

This event has CVE-2021-44228 and should show the most enrichment.

Objects tab:

| Object          | Added by        | What it contains                               |
|-----------------|-----------------|------------------------------------------------|
| `software`      | workflow        | vendor, product, version, architecture         |
| `vulnerability` | workflow        | all research fields from findings.json         |
| `vulnerability` | MISP cve module | CVSS score, description, references from CIRCL |
| `weakness`      | MISP cve module | CWE-502 description                            |
| `file`          | workflow        | path to affected binary                        |

Attributes tab:

| Type            | Value            | Added by                          |
|-----------------|------------------|-----------------------------------|
| `vulnerability` | CVE-2021-44228   | workflow (trigger for enrichment) |
| `filename`      | m340_fw_3.10.bin | workflow                          |
| `sha256`        | 9b8c7d6e...      | workflow                          |
| `port`          | 8443             | workflow                          |
| `port`          | 9090             | workflow                          |
| `comment`       | Triage summary   | workflow (see below)              |

### The triage summary comment

The workflow writes a structured comment back to each MISP event. It looks
like this:

```
=== Triage summary: Schneider Electric Modicon M340 3.10 ===

  [DISCLOSE NOW]  CVE-2021-44228
    Title:    Log4Shell in EcoStruxure configuration utility bundled with firmware
    CVSS:     10.0
    CWE:      CWE-502
    KEV:      YES, actively exploited in the wild
    EPSS:     0.943 [>50% exploitation probability]
    Impact:   process halt
    Exposure: internal network
    Score:    17.0

  [DISCLOSE NOW]  ICS-ZD-2026-003
    Title:    Unauthenticated firmware upload via undocumented debug endpoint
    CVSS:     8.2
    CWE:      CWE-306
    KEV:      no
    EPSS:     0.000
    Impact:   safety hazard
    Exposure: internal network
    Score:    12.2
```

Score breakdown for CVE-2021-44228:

| Component                        | Value |
|----------------------------------|-------|
| CVSS (from MISP enrichment)      | 10.0  |
| exploit_complexity: low          | +2.0  |
| operational_impact: process halt | +2.0  |
| exposure: internal network       | +1.0  |
| poc_available: true              | +1.0  |
| CISA KEV                         | +2.0  |
| EPSS > 0.5                       | +1.0  |
| Total                            | 19.0  |

## Check the Shuffle execution log

Open `http://localhost:3001` and log in with your Shuffle credentials.

Go to Workflows → open OT/ICS Firmware Triage → click Runs (top right).

You should see a completed execution. Click it to expand. The `act_triage`
node shows the full JSON output, ranked vulnerabilities, disclosure drafts.

If the execution failed, the node turns red and shows the Python traceback.
Common causes:

| Error                         | Cause                  | Fix                              |
|-------------------------------|------------------------|----------------------------------|
| `MISP_API_KEY` is placeholder | Auto-patch failed      | Paste key manually in Variables  |
| `Connection refused` to MISP  | MISP still starting    | Wait and resubmit                |
| `cve module not found`        | misp-modules not ready | Restart misp-modules             |
| `KEV fetch failed`            | No internet access     | Scores still work, KEV bonus = 0 |

## Interpreting KEV and EPSS

CISA KEV answers: *is this CVE being actively exploited right now?*

A CVE in the KEV catalogue means CISA has confirmed active in-the-wild
exploitation. In an OT context this is significant, it means attackers are
using it, not just researchers.

EPSS answers: *how likely is exploitation in the next 30 days?*

The score is a probability (0–1). Log4Shell has EPSS ≈ 0.94, meaning FIRST
estimates a 94 % chance of exploitation attempt in a 30-day window.

Both signals feed directly into the triage score. A vulnerability that is in
KEV and has high EPSS moves immediately to DISCLOSE NOW regardless of CVSS.

## Submit your own findings

```bash
bash scripts/import.sh --file my_findings.json
bash scripts/triage.sh
```

Your file can use:

Canonical format (recommended, full field set):

```
{
  "research_batch": { "lab": "...", "date": "YYYY-MM-DD", "researcher": "..." },
  "firmware": [ { "vendor": "...", "product": "...", "version": "...",
    "vulnerabilities": [ { "research_id": "...", "cve": null, ... } ] } ]
}
```

Simplified format (quick lab output, normalised automatically):
```json
{
  "firmwares": [
    {
      "vendor": "Acme",
      "device": "PLC-9000",
      "version": "2.0",
      "vulnerabilities": [
        { "cve": "CVE-2023-12345" },
        { "finding": "telnet enabled by default" }
      ]
    }
  ]
}
```

The ingestion script normalises both formats to the canonical schema before
posting to Shuffle.

See [docs/schema.md](schema.md) for all available fields.

## After the triage, what to do

For each DISCLOSE NOW or DISCLOSE WITHIN 60 DAYS finding, the
workflow generates a disclosure draft in the Shuffle execution output. It
contains:

- Subject line with vulnerability ID and product
- Vendor PSIRT address (Siemens ProductCERT, Schneider Electric PSIRT, ABB PSIRT, etc.)
- National CERT in CC (BSI, CERT-FR, NCSC-CH, etc.)
- VDE CERT in CC (ICS coordinator for all EU disclosures)
- ENISA CVD framework reference
- Deadline date

See [docs/contacts.md](contacts.md) for a PSIRT and national CERT list.
See [docs/triage.md](triage.md) for a scoring and decision table.

## Resetting the lab

```bash
make clean    # removes all containers and volumes, clean slate
make start
make init
```

`make clean` removes all MISP data, Shuffle workflows, and OpenSearch indices.
Use it when you want to start completely fresh.
