# Shuffle workflows

Two workflows handle the two stages of the pipeline.

## Workflow 1: OT/ICS Firmware Findings Import

File: `shuffle/workflows/ot-ics-import.json`
Name: OT/ICS Firmware Findings Import

### Pipeline

```
ingestion/ingest_findings.py
        ↓  POST JSON
Shuffle webhook (Firmware Findings Input)
        ↓
act_import (execute_python)
        ├─ for each firmware:
        │     create MISP event
        │     add software object (vendor, product, version, architecture)
        │     add sha256 + filename attributes
        │     for each vulnerability:
        │         add vulnerability object (CVE, ICS fields, title, CVSS)
        │         add file object  (if affected_binary)
        │         add port attribute  (if trigger_port)
        │     trigger MISP cve module enrichment
        │     sleep 10 s
        └─ return summary JSON
```

### Trigger

| Field | Value                                       |
|-------|---------------------------------------------|
| Type  | Webhook (HTTP POST)                         |
| Label | Firmware Findings Input                     |
| Input | `$exec` (Shuffle injects the raw POST body) |

`init-lab.sh` activates the trigger and saves its ID to `.shuffle-import-webhook-id`.

### Action: act_import

App: Shuffle Tools → execute_python

Creates MISP events and objects for each firmware image. Vulnerability objects
include the ICS scoring fields (`exploit-complexity`, `operational-impact`,
`exposure`, `poc-available`) stored as object attributes using `?force=1` to
bypass template validation for non-standard relation names.

After creating all objects for a firmware image, triggers the MISP `cve` module:

```
POST /events/enrichEvent/{event_id}   body: {"cve": true}
```

The module queries `cve.circl.lu` for each CVE attribute and adds enriched
`vulnerability` and `weakness` objects to the event. The action waits 10 seconds
per image for enrichment to complete.

### Workflow variables

| Name           | Default                            | Purpose                                          |
|----------------|------------------------------------|--------------------------------------------------|
| `MISP_URL`     | `http://host.docker.internal:8080` | MISP URL reachable from Shuffle worker containers |
| `MISP_API_KEY` | `REPLACE_WITH_YOUR_MISP_API_KEY`   | Auto-patched by `init-lab.sh`, or paste manually |

### What appears in MISP after import

For each firmware image:

- One event: `Firmware research -- <vendor> <product> <version>`
- `software` object: vendor, product, version, architecture
- `sha256` and `filename` attributes for the firmware image
- Per vulnerability:
  - `vulnerability` object with all ICS research fields (added by `act_import`)
  - `vulnerability` object added by the `cve` module (CVSS, CWE from CIRCL)
  - `weakness` object added by the `cve` module (CWE details)
  - `file` object, if `affected_binary` is set
  - `port` attribute, if `trigger_port` is set

---

## Workflow 2: OT/ICS Firmware Triage

File: `shuffle/workflows/ot-ics-triage.json`
Name: OT/ICS Firmware Triage

### Pipeline

```
bash scripts/triage.sh
        ↓  POST {} to webhook
Shuffle webhook (Run Triage)
        ↓
act_triage (execute_python)
        ├─ query MISP: all events with info containing "Firmware research --"
        ├─ fetch CISA KEV catalogue (once per run)
        ├─ for each event:
        │     read software object (vendor, product, version)
        │     read vulnerability objects (research objects only)
        │     for each research vulnerability:
        │         read ICS fields from vulnerability object attributes
        │         get CVSS from enrichment-added vulnerability object (if present)
        │         get CWEs from weakness objects
        │         check CISA KEV  → +2 if exploited
        │         fetch EPSS      → +1 if > 0.5
        │         compute ICS triage score
        │         build disclosure draft
        │     write triage summary as comment attribute on MISP event
        └─ return ranked JSON
```

### Trigger

| Field | Value                     |
|-------|---------------------------|
| Type  | Webhook (HTTP POST)       |
| Label | Run Triage                |
| Input | any body (including `{}`) |

`init-lab.sh` activates the trigger and saves its ID to `.shuffle-triage-webhook-id`.

### Action: act_triage

App: Shuffle Tools → execute_python

Does not receive findings data. Reads whatever is already in MISP. Distinguishes
research vulnerability objects from enrichment-added ones by looking for the
presence of ICS-specific fields (`exploit-complexity`, `operational-impact`,
`exposure`, `poc-available`). The triage workflow does not trigger enrichment.

### External API calls

| API      | URL                                                 | Purpose                                       |
|----------|-----------------------------------------------------|-----------------------------------------------|
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | Actively exploited CVEs, fetched once per run |
| EPSS     | `api.first.org/data/v1/epss?cve={id}`               | Exploitation probability, fetched per CVE     |

Both are public, no authentication required.

### Workflow variables

| Name           | Default                            | Purpose                                          |
|----------------|------------------------------------|--------------------------------------------------|
| `MISP_URL`     | `http://host.docker.internal:8080` | MISP URL reachable from Shuffle worker containers |
| `MISP_API_KEY` | `REPLACE_WITH_YOUR_MISP_API_KEY`   | Auto-patched by `init-lab.sh`, or paste manually |

### What appears in MISP after triage

A `comment` attribute is written to each event with the triage summary:

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
    Score:    19.0
```

### Workflow output

The action prints a JSON object that Shuffle stores as the execution result:

```json
{
  "success": true,
  "total": 6,
  "vulnerabilities": [
    {
      "rank": 1,
      "triage_score": 19.0,
      "triage_decision": "DISCLOSE NOW",
      "research_id": "CVE-2021-44228",
      "cve": "CVE-2021-44228",
      "cvss_score": 10.0,
      "kev": true,
      "epss": 0.943,
      "cwes_enriched": ["CWE-502"],
      "misp_event_id": "42",
      "disclosure": {
        "deadline_date": "2026-04-05",
        "vendor_psirt": { "name": "...", "email": "..." },
        "national_cert": { "name": "...", "email": "..." },
        "draft_body": "Subject: ..."
      }
    }
  ]
}
```

View execution results in Shuffle UI → Workflows → open workflow → Runs.
The full picture is in MISP at `http://localhost:8080`.

## Test steps

1. Bring the stack up: `make start`
2. Run init: `make init` (idempotent, safe to re-run)
3. Verify `cve` module is loaded in misp-modules:
   ```bash
   docker exec misp-modules curl -s http://localhost:6666/modules \
     | python3 -c "import json,sys; [print(m['name']) for m in json.load(sys.stdin)]" \
     | grep cve
   ```
   Expected output: `cve`
4. Import example findings: `bash scripts/import.sh --example`
   Expected: `[+] Accepted -- pipeline running.`
5. Wait ~30 seconds, then open MISP at `http://localhost:8080`
   - Event list should show `Firmware research -- Acme RTU-500 1.3.7`
   - Open the event, verify: software object, vulnerability objects with ICS fields
   - If `cve.circl.lu` was reachable: additional `vulnerability` object from the `cve` module
6. Run triage: `bash scripts/triage.sh`
7. Wait ~60 seconds, then open the MISP events and check the `comment` attribute for triage summaries
8. In Shuffle at `http://localhost:3001` → Workflows → Runs, verify both executions completed without errors