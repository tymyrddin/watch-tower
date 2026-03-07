# Triage walkthrough

You have finished analysing firmware. You have findings. This is what you do
with them.

## 1. Write up findings

Findings go into a JSON file. Use the canonical format:

```json
{
  "research_batch": {
    "lab": "ICS Firmware Lab",
    "date": "2026-03-06",
    "researcher": "Nina",
    "toolchain": "binwalk + ghidra + fuzzing + nmap"
  },
  "firmware": [
    {
      "vendor": "ABB",
      "product": "RTU560",
      "version": "11.7.1",
      "architecture": "armv7",
      "firmware_file": "rtu560_fw_11.7.1.bin",
      "firmware_sha256": "3c4a9c1fde72b805",
      "vulnerabilities": [
        {
          "research_id": "ICS-ZD-2026-001",
          "cve": null,
          "title": "Unauthenticated command execution in firmware update service",
          "cvss_score": 9.1,
          "cwe": "CWE-78",
          "exploit_complexity": "low",
          "operational_impact": "process halt",
          "exposure": "internal network",
          "poc_available": true,
          "disclosure_status": "private",
          "affected_binary": "/usr/bin/update_agent",
          "trigger_port": 8080
        }
      ]
    }
  ]
}
```

The lab already has a complete three-vendor example at `examples/findings.json`
covering ABB, Siemens, and Schneider Electric. Using that for this walkthrough:

```
cat examples/findings.json
```

Three firmware images, six vulnerabilities. Two zero-days with no CVE yet.
Three with assigned CVEs, including CVE-2021-44228. One already public.

The fields that drive the triage score (beyond CVSS) are:

- `exploit_complexity`, your hands-on assessment, not NVD's. `low` means you
  wrote the exploit in a day. `high` means it requires specific conditions you
  cannot reliably reproduce.
- `operational_impact`, what actually happens to the plant. `safety hazard`
  means a human could be hurt. `process halt` means production stops.
  `service disruption` means degraded operation.
- `exposure`, where does an attacker need to be? `internet` means it is
  reachable from anywhere. `internal network` means they need to be on the OT
  LAN. `air-gapped` means physical access.
- `poc_available`, do you have working exploit code?
- `disclosure_status`, `private` means you found it first and the vendor does
  not know. `public` means it is already in the NVD. `coordinated` means you
  are mid-disclosure.

These are the values filled in from lab notes. Everything else, 
CVSS enrichment, KEV status, EPSS, the pipeline fetches.

## 2. Import findings

```
bash scripts/import.sh --file examples/findings.json
```

```
[*] 3 firmware image(s), 6 finding(s)
[*] Posting to Shuffle...
[+] Accepted, pipeline running.

    MISP events:   http://localhost:8080
    Workflow runs: http://localhost:3001

    Results appear in MISP within ~30 seconds.
```

The import is running. Give it 30 seconds for MISP events and objects to appear.

## 3. Run triage

Once the import has completed:

```
bash scripts/triage.sh
```

```
[+] Triage triggered.

    Workflow runs: http://localhost:3001
    MISP events:   http://localhost:8080

    Triage summaries appear in MISP events within ~60 seconds.
```

## 4. Confirm execution in Shuffle

Open http://localhost:3001 and log in.

Go to Workflows → OT/ICS Firmware Triage → click Runs (top right corner).

You see the triage run you just triggered. Status: SUCCESS.

Click it. Click the `act_triage` node. The output JSON is there, ranked vulnerabilities, EPSS scores, KEV hits,
disclosure drafts. You can come back to the drafts in step 7. First, go to MISP to see the structured intelligence
records.

## 5. Open MISP and review the events

Open http://localhost:8080 and log in.

Go to Event Actions → List Events.

Three new events:

```
Firmware research -- ABB RTU560 11.7.1
Firmware research -- Siemens SCALANCE X308-2 4.1.3
Firmware research -- Schneider Electric Modicon M340 3.10
```

Open Firmware research -- Schneider Electric Modicon M340 3.10. This one has Log4Shell and shows the full enrichment.

### Objects tab

| Object                    | What it is                                                          |
|---------------------------|---------------------------------------------------------------------|
| `software`                | The firmware image: vendor, product, version, architecture          |
| `vulnerability` *(yours)* | Your research record: everything from your findings file            |
| `vulnerability` *(CIRCL)* | What the public CVE record says: CVSS 10.0, description, references |
| `weakness`                | CWE-502, the root-cause weakness class from the CVE record          |
| `file`                    | The affected binary: `/opt/mgmt/lib/log4j-core-2.14.1.jar`          |

The CIRCL `vulnerability` object and the `weakness` object were added
automatically by the MISP cve module after the pipeline called enrichment.
You did not have to do anything. The CVSS score of 10.0 came from CIRCL, 
the findings file had `"cvss_score": null` for this CVE, which is correct:
Log4Shell's score is published and the module fills it in.

For zero-days (no CVE), the CIRCL objects are absent. The `vulnerability`
object is all there is. Its CVSS comes from what was found in the findings file.

### Attributes tab

| Type            | Value                |
|-----------------|----------------------|
| `vulnerability` | CVE-2021-44228       |
| `vulnerability` | ICS-ZD-2026-003      |
| `filename`      | m340_fw_3.10.bin     |
| `sha256`        | 9b8c7d6e5f4a3b2c     |
| `port`          | 8443                 |
| `port`          | 9090                 |
| `comment`       | ← the triage summary |

### Triage summary

Scroll to the `comment` attribute. This is what the pipeline concluded:

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

Reading the scores:

The ICS score is not CVSS. CVSS tells you how bad the vulnerability is in
isolation. The ICS score tells you how urgently you need to act on it in this
operational context.

Log4Shell scores 19.0 because on top of CVSS 10.0, exploitation is trivial
(`low` complexity, +2), it halts a production process (`process halt`, +2),
it is on an internal OT network so any compromised workstation can reach it
(`internal network`, +1), you have a working proof-of-concept (+1), CISA has
confirmed active exploitation in the wild (+2), and FIRST's model says there
is a 94% chance of exploitation attempt in the next 30 days (+1).

The zero-day ICS-ZD-2026-003 scores 12.2 with no KEV and no EPSS because you
assessed it as a safety hazard (+3) with low complexity (+2), and your CVSS is
8.2, that alone is enough to push it to DISCLOSE NOW.

Score thresholds for example:

| Score | Decision                | Deadline |
|-------|-------------------------|----------|
| ≥ 9   | DISCLOSE NOW            | 30 days  |
| 7–8.9 | DISCLOSE WITHIN 60 DAYS | 60 days  |
| 4–6.9 | DISCLOSE WITHIN 90 DAYS | 90 days  |
| > 0   | MONITOR                 | —        |
| 0     | MANUAL REVIEW           | —        |

## 6. Check the other two events

Go back to the event list. Open the ABB and Siemens events and read their
triage summaries the same way.

ABB RTU560, two findings:
- ICS-ZD-2026-001: command injection, zero-day, CVSS 9.1 from your findings,
  low complexity, process halt, PoC ready → DISCLOSE NOW
- CVE-2025-44210: IEC 60870-5-104 buffer overflow, but `disclosure_status` is
  `public` → the triage summary says ALREADY PUBLIC. This one is in the
  NVD. Your job here is to confirm the device is patched, not to disclose.

Siemens SCALANCE X308-2, two findings:
- CVE-2023-44317: authentication bypass, CVSS 9.8, internet-exposed, safety
  hazard. High score. Check the summary for the decision.
- ICS-ZD-2026-002: SNMP heap corruption, zero-day, CVSS 7.5, internal
  network, no PoC. Will land in DISCLOSE WITHIN 60 DAYS.

## 7. Get the disclosure drafts

Go back to Shuffle at http://localhost:3001. Open the triage workflow run. Click
`act_triage`.

In the output JSON, find `disclosure_drafts`. For every finding that scored
DISCLOSE NOW or DISCLOSE WITHIN 60 DAYS, there is a draft containing:

- `to`, the vendor PSIRT address
- `cc`, national CERT (based on vendor country) + VDE CERT as ICS coordinator
- `subject`, ready-to-use subject line
- `body`, draft email with ENISA CVD framework reference, finding summary,
  and deadline date

For Schneider Electric (French vendor), the national CERT in CC is CERT-FR.
For Siemens (German vendor), it is BSI. For ABB (Swiss-Swedish), it is
NCSC-CH.

For zero-days without a CVE, the draft notes that no CVE is assigned yet and
uses your internal research ID. The vendor will request a CVE through their
PSIRT or through MITRE after they confirm the finding.

Copy the draft. Edit it, add your contact details and any attachments (PoC
code, packet captures, crash logs). Send it.

See [contacts.md](contacts.md) for a PSIRT and national CERT directory.

## 8. What stays in MISP

The three events that were created are the audit trail. They record:

- What firmware was analysed and when
- What was found, in structured MISP objects
- What the public CVE record said at the time of triage
- What KEV and EPSS said at the time of triage
- What decision can be made and why

When the vendor responds, update the event. When a CVE is assigned to a
zero-day, add a `vulnerability` attribute with the CVE ID and run enrichment
again. When a patch ships, tag the event with the patch version.

The disclosure deadline clock starts when running step 2.
