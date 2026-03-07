# Input schema

The webhook accepts a firmware vulnerability research batch.
One event is created in MISP per firmware entry.

## Top-level structure

```
{
  "research_batch": { ... },
  "firmware": [ ... ]
}
```

## Research batch

| Field        | Type       | Description                              |
|--------------|------------|------------------------------------------|
| `lab`        | string     | Lab or team name                         |
| `date`       | YYYY-MM-DD | Assessment date                          |
| `researcher` | string     | Lead researcher                          |
| `toolchain`  | string     | Tools used (binwalk, ghidra, fuzzing, …) |

## Firmware 

One object per firmware image analysed.

| Field             | Type   | Description                            |
|-------------------|--------|----------------------------------------|
| `vendor`          | string | Device manufacturer                    |
| `product`         | string | Product name / model                   |
| `version`         | string | Firmware version string                |
| `architecture`    | string | CPU architecture (armv7, x86, mips, …) |
| `firmware_file`   | string | Filename of the firmware image         |
| `firmware_sha256` | string | SHA-256 of the firmware image          |
| `vulnerabilities` | array  | See below                              |

## Vulnerabilities 

One object per vulnerability found in that firmware.
A vulnerability can be a known CVE or a zero-day with an internal ID.

### Identity

| Field               | Type           | Description                                                  |
|---------------------|----------------|--------------------------------------------------------------|
| `research_id`       | string         | Internal ID, use `ICS-ZD-YYYY-NNN` or `FW-<vendor>-YYYY-NNN` |
| `cve`               | string \| null | CVE ID if assigned; `null` for zero-days                     |
| `title`             | string         | Short description                                            |
| `description`       | string         | Full technical description                                   |
| `vuln_class`        | string         | E.g. `command injection`, `buffer overflow`                  |
| `cwe`               | string         | CWE code (e.g. `CWE-78`)                                     |
| `disclosure_status` | string         | `private`, `coordinated`, or `public`                        |

### Scoring

| Field                     | Type          | Description                                                     |
|---------------------------|---------------|-----------------------------------------------------------------|
| `cvss_score`              | float \| null | Self-assessed CVSS. If null and `cve` is set, CIRCL is queried. |
| `exploit_complexity`      | string        | `low`, `medium`, or `high`                                      |
| `attack_vector`           | string        | `network`, `local`, `physical`                                  |
| `authentication_required` | boolean       |                                                                 |
| `poc_available`           | boolean       | Proof-of-concept exists                                         |

### ICS-specific

| Field                 | Type   | Description                                                   |
|-----------------------|--------|---------------------------------------------------------------|
| `operational_impact`  | string | `none`, `service disruption`, `process halt`, `safety hazard` |
| `affected_subsystem`  | string | E.g. `RTU controller`, `Modbus TCP stack`                     |
| `exposure`            | string | `internet`, `internal network`, `vpn only`, `serial port`     |
| `trigger_mechanism`   | string | How the vulnerability is triggered                            |
| `required_privileges` | string | `none`, `user`, `admin`                                       |
| `required_conditions` | string | E.g. `device in maintenance mode`                             |
| `prerequisite`        | string | Any other required precondition                               |

### Artefact

| Field             | Type            | Description                                              |
|-------------------|-----------------|----------------------------------------------------------|
| `affected_binary` | string          | Full path inside firmware (e.g. `/usr/bin/update_agent`) |
| `binary_sha256`   | string          | SHA-256 of the binary                                    |
| `trigger_port`    | integer \| null | Network port (e.g. `502` for Modbus)                     |

## Example

```json
{
  "research_batch": {
    "lab": "ICS Firmware Lab",
    "date": "2026-03-06",
    "researcher": "Nina",
    "toolchain": "binwalk + ghidra + fuzzing"
  },
  "firmware": [
    {
      "vendor": "Acme",
      "product": "RTU-500",
      "version": "1.3.7",
      "architecture": "armv7",
      "firmware_file": "rtu500_fw_1.3.7.bin",
      "firmware_sha256": "3c4a9c1f...",
      "vulnerabilities": [
        {
          "research_id": "ICS-ZD-2026-001",
          "cve": null,
          "title": "Unauthenticated command execution in update service",
          "description": "Update agent passes unsanitised parameters to a shell command.",
          "vuln_class": "command injection",
          "cwe": "CWE-78",
          "cvss_score": 9.1,
          "exploit_complexity": "low",
          "attack_vector": "network",
          "authentication_required": false,
          "poc_available": true,
          "disclosure_status": "private",
          "operational_impact": "process halt",
          "affected_subsystem": "firmware update service",
          "exposure": "internal network",
          "trigger_mechanism": "malformed update packet",
          "required_privileges": "none",
          "required_conditions": "device reachable on LAN",
          "prerequisite": "none",
          "affected_binary": "/usr/bin/update_agent",
          "binary_sha256": "81e22c2a...",
          "trigger_port": 8080
        },
        {
          "research_id": "CVE-2025-44210",
          "cve": "CVE-2025-44210",
          "title": "Buffer overflow in Modbus handler",
          "description": "",
          "vuln_class": "buffer overflow",
          "cwe": "CWE-120",
          "cvss_score": null,
          "exploit_complexity": "medium",
          "attack_vector": "network",
          "authentication_required": false,
          "poc_available": false,
          "disclosure_status": "public",
          "operational_impact": "service disruption",
          "affected_subsystem": "Modbus TCP stack",
          "exposure": "internal network",
          "trigger_mechanism": "malformed Modbus packet",
          "required_privileges": "none",
          "required_conditions": "",
          "prerequisite": "",
          "affected_binary": "/usr/bin/modbusd",
          "binary_sha256": "",
          "trigger_port": 502
        }
      ]
    }
  ]
}
```