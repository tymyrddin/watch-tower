# Field → MISP object mapping

One MISP event is created per firmware entry. Objects and attributes are attached to that event.

## Event

| Source field                     | MISP field                                                                         |
|----------------------------------|------------------------------------------------------------------------------------|
| `vendor` + `product` + `version` | Event `info` (`"Firmware research -- <vendor> <product> <version>"`)               |
| Max CVSS in firmware             | `threat_level_id` (1 = High if ≥9, 2 = Medium if ≥7, 3 = Low if ≥4, 4 = Undefined) |
| —                                | `distribution`: 0 (Your organisation only)                                         |
| —                                | `analysis`: 1 (Ongoing)                                                            |

## Software object (one per firmware)

MISP object template: `software`

| Source field   | object_relation |
|----------------|-----------------|
| `vendor`       | `vendor`        |
| `product`      | `product`       |
| `version`      | `version`       |
| `architecture` | `architecture`  |

## Firmware artefact attributes (loose, on the event)

| Source field      | MISP attribute type |          Category |
|-------------------|---------------------|------------------:|
| `firmware_sha256` | `sha256`            | Artifacts dropped |
| `firmware_file`   | `filename`          | Artifacts dropped |

## Vulnerability object (one per vulnerability)

MISP object template: `vulnerability`

| Source field             | object_relation      | Notes                                               |
|--------------------------|----------------------|-----------------------------------------------------|
| `research_id` or `cve`   | `id`                 |                                                     |
| `title` or CIRCL summary | `summary`            | CIRCL summary used if title is empty and CVE is set |
| `description`            | `description`        |                                                     |
| `cvss_score`             | `cvss-score`         | Filled from CIRCL if null and CVE is set            |
| `cwe`                    | `cwe`                | Filled from CIRCL if empty and CVE is set           |
| `cve`                    | `cve`                | Empty string for zero-days                          |
| `disclosure_status`      | `state`              |                                                     |
| `exploit_complexity`     | `exploit-complexity` | Custom ICS extension                                |
| `operational_impact`     | `operational-impact` | Custom ICS extension                                |
| `exposure`               | `exposure`           | Custom ICS extension                                |
| `trigger_mechanism`      | `trigger-mechanism`  | Custom ICS extension                                |

## File object (one per vulnerability with affected_binary)

MISP object template: `file`

| Source field      | object_relation |
|-------------------|-----------------|
| `affected_binary` | `path`          |
| `binary_sha256`   | `sha256`        |

## Port attribute (one per vulnerability with trigger_port)

| Source field   | MISP attribute type |         Category |
|----------------|---------------------|-----------------:|
| `trigger_port` | `port`              | Network activity |

## Notes

- Objects with all-empty attributes are skipped silently.
- MISP distribution is set to 0 (internal only). Change `distribution` in `misp_create_event()` to share events with communities.
- MISP analysis is set to 1 (Ongoing). Change to 2 (Completed) once disclosure is done.
- The ICS-specific object_relation values (`exploit-complexity`, `operational-impact`, `exposure`, `trigger-mechanism`) are custom extensions not in the default MISP `vulnerability` template. They are stored as free-text attributes and will appear under the object even without a matching template.