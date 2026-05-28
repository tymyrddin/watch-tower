# Watch Tower

The Watch Tower does not look for threats. It takes findings that have already been made, enriches them with threat context, scores them against what is known to be actively exploited, and produces intelligence that tells an analyst whether a vulnerability is theoretical or immediately relevant.

It is an intelligence platform for industrial control systems and embedded infrastructure. Findings arrive as structured data. By the time they reach an analyst, each carries a risk score, exploitation context, and a MISP event record linking it to the broader threat picture. The platform does not make decisions. It produces scored, contextualised intelligence and puts it in front of a person who does.

```
firmware vulnerability findings
        ↓
ingestion (webhook or JSON import)
        ↓
MISP event creation  ·  Shuffle orchestrator
        ↓
CVE enrichment (CIRCL CVE Search – local corpus)
        ↓
CISA KEV check  ·  EPSS scoring
        ↓
analyst review and determination
```

Stack: MISP + Shuffle (SOAR) + CIRCL CVE Search + CISA KEV + EPSS

## Requirements

- Docker + Docker Compose
- Ports 8080 (MISP) and 3001 / 5001 (Shuffle) free

Minimum hardware (all services combined):

| Resource | Minimum                   | Recommended |
|----------|---------------------------|-------------|
| RAM      | 8 GB available to Docker  | 16 GB       |
| CPU      | 4 cores                   | 8 cores     |
| Disk     | 20 GB free                | 40 GB       |

MISP core + MySQL + OpenSearch are the heavy consumers. If Docker Desktop is used, set its memory limit to at least 8 GB in Settings → Resources.

## Quick start

```bash
cp .env.example .env   # edit: change all passwords
make start             # pull images and start all services
```

*Note on `make start` output: Docker Compose uses an animated progress bar that re-renders in place using terminal escape codes. Each refresh prints as a new line in some terminals, which looks like a loop but is not. The actual container status is printed at the end.*

```bash
make init              # configure MISP, import Shuffle workflows, download CVE corpus
```

*Note on first boot: `make init` waits automatically until MISP is ready before proceeding. On a fresh volume this can take 3-5 minutes while MISP runs database migrations and seeds default data. The CVE corpus download adds further time on first run; subsequent starts skip it.*

## Usage

```bash
# Import the built-in examples and verify the pipeline end-to-end
make import-examples

# Import your own findings
make import FILE=path/to/findings.json

# Scored summary of all pending events, ordered by composite risk score
make triage
```

The import pipeline is idempotent: importing the same finding twice produces one MISP event, not two.

Findings are normalised and posted to Shuffle. One MISP event per firmware image is created, enriched with CVE data, checked against the CISA KEV catalogue, and scored with EPSS. Triage reads all pending events and writes scored summaries back for analyst review.

See [docs/schema.md](docs/schema.md) for the input format.

## Analyst triage

Each enriched MISP event carries: the original finding, CVE data (CVSS score and vector, affected versions, NVD references), KEV status (whether CISA has confirmed active exploitation), and EPSS score (probability of exploitation in the next 30 days).

A finding with a CVSS of 9.8, a KEV entry, and an EPSS above 0.5 is an immediate concern regardless of which device it affects. A finding with CVSS of 5.0, no KEV match, and EPSS below 0.1 warrants attention but not urgency.

Some considerations that consistently inform good triage decisions:

- **KEV match overrides CVSS arithmetic.** A medium-severity vulnerability being actively exploited is more dangerous than a critical-severity one with no observed exploitation.
- **EPSS is a probability estimate, not a verdict.** Whether a given score matters depends on how many devices run the affected firmware and what those devices do.
- **Device context is not in the platform.** The Watch Tower knows about vulnerabilities; it does not independently know whether a device is deployed in critical infrastructure. That context comes from the analyst.

Determination outcomes: no further action, notification (quiet disclosure to manufacturer, operator, or national CERT), or escalation. Every determination is recorded in the MISP event. The audit trail runs from the original finding through enrichment to the decision.

## Useful commands

```bash
# Logs
make logs
docker compose logs -f misp-core
docker compose logs -f shuffle-backend

# Get MISP API credentials
make creds

# Restart a service
docker compose restart misp-core

# Stop (volumes preserved)
make stop

# Wipe everything (removes volumes)
make clean
```

## Docs

| File                                               | Contents                                    |
|----------------------------------------------------|---------------------------------------------|
| [docs/walkthrough.md](docs/walkthrough.md)         | Triage walkthrough (usage)                  |
| [docs/getting-started.md](docs/getting-started.md) | Getting started with explainers             |
| [docs/schema.md](docs/schema.md)                   | Input JSON schema: all fields               |
| [docs/workflow.md](docs/workflow.md)               | Shuffle workflow: what it does              |
| [docs/triage.md](docs/triage.md)                   | ICS triage scoring and disclosure timelines |
| [docs/misp-mapping.md](docs/misp-mapping.md)       | Field → MISP object mapping                 |
| [docs/contacts.md](docs/contacts.md)               | EU PSIRTs, national CERTs, ICS coordinators |

## Stack

| Service          | Image                                          | Port     |
|------------------|------------------------------------------------|----------|
| MISP core        | `ghcr.io/misp/misp-docker/misp-core:latest`    | 8080     |
| MISP modules     | `ghcr.io/misp/misp-docker/misp-modules:latest` | internal |
| MySQL 8          | `mysql:8.0`                                    | internal |
| Redis 7          | `redis:7-alpine`                               | internal |
| Shuffle backend  | `ghcr.io/shuffle/shuffle-backend:latest`       | 5001     |
| Shuffle frontend | `ghcr.io/shuffle/shuffle-frontend:latest`      | 3001     |
| Shuffle Orborus  | `ghcr.io/shuffle/shuffle-orborus:latest`       | internal |
| OpenSearch 2.10  | `opensearchproject/opensearch:2.10.0`          | internal |

## Licence

[Unlicence](LICENCE)
