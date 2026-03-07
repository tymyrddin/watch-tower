# OT/ICS Threat Intelligence Lab

Local threat intelligence lab for ICS/OT firmware vulnerability research.

```
firmware lab findings
        ↓
ingestion/ingest_findings.py
        ↓
Shuffle webhook
        ↓
MISP event + enrichment (cve module → CIRCL + CWE)
        ↓
CISA KEV  ·  EPSS  ·  ICS triage scoring
        ↓
analyst review in MISP + ENISA CVD disclosure drafts
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

MISP core + MySQL + OpenSearch are the heavy consumers. If Docker Desktop is
used, set its memory limit to at least 8 GB in Settings → Resources.

## Quick start

```bash
cp .env.example .env   # edit: change all passwords
make start             # pull images and start all services
```

*Note on `make start` output: Docker Compose uses an animated progress bar that re-renders in place using terminal escape codes. Each refresh prints as a new line in some terminals, which looks like a loop but is not. The actual container status is printed at the end.*

```bash
make init              # configure MISP, import Shuffle workflows
```

*Note on first boot: `make init` waits automatically until MISP is ready before proceeding. On a fresh volume this can take 3-5 minutes while MISP runs database migrations and seeds default data.*

## Usage

```bash
# Import the built-in example into MISP
bash scripts/import.sh --example

# Import your own findings
bash scripts/import.sh --file findings.json

# Run triage on all events in MISP
bash scripts/triage.sh
```

The import script normalises findings and posts them to Shuffle. One MISP event
per firmware image is created, with enriched vulnerability objects. Triage reads
all events and writes scored summaries back to each event.

See [docs/schema.md](docs/schema.md) for the input format.

## Useful commands

```bash
# Logs
docker compose logs -f misp-core
docker compose logs -f shuffle-backend

# Get MISP API key
bash scripts/get-misp-key.sh

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

## License

MIT