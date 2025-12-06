# RedFixer Design Document

**Date:** 2025-12-06
**Status:** Approved
**Author:** Collaborative design session

---

## Overview

**RedFixer** is a vulnerability assessment and remediation tool for RHEL9 environments. It takes RHSA or CVE identifiers as input, connects to target hosts via SSH, assesses exposure, and provides specific fix recommendations. An optional LLM-powered "hunt mode" searches for exploitation artifacts.

### Core Workflow

1. User provides RHSA ID or CVE ID
2. User optionally provides target hostname(s) via paste or file upload
3. RedFixer fetches vulnerability details from Red Hat Security Data API and Bugzilla
4. RedFixer connects to target hosts via Paramiko (SSH) to assess exposure
5. RedFixer reports affected packages/files and suggests specific fixes
6. Optional "hunt mode" uses LLM to search for exploitation artifacts

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        RedFixer                              │
├──────────────┬──────────────────┬───────────────────────────┤
│   Web UI     │      CLI         │         API               │
│  (React 19)  │   (Typer/Rich)   │      (FastAPI)            │
├──────────────┴──────────────────┴───────────────────────────┤
│                    Core Services                             │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │ VulnFetcher │ │ HostScanner │ │ HuntEngine  │            │
│  │ (RH APIs)   │ │ (Paramiko)  │ │ (LLM)       │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
├─────────────────────────────────────────────────────────────┤
│                    Data Layer (SQLite)                       │
└─────────────────────────────────────────────────────────────┘
```

---

## API Structure

**FastAPI Backend** - `/api/v1/`

### Vulnerability Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/vuln/lookup/{id}` | Fetch RHSA or CVE details from Red Hat APIs |
| GET | `/vuln/lookup/{id}/fixes` | Get fix recommendations for a vulnerability |

### Scan Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/scan/assess` | Run vulnerability assessment on hosts |
| GET | `/scan/assess/{scan_id}` | Get scan status/results |
| GET | `/scan/history` | List past scans |

**Request body for `/scan/assess`:**
```json
{
  "vuln_id": "RHSA-2024:1234",
  "hosts": ["server1.example.com", "server2.example.com"],
  "hunt_mode": false
}
```

### Host Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/hosts/validate` | Test SSH connectivity to hosts |
| POST | `/hosts/upload` | Upload hosts file, returns parsed list |

### Report Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/report/{scan_id}/json` | Results as JSON |
| GET | `/report/{scan_id}/csv` | Results as CSV |
| GET | `/report/{scan_id}/html` | Results as HTML report |

### Other
| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check endpoint |

**Authentication:** All endpoints require `X-API-Key` header.

---

## Core Services

### VulnFetcher Service

Retrieves vulnerability intelligence from external sources:

- Queries Red Hat Security Data API (`https://access.redhat.com/hydra/rest/securitydata/`)
- Queries Red Hat CVE database for CVE details
- Optionally queries Bugzilla for related bug info and workarounds
- Caches responses in SQLite to reduce API calls
- Supports optional Red Hat API credentials for higher rate limits

### HostScanner Service

Assesses target systems via Paramiko SSH:

- Checks installed RPM package versions against affected versions
- Checks if vulnerable packages are actually in use (process inspection)
- Identifies vulnerable config files or binaries mentioned in the advisory
- Compares kernel version for kernel-related CVEs
- Returns structured results: affected packages, current versions, fixed versions, severity

### HuntEngine Service

Optional LLM-powered artifact hunting:

- Reads CVE details and known exploitation patterns
- Generates targeted searches for:
  - Log entries (syslog, audit.log, secure, application logs)
  - Filesystem artifacts (webshells, backdoors, suspicious files)
  - Running processes and network connections
  - CVE-specific indicators of compromise
- Sends findings + context to configured LLM endpoint
- LLM returns analysis and confidence assessment

---

## CLI Interface

Built with **Typer + Rich** for beautiful terminal output. Shares Pydantic models with API.

```bash
# Basic vulnerability lookup
redfixer vuln lookup RHSA-2024:1234
redfixer vuln lookup CVE-2024-12345

# Assess hosts (paste inline or from file)
redfixer scan --vuln RHSA-2024:1234 --hosts server1.example.com,server2.example.com
redfixer scan --vuln CVE-2024-12345 --hosts-file /path/to/hosts.txt

# Enable hunt mode (LLM-powered artifact search)
redfixer scan --vuln RHSA-2024:1234 --hosts-file hosts.txt --hunt

# Output format options
redfixer scan --vuln RHSA-2024:1234 --hosts server1 --output json
redfixer scan --vuln RHSA-2024:1234 --hosts server1 --output csv
redfixer scan --vuln RHSA-2024:1234 --hosts server1 --report report.html

# Validate host connectivity
redfixer hosts validate server1.example.com,server2.example.com

# View past scans
redfixer history
redfixer history --scan-id abc123

# Configuration
redfixer config show
redfixer config set llm.provider ollama
redfixer config set llm.endpoint http://localhost:11434
```

**Output:** Rich tables with color-coded severity, progress bars during scans, spinners for API calls.

---

## Web Frontend

**React 19 + Vite + Tailwind CSS** with shadcn/ui components.

### Pages

1. **Dashboard** - Overview with recent scans, quick stats, quick-start scan form
2. **New Scan** - Main workflow:
   - Input field for RHSA/CVE ID with auto-validation
   - Textarea for pasting hostnames OR file upload button
   - Toggle switch for "Hunt Mode" (with warning about LLM usage)
   - "Run Scan" button with progress indicator
3. **Scan Results** - Detailed view:
   - Summary cards (hosts scanned, affected count, severity breakdown)
   - Table of hosts with status (affected/clean/error)
   - Expandable rows showing affected packages, versions, fix commands
   - Hunt mode findings in separate tab (if enabled)
   - Export buttons (JSON, CSV, HTML)
4. **History** - Paginated list of past scans with filters
5. **Settings** - API key display, LLM provider config, Red Hat credentials (optional)

**Responsive:** Works on desktop and tablet.

---

## Data Model

### Tables

**scans**
| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| vuln_id | string | RHSA-XXXX:XXXX or CVE-XXXX-XXXXX |
| vuln_title | string | Cached title from API |
| hunt_mode | boolean | Whether hunt mode was enabled |
| status | enum | pending, running, completed, failed |
| created_at | timestamp | |
| completed_at | timestamp | |

**scan_hosts**
| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| scan_id | UUID | Foreign key to scans |
| hostname | string | |
| status | enum | pending, scanning, affected, clean, error |
| error_message | string | Nullable |
| scanned_at | timestamp | |

**scan_findings**
| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| scan_host_id | UUID | Foreign key to scan_hosts |
| finding_type | enum | package, file, process, hunt_artifact |
| name | string | Package name, file path, etc. |
| current_value | string | Installed version, hash, etc. |
| expected_value | string | Fixed version, clean hash, etc. |
| severity | enum | critical, important, moderate, low |
| fix_command | string | Suggested remediation |
| details | JSON | Additional context |

**vuln_cache**
| Column | Type | Description |
|--------|------|-------------|
| vuln_id | string | Primary key |
| data | JSON | Cached API response |
| fetched_at | timestamp | |
| expires_at | timestamp | |

---

## Configuration

Location: `~/.redfixer/config.yaml` or `/etc/redfixer/config.yaml`

```yaml
# API Settings
api:
  host: 0.0.0.0
  port: 8000
  api_key: "your-secret-key-here"

# SSH Settings
ssh:
  user: root
  key_path: ~/.ssh/id_rsa
  timeout: 30

# Red Hat API (optional, for higher rate limits)
redhat:
  username: null
  password: null

# LLM Configuration
llm:
  provider: ollama  # ollama | uai_studio | openai | anthropic

  ollama:
    endpoint: http://localhost:11434
    model: llama3.1:8b

  uai_studio:
    endpoint: https://uai-studio.yourcompany.com/v1
    api_key: null
    model: gpt-4

  openai:
    api_key: null
    model: gpt-4-turbo

  anthropic:
    api_key: null
    model: claude-sonnet-4-20250514

# Database
database:
  path: ~/.redfixer/redfixer.db

# Cache
cache:
  vuln_ttl_hours: 24
```

---

## Deployment Options

### Option A: Python venv on RHEL9

```bash
# Install system dependencies
sudo dnf install python3.11 python3.11-pip python3.11-venv

# Create app directory
sudo mkdir -p /opt/redfixer
cd /opt/redfixer

# Create and activate venv
python3.11 -m venv venv
source venv/bin/activate

# Install RedFixer
pip install -e .

# Run API server
redfixer serve --host 0.0.0.0 --port 8000
```

### Option B: Podman Deployment

```bash
# Build container
podman build -t redfixer:latest .

# Run with mounted SSH keys and config
podman run -d \
  --name redfixer \
  -p 8000:8000 \
  -v ~/.ssh:/root/.ssh:ro \
  -v ~/.redfixer:/root/.redfixer \
  redfixer:latest

# Or use podman-compose
podman-compose up -d
```

### Option C: macOS (Apple Silicon) - Dev/Test

```bash
# Install Homebrew dependencies
brew install python@3.11 node ollama

# Create venv
python3.11 -m venv venv
source venv/bin/activate

# Install RedFixer
pip install -e .

# Run
redfixer serve --host 127.0.0.1 --port 8000
```

**Podman on macOS:**
```bash
brew install podman-desktop
podman machine init
podman machine start
podman run -d -p 8000:8000 -v ~/.ssh:/root/.ssh:ro redfixer:latest
```

### Systemd Units

Provided in `deploy/` directory for both venv and Podman deployments.

---

## Project Structure

```
redfixer/
├── backend/
│   ├── redfixer/
│   │   ├── __init__.py
│   │   ├── main.py              # FastAPI app entry point
│   │   ├── config.py            # Pydantic settings
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── routes/
│   │   │   │   ├── vuln.py
│   │   │   │   ├── scan.py
│   │   │   │   ├── hosts.py
│   │   │   │   └── report.py
│   │   │   └── deps.py
│   │   ├── services/
│   │   │   ├── vuln_fetcher.py
│   │   │   ├── host_scanner.py
│   │   │   ├── hunt_engine.py
│   │   │   └── report_gen.py
│   │   ├── llm/
│   │   │   ├── base.py
│   │   │   ├── ollama.py
│   │   │   ├── openai.py
│   │   │   ├── anthropic.py
│   │   │   └── uai_studio.py
│   │   ├── models/
│   │   │   ├── database.py
│   │   │   └── schemas.py
│   │   └── db/
│   │       ├── session.py
│   │       └── migrations/
│   ├── cli/
│   │   ├── __init__.py
│   │   └── main.py
│   ├── pyproject.toml
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   ├── components/
│   │   ├── pages/
│   │   ├── hooks/
│   │   ├── api/
│   │   └── lib/
│   ├── package.json
│   ├── vite.config.ts
│   └── tailwind.config.js
│
├── deploy/
│   ├── Containerfile
│   ├── podman-compose.yml
│   ├── redfixer.service
│   └── redfixer-podman.service
│
├── config/
│   └── config.example.yaml
│
├── scripts/
│   └── dev.sh
│
├── Makefile
├── .env.example
└── README.md
```

---

## Key Workflows

### Workflow 1: Basic Vulnerability Assessment

1. User submits: RHSA-2024:1234 + hosts [server1, server2]
2. VulnFetcher checks cache → miss → calls Red Hat Security Data API
3. API returns: affected packages (httpd < 2.4.57), severity, description, fix versions
4. For each host (parallel via asyncio):
   - Paramiko connects via SSH
   - Runs: `rpm -q httpd` → gets installed version
   - Compares: installed 2.4.51 < fixed 2.4.57 → AFFECTED
   - Generates fix: `dnf update httpd-2.4.57-1.el9`
5. Results saved to SQLite
6. Response returned with findings + fix commands

### Workflow 2: Hunt Mode (LLM-powered)

1. Basic assessment completes (as above)
2. If hunt_mode=true and host is affected:
   - VulnFetcher pulls CVE details, Bugzilla comments, known exploits
   - HuntEngine sends to LLM: "Given this CVE, what artifacts should we search for?"
   - LLM returns targeted checks (log patterns, file paths, process names)
   - For each check, Paramiko executes search on host
   - Findings sent back to LLM for analysis
   - LLM returns: "Found suspicious JNDI string in /var/log/app.log - HIGH confidence IOC"
3. Hunt findings added to scan results

### Workflow 3: Report Generation

1. User requests `/report/{scan_id}/html`
2. ReportGen loads scan + findings from SQLite
3. Renders Jinja2 template with:
   - Executive summary
   - Host-by-host breakdown
   - Severity chart
   - Fix commands (copy-paste ready)
   - Hunt findings (if applicable)
4. Returns styled HTML file

---

## Technology Stack

| Layer | Technology | Version |
|-------|------------|---------|
| Backend Framework | FastAPI | 0.115+ |
| Python | Python | 3.11+ |
| CLI Framework | Typer + Rich | latest |
| SSH Library | Paramiko | 3.x |
| Database | SQLite + SQLAlchemy | 2.x |
| Migrations | Alembic | latest |
| Validation | Pydantic | 2.x |
| HTTP Client | httpx | latest |
| Frontend Framework | React | 19.x |
| Build Tool | Vite | 6.x |
| CSS | Tailwind CSS | 4.x |
| Component Library | shadcn/ui | latest |
| LLM (default) | Ollama | latest |
| Container Runtime | Podman | latest |
| Target OS | RHEL 9, macOS (ARM64) | |

### External APIs

- Red Hat Security Data API (public, optional auth)
- Red Hat Bugzilla (public)
- LLM endpoint (configurable: Ollama, UAI Studio, OpenAI, Anthropic)

---

## Platform Compatibility

| Component | RHEL9 | macOS ARM64 | Notes |
|-----------|-------|-------------|-------|
| FastAPI | ✅ | ✅ | Pure Python |
| Paramiko | ✅ | ✅ | Pure Python |
| SQLite/SQLAlchemy | ✅ | ✅ | Pure Python |
| Typer/Rich | ✅ | ✅ | Pure Python |
| httpx | ✅ | ✅ | Pure Python |
| Pydantic | ✅ | ✅ | Pure Python |
| React/Vite/Node | ✅ | ✅ | Native ARM64 |
| Ollama | ✅ | ✅ | Native builds |
| Podman | ✅ | ✅ | Podman Desktop for Mac |

No native dependencies that would break on ARM64.
