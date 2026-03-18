# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A single-file Python CLI tool that integrates **Veeam Backup & Replication** with a security scanner. It publishes Veeam restore points via the Data Integration API, mounts them, runs the chosen scanner inside a Docker container, then unpublishes.

Supported scanners:
- **THOR / THOR Lite** (Nextron Systems) — APT/malware detection
- **PyrsistenceSniper** — Windows persistence mechanism detection

## Setup Requirements

- Linux host (tested Ubuntu 24.04), Python 3.x, Docker
- Python dependencies: `pip install requests python-dotenv`
- Veeam B&R server v12.3.2+ with API accessible on port 9419
- Copy `.env.example` to `.env` and fill in all values

## Configuration (.env)

```
VBR_URL=https://<vbr-server>:9419
VBR_API_VERSION=1.2-rev1
VBR_USERNAME=Administrator
VBR_PASSWORD=your-password-here
RESULTS_DIR=/tmp/output
```

The scanner is chosen per-run via `--dockerimage`, not in `.env`.

## Build Docker Images

```bash
# THOR Lite (default binary name)
docker build -f Dockerfile.thor -t thor-lite .

# Full THOR (different binary)
docker build -f Dockerfile.thor --build-arg THOR_BIN=thor-linux-64 -t thor .

# PyrsistenceSniper
docker build -f Dockerfile.pyrsistencesniper -t pyrsistencesniper .
```

## Run

```bash
# Interactive – choose restore point, default scanner (thor-lite)
./thor-scanner.py --host2scan Server01

# Explicit scanner selection
./thor-scanner.py --host2scan Server01 --dockerimage pyrsistencesniper

# Automated – use latest restore point (suitable for cron)
./thor-scanner.py --host2scan Server01 --latest --dockerimage thor
```

`--dockerimage` accepts: `thor`, `thor-lite` (default), `pyrsistencesniper`

No test suite or linter configuration exists in this project.

## Architecture

`thor-scanner.py` is a single-file script with a linear workflow orchestrated by `main()`:

1. **Config** — loads `.env` at startup; exits early if required vars are missing
2. **Auth** — `obtain_bearer_token()` authenticates via OAuth2 password grant
3. **Query** — fetches restore points for the target host via REST GET
4. **Select** — `select_restore_point()` prompts interactively (SIGALRM timeout) or picks latest
5. **Publish** — POSTs to the Data Integration API to mount the restore point
6. **Scan** — `trigger_scan()` dispatches the correct Docker command based on `DOCKER_IMAGE`
7. **Cleanup** — unpublishes the restore point and calls `api_logout()`

### Scanner dispatch in `trigger_scan()`

| `DOCKER_IMAGE` | Mount inside container | Output path inside container |
|---|---|---|
| `thor` / `thor-lite` | `/data` (rw) | `/thor/output` → `RESULTS_DIR` on host |
| `pyrsistencesniper` | `/evidence` (ro) | `/output` → `RESULTS_DIR` on host |

TLS verification is intentionally disabled for the Veeam API connection (self-signed certs common in backup environments).
