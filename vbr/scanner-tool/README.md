# Veeam Restore Point Scanner

## Version Information
~~~~
Version: 1.2 (March 18, 2026)
Requires: Veeam Backup & Replication v12.3.2 & Linux & Python 3.x
Author: Stephan "Steve" Herzig
~~~~

## Overview
This script publishes a restore point using the **Veeam Data Integration API**, mounts it on the scan host, runs the chosen security scanner inside a Docker container, then unpublishes the restore point.

Supported scanners:
- **THOR / THOR Lite** (Nextron Systems) — APT/malware detection
- **PyrsistenceSniper** — Windows persistence mechanism detection

## Requirements
- Linux host with Python 3.x
- Python modules: `requests`, `python-dotenv`, `cryptography`
- Veeam Backup & Replication server v12.3.2+
- Docker installed and the relevant Docker image built on the scan host

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```ini
VBR_URL=https://<vbr-server>:9419
VBR_API_VERSION=1.2-rev1
VBR_USERNAME=Administrator
VBR_PASSWORD=<encrypted-password>
VBR_KEY_FILE=/root/.vbr.key
RESULTS_DIR=/tmp/output
```

All credentials are read from `.env` at startup. The script exits immediately if `VBR_URL`, `VBR_USERNAME`, or `VBR_PASSWORD` are missing.

### Encrypting the password

The password in `.env` is stored Fernet-encrypted. Use the included helper to generate the key and encrypted password:

```bash
python3 encrypt-password.py
```

This will:
1. Generate a Fernet key and save it to `vbr.key`
2. Prompt for the VBR password and print the encrypted value
3. Show the two lines to add to `.env`

Then move the key file to a secure location:

```bash
sudo mv vbr.key /root/.vbr.key
sudo chmod 600 /root/.vbr.key
```

The key file and the `.env` should be stored separately — an attacker needs both to decrypt the password.

## Build Docker Images

The Dockerfile(s) and scanner binaries/licenses must reside in the same folder.

```bash
# THOR Lite (default binary name)
docker build -f Dockerfile.thor -t thor-lite .

# Full THOR (different binary name)
docker build -f Dockerfile.thor --build-arg THOR_BIN=thor-linux-64 -t thor .

# PyrsistenceSniper
docker build -f Dockerfile.pyrsistencesniper -t pyrsistencesniper .
```

## Usage

Make the script executable:

```bash
chmod +x scanner-tool.py
```

### Parameters

| Parameter | Required | Description |
|---|---|---|
| `--host2scan <HOSTNAME>` | Yes | Hostname whose restore points should be scanned |
| `--latest` | No | Skip the selection menu and use the newest restore point (suitable for cron) |
| `--dockerimage <IMAGE>` | No | Scanner to use: `thor`, `thor-lite` (default), or `pyrsistencesniper` |

### Examples

```bash
# Interactive – choose restore point, default scanner (thor-lite)
./scanner-tool.py --host2scan Server01

# Automated – latest restore point with full THOR
./scanner-tool.py --host2scan Server01 --latest --dockerimage thor

# PyrsistenceSniper scan
./scanner-tool.py --host2scan Server01 --dockerimage pyrsistencesniper
```

## Output

Scan results are written to the directory configured as `RESULTS_DIR` in `.env` (default: `/tmp/output`).

| Scanner | Output file pattern |
|---|---|
| `thor` / `thor-lite` | `<hostname>_thor_<timestamp>.html` |
| `pyrsistencesniper` | `<hostname>_pyrsistencesniper_<timestamp>.html` |

## Notes
- Tested on Ubuntu 24.04
- TLS verification is disabled for the Veeam API connection (self-signed certificates are common in backup environments)
- Each scan runs inside an isolated Docker container — multiple jobs can run in parallel without interfering with each other or the host system

## What is THOR?
Nextron Systems specializes in forensic threat detection. THOR is widely used by incident response and security teams to uncover attacker tools and traces that traditional solutions may miss.
Unlike classic antivirus integrations, THOR detects webshells, obfuscated scripts, malicious configurations, and backdoors — the kinds of artefacts that advanced attackers often leave behind. It also parses system artefacts such as Windows Registry hives and Event Logs with dedicated forensic modules, making it an effective complement to existing AV solutions within the Veeam ecosystem.

## Version History
- 1.2 (Mar 18, 2026)
  - Added PyrsistenceSniper scanner support
  - Replaced hardcoded credentials with `.env`-based configuration
  - Password stored Fernet-encrypted; key file kept separately
  - Added `encrypt-password.py` helper for one-time setup
  - Added `--dockerimage` CLI flag for per-run scanner selection
  - Multi-scanner Dockerfile support (`Dockerfile.thor`, `Dockerfile.pyrsistencesniper`)
- 1.1 (Oct 7, 2025)
  - Code review and improvements by Lumo
- 1.0 (Sep 26, 2025)
  - Initial version

## Disclaimer

This script is not officially supported by Veeam Software. Use it at your own risk.
