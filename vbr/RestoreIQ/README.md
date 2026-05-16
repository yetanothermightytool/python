# RestoreIQ

When a security incident hits, the question is not just *do we have a backup*  It is *which backup can we actually trust*. RestoreIQ answers that question before the pressure is on.

It connects to your Veeam Backup & Replication server, pulls restore points for all protected workloads across every platform, and cross-references them with Veeam's own malware detection events. Each restore point receives a confidence score that weighs its malware status, how far it sits from a potential infection window, whether neighboring restore points are already compromised, and whether it lives on a preferred repository. The result is a prioritised, at-a-glance HTML report that tells you which machines are clean and ready to recover, which need a closer look, and which are actively infected, before you start the restore.

 [![Open Live Demo](https://img.shields.io/badge/Preview-Live%20Demo-6366f1?style=for-the-badge)](https://htmlpreview.github.io/?https://github.com/yetanothermi
  ghtytool/python/blob/main/vbr/RestoreIQ/dashboard.html)

The report runs as a single self-contained HTML file with no external dependencies. Open it in any browser, toggle between dark and light mode, expand any row for the full restore point history and malware event timeline, and click the **?** icon for a full explanation of how the score is calculated.

## Features

- **Confidence score (0–100)** per restore point — malware status, safety margin, neighbor contamination, repository bonus
- **Malware event correlation** — cross-references `suspiciousActivityEvents` for each workload
- **All Veeam platforms** — VMware, Hyper-V, Cloud Director, Windows/Linux Physical, Unstructured Data
- **Repository bonus** — YAML config maps workloads/groups to preferred repositories
- **Per-workload error resilience** — one failed API call does not abort the report
- **Dark / Light mode** — persisted in browser localStorage
- **`--demo` mode** — no Veeam connection needed, built-in sample data

## Requirements

```
httpx
pyyaml        # optional — needed for --repo-config
python-dotenv # optional — auto-loads .env file
```

```bash
pip install httpx pyyaml python-dotenv
```

## Setup

Copy `sample.env` to `.env` and fill in your Veeam credentials:

```env
VEEAM_URL=https://veeam.corp.local:9419
VEEAM_USERNAME=administrator
VEEAM_PASSWORD=your-password-here
```

## Usage

```bash
# Demo — no Veeam connection required
./dashboard.py --demo

# Full report against live Veeam
./dashboard.py

# Single workload
./dashboard.py --hostname prod-db-01

# Custom lookback window and output file
./dashboard.py --days 14 --output report.html

# With repository bonus config
./dashboard.py --repo-config repo_config.yaml

# Self-signed certificate
./dashboard.py --no-ssl-verify

# All options
./dashboard.py --help
```

## Repository Bonus Config

Create a YAML file to assign preferred repositories per workload or group. Workloads with a restore point in a preferred repository receive +10 confidence points.

```yaml
groups:
  production:
    repos: [repo-gold, repo-offsite]
    hosts:
      - prod-db-01
      - prod-web-01

hosts:          # per-host override, takes precedence over group
  prod-db-01: [repo-gold-exclusive]
```

Matching is case-insensitive substring: `repo-gold` matches `Backup-Repo-Gold-01`.

## Confidence Score

| Component | Range | Details |
|---|---|---|
| Malware Status | 0 – 60 | Clean=60, Informative=30, Unknown=15, Suspicious/Infected=0 |
| Safety Margin | 0 – 25 | Time between restore point and now: ≥24h→25, ≥12h→20, ≥4h→12, ≥1h→5 |
| Neighbor Contamination | –30 – +15 | Infection state of newer restore points |
| Repository Bonus | 0 – +10 | Restore point in a preferred repository (`--repo-config`) |

Score colors: **green ≥ 70** (safe) · **orange 40–69** (review) · **red < 40** (high risk)

Click the **?** button next to "Confidence Score" in the report for the full breakdown.

