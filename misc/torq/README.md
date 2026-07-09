# RestoreIQ – Torq Automation

Automated Veeam restore point risk scoring, ported from [RestoreIQ](https://github.com/yetanothermightytool/python/tree/main/vbr/RestoreIQ) into a native Torq workflow (Veeam connector steps + inline Python scoring, no HTML report).

## What it does

Pulls restore points for all protected workloads (VMs, physical hosts, NFS/SMB shares) from Veeam Backup & Replication, cross-references them with Veeam's malware detection events, and scores every restore point on how safe it is to recover from. The result is a status per workload: `clean`, `suspicious`, `infected`, `low_confidence`, or `no_data`, ready for downstream branching (case creation, alerting, review queues).

## Flow

1. **List Restore Points** (Veeam step) – all restore points, last N days
2. **List Malware Detection Events** (Veeam step) – malware events, last N days
3. **Python step** – scores each restore point, groups by workload, returns a sorted JSON array
4. Downstream: loop over the array, branch on `status`

## Confidence score (0–100)

| Component | Range | Logic |
|---|---|---|
| Malware Status | 0–60 | Clean=60, Informative=30, Unknown=15, Suspicious/Infected=0 |
| Safety Margin | 0–25 | Age of restore point: ≥24h→25, ≥12h→20, ≥4h→12, ≥1h→5, <1h→0 |
| Neighbor Contamination | −30–+15 | Infection state of newer restore points on the same workload |
| Repository Bonus | 0–+10 | +10 if in a preferred repository (optional, off by default) |

## Workload status

| Status | Condition |
|---|---|
| `clean` | Best score ≥ threshold (default 70), no infected/suspicious restore points, no malware events |
| `suspicious` | At least one suspicious restore point or malware event in the lookback window |
| `infected` | At least one restore point marked Infected |
| `low_confidence` | Best score below threshold, no infected/suspicious restore points |
| `no_data` | No restore points found for this workload |

## Output (per entry)

```json
{
  "workload": "string",
  "status": "clean | suspicious | infected | low_confidence | no_data",
  "best_score": 0,
  "best_rp_time": "ISO timestamp",
  "best_malware": "Clean | Informative | Suspicious | Infected",
  "event_count": 0
}
```

## Notes

- "Workload" covers VMs, physical hosts, and unstructured data (NFS/SMB) restore points alike, eligibility is based purely on malware status, not VM-only operations like Instant Recovery.
- Threshold and repository bonus are configurable in the Python step.

## Disclaimer
This script is not officially supported by Veeam Software. Use it at your own risk.
