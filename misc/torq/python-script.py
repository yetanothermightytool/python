#!/usr/bin/env python3
"""
RestoreIQ scoring logic for a Torq "Run an inline Python script" step.
Pure functions only, no httpx / html / file output. Feed it Veeam restore
points + malware events (fetched by Torq's native Veeam B&R steps), get
back a scored, sorted JSON summary per workload (VM, physical host, or
NFS/SMB share) on stdout.

Torq wiring:
1. Fetch restore points with the Veeam "List Restore Points" step.
2. Fetch malware events with the Veeam "List Malware Detection Events" step.
3. Drop this script into a Python step, replace the two INPUT lines below
   with the actual $. references to those two steps.
4. Downstream, read $.<this_step_name>.stdout and branch on "status".
"""

import json
from datetime import datetime, timezone

# ── INPUT ────────────────────────────────────────────────────────────────
# Torq wraps native step responses under api_object. Raw strings (r'''...''')
# are required here, otherwise Python un-escapes the backslashes in Windows
# paths before json.loads() sees them, and parsing breaks.
restore_points = json.loads(r'''{{ $.list_restore_points.api_object.data }}''')
malware_events = json.loads(r'''{{ $.list_malware_events.api_object.data }}''')

threshold = 70
preferred_repos = []  # optional: ["repo-gold"] per host

_MALWARE_SCORES = {"Clean": 60, "Informative": 30, "Suspicious": 0, "Infected": 0}


def score_restore_point(point, all_points, now, preferred_repos=None):
    malware_score = _MALWARE_SCORES.get(point.get("malwareStatus") or "", 15)

    rp_time = datetime.fromisoformat(point["creationTime"].replace("Z", "+00:00"))
    age_hours = (now - rp_time).total_seconds() / 3600
    if age_hours >= 24:
        margin_score = 25
    elif age_hours >= 12:
        margin_score = 20
    elif age_hours >= 4:
        margin_score = 12
    elif age_hours >= 1:
        margin_score = 5
    else:
        margin_score = 0

    newer = [p for p in all_points
             if datetime.fromisoformat(p["creationTime"].replace("Z", "+00:00")) > rp_time]
    infected = [p for p in newer if p.get("malwareStatus") == "Infected"]
    suspicious_rps = [p for p in newer if p.get("malwareStatus") == "Suspicious"]

    if not infected and not suspicious_rps:
        neighbor_score = 15
    else:
        direct = min(newer, key=lambda p: datetime.fromisoformat(p["creationTime"].replace("Z", "+00:00"))) if newer else None
        if len(infected) >= 2 or (infected and suspicious_rps):
            neighbor_score = -30
        elif direct and direct.get("malwareStatus") == "Infected":
            neighbor_score = -20
        elif infected:
            neighbor_score = -10
        elif direct and direct.get("malwareStatus") == "Suspicious":
            neighbor_score = -10
        else:
            neighbor_score = -5

    repo_score = 0
    rp_repo = point.get("repositoryName") or ""
    if preferred_repos and rp_repo and any(r.lower() in rp_repo.lower() for r in preferred_repos):
        repo_score = 10

    return max(0, min(100, malware_score + margin_score + neighbor_score + repo_score))


def compute_summary(workload, rps, events, now, threshold, preferred_repos=None):
    if not rps:
        return {"workload": workload, "status": "no_data", "best_score": None,
                "best_rp_time": None, "best_malware": None,
                "event_count": len(events)}

    # Malware status is the only universal eligibility signal, works for
    # VMs, physical hosts, and unstructured data (NFS/SMB) restore points
    # alike. allowedOperations gates like StartViVMInstantRecovery only
    # exist for VM platforms and would wrongly exclude everything else.
    selectable = [p for p in rps if p.get("malwareStatus") not in ("Infected", "Suspicious")]

    if selectable:
        scored = sorted(((p, score_restore_point(p, rps, now, preferred_repos)) for p in selectable),
                         key=lambda x: x[1], reverse=True)
        best_rp, best_score = scored[0]
    else:
        best_rp = max(rps, key=lambda p: p["creationTime"])
        best_score = score_restore_point(best_rp, rps, now, preferred_repos)

    statuses = [p.get("malwareStatus") for p in rps]
    if "Infected" in statuses:
        status = "infected"
    elif "Suspicious" in statuses or len(events) > 0:
        status = "suspicious"
    elif best_score >= threshold:
        status = "clean"
    else:
        status = "low_confidence"

    return {"workload": workload, "status": status, "best_score": best_score,
            "best_rp_time": best_rp["creationTime"],
            "best_malware": best_rp.get("malwareStatus"),
            "event_count": len(events)}


# ── Run ──────────────────────────────────────────────────────────────────
now = datetime.now(timezone.utc)

grouped = {}
for rp in restore_points:
    grouped.setdefault(rp["name"], []).append(rp)

events_by_workload = {}
for ev in malware_events:
    name = (ev.get("machine") or {}).get("displayName")
    if name:
        events_by_workload.setdefault(name, []).append(ev)

order = {"infected": 0, "suspicious": 1, "low_confidence": 2, "clean": 3, "no_data": 4}
summaries = [
    compute_summary(name, rps, events_by_workload.get(name, []), now, threshold, preferred_repos)
    for name, rps in grouped.items()
]
summaries.sort(key=lambda s: (order.get(s["status"], 9), s["workload"]))

print(json.dumps(summaries))
