#!/usr/bin/env python3
"""
RestoreIQ scoring logic for a Torq "Run an inline Python script" step.
Pure functions only, no httpx / html / file output. Feed it Veeam restore
points + malware events (fetched by Torq's native Veeam B&R steps), get
back a scored, sorted JSON summary per VM on stdout.

Torq wiring:
1. Fetch restore points with the Veeam "List Restore Points" step.
2. Fetch malware events with the Veeam "List Malware Detection Events" step.
3. Drop this script into a Python step, replace the three INPUT lines below
   with the actual $. references to those two steps (and workflow params).
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


def compute_summary(vm, rps, events, now, threshold, preferred_repos=None):
    if not rps:
        return {"vm": vm, "status": "no_data", "best_score": None,
                "best_rp_time": None, "best_malware": None,
                "event_count": len(events)}

    selectable = [p for p in rps
                  if "StartViVMInstantRecovery" in p.get("allowedOperations", [])
                  and p.get("malwareStatus") not in ("Infected", "Suspicious")]

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

    return {"vm": vm, "status": status, "best_score": best_score,
            "best_rp_time": best_rp["creationTime"],
            "best_malware": best_rp.get("malwareStatus"),
            "event_count": len(events)}


# ── Run ──────────────────────────────────────────────────────────────────
now = datetime.now(timezone.utc)

grouped = {}
for rp in restore_points:
    grouped.setdefault(rp["name"], []).append(rp)

events_by_vm = {}
for ev in malware_events:
    vm_name = (ev.get("machine") or {}).get("displayName")
    if vm_name:
        events_by_vm.setdefault(vm_name, []).append(ev)

order = {"infected": 0, "suspicious": 1, "low_confidence": 2, "clean": 3, "no_data": 4}
summaries = [
    compute_summary(vm, rps, events_by_vm.get(vm, []), now, threshold, preferred_repos)
    for vm, rps in grouped.items()
]
summaries.sort(key=lambda s: (order.get(s["status"], 9), s["vm"]))

print(json.dumps(summaries))
