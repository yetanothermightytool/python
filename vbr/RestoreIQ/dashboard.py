#!/usr/bin/env python3
"""
RestoreIQ — Veeam Restore Point Intelligence Dashboard

Fetches all workloads from Veeam B&R, correlates restore points with malware
detection events, scores each restore point, and writes an HTML report.

Usage:
    python dashboard.py [--hostname NAME] [--days N] [--demo] [--output FILE]
    python dashboard.py --demo                         # sample data, no API calls
    python dashboard.py --hostname prod-db-01          # single workload
    python dashboard.py --days 14 --output report.html

Required env vars (or .env file):
    VEEAM_URL             https://veeam.corp.local:9419
    VEEAM_USERNAME        administrator
    VEEAM_PASSWORD        secret

Optional env vars:
    VEEAM_API_VERSION     1.3-rev1 (default)
"""

import argparse
import asyncio
import html
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import httpx

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import yaml as _yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

VEEAM_API_VERSION = os.getenv("VEEAM_API_VERSION", "1.3-rev1")


# ── Veeam Client ──────────────────────────────────────────────────────────────

class VeeamClient:
    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = True):
        self._base = base_url.rstrip("/")
        self._username = username
        self._password = password
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None
        self._http = httpx.AsyncClient(verify=verify_ssl, timeout=30.0)

    async def _authenticate(self) -> None:
        r = await self._http.post(
            f"{self._base}/api/oauth2/token",
            data={
                "grant_type": "password",
                "username": self._username,
                "password": self._password,
                "use_short_term_refresh": "false",
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "x-api-version": VEEAM_API_VERSION,
            },
        )
        if r.status_code != 200:
            raise RuntimeError(f"Auth failed ({r.status_code}): {r.text}")
        data = r.json()
        self._token = data["access_token"]
        self._token_expiry = datetime.now(timezone.utc) + timedelta(
            seconds=data.get("expires_in", 3600) - 60
        )

    async def _headers(self) -> dict:
        if not self._token or datetime.now(timezone.utc) >= self._token_expiry:
            await self._authenticate()
        return {
            "Authorization": f"Bearer {self._token}",
            "x-api-version": VEEAM_API_VERSION,
            "Content-Type": "application/json",
        }

    async def _get(self, path: str, params: dict = None) -> dict:
        headers = await self._headers()
        r = await self._http.get(f"{self._base}{path}", headers=headers, params=params)
        if not r.is_success:
            raise RuntimeError(f"GET {path} failed ({r.status_code}): {r.text}")
        return r.json()

    async def list_backups(self) -> list[dict]:
        """GET /api/v1/backups — all backup objects known to Veeam."""
        result = []
        skip = 0
        limit = 100
        while True:
            data = await self._get("/api/v1/backups", params={"skip": skip, "limit": limit})
            page = data.get("data", [])
            result.extend(page)
            if len(page) < limit:
                break
            skip += limit
        return result

    async def get_restore_points(self, vm_name: str, limit: int = 20) -> list[dict]:
        """GET /api/v1/restorePoints — all platforms, newest first.

        Covers: VMware, HyperV, CloudDirector, WindowsPhysical,
                LinuxPhysical, UnstructuredData.
        """
        data = await self._get(
            "/api/v1/restorePoints",
            params={
                "nameFilter": vm_name,
                "orderColumn": "CreationTime",
                "orderAsc": False,
                "skip": 0,
                "limit": limit,
            },
        )
        return data.get("data", [])

    async def enrich_with_repository(self, points: list[dict]) -> None:
        """Fetch repositoryName for each restore point via GET /api/v1/backups/{backupId}."""
        unique_ids = list({p["backupId"] for p in points if p.get("backupId")})

        async def _fetch(bid: str) -> tuple[str, dict]:
            try:
                return bid, await self._get(f"/api/v1/backups/{bid}")
            except RuntimeError:
                return bid, {}

        cache = dict(await asyncio.gather(*[_fetch(bid) for bid in unique_ids]))
        for p in points:
            info = cache.get(p.get("backupId") or "", {})
            p["repositoryId"] = info.get("repositoryId")
            p["repositoryName"] = info.get("repositoryName")

    async def get_malware_events(self, vm_name: str, after: datetime) -> list[dict]:
        """GET /api/v1/malwareDetection/suspiciousActivityEvents for a VM."""
        try:
            data = await self._get(
                "/api/v1/malwareDetection/suspiciousActivityEvents",
                params={
                    "nameFilter": vm_name,
                    "createdAfterFilter": after.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    "orderColumn": "DetectionTime",
                    "orderAsc": False,
                    "skip": 0,
                    "limit": 100,
                },
            )
            return data.get("data", [])
        except RuntimeError:
            return []

    async def close(self):
        await self._http.aclose()


# ── Confidence Scoring ────────────────────────────────────────────────────────
# Mirrors the logic in veeam_client.py — failure_time is "now" for the dashboard.

_MALWARE_SCORES = {"Clean": 60, "Informative": 30, "Suspicious": 0, "Infected": 0}


def score_restore_point(
    point: dict,
    all_points: list[dict],
    now: datetime,
    preferred_repos: list[str] = None,
) -> int:
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

    newer = [
        p for p in all_points
        if datetime.fromisoformat(p["creationTime"].replace("Z", "+00:00")) > rp_time
    ]
    infected = [p for p in newer if p.get("malwareStatus") == "Infected"]
    suspicious_rps = [p for p in newer if p.get("malwareStatus") == "Suspicious"]

    if not infected and not suspicious_rps:
        neighbor_score = 15
    else:
        direct = (
            min(newer, key=lambda p: datetime.fromisoformat(p["creationTime"].replace("Z", "+00:00")))
            if newer else None
        )
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
    if preferred_repos and rp_repo:
        if any(r.lower() in rp_repo.lower() for r in preferred_repos):
            repo_score = 10

    return max(0, min(100, malware_score + margin_score + neighbor_score + repo_score))


# ── Repository Config ─────────────────────────────────────────────────────────

def load_repo_config(path: str) -> dict[str, list[str]]:
    """
    Parse YAML repo config → {hostname: [preferred_repo_names]}.

    Format:
        groups:
          production:
            repos: [repo-gold, repo-offsite]
            hosts: [prod-db-01, prod-web-01]
        hosts:           # per-host override (takes precedence over group)
          prod-db-01: [repo-gold-exclusive]
    """
    if not _YAML_AVAILABLE:
        print("Warning: PyYAML not installed — repo config ignored. Run: pip install pyyaml", file=sys.stderr)
        return {}
    with open(path, encoding="utf-8") as f:
        cfg = _yaml.safe_load(f) or {}

    resolved: dict[str, list[str]] = {}

    for group in (cfg.get("groups") or {}).values():
        repos = group.get("repos") or []
        for host in (group.get("hosts") or []):
            if host not in resolved:
                resolved[host] = list(repos)

    for host, repos in (cfg.get("hosts") or {}).items():
        resolved[host] = list(repos or [])

    return resolved


def get_preferred_repos(hostname: str, repo_config: dict[str, list[str]]) -> list[str]:
    return repo_config.get(hostname, [])


# ── Demo Data ─────────────────────────────────────────────────────────────────

def _make_demo_data(days: int) -> list[dict]:
    now = datetime.now(timezone.utc)

    _demo_repos = {
        "prod-web-01": "repo-gold",
        "prod-db-01":  "repo-gold",
        "prod-app-02": "repo-silver",
        "prod-dc-01":  "repo-silver",
        "prod-files-01": "repo-bronze",
        "dev-build-01":  "repo-bronze",
    }

    def rp(vm, hours_ago, malware, rp_type="Increment", eligible=True):
        t = (now - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        ops = ["StartViVMInstantRecovery"] if eligible else []
        return {
            "id": f"rp-{vm}-{hours_ago}",
            "name": vm,
            "platformName": "VMware",
            "creationTime": t,
            "backupId": f"bk-{vm}",
            "type": rp_type,
            "malwareStatus": malware,
            "allowedOperations": ops,
            "repositoryName": _demo_repos.get(vm, "repo-default"),
        }

    def evt(vm, hours_ago, severity="Warning"):
        t = (now - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        return {
            "machineName": vm,
            "detectionTime": t,
            "details": "Suspicious file system activity detected",
            "severity": severity,
        }

    return [
        {
            "vm": "prod-web-01",
            "restore_points": [
                rp("prod-web-01", 2, "Clean"),
                rp("prod-web-01", 14, "Clean"),
                rp("prod-web-01", 26, "Clean", "Full"),
                rp("prod-web-01", 50, "Clean"),
            ],
            "malware_events": [],
        },
        {
            "vm": "prod-db-01",
            "restore_points": [
                rp("prod-db-01", 1, "Clean"),
                rp("prod-db-01", 13, "Informative"),
                rp("prod-db-01", 25, "Clean", "Full"),
            ],
            "malware_events": [evt("prod-db-01", 20, "Information")],
        },
        {
            "vm": "prod-app-02",
            "restore_points": [
                rp("prod-app-02", 3, "Suspicious"),
                rp("prod-app-02", 15, "Clean"),
                rp("prod-app-02", 27, "Clean", "Full"),
            ],
            "malware_events": [
                evt("prod-app-02", 4, "Warning"),
                evt("prod-app-02", 6, "Warning"),
            ],
        },
        {
            "vm": "prod-dc-01",
            "restore_points": [
                rp("prod-dc-01", 4, "Infected", eligible=False),
                rp("prod-dc-01", 16, "Infected", eligible=False),
                rp("prod-dc-01", 28, "Suspicious"),
                rp("prod-dc-01", 52, "Clean", "Full"),
            ],
            "malware_events": [
                evt("prod-dc-01", 5, "Critical"),
                evt("prod-dc-01", 17, "Critical"),
                evt("prod-dc-01", 29, "Warning"),
            ],
        },
        {
            "vm": "prod-files-01",
            "restore_points": [],
            "malware_events": [],
        },
        {
            "vm": "dev-build-01",
            "restore_points": [
                rp("dev-build-01", 6, "Clean"),
                rp("dev-build-01", 30, "Clean", "Full"),
            ],
            "malware_events": [],
        },
    ]


# ── Data Fetching ─────────────────────────────────────────────────────────────

async def fetch_all(client: VeeamClient, hostname: Optional[str], days: int) -> list[dict]:
    after = datetime.now(timezone.utc) - timedelta(days=days)

    if hostname:
        vms = [hostname]
    else:
        backups = await client.list_backups()
        seen: set[str] = set()
        vms = []
        for b in backups:
            name = b.get("name")
            if name and name not in seen:
                seen.add(name)
                vms.append(name)

    async def fetch_vm(vm_name: str) -> dict:
        try:
            rps, events = await asyncio.gather(
                client.get_restore_points(vm_name),
                client.get_malware_events(vm_name, after),
            )
            if rps:
                await client.enrich_with_repository(rps)
            return {"vm": vm_name, "restore_points": rps, "malware_events": events}
        except Exception as exc:
            return {"vm": vm_name, "restore_points": [], "malware_events": [], "error": str(exc)}

    return list(await asyncio.gather(*[fetch_vm(v) for v in vms]))


# ── Summarize ─────────────────────────────────────────────────────────────────

_STATUS_ORDER = {"infected": 0, "suspicious": 1, "low_confidence": 2, "clean": 3, "no_data": 4, "error": 5}

_STATUS_LABELS = {
    "clean": "Clean",
    "suspicious": "Suspicious",
    "infected": "Infected",
    "low_confidence": "Low Confidence",
    "no_data": "No Data",
    "error": "Error",
}

_STATUS_COLORS = {
    "clean": "#22c55e",
    "suspicious": "#f59e0b",
    "infected": "#ef4444",
    "low_confidence": "#f97316",
    "no_data": "#6b7280",
    "error": "#7c3aed",
}

_MALWARE_COLORS = {
    "Clean": "#22c55e",
    "Informative": "#3b82f6",
    "Suspicious": "#f59e0b",
    "Infected": "#ef4444",
}


def compute_summary(
    vm_data: dict,
    now: datetime,
    threshold: int,
    repo_config: dict[str, list[str]] = None,
) -> dict:
    if vm_data.get("error"):
        return {
            "vm": vm_data["vm"],
            "status": "error",
            "best_rp": None,
            "best_score": None,
            "best_rp_time": None,
            "best_malware": None,
            "event_count": 0,
            "restore_points": [],
            "malware_events": [],
            "error": vm_data["error"],
        }

    rps = vm_data["restore_points"]
    events = vm_data["malware_events"]
    preferred_repos = get_preferred_repos(vm_data["vm"], repo_config or {})

    if not rps:
        return {
            "vm": vm_data["vm"],
            "status": "no_data",
            "best_rp": None,
            "best_score": None,
            "best_rp_time": None,
            "best_malware": None,
            "event_count": len(events),
            "restore_points": rps,
            "malware_events": events,
        }

    selectable = [
        p for p in rps
        if "StartViVMInstantRecovery" in p.get("allowedOperations", [])
        and p.get("malwareStatus") not in ("Infected", "Suspicious")
    ]

    if selectable:
        scored = [(p, score_restore_point(p, rps, now, preferred_repos)) for p in selectable]
        scored.sort(key=lambda x: x[1], reverse=True)
        best_rp, best_score = scored[0]
    else:
        best_rp = max(rps, key=lambda p: p["creationTime"])
        best_score = score_restore_point(best_rp, rps, now, preferred_repos)

    malware_statuses = [p.get("malwareStatus") for p in rps]

    if "Infected" in malware_statuses:
        status = "infected"
    elif "Suspicious" in malware_statuses or len(events) > 0:
        status = "suspicious"
    elif best_score >= threshold:
        status = "clean"
    else:
        status = "low_confidence"

    return {
        "vm": vm_data["vm"],
        "status": status,
        "best_rp": best_rp,
        "best_score": best_score,
        "best_rp_time": best_rp["creationTime"],
        "best_malware": best_rp.get("malwareStatus"),
        "event_count": len(events),
        "restore_points": rps,
        "malware_events": events,
    }


# ── HTML Rendering ────────────────────────────────────────────────────────────

def _score_color(score: Optional[int]) -> str:
    if score is None:
        return "#6b7280"
    if score >= 70:
        return "#22c55e"
    if score >= 40:
        return "#f59e0b"
    return "#ef4444"


def _fmt_time(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return iso


def _render_rp_table(rps: list[dict]) -> str:
    if not rps:
        return "<p class='no-data'>No restore points found.</p>"
    rows = ""
    for rp in rps:
        malware = rp.get("malwareStatus") or "Unknown"
        mc = _MALWARE_COLORS.get(rp.get("malwareStatus"), "#6b7280")
        eligible = "✓" if "StartViVMInstantRecovery" in rp.get("allowedOperations", []) else "✗"
        rp_type = html.escape(rp.get("type") or "—")
        rows += (
            f"<tr>"
            f"<td>{_fmt_time(rp['creationTime'])}</td>"
            f"<td>{rp_type}</td>"
            f"<td><span class='badge' style='background:{mc}'>{html.escape(malware)}</span></td>"
            f"<td class='center'>{eligible}</td>"
            f"</tr>"
        )
    return (
        "<table class='sub-table'>"
        "<thead><tr><th>Time</th><th>Type</th><th>Malware Status</th><th>Eligible</th></tr></thead>"
        f"<tbody>{rows}</tbody>"
        "</table>"
    )


def _render_event_table(events: list[dict], days: int) -> str:
    sev_colors = {"Critical": "#ef4444", "Warning": "#f59e0b", "Information": "#3b82f6"}
    heading = f"<p class='sub-heading'>Malware Events (last {days}d)</p>"
    if not events:
        return heading + "<p class='no-data'>No malware events detected in this period.</p>"
    rows = ""
    for evt in events:
        sev = evt.get("severity") or "—"
        sc = sev_colors.get(sev, "#6b7280")
        details = html.escape(evt.get("details") or "—")
        t = _fmt_time(evt.get("detectionTime") or "")
        rows += (
            f"<tr>"
            f"<td>{t}</td>"
            f"<td><span class='badge' style='background:{sc}'>{html.escape(sev)}</span></td>"
            f"<td>{details}</td>"
            f"</tr>"
        )
    return (
        heading
        + "<table class='sub-table'>"
        "<thead><tr><th>Time</th><th>Severity</th><th>Details</th></tr></thead>"
        f"<tbody>{rows}</tbody>"
        "</table>"
    )


def render_html(
    summaries: list[dict],
    days: int,
    demo: bool,
    hostname: Optional[str],
    threshold: int,
) -> str:
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    clean_n = sum(1 for s in summaries if s["status"] == "clean")
    warn_n = sum(1 for s in summaries if s["status"] in ("suspicious", "low_confidence"))
    infected_n = sum(1 for s in summaries if s["status"] == "infected")
    nodata_n = sum(1 for s in summaries if s["status"] == "no_data")
    error_n = sum(1 for s in summaries if s["status"] == "error")
    total_n = len(summaries)

    demo_banner = (
        '<div class="demo-banner">&#9888; DEMO MODE &mdash; Sample Data Only</div>'
        if demo else ""
    )
    filter_note = (
        f" &mdash; filtered to <strong>{html.escape(hostname)}</strong>"
        if hostname else ""
    )

    # Summary cards
    cards_html = f"""
<div class="cards">
  <div class="card"><div class="card-num green">{clean_n}</div><div class="card-lbl">Clean</div></div>
  <div class="card"><div class="card-num orange">{warn_n}</div><div class="card-lbl">Suspicious / Low Conf.</div></div>
  <div class="card"><div class="card-num red">{infected_n}</div><div class="card-lbl">Infected</div></div>
  <div class="card"><div class="card-num gray">{nodata_n}</div><div class="card-lbl">No Data</div></div>
  <div class="card"><div class="card-num" style="color:#7c3aed">{error_n}</div><div class="card-lbl">API Errors</div></div>
  <div class="card"><div class="card-num blue">{total_n}</div><div class="card-lbl">Total</div></div>
</div>"""

    # Table rows
    rows_html = ""
    for s in summaries:
        status = s["status"]
        color = _STATUS_COLORS[status]
        label = _STATUS_LABELS[status]
        vm_esc = html.escape(s["vm"])
        row_id = f"d-{vm_esc}"

        score_cell = "—"
        if s["best_score"] is not None:
            sc = _score_color(s["best_score"])
            pct = s["best_score"]
            score_cell = (
                f"<div class='score-wrap'>"
                f"<span class='score-num' style='color:{sc}'>{s['best_score']}</span>"
                f"<div class='score-bar-bg'><div class='score-bar' style='width:{pct}%;background:{sc}'></div></div>"
                f"</div>"
            )

        rp_time_cell = _fmt_time(s["best_rp_time"]) if s["best_rp_time"] else "—"

        malware_cell = "—"
        if s["best_malware"]:
            mc = _MALWARE_COLORS.get(s["best_malware"], "#6b7280")
            malware_cell = f"<span class='badge' style='background:{mc}'>{html.escape(s['best_malware'])}</span>"
        elif s["best_rp"] is not None:
            malware_cell = "<span class='badge' style='background:#6b7280'>Unknown</span>"

        ec = s["event_count"]
        event_cell = (
            f"<span class='ev-badge ev-warn'>{ec}</span>"
            if ec > 0
            else f"<span class='ev-badge'>{ec}</span>"
        )

        if s.get("error"):
            detail_content = f"<p class='error-msg'>&#9888; API error: {html.escape(s['error'])}</p>"
        else:
            detail_content = (
                _render_rp_table(s.get("restore_points", []))
                + _render_event_table(s.get("malware_events", []), days)
            )

        rows_html += f"""
<tr class="vm-row" onclick="tog('{row_id}')">
  <td><span class="dot" style="background:{color}"></span>{vm_esc}</td>
  <td><span class="badge" style="background:{color}">{label}</span></td>
  <td class="center">{score_cell}</td>
  <td>{rp_time_cell}</td>
  <td>{malware_cell}</td>
  <td class="center">{event_cell}</td>
</tr>
<tr class="detail-row" id="{row_id}">
  <td colspan="6"><div class="detail-panel">{detail_content}</div></td>
</tr>"""

    css = """
* { box-sizing: border-box; margin: 0; padding: 0; }

/* ── Theme tokens ── */
:root {
  --bg:          #0f172a; --surface:    #1e293b; --surface2:  #111827;
  --surface3:    #0a1020; --border:     #334155; --border2:   #1e3a5f;
  --text:        #e2e8f0; --text-muted: #94a3b8; --text-dim:  #64748b;
  --text-sub:    #cbd5e1; --hint:       #475569; --hover:     #263244;
  --thead-bg:    #0f172a; --sub-thead:  #0d1a2a; --sub-bg:    #111827;
  --detail-bg:   #0a1020; --bar-bg:     #334155;
  --modal-bg:    #1e293b; --modal-ol:   rgba(0,0,0,.65);
  --card-lbl:    #94a3b8;
}
body.light {
  --bg:          #f1f5f9; --surface:    #ffffff; --surface2:  #f8fafc;
  --surface3:    #f1f5f9; --border:     #e2e8f0; --border2:   #cbd5e1;
  --text:        #0f172a; --text-muted: #475569; --text-dim:  #64748b;
  --text-sub:    #334155; --hint:       #94a3b8; --hover:     #f1f5f9;
  --thead-bg:    #f8fafc; --sub-thead:  #f1f5f9; --sub-bg:    #f8fafc;
  --detail-bg:   #f8fafc; --bar-bg:     #e2e8f0;
  --modal-bg:    #ffffff; --modal-ol:   rgba(0,0,0,.45);
  --card-lbl:    #64748b;
}

body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       background: var(--bg); color: var(--text); min-height: 100vh;
       transition: background .2s, color .2s; }

/* ── Demo banner ── */
.demo-banner { background: #7c3aed; color: #fff; text-align: center; padding: 9px 0;
               font-weight: 700; letter-spacing: 2px; font-size: 13px; }

/* ── Header ── */
header { background: var(--surface); border-bottom: 1px solid var(--border);
         padding: 18px 32px; display: flex; justify-content: space-between; align-items: center; gap: 16px; }
header h1 { font-size: 18px; font-weight: 700; }
header .meta { font-size: 11px; color: var(--text-dim); text-align: right; line-height: 1.6; }
.sub { font-size: 12px; color: var(--text-dim); margin-top: 3px; }
.hdr-controls { display: flex; align-items: center; gap: 10px; flex-shrink: 0; }

/* ── Theme toggle ── */
.theme-btn { background: var(--surface2); border: 1px solid var(--border); color: var(--text);
             border-radius: 20px; padding: 5px 14px; font-size: 12px; font-weight: 600;
             cursor: pointer; display: flex; align-items: center; gap: 6px;
             transition: background .15s, border-color .15s; white-space: nowrap; }
.theme-btn:hover { border-color: #60a5fa; }

/* ── Container / cards ── */
.container { max-width: 1280px; margin: 0 auto; padding: 24px 32px; }
.cards { display: grid; grid-template-columns: repeat(6, 1fr); gap: 14px; margin-bottom: 24px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
        padding: 18px; text-align: center; }
.card-num { font-size: 34px; font-weight: 800; line-height: 1; margin-bottom: 5px; }
.card-lbl { font-size: 11px; color: var(--card-lbl); text-transform: uppercase; letter-spacing: 1px; }
.green { color: #22c55e; } .orange { color: #f97316; }
.red   { color: #ef4444; } .gray   { color: #6b7280; } .blue  { color: #60a5fa; }

/* ── Section / hints ── */
.section-title { font-size: 13px; font-weight: 600; color: var(--text-muted);
                 text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
.hint { font-size: 11px; color: var(--hint); margin-bottom: 10px; }

/* ── Main table ── */
table.main { width: 100%; border-collapse: collapse; background: var(--surface);
             border-radius: 10px; overflow: hidden; border: 1px solid var(--border); }
table.main thead tr { background: var(--thead-bg); }
table.main th { padding: 11px 16px; text-align: left; font-size: 11px; font-weight: 600;
                text-transform: uppercase; letter-spacing: 1px; color: var(--text-dim); }
table.main td { padding: 11px 16px; border-top: 1px solid var(--border); font-size: 13px; }
.vm-row { cursor: pointer; transition: background .12s; }
.vm-row:hover { background: var(--hover); }
.detail-row { display: none; }
.detail-row td { background: var(--detail-bg); padding: 0; border-top: none; }
.detail-panel { padding: 16px 24px; border-top: 1px solid var(--border); }

/* ── Sub-table (restore points / events) ── */
.sub-table { width: 100%; border-collapse: collapse; background: var(--sub-bg);
             border: 1px solid var(--border2); border-radius: 6px; overflow: hidden;
             font-size: 12px; margin-top: 8px; }
.sub-table th { background: var(--sub-thead); padding: 7px 12px; text-align: left;
                font-size: 10px; font-weight: 600; text-transform: uppercase;
                letter-spacing: 1px; color: var(--text-dim); }
.sub-table td { padding: 7px 12px; border-top: 1px solid var(--border); color: var(--text-sub); }
.sub-heading { font-size: 12px; font-weight: 600; color: var(--text-muted);
               margin-top: 14px; margin-bottom: 4px; }
.no-data { font-size: 12px; color: var(--hint); font-style: italic; margin-top: 4px; }
.error-msg { font-size: 13px; color: #a78bfa; font-family: monospace; margin-top: 4px; }

/* ── Badges / dots ── */
.badge { display: inline-block; padding: 2px 9px; border-radius: 9999px;
         font-size: 11px; font-weight: 600; color: #fff; }
.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 7px; }
.center { text-align: center; }

/* ── Score cell ── */
.score-wrap { display: inline-flex; flex-direction: column; align-items: center; gap: 3px; }
.score-num { font-size: 16px; font-weight: 700; line-height: 1; }
.score-bar-bg { width: 60px; height: 4px; background: var(--bar-bg); border-radius: 2px; overflow: hidden; }
.score-bar { height: 4px; border-radius: 2px; }

/* ── Event count ── */
.ev-badge { display: inline-block; min-width: 22px; text-align: center;
            font-weight: 600; font-size: 13px; color: var(--text-dim); }
.ev-warn { color: #f59e0b; }

/* ── Help (?) button ── */
.help-btn { display: inline-flex; align-items: center; justify-content: center;
            width: 16px; height: 16px; border-radius: 50%; border: 1px solid var(--text-dim);
            color: var(--text-dim); font-size: 10px; font-weight: 700; cursor: pointer;
            margin-left: 5px; vertical-align: middle; line-height: 1;
            transition: border-color .15s, color .15s; background: transparent; }
.help-btn:hover { border-color: #60a5fa; color: #60a5fa; }

/* ── Modal ── */
.modal-overlay { display: none; position: fixed; inset: 0; background: var(--modal-ol);
                 z-index: 100; align-items: center; justify-content: center; }
.modal-overlay.open { display: flex; }
.modal { background: var(--modal-bg); border: 1px solid var(--border); border-radius: 14px;
         padding: 28px 32px; max-width: 620px; width: 90%; max-height: 85vh;
         overflow-y: auto; position: relative; box-shadow: 0 20px 60px rgba(0,0,0,.4); }
.modal h2 { font-size: 16px; font-weight: 700; margin-bottom: 6px; }
.modal .modal-sub { font-size: 12px; color: var(--text-muted); margin-bottom: 20px; }
.modal-close { position: absolute; top: 16px; right: 20px; background: none; border: none;
               color: var(--text-dim); font-size: 20px; cursor: pointer; line-height: 1;
               padding: 2px 6px; border-radius: 4px; }
.modal-close:hover { color: var(--text); }
.modal h3 { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px;
            color: var(--text-muted); margin: 18px 0 8px; }
.modal p { font-size: 13px; line-height: 1.6; color: var(--text-sub); margin-bottom: 8px; }
.modal table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 4px; }
.modal table th { text-align: left; padding: 7px 10px; background: var(--thead-bg);
                  color: var(--text-dim); font-size: 10px; text-transform: uppercase;
                  letter-spacing: 1px; border-bottom: 1px solid var(--border); }
.modal table td { padding: 7px 10px; border-bottom: 1px solid var(--border);
                  color: var(--text-sub); vertical-align: top; line-height: 1.5; }
.modal table tr:last-child td { border-bottom: none; }
.chip { display: inline-block; padding: 1px 7px; border-radius: 9999px; font-size: 10px;
        font-weight: 700; color: #fff; margin-right: 3px; }
.legend { display: flex; flex-direction: column; gap: 6px; margin-top: 4px; }
.legend-row { display: flex; align-items: center; gap: 10px; font-size: 12px;
              color: var(--text-sub); }
.legend-dot { width: 12px; height: 12px; border-radius: 50%; flex-shrink: 0; }

@media (max-width: 1100px) {
  .cards { grid-template-columns: repeat(3, 1fr); }
  .container { padding: 16px; }
  header { flex-wrap: wrap; }
}"""

    js = """
function tog(id) {
  var r = document.getElementById(id);
  r.style.display = r.style.display === 'table-row' ? 'none' : 'table-row';
}
function openModal() {
  document.getElementById('scoreModal').classList.add('open');
}
function closeModal() {
  document.getElementById('scoreModal').classList.remove('open');
}
document.addEventListener('keydown', function(e) { if (e.key === 'Escape') closeModal(); });

(function() {
  var saved = localStorage.getItem('veeam-dash-theme');
  var prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  var isDark = saved ? saved === 'dark' : prefersDark;
  if (!isDark) document.body.classList.add('light');
  updateThemeBtn(isDark);
})();

function toggleTheme() {
  var isLight = document.body.classList.toggle('light');
  var isDark = !isLight;
  localStorage.setItem('veeam-dash-theme', isDark ? 'dark' : 'light');
  updateThemeBtn(isDark);
}
function updateThemeBtn(isDark) {
  var btn = document.getElementById('themeBtn');
  if (btn) btn.innerHTML = isDark ? '&#9728; Light Mode' : '&#9790; Dark Mode';
}"""

    modal_html = f"""
<div class="modal-overlay" id="scoreModal" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <button class="modal-close" onclick="closeModal()" title="Close">&times;</button>
    <h2>Confidence Score</h2>
    <p class="modal-sub">Composite score (0 &ndash; 100) indicating how safe a restore point is for recovery.</p>

    <h3>Score Components</h3>
    <table>
      <thead>
        <tr><th>Component</th><th>Range</th><th>Details</th></tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>Malware Status</strong></td>
          <td>0 &ndash; 60</td>
          <td>
            <span class="chip" style="background:#22c55e">Clean</span> 60 &nbsp;
            <span class="chip" style="background:#3b82f6">Informative</span> 30 &nbsp;
            <span class="chip" style="background:#6b7280">Unknown</span> 15 &nbsp;
            <span class="chip" style="background:#f59e0b">Suspicious</span> 0 &nbsp;
            <span class="chip" style="background:#ef4444">Infected</span> 0
          </td>
        </tr>
        <tr>
          <td><strong>Safety Margin</strong></td>
          <td>0 &ndash; 25</td>
          <td>Time between restore point creation and now.<br>
            &ge;&thinsp;24&thinsp;h&nbsp;&rarr;&nbsp;25 &nbsp;&bull;&nbsp;
            &ge;&thinsp;12&thinsp;h&nbsp;&rarr;&nbsp;20 &nbsp;&bull;&nbsp;
            &ge;&thinsp;4&thinsp;h&nbsp;&rarr;&nbsp;12 &nbsp;&bull;&nbsp;
            &ge;&thinsp;1&thinsp;h&nbsp;&rarr;&nbsp;5 &nbsp;&bull;&nbsp;
            &lt;&thinsp;1&thinsp;h&nbsp;&rarr;&nbsp;0
          </td>
        </tr>
        <tr>
          <td><strong>Neighbor Contamination</strong></td>
          <td>&minus;30 &ndash; +15</td>
          <td>Infection state of restore points <em>newer</em> than this one.<br>
            None infected/suspicious&nbsp;&rarr;&nbsp;+15<br>
            Multiple infected or infected&thinsp;+&thinsp;suspicious&nbsp;&rarr;&nbsp;&minus;30<br>
            Direct neighbor infected&nbsp;&rarr;&nbsp;&minus;20<br>
            One infected (not direct)&nbsp;&rarr;&nbsp;&minus;10<br>
            Direct neighbor suspicious&nbsp;&rarr;&nbsp;&minus;10<br>
            Only suspicious&nbsp;&rarr;&nbsp;&minus;5
          </td>
        </tr>
        <tr>
          <td><strong>Repository Bonus</strong></td>
          <td>0 &ndash; +10</td>
          <td>+10 if the restore point resides in a preferred repository
              for this host (configured via <code>--repo-config</code> YAML file).
              Without a config file this component scores 0.</td>
        </tr>
      </tbody>
    </table>

    <h3>Score Thresholds</h3>
    <div class="legend">
      <div class="legend-row"><div class="legend-dot" style="background:#22c55e"></div>
        <span><strong>&ge; {threshold}</strong> &mdash; Safe, meets the configured confidence threshold</span></div>
      <div class="legend-row"><div class="legend-dot" style="background:#f59e0b"></div>
        <span><strong>40 &ndash; {threshold - 1}</strong> &mdash; Review recommended before restoring</span></div>
      <div class="legend-row"><div class="legend-dot" style="background:#ef4444"></div>
        <span><strong>&lt; 40</strong> &mdash; High risk &mdash; restore with caution</span></div>
    </div>

    <h3>Overall VM Status</h3>
    <table>
      <thead><tr><th>Status</th><th>Condition</th></tr></thead>
      <tbody>
        <tr><td><span class="chip" style="background:#22c55e">Clean</span></td>
            <td>Best eligible RP score &ge; threshold, no infected/suspicious RPs, no malware events</td></tr>
        <tr><td><span class="chip" style="background:#f59e0b">Suspicious</span></td>
            <td>At least one suspicious RP or at least one malware event in the lookback window</td></tr>
        <tr><td><span class="chip" style="background:#ef4444">Infected</span></td>
            <td>At least one restore point is marked Infected</td></tr>
        <tr><td><span class="chip" style="background:#f97316">Low Confidence</span></td>
            <td>Best score is below the threshold but no infected/suspicious RPs found</td></tr>
        <tr><td><span class="chip" style="background:#6b7280">No Data</span></td>
            <td>No restore points found for this VM</td></tr>
      </tbody>
    </table>
  </div>
</div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RestoreIQ</title>
<style>{css}</style>
</head>
<body>
{demo_banner}
<header>
  <div>
    <h1>RestoreIQ</h1>
    <div class="sub">Malware event window: last {days} days &nbsp;&bull;&nbsp; Confidence threshold: {threshold}{filter_note}</div>
  </div>
  <div class="hdr-controls">
    <div class="meta">Generated<br>{now_str}</div>
    <button class="theme-btn" id="themeBtn" onclick="toggleTheme()">&#9728; Light Mode</button>
  </div>
</header>
<div class="container">
  {cards_html}
  <div class="section-title">Virtual Machines</div>
  <p class="hint">Click a row to expand restore point details.</p>
  <table class="main">
    <thead>
      <tr>
        <th>VM Name</th>
        <th>Status</th>
        <th class="center">
          Confidence Score
          <button class="help-btn" onclick="event.stopPropagation();openModal()" title="How is the score calculated?">?</button>
        </th>
        <th>Best Restore Point</th>
        <th>RP Malware Status</th>
        <th class="center">Malware Events ({days}d)</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</div>
{modal_html}
<script>{js}</script>
</body>
</html>"""


# ── Main ──────────────────────────────────────────────────────────────────────

async def amain() -> None:
    parser = argparse.ArgumentParser(
        description="RestoreIQ — Veeam Restore Point Intelligence Dashboard"
    )
    parser.add_argument("--hostname", metavar="VM_NAME", help="Filter to a single VM")
    parser.add_argument("--days", type=int, default=7, metavar="N",
                        help="Malware event lookback window in days (default: 7)")
    parser.add_argument("--demo", action="store_true",
                        help="Use built-in sample data — no API calls")
    parser.add_argument("--output", default="dashboard.html", metavar="FILE",
                        help="Output HTML file (default: dashboard.html)")
    parser.add_argument("--no-ssl-verify", action="store_true",
                        help="Disable SSL certificate verification")
    parser.add_argument("--threshold", type=int, default=70, metavar="N",
                        help="Minimum confidence score considered safe (default: 70)")
    parser.add_argument("--repo-config", metavar="FILE",
                        help="YAML file mapping hosts/groups to preferred repositories (enables repo bonus)")
    args = parser.parse_args()

    now = datetime.now(timezone.utc)

    repo_config: dict[str, list[str]] = {}
    if args.repo_config:
        repo_config = load_repo_config(args.repo_config)
        print(f"Repo config loaded: {len(repo_config)} host mapping(s) from {args.repo_config}")

    if args.demo:
        print("Demo mode — using sample data, no API calls.")
        raw = _make_demo_data(args.days)
        if args.hostname:
            raw = [d for d in raw if args.hostname.lower() in d["vm"].lower()]
    else:
        url = os.environ.get("VEEAM_URL")
        user = os.environ.get("VEEAM_USERNAME")
        pwd = os.environ.get("VEEAM_PASSWORD")
        missing = [n for n, v in [("VEEAM_URL", url), ("VEEAM_USERNAME", user), ("VEEAM_PASSWORD", pwd)] if not v]
        if missing:
            print(f"Error: missing env vars: {', '.join(missing)}", file=sys.stderr)
            print("Create a .env file or export them. Use --demo for sample data.", file=sys.stderr)
            sys.exit(1)

        client = VeeamClient(url, user, pwd, verify_ssl=not args.no_ssl_verify)
        try:
            print(f"Connecting to {url} ...")
            raw = await fetch_all(client, args.hostname, args.days)
            print(f"  {len(raw)} VM(s) found")
        finally:
            await client.close()

    summaries = [compute_summary(d, now, args.threshold, repo_config) for d in raw]
    summaries.sort(key=lambda s: (_STATUS_ORDER.get(s["status"], 99), s["vm"]))

    out = Path(args.output)
    out.write_text(render_html(summaries, args.days, args.demo, args.hostname, args.threshold), encoding="utf-8")

    print(f"Dashboard written → {out.resolve()}")
    for status, label in _STATUS_LABELS.items():
        n = sum(1 for s in summaries if s["status"] == status)
        if n:
            print(f"  {label}: {n}")


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()
