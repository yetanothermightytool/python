#!/usr/bin/env python3
"""
Veeam EntraID Audit Log Downloader
Workflow:
  1. Get Bearer Token
  2. Discover backups / restore points / unstructured-data servers
  3. Mount EntraID audit log
  4. Download log files
"""

import os
import sys
import json
import time
import requests
import urllib3
from pathlib import Path
from dotenv import dotenv_values

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
cfg = dotenv_values("config.env")

BASE_URL    = cfg.get("VEEAM_HOST", "").rstrip("/")
VEEAM_USER  = cfg.get("VEEAM_USER", "")
VEEAM_PASS  = cfg.get("VEEAM_PASS", "")
SSL_VERIFY  = cfg.get("VEEAM_SSL_VERIFY", "false").lower() == "true"
API         = f"{BASE_URL}/api/v1"
OUTPUT_DIR  = Path("logs")
OUTPUT_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
session = requests.Session()
session.verify = SSL_VERIFY


def get_token() -> str:
    print("[*] Authenticating ...")
    resp = session.post(
        f"{BASE_URL}/api/oauth2/token",
        data={
            "grant_type": "password",
            "username": VEEAM_USER,
            "password": VEEAM_PASS,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp.raise_for_status()
    token = resp.json()["access_token"]
    session.headers.update({"Authorization": f"Bearer {token}"})
    print("[+] Token obtained.")
    return token


def get(path: str, params: dict = None) -> dict:
    resp = session.get(f"{API}{path}", params=params)
    resp.raise_for_status()
    return resp.json()


def post(path: str, body: dict) -> dict:
    resp = session.post(f"{API}{path}", json=body)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------
def list_backups() -> list:
    print("[*] Fetching backups ...")
    data = get("/backups")
    backups = data.get("data", data) if isinstance(data, dict) else data
    print(f"    Found {len(backups)} backup(s).")
    for b in backups:
        print(f"      id={b['id']}  name={b.get('name', '?')}")
    return backups


def list_restore_points(backup_id: str) -> list:
    print(f"[*] Fetching restore points for backup {backup_id} ...")
    data = get("/restorePoints", params={"backupIdFilter": backup_id})
    points = data.get("data", data) if isinstance(data, dict) else data
    print(f"    Found {len(points)} restore point(s).")
    for p in points:
        print(f"      id={p['id']}  created={p.get('creationTime', '?')}")
    return points


def list_unstructured_servers() -> list:
    print("[*] Fetching unstructured data servers ...")
    data = get("/unstructuredDataServers")
    servers = data.get("data", data) if isinstance(data, dict) else data
    print(f"    Found {len(servers)} server(s).")
    for s in servers:
        print(f"      id={s['id']}  name={s.get('name', '?')}")
    return servers


# ---------------------------------------------------------------------------
# Mount & download
# ---------------------------------------------------------------------------
def start_mount(restore_point_id: str) -> dict:
    print(f"[*] Starting EntraID audit log mount for restore point {restore_point_id} ...")
    body = {
        "restorePointId": restore_point_id,
        "autoUnmount": {
            "enabled": True,
            "timeout": 30,   # minutes
        },
    }
    result = post("/entraId/auditLogs/mount", body)
    print(f"[+] Mount started: {json.dumps(result, indent=2)}")
    return result


def wait_for_mount(session_id: str, poll_interval: int = 5, timeout: int = 300) -> dict:
    print(f"[*] Waiting for mount session {session_id} to become ready ...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = get(f"/entraId/auditLogs/mount/{session_id}")
        state = status.get("state", status.get("status", "?"))
        print(f"    state={state}")
        if state.lower() in ("success", "mounted", "completed"):
            print("[+] Mount ready.")
            return status
        if state.lower() in ("failed", "error"):
            print(f"[-] Mount failed: {status}")
            sys.exit(1)
        time.sleep(poll_interval)
    print("[-] Timeout waiting for mount.")
    sys.exit(1)


def list_log_files(session_id: str) -> list:
    print(f"[*] Listing log files for session {session_id} ...")
    data = get(f"/entraId/auditLogs/mount/{session_id}/files")
    files = data.get("data", data) if isinstance(data, dict) else data
    print(f"    Found {len(files)} log file(s).")
    for f in files:
        print(f"      {f}")
    return files


def download_file(session_id: str, file_id: str, filename: str):
    dest = OUTPUT_DIR / filename
    print(f"[*] Downloading {filename} -> {dest}")
    resp = session.get(f"{API}/entraId/auditLogs/mount/{session_id}/files/{file_id}/download", stream=True)
    resp.raise_for_status()
    with open(dest, "wb") as fh:
        for chunk in resp.iter_content(chunk_size=65536):
            fh.write(chunk)
    print(f"[+] Saved {dest} ({dest.stat().st_size} bytes)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if not BASE_URL or not VEEAM_USER:
        print("[-] Please fill in config.env first.")
        sys.exit(1)

    get_token()

    # --- Discovery: pick a restore point ---------------------------------
    backups = list_backups()
    if not backups:
        print("[-] No backups found.")
        sys.exit(1)

    # Use the first backup for now; adjust as needed
    backup = backups[0]
    backup_id = backup["id"]

    points = list_restore_points(backup_id)
    if not points:
        print("[-] No restore points found.")
        sys.exit(1)

    # Use the most recent restore point (last in list)
    restore_point = points[-1]
    restore_point_id = restore_point["id"]

    # --- Mount -----------------------------------------------------------
    mount_result = start_mount(restore_point_id)
    session_id = mount_result.get("id") or mount_result.get("sessionId")

    if session_id:
        mount_info = wait_for_mount(session_id)
        files = list_log_files(session_id)
        for f in files:
            file_id   = f.get("id") or f.get("fileId")
            file_name = f.get("name") or f.get("fileName") or file_id
            if file_id:
                download_file(session_id, file_id, file_name)
    else:
        print("[!] Mount response did not contain a session ID.")
        print(json.dumps(mount_result, indent=2))

    print("\n[+] Done. Log files saved to:", OUTPUT_DIR.resolve())


if __name__ == "__main__":
    main()
