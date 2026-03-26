#!/usr/bin/env python3
"""
Veeam EntraID Audit Log Downloader
Workflow (based on swagger.json):
  1.  POST /api/oauth2/token                                          → Bearer token
  2.  GET  /api/v1/backups                                            → backup list
  3.  GET  /api/v1/restorePoints?backupIdFilter=<id>                  → restore points
  4.  POST /api/v1/restore/entraId/auditLog                           → mount → sessionId
  5.  POST /api/v1/backupBrowser/flr/{sessionId}/browse  path="/"    → file list
  6.  POST /api/v1/backupBrowser/flr/{sessionId}/prepareDownload      → taskId
  7.  GET  /api/v1/backupBrowser/flr/{sessionId}/prepareDownload/{taskId}  (poll)
  8.  POST /api/v1/backupBrowser/flr/{sessionId}/prepareDownload/{taskId}/download → binary
  9.  POST /api/v1/restore/entraId/auditLog/{sessionId}/unmount       → cleanup
"""

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

BASE_URL   = cfg.get("VEEAM_HOST", "").rstrip("/")
VEEAM_USER = cfg.get("VEEAM_USER", "")
VEEAM_PASS = cfg.get("VEEAM_PASS", "")
SSL_VERIFY = cfg.get("VEEAM_SSL_VERIFY", "false").lower() == "true"
API        = f"{BASE_URL}/api/v1"
OUTPUT_DIR = Path("logs")
OUTPUT_DIR.mkdir(exist_ok=True)

session = requests.Session()
session.verify = SSL_VERIFY


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
def get_token() -> str:
    print("[*] Authenticating ...")
    resp = session.post(
        f"{BASE_URL}/api/oauth2/token",
        data={"grant_type": "password", "username": VEEAM_USER, "password": VEEAM_PASS},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp.raise_for_status()
    token = resp.json()["access_token"]
    session.headers.update({"Authorization": f"Bearer {token}"})
    print("[+] Token obtained.")
    return token


def api_get(path: str, params: dict = None) -> dict:
    resp = session.get(f"{API}{path}", params=params)
    resp.raise_for_status()
    return resp.json()


def api_post(path: str, body: dict = None) -> dict:
    resp = session.post(f"{API}{path}", json=body or {})
    resp.raise_for_status()
    return resp.json()


def api_post_binary(path: str, body: dict = None):
    """POST that returns a binary stream."""
    resp = session.post(f"{API}{path}", json=body or {}, stream=True)
    resp.raise_for_status()
    return resp


def extract_list(data) -> list:
    """Handle both paginated {data: [...]} and plain list responses."""
    if isinstance(data, dict):
        return data.get("data", [])
    return data if isinstance(data, list) else []


# ---------------------------------------------------------------------------
# Step 2 & 3: Discovery
# ---------------------------------------------------------------------------
def list_backups() -> list:
    print("[*] Fetching backups ...")
    backups = extract_list(api_get("/backups"))
    print(f"    Found {len(backups)} backup(s).")
    for b in backups:
        print(f"      id={b['id']}  name={b.get('name', '?')}")
    return backups


def list_restore_points(backup_id: str) -> list:
    print(f"[*] Fetching restore points for backup {backup_id} ...")
    points = extract_list(api_get("/restorePoints", params={"backupIdFilter": backup_id}))
    print(f"    Found {len(points)} restore point(s).")
    for p in points:
        print(f"      id={p['id']}  created={p.get('creationTime', '?')}")
    return points


# ---------------------------------------------------------------------------
# Step 4: Mount
# ---------------------------------------------------------------------------
def start_mount(restore_point_id: str) -> str:
    """Returns sessionId."""
    print(f"[*] Mounting EntraID audit log (restorePointId={restore_point_id}) ...")
    body = {
        "restorePointId": restore_point_id,
        "autoUnmount": {
            "isEnabled": True,
            "noActivityPeriodInMinutes": 30,
        },
    }
    result = api_post("/restore/entraId/auditLog", body)
    print(f"[+] Mount response: {json.dumps(result, indent=2)}")
    session_id = result.get("sessionId")
    if not session_id:
        print("[-] No sessionId in mount response.")
        sys.exit(1)
    return session_id


# ---------------------------------------------------------------------------
# Step 5: Browse
# ---------------------------------------------------------------------------
def browse(session_id: str, path: str = "/") -> list:
    """Returns list of FlrBrowserItemModel."""
    print(f"[*] Browsing path '{path}' ...")
    result = api_post(f"/backupBrowser/flr/{session_id}/browse", {"path": path})
    items = result.get("items", [])
    print(f"    Found {len(items)} item(s) at '{path}':")
    for item in items:
        itype = item.get("type", "?")
        name  = item.get("name", "?")
        size  = item.get("size", 0)
        loc   = item.get("location", "")
        print(f"      [{itype}]  {name}  ({size} bytes)  location={loc}")
    return items


def collect_files(session_id: str, path: str = "/") -> list:
    """Recursively collect all file paths."""
    items = browse(session_id, path)
    files = []
    for item in items:
        if item.get("type", "").lower() == "file":
            files.append(item.get("location") or item.get("name"))
        elif item.get("type", "").lower() in ("directory", "folder"):
            loc = item.get("location") or path.rstrip("/") + "/" + item.get("name", "")
            files.extend(collect_files(session_id, loc))
    return files


# ---------------------------------------------------------------------------
# Steps 6-8: Prepare & download
# ---------------------------------------------------------------------------
def poll_task(session_id: str, task_id: str, interval: int = 3, timeout: int = 300) -> dict:
    print(f"[*] Polling task {task_id} ...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        task = api_get(f"/backupBrowser/flr/{session_id}/prepareDownload/{task_id}")
        state  = task.get("state", "?")
        pct    = task.get("progressPercent", 0)
        result = task.get("result", "?")
        print(f"    state={state}  progress={pct}%")
        if state.lower() in ("succeeded", "success", "completed"):
            return task
        if state.lower() in ("failed", "error"):
            print(f"[-] Task failed: {task}")
            sys.exit(1)
        time.sleep(interval)
    print("[-] Timeout waiting for task.")
    sys.exit(1)


def prepare_and_download(session_id: str, file_paths: list):
    print(f"[*] Preparing download for {len(file_paths)} file(s) ...")
    task = api_post(
        f"/backupBrowser/flr/{session_id}/prepareDownload",
        {"sourcePath": file_paths},
    )
    task_id = task.get("id")
    if not task_id:
        print(f"[-] No task id returned: {task}")
        sys.exit(1)

    poll_task(session_id, task_id)

    print("[*] Downloading ...")
    resp = api_post_binary(
        f"/backupBrowser/flr/{session_id}/prepareDownload/{task_id}/download"
    )

    # Determine filename from Content-Disposition or fallback
    cd = resp.headers.get("Content-Disposition", "")
    filename = "auditlogs.zip"
    if "filename=" in cd:
        filename = cd.split("filename=")[-1].strip().strip('"')

    dest = OUTPUT_DIR / filename
    with open(dest, "wb") as fh:
        for chunk in resp.iter_content(chunk_size=65536):
            fh.write(chunk)
    print(f"[+] Saved: {dest} ({dest.stat().st_size} bytes)")
    return dest


# ---------------------------------------------------------------------------
# Step 9: Unmount
# ---------------------------------------------------------------------------
def unmount(session_id: str):
    print(f"[*] Unmounting session {session_id} ...")
    try:
        api_post(f"/restore/entraId/auditLog/{session_id}/unmount")
        print("[+] Unmounted.")
    except Exception as e:
        print(f"[!] Unmount failed (non-fatal): {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if not BASE_URL or not VEEAM_USER:
        print("[-] Please fill in config.env first.")
        sys.exit(1)

    get_token()

    # Discovery
    backups = list_backups()
    if not backups:
        print("[-] No backups found.")
        sys.exit(1)

    backup_id = backups[0]["id"]

    points = list_restore_points(backup_id)
    if not points:
        print("[-] No restore points found.")
        sys.exit(1)

    restore_point_id = points[-1]["id"]  # most recent

    # Mount
    session_id = start_mount(restore_point_id)

    try:
        # Browse & collect files
        files = collect_files(session_id, "/")
        if not files:
            print("[!] No files found in mount. Dumping raw browse result for inspection:")
            browse(session_id, "/")
        else:
            print(f"\n[*] Total files to download: {len(files)}")
            for f in files:
                print(f"      {f}")
            prepare_and_download(session_id, files)
    finally:
        unmount(session_id)

    print("\n[+] Done. Log files saved to:", OUTPUT_DIR.resolve())


if __name__ == "__main__":
    main()
