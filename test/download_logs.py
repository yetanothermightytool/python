#!/usr/bin/env python3
"""
Veeam EntraID Audit Log Downloader
Workflow (based on swagger.json):
  1.  POST /api/oauth2/token                                                    → Bearer token
  2.  GET  /api/v1/backups                                                       → backup list
  3.  POST /api/v1/restore/entraId/auditLog                                      → mount → sessionId
  4.  POST /api/v1/backupBrowser/flr/unstructuredData/{sessionId}/browse         → file list
  5.  POST /api/v1/backupBrowser/flr/unstructuredData/{sessionId}/copyTo         → copy to local path (taskId)
  6.  Poll task until complete
  7.  POST /api/v1/restore/unstructuredData/{sessionId}/unmount                  → cleanup
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

BASE_URL    = cfg.get("VEEAM_HOST", "").rstrip("/")
VEEAM_USER  = cfg.get("VEEAM_USER", "")
VEEAM_PASS  = cfg.get("VEEAM_PASS", "")
SSL_VERIFY  = cfg.get("VEEAM_SSL_VERIFY", "false").lower() == "true"
# Absolute path on the Veeam server where logs will be copied to
LOCAL_PATH  = cfg.get("VEEAM_OUTPUT_PATH", "/home/administrator/entraid/logs")
API         = f"{BASE_URL}/api/v1"

Path(LOCAL_PATH).mkdir(parents=True, exist_ok=True)

http = requests.Session()
http.verify = SSL_VERIFY


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
def get_token() -> str:
    print("[*] Authenticating ...")
    resp = http.post(
        f"{BASE_URL}/api/oauth2/token",
        data={"grant_type": "password", "username": VEEAM_USER, "password": VEEAM_PASS},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp.raise_for_status()
    token = resp.json()["access_token"]
    http.headers.update({"Authorization": f"Bearer {token}"})
    print("[+] Token obtained.")
    return token


def _raise(resp):
    try:
        detail = resp.json()
    except Exception:
        detail = resp.text
    print(f"[-] HTTP {resp.status_code} {resp.request.method} {resp.url}")
    print(f"    Response: {json.dumps(detail, indent=2) if isinstance(detail, dict) else detail}")
    resp.raise_for_status()


def api_get(path: str, params: dict = None) -> dict:
    resp = http.get(f"{API}{path}", params=params)
    if not resp.ok:
        _raise(resp)
    return resp.json()


def api_post(path: str, body: dict = None) -> dict:
    resp = http.post(f"{API}{path}", json=body or {})
    if not resp.ok:
        _raise(resp)
    return resp.json()


def extract_list(data) -> list:
    if isinstance(data, dict):
        return data.get("data", [])
    return data if isinstance(data, list) else []


# ---------------------------------------------------------------------------
# Step 2: Discovery
# ---------------------------------------------------------------------------
def list_backups() -> list:
    print("[*] Fetching backups ...")
    backups = extract_list(api_get("/backups"))
    print(f"    Found {len(backups)} backup(s).")
    for b in backups:
        print(f"      id={b['id']}  name={b.get('name', '?')}")
    return backups


# ---------------------------------------------------------------------------
# Step 3: Mount
# ---------------------------------------------------------------------------
def start_mount(backup_id: str) -> str:
    """Returns sessionId. Uses backupId (all-time mode) as required by the API."""
    print(f"[*] Mounting EntraID audit log (backupId={backup_id}) ...")
    body = {
        "backupId": backup_id,
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
# Step 4: Browse (unstructuredData browser)
# ---------------------------------------------------------------------------
def browse(session_id: str, path: str) -> list:
    print(f"[*] Browsing path '{path}' ...")
    result = api_post(
        f"/backupBrowser/flr/unstructuredData/{session_id}/browse",
        {"path": path},
    )
    items = result.get("items", [])
    print(f"    Found {len(items)} item(s):")
    for item in items:
        itype = item.get("type", "?")
        name  = item.get("name", "?")
        size  = item.get("size", 0)
        loc   = item.get("location", "")
        print(f"      [{itype}]  {name}  ({size} bytes)  location={loc}")
    return items


def collect_files(session_id: str, path: str, sep: str = "|") -> list:
    """Recursively collect all file locations."""
    items = browse(session_id, path)
    files = []
    for item in items:
        itype = item.get("type", "").lower()
        loc   = item.get("location", "")
        name  = item.get("name", "")
        if itype == "file":
            files.append(loc or name)
        elif itype in ("directory", "folder"):
            child_path = loc or (path.rstrip(sep) + sep + name if path != sep else sep + name)
            files.extend(collect_files(session_id, child_path, sep))
    return files


# ---------------------------------------------------------------------------
# Step 5: Copy to local path on Veeam server
# ---------------------------------------------------------------------------
def copy_to_local(session_id: str, source_paths: list) -> str:
    """Triggers copyTo on the Veeam server. Returns task id."""
    print(f"[*] Copying {len(source_paths)} item(s) to '{LOCAL_PATH}' on Veeam server ...")
    body = {
        "sourcePath": source_paths,
        "isRecursive": True,
        "copyToBackupServer": True,
        "path": LOCAL_PATH,
    }
    task = api_post(f"/backupBrowser/flr/unstructuredData/{session_id}/copyTo", body)
    task_id = task.get("id")
    if not task_id:
        print(f"[-] No task id in copyTo response: {task}")
        sys.exit(1)
    print(f"[+] CopyTo task started: {task_id}")
    return task_id


# ---------------------------------------------------------------------------
# Step 6: Poll task
# ---------------------------------------------------------------------------
def poll_task(task_id: str, interval: int = 5, timeout: int = 600) -> dict:
    print(f"[*] Polling task {task_id} ...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        task = api_get(f"/tasks/{task_id}")
        state = task.get("state", "?")
        pct   = task.get("progressPercent", 0)
        print(f"    state={state}  progress={pct}%")
        if state.lower() in ("succeeded", "success", "completed"):
            print("[+] Task completed.")
            return task
        if state.lower() in ("failed", "error"):
            print(f"[-] Task failed: {json.dumps(task, indent=2)}")
            sys.exit(1)
        time.sleep(interval)
    print("[-] Timeout waiting for task.")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Step 7: Unmount
# ---------------------------------------------------------------------------
def unmount(session_id: str):
    print(f"[*] Unmounting session {session_id} ...")
    try:
        api_post(f"/restore/unstructuredData/{session_id}/unmount")
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

    backups = list_backups()
    if not backups:
        print("[-] No backups found.")
        sys.exit(1)

    backup_id = backups[0]["id"]
    session_id = start_mount(backup_id)

    try:
        # Browse root — path separator is "|" per mount response
        items = browse(session_id, "|")
        if not items:
            print("[!] Root browse returned no items. Trying '/' ...")
            items = browse(session_id, "/")

        if not items:
            print("[!] No items found at root.")
            sys.exit(1)

        # Collect all file paths recursively, starting from root dirs/files
        all_files = []
        sep = "|"
        for item in items:
            itype = item.get("type", "").lower()
            loc   = item.get("location", "")
            name  = item.get("name", "")
            if itype == "file":
                all_files.append(loc or name)
            elif itype in ("directory", "folder"):
                all_files.extend(collect_files(session_id, loc or name, sep))

        if not all_files:
            print("[!] No files found to copy.")
            sys.exit(1)

        print(f"\n[*] Files to copy ({len(all_files)}):")
        for f in all_files:
            print(f"      {f}")

        task_id = copy_to_local(session_id, all_files)
        poll_task(task_id)

    finally:
        unmount(session_id)

    print(f"\n[+] Done. Log files are at: {LOCAL_PATH}")


if __name__ == "__main__":
    main()
