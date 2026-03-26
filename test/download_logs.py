#!/usr/bin/env python3
"""
Veeam EntraID Audit Log Downloader
Workflow:
  1.  POST /api/oauth2/token
  2.  GET  /api/v1/backups                          → find EntraID log backup
  3.  POST /api/v1/restore/entraId/auditLog         → mount (backupId, all-time)
  4.  GET  /api/v1/inventory/unstructuredDataServers → find dest server by hostname
  5.  POST /api/v1/backupBrowser/flr/unstructuredData/{sid}/browse  path=""  → list months
  6.  POST /api/v1/backupBrowser/flr/unstructuredData/{sid}/copyTo  (LatestPoint, recursive)
  7.  POST /api/v1/restore/unstructuredData/{sid}/unmount
  8.  POST /api/v1/oauth2/logout

Modes:
  --auto    Copy current month folder automatically
  --manual  Show all available folders and let user pick (default)
"""

import argparse
import socket
import time
import json
import sys
import pprint
from datetime import datetime

import requests
import urllib3
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
API_VER    = cfg.get("VEEAM_API_VERSION", "1.3-rev1")
API        = f"{BASE_URL}/api/v1"

http = requests.Session()
http.verify = SSL_VERIFY


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------
def _headers(token=None):
    h = {"accept": "application/json", "x-api-version": API_VER}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def get_token() -> str:
    print("[*] Authenticating ...")
    resp = requests.post(
        f"{BASE_URL}/api/oauth2/token",
        headers=_headers(),
        data={"grant_type": "password", "username": VEEAM_USER, "password": VEEAM_PASS},
        verify=SSL_VERIFY,
    )
    resp.raise_for_status()
    token = resp.json()["access_token"]
    http.headers.update(_headers(token))
    print("[+] Token obtained.")
    return token


def logout(token: str):
    try:
        requests.post(f"{BASE_URL}/api/oauth2/logout", headers=_headers(token), verify=SSL_VERIFY)
        print("[+] Logged out.")
    except Exception:
        pass


def _raise(resp):
    try:
        detail = resp.json()
    except Exception:
        detail = resp.text
    print(f"[-] HTTP {resp.status_code} {resp.request.method} {resp.url}")
    print(f"    {json.dumps(detail, indent=2) if isinstance(detail, dict) else detail}")
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
    return resp.json() if resp.content and resp.content.strip() else {}


# ---------------------------------------------------------------------------
# Step 2: Find EntraID log backup
# ---------------------------------------------------------------------------
def find_entraid_backup() -> dict:
    print("[*] Searching for EntraID audit log backup ...")
    data = api_get("/backups")
    items = data.get("data", []) if isinstance(data, dict) else data
    candidates = []
    for b in items:
        name = (b.get("name") or "").lower()
        jtype = (b.get("jobType") or b.get("type") or "").lower()
        plat = (b.get("platformName") or b.get("platform") or "").lower()
        if (
            ("entra" in jtype and "log" in jtype)
            or ("entra" in plat and ("log" in plat or "audit" in plat))
            or ("entra" in name and "log" in name)
            or ("audit" in name and "entra" in name)
        ):
            candidates.append(b)

    if not candidates:
        # Fallback: show all backups and use first
        print(f"[!] No EntraID log backup found by name/type. All backups ({len(items)}):")
        for b in items:
            print(f"      id={b['id']}  name={b.get('name','?')}  type={b.get('jobType','?')}")
        if not items:
            print("[-] No backups at all.")
            sys.exit(1)
        print("[!] Using first backup as fallback.")
        return items[0]

    print(f"[+] Found {len(candidates)} candidate(s):")
    for b in candidates:
        print(f"      id={b['id']}  name={b.get('name','?')}")
    return candidates[0]


# ---------------------------------------------------------------------------
# Step 3: Mount
# ---------------------------------------------------------------------------
def start_mount(backup_id: str, sleep_sec: int = 12) -> tuple[str, str]:
    """Returns (sessionId, pathSeparator)."""
    print(f"[*] Mounting EntraID audit log (backupId={backup_id}) ...")
    result = api_post("/restore/entraId/auditLog", {
        "backupId": backup_id,
        "autoUnmount": {"isEnabled": True, "noActivityPeriodInMinutes": 45},
    })
    print(f"[+] Mount response: {json.dumps(result, indent=2)}")
    session_id = result.get("sessionId")
    sep = result.get("properties", {}).get("pathSeparator") or "|"
    if not session_id:
        print("[-] No sessionId returned.")
        sys.exit(1)
    print(f"[*] Sleeping {sleep_sec}s before first browse ...")
    time.sleep(sleep_sec)
    return session_id, sep


# ---------------------------------------------------------------------------
# Step 4: Unstructured data servers
# ---------------------------------------------------------------------------
def list_unstructured_servers() -> list:
    print("[*] Listing unstructured data servers ...")
    data = api_get("/inventory/unstructuredDataServers",
                   params={"skip": "0", "limit": "0", "orderColumn": "Name", "orderAsc": "true"})
    servers = data.get("data", []) if isinstance(data, dict) else data
    print(f"    Found {len(servers)} server(s):")
    for s in servers:
        sid  = s.get("id") or s.get("serverId")
        name = s.get("name") or s.get("hostName") or s.get("displayName") or "?"
        stype = s.get("type", "?")
        print(f"      id={sid}  name={name}  type={stype}")
    return servers


def choose_dest_server(servers: list) -> str:
    """Match local hostname/FQDN against server list; fallback to first."""
    host = socket.gethostname().lower()
    fqdn = socket.getfqdn().lower()
    keys = ("name", "hostName", "hostname", "displayName", "fqdn")
    for s in servers:
        names = [str(s.get(k, "")).lower() for k in keys]
        if fqdn in names or host in names:
            sid = s.get("id") or s.get("serverId")
            print(f"[+] Matched dest server by hostname: {sid}")
            return sid
    for s in servers:
        txt = " ".join(str(s.get(k, "")).lower() for k in keys)
        if host in txt or fqdn in txt:
            sid = s.get("id") or s.get("serverId")
            print(f"[+] Matched dest server by partial hostname: {sid}")
            return sid
    sid = servers[0].get("id") or servers[0].get("serverId")
    print(f"[!] No hostname match — using first server: {sid}")
    return sid


# ---------------------------------------------------------------------------
# Step 5: Browse
# ---------------------------------------------------------------------------
def flr_browse(session_id: str, path: str = "", item_types: list = None) -> list:
    payload = {
        "path": path,
        "filter": ({"itemTypes": item_types} if item_types else {}),
        "order": {"orderColumn": "Name", "orderAsc": True},
        "pagination": {"skip": 0, "limit": 0},
    }
    print(f"  → browse path='{path}'")
    result = api_post(f"/backupBrowser/flr/unstructuredData/{session_id}/browse", payload)
    return result.get("items", [])


# ---------------------------------------------------------------------------
# Step 6: CopyTo
# ---------------------------------------------------------------------------
def flr_copy_to(session_id: str, source_paths: list, dest_server_id: str,
                dest_path: str, recursive: bool = True):
    body = {
        "sourcePath": source_paths,
        "isRecursive": recursive,
        "restoreMode": "LatestPoint",
        "unstructuredDataServerId": dest_server_id,
        "copyToBackupServer": False,
        "path": dest_path,
    }
    print(f"[*] CopyTo: {len(source_paths)} item(s) → {dest_path}  recursive={recursive}")
    result = api_post(f"/backupBrowser/flr/unstructuredData/{session_id}/copyTo", body)
    print("[+] CopyTo result:")
    pprint.pprint(result)
    return result


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
# Helpers: path / month
# ---------------------------------------------------------------------------
def item_path(item: dict, sep: str, parent_hint: str = "") -> str:
    p = item.get("path") or item.get("location")
    if p:
        if sep in p or (parent_hint and p.startswith(parent_hint)):
            return p
        if parent_hint:
            return parent_hint.rstrip(sep) + sep + p
    parent = parent_hint or item.get("parentPath") or ""
    name   = item.get("name") or ""
    if not parent:
        return name
    return parent.rstrip(sep) + sep + name


def pick_current_month(items: list, sep: str) -> dict:
    now   = datetime.now()
    year  = str(now.year)
    months_de = ["januar","februar","märz","april","mai","juni","juli",
                 "august","september","oktober","november","dezember"]
    months_en = ["january","february","march","april","may","june","july",
                 "august","september","october","november","december"]
    month_de = months_de[now.month - 1]
    month_en = months_en[now.month - 1]
    month_ch = "auguscht" if now.month == 8 else month_de

    def norm(s: str) -> str:
        s = (s or "").lower().strip()
        for ch, r in [("ä","ae"),("ö","oe"),("ü","ue")]:
            s = s.replace(ch, r)
        for ch in (" ","_","-","."):
            s = s.replace(ch, "")
        return s

    for it in items:
        n = norm(it.get("name") or "")
        has_m = any(m in n for m in [month_en, month_de, month_ch, month_en[:3], month_de[:3]])
        has_y = year in n
        if has_m and has_y:
            return it

    raise RuntimeError(f"No folder found for current month ({month_en} {year}).")


# ---------------------------------------------------------------------------
# Flows
# ---------------------------------------------------------------------------
def auto_flow(session_id: str, sep: str, dest_server_id: str, dest_path: str):
    print("[*] AUTO mode: copying current month ...")
    months = flr_browse(session_id, path="", item_types=["Folder"])
    if not months:
        raise RuntimeError("No month folders at root.")

    month_item = pick_current_month(months, sep)
    month_path = item_path(month_item, sep)
    print(f"[+] Current month folder: {month_path}")

    # List sub-folders (e.g. "Audit Logs", "Sign-in Logs")
    children = flr_browse(session_id, path=month_path, item_types=["Folder"])
    if children:
        print(f"    Sub-folders in month:")
        for c in children:
            print(f"      {item_path(c, sep, month_path)}")
        wanted = [item_path(c, sep, month_path) for c in children if item_path(c, sep, month_path)]
        if not wanted:
            wanted = [month_path]
    else:
        wanted = [month_path]

    flr_copy_to(session_id, wanted, dest_server_id, dest_path, recursive=True)


def manual_flow(session_id: str, sep: str, dest_server_id: str, dest_path: str, recursive: bool):
    print("[*] MANUAL mode: listing available folders ...")
    items = flr_browse(session_id, path="", item_types=["Folder"])
    if not items:
        raise RuntimeError("No folders at root.")

    print("\nIndex | Path")
    print("-" * 70)
    paths = []
    for i, it in enumerate(items):
        p = item_path(it, sep)
        print(f"  {i:>3} | {p}")
        paths.append(p)

    pick = input("\nFolder index(es) to restore (comma-separated, default=0): ").strip()
    if not pick:
        chosen = [paths[0]]
    else:
        chosen = []
        for t in pick.split(","):
            t = t.strip()
            if t.isdigit() and 0 <= int(t) < len(paths) and paths[int(t)]:
                chosen.append(paths[int(t)])
        if not chosen:
            chosen = [paths[0]]

    print(f"[*] Selected: {chosen}")
    flr_copy_to(session_id, chosen, dest_server_id, dest_path, recursive=recursive)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Veeam EntraID Audit Log FLR")
    parser.add_argument("--auto", action="store_true",
                        help="Automatic: copy current month folder recursively.")
    parser.add_argument("--dest-path", default="/tmp/entraid-logs",
                        help="Destination path on the unstructured data server.")
    parser.add_argument("--recursive", action="store_true",
                        help="Manual mode: copy recursively.")
    parser.add_argument("--sleep", type=int, default=12,
                        help="Seconds to wait after mount before browsing (default: 12).")
    args = parser.parse_args()

    if not BASE_URL or not VEEAM_USER:
        print("[-] Please fill in config.env.")
        sys.exit(1)

    token = get_token()
    session_id = None
    try:
        backup = find_entraid_backup()
        backup_id = backup["id"]
        print(f"[+] Using backup: {backup.get('name','?')} ({backup_id})")

        session_id, sep = start_mount(backup_id, sleep_sec=args.sleep)
        print(f"[+] Session: {session_id}  pathSeparator='{sep}'")

        servers = list_unstructured_servers()
        if not servers:
            raise RuntimeError("No unstructured data servers found.")
        dest_server_id = choose_dest_server(servers)

        if args.auto:
            auto_flow(session_id, sep, dest_server_id, args.dest_path)
        else:
            manual_flow(session_id, sep, dest_server_id, args.dest_path, args.recursive)

    finally:
        if session_id:
            unmount(session_id)
        logout(token)


if __name__ == "__main__":
    main()
