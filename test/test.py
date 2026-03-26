#!/usr/bin/python3
import argparse
import time
import socket
from datetime import datetime
import requests
import pprint
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from cryptography.fernet import Fernet

# ===== baseline =====
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
API_URL      = "https://vbrserver:9419"
API_VERSION  = "1.3-rev1"
USERNAME     = "restapiuser"

# ===== secrets =====
def get_password():
    with open("encryption_key.key", "rb") as kf:
        key = kf.read()
    with open("encrypted_password.bin", "rb") as pf:
        enc = pf.read()
    return Fernet(key).decrypt(enc).decode()

# ===== HTTP =====
def _headers(token=None, json_ct=False, xver=None):
    h = {"accept": "application/json", "x-api-version": xver or API_VERSION}
    if token:
        h["Authorization"] = f"Bearer {token}"
    if json_ct:
        h["Content-Type"] = "application/json"
    return h

def http_get(url, token, params=None):
    r = requests.get(url, headers=_headers(token), params=params, verify=False)
    try:
        r.raise_for_status()
    except requests.HTTPError as e:
        raise requests.HTTPError(f"{e} — Response body: {r.text}", response=r)
    return r.json()

def http_post(url, token, body):
    r = requests.post(url, headers=_headers(token, json_ct=True), json=body, verify=False)
    try:
        r.raise_for_status()
    except requests.HTTPError as e:
        raise requests.HTTPError(f"{e} — Response body: {r.text}", response=r)
    return r.json() if r.content and r.content.strip() else {}

def auth(username, password):
    url = f"{API_URL}/api/oauth2/token"
    body = {
        "grant_type": "password",
        "username": username,
        "password": password,
        "refresh_token": " ",
        "rememberMe": " ",
    }
    r = requests.post(url, headers=_headers(None), data=body, verify=False)
    r.raise_for_status()
    return r.json()["access_token"]

def logout(token):
    url = f"{API_URL}/api/oauth2/logout"
    r = requests.post(url, headers=_headers(token), verify=False)
    r.raise_for_status()
    print("✅ Logout successful.")

# ===== path helpers =====
def join_path(parent: str, name: str, sep: str) -> str:
    parent = parent or ""
    name = name or ""
    if not parent:
        return name
    return parent + ("" if parent.endswith(sep) else sep) + name

def item_path(item: dict, sep: str, parent_hint: str = None) -> str:
    """Prefer item's 'path' if complete; else parent_hint/parentPath + name."""
    if not isinstance(item, dict):
        return ""
    p = item.get("path")
    if p:
        if (sep in p) or (parent_hint and p.startswith(parent_hint)):
            return p
        if parent_hint:
            return join_path(parent_hint, p, sep)
    parent = parent_hint or item.get("parentPath") or ""
    name   = item.get("name") or ""
    return join_path(parent, name, sep)

def item_name(item: dict, sep: str) -> str:
    n = (item.get("name") or "").strip()
    if n:
        return n
    p = (item.get("path") or "").strip()
    if p and sep in p:
        return p.split(sep)[-1]
    return p or n

def is_root_child(item: dict, sep: str) -> bool:
    """Root-level month folders only."""
    parent = (item.get("parentPath") or "").strip()
    return parent == "" or parent == sep

# ===== domain =====
def list_entra_log_backups(token):
    print("STEP 1: List Entra LOG backups …")
    data = http_get(f"{API_URL}/api/v1/backups", token)
    items = data.get("data") or data.get("backups") or []
    cands = []
    for b in items if isinstance(items, list) else []:
        name = (b.get("name") or "").lower()
        jt   = (b.get("jobType") or b.get("type") or "").lower()
        pf   = (b.get("platformName") or b.get("platform") or "").lower()
        if ("entra" in jt and "log" in jt) or ("entra" in pf and ("log" in pf or "audit" in pf)) or ("entra" in name and "log" in name) or ("audit" in name and "entra" in name):
            cands.append(b)
    print(f"FOUND: {len(cands)} candidate backups.")
    return cands

def start_audit_log_restore(token, backup_id, auto_unmount_minutes=45):
    print(f"STEP 2: Start FLR session for backup {backup_id} …")
    url = f"{API_URL}/api/v1/restore/entraId/auditLog"
    body = {"backupId": backup_id, "autoUnmount": {"isEnabled": True, "noActivityPeriodInMinutes": int(auto_unmount_minutes)}}
    res  = http_post(url, token, body)
    sid  = (res or {}).get("sessionId") or (res or {}).get("id")
    src_props = (res or {}).get("sourceProperties") or {}
    sep  = src_props.get("pathSeparator") or "/"
    print(f"RESULT: sessionId = {sid} | pathSeparator = '{sep}'")
    return sid, sep

def flr_browse(token, session_id, path="", item_types=None, order_col="Name", order_asc=True, skip=0, limit=0):
    url = f"{API_URL}/api/v1/backupBrowser/flr/unstructuredData/{session_id}/browse"
    payload = {
        "path": path or "",
        "filter": ({ "itemTypes": item_types } if item_types else {}),
        "order":  { "orderColumn": order_col, "orderAsc": bool(order_asc) },
        "pagination": { "skip": int(skip), "limit": int(limit) }
    }
    print(f"  → BROWSE path='{payload['path']}' filter={payload.get('filter')}")
    return http_post(url, token, payload)

def list_unstructured_servers(token):
    print("STEP X: List unstructured data servers …")
    data = http_get(f"{API_URL}/api/v1/inventory/unstructuredDataServers", token,
                    params={"skip":"0","limit":"0","orderColumn":"Name","orderAsc":"true"})
    sv = data.get("data") or data.get("items") or []
    print(f"FOUND: {len(sv)} servers.")
    return sv

def flr_copy_to(token, session_id, source_paths, server_id=None, dest_path="/tmp",
                recursive=False, restore_mode="LatestPoint", to_dt=None,
                copy_to_backup_server=False):
    """Copy selected source paths to dest_path on the chosen unstructured data server."""
    url  = f"{API_URL}/api/v1/backupBrowser/flr/unstructuredData/{session_id}/copyTo"
    body = {
        "sourcePath": source_paths,
        "isRecursive": bool(recursive),
        "restoreMode": restore_mode,
        "toDateTime": to_dt,
        "copyToBackupServer": bool(copy_to_backup_server),
        "path": dest_path
    }
    if not copy_to_backup_server:
        if not server_id:
            raise ValueError("unstructuredDataServerId is required when copy_to_backup_server=False")
        body["unstructuredDataServerId"] = server_id

    print(f"STEP COPY → dest={dest_path} | items={len(source_paths)} | recursive={recursive} | mode={restore_mode} | toDateTime={to_dt}")
    res = http_post(url, token, body)
    print("COPY RESULT:"); pprint.pprint(res)
    return res

# ===== helpers =====
def choose_dest_server_id(servers):
    """Pick unstructured data server matching local hostname/FQDN; fallback to first."""
    host = socket.gethostname().lower()
    fqd  = socket.getfqdn().lower()
    name_keys = ("name","hostName","hostname","displayName","fqdn")
    for s in servers:
        names = [str(s.get(k,"")).lower() for k in name_keys]
        if fqd in names or host in names:
            return s.get("id") or s.get("serverId")
    for s in servers:
        txt = " ".join([str(s.get(k,"")).lower() for k in name_keys])
        if host in txt or fqd in txt:
            return s.get("id") or s.get("serverId")
    return servers[0].get("id") or servers[0].get("serverId")

def pick_current_month_item(items, sep):
    """Pick current month folder (supports de/en + 'auguscht'), must contain current year."""
    now = datetime.now()
    year = str(now.year)
    mnum = f"{now.month:02d}"
    months_de = ["januar","februar","märz","april","mai","juni","juli","august","september","oktober","november","dezember"]
    month_de = months_de[now.month-1]
    month_ch = "auguscht" if now.month == 8 else month_de
    months_en = ["january","february","march","april","may","june","july","august","september","october","november","december"]
    month_en = months_en[now.month-1]

    def norm(s: str) -> str:
        s = (s or "").strip().lower().replace("ä","ae").replace("ö","oe").replace("ü","ue")
        for ch in (" ", "_", "-", "."):
            s = s.replace(ch, "")
        return s

    cands = []
    for it in items:
        if not is_root_child(it, sep):
            continue
        n = norm(item_name(it, sep))
        has_m = (month_en in n) or (month_de in n) or (month_ch in n) or (month_en[:3] in n) or (month_de[:3] in n)
        has_y = year in n or f"{year}{mnum}" in n or f"{mnum}{year}" in n
        if has_m and has_y:
            cands.append(it)

    if not cands:
        raise RuntimeError(f"No folder found for current month ({month_ch} {year}).")
    cands.sort(key=lambda it: len(norm(item_name(it, sep))))
    return cands[0]

# ===== auto: ALL files via LatestPoint (recursive) on child folders =====
def auto_flow_latest_point(token, session_id, sep, dest_server_id, dest_path, _ignored):
    """
    Copy ALL log files visible at the latest restore point by restoring
    the month’s child folders (e.g., 'Audit Logs', 'Sign-in Logs') recursively.
    Uses exact API 'path' values and restore_mode='LatestPoint'.
    """
    # 1) list months at root
    root = flr_browse(token, session_id, path="", item_types=["Folder"], order_col="Name", order_asc=True)
    months = root.get("items", []) or root.get("data", []) or []
    if not months:
        raise RuntimeError("No month folders found at root.")

    # 2) pick current month
    month_item = pick_current_month_item(months, sep)
    month_path = month_item.get("path") or item_path(month_item, sep)
    print(f"AUTO: month = {month_path}")

    # 3) list children under month and select relevant folders
    kids = flr_browse(token, session_id, path=month_path, item_types=["Folder"], order_col="Name", order_asc=True)
    items = kids.get("items", []) or kids.get("data", []) or []

    wanted = []
    for it in items:
        name = (it.get("name") or item_name(it, sep) or "").lower()
        p = it.get("path")
        if not p:
            continue
        # pick typical log subfolders; adjust if deine Namen anders sind
        if "sign" in name or "audit" in name:
            wanted.append(p)

    # Fallback: if nothing matched, copy all child folders
    if not wanted:
        wanted = [it["path"] for it in items if it.get("path")]

    if not wanted:
        # last resort: copy the month itself (recursive)
        wanted = [month_path]

    print(f"AUTO: restoring {len(wanted)} folder(s) recursively (LatestPoint) to {dest_path}")
    flr_copy_to(token, session_id, wanted, dest_server_id,
                dest_path=dest_path, recursive=True,      # recursive allowed for LatestPoint
                restore_mode="LatestPoint", to_dt=None,
                copy_to_backup_server=False)
    print("AUTO: Done.")

# ===== manual =====
def manual_flow(token, session_id, dest_server_id, dest_path="/tmp", recursive=False, sep="/"):
    print("MANUAL: Browse root folders …")
    root = flr_browse(token, session_id, path="", item_types=["Folder"], order_col="Name", order_asc=True)
    items = root.get("items", []) or root.get("data", []) or []
    if not items:
        raise RuntimeError("No folders in root.")
    print("\nIndex | Folder")
    print("-"*70)
    paths = []
    for i, it in enumerate(items):
        p = item_path(it, sep)
        print(f"{i:>5} | {p}")
        paths.append(p)

    pick = input("Enter folder index(es) to export (comma-separated, default 0): ").strip()
    if not pick:
        chosen = [paths[0]]
    else:
        chosen = []
        for t in pick.split(","):
            t = t.strip()
            if t.isdigit():
                j = int(t)
                if 0 <= j < len(paths) and paths[j]:
                    chosen.append(paths[j])
        if not chosen:
            chosen = [paths[0]]

    print("MANUAL: Selected folder(s):"); pprint.pprint(chosen)
    flr_copy_to(token, session_id, chosen, dest_server_id,
                dest_path=dest_path, recursive=bool(recursive),
                restore_mode="LatestPoint", to_dt=None,
                copy_to_backup_server=False)

# ===== main =====
def main():
    parser = argparse.ArgumentParser(description="Entra ID Audit Logs FLR — Auto (LatestPoint, recursive on child folders) or Manual")
    parser.add_argument("--auto", action="store_true", help="Automatic: copy month child folders recursively at LatestPoint.")
    parser.add_argument("--sleep-after-start", type=int, default=12, help="Seconds to sleep after FLR start before first browse (default 12).")
    parser.add_argument("--dest-path", default="/tmp/entra-restore", help="Destination path on Unstructured Data Server (default /tmp/entra-restore).")
    parser.add_argument("--recursive", action="store_true", help="Manual only: copy selected folders recursively.")
    args = parser.parse_args()

    token = auth(USERNAME, get_password())
    session_id = None
    try:
        backs = list_entra_log_backups(token)
        if not backs:
            raise RuntimeError("No Entra ID LOG backups found.")
        backup_id = backs[0]["id"]
        print(f"== Using LOG backupId: {backup_id}")

        session_id, sep = start_audit_log_restore(token, backup_id)
        if not session_id:
            raise RuntimeError("No sessionId returned.")
        print(f"== Session ID: {session_id} | pathSeparator='{sep}'")
        print(f"== Sleep {args.sleep_after_start}s before first browse …")
        time.sleep(max(0, int(args.sleep_after_start)))

        servers = list_unstructured_servers(token)
        if not servers:
            raise RuntimeError("No unstructured data servers found.")
        dest_server_id = choose_dest_server_id(servers)
        print(f"== Destination server: {dest_server_id}")

        if args.auto:
            auto_flow_latest_point(
                token=token,
                session_id=session_id,
                sep=sep,
                dest_server_id=dest_server_id,
                dest_path=args.dest_path,
                _ignored=0
            )
        else:
            manual_flow(
                token=token,
                session_id=session_id,
                dest_server_id=dest_server_id,
                dest_path=args.dest_path,
                recursive=bool(args.recursive),
                sep=sep
            )

    finally:
        if token:
            logout(token)

if __name__ == "__main__":
    main()

