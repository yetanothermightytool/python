#!/usr/bin/env python3
"""
EntraID Audit Log → Neo4j Importer

Reads "Audit Logs" .log files from a Windows SMB share and imports
them into Neo4j running on Linux.

Graph model:
  Nodes:
    (:AuditEvent)       — one per log entry
    (:User)             — deduped by Microsoft ID
    (:Application)      — deduped by AppId
    (:ServicePrincipal) — deduped by Microsoft ID
    (:IPAddress)        — deduped by address

  Relationships:
    (:User)-[:INITIATED]->(:AuditEvent)
    (:Application)-[:INITIATED]->(:AuditEvent)
    (:AuditEvent)-[:TARGETED {modifiedProperties}]->(:User|:ServicePrincipal|:Other)
    (:User)-[:USED_IP]->(:IPAddress)

Usage:
  python3 import_neo4j.py
  python3 import_neo4j.py --neo4j-uri bolt://localhost:7687
"""

import argparse
import json
import sys
from pathlib import Path

import smbclient
import smbclient.path
from neo4j import GraphDatabase
from dotenv import dotenv_values

cfg = dotenv_values("config.env")


# ---------------------------------------------------------------------------
# Neo4j connection
# ---------------------------------------------------------------------------
def get_driver(uri: str, user: str, password: str):
    driver = GraphDatabase.driver(uri, auth=(user, password))
    driver.verify_connectivity()
    print(f"[+] Connected to Neo4j: {uri}")
    return driver


# ---------------------------------------------------------------------------
# Schema / indexes
# ---------------------------------------------------------------------------
INDEXES = [
    "CREATE CONSTRAINT audit_event_id IF NOT EXISTS FOR (e:AuditEvent) REQUIRE e.id IS UNIQUE",
    "CREATE CONSTRAINT user_id IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE",
    "CREATE CONSTRAINT app_id IF NOT EXISTS FOR (a:Application) REQUIRE a.appId IS UNIQUE",
    "CREATE CONSTRAINT sp_id IF NOT EXISTS FOR (s:ServicePrincipal) REQUIRE s.id IS UNIQUE",
    "CREATE CONSTRAINT ip_addr IF NOT EXISTS FOR (i:IPAddress) REQUIRE i.address IS UNIQUE",
]

def create_indexes(session):
    for stmt in INDEXES:
        session.run(stmt)
    print("[+] Indexes/constraints ensured.")


# ---------------------------------------------------------------------------
# SMB connection
# ---------------------------------------------------------------------------
def smb_connect():
    host   = cfg.get("SMB_HOST", "")
    user   = cfg.get("SMB_USER", "")
    passwd = cfg.get("SMB_PASS", "")
    domain = cfg.get("SMB_DOMAIN", "")
    if not host or not user:
        print("[-] SMB_HOST and SMB_USER must be set in config.env.")
        sys.exit(1)
    kwargs = {"username": user, "password": passwd}
    if domain:
        kwargs["domain"] = domain
    smbclient.register_session(host, **kwargs)
    print(f"[+] SMB session registered: {host}")


def smb_root() -> str:
    host    = cfg.get("SMB_HOST", "")
    share   = cfg.get("SMB_SHARE", "")
    subpath = cfg.get("SMB_PATH", "").strip("\\/ ")
    root = f"\\\\{host}\\{share}"
    if subpath:
        root = root + "\\" + subpath
    return root


# ---------------------------------------------------------------------------
# Log file discovery (over SMB)
# ---------------------------------------------------------------------------
def find_log_files() -> list[str]:
    root = smb_root()
    files = []
    print(f"[*] Scanning SMB share: {root}")
    try:
        month_dirs = sorted(smbclient.listdir(root))
    except Exception as e:
        print(f"[-] Cannot list share root '{root}': {e}")
        sys.exit(1)

    for month_name in month_dirs:
        month_path = root + "\\" + month_name
        if not smbclient.path.isdir(month_path):
            continue
        # Find "Audit Logs" subfolder (case-insensitive)
        try:
            children = smbclient.listdir(month_path)
        except Exception:
            continue
        audit_dir = None
        for child in children:
            if "audit" in child.lower():
                audit_dir = month_path + "\\" + child
                break
        if not audit_dir:
            continue
        try:
            log_names = sorted(smbclient.listdir(audit_dir))
        except Exception:
            continue
        for name in log_names:
            if name.lower().endswith(".log"):
                files.append(audit_dir + "\\" + name)

    print(f"[+] Found {len(files)} log file(s).")
    return files


def parse_log_file(smb_path: str) -> list[dict]:
    try:
        with smbclient.open_file(smb_path, mode="r", encoding="utf-8-sig") as f:
            text = f.read().strip()
    except Exception as e:
        print(f"[!] Cannot read '{smb_path}': {e}")
        return []
    if not text or text == "[]":
        return []
    try:
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError as e:
        print(f"[!] JSON parse error in {smb_path}: {e}")
        return []


# ---------------------------------------------------------------------------
# Cypher queries
# ---------------------------------------------------------------------------
MERGE_EVENT = """
MERGE (e:AuditEvent {id: $id})
SET e.activityDateTime    = $activityDateTime,
    e.activityDisplayName = $activityDisplayName,
    e.category            = $category,
    e.operationType       = $operationType,
    e.result              = $result,
    e.resultReason        = $resultReason,
    e.loggedByService     = $loggedByService,
    e.correlationId       = $correlationId
"""

MERGE_USER_INITIATED = """
MERGE (u:User {id: $userId})
SET u.userPrincipalName = $upn,
    u.displayName       = COALESCE($displayName, u.displayName)
WITH u
MATCH (e:AuditEvent {id: $eventId})
MERGE (u)-[:INITIATED]->(e)
"""

MERGE_APP_INITIATED = """
MERGE (a:Application {appId: $appId})
SET a.displayName        = COALESCE($displayName, a.displayName),
    a.servicePrincipalId = COALESCE($spId, a.servicePrincipalId)
WITH a
MATCH (e:AuditEvent {id: $eventId})
MERGE (a)-[:INITIATED]->(e)
"""

MERGE_IP = """
MERGE (ip:IPAddress {address: $address})
WITH ip
MATCH (u:User {id: $userId})
MERGE (u)-[:USED_IP]->(ip)
"""

MERGE_TARGET_USER = """
MERGE (t:User {id: $targetId})
SET t.userPrincipalName = COALESCE($upn, t.userPrincipalName),
    t.displayName       = COALESCE($displayName, t.displayName)
WITH t
MATCH (e:AuditEvent {id: $eventId})
MERGE (e)-[r:TARGETED]->(t)
SET r.modifiedProperties = $modifiedProperties
"""

MERGE_TARGET_SP = """
MERGE (t:ServicePrincipal {id: $targetId})
SET t.displayName = COALESCE($displayName, t.displayName)
WITH t
MATCH (e:AuditEvent {id: $eventId})
MERGE (e)-[r:TARGETED]->(t)
SET r.modifiedProperties = $modifiedProperties
"""

MERGE_TARGET_OTHER = """
MATCH (e:AuditEvent {id: $eventId})
MERGE (t:TargetResource {id: $targetId})
SET t.displayName = COALESCE($displayName, t.displayName),
    t.type        = $type
MERGE (e)-[r:TARGETED]->(t)
SET r.modifiedProperties = $modifiedProperties
"""


# ---------------------------------------------------------------------------
# Import logic
# ---------------------------------------------------------------------------
def modified_props_str(props: list) -> str:
    """Compact summary of ModifiedProperties for relationship property."""
    if not props:
        return ""
    parts = []
    for p in props:
        name = p.get("DisplayName", "?")
        old  = p.get("OldValue", "")
        new  = p.get("NewValue", "")
        parts.append(f"{name}: {old} → {new}")
    return " | ".join(parts)


def import_event(tx, event: dict):
    eid = event.get("Id", "")
    if not eid:
        return

    # --- AuditEvent node ---
    tx.run(MERGE_EVENT, {
        "id":                   eid,
        "activityDateTime":     event.get("ActivityDateTime", ""),
        "activityDisplayName":  event.get("ActivityDisplayName", ""),
        "category":             event.get("Category", ""),
        "operationType":        event.get("OperationType", ""),
        "result":               event.get("Result", -1),
        "resultReason":         event.get("ResultReason", ""),
        "loggedByService":      event.get("LoggedByService", ""),
        "correlationId":        event.get("CorrelationId", ""),
    })

    # --- Initiator ---
    initiated_by = event.get("InitiatedBy") or {}
    user_actor   = initiated_by.get("User")
    app_actor    = initiated_by.get("App")

    if user_actor and user_actor.get("Id"):
        tx.run(MERGE_USER_INITIATED, {
            "userId":  user_actor["Id"],
            "upn":     user_actor.get("UserPrincipalName", ""),
            "displayName": user_actor.get("DisplayName"),
            "eventId": eid,
        })
        ip = user_actor.get("IpAddress", "")
        if ip:
            tx.run(MERGE_IP, {"address": ip, "userId": user_actor["Id"]})

    if app_actor and app_actor.get("AppId"):
        tx.run(MERGE_APP_INITIATED, {
            "appId":       app_actor["AppId"],
            "displayName": app_actor.get("DisplayName"),
            "spId":        app_actor.get("ServicePrincipalId"),
            "eventId":     eid,
        })

    # --- Target resources ---
    for target in (event.get("TargetResources") or []):
        tid   = target.get("Id") or ""
        ttype = target.get("Type") or "Other"
        tdisplay = target.get("DisplayName")
        tupn  = target.get("UserPrincipalName")
        mprops = modified_props_str(target.get("ModifiedProperties") or [])

        if not tid:
            continue

        if ttype == "User":
            tx.run(MERGE_TARGET_USER, {
                "targetId": tid, "upn": tupn,
                "displayName": tdisplay, "eventId": eid,
                "modifiedProperties": mprops,
            })
        elif ttype == "ServicePrincipal":
            tx.run(MERGE_TARGET_SP, {
                "targetId": tid, "displayName": tdisplay,
                "eventId": eid, "modifiedProperties": mprops,
            })
        else:
            tx.run(MERGE_TARGET_OTHER, {
                "targetId": tid, "displayName": tdisplay,
                "type": ttype, "eventId": eid,
                "modifiedProperties": mprops,
            })


def import_events(driver, events: list, batch_size: int = 200):
    total = 0
    skipped = 0
    with driver.session() as session:
        batch = []
        for event in events:
            batch.append(event)
            if len(batch) >= batch_size:
                with session.begin_transaction() as tx:
                    for e in batch:
                        try:
                            import_event(tx, e)
                            total += 1
                        except Exception as ex:
                            print(f"[!] Skipped event {e.get('Id','?')}: {ex}")
                            skipped += 1
                batch = []
        if batch:
            with session.begin_transaction() as tx:
                for e in batch:
                    try:
                        import_event(tx, e)
                        total += 1
                    except Exception as ex:
                        print(f"[!] Skipped event {e.get('Id','?')}: {ex}")
                        skipped += 1
    return total, skipped


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Import EntraID Audit Logs into Neo4j")
    parser.add_argument("--neo4j-uri",  default=cfg.get("NEO4J_URI", "bolt://localhost:7687"),
                        help="Neo4j bolt URI.")
    parser.add_argument("--neo4j-user", default=cfg.get("NEO4J_USER", "neo4j"),
                        help="Neo4j username.")
    parser.add_argument("--neo4j-pass", default=cfg.get("NEO4J_PASS", ""),
                        help="Neo4j password.")
    args = parser.parse_args()

    smb_connect()
    driver = get_driver(args.neo4j_uri, args.neo4j_user, args.neo4j_pass)

    with driver.session() as session:
        create_indexes(session)

    log_files = find_log_files()
    if not log_files:
        print("[-] No log files found.")
        sys.exit(1)

    all_events = []
    empty_files = 0
    for f in log_files:
        events = parse_log_file(f)
        if events:
            all_events.extend(events)
            print(f"    {f.split(chr(92))[-1]}: {len(events)} event(s)")
        else:
            empty_files += 1

    print(f"\n[+] Total events to import: {len(all_events)}  (skipped {empty_files} empty files)")

    if not all_events:
        print("[-] Nothing to import.")
        sys.exit(0)

    total, skipped = import_events(driver, all_events)
    driver.close()

    print(f"\n[+] Import complete: {total} events imported, {skipped} skipped.")
    print("""
Useful Cypher queries to get started:

  // All activities by a user
  MATCH (u:User)-[:INITIATED]->(e:AuditEvent)
  RETURN u.userPrincipalName, e.activityDisplayName, e.activityDateTime
  ORDER BY e.activityDateTime DESC LIMIT 50

  // Which users were targeted most
  MATCH (e:AuditEvent)-[:TARGETED]->(u:User)
  RETURN u.userPrincipalName, count(e) AS changes ORDER BY changes DESC

  // IPs used per user
  MATCH (u:User)-[:USED_IP]->(ip:IPAddress)
  RETURN u.userPrincipalName, collect(ip.address) AS ips

  // Correlated events (same CorrelationId)
  MATCH (e:AuditEvent) WHERE e.correlationId = '<id>'
  RETURN e ORDER BY e.activityDateTime

  // All property changes on a specific user
  MATCH (e:AuditEvent)-[r:TARGETED]->(u:User {userPrincipalName: 'user@domain.com'})
  WHERE r.modifiedProperties <> ''
  RETURN e.activityDateTime, e.activityDisplayName, r.modifiedProperties
""")


if __name__ == "__main__":
    main()
