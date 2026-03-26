#!/usr/bin/env python3
"""
EntraID Audit Log + Sign-in Log → Neo4j Importer

Reads "Audit Logs" and "Sign-in Logs" .log files from a Windows SMB share
and imports them into Neo4j running on Linux.

Graph model:
  Nodes:
    (:AuditEvent)       — one per audit log entry
    (:SignInEvent)      — one per sign-in log entry
    (:User)             — deduped by Microsoft ID (shared across both)
    (:Application)      — deduped by AppId
    (:ServicePrincipal) — deduped by Microsoft ID
    (:IPAddress)        — deduped by address (shared across both)
    (:Location)         — deduped by city+country
    (:Correlation)      — deduped by correlationId (groups related events)
    (:ErrorCode)        — deduped by errorCode (sign-in failures)

  Relationships:
    (:User)-[:INITIATED]->(:AuditEvent)
    (:Application)-[:INITIATED]->(:AuditEvent)
    (:AuditEvent)-[:TARGETED {modifiedProperties}]->(:User|:ServicePrincipal|:TargetResource)
    (:User)-[:CHANGED_BY]->(:User)           — actor changed target user (from AuditEvent)
    (:AuditEvent)-[:PART_OF]->(:Correlation)
    (:User)-[:INITIATED]->(:SignInEvent)
    (:SignInEvent)-[:ACCESSED]->(:Application)
    (:SignInEvent)-[:FROM_LOCATION]->(:Location)
    (:SignInEvent)-[:PART_OF]->(:Correlation)
    (:SignInEvent)-[:FAILED_WITH]->(:ErrorCode)
    (:User)-[:USED_IP]->(:IPAddress)
    (:IPAddress)-[:LOCATED_IN]->(:Location)

Usage:
  python3 import_neo4j.py
  python3 import_neo4j.py --neo4j-uri bolt://localhost:7687
"""

import argparse
import json
import sys

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
    "CREATE CONSTRAINT audit_event_id   IF NOT EXISTS FOR (e:AuditEvent)       REQUIRE e.id             IS UNIQUE",
    "CREATE CONSTRAINT signin_event_id  IF NOT EXISTS FOR (e:SignInEvent)       REQUIRE e.id             IS UNIQUE",
    "CREATE CONSTRAINT user_id          IF NOT EXISTS FOR (u:User)              REQUIRE u.id             IS UNIQUE",
    "CREATE CONSTRAINT app_id           IF NOT EXISTS FOR (a:Application)       REQUIRE a.appId          IS UNIQUE",
    "CREATE CONSTRAINT sp_id            IF NOT EXISTS FOR (s:ServicePrincipal)  REQUIRE s.id             IS UNIQUE",
    "CREATE CONSTRAINT ip_addr          IF NOT EXISTS FOR (i:IPAddress)         REQUIRE i.address        IS UNIQUE",
    "CREATE CONSTRAINT location_id      IF NOT EXISTS FOR (l:Location)          REQUIRE l.id             IS UNIQUE",
    "CREATE CONSTRAINT correlation_id   IF NOT EXISTS FOR (c:Correlation)       REQUIRE c.correlationId  IS UNIQUE",
    "CREATE CONSTRAINT errorcode_id     IF NOT EXISTS FOR (ec:ErrorCode)        REQUIRE ec.code          IS UNIQUE",
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
# Returns list of (smb_path, log_type) where log_type is "audit" or "signin"
# ---------------------------------------------------------------------------
def find_log_files() -> list[tuple[str, str]]:
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
        try:
            children = smbclient.listdir(month_path)
        except Exception:
            continue
        for child in children:
            child_lower = child.lower()
            if "audit" in child_lower:
                log_type = "audit"
            elif "sign" in child_lower:
                log_type = "signin"
            else:
                continue
            child_path = month_path + "\\" + child
            try:
                log_names = sorted(smbclient.listdir(child_path))
            except Exception:
                continue
            for name in log_names:
                if name.lower().endswith(".log"):
                    files.append((child_path + "\\" + name, log_type))

    audit_count  = sum(1 for _, t in files if t == "audit")
    signin_count = sum(1 for _, t in files if t == "signin")
    print(f"[+] Found {len(files)} log file(s): {audit_count} audit, {signin_count} sign-in.")
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
# Shared Cypher helpers
# ---------------------------------------------------------------------------
MERGE_IP = """
MERGE (ip:IPAddress {address: $address})
WITH ip
MATCH (u:User {id: $userId})
MERGE (u)-[:USED_IP]->(ip)
"""

MERGE_IP_LOCATION = """
MERGE (l:Location {id: $locationId})
SET l.city    = $city,
    l.country = $country
WITH l
MERGE (ip:IPAddress {address: $address})
MERGE (ip)-[:LOCATED_IN]->(l)
"""

MERGE_CORRELATION = """
MERGE (c:Correlation {correlationId: $correlationId})
WITH c
MATCH (e {id: $eventId})
MERGE (e)-[:PART_OF]->(c)
"""


# ---------------------------------------------------------------------------
# Audit log Cypher
# ---------------------------------------------------------------------------
MERGE_AUDIT_EVENT = """
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

MERGE_USER_INITIATED_AUDIT = """
MERGE (u:User {id: $userId})
SET u.userPrincipalName = COALESCE($upn, u.userPrincipalName),
    u.displayName       = COALESCE($displayName, u.displayName)
WITH u
MATCH (e:AuditEvent {id: $eventId})
MERGE (u)-[:INITIATED]->(e)
"""

MERGE_APP_INITIATED_AUDIT = """
MERGE (a:Application {appId: $appId})
SET a.displayName        = COALESCE($displayName, a.displayName),
    a.servicePrincipalId = COALESCE($spId, a.servicePrincipalId)
WITH a
MATCH (e:AuditEvent {id: $eventId})
MERGE (a)-[:INITIATED]->(e)
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
MERGE (t:TargetResource {id: $targetId})
SET t.displayName = COALESCE($displayName, t.displayName),
    t.type        = $type
WITH t
MATCH (e:AuditEvent {id: $eventId})
MERGE (e)-[r:TARGETED]->(t)
SET r.modifiedProperties = $modifiedProperties
"""

MERGE_CHANGED_BY = """
MATCH (actor:User {id: $actorId})
MATCH (target:User {id: $targetId})
MERGE (target)-[r:CHANGED_BY]->(actor)
SET r.lastSeen          = $dateTime,
    r.operationCount    = COALESCE(r.operationCount, 0) + 1
"""


def modified_props_str(props: list) -> str:
    if not props:
        return ""
    parts = []
    for p in props:
        name = p.get("DisplayName", "?")
        old  = p.get("OldValue", "")
        new  = p.get("NewValue", "")
        parts.append(f"{name}: {old} → {new}")
    return " | ".join(parts)


def import_audit_event(tx, event: dict):
    eid = event.get("Id", "")
    if not eid:
        return

    tx.run(MERGE_AUDIT_EVENT, {
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

    initiated_by = event.get("InitiatedBy") or {}
    user_actor   = initiated_by.get("User")
    app_actor    = initiated_by.get("App")

    if user_actor and user_actor.get("Id"):
        tx.run(MERGE_USER_INITIATED_AUDIT, {
            "userId":      user_actor["Id"],
            "upn":         user_actor.get("UserPrincipalName", ""),
            "displayName": user_actor.get("DisplayName"),
            "eventId":     eid,
        })
        ip = user_actor.get("IpAddress", "")
        if ip:
            tx.run(MERGE_IP, {"address": ip, "userId": user_actor["Id"]})

    if app_actor and app_actor.get("AppId"):
        tx.run(MERGE_APP_INITIATED_AUDIT, {
            "appId":       app_actor["AppId"],
            "displayName": app_actor.get("DisplayName"),
            "spId":        app_actor.get("ServicePrincipalId"),
            "eventId":     eid,
        })

    actor_user_id = (initiated_by.get("User") or {}).get("Id")

    for target in (event.get("TargetResources") or []):
        tid      = target.get("Id") or ""
        ttype    = target.get("Type") or "Other"
        tdisplay = target.get("DisplayName")
        tupn     = target.get("UserPrincipalName")
        mprops   = modified_props_str(target.get("ModifiedProperties") or [])
        if not tid:
            continue
        if ttype == "User":
            tx.run(MERGE_TARGET_USER, {
                "targetId": tid, "upn": tupn,
                "displayName": tdisplay, "eventId": eid,
                "modifiedProperties": mprops,
            })
            if actor_user_id and actor_user_id != tid:
                tx.run(MERGE_CHANGED_BY, {
                    "actorId":  actor_user_id,
                    "targetId": tid,
                    "dateTime": event.get("ActivityDateTime", ""),
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

    # Correlation
    corr = event.get("CorrelationId", "")
    if corr:
        tx.run(MERGE_CORRELATION, {"correlationId": corr, "eventId": eid})


# ---------------------------------------------------------------------------
# Sign-in log Cypher
# ---------------------------------------------------------------------------
MERGE_SIGNIN_EVENT = """
MERGE (e:SignInEvent {id: $id})
SET e.createdDateTime         = $createdDateTime,
    e.appDisplayName          = $appDisplayName,
    e.clientAppUsed           = $clientAppUsed,
    e.isInteractive           = $isInteractive,
    e.correlationId           = $correlationId,
    e.conditionalAccessStatus = $conditionalAccessStatus,
    e.riskLevelAggregated     = $riskLevelAggregated,
    e.riskLevelDuringSignIn   = $riskLevelDuringSignIn,
    e.riskState               = $riskState,
    e.errorCode               = $errorCode,
    e.failureReason           = $failureReason,
    e.ipAddress               = $ipAddress,
    e.city                    = $city,
    e.country                 = $country,
    e.browser                 = $browser,
    e.operatingSystem         = $operatingSystem,
    e.resourceDisplayName     = $resourceDisplayName
"""

MERGE_USER_INITIATED_SIGNIN = """
MERGE (u:User {id: $userId})
SET u.userPrincipalName = COALESCE($upn, u.userPrincipalName),
    u.displayName       = COALESCE($displayName, u.displayName)
WITH u
MATCH (e:SignInEvent {id: $eventId})
MERGE (u)-[:INITIATED]->(e)
"""

MERGE_APP_ACCESSED = """
MERGE (a:Application {appId: $appId})
SET a.displayName = COALESCE($displayName, a.displayName)
WITH a
MATCH (e:SignInEvent {id: $eventId})
MERGE (e)-[:ACCESSED]->(a)
"""

MERGE_SIGNIN_LOCATION = """
MERGE (l:Location {id: $locationId})
SET l.city    = $city,
    l.country = $country
WITH l
MATCH (e:SignInEvent {id: $eventId})
MERGE (e)-[:FROM_LOCATION]->(l)
"""

MERGE_ERRORCODE = """
MERGE (ec:ErrorCode {code: $code})
SET ec.description = COALESCE($description, ec.description)
WITH ec
MATCH (e:SignInEvent {id: $eventId})
MERGE (e)-[:FAILED_WITH]->(ec)
"""


def import_signin_event(tx, event: dict):
    eid = event.get("Id", "")
    if not eid:
        return

    status    = event.get("Status") or {}
    device    = event.get("DeviceDetail") or {}
    location  = event.get("Location") or {}

    tx.run(MERGE_SIGNIN_EVENT, {
        "id":                     eid,
        "createdDateTime":        event.get("CreatedDateTime", ""),
        "appDisplayName":         event.get("AppDisplayName", ""),
        "clientAppUsed":          event.get("ClientAppUsed", ""),
        "isInteractive":          event.get("IsInteractive", False),
        "correlationId":          event.get("CorrelationId", ""),
        "conditionalAccessStatus": event.get("ConditionalAccessStatus", -1),
        "riskLevelAggregated":    event.get("RiskLevelAggregated", 0),
        "riskLevelDuringSignIn":  event.get("RiskLevelDuringSignIn", 0),
        "riskState":              event.get("RiskState", 0),
        "errorCode":              status.get("ErrorCode", 0),
        "failureReason":          status.get("FailureReason", ""),
        "ipAddress":              event.get("IpAddress", ""),
        "city":                   location.get("City", ""),
        "country":                location.get("CountryOrRegion", ""),
        "browser":                device.get("Browser", ""),
        "operatingSystem":        device.get("OperatingSystem", ""),
        "resourceDisplayName":    event.get("ResourceDisplayName", ""),
    })

    user_id  = event.get("UserId", "")
    user_upn = event.get("UserPrincipalName", "")
    user_dn  = event.get("UserDisplayName", "")
    if user_id:
        tx.run(MERGE_USER_INITIATED_SIGNIN, {
            "userId":      user_id,
            "upn":         user_upn,
            "displayName": user_dn,
            "eventId":     eid,
        })
        ip = event.get("IpAddress", "")
        if ip:
            tx.run(MERGE_IP, {"address": ip, "userId": user_id})

    app_id = event.get("AppId", "")
    if app_id:
        tx.run(MERGE_APP_ACCESSED, {
            "appId":       app_id,
            "displayName": event.get("AppDisplayName", ""),
            "eventId":     eid,
        })

    # Location
    city    = location.get("City", "")
    country = location.get("CountryOrRegion", "")
    if city or country:
        location_id = f"{country}:{city}".lower()
        tx.run(MERGE_SIGNIN_LOCATION, {
            "locationId": location_id,
            "city":       city,
            "country":    country,
            "eventId":    eid,
        })
        ip = event.get("IpAddress", "")
        if ip:
            tx.run(MERGE_IP_LOCATION, {
                "locationId": location_id,
                "city":       city,
                "country":    country,
                "address":    ip,
            })

    # ErrorCode (only on failure)
    error_code = status.get("ErrorCode", 0)
    if error_code and error_code != 0:
        tx.run(MERGE_ERRORCODE, {
            "code":        error_code,
            "description": status.get("FailureReason", ""),
            "eventId":     eid,
        })

    # Correlation
    corr = event.get("CorrelationId", "")
    if corr:
        tx.run(MERGE_CORRELATION, {"correlationId": corr, "eventId": eid})


# ---------------------------------------------------------------------------
# Batch import
# ---------------------------------------------------------------------------
def import_all(driver, audit_events: list, signin_events: list, batch_size: int = 200):
    total_audit = total_signin = skipped = 0

    def run_batch(session, batch, fn):
        nonlocal skipped
        with session.begin_transaction() as tx:
            for e in batch:
                try:
                    fn(tx, e)
                except Exception as ex:
                    print(f"[!] Skipped {e.get('Id','?')}: {ex}")
                    skipped += 1

    with driver.session() as session:
        batch = []
        for e in audit_events:
            batch.append(e)
            if len(batch) >= batch_size:
                run_batch(session, batch, import_audit_event)
                total_audit += len(batch)
                batch = []
        if batch:
            run_batch(session, batch, import_audit_event)
            total_audit += len(batch)

        batch = []
        for e in signin_events:
            batch.append(e)
            if len(batch) >= batch_size:
                run_batch(session, batch, import_signin_event)
                total_signin += len(batch)
                batch = []
        if batch:
            run_batch(session, batch, import_signin_event)
            total_signin += len(batch)

    return total_audit, total_signin, skipped


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Import EntraID Audit + Sign-in Logs into Neo4j")
    parser.add_argument("--neo4j-uri",  default=cfg.get("NEO4J_URI",  "bolt://localhost:7687"))
    parser.add_argument("--neo4j-user", default=cfg.get("NEO4J_USER", "neo4j"))
    parser.add_argument("--neo4j-pass", default=cfg.get("NEO4J_PASS", ""))
    args = parser.parse_args()

    smb_connect()
    driver = get_driver(args.neo4j_uri, args.neo4j_user, args.neo4j_pass)

    with driver.session() as session:
        create_indexes(session)

    log_files = find_log_files()
    if not log_files:
        print("[-] No log files found.")
        sys.exit(1)

    audit_events  = []
    signin_events = []
    empty_files   = 0

    for smb_path, log_type in log_files:
        events = parse_log_file(smb_path)
        fname  = smb_path.split("\\")[-1]
        if events:
            if log_type == "audit":
                audit_events.extend(events)
            else:
                signin_events.extend(events)
            print(f"    [{log_type:6}] {fname}: {len(events)} event(s)")
        else:
            empty_files += 1

    print(f"\n[+] Audit events:  {len(audit_events)}")
    print(f"[+] Sign-in events:{len(signin_events)}")
    print(f"[+] Empty files:   {empty_files}")

    if not audit_events and not signin_events:
        print("[-] Nothing to import.")
        sys.exit(0)

    total_audit, total_signin, skipped = import_all(driver, audit_events, signin_events)
    driver.close()

    print(f"\n[+] Import complete:")
    print(f"    Audit events imported:   {total_audit}")
    print(f"    Sign-in events imported: {total_signin}")
    print(f"    Skipped:                 {skipped}")
    print("""
Useful Cypher queries:

  // Who changed whom most often
  MATCH (target:User)-[r:CHANGED_BY]->(actor:User)
  RETURN actor.userPrincipalName, target.userPrincipalName, r.operationCount
  ORDER BY r.operationCount DESC

  // Failed sign-ins per user
  MATCH (u:User)-[:INITIATED]->(e:SignInEvent)-[:FAILED_WITH]->(ec:ErrorCode)
  RETURN u.userPrincipalName, ec.code, ec.description, count(e) AS failures
  ORDER BY failures DESC

  // Sign-ins by country
  MATCH (e:SignInEvent)-[:FROM_LOCATION]->(l:Location)
  RETURN l.country, l.city, count(e) AS total ORDER BY total DESC

  // High-risk sign-ins with location
  MATCH (u:User)-[:INITIATED]->(e:SignInEvent)-[:FROM_LOCATION]->(l:Location)
  WHERE e.riskLevelAggregated >= 4
  RETURN u.userPrincipalName, e.ipAddress, l.city, l.country, e.createdDateTime

  // All events in the same correlation group (audit + sign-in together)
  MATCH (e)-[:PART_OF]->(c:Correlation {correlationId: '<id>'})
  RETURN labels(e), e ORDER BY e.createdDateTime

  // IPs and their locations
  MATCH (ip:IPAddress)-[:LOCATED_IN]->(l:Location)
  RETURN ip.address, l.city, l.country

  // User changed AND had failed sign-in (potential account takeover)
  MATCH (target:User)-[:CHANGED_BY]->(actor:User)
  MATCH (target)-[:INITIATED]->(s:SignInEvent)-[:FAILED_WITH]->(ec:ErrorCode)
  RETURN target.userPrincipalName, actor.userPrincipalName, ec.code, count(s) AS failedSignIns
  ORDER BY failedSignIns DESC
""")


if __name__ == "__main__":
    main()
