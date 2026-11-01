#!/usr/bin/env python3
import argparse
import getpass
import io
import os
import shutil
import sys
import zipfile
import time
from datetime import datetime, timedelta, timezone

import requests
import urllib3

API_VERSION = "1.3-rev2"
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parse_args():
    p = argparse.ArgumentParser(description="Export Veeam B&R logs via REST API")
    p.add_argument("--server", required=True, help="Backup server hostname or IP")
    p.add_argument("--port", type=int, default=9419)
    p.add_argument("--user", required=True)
    p.add_argument("--password", help="Falls back to VEEAM_PASSWORD env var or prompt")
    p.add_argument("--hours", type=int, default=24, help="Export last N hours (default 24)")
    p.add_argument("--from", dest="date_from", help="Start, e.g. 2026-10-01T00:00")
    p.add_argument("--to", dest="date_to", help="End, e.g. 2026-10-02T00:00 (default now)")
    p.add_argument("--all", action="store_true", help="Export all logs, ignore time range")
    p.add_argument("--scope", choices=["Hosts", "Jobs"], default="Hosts")
    p.add_argument("--host-ids", nargs="*", default=[], help="Managed server IDs (empty = backup server)")
    p.add_argument("--job-ids", nargs="*", default=[], help="Job IDs (required for scope Jobs)")
    p.add_argument("--pg-logs", action="store_true", help="Include local PostgreSQL logs")
    p.add_argument("--output", help="Target folder for audit logs, or ZIP file with --full")
    p.add_argument("--full", action="store_true", help="Keep the complete log bundle instead of audit logs only")
    p.add_argument("--keep-zip", action="store_true", help="Keep the downloaded ZIP next to the audit folder")
    p.add_argument("--timeout", type=int, default=3600, help="Max wait for export in seconds")
    return p.parse_args()


def to_utc(value):
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt.astimezone(timezone.utc)


def is_audit_path(name):
    parts = [x.lower() for x in name.replace("\\", "/").split("/") if x]
    return any(parts[i] == "backup" and parts[i + 1] == "audit" for i in range(len(parts) - 1))


def extract_audit(zf, target, prefix=""):
    count = 0
    for info in zf.infolist():
        name = info.filename.replace("\\", "/")
        if name.lower().endswith(".zip"):
            with zf.open(info) as inner:
                with zipfile.ZipFile(io.BytesIO(inner.read())) as nested:
                    count += extract_audit(nested, target, prefix + os.path.splitext(name)[0] + "/")
            continue
        full = prefix + name
        if info.is_dir() or not is_audit_path(full):
            continue
        dest = os.path.normpath(os.path.join(target, full))
        if not dest.startswith(os.path.abspath(target)):
            continue
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with zf.open(info) as src, open(dest, "wb") as dst:
            shutil.copyfileobj(src, dst)
        count += 1
    return count


class Api:
    def __init__(self, base):
        self.base = base
        self.headers = {"x-api-version": API_VERSION}

    # verify=False is passed on every call so env vars like REQUESTS_CA_BUNDLE cannot override it
    def call(self, method, path, **kw):
        r = requests.request(method, self.base + path, headers=self.headers, verify=False, **kw)
        r.raise_for_status()
        return r


def main():
    args = parse_args()

    if args.scope == "Jobs" and not args.job_ids:
        sys.exit("Error: --job-ids is required when --scope Jobs is used")

    password = args.password or os.environ.get("VEEAM_PASSWORD") or getpass.getpass("Password: ")
    api = Api(f"https://{args.server}:{args.port}")

    r = api.call("POST", "/api/oauth2/token",
                 data={"grant_type": "password", "username": args.user, "password": password})
    api.headers["Authorization"] = f"Bearer {r.json()['access_token']}"

    try:
        body = {"scopeType": args.scope, "exportLocalPgLogs": args.pg_logs}
        if args.scope == "Hosts":
            body["hostIds"] = args.host_ids
        else:
            body["jobIds"] = args.job_ids

        if args.all:
            body["exportType"] = "All"
            print("Exporting all logs")
        else:
            date_to = to_utc(args.date_to) if args.date_to else datetime.now(timezone.utc)
            date_from = to_utc(args.date_from) if args.date_from else date_to - timedelta(hours=args.hours)
            if date_from >= date_to:
                sys.exit("Error: start must be before end")
            body["exportType"] = "DateRange"
            body["dateFrom"] = date_from.isoformat().replace("+00:00", "Z")
            body["dateTo"] = date_to.isoformat().replace("+00:00", "Z")
            print(f"Exporting logs from {body['dateFrom']} to {body['dateTo']}")

        session_id = api.call("POST", "/api/v1/exportlogs", json=body).json()["id"]
        print(f"Export session started: {session_id}")

        deadline = time.time() + args.timeout
        while True:
            sess = api.call("GET", f"/api/v1/sessions/{session_id}").json()
            print(f"  state={sess.get('state')} progress={sess.get('progressPercent', 0)}%")
            if sess.get("state") == "Stopped":
                break
            if time.time() > deadline:
                sys.exit("Error: export did not finish within timeout")
            time.sleep(10)

        result = (sess.get("result") or {}).get("result")
        if result not in ("Success", "Warning"):
            sys.exit(f"Error: export finished with result {result}: {sess['result'].get('message')}")

        stamp = f"{args.server}_{datetime.now():%Y%m%d_%H%M%S}"
        if args.full:
            zip_path = args.output or f"veeam_logs_{stamp}.zip"
        else:
            out_dir = os.path.abspath(args.output or f"veeam_audit_{stamp}")
            zip_path = out_dir + ".zip"

        with api.call("GET", f"/api/v1/exportlogs/{session_id}/download", stream=True) as r:
            with open(zip_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    f.write(chunk)
        print(f"Downloaded {zip_path} ({os.path.getsize(zip_path) / 1024 / 1024:.1f} MB)")

        if not args.full:
            os.makedirs(out_dir, exist_ok=True)
            with zipfile.ZipFile(zip_path) as zf:
                count = extract_audit(zf, out_dir)
            if not args.keep_zip:
                os.remove(zip_path)
            if count == 0:
                print("Warning: no files found under Backup/Audit in the log bundle")
            else:
                print(f"Extracted {count} audit file(s) to {out_dir}")

    finally:
        try:
            api.call("POST", "/api/oauth2/logout")
        except requests.RequestException:
            pass


if __name__ == "__main__":
    main()
