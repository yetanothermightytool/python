#!/usr/bin/env python3
import argparse
import requests
import json
import datetime
import sys
import time
from cryptography.fernet import Fernet
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

API_VERSION = "1.3-rev1"
USERNAME = "Administrator"
REQUEST_TIMEOUT = 120

def get_password() -> str:
    with open("encryption_key.key", "rb") as kf:
        key = kf.read()
    with open("encrypted_password.bin", "rb") as pf:
        encrypted = pf.read()
    return Fernet(key).decrypt(encrypted).decode()

def create_session():
    sess = requests.Session()
    sess.headers.update({
        "x-api-version": API_VERSION,
        "accept": "application/json",
    })
    return sess

def obtain_bearer_token(sess, username, password, api_url):
    token_url = f"{api_url}/api/oauth2/token"
    payload = {
        "grant_type": "password",
        "username": username,
        "password": password,
        "refresh_token": "",
        "rememberMe": ""
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = sess.post(token_url, data=payload, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
    resp.raise_for_status()
    return resp.json()["access_token"]

def api_get(sess, endpoint, token, api_url, params=None):
    url = f"{api_url}/api/{endpoint}"
    hdr = {"Authorization": f"Bearer {token}"}
    resp = sess.get(url, headers=hdr, params=params, timeout=REQUEST_TIMEOUT, verify=False)
    resp.raise_for_status()
    return resp.json()

def api_post(sess, endpoint, token, api_url, body):
    url = f"{api_url}/api/{endpoint}"
    hdr = {"Authorization": f"Bearer {token}"}
    resp = sess.post(url, headers=hdr, json=body, timeout=REQUEST_TIMEOUT, verify=False)
    resp.raise_for_status()
    return resp.json()

def display_restore_points(rp: dict):
    print("\n{:5} {:30} {:20} {:15}".format("Idx", "Name/Hostname", "Creation Time", "Malware"))
    print("-" * 75)
    for idx, point in enumerate(rp["data"]):
        raw = point["creationTime"]
        fmt = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
        status = point.get("malwareStatus", "-")
        if status.lower() == "clean":
            status = "✅ Clean"
        elif status:
            status = f"🐞 {status}"
        print("{:5} {:30} {:20} {:15}".format(idx, point["name"], fmt, status))

def get_restore_point(sess, token, hostname, api_url):
    params = {
        "skip": "0", "limit": "10", "orderColumn": "CreationTime",
        "orderAsc": "false", "nameFilter": hostname
    }
    data = api_get(sess, "v1/restorePoints", token, api_url, params)
    if not data.get("data"):
        print(f"❌ No restore points for {hostname}.")
        return None
    return data

def get_credentials_id(sess, token, user, api_url):
    params = {"nameFilter": user}
    resp = api_get(sess, "v1/credentials", token, api_url, params)
    if not resp.get("data"):
        print(f"❌ No credentials found for user '{user}'!")
        return None
    cred_id = resp["data"][0]["id"]
    print(f"✅ Using credentials ID: {cred_id} for user '{user}'")
    return cred_id

def start_flr_session(sess, token, rp, api_url, credentials_id=None):
    body = {
        "restorePointId": rp["id"],
        "type": "Windows",
        "autoUnmount": {
            "isEnabled": True,
            "noActivityPeriodInMinutes": 15
        },
        "mountMode": "Automatic",
        "reason": "Automated FLR"
    }
    if credentials_id:
        body["credentialsId"] = credentials_id
    flr_resp = api_post(sess, "v1/restore/flr", token, api_url, body)
    #print("DEBUG FLR API-RESPONSE:", flr_resp)
    return flr_resp

def validate_credentials(sess, token, session_id, api_url):
    url = f"{api_url}/api/v1/restore/flr/{session_id}/validateCredentials"
    body = {
        "restoreMode": "OriginalLocation"
    }
    headers = {
        "x-api-version": API_VERSION,
        "Authorization": f"Bearer {token}"
    }
    #print(f"DEBUG validate_credentials BODY: {body}, SESSION_ID: {session_id}")
    try:
        resp = sess.post(url, json=body, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
        if resp.status_code == 200:
            print("✅ Credentials validated for FLR session.")
        else:
            print("⚠️  Credentials validation returned status:", resp.status_code)
    except requests.exceptions.Timeout:
        print("❌ Connection timed out while validating credentials.")
        sys.exit(2)
    except requests.exceptions.RequestException as e:
        print(f"❌ Exception during credential validation: {e}")
        sys.exit(2)

def browse_flr(sess, token, session_id, api_url, path):
    url = f"{api_url}/api/v1/backupBrowser/flr/{session_id}/browse"
    payload = {
        "path": path,
    }
    headers = {
        "Content-Type": "application/json",
        "x-api-version": API_VERSION,
        "Authorization": f"Bearer {token}"
    }
    #print(f"DEBUG browse_flr BODY: {payload}, SESSION_ID: {session_id}")
    try:
        resp = sess.post(url, json=payload, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
        print(json.dumps(resp.json(), indent=2))
        try:
            print("✅ Browse successful.")
        except Exception:
            print(resp.text)
    except requests.exceptions.Timeout:
        print("❌ Connection timed out while browsing FLR.")
        sys.exit(3)
    except requests.exceptions.RequestException as e:
        print(f"❌ Exception during FLR browse: {e}")
        sys.exit(3)

def compare_flr(sess, token, session_id, api_url, paths):
    url = f"{api_url}/api/v1/backupBrowser/flr/{session_id}/compareToProduction"
    payload = {
        "isEnabled": True,
        "paths": paths
    }
    headers = {
        "Content-Type": "application/json",
        "x-api-version": API_VERSION,
        "Authorization": f"Bearer {token}"
    }
    #print(f"DEBUG compare_flr BODY: {payload}, SESSION_ID: {session_id}")
    try:
        resp = sess.post(url, json=payload, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
        try:
            print("✅ Compare to Production started.")
        except Exception:
            print(resp.text)
    except requests.exceptions.Timeout:
        print("❌ Connection timed out while running FLR compare.")
        sys.exit(4)
    except requests.exceptions.RequestException as e:
        print(f"❌ Exception during FLR compare: {e}")
        sys.exit(4)

def poll_browse_until_done(sess, token, session_id, api_url, path, max_wait=120, interval=10):
    waited = 0
    data = None
    while waited < max_wait:
        url = f"{api_url}/api/v1/backupBrowser/flr/{session_id}/browse"
        payload = {"path": path}
        headers = {
            "Content-Type": "application/json",
            "x-api-version": API_VERSION,
            "Authorization": f"Bearer {token}"
        }
        resp = sess.post(url, json=payload, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
        data = resp.json()
        comparing_items = [item for item in data.get("items", []) if item.get("itemState") == "Comparing"]
        if not comparing_items:
            print(json.dumps(data, indent=2))
            return data
        print(f"Still comparing {len(comparing_items)} items, waited {waited} seconds...")
        time.sleep(interval)
        waited += interval
    print("Timeout reached. Some items are still comparing.")
    print(json.dumps(data, indent=2))
    return data

def get_filename(host, rp):
    raw_time = rp.get("creationTime", "")
    try:
        dt = datetime.datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
    except Exception:
        dt = datetime.datetime.now()
    timestamp = dt.strftime("%Y%m%d_%H%M%S")
    filename = f"{host}_compare_{timestamp}.json"
    return filename

def main():
    parser = argparse.ArgumentParser(description="Veeam FLR Compare Script")
    parser.add_argument("--host", required=True, help="VM hostname to restore from")
    parser.add_argument("--vbrserver", default="vbr.test.local", help="VBR Server hostname (default: vbr.test.local)")
    parser.add_argument("--user", required=True, help="Credential username for Windows FLR")
    parser.add_argument("--comparepaths", nargs='+', help="One or more paths to compare, e.g. --comparepaths C:\\Users C:\\Downloads")
    parser.add_argument("--output", action="store_true", help="Write comparison result to a JSON file")
    parser.add_argument("--latest", action="store_true", help="Automatically select the latest restore point")
    args = parser.parse_args()

    api_url = f"https://{args.vbrserver}:9419"
    password = get_password()
    sess = create_session()
    token = obtain_bearer_token(sess, USERNAME, password, api_url)

    rpdata = get_restore_point(sess, token, args.host, api_url)
    if not rpdata or not rpdata.get("data"):
        sys.exit(1)

    print(f"📂 Restore points for {args.host}:")
    display_restore_points(rpdata)
    if args.latest:
        sel_idx = 0
    else:
        try:
            sel_idx = int(input("❓ Number: "))
        except Exception:
            sel_idx = 0
        if sel_idx < 0 or sel_idx >= len(rpdata["data"]):
            print("❌ Invalid input – defaulting to 0.")
            sel_idx = 0
    rp = rpdata["data"][sel_idx]

    credentials_id = get_credentials_id(sess, token, args.user, api_url)
    if not credentials_id:
        sys.exit(1)

    flr = start_flr_session(sess, token, rp, api_url, credentials_id=credentials_id)
    session_id = flr.get("sessionId") or flr.get("id")
    if not session_id:
        print("❌ Could not determine FLR session ID.")
        sys.exit(1)
    print(f"✅ FLR Session started: {session_id}")

    validate_credentials(sess, token, session_id, api_url)

    comparison_results = {}
    if args.comparepaths:
        compare_flr(sess, token, session_id, api_url, args.comparepaths)
        print("⏳ Waiting for comparison to finish...")

        for path in args.comparepaths:
            print(f"🔍 Browsing comparison results for: {path}")
            data = poll_browse_until_done(sess, token, session_id, api_url, path, max_wait=120, interval=10)
            comparison_results[path] = data

        if args.output:
            filename = get_filename(args.host, rp)
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(comparison_results, f, indent=2)
            print(f"✅ Output written to {filename}")
    
if __name__ == "__main__":
    main()
