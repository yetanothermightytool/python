#!/usr/bin/python3
import os
import sys
import base64
import subprocess
import argparse
import datetime
import time
from cryptography.fernet import Fernet
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

os.system('clear')

# Disable SSL warnings - Use only in test environments
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Variables - Change where necessary
api_url         = "https://vbr-server-here:9419"
api_version     = "1.2-rev0"

# Function - Get Bearer Token from Veeam REST API
def connect_veeam_rest_api(api_url, username, password):
    token_url = f"{api_url}/api/oauth2/token"

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "x-api-version": api_version,
        "accept": "application/json"
    }

    body = {
        "grant_type"    : "password",
        "username"      : username,
        "password"      : password,
        "refresh_token" : "",
        "rememberMe"    : ""
    }

    response = requests.post(token_url, headers=headers, data=body, verify=False)
    response.raise_for_status()

    return response.json()["access_token"]

# Function - POST against Veeam REST API
def post_veeam_rest_api(api_url, endpoint, token, body):
    url     = f"{api_url}/api/{endpoint}"
    headers = {
        "accept": "application/json",
        "x-api-version": api_version,
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }

    response = requests.post(url, headers=headers, json=body, verify=False)
    response.raise_for_status()

    return response.json()

# Function - GET against Veeam REST API
def get_veeam_rest_api(api_url, endpoint, token, params=None):
    url     = f"{api_url}/api/{endpoint}"
    headers = {
        "accept": "application/json",
        "x-api-version": api_version,
        "Authorization": f"Bearer {token}"
    }

    response = requests.get(url, headers=headers, params=params, verify=False)
    response.raise_for_status()

    return response.json()

# Function - Logout from Veeam REST API
def post_logout(api_url, token):
    url     = f"{api_url}/api/oauth2/logout"
    headers = {
        "accept": "application/json",
        "x-api-version": api_version,
        "Authorization": f"Bearer {token}"
    }

    response = requests.post(url, headers=headers, verify=False)

    response.raise_for_status()
    print("✅ Logout successful.")

# Function - Display Restore Points
def display_restore_points(restorePoint):
    print("\n{:<5} {:<25} {:<20} {:<15}".format("Index", "Hostname", "Creation Time", "Malware Status"))
    print("-" * 70)

    for idx, point in enumerate(restorePoint["data"][:10]):
        # Format creationTime - Check frational seconds have 6 digits otherwise add 0s
        # Issue found with restore points created before v12.1. Investigating.
        raw_time = point["creationTime"]

        if "." in raw_time:
            base, fractional = raw_time.split(".")
            if "+" in fractional or "-" in fractional:
                fractional, tz = fractional.split("+") if "+" in fractional else fractional.split("-")
                fractional = fractional.ljust(6, "0")
                raw_time = f"{base}.{fractional}+{tz}" if "+" in raw_time else f"{base}.{fractional}-{tz}"
            else:
                fractional = fractional.ljust(6, "0")
                raw_time = f"{base}.{fractional}"

        formatted_time = datetime.datetime.fromisoformat(raw_time.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")

        if point["malwareStatus"].lower() == "clean":
            status_display = "✅ Clean"
        else:
            status_display = "🐞 " + point["malwareStatus"]
        print("{:<5} {:<25} {:<20} {:<15}".format(idx, point["name"], formatted_time, status_display))

# Function - Scan Backup Session Monitoring
def monitor_session(api_url, scan_session_id, token):
    scan_session_endpoint = f"v1/sessions/{scan_session_id}"

    headers = {
        "accept": "application/json",
        "x-api-version": api_version,
        "Authorization": f"Bearer {token}"
    }

    print("🚀 Monitoring session progress...")

    while True:
        response = get_veeam_rest_api(api_url, scan_session_endpoint, token)
        state    = response.get("state", "Unknown")
        progress = response.get("progressPercent", 0)
        result   = response.get("result", {}).get("result", "").strip()
        message  = response.get("result", {}).get("message", "")

        if state.lower() != "stopped":
            sys.stdout.write(f"\r🔄 State: {state} - Progress: {progress}%  ")
            sys.stdout.flush()
            time.sleep(5)
        else:
            if "failed" in result.lower():
                result = "Threats have been detected!"
            sys.stdout.write(f"\r🔄 State: {state} - Progress: {progress}%   \n")
            sys.stdout.flush()
            print("✅ Session stopped!")
            print(f"🎯 Final Result: {result}")  # Modified result is used here
            break

# Function - Get Stored Password
def get_password():
    try:
        with open("encryption_key.key", "rb") as key_file:
            key = key_file.read()

        with open("encrypted_password.bin", "rb") as password_file:
            encrypted_password = password_file.read()

        fernet = Fernet(key)
        decrypted_password = fernet.decrypt(encrypted_password).decode()
        return decrypted_password

    except FileNotFoundError as e:
        raise Exception(f"Required file not found: {e.filename}")
    except Exception as e:
        raise Exception(f"Failed to retrieve the password: {e}")

# Main section
def main():
    parser = argparse.ArgumentParser(description="Trigger a THOR APT Scan using Data Integration API.")
    parser.add_argument("-host2scan", required=True, help="Hostname from which the backups will be scanned")

    args = parser.parse_args()

    # General Variables
    username = "ChangeMe"
    password = get_password()

    if not password:
        print("❌ Password not found.")
        return

    # Request Bearer Token
    print("🐻 Get Bearer Token...")
    token = connect_veeam_rest_api(api_url, username, password)

    # Define Query Parameters
    print("📂 Get 10 latest Restore Points for "+args.host2scan+"...")
    rp_query_params = {
        "skip"               : "0",
        "limit"              : "10",
        "orderColumn"        : "CreationTime",
        "orderAsc"           : "false",
        "nameFilter"         : args.host2scan
    }

    # Get Restore Points
    restorePoint = get_veeam_rest_api(api_url=api_url,endpoint="v1/restorePoints",token=token,params=rp_query_params)

    # Bad luck - No Restore Point
    if not restorePoint.get("data"):
       print("❌ No restore points found for " + args.host2scan + ". Exiting script.")
       exit(1)

    # Show found Restore Points
    print("📂 Found Restore Points for " + args.host2scan + "...")
    display_restore_points(restorePoint)

    # Get Backup Object Information
    backup_id        = restorePoint["data"][0]["backupId"]
    backup_object_endpoint = f"v1/backups/{backup_id}/objects"
    backup_object = get_veeam_rest_api(api_url=api_url,endpoint=backup_object_endpoint,token=token,params=rp_query_params)
    backup_object_id = backup_object["data"][0]["id"]
    time.sleep(3)

    # Start Backup Scan
    backup_scan_body = {

     "backupObjectPair": [
      {
        "backupId"          : backup_id,
        "backupObjectId"    : backup_object_id
      }
       ],
        "scanMode"          : "MostRecent",
        "scanEngine"        : {
        "useAntivirusEngine": "true",
        "useYaraRule"       : "false",
       }
      }

    print()
    print(f"🔍 Starting scan for {args.host2scan}....")
    start_scan      = post_veeam_rest_api(api_url, "v1/malwareDetection/scanBackup", token, body=backup_scan_body)
    scan_session_id = start_scan["id"]

    # Get Session Information
    scan_session_endpoint = f"v1/sessions/{scan_session_id}"
    get_scan_session = get_veeam_rest_api(api_url, scan_session_endpoint, token, params="")

    monitor_session(api_url, scan_session_id, token)

    return token

if __name__ == "__main__":
    token = main()
    if token:
        print("🚪 Logging out...")
        post_logout(api_url, token)

