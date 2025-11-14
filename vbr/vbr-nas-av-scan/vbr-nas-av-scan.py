#!/usr/bin/env python3
import argparse
import json
import signal
import time
import os
import re
import subprocess
import requests
from cryptography.fernet import Fernet
from dateutil import parser as dtparser
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Variables & SSL disable warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
API_VERSION = "1.3-rev1"
CLAMSCAN_PATH = "/usr/bin/clamscan"

# Def Section
def get_password():
   with open("encryption_key.key", "rb") as key_file:
       key = key_file.read()
   with open("encrypted_password.bin", "rb") as password_file:
       encrypted_password = password_file.read()
   return Fernet(key).decrypt(encrypted_password).decode()

def get_smb_password():
   with open("encryption_key.key", "rb") as key_file:
       key = key_file.read()
   with open("encrypted_smb_password.bin", "rb") as password_file:
       encrypted_password = password_file.read()
   return Fernet(key).decrypt(encrypted_password).decode()

def connect_veeam_rest_api(api_url, username, password):
   url = f"{api_url}/api/oauth2/token"
   headers = {
       "Content-Type": "application/x-www-form-urlencoded",
       "x-api-version": API_VERSION,
       "accept": "application/json"
   }
   data = {"grant_type": "password", "username": username, "password": password}
   response = requests.post(url, headers=headers, data=data, verify=False)
   response.raise_for_status()
   return response.json()["access_token"]

def get_veeam_rest_api(api_url, endpoint, token, params=None):
   url = f"{api_url}/api/{endpoint}"
   headers = {
       "accept": "application/json",
       "x-api-version": API_VERSION,
       "Authorization": f"Bearer {token}"
   }
   response = requests.get(url, headers=headers, params=params, verify=False)
   response.raise_for_status()
   return response.json()

def post_veeam_rest_api(api_url, endpoint, token, body):
   url = f"{api_url}/api/{endpoint}"
   headers = {
       "accept": "application/json",
       "x-api-version": API_VERSION,
       "Content-Type": "application/json",
       "Authorization": f"Bearer {token}"
   }
   response = requests.post(url, headers=headers, json=body, verify=False)
   response.raise_for_status()
   if response.content:
       return response.json()
   return {}

def post_logout(api_url, token):
   url = f"{api_url}/api/oauth2/logout"
   headers = {
       "accept": "application/json",
       "x-api-version": API_VERSION,
       "Authorization": f"Bearer {token}"
   }
   requests.post(url, headers=headers, verify=False)

def get_nas_restore_points(api_url, token, sharename, limit=10):
   params = {
       "skip": 0,
       "limit": limit,
       "orderColumn": "CreationTime",
       "orderAsc": "false",
       "platformNameFilter": "UnstructuredData",
       "nameFilter": f"*{sharename}*"
   }
   return get_veeam_rest_api(api_url, "v1/restorePoints", token, params=params)


def display_nas_restore_points(rp_response):
   data = rp_response.get("data", [])
   print("\n{:<5} {:<50} {:<25}".format("Id", "Name", "Creation Time"))
   print("-" * 90)
   for idx, rp in enumerate(data):
       name = rp.get("name", "<no-name>")
       creation_iso = rp.get("creationTime")
       try:
           creation_str = dtparser.isoparse(creation_iso).strftime("%Y-%m-%d %H:%M:%S")
       except Exception:
           creation_str = creation_iso or "unknown"
       print("{:<5} {:<50} {:<25}".format(idx, name, creation_str))

class TimeoutException(Exception):
   pass

def _timeout_handler(signum, frame):
   raise TimeoutException

def select_restore_point(num_items, timeout_seconds=30):
   signal.signal(signal.SIGALRM, _timeout_handler)
   print(f"\nYou have {timeout_seconds} seconds to select a restore point.")
   print("Default is 0 (latest) if nothing is selected.")
   signal.alarm(timeout_seconds)
   try:
       choice = input(f"Enter number (0-{num_items - 1}): ")
       signal.alarm(0)
   except TimeoutException:
       print("Timeout reached → using index 0.")
       return 0

   if not choice.isdigit():
       print("Invalid input → using index 0.")
       return 0

   idx = int(choice)
   if 0 <= idx < num_items:
       return idx

   print("Out of range. Using index 0.")
   return 0

def get_managed_server_id(api_url, token, mounthost):
   params = {"nameFilter": mounthost}
   resp = get_veeam_rest_api(api_url, "v1/backupInfrastructure/managedServers", token, params=params)
   data = resp.get("data", [])
   if not data:
       raise RuntimeError(f"No managed server found for nameFilter='{mounthost}'.")
   if len(data) > 1:
       print(f"Warning: multiple managed servers match '{mounthost}', using the first one.")
   return data[0].get("id")

def deep_contains_id(obj, target_id):
   if isinstance(obj, dict):
       for v in obj.values():
           if v == target_id:
               return True
           if deep_contains_id(v, target_id):
               return True
   elif isinstance(obj, list):
       for item in obj:
           if deep_contains_id(item, target_id):
               return True
   return False

def resolve_mount_server_id(api_url, token, managed_server_id):
   ms_list = get_veeam_rest_api(api_url, "v1/backupInfrastructure/mountServers", token)
   candidates = ms_list.get("data", [])
   if not candidates:
       raise RuntimeError("No mount servers returned by API.")

   matched = []
   for ms in candidates:
       ms_id = ms.get("id")
       if not ms_id:
           continue
       detail = get_veeam_rest_api(api_url, f"v1/backupInfrastructure/mountServers/{ms_id}", token)
       if deep_contains_id(detail, managed_server_id):
           ms_type = ms.get("type", "")
           matched.append((ms_id, ms_type))

   if not matched:
       raise RuntimeError("No mount server found that references the given managed server id.")

   windows_matches = [m for m in matched if m[1] == "Windows"]
   if windows_matches:
       ms_id = windows_matches[0][0]
       print(f"Using Windows mount server: {ms_id}")
       return ms_id

   ms_id = matched[0][0]
   print(f"Using mount server: {ms_id}")
   return ms_id

def start_instant_file_share_recovery(api_url, token, restore_point_id, mount_server_id, smb_user):
   payload = {
       "autoSelectMountServers": False,
       "restoreOptions": [
           {
               "restorePointId": restore_point_id,
               "mountServerId": mount_server_id,
               "permissions": {
                   "owner": "Administrator",
                   #"permissionType": "AllowSelected",
                   #"permissionScope": [smb_user]
                   "permissionType": "AllowEveryone",
                   "permissionScope": []
               }
           }
       ],
       "reason": "AV Scan"
   }
   print("Starting Instant File Share Recovery...")
   return post_veeam_rest_api(
       api_url,
       "v1/restore/instantRecovery/unstructuredData",
       token,
       body=payload
   )

def stop_instant_file_share_recovery(api_url, token, session_id):
   url = f"{api_url}/api/v1/restore/instantRecovery/unstructuredData/{session_id}/unmount"
   headers = {
       "accept": "application/json",
       "x-api-version": API_VERSION,
       "Content-Type": "application/json",
       "Authorization": f"Bearer {token}"
   }
   print("Stopping Instant File Share Recovery...")
   resp = requests.post(url, headers=headers, json={}, verify=False)
   if resp.status_code not in (200, 202, 204):
       print(f"Warning: unmount request returned HTTP {resp.status_code}")

def try_extract_session_id(ir_response):
   if isinstance(ir_response, dict):
       if isinstance(ir_response.get("id"), str):
           return ir_response["id"]
       for v in ir_response.values():
           sid = try_extract_session_id(v)
           if sid:
               return sid
   elif isinstance(ir_response, list):
       for item in ir_response:
           sid = try_extract_session_id(item)
           if sid:
               return sid
   return None

def extract_production_share_name(ir_response):
   name_value = None
   if isinstance(ir_response, dict):
       if isinstance(ir_response.get("name"), str):
           name_value = ir_response["name"]
       else:
           for v in ir_response.values():
               if isinstance(v, dict) and isinstance(v.get("name"), str):
                   name_value = v["name"]
                   break
               if isinstance(v, list):
                   for item in v:
                       if isinstance(item, dict) and isinstance(item.get("name"), str):
                           name_value = item["name"]
                           break
                   if name_value:
                       break
   if not name_value:
       return None, None

   s = name_value.strip()
   s = s.lstrip("\\/")
   parts = s.split("\\")
   if len(parts) < 2:
       return None, None
   host = parts[0]
   share = parts[1]
   share = share.rstrip("$")
   return host, share

def build_mountpoint(mount_base, mounthost, share_name):
   raw = f"{mounthost}_{share_name}"
   name = re.sub(r"[^A-Za-z0-9._-]+", "_", raw)
   if not name:
       name = "veeam_share"
   return os.path.join(mount_base, name)

def scan_share_with_clamav(mounthost, share_name, mount_base, smb_user, smb_pass):
   smb_unc = f"//{mounthost}/{share_name}"
   mountpoint = build_mountpoint(mount_base, mounthost, share_name)
   os.makedirs(mountpoint, exist_ok=True)

   opts = f"username={smb_user},password={smb_pass},ro"

   cmd_mount = ["mount", "-t", "cifs", smb_unc, mountpoint, "-o", opts]
   print(f"Mounting SMB share '{smb_unc}' to '{mountpoint}'...")
   try:
       subprocess.run(cmd_mount, check=True)
   except subprocess.CalledProcessError as e:
       print(f"Error mounting share: {e}")
       return

   try:
       if not os.path.exists(CLAMSCAN_PATH):
           print(f"ClamAV binary not found at {CLAMSCAN_PATH}.")
           return

       print(f"Running ClamAV scan on '{mountpoint}'...")
       cmd_scan = [CLAMSCAN_PATH, "--no-summary", "-i", "-r", mountpoint]
       result = subprocess.run(cmd_scan, capture_output=True, text=True)
       stdout = result.stdout
       stderr = result.stderr

       if stderr:
           print("ClamAV stderr:")
           print(stderr)

       detections = []
       for line in stdout.splitlines():
           if re.search(r"FOUND$", line):
               detections.append(line)

       print("ClamAV output:")
       print(stdout)

       if detections:
           print("\nDetections:")
           for d in detections:
               print(f"🐞 {d}")
       else:
           print("\nNo detections found by ClamAV (no lines ending with 'FOUND').")

   finally:
       print(f"Unmounting '{mountpoint}'...")
       subprocess.run(["umount", mountpoint], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
       try:
           os.rmdir(mountpoint)
       except OSError:
           pass

def main():
   parser = argparse.ArgumentParser(description="NAS Instant File Share Recovery with ClamAV scan from Linux")
   parser.add_argument("--vbrserver", required=True, help="VBR server hostname or IP")
   parser.add_argument("--sharename", required=True, help="Share name")
   parser.add_argument("--mounthost", required=True, help="Hostname of the Windows mount host (managed server)")
   parser.add_argument("--username", default="Administrator", help="Veeam REST API username")
   parser.add_argument("--timeout", type=int, default=30, help="Seconds for restore point selection timeout")
   parser.add_argument("--wait", type=int, default=60, help="Seconds to wait after starting Instant Recovery before scanning")
   parser.add_argument("--mount-base", default="/mnt", help="Base directory where SMB share will be mounted (default: /mnt)")
   parser.add_argument("--smb-user", help="SMB username override (default: same as --username)")
   parser.add_argument("--smb-share", help="Explicit SMB share name on mount host (overrides auto-detected share name)")
   parser.add_argument("--noninteractive", action="store_true", help="Do not prompt, always use latest restore point")
   args = parser.parse_args()

   api_url = f"https://{args.vbrserver}:9419"
   username = args.username
   smb_user = args.smb_user if args.smb_user else username

   password = get_password()
   smb_pass = get_smb_password()

   print("Getting authentication token...")
   token = connect_veeam_rest_api(api_url, username, password)
   print("Authentication successful.")

   session_id = None

   try:
       print(f"Resolving managed server id for mount host '{args.mounthost}'...")
       managed_server_id = get_managed_server_id(api_url, token, args.mounthost)

       print("Resolving mount server for this managed server...")
       mount_server_id = resolve_mount_server_id(api_url, token, managed_server_id)

       print(f"\nQuerying NAS restore points for share '{args.sharename}'...")
       rp_response = get_nas_restore_points(api_url, token, args.sharename, limit=10)
       data = rp_response.get("data", [])
       if not data:
           print("No restore points found.")
           return

       display_nas_restore_points(rp_response)

       if args.noninteractive:
           selected_index = 0
           print("\nNon-interactive mode. Using latest restore point.")
       else:
           selected_index = select_restore_point(len(data), timeout_seconds=args.timeout)

       selected_rp = data[selected_index]

       rp_id = selected_rp.get("id")
       rp_name = selected_rp.get("name")
       creation_str = dtparser.isoparse(selected_rp["creationTime"]).strftime("%Y-%m-%d %H:%M:%S")

       print(f"\nSelected restore point -  Name: {rp_name} - Created: {creation_str}")

       ir_response = start_instant_file_share_recovery(api_url, token, rp_id, mount_server_id, smb_user)

       session_id = try_extract_session_id(ir_response)
       if session_id:
           print(f"Detected Instant Recovery session id: {session_id}")
       else:
           print("Warning: no session id could be detected in Instant Recovery response.")

       print(f"\nWaiting {args.wait} seconds for share to be presented...")
       time.sleep(args.wait)

       prod_host, prod_share = extract_production_share_name(ir_response)
       if prod_share:
           effective_share = args.smb_share if args.smb_share else prod_share
           print(f"Production share from IR response: \\\\{prod_host}\\{prod_share}")
           print(f"Derived/used IR SMB share on mount host: \\\\{args.mounthost}\\{effective_share}")
           print(f"Starting ClamAV scan from this Linux host using SMB mount as user '{smb_user}'...")
           scan_share_with_clamav(args.mounthost, effective_share, args.mount_base, smb_user=smb_user, smb_pass=smb_pass)
       else:
           print("\nCould not extract production share name from response, cannot mount from Linux.")

       if session_id:
           stop_instant_file_share_recovery(api_url, token, session_id)
       else:
           print("Instant Recovery session was not stopped automatically because no session id was found.")

   finally:
       print("\nLogging out...")
       post_logout(api_url, token)


if __name__ == "__main__":
   main()
