#!/usr/bin/env python3
import argparse
import json
import signal
import time
import os
import re
import subprocess
import requests
import socket
from cryptography.fernet import Fernet
from dateutil import parser as dtparser
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from datetime import datetime

# Variables & disable self-signed certificate warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
timestamp   = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
API_VERSION = "1.3-rev1"

# Def section
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

def load_scan_engines():
   if not os.path.exists("scan-engines.json"):
       return []
   with open("scan-engines.json", "r") as f:
       data = json.load(f)
   engines = []
   for eng in data.get("engines", []):
       if os.path.exists(eng["path"]):
           engines.append(eng)
   return engines

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
   r = requests.get(url, headers=headers, params=params, verify=False)
   r.raise_for_status()
   return r.json()

def post_veeam_rest_api(api_url, endpoint, token, body):
   url = f"{api_url}/api/{endpoint}"
   headers = {
       "accept": "application/json",
       "x-api-version": API_VERSION,
       "Content-Type": "application/json",
       "Authorization": f"Bearer {token}"
   }
   r = requests.post(url, headers=headers, json=body, verify=False)
   r.raise_for_status()
   if r.content:
       return r.json()
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
   return get_veeam_rest_api(api_url, "v1/restorePoints", token, params)

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
   print("Default is 0 (latest).")
   signal.alarm(timeout_seconds)
   try:
       choice = input(f"Enter number (0-{num_items - 1}): ")
       signal.alarm(0)
   except TimeoutException:
       print("Timeout → using index 0.")
       return 0
   if not choice.isdigit():
       print("Invalid → index 0.")
       return 0
   idx = int(choice)
   if 0 <= idx < num_items:
       return idx
   print("Out of range → index 0.")
   return 0

def get_managed_server_id(api_url, token, mounthost):
   params = {"nameFilter": mounthost}
   resp = get_veeam_rest_api(api_url, "v1/backupInfrastructure/managedServers", token, params)
   data = resp.get("data", [])
   if not data:
       raise RuntimeError(f"No managed server matches '{mounthost}'.")
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
   matched = []
   for ms in candidates:
       ms_id = ms.get("id")
       detail = get_veeam_rest_api(api_url, f"v1/backupInfrastructure/mountServers/{ms_id}", token)
       if deep_contains_id(detail, managed_server_id):
           matched.append((ms_id, ms.get("type", "")))
   if not matched:
       raise RuntimeError("No mount server found.")
   win = [m for m in matched if m[1] == "Windows"]
   return win[0][0] if win else matched[0][0]

def start_instant_file_share_recovery(api_url, token, rp_id, mount_server_id, smb_user):
   payload = {
       "autoSelectMountServers": False,
       "restoreOptions": [
           {
               "restorePointId": rp_id,
               "mountServerId": mount_server_id,
               "permissions": {
                   "owner": "Administrator",
                   "permissionType": "AllowEveryone",
                   "permissionScope": []
               }
           }
       ],
       "reason": "AV Scan"
   }
   return post_veeam_rest_api(api_url, "v1/restore/instantRecovery/unstructuredData", token, payload)

def stop_instant_file_share_recovery(api_url, token, session_id):
   url = f"{api_url}/api/v1/restore/instantRecovery/unstructuredData/{session_id}/unmount"
   headers = {
       "accept": "application/json",
       "x-api-version": API_VERSION,
       "Content-Type": "application/json",
       "Authorization": f"Bearer {token}"
   }
   requests.post(url, headers=headers, json={}, verify=False)

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
   """
   Returns (host, share_or_export)

   SMB example:  '\\\\SERVER\\SHARE$'  -> ('SERVER', 'SHARE')
   NFS example:  'NFSSERVER:/export/path' -> ('NFSSERVER', '/export/path')
   """
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
   if not name_value:
       return None, None

   s = name_value.strip().lstrip("\\/")

   # NFS-style: SERVER:/export/path
   if ":/" in s:
       server, export = s.split(":/", 1)
       export = "/" + export.lstrip("/")
       return server, export

   # SMB-style: \\SERVER\SHARE
   parts = s.split("\\")
   if len(parts) < 2:
       return None, None
   return parts[0], parts[1].rstrip("$")

def build_mountpoint(base, host, share):
   raw = f"{host}_{share}"
   name = re.sub(r"[^A-Za-z0-9._-]+", "_", raw) or "veeam_share"
   return os.path.join(base, name)

def run_scan_engine(engine, mountpoint):
   params = []
   has_placeholder = False
   for p in engine.get("params", []):
       if p == "{path}":
           params.append(mountpoint)
           has_placeholder = True
       else:
           params.append(p)
   if not has_placeholder:
       params.append(mountpoint)

   cmd = [engine["path"]] + params
   result = subprocess.run(cmd, capture_output=True, text=True)
   stdout = result.stdout
   regex = re.compile(engine["regex"])
   detections = [line for line in stdout.splitlines() if regex.search(line)]

   print(f"\n=== {engine['name']} scan output ===")
   print(stdout)
   if detections:
       print(f"\n{engine['name']} detections:")
       for d in detections:
           print(f"{timestamp} 🐞 {d}")
   else:
       print(f"\n{timestamp} No detections from {engine['name']}.")

def main():
   parser = argparse.ArgumentParser(description="NAS Instant File Share Recovery with multi-engine scan from Linux")
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

   # Load scan engines json file
   engines = load_scan_engines()

   api_url = f"https://{args.vbrserver}:9419"
   username = args.username
   smb_user = args.smb_user or username
   password = get_password()
   smb_pass = get_smb_password()

   print("Getting Bearer token...")
   token = connect_veeam_rest_api(api_url, username, password)

   session_id = None
   mountpoint = None

   try:
       managed_server_id = get_managed_server_id(api_url, token, args.mounthost)
       mount_server_id = resolve_mount_server_id(api_url, token, managed_server_id)

       rp_response = get_nas_restore_points(api_url, token, args.sharename, 10)
       data = rp_response.get("data", [])
       if not data:
           print("No restore points found.")
           return
       print(f"📂 Showing latest 10 restore points for share filter '{args.sharename}'...")
       display_nas_restore_points(rp_response)

       if args.noninteractive:
           selected_index = 0
       else:
           selected_index = select_restore_point(len(data), args.timeout)

       selected_rp = data[selected_index]
       rp_id = selected_rp.get("id")

       ir_response = start_instant_file_share_recovery(api_url, token, rp_id, mount_server_id, smb_user)
       session_id = try_extract_session_id(ir_response)

       print(f"\nWaiting {args.wait} seconds...")
       time.sleep(args.wait)

       prod_host, prod_share = extract_production_share_name(ir_response)
       if not prod_share:
           print("Could not extract share.")
           return

       # For mounting from Windows mount host via SMB, strip leading slashes
       effective_share = (args.smb_share or prod_share).lstrip("/\\")

       try:
           server_ip = socket.gethostbyname(args.mounthost)
       except Exception:
           print(f"Cannot resolve {args.mounthost}")
           return

       mountpoint = build_mountpoint(args.mount_base, args.mounthost, effective_share)
       os.makedirs(mountpoint, exist_ok=True)

       smb_unc = f"//{args.mounthost}/{effective_share}"
       opts = f"username={smb_user},password={smb_pass},ro,ip={server_ip}"
       cmd_mount = ["mount", "-t", "cifs", smb_unc, mountpoint, "-o", opts]

       print(f"Mounting {smb_unc}...")
       try:
           subprocess.run(cmd_mount, check=True)
       except Exception:
           print("Mount failed.")
           return

       for eng in engines:
           run_scan_engine(eng, mountpoint)

   finally:
       print("\nUnmounting...")
       if mountpoint:
           subprocess.run(["umount", mountpoint], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
           try:
               os.rmdir(mountpoint)
           except Exception:
               pass

       if session_id:
           stop_instant_file_share_recovery(api_url, token, session_id)

       post_logout(api_url, token)

if __name__ == "__main__":
   main()
