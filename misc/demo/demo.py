#!/usr/bin/env python3
import os
import subprocess
import argparse
import datetime
import time
import signal
import socket
import json
import requests
import concurrent.futures
from cryptography.fernet import Fernet
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from dateutil import parser as dtparser

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

api_url = "https://vbr-host01:9419"
api_version = "1.2-rev1"
mnt_base = "/mnt"
results_dir = "/tmp/output"
session_file = "mount_sessions.json"

def get_local_ip():
   s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
   try:
       s.connect(("1.1.1.1", 80))
       return s.getsockname()[0]
   finally:
       s.close()

def connect_veeam_rest_api(api_url, username, password):
   url = f"{api_url}/api/oauth2/token"
   headers = {
       "Content-Type": "application/x-www-form-urlencoded",
       "x-api-version": api_version,
       "accept": "application/json"
   }
   data = {"grant_type": "password", "username": username, "password": password}
   response = requests.post(url, headers=headers, data=data, verify=False)
   response.raise_for_status()
   return response.json()["access_token"]

def get_password():
   with open("encryption_key.key", "rb") as key_file:
       key = key_file.read()
   with open("encrypted_password.bin", "rb") as password_file:
       encrypted_password = password_file.read()
   return Fernet(key).decrypt(encrypted_password).decode()

def get_veeam_rest_api(api_url, endpoint, token, params=None):
   url = f"{api_url}/api/{endpoint}"
   headers = {
       "accept": "application/json",
       "x-api-version": api_version,
       "Authorization": f"Bearer {token}"
   }
   response = requests.get(url, headers=headers, params=params, verify=False)
   response.raise_for_status()
   return response.json()

def post_veeam_rest_api(api_url, endpoint, token, body):
   url = f"{api_url}/api/{endpoint}"
   headers = {
       "accept": "application/json",
       "x-api-version": api_version,
       "Content-Type": "application/json",
       "Authorization": f"Bearer {token}"
   }
   response = requests.post(url, headers=headers, json=body, verify=False)
   response.raise_for_status()
   return response.json()

def post_logout(api_url, token):
   url = f"{api_url}/api/oauth2/logout"
   headers = {
       "accept": "application/json",
       "x-api-version": api_version,
       "Authorization": f"Bearer {token}"
   }
   requests.post(url, headers=headers, verify=False)
   print("✅ Logout successful.")

def load_sessions():
   if not os.path.exists(session_file):
       return []
   with open(session_file, "r") as f:
       return json.load(f)

def save_sessions(sessions):
   with open(session_file, "w") as f:
       json.dump(sessions, f, indent=2)

def display_restore_points(restorePoint):
   print("\n{:<5} {:<25} {:<20} {:<15}".format("Index", "Hostname", "Creation Time", "Malware Status"))
   print("-" * 70)
   for idx, point in enumerate(restorePoint["data"][:10]):
       time_str = dtparser.isoparse(point["creationTime"]).strftime("%Y-%m-%d %H:%M:%S")
       status = point["malwareStatus"]
       status_display = "✅ Clean" if status.lower() == "clean" else "🐞 " + status
       print("{:<5} {:<25} {:<20} {:<15}".format(idx, point["name"], time_str, status_display))

class TimeoutException(Exception): pass
def timeout_handler(signum, frame): raise TimeoutException

def select_restore_point(restorePoint):
   try:
       signal.signal(signal.SIGALRM, timeout_handler)
       print("\n⏳ You have 15 seconds to select. (Default 0 if nothing selected)")
       signal.alarm(15)
       choice = input("❓ Enter number (0-9): ")
       signal.alarm(0)
       return int(choice) if choice.isdigit() else 0
   except TimeoutException:
       print("⏱️ Timeout – using Index 0")
       return 0

def run_iscsi_login(ip, port):
   print(f"🔌 iSCSI login to {ip}:{port}")
   subprocess.run(f"sudo iscsiadm -m discovery -t sendtargets -p {ip}:{port}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
   subprocess.run(f"sudo iscsiadm -m node -p {ip}:{port} -l", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_iscsi_logout(ip, port):
   print(f"🛑 iSCSI logout from {ip}:{port}")
   subprocess.run(f"sudo iscsiadm -m node -p {ip}:{port} -u", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
   subprocess.run(f"sudo iscsiadm -m node -p {ip}:{port} -o delete", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def handle_unmount(token, host):
   sessions = load_sessions()
   remaining = []
   for s in sessions:
       if s["host"] == host:
           print(f"[{host}] 🛑 Unpublishing {s['mount_id']} ({s['type']})")
           try:
               post_veeam_rest_api(api_url, f"v1/dataIntegration/{s['mount_id']}/unpublish", token, body={})
               if s["type"] == "ISCSITarget" and s.get("iscsi_ip") and s.get("iscsi_port"):
                   run_iscsi_logout(s["iscsi_ip"], s["iscsi_port"])
           except Exception as e:
               print(f"[{host}] ⚠️ Failed to unpublish: {e}")
       else:
           remaining.append(s)
   save_sessions(remaining)

def show_status():
   sessions = load_sessions()
   if not sessions:
       print("ℹ️ No active sessions.")
       return
   print(f"\n🗂️ Active mount sessions:")
   for s in sessions:
       print(f"🔸 {s['host']} | ID: {s['mount_id']} | Type: {s['type']} | TS: {s['timestamp']}")

def main():
   parser = argparse.ArgumentParser(description="Veeam Data Integration Script")
   parser.add_argument("--host2scan", help="Specify host to scan or mount")
   parser.add_argument("--repo2scan", help="Scan all hosts in repository")
   parser.add_argument("--all", action="store_true", help="Mount all latest restore points")
   parser.add_argument("--start", action="store_true", help="Start mounts")
   parser.add_argument("--stop", action="store_true", help="Stop/unmount sessions")
   parser.add_argument("--status", action="store_true", help="Show current mount status")
   parser.add_argument("--iscsi", action="store_true", help="Use iSCSI instead of FUSE")
   parser.add_argument("--maxhosts", type=int, default=1, help="Max parallel workers for repo2scan")
   args = parser.parse_args()

   username = "administrator"
   password = get_password()

   if args.status:
       show_status()
       return

   token = connect_veeam_rest_api(api_url, username, password)
   scanhost = socket.gethostname()
   local_ip = get_local_ip()

   if args.stop and args.host2scan:
       handle_unmount(token, args.host2scan)
       post_logout(api_url, token)
       return
   elif args.stop:
       print("❌ Please provide --host2scan to stop a session.")
       return

   def mount_restore_point(host, rp_id, ts):
       mount_type = "ISCSITarget" if args.iscsi else "FUSELinuxMount"
       mount_body = {
           "restorePointId": rp_id,
           "type": mount_type,
           "targetServerName": scanhost,
           "targetServerCredentialsId": get_veeam_rest_api(api_url, "v1/backupInfrastructure/managedServers", token, params={"nameFilter": scanhost})["data"][0]["credentialsId"],
           "allowedIps": [local_ip]
       }
       mount_resp = post_veeam_rest_api(api_url, "v1/dataIntegration/publish", token, body=mount_body)
       mount_id = mount_resp["id"]
       print(f"[{host}] 📦 Published (mount ID: {mount_id})")

       session = {
           "host": host,
           "mount_id": mount_id,
           "type": mount_type,
           "timestamp": ts
       }

       if args.iscsi:
           time.sleep(30)
           mount_info = get_veeam_rest_api(api_url, f"v1/dataIntegration/{mount_id}", token)
           ip = mount_info["info"]["serverIps"][0]
           port = mount_info["info"]["serverPort"]
           run_iscsi_login(ip, port)
           session["iscsi_ip"] = ip
           session["iscsi_port"] = port

       sessions = load_sessions()
       sessions = [s for s in sessions if s["host"] != host]
       sessions.append(session)
       save_sessions(sessions)

   if args.host2scan and args.start:
       rp_query = {
           "skip": "0", "limit": "10", "orderColumn": "CreationTime",
           "orderAsc": "false", "nameFilter": args.host2scan
       }
       restorePoint = get_veeam_rest_api(api_url, "v1/restorePoints", token, params=rp_query)
       if not restorePoint.get("data"):
           print("❌ No restore points found.")
           return

       display_restore_points(restorePoint)
       selected = select_restore_point(restorePoint)
       selected_rp = restorePoint["data"][selected]
       restore_point_id = selected_rp["id"]
       ts = dtparser.isoparse(selected_rp["creationTime"]).strftime("%Y-%m-%d %H:%M:%S")
       print(f"✅ Mounting {args.host2scan} with restore point {ts}")
       mount_restore_point(args.host2scan, restore_point_id, ts)
       post_logout(api_url, token)
       return

   if args.repo2scan and args.all and args.start:
       all_repos = get_veeam_rest_api(api_url, "v1/backupInfrastructure/repositories", token)
       repo = next((r for r in all_repos["data"] if r["name"].strip() == args.repo2scan.strip()), None)
       if not repo:
           print("❌ Repository not found.")
           return

       backups = get_veeam_rest_api(api_url, "v1/backups", token)
       backup_ids = [b["id"] for b in backups["data"] if b["repositoryId"] == repo["id"]]
       valid_platforms = ["VMware", "HyperV", "WindowsPhysical", "LinuxPhysical"]
       hostnames = []
       for bid in backup_ids:
           rps = get_veeam_rest_api(api_url, "v1/restorePoints", token, params={"backupIdFilter": bid})
           for rp in rps.get("data", []):
               if rp.get("platformName", "") in valid_platforms:
                   hostnames.append(rp["name"])
       hostnames = sorted(set(hostnames))

       def handle_repo_mount(host):
           query = {
               "skip": "0", "limit": "1", "orderColumn": "CreationTime",
               "orderAsc": "false", "nameFilter": host
           }
           rp = get_veeam_rest_api(api_url, "v1/restorePoints", token, params=query)
           if not rp.get("data"): return
           restore = rp["data"][0]
           ts = dtparser.isoparse(restore["creationTime"]).strftime("%Y-%m-%d %H:%M:%S")
           mount_restore_point(host, restore["id"], ts)

       with concurrent.futures.ThreadPoolExecutor(max_workers=args.maxhosts) as executor:
           executor.map(handle_repo_mount, hostnames)

       post_logout(api_url, token)

if __name__ == "__main__":
   main()
