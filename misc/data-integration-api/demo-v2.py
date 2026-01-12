#!/usr/bin/env python3
import os
import subprocess
import argparse
import datetime
import time
import signal
import socket
import requests
import concurrent.futures
from cryptography.fernet import Fernet
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from dateutil import parser as dtparser

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Script variables
api_version = "1.3-rev0"
mnt_base    = "/mnt"
results_dir = "/tmp/output"

# Get local IP Address for iSCSI allowlist (wird bei FUSE nicht genutzt, bleibt aber drin)
def get_local_ip():
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  try:
      s.connect(("1.1.1.1", 80))
      return s.getsockname()[0]
  finally:
      s.close()

# Connect to Veeam REST API - Get Bearer Token
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

# Get password (Fernet)
def get_password():
  with open("encryption_key.key", "rb") as key_file:
      key = key_file.read()
  with open("encrypted_password.bin", "rb") as password_file:
      encrypted_password = password_file.read()
  return Fernet(key).decrypt(encrypted_password).decode()

# Veeam REST API GET
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

# Veeam REST API POST
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

# Veeam REST API Logout
def post_logout(api_url, token):
  url = f"{api_url}/api/oauth2/logout"
  headers = {
      "accept": "application/json",
      "x-api-version": api_version,
      "Authorization": f"Bearer {token}"
  }
  requests.post(url, headers=headers, verify=False)
  print("✅ Logout successful.")

# Log file
def log_message(hostname, message):
  os.makedirs(results_dir, exist_ok=True)
  logfile = os.path.join(results_dir, f"{hostname}.log")
  with open(logfile, "a") as f:
      f.write(f"{datetime.datetime.now()}: {message}\n")

# Display Restore Points Table
def display_restore_points(restorePoint):
  print("\n{:<5} {:<25} {:<20} {:<15}".format("Index", "Hostname", "Creation Time", "Malware Status"))
  print("-" * 70)
  for idx, point in enumerate(restorePoint["data"][:10]):
      time_str = dtparser.isoparse(point["creationTime"]).strftime("%Y-%m-%d %H:%M:%S")
      status = point.get("malwareStatus", "unknown")
      status_display = "✅ Clean" if str(status).lower() == "clean" else "🐞 " + str(status)
      print("{:<5} {:<25} {:<20} {:<15}".format(idx, point["name"], time_str, status_display))

class TimeoutException(Exception):
  pass

def timeout_handler(signum, frame):
  raise TimeoutException

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

# Veeam REST API for Data Integration API - Uses FUSE or iSCSI
def do_mount_scan(api_url, token, scanhost, local_ip, restore_point_id, host_name, use_iscsi, scan_wait):
  srv = get_veeam_rest_api(
      api_url,
      "v1/backupInfrastructure/managedServers",
      token,
      params={"nameFilter": scanhost, "typeFilter": "LinuxHost"}
  )
  if not srv.get("data"):
      print(f"[{host_name}|{restore_point_id}] ❌ Scanhost '{scanhost}' not found as LinuxHost in managedServers.")
      log_message(host_name, f"[{restore_point_id}] Scanhost not found as LinuxHost in managedServers.")
      return

  cred_id = srv["data"][0]["credentialsId"]

  mount_body = {
      "restorePointId": restore_point_id,
      "type": "ISCSITarget" if use_iscsi else "FUSELinuxMount",
      "targetServerName": scanhost,
      "credentialsStorageType": "Permanent",
      "targetServerCredentialsId": cred_id
  }

  if use_iscsi:
      mount_body["allowedIps"] = [local_ip]

  print(f"[{host_name}|{restore_point_id}] 📦 Publishing disk content for {host_name} ({'iSCSI' if use_iscsi else 'FUSE'})...")
  log_message(host_name, f"[{restore_point_id}] Publishing disk content...")

  try:
      mount_resp = post_veeam_rest_api(api_url, "v1/dataIntegration/publish", token, body=mount_body)
  except Exception as e:
      print(f"[{host_name}|{restore_point_id}] ❌ Failed to publish: {e}")
      log_message(host_name, f"[{restore_point_id}] ❌ Failed to publish: {e}")
      return

  mount_id = mount_resp.get("id")
  print(f"[{host_name}|{restore_point_id}] ✅ Published. ID={mount_id}")

  print(f"[{host_name}|{restore_point_id}] ⏳ Waiting 30 seconds for mount...")
  time.sleep(30)

  if not use_iscsi:
      print(f"[{host_name}|{restore_point_id}] ⏳ Simulating scan... (sleep {scan_wait}s)")
      log_message(host_name, f"[{restore_point_id}] Simulating scan... (sleep {scan_wait}s)")
      time.sleep(scan_wait)

  print(f"[{host_name}|{restore_point_id}] 🛑 Unpublishing...")
  time.sleep(3)
  try:
      post_veeam_rest_api(api_url, f"v1/dataIntegration/{mount_id}/unpublish", token, body=mount_body)
      log_message(host_name, f"[{restore_point_id}] Unpublished.")
  except Exception as e:
      print(f"[{host_name}|{restore_point_id}] ⚠️ Unpublish failed: {e}")
      log_message(host_name, f"[{restore_point_id}] ⚠️ Unpublish failed: {e}")

def main():
  parser = argparse.ArgumentParser(description="Veeam Data Integration API")

  parser.add_argument("--vbrserver", default="vbr-host01", help="VBR server hostname (default: vbr-host01)")
  parser.add_argument("--username", default="restapiuser", help="REST API username (default: restapiuser)")
  
  parser.add_argument("--host2scan", help="Specify host to scan")
  parser.add_argument("--repo2scan", help="Specify repository to scan hosts from")
  parser.add_argument("--all", action="store_true", help="Scan all valid hosts from the repo")
  parser.add_argument("--iscsi", action="store_true", help="Use iSCSI instead of FUSE")
  parser.add_argument("--maxhosts", type=int, default=1, help="Max parallel hosts to scan (default 1)")
  parser.add_argument("--latest", action="store_true", help="Automatically use latest restore point (skip selection menu)")
  parser.add_argument("--scan-wait", type=int, default=60, help="Seconds to sleep while 'scanning' (default 60)")

  args = parser.parse_args()

  api_url  = f"https://{args.vbrserver}:9419"
  username = args.username
  password = get_password()

  print("🐻 Get Bearer Token....")
  token = connect_veeam_rest_api(api_url, username, password)

  scanhost = socket.gethostname()
  local_ip = get_local_ip()

  valid_platforms = ["VMware", "HyperV", "WindowsPhysical", "LinuxPhysical"]

  if args.repo2scan:
      print(f"📦 Looking up repository {args.repo2scan}")
      all_repos = get_veeam_rest_api(api_url, "v1/backupInfrastructure/repositories", token)
      repo = next((r for r in all_repos["data"] if r["name"].strip() == args.repo2scan.strip()), None)
      if not repo:
          print("❌ Repository not found.")
          return token, api_url

      backups = get_veeam_rest_api(api_url, "v1/backups", token)
      backup_ids = [b["id"] for b in backups["data"] if b["repositoryId"] == repo["id"]]

      hostnames = []
      for bid in backup_ids:
          rps = get_veeam_rest_api(api_url, "v1/restorePoints", token, params={"backupIdFilter": bid})
          for rp in rps.get("data", []):
              if rp.get("platformName", "") in valid_platforms:
                  hostnames.append(rp["name"])

      if not hostnames:
          print("❌ No valid restore points in this repository.")
          return token, api_url

      hostnames = sorted(set(hostnames))

      if args.all:
          print("🔍 Scanning latest restore point of all valid hosts...")
          with concurrent.futures.ThreadPoolExecutor(max_workers=args.maxhosts) as executor:
              futures = []
              for host in hostnames:
                  query = {
                      "skip": "0", "limit": "1", "orderColumn": "CreationTime",
                      "orderAsc": "false", "nameFilter": host
                  }
                  rp = get_veeam_rest_api(api_url, "v1/restorePoints", token, params=query)
                  if rp.get("data"):
                      restore_id = rp["data"][0]["id"]
                      ts = dtparser.isoparse(rp["data"][0]["creationTime"]).strftime("%Y-%m-%d %H:%M:%S")
                      print(f"🖥️ Scanning host {host} (latest restore point {ts})")
                      futures.append(executor.submit(
                          do_mount_scan,
                          api_url, token, scanhost, local_ip,
                          restore_id, host, args.iscsi, args.scan_wait
                      ))
              for f in concurrent.futures.as_completed(futures):
                  f.result()
          return token, api_url

      print("\n📄 Hosts in backup")
      for idx, name in enumerate(hostnames):
          print(f" {idx}. {name}")

      selected = select_restore_point({
          "data": [{"name": name, "creationTime": datetime.datetime.now().isoformat(), "malwareStatus": "unknown"}
                   for name in hostnames]
      })
      args.host2scan = hostnames[selected]
      print(f"🖥️ Selected host {args.host2scan}")

  elif not args.host2scan:
      print("❌ You must specify either --host2scan or --repo2scan")
      return token, api_url

  rp_query = {
      "skip": "0",
      "limit": "1" if args.latest else "10",
      "orderColumn": "CreationTime",
      "orderAsc": "false",
      "nameFilter": args.host2scan
  }

  print(("📂 Get latest Restore Point for " if args.latest else "📂 Get 10 latest Restore Points for ")
        + args.host2scan + "....")
  restorePoint = get_veeam_rest_api(api_url, "v1/restorePoints", token, params=rp_query)
  if not restorePoint.get("data"):
      print("❌ No restore points found.")
      return token, api_url

  if args.latest:
      selected_rp = restorePoint["data"][0]
  else:
      display_restore_points(restorePoint)
      selected = select_restore_point(restorePoint)
      selected_rp = restorePoint["data"][selected]

  ts = dtparser.isoparse(selected_rp["creationTime"]).strftime("%Y-%m-%d %H:%M:%S")
  restore_point_id = selected_rp["id"]
  print(f"✅ Selected restore point id {restore_point_id} created on {ts}")

  do_mount_scan(api_url, token, scanhost, local_ip, restore_point_id, args.host2scan, args.iscsi, args.scan_wait)
  return token, api_url

if __name__ == "__main__":
  token, api_url = main()
  if token:
      print("🚪 Logout...")
      post_logout(api_url, token)
