#!/usr/bin/env python3
import os
import sys
import time
import signal
import socket
import subprocess
import argparse
import datetime
import requests
from cryptography.fernet import Fernet

# Disable TLS verification
import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)

# ----------------------------------------------------------------------
# Configuration / Change where necessary 
# ----------------------------------------------------------------------
REQUEST_TIMEOUT      = 10               # seconds for HTTP requests
PUBLISH_WAIT_SECONDS = 30               # wait after publishing a disk
SELECT_TIMEOUT       = 15               # seconds for user selection
DOCKER_IMAGE         = "thor-lite"
RESULTS_DIR          = "/tmp/output"
USERNAME             = "Administrator"
API_URL              = "https://<vbr-server>:9419"
API_VERSION          = "1.2-rev1"

# Helper functions
def get_password() -> str:
   with open("encryption_key.key", "rb") as kf:
       key = kf.read()
   with open("encrypted_password.bin", "rb") as pf:
       encrypted = pf.read()
   return Fernet(key).decrypt(encrypted).decode()

def create_session() -> requests.Session:
   """Reusable HTTP session with common headers (no global Content-Type)."""
   sess = requests.Session()
   sess.headers.update({
       "x-api-version": API_VERSION,
       "accept": "application/json",
   })
   return sess

def obtain_bearer_token(sess: requests.Session, username: str, password: str) -> str:
   token_url = f"{API_URL}/api/oauth2/token"
   payload = {
       "grant_type": "password",
       "username": username,
       "password": password,
       "refresh_token": "",
       "rememberMe": ""
   }
   token_headers = {"Content-Type": "application/x-www-form-urlencoded"}
   resp = sess.post(
       token_url,
       data=payload,
       headers=token_headers,
       timeout=REQUEST_TIMEOUT,
       verify=False
   )
   resp.raise_for_status()
   return resp.json()["access_token"]

def api_get(sess: requests.Session, endpoint: str, token: str,
           params: dict | None = None) -> dict:
   url = f"{API_URL}/api/{endpoint}"
   hdr = {"Authorization": f"Bearer {token}"}
   resp = sess.get(
       url,
       headers=hdr,
       params=params,
       timeout=REQUEST_TIMEOUT,
       verify=False
   )
   resp.raise_for_status()
   return resp.json()

def api_post(sess: requests.Session, endpoint: str, token: str,
            body: dict) -> dict:
   url = f"{API_URL}/api/{endpoint}"
   hdr = {"Authorization": f"Bearer {token}"}
   resp = sess.post(
       url,
       headers=hdr,
       json=body,
       timeout=REQUEST_TIMEOUT,
       verify=False
   )
   resp.raise_for_status()
   return resp.json()

def api_logout(sess: requests.Session, token: str) -> None:
   url = f"{API_URL}/api/oauth2/logout"
   hdr = {"Authorization": f"Bearer {token}"}
   resp = sess.post(
       url,
       headers=hdr,
       timeout=REQUEST_TIMEOUT,
       verify=False
   )
   resp.raise_for_status()
   print("✅ Logout successful.")

def find_parent_folder(publish_info: dict) -> str:
   if not isinstance(publish_info, dict):
       raise FileNotFoundError("Invalid publish info")
   disks = publish_info.get("disks") or (publish_info.get("info") or {}).get("disks")
   if not disks:
       raise FileNotFoundError("No disk information")
   mount_points = []
   for d in disks:
       mount_points.extend(d.get("mountPoints") or [])
   if not mount_points:
       raise FileNotFoundError("No mount points")
   first_path = mount_points[0]
   parts = first_path.split('/')
   parent = None
   for i, part in enumerate(parts):
       if part.startswith("Veeam.Mount.FS."):
           parent = '/'.join(parts[:i + 1]) + '/'
           break
   if not parent:
       parent = os.path.dirname(first_path) + '/'
   print(f"📂 Parent folder: {parent}")
   return parent

def trigger_scan(parent_folder: str, host_to_scan: str) -> None:
   html_file = f"/thor/output/{host_to_scan}_thor_:time:.html"
   hostname = subprocess.check_output("hostname", shell=True).decode().strip()
   cmd = [
       "docker", "run", "--rm",
       "--hostname", hostname,
       "-v", f"{parent_folder}:/data",
       "-v", f"{RESULTS_DIR}:/thor/output",
       DOCKER_IMAGE,
       "--path", "/data",
       "--htmlfile", html_file,
       "-e", "/thor/output"
   ]
   print(f"🔍 Scanning {host_to_scan} …")
   try:
       subprocess.run(cmd, check=True)
       print(f"✅ Scan finished – results in {RESULTS_DIR}")
   except subprocess.CalledProcessError as exc:
       print(f"❌ Scan failed: {exc}")

def display_restore_points(rp: dict) -> None:
   print("\n{:5} {:25} {:20} {:15}".format("Idx", "Hostname", "Creation Time", "Malware"))
   print("-" * 70)
   for idx, point in enumerate(rp["data"][:10]):
       raw = point["creationTime"]
       fmt = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
       status = "✅ Clean" if point["malwareStatus"].lower() == "clean" else f"🐞 {point['malwareStatus']}"
       print("{:5} {:25} {:20} {:15}".format(idx, point["name"], fmt, status))

class TimeoutException(Exception):
   pass

def _alarm_handler(signum, frame):
   raise TimeoutException

def select_restore_point(rp: dict) -> int:
   signal.signal(signal.SIGALRM, _alarm_handler)
   print("\n⏳ You have 15 seconds to pick a restore point (0-9).")
   signal.alarm(SELECT_TIMEOUT)
   try:
       choice = input("❓ Number: ")
       signal.alarm(0)
       if choice.isdigit() and int(choice) < len(rp["data"]):
           return int(choice)
       print("❌ Invalid input – defaulting to 0.")
       return 0
   except TimeoutException:
       print("\n⏳ Timeout – defaulting to 0.")
       return 0
   except EOFError:
       print("\n⏳ No input – defaulting to 0.")
       return 0

# Main workflow
def main() -> str | None:
   parser = argparse.ArgumentParser(description="Trigger a THOR APT scan via Veeam Data Integration API.")
   parser.add_argument("--host2scan", required=True,help="Hostname whose latest backup will be scanned")
   parser.add_argument("--latest", action="store_true",help="Skip prompt and use the newest restore point")
   args = parser.parse_args()

   try:
       password = get_password()
   except Exception as e:
       print(f"❌ Unable to read password: {e}")
       return None

   scan_host = socket.gethostname()
   sess = create_session()
   print("🐻 Getting bearer token …")
   try:
       token = obtain_bearer_token(sess, USERNAME, password)
   except Exception as e:
       print(f"❌ Token request failed: {e}")
       return None

   rp_params = {
       "skip": "0",
       "limit": "10",
       "orderColumn": "CreationTime",
       "orderAsc": "false",
       "nameFilter": args.host2scan
   }

   try:
       restore_points = api_get(sess, "v1/restorePoints", token, rp_params)
   except Exception as e:
       print(f"❌ Failed to fetch restore points: {e}")
       return None

   if not restore_points.get("data"):
       print(f"❌ No restore points for {args.host2scan}.")
       return None

   if args.latest:
       print("⚙️ Auto mode – using newest restore point.")
       sel_idx = 0
   else:
       print(f"📂 Restore points for {args.host2scan}:")
       display_restore_points(restore_points)
       sel_idx = select_restore_point(restore_points)

   rp_id = restore_points["data"][sel_idx]["id"]
   rp_time = restore_points["data"][sel_idx]["creationTime"]
   print(f"✅ Selected restore point created at {rp_time}")

   srv_params = {"nameFilter": scan_host, "typeFilter": "LinuxHost"}
   try:
       srv_info = api_get(sess, "v1/backupInfrastructure/managedServers", token, srv_params)
       cred_id = srv_info["data"][0]["credentialsId"]
   except Exception as e:
       print(f"❌ Failed to get scan server info: {e}")
       return None

   publish_body = {
       "restorePointId": rp_id,
       "type": "FUSELinuxMount",
       "targetServerName": scan_host,
       "targetServerCredentialsId": cred_id
   }

   try:
       publish_resp = api_post(sess, "v1/dataIntegration/publish", token, publish_body)
       publish_id = publish_resp.get("id")
       print(f"✅ Disk published – ID: {publish_id}")
   except Exception as e:
       print(f"❌ Disk publish failed: {e}")
       return None

   print("⏳ Waiting for mount to finish …")
   time.sleep(PUBLISH_WAIT_SECONDS)

   try:
       mount_info = api_get(sess, f"v1/dataIntegration/{publish_id}", token)
       parent_folder = find_parent_folder(mount_info)
   except Exception as e:
       print(f"❌ Could not determine mount path: {e}")
       parent_folder = None

   if parent_folder:
       trigger_scan(parent_folder, args.host2scan)

   print("🛑 Stopping disk publish …")
   time.sleep(5)
   unpublish_ep = f"v1/dataIntegration/{publish_id}/unpublish"
   try:
       api_post(sess, unpublish_ep, token, publish_body)
       print("✅ Disk publish stopped.")
   except Exception as e:
       print(f"❌ Unpublish failed: {e}")

   return token

if __name__ == "__main__":
   bearer = main()
   if bearer:
       sess = create_session()
       api_logout(sess, bearer)
