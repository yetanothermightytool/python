#!/usr/bin/env python3
import os
import base64
import subprocess
import argparse
import datetime
import time
import signal
import requests
import socket
from cryptography.fernet import Fernet
from requests.packages.urllib3.exceptions import InsecureRequestWarning

os.system('clear')
# Disable SSL warnings - Use only in test environments
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Variables - Change where necessary
username        = "Administrator"
api_url         = "https://<vbr-host>:9419"
api_version     = "1.2-rev1"
docker_image    = "thor-lite"
scan_base_dir   = "/tmp"
pattern_prefix  = "Veeam.Mount.FS."
results_dir     = "/tmp/output"

# Get encrypted password (Fernet)
def get_password():
   with open("encryption_key.key", "rb") as key_file:
       key = key_file.read()
   with open("encrypted_password.bin", "rb") as password_file:
       encrypted_password = password_file.read()
   return Fernet(key).decrypt(encrypted_password).decode()


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

# Function - GET against Veeam REST API
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

# Function - Logout from Veeam REST API
def post_logout(api_url, token):
   url = f"{api_url}/api/oauth2/logout"
   headers = {
       "accept": "application/json",
       "x-api-version": api_version,
       "Authorization": f"Bearer {token}"
   }

   response = requests.post(url, headers=headers, verify=False)

   # Check for HTTP error status
   response.raise_for_status()

   print("✅ Logout successful.")

# Function - Find parent folder containing the published disks
def find_parent_folder(get_disk_publish_info):
   if not isinstance(get_disk_publish_info, dict):
       raise FileNotFoundError("Invalid API response type for mount info")

   disks = get_disk_publish_info.get("disks")
   if not disks:
       disks = (get_disk_publish_info.get("info") or {}).get("disks")

   if not disks:
       raise FileNotFoundError("No disks information found in Data Integration API response")

   mount_points = []
   for d in disks:
       mps = d.get("mountPoints") or []
       mount_points.extend(mps)

   if not mount_points:
       raise FileNotFoundError("No mountPoints found in Data Integration API response")

   first_path = mount_points[0]

   # Extract the parent '/.../Veeam.Mount.FS.<id>/' from the path
   parts = first_path.split('/')
   parent = None
   for i, part in enumerate(parts):
       if part.startswith("Veeam.Mount.FS."):
           parent = '/'.join(parts[:i+1]) + '/'
           break

   # Fallback (Testing only - shouldn't be needed)
   if not parent:
       parent = os.path.dirname(first_path) + '/'

   print(f"📂 Using parent folder {parent}")
   return parent

# Function - Trigger THOR scan
def trigger_scan(parent_folder, host2scan):
  # Construct the HTML output file path
  html_file = f"/thor/output/{host2scan}_thor_:time:.html"

  physical_hostname = subprocess.check_output("hostname",  shell=True).decode().strip()

  # Build the Docker run command
  command = [
      "sudo", "docker", "run", "--rm",
      "--hostname", physical_hostname,
      "-v", f"{parent_folder}:/data",
      "-v", f"{results_dir}:/thor/output",
      docker_image,
      "--path", "/data",
      #"--quick",
      "--htmlfile", html_file,
      "-e", "/thor/output"
  ]
  # Trigger the scan
  print(f"🔍 Starting scan for {host2scan}")

  try:
      subprocess.run(command, check=True)
      print(f"✅ Scan completed. Results available in {results_dir}")
  except subprocess.CalledProcessError as e:
      print(f"❌ Error running scan: {e}")

# Function - Display Restore Points
def display_restore_points(restorePoint):
   print("\n{:<5} {:<25} {:<20} {:<15}".format("Index", "Hostname", "Creation Time", "Malware Status"))
   print("-" * 70)

   for idx, point in enumerate(restorePoint["data"][:10]):
       # Shorten creation time
       raw_time = point["creationTime"]
       formatted_time = datetime.datetime.fromisoformat(raw_time.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")

       if point["malwareStatus"].lower() == "clean":
           status_display = "✅ Clean"
       else:
           status_display = "🐞 " + point["malwareStatus"]

       print("{:<5} {:<25} {:<20} {:<15}".format(idx, point["name"], formatted_time, status_display))

# Function - Get Selected Restore Point
class TimeoutException(Exception):
   pass

def timeout_handler(signum, frame):
   raise TimeoutException

def select_restore_point(restorePoint):
   try:
       signal.signal(signal.SIGALRM, timeout_handler)
       # Timer set to 15 seconds. Adjust if needed.
       print()
       print("⏳ You have 15 seconds to select a restore point, otherwise, the latest will be chosen automatically.")
       signal.alarm(15)

       # Restore Point Selection and Validation
       choice = input("❓ Select a restore point by entering a number (0-9):")
       signal.alarm(0)

       if choice.isdigit() and int(choice) in range(len(restorePoint["data"])):
           return int(choice)
       else:
           print("❌ Invalid selection. Defaulting to the first item.")
           return 0

   except TimeoutException:
       print("⏳ Timeout! Defaulting to the first item.")
       return 0
   except EOFError:
       # Fallback to the latest restore point (index 0).
       print("⏳ No input (EOF). Defaulting to the first item.")
       return 0

# Main section
def main():
   parser = argparse.ArgumentParser(description="Trigger a THOR APT Scan using Data Integration API.")
   parser.add_argument("--host2scan", required=True, help="Hostname from which the last backup will be scanned")
   parser.add_argument("--latest", action="store_true", help="Automatically use the latest restore point without prompting")
   args = parser.parse_args()

   # General Variables
   password = get_password()
   scanhost = socket.gethostname()

   if not password:
       print("❌ Password not found in the password file.")
       return

   # Request Bearer Token
   print("🐻 Get Bearer Token....")
   token = connect_veeam_rest_api(api_url, username, password)

   # Define Query Parameters
   print("📂 Get latest Restore Points for " + args.host2scan + "....")
   rp_query_params = {
       "skip"               : "0",
       "limit"              : "10",
       "orderColumn"        : "CreationTime",
       "orderAsc"           : "false",
       "nameFilter"         : args.host2scan
   }

   scansrv_query_params = {
       "nameFilter"         : scanhost,
       "typeFilter"         : "LinuxHost"
   }

   # Start REST API Commands
   # Get Restore Points
   restorePoint = get_veeam_rest_api(api_url=api_url, endpoint="v1/restorePoints", token=token, params=rp_query_params)

   # Bad luck - No Restore Point
   if not restorePoint.get("data"):
      print("❌ No restore points found for " + args.host2scan + ". Exiting script.")
      exit(1)

   # Selection logic:
   if args.latest:
       print("⚙️ Auto mode - Scanning using latest restore point.")
       selected_index = 0
   else:
       # Show found Restore Points
       print("📂 Found Restore Points for " + args.host2scan + "....")
       display_restore_points(restorePoint)
       # Select an index value
       selected_index = select_restore_point(restorePoint)

   # Extract restore point parameters of the selected restore point
   restore_point_id = restorePoint["data"][selected_index]["id"]
   restore_point_creationtime = restorePoint["data"][selected_index]["creationTime"]
   print(f"✅ Selected Restore Point Creation Time: {restore_point_creationtime}")

   # Get Scanhost Credentials
   scansrv        = get_veeam_rest_api(api_url, "v1/backupInfrastructure/managedServers", token, params=scansrv_query_params)
   scansrv_credId = scansrv["data"][0]["credentialsId"]

   # Start Data Integration API Disk Publish
   data_integration_api_body = {
       "restorePointId"            : restore_point_id,
       "type"                      : "FUSELinuxMount",
       "targetServerName"          : scanhost,
       "targetServerCredentialsId" : scansrv_credId
   }

   start_disk_publish = post_veeam_rest_api(api_url, "v1/dataIntegration/publish", token, body=data_integration_api_body)
   disk_publish_id    = start_disk_publish.get("id")
   print("✅ Disk published. Id:", disk_publish_id)
   print("⏳ Wait for the mount process to finish....")
   time.sleep(30)
   get_disk_publish_info = get_veeam_rest_api(api_url, f"v1/dataIntegration/{disk_publish_id}", token)
   # print(f"{get_disk_publish_info}")

   # Start THOR APT Scan
   try:
      parent_folder = find_parent_folder(get_disk_publish_info)
      print(f"📂 Found parent folder: {parent_folder}")

      # Trigger the scan
      print(f"📦 Using container image: {docker_image}")
      trigger_scan(parent_folder, args.host2scan)
   except FileNotFoundError as e:
      print(e)

   # Stop Disk Publish
   print(f"🛑 Stop publishing backup....")
   time.sleep(5)
   unpublish_endpoint = f"v1/dataIntegration/{disk_publish_id}/unpublish"
   stop_disk_publish  = post_veeam_rest_api(api_url, unpublish_endpoint , token, body=data_integration_api_body)

   return token

if __name__ == "__main__":
   token = main()
   if token:
       print("🚪 Logging out....")
       post_logout(api_url, token)
