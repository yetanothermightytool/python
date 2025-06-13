#!/usr/bin/python3
import argparse
import json
import subprocess
import requests
from cryptography.fernet import Fernet
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Veeam Backup & Replicaton Server - Adjust Hostname
api_url = "https://vbr-host01:9419"
api_version = "1.2-rev1"

# Get password (Fernet) for REST API calls agains Veeam Backup & Replication REST API
def get_password():
   with open("encryption_key.key", "rb") as key_file:
       key = key_file.read()
   with open("encrypted_password.bin", "rb") as password_file:
       encrypted_password = password_file.read()
   return Fernet(key).decrypt(encrypted_password).decode()

# Connect to Veeam REST API - Get Bearer Token
def connect_veeam_rest_api(api_url, username, password):
   headers = {
       "Content-Type": "application/x-www-form-urlencoded",
       "x-api-version": api_version,
       "accept": "application/json"
   }
   body = {
       "grant_type": "password",
       "username": username,
       "password": password,
       "refresh_token": "",
       "rememberMe": ""
   }
   response = requests.post(f"{api_url}/api/oauth2/token", headers=headers, data=body, verify=False)
   response.raise_for_status()
   return response.json()["access_token"]

# VEEAM REST API POST
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

# VEEAM REST API GET
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

# VEEAM REST API Logout
def post_logout(api_url, token):
   url = f"{api_url}/api/oauth2/logout"
   headers = {
       "accept": "application/json",
       "x-api-version": api_version,
       "Authorization": f"Bearer {token}"
   }
   requests.post(url, headers=headers, verify=False)

# VEEAM REST API GET Host ID from Managed Servers
def resolve_host_id(token, hostname, type_filter):
   params = {"typeFilter": type_filter, "nameFilter": hostname}
   data = get_veeam_rest_api(api_url, "v1/backupInfrastructure/managedServers", token, params)
   for item in data.get("data", []):
       if item["name"].lower() == hostname.lower():
           return item["id"]
   raise Exception(f"{type_filter} host '{hostname}' not found.")

# VEEAM REST API GET Repository ID
def resolve_repository_id(token, repo_name):
   params = {"nameFilter": repo_name}
   data = get_veeam_rest_api(api_url, "v1/backupInfrastructure/repositories", token, params)
   for repo in data.get("data", []):
       if repo["name"].lower() == repo_name.lower():
           return repo["id"]
   raise Exception(f"Repository '{repo_name}' not found.")

# VEEAM REST API GET Credential ID
def resolve_credential_id(token, name_filter):
   params = {"nameFilter": name_filter, "typeFilter": "Linux"}
   data = get_veeam_rest_api(api_url, "v1/credentials", token, params)
   for item in data.get("data", []):
       return item["id"]
   raise Exception(f"Credential '{name_filter}' not found.")

# VEEAM REST API GET SSH Fingerprint
def get_fingerprint_via_veeam_api(server_name, credential_id, token):
   url = f"{api_url}/api/v1/connectionCertificate"
   headers = {
       "Content-Type": "application/json",
       "x-api-version": api_version,
       "Authorization": f"Bearer {token}"
   }
   body = {
       "serverName": server_name,
       "credentialsStorageType": "Permanent",
       "credentialsId": credential_id,
       "type": "LinuxHost"
   }
   response = requests.post(url, headers=headers, json=body, verify=False)
   response.raise_for_status()
   return response.json().get("fingerprint")

# VEEAM REST AI ADD Linux Host
def add_linux_host(args, token):
   cred_id = resolve_credential_id(token, args.credentials_name)
   if args.fingerprint:
       fingerprint = args.fingerprint.strip()
   else:
       print(f"🔍 Get SSH-Fingerprint for {args.name}...")
       fingerprint = get_fingerprint_via_veeam_api(args.name, cred_id, token)
       print("✅ Fingerprint OK.")
   body = {
       "sshSettings": {
           "sshTimeOutMs": 20000,
           "portRangeStart": 2500,
           "portRangeEnd": 3300,
           "serverSide": False,
           "managementPort": 6162
       },
       "type": "LinuxHost",
       "name": args.name,
       "description": "Scanner",
       "credentialsId": cred_id,
       "credentialsStorageType": "Permanent",
       "sshFingerprint": fingerprint
   }
   print(f"➕ Adding Linux server {args.name}")
   result = post_veeam_rest_api(api_url, "v1/backupInfrastructure/managedServers", token, body)
   #print(json.dumps(result, indent=2))

# VEEAM REST API Delete Linux Host
def delete_linux_host(args, token):
   host_id = resolve_host_id(token, args.name, "LinuxHost")
   url = f"{api_url}/api/v1/backupInfrastructure/managedServers/{host_id}"
   headers = {
       "accept": "application/json",
       "x-api-version": api_version,
       "Authorization": f"Bearer {token}"
   }
   response = requests.delete(url, headers=headers, verify=False)
   if response.status_code == 200:
       print(f"✅ Linux-Host '{args.name}' (ID: {host_id}) deleted.")
   else:
       print("❌ Error while deleting.")
       print(response.json())

# Veeam REST API Add Repository (Linux)
def add_repository(args, token):
   linux_host_id = resolve_host_id(token, args.linux_host, "LinuxHost")
   windows_host_id = resolve_host_id(token, args.mount_server, "WindowsHost")
   body = {
       "hostId": linux_host_id,
       "repository": {
           "path": args.path,
           "taskLimitEnabled": True,
           "maxTaskCount": args.task_count,
           "readWriteLimitEnabled": True,
           "readWriteRate": args.read_write_rate,
           "useFastCloningOnXFSVolumes": False,
           "useImmutableBackups": False,
           "advancedSettings": {
               "RotatedDriveCleanupMode": "Disabled",
               "alignDataBlocks": True,
               "decompressBeforeStoring": True,
               "rotatedDrives": False,
               "perVmBackup": True
           }
       },
       "mountServer": {
           "mountServerId": windows_host_id,
           "writeCacheFolder": "C:\\ProgramData\\Veeam\\Backup\\IRCache2\\",
           "vPowerNFSEnabled": True,
           "vPowerNFSPortSettings": {
               "mountPort": 1058,
               "vPowerNFSPort": 2049
           }
       },
       "type": args.type,
       "name": args.name,
       "description": args.description
   }
   print("➕ Create Repository...")
   result = post_veeam_rest_api(api_url, "v1/backupInfrastructure/repositories", token, body)
   #print(json.dumps(result, indent=2))

# VEEAM REST API Rescan Backup Repository
def rescan_repository(args, token):
   repo_id = resolve_repository_id(token, args.repo_name)
   body = {"repositoryIds": [repo_id]}
   result = post_veeam_rest_api(api_url, "v1/backupInfrastructure/repositories/rescan", token, body)
   print(f"✅ Repository '{args.repo_name}' (ID: {repo_id}) will be scanned.")

# VEEAM REST API Delete Backup Repository
def delete_repository(args, token):
   repo_id = resolve_repository_id(token, args.repo_name)
   url = f"{api_url}/api/v1/backupInfrastructure/repositories/{repo_id}"
   headers = {
       "accept": "application/json",
       "x-api-version": api_version,
       "Authorization": f"Bearer {token}"
   }
   params = {
       "deleteBackups": "true"
   }
   response = requests.delete(url, headers=headers, params=params, verify=False)
   if response.status_code == 204:
       print(f"✅ Repository '{args.repo_name}' (ID: {repo_id}) deleted.")
   else:
       print("❌ Error while deleting Repository.")
       #print(response.json())

# Main
def main():
   parser = argparse.ArgumentParser(description="Veeam Repository Manager")
   subparsers = parser.add_subparsers(dest="command", required=True)
   add_host = subparsers.add_parser("add-linux-host", help="Add a Linux host")
   add_host.add_argument("--name", required=True)
   add_host.add_argument("--credentials-name", required=True)
   add_host.add_argument("--description", default="Backup Repository")
   add_host.add_argument("--fingerprint", required=False, help="SSH-Fingerprint (optional)")
   add_repo = subparsers.add_parser("add", help="Add Repository")
   add_repo.add_argument("--linux-host", required=True)
   add_repo.add_argument("--mount-server", required=True)
   add_repo.add_argument("--path", required=True)
   add_repo.add_argument("--name", required=True)
   add_repo.add_argument("--description", default="")
   add_repo.add_argument("--type", default="LinuxLocal")
   add_repo.add_argument("--task-count", type=int, default=4)
   add_repo.add_argument("--read-write-rate", type=int, default=1)
   rescan = subparsers.add_parser("rescan", help="Rescan Repository")
   rescan.add_argument("--repo-name", required=True)
   delete = subparsers.add_parser("delete", help="Delete Repository")
   delete.add_argument("--repo-name", required=True)
   delete_host = subparsers.add_parser("delete-linux-host", help="Delete Linux host")
   delete_host.add_argument("--name", required=True, help="Linux hostname")
   args = parser.parse_args()
   username = "restapiuser"
   password = get_password()
   token = connect_veeam_rest_api(api_url, username, password)
   try:
       if args.command == "add-linux-host":
           add_linux_host(args, token)
       elif args.command == "add":
           add_repository(args, token)
       elif args.command == "rescan":
           rescan_repository(args, token)
       elif args.command == "delete":
           delete_repository(args, token)
       elif args.command == "delete-linux-host":
           delete_linux_host(args, token)
   finally:
       post_logout(api_url, token)
if __name__ == "__main__":
   main()
