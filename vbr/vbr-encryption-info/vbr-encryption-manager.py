#!/usr/bin/python3
import argparse
import requests
import json
import sys
from getpass import getpass
from cryptography.fernet import Fernet
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from datetime import datetime

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Version 1.3-rev0 for key APIs
api_version = "1.3-rev0"

def get_password():
   with open("encryption_key.key", "rb") as key_file:
       key = key_file.read()
   with open("encrypted_password.bin", "rb") as password_file:
       encrypted_password = password_file.read()
   return Fernet(key).decrypt(encrypted_password).decode()

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

def post_logout(api_url, token):
   url = f"{api_url}/api/oauth2/logout"
   headers = {
       "accept": "application/json",
       "x-api-version": api_version,
       "Authorization": f"Bearer {token}"
   }
   requests.post(url, headers=headers, verify=False)

def print_section(title, items, columns):
   print(f"\n==== {title} ====")
   if not items:
       print(f"No data found for {title}.")
       return
   col_widths = [max(len(str(row.get(col, ''))) for row in items + [{col: col}]) for col in columns]
   header = " | ".join(col.ljust(width) for col, width in zip(columns, col_widths))
   print(header)
   print("-+-".join('-' * width for width in col_widths))
   for row in items:
       print(" | ".join(str(row.get(col, '')).ljust(width) for col, width in zip(columns, col_widths)))

def write_html_report(jobs, certs, keys, kms, filename, backup_server_name, build_version):
   html = []
   html.append("<html><head><meta charset='UTF-8'><title>VBR Encryption Report</title>")
   html.append("""
   <style>
       body { font-family: Arial, sans-serif; }
       h2 { color: #246; }
       table { border-collapse: collapse; width: 100%; margin-bottom: 2em;}
       th, td { border: 1px solid #aaa; padding: 6px; }
       th { background-color: #e0e7f1; }
       tr:nth-child(even){background-color: #f9f9f9;}
   </style></head><body>
   """)
   html.append("<h1>Veeam Encryption Report</h1>")
   html.append("<h2>Backup Server Information</h2>")
   html.append(f"<p><b>Name:</b> {backup_server_name}<br>")
   html.append(f"<b>Version:</b> {build_version}</p>")

   def table(title, items, columns):
       html.append(f"<h2>{title}</h2>")
       if not items:
           html.append("<p>No data found.</p>")
           return
       html.append("<table><tr>" + "".join(f"<th>{col}</th>" for col in columns) + "</tr>")
       for row in items:
           html.append("<tr>" + "".join(f"<td>{row.get(col, '')}</td>" for col in columns) + "</tr>")
       html.append("</table>")

   table("Backup Jobs", jobs, ["Name", "Type", "TargetRepository", "TargetRepositoryPath", "EncryptionStatus", "KeyType", "EncryptionPasswordId"])
   table("Certificates", certs, ["Thumbprint", "Subject", "ValidFrom", "ValidBy"])
   table("Encryption Passwords", keys, ["Description", "ModificationDate", "Id"])
   table("KMS Servers", kms, ["Name", "Port"])

   html.append("</body></html>")
   with open(filename, "w", encoding="utf-8") as f:
       f.write("\n".join(html))

def encryption_info(api_url, token, html=False, json_output=False):
   # Get backup server information
   server_info_data = get_veeam_rest_api(api_url, "v1/serverInfo", token)
   backup_server_name = server_info_data.get("name", "-")
   build_version = server_info_data.get("buildVersion", "-")

   # Backup Jobs Encryption Info
   jobs_data = get_veeam_rest_api(api_url, "v1/jobs", token)
   job_items = []
   repo_cache = {}

   for job in jobs_data.get("data", []):
       job_type = job.get("type", "-")
       job_name = job.get("name", "-")

       repo_name = "-"
       repo_path = "-"
       encryption_status = "Unencrypted"
       key_type = "-"
       encryption_password_id = "-"

       storage = job.get("storage", {})
       repo_id = storage.get("backupRepositoryId")

       adv_settings = storage.get("advancedSettings", {})
       storage_data = adv_settings.get("storageData", {})
       encryption = storage_data.get("encryption", {})
       if encryption.get("isEnabled", False):
           encryption_status = "Enabled"
           key_type = encryption.get("encryptionType", "-")
           encryption_password_id = encryption.get("encryptionPasswordId", "-")

       if repo_id:
           if repo_id not in repo_cache:
               try:
                   repo_info = get_veeam_rest_api(api_url, f"v1/backupInfrastructure/repositories/{repo_id}", token)
                   repo_cache[repo_id] = {
                       "name": repo_info.get("name", "-"),
                       "path": repo_info.get("repository", {}).get("path", "-")
                   }
               except Exception:
                   repo_cache[repo_id] = {"name": "Error", "path": "Error"}
           repo_name = repo_cache[repo_id]["name"]
           repo_path = repo_cache[repo_id]["path"]

       job_items.append({
           "Name": job_name,
           "Type": job_type,
           "TargetRepository": repo_name,
           "TargetRepositoryPath": repo_path,
           "EncryptionStatus": encryption_status,
           "KeyType": key_type,
           "EncryptionPasswordId": encryption_password_id
       })

   # Certificates
   certs = get_veeam_rest_api(api_url, "v1/serverCertificate", token)
   cert_report = [{
       "Thumbprint": certs.get("thumbprint", ""),
       "Subject": certs.get("subject", ""),
       "ValidFrom": certs.get("validFrom", ""),
       "ValidBy": certs.get("validBy", "")
   }]

   # Encryption Passwords (Keys)
   keys_data = get_veeam_rest_api(api_url, "v1/encryptionPasswords", token)
   key_items = []
   for key in keys_data.get("data", []):
       key_items.append({
           "Description": key.get("hint", ""),
           "ModificationDate": key.get("modificationTime", ""),
           "Id": key.get("id", "")
       })

   # KMS Servers
   kms_data = get_veeam_rest_api(api_url, "v1/kmsServers", token)
   kms_items = []
   for kms in kms_data.get("data", []):
       kms_items.append({
           "Name": kms.get("name"),
           "Port": kms.get("port")
       })

   if json_output:
       out = {
           "BackupServer": {"Name": backup_server_name, "Version": build_version},
           "BackupJobs": job_items,
           "Certificates": cert_report,
           "EncryptionPasswords": key_items,
           "KMSServers": kms_items
       }
       print(json.dumps(out, indent=2))
   elif html:
       timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
       safe_server_name = "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in backup_server_name)
       filename = f"vbr-encryption-report-{safe_server_name}-{timestamp}.html"
       write_html_report(job_items, cert_report, key_items, kms_items, filename, backup_server_name, build_version)
       print(f"\nHTML report written to: {filename}")
   else:
       print_section(
           "Backup Jobs",
           job_items,
           ["Name", "Type", "TargetRepository", "TargetRepositoryPath", "EncryptionStatus", "KeyType", "EncryptionPasswordId"]
       )
       print_section("Certificates", cert_report, [
           "Thumbprint", "Subject", "ValidFrom", "ValidBy"
       ])
       print_section("Encryption Passwords", key_items, ["Description", "ModificationDate", "Id"])
       print_section("KMS Servers", kms_items, ["Name", "Port"])

# Key Manager
def read_secret_from_args(args, prompt="Enter password: "):
   # Priority: --password-stdin > --password-file > interactive getpass
   if getattr(args, "password_stdin", False):
       data = sys.stdin.read()
       return data.rstrip("\n\r")
   if getattr(args, "password_file", None):
       with open(args.password_file, "r", encoding="utf-8") as f:
           return f.read().strip()
   return getpass(prompt)

def key_manager(api_url, token, keyname, verify=False, change=False, new_hint=None, args=None):
   # 1) find key by hintFilter
   params = {
       "skip": 0,
       "limit": 200,
       "orderColumn": "Hint",
       "orderAsc": True,
       "hintFilter": keyname
   }
   resp = get_veeam_rest_api(api_url, "v1/encryptionPasswords", token, params=params)
   matches = resp.get("data", []) or []
   if not matches:
       print(f"No keys found with hintFilter='{keyname}'.")
       return
   # prefer exact hint match if multiple
   exact = [k for k in matches if (k.get("hint") or "") == keyname]
   selected = None
   if len(exact) == 1:
       selected = exact[0]
   elif len(matches) == 1:
       selected = matches[0]
   else:
       # checker
       print("Multiple keys matched. Please refine --keyname. Candidates:")
       for k in matches:
           print(f"- Id={k.get('id')}  Hint='{k.get('hint')}'  Modified={k.get('modificationTime')}")
       return

   key_id = selected.get("id")
   key_hint = selected.get("hint") or ""
   print(f"Selected key Id={key_id} Hint='{key_hint}'")

   # verify
   if verify:
       secret = read_secret_from_args(args, prompt="Enter key password for verification: ")
       payload = {"password": secret}
       try:
           result = post_veeam_rest_api(api_url, f"v1/encryptionPasswords/{key_id}/verify", token, payload)
           ok = result.get("isValid") if isinstance(result, dict) else None
           if ok is True:
               print("Password verification: SUCCESS")
           elif ok is False:
               print("Password verification: FAILED")
           else:
               print("Verification completed. Response:")
               print(json.dumps(result, indent=2))
       except requests.HTTPError as e:
           print(f"Verification failed: {e}")
           if e.response is not None:
               print(e.response.text)
           return

   # change
   if change:
       # read new password (and optional new hint)
       new_password = read_secret_from_args(args, prompt="Enter NEW key password: ")
       if not new_hint:
           # keep existing hint by default
           new_hint = key_hint or "Updated key"
       payload = {"hint": new_hint, "password": new_password}
       try:
           result = post_veeam_rest_api(api_url, f"v1/encryptionPasswords/{key_id}/changepassword", token, payload)
           print("Password change requested. Response:")
           print(json.dumps(result, indent=2))
       except requests.HTTPError as e:
           print(f"Change password failed: {e}")
           if e.response is not None:
               print(e.response.text)

def main():
   parser = argparse.ArgumentParser(description="Veeam Encryption Info Reporter")
   parser.add_argument("--vbrserver", required=True, help="VBR server hostname or IP")
   subparsers = parser.add_subparsers(dest="command", required=True)

   # encryption-info
   encryption_parser = subparsers.add_parser("encryption-info", help="Show encryption and key info")
   mx = encryption_parser.add_mutually_exclusive_group()
   mx.add_argument("--html", action="store_true", help="Export report as HTML")
   mx.add_argument("--json", action="store_true", help="Print report as JSON to stdout")

   # key-manager
   km = subparsers.add_parser("key-manager", help="Manage encryption passwords (filter by hint)")
   km.add_argument("--keyname", required=True, help="Key hint filter (exact match preferred)")
   action = km.add_mutually_exclusive_group(required=True)
   action.add_argument("--verify", action="store_true", help="Verify the key password")
   action.add_argument("--change", action="store_true", help="Change the key password")
   km.add_argument("--hint", dest="new_hint", help="New hint when changing the password (optional)")
   # secret input options (avoid plaintext on CLI)
   km.add_argument("--password-stdin", action="store_true", help="Read password from STDIN (pipe)")
   km.add_argument("--password-file", help="Read password from file")

   args = parser.parse_args()
   api_url = f"https://{args.vbrserver}:9419"

   username = "veeamadmin"
   password = get_password()
   token = connect_veeam_rest_api(api_url, username, password)
   try:
       if args.command == "encryption-info":
           encryption_info(api_url, token, html=args.html, json_output=args.json)
       elif args.command == "key-manager":
           key_manager(
               api_url,
               token,
               keyname=args.keyname,
               verify=args.verify,
               change=args.change,
               new_hint=args.new_hint,
               args=args
           )
   finally:
       post_logout(api_url, token)

if __name__ == "__main__":
   main()

