#!/usr/bin/python3
import argparse
import requests
import json
from cryptography.fernet import Fernet
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from datetime import datetime

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

api_version = "1.2-rev1"

# Get fernet password files.
def get_password():
   with open("encryption_key.key", "rb") as key_file:
       key = key_file.read()
   with open("encrypted_password.bin", "rb") as password_file:
       encrypted_password = password_file.read()
   return Fernet(key).decrypt(encrypted_password).decode()

 # Veeam REST API functions
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


def job_info(api_url, token):
   # Backup Jobs Info
   jobs_data = get_veeam_rest_api(api_url, "v1/jobs", token)
   job_items = []

   for job in jobs_data.get("data", []):
       job_type = job.get("type", "-")
       job_name = job.get("name", "-")

       storage = job.get("storage", {}) or {}
       adv_settings = storage.get("advancedSettings", {}) or {}
       backup_mode = adv_settings.get("backupModeType", "-")

       if backup_mode == "ReverseIncremental":
           job_items.append({
               "Name": job_name,
               "Type": job_type,
               "Backup Mode": backup_mode
           })

   if job_items:
       print_section(
           "Backup Jobs (ReverseIncremental)",
           job_items,
           ["Name", "Type", "Backup Mode"]
       )
   else:
       print("\nNo Jos with backup mode 'Reverse Incremental' found.")

def main():
   parser = argparse.ArgumentParser(description="Veeam Job Checker")
   parser.add_argument("--vbrserver", required=True, help="VBR server hostname or IP (required)")
   args = parser.parse_args()

   api_url = f"https://{args.vbrserver}:9419"

   username = "administrator"
   password = get_password()
   token = connect_veeam_rest_api(api_url, username, password)
   job_info(api_url, token)
   post_logout(api_url, token)

if __name__ == "__main__":
   main()
