#!/usr/bin/python3
import os
import base64
import subprocess
import argparse
import datetime
import time
import signal
import requests
import pprint
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from cryptography.fernet import Fernet

os.system('clear')
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

api_version = "1.3-rev1"

def get_password():
   try:
       with open("encryption_key.key", "rb") as key_file:
           key = key_file.read()
       with open("encrypted_password.bin", "rb") as password_file:
           encrypted_password = password_file.read()
       fernet = Fernet(key)
       return fernet.decrypt(encrypted_password).decode()
   except FileNotFoundError as e:
       raise Exception(f"Required file not found: {e.filename}")
   except Exception as e:
       raise Exception(f"Failed to retrieve the password: {e}")

def connect_veeam_rest_api(api_url, username, password):
   token_url = f"{api_url}/api/oauth2/token"
   headers = {
       "Content-Type": "application/x-www-form-urlencoded",
       "x-api-version": api_version,
       "accept": "application/json"
   }
   body = {
       "grant_type": "password",
       "username": username,
       "password": password,
       "refresh_token": " ",
       "rememberMe": " "
   }
   response = requests.post(token_url, headers=headers, data=body, verify=False)
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
   response = requests.post(url, headers=headers, verify=False)
   response.raise_for_status()
   print("✅ Logout successful.")

def display_restore_points(restorePoint):
   print("\n{:<5} {:<25} {:<20}".format("Index", "Tenant Name", "Creation Time"))
   print("-" * 70)
   for idx, point in enumerate(restorePoint["data"][:10]):
       raw_time = point["creationTime"]
       formatted_time = datetime.datetime.fromisoformat(
           raw_time.replace("Z", "+00:00")
       ).strftime("%Y-%m-%d %H:%M:%S")
       print("{:<5} {:<25} {:<20}".format(idx, point["name"], formatted_time))

class TimeoutException(Exception):
   pass

def timeout_handler(signum, frame):
   raise TimeoutException

def select_restore_point(restorePoint):
   try:
       signal.signal(signal.SIGALRM, timeout_handler)
       print()
       print("⏳ You have 15 seconds to select a restore point, otherwise, the latest will be chosen automatically.")
       signal.alarm(15)
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

def find_restore_point(get_rp, search_type, rpId, selected_index):
   data = get_rp.get("data")
   if not data or not isinstance(data, list):
       print(f"❌ {search_type} not found in restore point.")
       return False
   if 0 <= selected_index < len(data):
       comparisonId = data[selected_index]["id"]
       if comparisonId == rpId:
           print(f"✅ Found {search_type} in the selected restore point with creation time {data[selected_index]['creationTime']}.")
           return True
       else:
           print(f"❌ {search_type} not found in the selected restore point.")
           return False
   else:
       matching_restore_points = [item for item in data if item["id"] == rpId]
       if matching_restore_points:
           matching_restore_points.sort(key=lambda x: x["creationTime"], reverse=True)
           print(f"✅ Found {search_type} in newest matching restore point {matching_restore_points[0]['creationTime']}.")
           return True
       else:
           print(f"❌ {search_type} not found in restore point.")
           return False

def main():
   parser = argparse.ArgumentParser(description="")

   parser.add_argument("--vbrserver", required=True)
   parser.add_argument("--restapiuser", required=False, default="administrator")

   parser.add_argument("--latest", action="store_true")

   parser.add_argument("--username", required=False)
   parser.add_argument("--groupname", required=False)
   parser.add_argument("--applicationname", required=False)

   parser.add_argument("--checkprod", action="store_true")
   parser.add_argument("--compareprod", action="store_true")

   args = parser.parse_args()

   api_url = f"https://{args.vbrserver}:9419"
   username = args.restapiuser
   password = get_password()

   print("🐻 Get Bearer Token....")
   token = connect_veeam_rest_api(api_url, username, password)

   print("📂 Get 10 latest Restore Points....")
   rp_query_params = {
       "limit": "10",
       "orderColumn": "CreationTime",
       "orderAsc": "false",
       "platformNameFilter": "EntraID"
   }

   restorePoint = get_veeam_rest_api(api_url, "v1/restorePoints", token, params=rp_query_params)

   if not restorePoint.get("data"):
       print("❌ No restore points found.")
       exit(1)

   backupId = restorePoint["data"][0]["backupId"]

   rp_query_params = {
       "limit": 10,
       "sorting": {
           "property": "creationTime",
           "direction": "descending"
       }
   }

   get_rp = post_veeam_rest_api(api_url, f"v1/backupBrowser/entraIdTenant/{backupId}/restorePoints", token, body=rp_query_params)

   print("📂 Found Restore Points")
   display_restore_points(restorePoint)

   if args.latest:
       print("⚡ --latest enabled → Selecting index 0 automatically")
       selected_index = 0
   else:
       selected_index = select_restore_point(restorePoint)

   rpId = get_rp["data"][selected_index]["id"]
   print(f"✅ Selected Restore Point ID: {rpId}")

   restore_tenant_body = {"backupId": backupId}
   start_restore_tenant = post_veeam_rest_api(api_url, "v1/restore/entraId/tenant", token, body=restore_tenant_body)
   restore_tenant_sess_id = start_restore_tenant.get("sessionId")

   print("⏳ Wait for the process to finish....")
   time.sleep(15)

   if args.username:
       search_type = "User"
       filter_value = args.username
   elif args.groupname:
       search_type = "Group"
       filter_value = args.groupname
   elif args.applicationname:
       search_type = "Application"
       filter_value = args.applicationname
   else:
       raise ValueError("No valid argument provided.")

   search_body = {"type": search_type, "filter": {"displayName": filter_value}}

   search_id = post_veeam_rest_api(api_url, f"v1/backupBrowser/entraIdTenant/{backupId}/browse", token, body=search_body)

   if search_id.get("data"):
       itemId = search_id["data"][0]["id"]
   else:
       print(f"❌ {search_type} not found.")
       post_veeam_rest_api(api_url, f"v1/restore/entraId/tenant/{restore_tenant_sess_id}/stop", token, body=restore_tenant_body)
       return token, api_url

   get_rp = post_veeam_rest_api(
       api_url,
       f"v1/backupBrowser/entraIdTenant/{backupId}/browse/{itemId}/restorePoints",
       token,
       body=rp_query_params
   )

   found = find_restore_point(get_rp, search_type, rpId, selected_index)

   if found and args.checkprod:
       search_item_body = {"items": [{"itemId": itemId, "restorePointId": rpId}]}
       check_prod = post_veeam_rest_api(
           api_url,
           f"v1/backupBrowser/entraIdTenant/{restore_tenant_sess_id}/checkProductionItems",
           token,
           body=search_item_body
       )
       if check_prod.get("items"):
           print(f"✅ {search_type} exists in production")
       else:
           print(f"❌ {search_type} NOT found in production")

   if found and args.compareprod:
       compare_item_body = {
           "itemId": itemId,
           "itemType": search_type,
           "oldRestorePointId": rpId,
           "showUnchangedAttributes": False,
           "reloadCache": True
       }
       compare_prod = post_veeam_rest_api(
           api_url,
           f"v1/backupBrowser/entraIdTenant/{restore_tenant_sess_id}/compare",
           token,
           body=compare_item_body
       )

       if compare_prod.get("properties"):
           print("🔎 Differences:")
           pprint.pprint(compare_prod["properties"])
       else:
           print("❌ No differences found")

   post_veeam_rest_api(api_url, f"v1/restore/entraId/tenant/{restore_tenant_sess_id}/stop", token, body=restore_tenant_body)

   return token, api_url


if __name__ == "__main__":
   token, api_url = main()
   if token:
       print("🚪 Logging out....")
       post_logout(api_url, token)
