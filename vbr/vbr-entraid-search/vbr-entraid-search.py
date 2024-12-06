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
# Disable SSL warnings - Use only in test environments
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Variables - Change where necessary
api_url         = "https://<your_vbr_server_here>:9419"
api_version     = "1.2-rev0"

# Function - Get Stored Password
def get_password():
    try:
        with open("encryption_key.key", "rb") as key_file:
            key = key_file.read()

        with open("encrypted_password.bin", "rb") as password_file:
            encrypted_password = password_file.read()

        fernet = Fernet(key)
        decrypted_password = fernet.decrypt(encrypted_password).decode()
        return decrypted_password

    except FileNotFoundError as e:
        raise Exception(f"Required file not found: {e.filename}")
    except Exception as e:
        raise Exception(f"Failed to retrieve the password: {e}")

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
        "refresh_token" : " ",
        "rememberMe"    : " "
    }

    response = requests.post(token_url, headers=headers, data=body, verify=False)
    response.raise_for_status()

    return response.json()["access_token"]

# Function - POST against Veeam REST API - not used yet
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

# Function - Display Restore Points
def display_restore_points(restorePoint):
    print("\n{:<5} {:<25} {:<20}".format("Index", "Tenant Name", "Creation Time"))
    print("-" * 70)

    for idx, point in enumerate(restorePoint["data"][:10]):
        # Shorten creation time
        raw_time = point["creationTime"]
        formatted_time = datetime.datetime.fromisoformat(raw_time.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")

        print("{:<5} {:<25} {:<20}".format(idx, point["name"], formatted_time))

# Functions and Class - Get Selected Restore Point with timeout counter
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

# Function - Find matching Restore Point - Work in progress 
def find_restore_point(get_rp, search_type, rpId, selected_index):
    data = get_rp.get("data")
    if not data or not isinstance(data, list):
        print(f"❌ {search_type} not found in restore point.")
        return False

    if 0 <= selected_index < len(data):
        comparisonId = data[selected_index]["id"]
        if comparisonId == rpId:
            print(f"✅ Found {search_type} in the specifically selected restore point with creation time {data[selected_index]['creationTime']}.")
            return True
        else:
            print(f"❌ {search_type} not found in the selected restore point.")
            return False
    else:
        matching_restore_points = [item for item in data if item["id"] == rpId]
        if matching_restore_points:
            matching_restore_points.sort(
                key=lambda x: x["creationTime"], reverse=True
            )
            comparisonId = matching_restore_points[0]["id"]
            print(f"✅ Found {search_type} in the most recent matching restore point with creation time {matching_restore_points[0]['creationTime']}.")
            return True
        else:
            print(f"❌ {search_type} not found in restore point.")
            return False

# Main section
def main():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-username", required=False, help="Display name of the user to be searched for.")
    parser.add_argument("-groupname", required=False, help="Display name of the group to be searched for.")
    parser.add_argument("-applicationname", required=False, help="Display name of the application to be searched for.")
    parser.add_argument("-checkprod", action='store_true', required=False, help="Checks if item exists in production")
    parser.add_argument("-compareprod", action='store_true', required=False, help="Compares item properties between a restore point and production")

    args = parser.parse_args()

    # Get User Credentals for REST API Queries - Change username if necessary
    username = "<your_username_here>"
    password = get_password()

    if not password:
        print("❌ Password not found in the password file.")
        return

    # Request Bearer Token
    print("🐻 Get Bearer Token....")
    token = connect_veeam_rest_api(api_url, username, password)

    # Define Query Parameters
    print("📂 Get 10 latest Restore Points....")
    rp_query_params = {
        "limit"              : "10",
        "orderColumn"        : "CreationTime",
        "orderAsc"           : "false",
        "platformNameFilter" : "EntraID"
    }

    # Get Restore Points
    restorePoint = get_veeam_rest_api(api_url=api_url,endpoint="v1/restorePoints",token=token,params=rp_query_params)

    # Bad luck - No Restore Point
    if not restorePoint.get("data"):
       print("❌ No restore points found for protected EntraId tenant.")
       exit(1)

    backupId = restorePoint["data"][0]["backupId"]

    rp_query_params =  {
        "limit": 10,
        "sorting": {
        "property": "creationTime",
        "direction": "descending"
        }
    }

    get_rp_url = f"/v1/backupBrowser/entraIdTenant/{backupId}/restorePoints"
    get_rp     = post_veeam_rest_api(api_url, get_rp_url, token, body=rp_query_params)

    # Show found Restore Points
    print("📂 Found Restore Points for....")
    display_restore_points(restorePoint)

    # Select an index value
    selected_index = select_restore_point(restorePoint)

    # Extract the ID of the selected restore point
    rpId = get_rp["data"][selected_index]["id"]
    print(f"✅ Selected Restore Point ID: {rpId}")

    # Start Entra ID Restore Session
    restore_tenant_body = {
        "backupId" : backupId
    }

    start_restore_tenant   = post_veeam_rest_api(api_url, "v1/restore/entraId/tenant", token, body=restore_tenant_body)
    restore_tenant_sess_id = start_restore_tenant.get("sessionId")
    print("✅ Tenant Restore Session started. Session Id:",restore_tenant_sess_id)
    print("⏳ Wait for the process to finish....")
    time.sleep(15)

    # Dynamically build Body, based on passed argument
    if hasattr(args, "username") and args.username:
        search_type  = "User"
        filter_value = args.username
    elif hasattr(args, "groupname") and args.groupname:
        search_type  = "Group"
        filter_value = args.groupname
    elif hasattr(args, "applicationname") and args.applicationname:
        search_type  = "Application"
        filter_value = args.applicationname
    else:
        raise ValueError("No valid argument provided. Please provide username, groupname, or applicationname.")

    search_body = {
        "type": search_type,
        "filter": {
        "displayName": filter_value
        }
    }

    browse_rp_url = f"/v1/backupBrowser/entraIdTenant/{backupId}/browse"
    search_id     = post_veeam_rest_api(api_url, browse_rp_url, token, body=search_body)

    if search_id.get('data'):
       itemId        = search_id["data"][0]["id"]
    else:
        print(f"❌ {search_type} not found.")
        print(f"🛑 Stop Restore Session....")
        time.sleep(5)
        stop_endpoint        = f"/v1/restore/entraId/tenant/{restore_tenant_sess_id}/stop"
        stop_restore_tenant  = post_veeam_rest_api(api_url, stop_endpoint , token, body=restore_tenant_body)
        return token

    get_rp_body = {
        "limit": 10,
        "sorting": {
        "property": "creationTime",
        "direction": "descending"
          }
    }

    get_rp_url    = f"/v1/backupBrowser/entraIdTenant/{backupId}/browse/{itemId}/restorePoints"
    get_rp        = post_veeam_rest_api(api_url, get_rp_url, token, body=get_rp_body)

    found = find_restore_point(get_rp, search_type, rpId, selected_index)

    if not found:
        print(f"❌ {search_type} not found.")

    else:

    # Checks if item exists in production - optional parameter
        if args.checkprod:
            print(f"🔍 Check if item exists in production....")
            search_item_body ={
                "items": [
                {
                "itemId": itemId,
                "restorePointId": rpId
                }
                ]
            }
            check_url  = f"/v1/backupBrowser/entraIdTenant/{restore_tenant_sess_id}/checkProductionItems"
            check_prod = post_veeam_rest_api(api_url, check_url, token, body=search_item_body)

            if check_prod.get('items'):
                print(f"✅ {search_type} found in production!")
            else:
                print(f"❌ {search_type} not found in production!")

        # Compares selected restore point with production - optional parameter
        if args.compareprod:
            print(f"🔍 Compare item between restore point and production....")
            compare_item_body ={
                "itemId": itemId,
                "itemType": search_type,
                "oldRestorePointId": rpId,
                "showUnchangedAttributes": False,
                "reloadCache": True
            }

            compare_url  = f"/v1/backupBrowser/entraIdTenant/{restore_tenant_sess_id}/compare"
            compare_prod = post_veeam_rest_api(api_url, compare_url, token, body=compare_item_body)

            if compare_prod.get('properties'):
                print("🔎 Differences found:")
                pprint.pprint(compare_prod['properties'])
            else:
                print("❌ No differences found.")

        # Stop Restore Session
        print(f"🛑 Stop Restore Session....")
        time.sleep(5)
        stop_endpoint        = f"/v1/restore/entraId/tenant/{restore_tenant_sess_id}/stop"
        stop_restore_tenant  = post_veeam_rest_api(api_url, stop_endpoint , token, body=restore_tenant_body)

        return token # I like Token Ring

if __name__ == "__main__":
    token = main()
    if token:
        print("🚪 Logging out....")
        post_logout(api_url, token)

