import base64
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from datetime import datetime, timezone, timedelta
import argparse

# Disable SSL warnings - Use only in test environments
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Latest x-api-version - Change server address
api_url     = "https://localhost:9419"
api_version = "1.1-rev1"

def decode_password(encoded_password):
    decoded_bytes = base64.b64decode(encoded_password.encode())
    return decoded_bytes.decode()

# Change filename if secret was stored differently
def get_password():
    try:
        with open("secret.txt", "r") as file:
            encoded_password = file.read().strip()
            return decode_password(encoded_password)
    except FileNotFoundError:
        return None

def connect_veeam_rest_api(api_url, username, password):
    token_url = f"{api_url}/api/oauth2/token"

    headers = {
        "Content-Type" : "application/x-www-form-urlencoded",
        "x-api-version": api_version,
        "accept"       : "application/json"
    }

    body = {
        "grant_type"   : "password",
        "username"     : username,
        "password"     : password,
        "refresh_token": " ",
        "rememberMe"   : " "
    }

    response = requests.post(token_url, headers=headers, data=body, verify=False)
    response.raise_for_status()

    return response.json()["access_token"]

def post_veeam_rest_api(api_url, endpoint, token, body):
    url = f"{api_url}/api/{endpoint}"
    headers = {
        "accept"       : "application/json",
        "x-api-version": api_version,
        "Content-Type" : "application/json",
        "Authorization": f"Bearer {token}"
    }

    response = requests.post(url, headers=headers, json=body, verify=False)
    response.raise_for_status()

    return response.json()

def post_logout(api_url, token):
    url = f"{api_url}/api/oauth2/logout"
    headers = {
        "accept"       : "application/json",
        "x-api-version": api_version,
        "Authorization": f"Bearer {token}"
    }

    response = requests.post(url, headers=headers, verify=False)

    # Check for HTTP error status
    response.raise_for_status()
    print("Logout successful.")


def main():
    parser = argparse.ArgumentParser(description="Start an Instant VM recovery for the given VM.")
    parser.add_argument("-hostname", required=True, help="Hostname of the to be recovered VM")
    parser.add_argument("-past", type=int, required=True, help="Number of past days to search from today")

    args = parser.parse_args()

    # General Variables - Change password retrieval logic
    username = "Administrator"
    password = get_password()

    if not password:
        print("Password not found in the password file.")
        return

    # Calculate date filters
    current_date          = datetime.now(timezone.utc)
    past_days             = timedelta(days=args.past)
    created_after_filter  = (current_date - past_days).isoformat()
    created_before_filter = current_date.isoformat()

    # Request Bearer Token
    print("Get Bearer Token....")
    token = connect_veeam_rest_api(api_url, username, password)

    # Get Restore Points 
    print("Get Restore Points for "+args.hostname+" ....")
    query_params = {
        "skip"               : "0",
        "limit"              : "1",
        "orderColumn"        : "CreationTime",
        "orderAsc"           : "true",
        "createdAfterFilter" : created_after_filter,
        "createdBeforeFilter": created_before_filter,
        "nameFilter"         : args.hostname
    }

    headers = {
        "x-api-version": api_version,
        "Authorization": f"Bearer {token}"
    }

    response = requests.get(f"{api_url}/api/v1/restorePoints", headers=headers, params=query_params, verify=False)
    response.raise_for_status()
    restorePoint = response.json()
    print("Response:", restorePoint)

    restore_point_id = None

    if restorePoint and "data" in restorePoint and restorePoint["data"]:
        restore_point_id = restorePoint["data"][0]["id"]  
    
    # If restore point ID is found, continue with the restore process
    if restore_point_id:
        print("Restore point found with ID:", restore_point_id)
        print("Do you want to continue with the restore process? (yes/no)")
        user_input = input().strip().lower()
        if user_input != 'yes':
            print("Exiting...")
            exit(0)

        # Construct payload for the second REST API call
        payload = {
            "restorePointId": restore_point_id,
            "type"          : "Customized",
            "secureRestore" : {
                "antivirusScanEnabled"   : False,
                "virusDetectionAction"   : "DisableNetwork",
                "entireVolumeScanEnabled": False
            },
            "nicsEnabled" : False,
            "powerUp"     : False,
            "reason"      : "string",
            "destination" : {
                "restoredVmName" : f"{args.hostname}_restored",
                "destinationHost": {
                    "platform"   : "VMware",
                    "hostName"   : "esx-srv.domain.local",
                    "name"       : "esx-srv",                   
                    "type"       : "Host",

                },
                "folder": {
                "platform": "VMware",
                "hostName": "esx-srv.domain.local",
                "name": "Folder01",
                "type": "Folder",
                },
                "resourcePool": {
                "platform": "VMware",
                "hostName": "esx-srv.domain.local",
                "name": "Pool01",
                "type": "ResourcePool",
                },
                "biosUuidPolicy": "preserve"
            },
            "datastore": {
                "redirectEnabled": True,
                "cacheDatastore": {
                "platform": "VMware",
                "size": "string",
                "hostName": "esx-srv.domain.local",
                "name": "Datastore01",
                "type": "Datastore",
                }
            },
            "overwrite": False
}
        print("Instant VM recovery...")
        second_app_uri = "v1/restore/instantRecovery/vmware/vm/"
        second_url = f"{api_url}/api/{second_app_uri}"
        second_headers = {
            "accept"       : "application/json",
            "x-api-version": api_version,
            "Content-Type" : "application/json",
            "Authorization": f"Bearer {token}"
        }
        second_response = requests.post(second_url, json=payload, headers=second_headers, verify=False)
        
        print("Restore process response:", second_response)
    else:
        print("No restore points found.")
        
    return token

if __name__ == "__main__":
    token = main()
    if token:
        print("Log out....")
        post_logout(api_url, token)

