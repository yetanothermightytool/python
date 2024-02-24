import base64
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from datetime import datetime, timezone, timedelta
import argparse

# Disable SSL warnings - Use only in test environments
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Latest x-api-version - V12.1 - Change server address
api_url     = "https://localhost:9419"
api_version = "1.1-rev1"

def decode_password(encoded_password):
    decoded_bytes = base64.b64decode(encoded_password.encode())
    return decoded_bytes.decode()

# Change filename if secret was stored differently
def get_password():
    try:
        with open(".secret.txt", "r") as file:
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


def find_object_id(data, esxihost_name):
    for item in data:
        if item['type'] == 'Host' and item['name'] == esxihost_name:
            return item['objectId']
    return None

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
    parser.add_argument("-past", type=int, required=True, help="Number of past days to search for restore points from today")
    parser.add_argument("-vcenter", required=True, help="vCenter hostname")
    parser.add_argument("-esxihost", required=True, help="ESXi host where VM should be restored to")

    args = parser.parse_args()

    # General Variables - Change username
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
        "orderAsc"           : "false",
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
    # print("Response:", restorePoint)

    restore_point_id = None

    if restorePoint and "data" in restorePoint and restorePoint["data"]:
        restore_point_id = restorePoint["data"][0]["id"]

    # Get VMware vSphere Objects
        query = {

            }

        print("Getting vCenter Objects...")
        vmware_objects_uri = "v1/inventory/"+args.vcenter
        vmware_objects_url = f"{api_url}/api/{vmware_objects_uri}"
        get_vmware_objects = requests.post(vmware_objects_url, params=query, headers=headers, verify=False)
        data = get_vmware_objects.json()
        
		# Find objectId of the specified ESXi host
        esxihost_id = find_object_id(data['data'], args.esxihost)

        if esxihost_id:
           print(f"Found objectId for {args.esxihost}: {esxihost_id}")
        else:
           print(f"ObjectId not found for {args.esxihost}")

    # Construct payload for Instant VM recovery
        payload = {
        "restorePointId": restore_point_id,
        "type" : "Customized",
        "vmTagsRestoreEnabled": True,
        "secureRestore": {
            "antivirusScanEnabled": True,
            "virusDetectionAction": "DisableNetwork",
            "entireVolumeScanEnabled": True
        },
        "nicsEnabled": False,
        "powerUp": False,
        "reason": "Python Script",
        "destination": {
            "restoredVmName": args.hostname+"_restored",
            "destinationHost": {
            "platform": "VMware",
            "hostName": args.vcenter,
            "name": args.esxihost,
            "type": "Host",
            "objectId": esxihost_id
            },
            "folder": {
            "platform": "VMware",
            "hostName": args.vcenter,
            "name": "CleanRoom",
            "type": "Folder",
            "objectId": "group-v55555"
            },
            "resourcePool": {
            "platform": "VMware",
            "hostName": args.vcenter,
            "name": "Resources",
            "type": "ResourcePool",
            "objectId": "resgroup-1"
            },
            "biosUuidPolicy": "preserve"
        },
        "datastore": {
            "redirectEnabled": False
        },
        "overwrite": False
        }

        print("Restore VM...")
        restore_vm_uri = "v1/restore/instantRecovery/vSphere/vm"
        restore_vm_url = f"{api_url}/api/{restore_vm_uri}"
        instant_vm_recovery = requests.post(restore_vm_url, json=payload, headers=headers, verify=False)

        print("Restore process response:", instant_vm_recovery)
    else:
        print("No restore points found.")

    return token

if __name__ == "__main__":
    token = main()
    if token:
        print("Log out....")
        post_logout(api_url, token)

