#!/usr/bin/env python3
import requests
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# WARNING: Hardcoded credentials are NOT safe and should ONLY be used for testing purposes!
USERNAME = "Administrator"
PASSWORD = "YourPasswordHere"  # <--- Replace with your test password
API_VERSION = "1.3-rev1"

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def connect_veeam_rest_api(api_url, username, password):
    url = f"{api_url}/api/oauth2/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "x-api-version": API_VERSION,
        "accept": "application/json"
    }
    data = {"grant_type": "password", "username": username, "password": password}
    response = requests.post(url, headers=headers, data=data, verify=False)
    response.raise_for_status()
    return response.json()["access_token"]

def post_inventory(api_url, token, payload):
    url = f"{api_url}/api/v1/inventory"
    headers = {
        "accept": "application/json",
        "x-api-version": API_VERSION,
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    response = requests.post(url, headers=headers, json=payload, verify=False)
    response.raise_for_status()
    return response.json()

def post_inventory_detail(api_url, token, object_id, payload=None):
    url = f"{api_url}/api/v1/inventory/{object_id}"
    headers = {
        "accept": "application/json",
        "x-api-version": API_VERSION,
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    response = requests.post(url, headers=headers, json=payload or {}, verify=False)
    response.raise_for_status()
    return response.json()

def post_logout(api_url, token):
    url = f"{api_url}/api/oauth2/logout"
    headers = {
        "accept": "application/json",
        "x-api-version": API_VERSION,
        "Authorization": f"Bearer {token}"
    }
    requests.post(url, headers=headers, verify=False)

def main():
    parser = argparse.ArgumentParser(description="Search for a VM by exact name in Veeam via vCenter")
    parser.add_argument("--vbrserver", required=True, help="Veeam Backup & Replication server (FQDN or IP)")
    parser.add_argument("--vmname", required=True, help="Exact name of the VM to search for")
    args = parser.parse_args()

    api_url = f"https://{args.vbrserver}:9419"
    vm_name = args.vmname

    print("Getting authentication token...")
    token = connect_veeam_rest_api(api_url, USERNAME, PASSWORD)
    print("Authentication successful.")

    # Step 1: Find vCenter server object
    payload_vc = {
        "filter": {
            "type": "PredicateExpression",
            "operation": "equals",
            "property": "type",
            "value": "vCenterServer"
        }
    }
    response_vc = post_inventory(api_url, token, payload_vc)
    vc_objects = response_vc.get("data", [])
    if not vc_objects:
        print("No vCenter server found!")
        post_logout(api_url, token)
        return

    # Use the first vCenter server found
    vc = vc_objects[0]
    vc_id = vc.get("objectId")
    print(f"Using vCenter '{vc.get('name')}' with ObjectId {vc_id}")

    # Step 2: Search for VMs under vCenter (broader search using 'contains')
    payload_vm = {
        "query": {
            "filter": {
                "type": "GroupExpression",
                "operation": "and",
                "items": [
                    {
                        "type": "PredicateExpression",
                        "operation": "contains",
                        "property": "name",
                        "value": vm_name
                    },
                    {
                        "type": "PredicateExpression",
                        "operation": "equals",
                        "property": "type",
                        "value": "Vm"
                    }
                ]
            }
        }
    }
    response_vm = post_inventory_detail(api_url, token, vc_id, payload_vm)
    vm_objects = response_vm.get("data", [])

    # Now filter for exact match (case-insensitive)
    exact_vms = [vm for vm in vm_objects if vm.get('name', '').lower() == vm_name.lower()]

    if exact_vms:
        print("Found exact matching VM(s):")
        for vm in exact_vms:
            print(f"- Name: {vm.get('name')}, Hostname: {vm.get('hostName')}, ObjectId: {vm.get('objectId')}, Type: {vm.get('type')}")
    else:
        print(f"No VM with the exact name '{vm_name}' exists in vCenter.")

    post_logout(api_url, token)

if __name__ == "__main__":
    main()
