#!/usr/bin/env python3
import requests
import argparse
import sys
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

def post_inventory_physical(api_url, token, payload):
    url = f"{api_url}/api/v1/inventory/physical"
    headers = {
        "accept": "application/json",
        "x-api-version": API_VERSION,
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    response = requests.post(url, headers=headers, json=payload, verify=False)
    response.raise_for_status()
    return response.json()

def post_inventory_physical_detail(api_url, token, protection_group_id, payload):
    url = f"{api_url}/api/v1/inventory/physical/{protection_group_id}"
    headers = {
        "accept": "application/json",
        "x-api-version": API_VERSION,
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    response = requests.post(url, headers=headers, json=payload, verify=False)
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
    parser = argparse.ArgumentParser(description="Search for an agent (protected host) by exact name in all Veeam Protection Groups")
    parser.add_argument("--vbrserver", required=True, help="Veeam Backup & Replication server (FQDN or IP)")
    parser.add_argument("--agentname", required=True, help="Exact name of the agent (host) to search for")
    args = parser.parse_args()

    api_url = f"https://{args.vbrserver}:9419"
    agent_name = args.agentname

    print("Getting authentication token...")
    token = connect_veeam_rest_api(api_url, USERNAME, PASSWORD)
    print("Authentication successful.")

    # Step 1: Get all Protection Groups (no filter, get all)
    payload_pg = {}
    try:
        response_pg = post_inventory_physical(api_url, token, payload_pg)
    except requests.HTTPError as e:
        print("Error while retrieving protection groups:", e)
        post_logout(api_url, token)
        sys.exit(1)

    pg_objects = response_pg.get("data", [])
    if not pg_objects:
        print("No Protection Groups found!")
        post_logout(api_url, token)
        sys.exit(0)

    found = False
    for pg in pg_objects:
        pg_id = pg.get("id") or pg.get("protectionGroupId")
        pg_name = pg.get("name")
        if not pg_id:
            print(f"Skipping entry without id: {pg}")
            continue
        # Step 2: Search each Protection Group for the agent (contains for prefilter, exact match in Python)
        payload_agent = {
            "filter": {
                "type": "PredicateExpression",
                "operation": "contains",
                "property": "name",
                "value": agent_name
            }
        }
        try:
            response_agents = post_inventory_physical_detail(api_url, token, pg_id, payload_agent)
        except requests.HTTPError as e:
            print(f"Error while querying protection group '{pg_name}' ({pg_id}):", e)
            continue
        agent_objects = response_agents.get("data", [])
        # Filter for exact match (case-insensitive)
        exact_agents = [a for a in agent_objects if a.get('name', '').lower() == agent_name.lower()]
        if exact_agents:
            found = True
            for agent in exact_agents:
                print(f"Found agent '{agent.get('name')}' in protection group '{pg_name}' (Protection Group ID: {pg_id}):")
                print(f"- Hostname: {agent.get('hostName')}")
                print(f"- ObjectId: {agent.get('id') or agent.get('objectId')}")
                print(f"- Type: {agent.get('type')}")
    if not found:
        print(f"No agent with the exact name '{agent_name}' exists in any Protection Group.")

    post_logout(api_url, token)

if __name__ == "__main__":
    main()
