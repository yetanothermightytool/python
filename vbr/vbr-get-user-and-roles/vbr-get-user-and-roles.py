#!/usr/bin/python3
import argparse
import requests
from cryptography.fernet import Fernet
from tabulate import tabulate
import json

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

api_version = "1.3-rev1"

def get_password():
    # Read and decrypt the password using Fernet key
    with open("encryption_key.key", "rb") as key_file:
        key = key_file.read()
    with open("encrypted_password.bin", "rb") as password_file:
        encrypted_password = password_file.read()
    return Fernet(key).decrypt(encrypted_password).decode()

def connect_veeam_rest_api(api_url, username, password):
    # Authenticate and get access token from Veeam REST API
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

def get_veeam_rest_api(api_url, endpoint, token, params=None):
    # Generic function to perform a GET request on Veeam REST API
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
    # Logout from Veeam REST API session
    url = f"{api_url}/api/oauth2/logout"
    headers = {
        "accept": "application/json",
        "x-api-version": api_version,
        "Authorization": f"Bearer {token}"
    }
    requests.post(url, headers=headers, verify=False)

def main():
    parser = argparse.ArgumentParser(description="Veeam GET users, roles and permissions (with filter options and export)")
    parser.add_argument("--vbrserver", required=True, help="VBR server hostname or IP (required)")
    parser.add_argument("--name", help="Filter by username or group name (case-insensitive substring)")
    parser.add_argument("--serviceaccounts", action="store_true", help="Show only service accounts")
    parser.add_argument("--export", action="store_true", help="Export permissions for the user/group as JSON (only with --name)")
    args = parser.parse_args()

    if args.export and not args.name:
        print("Export is only supported in combination with --name.")
        return

    api_url = f"https://{args.vbrserver}:9419"
    username = "Administrator"
    password = get_password()
    token = connect_veeam_rest_api(api_url, username, password)
    try:
        result = get_veeam_rest_api(api_url, "v1/security/users", token)
        rows = []
        export_data = None
        for item in result.get("data", []):
            # Apply name filter if specified
            if args.name and args.name.lower() not in item.get("name", "").lower():
                continue
            # Apply service account filter if specified
            if args.serviceaccounts and not item.get("isServiceAccount", False):
                continue
            # Gather roles and permissions for each user/group
            role_infos = []
            permissions_set = set()
            for role in item.get("roles", []):
                role_id = role.get("id", "")
                role_name = role.get("name", "")
                role_infos.append(role_name)
                # Get permissions for each role
                try:
                    perm_result = get_veeam_rest_api(api_url, f"v1/security/roles/{role_id}/permissions", token)
                    permissions_set.update(perm_result.get("permissions", []))
                except Exception as e:
                    permissions_set.add(f"Error fetching permissions for role {role_name}")
            # Prepare permissions output
            permissions_list = sorted(list(permissions_set))
            max_perms = 10
            if len(permissions_list) > max_perms:
                permissions_str = '\n'.join(permissions_list[:max_perms]) + f"\n... ({len(permissions_list)} total)"
            else:
                permissions_str = '\n'.join(permissions_list)
            rows.append([
                item.get("id", ""),
                item.get("name", ""),
                item.get("type", ""),
                ', '.join(role_infos),
                item.get("isServiceAccount", False),
                permissions_str
            ])
            # Prepare export data if requested and with --name
            if args.export and args.name:
                export_data = {
                    "id": item.get("id", ""),
                    "name": item.get("name", ""),
                    "type": item.get("type", ""),
                    "roles": role_infos,
                    "isServiceAccount": item.get("isServiceAccount", False),
                    "permissions": permissions_list
                }
                # Nur den ersten passenden Benutzer exportieren
                break
        headers = [
            "id", "name", "type", "roles", "isServiceAccount", "permissions"
        ]
        if rows:
            print(tabulate(rows, headers, tablefmt="grid", stralign="left"))
        else:
            print("No users/groups found matching the filter criteria.")
        # Export as JSON if requested
        if args.export and export_data:
            safe_name = export_data["name"].replace(" ", "_").replace("/", "_")
            filename = f"{safe_name}_vbr_permission.json"
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2)
            print(f"Exported permissions to {filename}")
    finally:
        post_logout(api_url, token)

if __name__ == "__main__":
    main()
