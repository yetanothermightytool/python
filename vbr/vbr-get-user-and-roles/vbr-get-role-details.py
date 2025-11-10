#!/usr/bin/python3
import argparse
import requests
from cryptography.fernet import Fernet
from tabulate import tabulate
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
    parser = argparse.ArgumentParser(description="Veeam GET roles and permissions")
    parser.add_argument("--vbrserver", required=True, help="VBR server hostname or IP (required)")
    parser.add_argument("--fulldetails", action="store_true", help="Print all permissions to console")
    parser.add_argument("--export", action="store_true", help="Export permissions for each role as a text file")
    args = parser.parse_args()

    api_url = f"https://{args.vbrserver}:9419"
    username = "Administrator"
    password = get_password()
    token = connect_veeam_rest_api(api_url, username, password)
    try:
        # Get all roles
        result = get_veeam_rest_api(api_url, "v1/security/roles", token)
        rows = []
        for item in result.get("data", []):
            role_id = item.get("id", "")
            role_name = item.get("name", "")
            role_desc = item.get("description", "")
            # Get permissions for each role
            perm_result = get_veeam_rest_api(api_url, f"v1/security/roles/{role_id}/permissions", token)
            perm_list = perm_result.get("permissions", [])
            if args.fulldetails:
                permissions = '\n'.join(perm_list)
            else:
                max_perms = 3
                if len(perm_list) > max_perms:
                    permissions = '\n'.join(perm_list[:max_perms]) + f"\n... ({len(perm_list)} total)"
                else:
                    permissions = '\n'.join(perm_list)
            if args.export:
                fname = f"permissions_{role_name.replace(' ', '_').replace('/', '_')}.txt"
                with open(fname, "w") as f:
                    for perm in perm_list:
                        f.write(perm + "\n")
                permissions += f"\n(exported to {fname})"
            rows.append([
                role_name,
                role_desc,
                permissions
            ])
        headers = [
            "Role name", "Description", "Permissions"
        ]
        if rows:
            print(tabulate(rows, headers, tablefmt="grid", stralign="left"))
        else:
            print("No roles found.")
    finally:
        post_logout(api_url, token)

if __name__ == "__main__":
    main()
