import base64
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import argparse
from tabulate import tabulate

# Disable SSL warnings - Use only in test environments
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Change parameters where necessary
api_url           = "https://localhost:9419"
api_major_version = "v1"
api_version       = "1.1-rev1"
secret_file       = "secret.txt"

# Functions
def decode_password(encoded_password):
    decoded_bytes = base64.b64decode(encoded_password.encode())
    return decoded_bytes.decode()

def get_password():
    try:
        with open(secret_file, "r") as file:
            encoded_password = file.read().strip()
            return decode_password(encoded_password)
    except FileNotFoundError:
        return None

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

def get_veeam_rest_api(api_url, api_version, endpoint, token, params=None):
    url = f"{api_url}/api/{api_major_version}/{endpoint}"
    headers = {
        "accept": "application/json",
        "x-api-version": api_version,
        "Authorization": f"Bearer {token}"
    }

    response = requests.get(url, headers=headers, params=params, verify=False)
    response.raise_for_status()

    return response.json()

def post_veeam_rest_api(api_url, endpoint, token, body, headers=None):
    url = f"{api_url}/api/{endpoint}"
    default_headers = {
        "accept": "application/json",
        "x-api-version": api_version,
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }

    headers = headers or default_headers

    response = requests.post(url, headers=headers, json=body, verify=False)
    response.raise_for_status()

    return response

def change_password(api_url, api_major_version, api_version, cred_id, token, new_password):
    endpoint = f"{api_major_version}/credentials/{cred_id}/changepassword"
    payload = {"password": new_password}

    headers = {
        "Content-Type": "application/json",
        "x-api-version": api_version,
        "Authorization": f"Bearer {token}"
    }

    print(f"Changing password for credential {cred_id}...")

    try:
        response = post_veeam_rest_api(api_url, endpoint, token, payload, headers=headers)

        if response.status_code == 200:
            print("Password change successful")
        else:
            print(f"Password change failed. Status Code: {response.status_code}")
            print("Raw Response:")
            print(response.text)

    except requests.exceptions.HTTPError as e:
        print(f"Error changing password: {e}")
        print("Response text:")
        print(e.response.text)


def main():
    parser = argparse.ArgumentParser(description='Veeam Backup & Replication Credentials Manager')
    parser.add_argument("-get", action="store_true", help="Returns all credentials")
    parser.add_argument("-getCredId", metavar="credentialId", help="Returns the credential informations with the specified credentialId")
    parser.add_argument("-chgCred", nargs=2, metavar=("credentialId", "newPassword"), help="Change the password for the specified credentialId")
    
    args = parser.parse_args()

    username = ".\\Administrator"
    password = get_password()

    if not password:
        print("Password not found in the password.txt file.")
        return

    # Request Bearer Token
    print("Get Bearer Token....")
    token = connect_veeam_rest_api(api_url, username, password)

    if args.getCredId:
        cred_id = args.getCredId
        endpoint = f"credentials/{cred_id}"
        assign_host_response = get_veeam_rest_api(api_url, api_version, endpoint, token)
  
        formatted_response = []
        print("Details for given credential ID:")

        obj = assign_host_response
        formatted_response.append({
            "uniqueId"     : obj.get("uniqueId", ""),
            "type"         : obj.get("type", ""),
            "id"           : obj.get("id", ""),
            "username"     : obj.get("username", ""),
            "description"  : obj.get("description", ""),
            "creationTime" : obj.get("creationTime", ""),
            "SSHPort"      : obj.get("SSHPort", ""),
            "elevateToRoot": obj.get("elevateToRoot", ""),
            "addToSudoers" : obj.get("addToSudoers", ""),
            "useSu"        : obj.get("useSu", ""),
            "privateKey"   : obj.get("privateKey", ""),
            "passphrase"   : obj.get("passphrase", ""),
        })

        print(tabulate(formatted_response, headers="keys", tablefmt="pretty"))
        return
  
    if args.get:
        get_endpoint = "credentials"
        credentials  = get_veeam_rest_api(api_url, api_version, get_endpoint, token)
        
        print("All Credentials:")
        print(tabulate(credentials.get("data", []), headers="keys", tablefmt="pretty"))
        return

    if args.chgCred:
        cred_id, new_password = args.chgCred
        change_password(api_url, api_major_version, api_version, cred_id, token, new_password)
        return

if __name__ == "__main__":
    main()

