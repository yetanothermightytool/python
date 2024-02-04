import base64
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import argparse
from tabulate import tabulate

# Note: Using currently undocumented private endpoints

# Disable SSL warnings - Use only in test environments
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Change parameters where necessary
api_url     = "https://localhost:1239"
api_version = "v2.2"
secret_file = "secret.txt"
user_name   = ".\\Administrator"

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

def connect_veeam_one_rest_api(api_url, username, password):
    token_url = f"{api_url}/api/token"

    headers = {
        "Content-Type"  : "application/x-www-form-urlencoded",
        "x-api-version" : api_version,
        "accept"        : "application/json"
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

def get_veeam_one_rest_api(api_url, api_version, endpoint, token, params=None):
    url = f"{api_url}/api/{api_version}/{endpoint}"
    headers = {
        "accept": "application/json",
        "x-api-version": api_version,
        "Authorization": f"Bearer {token}"
    }

    response = requests.get(url, headers=headers, params=params, verify=False)
    response.raise_for_status()

    return response.json()

def post_veeam_one_rest_api(api_url, endpoint, token, body):
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

def change_veeam_one_credentials(api_url, api_version, credential_id, token, new_credentials):
    endpoint = f"credentials/{credential_id}/assign/host"
    url = f"{api_url}/api/{api_version}/{endpoint}"

    headers = {
        "accept"        : "application/json",
        "x-api-version" : api_version,
        "Content-Type"  : "application/json",
        "Authorization" : f"Bearer {token}"
    }

    body = {
        "newCredentials": new_credentials
    }

    response = requests.post(url, headers=headers, json=body, verify=False)
    response.raise_for_status()

    print(f"Raw Response for '{endpoint}':")
    print(response.text)

    return response.json()

def main():
    parser = argparse.ArgumentParser(description='Veeam ONE Credentials Manager')
    parser.add_argument("-get", action="store_true", help="Returns all credentials")
    parser.add_argument("-getCredId", metavar="credentialId", help="Returns the credential set with the specified credentialId")
    parser.add_argument("-chgCred", nargs=2, metavar=("credential_id", "new_credentials"), required=False,
                        help="Change credentials with the specified credential_id and new_credentials")
    args = parser.parse_args()

    username = user_name
    password = get_password()

    if not password:
        print("Password not found in the secret.txt file.")
        return

    # Request Bearer Token
    print("Get Bearer Token....")
    token = connect_veeam_one_rest_api(api_url, username, password)

    if args.getCredId:
        cred_id = args.getCredId
        endpoint = f"credentials/{cred_id}/assign/host"
        assign_host_response = get_veeam_one_rest_api(api_url, api_version, endpoint, token)

        print(f"Details for credential ID {cred_id}:")
        formatted_response = []
        for obj in assign_host_response.get("assignedObjects", []):
            formatted_response.append({
                "credentialId": cred_id,
                "userName"   : assign_host_response.get("userName", ""),
                "objectId"   : obj.get("objectId", ""),
                "objectName" : obj.get("objectName", ""),
                "objectType" : obj.get("objectType", "")
            })

        print(tabulate(formatted_response, headers="keys", tablefmt="pretty"))
        return

    if args.get:
        get_endpoint = "credentials"
        credentials = get_veeam_one_rest_api(api_url, api_version, get_endpoint, token)
        
        print("All Credentials:")
        print(tabulate(credentials.get("items", []), headers="keys", tablefmt="pretty"))
        return

    if args.chgCred:
        credential_id, new_credentials = args.chgCred
        change_veeam_one_credentials(api_url, api_version, credential_id, token, new_credentials)
        print(f"Credentials for credential_id {credential_id} changed successfully.")
        return

if __name__ == "__main__":
    main()

