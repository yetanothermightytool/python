import keyring
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from datetime import datetime, timezone
import argparse

# Disable SSL warnings - Use only in test environemts
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Latest x-api-version
api_version = "1.1-rev1"

def get_password(service, username):
    return keyring.get_password(service, username)

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

def main():
    parser = argparse.ArgumentParser(description="Trigger an Incident API event.")
    parser.add_argument("-fqdn", required=True, help="Fully Qualified Domain Name")
    parser.add_argument("-ip", required=True, help="IP address")
    parser.add_argument("-details", required=True, help="Details")

    args = parser.parse_args()

    # General Variables - Change to your environment
    api_url = "https://<your vbr server>:9419"
    username = "Administrator"
    password = get_password("<your keyring service name>", username)

    if not password:
        print("Password not found in keyring. Please set it using the set-keyring utility.")
        return

    # Request Bearer Token
    print("Get Bearer Token....")
    token = connect_veeam_rest_api(api_url, username, password)
    
    # Body for the Incident API event
    body_data = {
        "detectionTimeUtc": datetime.now(timezone.utc).isoformat() + "Z",
        "machine": {
            "fqdn": args.fqdn,
            "ipv4": args.ip
        },
        "details": args.details,
        "engine": "YAMT Test Script"
    }

    print("Triggering Incident API event....")
    app_uri = "v1/malwareDetection/events"
    response = post_veeam_rest_api(api_url, app_uri, token, body_data)
    
    print("Incdient API event triggered successfully.")
    #print("Response:", response)

if __name__ == "__main__":
    main()

