#!/usr/bin/env python3
import argparse
import os
import re
import sys
import time
import urllib3
import requests
from dotenv import load_dotenv

load_dotenv()

# (connect, read) — keeps the CLI from hanging on an unreachable VBR server
HTTP_TIMEOUT = (5, 60)

# DellDataDomain was only added to the repositories endpoint in 1.3-rev2
DELL_DATA_DOMAIN_MIN_API = (1, 3, 2)


def load_config():
    endpoint = os.getenv("VEEAM_ENDPOINT")
    username = os.getenv("VEEAM_USERNAME")
    password = os.getenv("VEEAM_PASSWORD")
    api_version = os.getenv("VEEAM_API_VERSION", "1.3-rev1")
    verify_raw = os.getenv("VEEAM_SSL_VERIFY", "true").strip()
    # token renewal is handled transparently, so this is purely a patience setting
    session_timeout = int(os.getenv("VEEAM_SESSION_TIMEOUT", "3600"))

    missing = [k for k, v in {
        "VEEAM_ENDPOINT": endpoint,
        "VEEAM_USERNAME": username,
        "VEEAM_PASSWORD": password,
    }.items() if not v]
    if missing:
        sys.exit(f"Missing required .env entries: {', '.join(missing)}")

    # verify accepts true/false or a path to a CA/cert file (pinning)
    if verify_raw.lower() in ("true", "1", "yes"):
        verify = True
    elif verify_raw.lower() in ("false", "0", "no"):
        verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    else:
        verify = verify_raw

    return {
        "endpoint": endpoint.rstrip("/"),
        "username": username,
        "password": password,
        "api_version": api_version,
        "verify": verify,
        "session_timeout": session_timeout,
    }


# populated by main() so that --help works without a complete .env
CFG = {}


def check_response(response):
    if not response.ok:
        try:
            detail = response.json()
        except ValueError:
            detail = response.text
        sys.exit(f"API error {response.status_code} on {response.url}\n{detail}")
    return response


def api_headers(token=None, content_type=None):
    headers = {"accept": "application/json", "x-api-version": CFG["api_version"]}
    if token is not None:
        headers["Authorization"] = f"Bearer {token.access}"
    if content_type:
        headers["Content-Type"] = content_type
    return headers


class TokenStore:
    """Holds the OAuth pair.

    An access token is only valid for 15 minutes, which is shorter than a large
    repository rescan. Sessions are therefore polled with a store that renews
    itself instead of a bare token string.
    """

    def __init__(self, payload):
        self.update(payload)

    def update(self, payload):
        self.access = payload["access_token"]
        # a refresh token can be used only once, so keep the new one every time
        self.refresh = payload.get("refresh_token")
        lifetime = int(payload.get("expires_in") or 900)
        # renew a minute early so a long poll never races the expiry
        self.expires_at = time.monotonic() + max(lifetime - 60, 30)

    def expired(self):
        return time.monotonic() >= self.expires_at


def request_token(body):
    return requests.post(
        f"{CFG['endpoint']}/api/oauth2/token",
        headers=api_headers(content_type="application/x-www-form-urlencoded"),
        data=body,
        verify=CFG["verify"],
        timeout=HTTP_TIMEOUT,
    )


def password_grant():
    return {
        "grant_type": "password",
        "username": CFG["username"],
        "password": CFG["password"],
        "refresh_token": "",
        "rememberMe": "",
    }


def connect_veeam_rest_api():
    response = request_token(password_grant())
    check_response(response)
    return TokenStore(response.json())


def renew(token):
    """Trade the refresh token for a new access token, or log in again."""
    if token.refresh:
        response = request_token({
            "grant_type": "refresh_token",
            "refresh_token": token.refresh,
        })
        if response.ok:
            token.update(response.json())
            return True
    # the refresh token is single-use and may itself be spent or expired
    response = request_token(password_grant())
    if response.ok:
        token.update(response.json())
        return True
    return False


def send(method, endpoint, token, content_type=None, **kwargs):
    """Single entry point for API calls, so an expired token is renewed transparently."""
    url = f"{CFG['endpoint']}/api/{endpoint}"

    def fire():
        return requests.request(
            method, url,
            headers=api_headers(token, content_type),
            verify=CFG["verify"],
            timeout=HTTP_TIMEOUT,
            **kwargs,
        )

    if token.expired():
        renew(token)
    response = fire()
    # belt and braces: the server is the authority on whether the token is stale
    if response.status_code == 401 and renew(token):
        response = fire()
    return response


def post_veeam_rest_api(endpoint, token, body):
    response = send("POST", endpoint, token, "application/json", json=body)
    check_response(response)
    return response.json()


def get_veeam_rest_api(endpoint, token, params=None):
    response = send("GET", endpoint, token, params=params)
    check_response(response)
    return response.json()


def delete_veeam_rest_api(endpoint, token, params=None):
    return send("DELETE", endpoint, token, params=params)


def post_logout(token):
    # runs in a finally block, so it must never mask the command's own outcome
    try:
        requests.post(
            f"{CFG['endpoint']}/api/oauth2/logout",
            headers=api_headers(token),
            verify=CFG["verify"],
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException:
        pass


def confirm(prompt, assume_yes):
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        sys.exit(f"{prompt}\nRefusing to continue without --yes (no interactive terminal).")
    return input(f"{prompt} [y/N]: ").strip().lower() in ("y", "yes")


def session_id_from(payload):
    """Async endpoints answer with a SessionModel; sync ones with the entity itself."""
    if not isinstance(payload, dict):
        return None
    if payload.get("sessionType") or payload.get("state"):
        return payload.get("id")
    return None


def wait_for_session(token, session_id, timeout=None):
    """Poll a SessionModel until state is 'Stopped'. Returns False only on a hard failure."""
    timeout = timeout or CFG["session_timeout"]
    print(f"Waiting for session {session_id} to finish...", end="", flush=True)
    deadline = time.monotonic() + timeout
    last_progress = None
    while time.monotonic() < deadline:
        session = get_veeam_rest_api(f"v1/sessions/{session_id}", token)
        if session.get("state") == "Stopped":
            print()
            result = (session.get("result") or {}).get("result", "None")
            message = (session.get("result") or {}).get("message", "")
            if result == "Success":
                print("Session finished successfully.")
                return True
            # Warning means the operation completed, but with something worth reading
            print(f"Session finished with result '{result}': {message}".rstrip(": "))
            print(f"Details: GET /api/v1/sessions/{session_id}/logs")
            return result == "Warning"
        progress = session.get("progressPercent")
        if progress is not None and progress != last_progress:
            print(f" {progress}%", end="", flush=True)
            last_progress = progress
        else:
            print(".", end="", flush=True)
        time.sleep(3)
    print()
    print(f"Timed out after {timeout}s waiting for session {session_id}. "
          f"It may still be running — check: GET /api/v1/sessions/{session_id}")
    return False


def track(token, payload, started_message=None):
    """Follow the session a repo/host action returned, if it returned one."""
    session_id = session_id_from(payload)
    if not session_id:
        if started_message:
            print(started_message)
        return True
    if started_message:
        print(started_message)
    return wait_for_session(token, session_id)


def api_version_tuple(value):
    """'1.3-rev2' -> (1, 3, 2). None if the string is not in that shape."""
    match = re.fullmatch(r"(\d+)\.(\d+)(?:-rev(\d+))?", value.strip())
    if not match:
        return None
    major, minor, revision = match.groups()
    return int(major), int(minor), int(revision or 0)


def require_api_version(minimum, feature):
    """Fail early instead of letting the server reject an unknown repository type."""
    current = api_version_tuple(CFG["api_version"])
    # an unparsable version is left to the server to judge
    if current is None or current >= minimum:
        return
    wanted = f"{minimum[0]}.{minimum[1]}-rev{minimum[2]}"
    sys.exit(f"{feature} requires API revision {wanted} or newer, but VEEAM_API_VERSION "
             f"is '{CFG['api_version']}'. Update the .env entry and retry.")


def resolve_host_id(token, hostname, type_filter=None):
    params = {"nameFilter": hostname}
    if type_filter:
        params["typeFilter"] = type_filter
    data = get_veeam_rest_api("v1/backupInfrastructure/managedServers", token, params)
    for item in data.get("data", []):
        if item["name"].lower() == hostname.lower():
            return item["id"]
    raise SystemExit(f"{type_filter or 'Managed'} host '{hostname}' not found.")


def resolve_repository_id(token, repo_name):
    params = {"nameFilter": repo_name}
    data = get_veeam_rest_api("v1/backupInfrastructure/repositories", token, params)
    for repo in data.get("data", []):
        if repo["name"].lower() == repo_name.lower():
            return repo["id"]
    raise SystemExit(f"Repository '{repo_name}' not found.")


def resolve_credential_id(token, name_filter, cred_type="Linux"):
    # CredentialsModel has no "name" — the account lives in "username".
    # nameFilter matches any credentials field and needs explicit * wildcards,
    # so it is already exact here; match again locally to stay unambiguous.
    params = {"nameFilter": name_filter, "typeFilter": cred_type}
    data = get_veeam_rest_api("v1/credentials", token, params)
    items = data.get("data", [])
    wanted = name_filter.lower()
    matches = [i for i in items if str(i.get("username", "")).lower() == wanted]
    if not matches:
        matches = [i for i in items if str(i.get("description", "")).lower() == wanted]
    if len(matches) == 1:
        return matches[0]["id"]
    if len(matches) > 1:
        raise SystemExit(f"{cred_type} credential '{name_filter}' is ambiguous "
                         f"({len(matches)} matches).")
    candidates = ", ".join(str(i.get("username")) for i in items) or "none"
    raise SystemExit(f"{cred_type} credential '{name_filter}' not found. "
                     f"Candidates returned by the filter: {candidates}")


def get_ssh_fingerprint(server_name, credential_id, token):
    body = {
        "serverName": server_name,
        "credentialsStorageType": "Permanent",
        "credentialsId": credential_id,
        "type": "LinuxHost",
    }
    result = post_veeam_rest_api("v1/connectionCertificate", token, body)
    return result.get("fingerprint")


def add_host(args, token):
    if args.type == "WindowsHost":
        cred_id = resolve_credential_id(token, args.credentials_name, cred_type="Standard")
        body = {
            "type": "WindowsHost",
            "name": args.name,
            "description": args.description,
            "credentialsId": cred_id,
            "credentialsStorageType": args.credentials_storage_type,
        }
    else:
        cred_id = resolve_credential_id(token, args.credentials_name, cred_type="Linux")
        if args.fingerprint:
            fingerprint = args.fingerprint.strip()
        else:
            print(f"Getting SSH fingerprint for {args.name}...")
            fingerprint = get_ssh_fingerprint(args.name, cred_id, token)
        body = {
            "sshSettings": {
                "sshTimeOutMs": 20000,
                "portRangeStart": 2500,
                "portRangeEnd": 3300,
                "serverSide": False,
                "managementPort": 6162,
            },
            "type": "LinuxHost",
            "name": args.name,
            "description": args.description,
            "credentialsId": cred_id,
            "credentialsStorageType": args.credentials_storage_type,
            "sshFingerprint": fingerprint,
        }
    print(f"Adding {args.type} server {args.name}...")
    result = post_veeam_rest_api("v1/backupInfrastructure/managedServers", token, body)
    return track(token, result)


def handle_delete_response(token, response, done_message):
    """Repositories answer 204 (synchronous); managedServers answer 201 + SessionModel."""
    if not response.ok:
        sys.exit(f"Error while deleting: {response.status_code} {response.text}")
    if response.status_code == 204 or not response.content:
        print(done_message)
        return True
    try:
        payload = response.json()
    except ValueError:
        print(done_message)
        return True
    return track(token, payload, started_message=done_message)


def delete_host(args, token):
    host_id = resolve_host_id(token, args.name, args.type)
    if not confirm(f"Delete {args.type} '{args.name}' (ID: {host_id})?", args.yes):
        sys.exit("Aborted.")
    response = delete_veeam_rest_api(
        f"v1/backupInfrastructure/managedServers/{host_id}", token
    )
    return handle_delete_response(
        token, response, f"Deleting {args.type} '{args.name}' (ID: {host_id})..."
    )


def validate_add_args(args):
    """Type-specific argument checks, run before logging in so they fail instantly."""
    dd_only = {
        "--dd-server": args.dd_server,
        "--dd-credentials-name": args.dd_credentials_name,
        "--dd-fibre-channel": args.dd_fibre_channel,
        "--dd-boost-encryption": args.dd_boost_encryption,
        "--gateway-server": args.gateway_server,
        "--immutability-days": args.immutability_days,
    }
    if args.type != "DellDataDomain":
        if not args.host:
            sys.exit(f"--host is required for {args.type} repositories.")
        ignored = [name for name, value in dd_only.items() if value]
        if ignored:
            print(f"Note: DellDataDomain-only options ignored for {args.type}: "
                  f"{', '.join(ignored)}.")
        if args.fast_clone and args.type == "WinLocal":
            print("Note: --fast-clone is ignored for WinLocal repositories.")
        return

    require_api_version(DELL_DATA_DOMAIN_MIN_API, "Adding a DellDataDomain repository")
    # --host stays accepted so the three repository types can be scripted uniformly
    args.dd_server = args.dd_server or args.host
    if not args.dd_server:
        sys.exit("--dd-server (the Dell Data Domain server name) is required "
                 "for DellDataDomain repositories.")
    if not args.dd_credentials_name:
        sys.exit("--dd-credentials-name is required for DellDataDomain repositories.")
    if args.fast_clone:
        print("Note: --fast-clone is ignored for DellDataDomain repositories.")


def advanced_repository_settings():
    return {
        "RotatedDriveCleanupMode": "Disabled",
        "alignDataBlocks": True,
        "decompressBeforeStoring": True,
        "rotatedDrives": False,
        "perVmBackup": True,
    }


def build_mount_server(args, token):
    """MountServersSettingsModel — settings nested per mount server OS (API 1.3-rev1)."""
    mount_type = args.mount_server_type
    mount_host_filter = "WindowsHost" if mount_type == "Windows" else "LinuxHost"
    mount_host_id = resolve_host_id(token, args.mount_server, mount_host_filter)
    write_cache = args.write_cache_folder or (
        "C:\\ProgramData\\Veeam\\Backup\\IRCache\\" if mount_type == "Windows"
        else "/tmp/VeeamBackup/"
    )
    return {
        "mountServerSettingsType": mount_type,
        mount_type.lower(): {
            "mountServerId": mount_host_id,
            "writeCacheFolder": write_cache,
            "vPowerNFSEnabled": True,
            "vPowerNFSPortSettings": {"mountPort": 1058, "vPowerNFSPort": 2049},
        },
    }


def build_local_repository_body(args, token, mount_server):
    """WinLocal / LinuxLocal: the repository lives on a managed server."""
    host_filter = "WindowsHost" if args.type == "WinLocal" else "LinuxHost"
    host_id = resolve_host_id(token, args.host, host_filter)
    repository = {
        "path": args.path,
        "taskLimitEnabled": True,
        "maxTaskCount": args.task_count,
        # throttling stays off unless a rate is passed explicitly
        "readWriteLimitEnabled": args.read_write_rate is not None,
        "advancedSettings": advanced_repository_settings(),
    }
    if args.read_write_rate is not None:
        repository["readWriteRate"] = args.read_write_rate
    if args.type == "LinuxLocal":
        # XFS fast cloning only applies to Linux-hosted repositories
        repository["useFastCloningOnXFSVolumes"] = args.fast_clone

    return {
        "hostId": host_id,
        "repository": repository,
        "mountServer": mount_server,
        "type": args.type,
        "name": args.name,
        "description": args.description,
    }


def build_dell_data_domain_body(args, token, mount_server):
    """DellDataDomain (API 1.3-rev2): no hostId — VBR talks to the appliance itself."""
    # DD Boost logins are user/password, so they are Standard credentials, not Linux
    cred_id = resolve_credential_id(token, args.dd_credentials_name, cred_type="Standard")
    storage = {
        # the schema spells the property 'ddServername' (lowercase n) — the entry in
        # its own "required" list is a copy-paste typo, the property name is what counts
        "ddServername": args.dd_server,
        "credentialsId": cred_id,
        "useFCConnectivity": args.dd_fibre_channel,
        "ddBoostEncryptionEnabled": args.dd_boost_encryption is not None,
    }
    if args.dd_boost_encryption:
        storage["ddBoostEncryptionType"] = args.dd_boost_encryption
    if args.gateway_server:
        storage["gatewayServer"] = {
            "autoSelection": False,
            "gatewayServerIds": [resolve_host_id(token, name)
                                 for name in args.gateway_server],
        }
    else:
        storage["gatewayServer"] = {"autoSelection": True}

    # deduplication appliances use their own field names for the two limits
    repository = {
        "path": args.path,
        "enableTaskLimit": True,
        "maxTaskCount": args.task_count,
        "enableReadWriteLimit": args.read_write_rate is not None,
        "advancedSettings": advanced_repository_settings(),
    }
    if args.read_write_rate is not None:
        repository["readWriteRate"] = args.read_write_rate
    if args.immutability_days is not None:
        # DD Retention Lock, which has to be licensed and enabled on the appliance
        repository["immutability"] = {
            "isEnabled": True,
            "daysCount": args.immutability_days,
        }

    return {
        "dellDataDomain": storage,
        "repository": repository,
        # plural here, unlike the local types — see MountServersSettingsModel usage
        "mountServers": mount_server,
        "type": args.type,
        "name": args.name,
        "description": args.description,
    }


def add_repository(args, token):
    mount_server = build_mount_server(args, token)
    if args.type == "DellDataDomain":
        body = build_dell_data_domain_body(args, token, mount_server)
    else:
        body = build_local_repository_body(args, token, mount_server)
    result = post_veeam_rest_api("v1/backupInfrastructure/repositories", token, body)
    return track(token, result, started_message=f"Creating repository '{args.name}'...")


def rescan_repository(args, token):
    repo_id = resolve_repository_id(token, args.repo_name)
    body = {"repositoryIds": [repo_id]}
    result = post_veeam_rest_api("v1/backupInfrastructure/repositories/rescan", token, body)
    return track(
        token, result,
        started_message=f"Repository '{args.repo_name}' (ID: {repo_id}) rescan started.",
    )


def delete_repository(args, token):
    repo_id = resolve_repository_id(token, args.repo_name)
    suffix = " AND ALL ITS BACKUPS" if args.delete_backups else ""
    if not confirm(f"Delete repository '{args.repo_name}' (ID: {repo_id}){suffix}?", args.yes):
        sys.exit("Aborted.")
    params = {"deleteBackups": "true" if args.delete_backups else "false"}
    response = delete_veeam_rest_api(
        f"v1/backupInfrastructure/repositories/{repo_id}", token, params
    )
    return handle_delete_response(
        token, response,
        f"Deleting repository '{args.repo_name}' (ID: {repo_id}){suffix.lower()}...",
    )


def main():
    parser = argparse.ArgumentParser(description="Veeam Repository Manager")
    subparsers = parser.add_subparsers(dest="command", required=True)

    add_host_parser = subparsers.add_parser("add-host", help="Add a Linux or Windows host")
    add_host_parser.add_argument("--name", required=True)
    add_host_parser.add_argument("--type", choices=["LinuxHost", "WindowsHost"],
                                 default="LinuxHost")
    add_host_parser.add_argument("--credentials-name", required=True)
    add_host_parser.add_argument("--description", default="Backup Repository")
    add_host_parser.add_argument("--credentials-storage-type",
                                 choices=["Permanent", "SingleUse", "Certificate"],
                                 default="Permanent")
    add_host_parser.add_argument("--fingerprint",
                                 help="SSH fingerprint (Linux only, optional)")

    add_repo = subparsers.add_parser("add", help="Add repository")
    add_repo.add_argument("--host",
                          help="Storage host: Linux host for LinuxLocal, Windows host for "
                               "WinLocal. Also accepted as the DD server name.")
    add_repo.add_argument("--type", choices=["LinuxLocal", "WinLocal", "DellDataDomain"],
                          default="LinuxLocal")
    add_repo.add_argument("--mount-server", required=True)
    add_repo.add_argument("--mount-server-type", choices=["Windows", "Linux"],
                          default="Windows")
    add_repo.add_argument("--path", required=True)
    add_repo.add_argument("--name", required=True)
    add_repo.add_argument("--description", default="")
    add_repo.add_argument("--task-count", type=int, default=4)
    add_repo.add_argument("--read-write-rate", type=int, default=None,
                          help="Read/write throttling, MB/s as in the UI (default: no limit)")
    add_repo.add_argument("--fast-clone", action="store_true",
                          help="Enable fast cloning on XFS volumes (LinuxLocal only)")
    add_repo.add_argument("--write-cache-folder", default=None,
                          help="Defaults to the vPower cache path matching --mount-server-type")
    add_repo.add_argument("--dd-server", metavar="NAME",
                          help="Dell Data Domain server name, the 'ddServername' field "
                               "(DellDataDomain only, required; --host is accepted instead)")
    add_repo.add_argument("--dd-credentials-name",
                          help="Standard credentials for the DD Boost user "
                               "(DellDataDomain only, required)")
    add_repo.add_argument("--dd-fibre-channel", action="store_true",
                          help="Connect over Fibre Channel instead of IP (DellDataDomain only)")
    add_repo.add_argument("--dd-boost-encryption", choices=["Medium", "High"], default=None,
                          help="Enable DD Boost in-flight encryption (DellDataDomain only)")
    add_repo.add_argument("--gateway-server", action="append", default=None, metavar="NAME",
                          help="Gateway server, repeatable (DellDataDomain only, "
                               "default: automatic selection)")
    add_repo.add_argument("--immutability-days", type=int, default=None,
                          help="Enable DD Retention Lock for this many days "
                               "(DellDataDomain only, default: off)")

    rescan = subparsers.add_parser("rescan", help="Rescan repository")
    rescan.add_argument("--repo-name", required=True)

    delete = subparsers.add_parser("delete", help="Delete repository")
    delete.add_argument("--repo-name", required=True)
    delete.add_argument("--delete-backups", action="store_true",
                        help="Also delete all backups in the repository")
    delete.add_argument("--yes", action="store_true",
                        help="Skip the confirmation prompt")

    delete_host_parser = subparsers.add_parser("delete-host", help="Delete a Linux or Windows host")
    delete_host_parser.add_argument("--name", required=True)
    delete_host_parser.add_argument("--type", choices=["LinuxHost", "WindowsHost"],
                                    default="LinuxHost")
    delete_host_parser.add_argument("--yes", action="store_true",
                                    help="Skip the confirmation prompt")

    args = parser.parse_args()

    CFG.update(load_config())
    if args.command == "add":
        validate_add_args(args)

    token = connect_veeam_rest_api()
    try:
        commands = {
            "add-host": add_host,
            "add": add_repository,
            "rescan": rescan_repository,
            "delete": delete_repository,
            "delete-host": delete_host,
        }
        succeeded = commands[args.command](args, token)
    finally:
        post_logout(token)
    return 0 if succeeded else 1


if __name__ == "__main__":
    sys.exit(main())
