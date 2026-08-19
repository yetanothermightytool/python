#!/usr/bin/env python3
"""Veeam B&R Data Integration API: publish restore point disks as an iSCSI
target on a mount server. The mount server is given by hostname, its
mountHostId is resolved via the REST API.

API 1.3-rev2 - POST /api/v1/dataIntegration/publish
"""

import argparse
import json
import os
import sys
import time
import urllib.parse
from pathlib import Path

import requests
import urllib3

def load_dotenv(path: Path) -> None:
    """Read a simple .env file (KEY=VALUE, # comment)."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        # existing environment variables win
        os.environ.setdefault(key, value)


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "y", "on", "ja")


class VeeamError(RuntimeError):
    pass


class VbrClient:
    def __init__(self, host, port, username, password, api_version, verify_ssl):
        self.base_url = f"https://{host}:{port}"
        self.username = username
        self.password = password
        self.api_version = api_version
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self._token = None
        self._refresh_token = None
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _headers(self, extra=None):
        headers = {
            "x-api-version": self.api_version,
            "Accept": "application/json",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        if extra:
            headers.update(extra)
        return headers

    def _request(self, method, path, **kwargs):
        url = self.base_url + path
        headers = self._headers(kwargs.pop("headers", None))
        try:
            response = self.session.request(
                method, url, headers=headers, timeout=kwargs.pop("timeout", 120), **kwargs
            )
        except requests.exceptions.RequestException as exc:
            raise VeeamError(f"Verbindung zu {url} fehlgeschlagen: {exc}") from exc

        if response.status_code >= 400:
            detail = response.text
            try:
                payload = response.json()
                detail = payload.get("message") or payload.get("errors") or payload
                detail = json.dumps(detail, ensure_ascii=False)
            except ValueError:
                pass
            raise VeeamError(
                f"{method} {path} -> HTTP {response.status_code}: {detail}"
            )

        if not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            return response.text

    def get(self, path, params=None):
        if params:
            query = urllib.parse.urlencode(
                {k: v for k, v in params.items() if v is not None}, doseq=True
            )
            path = f"{path}?{query}"
        return self._request("GET", path)

    def post(self, path, json_body=None):
        return self._request("POST", path, json=json_body)

    def login(self):
        data = {
            "grant_type": "password",
            "username": self.username,
            "password": self.password,
        }
        result = self._request(
            "POST",
            "/api/oauth2/token",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self._token = result.get("access_token")
        self._refresh_token = result.get("refresh_token")
        if not self._token:
            raise VeeamError("Kein access_token erhalten.")
        return result

    def logout(self):
        if not self._token:
            return
        try:
            self._request("POST", "/api/oauth2/logout")
        except VeeamError:
            pass
        finally:
            self._token = None


def get_mount_servers(client):
    """Servers holding the mount server role, including their names.

    /backupInfrastructure/mountServers returns IDs only; the ID equals the
    managed server ID, so names come from /backupInfrastructure/managedServers.
    """
    mount_servers = client.get(
        "/api/v1/backupInfrastructure/mountServers", {"limit": 1000}
    ).get("data", [])

    managed = client.get(
        "/api/v1/backupInfrastructure/managedServers",
        {"limit": 1000, "includeNestedHosts": "true"},
    ).get("data", [])
    managed_by_id = {m["id"]: m for m in managed}

    result = []
    for ms in mount_servers:
        host = managed_by_id.get(ms["id"], {})
        result.append(
            {
                "id": ms["id"],
                "name": host.get("name", "<unbekannt>"),
                "description": host.get("description", ""),
                "hostType": host.get("type", ""),
                "osType": ms.get("type", ""),
                "isDefault": ms.get("isDefault", False),
                "writeCacheFolder": (ms.get("settings") or {}).get("writeCacheFolder", ""),
            }
        )
    return result


def resolve_mount_host_id(client, hostname):
    """Resolve mountHostId from the mount server hostname."""
    servers = get_mount_servers(client)
    wanted = hostname.strip().lower()

    # exact full name
    exact = [s for s in servers if s["name"].lower() == wanted]
    if len(exact) == 1:
        return exact[0]

    # short name vs. FQDN (winsrv01 == winsrv01.contoso.local)
    short = [
        s
        for s in servers
        if s["name"].lower().split(".")[0] == wanted.split(".")[0]
    ]
    if len(short) == 1:
        return short[0]

    # substring
    partial = [s for s in servers if wanted in s["name"].lower()]
    if len(partial) == 1:
        return partial[0]

    candidates = exact or short or partial
    if len(candidates) > 1:
        names = ", ".join(f"{s['name']} ({s['id']})" for s in candidates)
        raise VeeamError(
            f"Mount Server '{hostname}' ist nicht eindeutig. Treffer: {names}"
        )

    available = ", ".join(s["name"] for s in servers) or "<keine>"
    raise VeeamError(
        f"Mount Server '{hostname}' wurde nicht gefunden. "
        f"Verfuegbare Mount Server: {available}"
    )


def find_latest_restore_point(client, object_name):
    """Latest restore point of a backup object (e.g. a Windows server)."""
    objects = client.get(
        "/api/v1/backupObjects", {"nameFilter": object_name, "limit": 100}
    ).get("data", [])

    if not objects:
        raise VeeamError(f"Kein Backup-Objekt gefunden fuer '{object_name}'.")

    exact = [o for o in objects if (o.get("name") or "").lower() == object_name.lower()]
    if len(exact) == 1:
        backup_object = exact[0]
    elif len(objects) == 1:
        backup_object = objects[0]
    else:
        names = ", ".join(f"{o.get('name')} ({o['id']})" for o in objects)
        raise VeeamError(
            f"Backup-Objekt '{object_name}' ist nicht eindeutig. Treffer: {names}"
        )

    points = client.get(
        f"/api/v1/backupObjects/{backup_object['id']}/restorePoints",
        {"limit": 1, "orderColumn": "CreationTime", "orderAsc": "false"},
    ).get("data", [])

    if not points:
        raise VeeamError(
            f"Backup-Objekt '{backup_object.get('name')}' hat keine Restore Points."
        )

    point = points[0]
    point["_objectName"] = backup_object.get("name")
    return point


def list_restore_points(client, object_name, limit):
    points = client.get(
        "/api/v1/restorePoints",
        {
            "nameFilter": object_name,
            "limit": limit,
            "orderColumn": "CreationTime",
            "orderAsc": "false",
        },
    ).get("data", [])
    return points


def publish_disks(client, restore_point_id, mount_host_id, allowed_ips, reason, disk_names):
    """POST /api/v1/dataIntegration/publish in ISCSITarget mode."""
    spec = {
        "restorePointId": restore_point_id,
        "type": "ISCSITarget",
        "allowedIps": allowed_ips,
        "mountHostId": mount_host_id,
    }
    if reason:
        spec["reason"] = reason
    if disk_names:
        spec["diskNames"] = disk_names
    return client.post("/api/v1/dataIntegration/publish", spec)


def wait_for_session(client, session_id, timeout, interval=5):
    """Poll the session until its state is 'Stopped'."""
    deadline = time.time() + timeout
    last_state = None
    while time.time() < deadline:
        session = client.get(f"/api/v1/sessions/{session_id}")
        state = session.get("state")
        if state != last_state:
            print(f"  Session-Status: {state} ({session.get('progressPercent', 0)}%)")
            last_state = state
        if state == "Stopped":
            return session
        time.sleep(interval)
    raise VeeamError(
        f"Timeout: Session {session_id} wurde innerhalb von {timeout}s nicht beendet."
    )


def find_mount(client, session, restore_point_id):
    """Look up the mount object holding the iSCSI target details."""
    candidates = [session.get("resourceId"), session.get("id")]
    for mount_id in [c for c in candidates if c]:
        try:
            return client.get(f"/api/v1/dataIntegration/{mount_id}")
        except VeeamError:
            continue

    mounts = client.get("/api/v1/dataIntegration", {"limit": 500}).get("data", [])
    for mount in mounts:
        if mount.get("restorePointId") == restore_point_id:
            return mount
    return None


def unpublish(client, mount_id):
    return client.post(f"/api/v1/dataIntegration/{mount_id}/unpublish")


def print_mount_details(mount):
    info = mount.get("info") or {}
    print("")
    print("=" * 72)
    print("Disk Publish erfolgreich")
    print("=" * 72)
    print(f"  Mount ID          : {mount.get('id')}")
    print(f"  Mount State       : {mount.get('mountState')}")
    print(f"  Backup            : {mount.get('backupName')}")
    print(f"  Restore Point     : {mount.get('restorePointName')} ({mount.get('restorePointId')})")
    print(f"  Modus             : {info.get('mode')}")
    print(f"  iSCSI Target IP(s): {', '.join(info.get('serverIps') or []) or '-'}")
    print(f"  iSCSI Port        : {info.get('serverPort')}")
    print("")
    print("  Publizierte Disks:")
    for disk in info.get("disks") or []:
        print(f"    - {disk.get('diskName')}")
        if disk.get("accessLink"):
            print(f"      IQN / Access Link : {disk.get('accessLink')}")
        for mount_point in disk.get("mountPoints") or []:
            print(f"      Mount Point       : {mount_point}")
    print("")
    print("  Auf dem Windows-Zielhost verbinden (Beispiel):")
    for ip in info.get("serverIps") or []:
        print(f"    iscsicli QAddTargetPortal {ip}")
    print("    iscsicli ListTargets")
    print("")
    print("  Wieder aushaengen:")
    print(f"    {Path(sys.argv[0]).name} --unpublish {mount.get('id')}")
    print("=" * 72)


def build_parser():
    parser = argparse.ArgumentParser(
        description=(
            "Veeam VBR Data Integration API: Windows-Backup Disks per iSCSI "
            "publizieren. Verbindungsdaten kommen aus dem .env File."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Beispiele:\n"
            "  %(prog)s --mount-server mountsrv01 --object FILESRV01\n"
            "  %(prog)s --mount-server mountsrv01.contoso.local "
            "--restore-point 58d8ce8c-2e04-47c7-8f11-a17875b1eed3\n"
            "  %(prog)s --list-mount-servers\n"
            "  %(prog)s --list-restore-points FILESRV01\n"
            "  %(prog)s --list-mounts\n"
            "  %(prog)s --unpublish bce89e03-9269-4cb0-aa49-c8b04d4273d5\n"
        ),
    )
    parser.add_argument(
        "--mount-server",
        "-m",
        help="Hostname/FQDN des Mount Servers. Die mountHostId wird daraus ermittelt.",
    )
    parser.add_argument(
        "--object",
        "-o",
        help="Name des Backup-Objekts (Windows Server/VM). Es wird der neueste Restore Point verwendet.",
    )
    parser.add_argument(
        "--restore-point",
        "-r",
        help="Restore Point ID (alternativ zu --object).",
    )
    parser.add_argument(
        "--allowed-ips",
        action="append",
        help=(
            "IP-Adresse, die auf das iSCSI Target zugreifen darf. Mehrfach "
            "verwendbar oder als Komma-Liste. Default: ALLOWED_IPS aus dem .env."
        ),
    )
    parser.add_argument(
        "--disk",
        action="append",
        dest="disks",
        help="Nur diese Disk publizieren (mehrfach verwendbar). Default: alle Disks.",
    )
    parser.add_argument("--reason", help="Begruendung fuer die History.")
    parser.add_argument(
        "--timeout",
        type=int,
        default=900,
        help="Maximale Wartezeit auf die Publish-Session in Sekunden (Default: 900).",
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Nicht auf das Ende der Session warten, nur Session-ID ausgeben.",
    )
    parser.add_argument(
        "--env-file",
        default=str(Path(__file__).with_name(".env")),
        help="Pfad zum .env File (Default: .env neben dem Script).",
    )
    parser.add_argument("--json", action="store_true", help="Ergebnis als JSON ausgeben.")

    parser.add_argument(
        "--list-mount-servers", action="store_true", help="Verfuegbare Mount Server auflisten."
    )
    parser.add_argument(
        "--list-restore-points",
        metavar="OBJEKTNAME",
        help="Restore Points eines Backup-Objekts auflisten.",
    )
    parser.add_argument(
        "--list-mounts", action="store_true", help="Aktuell publizierte Disks auflisten."
    )
    parser.add_argument(
        "--unpublish", metavar="MOUNT_ID", help="Publizierte Disks wieder aushaengen."
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    load_dotenv(Path(args.env_file))

    host = os.environ.get("VBR_HOST")
    port = os.environ.get("VBR_PORT", "9419")
    user = os.environ.get("VBR_USER")
    password = os.environ.get("VBR_PASSWORD")
    api_version = os.environ.get("VBR_API_VERSION", "1.3-rev2")
    # self-signed certificates are ignored by default
    verify_ssl = not env_bool("VBR_SKIP_SSL_VERIFY", True)

    missing = [
        name
        for name, value in (
            ("VBR_HOST", host),
            ("VBR_USER", user),
            ("VBR_PASSWORD", password),
        )
        if not value
    ]
    if missing:
        parser.error(
            f"Fehlende Werte im .env File ({args.env_file}): {', '.join(missing)}"
        )

    mount_server = args.mount_server or os.environ.get("MOUNT_SERVER") or None
    allowed_ips_raw = args.allowed_ips or [os.environ.get("ALLOWED_IPS", "")]
    allowed_ips = [
        ip.strip()
        for entry in allowed_ips_raw
        for ip in entry.split(",")
        if ip.strip()
    ]
    reason = args.reason or os.environ.get("PUBLISH_REASON") or None

    client = VbrClient(host, port, user, password, api_version, verify_ssl)

    try:
        print(f"[1] Anmeldung an https://{host}:{port} (API {api_version}) ...")
        client.login()
        print("    Anmeldung erfolgreich.")

        # info-only modes
        if args.list_mount_servers:
            servers = get_mount_servers(client)
            if args.json:
                print(json.dumps(servers, indent=2, ensure_ascii=False))
            else:
                print("\nMount Server:")
                for s in servers:
                    default = " [default]" if s["isDefault"] else ""
                    print(f"  {s['name']}{default}")
                    print(f"    ID       : {s['id']}   <- mountHostId")
                    print(f"    OS/Typ   : {s['osType']} / {s['hostType']}")
                    print(f"    Cache    : {s['writeCacheFolder']}")
            return 0

        if args.list_restore_points:
            points = list_restore_points(client, args.list_restore_points, 50)
            if args.json:
                print(json.dumps(points, indent=2, ensure_ascii=False))
            else:
                print(f"\nRestore Points fuer '{args.list_restore_points}':")
                for p in points:
                    print(
                        f"  {p.get('creationTime')}  {p.get('name')}  "
                        f"[{p.get('type')}]  {p.get('id')}"
                    )
            return 0

        if args.list_mounts:
            mounts = client.get("/api/v1/dataIntegration", {"limit": 500}).get("data", [])
            if args.json:
                print(json.dumps(mounts, indent=2, ensure_ascii=False))
            else:
                print("\nPublizierte Disks:")
                for m in mounts:
                    info = m.get("info") or {}
                    print(
                        f"  {m.get('id')}  {m.get('mountState')}  "
                        f"{m.get('restorePointName')}  "
                        f"IP(s): {', '.join(info.get('serverIps') or []) or '-'}"
                    )
            return 0

        if args.unpublish:
            print(f"[2] Unpublish von Mount {args.unpublish} ...")
            session = unpublish(client, args.unpublish)
            session_id = (session or {}).get("id")
            if session_id and not args.no_wait:
                session = wait_for_session(client, session_id, args.timeout)
            result = ((session or {}).get("result") or {}).get("result")
            print(f"    Unpublish abgeschlossen (Ergebnis: {result}).")
            return 0

        # publish
        if not mount_server:
            parser.error(
                "Mount Server fehlt: --mount-server <hostname> angeben "
                "(oder MOUNT_SERVER im .env setzen)."
            )
        if not args.restore_point and not args.object:
            parser.error("Entweder --restore-point <id> oder --object <name> angeben.")
        if not allowed_ips:
            parser.error(
                "Keine erlaubten IPs: --allowed-ips <ip>[,<ip>] angeben "
                "(oder ALLOWED_IPS im .env setzen)."
            )

        print(f"[2] Mount Server '{mount_server}' aufloesen ...")
        mount_srv = resolve_mount_host_id(client, mount_server)
        print(f"    {mount_srv['name']} -> mountHostId {mount_srv['id']} ({mount_srv['osType']})")

        if args.restore_point:
            restore_point_id = args.restore_point
            print(f"[3] Restore Point: {restore_point_id}")
        else:
            print(f"[3] Neuesten Restore Point fuer '{args.object}' suchen ...")
            point = find_latest_restore_point(client, args.object)
            restore_point_id = point["id"]
            print(
                f"    {point.get('_objectName')} / {point.get('creationTime')} "
                f"-> {restore_point_id}"
            )

        print(
            f"[4] Disk Publish starten (ISCSITarget, allowedIps={', '.join(allowed_ips)}) ..."
        )
        session = publish_disks(
            client, restore_point_id, mount_srv["id"], allowed_ips, reason, args.disks
        )
        session_id = session.get("id")
        print(f"    Session gestartet: {session_id}")

        if args.no_wait:
            if args.json:
                print(json.dumps(session, indent=2, ensure_ascii=False))
            return 0

        print("[5] Auf Abschluss der Session warten ...")
        session = wait_for_session(client, session_id, args.timeout)
        result = (session.get("result") or {}).get("result")
        message = (session.get("result") or {}).get("message")
        if result == "Failed":
            raise VeeamError(f"Publish fehlgeschlagen: {message}")

        mount = find_mount(client, session, restore_point_id)
        if mount is None:
            raise VeeamError(
                "Session beendet, aber der Mount konnte nicht ermittelt werden."
            )

        if args.json:
            print(json.dumps(mount, indent=2, ensure_ascii=False))
        else:
            print_mount_details(mount)
        return 0

    except VeeamError as exc:
        print(f"\nFEHLER: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nAbgebrochen.", file=sys.stderr)
        return 130
    finally:
        client.logout()


if __name__ == "__main__":
    sys.exit(main())
