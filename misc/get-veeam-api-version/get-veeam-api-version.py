#!/usr/bin/env python3
import argparse
import json
import sys

import requests
import urllib3


def get_api_version(host: str, port: int, insecure: bool, timeout: float) -> dict:
    url = f"https://{host}:{port}/swagger/v1/swagger.json"

    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    response = requests.get(url, verify=not insecure, timeout=timeout)
    response.raise_for_status()

    info = response.json().get("info", {})
    return {
        "url": url,
        "title": info.get("title"),
        "version": info.get("version"),
        "prev_version": info.get("x-veeam-prev-version"),
    }

def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch the REST API version from a Veeam Backup & Replication server's swagger.json")
    parser.add_argument("host", help="Hostname or IP of the VBR server")
    parser.add_argument("--port", type=int, default=9419, help="REST API port (default: 9419)")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification (self-signed cert)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Timeout in seconds (default: 10)")
    args = parser.parse_args()

    try:
        result = get_api_version(args.host, args.port, args.insecure, args.timeout)
    except requests.exceptions.RequestException as exc:
        print(f"Failed to fetch swagger.json: {exc}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

