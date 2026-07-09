#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from urllib.parse import urljoin

import requests
import urllib3

SPEC_URL_PATTERN = re.compile(r'["\']url["\']\s*:\s*["\']([^"\']+)["\']')
SCRIPT_SRC_PATTERN = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']')


def discover_spec_url(session: requests.Session, base_url: str, timeout: float) -> str:
    index_url = f"{base_url}/swagger/index.html"
    index_resp = session.get(index_url, timeout=timeout)
    index_resp.raise_for_status()
    html = index_resp.text

    candidates = []
    for match in SPEC_URL_PATTERN.finditer(html):
        candidates.append(match.group(1))

    if not candidates:
        for src in SCRIPT_SRC_PATTERN.findall(html):
            script_url = urljoin(index_url, src)
            script_resp = session.get(script_url, timeout=timeout)
            if script_resp.ok:
                candidates.extend(SPEC_URL_PATTERN.findall(script_resp.text))

    candidates = [c for c in candidates if "swagger.json" in c or "openapi.json" in c]
    if not candidates:
        raise RuntimeError(f"Could not find a spec URL referenced in {index_url}")

    return urljoin(index_url, candidates[0])


def get_api_version(host: str, port: int, insecure: bool, timeout: float, spec_url: str | None) -> dict:
    base_url = f"https://{host}:{port}"

    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()
    session.verify = not insecure

    resolved_spec_url = spec_url or discover_spec_url(session, base_url, timeout)

    response = session.get(resolved_spec_url, timeout=timeout)
    response.raise_for_status()

    info = response.json().get("info", {})
    return {
        "spec_url": resolved_spec_url,
        "title": info.get("title"),
        "version": info.get("version"),
        "prev_version": info.get("x-veeam-prev-version"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch the REST API version from a Veeam Backup & Replication server's swagger/OpenAPI spec")
    parser.add_argument("host", help="Hostname or IP of the VBR server")
    parser.add_argument("--port", type=int, default=9419, help="REST API port (default: 9419)")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification (self-signed cert)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Timeout in seconds (default: 10)")
    parser.add_argument("--spec-url", help="Skip discovery and fetch this spec URL directly")
    args = parser.parse_args()

    try:
        result = get_api_version(args.host, args.port, args.insecure, args.timeout, args.spec_url)
    except (requests.exceptions.RequestException, RuntimeError) as exc:
        print(f"Failed to determine API version: {exc}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
