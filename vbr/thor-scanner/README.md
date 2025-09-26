# Veeam Restore Point Scanner with THOR

## Version Information
~~~~
Version: 1.0 (September 26, 2025)
Requires: Veeam Backup & Replication v12.3.2 & Linux & Python 3.1+
Author: Stephan "Steve" Herzig
~~~~
## Script
This script publishes a restore point using the **Veeam Data Integration API**, and runs a [THOR](https://www.nextron-systems.com/thor/) (or THOR Lite) scan against the mounted restore point.

## Requirements
- Linux host with Python 3.x 
- Python modules: `cryptography`, `requests`
- Veeam Backup & Replication server
- Docker installed and Docker image created on the scan host

### Credentials
Save the keyfiles for the REST API user to be used with this [script.](https://github.com/yetanothermightytool/python/tree/main/misc/fernet). The username Administrator is stored as the default user in the Python script.

### Important
Username & Veeam Backup & Replication Server
 Set the Veeam Backup & Replication hostname/IP address and username to query the REST API'.
 ```python
username        = "Administrator"
api_url         = "https://vbr-host:9419"
```

The script can run **with THOR or THOR Lite**. Set the correct container image name in the script.
 ```python
 docker_image = "thor-lite"   # or "thor"
```

### Build the Docker image before running the script
The Dockerfile and the Python script must be placed in the same folder as your THOR files (binaries, licenssignatures, etc.
Build the THOR (or THOR Lite) Docker image before running the script. Sample for thor-lite (Adjust the path in the Dockerfile if necessary).
```bash
docker build -t thor-lite .
```

## Script Usage
Make the script executable and run it directly.

chmod +x script.py
./thor-scanner.py -host2scan <HOSTNAME> [--latest]

Parameters
- `--host2scan <HOSTNAME>`
The hostname for which the latest backup (restore points) should be scanned.

- `--latest`
Optional flag. If set, the script automatically uses the newest restore point without showing a menu or waiting for user input.
Useful for automation (e.g. cron jobs).

Examples

Interactive mode (choose restore point manually):
'''bash
./thor-scanner.py -host2scan Server01
'''

Automated mode (always the latest restore point):
'''bash
./thor-scanner.py -host2scan Server01 --latest
'''

## Notes
- Scan results are written to /tmp/output.
- Tested on Ubuntu 24.04
- Why Docker! Because I want! ## The scan runs inside a container for better control and isolation. This way multiple jobs can run in parallel without interfering with each other or the host system.

## Who is Nextron and what is THOR?
Nextron Systems specializes in forensic threat detection. Their product, THOR, is widely used by incident response and security teams to uncover attacker tools and traces that traditional solutions may miss. 
Unlike classic antivirus integrations, THOR is designed to detect webshells, obfuscated scripts, malicious configurations, and backdoors, the kinds of artefacts that advanced attackers often leave behind. In addition, THOR parses system artefacts such as Windows Registry hives or Event Logs with dedicated modules, applying forensic rules that go far beyond a simple file-level scan. 
This makes THOR an effective complement to existing AV solutions within the Veeam ecosystem.

## Version History
- 1.0 (Sep 26 2025)
  - Initial version
    
## Disclaimer

This script is not officially supported by Veeam Software. Use it at your own risk.
