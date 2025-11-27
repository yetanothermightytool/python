# Veeam NAS Instant Recovery – AV Scan

## Overview

This Python script uses the Veeam Backup & Replication REST API to locate NAS restore points, start an Instant File Share Recovery session, mount the recovered SMB share or NFS Export on Linux, run one or more malware scanners defined in a scan-engines.json configuration file (currently ClamAV, THOR and YARA), and finally unmount the share and stop the recovery session. It supports both interactive and non-interactive execution modes.

## Prerequisites

### Python Environment

Install required Python modules:

```bash
sudo apt install python3 python3-pip python3-dateutil
pip install cryptography requests
```

### Encrypted Password Storage (Fernet)

Run the password setup script to generate the necessary files. Files must be stored in the same directory as the Python script.

```bash
./create-fernet-files.py
```

## Scan Engines
The script utilizes the scan configuration specified in the scan-engines.json file. Currently, ClamAV and the Thor Scanner are included.

### Install ClamAV

```bash
sudo apt install clamav clamav-daemon
sudo freshclam
```
The scan-engines.json expects the ClamAV scanner at /usr/bin/clamscan.

## Script Parameters

**--vbrserver**

Hostname or IP of the Veeam Backup & Replication server. (Required)

**--sharename**

Search pattern for the NAS share/NFS Export name inside restore points. (Required)

**--mounthost**

Windows mount host where the Instant Recovery share is presented. (Required)

**--username**

REST API username (default: Administrator). Also used as default SMB username.

**–-smb-user**

Override SMB username.
Password is read from encrypted_smb_password.bin.

**–-timeout**

Seconds to wait for manual restore point selection.
Default: 30

**–-wait**

Seconds to wait before attempting to mount the recovered SMB share.
Default: 60

**-–mount-base**

Local base directory for SMB mounts. Default /mnt

**–noninteractive**

Automatically select the latest restore point.

## Usage Examples

Interactive mode (manual restore point selection)
```bash
sudo ./nas-av-scan.py --vbrserver vbr01.example.com --sharename data --mounthost win-mount01
```
Non-interactive mode (always use latest restore point)

```bash
sudo ./nas-av-scan.py --vbrserver vbr01.example.com --sharename data --mounthost win-mount01 --noninteractive
```

### Output Format

ClamAV detections appear as "🐞 /mnt/win-ir01_backup/file.exe: Eicar-Test-Signature FOUND"

If nothing is detected "No detections found by ClamAV (no lines ending with 'FOUND')."


## Notes
- Requires Python 3 and modules: requests, cryptography, dateutil
- Requires a supported scan engine installed and updated
- Compatible with Veeam REST API version 1.3-rev1
- Supports NAS restore points (platformName = UnstructuredData)

**Please note this script is unofficial and is not created nor supported by Veeam Software.**

## Version Information
~~~~
Version: 1.2 (November 27 2025)
Author: Steve Herzig
~~~~

## Version History
- 1.2
  - YARA scan. Rule must reside in the defined directory in scan-engines.json
  - Scanning protected NFS exports. Instant File Share Recovery uses SMB to present the data.
- 1.1
  - Using the scan-engines.json file to define which engine(s) to be used.
- 1.0
  - Initial release
