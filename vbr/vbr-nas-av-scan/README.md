# Veeam NAS Instant Recovery – Linux ClamAV Scan

## Overview

This Python script uses the Veeam Backup & Replication REST API to:

- Find NAS backup restore points
- Start an Instant File Share Recovery session
- Mount the recovered SMB share on a Linux machine
- Scan the data with ClamAV
- And automatically unmount and stop the recovery session.

It supports interactive and automated (non-interactive) operation.

## Prerequisites

### Python Environment

Install required Python modules:

```bash
sudo apt install python3 python3-pip python3-dateutil
pip install cryptography requests
```
### Install ClamAV

```bash
sudo apt install clamav clamav-daemon
sudo freshclam
```

The script expects the ClamAV scanner at:

/usr/bin/clamscan

### Encrypted Password Storage (Fernet)

Run the password setup script to generate encryption files

```bash
./create-fernet-files.py
```

Parameters

–vbrserver
Hostname or IP of the Veeam Backup & Replication server. (Required)

–sharename
Search pattern for the NAS share name inside restore points. (Required)

–mounthost
Windows mount host where the Instant Recovery share is presented. (Required)

–username
REST API username (default: Administrator).
Also used as default SMB username.

–smb-user
Override SMB username.
Password is read from encrypted_smb_password.bin.

–timeout
Seconds to wait for manual restore point selection.
Default: 30

–wait
Seconds to wait before attempting to mount the recovered SMB share.
Default: 30

–mount-base
Local base directory for SMB mounts.
Default: /mnt

–noninteractive
Automatically select the newest restore point (index 0).


Usage Examples

Interactive mode (manual restore point selection)

sudo ./nas-av-scan.py \
 --vbrserver vbr01.example.com \
 --sharename data \
 --mounthost win-mount01

Non-interactive mode (always use latest restore point)

sudo ./nas-av-scan.py \
 --vbrserver vbr01 \
 --sharename finance \
 --mounthost win-mt01 \
 --noninteractive

Using a separate SMB account

sudo ./nas-av-scan.py \
 --vbrserver vbr01 \
 --sharename backup \
 --mounthost win-ir01 \
 --smb-user Administrator \
 --noninteractive


Output Format

ClamAV detections appear as:

🐞 /mnt/win-ir01_backup/file.exe: Eicar-Test-Signature FOUND

If nothing is detected:

No detections found by ClamAV (no lines ending with 'FOUND').


Notes
• Requires Python 3 and modules: requests, cryptography, dateutil
• Requires ClamAV installed and updated
• Compatible with Veeam REST API version 1.3-rev1
• Supports NAS restore points (platformName = UnstructuredData)

**Please note this script is unofficial and is not created nor supported by Veeam Software.**

Version History

1.0
• Initial release
