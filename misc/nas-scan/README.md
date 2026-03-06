# NAS SCAN

**This script is derived from this [script.](https://github.com/yetanothermightytool/python/tree/main/vbr/vbr-nas-av-scan)**

This script connects to a Veeam Backup & Replication server via REST API, mounts a NAS backup using Instant File Share Recovery, and then scans the mounted share with one or more configurable antivirus/scan engines. After scanning it automatically unmounts the share and stops the recovery session. Credentials and server details are stored in a .env file.

## Usage

```bash
sudo ./nas-scan.py --sharename data --mounthost win-mount01 --noninteractive
```

## Script Parameters

**Required parameters:**

`--sharename` — The name (or partial name) of the NAS share to look up in VBR. Used as a filter to find matching restore points.

`--mounthost` — Hostname of the Windows server registered in VBR as a mount server. This is where Veeam will expose the backup as a live SMB share.


**Optional parameters (can be set in `.env` instead):**

`--vbrserver` — Hostname or IP address of the Veeam Backup & Replication server. Overrides `VBR_SERVER` from `.env`.

`--username` — Username for the VBR REST API. Overrides `VBR_USERNAME` from `.env`.


**Optional parameters:**

`--smb-user` — SMB username used to mount the share on the Linux host. Defaults to the value of `--username`.

`--smb-share` — Explicitly sets the SMB share name on the mount host. Use this if the auto-detected share name is incorrect.

`--mount-base` — Base directory on the Linux host where the SMB share will be mounted. Default: `/mnt`.

`--timeout` — How many seconds the user has to select a restore point interactively before the script defaults to the latest one. Default: `30`.

`--wait` — Seconds to wait after starting Instant Recovery before attempting to mount and scan. Allows Veeam time to prepare the share. Default: `60`.

`--noninteractive` — Skips the restore point selection prompt and always uses the latest restore point automatically. 

