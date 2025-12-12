# Veeam VBR Holiday Monitor

This script provides a live, terminal-based visualization of Veeam Backup & Replication job states using the VBR REST API.

Backup jobs are displayed as ornaments on a tree. The view updates continuously and reflects the current state of the backup job status.

## Credentials
Save the keyfiles for the REST API user to be used with this [script.](https://github.com/yetanothermightytool/python/tree/main/misc/fernet). The username restapiuser is stored as the default user in the Python script. The role Backup Viewer must be assigned to this user.

## Usage
Run the script from a terminal

```bash
./vbr-holidays-monitor.py --vbrserver <VBR_HOSTNAME>
```
Parameters

`--vbrserver` Hostname or IP address of the Veeam Backup & Replication server.

`--interval`  (optional, default: 5) Interval in minutes for refreshing job data from the REST API.

## Notes

• Each job is mapped to a fixed position on the tree.

• Job status is visualized using colored ornaments.

• Running jobs blink to indicate activity.

• Empty positions are filled with snowflakes.

• The star on top reflects the overall job state.

• The packages below the tree show up to eight monitored job names.

• The display refreshes independently from the API polling interval.

• Designed for monospace terminals (macOS Terminal, Linux, Windows Terminal).

• Read-only: no changes are made to the Veeam environment. Backup Viewer role must be assigned to the user.
