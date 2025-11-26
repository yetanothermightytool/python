# Veeam FLR Compare – File-Level Restore Comparison Script

## Overview
This script utilizes the Veeam Backup & Replication REST API to initiate a File-Level Recovery session for a selected restore point and compare one or more specified paths with the current production state of the VM. 
Its main purpose is to retrieve differences between the restore point and the live system and, optionally, save these results as a JSON file.

## Prerequisites

### Encrypted Password Storage (Fernet)
Save the keyfiles for the REST API user to be used with this [script.](https://github.com/yetanothermightytool/python/tree/main/misc/fernet). The username Administrator is stored as the default user in the Python script.

## The Script
### Script Parameters

- `--host` (required) Hostname of the VM used to filter restore points.

- `--vbrserver` Hostname or IP of the Veeam Backup & Replication server. Default: vbr.test.local (can be changed)

- `--user` (required) Windows username for accessing the production VM.

- `--comparepaths` One or more paths to compare with the production system. Example: --comparepaths "C:\Users" "C:\Downloads"

- `--output` Write comparison results to a timestamped JSON file.

- `--latest` Uses the latest restore point (auto mode)

### Usage Examples

Interactive restore point selection
```bash
./vbr-flr-compare.py --host myvm01 --vbrserver vbr01.example.com --user Administrator --comparepaths C:\Users
```

Compare multiple paths and write results to a file
```bash
./vbr-flr-compare.py --host myvm01 --vbrserver vbr01.example.com --user backupuser --comparepaths "C:\Users" "C:\Temp" --output
```

### Output Behavior
After Veeam completes the comparison, the script prints the results in JSON format.
With --output, a file file is saved with a format like <hostname>_compare_<restore_point_creation_date>.json

## Notes
- Tested with Veeam REST API version 1.3-rev1

## Version Information
~~~~
Version: 1.0 (November 26 2025)
Author: Steve Herzig
~~~~

## Version History
1.0
 - Initial release
