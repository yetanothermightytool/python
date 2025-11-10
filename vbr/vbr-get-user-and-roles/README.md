# Veeam User Roles & Permissions Query

## Overview

This Python script connects to a Veeam Backup & Replication server via REST API and retrieves users (or groups), their assigned roles, and the corresponding permissions. It supports filtering by username, showing only service accounts, and exporting permissions for a specific user to a JSON file.

## Parameters

**--vbrserver**  
Hostname or IP address of the Veeam Backup & Replication server. (Required)

**--name**  
Case-insensitive substring to filter by username or group name.

**--serviceaccounts**  
If set, only users/groups that are service accounts will be shown.

**--export**  
If set together with `--name`, exports the roles and permissions for the specified user/group to a JSON file named `<name>_vbr_permission.json`.

## Usage Example

Show all users/groups and their roles:
```bash
./vbr-get-user-and-roles.py --vbrserver my.veeam.server
```

Show only service accounts:
```bash
./vbr-get-user-and-roles.py --vbrserver my.veeam.server --serviceaccounts
```

Show roles and permissions for a specific user and export to JSON:
```bash
./vbr-get-user-and-roles.py --vbrserver my.veeam.server --name myusername --export
```

### Credentials
Save the keyfiles for the REST API user to be used with this [script.](https://github.com/yetanothermightytool/python/tree/main/misc/fernet) Administrator is stored as the default user within the Python script.

## Notes
- Requires Python 3, the `requests`, `tabulate`, and `cryptography` modules.
- Designed for use with Veeam Backup & Replication REST API v1.3-rev1 (Version 13.0.1)

**Please note this script is unofficial and is not created nor supported by Veeam Software.**

## Version Information
~~~~
Version: 1.0 (November 10 2025)
Author: Steve Herzig
~~~~

## Version History
*  1.0
    * Initial Release
