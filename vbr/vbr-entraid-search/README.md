# VBR Entra ID Search

## Version Information
~~~~
Version: 1.1 (December 11 2025)
Author: Stephan "Steve" Herzig
~~~~

## Purpose
This script allows you to search and compare secured Entra ID objects such as users, groups, or applications.

## Parameter
The script can be controlled using these parameters:

- `vbrserver`       : Hostname or IP address of Veeam Backup & Replication server 
- `restapiuser`     : Username for REST API query. Default is Administrator
- `username`        : Display name of the user to be searched for.
- `groupname`       : Display name of the group to be searched for.
- `applicationname` : Display name of the application to be searched for.
- `checkprod`       : Checks if item exists in production 
- `compareprod`     : Compares item properties between the selected restore point and production
- `latest`          : Uses the latest restore point for the query (automode)
  
## Usage Examples
Check if user exists in selected restore point.
```python
./vbr-entraid-search.py --vbrserver VBR01 --username "Joe Doe"
```

Check if user exists in selected restore point and check if it exists in production.
```python
./vbr-entraid-search.py --vbrserver VBR01 --username "Joe Doe" --checkprod
```

## Notes
This script uses Fernet from the Python cryptography library to securely decrypt the password used for the REST API access. Create the required files using this [script](https://github.com/yetanothermightytool/python/blob/master/misc/fernet/create-fernet-files.py).

This script has been tested with the following versions of Veeam Backup & Replication
- Veeam Backup & Replication 12.3.2 & 13.0.1
- Python 3.12.3 on Linux

**Please note this script is unofficial and is not created nor supported by Veeam Software.**

## Version History
*  1.1
    * New parameters vbrserver, restapiuser and latest
    * REST API version 1.3-rev1 (can be adjusted)
*  1.0 December 6th 2024 
    * Initial Release
