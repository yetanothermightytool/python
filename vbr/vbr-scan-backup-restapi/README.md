# VBR Scan Backup via REST API

## Version Information
~~~~
Version: 1.0 (December 4th 2024)
Author: Stephan "Steve" Herzig
~~~~

## Purpose
This script scans backups using the configured antivirus via the REST API interface.

## Parameter
The script uses the following parameter:

- `host2scan`      (mandatory): Hostname from which the backups will be scanned.


![alt text](https://github.com/yetanothermightytool/python/blob/master/vbr/vbr-scan-backup-restapi/pictures/script-ouput.png)


## Variables
The following variables are stored in the script and must be changed/adjusted before the first run

```python
api_url         = "https://<your_vbr_server_here>:9419"
```

The user for whom the password file was created must be entered here (might get added as an command line argument in a later release). The user must have the Backup Administrator role.
 
```python
username = "<your_username_here>"
```

## Notes
This script uses Fernet from the Python cryptography library to securely decrypt the password used for the REST API access. Create the required files  using this [script](https://github.com/yetanothermightytool/python/blob/master/misc/fernet/create-fernet-files.py)https://github.com/yetanothermightytool/python/tree/main/misc/fernet .


This script has been tested with the following versions of Veeam Backup & Replication
- Veeam Backup & Replication v12.3
- Python 3.12.3

**Please note this script is unofficial and is not created nor supported by Veeam Software.**

## Version History
*  1.0
    * Initial Release
