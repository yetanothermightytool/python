# VBR Entra ID Search

## Version Information
~~~~
Version: 1.0 (December 6th 2024 🎅)
Author: Stephan "Steve" Herzig
~~~~

## Purpose
This script allows you to search and compare secured Entra ID objects such as users, groups, or applications.

## Parameter
The script can be controlled using these parameters:

- `username`        : Display name of the user to be searched for.
- `groupname`       : Display name of the group to be searched for.
- `applicationname` : Display name of the application to be searched for.
- `checkprod`       : Checks if item exists in production 
- `compareprod`     : Compares item properties between the selected restore point and production

## Usage Examples
Check if user exists in selected restore point.
```python
./vbr-entraid-search.py -username "Joe Doe"
```

Check if user exists in selected restore point and check if it exists in production.
```python
./vbr-entraid-search.py -username "Joe Doe" -checkprod
```
Note: The latest restore point will be chosen automatically if there is no user input

## Variables
The following variables are stored in the script and must be changed/adjusted before the first run.

```python
api_url         = "https://<your_vbr_server_here>:9419"
```

The user for whom the password file was created must be entered here (might get added as an command line argument in a later release).
 
```python
username = "<your_username_here>"
```

## Notes
This script uses Fernet from the Python cryptography library to securely decrypt the password used for the REST API access. Create the required files using this [script](https://github.com/yetanothermightytool/python/blob/master/misc/fernet/create-fernet-files.py).

This script has been tested with the following versions of Veeam Backup & Replication
- Veeam Backup & Replication v12.3
- Python 3.12.3 on Linux

**Please note this script is unofficial and is not created nor supported by Veeam Software.**

## Version History
*  1.0
    * Initial Release
