# Data Integration API

## Description
This folder contains a set of Python scripts for running a scan against a filesystem presented by the Veeam Data Integration API.

## Prerequisites
Some preparations are required for this script to run. 

### Python Modules
The following Python modules are not part of the standard library and must be installed separately using pip.
- requests
- cryptography (for cryptography.fernet.Fernet)
- colorama

### Credentials
Save the keyfiles for the REST API user to be used with this [script.](https://github.com/yetanothermightytool/python/tree/main/misc/fernet). Administrator is stored as the default user in the data-integration-api Python script.


## data-integration-api.py script and parameters
The following parameters must be passed to the script

- `--host2scan`
Hostname for which the backups must be presented.
- `--repo2scan`
Repository name for which the hosts and restore points are retreved. Can be combined with --all.
- `--all`
_(optional)_ Scans the latest restore point of all valid hosts in the specified repository. Recommended to use with --iscsi for better performance. Supported platforms are VMware, Hyper-V, Windows Agent, Linux Agent.
- `--maxhosts`
_(optoinal)_ The maximum number of hosts to be scanned in parallel when using --all. (Default 1)
- `--iscsi`
_(optional)_ Present the backups using iSCSI. Only filesystems with the NTFS, ext4 and xfs filesystem can be scanned.
  
## Disclaimer

This script is not officially supported by Veeam Software. Use it at your own risk.
