# VBR Hash Scanner

## Version Information
~~~~
Version: 1.0 (May 19th 2025)
Requires: Veeam Backup & Replication v12.3.1 & Linux & Python 3.1+
Author: Stephan "Steve" Herzig
~~~~
## Description
This folder contains a set of Python scripts for running a scan against a filesystem presented by the Veeam Data Integration API.

## Prerequisites
Some preparations are required for this script to run. 

### Prepare the script directory
```bash
mkdir ~/vbr-hash-scanner
cd ~/vbr-hash-scanner
```
### Credentials
Save the keyfiles for the REST API user to be used with this [script.](https://github.com/yetanothermightytool/python/tree/main/misc/fernet)

### Store script files
Save the following scripts in the script folder:
- **data-integration-api.py**
  Executes the mount via the Veeam REST API and then triggers the scanner.py script
- **scanner.py**
  Scanner script
- **create-db.py**
  Initializes and fills the SQLite database (badfiles.db)
- **import_malwarebazaar.py**
  Imports malware hashes from CSV

### Database
The script loads the contents of the database into memory during runtime. There are currently two tables, lobas and malwarebazaar. The lolbas table contains the binaries that malicious actors frequently use. They perform actions that do not correspond to their original purpose. This script checks whether one of the files is outside its “natural habitat”. Download the [CSV file](https://lolbas-project.github.io/api/) and save it as lolbin_hashes.csv to the script folder.


```bash
./create-db.py
```

The malwarebazaar table contains the SHA256 values of the malware files. Download the complete [data dump](https://bazaar.abuse.ch/export/#csv) and unzip the CSV file as malwarebazaar.csv to the script folder. The script import_malwarebazaar_data.py imports the values into the database.

```bash
./import_malwarebazaar_data.py
```
Additional tables might be added in the future.

## The Scan Scripts
There are two scripts for scanning. The first script takes over the part of the Veeam Data Integration API and then triggers the scan script. The scan script itself does the “hard work”.

## data-integration-api.py script and parameters
The following parameters must be passed to the script

- `--host2scan`
_(mandatory)_ Hostname for which the backup must be presented.
- `--workers`
_(mandatory)_ The number of workers to use for the scanning process.
- `--iscsi`
_(optional)_ Present the backups using iSCSI. Only filesystems with the NTFS, ext4 and xfs filesystem can be scanned.

### Example
```bash
sudo ./data-integration-api.py --host2scan win-server-01 --workers 8 --iscsi
```

### Scanning Process Details
The following folders are excluded from the scanning process. You can adjust the list using the existing DEFAULT_EXCLUDES variable.

- **Windows\\WinSxS**
- **Windows\\Temp**
- **Windows\\SysWOW64**
- **Windows\\System32\\DriverStore**
- **Windows\\Servicing**
- **ProgramData\\Microsoft\\Windows Defender**
- **ProgramData\\Microsoft\\Windows Defender\\Platform**
- **System Volume Information**
- **Recovery**
- **Windows\\Logs**
- **Windows\\SoftwareDistribution\\Download**
- **Windows\\Prefetch**
- **Program Files\\Common Files\\Microsoft Shared**
- **Windows\\Microsoft.NET\\Framework64**
- **$Recycle.Bin**

### scanner.py Parameters
The Data Integration API script is not using all the available scanner.py parameters. This can be adjusted if necessary.
- Mount			Path to the mounted backup filesystem
- Workers		Default = Multiprocessing CPU Count / 2

Optional Parameters
- Filetypes		Comma-separated list of file extensions (e.g., .exe,.dll)")
- Maxsize		Maximum file size in MB
- Exclude		Experimental Comma-separated list of directories to exclude (partial paths)
- CSV			Save results to this CSV file
- Verbose		Print all scanned files, not just matches
- Logfile			Path to logfile for matches (might get removed)

## Possible improvements
- Bloom filter support to improve memory efficiency when handling large hash sets.
- Mark the scanned restore point as infected in Veeam Backup & Replication.
- And a few other nice things that I'm currently researching.

## Version History
- 1.0
  - Initial version
    
## Disclaimer

This script is not officially supported by Veeam Software. Use it at your own risk.
