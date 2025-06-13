# VBR Scanner

## Version Information
~~~~
Version: 1.1 (June 11 2025)
Requires: Veeam Backup & Replication v12.3.1 & Linux & Python 3.1+
Author: Stephan "Steve" Herzig
~~~~
## Description
This folder contains a set of Python scripts for running a scan against a filesystem presented by the Veeam Data Integration API.

## Prerequisites
Some preparations are required for this script to run. 

### Python Modules
The following Python modules are not part of the standard library and must be installed separately using pip.
- requests
- cryptography (for cryptography.fernet.Fernet)
- colorama
- yara (usually installed via yara-python)


### Prepare the script directory and YARA rules directory
```bash
mkdir ~/vbr-scanner
cd ~/vbr-scanner
mkdir yara_rules
```
## Credentials
Save the keyfiles for the REST API user to be used with this [script.](https://github.com/yetanothermightytool/python/tree/main/misc/fernet). Administrator is stored as the default user in the vbr-scanner Python script.

## Store script files
Save the following scripts in the script folder:
- **vbr-scanner.py**
  Executes the mount via the Veeam REST API and then triggers the scanner.py script
- **scanner.py**
  Scanner script
- **create-db.py**
  Initializes and fills the SQLite database (badfiles.db)
- **import_malwarebazaar.py**
  Imports malware hashes from CSV

## YARA Rules
Save the YARA files in the script folder directory yara_rules. (File extensions .yar and .yara).

## Database
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

## vbr-scanner.py script and parameters
The following parameters must be passed to the script

- `--host2scan`
Hostname for which the backups must be presented.
- `--repo2scan`
Repository name for which the hosts and restore points are retreved. Can be combined with --all.
- `--all`
_(optional)_ Scans the latest restore point of all valid hosts in the specified repository. Recommended to use with --iscsi for better performance. Supported platforms are VMware, Hyper-V, Windows Agent, Linux Agent.
- `--maxhosts`
_(optional)_ The maximum number of hosts to be scanned in parallel when using --all. (Default 1)
- `--workers`
_(mandatory)_ The number of workers to use for the scanning process.
- `--iscsi`
_(optional)_ Present the backups using iSCSI. Only filesystems with the NTFS, ext4 and xfs filesystem can be scanned.
- `--yaramode`
_(optional)_ YARA scan mode - off (default), all, suspicious (scans only files that show indicators of compromise), content (Targets commont document/text files to detecte sensitive data patterns (e.g. PII, credentials) 

### Examples
Scan host win-server-01. Restore points are presented using iSCSI.
```bash
sudo ./vbr-scanner.py --host2scan win-server-01 --workers 8 --iscsi
```
Scan the latest restore point of all suppored hosts from Veeam Repository "Repository 01". Triggers a YARA scan, when a suspicious file is found. Restore points are presented using iSCSI.
```bash
sudo ./vbr-scanner.py --repo2scan "Repository 01" --workers 8 --yaramode suspicious --iscsi
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
- `--Filetypes`
_(optional)_ Comma-separated list of file extensions (e.g., .exe,.dll)")
- `--Maxsize`
_(optional)_ Maximum file size in MB
- `--Exclude`
_(optional)_ Experimental Comma-separated list of directories to exclude (partial paths)
- `--CSV`
_(optional)_ Save results to this CSV file
- `--Verbose`
_(optional)_ Print all scanned files, not just matches
- `--Logfile`
_(optional)_ Path to logfile for matches (might get removed)
- `--yara`
_(optional)_ YARA scan mode (off, all, suspicious, content)

## store.py script details (Version 2.0)
This script scans the mounted file system and collects detailed metadata for selected files. It calculates a SHA-256 hash for each file and stores all data in a local SQLite database. If the database does not exist, it is automatically created during the first run. The metadata stored includes file name, path, size, timestamps, extension, file type, and whether the file is executable. Each entry is tagged with a hostname, restore point ID, and timestamp, making later comparisons across backups possible.
The script supports parallel processing and can speed up scanning using multiple CPU cores. Filters can be applied to limit which files are scanned: only specific file types (like .exe or .dll), a maximum file size, and folders to exclude. 
The script extracts key information for each file that matches the filters and calculates its SHA-256 hash. All collected data is inserted into the database, unless an entry with the same hostname and hash already exists.

### File Type Detection (Simple explanation)
The script detects files based on their extensions:
- Executables: .exe, .dll, .bin, .sh, etc. 
- Scripts: .py, .js, .ps1, .bat 
- Images: .jpg, .png, .gif, etc. 
- Documents: .pdf, .docx, .txt, etc. 
- Archives: .zip, .tar, .7z, etc.
If a file doesn’t match known types, it is labeled "other".

### Argument Description
- `--mount`
_(mandatory)_ Root directory to scan
- `--hostname`
_(mandadory)_ The name of the host to which this data belongs
- `--restorepoint-id`
_(mandatory)_ The Veeam restore point ID
- `--rp-timestamp`
_(mandatory)_ Timestamp of the restore point
- `--Filetypes`
_(optional)_ Comma-separated file extensions to scan
- `--workers`
_(optional)_ Number of parallel worker processes to use (default: half of CPU cores)
- `--maxsize`
_(optional)_ Max file size in MB to include (e.g., skip huge ISO files)
- `--exclude`
_(optional)_ Comma-separated list of folder names to skip 
- `--db`
_(optional)_ SQLite DB path (default is file_index.db)

## analyzer.py script (Version 2.0)
This script analyzes previously indexed file metadata stored in file_index.db. It compares the data against known malware hashes from badfiles.db and checks for suspicious or changing file patterns across restore points. This helps to detect possible malware infections, tampering, or unusual activity on backup data.

The script connects to both SQLite databases and performs several queries:
- Looks for files with known malicious hashes.
- Detects .exe files stored in suspicious paths (like AppData).
- Finds large executable files over 50 MB.
- Compares hashes of files with the same name on the same host to detect modified content.
- Compares file sizes to detect unexpected changes across backups.

If matches are found, results are printed as readable tables. File paths are shortened for display, and hashes are truncated for readability. If no issues are found, a green checkmark is printed.
 
## Possible improvements

- Bloom filter support to improve memory efficiency when handling large hash sets.
- Mark the scanned restore point as infected in Veeam Backup & Replication.
- And a few other nice things that I'm currently researching.

## Version History
- 1.1 (June 11 2025)
  - Repo2Scan - Scan specific or all hosts found in a specific Veeam Repository
  - YARA Scan - New argument yaramode
  - YARA scan in scanner.py 
- 1.0 (May 19th 2025)
  - Initial version
    
## Disclaimer

This script is not officially supported by Veeam Software. Use it at your own risk.
