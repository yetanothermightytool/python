# Automating Compliance Checks - Reporting Script for Veeam Encryption Settings

## Version Information
~~~~
Version: 1.1 (September 23, 2025)
Requires: Veeam Backup & Replication v12.3.1 & Linux & Python 3.1+ / v13 for the key-manager command
Author: Stephan "Steve" Herzig
~~~~

## Script
The script get-vbr-encryption-manager.py connects to a Veeam Backup & Replication server via the REST API and creates a report about encryption settings. It provides details on:
- Backup jobs and whether encryption is enabled
- Certificates installed on the backup server
- Stored encryption passwords (keys)
- Configured KMS servers

The script can also manage encryption keys on the Veeam Backup & Replication server, whether verifying or setting encryption passwords.

## Credentials
Save the keyfiles for the REST API user to be used with this [script.](https://github.com/yetanothermightytool/python/tree/main/misc/fernet). The username Administrator is stored as the default user in the Python script.

## Reports
You can generate the report in three different formats:
- As a readable table in your console (default)
- As JSON output (useful for automation or further processing)
- As an HTML report with a clear table layout

### Commands
- `encryption-info`
Show encryption and key information.
- `key-manager`  Veeam Backup & Replicatoin V13 (change key password). Manage encryption keys on the VBR server.
- 
There might be more commands/modules to be integrated in the future.

### Required Parameters
- `--vbrserver <VBR_SERVER>` Hostname or IP address of the VBR server (required).
- `--keyname <hint>`   (key-manager) The key hint to search for. This script uses the **Hint* propety as the identifier. Please make sure your key hints are unique so the correct key can be selected.

## Usage for reporting
```bash
./get-vbr-encryption-info.py --vbrserver <VBR_SERVER> encryption-info [--html | --json]
```

Output Options for encryption-info
- *(Default)* no option given
Prints a human-readable table in the terminal.
- `--html`
Export the report as an HTML file.
The file will be saved as vbr-encryption-report-<servername>-<timestamp>.html.
- `--json`
Print the report in JSON format to stdout (useful for automation, parsing with jq, etc.).

### Examples
Show report in human-readable tables
```bash
./get-vbr-encryption-info.py --vbrserver 10.20.30.40 encryption-info
```
Export report as HTML file
```bash
./get-vbr-encryption-info.py --vbrserver 10.20.30.40 encryption-info --html
```
Print report in JSON format
```bash
./get-vbr-encryption-info.py --vbrserver 10.20.30.40 encryption-info --json
```
## Sample Report
You can view a live sample report here:  
[Open Sample Report](https://github.com/yetanothermightytool/python/blob/main/vbr/vbr-encryption-info/vbr-encryption-sample-report.html)

## Key Manager

### Actions
- `--verify`  
 Verify the given password against the selected key.
- `--change`  
 Change the password of the selected key.

### Parameters
- *(default)*  
 If no password option is given, the script will prompt for the password (hidden input).
- `--hint <text>`  
 New hint when changing the password. Defaults to the current hint if not specified.
- `--password-stdin`  
 Read the password from **STDIN**.
- `--password-file <file>`  
 Read the password from the given file. There must be no new line in the password file so the password can be read correctly. E.g. printf '%s' 'Pesche2000' > pass.txt

## Examples

# Verify a key password (prompted interactively, hidden input)
```bash
./vbr-encryption-manager.py --vbrserver 10.0.0.5 key-manager --keyname "My Key" --verify
```

# Verify a key password using stdin
```bash
printf 'secret123\n' | ./vbr-encryption-manager.py --vbrserver 10.0.0.5 key-manager --keyname "My Key" --verify --password-stdin
```
# Change a key password (prompted interactively)
```bash
./vbr-encryption-manager.py --vbrserver 10.0.0.5 key-manager --keyname "My Key" --change
```
# Verify a several key passwords and password from file
```bash
for key in "Key1" "Key2" "Key3"; do
 python3 script.py --vbrserver 10.0.0.5 key-manager --keyname "$key" --verify --password-file /secure/pass.txt
done
```
# Change a key password with a new hint and password from file
```bash
./vbr-encryption-manager.py --vbrserver 10.0.0.5 key-manager --keyname "My Key" --change --hint "New hint" --password-file /secure/path/newpass.txt
```

## Version History
- 1.1 (Sep 23 2025)
   - Rename to vbr-encryption-manager
   - Addded key-manager command
- 1.0 (Sep 16 2025)
  - Initial version
    
## Disclaimer

This script is not officially supported by Veeam Software. Use it at your own risk.
