# Automating Compliance Checks - Reporting Script for Veeam Encryption Settings

## Version Information
~~~~
Version: 1.0 (September 16, 2025)
Requires: Veeam Backup & Replication v12.3.1 & Linux & Python 3.1+
Author: Stephan "Steve" Herzig
~~~~

## Script
The script get-vbr-encryption-info.py connects to a Veeam Backup & Replication server via the REST API and creates a report about encryption settings. It provides details on:
- Backup jobs and whether encryption is enabled
- Certificates installed on the backup server
- Stored encryption passwords (keys)
- Configured KMS servers

## Reports
You can generate the report in three different formats:
- As a readable table in your console (default)
- As JSON output (useful for automation or further processing)
- As an HTML report with a clear table layout

## Credentials
Save the keyfiles for the REST API user to be used with this [script.](https://github.com/yetanothermightytool/python/tree/main/misc/fernet). The username Administrator is stored as the default user in the Python script.

## Usage

```bash
./get-vbr-encryption-info.py --vbrserver <VBR_SERVER> encryption-info [--html | --json]
```

### Required Parameters
- `--vbrserver <VBR_SERVER>`
Hostname or IP address of the VBR server (required).

Commands
- `encryption-info`
Show encryption and key information. There might be more commands/modules to be integrated in the future.

Output Options (mutually exclusive)
- **Default (no option given)
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
./get-vbr-encryption-info.py --vbrserver 10.20.30.40 encryption-info --json | 
```

## Version History
- 1.0 (Sep 16 2025)
  - Initial version
    
## Disclaimer

This script is not officially supported by Veeam Software. Use it at your own risk.




