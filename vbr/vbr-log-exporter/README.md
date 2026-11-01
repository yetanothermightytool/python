# vbr-log-exporter

A small Python script that collects the restore audit logs from a Veeam Backup & Replication (VBR) server through the REST API.

VBR writes a CSV file for every file-level restore. Each file shows who restored which file, when, and whether it worked. 
This script exports the logs bundle, keeps only the audit CSV files and turns them into one JSON file, ready for upload to a Log Analytics workspace.

## What it does

1. Logs in to the VBR REST API.
2. Starts a log export for the last 24 hours (or a time range you choose).
3. Waits until the export is finished and downloads the ZIP bundle.
4. Picks out all `.csv` files under `<hostname>\Backup\Audit\`.
5. Saves the CSV files and a combined `veeam_audit.json` with one record per restore action.
6. Remembers which files it has already processed, so running it again does not create duplicates.


## Usage

```bash
# Audit logs of the last 24 hours
./vbr-log-exporter.py --server 10.10.11.240 --user admin

# Last 72 hours
./vbr-log-exporter.py --server 10.10.11.240 --user admin --hours 72

# A fixed time range (local time)
./vbr-log-exporter.py --server 10.10.11.240 --user admin --from 2026-10-01T00:00 --to 2026-10-08T00:00

# Keep the complete log bundle instead of the audit files only
./vbr-log-exporter.py --server 10.10.11.240 --user admin --full
```

The password is taken from `--password`, from the `VEEAM_PASSWORD` environment variable, or asked for when the script starts.

## Main options

| Option | Meaning |
|---|---|
| `--server` | VBR server name or IP address |
| `--user` | VBR user name |
| `--hours` | Export the last N hours (default 24) |
| `--from`, `--to` | Export a fixed time range instead |
| `--output` | Target folder (default `veeam_audit_<server>_<timestamp>`) |
| `--state` | File that remembers processed CSV files (default `veeam_audit_state.json`) |
| `--no-csv` | Write only the JSON file, not the CSV files |
| `--full` | Save the complete log bundle as ZIP, no filtering |

Run `./vbr-log-exporter.py --help` for all options.

## Output

Each record in `veeam_audit.json` looks like this:

```json
{
  "TimeGenerated": "2026-10-14T06:42:21Z",
  "VbrServer": "10.10.50.150",
  "Computer": "vbr-host",
  "User": "WIN-VBR-01\\Administrator",
  "UserSid": "S-1-5-21-...-500",
  "Operation": "CopyTo",
  "Result": "Success",
  "Object": "\\\\?\\volume{...}\\1_Ziebelemaerit\\Zwiebel.txt",
  "SourceFile": "CopyTo-2026-10-14-06-42-21Z-WIN-VBR-01-Administrator-1.csv"
}
```

All times are in UTC. If no new audit files are found, the script ends without creating a folder.

## Good to know

- The VBR API cannot export single log types. The server always builds the full log bundle, so an export takes as long as a normal support log export.

## Version History
- 1.0 (October 14 2026)
  - Initial version
    
## Disclaimer

This script is not officially supported by Veeam Software. Use it at your own risk.
