## Automating Compliance Checks - Reporting Script for Veeam Encryption Settings

The script connects to a Veeam Backup & Replication (VBR) server via the REST API and creates a report about your encryption settings. It provides details on:

Backup jobs and whether encryption is enabled
Certificates installed on the backup server
Stored encryption passwords (keys)
Configured KMS servers
You can generate the report in three different formats:

As a readable table in your console (default)
As JSON output (useful for automation or further processing)
As an HTML report with a clear table layout
