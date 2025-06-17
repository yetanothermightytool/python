# Retro Hunter 🕵🏾‍♀️
**Security Scanner & Threat Audit Tool** for Veeam Backup & Replication Restore Points using the Data Integration API.

## 🛡️Find Threats in Your Backups – With Retro Hunter
Imagine you’re responsible for your company’s security. You have backups. You trust them. But what if malware or suspicious files are hiding right now or were silently active weeks ago? Wouldn’t it be great to look inside your backups, like a time machine, and search for threats?

That’s exactly what Retro Hunter does!
It connects directly to your Veeam backups and scans files from past restore points for signs of malware, hacked binaries, and other suspicious behavior. And the best part: it comes with a beautiful, easy-to-use dashboard that shows you everything.

Retro Hunter is a lightweight Python-based toolkit that scans Veeam Backup & Replication restore points for malware, suspicious binaries, and unusual patterns.

It allows you to investigate historical restore points and perform regular scans over time. By integrating with threat intelligence sources like MalwareBazaar, it continuously checks known file hashes and monitors the scanning results.

## ✅ Key Features

- Scans mounted Veeam restore points
- Parallelized scanning using Python’s multiprocessing for fast performance
- Detects known malware using hash lookups from MalwareBazaar
- Identifies out of place LOLBAS (Living Off the Land Binaries and Scripts)
- Optionally applies YARA rules to selected file types during scan
- Tracks file changes across restore points (hash or size drift)
- Displays findings in a clean Streamlit dashboard
- (Currently) Uses SQLite for persistent storage (file index and scan results)

## 🐳 Docker Support
A minimal Docker setup is provided to run the dashboard in isolated environments.

