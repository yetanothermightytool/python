# Veeam Repository Manager

Small CLI tool to manage backup repositories in Veeam Backup & Replication via the REST API. Add or remove Linux and Windows hosts, create Linux- or Windows-backed repositories, trigger rescans, and delete repositories.

Tested against VBR REST API 1.3-rev1 (VBR 13.0.2).

## Required Python Modules

```
requests python-dotenv
```

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```
VEEAM_ENDPOINT=https://vbr-host01:9419
VEEAM_USERNAME=restapiuser
VEEAM_PASSWORD=changeme
VEEAM_API_VERSION=1.3-rev1
VEEAM_SSL_VERIFY=false
VEEAM_SESSION_TIMEOUT=900
```

`VEEAM_ENDPOINT`, `VEEAM_USERNAME` and `VEEAM_PASSWORD` are required; the rest are optional.

- `VEEAM_API_VERSION` defaults to `1.3-rev1`. Older revisions use a different `mountServer` structure and will reject the `add` payload.
- `VEEAM_SSL_VERIFY` accepts `true`, `false`, or a path to a certificate file to pin a self-signed cert.
- `VEEAM_SESSION_TIMEOUT` is the number of seconds to wait for a session to finish (default `900`). Raise it for large repositories, where a rescan can take considerably longer.

## Usage

Add a Linux host:

```
./repo-mgr.py add-host --name linux01.local --type LinuxHost --credentials-name repouser
```

Add a Windows host:

```
./repo-mgr.py add-host --name winmount01.local --type WindowsHost --credentials-name winrepouser
```

Add a Linux-backed repository:

```
./repo-mgr.py add \
  --host linux01.local \
  --type LinuxLocal \
  --mount-server winmount01.local \
  --path /mnt/backup \
  --name repo01
```

Add a Windows-backed repository:

```
./repo-mgr.py add \
  --host winmount01.local \
  --type WinLocal \
  --mount-server winmount01.local \
  --path D:\\Backup \
  --name repo02
```

Use a Linux mount server instead of the default Windows one:

```
./repo-mgr.py add \
  --host linux01.local \
  --type LinuxLocal \
  --mount-server linux01.local \
  --mount-server-type Linux \
  --path /mnt/backup \
  --name repo01
```

Raise the concurrent task limit and throttle the repository:

```
./repo-mgr.py add \
  --host linux01.local \
  --type LinuxLocal \
  --mount-server winmount01.local \
  --path /mnt/backup \
  --name repo01 \
  --task-count 8 \
  --read-write-rate 50
```

Rescan a repository:

```
./repo-mgr.py rescan --repo-name repo01
```

Delete a repository (add `--delete-backups` to also remove its backups):

```
./repo-mgr.py delete --repo-name repo01
```

Remove a host:

```
./repo-mgr.py delete-host --name linux01.local --type LinuxHost
```

Both delete commands ask for confirmation. Pass `--yes` to skip the prompt when running unattended:

```
./repo-mgr.py delete --repo-name repo01 --delete-backups --yes
```

## Session Tracking

Most write operations in the VBR REST API are asynchronous. A POST that kicks off long-running work, e.g. adding a host, creating a repository, rescanning, does not wait for that work to finish. It returns `201` right away with a **session object**, and the `id` in that response is the handle you use to follow the actual progress:

```
GET /api/v1/sessions/{id}
```

The session carries a `state` (`Starting`, `Working`, `Postprocessing`, … , `Stopped`) and, once it has stopped, a `result` of `Success`, `Warning` or `Failed`. Without polling it, a `201` only tells you that VBR accepted the request — not that the repository exists or that the host was added successfully.

This script does the polling for you. `add-host`, `add`, `rescan` and `delete-host` all follow their session to completion and print progress while they wait:

```
Creating repository 'repo01'...
Waiting for session 6f2c... to finish... 20% 60% 100%
Session finished successfully.
```

Deleting a repository is the exception: it is handled synchronously and returns `204` once done, with no session involved.

If a session ends with `Warning`, the message is printed and the run still counts as successful. On `Failed`, the script points at `GET /api/v1/sessions/{id}/logs` for details.

Exit codes: `0` on success (including `Warning`), `1` if the session failed or the timeout was reached. A timeout does not cancel anything — the operation may well still be running on the VBR server, so check the session before retrying.

## Repository Settings and Best Practices

The values this script sends are working defaults for a demo setup, **not** a sizing recommendation. Concurrent tasks, throttling and block alignment should follow the Veeam best practices for your storage and your backup window — review them before using this in production, and adjust afterwards in the VBR console if needed. Everything the script sets can be changed later in the GUI under *Backup Infrastructure > Backup Repositories > Edit*.

Exposed as CLI arguments:

| Argument | Default | Note |
| --- | --- | --- |
| `--task-count` | `4` | Concurrent tasks. Rule of thumb is one task per CPU core of the repository server; too high starves the storage, too low wastes the backup window. |
| `--read-write-rate` | unset | No throttling unless a value is passed. The unit matches the field in the VBR console — check there before setting it. |
| `--fast-clone` | off | XFS fast cloning, `LinuxLocal` only. Requires an XFS volume formatted with reflink support. |
| `--write-cache-folder` | per OS | vPower NFS cache path, see notes below. |

Hardcoded in the script and only changeable by editing it (or in the GUI afterwards):

- `alignDataBlocks`, `decompressBeforeStoring` and `perVmBackup` are all enabled; `rotatedDrives` is disabled.
- vPower NFS is enabled with mount port `1058` and NFS port `2049`.
- Linux hosts are added with SSH port range `2500-3300`, management port `6162` and a 20 s SSH timeout.
- `taskLimitEnabled` is always `true`, so `--task-count` is always in effect.

If your environment needs different values here, change them in the payload before the first run rather than fixing every repository by hand afterwards.

## Notes

- Credentials referenced by `--credentials-name` must already exist in VBR. Use type `Linux` for Linux hosts, type `Standard` for Windows hosts. The value is matched against the credential's **username**, falling back to its description; ambiguous matches abort instead of picking one.
- `--delete-backups` is opt-in; without it, backups in the repository are kept.
- `--credentials-storage-type` defaults to `Permanent`. Use `SingleUse` if you don't want credentials stored persistently in the VBR configuration database.
- `--write-cache-folder` defaults to the vPower cache path matching `--mount-server-type`: `C:\ProgramData\Veeam\Backup\IRCache\` for Windows, `/tmp/VeeamBackup/` for Linux. Override it if the default path is unsuitable — on Linux in particular, `/tmp` may be too small or cleared on reboot.
- For Linux hosts, the SSH fingerprint is fetched automatically unless you pass `--fingerprint` explicitly.
- Both delete commands refuse to run without `--yes` when there is no interactive terminal, so an unattended job never deletes silently.
