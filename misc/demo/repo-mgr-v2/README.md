# Veeam Repository Manager

Small CLI tool to manage backup repositories in Veeam Backup & Replication via the REST API. Add or remove Linux and Windows hosts, create Linux-backed, Windows-backed or Dell Data Domain repositories, trigger rescans, and delete repositories.

Tested against VBR REST API 1.3-rev1 (VBR 13.0.1).

Dell Data Domain requires 1.3-rev2, see [Dell Data Domain](#dell-data-domain).

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
VEEAM_API_VERSION=1.3-rev2
VEEAM_SSL_VERIFY=false
VEEAM_SESSION_TIMEOUT=900
```

`VEEAM_ENDPOINT`, `VEEAM_USERNAME` and `VEEAM_PASSWORD` are required; the rest are optional.

- `VEEAM_API_VERSION` defaults to `1.3-rev1`. Older revisions use a different `mountServer` structure and will reject the `add` payload. Set it to `1.3-rev2` for Dell Data Domain repositories: The type does not exist before that revision, and `add --type DellDataDomain` refuses to run without it.
- `VEEAM_SSL_VERIFY` accepts `true`, `false`, or a path to a certificate file to pin a self-signed cert.
- `VEEAM_SESSION_TIMEOUT` is the number of seconds to wait for a session to finish (default `900`).

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

Add a Dell Data Domain repository:

```
./repo-mgr.py add \
  --type DellDataDomain \
  --dd-server ddhostname \
  --dd-credentials-name ddboost \
  --mount-server winmount01.local \
  --path ddboost://ddhostname:UNIT@/ \
  --name dd-repo01
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

Print existing repositories as raw JSON, optionally filtered:

```
./repo-mgr.py show --type DellDataDomain
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

## Authentication

Logging in with grant_type=password returns an access token that is valid for 15 minutes, plus a refresh token valid for 14 days. Fifteen minutes is shorter than plenty of real operations, e.g. rescanning a large repository can easily run longer.

This script keeps both tokens and renews them as needed:

- Before each request, if the access token is about to expire (a minute of headroom), it is renewed pre-emptively.
- If the server answers `401` regardless, the token is renewed and the request retried once. The server, not the local clock, has the final say.
- Renewal uses `grant_type=refresh_token`. A refresh token can be used **only once**, so the new one from each response replaces the old one.
- If the refresh token is spent or expired, the script falls back to a full username/password login.

All of this is transparent: No flags, no configuration. It just means a long-running session is polled to completion instead of failing at the 15 minute mark.

## Session Tracking

Most write operations in the VBR REST API are asynchronous. A POST that kicks off long-running work: adding a host, creating a repository, rescanning. It does not wait for that work to finish. It returns `201` right away with a **session object**, and the `id` in that response is the handle you use to follow the actual progress:

```
GET /api/v1/sessions/{id}
```

The session carries a `state` (`Starting`, `Working`, `Postprocessing`, … , `Stopped`) and, once it has stopped, a `result` of `Success`, `Warning` or `Failed`. Without polling it, a `201` only tells you that VBR accepted the request, not that the repository exists or that the host was added successfully.

This script does the polling for you. `add-host`, `add`, `rescan` and `delete-host` all follow their session to completion and print progress while they wait:

```
Creating repository 'repo01'...
Waiting for session 6f2c... to finish... 20% 60% 100%
Session finished successfully.
```

Deleting a repository is the exception: it is handled synchronously and returns `204` once done, with no session involved.

If a session ends with `Warning`, the message is printed and the run still counts as successful. On `Failed`, the script points at `GET /api/v1/sessions/{id}/logs` for details.

Exit codes: `0` on success (including `Warning`), `1` if the session failed or `VEEAM_SESSION_TIMEOUT` was reached. A timeout does not cancel anything — the operation may well still be running on the VBR server, so check the session before retrying.

## Dell Data Domain

API revision 1.3-rev2 added deduplication appliances to `/api/v1/backupInfrastructure/repositories`, so a Data Domain can now be registered with the same `add` command as a local repository. It behaves differently in a few ways that are worth knowing before the first run:

- **No managed server.** A Data Domain is not added to the backup infrastructure first, VBR connects to the appliance itself. The appliance is named with `--dd-server` (the `ddServername` field of the API), not with `--host`, and it does not have to be added with `add-host` beforehand. The payload carries no `hostId` at all. `--host` is still accepted as a synonym so the three repository types can be scripted uniformly.
- **Standard credentials.** `--dd-credentials-name` works exactly like `--credentials-name` on `add-host`: the record must already exist in VBR and is looked up by name — matched against the credential's **username**, falling back to its description. The only difference is the type it is searched under: **Standard** (user/password, as DD Boost uses), not Linux. It is required; the command aborts if it is missing.
- **A mount server is still needed.** `--mount-server` works exactly as it does for the local types, including `--mount-server-type` and `--write-cache-folder`.
- **API revision.** The command checks `VEEAM_API_VERSION` before sending anything and aborts with a clear message if it is older than `1.3-rev2`, rather than letting the server reject an unknown repository type. The type is not new in rev2, it was *renamed*: the changelog in `swagger.json` lists `DDBoost` → `DellDataDomain` under Breaking Changes, so older documentation and older revisions call it `DDBoost`.

Data Domain specific arguments:

| Argument | Default | Note |
| --- | --- | --- |
| `--dd-server` | — | Required. DD server name, sent as `ddServername`. `--host` is accepted instead. |
| `--dd-credentials-name` | — | Required. DD Boost user, matched against **Standard** credentials. |
| `--dd-fibre-channel` | off | Connect over Fibre Channel instead of IP. |
| `--dd-boost-encryption` | off | `Medium` or `High`; passing either enables DD Boost in-flight encryption. |
| `--gateway-server` | automatic | Gateway server name, repeatable. Without it, VBR selects gateway servers automatically. |
| `--immutability-days` | off | Enables DD Retention Lock for the given number of days. Retention Lock must be licensed and enabled on the appliance, otherwise the session fails. |

`--fast-clone` is ignored (XFS only), and the remaining shared arguments — `--task-count`, `--read-write-rate`, `--path`, `--name`, `--description` — behave as they do for the other types. `rescan` and `delete` need no changes: both look the repository up by name and work with a Data Domain as they do with any other repository.


## Repository Settings and Best Practices

The values this script sends are working defaults for a demo setup, **not** a sizing recommendation. Concurrent tasks, throttling and block alignment should follow the Veeam best practices for your storage and your backup window. Review them before using this in production, and adjust afterwards in the VBR console if needed. Everything the script sets can be changed later in the GUI under *Backup Infrastructure > Backup Repositories > Edit*.

Exposed as CLI arguments:

| Argument | Default | Note |
| --- | --- | --- |
| `--task-count` | `4` | Concurrent tasks. Rule of thumb is one task per CPU core of the repository server; too high starves the storage, too low wastes the backup window. |
| `--read-write-rate` | unset | No throttling unless a value is passed. The unit matches the field in the VBR console. Check there before setting it. |
| `--fast-clone` | off | XFS fast cloning, `LinuxLocal` only. Requires an XFS volume formatted with reflink support. |
| `--write-cache-folder` | per OS | vPower NFS cache path, see notes below. |
| `--advanced` | per type | Overrides a single `advancedSettings` field, repeatable. See below for the defaults it overrides. |

Dell Data Domain adds `--dd-server`, `--dd-credentials-name`, `--dd-fibre-channel`, `--dd-boost-encryption`, `--gateway-server` and `--immutability-days`, documented under [Dell Data Domain](#dell-data-domain).

Hardcoded in the script and only changeable with `--advanced` (or in the GUI afterwards):

- `alignDataBlocks`, `decompressBeforeStoring` and `perVmBackup` are all enabled; `rotatedDrives` is disabled. **Not for `DellDataDomain`** , the appliance rejects them, so no `advancedSettings` block is sent at all unless `--advanced` asks for one.
- vPower NFS is enabled with mount port `1058` and NFS port `2049`.
- Linux hosts are added with SSH port range `2500-3300`, management port `6162` and a 20 s SSH timeout.
- `taskLimitEnabled` is always `true`, so `--task-count` is always in effect.

If your environment needs different values here, pass them with `--advanced` or change them in the payload before the first run, rather than fixing every repository by hand afterwards.

## Notes

- Credentials referenced by `--credentials-name` must already exist in VBR. Use type `Linux` for Linux hosts, type `Standard` for Windows hosts and for the DD Boost user behind `--dd-credentials-name`. The value is matched against the credential's **username**, falling back to its description; ambiguous matches abort instead of picking one.
- `--delete-backups` is opt-in; without it, backups in the repository are kept.
- `--credentials-storage-type` defaults to `Permanent`. Use `SingleUse` if you don't want credentials stored persistently in the VBR configuration database.
- `--write-cache-folder` defaults to the vPower cache path matching `--mount-server-type`: `C:\ProgramData\Veeam\Backup\IRCache\` for Windows, `/tmp/VeeamBackup/` for Linux. Override it if the default path is unsuitable, on Linux in particular, `/tmp` may be too small or cleared on reboot.
- For Linux hosts, the SSH fingerprint is fetched automatically unless you pass `--fingerprint` explicitly.
- Both delete commands refuse to run without `--yes` when there is no interactive terminal, so an unattended job never deletes silently.
