# Veeam Repository Manager

Small CLI tool to manage backup repositories in Veeam Backup & Replication via the REST API. Add or remove Linux and Windows hosts, create Linux- or Windows-backed repositories, trigger rescans, and delete repositories.

Tested against VBR REST API 1.3-rev1 (VBR 13.0.1).

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
```

`VEEAM_SSL_VERIFY` accepts `true`, `false`, or a path to a certificate file to pin a self-signed cert.

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
  --name repo01 \
  --write-cache-folder /var/cache/veeam
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

## Notes

- Credentials referenced by `--credentials-name` must already exist in VBR. The type `Linux` for Linux hosts, type `Standard` for Windows hosts.
- `--delete-backups` is opt-in; without it, backups in the repository are kept.
- `--fast-clone` only applies to `LinuxLocal` repositories on XFS volumes and is ignored for `WinLocal`.
- `--credentials-storage-type` defaults to `Permanent`. Use `SingleUse` if you don't want credentials stored persistently in the VBR configuration database.
