# Secret files

The installed secret directory is `/etc/filebrowser-enterprise/secrets`, owned by
`root:filebrowser-enterprise` with directory mode `0750`. Secret files use mode
`0440` or `0640`; no secret value belongs in Compose, Git, an image layer, or a
command line. Each file contains exactly one line, has at least 32 characters,
and must not be a repeated-character/low-diversity placeholder.

Required stable files:

- `jwt_token_secret`: at least 32 random characters. This signs FileBrowser web
  and API JWTs and must remain stable across every restart.
- `totp_secret`: at least 32 independent random characters. This encrypts user
  TOTP material and must be backed up with the database.

Generate them only on the target Debian host, either with the explicit
`bootstrap-admin.sh --generate-secrets` option or an approved secret manager.
For a manual generation workflow, use `openssl rand -hex 32` under `umask 0077`,
then set the documented owner and `0640` mode. Never reuse one value for both
files.

Transient files:

- `bootstrap_admin_password` exists only while the first private start creates
  the database. The container refuses an initialized database while this file
  remains.
- `emergency_admin_password.recovery` exists only while bootstrap sends the
  emergency credential over stdin to the private administrator API.
- `*.recovery` files indicate an interrupted bootstrap. Production validation
  rejects them unless the bootstrap script is actively finalizing recovery.

Bootstrap and emergency password/recovery files are also regular, non-symlink,
`root:filebrowser-enterprise` files with mode `0440` or `0640`. They contain one
line of 24-4096 characters with the same diversity checks. Do not edit, replace,
or re-own a recovery file; run a dry-run `bootstrap-admin.sh --resume` before the
matching apply operation. Stable JWT/TOTP files must not change during resume.

Backup archives mark `secrets` as high sensitivity. Encrypt and export completed
local snapshots with the organization's Restic/Borg policy. A same-host copy is
not disaster recovery.
