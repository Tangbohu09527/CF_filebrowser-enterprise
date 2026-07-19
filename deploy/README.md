# FileBrowser Enterprise Debian deployment

These assets deploy FileBrowser Enterprise and Nginx on one internal Debian
host. Hermes, WeChat business logic, AI workers, model services, OCR, and RAG are
intentionally absent. A future message relay must be a separate service and may
join an explicitly reviewed internal Docker network; it must not be added to the
FileBrowser container.

## Host layout

```text
/opt/filebrowser-enterprise/          Compose, Nginx, systemd copies, scripts, .env
/etc/filebrowser-enterprise/          config.yaml, secrets/, tls/
/var/lib/filebrowser-enterprise/      database.db
/var/lib/filebrowser-enterprise-lifecycle/  root-only restore journal and upgrade history
/var/cache/filebrowser-enterprise/    SQL index, thumbnails, downloads, icons
/srv/filebrowser/files/               enterprise files and chunk-upload temp files
/var/backups/filebrowser-enterprise/  encrypted-export source snapshots
```

The database, files, secrets, certificates, and backups never live in a
container writable layer. Cache is persistent for performance but excluded from
backup and rebuilt after restore or rollback.

`DEPLOY_ROOT` and `BACKUP_ROOT` are fixed to the paths above because the systemd
working directory and backup sandbox name them explicitly. Production validation
rejects alternate values. The other host roots may be changed only before first
bootstrap and must still satisfy the non-nesting and atomic-restore checks.

## Prerequisites

- Debian 12 or 13 with current security updates.
- Docker Engine and Compose v2.20.0 or newer.
- `python3` plus Debian package `python3-yaml`.
- `openssl`, GNU `tar`, `sha256sum`, `flock`, `realpath`, `mountpoint`,
  `sync`, `awk`, `systemd`, and `fuser` from Debian package `psmisc`.
- Two approved images mirrored internally and pinned as `tag@sha256:digest`.

Build the customized FileBrowser image from this repository root with
`_docker/Dockerfile`; `deploy/compose.build.yaml` is the local/internal CI
override. The production stack reads only `FILEBROWSER_IMAGE` and never defaults
to an upstream FileBrowser image. Publish the resulting digest to the internal
registry before installation. The current Dockerfile base tags and `npm i` mean
that an arbitrary later rebuild is not bit-for-bit reproducible; retain the
approved image by digest. `compose.build.yaml` stays in the source checkout for
internal builds; it is intentionally not installed under `/opt` because its
relative build context is valid only in the repository.

Make both exact image references available on the Debian host before bootstrap.
For an online internal-registry host, authenticate interactively and pull both
`tag@sha256:digest` references from the completed `.env`:

```bash
sudo docker login registry.internal.example
sudo docker pull 'registry.internal.example/filebrowser-enterprise:v1.0.0@sha256:REPLACE_WITH_64_HEX'
sudo docker pull 'registry.internal.example/third-party/nginx-unprivileged:1.27.4@sha256:REPLACE_WITH_64_HEX'
sudo docker image inspect 'registry.internal.example/filebrowser-enterprise:v1.0.0@sha256:REPLACE_WITH_64_HEX'
sudo docker image inspect 'registry.internal.example/third-party/nginx-unprivileged:1.27.4@sha256:REPLACE_WITH_64_HEX'
```

For an offline host, verify the transport archives supplied by the internal
release process before `docker load`, then inspect the same exact digest
references. A successful load under a tag alone is not sufficient:

```bash
sha256sum --check filebrowser-image.tar.sha256 nginx-image.tar.sha256
sudo docker load --input filebrowser-image.tar
sudo docker load --input nginx-image.tar
sudo docker image inspect 'registry.internal.example/filebrowser-enterprise:v1.0.0@sha256:REPLACE_WITH_64_HEX'
sudo docker image inspect 'registry.internal.example/third-party/nginx-unprivileged:1.27.4@sha256:REPLACE_WITH_64_HEX'
```

## Install without starting

Prepare completed copies of `compose.env.example` and `config.yaml.example`
outside Git. Replace both `.invalid` hosts and both placeholder digests. Keep
`INTERNAL_REGISTRY_HOST` equal to the exact registry host (and port, if any) used
by both image references; arbitrary public registry hosts are rejected. Keep
`server.baseURL: "/"`; the included proxy is intentionally root-path only.

```bash
sudo ./scripts/install-debian.sh --dry-run \
  --env-file /secure/staging/filebrowser.env \
  --config-file /secure/staging/config.yaml \
  --tls-cert /secure/staging/tls.crt \
  --tls-key /secure/staging/tls.key

sudo ./scripts/install-debian.sh \
  --env-file /secure/staging/filebrowser.env \
  --config-file /secure/staging/config.yaml \
  --tls-cert /secure/staging/tls.crt \
  --tls-key /secure/staging/tls.key
```

`--dry-run` prints the idempotent actions. The installer creates separate
FileBrowser and Nginx host identities, writes their numeric IDs into `.env`,
installs but does not start the stack, never changes firewall rules, and never
generates a password. Re-running preserves an existing `.env`, config, TLS, and
secrets unless replacement files are explicitly provided. On file-install
failure, files replaced in that run are restored.

`tls.crt` must be a leaf-first PEM fullchain covering `PUBLIC_HOST`; `tls.key`
must match and remain protected. The chain must verify through Debian's system
trust store, so install an internal root CA there before validation when needed.
Renewal automation is site-specific. Atomically replace `tls.crt` and `tls.key`
individually inside the existing mounted `tls/` directory; do not exchange the
directory itself. Then run the full lifecycle reload and confirm the certificate
actually served on the configured bind address:

```bash
sudo /opt/filebrowser-enterprise/scripts/validate-deployment.sh --production
sudo systemctl reload filebrowser-enterprise.service
sudo /opt/filebrowser-enterprise/scripts/validate-deployment.sh --production --runtime
```

HSTS is always enabled by this production template. Do not put the host into
service until its complete HTTPS issuance and renewal lifecycle is ready.

## Safe initialization

The example binds 80/443 to loopback. Do not change that before bootstrap.
Create or provision the two stable secrets described in `secrets/README.md`,
then first validate the complete plan without changing the host. The first apply
starts Nginx only on loopback so an SSH tunnel can be used immediately:

```bash
sudo /opt/filebrowser-enterprise/scripts/bootstrap-admin.sh \
  --generate-secrets --start-nginx
sudo /opt/filebrowser-enterprise/scripts/bootstrap-admin.sh \
  --apply --generate-secrets --start-nginx
```

The script keeps Nginx stopped, creates the first DB with a random one-time
administrator password, removes the persistent password override, restarts with
the permanent JWT/TOTP secrets, uploads a synthetic probe, verifies its token and
content across restart, creates a separate emergency administrator while the
main process is running through its private administrator API, restarts, logs in
with the emergency password to verify the account, and deletes the probe.
Credentials are printed once; put them directly in the approved vault. An
interrupted run retains a root-owned recovery file. Inspect a resume without
changes, then apply it without changing the stable JWT/TOTP files:

```bash
sudo /opt/filebrowser-enterprise/scripts/bootstrap-admin.sh --resume --start-nginx
sudo /opt/filebrowser-enterprise/scripts/bootstrap-admin.sh --resume --start-nginx --apply
```

`--start-nginx` is accepted only while both bind addresses are `127.0.0.1`.
Reach it through an SSH tunnel and immediately change the bootstrap administrator
password. Confirm the emergency account from an isolated administrative session.
Only after that may an operator change the bind addresses to an approved internal
interface or `0.0.0.0`, apply host firewall policy, run production validation,
and start/enable systemd:

```bash
sudo /opt/filebrowser-enterprise/scripts/validate-deployment.sh --production
sudo systemctl enable --now filebrowser-enterprise.service
sudo systemctl enable --now filebrowser-enterprise-backup.timer
sudo /opt/filebrowser-enterprise/scripts/validate-deployment.sh --production --runtime
```

## Compose and Nginx behavior

FileBrowser listens on unprivileged port 8080 only on the internal Docker
network. Nginx is the sole 80/443 publisher. Both containers run with explicit
non-root IDs, a read-only root, tmpfs `/tmp`, all capabilities dropped,
`no-new-privileges`, restart/stop policies, health checks, and CPU/memory/PID
limits.

All lifecycle commands use the fixed project name `filebrowser-enterprise` and
remove inherited Compose interpolation/control variables before reading the
root-managed `.env`. This prevents a shell export from selecting another stack,
image, bind address, or data mount. Restore and upgrade health checks use
`compose.maintenance.yaml`: both restart policies are disabled and the
maintenance Nginx template returns `503` for every business request. Only after
durable transaction state commits is Nginx forcibly recreated with the
production proxy template and checked again.

Nginx terminates TLS 1.2/1.3, redirects HTTP, sets HSTS and restrained security
headers, forces Secure/HttpOnly/SameSite on application cookies, disables proxy
buffering for upload/download/SSE, supports connection upgrades, applies
configurable large-transfer limits/timeouts, and rejects `Depth: infinity`.
The trust-bearing `X-Real-IP`, `X-Forwarded-For/Host/Proto/Port` values are
overwritten from the connection rather than appended, and common proxy identity
headers are cleared. Access logs use `$uri`, not `$request_uri`, and
never include Authorization or Cookie. Backend API access logging is disabled
because the current application logger includes raw query strings.

WebDAV is explicitly disabled by default (`server.disableWebDAV: true`). After a
security review it can be enabled by setting the field false; the endpoint is
`/dav/{source}/...`, and the current application expects a FileBrowser JWT as the
Basic Auth password. The Nginx depth guard still applies.

The source is private and new users are read-only by default. Enable Share,
write permissions, WebDAV, or a future relay service only through a separate
permission review. `maxArchiveSize` and Nginx upload size are independent limits.

## systemd ownership

`filebrowser-enterprise.service` is the only boot-time owner of the Compose
stack. Its start, reload, and stop operations call `stack.sh`, which holds the
global lifecycle lock, validates before `compose up`, enforces scale one, and
stops Nginx before FileBrowser. Do not create a second native FileBrowser unit
or invoke raw Compose lifecycle commands in parallel.

Boot/start, validation, backup, install, restore, and bootstrap also reject any
non-terminal state under
`/var/lib/filebrowser-enterprise-lifecycle/upgrade-history`. Only the transaction
that owns the global lock may use its own state. After an interrupted upgrade or
rollback, inspect the root-owned `state.tsv` and run the recorded state through
`rollback.sh --state PATH` first, then repeat with `--apply`; do not delete or
hand-edit the state to bypass the guard. Successful rollback and safe abort paths
queue `systemctl start --no-block filebrowser-enterprise.service` when the unit
is inactive. The queued oneshot waits for the lifecycle lock and restores
systemd ownership after the transaction exits.

`filebrowser-enterprise-backup.timer` schedules the consistent local backup at
02:30 with a randomized delay. The backup unit has a read-only system sandbox
apart from the backup root, lifecycle lock, and Docker socket; it only reads and
verifies the separate root-only lifecycle state directory.

### Future Hermes account

This deployment creates no Hermes account or token and runs no Hermes service on
Debian. When the AI-host integration is approved, create a dedicated ordinary
FileBrowser service account through the audited administrator UI. Scope it to a
dedicated subdirectory of `enterprise-files`; enable API plus only the exact
Browse/Preview/Download/Create/Modify operations the bridge needs. Do not grant
Admin, Share, Delete, or a wider source scope unless a separate permission review
requires them. Create a short-lived, named API token whose permissions are the
intersection of the account and token grants, store it only in the AI host's
approved secret manager, test revocation and least-privilege denial, and record
its owner/expiry/rotation procedure. Verify token and upload continuity across a
FileBrowser restart before enabling task traffic. Never put that token in this
Compose stack, config, image, logs, or Debian relay environment.

## Backup and restore

```bash
sudo /opt/filebrowser-enterprise/scripts/backup.sh
sudo /opt/filebrowser-enterprise/scripts/restore.sh \
  --backup /var/backups/filebrowser-enterprise/backup-TIMESTAMP
sudo /opt/filebrowser-enterprise/scripts/restore.sh \
  --backup /var/backups/filebrowser-enterprise/backup-TIMESTAMP --apply
```

Backup uses `flock`, stops Nginx first, gracefully stops the sole FileBrowser
instance, verifies clean exit, and only then archives Bolt and business files.
It also refuses to continue if any process still has `database.db` open, covering
an unmanaged container or host process outside the fixed Compose project.
It includes config, high-sensitivity secrets, TLS, deployment assets, installed
units, database, and files; cache/index data is excluded. A temporary directory,
manifest, per-payload SHA-256 hashes, restrictive modes, and same-filesystem
atomic rename prevent partial snapshots from appearing complete. The original
service state is restored on success or failure unless a lifecycle wrapper uses
`--keep-stopped`.

The timer keeps seven verified `reason=scheduled` snapshots by default, as set
by `BACKUP_RETENTION_COUNT`. Retention deletes only snapshots whose manifest and
all required payload hashes verify. Manual, restore, upgrade, rollback, and
damaged snapshots are never deleted automatically; monitor disk use and remove
them only through an approved review. These same-host tar files include plaintext
high-sensitivity secrets and are not encrypted disaster recovery artifacts.

Restore is dry-run by default. It rejects symlinks, traversal paths, hash errors,
wrong target paths, unsupported manifest/database schemas, and any image other
than the exact source digest. It also rejects a backup tree that is not
root-owned and protected from group/other writes. Apply mode requires both
services already stopped, backs up the current state, stages and swaps targets,
creates a fresh cache, starts FileBrowser alone, then validates Nginx through a
fail-closed `503` maintenance entry point. Failed pre-commit health automatically
swaps the prior state back. After commit, Nginx is recreated with the production
template and runtime-validated again. Immediate `.pre-restore-*` siblings are
removed automatically after a successful commit; the durable rollback bundle is
retained until an operator removes it under retention policy.
An abrupt kill after journal removal but before that cleanup can leave protected
`.pre-restore-RESTORE_ID` siblings. Upgrade/rollback records the exact restore ID
in its active state. For a standalone restore, use the exact shared suffix visible
on the same-parent siblings and the operation log where available. Remove only
those exact paths under change control after runtime validation; never use a
wildcard cleanup or delete them while a journal exists.
Archive members that are devices, FIFOs, absolute links, or links escaping their
payload root are rejected. If business data intentionally contains an external
symlink, replace it with an approved in-root layout before treating the backup as
restorable.

Atomic sibling swaps require `DEPLOY_ROOT`, `CONFIG_ROOT`, `CACHE_ROOT`, and
`FILES_ROOT` themselves, plus `database.db`, to be on the same device as their
parent and not be mount points (including same-device bind mounts). A dedicated
disk may be mounted at the parent, with the configured target as its child. The
default restore dry run checks this before any mutation.

If power loss or `SIGKILL` leaves
`/var/lib/filebrowser-enterprise-lifecycle/restore-journal.tsv`, normal stack
start fails closed. Use the stable runner outside the swappable deploy root:

```bash
sudo /usr/local/sbin/filebrowser-enterprise-recover
sudo /usr/local/sbin/filebrowser-enterprise-recover --apply
```

The first command previews only allowlisted transaction paths. Apply reverts in
reverse order and keeps Nginx on the `503` maintenance template until FileBrowser
and TLS/backend checks pass. A standalone restore recovery then commits the
journal and promotes the production proxy. If an upgrade/rollback state remains
non-terminal, recovery instead stops Nginx after the filesystem rollback and
requires the recorded `rollback.sh --state ... --apply` continuation. Do not
delete or edit the root-owned `0600` journal manually.

Direct writers outside FileBrowser invalidate the stop-the-application snapshot
assumption. Quiesce them separately. Export every accepted local snapshot to an
encrypted, access-controlled, independent failure domain with approved Restic or
Borg retention; the timer's same-host copy is not disaster recovery.

## Upgrade and rollback

```bash
sudo /opt/filebrowser-enterprise/scripts/upgrade.sh \
  --image registry.internal.example/filebrowser-enterprise:v1.0.1@sha256:DIGEST
sudo /opt/filebrowser-enterprise/scripts/upgrade.sh \
  --image registry.internal.example/filebrowser-enterprise:v1.0.1@sha256:DIGEST --apply

sudo /opt/filebrowser-enterprise/scripts/rollback.sh --state latest
sudo /opt/filebrowser-enterprise/scripts/rollback.sh --state latest --apply
```

Upgrade is dry-run first, uses an exact digest already loaded locally or pulls it
from the internal registry, records current image ID, application Git SHA/version,
and target identity under the root-only lifecycle state directory, then creates
a stopped backup. Only one candidate opens Bolt. The public entry is blocked:
Nginx is stopped during backup and early candidate start, and returns `503`
whenever maintenance Nginx is running. Production proxying resumes only after
candidate health and durable upgrade commit. Any failure invokes rollback.
Rollback first captures a roll-forward point, then
restores both the old pinned image and its matching database/files/config backup;
cache is rebuilt. It never attempts an in-place database downgrade.

The roll-forward point is create-once: a resumed rollback verifies and reuses the
recorded hashes, reason, new image digest, and image ID instead of overwriting it.
Before the restore journal is durable, `.env` remains pinned to the entry/new
image. The journaled deployment-root swap installs the old pin with the old data.
After old FileBrowser and maintenance Nginx pass health checks, restore writes the
non-terminal `rollback-data-restored` phase before removing the journal. A reboot
from that phase either repeats restore after journal recovery returned to the new
image, or resumes production proxy promotion when the old image/data is already
committed. `rolled-back` is written only after proxy/runtime validation and
restart-policy restoration succeed.

If interruption occurs before the pre-upgrade backup path is recorded, the same
rollback command recognizes the `pending` backup with a `preparing` state and
safely aborts to the unchanged old image/data. If interruption occurs later, it
uses the recorded pre-upgrade backup. A durable `backed-up` state also proves the
candidate was never started, so an interruption while changing the image pin is
repaired by restoring the old pin and verified old service without relabeling or
copying the database. Any non-committed data-rollback phase with an unexpected old
image pin fails closed for operator review rather than guessing the Bolt version.

The application has no migration dry-run or formal downgrade compatibility
gate. Rehearse every candidate against a copied backup in isolated staging before
production. `/health` proves HTTP startup only; it is not a database or storage
integrity check. Complete the permission, Share, WebDAV, upload/download, token,
and ordinary-user acceptance matrix during that rehearsal.

## Known application constraint

This revision defines `http.trustedHeaders` and `http.disableRateLimit`, but its
YAML top-level whitelist discards `http`. The deployment intentionally forbids
claiming those fields are active. The secure Go default leaves backend auth rate
limiting enabled, while Nginx adds a real-client-IP auth limit. Because the
backend still sees the Nginx container address, all proxied clients share its
10-RPM IP bucket in this revision. Nginx therefore applies both a smaller
per-client bucket and an 8-RPM aggregate guard, but it cannot provide fair use of
the backend's shared bucket. This is a production go-live blocker, not an
accepted deployment limitation. Keep the assets in staging until the backend
loader/trusted-proxy rate-limit fix is integrated and concurrent ordinary-user
login acceptance proves that clients no longer share one bucket.

See `FAILURE_DRILLS.md` for isolated failure injection and acceptance evidence.
