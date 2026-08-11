# Shared-host Docker deployment

This directory defines the `cf-filebrowser` Compose project for a Debian 12/13
host that also runs unrelated Docker projects. It has one business service,
`filebrowser-enterprise`, and one project-scoped `private` bridge network. The
base Compose file publishes no host ports. The Debug override publishes only
`127.0.0.1:18081:8080`.

This mode does not install systemd units, Nginx, a Gateway, PostgreSQL, Redis,
cron, or a backup scheduler. It does not use `cf-edge` or another shared Docker
network, and it does not bind ports 80 or 443. The ordinary project-private
bridge is intentionally not marked `internal` yet so outbound image behavior
can be evaluated during Staging.

The existing exclusive-host deployment under `deploy/` remains a separate
mode. Do not mix its Compose files, lifecycle scripts, Nginx configuration, or
systemd units with this directory.

## Fixed checkout only

Deployment assets on the server must come from a fixed GitHub checkout. Do not
copy them from a Windows workstation, a Codex worktree,
`.codex/visualizations`, or another uncommitted directory.

Set the approved HTTPS repository URL and immutable revision in the operator
shell, then clone or update the checkout:

```bash
export SOURCE_ROOT=/opt/cf-filebrowser-enterprise
export APPROVED_GITHUB_REPOSITORY_URL='https://github.com/APPROVED_ORG/APPROVED_REPOSITORY.git'
export APPROVED_REF='APPROVED_FULL_SHA_OR_SIGNED_TAG'
export APPROVED_SHA='APPROVED_FULL_40_CHARACTER_COMMIT_SHA'

sudo git clone "$APPROVED_GITHUB_REPOSITORY_URL" "$SOURCE_ROOT"
sudo git -C "$SOURCE_ROOT" fetch --tags origin
sudo git -C "$SOURCE_ROOT" checkout --detach "$APPROVED_REF"
sudo git -C "$SOURCE_ROOT" rev-parse HEAD
test "$(sudo git -C "$SOURCE_ROOT" rev-parse HEAD)" = "$APPROVED_SHA"
test -z "$(sudo git -C "$SOURCE_ROOT" status --porcelain=v1)"
```

For an existing checkout, run the `fetch`, detached checkout, SHA comparison,
and clean-status check again. Never deploy a moving branch head, `latest` tag,
or uncommitted server files.

## Build and identify a Staging image

`compose.build.yaml` is only a local Staging build override. Its context is the
fixed repository root and it uses `_docker/Dockerfile`. `BUILD_VERSION` and
`BUILD_REVISION` are passed to that Dockerfile as `VERSION` and `REVISION`.
Choose a unique local image name and use the verified full Git SHA:

```bash
cd "$SOURCE_ROOT"
export APPROVED_VERSION='staging-APPROVED_CHANGE_ID'
export ACTUAL_SHA
ACTUAL_SHA=$(sudo git -C "$SOURCE_ROOT" rev-parse HEAD)
export STAGING_IMAGE="cf-filebrowser-enterprise:staging-${ACTUAL_SHA}"

sudo env \
  FILEBROWSER_BUILD_IMAGE="$STAGING_IMAGE" \
  BUILD_VERSION="$APPROVED_VERSION" \
  BUILD_REVISION="$ACTUAL_SHA" \
  docker compose \
    --env-file deploy/shared-host/compose.env.example \
    -f deploy/shared-host/compose.yaml \
    -f deploy/shared-host/compose.build.yaml \
    --profile approved \
    build filebrowser-enterprise

sudo docker image inspect --format '{{.Id}}' "$STAGING_IMAGE"
```

Record the exact image ID with the Staging evidence. This task does not build
an image. Building later must still start from a clean, fixed checkout.

The local tag and image ID are sufficient only for isolated Staging. Before a
Candidate or production deployment, publish through the approved image process,
record the immutable registry digest, and set `FILEBROWSER_IMAGE` to the full
approved reference ending in `@sha256:<64 lowercase hex characters>`. Candidate
and production validation rejects tags without a digest and the all-zero digest.

## Prepare host paths manually

The following numeric identity is a contract, not an account to create:

```text
FILEBROWSER_UID=10001
FILEBROWSER_GID=10001
```

`validate.sh` fails if either number maps to an existing host account or group.
The container runs directly as `10001:10001`; do not add a host login merely to
give the number a name.

Confirm `/srv/storage` is already an independent mount and that its RAID state
has been checked through the approved host procedure. Then create the roots
manually:

```bash
export CONFIG_ROOT=/etc/cf-filebrowser-enterprise
export DATA_ROOT=/var/lib/cf-filebrowser-enterprise
export CACHE_ROOT=/var/cache/cf-filebrowser-enterprise
export FILES_ROOT=/srv/storage/cf-filebrowser-enterprise/files
export BACKUP_ROOT=/srv/storage/cf-filebrowser-enterprise/backups
export FILEBROWSER_UID=10001
export FILEBROWSER_GID=10001

sudo install -d -o root -g "$FILEBROWSER_GID" -m 0750 "$CONFIG_ROOT"
sudo install -d -o root -g "$FILEBROWSER_GID" -m 0750 "$CONFIG_ROOT/secrets"
sudo install -d -o "$FILEBROWSER_UID" -g "$FILEBROWSER_GID" -m 0750 "$DATA_ROOT"
sudo install -d -o "$FILEBROWSER_UID" -g "$FILEBROWSER_GID" -m 0750 "$CACHE_ROOT"
sudo install -d -o "$FILEBROWSER_UID" -g "$FILEBROWSER_GID" -m 0750 "$FILES_ROOT"
sudo install -d -o root -g root -m 0700 "$BACKUP_ROOT"
```

`BACKUP_ROOT` records the future backup location. It is deliberately not mounted
into the application container and this mode does not schedule backups.

## Create the real env, config, and Secret files

Keep runtime configuration outside the Git checkout. Create the real env file
from the tracked example, make it root-only, and replace every image/build
placeholder. For local Staging, set `FILEBROWSER_IMAGE` to the exact
`STAGING_IMAGE` built above. Candidate and production must use the approved
digest reference.

```bash
sudo install -o root -g root -m 0600 \
  "$SOURCE_ROOT/deploy/shared-host/compose.env.example" \
  "$CONFIG_ROOT/.env"
sudoedit "$CONFIG_ROOT/.env"

sudo install -o root -g "$FILEBROWSER_GID" -m 0640 \
  "$SOURCE_ROOT/deploy/shared-host/config.yaml.example" \
  "$CONFIG_ROOT/config.yaml"
```

Do not add passwords, Secret values, Tokens, Cookies, or certificates to the env
or YAML config. Compose bind-mounts the existing reviewed
`scripts/container-entrypoint.sh`; there is no shared-host copy to drift from it.

The host Secret source paths are:

```text
/etc/cf-filebrowser-enterprise/secrets/jwt_token_secret
/etc/cf-filebrowser-enterprise/secrets/totp_secret
/etc/cf-filebrowser-enterprise/secrets/bootstrap_admin_password
```

Compose mounts that directory read-only at `/run/filebrowser-secrets`; the
entrypoint therefore reads the same three filenames from that container path.

Provision them from the approved Secret handling path without displaying their
contents. JWT and TOTP values must each be a single line of 32-4096 characters.
The bootstrap administrator password must be a single line of 24-4096
characters. Each file must be a regular non-symlink owned by `root:10001` with
mode `0440`:

```bash
sudo install -o root -g "$FILEBROWSER_GID" -m 0440 \
  "$APPROVED_JWT_SECRET_FILE" "$CONFIG_ROOT/secrets/jwt_token_secret"
sudo install -o root -g "$FILEBROWSER_GID" -m 0440 \
  "$APPROVED_TOTP_SECRET_FILE" "$CONFIG_ROOT/secrets/totp_secret"
sudo install -o root -g "$FILEBROWSER_GID" -m 0440 \
  "$APPROVED_BOOTSTRAP_PASSWORD_FILE" "$CONFIG_ROOT/secrets/bootstrap_admin_password"
```

The variables on the left identify inputs managed outside this repository; do
not substitute literal Secret values into the command line or shell history.

## Staging permission decision

The tracked config deliberately sets `denyByDefault: false`,
`defaultEnabled: true`, and enables Browse, Preview, and Download for new users.
API, Admin, Share, Create, Modify, Delete, and Realtime remain disabled. These
three default grants and both source flags are a Staging configuration decision,
not standing production approval. Review and approve them again before go-live.
WebDAV is disabled.

## Static and host preparation validation

Repository-only checks can run on a development or CI host. They parse Compose
but never pull, build, create, or start a container:

```bash
bash -n deploy/shared-host/validate.sh

docker compose \
  --env-file deploy/shared-host/compose.env.example \
  -f deploy/shared-host/compose.yaml \
  config --no-interpolate --quiet

docker compose \
  --env-file deploy/shared-host/compose.env.example \
  -f deploy/shared-host/compose.yaml \
  -f deploy/shared-host/compose.debug.yaml \
  config --no-interpolate --quiet

bash deploy/shared-host/validate.sh \
  --assets-only \
  --mode staging \
  --env-file deploy/shared-host/compose.env.example
```

The validator also requires Python 3 with PyYAML (Debian package
`python3-yaml`). It does not install that prerequisite. `--assets-only`
explicitly skips the operating-system, mount, RAID, hostname,
port, ownership, and file checks. It is not deployment approval.

On CFserver, run the full read-only preparation check. It accepts only Debian
12/13 and Docker Compose 2.20 or newer. It verifies the confirmed hostname,
independent `/srv/storage` mount, unused numeric identity, exact bind paths,
config/Secret modes, Secret shape without printing contents, bootstrap lifecycle,
and Debug port availability. Supply either an approved read-only RAID checker or
an explicit confirmation backed by separately recorded evidence:

```bash
export APPROVED_HOSTNAME='HOSTNAME_FROM_THE_APPROVED_CHANGE_RECORD'

sudo bash "$SOURCE_ROOT/deploy/shared-host/validate.sh" \
  --mode staging \
  --debug \
  --env-file "$CONFIG_ROOT/.env" \
  --hostname "$APPROVED_HOSTNAME" \
  --raid-check-command /ABSOLUTE/PATH/TO/APPROVED_READ_ONLY_RAID_CHECK
```

If RAID evidence was reviewed outside the script, replace the last option with
`--raid-confirmed`. That flag records an operator assertion; it does not inspect
RAID state. Candidate validation uses `--mode candidate`; production uses
`--mode production`. Add `--debug` only when the loopback Debug override will be
used. An external checker runs with the validator's identity, receives
`/srv/storage` as its only argument, and must be pre-reviewed as read-only. The
validator requires the checker and every parent directory to be root-owned and
not writable by group or other.

The validator performs no directory creation, ownership or mode changes,
package installation, firewall changes, user/group changes, network creation,
image pull/build, container lifecycle operation, or systemd operation.

## Start and stop loopback Debug

First make `FILEBROWSER_IMAGE` in the real env file name the already built local
Staging image or approved digest. Do not include the build override in the start
command, which prevents an implicit rebuild:

```bash
sudo docker compose \
  --env-file "$CONFIG_ROOT/.env" \
  -f "$SOURCE_ROOT/deploy/shared-host/compose.yaml" \
  -f "$SOURCE_ROOT/deploy/shared-host/compose.debug.yaml" \
  --profile approved \
  up -d --no-build filebrowser-enterprise
```

The only host listener added by this override is `127.0.0.1:18081`. It is for
initial Staging diagnostics, is not public ingress, and does not occupy 80/443.

Stop without deleting bind-mounted data:

```bash
sudo docker compose \
  --env-file "$CONFIG_ROOT/.env" \
  -f "$SOURCE_ROOT/deploy/shared-host/compose.yaml" \
  -f "$SOURCE_ROOT/deploy/shared-host/compose.debug.yaml" \
  --profile approved \
  stop filebrowser-enterprise
```

Remove the stopped container and this project's private network, still without
deleting bind-mounted data:

```bash
sudo docker compose \
  --env-file "$CONFIG_ROOT/.env" \
  -f "$SOURCE_ROOT/deploy/shared-host/compose.yaml" \
  -f "$SOURCE_ROOT/deploy/shared-host/compose.debug.yaml" \
  --profile approved \
  down --remove-orphans
```

## First administrator initialization

For the first start, `database.db` must be absent or empty and all three Secret
files must be present. Use the bootstrap password only through the normal login
and existing security workflow. After the database is initialized and the first
administrator is verified:

1. Stop the service.
2. Remove `bootstrap_admin_password` through the approved Secret destruction process.
3. Run full validation again; an initialized database now requires that file to be absent.
4. Start the same pinned image again and verify administrator login without the file.

The reviewed entrypoint refuses to restart an initialized database while the
bootstrap password file still exists. JWT and TOTP Secret files remain required.

## Functional acceptance

Before promotion, record at least the following against the pinned image:

- `/health` succeeds through `127.0.0.1:18081` and no non-loopback listener exists.
- The initialized administrator can log in after bootstrap Secret removal.
- Database, cache, and file data persist across a controlled restart.
- An ordinary new user receives exactly the approved source and default permissions.
- Browse, Preview, and Download succeed for approved test data.
- API, Admin, Share, Create, Modify, Delete, and Realtime actions are denied.
- WebDAV remains disabled.
- Large-file behavior, archive limits, logs, CPU/memory/PID limits, and graceful stop are acceptable.
- The recorded Git SHA, image ID, and Candidate/production digest match the change record.

`/health` alone is not storage, database, permission, or authentication evidence.

## Future ingress and networking

This FileBrowser-only phase has no Gateway dependency and no external Docker
network. Connecting a later approved `cf-edge` service or shared network is a
separate change with its own ingress, trust, permission, and rollback review.
Do not add that network, Gateway paths, Nginx, or 80/443 mappings locally to
these files.
