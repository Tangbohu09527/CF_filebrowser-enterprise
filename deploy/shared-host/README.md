# Shared-host: fixed-source installation and recovery

This is the `cf-filebrowser` project for a clean Debian 13 amd64 host. The base
Compose has one business service, no published ports, and a project-private
bridge. Debug adds only `127.0.0.1:18081`. The optional LAN override publishes
native HTTPS on an explicitly selected address and non-privileged port.

Do not mix in the historical exclusive-host `deploy/` Nginx, systemd, lifecycle,
or backup assets. This mode installs no FileBrowser systemd unit or timer,
shared Docker network, host Nginx, host database, or port 80/443 listener.

## 1. Required inputs and dependency preparation

Record these inputs before installation:

| Input | Requirement |
| --- | --- |
| Source | Full approved GitHub SHA, containing the V1 integration and deployment changes |
| Host | Debian 13, amd64, explicitly confirmed hostname |
| Storage | Independently mounted `/srv/storage`; an existing mount is required before any project path is created |
| Identity | UID/GID `10001:10001`, unused by host accounts/groups |
| Image | Actual image from the fixed-source build below; Candidate/production require an approved `repository@sha256:...` |
| Admin | Single-line bootstrap password, 24–4096 characters, in a protected root-owned input file |
| LAN (optional) | Assigned IPv4 address, port 1024–65535, explicit allowed client CIDRs, TLS DNS name, certificate/key/CA input files |
| Recovery | Archive, separately recorded SHA-256, exact source SHA/image reference/Image ID, and protected independent key custody |

The human management account stays separate from the service identity. It must
already have explicitly authorized `sudo` access from host provisioning; do not
add it to `root` or `docker`, or change sudo policy for this application. Run the
following blocks in order from that account. Each block runs in its own Bash
process and stops on failure, without changing the management shell's options.
Replace every input placeholder in each block from the approved inventory;
variables do not carry over between blocks. Record the displayed local Image ID.
Inspect the failed stage before continuing; do not delete existing configuration
to make a rerun pass.

The following signed APT setup follows [Docker's Debian installation instructions](https://docs.docker.com/engine/install/debian/).
It is for a clean Debian 13 amd64 host. The preflight stops if Docker packages,
a Docker APT source/key, or daemon overrides already exist: review that host's
existing installation separately instead of overwriting or removing it.

```bash
bash <<'PREPARE_DOCKER_APT'
set -euo pipefail
trap 'printf "Dependency preparation failed at line %s; inspect before continuing.\n" "$LINENO" >&2' ERR
test "$(id -u)" -ne 0
sudo -v
. /etc/os-release
test "$ID" = debian
test "$VERSION_ID" = 13
test "$(dpkg --print-architecture)" = amd64
test "$(ps -p 1 -o comm=)" = systemd
if id -nG | tr ' ' '\n' | grep -Eq '^(root|docker)$'; then
  printf 'Use the separately provisioned management account.\n' >&2
  exit 1
fi
installed=$(dpkg-query -W -f='${db:Status-Status} ${binary:Package}\n' |
  awk '$1 == "installed" && $2 ~ /^(docker[^ :]*|podman-docker|containerd(\.io)?|runc)(:amd64)?$/ {print $2}')
if test -n "$installed" || command -v docker >/dev/null; then
  printf 'Existing container packages/CLI require review before host preparation.\n%s\n' "$installed" >&2
  exit 1
fi
for path in /etc/apt/keyrings/docker.asc /etc/apt/keyrings/docker.gpg \
  /etc/apt/sources.list.d/docker.list /etc/apt/sources.list.d/docker.sources \
  /etc/docker/daemon.json /etc/systemd/system/docker.service \
  /etc/systemd/system/docker.service.d /etc/systemd/system/docker.socket.d; do
  if sudo test -e "$path" || sudo test -L "$path"; then
    printf 'Existing Docker configuration requires review: %s\n' "$path" >&2
    exit 1
  fi
done
if sudo grep -rlE 'download[.]docker[.]com' /etc/apt; then
  printf 'Existing Docker APT source requires review.\n' >&2
  exit 1
else
  test "$?" -eq 1
fi
sudo apt-get update
sudo apt-get install --no-upgrade --no-install-recommends \
  git ca-certificates curl openssl python3 python3-yaml util-linux iproute2 </dev/tty
sudo test ! -L /etc/apt/keyrings
if ! sudo test -d /etc/apt/keyrings; then
  sudo mkdir -m 0755 /etc/apt/keyrings
fi
sudo bash -c 'set -euo pipefail; set -o noclobber; umask 022
  curl --fail --silent --show-error https://download.docker.com/linux/debian/gpg > /etc/apt/keyrings/docker.asc'
sudo bash -c 'set -euo pipefail; set -o noclobber; umask 022
  cat > /etc/apt/sources.list.d/docker.sources' <<'DOCKER_SOURCE'
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: trixie
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.asc
DOCKER_SOURCE
sudo apt-get update
apt-cache madison docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
PREPARE_DOCKER_APT
```

Select exact available versions from that output. Engine and CLI use the same
version string; containerd, Buildx and the Docker Compose plugin have their own
versions. Compose must be at least 2.20. Run the next block from a terminal and
enter all four reviewed values when prompted. It refuses already installed
Docker packages and does not add an APT hold or run a system upgrade. Keep APT's
proposed changes reviewable; stop if they exceed the authorized host preparation.

```bash
bash <<'INSTALL_DOCKER'
set -euo pipefail
trap 'printf "Docker installation failed at line %s; inspect before continuing.\n" "$LINENO" >&2' ERR
installed=$(dpkg-query -W -f='${db:Status-Status} ${binary:Package}\n' |
  awk '$1 == "installed" && $2 ~ /^(docker[^ :]*|podman-docker|containerd(\.io)?|runc)(:amd64)?$/ {print $2}')
test -z "$installed"
read -r -p 'Exact Docker Engine and CLI version: ' DOCKER_VERSION </dev/tty
read -r -p 'Exact containerd.io version: ' CONTAINERD_VERSION </dev/tty
read -r -p 'Exact docker-buildx-plugin version: ' BUILDX_VERSION </dev/tty
read -r -p 'Exact docker-compose-plugin version (>=2.20): ' COMPOSE_VERSION </dev/tty
for version in "$DOCKER_VERSION" "$CONTAINERD_VERSION" "$BUILDX_VERSION" "$COMPOSE_VERSION"; do
  test -n "$version"
  [[ "$version" != *[[:space:]]* ]]
done
sudo apt-get install --no-upgrade --no-install-recommends \
  "docker-ce=$DOCKER_VERSION" "docker-ce-cli=$DOCKER_VERSION" \
  "containerd.io=$CONTAINERD_VERSION" "docker-buildx-plugin=$BUILDX_VERSION" \
  "docker-compose-plugin=$COMPOSE_VERSION" </dev/tty
sudo systemctl enable --now docker
sudo systemctl is-enabled docker
sudo systemctl is-active docker
dpkg-query -W -f='${binary:Package}\t${Version}\n' \
  git ca-certificates curl openssl python3 python3-yaml util-linux iproute2 \
  docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo docker version
sudo docker compose version
INSTALL_DOCKER
```

Save the package and Docker/Compose version output with the installation
evidence. On an already prepared host, review those same read-only version and
service checks rather than rerunning package installation. Continue with the
fixed checkout in section 2, then the formal `image.sh` and `manage.sh` stages;
those tools do not install packages or change users, RAID, disks, or mounts.

Docker uses its normal operating-system service/autostart. FileBrowser uses
Docker's `unless-stopped` policy; a deliberately stopped container stays stopped
until an explicit start. No FileBrowser systemd service or timer is installed.
Confirm normal Docker autostart during the host-reboot acceptance below.

Validate `/srv/storage` with `findmnt --mountpoint /srv/storage`. Never create a
same-named fallback on the root filesystem. Record RAID evidence separately when
applicable. `--test-disk` means a real independently mounted disposable Staging
disk; it does **not** certify RAID. Candidate/production retain the separately
reviewed `--raid-confirmed` contract.

## 2. Obtain a fixed GitHub checkout

For a new host, with a reviewed 40-character SHA:

```bash
bash <<'CHECKOUT_SOURCE'
set -euo pipefail
SOURCE_ROOT=/opt/cf-filebrowser-enterprise
APPROVED_SHA='REPLACE_WITH_APPROVED_FULL_GIT_SHA'
sudo test ! -e "$SOURCE_ROOT"
sudo git clone https://github.com/Tangbohu09527/CF_filebrowser-enterprise.git "$SOURCE_ROOT"
sudo git -C "$SOURCE_ROOT" fetch origin "$APPROVED_SHA"
sudo git -C "$SOURCE_ROOT" checkout --detach "$APPROVED_SHA"
sudo git -C "$SOURCE_ROOT" rev-parse HEAD
sudo git -C "$SOURCE_ROOT" status --short
CHECKOUT_SOURCE
```

An existing checkout must already match the approved SHA and be clean. The
management tools refuse mismatches; they never reset, clean, switch branches,
or overwrite a checkout. Do not deploy a moving branch, `latest` application
tag, an old computer's image tag, or copied/uncommitted workstation assets.

## 3. Build, identify and transfer the real image

```bash
bash <<'BUILD_IMAGE'
set -euo pipefail
SOURCE_ROOT=/opt/cf-filebrowser-enterprise
APPROVED_SHA='REPLACE_WITH_APPROVED_FULL_GIT_SHA'
sudo bash "$SOURCE_ROOT/deploy/shared-host/image.sh" build \
  --source-sha "$APPROVED_SHA" --version "verified-$APPROVED_SHA" \
  --image "cf-filebrowser:verified-$APPROVED_SHA" \
  --evidence /root/cf-build-evidence-UNIQUE
BUILD_IMAGE
```

The evidence directory must not exist and must be outside the checkout. The
entry point resolves all four base images to registry digests and passes those
immutable references to the existing Compose build override and Dockerfile.
The frontend uses the committed lockfile with `npm ci`; the backend build uses
read-only module resolution. Evidence includes input hashes, source SHA, base
image IDs/digests, Docker/Compose versions and the actual application Image ID.
The image contains resolved Go modules, the frontend lockfile, tool versions and
installed system packages under `/usr/share/filebrowser/build-inputs`.

The default base tags retain the repository's existing choices. To replay the
same base inputs, pass the recorded `--ffmpeg-image`, `--go-image`, `--node-image`
and `--runtime-image` digest references. System package repositories can change;
keep the resolved package evidence and the approved built image. A source SHA
alone is not a claim of bit-for-bit reproducible third-party repositories.

A local staging image is not a remotely obtainable release. In an **isolated,
explicitly approved test registry**, with trusted TLS and normal protected
Docker authentication already configured:

```bash
bash <<'PUBLISH_TEST_IMAGE'
set -euo pipefail
SOURCE_ROOT=/opt/cf-filebrowser-enterprise
APPROVED_SHA='REPLACE_WITH_APPROVED_FULL_GIT_SHA'
APPROVED_IMAGE='EXACT_BUILT_STAGING_REFERENCE'
IMAGE_ID=$(sudo docker image inspect "$APPROVED_IMAGE" --format '{{.Id}}')
printf 'Local Image ID: %s\n' "$IMAGE_ID"
TEST_REGISTRY='registry.test:5000'
sudo bash "$SOURCE_ROOT/deploy/shared-host/image.sh" publish \
  --source-sha "$APPROVED_SHA" --image "$IMAGE_ID" \
  --target "$TEST_REGISTRY/filebrowser:$APPROVED_SHA" \
  --approved-registry "$TEST_REGISTRY" --evidence /root/cf-publish-evidence-UNIQUE
PUBLISH_TEST_IMAGE
```

On the second host, set the resulting complete `repository@sha256:...` reference
in this independent block before pulling it. Verify the approved RepoDigest and
revision label, and record its **local** Image ID for lifecycle/backup operations:

```bash
bash <<'PULL_RECOVERY_IMAGE'
set -euo pipefail
APPROVED_IMAGE='EXACT_APPROVED_REGISTRY_DIGEST'
sudo docker pull --platform linux/amd64 "$APPROVED_IMAGE"
sudo docker image inspect "$APPROVED_IMAGE" --format '{{json .RepoDigests}}'
sudo docker image inspect "$APPROVED_IMAGE" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'
IMAGE_ID=$(sudo docker image inspect "$APPROVED_IMAGE" --format '{{.Id}}')
printf 'Local Image ID: %s\n' "$IMAGE_ID"
PULL_RECOVERY_IMAGE
```

Docker's classic and containerd image stores can identify the same approved
content differently (configuration versus manifest/index digest). Do not
substitute an unrelated ID or compare cross-store IDs as the sole integrity
check. Keep the immutable registry digest and build-input record; the CI transfer
check additionally verifies manifest/config SHA-256, runtime configuration,
root filesystem layers and the local container identity. Restore requires the
same recorded local Image ID, so use the matching Docker image-store contract
on the recovery host; incompatibility is refused.

 The test publication helper does not
publish to Docker Hub or GHCR. Promotion to an organization's production
registry is a separate explicitly approved publication operation using the
same verified image and recorded destination digest; this delivery never
publishes a production image. Do not use `--insecure`, disable certificate
verification, or transmit registry credentials in command arguments.

## 4. Prepare configuration, storage and secrets

Required roots are fixed:

```text
/opt/cf-filebrowser-enterprise
/etc/cf-filebrowser-enterprise/.env
/var/lib/cf-filebrowser-enterprise
/var/cache/cf-filebrowser-enterprise
/srv/storage/cf-filebrowser-enterprise/files
/srv/storage/cf-filebrowser-enterprise/backups
```

Create a protected **input** password through your secret-management procedure.
For a new isolated installation, an example that refuses to overwrite a file is:

```bash
bash <<'PREPARE_PASSWORD_INPUT'
set -euo pipefail
sudo install -d -o root -g root -m 0700 /root/cf-install-inputs
sudo bash -c 'umask 077; set -o noclobber; openssl rand -hex 24 > "$1"' \
  bash /root/cf-install-inputs/admin-password
PREPARE_PASSWORD_INPUT
```

Keep this input independently protected for administrator login and interrupted
bootstrap recovery. Never paste the password into flags, YAML, `.env`, logs,
Git, or CI output. `prepare` generates JWT and TOTP keys without printing them.
It preserves an existing valid deployment on identical reruns and refuses
partial or conflicting installations instead of filling them with new secrets.

```bash
bash <<'PREPARE_DEPLOYMENT'
set -euo pipefail
SOURCE_ROOT=/opt/cf-filebrowser-enterprise
APPROVED_SHA='REPLACE_WITH_APPROVED_FULL_GIT_SHA'
HOSTNAME_APPROVED='EXACT_TARGET_HOSTNAME'
APPROVED_IMAGE='EXACT_BUILT_STAGING_REFERENCE_OR_APPROVED_REGISTRY_DIGEST'
sudo bash "$SOURCE_ROOT/deploy/shared-host/manage.sh" check --hostname "$HOSTNAME_APPROVED"
IMAGE_ID=$(sudo docker image inspect "$APPROVED_IMAGE" --format '{{.Id}}')
printf 'Local Image ID: %s\n' "$IMAGE_ID"
sudo bash "$SOURCE_ROOT/deploy/shared-host/manage.sh" prepare \
  --hostname "$HOSTNAME_APPROVED" --source-sha "$APPROVED_SHA" \
  --image-ref "$APPROVED_IMAGE" --mode staging --test-disk --exposure debug \
  --bootstrap-password-file /root/cf-install-inputs/admin-password
PREPARE_DEPLOYMENT
```

For LAN, select `--exposure lan` **during prepare** and additionally provide
`--lan-bind-address IP --lan-port PORT --lan-allowed-cidrs CIDR[,CIDR...]`,
`--tls-name DNS_NAME`, `--tls-cert-file /PROTECTED/server.crt`,
`--tls-key-file /PROTECTED/server.key`, and `--tls-ca-file /PROTECTED/ca.crt`.
Inputs and their parents must have the protected ownership/modes checked by the
entry point. The certificate must cover the selected DNS name and pass strict X.509 chain
and server-auth purpose verification against the provided CA. In particular,
CA certificates need valid CA basic constraints and certificate-signing Key
Usage; client-only leaf certificates are rejected. Prepare and every runtime
validation/start enforce this policy. Existing deployment settings are not
silently replaced by prepare.

The server enforces the explicit CIDRs against the actual TCP peer, before
HTTP/TLS processing, including all UI/API/WebDAV routes. It does not trust
`X-Forwarded-For` or `X-Real-IP`. Loopback is separately allowed for container
health. Bind address selection alone is not source authorization. A network
that rewrites all peers through a proxy/NAT cannot be treated as verified
source isolation: test allowed and denied clients over the real Docker
publication path before approval. Do not broaden the allowlist to a gateway
to make a failing negative test pass.

## 5. First start and mandatory bootstrap completion

```bash
bash <<'COMPLETE_BOOTSTRAP'
set -euo pipefail
SOURCE_ROOT=/opt/cf-filebrowser-enterprise
HOSTNAME_APPROVED='EXACT_TARGET_HOSTNAME'
sudo bash "$SOURCE_ROOT/deploy/shared-host/manage.sh" validate --hostname "$HOSTNAME_APPROVED"
sudo bash "$SOURCE_ROOT/deploy/shared-host/manage.sh" start --hostname "$HOSTNAME_APPROVED"
sudo bash "$SOURCE_ROOT/deploy/shared-host/manage.sh" bootstrap-finish --hostname "$HOSTNAME_APPROVED"
sudo bash "$SOURCE_ROOT/deploy/shared-host/manage.sh" status --hostname "$HOSTNAME_APPROVED"
COMPLETE_BOOTSTRAP
```

`bootstrap-finish` performs a normal password login and verifies the authenticated
administrator, stops the container, removes only the one-time bootstrap file,
restarts the same Image ID, verifies administrator login again, and records
completion. An initialized database with a residual bootstrap file remains a
startup error. Never delete the database to retry. Failure preserves the stage
and data; after interrupted removal, use the retained protected input with
`--admin-password-file` as instructed by the error. JWT/TOTP keys remain required.

The source is private by default. If this installation requires Share, pass
`--enable-share-source` explicitly during `prepare`; it permits sharing from
this source without granting Share to ordinary users. Repeated preparation must
retain the same decision. Grant and test individual user Share permissions in
the existing administration interface.

The ordinary default user has Browse/Preview/Download; API, Admin, Share,
Create, Modify, Delete and Realtime are initially denied. Review these source
and default grants before promotion. WebDAV/OnlyOffice code and tests remain
present. To enable WebDAV, pass `--enable-webdav` during `prepare`; repeated
preparation must retain that choice. The existing user and Token permission
checks still apply. OnlyOffice requires a separately configured real Document
Server and actual client acceptance. Storing a document does not prove its
preview/editor works.

## 6. Normal operation and restarts

Use `manage.sh status`, `stop`, `validate` and `start`, each with the confirmed
hostname. Start performs no implicit build or pull. The shared lock prevents
management and backup/restore from running concurrently. Data and files are
bind-mounted; cache may be regenerated.

The installation writes a protected expected storage identity in configuration
and a matching marker on the independently mounted storage. All Compose binds
use `create_host_path: false`. Missing mounts/markers prevent startup; mismatched
markers fail before secrets or database initialization. If the disk arrives
late, verify the real mount and rerun the normal start. Do not copy the marker
onto the root filesystem or loosen checks. Test container recreation and a real
host reboot; a successful health check is not persistence evidence.

## 7. Controlled backup and blank-machine recovery

Backups stop only this project's containers and leave the service stopped.
They include business files, the entire data directory (database and persistent
audit), configuration, deployment metadata, JWT/TOTP and required TLS material.
Cache and one-time bootstrap credentials are excluded. Files must satisfy the
reviewed metadata rules; links, devices, unsupported modes and unsafe paths
cause refusal rather than following paths outside the project.

```bash
bash <<'CREATE_BACKUP'
set -euo pipefail
SOURCE_ROOT=/opt/cf-filebrowser-enterprise
APPROVED_SHA='REPLACE_WITH_APPROVED_FULL_GIT_SHA'
HOSTNAME_APPROVED='EXACT_TARGET_HOSTNAME'
APPROVED_IMAGE='EXACT_IMAGE_REFERENCE_RECORDED_FOR_THIS_DEPLOYMENT'
IMAGE_ID=$(sudo docker image inspect "$APPROVED_IMAGE" --format '{{.Id}}')
printf 'Local Image ID: %s\n' "$IMAGE_ID"
ARCHIVE=/srv/storage/cf-filebrowser-enterprise/backups/backup-UNIQUE.tar
sudo bash "$SOURCE_ROOT/deploy/shared-host/backup.sh" create "$ARCHIVE" \
  --hostname "$HOSTNAME_APPROVED" --source-sha "$APPROVED_SHA" \
  --image-ref "$APPROVED_IMAGE" --image-id "$IMAGE_ID"
# Independently record the emitted SHA-256 before optionally starting again.
sudo bash "$SOURCE_ROOT/deploy/shared-host/manage.sh" start --hostname "$HOSTNAME_APPROVED"
CREATE_BACKUP
```

The package contains keys and must remain root-only (0600 inside 0700 backup
storage), encrypted under your approved off-device backup process. Keep a
separately protected, independently retrievable copy of persistent keys and
the source/image/digest inventory. An archive's internal manifest is not proof
of authenticity if an attacker can replace the archive and manifest together.
Do not upload packages, keys, sessions or VM disks as CI artifacts.

For off-device transfer, use an explicitly approved SSH destination with pinned
host identity and a protected receiving directory; authenticate with protected
SSH keys, copy over SSH/SFTP without exposing the archive to normal users, and
compare the recorded SHA-256 at both ends. No external account is accessed by
these tools. A backup on the same RAID is not off-device disaster recovery.

On a second clean Debian host: prepare Docker and the independent storage mount,
obtain the **same** fixed GitHub checkout and registry image, retrieve the
protected package from independent custody, and run:

```bash
bash <<'RESTORE_BACKUP'
set -euo pipefail
SOURCE_ROOT=/opt/cf-filebrowser-enterprise
APPROVED_SHA='REPLACE_WITH_APPROVED_FULL_GIT_SHA'
HOSTNAME_APPROVED='EXACT_TARGET_HOSTNAME'
APPROVED_IMAGE='EXACT_IMAGE_REFERENCE_RECORDED_IN_BACKUP'
RECORDED_BACKUP_SHA256='REPLACE_WITH_INDEPENDENTLY_RECORDED_SHA256'
IMAGE_ID=$(sudo docker image inspect "$APPROVED_IMAGE" --format '{{.Id}}')
printf 'Local Image ID: %s\n' "$IMAGE_ID"
sudo bash "$SOURCE_ROOT/deploy/shared-host/backup.sh" restore /root/recovery/package.tar \
  --hostname "$HOSTNAME_APPROVED" --source-sha "$APPROVED_SHA" \
  --image-ref "$APPROVED_IMAGE" --image-id "$IMAGE_ID" --sha256 "$RECORDED_BACKUP_SHA256"
sudo bash "$SOURCE_ROOT/deploy/shared-host/manage.sh" validate --hostname "$HOSTNAME_APPROVED"
sudo bash "$SOURCE_ROOT/deploy/shared-host/manage.sh" start --hostname "$HOSTNAME_APPROVED"
RESTORE_BACKUP
```

Do **not** run `prepare` before blank recovery. Restore validates the complete
archive, external hash, source/image/version and empty targets before creating
project roots. It rejects existing data, incomplete/corrupted packages, unsafe
permissions, traversal, links and incompatible versions. It rotates the storage
identity for the new disk and keeps the recovered service stopped until explicit
validation/start. Partial write failures retain the recovery scene and never
start a partially restored database. No bootstrap secret is needed.

For LAN recovery, reserve the approved service address/DNS for the replacement
machine with the original offline; confirm certificate identity and allowed
clients before starting. Host network reconfiguration is an explicit operator
operation, not performed by restore. Verify file hashes, administrator login,
ordinary-user permissions, active and revoked Tokens/Shares, audit and real
read/write after recovery. Merely listing archive members is not recovery proof.

Code/image rollback and database restoration are separate. Restore requires an
exact source/image match. A database already migrated by newer code must not be
opened with an arbitrary older image; use the matching pre-upgrade backup in an
empty recovery environment. Existing synthetic migration failure tests remain
part of backend regression; production databases are never test inputs.

## Validation and evidence boundaries

Use `make validate-deployment` for existing deployment tests (including new
shared-host tests), `make test-backend`, `make lint-backend`, frontend
`npm run typecheck`, `make lint-frontend test-frontend`, and the existing
`make test-playwright`. Every Shell file is checked individually with `bash -n`.
The `shared-host-delivery` workflow targets the integration PR and builds the
real frontend/backend image; it does not publish a production artifact.

Record each actual run against source SHA, Image ID/registry digest, VM image
checksum, OS/tool versions and sanitized results. Distinguish A (isolated real
Docker), B (clean Debian 13 VM with systemd and actual reboot/blank recovery),
and C (real target device/client). Only mark a row passed after that run.
WebDAV, OnlyOffice, browser previews and FileBridge HTTPS/minimum-permission
checks each require their own real-client evidence. An independent FileBridge
client does not certify Hermes or a WeChat file chain.

The persistent audit store and signed pagination cursor are not a WORM archive.
Backup checksums do not add WORM or externally witnessed tamper-proof storage.
