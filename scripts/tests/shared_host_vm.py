#!/usr/bin/env python3
"""Real Debian 13/systemd acceptance on two disposable GitHub CI VMs.

Never run this on a deployment host. Only the dedicated evidence directory is
publishable: VM disks, SSH/TLS private keys, API state and backups are private.
The caller builds the product first with deploy/shared-host/image.sh build.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
PRODUCT = "https://github.com/Tangbohu09527/CF_filebrowser-enterprise.git"
CLOUD = "https://cloud.debian.org/images/cloud/trixie/latest/"
CLOUD_IMAGE = "debian-13-genericcloud-amd64.qcow2"
VM_USER = "cf-manager"
SERVER_IP = "192.0.2.11"
CLIENT_IP = "192.0.2.12"
DENIED_IP = "192.0.2.99"
TLS_NAME = "files.cf.test"
TLS_PORT = 18443
GUEST = "/root/cf-verification"
SOURCE = "/opt/cf-filebrowser-enterprise"
GIB = 1024 ** 3
SYSTEM_DISK_GIB = 24
TEST_DISK_GIB = 11
VM_MEMORY_MIB = 2048


class VerificationError(RuntimeError):
    pass


def execute(command, *, input_bytes=None, timeout=900, check=True):
    result = subprocess.run(command, input=input_bytes, capture_output=True, timeout=timeout, check=False)
    if check and result.returncode:
        # SSH/API output can contain secrets. Never reflect raw subprocess text.
        raise VerificationError(f"{Path(command[0]).name} failed with exit {result.returncode}; private output retained only in process memory")
    return result


def private_write(path, value, mode=0o600):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as output:
        output.write(value.encode() if isinstance(value, str) else value)


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def download(url, destination):
    request = urllib.request.Request(url, headers={"User-Agent": "CF-isolated-delivery-verification/1"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response, destination.open("xb") as output:
            shutil.copyfileobj(response, output)
    except OSError as error:
        raise VerificationError("official Debian download failed for " + url.rsplit("/", 1)[-1] + "; partial download retained") from error


def cloud_image(work):
    manifest = work / "SHA512SUMS"
    download(CLOUD + "SHA512SUMS", manifest)
    expected = None
    for line in manifest.read_text().splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].lstrip("*") == CLOUD_IMAGE and re.fullmatch(r"[0-9a-f]{128}", fields[0]):
            expected = fields[0]
    if expected is None:
        raise VerificationError("official Debian manifest does not identify the requested cloud image")
    path = work / CLOUD_IMAGE
    download(CLOUD + CLOUD_IMAGE, path)
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha512").hexdigest()
    if actual != expected:
        raise VerificationError("Debian image does not match the official SHA512 manifest")
    return path, {"url": CLOUD + CLOUD_IMAGE, "sha512": actual, "checksum_url": CLOUD + "SHA512SUMS"}


def resource_budget(base_virtual_bytes, seed_bytes=2 * 16 * 1024 ** 2):
    total = 2 * (SYSTEM_DISK_GIB + TEST_DISK_GIB) * GIB + base_virtual_bytes + seed_bytes
    memory = 2 * VM_MEMORY_MIB * 1024 ** 2
    # QEMU's G/M disk and memory inputs are binary; the authorized GB limits are decimal.
    if total > 80_000_000_000 or memory > 8_000_000_000:
        raise VerificationError("two-VM resource budget exceeds 8 GB RAM or 80 GB total sparse disk capacity; no automatic expansion is allowed")
    return {"vm_count": 2, "system_disk_gib_per_vm": SYSTEM_DISK_GIB, "test_disk_gib_per_vm": TEST_DISK_GIB,
            "base_virtual_bytes": base_virtual_bytes, "seed_bytes": seed_bytes, "total_virtual_disk_bytes": total,
            "maximum_virtual_disk_bytes": 80_000_000_000, "configured_memory_bytes": memory, "maximum_memory_bytes": 8_000_000_000}


class VM:
    def __init__(self, number, work, base, ssh_key, peer_port, accelerator):
        self.number = number
        self.name = f"cf-verification-{number}"
        self.directory = work / self.name
        self.directory.mkdir(mode=0o700)
        self.ssh_port = port()
        self.ssh_key = ssh_key
        self.process = None
        self.tunnel = None
        self.ip = SERVER_IP if number == 1 else CLIENT_IP
        host_key = self.directory / "ssh_host_ed25519_key"
        execute(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(host_key)])
        host_public = host_key.with_suffix(".pub").read_text().split()
        known = self.directory / "known_hosts"
        private_write(known, f"[127.0.0.1]:{self.ssh_port} {' '.join(host_public[:2])}\n")
        self.ssh_options = ["-i", str(ssh_key), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known}", "-o", "ConnectTimeout=5", "-p", str(self.ssh_port)]
        public = ssh_key.with_suffix(".pub").read_text().strip()
        private = "\n".join("    " + line for line in host_key.read_text().splitlines())
        user_data = f"""#cloud-config
hostname: {self.name}
manage_etc_hosts: true
disable_root: true
ssh_pwauth: false
users:
  - name: {VM_USER}
    uid: 1000
    groups: [users]
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    shell: /bin/bash
    lock_passwd: true
    ssh_authorized_keys:
      - {public}
ssh_keys:
  ed25519_private: |
{private}
  ed25519_public: {host_key.with_suffix('.pub').read_text().strip()}
write_files:
  - path: /run/cf-shared-host-disposable
    owner: root:root
    permissions: '0400'
    content: '{self.name}'
  - path: /etc/cf-shared-host-disposable
    owner: root:root
    permissions: '0400'
    content: '{self.name}'
"""
        nat_mac = f"52:54:00:00:{number:02x}:01"
        lan_mac = f"52:54:00:00:{number:02x}:02"
        network = f"""version: 2
ethernets:
  nat:
    match:
      macaddress: '{nat_mac}'
    set-name: cfnat
    dhcp4: true
  lan:
    match:
      macaddress: '{lan_mac}'
    set-name: cflan
    dhcp4: false
    addresses: [{self.ip}/24]
"""
        for name, value in (("user-data", user_data), ("network-config", network), ("meta-data", f"instance-id: {self.name}\nlocal-hostname: {self.name}\n")):
            private_write(self.directory / name, value)
        seed = self.directory / "seed.iso"
        execute(["cloud-localds", "--network-config", str(self.directory / "network-config"), str(seed), str(self.directory / "user-data"), str(self.directory / "meta-data")])
        disk = self.directory / "system.qcow2"
        data = self.directory / "test-storage.qcow2"
        execute(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base), str(disk), f"{SYSTEM_DISK_GIB}G"])
        execute(["qemu-img", "create", "-f", "qcow2", str(data), f"{TEST_DISK_GIB}G"])
        peer = f"listen=127.0.0.1:{peer_port}" if number == 1 else f"connect=127.0.0.1:{peer_port}"
        self.command = ["qemu-system-x86_64", "-accel", accelerator, "-machine", "q35", "-m", str(VM_MEMORY_MIB), "-smp", "2", "-display", "none", "-monitor", "none", "-serial", f"file:{self.directory / 'serial.private.log'}", "-drive", f"file={disk},format=qcow2,if=none,id=system", "-device", "virtio-blk-pci,drive=system", "-drive", f"file={data},format=qcow2,if=none,id=storage", "-device", "virtio-blk-pci,drive=storage,serial=cf-test-data", "-drive", f"file={seed},format=raw,if=none,id=seed,readonly=on", "-device", "virtio-blk-pci,drive=seed", "-netdev", f"user,id=nat,hostfwd=tcp:127.0.0.1:{self.ssh_port}-:22", "-device", f"virtio-net-pci,netdev=nat,mac={nat_mac}", "-netdev", f"socket,id=lan,{peer}", "-device", f"virtio-net-pci,netdev=lan,mac={lan_mac}"]

    def launch(self):
        # QEMU >= 3.0 requires serial on -device, not -drive. Keep the
        # system/storage/seed virtio devices explicit and ordered (vda/vdb/vdc).
        # Guest serial output and QEMU host diagnostics are separate private logs.
        log_path = self.directory / "qemu.private.stderr.log"
        descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stderr:
            self.process = subprocess.Popen(self.command, stdout=subprocess.DEVNULL, stderr=stderr)

    def startup_diagnostic(self):
        log_path = self.directory / "qemu.private.stderr.log"
        raw = log_path.read_bytes() if log_path.exists() else b""
        # Report only fixed, recognized causes; never arbitrary stderr, paths,
        # key contents or guest console output. Preserve the private original.
        causes = (
            (b"does not support the option 'serial'", "unsupported-drive-serial"),
            (b"Address already in use", "listener-address-in-use"),
            (b"Connection refused", "peer-listener-not-ready"),
            (b"Permission denied", "host-resource-permission-denied"),
            (b"Cannot allocate memory", "insufficient-host-memory"),
            (b"No space left on device", "insufficient-host-disk-space"),
            (b"Failed to get", "image-lock-or-resource-unavailable"),
        )
        cause = next((label for marker, label in causes if marker in raw), "unclassified-qemu-startup-error")
        return {"exit_code": self.process.poll(), "cause": cause, "private_stderr_sha256": hashlib.sha256(raw).hexdigest(), "private_stderr_bytes": len(raw)}

    def command_on_guest(self, script, *, check=True, timeout=900):
        guard = f"set -Eeuo pipefail\ntest \"$(cat /etc/cf-shared-host-disposable)\" = {shlex.quote(self.name)}\ntest \"$(hostname)\" = {shlex.quote(self.name)}\n"
        # Only a numeric line marker is reflected from guest stderr. Arbitrary
        # command/API output remains private, including on authentication failure.
        guard += "trap 'printf \"[cf-vm-command-error] line=%s\\n\" \"$LINENO\" >&2' ERR\n"
        result = execute(["ssh", *self.ssh_options, VM_USER + "@127.0.0.1", "sudo", "-n", "bash", "-s"], input_bytes=(guard + script).encode(), check=False, timeout=timeout)
        if check and result.returncode:
            lines = re.findall(rb"\[cf-vm-command-error\] line=(\d+)", result.stderr)
            detail = "; submitted guest-script line " + lines[-1].decode() if lines else ""
            # Only lifecycle.py's explicitly sanitized error contract is added.
            # Never include arbitrary command stderr, authentication or API text.
            safe = re.findall(rb"^\[shared-host (?:check|prepare|validate|start|bootstrap-finish|stop|status)\] ERROR: [ -~]{1,500}$", result.stderr, re.MULTILINE)
            if safe:
                detail += "; " + safe[-1].decode("ascii")
            error = VerificationError(f"{self.name}: SSH guest action failed (exit {result.returncode})" + detail)
            error.guest_exit_code = result.returncode
            raise error
        return result

    def wait_ready(self):
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                diagnostic = self.startup_diagnostic()
                raise VerificationError(f"{self.name}: QEMU exited during boot (exit {diagnostic['exit_code']}); {diagnostic['cause']}; private stderr SHA-256 {diagnostic['private_stderr_sha256']}")
            result = self.command_on_guest("true", check=False)
            if result.returncode == 0:
                self.command_on_guest("cloud-init status --wait >/dev/null", timeout=600)
                return
            time.sleep(3)
        raise VerificationError(f"{self.name}: SSH/cloud-init did not become ready")

    def write_file(self, path, data, mode="0600"):
        # Values enter SSH stdin, not command arguments, environment or logs.
        command = f"umask 077; mkdir -p {GUEST}; cat > {shlex.quote(path)}; chmod {mode} {shlex.quote(path)}"
        execute(["ssh", *self.ssh_options, VM_USER + "@127.0.0.1", "sudo", "-n", "bash", "-c", shlex.quote(command)], input_bytes=data)

    def read_file(self, path):
        return self.command_on_guest("cat -- " + shlex.quote(path)).stdout

    def forward_registry(self, registry_port):
        self.tunnel = subprocess.Popen(["ssh", *self.ssh_options, "-o", "ExitOnForwardFailure=yes", "-N", "-R", f"127.0.0.1:{registry_port}:127.0.0.1:{registry_port}", VM_USER + "@127.0.0.1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        if self.tunnel.poll() is not None:
            raise VerificationError(f"{self.name}: isolated registry forwarding failed")

    def reboot(self):
        before = self.read_file("/proc/sys/kernel/random/boot_id").decode().strip()
        self.command_on_guest("systemctl reboot", check=False)
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            result = self.command_on_guest("cat /proc/sys/kernel/random/boot_id", check=False)
            if result.returncode == 0 and result.stdout.decode().strip() != before:
                return {"before": before, "after": result.stdout.decode().strip()}
            time.sleep(3)
        raise VerificationError(f"{self.name}: real host boot ID did not change")

    def close(self):
        for process in (self.tunnel, self.process):
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


def prerequisites(vm, revision, *, storage_only=False):
    source_setup = "" if storage_only else f"""
test ! -e {SOURCE}
git clone {PRODUCT} {SOURCE}
git -C {SOURCE} fetch origin {revision}
git -C {SOURCE} checkout --detach {revision}
test "$(git -C {SOURCE} rev-parse HEAD)" = {revision}
test -z "$(git -C {SOURCE} status --porcelain=v1)"
bash {SOURCE}/deploy/shared-host/manage.sh check --hostname {vm.name}
"""
    vm.command_on_guest(f"""
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install --yes --no-install-recommends ca-certificates curl git python3-yaml openssl util-linux iproute2 e2fsprogs strace
install -d -m 0755 /etc/apt/keyrings
curl --fail --silent --show-error https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod 0644 /etc/apt/keyrings/docker.asc
cat > /etc/apt/sources.list.d/docker.sources <<'DOCKER_SOURCE'
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: trixie
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.asc
DOCKER_SOURCE
apt-get update -qq
apt-get install --yes --no-install-recommends docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
test "$(ps -p 1 -o comm=)" = systemd
systemctl is-enabled docker >/dev/null
systemctl is-active docker >/dev/null
! id -nG {VM_USER} | tr ' ' '\\n' | grep -Eq '^(root|docker)$'
test "$(lsblk -dn -o SERIAL /dev/vdb | tr -d ' ')" = cf-test-data
test -z "$(blkid -o value -s TYPE /dev/vdb || true)"
mkfs.ext4 -q -L cf-test-storage /dev/vdb
install -d -o root -g root -m 0755 /srv/storage
uuid=$(blkid -o value -s UUID /dev/vdb)
printf 'UUID=%s /srv/storage ext4 defaults,nofail,x-systemd.device-timeout=5s 0 2\\n' "$uuid" >> /etc/fstab
mount /srv/storage
install -d -o root -g root -m 0700 {GUEST}
printf '{SERVER_IP} {TLS_NAME}\\n' >> /etc/hosts
{source_setup}
""", timeout=1800)


def certificates(work):
    directory = work / "tls"
    directory.mkdir(mode=0o700)
    ca_key, ca = directory / "ca.key", directory / "ca.crt"
    # Debian 13's Python client keeps X509_STRICT enabled. Make the test CA's
    # signing authority explicit instead of relying on ambient openssl.cnf.
    ca_extensions = ["-addext", "basicConstraints=critical,CA:TRUE",
                     "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                     "-addext", "subjectKeyIdentifier=hash",
                     "-addext", "authorityKeyIdentifier=keyid:always"]
    execute(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3", "-subj", "/CN=CF disposable verification CA", "-keyout", str(ca_key), "-out", str(ca), *ca_extensions])
    execute(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3", "-subj", "/CN=Untrusted isolated test CA", "-keyout", str(directory / "untrusted-ca.key"), "-out", str(directory / "untrusted-ca.crt"), *ca_extensions])
    for name, san in (("registry", "DNS:localhost,IP:127.0.0.1"), ("server", "DNS:" + TLS_NAME)):
        key, csr, cert = (directory / (name + suffix) for suffix in (".key", ".csr", ".crt"))
        execute(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + ("localhost" if name == "registry" else TLS_NAME), "-keyout", str(key), "-out", str(csr)])
        extension = directory / (name + ".extensions")
        private_write(extension, "basicConstraints=critical,CA:FALSE\n"
                      "keyUsage=critical,digitalSignature,keyEncipherment\n"
                      "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
                      f"subjectAltName={san}\nextendedKeyUsage=serverAuth\n")
        execute(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key), "-CAcreateserial", "-days", "3", "-extfile", str(extension), "-out", str(cert)])
    return directory



def decode_registry_blob(payload, digest):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) or "sha256:" + hashlib.sha256(payload).hexdigest() != digest:
        raise VerificationError("registry blob does not match its immutable SHA-256 digest")
    return json.loads(payload)


def registry_identity(reference, ca_file):
    match = re.fullmatch(r"(localhost:[0-9]+)/cf-filebrowser@(sha256:[0-9a-f]{64})", reference)
    if not match:
        raise VerificationError("identity verification requires the isolated localhost registry and fixed digest")
    authority, pinned = match.groups()
    context = ssl.create_default_context(cafile=str(ca_file))

    def read(kind, digest):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise VerificationError("invalid registry descriptor digest")
        request = urllib.request.Request(f"https://{authority}/v2/cf-filebrowser/{kind}/{digest}", headers={"Accept": "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"})
        with urllib.request.urlopen(request, context=context, timeout=60) as response:
            payload = response.read(2 * 1024 * 1024 + 1)
        if len(payload) > 2 * 1024 * 1024:
            raise VerificationError("registry metadata exceeds the bounded identity document size")
        return decode_registry_blob(payload, digest)

    manifest = read("manifests", pinned)
    manifest_digest = pinned
    if "manifests" in manifest:
        platforms = [item for item in manifest["manifests"] if item.get("platform", {}).get("os") == "linux" and item.get("platform", {}).get("architecture") == "amd64"]
        if len(platforms) != 1:
            raise VerificationError("registry index must identify exactly one Linux amd64 image")
        manifest_digest = platforms[0]["digest"]
        manifest = read("manifests", manifest_digest)
    if manifest.get("schemaVersion") != 2 or "config" not in manifest:
        raise VerificationError("registry identity requires a schema-2 image manifest")
    config_digest = manifest["config"]["digest"]
    config = read("blobs", config_digest)
    return {"registry_reference": reference, "registry_digest": pinned, "manifest_digest": manifest_digest, "config_digest": config_digest, "config": config}


def normalized_image_config(value):
    # Docker inspect serializes optional zero values differently across API
    # versions. Only omit those empty values; preserve every populated field.
    if isinstance(value, dict):
        return {key: normalized_image_config(item) for key, item in value.items() if item not in (None, "", [], {}, False, 0)}
    if isinstance(value, list):
        return [normalized_image_config(item) for item in value]
    return value


def image_identity_record(info):
    configuration = normalized_image_config(info.get("Config", {}))
    descriptor = info.get("Descriptor") or {}
    return {"image_id": info.get("Id"), "descriptor": {key: descriptor[key] for key in ("digest", "mediaType", "size", "platform") if key in descriptor}, "repo_digests": info.get("RepoDigests", []), "os": info.get("Os"), "architecture": info.get("Architecture"), "source_sha": info.get("Config", {}).get("Labels", {}).get("org.opencontainers.image.revision"), "runtime_config_sha256": hashlib.sha256(json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), "rootfs": info.get("RootFS", {})}


def verify_image_identity(info, expected, revision):
    config = expected["config"]
    if expected["registry_reference"] not in info.get("RepoDigests", []):
        raise VerificationError("local image RepoDigests does not contain the verified registry reference")
    # Legacy image stores identify the config; containerd stores identify the
    # target manifest/index. Both must be in this cryptographically checked graph.
    if info.get("Id") not in {expected["config_digest"], expected["manifest_digest"], expected["registry_digest"]}:
        raise VerificationError("local Image ID is outside the verified registry manifest/config graph")
    descriptor = info.get("Descriptor") or {}
    if descriptor and descriptor.get("digest") != expected["registry_digest"]:
        raise VerificationError("local descriptor differs from the pinned registry target")
    if (info.get("Os"), info.get("Architecture"), config.get("os"), config.get("architecture")) != ("linux", "amd64", "linux", "amd64"):
        raise VerificationError("local and registry image must both be Linux amd64")
    if info.get("Config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != revision or config.get("config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != revision:
        raise VerificationError("local or registry image has an unexpected source revision")
    if normalized_image_config(info.get("Config", {})) != normalized_image_config(config.get("config", {})):
        raise VerificationError("local runtime configuration differs from the verified registry config blob")
    rootfs = info.get("RootFS", {})
    if rootfs.get("Type") != config.get("rootfs", {}).get("type") or rootfs.get("Layers") != config.get("rootfs", {}).get("diff_ids"):
        raise VerificationError("local root filesystem layers differ from the verified registry config")


def container_image_probe(vm, reference):
    # Create without starting, networking or project mounts. Retain only safe
    # identity fields; remove precisely this never-started probe container.
    container_id = vm.command_on_guest(f"docker create --pull never --network none --entrypoint /bin/true --label cf.delivery.identity-probe=true {shlex.quote(reference)}").stdout.decode().strip()
    if not re.fullmatch(r"[0-9a-f]{64}", container_id):
        raise VerificationError("image identity probe did not return one precise container ID")
    try:
        value = json.loads(vm.command_on_guest("docker inspect " + container_id).stdout)[0]
        return {"container_image_id": value.get("Image"), "image_manifest_descriptor": value.get("ImageManifestDescriptor"), "status": value.get("State", {}).get("Status"), "running": value.get("State", {}).get("Running"), "network_mode": value.get("HostConfig", {}).get("NetworkMode"), "mount_count": len(value.get("Mounts", []))}
    finally:
        vm.command_on_guest("docker rm " + container_id + " >/dev/null")


def registry(work, tls, local_image, revision, registry_port):
    target = f"localhost:{registry_port}/cf-filebrowser:verification-{revision}"
    trust = f"/etc/docker/certs.d/localhost:{registry_port}"
    execute(["sudo", "install", "-d", "-m", "0755", trust])
    execute(["sudo", "install", "-m", "0644", str(tls / "ca.crt"), trust + "/ca.crt"])
    execute(["docker", "pull", "registry:2"])
    registry_info = json.loads(execute(["docker", "image", "inspect", "registry:2"]).stdout)[0]
    name = "cf-verification-registry-" + revision[:12]
    container = execute(["docker", "run", "--detach", "--name", name, "--label", "cf.delivery.isolated=true", "--publish", f"127.0.0.1:{registry_port}:5000", "--mount", f"type=bind,src={tls},dst=/certs,readonly", "--env", "REGISTRY_HTTP_TLS_CERTIFICATE=/certs/registry.crt", "--env", "REGISTRY_HTTP_TLS_KEY=/certs/registry.key", registry_info["Id"]]).stdout.decode().strip()
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        result = execute(["curl", "--fail", "--silent", "--show-error", "--cacert", str(tls / "ca.crt"), f"https://localhost:{registry_port}/v2/"], check=False)
        if result.returncode == 0:
            break
        time.sleep(1)
    else:
        raise VerificationError("isolated registry did not accept strictly verified HTTPS")
    image_id = json.loads(execute(["docker", "image", "inspect", local_image]).stdout)[0]["Id"]
    publish_evidence = work / "registry-publish"
    execute(["bash", str(ROOT / "deploy/shared-host/image.sh"), "publish", "--source-sha", revision, "--image", image_id, "--target", target, "--approved-registry", f"localhost:{registry_port}", "--evidence", str(publish_evidence)], timeout=1800)
    record = json.loads((publish_evidence / "image.json").read_text())
    return container, record["registry_reference"], image_id, registry_info["Id"]


def sentinel(vm):
    vm.command_on_guest("""
docker pull busybox:1.37.0 >/dev/null
reference=$(docker image inspect busybox:1.37.0 --format '{{index .RepoDigests 0}}')
install -d -m 0700 /root/cf-sentinel /var/lib/cf-sentinel
printf 'unrelated-project-must-survive\n' > /var/lib/cf-sentinel/index.html
cat > /root/cf-sentinel/compose.yaml <<SENTINEL
name: cf-unrelated-sentinel
services:
  sentinel:
    image: $reference
    restart: unless-stopped
    command: [httpd, -f, -p, '8080', -h, /data]
    ports: ['127.0.0.1:19091:8080']
    volumes:
      - /var/lib/cf-sentinel:/data:ro
SENTINEL
docker compose -f /root/cf-sentinel/compose.yaml up -d --pull never
""")
    return sentinel_state(vm)


def sentinel_state(vm):
    value = vm.command_on_guest("""
python3 - <<'PY'
import hashlib,json,subprocess
ids=subprocess.check_output(['docker','ps','-q','--filter','label=com.docker.compose.project=cf-unrelated-sentinel']).decode().split()
assert len(ids)==1
c=json.loads(subprocess.check_output(['docker','inspect',ids[0]]))[0]
print(json.dumps({'id':c['Id'],'image':c['Image'],'networks':{name:{key:net.get(key) for key in ('NetworkID','IPAddress','IPPrefixLen','Gateway','Aliases')} for name,net in c['NetworkSettings']['Networks'].items()},'ports':c['HostConfig']['PortBindings'],'mounts':c['Mounts'],'data_sha256':hashlib.sha256(open('/var/lib/cf-sentinel/index.html','rb').read()).hexdigest()},sort_keys=True))
PY
""").stdout
    return json.loads(value)


def healthy(vm):
    vm.command_on_guest("""
for attempt in $(seq 1 90); do
  id=$(docker ps -aq --filter label=com.docker.compose.project=cf-filebrowser)
  if [ -n "$id" ] && [ "$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$id")" = healthy ]; then exit 0; fi
  sleep 2
done
exit 1
""", timeout=210)



REBOOT_ERRORS = (VerificationError, OSError, ValueError, KeyError, subprocess.TimeoutExpired)


def reboot_error_class(error):
    if isinstance(error, subprocess.TimeoutExpired):
        return "subprocess-timeout"
    if isinstance(error, VerificationError):
        return "verification-failed"
    if isinstance(error, OSError):
        return "os-error"
    if isinstance(error, KeyError):
        return "missing-result-field"
    return "invalid-result"


def reboot_observation(vm):
    # Read-only, bounded diagnostics. Never print docker inspect/logs, environment,
    # configuration, marker values, authentication material or exception text.
    script = r"""python3 -B - <<'REBOOT_OBSERVATION'
import hashlib,json,os,re,subprocess
from pathlib import Path

def run(*args):
    return subprocess.run(args,capture_output=True,text=True,check=False,timeout=5)

def safe(value, allowed, fallback='unknown'):
    return value if value in allowed else fallback

report={'available':True,'docker':safe(run('systemctl','is-active','docker').stdout.strip(),
    ('active','inactive','activating','deactivating','failed','unknown'))}
root=Path('/srv/storage')
report['storage_mounted']=run('mountpoint','--quiet',str(root)).returncode==0
report['storage_on_root_device']=root.exists() and root.stat().st_dev==Path('/').stat().st_dev
uuid=run('findmnt','-n','-o','UUID','--mountpoint',str(root)).stdout.strip()
report['storage_uuid']=uuid if re.fullmatch(r'[0-9a-f-]{36}',uuid) else None
left=Path('/etc/cf-filebrowser-enterprise/storage.identity')
right=root/'cf-filebrowser-enterprise/.storage-identity'
report['storage_identity_matches']=(left.is_file() and right.is_file() and not left.is_symlink()
    and not right.is_symlink() and left.stat().st_size==65 and right.stat().st_size==65
    and left.read_bytes()==right.read_bytes())
report['bootstrap_absent']=not os.path.lexists('/etc/cf-filebrowser-enterprise/secrets/bootstrap_admin_password')
config=Path('/etc/cf-filebrowser-enterprise/config.yaml')
report['config_sha256']=hashlib.sha256(config.read_bytes()).hexdigest() if config.is_file() and config.stat().st_size<=1048576 else None
# Do not cause Docker socket activation while observing its autostart state.
if report['docker']=='active':
    ids=run('docker','ps','-aq','--no-trunc','--filter','label=com.docker.compose.project=cf-filebrowser').stdout.split()
    report['container_count']=len(ids)
    if len(ids)==1 and re.fullmatch(r'[0-9a-f]{64}',ids[0]):
        result=run('docker','inspect',ids[0])
        if result.returncode==0:
            info=json.loads(result.stdout)[0];state=info.get('State',{})
            report.update(container_id=ids[0],image_id=info.get('Image'),
                running=state.get('Running') is True,
                status=safe(state.get('Status'),('created','running','paused','restarting','removing','exited','dead')),
                health=safe(state.get('Health',{}).get('Status'),('starting','healthy','unhealthy'),'absent'),
                exit_code=state.get('ExitCode'),restart_count=info.get('RestartCount'))
            error=state.get('Error','').lower()
            report['container_error']=next((label for marker,label in (
                ('bind source path does not exist','missing-bind-source'),
                ('no such file or directory','missing-path'),('permission denied','permission-denied'))
                if marker in error),'unclassified' if error else 'none')
print(json.dumps(report,sort_keys=True))
REBOOT_OBSERVATION
"""
    process = vm.command_on_guest(script, check=False, timeout=45)
    if process.returncode or len(process.stdout) > 65536:
        raise VerificationError("bounded reboot observation unavailable")
    try:
        value = json.loads(process.stdout)
    except (ValueError, UnicodeError) as error:
        raise VerificationError("invalid reboot observation") from error
    bools = {'available', 'storage_mounted', 'storage_on_root_device', 'storage_identity_matches', 'bootstrap_absent', 'running'}
    ints = {'container_count', 'exit_code', 'restart_count'}
    enums = {'docker': {'active','inactive','activating','deactivating','failed','unknown'},
             'status': {'created','running','paused','restarting','removing','exited','dead','unknown'},
             'health': {'starting','healthy','unhealthy','absent'},
             'container_error': {'missing-bind-source','missing-path','permission-denied','unclassified','none'}}
    patterns = {'storage_uuid': r'[0-9a-f-]{36}', 'container_id': r'[0-9a-f]{64}', 'image_id': r'sha256:[0-9a-f]{64}', 'config_sha256': r'[0-9a-f]{64}'}
    required = {'available','docker','storage_mounted','storage_on_root_device','storage_uuid','storage_identity_matches','bootstrap_absent'}
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - (bools | ints | enums.keys() | patterns.keys()):
        raise VerificationError("invalid reboot observation schema")
    for key, item in value.items():
        valid = ((key in bools and type(item) is bool)
                 or (key in ints and type(item) is int and 0 <= item <= 1000000)
                 or (key in enums and isinstance(item, str) and item in enums[key])
                 or (key in patterns and ((key in ('storage_uuid', 'config_sha256') and item is None)
                     or (isinstance(item, str) and re.fullmatch(patterns[key], item) is not None))))
        if not valid:
            raise VerificationError("invalid reboot observation value")
    return value


def reboot_operation(args, evidence, vm, name, operation, *, diagnostic_vm=None):
    if name not in ('boot-id-change', 'container-health', 'https-lan', 'file-api'):
        raise VerificationError("unknown reboot operation")
    record = {'operation': name, 'vm': vm.name, 'result': 'failed', 'exit_code': None}
    diagnostic_vm = diagnostic_vm or vm
    evidence.setdefault('reboot_operations', []).append(record)
    record_stage(args, evidence, 'real-host-reboot-and-api/' + name)
    started = time.monotonic()
    try:
        value = operation()
        record['result'] = 'passed'
        record['exit_code'] = 0
        return value
    except REBOOT_ERRORS as error:
        record['elapsed_seconds'] = round(time.monotonic() - started, 3)
        record['classification'] = reboot_error_class(error)
        if isinstance(error, subprocess.TimeoutExpired):
            record['timeout_seconds'] = error.timeout
        if type(getattr(error, 'guest_exit_code', None)) is int:
            record['exit_code'] = error.guest_exit_code
        # Preserve the original failure even if this independent probe fails.
        try:
            evidence['reboot_failure_state_vm'] = diagnostic_vm.name
            evidence['reboot_failure_state'] = reboot_observation(diagnostic_vm)
        except REBOOT_ERRORS as diagnostic_error:
            evidence['reboot_failure_state'] = {'available': False, 'classification': reboot_error_class(diagnostic_error)}
        raise
    finally:
        record.setdefault('elapsed_seconds', round(time.monotonic() - started, 3))
        record_stage(args, evidence, 'real-host-reboot-and-api/' + name)


def runtime_readiness_script():
    return r"""
python3 - <<'CF_RUNTIME_IDENTITY'
import json,re,subprocess

def run(argv):
    return subprocess.run(argv,capture_output=True,text=True,check=False,timeout=60)

ids=run(['docker','ps','-q','--filter','label=com.docker.compose.project=cf-filebrowser','--filter','label=com.docker.compose.service=filebrowser-enterprise']).stdout.split()
if len(ids)!=1:
    raise SystemExit('one running FileBrowser service is required for runtime verification')
container=ids[0]
info=json.loads(run(['docker','inspect',container]).stdout)[0]

def inside(*argv):
    # No --user override: all probes run with the real configured service identity.
    return run(['docker','exec',container,*argv])

def numeric(*argv):
    result=inside(*argv)
    return int(result.stdout.strip()) if result.returncode==0 and result.stdout.strip().isdigit() else None

def identity(kind):
    result=inside('awk','$1=="'+kind+':" {print $2,$3,$4,$5}','/proc/1/status')
    fields=result.stdout.split()
    return [int(value) for value in fields] if result.returncode==0 and len(fields)==4 and all(value.isdigit() for value in fields) else []

record={'container_id':container,'image_id':info.get('Image'),'health':info.get('State',{}).get('Health',{}).get('Status'),'running':info.get('State',{}).get('Running'),'readonly_rootfs':info.get('HostConfig',{}).get('ReadonlyRootfs'),'exec_uid':numeric('id','-u'),'exec_gid':numeric('id','-g'),'pid1_uid':identity('Uid'),'pid1_gid':identity('Gid'),'tools':{},'writable':{},'denied_writes':{},'readable':{}}
versions={'ffmpeg':(['ffmpeg','-version'],r'^ffmpeg version (\S+)'),'ffprobe':(['ffprobe','-version'],r'^ffprobe version (\S+)'),'exiftool':(['exiftool','-ver'],r'^(\d+(?:\.\d+)+)'),'curl':(['curl','--version'],r'^curl (\S+)'),'filebrowser':(['/home/filebrowser/filebrowser','version'],r'(?m)^\s*Version\s*:\s*(\S+)')}
for name,(argv,pattern) in versions.items():
    result=inside(*argv)
    match=re.search(pattern,result.stdout)
    record['tools'][name]={'exit_code':result.returncode,'version':match.group(1)[:160] if match else None}
    if name=='filebrowser':
        commit=re.search(r'(?m)^\s*Commit\s*:\s*([0-9a-f]{40})\s*$',result.stdout)
        record['filebrowser_commit']=commit.group(1) if commit else None

# Each probe owns a fresh mktemp file, performs byte I/O only on that file and
# removes exactly that file even after a failed assertion. No database is opened.
write_probe='set -eu; probe=$(mktemp "$1/.cf-runtime-XXXXXXXXXX"); trap \'rm -f -- "$probe"\' EXIT HUP INT TERM; printf "cf-runtime-check\\n" > "$probe"; test "$(cat "$probe")" = cf-runtime-check; rm -f -- "$probe"; trap - EXIT HUP INT TERM'
for name,path in {'files':'/srv/filebrowser/files','data':'/var/lib/filebrowser-enterprise','cache':'/var/cache/filebrowser-enterprise'}.items():
    record['writable'][name]=inside('sh','-c',write_probe,'sh',path).returncode==0

# A successful open-for-append would be an error, but writes no bytes and never
# truncates/replaces the configuration. The root probe cleans up only its own file.
record['denied_writes']['config']=inside('sh','-c','exec 3>> "$1"; exec 3>&-','sh','/etc/filebrowser-enterprise/config.yaml').returncode!=0
root_probe='test -d "$1" || exit 1; probe=$(mktemp "$1/.cf-runtime-XXXXXXXXXX" 2>/dev/null) || exit 0; rm -f -- "$probe"; exit 1'
record['denied_writes']['root']=inside('sh','-c',root_probe,'sh','/').returncode==0
paths={'entrypoint':'/opt/filebrowser-enterprise/scripts/container-entrypoint.sh','config':'/etc/filebrowser-enterprise/config.yaml','jwt':'/run/filebrowser-secrets/jwt_token_secret','totp':'/run/filebrowser-secrets/totp_secret','storage_identity':'/run/filebrowser-storage-identity','tls_certificate':'/etc/filebrowser-enterprise/tls/server.crt','tls_key':'/etc/filebrowser-enterprise/tls/server.key','tls_ca':'/etc/filebrowser-enterprise/tls/ca.crt'}
for name,path in paths.items():
    # Access metadata only: never read or echo Secret/config/certificate contents.
    record['readable'][name]=inside('sh','-c','test -f "$1" && test -r "$1"','sh',path).returncode==0
record['entrypoint_executable']=inside('test','-x',paths['entrypoint']).returncode==0
record['entrypoint_syntax_valid']=inside('sh','-n',paths['entrypoint']).returncode==0
record['bootstrap_absent']=inside('test','!','-e','/run/filebrowser-secrets/bootstrap_admin_password').returncode==0
readonly={'/etc/filebrowser-enterprise/config.yaml','/run/filebrowser-secrets','/etc/filebrowser-enterprise/storage.identity','/run/filebrowser-storage-identity','/opt/filebrowser-enterprise/scripts/container-entrypoint.sh','/etc/filebrowser-enterprise/tls'}
mounts={entry['Destination']:entry for entry in info.get('Mounts',[])}
record['readonly_bind_mounts']=all(path in mounts and mounts[path].get('Type')=='bind' and mounts[path].get('RW') is False for path in readonly)
print(json.dumps(record,sort_keys=True))
CF_RUNTIME_IDENTITY
"""


def verify_runtime_readiness(record, image_id, revision):
    expected = {'image_id': image_id, 'health': 'healthy', 'running': True, 'readonly_rootfs': True, 'exec_uid': 10001, 'exec_gid': 10001, 'pid1_uid': [10001] * 4, 'pid1_gid': [10001] * 4, 'filebrowser_commit': revision, 'entrypoint_executable': True, 'entrypoint_syntax_valid': True, 'readonly_bind_mounts': True, 'bootstrap_absent': True}
    for name, value in expected.items():
        if record.get(name) != value:
            raise VerificationError('actual service runtime check failed: ' + name)
    for section, names in {'writable': ('files', 'data', 'cache'), 'denied_writes': ('root', 'config'), 'readable': ('entrypoint', 'config', 'jwt', 'totp', 'storage_identity', 'tls_certificate', 'tls_key', 'tls_ca')}.items():
        for name in names:
            if record.get(section, {}).get(name) is not True:
                raise VerificationError('actual service runtime check failed: ' + section + '/' + name)
    for name in ('ffmpeg', 'ffprobe', 'exiftool', 'curl', 'filebrowser'):
        tool = record.get('tools', {}).get(name, {})
        if tool.get('exit_code') != 0 or not tool.get('version'):
            raise VerificationError('actual service dependency check failed: ' + name)



def missing_storage_state(vm, container_id, sentinel_id, *, timeout=900):
    if not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in (container_id, sentinel_id)):
        raise VerificationError("missing-storage verification requires precise pre-reboot container IDs")
    return json.loads(vm.command_on_guest(f"""
python3 - <<'CF_MISSING_STORAGE'
import json,os,subprocess
from pathlib import Path

def run(*args):
    return subprocess.run(args,capture_output=True,text=True,check=False)

def inspect(container):
    result=run('docker','inspect',container)
    return json.loads(result.stdout)[0] if result.returncode==0 else {{}}

docker_active=run('systemctl','is-active','--quiet','docker').returncode==0
# Do not touch docker.socket before automatic docker.service activation: even a
# read-only Docker API request could otherwise trigger systemd socket activation.
service=inspect('{container_id}') if docker_active else {{}}
sentinel=inspect('{sentinel_id}') if docker_active else {{}}
service_ids=run('docker','ps','--no-trunc','-aq','--filter','label=com.docker.compose.project=cf-filebrowser').stdout.split() if docker_active else []
root=Path('/srv/storage')
print(json.dumps({{'docker_active':docker_active,'sentinel_id':sentinel.get('Id'),'sentinel_running':sentinel.get('State',{{}}).get('Running'),'service_ids':service_ids,'service_id':service.get('Id'),'service_running':service.get('State',{{}}).get('Running'),'service_status':service.get('State',{{}}).get('Status'),'storage_mounted':run('mountpoint','--quiet',str(root)).returncode==0,'storage_directory_exists':root.is_dir(),'storage_device_is_root':root.is_dir() and root.stat().st_dev==Path('/').stat().st_dev,'business_path_exists':os.path.lexists(root/'cf-filebrowser-enterprise')}},sort_keys=True))
CF_MISSING_STORAGE
""", timeout=timeout).stdout)



def wait_missing_storage_ready(vm, container_id, sentinel_id, record):
    # Reuse the existing health wait's 180-second budget. Observation only:
    # neither Docker nor the sentinel is started by this readiness wait.
    deadline = time.monotonic() + 180
    record.update(readiness_budget_seconds=180, readiness_observations=0)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise VerificationError("missing-storage Docker/sentinel autostart readiness timed out after 180 seconds; last state retained")
        try:
            state = missing_storage_state(vm, container_id, sentinel_id, timeout=remaining)
        except subprocess.TimeoutExpired as error:
            record["readiness_observation_timed_out"] = True
            raise VerificationError("missing-storage Docker/sentinel observation timed out within the 180 seconds budget; last state retained") from error
        # The surrounding scenario owns this dictionary and persists it even if
        # an invariant fails or readiness expires before a final successful sample.
        record["before_explicit_start"] = state
        record["readiness_observations"] += 1
        safe = {'storage_mounted': False, 'storage_directory_exists': True, 'storage_device_is_root': True, 'business_path_exists': False}
        for name, expected in safe.items():
            if state.get(name) != expected:
                raise VerificationError('missing-storage safety check failed while awaiting autostart: ' + name)
        if state.get('service_running') is True:
            raise VerificationError('missing-storage service ran while awaiting Docker/sentinel autostart')
        if state.get('service_id') not in (None, container_id) or state.get('sentinel_id') not in (None, sentinel_id):
            raise VerificationError('missing-storage original container identity changed while awaiting autostart')
        if state.get('service_ids') and state['service_ids'] != [container_id]:
            raise VerificationError('missing-storage project containers changed while awaiting autostart')
        if state.get('docker_active') is True and state.get('sentinel_running') is True and state.get('sentinel_id') == sentinel_id and state.get('service_id') == container_id and state.get('service_ids') == [container_id] and state.get('service_running') is False:
            return
        time.sleep(min(2, max(0, deadline - time.monotonic())))


def verify_missing_storage_state(record, container_id, sentinel_id):
    expected = {'docker_active': True, 'sentinel_id': sentinel_id, 'sentinel_running': True, 'service_ids': [container_id], 'service_id': container_id, 'service_running': False, 'storage_mounted': False, 'storage_directory_exists': True, 'storage_device_is_root': True, 'business_path_exists': False}
    for name, value in expected.items():
        if record.get(name) != value:
            raise VerificationError('missing-storage refusal check failed: ' + name)


def missing_storage_rejection(result):
    causes = ((b'bind source path does not exist', 'missing-bind-source'), (b'no such file or directory', 'missing-bind-path'), (b'storage identity', 'storage-identity-refused'))
    category = next((label for marker, label in causes if marker in result.stderr), 'unclassified-start-refusal')
    return {'exit_code': result.returncode, 'category': category, 'private_stderr_bytes': len(result.stderr), 'private_stderr_sha256': hashlib.sha256(result.stderr).hexdigest()}


def api(vm, phase, evidence_name, *, state_name="api-state.json", timeout=900):
    if state_name not in ("api-state.json", "audit-pending-state.json"):
        raise VerificationError("unexpected private API state name")
    extra = f" --filebridge-bin {GUEST}/filebrowser-agentctl" if phase == "protocols" else ""
    result = vm.command_on_guest(f"python3 -B {SOURCE}/scripts/tests/shared-host-api.py {phase} --url https://{TLS_NAME}:{TLS_PORT} --ca-file {GUEST}/ca.crt --admin-password-file {GUEST}/admin-password --state-file {GUEST}/{state_name} --evidence {GUEST}/{evidence_name}{extra}", check=False, timeout=timeout)
    try:
        if phase.startswith("audit-pending-"):
            raw = vm.command_on_guest("cat -- " + shlex.quote(GUEST + "/" + evidence_name), timeout=15).stdout
        else:
            raw = vm.read_file(GUEST + "/" + evidence_name)
        report = json.loads(raw)
    except (VerificationError, ValueError, OSError):
        report = {"phase": phase, "passed": False, "failure": "API helper did not produce its sanitized evidence; private output suppressed"}
    if result.returncode or not report.get("passed"):
        error = VerificationError(f"{vm.name}: API {phase} failed (exit {result.returncode}); sanitized check evidence retained")
        error.api_evidence = report
        raise error
    return report


def pending_container_script(image_id, container_id=None, *, kill=False):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) or (container_id is not None and not re.fullmatch(r"[0-9a-f]{64}", container_id)):
        raise VerificationError("invalid pending probe container identity")
    if kill and container_id is None:
        raise VerificationError("pending probe kill requires the previously verified container")
    source = "import json, re, subprocess\nexpected_image=" + repr(image_id) + "\nexpected_id=" + repr(container_id) + "\nkill=" + repr(kill) + "\n"
    source += r'''def docker(*args, timeout=5):
    return subprocess.run(['docker','--host','unix:///var/run/docker.sock',*args], capture_output=True, check=True, timeout=timeout,
                          env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root'}).stdout
ids=docker('container','ls','--all','--quiet','--filter','label=com.docker.compose.project=cf-filebrowser').decode().split()
if len(ids)!=1 or not re.fullmatch(r'[0-9a-f]{12,64}',ids[0]): raise RuntimeError('pending container selection rejected')
info=json.loads(docker('container','inspect',ids[0]))[0]
def valid(value):
    labels=value.get('Config',{}).get('Labels',{})
    return (re.fullmatch(r'[0-9a-f]{64}',value.get('Id','')) is not None
            and (expected_id is None or value['Id']==expected_id) and value.get('Image')==expected_image
            and labels.get('com.docker.compose.project')=='cf-filebrowser'
            and labels.get('com.docker.compose.service')=='filebrowser-enterprise'
            and value.get('HostConfig',{}).get('RestartPolicy',{}).get('Name')=='unless-stopped')
if not valid(info): raise RuntimeError('pending container identity rejected')
if kill:
    if info.get('State',{}).get('Running') is not True: raise RuntimeError('pending container already stopped')
    before=info
    docker('container','kill','--signal','KILL',info['Id'],timeout=15)
    info=json.loads(docker('container','inspect',before['Id']))[0]
    if (not valid(info) or info.get('State',{}).get('Running') is not False or info['State'].get('ExitCode')!=137
            or info['State'].get('OOMKilled') is not False or info.get('RestartCount')!=before.get('RestartCount')):
        raise RuntimeError('pending container interruption not verified')
print(json.dumps({'id':info['Id'],'image':info['Image'],'running':info.get('State',{}).get('Running'),
                  'restart_count':info.get('RestartCount'),'healthy':info.get('State',{}).get('Health',{}).get('Status')=='healthy'},sort_keys=True))
'''
    return "python3 -B - <<'PENDING_CONTAINER'\n" + source + "PENDING_CONTAINER\n"


def pending_filesystem_script():
    return f"""python3 -B - <<'PENDING_FILES'
import importlib.util, json
from pathlib import Path
spec=importlib.util.spec_from_file_location('pending_api', '{SOURCE}/scripts/tests/shared-host-api.py')
api=importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)
control=json.loads(api.protected_path('{GUEST}/audit-pending-state.control.json',secret=True).read_bytes())
print(json.dumps(api.audit_pending_filesystem(control),sort_keys=True))
PENDING_FILES
"""


PENDING_API_PHASES = ("audit-pending-prepare", "audit-pending-hold", "audit-pending-verify")
PENDING_API_CHECKS = frozenset((
    "administrator_login", "administrator_login_session_shape", "administrator_identity", "administrator_privilege",
    "pending_create", "pending_lookup", "pending_created_once", "pending_login", "pending_login_session_shape", "pending_ordinary_identity",
    "audit_pending_directory_create", "audit_pending_original_create", "audit_pending_original_read", "audit_pending_original_download",
    "audit_pending_query", "audit_pending_query_bounded", "audit_pending_no_prior_modify", "audit_pending_prepared",
    "audit_pending_writer_login", "audit_pending_writer_login_session_shape", "audit_pending_prefix_shape", "audit_pending_connection_interrupted",
    "audit_pending_hold_completed", "audit_pending_one_recovered_event", "audit_pending_event_shape", "audit_pending_recovered_identity",
    "audit_pending_recovered_terminal", "audit_pending_real_request_id", "audit_pending_exact_request_lookup",
    "audit_pending_restarted_writer_login", "audit_pending_restarted_writer_login_session_shape", "audit_pending_restarted_download",
    "audit_pending_original_not_overwritten", "audit_pending_following_write", "audit_pending_following_download", "audit_pending_following_read",
))


def pending_api_failure(report, phase):
    if phase not in PENDING_API_PHASES:
        raise VerificationError("invalid pending API evidence phase")
    fallback = {"version": 1, "phase": phase, "passed": False, "checks": [], "failure": "invalid_api_evidence"}
    if (not isinstance(report, dict) or type(report.get("version")) is not int or report["version"] != 1
            or report.get("phase") != phase or type(report.get("passed")) is not bool
            or not isinstance(report.get("checks"), list) or len(report["checks"]) > 100):
        return fallback
    checks = []
    for check in report["checks"]:
        if (not isinstance(check, dict) or not set(check).issubset({"check", "passed", "http_status", "record_count"})
                or check.get("check") not in PENDING_API_CHECKS or type(check.get("passed")) is not bool):
            return fallback
        for key, minimum, maximum in (("http_status", 100, 599), ("record_count", 0, 100)):
            if key in check and (type(check[key]) is not int or not minimum <= check[key] <= maximum):
                return fallback
        checks.append(dict(check))
    safe = {"version": 1, "phase": phase, "passed": False, "checks": checks,
            "failure": "api_check_failed" if any(not check["passed"] for check in checks) else "api_phase_failed"}
    if type(report.get("requests")) is int and 0 <= report["requests"] <= 100:
        safe["requests"] = report["requests"]
    # Never copy failure text, arbitrary response fields, credentials or IDs.
    return safe


def audit_pending_interrupt(server, client, args, evidence, image_id, baseline):
    """Only a dedicated synthetic namespace, before the main acceptance seed."""
    operation = "sentinel"
    summary = {"passed": False, "operation": operation, "checks": []}
    evidence["audit_pending"] = summary
    def check(label, condition, count=None):
        entry = {"check": label, "passed": bool(condition)}
        if count is not None:
            entry["count"] = count
        summary["operation"] = operation
        summary["checks"].append(entry)
        record_stage(args, evidence, label)
        if not condition:
            raise VerificationError(label)
    def phase(name):
        expected_phase = "audit-pending-" + name
        try:
            return api(client, expected_phase, expected_phase + ".json",
                       state_name="audit-pending-state.json", timeout=140 if name == "hold" else 300)
        except VerificationError as error:
            failure = VerificationError("pending API phase failed; sanitized evidence retained")
            failure.pending_phase = expected_phase
            failure.api_evidence = pending_api_failure(getattr(error, "api_evidence", None), expected_phase)
            raise failure from None
    def filesystem():
        return json.loads(server.command_on_guest(pending_filesystem_script(), timeout=15).stdout)
    holder, outcome = None, {}
    try:
        for vm in (server, client):
            check("audit_pending_sentinel_before", sentinel_state(vm) == baseline[vm.name])
        operation = "prepare"
        prepared = phase("prepare")
        check("audit_pending_prepared", prepared.get("passed") is True, len(prepared.get("checks", [])))
        server.write_file(GUEST + "/audit-pending-state.control.json", client.read_file(GUEST + "/audit-pending-state.control.json"))
        operation = "observe"
        original = filesystem()
        check("audit_pending_clean_namespace", original.get("temporary") is None)
        operation = "identity"
        container = json.loads(server.command_on_guest(pending_container_script(image_id), timeout=20).stdout)
        check("audit_pending_fixed_image_running", container.get("running") is True and container.get("healthy") is True)
        def hold():
            try:
                outcome["report"] = phase("hold")
            except Exception as error:
                outcome["failed"] = True
                if hasattr(error, "api_evidence"):
                    outcome["api_evidence"] = pending_api_failure(error.api_evidence, "audit-pending-hold")
        operation = "hold"
        holder = threading.Thread(target=hold, name="audit-pending-client")
        holder.start()
        deadline = time.monotonic() + 45
        ready = None
        operation = "observe"
        summary["operation"] = operation
        record_stage(args, evidence, "audit_pending_wait_for_persisted_prefix")
        while time.monotonic() < deadline:
            observed = filesystem()
            check_same = observed.get("target") == original["target"] and observed.get("directory") == original["directory"]
            if not check_same:
                check("audit_pending_original_unchanged_before_kill", False)
            if observed.get("temporary") and observed["temporary"].get("complete") is True:
                ready = observed
                break
            if not holder.is_alive():
                break
            time.sleep(0.25)
        check("audit_pending_persisted_prefix_observed", ready is not None, 1 if ready is not None else 0)
        operation = "kill"
        stopped = json.loads(server.command_on_guest(pending_container_script(image_id, container["id"], kill=True), timeout=35).stdout)
        check("audit_pending_only_verified_service_killed", stopped.get("running") is False and stopped.get("id") == container["id"])
        operation = "hold"
        holder.join(timeout=20)
        if "api_evidence" in outcome:
            summary["failed_api"] = outcome["api_evidence"]
        check("audit_pending_client_interruption_observed", not holder.is_alive() and not outcome.get("failed") and outcome.get("report", {}).get("passed") is True)
        operation = "observe"
        check("audit_pending_stopped_files_preserved", filesystem() == ready)
        operation = "start"
        server.command_on_guest(f"bash {SOURCE}/deploy/shared-host/manage.sh start --hostname {server.name}", timeout=900)
        healthy(server)
        restarted = json.loads(server.command_on_guest(pending_container_script(image_id, container["id"]), timeout=20).stdout)
        check("audit_pending_formal_same_image_restart", restarted.get("running") is True and restarted.get("healthy") is True)
        operation = "observe"
        check("audit_pending_restart_files_preserved", filesystem() == ready)
        operation = "verify"
        verified = phase("verify")
        check("audit_pending_recovered_and_following_write", verified.get("passed") is True, len(verified.get("checks", [])))
        for label in ("audit_pending_recovered_terminal", "audit_pending_exact_request_lookup",
                      "audit_pending_original_not_overwritten", "audit_pending_following_write", "audit_pending_following_read"):
            matches = [entry for entry in verified.get("checks", []) if entry.get("check") == label]
            check(label, len(matches) == 1 and matches[0].get("passed") is True)
        operation = "sentinel"
        for vm in (server, client):
            check("audit_pending_sentinel_after", sentinel_state(vm) == baseline[vm.name])
        summary["passed"] = True
        record_stage(args, evidence, "audit_pending_interruption_recovery_verified")
    except Exception as error:
        summary["passed"] = False
        summary["operation"] = operation
        if hasattr(error, "api_evidence") and getattr(error, "pending_phase", None) in PENDING_API_PHASES:
            summary["failed_api"] = pending_api_failure(error.api_evidence, error.pending_phase)
        record_stage(args, evidence, "audit_pending_interruption_probe_failed")
        raise VerificationError("audit_pending_interruption_probe_failed; private evidence retained") from None
    finally:
        if holder is not None:
            # Client socket finally closes by 120s; existing SSH execution has
            # an independent 140s timeout plus a bounded 15s evidence read.
            # Never clear its files or kill a VM.
            holder.join(timeout=160)
            if not summary["passed"] and "api_evidence" in outcome:
                summary["failed_api"] = outcome["api_evidence"]
                record_stage(args, evidence, "audit_pending_interruption_probe_failed")
            if holder.is_alive():
                summary["passed"] = False
                check("audit_pending_client_deadline", False)



FAULT_PHASES = frozenset(("prepare", "control", "fault", "verify", "server", "detached", "restarted"))
FAULT_STAGES = frozenset(("preflight", "identity", "attach", "ready_window", "release", "complete"))


def fault_public_report(report, phase, *, mode=None):
    """Private syscall/process/request identities never enter runner evidence."""
    if phase not in FAULT_PHASES or (phase == "server" and mode not in ("observe", "inject")):
        raise VerificationError("invalid fault evidence phase")
    fallback = {"version": 1, "phase": phase, "passed": False, "failure": "invalid_fault_evidence"}
    if (not isinstance(report, dict) or type(report.get("version")) is not int or report["version"] != 1
            or report.get("phase") != phase or type(report.get("passed")) is not bool):
        return fallback
    safe = {"version": 1, "phase": phase, "passed": report["passed"] is True and report.get("failure") is None,
            "failure": None if report["passed"] is True and report.get("failure") is None else "fault_phase_failed"}
    if phase == "server":
        if (report.get("mode") != mode or report.get("stage") not in FAULT_STAGES
                or type(report.get("detached")) is not bool):
            return fallback
        safe.update(mode=mode, stage=report["stage"], detached=report["detached"])
        if "coverage_samples" in report:
            if type(report["coverage_samples"]) is not int or not 0 <= report["coverage_samples"] <= 10000:
                return fallback
            safe["coverage_samples"] = report["coverage_samples"]
        if report.get("strace_version") == "6.13":
            safe["strace_version"] = "6.13"
        counts = report.get("counts")
        if counts is not None:
            if (not isinstance(counts, dict) or set(counts) != {"writes", "successful", "injected_eio"}
                    or any(type(value) is not int or not 0 <= value <= 10000 for value in counts.values())):
                return fallback
            safe["counts"] = dict(counts)
        if safe["passed"] and (not safe["detached"] or safe.get("strace_version") != "6.13"
                or safe.get("coverage_samples", 0) < 1 or not counts or counts["writes"] < 1
                or counts["writes"] != counts["injected_eio" if mode == "inject" else "successful"]
                or counts["successful" if mode == "inject" else "injected_eio"] != 0
                or safe["stage"] != "complete"):
            return fallback
    elif phase == "detached":
        if type(report.get("detached")) is not bool or safe["passed"] and not report["detached"]:
            return fallback
        safe["detached"] = report["detached"]
    elif phase != "restarted":
        checks = report.get("checks")
        if (not isinstance(checks, list) or len(checks) > 100 or type(report.get("requests")) is not int
                or not 0 <= report["requests"] <= 100
                or any(not isinstance(item, dict) or type(item.get("passed")) is not bool for item in checks)):
            return fallback
        if safe["passed"] and any(not item["passed"] for item in checks):
            return fallback
        required = {"fault": {"audit_store_exact_503_response"}, "verify": {
            "same_saved_session_write_and_terminal_after_formal_restart",
            "failed_request_absent_after_startup_pending_recovery"}}.get(phase, set())
        if safe["passed"] and not required.issubset({item.get("check") for item in checks if item["passed"]}):
            return fallback
        safe.update(requests=report["requests"], check_count=len(checks))
    return safe


def fault_guest(vm, phase, evidence_name, *arguments, timeout=120):
    if phase not in FAULT_PHASES or not re.fullmatch(r"fault-[a-z-]+\.json", evidence_name):
        raise VerificationError("invalid fault guest phase")
    mode = arguments[arguments.index("--mode") + 1] if "--mode" in arguments else None
    argv = ["python3", "-B", SOURCE + "/scripts/tests/shared_host_audit_fault.py", phase,
            "--evidence", GUEST + "/" + evidence_name, *arguments]
    if phase in ("prepare", "control", "fault", "verify"):
        argv += ["--url", f"https://{TLS_NAME}:{TLS_PORT}", "--ca-file", GUEST + "/ca.crt",
                 "--admin-password-file", GUEST + "/admin-password", "--state-file", GUEST + "/audit-fault-state.json"]
    result = vm.command_on_guest(shlex.join(argv), check=False, timeout=timeout)
    try:
        raw = vm.command_on_guest("cat -- " + shlex.quote(GUEST + "/" + evidence_name), timeout=15).stdout
        report = fault_public_report(json.loads(raw), phase, mode=mode)
    except (VerificationError, ValueError, UnicodeError, TypeError):
        report = fault_public_report(None, phase, mode=mode)
    if result.returncode or not report["passed"]:
        report["passed"] = False
        error = VerificationError("audit Store guest phase failed; private output suppressed")
        error.fault_evidence = report
        raise error
    return report


def fault_wait_ready(server, mode, container, image, worker):
    path = GUEST + "/fault-" + mode + "-ready.json"
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        result = server.command_on_guest(f"if test -f {shlex.quote(path)}; then cat -- {shlex.quote(path)}; else printf '{{}}'; fi", timeout=5)
        try:
            ready = json.loads(result.stdout)
        except (ValueError, UnicodeError):
            raise VerificationError("fault ready evidence invalid") from None
        if ready:
            if (not isinstance(ready, dict) or type(ready.get("version")) is not int or ready["version"] != 1
                    or ready.get("ready") is not True or ready.get("mode") != mode
                    or ready.get("container") != container or ready.get("image") != image
                    or not isinstance(ready.get("nonce"), str) or not re.fullmatch(r"[a-f0-9]{32}", ready["nonce"])
                    or not isinstance(ready.get("control_sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", ready["control_sha256"])):
                raise VerificationError("fault ready identity rejected")
            # Copy only these fields; arbitrary guest output is never forwarded.
            return {key: ready[key] for key in ("version", "ready", "mode", "container", "image", "nonce", "control_sha256")}
        if not worker.is_alive():
            break
        time.sleep(0.1)
    raise VerificationError("fault server did not become ready")


def audit_store_fault(server, client, args, evidence, image_id, baseline):
    summary = {"passed": False, "operation": "sentinel", "checks": [], "phases": {}}
    evidence["audit_store_fault"] = summary
    def check(label, condition):
        summary["checks"].append({"check": label, "passed": bool(condition)})
        record_stage(args, evidence, label)
        if not condition:
            raise VerificationError(label)
    def run(machine, phase, name, *arguments):
        try:
            report = fault_guest(machine, phase, name, *arguments)
        except VerificationError as error:
            if hasattr(error, "fault_evidence"):
                failed = fault_public_report(error.fault_evidence, phase)
                failed.update(passed=False, failure="fault_phase_failed")
                summary["phases"][name] = failed
            raise VerificationError("fault phase rejected") from None
        summary["phases"][name] = report
        return report
    try:
        for vm in (server, client):
            check("audit_store_sentinel_before", sentinel_state(vm) == baseline[vm.name])
        summary["operation"] = "identity"
        container = json.loads(server.command_on_guest(pending_container_script(image_id), timeout=20).stdout)
        check("audit_store_fixed_image_running", container.get("running") is True and container.get("healthy") is True
              and container.get("image") == image_id and re.fullmatch(r"[a-f0-9]{64}", container.get("id", "")) is not None)
        identity = ("--expected-container", container["id"], "--expected-image", image_id)
        summary["operation"] = "prepare"
        check("audit_store_prepared", run(client, "prepare", "fault-prepare.json")["passed"])
        server.write_file(GUEST + "/audit-fault-state.control.json", client.read_file(GUEST + "/audit-fault-state.control.json"))
        for mode, phase in (("observe", "control"), ("inject", "fault")):
            summary["operation"] = mode
            outcome, ready, release_ok = {}, None, True
            def serve():
                try:
                    extra = ("--observation-file", GUEST + "/fault-observe.json") if mode == "inject" else ()
                    outcome["report"] = fault_guest(server, "server", "fault-" + mode + ".json",
                        "--mode", mode, "--control-file", GUEST + "/audit-fault-state.control.json",
                        "--ready-file", GUEST + "/fault-" + mode + "-ready.json",
                        "--release-file", GUEST + "/fault-" + mode + "-release.json", *identity, *extra)
                except Exception as error:
                    outcome["failed"] = True
                    if hasattr(error, "fault_evidence"):
                        failed = fault_public_report(error.fault_evidence, "server", mode=mode)
                        failed.update(passed=False, failure="fault_phase_failed")
                        outcome["report"] = failed
            worker = threading.Thread(target=serve, name="audit-store-" + mode)
            worker.start()
            try:
                ready = fault_wait_ready(server, mode, container["id"], image_id, worker)
                check("audit_store_" + mode + "_ready", True)
                ready_name = GUEST + "/fault-" + mode + "-ready.json"
                client.write_file(ready_name, json.dumps(ready).encode())
                summary["operation"] = phase
                check("audit_store_" + phase + "_complete", run(client, phase, "fault-" + phase + ".json",
                       "--ready-file", ready_name)["passed"])
            finally:
                # Even if client PUT/transport/evidence fails, release exactly
                # this window and join its bounded server + independent watchdog.
                if ready is not None:
                    try:
                        server.write_file(GUEST + "/fault-" + mode + "-release.json",
                                          json.dumps({"version": 1, "nonce": ready["nonce"]}).encode())
                    except Exception:
                        release_ok = False
                worker.join(timeout=140)
                joined = not worker.is_alive()
                check("audit_store_" + mode + "_worker_joined", joined)
                if "report" in outcome:
                    summary["phases"]["fault-" + mode + ".json"] = outcome["report"]
                # Independent read-only check also runs when server report is
                # missing. It never signals arbitrary PIDs or alters product data.
                detached = run(server, "detached", "fault-" + mode + "-detached.json", *identity)
                check("audit_store_" + mode + "_detached", detached.get("detached") is True)
                check("audit_store_" + mode + "_release", release_ok)
            check("audit_store_" + mode + "_window_passed", not outcome.get("failed")
                  and outcome.get("report", {}).get("passed") is True and outcome["report"].get("detached") is True)
        summary["operation"] = "formal_restart"
        server.command_on_guest(f"bash {SOURCE}/deploy/shared-host/manage.sh stop --hostname {server.name}\nbash {SOURCE}/deploy/shared-host/manage.sh start --hostname {server.name}", timeout=900)
        healthy(server)
        run(server, "restarted", "fault-restarted.json", "--server-report", GUEST + "/fault-inject.json", *identity)
        for name in ("fault-inject.json", "fault-restarted.json"):
            client.write_file(GUEST + "/" + name, server.read_file(GUEST + "/" + name))
        summary["operation"] = "verify"
        check("audit_store_restarted_session_and_audit", run(client, "verify", "fault-verify.json",
              "--server-report", GUEST + "/fault-inject.json", "--restart-report", GUEST + "/fault-restarted.json")["passed"])
        summary["operation"] = "sentinel"
        for vm in (server, client):
            check("audit_store_sentinel_after", sentinel_state(vm) == baseline[vm.name])
        summary["passed"] = True
        record_stage(args, evidence, "audit_store_write_failure_verified")
    except Exception:
        summary["passed"] = False
        record_stage(args, evidence, "audit_store_write_failure_probe_failed")
        raise VerificationError("audit_store_write_failure_probe_failed; private state preserved") from None


def build_filebridge(vm):
    vm.command_on_guest(f"""
export DEBIAN_FRONTEND=noninteractive
apt-get install --yes --no-install-recommends golang-go
cd {SOURCE}/tools/filebrowser-agentctl
go build -mod=readonly -trimpath -o {GUEST}/filebrowser-agentctl ./cmd/filebrowser-agentctl
chmod 0700 {GUEST}/filebrowser-agentctl
go version > {GUEST}/filebridge-go-version.txt
test -z "$(git -C {SOURCE} status --porcelain=v1)"
""".replace("\n+", "\n"), timeout=1800)
    return {"go_version": vm.read_file(GUEST + "/filebridge-go-version.txt").decode().strip(), "binary_sha256": hashlib.sha256(vm.read_file(GUEST + "/filebrowser-agentctl")).hexdigest()}


UI_CASE_IDS = ('crud', 'png', 'jpg', 'xlsx', 'logout')
UI_CASE_STATUSES = ('passed', 'failed', 'timedOut', 'skipped', 'interrupted')
UI_CASE_STAGES = {
    'crud': ('login', 'listing', 'upload', 'edit', 'edit_open', 'edit_render', 'edit_focus', 'edit_replace', 'save_menu', 'save_response', 'save_navigation', 'rename', 'download', 'delete'),
    'xlsx': ('login', 'listing', 'xlsx', 'xlsx1_request', 'xlsx1_response', 'xlsx1_status', 'xlsx1_viewer', 'xlsx1_decode',
             'xlsx2_request', 'xlsx2_response', 'xlsx2_status', 'xlsx2_viewer', 'xlsx2_decode', 'xlsx_evidence', 'xlsx_checks'),
    **{case: ('login', 'listing', case) for case in ('png', 'jpg', 'logout')},
}


def ui_case_evidence(raw):
    try:
        if len(raw) > 16 * 1024:
            raise ValueError('case summary exceeds bound')
        lines = raw.splitlines()
        if not 1 <= len(lines) <= 15:
            raise ValueError('case attempt count invalid')
        attempts, final, last_retry = [], {}, {}
        for line in lines:
            record = json.loads(line)
            if not isinstance(record, dict) or set(record) != {'case', 'status', 'retry', 'stage'}:
                raise ValueError('case fields invalid')
            case, status, retry = record['case'], record['status'], record['retry']
            if case not in UI_CASE_IDS or status not in UI_CASE_STATUSES or type(retry) is not int or not 0 <= retry <= 2:
                raise ValueError('case values invalid')
            stage = record['stage']
            if stage is not None and (type(stage) is not str or stage not in UI_CASE_STAGES[case]):
                raise ValueError('case operation invalid')
            if status == 'passed' and stage != UI_CASE_STAGES[case][-1]:
                raise ValueError('passed case has no final operation')
            if retry != last_retry.get(case, -1) + 1:
                raise ValueError('case retry order invalid')
            attempts.append({'case': case, 'status': status, 'retry': retry, 'stage': stage})
            final[case], last_retry[case] = status, retry
        return {'schema': 1, 'attempts': attempts, 'final': final,
                'passed': set(final) == set(UI_CASE_IDS) and all(status == 'passed' for status in final.values())}
    except (ValueError, TypeError, UnicodeError):
        raise VerificationError('UI case evidence missing or invalid; private output suppressed') from None


def ui_raster_evidence(value, *, require_content=True):
    def require(condition):
        if not condition:
            raise VerificationError("UI raster evidence contract failed; private output suppressed") from None

    require(isinstance(value, dict) and set(value) == {'schema', 'rasters'})
    require(type(value['schema']) is int and value['schema'] == 1)
    require(isinstance(value['rasters'], list) and len(value['rasters']) == 2)
    rasters = []
    for raster in value['rasters']:
        require(isinstance(raster, dict) and set(raster) == {'width', 'height', 'nonWhitePixels', 'pixelSha256'})
        require(all(type(raster[field]) is int for field in ('width', 'height', 'nonWhitePixels')))
        require(1 <= raster['width'] <= 1024 and 1 <= raster['height'] <= 1024)
        require(0 <= raster['nonWhitePixels'] <= raster['width'] * raster['height'])
        require(not require_content or raster['nonWhitePixels'] > 10)
        require(isinstance(raster['pixelSha256'], str) and re.fullmatch(r'[0-9a-f]{64}', raster['pixelSha256']) is not None)
        rasters.append({name: raster[name] for name in ('width', 'height', 'nonWhitePixels', 'pixelSha256')})
    require(not require_content or rasters[0]['pixelSha256'] != rasters[1]['pixelSha256'])
    return {'schema': 1, 'rasters': rasters}


def real_ui(vm):
    # Browser/API trust is installed only inside this disposable test VM. The
    # browser runs as the unprivileged management user, with private outputs.
    result = vm.command_on_guest(f"""
export DEBIAN_FRONTEND=noninteractive
apt-get install --yes --no-install-recommends nodejs npm libnss3-tools
install -m 0644 {GUEST}/ca.crt /usr/local/share/ca-certificates/cf-verification.crt
update-ca-certificates >/dev/null
cd {SOURCE}/frontend
npm ci --no-audit --no-fund
PLAYWRIGHT_BROWSERS_PATH=/opt/cf-playwright npx playwright install --with-deps chromium
install -d -o {VM_USER} -g users -m 0700 /home/{VM_USER}/verification /home/{VM_USER}/.pki /home/{VM_USER}/.pki/nssdb
install -o {VM_USER} -g users -m 0600 {GUEST}/ca.crt /home/{VM_USER}/verification/ca.crt
install -o {VM_USER} -g users -m 0600 {GUEST}/api-state.json /home/{VM_USER}/verification/api-state.json
sudo -u {VM_USER} certutil -N -d sql:/home/{VM_USER}/.pki/nssdb --empty-password
sudo -u {VM_USER} certutil -A -d sql:/home/{VM_USER}/.pki/nssdb -n 'CF disposable verification CA' -t 'C,,' -i /home/{VM_USER}/verification/ca.crt
sudo -u {VM_USER} env HOME=/home/{VM_USER} PLAYWRIGHT_BROWSERS_PATH=/opt/cf-playwright NODE_EXTRA_CA_CERTS=/home/{VM_USER}/verification/ca.crt FILEBROWSER_ACCEPTANCE_CA=/home/{VM_USER}/verification/ca.crt FILEBROWSER_ACCEPTANCE_URL=https://{TLS_NAME}:{TLS_PORT} FILEBROWSER_ACCEPTANCE_STATE=/home/{VM_USER}/verification/api-state.json FILEBROWSER_ACCEPTANCE_OUTPUT=/home/{VM_USER}/verification/playwright-output npx playwright test --project shared-host
test -z "$(git -C {SOURCE} status --porcelain=v1)"
""", timeout=1800, check=False)
    report = {'passed': False, 'cases': {'passed': False, 'failure': 'missing-or-invalid'}, 'raster_passed': False}
    if type(result.returncode) is int and -255 <= result.returncode <= 255:
        report['process_exit_code'] = result.returncode
    output = f"/home/{VM_USER}/verification/playwright-output/"
    try:
        report['cases'] = ui_case_evidence(vm.read_file(output + 'ui-case-evidence.ndjson'))
    except (VerificationError, OSError, ValueError, TypeError):
        pass
    try:
        raw = vm.read_file(output + 'xlsx-raster-evidence.json')
        if len(raw) > 16 * 1024:
            raise ValueError('bounded raster summary exceeded')
        report['raster'] = ui_raster_evidence(json.loads(raw), require_content=False)
        ui_raster_evidence(report['raster'])
        report['raster_passed'] = True
    except (VerificationError, OSError, ValueError, TypeError):
        pass
    report['passed'] = report.get('process_exit_code') == 0 and report['cases']['passed'] and report['raster_passed']
    if not report['passed']:
        error = VerificationError('existing Playwright UI failed; sanitized case evidence retained')
        error.ui_evidence = report
        raise error from None
    return report


def continuable_initial_ui_failure(error):
    """Only completed case failures qualify; transport/setup failures still stop."""
    report = getattr(error, "ui_evidence", None)
    required = {"passed", "process_exit_code", "cases", "raster_passed"}
    try:
        if (not isinstance(report, dict) or not required.issubset(report)
                or set(report) - required - {"raster"} or report["passed"] is not False
                or type(report["process_exit_code"]) is not int or report["process_exit_code"] != 1
                or type(report["raster_passed"]) is not bool):
            return None
        cases = report["cases"]
        if (not isinstance(cases, dict) or set(cases) != {"schema", "attempts", "final", "passed"}
                or type(cases["schema"]) is not int or cases["schema"] != 1 or cases["passed"] is not False
                or not isinstance(cases["attempts"], list) or len(cases["attempts"]) != len(UI_CASE_IDS)):
            return None
        verified = ui_case_evidence(b"\n".join(json.dumps(item).encode() for item in cases["attempts"]))
        if (verified != cases or verified["passed"] is not False or set(verified["final"]) != set(UI_CASE_IDS)
                or any(item["retry"] != 0 or item["stage"] is None for item in verified["attempts"])
                or any(status not in ("passed", "failed", "timedOut") for status in verified["final"].values())
                or not any(status in ("failed", "timedOut") for status in verified["final"].values())):
            return None
        safe = {"passed": False, "process_exit_code": 1, "cases": verified, "raster_passed": False}
        if "raster" in report:
            safe["raster"] = ui_raster_evidence(report["raster"], require_content=False)
            try:
                ui_raster_evidence(safe["raster"])
                safe["raster_passed"] = True
            except VerificationError:
                pass
        if verified["final"]["xlsx"] == "passed" and not safe["raster_passed"]:
            return None
        return safe if safe["raster_passed"] == report["raster_passed"] else None
    except (VerificationError, ValueError, TypeError, KeyError, UnicodeError):
        return None


def initial_ui_with_preservation(server, client, args, evidence, image_id, pinned, baseline):
    try:
        evidence["initial_ui"] = real_ui(client)
        return
    except VerificationError as error:
        report = continuable_initial_ui_failure(error)
        if report is None:
            raise
    evidence["initial_ui"] = report
    evidence["result"] = "failed"
    evidence.setdefault("ui_failures", []).append("initial_ui")
    snapshot = {"passed": False, "kind": "controlled_stop_disk_snapshot",
                "includes": ["business_files", "database_and_audit", "configuration_and_keys"],
                "private_ui_output_retained": True, "process_memory_preserved": False}
    evidence["initial_ui_preservation"] = snapshot
    record_stage(args, evidence, "initial-ui-failure-preservation")
    for vm in (server, client):
        if sentinel_state(vm) != baseline[vm.name]:
            raise VerificationError("UI failure preservation refused: unrelated project changed")
    original = json.loads(server.command_on_guest(pending_container_script(image_id), timeout=20).stdout)
    if (original.get("running") is not True or original.get("healthy") is not True or original.get("image") != image_id
            or re.fullmatch(r"[a-f0-9]{64}", original.get("id", "")) is None):
        raise VerificationError("UI failure preservation requires the healthy original fixed-image service")
    archive = "/srv/storage/cf-filebrowser-enterprise/backups/ui-failure-initial.tar"
    flags = shlex.join(["--hostname", server.name, "--source-sha", args.source_sha, "--image-ref", pinned, "--image-id", image_id])
    server.command_on_guest(f"bash {SOURCE}/deploy/shared-host/backup.sh create {archive} {flags}", timeout=900)
    # The formal backup is create-only and validates its entire archive. Recheck
    # its protected inode before resuming; keep it private for the runner lifetime.
    raw = server.command_on_guest("""python3 -B - <<'UI_FAILURE_SNAPSHOT'
import hashlib,json,os,stat
path='/srv/storage/cf-filebrowser-enterprise/backups/ui-failure-initial.tar'
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
with os.fdopen(fd,'rb') as stream:
    before=os.fstat(stream.fileno())
    if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode)!=0o600
            or before.st_uid!=0 or before.st_gid!=0 or before.st_nlink!=1 or before.st_size<=0):
        raise SystemExit(1)
    checksum=hashlib.file_digest(stream,'sha256').hexdigest()
    after=os.fstat(stream.fileno())
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
        raise SystemExit(1)
print(json.dumps({'version':1,'verified':True,'sha256':checksum,'size':before.st_size}))
UI_FAILURE_SNAPSHOT
""", timeout=120).stdout
    try:
        saved = json.loads(raw)
        if (not isinstance(saved, dict) or set(saved) != {"version", "verified", "sha256", "size"}
                or type(saved["version"]) is not int or saved["version"] != 1 or saved["verified"] is not True
                or type(saved["size"]) is not int or saved["size"] <= 0
                or not isinstance(saved["sha256"], str) or re.fullmatch(r"[a-f0-9]{64}", saved["sha256"]) is None):
            raise ValueError("invalid snapshot summary")
    except (ValueError, TypeError, UnicodeError):
        raise VerificationError("UI failure snapshot metadata is invalid; private data retained") from None
    snapshot.update(passed=True, archive_sha256=saved["sha256"], archive_bytes=saved["size"])
    record_stage(args, evidence, "initial-ui-failure-private-snapshot-retained")
    server.command_on_guest(f"bash {SOURCE}/deploy/shared-host/manage.sh start --hostname {server.name}", timeout=900)
    healthy(server)
    resumed = json.loads(server.command_on_guest(pending_container_script(image_id, original["id"]), timeout=20).stdout)
    if resumed.get("id") != original["id"] or resumed.get("image") != image_id or resumed.get("healthy") is not True or resumed.get("running") is not True:
        raise VerificationError("UI failure preservation did not resume the original healthy fixed-image service")
    for vm in (server, client):
        if sentinel_state(vm) != baseline[vm.name]:
            raise VerificationError("unrelated project changed during UI failure preservation")
    record_stage(args, evidence, "initial-ui-failed-independent-lifecycle-continuing")


def complete_scenario(args, evidence):
    if evidence.get("ui_failures") or any(evidence.get(phase, {}).get("passed") is not True for phase in ("initial_ui", "restored_ui")):
        evidence["result"] = "failed"
        record_stage(args, evidence, "completed-with-ui-failure")
        raise VerificationError("UI acceptance failed; completed independent lifecycle/restore results and private disk snapshot retained")
    evidence["result"] = "passed"
    record_stage(args, evidence, "completed")


LAN_PROBE_STAGES = ('guest-dispatch', 'allowed-health-before', 'allowed-ui', 'trusted-context',
                    'denied-tcp-connect', 'denied-socket-identity', 'denied-tls-handshake',
                    'wrong-ca', 'allowed-health-after', 'complete')
LAN_ERROR_CATEGORIES = ('assertion', 'tls-certificate', 'dns', 'timeout', 'eof', 'connection',
                        'tls', 'os', 'internal', 'invalid-report')
LAN_INTEGER_FIELDS = {'curl_exit_code': (-255, 255), 'http_status': (100, 599),
                      'elapsed_ms': (0, 3_600_000), 'application_bytes_received': (0, 1_048_576),
                      'errno': (-32768, 32767), 'verify_code': (0, 255)}


def lan_safe_fields(value):
    if not isinstance(value, dict):
        return {}
    safe = {}
    for name, (minimum, maximum) in LAN_INTEGER_FIELDS.items():
        number = value.get(name)
        if type(number) is int and minimum <= number <= maximum:
            safe[name] = number
    for name in ('body_expected', 'tcp_connected', 'source_matches', 'peer_matches', 'tls_handshake_completed'):
        if type(value.get(name)) is bool:
            safe[name] = value[name]
    if value.get('category') in LAN_ERROR_CATEGORIES:
        safe['category'] = value['category']
    if value.get('rejection') in ('tls-eof', 'tcp-reset'):
        safe['rejection'] = value['rejection']
    return safe


def lan_error_fields(error):
    # Classify a known transport cause, never serialize its text or type name.
    cause = error.__cause__ if isinstance(error, VerificationError) and error.__cause__ is not None else error
    category = 'internal'
    for kind, label in ((ssl.SSLCertVerificationError, 'tls-certificate'), (socket.gaierror, 'dns'),
                        ((TimeoutError, subprocess.TimeoutExpired), 'timeout'), (ssl.SSLEOFError, 'eof'),
                        (ConnectionError, 'connection'), (ssl.SSLError, 'tls'), (OSError, 'os'),
                        (VerificationError, 'assertion')):
        if isinstance(cause, kind):
            category = label
            break
    fields = {'category': category, 'errno': getattr(cause, 'errno', None)}
    if isinstance(cause, ssl.SSLCertVerificationError):
        fields['verify_code'] = getattr(cause, 'verify_code', None)
    return lan_safe_fields(fields)


def sanitized_lan_report(value):
    report = {'schema': 'cf-lan-boundary/v1', 'passed': False, 'stage': 'guest-dispatch',
              'completed': [], 'observations': {}, 'failure': {'category': 'invalid-report'}}
    if not isinstance(value, dict) or value.get('schema') != report['schema']:
        return report
    if value.get('stage') in LAN_PROBE_STAGES:
        report['stage'] = value['stage']
    if isinstance(value.get('completed'), list):
        expected_prefix = LAN_PROBE_STAGES[1:LAN_PROBE_STAGES.index(report['stage'])]
        for expected, claimed in zip(expected_prefix, value['completed']):
            if claimed != expected:
                break
            report['completed'].append(expected)
    observable = set(report['completed'])
    if report['stage'] in LAN_PROBE_STAGES[1:-1]:
        observable.add(report['stage'])
    if isinstance(value.get('observations'), dict):
        report['observations'] = {stage: lan_safe_fields(fields) for stage, fields in value['observations'].items() if stage in observable}
    failure = lan_safe_fields(value.get('failure'))
    report['failure'] = failure if 'category' in failure else report['failure']
    required = {stage: {'curl_exit_code': 0, 'http_status': 200, 'body_expected': True}
                for stage in ('allowed-health-before', 'allowed-ui', 'allowed-health-after')}
    required.update({'denied-tcp-connect': {'tcp_connected': True},
                     'denied-socket-identity': {'source_matches': True, 'peer_matches': True},
                     'denied-tls-handshake': {'tls_handshake_completed': False, 'application_bytes_received': 0},
                     'wrong-ca': {'curl_exit_code': 60}})
    observed = all(report['observations'].get(stage, {}).get(name) == expected
                   for stage, fields in required.items() for name, expected in fields.items())
    denied = report['observations'].get('denied-tls-handshake', {})
    prompt_refusal = denied.get('rejection') in ('tls-eof', 'tcp-reset') and type(denied.get('elapsed_ms')) is int and 0 <= denied['elapsed_ms'] < 5000
    report['passed'] = value.get('passed') is True and 'failure' not in value and report['stage'] == 'complete' and report['completed'] == list(LAN_PROBE_STAGES[1:-1]) and observed and prompt_refusal
    if report['passed']:
        report.pop('failure')
    return report


def lan_probe_report(ca_file, untrusted_ca_file, empty_trust):
    report = {'schema': 'cf-lan-boundary/v1', 'passed': False, 'stage': 'guest-dispatch',
              'completed': [], 'observations': {}}
    try:
        probe_lan_boundary(ca_file, untrusted_ca_file, empty_trust, report=report)
        report.update(passed=True, stage='complete')
    except Exception as error:
        report['failure'] = lan_error_fields(error)
    return sanitized_lan_report(report)


def probe_lan_boundary(ca_file, untrusted_ca_file, empty_trust, *, report=None):
    """Run in the disposable client guest; never treat transport trouble as denial."""
    report = report if report is not None else {'stage': 'guest-dispatch', 'completed': [], 'observations': {}}

    def stage(name):
        report['stage'] = name

    def observed(**fields):
        report['observations'].setdefault(report['stage'], {}).update(lan_safe_fields(fields))

    def completed():
        report['completed'].append(report['stage'])

    base = f"https://{TLS_NAME}:{TLS_PORT}"
    common = ["curl", "--fail", "--silent", "--show-error", "--noproxy", "*",
              "--interface", CLIENT_IP, "--max-time", "5", "--write-out", "\n%{http_code}"]

    def curl(path, ca, *extra):
        try:
            return subprocess.run(common + ["--cacert", str(ca), *extra, base + path],
                                  capture_output=True, check=False, timeout=10)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise VerificationError("LAN curl probe did not complete; private output suppressed") from error

    def allowed(path, *headers):
        response = curl(path, ca_file, *headers)
        body, _, status = response.stdout.rpartition(b"\n")
        expected = b'<html' in body if path == '/' else body.strip() == b'{"message":"ok"}'
        observed(curl_exit_code=response.returncode, http_status=int(status) if re.fullmatch(rb'[1-5][0-9]{2}', status) else None, body_expected=expected)
        if response.returncode != 0 or status != b'200' or not expected:
            raise VerificationError("allowed-source HTTPS control failed; private output suppressed")
        return 200

    stage('allowed-health-before')
    before = allowed('/health')
    completed()
    stage('allowed-ui')
    allowed('/')
    completed()
    stage('trusted-context')
    context = ssl.create_default_context(cafile=str(ca_file))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    completed()
    raw = secured = None
    try:
        stage('denied-tcp-connect')
        try:
            raw = socket.create_connection((TLS_NAME, TLS_PORT), timeout=5, source_address=(DENIED_IP, 0))
        except OSError as error:
            raise VerificationError("denied-source TCP must connect before testing listener refusal") from error
        observed(tcp_connected=True)
        completed()
        stage('denied-socket-identity')
        source, peer = raw.getsockname()[0], raw.getpeername()[0]
        observed(source_matches=source == DENIED_IP, peer_matches=peer == SERVER_IP)
        if source != DENIED_IP or peer != SERVER_IP:
            raise VerificationError("denied-source socket identity differs from the isolated LAN fixture")
        completed()
        stage('denied-tls-handshake')
        secured = context.wrap_socket(raw, server_hostname=TLS_NAME, do_handshake_on_connect=False)
        started = time.monotonic()
        try:
            secured.do_handshake()
        except ssl.SSLEOFError:
            rejection = 'tls-eof'
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            rejection = 'tcp-reset'
        except OSError as error:
            # Timeout, invalid certificate and other TLS/protocol errors do not
            # establish that the native listener refused this TCP peer.
            raise VerificationError("denied-source probe failed without a prompt EOF/reset") from error
        else:
            observed(tls_handshake_completed=True)
            raise VerificationError("denied-source socket unexpectedly completed TLS")
        elapsed = time.monotonic() - started
        observed(tls_handshake_completed=False, rejection=rejection, application_bytes_received=0, elapsed_ms=int(elapsed * 1000))
        if elapsed >= 5:
            raise VerificationError("denied-source refusal was not prompt")
        completed()
    finally:
        if secured is not None:
            secured.close()
        elif raw is not None:
            raw.close()

    stage('wrong-ca')
    untrusted = curl('/health', untrusted_ca_file, '--capath', str(empty_trust))
    observed(curl_exit_code=untrusted.returncode)
    if untrusted.returncode != 60:
        raise VerificationError("untrusted CA probe must fail with curl certificate verification exit 60")
    completed()
    stage('allowed-health-after')
    # The denied peer cannot send HTTP headers: TLS is refused first. Exercise
    # forged forwarding headers over valid HTTPS from the allowed socket instead.
    after = allowed('/health', '-H', 'X-Forwarded-For: ' + DENIED_IP,
                    '-H', 'X-Real-IP: ' + DENIED_IP)
    completed()
    return {'allowed_before_status': before, 'allowed_after_status': after,
            'allowed_source': CLIENT_IP, 'forwarded_headers_ignored_on_allowed_tls': True,
            'untrusted_ca_exit_code': untrusted.returncode,
            'denied_source': {'tcp_connected': True, 'socket_source': source, 'socket_peer': peer,
                              'tls_handshake_completed': False, 'rejection': rejection,
                              'application_bytes_received': 0, 'elapsed_ms': round(elapsed * 1000)}}


def lan_boundary(vm):
    response = vm.command_on_guest(f"""
ip address add {DENIED_IP}/24 dev cflan
trap 'ip address del {DENIED_IP}/24 dev cflan' EXIT
mkdir -p {GUEST}/empty-trust
python3 -B - <<'CF_LAN_BOUNDARY'
import importlib.util,json
spec=importlib.util.spec_from_file_location('cf_vm_lan_probe','{SOURCE}/scripts/tests/shared_host_vm.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
report=module.lan_probe_report('{GUEST}/ca.crt','{GUEST}/untrusted-ca.crt','{GUEST}/empty-trust')
print(json.dumps(report,sort_keys=True))
raise SystemExit(0 if report['passed'] else 1)
CF_LAN_BOUNDARY
""", check=False)
    try:
        report = sanitized_lan_report(json.loads(response.stdout))
    except (ValueError, UnicodeError):
        report = sanitized_lan_report(None)
    if response.returncode or not report['passed']:
        report['passed'] = False
        error = VerificationError(f"{vm.name}: LAN boundary failed at {report['stage']}; sanitized check evidence retained")
        error.lan_evidence = report
        raise error
    return report


def record_stage(args, evidence, name):
    evidence["stage"] = name
    (args.evidence / "vm-result.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print("[shared-host-vm] stage=" + name, flush=True)



def recovery_probe(vm, args, evidence, name, arguments):
    command = "python3 " + SOURCE + "/scripts/tests/shared_host_restore_evidence.py " + shlex.join(arguments)
    process = vm.command_on_guest(command, check=False)
    try:
        report = json.loads(process.stdout)
        if not isinstance(report, dict):
            raise ValueError("invalid report")
    except (ValueError, UnicodeError):
        report = {"verified": False, "failure": "guest recovery probe did not return a valid report",
                  "private_output_sha256": hashlib.sha256(process.stdout).hexdigest()}
    evidence[name] = report
    # Persist the sanitized guest outcome before failing the scenario.
    record_stage(args, evidence, name)
    if process.returncode != 0 or report.get("verified") is not True:
        raise VerificationError("protected recovery evidence validation failed: " + name)
    return report



def storage_evidence(vm, args, evidence, phase, probe_path=None):
    if phase not in ('before','after','failure','mount-diagnostic','control-5s','control-90s-before','control-90s'):
        raise VerificationError('unknown storage evidence phase')
    path = probe_path or SOURCE + "/scripts/tests/shared_host_storage_probe.py"
    response = vm.command_on_guest(f"python3 -B {shlex.quote(path)} {phase}", check=False, timeout=180)
    try:
        if len(response.stdout) > 1024 * 1024:
            raise ValueError('storage evidence bound')
        report = json.loads(response.stdout)
        if not isinstance(report, dict) or response.returncode or report.get('collection_failed'):
            raise ValueError('storage evidence unavailable')
    except (ValueError, UnicodeError) as error:
        evidence['storage_' + phase] = {'collection_failed': True, 'exit_code': response.returncode}
        record_stage(args, evidence, 'storage-evidence/' + phase)
        raise VerificationError('bounded storage evidence unavailable: ' + phase) from error
    evidence['storage_' + phase] = report
    record_stage(args, evidence, 'storage-evidence/' + phase)
    return report


def verify_storage_evidence(before, after):
    # Import only the pure comparisons; the destructive guest CLI has its own guard.
    from shared_host_storage_probe import same_disk, unchanged_underlay
    if not same_disk(before, after):
        raise VerificationError('storage test disk identity changed or is unavailable')
    if not unchanged_underlay(before, after):
        raise VerificationError('root filesystem storage underlay changed or was not fully observed')
    if before['root_underlay']['entry_count'] != 0:
        raise VerificationError('root filesystem storage underlay was not empty before reboot')


def targeted_reboot(args, evidence, server, client, image_id, baseline):
    """Reuse formal setup; finish before the independent full acceptance suites."""
    evidence['scope'] = 'reboot-blocker-only'
    record_stage(args, evidence, 'reboot-target/seed-file-and-permission-state')
    evidence['reboot_initial_api'] = api(client, 'reboot-seed', 'api-reboot-seed.json')
    before = reboot_observation(server)
    evidence['reboot_before_state'] = before
    verify_reboot_state(before, image_id)
    storage_before = storage_evidence(server, args, evidence, 'before')
    verify_storage_evidence(storage_before, storage_before)
    try:
        evidence['host_reboot'] = reboot_operation(args, evidence, server, 'boot-id-change', server.reboot)
        reboot_operation(args, evidence, server, 'container-health', lambda: healthy(server))
    except REBOOT_ERRORS:
        failed_stage = evidence['stage']
        try:
            storage_evidence(server, args, evidence, 'failure')
            # Failure evidence is persisted above BEFORE the single optional
            # diagnostic mount. No manual FileBrowser start or API success claim.
            storage_evidence(server, args, evidence, 'mount-diagnostic')
        except REBOOT_ERRORS as error:
            evidence['storage_collection_failure'] = reboot_error_class(error)
        record_stage(args, evidence, failed_stage)
        raise
    storage_after = storage_evidence(server, args, evidence, 'after')
    verify_storage_evidence(storage_before, storage_after)
    evidence['root_storage_underlay_unchanged'] = True
    after = reboot_observation(server)
    evidence['reboot_after_state'] = after
    verify_reboot_state(after, image_id)
    for field in ('container_id', 'image_id', 'storage_uuid', 'config_sha256'):
        if before[field] != after[field]:
            raise VerificationError('reboot changed protected state: ' + field)
    evidence['host_restart_lan_boundary'] = reboot_operation(args, evidence, client, 'https-lan', lambda: lan_boundary(client), diagnostic_vm=server)
    evidence['host_restart_api'] = reboot_operation(args, evidence, client, 'file-api', lambda: api(client, 'reboot-verify', 'api-reboot-verify.json'), diagnostic_vm=server)
    for vm in (server, client):
        if sentinel_state(vm) != baseline[vm.name]:
            raise VerificationError('reboot changed unrelated project identity/network/port/data')
    evidence['boundaries'] = {'B': 'reboot blocker targeted verification only; full A/B acceptance remains separate',
                              'UI_PDF_OnlyOffice_restore': 'not executed by this scope',
                              'C': 'not executed; no target device or production client accessed'}
    evidence['result'] = 'passed'
    record_stage(args, evidence, 'reboot-target/complete')


def storage_control(args, work, evidence, base, key):
    """One same-disk, same-guest 5s/90s device-budget experiment; no app image."""
    vm=VM(1,work,base,key,port(),args.accelerator)
    evidence.update(scope='storage-control-only',actual_vm_count=1)
    try:
        record_stage(args,evidence,'storage-control/guest-prepare')
        vm.launch();vm.wait_ready()
        # Retain the same guest OS/Docker packages and boot load as product runs,
        # but acquire no FileBrowser source, image, registry or business assets.
        prerequisites(vm,args.source_sha,storage_only=True)
        vm.write_file(GUEST+'/storage-probe.py',(ROOT/'scripts/tests/shared_host_storage_probe.py').read_bytes())
        vm.command_on_guest('systemctl daemon-reload')
        probe=lambda phase: storage_evidence(vm,args,evidence,phase,GUEST+'/storage-probe.py')
        before=probe('before');verify_storage_evidence(before,before)
        record_stage(args,evidence,'storage-control/original-5s-reboot')
        evidence['control_5s_boot']=vm.reboot()
        after=probe('control-5s');verify_storage_evidence(before,after)
        if after['boot_id']!=evidence['control_5s_boot']['after']:
            raise VerificationError('storage control boot evidence mismatch')
        events=after['journal']['events']+after['pid1_events']
        failed={e['unit'] for e in events if e['unit'].endswith('.device') and e.get('JOB_RESULT')=='timeout'}
        budgets={n:after['related_units'].get(n,{}).get('JobRunningTimeoutUSec') for n in failed}
        evidence['control_failed_device_budgets']=budgets
        if after['mounted'] or not failed or any(v!='5s' for v in budgets.values()):
            raise VerificationError('original storage control lacks a failed device job with observed 5s budget; no variable change attempted')
        # Exactly one variable; preserve UUID, nofail, fsck pass and all other rows.
        record_stage(args,evidence,'storage-control/change-only-device-budget')
        vm.command_on_guest("""
python3 - <<'CONTROL_FSTAB'
from pathlib import Path
p=Path('/etc/fstab');text=p.read_text();rows=text.splitlines(keepends=True)
hits=[i for i,line in enumerate(rows) if not line.lstrip().startswith('#') and len(line.split())==6 and line.split()[1]=='/srv/storage']
assert len(hits)==1
old=rows[hits[0]];assert old.split()[3]=='defaults,nofail,x-systemd.device-timeout=5s'
rows[hits[0]]=old.replace('x-systemd.device-timeout=5s','x-systemd.device-timeout=90s')
Path('/root/cf-verification/fstab-control-5s').write_text(text)
p.write_text(''.join(rows))
CONTROL_FSTAB
systemctl daemon-reload
""")
        probe('control-90s-before')
        record_stage(args,evidence,'storage-control/finite-90s-reboot')
        evidence['control_90s_boot']=vm.reboot()
        after=probe('control-90s');verify_storage_evidence(before,after)
        if after['boot_id']!=evidence['control_90s_boot']['after'] or not after['mounted']:
            raise VerificationError('finite device-budget control did not mount automatically')
        evidence.update(result='passed',automatic_storage_mount=True,
                        boundaries='storage hypothesis experiment only; no FileBrowser/API, manual mount or product recovery claim')
        record_stage(args,evidence,'storage-control/complete')
    finally:
        vm.close()


def verify_reboot_state(state, image_id):
    expected = {'available': True, 'docker': 'active', 'storage_mounted': True, 'storage_on_root_device': False,
                'storage_identity_matches': True, 'bootstrap_absent': True, 'container_count': 1,
                'running': True, 'status': 'running', 'health': 'healthy', 'image_id': image_id}
    for field, value in expected.items():
        if state.get(field) != value:
            raise VerificationError('reboot runtime state rejected: ' + field)
    for field in ('container_id', 'storage_uuid', 'config_sha256'):
        if not state.get(field):
            raise VerificationError('reboot runtime identity absent: ' + field)

def scenario(args, work, evidence):
    record_stage(args, evidence, "official-debian-image-download-and-sha512")
    base, cloud_record = cloud_image(work)
    evidence.update(cloud_image=cloud_record)
    record_stage(args, evidence, "two-vm-resource-preflight")
    base_info = json.loads(execute(["qemu-img", "info", "--output=json", str(base)]).stdout)
    evidence["resources"] = resource_budget(base_info["virtual-size"])
    evidence["resources"]["host_free_disk_bytes"] = shutil.disk_usage(work).free
    available = next(int(line.split()[1]) * 1024 for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:"))
    evidence["resources"]["host_available_memory_bytes"] = available
    if evidence["resources"]["host_free_disk_bytes"] < 12 * GIB or available < evidence["resources"]["configured_memory_bytes"]:
        raise VerificationError("runner has less than 12 GiB free disk or the configured 4 GiB RAM available; no VM or disk expansion attempted")
    key = work / "client-key"
    execute(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
    if args.scope == "storage":
        storage_control(args, work, evidence, base, key)
        return
    tls = certificates(work)
    registry_id = None
    vms = []
    try:
        record_stage(args, evidence, "isolated-tls-registry-publish")
        registry_port = port()
        registry_id, pinned, image_id, registry_image = registry(work, tls, args.image_ref, args.source_sha, registry_port)
        evidence.update(image_id=image_id, registry_reference=pinned, registry_image_id=registry_image)
        record_stage(args, evidence, "verify-published-registry-manifest-and-config")
        expected_image = registry_identity(pinned, tls / "ca.crt")
        evidence["registry_identity"] = {key: value for key, value in expected_image.items() if key != "config"}
        builder_info = json.loads(execute(["docker", "image", "inspect", pinned]).stdout)[0]
        evidence["builder_image"] = image_identity_record(builder_info)
        record_stage(args, evidence, "verify-builder-image-content")
        verify_image_identity(builder_info, expected_image, args.source_sha)
        guest_images = {}
        peer_port = port()
        record_stage(args, evidence, "create-and-boot-two-debian-systemd-vms")
        for number in (1, 2):
            vm = VM(number, work, base, key, peer_port, args.accelerator)
            vms.append(vm)
        seed_size = sum((vm.directory / "seed.iso").stat().st_size for vm in vms)
        evidence["resources"].update(resource_budget(base_info["virtual-size"], seed_size))
        record_stage(args, evidence, "launch-two-debian-systemd-vms")
        for vm in vms:
            vm.launch()
        for vm in vms:
            record_stage(args, evidence, "cloud-init-and-dependencies-" + vm.name)
            vm.wait_ready()
            prerequisites(vm, args.source_sha)
            evidence.setdefault("environments", {})[vm.name] = json.loads(vm.command_on_guest("""
python3 - <<'ENVIRONMENT'
import json,platform,subprocess
from pathlib import Path
def out(*argv):
    return subprocess.check_output(argv).decode().strip()
print(json.dumps({"os_release":Path('/etc/os-release').read_text(),"kernel":platform.release(),"architecture":platform.machine(),"pid1":out('ps','-p','1','-o','comm='),"docker":json.loads(out('docker','version','--format','{{json .}}')),"compose":out('docker','compose','version','--short'),"storage":json.loads(out('findmnt','--json','--target','/srv/storage')),"source_sha":out('git','-C','/opt/cf-filebrowser-enterprise','rev-parse','HEAD')},sort_keys=True))
ENVIRONMENT
""".replace("\n+", "\n")).stdout)
            vm.write_file(GUEST + "/ca.crt", (tls / "ca.crt").read_bytes())
            vm.write_file(GUEST + "/untrusted-ca.crt", (tls / "untrusted-ca.crt").read_bytes())
            record_stage(args, evidence, "fresh-registry-digest-pull-" + vm.name)
            vm.forward_registry(registry_port)
            vm.command_on_guest(f"""
test -z "$(docker image ls --quiet)"
install -d -m 0755 /etc/docker/certs.d/localhost:{registry_port}
install -m 0644 {GUEST}/ca.crt /etc/docker/certs.d/localhost:{registry_port}/ca.crt
curl --fail --silent --show-error --cacert {GUEST}/ca.crt https://localhost:{registry_port}/v2/ >/dev/null
docker pull {shlex.quote(pinned)} >/dev/null
""", timeout=1800)
            guest_info = json.loads(vm.command_on_guest("docker image inspect " + shlex.quote(pinned)).stdout)[0]
            guest_images[vm.name] = guest_info["Id"]
            evidence["environments"][vm.name]["image"] = image_identity_record(guest_info)
            record_stage(args, evidence, "verify-pulled-image-content-" + vm.name)
            verify_image_identity(guest_info, expected_image, args.source_sha)
            record_stage(args, evidence, "never-started-container-image-probe-" + vm.name)
            probe = container_image_probe(vm, pinned)
            evidence["environments"][vm.name]["image"]["container_probe"] = probe
            record_stage(args, evidence, "verify-local-container-image-contract-" + vm.name)
            if probe["container_image_id"] != guest_info["Id"] or probe["status"] != "created" or probe["running"] or probe["network_mode"] != "none" or probe["mount_count"]:
                raise VerificationError("never-started container does not match the local image identity/isolation contract")
        server, client = vms
        image_id = guest_images[server.name]
        if guest_images[client.name] != image_id:
            raise VerificationError("the two clean Debian Docker environments resolve different local Image IDs; restore requires an explicit compatibility decision")
        evidence["deployment_image_id"] = image_id
        evidence["checks"].append("builder and both fresh guests match pinned registry/config/source/layers; each never-started isolated container matches its environment's recorded actual Image ID")
        record_stage(args, evidence, "unrelated-project-isolation-baseline")
        baseline = {vm.name: sentinel(vm) for vm in vms}
        password = os.urandom(24).hex().encode() + b"\n"
        for vm in vms:
            vm.write_file(GUEST + "/admin-password", password, "0400")
        for name in ("server.crt", "server.key"):
            server.write_file(GUEST + "/" + name, (tls / name).read_bytes(), "0400")
        manage = f"bash {SOURCE}/deploy/shared-host/manage.sh"
        record_stage(args, evidence, "formal-empty-root-prepare")
        server.command_on_guest(f"""
test ! -e /etc/cf-filebrowser-enterprise
test ! -e /var/lib/cf-filebrowser-enterprise
test ! -e /srv/storage/cf-filebrowser-enterprise
{manage} prepare --hostname {server.name} --source-sha {args.source_sha} --image-ref {shlex.quote(pinned)} --mode staging --exposure lan --test-disk --enable-share-source --enable-webdav --bootstrap-password-file {GUEST}/admin-password --lan-bind-address {SERVER_IP} --lan-port {TLS_PORT} --lan-allowed-cidrs {CLIENT_IP}/32 --tls-name {TLS_NAME} --tls-cert-file {GUEST}/server.crt --tls-key-file {GUEST}/server.key --tls-ca-file {GUEST}/ca.crt
""", timeout=900)
        record_stage(args, evidence, "first-start")
        server.command_on_guest(f"{manage} start --hostname {server.name}", timeout=900)
        record_stage(args, evidence, "bootstrap-admin-verification-stop-remove-restart-login")
        server.command_on_guest(f"{manage} bootstrap-finish --hostname {server.name}\ntest ! -e /etc/cf-filebrowser-enterprise/secrets/bootstrap_admin_password", timeout=900)
        record_stage(args, evidence, "actual-service-identity-tools-and-directory-access")
        evidence["runtime_readiness"] = json.loads(server.command_on_guest(runtime_readiness_script(), timeout=900).stdout)
        record_stage(args, evidence, "verify-actual-service-runtime-contract")
        verify_runtime_readiness(evidence["runtime_readiness"], image_id, args.source_sha)
        evidence["checks"].append("actual service and PID1 UID/GID 10001, dependency versions, writable files/data/cache and denied root/config writes, readable protected inputs without reading their values")
        record_stage(args, evidence, "idempotent-prepare-after-bootstrap")
        server.command_on_guest(f"{manage} prepare --hostname {server.name} --source-sha {args.source_sha} --image-ref {shlex.quote(pinned)} --mode staging --exposure lan --test-disk --enable-share-source --enable-webdav --bootstrap-password-file {GUEST}/admin-password", timeout=900)
        evidence["checks"].append("formal empty-root install, admin verification, bootstrap removal, same-image login, idempotent prepare")
        record_stage(args, evidence, "second-vm-real-lan-and-https-boundaries")
        evidence["initial_lan_boundary"] = lan_boundary(client)
        evidence["checks"].append("second-VM HTTPS UI/API controls before/after, curl certificate rejection, connected denied TCP peer refused before TLS, forwarded headers ignored on allowed HTTPS")
        if args.scope == "reboot":
            targeted_reboot(args, evidence, server, client, image_id, baseline)
            return
        record_stage(args, evidence, "audit-pending-process-interruption")
        audit_pending_interrupt(server, client, args, evidence, image_id, baseline)
        record_stage(args, evidence, "audit-store-real-write-failure")
        audit_store_fault(server, client, args, evidence, image_id, baseline)
        record_stage(args, evidence, "initial-real-api-exercise")
        evidence["initial_api"] = api(client, "exercise", "api-initial.json")
        record_stage(args, evidence, "fixed-source-filebridge-build")
        evidence["filebridge_build"] = build_filebridge(client)
        server.write_file(GUEST + "/filebrowser-agentctl", client.read_file(GUEST + "/filebrowser-agentctl"), "0700")
        record_stage(args, evidence, "real-filebridge-and-webdav-protocols")
        evidence["protocols"] = api(client, "protocols", "api-protocols.json")
        evidence["checks"].append("fixed-source FileBridge binary and WebDAV exercised over strictly verified HTTPS with ordinary-user/Token denial boundaries")
        record_stage(args, evidence, "initial-existing-playwright-ui")
        initial_ui_with_preservation(server, client, args, evidence, image_id, pinned, baseline)
        if evidence["initial_ui"]["passed"]:
            evidence["checks"].append("existing Playwright shared-host project passed in second VM with normal-user Chromium and explicit trusted CA")
        record_stage(args, evidence, "formal-stop-start-and-container-restart")
        server.command_on_guest(f"{manage} stop --hostname {server.name}\n{manage} start --hostname {server.name}")
        server.command_on_guest("docker restart $(docker ps -q --filter label=com.docker.compose.project=cf-filebrowser) >/dev/null")
        healthy(server)
        evidence["container_restart_api"] = api(client, "verify-restored", "api-container-restart.json")
        record_stage(args, evidence, "docker-daemon-restart-and-api")
        server.command_on_guest("systemctl restart docker")
        healthy(server)
        evidence["docker_restart_api"] = api(client, "verify-restored", "api-docker-restart.json")
        record_stage(args, evidence, "real-host-reboot-and-api")
        evidence["host_reboot"] = reboot_operation(args, evidence, server, "boot-id-change", server.reboot)
        reboot_operation(args, evidence, server, "container-health", lambda: healthy(server))
        evidence["host_restart_lan_boundary"] = reboot_operation(args, evidence, client, "https-lan", lambda: lan_boundary(client), diagnostic_vm=server)
        evidence["host_restart_api"] = reboot_operation(args, evidence, client, "file-api", lambda: api(client, "verify-restored", "api-host-restart.json"), diagnostic_vm=server)
        evidence["checks"].append("controlled stop/start, Docker container restart, Docker daemon restart, real systemd host reboot and retained permissions/data")
        # Do not manually stop the app before reboot: unless-stopped must attempt
        # normal daemon recovery against the deliberately absent business mount.
        record_stage(args, evidence, "capture-original-container-before-missing-storage-reboot")
        missing_container_id = server.command_on_guest("docker ps --no-trunc -q --filter label=com.docker.compose.project=cf-filebrowser").stdout.decode().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", missing_container_id):
            raise VerificationError("missing-storage test requires exactly one running original service")
        evidence["missing_storage"] = {"original_container_id": missing_container_id, "original_sentinel_id": baseline[server.name]["id"]}
        record_stage(args, evidence, "missing-business-mount-real-reboot")
        server.command_on_guest("cp --preserve=mode /etc/fstab /root/cf-verification/fstab.saved\nsed -i '\\| /srv/storage |s/^/# missing-disk-test /' /etc/fstab")
        evidence["missing_disk_reboot"] = server.reboot()
        record_stage(args, evidence, "missing-storage-docker-and-original-sentinel-readiness")
        missing = evidence["missing_storage"]
        wait_missing_storage_ready(server, missing_container_id, baseline[server.name]["id"], missing)
        record_stage(args, evidence, "verify-missing-storage-before-explicit-start")
        verify_missing_storage_state(missing["before_explicit_start"], missing_container_id, baseline[server.name]["id"])
        record_stage(args, evidence, "explicit-original-container-start-with-missing-storage")
        rejected = server.command_on_guest("docker start " + missing_container_id, check=False)
        missing["explicit_start"] = missing_storage_rejection(rejected)
        missing["after_explicit_start"] = missing_storage_state(server, missing_container_id, baseline[server.name]["id"])
        record_stage(args, evidence, "verify-real-missing-storage-refusal-and-no-system-disk-writes")
        if rejected.returncode == 0:
            raise VerificationError("original container unexpectedly started while business storage was absent")
        verify_missing_storage_state(missing["after_explicit_start"], missing_container_id, baseline[server.name]["id"])
        server.command_on_guest("""
! mountpoint -q /srv/storage
test ! -e /srv/storage/cf-filebrowser-enterprise
id=$(docker ps -aq --filter label=com.docker.compose.project=cf-filebrowser)
test -n "$id"
test "$(docker inspect --format '{{.State.Running}}' "$id")" != true
cp --preserve=mode /root/cf-verification/fstab.saved /etc/fstab
systemctl daemon-reload
mount /srv/storage
""")
        record_stage(args, evidence, "late-mount-formal-start-and-api")
        server.command_on_guest(f"{manage} start --hostname {server.name}")
        healthy(server)
        evidence["late_mount_api"] = api(client, "verify-restored", "api-late-mount.json")
        evidence["checks"].append("missing business mount blocks automatic boot without creating system-disk paths; late mount plus formal start recovers")
        for vm in vms:
            if sentinel_state(vm) != baseline[vm.name]:
                raise VerificationError("unrelated project's container/network/port/data changed during lifecycle tests")
        record_stage(args, evidence, "container-recreation-and-persistence")
        # Recreate only this project's stopped service; no prune, down or volume removal.
        server.command_on_guest(f"{manage} stop --hostname {server.name}\nid=$(docker ps -aq --filter label=com.docker.compose.project=cf-filebrowser)\ndocker rm \"$id\" >/dev/null\n{manage} start --hostname {server.name}")
        evidence["recreated_api"] = api(client, "verify-restored", "api-recreated.json")
        backup = "/srv/storage/cf-filebrowser-enterprise/backups/verification.tar"
        flags = f"--source-sha {args.source_sha} --image-ref {shlex.quote(pinned)} --image-id {image_id}"
        record_stage(args, evidence, "formal-controlled-stop-backup")
        server.command_on_guest(f"bash {SOURCE}/deploy/shared-host/backup.sh create {backup} --hostname {server.name} {flags}")
        checksum = server.command_on_guest("sha256sum " + backup).stdout.decode().split()[0]
        original_identity = recovery_probe(server, args, evidence, "original_storage_identity", ["snapshot"])["storage_identity_sha256"]
        # Transfer only between these two isolated VM states, over authenticated
        # SSH. The bytes never become an uploaded artifact or an ordinary log.
        record_stage(args, evidence, "private-authenticated-backup-transfer")
        client.write_file(GUEST + "/verification.tar", server.read_file(backup))
        server.write_file(GUEST + "/api-state.json", client.read_file(GUEST + "/api-state.json"))
        record_stage(args, evidence, "blank-target-backup-rejection-tests-and-formal-restore")
        client.command_on_guest(f"""
test ! -e /etc/cf-filebrowser-enterprise
test ! -e /var/lib/cf-filebrowser-enterprise
test ! -e /srv/storage/cf-filebrowser-enterprise
python3 - <<'BAD_BACKUPS'
from pathlib import Path
import os
root=Path("{GUEST}")
payload=(root/"verification.tar").read_bytes()
(root/"incomplete.tar").write_bytes(payload[:len(payload)//2])
os.chmod(root/"incomplete.tar",0o600)
(root/"bad-permissions.tar").write_bytes(payload)
os.chmod(root/"bad-permissions.tar",0o644)
BAD_BACKUPS
incomplete_sha=$(sha256sum {GUEST}/incomplete.tar | cut -d ' ' -f1)
if bash {SOURCE}/deploy/shared-host/backup.sh restore {GUEST}/incomplete.tar --hostname {client.name} {flags} --sha256 "$incomplete_sha"; then exit 1; fi
if bash {SOURCE}/deploy/shared-host/backup.sh restore {GUEST}/bad-permissions.tar --hostname {client.name} {flags} --sha256 {checksum}; then exit 1; fi
if bash {SOURCE}/deploy/shared-host/backup.sh restore {GUEST}/verification.tar --hostname {client.name} {flags} --sha256 {'0' * 64}; then exit 1; fi
if bash {SOURCE}/deploy/shared-host/backup.sh restore {GUEST}/verification.tar --hostname {client.name} --source-sha {'0' * 40} --image-ref {shlex.quote(pinned)} --image-id {image_id} --sha256 {checksum}; then exit 1; fi
test ! -e /etc/cf-filebrowser-enterprise
test ! -e /var/lib/cf-filebrowser-enterprise
test ! -e /srv/storage/cf-filebrowser-enterprise
bash {SOURCE}/deploy/shared-host/backup.sh restore {GUEST}/verification.tar --hostname {client.name} {flags} --sha256 {checksum}
test ! -e /etc/cf-filebrowser-enterprise/secrets/bootstrap_admin_password
if bash {SOURCE}/deploy/shared-host/backup.sh restore {GUEST}/verification.tar --hostname {client.name} {flags} --sha256 {checksum}; then exit 1; fi
""", timeout=900)
        recovery_probe(client, args, evidence, "restored_storage_identity", [
            "restore", "--archive-name", "verification.tar", "--archive-sha256", checksum,
            "--source-sha", args.source_sha, "--image-ref", pinned, "--image-id", image_id,
            "--previous-identity-sha256", original_identity])
        record_stage(args, evidence, "restored-address-transfer-and-formal-start")
        # A restored fixed LAN config assumes the same address. Transfer that
        # address after stopping the original, instead of editing restored data.
        server.command_on_guest(f"ip address del {SERVER_IP}/24 dev cflan\nip address add {CLIENT_IP}/24 dev cflan")
        client.command_on_guest(f"ip address del {CLIENT_IP}/24 dev cflan\nip address add {SERVER_IP}/24 dev cflan\n{manage} start --hostname {client.name}")
        healthy(client)
        lan_boundary(server)
        record_stage(args, evidence, "restored-real-api-verification")
        evidence["restored_api"] = api(server, "verify-restored", "api-restored.json")
        record_stage(args, evidence, "restored-existing-playwright-ui")
        evidence["restored_ui"] = real_ui(server)
        evidence["checks"].append("existing Playwright UI passed against restored system from the other isolated VM")
        evidence["checks"].append("consistent stopped backup, authenticated transfer, corrupt/incomplete/permission/version/occupied-target refusals, formal blank second-VM restore, bootstrap absent and same-image live read/write")
        for vm in vms:
            if sentinel_state(vm) != baseline[vm.name]:
                raise VerificationError("unrelated project's container/network/port/data changed during backup/restore")
        evidence["checks"].append("unrelated Docker project's container ID, image, network, ports, mounts and data unchanged throughout")
        evidence["boundaries"] = {"B": "real Debian13 systemd VMs; actual host boot IDs recorded", "C": "not run: no actual target device or user client accessed", "WebDAV": "real HTTPS protocol requests and persistence/revocation assertions completed by the protocol client; no separate desktop WebDAV application is claimed", "OnlyOffice": "not completed without a real Document Server and client", "UI": "existing Playwright shared-host project executed in each client VM before and after restore, without disabling TLS verification"}
        complete_scenario(args, evidence)
    finally:
        evidence["qemu_diagnostics"] = {vm.name: vm.startup_diagnostic() for vm in vms if vm.process is not None and vm.process.poll() not in (None, 0)}
        for vm in reversed(vms):
            vm.close()
        if registry_id:
            execute(["docker", "rm", "--force", registry_id], check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--scope", choices=("full", "reboot", "storage"), default="full", help="reboot runs only formal setup and the host reboot blocker checks")
    parser.add_argument("--image-ref", help="local image already built by the formal image.sh entry point")
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--accelerator", choices=("kvm", "tcg"), default="kvm")
    args = parser.parse_args()
    if args.scope != "storage" and not args.image_ref:
        parser.error("--image-ref is required for product verification")
    if sys.platform != "linux" or os.environ.get("GITHUB_ACTIONS") != "true":
        parser.error("this destructive VM-fixture harness runs only on a disposable Linux GitHub Actions runner")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        parser.error("source SHA must be a full immutable lowercase commit")
    if args.accelerator == "kvm" and not os.access("/dev/kvm", os.R_OK | os.W_OK):
        parser.error("KVM is unavailable to this runner; grant CI access explicitly or select --accelerator tcg with a larger timeout")
    for name in ("qemu-system-x86_64", "qemu-img", "cloud-localds", "ssh", "ssh-keygen", "openssl", "docker", "curl", "sudo"):
        if not shutil.which(name):
            parser.error("required CI dependency is missing: " + name)
    os.umask(0o077)
    args.evidence = args.evidence.absolute()
    if args.evidence == ROOT or ROOT in args.evidence.parents or args.evidence.exists():
        parser.error("evidence must be a new directory outside the source checkout")
    args.evidence.mkdir(mode=0o700, parents=True)
    work = Path(tempfile.mkdtemp(prefix="cf-private-vm-", dir=os.environ.get("RUNNER_TEMP")))
    evidence = {"schema": "cf-shared-host-vm/v1", "source_sha": args.source_sha, "result": "failed", "checks": [], "accelerator": args.accelerator}
    try:
        scenario(args, work, evidence)
        message = "reboot blocker targeted verification passed; full A/B remains separate" if args.scope == "reboot" else "real Debian/systemd/LAN/restore verification passed"
        if args.scope == "storage": message = "storage device-budget control completed; product verification remains separate"
        print("[shared-host-vm] " + message + "; publish only the evidence directory")
        return 0
    except (VerificationError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        message = str(error) if isinstance(error, VerificationError) else "environment or operation failure; inspect private CI state"
        evidence["failure"] = message
        if getattr(error, "api_evidence", None) is not None:
            evidence["failed_api"] = error.api_evidence
        if getattr(error, "lan_evidence", None) is not None:
            evidence["lan_failure"] = error.lan_evidence
        if getattr(error, "ui_evidence", None) is not None:
            evidence["failed_ui"] = error.ui_evidence
        print("[shared-host-vm] ERROR: " + message, file=sys.stderr)
        return 1
    finally:
        (args.evidence / "vm-result.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        # Preserve private failure state for the ephemeral runner's lifetime.
        # Never upload the work directory or perform a broad filesystem cleanup.


if __name__ == "__main__":
    raise SystemExit(main())
