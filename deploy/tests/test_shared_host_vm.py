#!/usr/bin/env python3
"""QEMU launch and diagnostic regressions; no VM is booted by these tests."""
from __future__ import annotations

import importlib.util
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts/tests/shared_host_vm.py"
SPEC = importlib.util.spec_from_file_location("shared_host_vm_tests", MODULE_PATH)
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)


class QemuLaunchTests(unittest.TestCase):
    def make_vm(self, directory):
        root = Path(directory)
        ssh_key = root / "client-key"
        ssh_key.with_suffix(".pub").write_text("ssh-ed25519 public-test-key\n")
        calls = []

        def setup_command(command, **kwargs):
            calls.append(command)
            if command[0] == "ssh-keygen":
                path = Path(command[command.index("-f") + 1])
                path.write_text("private-test-key\n")
                path.with_suffix(".pub").write_text("ssh-ed25519 public-test-key\n")
            if command[0] == "cloud-localds":
                Path(command[-3]).write_bytes(b"seed-test")
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with mock.patch.object(harness, "execute", side_effect=setup_command), mock.patch.object(harness, "port", return_value=22222):
            vm = harness.VM(1, root, root / "base.qcow2", ssh_key, 22223, "tcg")
        return vm, calls

    def test_disk_serial_is_a_device_property_and_disk_order_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            vm, _ = self.make_vm(directory)
            drives = [vm.command[index + 1] for index, value in enumerate(vm.command) if value == "-drive"]
            devices = [vm.command[index + 1] for index, value in enumerate(vm.command) if value == "-device" and vm.command[index + 1].startswith("virtio-blk-pci")]
            self.assertTrue(all("serial=" not in drive for drive in drives), "QEMU removed -drive serial= in 3.0")
            self.assertEqual(devices, ["virtio-blk-pci,drive=system", "virtio-blk-pci,drive=storage,serial=cf-test-data", "virtio-blk-pci,drive=seed"])
            self.assertTrue(all("if=none" in drive for drive in drives))
            self.assertIn("readonly=on", drives[2])

    def test_sparse_disks_stay_within_the_authorized_two_vm_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            _, calls = self.make_vm(directory)
            creates = [command for command in calls if command[:2] == ["qemu-img", "create"]]
            self.assertEqual([command[-1] for command in creates], ["24G", "14G"])
        budget = harness.resource_budget(3 * 1024 ** 3, 1024 ** 2)
        self.assertLessEqual(budget["total_virtual_disk_bytes"], 80 * 1024 ** 3)
        self.assertLessEqual(budget["configured_memory_bytes"], 8 * 1024 ** 3)
        with self.assertRaises(harness.VerificationError):
            harness.resource_budget(5 * 1024 ** 3)

    def test_qemu_error_is_retained_and_only_known_diagnostic_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            vm, _ = self.make_vm(directory)
            private_log = vm.directory / "qemu.private.stderr.log"
            private_log.write_text("qemu-system-x86_64: Block format 'qcow2' does not support the option 'serial'\nPRIVATE-KEY-MUST-NOT-LEAK\n")
            vm.process = mock.Mock()
            vm.process.poll.return_value = 1
            with self.assertRaises(harness.VerificationError) as error:
                vm.wait_ready()
            self.assertIn("unsupported-drive-serial", str(error.exception))
            self.assertIn("exit 1", str(error.exception))
            self.assertNotIn("PRIVATE-KEY", str(error.exception))
            self.assertNotIn(directory, str(error.exception))
            self.assertIn("PRIVATE-KEY", private_log.read_text())


class ImageIdentityTests(unittest.TestCase):
    def fixture(self):
        revision = "a" * 40
        manifest_digest = "sha256:" + "b" * 64
        config_digest = "sha256:" + "c" * 64
        config = {"architecture": "amd64", "os": "linux", "config": {"User": "10001:10001", "Labels": {"org.opencontainers.image.revision": revision}, "Env": ["PATH=/usr/bin"], "Entrypoint": ["/entrypoint.sh"]}, "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "d" * 64]}}
        expected = {"registry_reference": "localhost:5001/cf-filebrowser@" + manifest_digest, "registry_digest": manifest_digest, "manifest_digest": manifest_digest, "config_digest": config_digest, "config": config}
        info = {"Id": config_digest, "RepoDigests": [expected["registry_reference"]], "Config": copy.deepcopy(config["config"]), "Os": "linux", "Architecture": "amd64", "RootFS": {"Type": "layers", "Layers": config["rootfs"]["diff_ids"]}}
        return revision, expected, info

    def test_legacy_config_id_and_containerd_manifest_id_verify_same_content(self):
        revision, expected, info = self.fixture()
        harness.verify_image_identity(info, expected, revision)
        info["Id"] = expected["manifest_digest"]
        info["Descriptor"] = {"digest": expected["manifest_digest"], "mediaType": "application/vnd.oci.image.manifest.v1+json"}
        harness.verify_image_identity(info, expected, revision)
        record = harness.image_identity_record(info)
        self.assertEqual(record["image_id"], expected["manifest_digest"])
        self.assertEqual(record["descriptor"]["digest"], expected["manifest_digest"])
        self.assertNotIn("Env", json.dumps(record))

    def test_wrong_pin_id_configuration_layers_or_revision_are_rejected(self):
        revision, expected, info = self.fixture()
        mutations = [lambda x: x.update(RepoDigests=[]), lambda x: x.update(Id="sha256:" + "e" * 64), lambda x: x["Config"].update(User="0:0"), lambda x: x["Config"]["Labels"].update({"org.opencontainers.image.revision": "f" * 40}), lambda x: x["RootFS"].update(Layers=[]), lambda x: x.update(Descriptor={"digest": "sha256:" + "e" * 64})]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                changed = copy.deepcopy(info)
                mutate(changed)
                with self.assertRaises(harness.VerificationError):
                    harness.verify_image_identity(changed, expected, revision)

    def test_registry_blob_bytes_must_match_digest_before_json_is_trusted(self):
        payload = b'{"schemaVersion":2}'
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        self.assertEqual(harness.decode_registry_blob(payload, digest), {"schemaVersion": 2})
        with self.assertRaises(harness.VerificationError):
            harness.decode_registry_blob(payload + b" ", digest)


class FailureEvidenceTests(unittest.TestCase):
    def test_failed_api_retains_sanitized_checks_without_raw_output(self):
        vm = mock.Mock(name="guest")
        vm.name = "cf-verification-2"
        vm.command_on_guest.return_value = subprocess.CompletedProcess([], 1, b"TOKEN-MUST-NOT-LEAK", b"PASSWORD-MUST-NOT-LEAK")
        report = {"version": 1, "phase": "protocols", "passed": False, "checks": [{"name": "webdav_put_denied", "passed": False}], "failure": "unexpected status"}
        vm.read_file.return_value = json.dumps(report).encode()
        with self.assertRaises(harness.VerificationError) as caught:
            harness.api(vm, "protocols", "api-protocols.json")
        self.assertEqual(caught.exception.api_evidence, report)
        self.assertNotIn("TOKEN", str(caught.exception))
        self.assertNotIn("PASSWORD", str(caught.exception))
        self.assertFalse(vm.command_on_guest.call_args.kwargs["check"])

    def test_api_configuration_failure_does_not_mask_original_exit(self):
        vm = mock.Mock(name="guest")
        vm.name = "cf-verification-2"
        vm.command_on_guest.return_value = subprocess.CompletedProcess([], 2, b"secret", b"secret")
        vm.read_file.side_effect = harness.VerificationError("missing")
        with self.assertRaises(harness.VerificationError) as caught:
            harness.api(vm, "exercise", "api-initial.json")
        self.assertIn("exit 2", str(caught.exception))
        self.assertFalse(caught.exception.api_evidence["passed"])


class RuntimeReadinessTests(unittest.TestCase):
    def fixture(self):
        return {"image_id": "sha256:" + "a" * 64, "health": "healthy", "running": True, "readonly_rootfs": True, "exec_uid": 10001, "exec_gid": 10001, "pid1_uid": [10001] * 4, "pid1_gid": [10001] * 4, "tools": {name: {"exit_code": 0, "version": "1.2.3"} for name in ("ffmpeg", "ffprobe", "exiftool", "curl", "filebrowser")}, "filebrowser_commit": "b" * 40, "writable": {name: True for name in ("files", "data", "cache")}, "denied_writes": {"root": True, "config": True}, "readable": {name: True for name in ("entrypoint", "config", "jwt", "totp", "storage_identity", "tls_certificate", "tls_key", "tls_ca")}, "entrypoint_executable": True, "entrypoint_syntax_valid": True, "readonly_bind_mounts": True, "bootstrap_absent": True}

    def test_runtime_contract_requires_real_numeric_identity_and_all_boundaries(self):
        record = self.fixture()
        harness.verify_runtime_readiness(record, record["image_id"], record["filebrowser_commit"])
        for key, bad in (("exec_uid", 0), ("exec_gid", 0), ("pid1_uid", [0] * 4), ("health", "unhealthy"), ("readonly_rootfs", False), ("readonly_bind_mounts", False), ("bootstrap_absent", False)):
            with self.subTest(key=key):
                changed = copy.deepcopy(record)
                changed[key] = bad
                with self.assertRaises(harness.VerificationError):
                    harness.verify_runtime_readiness(changed, record["image_id"], record["filebrowser_commit"])
        for section, key, bad in (("tools", "ffmpeg", {"exit_code": 1, "version": ""}), ("writable", "files", False), ("denied_writes", "config", False), ("readable", "jwt", False)):
            with self.subTest(section=section):
                changed = copy.deepcopy(record)
                changed[section][key] = bad
                with self.assertRaises(harness.VerificationError):
                    harness.verify_runtime_readiness(changed, record["image_id"], record["filebrowser_commit"])

    def test_runtime_script_uses_service_identity_and_only_temporary_writes(self):
        script = harness.runtime_readiness_script()
        self.assertNotIn('"--user"', script)
        self.assertNotIn('chown', script)
        self.assertNotIn('chmod', script)
        self.assertNotIn('database.db', script)
        self.assertIn('mktemp', script)
        self.assertIn('test -r', script)
        self.assertIn('exec 3>>', script)


class MissingStorageTests(unittest.TestCase):
    def fixture(self):
        return {"docker_active": True, "sentinel_id": "b" * 64, "sentinel_running": True, "service_ids": ["a" * 64], "service_id": "a" * 64, "service_running": False, "storage_mounted": False, "storage_directory_exists": True, "storage_device_is_root": True, "business_path_exists": False}

    def test_daemon_not_restored_yet_cannot_count_as_missing_disk_refusal(self):
        # This met the old SSH-boot-ID/nonrunning/no-project-path assertions.
        record = self.fixture()
        record.update(docker_active=False, sentinel_running=False)
        with self.assertRaises(harness.VerificationError):
            harness.verify_missing_storage_state(record, "a" * 64, "b" * 64)

    def test_exact_original_containers_and_no_system_disk_writes_are_required(self):
        record = self.fixture()
        harness.verify_missing_storage_state(record, "a" * 64, "b" * 64)
        for field, value in (("sentinel_id", "c" * 64), ("sentinel_running", False), ("service_id", "c" * 64), ("service_running", True), ("business_path_exists", True), ("storage_mounted", True), ("storage_device_is_root", False)):
            with self.subTest(field=field):
                changed = dict(record)
                changed[field] = value
                with self.assertRaises(harness.VerificationError):
                    harness.verify_missing_storage_state(changed, "a" * 64, "b" * 64)

    def test_wait_allows_delayed_autostart_without_starting_anything(self):
        ready = self.fixture()
        waiting = dict(ready, docker_active=False, sentinel_running=False)
        record = {}
        with mock.patch.object(harness, "missing_storage_state", side_effect=[waiting, ready]) as read, mock.patch.object(harness.time, "monotonic", return_value=0), mock.patch.object(harness.time, "sleep") as sleep:
            harness.wait_missing_storage_ready(mock.Mock(), "a" * 64, "b" * 64, record)
        self.assertEqual(read.call_count, 2)
        sleep.assert_called_once_with(2)
        self.assertEqual(record["before_explicit_start"], ready)
        self.assertEqual(record["readiness_observations"], 2)

    def test_wait_retries_a_snapshot_taken_during_daemon_transition(self):
        ready = self.fixture()
        transitional = dict(ready, service_id=None, service_ids=[], service_running=None)
        record = {}
        with mock.patch.object(harness, "missing_storage_state", side_effect=[transitional, ready]) as read, mock.patch.object(harness.time, "monotonic", return_value=0), mock.patch.object(harness.time, "sleep"):
            harness.wait_missing_storage_ready(mock.Mock(), "a" * 64, "b" * 64, record)
        self.assertEqual(read.call_count, 2)
        self.assertEqual(record["before_explicit_start"], ready)

    def test_inactive_daemon_probe_never_triggers_docker_socket_activation(self):
        vm = mock.Mock()
        vm.command_on_guest.return_value = subprocess.CompletedProcess([], 0, b"{}", b"")
        harness.missing_storage_state(vm, "a" * 64, "b" * 64)
        script = vm.command_on_guest.call_args.args[0]
        body = script.split("<<'CF_MISSING_STORAGE'\n", 1)[1].rsplit("\nCF_MISSING_STORAGE", 1)[0]
        with mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 3, "", "")) as commands, mock.patch("builtins.print"):
            exec(compile(body, "missing-storage-guest", "exec"), {})
        self.assertTrue(commands.called)
        self.assertTrue(all(call.args[0][0] != "docker" for call in commands.call_args_list))

    def test_wait_times_out_and_retains_last_state(self):
        waiting = dict(self.fixture(), docker_active=False, sentinel_running=False)
        record = {}
        with mock.patch.object(harness, "missing_storage_state", return_value=waiting), mock.patch.object(harness.time, "monotonic", side_effect=[0, 0, 0, 180]), mock.patch.object(harness.time, "sleep"):
            with self.assertRaisesRegex(harness.VerificationError, "180 seconds"):
                harness.wait_missing_storage_ready(mock.Mock(), "a" * 64, "b" * 64, record)
        self.assertEqual(record["before_explicit_start"], waiting)

    def test_wait_never_tolerates_a_system_disk_write_or_returned_mount(self):
        for field, value in (("business_path_exists", True), ("storage_mounted", True), ("service_running", True)):
            with self.subTest(field=field):
                unsafe = dict(self.fixture(), docker_active=False, sentinel_running=False)
                unsafe[field] = value
                record = {}
                with mock.patch.object(harness, "missing_storage_state", return_value=unsafe), mock.patch.object(harness.time, "monotonic", return_value=0), mock.patch.object(harness.time, "sleep") as sleep:
                    with self.assertRaises(harness.VerificationError):
                        harness.wait_missing_storage_ready(mock.Mock(), "a" * 64, "b" * 64, record)
                sleep.assert_not_called()
                self.assertEqual(record["before_explicit_start"], unsafe)

    def test_missing_storage_probe_uses_full_saved_container_ids(self):
        vm = mock.Mock()
        vm.command_on_guest.return_value = subprocess.CompletedProcess([], 0, json.dumps(self.fixture()).encode(), b"")
        harness.missing_storage_state(vm, "a" * 64, "b" * 64)
        script = vm.command_on_guest.call_args.args[0]
        self.assertIn("'--no-trunc'", script)
        self.assertIn("inspect('" + "a" * 64 + "')", script)
        with self.assertRaises(harness.VerificationError):
            harness.missing_storage_state(vm, "a" * 12, "b" * 64)

    def test_explicit_start_rejection_retains_only_known_error_category(self):
        report = harness.missing_storage_rejection(subprocess.CompletedProcess([], 1, b"SECRET", b"Error: bind source path does not exist: /private/path\nTOKEN"))
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["category"], "missing-bind-source")
        self.assertNotIn("SECRET", json.dumps(report))
        self.assertNotIn("TOKEN", json.dumps(report))
        self.assertNotIn("/private/path", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
