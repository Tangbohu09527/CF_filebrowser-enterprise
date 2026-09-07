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


if __name__ == "__main__":
    unittest.main()
