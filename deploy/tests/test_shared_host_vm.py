#!/usr/bin/env python3
"""QEMU launch and diagnostic regressions; no VM is booted by these tests."""
from __future__ import annotations

import importlib.util
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


if __name__ == "__main__":
    unittest.main()
