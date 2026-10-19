"""Interrupted prepare retains the original secret and refuses changed assets.

The portable tests exercise real files; POSIX ownership/path validation is
covered by the existing validator and the Debian integration job.
"""
import base64
import contextlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "prepare_resume", Path(__file__).resolve().parents[1] / "shared-host/lifecycle.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class PrepareResumeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = module.Paths(Path(self.temp.name))
        for parent in (self.paths.config.parent, self.paths.data.parent,
                       self.paths.cache.parent, self.paths.storage):
            parent.mkdir(parents=True, exist_ok=True)
        _, layout = module.preparation_layout(self.paths, False)
        self.payload = {path: ("original-" + path.name).encode() for path in layout}
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(module, "assert_safe_path"))
        stack.enter_context(mock.patch.object(module, "sync_directory"))
        stack.enter_context(mock.patch.object(module, "create_directory", side_effect=lambda path, *a: path.mkdir()))
        self.writes = 0
        self.fail_after = None

        def write(path, data, *args):
            if self.writes == self.fail_after:
                raise OSError("injected interruption between files")
            self.writes += 1
            with path.open("xb") as stream:
                stream.write(data)
        stack.enter_context(mock.patch.object(module, "write_new", side_effect=write))

    def interrupt(self):
        self.fail_after = 4
        with self.assertRaises(OSError):
            module.materialize_preparation(self.paths, "binding-a", self.payload, False)
        self.assertTrue(self.paths.preparation.is_file())
        self.assertFalse(self.paths.metadata.exists())
        self.fail_after = None

    def test_resume_uses_exact_original_bytes_and_removes_private_intent(self):
        self.interrupt()
        changed_secrets = {path: b"must-not-be-used" for path in self.payload}
        module.materialize_preparation(self.paths, "binding-a", changed_secrets, False)
        self.assertFalse(self.paths.preparation.exists())
        for path, expected in self.payload.items():
            self.assertEqual(path.read_bytes(), expected)

    def test_changed_input_binding_never_continues_partial_install(self):
        self.interrupt()
        before = self.writes
        with self.assertRaisesRegex(module.DeploymentError, "inputs differ"):
            module.materialize_preparation(self.paths, "binding-b", self.payload, False)
        self.assertEqual(self.writes, before)

    def test_changed_existing_file_is_not_replaced_and_no_new_files_written(self):
        self.interrupt()
        self.paths.env.write_bytes(b"concurrent-change")
        before = self.writes
        with self.assertRaisesRegex(module.DeploymentError, "file changed"):
            module.materialize_preparation(self.paths, "binding-a", self.payload, False)
        self.assertEqual(self.paths.env.read_bytes(), b"concurrent-change")
        self.assertEqual(self.writes, before)

    def test_unknown_partial_assets_and_intent_paths_are_rejected(self):
        self.interrupt()
        extra = self.paths.data / "employee-unique-original"
        extra.write_bytes(b"keep")
        with self.assertRaisesRegex(module.DeploymentError, "unknown partial"):
            module.materialize_preparation(self.paths, "binding-a", self.payload, False)
        self.assertEqual(extra.read_bytes(), b"keep")
        plan = json.loads(self.paths.preparation.read_bytes())
        plan["files"][str(Path(self.temp.name) / "outside")] = base64.b64encode(b"bad").decode()
        self.paths.preparation.write_text(json.dumps(plan))
        with self.assertRaisesRegex(module.DeploymentError, "path allowlist"):
            module.materialize_preparation(self.paths, "binding-a", self.payload, False)
        self.assertFalse((Path(self.temp.name) / "outside").exists())

    def test_unrecognized_partial_install_never_gets_an_intent(self):
        self.paths.data.mkdir()
        with self.assertRaisesRegex(module.DeploymentError, "partial|existing"):
            module.materialize_preparation(self.paths, "binding-a", self.payload, False)
        self.assertFalse(self.paths.preparation.exists())


if __name__ == "__main__":
    unittest.main()
