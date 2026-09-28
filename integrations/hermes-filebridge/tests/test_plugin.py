import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "plugin" / "__init__.py"
spec = importlib.util.spec_from_file_location("filebridge_plugin_test", PATH)
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)


class Context:
    def __init__(self, settings=None):
        self.settings = settings or {}
        self.registration = None

    def get_config(self, key, default=None):
        return self.settings.get(key, default)

    def register_tool(self, **kwargs):
        self.registration = kwargs


class PluginTests(unittest.TestCase):
    def fixture(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        executable, config = root / "client.exe", root / "config.json"
        executable.write_bytes(b"synthetic-client")
        config.write_text("{}")
        return Context({"client_path": str(executable), "config_path": str(config),
                        "client_sha256": hashlib.sha256(executable.read_bytes()).hexdigest()})

    def test_registration_read_only(self):
        ctx = Context()
        plugin.register(ctx)
        self.assertEqual(ctx.registration["toolset"], "cf_filebridge")
        self.assertFalse(ctx.registration["override"])
        commands = ctx.registration["schema"]["parameters"]["properties"]["command"]["enum"]
        self.assertEqual(commands, list(plugin.READ_COMMANDS))

    def test_configuration_does_not_enable_writes(self):
        ctx = Context({"allow_writes": True})
        plugin.register(ctx)
        commands = ctx.registration["schema"]["parameters"]["properties"]["command"]["enum"]
        for command in ("mkdir", "upload-new", "create-text", "replace-text", "delete-file", "delete"):
            with self.subTest(command=command), patch.object(plugin.subprocess, "run") as run:
                self.assertNotIn(command, commands)
                answer = ctx.registration["handler"]({"command": command, "input": {}})
                self.assertFalse(json.loads(answer)["ok"])
                run.assert_not_called()

    def test_reject_unknown_routes_without_process(self):
        for value in ({"command": "shell"}, {"command": "read", "url": "x"},
                      {"command": "read", "input": {"token": "do-not-echo"}},
                      {"command": "read", "input": {}, "apply": False},
                      {"command": "read", "input": {"local_file": "secret"}},
                      {"command": "ping"}, {"command": "read", "input": []}):
            with self.subTest(value=value), patch.object(plugin.subprocess, "run") as run:
                output = plugin.handler_for(Context())(value)
                self.assertFalse(json.loads(output)["ok"])
                run.assert_not_called()
                self.assertNotIn("do-not-echo", output)

    def test_fixed_args_env_and_unicode(self):
        ctx = self.fixture()
        payload = {"schema_version": "filebrowser-agentctl/v1", "command": "read", "ok": True,
                   "result": {"content": "实际内容", "untrusted": True}}
        result = subprocess.CompletedProcess([], 0, json.dumps(payload).encode(), b"private-do-not-echo")
        with patch.dict(os.environ, {"FILEBROWSER_AGENT_TOKEN": "secret", "HTTPS_PROXY": "secret-url",
                                     "CF_FILEBRIDGE_HOST_TEST_SERVICE_TOKEN": "synthetic-host-service-secret-only"}), patch.object(plugin.subprocess, "run", return_value=result) as run:
            answer = plugin.handler_for(ctx)({"command": "read", "input": {"source": "s", "path": "/你好"}})
        self.assertEqual(json.loads(answer), payload)
        args = run.call_args
        self.assertFalse(args.kwargs["shell"])
        self.assertNotIn("FILEBROWSER_AGENT_TOKEN", args.kwargs["env"])
        self.assertNotIn("HTTPS_PROXY", args.kwargs["env"])
        self.assertNotIn("CF_FILEBRIDGE_HOST_TEST_SERVICE_TOKEN", args.kwargs["env"])
        self.assertEqual(json.loads(args.kwargs["input"])["path"], "/你好")
        self.assertNotIn("--apply", args.args[0])
        self.assertNotIn("secret", repr(args.args))
        self.assertNotIn("synthetic-host-service-secret-only", answer)

        ctx.settings.update(create_enabled=True, create_config_path=ctx.settings["config_path"])
        creation_payload = {"schema_version": "filebrowser-agentctl/v1", "command": "create-text", "ok": True}
        creation_result = subprocess.CompletedProcess([], 0, json.dumps(creation_payload).encode(), b"")
        with patch.dict(os.environ, {"CF_FILEBRIDGE_HOST_TEST_SERVICE_TOKEN": "synthetic-host-service-secret-only"}), patch.object(plugin.subprocess, "run", return_value=creation_result) as run:
            creation_answer = plugin.handler_for(ctx, creation=True)({
                "command": "plan", "input": {"source": "s", "path": "/new.txt", "content": "new text"}})
        self.assertEqual(json.loads(creation_answer), creation_payload)
        self.assertNotIn("CF_FILEBRIDGE_HOST_TEST_SERVICE_TOKEN", run.call_args.kwargs["env"])
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertNotIn("--apply", run.call_args.args[0])
        self.assertNotIn("synthetic-host-service-secret-only", repr(run.call_args.args) + creation_answer)

    def test_bad_binary_pin(self):
        ctx = self.fixture()
        ctx.settings["client_sha256"] = "0" * 64
        with patch.object(plugin.subprocess, "run") as run:
            answer = plugin.handler_for(ctx)({"command": "ping", "input": {}})
            self.assertEqual(json.loads(answer)["error"]["code"], "client_digest_mismatch")
            run.assert_not_called()

    def test_timeout_no_retry_or_private_output(self):
        with patch.object(plugin.subprocess, "run", side_effect=subprocess.TimeoutExpired(["private"], 180, output=b"secret")) as run:
            answer = plugin.handler_for(self.fixture())({"command": "ping", "input": {}})
            self.assertEqual(json.loads(answer)["error"]["code"], "client_timeout")
            self.assertEqual(run.call_count, 1)
            self.assertNotIn("secret", answer)

    def test_response_mismatch_rejected(self):
        for result in (subprocess.CompletedProcess([], 1, b'{"schema_version":"filebrowser-agentctl/v1","command":"ping","ok":true}', b"secret"),
                       subprocess.CompletedProcess([], 0, b'{"ok":true}', b"secret"),
                       subprocess.CompletedProcess([], 0, b'not-json', b"secret")):
            with patch.object(plugin.subprocess, "run", return_value=result):
                answer = plugin.handler_for(self.fixture())({"command": "ping", "input": {}})
                self.assertFalse(json.loads(answer)["ok"])
                self.assertNotIn("secret", answer)

    def test_input_size_and_nonfinite_rejected(self):
        ctx = self.fixture()
        for data in ({"path": "x" * (1024 * 1024)}, {"path": float("nan")}):
            with patch.object(plugin.subprocess, "run") as run:
                answer = plugin.handler_for(ctx)({"command": "read", "input": data})
                self.assertFalse(json.loads(answer)["ok"])
                run.assert_not_called()




class CreateContext(Context):
    def __init__(self, settings=None):
        super().__init__(settings)
        self.registrations = []

    def register_tool(self, **kwargs):
        self.registrations.append(kwargs)


class CreatePluginTests(unittest.TestCase):
    fixture = PluginTests.fixture

    def create_fixture(self):
        ctx = self.fixture()
        ctx.settings.update(create_enabled=True, create_config_path=ctx.settings["config_path"])
        return ctx

    def test_optional_registration_only(self):
        for settings, count in (({}, 1), ({"allow_writes": True}, 1),
                                ({"create_enabled": "true", "create_config_path": "x"}, 1),
                                ({"create_enabled": True}, 1),
                                ({"create_enabled": True, "create_config_path": "x"}, 2)):
            ctx = CreateContext(settings)
            plugin.register(ctx)
            self.assertEqual(len(ctx.registrations), count)
            self.assertEqual(ctx.registrations[0]["name"], "filebrowser_files")
            if count == 2:
                self.assertEqual(ctx.registrations[1]["name"], "filebrowser_create_text")
                self.assertEqual(ctx.registrations[1]["schema"]["parameters"]["properties"]["command"]["enum"], ["plan", "apply", "status"])

    def test_no_self_approval_or_unknown_args(self):
        for command, data in (("approve-create", {}), ("approve", {}), ("shell", {}),
                              ("apply", {"approved": True}), ("apply", {"content": "override"}),
                              ("plan", {"local_file": "secret"}), ("plan", {"url": "secret"}),
                              ("plan", {"apply": True})):
            with self.subTest(command=command, data=data), patch.object(plugin.subprocess, "run") as call:
                reply = plugin.handler_for(self.create_fixture(), creation=True)({"command": command, "input": data})
                self.assertFalse(json.loads(reply)["ok"])
                call.assert_not_called()

    def test_apply_uses_only_approved_command_and_second_config(self):
        ctx = self.create_fixture()
        for command, actual in (("plan", "create-text"), ("apply", "create-approved"), ("status", "create-status")):
            result = subprocess.CompletedProcess([], 0, json.dumps({"schema_version": "filebrowser-agentctl/v1", "command": actual, "ok": True}).encode(), b"secret")
            with patch.object(plugin.subprocess, "run", return_value=result) as call:
                response = plugin.handler_for(ctx, creation=True)({"command": command, "input": {"operation_id": "op-proposed-01"}})
                self.assertTrue(json.loads(response)["ok"])
                self.assertEqual(call.call_args.args[0][-1], actual)
                self.assertEqual("--apply" in call.call_args.args[0], command == "apply")
                self.assertEqual(call.call_args.args[0][2], ctx.settings["create_config_path"])
                self.assertNotIn("secret", response)

    def test_apply_timeout_is_unknown_and_no_retry(self):
        with patch.object(plugin.subprocess, "run", side_effect=subprocess.TimeoutExpired([], 180)) as call:
            response = plugin.handler_for(self.create_fixture(), creation=True)({"command": "apply", "input": {}})
            self.assertEqual(json.loads(response)["error"]["code"], "create_outcome_unknown_check_status")
            self.assertEqual(call.call_count, 1)

    def test_disable_after_registration_is_checked(self):
        ctx = self.create_fixture()
        handler = plugin.handler_for(ctx, creation=True)
        ctx.settings["create_enabled"] = False
        with patch.object(plugin.subprocess, "run") as call:
            self.assertEqual(json.loads(handler({"command": "plan", "input": {}}))["error"]["code"], "create_disabled")
            call.assert_not_called()

if __name__ == "__main__":
    unittest.main()
