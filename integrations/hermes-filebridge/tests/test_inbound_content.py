"""Read-only content components: synthetic grants, real HTTPS/native disk worker.

The fixed official Hermes API/Agent/vision acceptance probe is separate. These
tests do not impersonate an authenticated production dispatch or a live model.
"""
import asyncio
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch
import zipfile

import test_inbound_host as fixture


content = importlib.import_module(fixture.spec.name + ".inbound_content")
TOOL = "filebrowser_read_inbound"


from inbound_content_fixtures import pdf_fixture, office_fixture


class ContentParserTests(unittest.TestCase):
    def test_real_pdf_and_office_bytes_produce_content(self):
        for kind, body in [("pdf", pdf_fixture()), *[(x, office_fixture(x)) for x in ("docx", "xlsx", "pptx")]]:
            with self.subTest(kind=kind):
                result = content._extract_document(body)
                self.assertTrue(result["ok"], result)
                self.assertEqual(result["format"], kind)
                self.assertIn("1234", result["content"])
                self.assertEqual(result["location_kind"], {"pdf": "extracted_line", "docx": "paragraph_table", "xlsx": "sheet_cell", "pptx": "slide_shape"}[kind])
                if kind == "docx":
                    self.assertEqual(result["units"][1]["location"], {"paragraph": 2})
                if kind == "xlsx":
                    self.assertEqual(result["units"][0]["location"], {"sheet": "Revenue", "cell": "A1"})
                    self.assertEqual(result["units"][1]["location"], {"sheet": "Revenue", "cell": "B1"})
                if kind == "pptx":
                    self.assertEqual(result["units"][0]["location"], {"slide": 1, "shape": 1, "paragraph": 1})
                self.assertTrue(result["untrusted_content"])
                self.assertFalse(result["ocr_performed"])

    def test_scanned_encrypted_truncated_and_unsupported_are_explicit(self):
        for data, expected in [(pdf_fixture(scanned=True), "needs_ocr"),
                               (pdf_fixture(mixed=True), "needs_ocr"),
                               (pdf_fixture(encrypted=True), "document_encrypted"),
                               (pdf_fixture()[:80], "document_malformed"),
                               (b"MZnot-a-document", "content_unsupported")]:
            with self.subTest(expected=expected):
                result = content._extract_document(data)
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"]["code"], expected)

    def test_archive_bombs_macros_and_output_are_bounded(self):
        macro = content._extract_document(office_fixture("docx", macro=True))
        self.assertEqual(macro["error"]["code"], "active_content_unsupported")
        import random
        rng = random.Random(1234)
        large = content._extract_document(office_fixture("docx", text="".join(rng.choices("abcdefghijklmno ", k=40000))))
        self.assertTrue(large["ok"])
        self.assertTrue(large["truncated"])
        self.assertLessEqual(len(large["content"]), content.MAX_TEXT_CHARS)

    def test_zip_traversal_xml_entities_and_bad_images_are_rejected(self):
        for name, data in [("../outside.xml", b"<a/>"),
                           ("word/document.xml", b'<!DOCTYPE a [<!ENTITY x SYSTEM "file:///outside">]><a>&x;</a>')]:
            package = io.BytesIO()
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr(name, data)
            self.assertFalse(content._extract_document(package.getvalue())["ok"])
        self.assertEqual(content._extract_document(b"\xff\xd8\xffbroken")["error"]["code"], "document_malformed")

    def test_parser_watchdog_ends_process_without_stdin_eof(self):
        env = {key: value for key, value in os.environ.items() if key.upper() in {"SYSTEMROOT", "WINDIR"}}
        process = subprocess.Popen([sys.executable, "-I", "-X", "utf8", "-B", content.__file__, "--parse-stdin"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
            cwd=str(Path(content.__file__).parent))
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        self.addCleanup(process.stdout.close)
        self.addCleanup(process.stderr.close)
        self.addCleanup(process.stdin.close)
        started = time.monotonic()
        process.stdin.write(struct.pack("!d", started + 2))
        process.stdin.flush()
        # Keep stdin open: the real child must leave its blocking read because
        # the absolute lease expires, even without a cooperative parent close.
        self.assertEqual(process.wait(timeout=4), 124)
        self.assertLess(time.monotonic() - started, 3.5)
        self.assertEqual(process.stdout.read(), b"")

    def test_parser_read_only_guard_blocks_network_process_and_outside_files(self):
        code = r'''
import importlib.util,json,pathlib,subprocess,socket,sys
spec=importlib.util.spec_from_file_location('content_guard',sys.argv[1]);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
module._parser_guard()
import anydoc
denied=[]
for name,operation in [
 ('outside_read',lambda:open(sys.argv[2],'rb')),
 ('write',lambda:open(sys.argv[2],'wb')),
 ('traversal',lambda:open(str(pathlib.Path(sys.prefix)/'..'/'..'/'must-not-read'),'rb')),
 ('network',lambda:socket.socket()),
 ('process',lambda:subprocess.run([sys.executable,'-c','pass']))]:
 try: operation()
 except PermissionError: denied.append(name)
print(json.dumps(denied))
'''
        with tempfile.TemporaryDirectory(prefix="cf-parser-guard-") as raw:
            outside = Path(raw) / "outside.txt"
            outside.write_bytes(b"must not read")
            env = {key: value for key, value in os.environ.items() if key.upper() in {"SYSTEMROOT", "WINDIR"}}
            result = subprocess.run([sys.executable, "-I", "-X", "utf8", "-B", "-c", code,
                content.__file__, str(outside)], env=env, cwd=raw, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(json.loads(result.stdout), ["outside_read", "write", "traversal", "network", "process"])
            self.assertEqual(outside.read_bytes(), b"must not read")


class ContentWireTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.HostControlTests.setUpClass()

    def setUp(self):
        self.service = fixture.HostControlTests(methodName="runTest")
        self.service.make_adapter = False
        self.service.setUp()
        self.addCleanup(self.service.doCleanups)
        f = self.service
        f.raw["consumer_tools"] = [TOOL]
        f.config = fixture.control.HostConfig.from_context(fixture.Settings(f.raw))
        f.client = fixture.control.ControlClient(f.config)
        f.bridge = fixture.inbound.HostBridge(str(f.worker), f.worker_hash)
        f.adapter = fixture.host.HostAdapter(f.client, f.bridge, downstream_tools=[TOOL])
        self.addCleanup(f.adapter.close)
        self.settings = type("ContentSettings", (), {"get_config": lambda _self, key, default=None:
            True if key in {"inbound_enabled", "inbound_content_enabled"} else default})()
        self.handler = content.handler_for(self.settings)

    def call(self, args=None, session="content-session"):
        f = self.service
        answer = f.adapter.middleware(TOOL, args or {"attachment_id": 5},
            lambda values: asyncio.run(self.handler(values)), session_id=session, task_id=session)
        if isinstance(answer, str):
            answer = json.loads(answer)
        rendered = json.dumps(answer)
        self.assertNotIn(fixture.READ_SECRET, rendered)
        self.assertNotIn(fixture.SERVICE_SECRET, rendered)
        self.assertNotIn(str(f.work_root), rendered)
        return answer

    def test_one_call_downloads_reads_real_bytes_and_repeat_keeps_budget(self):
        f = self.service
        f.body = pdf_fixture()
        result = self.call()
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["verified"])
        self.assertFalse(result["formal_archive"])
        self.assertIn("1234", result["content"])
        self.assertEqual(result["sha256"], hashlib.sha256(f.body).hexdigest())
        again = self.call()
        self.assertEqual(again["handle"], result["handle"])
        self.assertEqual(f.download_calls, 1)
        self.assertEqual(f.resolve_calls, 1)
        f.adapter.on_session_end(session_id="content-session")
        self.assertFalse(self.call()["ok"])
        self.assertEqual(f.download_calls, 1)

    def test_no_scope_and_model_authority_fields_fail_closed(self):
        result = json.loads(asyncio.run(self.handler({"attachment_id": 5})))
        self.assertEqual(result["error"]["code"], "trusted_context_unavailable")
        for extra in ({"task_context": {}}, {"path": "C:\\outside.pdf"}, {"url": "https://outside.invalid"}):
            result = json.loads(asyncio.run(self.handler({"attachment_id": 5, **extra})))
            self.assertEqual(result["error"]["code"], "invalid_tool_input")
        self.assertEqual(self.service.download_calls, 0)

    def test_office_documents_reach_real_parser_through_verified_workcopy(self):
        f = self.service
        for kind in ("docx", "xlsx", "pptx"):
            f.body = office_fixture(kind)
            # Gateway v1 carries non-PDF documents as octet-stream. The actual
            # verified bytes determine content type; no descriptor broadening.
            f.mime = "application/octet-stream"
            result = self.call(session="office-" + kind)
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["format"], kind)
            self.assertIn("1234", result["content"])
            f.adapter.on_session_end(session_id="office-" + kind)

    def test_revocation_stops_actual_parser_and_returns_no_cached_content(self):
        f = self.service
        f.body = pdf_fixture()
        original = content.asyncio.create_subprocess_exec
        children = []

        async def observe(*args, **kwargs):
            process = await original(*args, **kwargs)
            children.append(process)
            f.adapter.on_session_end(session_id="content-session")
            return process

        with patch.object(content.asyncio, "create_subprocess_exec", observe):
            result = self.call()
        self.assertFalse(result["ok"], result)
        self.assertNotIn("content", result)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        self.assertFalse(self.call()["ok"])
        self.assertEqual(f.download_calls, 1)

    def test_parser_configuration_is_not_a_model_override(self):
        original = self.settings.get_config
        self.settings.get_config = lambda key, default=None: "wrong" if key == "inbound_content_python_sha256" else original(key, default)
        result = self.call()
        self.assertEqual(result["error"]["code"], "client_inventory_invalid")
        self.assertEqual(self.service.download_calls, 0)

    def test_explicit_parser_inventory_reads_with_same_lease(self):
        original = self.settings.get_config
        interpreter = str(Path(sys.executable).absolute())
        digest = hashlib.sha256(Path(interpreter).read_bytes()).hexdigest()
        configured = {"inbound_content_python": interpreter, "inbound_content_python_sha256": digest}
        self.settings.get_config = lambda key, default=None: configured.get(key, original(key, default))
        self.service.body = pdf_fixture()
        result = self.call()
        if Path(interpreter).is_symlink():
            # An explicitly configured interpreter must be an ordinary pinned
            # file. Linux venv launch symlinks remain valid only for the default
            # already-running interpreter, not as a path inventory bypass.
            self.assertEqual(result["error"]["code"], "client_inventory_invalid")
            self.assertEqual(self.service.download_calls, 0)
            return
        self.assertTrue(result["ok"], result)
        deadline = self.service.scope("content-session").resolved.deadline_monotonic
        self.assertTrue(self.call()["ok"])
        self.assertEqual(self.service.scope("content-session").resolved.deadline_monotonic, deadline)
        self.assertEqual(self.service.download_calls, 1)

    def test_vision_capability_failure_and_cancellation_do_not_return_success(self):
        f = self.service
        f.body = (fixture.FIXTURES / "sample.jpg").read_bytes()
        f.mime = "image/jpeg"
        cancelled = []

        async def image_entry(_args):
            timer = threading.Timer(0.05, f.adapter.on_session_end, kwargs={"session_id": "vision-cancel"})
            timer.start()
            try:
                await asyncio.sleep(10)
                return {"success": True, "analysis": "must never return"}
            finally:
                cancelled.append(True)

        image_entry.__module__ = "tools.vision_tools"
        entry = types.SimpleNamespace(handler=image_entry, is_async=True, check_fn=lambda: False)
        registry_module = types.ModuleType("tools.registry")
        registry_module.registry = types.SimpleNamespace(get_entry=lambda _name: entry)
        with patch.dict(sys.modules, {"tools.registry": registry_module}):
            result = self.call(session="vision-unavailable")
            self.assertEqual(result["error"]["code"], "vision_unavailable")
            entry.check_fn = lambda: True
            result = self.call(session="vision-cancel")
            self.assertFalse(result["ok"])
            self.assertNotIn("must never return", json.dumps(result))
        self.assertEqual(cancelled, [True])

    def test_image_bytes_and_quality_are_preserved_through_consumer_component(self):
        # This entry is a declared component stub. The separate official
        # HTTP/Agent test verifies the unmodified registered vision handler.
        f = self.service
        f.body = (fixture.FIXTURES / "sample.jpg").read_bytes()
        f.mime = "image/jpeg"
        seen = []

        async def image_entry(args):
            fixture.host.ensure_active()
            seen.append(args)
            return {"_multimodal": True, "content": [{"type": "image_url", "image_url": {"url": args["image_url"]},
                                                        "private_path": "must-not-escape"}]}

        image_entry.__module__ = "tools.vision_tools"
        registry_module = types.ModuleType("tools.registry")
        registry_module.registry = types.SimpleNamespace(get_entry=lambda name: types.SimpleNamespace(
            handler=image_entry, is_async=True, check_fn=lambda: True) if name == "vision_analyze" else None)
        with patch.dict(sys.modules, {"tools.registry": registry_module}):
            result = self.call({"attachment_id": 5, "question": "Read the label."})
        self.assertTrue(result["_multimodal"])
        import base64
        self.assertEqual(base64.b64decode(seen[0]["image_url"].split(",", 1)[1]), f.body)
        self.assertEqual(seen[0]["question"], "Read the label.")
        receipt = json.loads(result["text_summary"])
        self.assertTrue(receipt["verified"])
        self.assertEqual(receipt["original_comparison"], "not_checked")
        self.assertFalse(receipt["formal_archive"])
        self.assertNotIn("private_path", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
