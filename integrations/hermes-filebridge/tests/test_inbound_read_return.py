"""Unit contracts for PDF/PNG read-to-return; no worker, network or real model."""
from contextlib import contextmanager
import asyncio
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import threading
import time
import types
from unittest.mock import patch

import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("filebridge_read_return_unit", ROOT / "plugin/__init__.py")
plugin = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = plugin
SPEC.loader.exec_module(plugin)
inbound = __import__(SPEC.name + ".inbound", fromlist=["BridgeError"])
control = __import__(SPEC.name + ".inbound_control", fromlist=["ResolvedBinding"])
host = __import__(SPEC.name + ".inbound_host", fromlist=["HostAdapter"])
content = __import__(SPEC.name + ".inbound_content", fromlist=["handler_for"])
RETURN_MODULE = "cf_agent_gateway.hermes.return_bridge.plugin"
BINDING = {"dispatch_id": 47, "message_id": 4308,
    "enterprise_identity_id": "00000000-0000-4000-8000-000000000001",
    "thread_id": "00000000-0000-4000-8000-000000000002", "profile_reference": "synthetic",
    "profile_revision": 1, "session_id": "synthetic-session", "task_id": "synthetic-session",
    "turn_id": "synthetic-turn"}
PDF = b"%PDF-1.7\nSynthetic isolated fixture\n%%EOF\n"


class Harness:
    def __init__(self, body=PDF, kind="pdf", formats=None):
        self.body, self.kind, self.formats = body, kind, formats
        self.stream = io.BytesIO(body)
        self.live = True
        self.prepared = []
        self.module = types.ModuleType(RETURN_MODULE)
        def prepare(**kwargs):
            return self.prepare(**kwargs)
        prepare.__module__ = RETURN_MODULE
        self.module.prepare_inbound_return = prepare
        self.receipt = {"ok": True, "handle": "inbound:" + "a" * 48,
            "bytes_written": len(body), "sha256": hashlib.sha256(body).hexdigest(),
            "verified": True, "formal_archive": False, "dispatch_id": "gateway:synthetic",
            "task_id": "synthetic-session", "declared_quality": None, "original_comparison": "not_checked"}

    def check(self):
        if not self.live:
            raise inbound.BridgeError("task_cancelled")

    @contextmanager
    def opened(self, handle):
        assert handle == self.receipt["handle"]
        self.check()
        try:
            yield self.stream
        finally:
            self.stream.close()

    async def parser(self, data, executable):
        assert data == self.body
        return {"ok": True, "format": self.kind, "mime_type": "image/png" if self.kind == "png" else "application/pdf",
                "content": "synthetic extracted text", "units": []}

    def capture(self, attachment_id):
        assert attachment_id == 2
        return dict(BINDING), "original." + self.kind, self.check

    def prepare(self, **kwargs):
        self.check()
        assert kwargs["stream"] is self.stream and not self.stream.closed
        assert kwargs["stream"].tell() == 0
        assert kwargs["stream"].read() == self.body
        assert kwargs["binding"] == BINDING
        assert kwargs["attachment_id"] == 2
        kwargs["check_active"]()
        self.prepared.append(kwargs)
        return {"file_ref": "inbound-" + "b" * 32 + "." + self.kind, "kind": "file" if self.kind == "pdf" else "image",
                "filename": "original." + self.kind, "size_bytes": len(self.body),
                "sha256": hashlib.sha256(self.body).hexdigest()}

    def call(self, args=None):
        settings = types.SimpleNamespace(get_config=lambda key, default=None:
            True if key in {"inbound_enabled", "inbound_content_enabled"} else self.formats if key == "inbound_content_formats" else default)
        with patch.object(inbound, "handler_for", return_value=lambda args: json.dumps(self.receipt)), \
             patch.object(host, "ensure_active", self.check), \
             patch.object(host, "open_workcopy", self.opened), \
             patch.object(host, "capture_return_context", self.capture, create=True), \
             patch.object(content, "_run_parser", self.parser), \
             patch.dict(sys.modules, {RETURN_MODULE: self.module}):
            result = asyncio.run(content.handler_for(settings)(args or {"attachment_id": 2, "prepare_return": True}))
        return json.loads(result) if isinstance(result, str) else result



class ReadReturnTests(unittest.TestCase):

    def test_pdf_prepares_same_original_stream_after_reading(self):
        h = Harness()
        result = h.call()
        assert result["ok"] is True and result["read_succeeded"] is True
        assert result["content"] == "synthetic extracted text"
        prepared = result["return_preparation"]
        assert prepared["ok"] is True and prepared["file_ref"] == "inbound-" + "b" * 32 + ".pdf"
        assert prepared["next_tool"] == "cf_return_current_chat"
        assert len(h.prepared) == 1 and h.stream.closed
        assert "call cf_return_current_chat" in result["next_step"]


    def test_default_read_does_not_prepare_or_discover_return_module(self):
        h = Harness()
        h.module.prepare_inbound_return = lambda **kw: (_ for _ in ()).throw(AssertionError("preparation not requested"))
        result = h.call({"attachment_id": 2})
        assert result["ok"] is True and h.prepared == []
        assert "return_preparation" not in result


    def test_prepare_return_requires_real_bool(self):
        for value in [1, 0, None, "true", {}, []]:
            with self.subTest(value=value):
                result = Harness().call({"attachment_id": 2, "prepare_return": value})
                assert result["error"]["code"] == "invalid_tool_input"


    def test_prepare_failure_keeps_read_success_and_no_guessed_path(self):
        h = Harness()
        def failed(**kwargs):
            raise RuntimeError("SECRET synthetic absolute path and authorization")
        failed.__module__ = RETURN_MODULE
        h.module.prepare_inbound_return = failed
        result = h.call()
        assert result["ok"] is True and result["read_succeeded"] is True
        assert result["content"] == "synthetic extracted text"
        assert result["return_preparation"]["ok"] is False
        assert result["return_preparation"]["error"]["code"] == "return_preparation_failed"
        assert "file_ref" not in result["return_preparation"]
        assert "SECRET" not in json.dumps(result)


    def test_long_valid_original_filename_is_preserved(self):
        h = Harness()
        original = h.module.prepare_inbound_return
        name = "x" * 240 + ".pdf"
        def prepare(**kwargs):
            return {**original(**kwargs), "filename": name}
        prepare.__module__ = RETURN_MODULE
        h.module.prepare_inbound_return = prepare
        result = h.call()
        self.assertTrue(result["return_preparation"]["ok"])
        self.assertEqual(result["return_preparation"]["filename"], name)

    def test_read_failure_never_prepares(self):
        h = Harness()
        async def parser(*args):
            return {"ok": False, "error": {"code": "needs_ocr", "retryable": False}}
        h.parser = parser
        result = h.call()
        assert result["error"]["code"] == "needs_ocr" and h.prepared == []


    def test_expiry_during_prepare_discards_content(self):
        h = Harness()
        def cancelled(**kwargs):
            h.live = False
            kwargs["check_active"]()
        cancelled.__module__ = RETURN_MODULE
        h.module.prepare_inbound_return = cancelled
        result = h.call()
        assert result["ok"] is False and "content" not in result
        assert result["error"]["code"] == "task_cancelled"


    def test_office_read_does_not_expand_return_format(self):
        h = Harness(b"synthetic existing office document", "docx")
        result = h.call()
        assert result["ok"] is True and result["content"] == "synthetic extracted text"
        assert result["return_preparation"]["error"]["code"] == "return_format_unsupported"
        assert h.prepared == []


    def test_native_png_prepare_preserves_multimodal_image_and_source_bytes(self):
        h = Harness(b"\x89PNG\r\n\x1a\nsynthetic source pixels", "png")
        async def vision(*args):
            import base64
            return {"_multimodal": True, "content": [{"type": "image_url", "image_url": {
                "url": "data:image/png;base64," + base64.b64encode(h.body).decode()}}]}
        with patch.object(content, "_vision", vision):
            result = h.call()
        summary = json.loads(result["text_summary"])
        assert result["_multimodal"] is True and len(result["content"]) == 2
        assert summary["return_preparation"]["ok"] is True
        assert summary["return_preparation"]["kind"] == "image"
        assert len(h.prepared) == 1


    def test_auxiliary_png_failure_never_prepares(self):
        h = Harness(b"\x89PNG\r\n\x1a\nsynthetic source pixels", "png")
        async def vision(*args):
            return {"success": False, "analysis": "not successful"}
        with patch.object(content, "_vision", vision):
            result = h.call()
        assert result["error"]["code"] == "vision_failed" and h.prepared == []


    def test_prepare_schema_documents_bool_and_prohibits_handle_as_path(self):
        registered = []
        context = types.SimpleNamespace(register_tool=lambda **kw: registered.append(kw))
        content.register_content(context)
        schema = registered[0]["schema"]
        assert schema["parameters"]["properties"]["prepare_return"]["type"] == "boolean"
        assert schema["parameters"]["properties"]["prepare_return"]["default"] is False
        assert "cf_return_current_chat" in schema["description"]
        assert "filebrowser_files" in schema["description"]


    def test_binding_identity_preserves_trusted_resolve_fields(self):
        wanted = {name for name in BINDING if name not in {"turn_id", "session_id", "task_id"}}
        assert wanted <= set(control.ResolvedBinding.__dataclass_fields__)


    def test_captured_context_cannot_move_to_another_scope_or_extend_deadline(self):
        resolved = types.SimpleNamespace(**{k: v for k, v in BINDING.items() if k != "turn_id"},
            deadline_monotonic=time.monotonic() + 2,
            worker_binding={"dispatch_id": "gateway:fixed", "attachments": [{"attachment_id": 2, "filename": "original.pdf"}]})
        scope = types.SimpleNamespace(lock=threading.Lock(), stopped=threading.Event(), started=True, resolved=resolved)
        dispatch = types.SimpleNamespace(stopped=threading.Event())
        adapter = types.SimpleNamespace(bridge=types.SimpleNamespace(_lock=threading.Lock(), _dispatches={"gateway:fixed": dispatch}))
        token = host._active_host.set((adapter, scope))
        tool_token = host._active_tool.set(("filebrowser_read_inbound", "synthetic-turn"))
        try:
            binding, filename, check = host.capture_return_context(2)
            assert binding == BINDING and filename == "original.pdf"
            check()
        finally:
            host._active_tool.reset(tool_token)
            host._active_host.reset(token)
        # Captured authority belongs to its original scope even outside ContextVar.
        check()
        dispatch.stopped.set()
        with self.assertRaisesRegex(inbound.BridgeError, "task_cancelled"):
            check()


    def test_host_context_without_official_reader_marker_refuses(self):
        with self.assertRaises(inbound.BridgeError):
            host.capture_return_context(2)

    def test_explicit_formats_block_office_and_jpeg_before_parser(self):
        for body, kind in [(b"PKsynthetic", "docx"), (b"\xff\xd8\xffsynthetic", "jpeg")]:
            with self.subTest(kind=kind):
                h = Harness(body, kind, formats=["pdf", "png"])
                async def parser(*args):
                    raise AssertionError("forbidden format reached parser")
                h.parser = parser
                result = h.call()
                self.assertEqual(result["error"]["code"], "content_format_disabled")
                self.assertEqual(h.prepared, [])

    def test_invalid_format_policies_refuse_without_parser(self):
        for value in [[], "pdf", ["docx"], ["pdf", "pdf"], [{}], [True]]:
            with self.subTest(value=value):
                result = Harness(formats=value).call()
                self.assertEqual(result["error"]["code"], "content_formats_invalid")

    def test_pdf_policy_and_read_only_false_keep_expected_contract(self):
        h = Harness(formats=["pdf", "png"])
        result = h.call({"attachment_id": 2, "prepare_return": False})
        self.assertTrue(result["ok"])
        self.assertEqual(h.prepared, [])
        self.assertNotIn("return_preparation", result)

    def test_unknown_or_wrong_module_is_not_loaded_or_called(self):
        h = Harness()
        called = []
        h.module.prepare_inbound_return = lambda **kwargs: called.append(kwargs)
        result = h.call()
        self.assertTrue(result["ok"])
        self.assertEqual(result["return_preparation"]["error"]["code"], "return_preparation_unavailable")
        self.assertEqual(called, [])

    def test_untrusted_staging_receipt_is_not_forwarded(self):
        for bad in [
            {"private_path": "synthetic-secret"},
            {"file_ref": "../secret", "kind": "file", "filename": "x.pdf", "size_bytes": len(PDF), "sha256": hashlib.sha256(PDF).hexdigest()},
            {"file_ref": "x.pdf", "kind": "file", "filename": "x.pdf", "size_bytes": len(PDF), "sha256": "0" * 64},
        ]:
            h = Harness()
            def prepare(**kwargs):
                return bad
            prepare.__module__ = RETURN_MODULE
            h.module.prepare_inbound_return = prepare
            result = h.call()
            self.assertTrue(result["read_succeeded"])
            self.assertFalse(result["return_preparation"]["ok"])
            self.assertNotIn("synthetic-secret", json.dumps(result))


class HostReturnContextTests(unittest.TestCase):
    def capture(self, *, tool="filebrowser_read_inbound", turn="synthetic-turn", attachment_id=2):
        resolved = types.SimpleNamespace(**{k: v for k, v in BINDING.items() if k != "turn_id"},
            deadline_monotonic=time.monotonic() + 3,
            worker_binding={"dispatch_id": "gateway:fixed", "attachments": [{"attachment_id": 2, "filename": "original.pdf"}]})
        scope = types.SimpleNamespace(lock=threading.Lock(), stopped=threading.Event(), started=True, resolved=resolved)
        dispatch = types.SimpleNamespace(stopped=threading.Event())
        adapter = types.SimpleNamespace(bridge=types.SimpleNamespace(_lock=threading.Lock(), _dispatches={"gateway:fixed": dispatch}))
        token = host._active_host.set((adapter, scope))
        tool_token = host._active_tool.set((tool, turn))
        try:
            captured = host.capture_return_context(attachment_id)
        finally:
            host._active_tool.reset(tool_token)
            host._active_host.reset(token)
        return scope, adapter, dispatch, captured

    def test_wrong_tool_turn_or_attachment_denied(self):
        for changes in ({"tool": "cf_return_current_chat"}, {"turn": None}, {"turn": ""},
                        {"attachment_id": 3}, {"attachment_id": True}):
            with self.subTest(changes=changes), self.assertRaises(inbound.BridgeError):
                self.capture(**changes)

    def test_original_guard_rejects_scope_dispatch_or_deadline_replacement(self):
        for changed in ("scope", "dispatch", "deadline", "expired", "revoked"):
            scope, adapter, dispatch, captured = self.capture()
            check = captured[2]
            if changed == "scope":
                scope.resolved = types.SimpleNamespace(**vars(scope.resolved))
            elif changed == "dispatch":
                adapter.bridge._dispatches["gateway:fixed"] = types.SimpleNamespace(stopped=threading.Event())
            elif changed == "deadline":
                scope.resolved.deadline_monotonic += 30
            elif changed == "expired":
                scope.resolved.deadline_monotonic = time.monotonic() - 1
            else:
                scope.stopped.set()
            with self.subTest(changed=changed), self.assertRaisesRegex(inbound.BridgeError, "task_cancelled"):
                check()

    def test_official_middleware_sets_and_clears_reader_marker(self):
        scope, adapter, dispatch, _ = self.capture()
        scope.active_calls = 0
        scope.calls_finished = threading.Event()
        scope.calls_finished.set()
        @contextmanager
        def activate(dispatch_id):
            assert dispatch_id == "gateway:fixed"
            yield
        adapter.bridge.activate = activate
        adapter._tools = {"filebrowser_read_inbound"}
        adapter._scope = lambda session, task: scope
        adapter._terminate = lambda scope: scope.stopped.set()
        def consume(args):
            binding, filename, check = host.capture_return_context(2)
            self.assertEqual(binding, BINDING)
            check()
            return "ok"
        result = host.HostAdapter.middleware(adapter, "filebrowser_read_inbound", {}, consume,
            session_id=BINDING["session_id"], task_id=BINDING["task_id"], turn_id=BINDING["turn_id"])
        self.assertEqual(result, "ok")
        self.assertIsNone(host._active_host.get())
        self.assertIsNone(host._active_tool.get())
        self.assertEqual(scope.active_calls, 0)
        self.assertTrue(scope.calls_finished.is_set())


    def test_ordinary_return_without_inbound_scope_does_not_resolve(self):
        adapter = types.SimpleNamespace(_lock=threading.Lock(), _scopes={}, _tools={"cf_return_current_chat"})
        adapter._scope = lambda *args: (_ for _ in ()).throw(AssertionError("ordinary return must not resolve inbound"))
        calls = []
        result = host.HostAdapter.middleware(adapter, "cf_return_current_chat", {"file_ref": "generated.pdf"},
            lambda args: calls.append(args) or "original-return-result",
            session_id="ordinary-session", task_id="ordinary-session", turn_id="ordinary-turn")
        self.assertEqual(result, "original-return-result")
        self.assertEqual(calls, [{"file_ref": "generated.pdf"}])
        self.assertEqual(adapter._scopes, {})

    def test_existing_ended_inbound_scope_cannot_use_ordinary_return_passthrough(self):
        ended = types.SimpleNamespace(stopped=threading.Event())
        ended.stopped.set()
        adapter = types.SimpleNamespace(_lock=threading.Lock(), _tools={"cf_return_current_chat"},
            _scopes={("ended", "ended"): ended})
        adapter._scope = lambda *args: (_ for _ in ()).throw(inbound.BridgeError("task_cancelled"))
        adapter._terminate = lambda *args: None
        result = host.HostAdapter.middleware(adapter, "cf_return_current_chat", {},
            lambda args: (_ for _ in ()).throw(AssertionError("ended scope reached return")),
            session_id="ended", task_id="ended", turn_id="turn")
        self.assertFalse(json.loads(result)["ok"])


class ResolveIdentityTests(unittest.TestCase):
    def test_real_control_validation_preserves_identity_without_worker_key_confusion(self):
        from datetime import datetime, timedelta, timezone
        import uuid
        session = BINDING["session_id"]
        owner = {"schema": control.RESOLVE_SCHEMA, "session_id": session, "task_id": session,
                 "host_instance_id": "synthetic-host", "host_nonce": "n" * 32}
        binding_id = str(uuid.uuid4())
        origin = "https://gateway.invalid"
        now = datetime.now(timezone.utc)
        expires = (now + timedelta(seconds=20)).isoformat()
        payload = {**owner, **{k: v for k, v in BINDING.items() if k not in {"turn_id", "session_id", "task_id"}},
            "binding_id": binding_id, "claim_epoch": str(uuid.uuid4()), "lease_valid_until": expires,
            "server_now": now.isoformat(),
            "state": "running", "budget_scope": "message:4308:attachment:2", "event_sequence": 1,
            "attachments": [{"schema": "cf-inbound-read/v1", "message_id": 4308, "attachment_id": 2,
                "thread_id": BINDING["thread_id"], "enterprise_identity_id": BINDING["enterprise_identity_id"],
                "url": origin + "/inbound-media/2/content", "authorization": "Bearer synthetic-only-read-token",
                "expires_at": expires, "download_policy": {"max_attempts": 4, "total_timeout_seconds": 30,
                    "retryable_status_codes": [503], "retry_after_seconds": 1},
                "size": len(PDF), "sha256": hashlib.sha256(PDF).hexdigest(), "mime_type": "application/pdf",
                "filename": "original.pdf", "declared_quality": None, "original_comparison": "not_checked",
                "formal_archive": False}]}
        client = object.__new__(control.ControlClient)
        client.config = types.SimpleNamespace(gateway_origin=origin, service_token="synthetic-other-token",
            profile_reference="synthetic", profile_revision=1, work_root="unused-test-root", max_bytes=1048576,
            ca_file=None)
        client._post = lambda path, body: payload
        with patch.object(control, "create_task_directory", return_value="never-created-synthetic-directory"):
            resolved = client.resolve(session, session, owner["host_instance_id"], owner["host_nonce"])
        self.assertEqual(resolved.dispatch_id, 47)
        self.assertEqual(resolved.worker_binding["dispatch_id"], "gateway:" + binding_id)
        for key, value in BINDING.items():
            if key != "turn_id":
                self.assertEqual(getattr(resolved, key), value)
        self.assertNotIn("synthetic-only-read-token", repr(resolved))


if __name__ == "__main__":
    unittest.main()
