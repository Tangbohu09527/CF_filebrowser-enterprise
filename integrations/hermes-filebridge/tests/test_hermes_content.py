"""Real official HTTP/Agent/loader/content/vision with synthetic TLS and model.

Run explicitly for the upstream integration. Ordinary unittest discovery only
checks the narrow parser-launch exception. The model makes no visual judgment:
we verify actual image bytes/pixels in its subsequent HTTP request.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = Path(__file__).resolve().parent
TOOL = "filebrowser_read_inbound"
CURRENT = "0f4a98f87c17007b81500239d0bd5b9574027b73"
TEXT = "Quarterly revenue is 1234 USD."
OBSERVER = '''import json, os, threading
_lock = threading.Lock()
def record(kind, value):
    with _lock, open(os.environ["CF_JOINT_EVENTS"], "a", encoding="utf-8") as stream:
        stream.write(json.dumps({"kind": kind, **value}) + "\\n")
def register(ctx):
    def execution(*, next_call, tool_name, args, **context):
        result = next_call(args)
        if tool_name == "filebrowser_read_inbound":
            from tools.registry import registry
            parsed = json.loads(result) if isinstance(result, str) else result
            if isinstance(parsed, dict) and parsed.get("_multimodal"):
                parsed = json.loads(parsed["text_summary"])
            vision = registry.get_entry("vision_analyze")
            record("tool", {"tool": tool_name, "result": parsed,
                "session_id": context.get("session_id"), "task_id": context.get("task_id"),
                "vision_handler_module": vision.handler.__module__ if vision else None,
                "original_tools_registered": all(registry.get_entry(name) is not None
                    for name in ("filebrowser_files", "filebrowser_create_text"))})
        return result
    def ended(**context):
        record("end", {key: context.get(key) for key in ("session_id", "task_id", "failed", "interrupted")})
    ctx.register_middleware("tool_execution", execution)
    ctx.register_hook("on_session_end", ended)
'''


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[name] = loaded
    spec.loader.exec_module(loaded)
    return loaded


class ContentParserGuardTests(unittest.TestCase):
    def test_fixed_parser_launch_and_rejected_variants(self):
        joint = module("content_guard_helpers", "test_gateway_hermes_joint.py")
        with tempfile.TemporaryDirectory(prefix="cf-content-guard-") as temp:
            sandbox = Path(temp)
            parser = sandbox / "profile/plugins/cf-filebridge/inbound_content.py"
            command = [sys.executable, "-I", "-X", "utf8", "-B", str(parser), "--parse-stdin"]
            environment = {key: value for key, value in os.environ.items()
                           if key.upper() in {"SYSTEMROOT", "WINDIR"}}
            def allowed(argv=command, env=environment, cwd=str(parser.parent), executable=sys.executable):
                wire = subprocess.list2cmdline(argv) if os.name == "nt" else argv
                return joint.content_parser_launch_allowed(sandbox, executable, wire, cwd, env)
            self.assertTrue(allowed())
            self.assertFalse(allowed(command + ["extra"]))
            self.assertFalse(allowed([sys.executable, "-c", "pass"]))
            self.assertFalse(allowed(env={**environment, "CF_FILEBRIDGE_HOST_SECRET": "synthetic"}))
            self.assertFalse(allowed(env=None))
            self.assertFalse(allowed(cwd=str(sandbox)))
            self.assertFalse(allowed(executable="arbitrary-python"))
            if os.name == "nt":
                lowered = [*command[:5], os.path.normcase(str(parser)), command[-1]]
                self.assertTrue(allowed(lowered, cwd=os.path.normcase(str(parser.parent))))
                self.assertFalse(allowed([command[0], "-i", *command[2:]]))


class ModelServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), ModelHandler)
        self.requests = []
        self.lock = threading.Lock()
        self.revoke_entered = threading.Event()
        self.revoke_release = threading.Event()

    def handle_error(self, *_args):
        pass


class ModelHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def send_json(self, payload):
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.send_json({"object": "list", "data": [{"id": "cf-content-model", "object": "model"}]})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        with self.server.lock:
            self.server.requests.append(body)
        messages = body.get("messages", [])
        index = next((i for i in range(len(messages)-1, -1, -1)
                      if messages[i].get("role") == "user" and
                      "content-case:" in str(messages[i].get("content", ""))), -1)
        text = str(messages[index].get("content", "")) if index >= 0 else ""
        results = [item for item in messages[index+1:] if item.get("role") == "tool"]
        names = {item.get("function", {}).get("name") for item in body.get("tools", [])}
        if "content-case:revoked" in text and len(results) == 1:
            self.server.revoke_entered.set()
            assert self.server.revoke_release.wait(20), "test did not release its model gate"
        limit = 1 if "content-case:after" in text else 2
        if names and index >= 0 and len(results) < limit:
            name, args = TOOL, {"attachment_id": 5, "question": "Describe the supplied pixels."}
            if name not in names:
                assert "tool_call" in names, "official deferred tool dispatcher missing"
                name, args = "tool_call", {"calls": [{"name": name, "arguments": args}]}
            message = {"role": "assistant", "content": None, "tool_calls": [{
                "id": "call_content_" + str(len(results)), "type": "function",
                "function": {"name": name, "arguments": json.dumps(args)}}]}
            finish = "tool_calls"
        else:
            message = {"role": "assistant", "content": "Deterministic model fixture completed."}
            finish = "stop"
        envelope = {"id": "chatcmpl-content", "object": "chat.completion", "created": int(time.time()),
            "model": "cf-content-model", "choices": [{"index": 0, "message": message, "finish_reason": finish}],
            "usage": {"prompt_tokens": 20, "completion_tokens": 20, "total_tokens": 40}}
        if not body.get("stream"):
            self.send_json(envelope)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        delta = {key: value for key, value in message.items() if key != "role"}
        if "tool_calls" in delta:
            delta["tool_calls"] = [{"index": index, **value} for index, value in enumerate(delta["tool_calls"])]
        chunk = {key: value for key, value in envelope.items() if key not in {"choices", "usage"}}
        chunk["object"] = "chat.completion.chunk"
        for piece, reason in (({"role": "assistant", **delta}, None), ({}, finish)):
            chunk["choices"] = [{"index": 0, "delta": piece, "finish_reason": reason}]
            self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


def recorded(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


def image_payloads(value):
    if isinstance(value, dict):
        if value.get("type") == "image_url":
            url = value.get("image_url", {}).get("url", "")
            if url.startswith("data:image/") and ";base64," in url:
                yield base64.b64decode(url.split(";base64,", 1)[1], validate=True)
        for item in value.values():
            yield from image_payloads(item)
    elif isinstance(value, list):
        for item in value:
            yield from image_payloads(item)


async def until(predicate, timeout=20):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("content integration condition timed out")
        await asyncio.sleep(0.025)


async def orchestrate(args):
    sys.path.insert(0, str(HERE))
    from aiohttp import ClientSession, ClientTimeout
    from PIL import Image
    from test_inbound_host import HostControlTests, SERVICE_ENV, SERVICE_SECRET, READ_SECRET
    from test_inbound_content import pdf_fixture, office_fixture
    from hermes_joint_host import ExternalHermesHost
    from hermes_probe_support import isolated_environment
    HostControlTests.worker = args.worker
    HostControlTests.worker_hash = hashlib.sha256(args.worker.read_bytes()).hexdigest()
    HostControlTests.worker_launches = []
    reports = []
    for kind in args.case or ["pdf", "docx", "xlsx", "pptx", "image", "image-internal", "retry", "revoked"]:
        original_environment = dict(os.environ)
        fixture = HostControlTests()
        fixture.make_adapter = False
        fixture.setUp()
        model = ModelServer()
        threading.Thread(target=model.serve_forever, daemon=True).start()
        host = pending = None
        home = fixture.root / "profile"
        event_path = fixture.root / "events.jsonl"
        secret = secrets.token_urlsafe(32)
        try:
            fixture.lease_seconds = 30
            fixture.body = office_fixture(kind) if kind in {"docx", "xlsx", "pptx"} else pdf_fixture()
            fixture.mime = "application/octet-stream" if kind in {"docx", "xlsx", "pptx"} else "application/pdf"
            if kind in {"image", "image-internal"}:
                picture = Image.new("RGB", (24, 16), (37, 181, 93))
                picture.putpixel((3, 4), (241, 29, 87))
                stream = io.BytesIO()
                picture.save(stream, format="PNG")
                fixture.body, fixture.mime = stream.getvalue(), "image/png"
            if kind == "retry":
                fixture.mode = "503_once"
            shutil.copytree(HERE.parent / "plugin", home / "plugins/cf-filebridge",
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            observer = home / "plugins/cf-a-content-observer"
            observer.mkdir()
            (observer / "plugin.yaml").write_text('name: cf-a-content-observer\nversion: "1.0.0"\nkind: standalone\n')
            (observer / "__init__.py").write_text(OBSERVER, encoding="utf-8")
            fixture.raw["consumer_tools"] = [TOOL]
            config = {"plugins": {"enabled": ["cf-filebridge", "cf-a-content-observer"], "entries": {
                "cf-filebridge": {"settings": {"inbound_enabled": True, "inbound_content_enabled": True,
                    "inbound_host_enabled": True, "inbound_host": fixture.raw, "create_enabled": True,
                    "create_config_path": str(home / "unused-create-config.json")}}}},
                "platform_toolsets": {"api_server": ["cf_filebridge", "cf_filebridge_create",
                    "cf_filebridge_inbound", "cf_filebridge_inbound_content", "vision"]},
                "model": {"provider": "custom", "default": "cf-content-model", "api_mode": "chat_completions",
                    "base_url": f"http://127.0.0.1:{model.server_port}/v1", "context_length": 131072,
                    "supports_vision": True, "api_key": "public-isolated-model-not-a-credential"},
                "agent": {"max_iterations": 6, "environment_probe": False},
                "security": {"allow_lazy_installs": False}, "memory": {"enabled": False},
                "skills": {"enabled": False}, "compression": {"enabled": False}}
            if kind == "image-internal":
                config["platform_toolsets"]["api_server"].remove("vision")
            (home / "config.yaml").write_text(json.dumps(config), encoding="utf-8")
            environment = isolated_environment(fixture.root, {SERVICE_ENV: SERVICE_SECRET,
                "CF_JOINT_HERMES_KEY": secret, "CF_JOINT_EVENTS": str(event_path)})
            os.environ.clear()
            os.environ.update(environment)
            host = ExternalHermesHost(args.hermes_python, args.hermes_source, fixture.root, args.worker,
                hermes_commit=args.hermes_commit, hermes_archive=args.hermes_archive,
                observer="cf-a-content-observer", allow_content_parser=True)
            origin = await host.start()
            async with ClientSession(timeout=ClientTimeout(total=45)) as client:
                session = "isolated-content-" + kind
                async def request(label):
                    async with client.post(origin + "/v1/chat/completions", headers={
                        "Authorization": "Bearer " + secret, "X-Hermes-Session-Id": session},
                        json={"model": "cf-hermes-api", "stream": False,
                              "messages": [{"role": "user", "content": "content-case:" + label}]}) as response:
                        return response.status, await response.json()
                if kind == "revoked":
                    pending = asyncio.create_task(request(kind))
                    await until(model.revoke_entered.is_set)
                    with fixture.lock:
                        fixture.records[session].update(sequence=2, state="revoked", reason="test_content_revoked")
                    await until(lambda: fixture.closed_calls == 1)
                    model.revoke_release.set()
                    response = await pending
                else:
                    response = await request(kind)
                assert response[0] == 200, {"case": kind, "http_status": response[0]}
                await until(lambda: fixture.closed_calls == 1)
                tools = [item for item in recorded(event_path) if item["kind"] == "tool"]
                assert len(tools) == 2, {"case": kind, "tools": tools}
                assert all(item["session_id"] == session == item["task_id"] for item in tools)
                assert all(item["original_tools_registered"] for item in tools), "legacy read/create registration lost"
                results = [item["result"] for item in tools]
                assert results[0].get("ok") is True, {"case": kind, "result": results[0]}
                assert results[0]["verified"] is True and results[0]["formal_archive"] is False
                assert results[0]["sha256"] == hashlib.sha256(fixture.body).hexdigest()
                assert results[0]["bytes_written"] == len(fixture.body)
                if kind == "revoked":
                    assert results[1].get("ok") is False, "revoked consumer succeeded"
                else:
                    assert results[1].get("ok") is True, results[1]
                    assert results[0]["handle"] == results[1]["handle"], "repeat refreshed the workcopy"
                assert fixture.resolve_calls == fixture.event_calls == 1
                assert fixture.download_calls == (2 if kind == "retry" else 1), "repeat refreshed the shared download budget"
                if kind in {"image", "image-internal"}:
                    assert tools[0]["vision_handler_module"] == "tools.vision_tools"
                    assert results[0]["vision"] == "native_image_attached", results[0]
                    payloads = list(image_payloads(model.requests))
                    assert payloads, "no actual image reached the model HTTP endpoint"
                    expected = Image.open(io.BytesIO(fixture.body)).convert("RGB")
                    actual = Image.open(io.BytesIO(payloads[0])).convert("RGB")
                    assert actual.size == expected.size and actual.tobytes() == expected.tobytes(), "model received different pixels"
                    assert payloads[0] == fixture.body, "small PNG bytes changed in the official native vision path"
                else:
                    expected_format = kind if kind in {"docx", "xlsx", "pptx"} else "pdf"
                    assert results[0]["format"] == expected_format, results[0]
                    assert TEXT in results[0]["content"] and results[0]["untrusted_content"] is True
                    assert results[0]["ocr_performed"] is False
                    assert TEXT in json.dumps(model.requests), "actual extracted text never reached a subsequent model call"
                counters = (fixture.resolve_calls, fixture.event_calls, fixture.download_calls)
                await request("after")
                assert counters == (fixture.resolve_calls, fixture.event_calls, fixture.download_calls)
                replay = [item for item in recorded(event_path) if item["kind"] == "tool"][2:]
                assert len(replay) == 1 and replay[0]["result"].get("ok") is False, "ended session consumer was revived"
            assert fixture.control_headers_valid and fixture.media_headers_valid
            await host.stop()
            snapshot = await host.snapshot()
            if args.hermes_commit == CURRENT:
                assert snapshot["python_version"] == "3.14.7", "current Hermes probe requires exact Python 3.14.7"
            material = [json.dumps(model.requests).encode(), event_path.read_bytes()]
            material += [path.read_bytes() for path in home.rglob("*") if path.is_file()]
            assert all(value.encode() not in data for value in (SERVICE_SECRET, READ_SECRET, secret)
                       for data in material), "authorization reached model/history/profile"
            assert snapshot["audit_violations"] == [] and snapshot["active_scopes"] == 0
            assert len(snapshot["scopes"]) == 1 and all(
                scope["finished"] and scope["ended"] and scope["worker_exit"] == 0
                for scope in snapshot["scopes"]), "ended content worker was not joined"
            reports.append({"case": kind, "ok": True, "download_requests": fixture.download_calls,
                "closed": fixture.closed_calls, "repeat_shared_budget": True,
                "ended_consumer_rejected": True, "legacy_tools_registered": True,
                "official_vision_pixels_in_model_request": kind in {"image", "image-internal"},
                "vision_toolset_enabled": kind != "image-internal", "audit_violations": [],
                "python": snapshot["python_version"], "scratch_housekeeping_validated": False})
        except BaseException:
            diagnostic = {"case": kind, "resolve": fixture.resolve_calls, "events": fixture.event_calls,
                "downloads": fixture.download_calls, "closed": fixture.closed_calls,
                "tool_events": recorded(event_path)}
            if host is not None and host.status.exists():
                diagnostic["host_status"] = await host.snapshot()
            print(json.dumps(diagnostic), file=sys.stderr)
            raise
        finally:
            model.revoke_release.set()
            fixture.download_release.set()
            try:
                if host is not None:
                    await host.stop()
            finally:
                model.shutdown()
                model.server_close()
                if pending is not None:
                    if not pending.done():
                        pending.cancel()
                    await asyncio.gather(pending, return_exceptions=True)
                fixture.doCleanups()
                os.environ.clear()
                os.environ.update(original_environment)
    print(json.dumps({"ok": True, "hermes_commit": args.hermes_commit, "cases": reports,
        "actual_official_http_agent_loader_middleware": True, "actual_native_worker": True,
        "real_gateway_joint": False, "production_acceptance": False, "real_visual_accuracy_validated": False,
        "stubs": ["TLS Gateway control/media", "deterministic loopback model"]}))


def run(args):
    support = module("content_source_support", "hermes_probe_support.py")
    support.verify_source(args.hermes_source, args.hermes_commit, args.hermes_archive)
    with tempfile.TemporaryDirectory(prefix="cf-hermes-content-") as temp:
        sandbox = Path(temp).resolve()
        environment = support.isolated_environment(sandbox)
        command = [sys.executable, "-I", "-B", "-X", "utf8", str(Path(__file__).resolve()),
            "--hermes-source", str(args.hermes_source), "--hermes-commit", args.hermes_commit,
            "--hermes-python", str(args.hermes_python), "--worker", str(args.worker), "--orchestrator"]
        if args.hermes_archive:
            command += ["--hermes-archive", str(args.hermes_archive)]
        for case in args.case or []:
            command += ["--case", case]
        result = subprocess.run(command, cwd=sandbox, env=environment, capture_output=True,
                                text=True, encoding="utf-8", timeout=360)
        protected = ("synthetic-only-host-service-secret-never-a-live-credential",
                     "Bearer synthetic-only-attachment-grant-never-a-live-credential")
        if any(value in result.stdout or value in result.stderr for value in protected):
            raise RuntimeError("content probe diagnostic contained synthetic authorization; withheld")
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        if result.returncode:
            raise SystemExit(result.returncode)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hermes-source", type=Path, required=True)
    parser.add_argument("--hermes-commit", required=True)
    parser.add_argument("--hermes-archive", type=Path)
    parser.add_argument("--hermes-python", type=Path, default=Path(sys.executable))
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--case", action="append", choices=["pdf", "docx", "xlsx", "pptx", "image", "image-internal", "retry", "revoked"])
    parser.add_argument("--orchestrator", action="store_true", help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    arguments.hermes_source = arguments.hermes_source.resolve(strict=True)
    arguments.worker = arguments.worker.resolve(strict=True)
    arguments.hermes_python = arguments.hermes_python.absolute()  # Preserve a venv symlink entry.
    if arguments.hermes_archive:
        arguments.hermes_archive = arguments.hermes_archive.resolve(strict=True)
    if arguments.orchestrator:
        asyncio.run(orchestrate(arguments))
    else:
        run(arguments)
