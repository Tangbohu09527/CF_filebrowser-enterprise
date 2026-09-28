"""Real pinned Gateway -> Hermes HTTP/AIAgent -> FileBridge -> native worker.

Explicit Linux test, never silently skipped by unittest discovery. Only the
loopback model and upstream WeChat fetch are doubles. Database admission, durable
claim, child-session preparation, authentication, SSE, download and both stores
are real. No manual HostBridge.start_dispatch, fake PluginContext or core patch.
The Linux Gateway staging implementation intentionally refuses Windows.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
import mimetypes
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback

HERE = Path(__file__).resolve().parent
PLUGIN = HERE.parent / "plugin"
GATEWAY_COMMIT = "0ec54bf0f25f421e37e16e11bd098a814beca258"
GATEWAY_ZIP_SHA256 = "c0ad44618fcd7c640c640f921e8910b8292dcadc24dd2c03cc03a34c2761c445"
DOWNLOAD = "filebrowser_download_inbound"
CONSUME = "probe_consume_workcopy"
SERVICE_ENV = "CF_FILEBRIDGE_HOST_JOINT_SERVICE"
PROFILE = "profiles/joint-isolated/1"
_test_secrets = []
GATEWAY_BLOBS = {
    "docs/development/inbound-host-binding-contract.md": "c997a05af5fbe8466e13f572e4de7422b71f7615",
    "docs/development/inbound-host-session-compatibility.md": "699caa7b271724d8b71d60438955b73dcfe6abff",
    "tests/fixtures/inbound-host-binding-v1.json": "a2f4868b7fd4a1bce0b13c6c33b2afbd90df3efb",
    "src/cf_agent_gateway/adapters/wechat/inbound_media_staging.py": "08a2619565d0a9ffe04b0e855391112abd95e67c",
    "src/cf_agent_gateway/database.py": "111b4aa0e745c37b5b915495e18562700c6f3374",
    "src/cf_agent_gateway/gateway/app.py": "6e67f84a252d93bfa360a50e423422c2f4e99d17",
    "src/cf_agent_gateway/gateway/security.py": "b3772f0d426c7b415c51dd340e7fcd4433fb7012",
    "src/cf_agent_gateway/hermes/client.py": "a95c1f082af959f8de027685a728241f10f2ab75",
    "src/cf_agent_gateway/hermes/service.py": "fdc501938cdb7cde10d334fab577e2a940ae4d35",
    "src/cf_agent_gateway/hermes/worker.py": "81d6bcd7dfb3f893565a7cf92539e1056c9fa0fb",
    "src/cf_agent_gateway/inbound/access.py": "46c4c8552c82485f41076bd392e674a4c30f2b45",
    "src/cf_agent_gateway/inbound/host_binding.py": "42988da5fda0d13c81334eec1f2b7ed63ae5f62b",
    "src/cf_agent_gateway/inbound/host_binding_config.py": "8df47b4dcfa6dd6db85fc1dd9ffba0c55d9d39a7",
    "src/cf_agent_gateway/inbound/host_binding_models.py": "594ff7e2c1f46290504da103feb95de7685850a6",
    "src/cf_agent_gateway/inbound/host_binding_routes.py": "a953033ce1b3dbd1b8333208c378a298d463c8de",
    "src/cf_agent_gateway/inbound/store.py": "097297ab54cc874b5272f072edac2f8cfc83dd63",
    "src/cf_agent_gateway/inbound/worker.py": "a43eafb37c248d447d8287462677329ef419ceb9",
    "src/cf_agent_gateway/task/model/store.py": "f5daad32637b9c75e40483704506b23f0de41337",
}
HERMES_SESSION_BLOBS = {
    "hermes_state_sessions.py": "cfd7811fdf5965b735d7407114d1bb4d1c4041c8",
    "hermes_state_messages.py": "4e7b96faa7b82f23c703a4b9f58c2dcf759b712e",
    "hermes_state_compression.py": "9f8415faba7e3a356bb3b427286e86b15813c33e",
    "gateway/platforms/api_server_runs.py": "3976ff02de219fa0c0de6bb7919fbb51e8cffecc",
}


def verify_blobs(source, blobs):
    for relative, expected in blobs.items():
        data = (source / relative).read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if actual != expected:
            raise ValueError("Immutable source mismatch: " + relative)


def verify_sources(gateway, hermes, archive=None):
    if archive is not None and hashlib.sha256(archive.read_bytes()).hexdigest() != GATEWAY_ZIP_SHA256:
        raise ValueError("Fixed Gateway archive SHA-256 mismatch")
    verify_blobs(gateway, GATEWAY_BLOBS)
    spec = importlib.util.spec_from_file_location("joint_source_verifier", HERE / "test_hermes_loader.py")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    verifier.verify_source(hermes)
    verify_blobs(hermes, HERMES_SESSION_BLOBS)
    return verifier.HERMES_COMMIT


# This separate observer/consumer uses only public plugin registrations. It
# cannot issue bindings and has no Gateway credential or descriptor access.
OBSERVER = '''import hashlib, importlib, json, os, threading
_lock = threading.Lock()
retained_streams = []
native_processes = []
def record(kind, data):
    with _lock, open(os.environ["CF_JOINT_EVENTS"], "a", encoding="utf-8") as stream:
        stream.write(json.dumps({"kind": kind, **data}) + "\\n")
def consume(args, **kwargs):
    from hermes_cli.plugins import get_plugin_manager
    module = get_plugin_manager()._plugins["cf-filebridge"].module
    host = importlib.import_module(module.__name__ + ".inbound_host")
    try:
        if os.environ.get("CF_JOINT_RETAIN_STREAM") == "1":
            context = host.open_workcopy(args["handle"])
            stream = context.__enter__()
            retained_streams.append((context, stream))
            data = stream.read()
            # Read-only observation of the real native child for exit checks;
            # the test never creates, changes or injects a dispatch binding.
            adapter, scope = host._active_host.get()
            native_processes.append(adapter.bridge._dispatches[scope.resolved.worker_binding["dispatch_id"]].process)
        else:
            with host.open_workcopy(args["handle"]) as stream:
                data = stream.read()
        result = {"ok": True, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                  "actual_stream_read": True}
    except Exception:
        result = {"ok": False, "error": {"code": "workcopy_unavailable"}}
    return json.dumps(result)
def register(ctx):
    def execution(*, next_call, tool_name, args, **context):
        result = next_call(args)
        if tool_name in ("filebrowser_download_inbound", "probe_consume_workcopy"):
            parsed = json.loads(result) if isinstance(result, str) else result
            record("tool", {"tool": tool_name, "session_id": context.get("session_id"),
                "task_id": context.get("task_id"), "result": parsed})
        return result
    def ended(**context):
        record("end", {k: context.get(k) for k in ("session_id", "task_id", "interrupted", "failed")})
    ctx.register_middleware("tool_execution", execution)
    ctx.register_hook("on_session_end", ended)
    ctx.register_tool("probe_consume_workcopy", "cf_joint_probe", {
        "name": "probe_consume_workcopy", "description": "Test consumer of an authorized workcopy handle",
        "parameters": {"type": "object", "required": ["handle"], "additionalProperties": False,
                       "properties": {"handle": {"type": "string"}}}}, consume)
'''


class ModelServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), ModelHandler)
        self.requests = []
        self.lock = threading.Lock()
        self.barrier = threading.Barrier(2, timeout=15)
        self.control_events = {name: (threading.Event(), threading.Event()) for name in ("control", "disconnect")}

    def handle_error(self, *_):
        pass


class ModelHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.send_json({"object": "list", "data": [{"id": "cf-joint-model", "object": "model"}]})

    def send_json(self, payload, status=200):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        messages = body.get("messages", [])
        user_index = next((i for i in range(len(messages)-1, -1, -1)
                           if messages[i].get("role") == "user"), -1)
        text = str(messages[user_index].get("content", "")) if user_index >= 0 else ""
        results = [m["content"] for m in messages[user_index+1:] if m.get("role") == "tool"]
        tools = {t.get("function", {}).get("name") for t in body.get("tools", [])}
        label = next((name for name in ("alice", "bob", "error") if "joint-" in text and name in text), "auxiliary")
        with self.server.lock:
            self.server.requests.append(body)
        control_case = next((name for name in self.server.control_events if "joint-control-" + name in text), None)
        if control_case is not None and tools:
            entered, release = self.server.control_events[control_case]
            entered.set()
            assert release.wait(20), "independent control HTTP probe did not release model"
        if "joint-error" in text and results and tools:
            self.send_json({"error": {"type": "invalid_request_error", "message": "isolated model failure"}}, 400)
            return
        if "joint-attachment-lease" in text and len(results) == 1 and tools:
            # The real nonrenewable Gateway host lease is 30 seconds. Keep the
            # model connection idle; no frozen clock or synthetic end event.
            time.sleep(31)
        call = None
        if tools and ("joint-attachment" in text or "joint-error" in text):
            match = re.search(r'"attachment_id"\s*:\s*(\d+)', text)
            assert match is not None, "Gateway omitted attachment ID"
            attachment_id = int(match.group(1))
            if len(results) < 2:
                if not results and label in {"alice", "bob"}:
                    self.server.barrier.wait()
                call = (DOWNLOAD, {"attachment_id": attachment_id})
            elif len(results) == 2:
                first = json.JSONDecoder().raw_decode(results[0])[0]
                if first.get("ok"):
                    assert first.get("verified"), first
                    call = (CONSUME, {"handle": first["handle"]})
        elif tools and "joint-after" in text and not results:
            previous = [m.get("content", "") for m in messages[:user_index] if m.get("role") == "tool"]
            handles = []
            for value in previous:
                try:
                    value = json.JSONDecoder().raw_decode(value)[0]
                    if value.get("verified") is True:
                        handles.append(value["handle"])
                except (ValueError, AttributeError, TypeError):
                    pass
            assert handles, "real forked history did not retain the download handle"
            call = (CONSUME, {"handle": handles[-1]})
        if call:
            name, args = call
            if name not in tools:
                assert "tool_call" in tools, "official deferred tool bridge missing"
                name, args = "tool_call", {"calls": [{"name": name, "arguments": args}]}
            message = {"role": "assistant", "content": None, "tool_calls": [{
                "id": f"call_{label}_{len(results)}", "type": "function", "function": {
                    "name": name, "arguments": json.dumps(args)}}]}
            finish = "tool_calls"
        else:
            message = {"role": "assistant", "content": json.dumps({"joint": label, "results": results})}
            finish = "stop"
        envelope = {"id": "chatcmpl-joint", "object": "chat.completion", "created": int(time.time()),
                    "model": "cf-joint-model", "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 20, "total_tokens": 40}}
        if not body.get("stream"):
            self.send_json(envelope)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        delta = {key: value for key, value in message.items() if key != "role"}
        if "tool_calls" in delta:
            delta["tool_calls"] = [{"index": i, **v} for i, v in enumerate(delta["tool_calls"])]
        chunk = {key: value for key, value in envelope.items() if key not in {"choices", "usage"}}
        chunk["object"] = "chat.completion.chunk"
        for piece, reason in (({"role": "assistant", **delta}, None), ({}, finish)):
            chunk["choices"] = [{"index": 0, "delta": piece, "finish_reason": reason}]
            self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


def isolated_guard(sandbox, sources, worker):
    violations = []
    roots = (sandbox, *sources, HERE, Path(sys.prefix), Path(sys.base_prefix))
    metadata = {"/proc/1/cgroup", "/proc/self/mountinfo", "/proc/stat", "/proc/version",
                "/etc/os-release", "/usr/lib/os-release", "/etc/mime.types", "/etc/localtime",
                "/etc/ssl/certs/ca-certificates.crt"}
    # Pinned hermes_state_common._write_lock_holder_record and gateway.status
    # read this exact process start fingerprint; denying it aborts SessionDB's
    # real lock acquisition. No other PID, argv, environment or /proc tree is
    # allowed. It is read-only kernel metadata, not a user/runtime directory.
    metadata.add(f"/proc/{os.getpid()}/stat")
    def within(path, allowed):
        value = Path(os.path.abspath(os.fsdecode(path)))
        return any(value == root or root in value.parents for root in allowed)
    def guard(event, args):
        denied = False
        if event == "open" and not isinstance(args[0], int):
            path, _mode, flags = args
            write = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            denied = not within(path, (sandbox,) if write else roots)
            if not write and (os.fsdecode(path) in metadata or Path(os.path.abspath(path)) == worker):
                denied = False
            # Real POSIX staging/task-directory code walks ancestors with
            # O_DIRECTORY and O_NOFOLLOW; this permits handles, not file reads.
            if not write and flags & getattr(os, "O_DIRECTORY", 0):
                candidate = Path(os.path.abspath(path))
                if candidate in sandbox.parents:
                    denied = False
            if os.fsdecode(path) == os.devnull:
                denied = False
        elif event in {"socket.bind", "socket.connect"}:
            address = args[1]
            denied = not isinstance(address, tuple) or address[0] not in {"127.0.0.1", "::1"}
        elif event == "socket.getaddrinfo":
            denied = args[0] not in {"127.0.0.1", "::1", "localhost", None}
        elif event == "subprocess.Popen":
            executable, command, _cwd, _env = args
            denied = Path(executable) != worker or command != [str(worker)]
        elif event in {"os.system", "os.exec", "os.posix_spawn"}:
            denied = True
        if denied:
            detail = {"event": event}
            if event == "open":
                detail["path"] = os.fsdecode(args[0])
            violations.append(detail)
            # Paths only (never file contents, command arguments or headers)
            # make a swallowed optional import/SessionDB failure diagnosable.
            raise RuntimeError("joint test rejected operation " + json.dumps(detail))
    sys.addaudithook(guard)
    return violations


async def child(gateway, hermes, worker):
    sandbox = Path(os.environ["HERMES_HOME"]).parent
    home = sandbox / "profile"
    # Bootstrap documented stdlib OS metadata before the strict boundary.
    mimetypes.init()
    model = ModelServer()
    threading.Thread(target=model.serve_forever, daemon=True).start()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    origin = f"https://127.0.0.1:{listener.getsockname()[1]}"
    service_token, hermes_token, grant_key = (secrets.token_urlsafe(32) for _ in range(3))
    grant_key = base64.b64encode(secrets.token_bytes(32)).decode()
    _test_secrets.extend((service_token, hermes_token, grant_key))
    os.environ[SERVICE_ENV] = service_token
    os.environ["CF_JOINT_GRANT_KEY"] = grant_key
    os.environ["CF_JOINT_HERMES_KEY"] = hermes_token
    config = json.loads((home / "config.yaml").read_text())
    config["model"] = {"provider": "custom", "default": "cf-joint-model", "api_mode": "chat_completions",
        "base_url": f"http://127.0.0.1:{model.server_port}/v1", "context_length": 131072,
        "api_key": "public-isolated-model-not-a-credential"}
    config["plugins"]["entries"]["cf-filebridge"]["settings"]["inbound_host"] = {
        "gateway_origin": origin, "service_token_env": SERVICE_ENV, "profile_reference": PROFILE,
        "profile_revision": 1, "work_root": str(sandbox / "work"), "client_path": str(worker),
        "client_sha256": hashlib.sha256(worker.read_bytes()).hexdigest(),
        "ca_file": str(sandbox / "cert.pem"), "ca_sha256": hashlib.sha256((sandbox / "cert.pem").read_bytes()).hexdigest(),
        "consumer_tools": [CONSUME]}
    (home / "config.yaml").write_text(json.dumps(config))
    violations = isolated_guard(sandbox, (gateway, hermes), worker)
    sys.path[:0] = [str(hermes), str(gateway / "src")]
    import uvicorn
    from aiohttp import ClientSession, ClientTimeout, TCPConnector
    from sqlalchemy import select
    from cf_agent_gateway.config import Settings, DatabaseSettings, InboundMediaSettings, WorkerSettings, HermesSettings, LoggingSettings
    from cf_agent_gateway.gateway.app import create_app
    from cf_agent_gateway.access import AccessPolicyService, RiskLevel
    from cf_agent_gateway.identity.service import IdentityService
    from cf_agent_gateway.adapters.wechat import NormalizedWechatMessage
    from cf_agent_gateway.adapters.wechat.inbound_media import parse_inbound_media
    from cf_agent_gateway.adapters.wechat.inbound_media_http import BoundMediaResult
    from cf_agent_gateway.adapters.wechat.inbound_media_staging import InboundMediaStaging
    from cf_agent_gateway.inbound.worker import InboundMediaWorker
    from cf_agent_gateway.inbound.models import InboundMediaJob
    from cf_agent_gateway.inbound.host_binding_config import HostBindingSettings
    from cf_agent_gateway.inbound.host_binding_models import InboundHostBinding
    from cf_agent_gateway.ingestion import MessageAdmissionService
    from cf_agent_gateway.hermes import HermesClient
    from cf_agent_gateway.runtime.dispatch_worker import build_dispatch_worker
    from cf_agent_gateway.task.model import HermesDispatchStatus
    from cf_agent_gateway.workspace.models import AIThread
    from hermes_cli.plugins import discover_plugins, get_plugin_manager
    from gateway.config import PlatformConfig
    from gateway.platforms.api_server import APIServerAdapter

    # Fail explicitly at the real public DB boundary instead of allowing the
    # API's optional lazy-open catch to hide a missing dependency/guard denial.
    from hermes_state import SessionDB
    preflight_database = SessionDB(db_path=sandbox / "preflight-state.db")
    preflight_database.close()

    discover_plugins()
    manager = get_plugin_manager()
    for name in ("cf-filebridge", "cf-a-joint-observer"):
        plugin = manager._plugins.get(name)
        assert plugin and plugin.enabled and plugin.error is None, name
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={
        "host": "127.0.0.1", "port": 0, "key": hermes_token, "model_name": "cf-joint-model"}))
    server = None
    serving = None
    hermes_client = None
    try:
        assert await adapter.connect()
        hermes_origin = f"http://127.0.0.1:{adapter._site._server.sockets[0].getsockname()[1]}"
        settings = Settings(database=DatabaseSettings(f"sqlite:///{(sandbox / 'gateway.db').as_posix()}"),
            logging=LoggingSettings("WARNING"),
            inbound_media=InboundMediaSettings(enabled=True, staging_root=str(sandbox / "staging"), public_base_url=origin),
            host_binding=HostBindingSettings(enabled=True, dedicated_endpoint_confirmed=True,
                host_id="joint-isolated-host", profile_reference=PROFILE, profile_revision=1,
                service_token_env=SERVICE_ENV, encryption_key_env="CF_JOINT_GRANT_KEY",
                runtime_model="cf-joint-model", runtime_provider="custom", legacy_runtime_confirmed=True),
            worker=WorkerSettings(enabled=True, concurrency=2, lease_seconds=60, retry_limit=0),
            hermes=HermesSettings(enabled=True, base_url=hermes_origin, api_key_env="CF_JOINT_HERMES_KEY", model="cf-joint-model"))
        app = create_app(settings)
        gateway_requests = []
        paused_content = {}
        delay_closed_requests = [False]
        release_closed = asyncio.Event()
        blocked_closed_count = [0]
        async def observe_gateway(scope, receive, send):
            # Passive ASGI observer: preserve the actual app/auth/routes/body
            # unchanged, and never retain headers, queries or capability values.
            if scope.get("path", "").endswith("/closed") and delay_closed_requests[0]:
                # Network fixture delays delivery *before* the unmodified app;
                # the client times out and the real lease barrier must expire.
                # Releasing later still delegates to the actual authenticated
                # route rather than manufacturing an acknowledgement.
                blocked_closed_count[0] += 1
                await release_closed.wait()
            async def observed_send(message):
                if scope["type"] == "http" and message["type"] == "http.response.start":
                    gateway_requests.append((scope["method"], scope["path"], message["status"]))
                if scope.get("path", "").endswith("/resolve") and message["type"] == "http.response.body":
                    # Remember only for negative leakage assertions; never log,
                    # return or persist this real per-attachment capability.
                    payload = json.loads(message.get("body", b"{}"))
                    for descriptor in payload.get("attachments", []):
                        authorization = descriptor.get("authorization", "")
                        if authorization:
                            _test_secrets.extend((authorization, authorization.removeprefix("Bearer ")))
                pause = paused_content.get(scope.get("path"))
                if pause is not None and message["type"] == "http.response.body":
                    # A wire-level delayed response after the real route has
                    # checked auth and read the real staging file. No route or
                    # authorization decision is replaced by this fault fixture.
                    pause[0].set()
                    await pause[1].wait()
                await send(message)
            await app(scope, receive, observed_send)
        server = uvicorn.Server(uvicorn.Config(observe_gateway, log_level="warning", access_log=False, loop="asyncio",
            ssl_certfile=str(sandbox / "cert.pem"), ssl_keyfile=str(sandbox / "key.pem")))
        serving = asyncio.create_task(server.serve(sockets=[listener]))
        async with asyncio.timeout(20):
            while not server.started:
                if serving.done():
                    await serving
                    raise AssertionError("Gateway failed to start")
                await asyncio.sleep(0.02)
        sessions = app.state.database_session_factory
        with sessions() as session:
            for name in ("alice", "bob", "error", "retry", "exhaust", "lease", "cancel", "lostclosed", "control", "disconnect"):
                identity_service = IdentityService(session)
                identity = identity_service.create_identity(employee_id="joint-" + name)
                identity_service.create_mapping(platform="wechat", account_id="wxid-joint-gateway",
                    sender_id="wxid-" + name, enterprise_identity_id=identity.id)
                AccessPolicyService(session).upsert_user_policy(enterprise_identity_id=identity.id, enabled=True)
            AccessPolicyService(session).upsert_gateway_policy(enabled=True, allowed_risk_levels={RiskLevel.NORMAL})
        sequence = 0
        def admit(name, stage, media=False):
            nonlocal sequence
            sequence += 1
            message = NormalizedWechatMessage.model_validate({"source_account_id": "wxid-joint-gateway",
                "source_message_id": str(sequence), "source_local_id": str(sequence), "source_server_id": str(sequence),
                "source_message_id_is_fallback": False, "event_id": "joint:" + str(sequence),
                "conversation_id": "wxid-" + name, "conversation_type": "private", "conversation_name": name,
                "sender_type": "human", "sender_id": "wxid-" + name, "sender_name": name,
                "message_type": ("image" if name == "bob" else "file") if media else "text",
                "raw_type": (3 if name == "bob" else 49) if media else 1,
                "content": "joint-" + stage + "-" + name, "timestamp": datetime.now(timezone.utc),
                "is_mentioned": None, "is_self": False, "reply": None})
            with sessions() as session:
                return MessageAdmissionService(session, inbound_media=settings.inbound_media).process(message)
        class WechatFetchStub:
            def fetch(self, source):
                jpeg = source.raw_type == 3
                data = (HERE / "fixtures" / ("sample.jpg" if jpeg else "sample.pdf")).read_bytes()
                return BoundMediaResult(source.fingerprint, parse_inbound_media({"type": "image" if jpeg else "file",
                    "filename": "joint.jpg" if jpeg else "joint.pdf", "data": base64.b64encode(data).decode()}))
        intake = InboundMediaWorker(sessions, WechatFetchStub(), InboundMediaStaging(sandbox / "staging"))
        hermes_client = HermesClient(hermes_origin, hermes_token, "cf-joint-model")
        dispatcher = build_dispatch_worker(settings, session_factory=sessions, hermes_client=hermes_client, sender_factory=None)
        async def execute_pair():
            claims = [dispatcher.claim_once(), dispatcher.claim_once()]
            assert all(claims) and claims[0].ai_thread_id != claims[1].ai_thread_id
            assert dispatcher.claim_once() is None, "active thread FIFO allowed another claim"
            results = await asyncio.gather(*(asyncio.to_thread(dispatcher.process_claim, claim) for claim in claims))
            assert all(result.status is HermesDispatchStatus.SUCCESS for result in results), [
                {"status": result.status.value, "error": result.error_code} for result in results]
            return claims
        before = [admit(name, "before") for name in ("alice", "bob")]
        await execute_pair()
        with sessions() as session:
            parents = {item.ai_thread_id: session.get(AIThread, item.ai_thread_id).hermes_thread_id for item in before}
        media = [admit(name, "attachment", True) for name in ("alice", "bob")]
        for _ in media:
            assert await asyncio.to_thread(intake.run_once) == "ready"
        await execute_pair()
        with sessions() as session:
            bindings = list(session.scalars(select(InboundHostBinding)))
            assert len(bindings) == 2
            for binding in bindings:
                assert binding.parent_session_id == parents[binding.ai_thread_id]
                assert binding.session_id != binding.parent_session_id
                assert binding.history_digest and binding.runtime_config_digest
                assert binding.closed_at is not None and binding.grant_ciphertext is None
                assert binding.host_instance_id and binding.host_nonce_hash
                assert binding.task_id == binding.session_id
                assert session.get(AIThread, binding.ai_thread_id).hermes_thread_id == binding.session_id
            child_sessions = {binding.session_id for binding in bindings}
        events_path = Path(os.environ["CF_JOINT_EVENTS"])
        events = [json.loads(line) for line in events_path.read_text().splitlines()]
        downloads = [event for event in events if event["kind"] == "tool" and event["tool"] == DOWNLOAD]
        consumers = [event for event in events if event["kind"] == "tool" and event["tool"] == CONSUME]
        assert len(downloads) == 4 and len(consumers) == 2, events
        for session_id in child_sessions:
            copies = [event["result"] for event in downloads if event["session_id"] == session_id]
            assert len(copies) == 2 and copies[0] == copies[1], copies
            assert copies[0]["ok"] and copies[0]["verified"] is True and copies[0]["formal_archive"] is False
            assert copies[0]["original_comparison"] == "not_checked"
            consumed = [event["result"] for event in consumers if event["session_id"] == session_id]
            assert len(consumed) == 1 and consumed[0]["actual_stream_read"] is True
            assert consumed[0]["sha256"] == copies[0]["sha256"] and consumed[0]["bytes"] == copies[0]["bytes_written"]
        assert len({event["result"]["handle"] for event in downloads}) == 2
        files = list((sandbox / "work").glob("*/work-*"))
        assert len(files) == 2 and all(path.is_file() for path in files)
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in files)
        expected = {hashlib.sha256((HERE / "fixtures" / name).read_bytes()).hexdigest() for name in ("sample.pdf", "sample.jpg")}
        assert {hashlib.sha256(path.read_bytes()).hexdigest() for path in files} == expected
        content_reads = [item for item in gateway_requests if re.fullmatch(r"/inbound-media/\d+/content", item[1])]
        assert len(content_reads) == 2 and all(item[2] == 200 for item in content_reads), content_reads
        assert sum(path.endswith("/resolve") and status == 200 for _method, path, status in gateway_requests) == 2
        assert sum(path.endswith("/events") and status == 200 for _method, path, status in gateway_requests) == 2
        assert sum(path.endswith("/closed") and status == 200 for _method, path, status in gateway_requests) == 2
        for name in ("alice", "bob"):
            admit(name, "after")
        await execute_pair()
        events = [json.loads(line) for line in events_path.read_text().splitlines()]
        rejected = [event for event in events if event["kind"] == "tool" and event["tool"] == CONSUME
                    and event["result"].get("ok") is False]
        assert len(rejected) == 2, events
        assert len([item for item in gateway_requests if item[1].endswith("/resolve")]) == 2, "ended handle replay attempted to acquire new authority"
        # A real HTTP-200 model failure has no upstream end hook. The actual
        # Gateway worker must revoke via SSE and wait for host closed instead.
        failure = admit("error", "error", True)
        assert await asyncio.to_thread(intake.run_once) == "ready"
        failed_claim = dispatcher.claim_once()
        assert failed_claim and failed_claim.record_id == failure.dispatch_record_id
        failed_result = await asyncio.to_thread(dispatcher.process_claim, failed_claim)
        assert failed_result.status is HermesDispatchStatus.UNCERTAIN, failed_result.status.value
        with sessions() as session:
            failed_binding = session.scalar(select(InboundHostBinding).where(InboundHostBinding.dispatch_id == failed_claim.record_id))
            assert failed_binding.closed_at is not None and failed_binding.grant_ciphertext is None
            assert session.get(InboundMediaJob, failed_binding.job_id).read_token_hash is None
            failed_session = failed_binding.session_id
        events = [json.loads(line) for line in events_path.read_text().splitlines()]
        assert not any(event["kind"] == "end" and event["session_id"] == failed_session for event in events)
        assert any(event["kind"] == "tool" and event["session_id"] == failed_session
                   and event["result"].get("verified") is True for event in events)
        def job_for(outcome):
            with sessions() as session:
                return session.scalar(select(InboundMediaJob).where(InboundMediaJob.message_id == outcome.message_id))
        def binding_for(claim):
            with sessions() as session:
                return session.scalar(select(InboundHostBinding).where(InboundHostBinding.dispatch_id == claim.record_id))
        def tool_events(session_id, name=DOWNLOAD):
            entries = [json.loads(line) for line in events_path.read_text().splitlines()]
            return [entry["result"] for entry in entries if entry["kind"] == "tool"
                    and entry["tool"] == name and entry["session_id"] == session_id]
        async def wait_until(predicate, seconds=8):
            async with asyncio.timeout(seconds):
                while not predicate():
                    await asyncio.sleep(0.02)
        # Real storage contention, not HTTP status fabrication: Gateway's own
        # flock failure is classified as retryable 503 with Retry-After: 1.
        import fcntl
        retry_counts = {}
        for scenario in ("retry", "exhaust"):
            item = admit(scenario, "attachment", True)
            assert await asyncio.to_thread(intake.run_once) == "ready"
            job = job_for(item)
            path = f"/inbound-media/{job.id}/content"
            fd = os.open(sandbox / "staging", os.O_RDONLY | os.O_DIRECTORY)
            fcntl.flock(fd, fcntl.LOCK_EX)
            claim = dispatcher.claim_once()
            pending = asyncio.create_task(asyncio.to_thread(dispatcher.process_claim, claim))
            try:
                await wait_until(lambda: any(p == path and status == 503 for _method, p, status in gateway_requests))
                if scenario == "retry":
                    fcntl.flock(fd, fcntl.LOCK_UN)
                result = await asyncio.wait_for(pending, 35)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
            observed = [status for _method, p, status in gateway_requests if p == path]
            binding = binding_for(claim)
            calls = tool_events(binding.session_id)
            assert len(calls) == 2 and calls[0] == calls[1], calls
            if scenario == "retry":
                assert observed == [503, 200] and calls[0].get("verified") is True, observed
                assert tool_events(binding.session_id, CONSUME)[0].get("actual_stream_read") is True
                assert result.status is HermesDispatchStatus.SUCCESS
            else:
                assert observed == [503] * 4 and calls[0].get("ok") is False, observed
                assert not tool_events(binding.session_id, CONSUME)
            assert binding.closed_at is not None and binding.grant_ciphertext is None
            retry_counts[scenario] = len(observed)
        # Revocation while a genuine authorized HTTPS body is still withheld.
        # Use the production cancellation transition in the real Gateway DB.
        from cf_agent_gateway.inbound.host_binding import revoke_dispatch
        item = admit("cancel", "attachment", True)
        assert await asyncio.to_thread(intake.run_once) == "ready"
        cancel_job = job_for(item)
        cancel_path = f"/inbound-media/{cancel_job.id}/content"
        started, release = asyncio.Event(), asyncio.Event()
        paused_content[cancel_path] = (started, release)
        cancel_claim = dispatcher.claim_once()
        before_cancel_files = set((sandbox / "work").glob("*/work-*"))
        pending = asyncio.create_task(asyncio.to_thread(dispatcher.process_claim, cancel_claim))
        try:
            await asyncio.wait_for(started.wait(), 12)
            def cancel_real_claim():
                with sessions() as session:
                    revoke_dispatch(session, cancel_claim.record_id, "joint_cancel", claim_token=cancel_claim.claim_token)
                    session.commit()
            await asyncio.to_thread(cancel_real_claim)
            await wait_until(lambda: binding_for(cancel_claim).closed_at is not None)
            cancel_binding = binding_for(cancel_claim)
            assert all(result.get("ok") is False for result in tool_events(cancel_binding.session_id))
        finally:
            release.set()
        await asyncio.wait_for(pending, 15)
        assert tool_events(cancel_binding.session_id) and not tool_events(cancel_binding.session_id, CONSUME)
        assert set((sandbox / "work").glob("*/work-*")) == before_cancel_files, "cancelled download published a working copy"
        # Idle expiry must kill the native worker even without a next tool call
        # or an upstream end hook. The next actual tool call may not refresh it.
        item = admit("lease", "attachment", True)
        assert await asyncio.to_thread(intake.run_once) == "ready"
        lease_claim = dispatcher.claim_once()
        await asyncio.wait_for(asyncio.to_thread(dispatcher.process_claim, lease_claim), 50)
        lease_binding = binding_for(lease_claim)
        lease_calls = tool_events(lease_binding.session_id)
        assert lease_calls[0].get("verified") is True and lease_calls[1].get("ok") is False, lease_calls
        assert all(result.get("ok") is False for result in tool_events(lease_binding.session_id, CONSUME))
        assert lease_binding.closed_at is not None and lease_binding.grant_ciphertext is None
        assert sum(p == f"/inbound-media/{job_for(item).id}/content" for _method, p, _status in gateway_requests) == 1
        # Lose delivery of a real /closed request. Local worker/stream shutdown
        # must precede that acknowledgement, and Gateway's actual fixed lease
        # must unblock completion without a reconnect or refreshed budget.
        item = admit("lostclosed", "attachment", True)
        assert await asyncio.to_thread(intake.run_once) == "ready"
        closed_claim = dispatcher.claim_once()
        observer = manager._plugins["cf-a-joint-observer"].module
        os.environ["CF_JOINT_RETAIN_STREAM"] = "1"
        delay_closed_requests[0] = True
        began = time.monotonic()
        try:
            await asyncio.wait_for(asyncio.to_thread(dispatcher.process_claim, closed_claim), 42)
            closed_elapsed = time.monotonic() - began
            lost_binding = binding_for(closed_claim)
            assert blocked_closed_count[0] == 1, "host retried an uncertain closed request"
            assert lost_binding.closed_at is None and lost_binding.grant_ciphertext is None
            assert 25 <= closed_elapsed < 42, closed_elapsed
            assert observer.retained_streams and all(stream.closed for _context, stream in observer.retained_streams)
            assert observer.native_processes and all(process.poll() is not None for process in observer.native_processes)
        finally:
            delay_closed_requests[0] = False
            release_closed.set()
            os.environ.pop("CF_JOINT_RETAIN_STREAM", None)
            for context, _stream in observer.retained_streams:
                context.__exit__(None, None, None)
        # These are independent authenticated control-protocol negative probes,
        # not successful downloads or fabricated plugin bindings. A genuine
        # Gateway worker prebinds each child and waits inside the real model
        # request while this explicit synthetic host exercises the HTTP fences.
        tls = ssl.create_default_context(cafile=str(sandbox / "cert.pem"))
        direct_control_cases = []
        async with ClientSession(connector=TCPConnector(ssl=tls), timeout=ClientTimeout(total=8)) as client:
            for scenario in ("control", "disconnect"):
                item = admit(scenario, "control", True)
                assert await asyncio.to_thread(intake.run_once) == "ready"
                claim = dispatcher.claim_once()
                pending = asyncio.create_task(asyncio.to_thread(dispatcher.process_claim, claim))
                entered, release = model.control_events[scenario]
                assert await asyncio.to_thread(entered.wait, 10), "real model did not receive prebound request"
                binding = binding_for(claim)
                body = {"schema": "cf-inbound-host-binding/v1", "session_id": binding.session_id,
                    "task_id": binding.session_id, "host_instance_id": "joint-direct-" + scenario,
                    "host_nonce": secrets.token_urlsafe(32)}
                headers = {"Authorization": "Bearer " + service_token}
                try:
                    async with client.post(origin + "/internal/hermes/inbound-bindings/resolve", json=body, headers=headers) as response:
                        assert response.status == 200
                        resolved = await response.json()
                    descriptor = resolved["attachments"][0]
                    authorization = descriptor["authorization"]
                    _test_secrets.extend((authorization, authorization.removeprefix("Bearer "), body["host_nonce"]))
                    # Successful resolve alone cannot authorize byte delivery.
                    async with client.get(descriptor["url"], headers={"Authorization": authorization}) as response:
                        assert response.status == 403
                    for changed in ({**body, "host_instance_id": "old-instance"},
                                    {**body, "host_nonce": "old_nonce_" + "x" * 32}):
                        async with client.post(origin + "/internal/hermes/inbound-bindings/resolve", json=changed, headers=headers) as response:
                            assert response.status == 403
                    owner = {**body, "claim_epoch": resolved["claim_epoch"]}
                    event_headers = {**headers, "X-CF-Session-Id": body["session_id"], "X-CF-Task-Id": body["task_id"],
                        "X-CF-Host-Instance-Id": body["host_instance_id"], "X-CF-Host-Nonce": body["host_nonce"],
                        "X-CF-Claim-Epoch": resolved["claim_epoch"]}
                    endpoint = origin + "/internal/hermes/inbound-bindings/" + resolved["binding_id"]
                    async with client.get(endpoint + "/events", headers={**event_headers,
                            "X-CF-Claim-Epoch": "00000000-0000-0000-0000-000000000000"}) as response:
                        assert response.status == 403
                    if scenario == "control":
                        async with client.get(endpoint + "/events", headers={**event_headers,
                                "Last-Event-ID": str(resolved["event_sequence"] + 1)}) as response:
                            assert response.status == 403
                    else:
                        async with client.get(endpoint + "/events", headers=event_headers) as response:
                            assert response.status == 200
                            frame = await response.content.readuntil(b"\n\n")
                            assert b"event: binding" in frame
                            response.close()
                    await wait_until(lambda: binding_for(claim).state == "revoked")
                    async with client.get(descriptor["url"], headers={"Authorization": authorization}) as response:
                        assert response.status == 403
                    # This synthetic host has never activated a worker or opened
                    # a file; its authenticated explicit close is truthful.
                    async with client.post(endpoint + "/closed", json=owner, headers=headers) as response:
                        assert response.status == 200
                    for changed in ({**owner, "host_nonce": "old_nonce_" + "x" * 32},
                                    {**owner, "claim_epoch": "00000000-0000-0000-0000-000000000000"}):
                        async with client.post(endpoint + "/closed", json=changed, headers=headers) as response:
                            assert response.status == 403
                    direct_control_cases.append(scenario)
                finally:
                    release.set()
                await asyncio.wait_for(pending, 12)
        # Real Gateway authentication and replay denial; no route overrides.
        tls = ssl.create_default_context(cafile=str(sandbox / "cert.pem"))
        async with ClientSession(connector=TCPConnector(ssl=tls), timeout=ClientTimeout(total=5)) as client:
            body = {"schema": "cf-inbound-host-binding/v1", "session_id": failed_session,
                "task_id": failed_session, "host_instance_id": "joint-unauthorized", "host_nonce": "x" * 32}
            for token in (None, "wrong-public-test-value", service_token):
                headers = {} if token is None else {"Authorization": "Bearer " + token}
                async with client.post(origin + "/internal/hermes/inbound-bindings/resolve", json=body, headers=headers) as response:
                    assert response.status == 403
        # Only ciphertext is allowed in the Gateway DB; ordinary Hermes profile,
        # model traffic, tool outputs and logs must contain none of these secrets.
        materials = [json.dumps(model.requests).encode(), events_path.read_bytes()]
        materials += [path.read_bytes() for path in home.rglob("*") if path.is_file()]
        for secret in _test_secrets:
            assert all(secret.encode() not in material for material in materials), "credential leaked into model/profile/output"
        assert "Bearer " not in json.dumps(model.requests)
        assert violations == [], "unexpected isolated-operation attempt"
        print(json.dumps({"ok": True, "gateway_commit": GATEWAY_COMMIT,
            "hermes_commit": verify_sources(gateway, hermes), "real_gateway_database_claim_prebinding": True,
            "real_gateway_https_auth_resolve_events_closed": True, "real_hermes_http_agent_loader": True,
            "real_native_downloader": True, "authenticated_request_binding": True,
            "parallel_pdf_jpeg_verified_consumed": 2, "repeated_tools_shared_workcopy": True,
            "gateway_content_gets_for_four_tools": len(content_reads),
            "text_attachment_text_history_and_fifo": True, "expired_handle_replays_rejected": 2,
            "model_failure_without_end_hook_revoked_by_gateway": True,
            "real_staging_503_attempt_counts": retry_counts,
            "cancel_during_https_body_no_workcopy": True,
            "real_30_second_idle_lease_no_budget_refresh": True,
            "lost_closed_request_local_resources_revoked_before_real_lease_barrier": True,
            "lost_closed_request_elapsed_seconds": round(closed_elapsed, 2),
            "independent_real_control_negative_probes": direct_control_cases,
            "stubs": ["loopback model HTTP", "upstream WeChat fetch"],
            "production_host_acceptance": False, "isolation_audit_violations": len(violations)}))
    finally:
        if hermes_client:
            hermes_client.close()
        await adapter.disconnect()
        manager.unload()
        if server:
            server.should_exit = True
        if serving:
            await asyncio.wait_for(serving, 10)
        listener.close()
        model.shutdown()
        model.server_close()


def run(gateway, hermes, worker):
    if sys.platform != "linux":
        raise RuntimeError("Real Gateway staging requires Linux; run this explicit joint gate on Linux CI")
    with tempfile.TemporaryDirectory(prefix="cf-gateway-hermes-joint-") as temporary:
        sandbox = Path(temporary).resolve()
        home = sandbox / "profile"
        shutil.copytree(PLUGIN, home / "plugins" / "cf-filebridge", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        observer = home / "plugins" / "cf-a-joint-observer"
        observer.mkdir()
        (observer / "plugin.yaml").write_text('name: cf-a-joint-observer\nversion: "1.0.0"\nkind: standalone\n')
        (observer / "__init__.py").write_text(OBSERVER)
        for name in ("work", "staging", "empty-bundled", "temp", "user"):
            (sandbox / name).mkdir(mode=0o700)
        for name in ("cert.pem", "key.pem"):
            shutil.copyfile(HERE / "fixtures" / name, sandbox / name)
        config = {"plugins": {"enabled": ["cf-filebridge", "cf-a-joint-observer"], "entries": {
            "cf-filebridge": {"settings": {"inbound_enabled": True, "inbound_host_enabled": True}}}},
            "platform_toolsets": {"api_server": ["cf_filebridge_inbound", "cf_joint_probe"]},
            "agent": {"max_iterations": 6}, "memory": {"enabled": False}, "skills": {"enabled": False},
            "compression": {"enabled": False}}
        (home / "config.yaml").write_text(json.dumps(config))
        env = {key: value for key, value in os.environ.items() if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR"}}
        env.update({"HOME": str(sandbox / "user"), "USERPROFILE": str(sandbox / "user"),
            "APPDATA": str(sandbox / "user"), "LOCALAPPDATA": str(sandbox / "user"),
            "HERMES_HOME": str(home), "HERMES_BUNDLED_PLUGINS": str(sandbox / "empty-bundled"),
            "HERMES_ENABLE_PROJECT_PLUGINS": "false", "CF_JOINT_EVENTS": str(sandbox / "events.jsonl"),
            "HERMES_TEST_ISOLATION": "1",
            "TEMP": str(sandbox / "temp"), "TMP": str(sandbox / "temp"), "TMPDIR": str(sandbox / "temp"),
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"})
        completed = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()),
            "--gateway-source", str(gateway), "--hermes-source", str(hermes), "--worker", str(worker), "--child"],
            cwd=sandbox, env=env, capture_output=True, text=True, encoding="utf-8", timeout=240)
        if completed.returncode:
            # All credentials are generated inside child memory/environment;
            # upstream error representations must not accidentally expose them.
            print(completed.stdout, end="")
            print(completed.stderr, end="", file=sys.stderr)
            raise SystemExit(completed.returncode)
        report = json.loads(completed.stdout.strip().splitlines()[-1])
        assert report["ok"] is True
        print(json.dumps(report))


def run_child_sanitized(gateway, hermes, worker):
    output, errors = io.StringIO(), io.StringIO()
    failed = False
    with redirect_stdout(output), redirect_stderr(errors):
        try:
            asyncio.run(child(gateway, hermes, worker))
        except BaseException:
            failed = True
            traceback.print_exc()
    stdout, stderr = output.getvalue(), errors.getvalue()
    # Upstream diagnostics must not expose even synthetic per-run credentials.
    # A leak is a hard failure, and the raw diagnostic is never printed.
    if any(secret in stdout or secret in stderr for secret in _test_secrets):
        print("joint child emitted a protected credential; diagnostic withheld", file=sys.stderr)
        raise SystemExit(1)
    if failed:
        print(stdout, end="")
        print(stderr, end="", file=sys.stderr)
        raise SystemExit(1)
    report = json.loads(stdout.strip().splitlines()[-1])
    assert report["ok"] is True
    print(json.dumps(report))


def verify_isolated(gateway, hermes, *, session_probe=False):
    with tempfile.TemporaryDirectory(prefix="cf-joint-verify-") as temporary:
        root = Path(temporary).resolve()
        for name in ("profile", "user", "empty-bundled", "temp"):
            (root / name).mkdir(mode=0o700)
        (root / "profile/config.yaml").write_text(json.dumps({"plugins": {"enabled": []},
            "memory": {"enabled": False}, "skills": {"enabled": False}, "compression": {"enabled": False}}))
        env = {key: value for key, value in os.environ.items() if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR"}}
        env.update({"HERMES_HOME": str(root / "profile"), "HOME": str(root / "user"),
            "USERPROFILE": str(root / "user"), "APPDATA": str(root / "user"), "LOCALAPPDATA": str(root / "user"),
            "HERMES_BUNDLED_PLUGINS": str(root / "empty-bundled"), "HERMES_ENABLE_PROJECT_PLUGINS": "false",
            "HERMES_TEST_ISOLATION": "1", "TEMP": str(root / "temp"), "TMP": str(root / "temp"),
            "TMPDIR": str(root / "temp"), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"})
        command = [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--gateway-source", str(gateway),
                   "--hermes-source", str(hermes), "--verify-import-child"]
        if session_probe:
            command.append("--session-probe")
        completed = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, encoding="utf-8", timeout=45)
        print(completed.stdout, end="")
        print(completed.stderr, end="", file=sys.stderr)
        if completed.returncode:
            raise SystemExit(completed.returncode)


def verify_import_child(gateway, hermes, *, session_probe=False):
    root = Path(os.environ["HERMES_HOME"]).parent
    platform.system()
    mimetypes.init()
    violations = isolated_guard(root, (gateway, hermes), root / "no-permitted-worker")
    sys.path[:0] = [str(hermes), str(gateway / "src")]
    from cf_agent_gateway.gateway.app import create_app
    from cf_agent_gateway.runtime.dispatch_worker import build_dispatch_worker
    if session_probe:
        from hermes_state import SessionDB
        # Public constructor in a wholly separate disposable DB. No injected
        # adapter DB/cache or monkeypatch of the official lazy session path.
        database = SessionDB(db_path=root / "probe-state.db")
        database.close()
    assert violations == [], violations
    print(json.dumps({"source_verified": True, "dependency_imports": True, "gateway_commit": GATEWAY_COMMIT,
        "hermes_commit": verify_sources(gateway, hermes), "isolation_audit_violations": len(violations),
        "public_session_db_constructed": session_probe, "joint_execution_performed": False}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-source", required=True, type=Path)
    parser.add_argument("--gateway-archive", type=Path, help="Optional additional exact codeload ZIP SHA-256 verification")
    parser.add_argument("--hermes-source", required=True, type=Path)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--verify-only", action="store_true", help="Verify immutable source/dependency imports only; does not claim integration pass")
    parser.add_argument("--session-probe", action="store_true", help="Also construct/close the official public SessionDB in an isolated temporary directory")
    parser.add_argument("--verify-import-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    gateway = args.gateway_source.resolve(strict=True)
    hermes = args.hermes_source.resolve(strict=True)
    hermes_commit = verify_sources(gateway, hermes, args.gateway_archive)
    if args.verify_import_child:
        verify_import_child(gateway, hermes, session_probe=args.session_probe)
    elif args.verify_only:
        verify_isolated(gateway, hermes, session_probe=args.session_probe)
    else:
        if not args.worker:
            parser.error("--worker is required for the actual integration gate")
        worker = args.worker.resolve(strict=True)
        if args.child:
            run_child_sanitized(gateway, hermes, worker)
        else:
            run(gateway, hermes, worker)
