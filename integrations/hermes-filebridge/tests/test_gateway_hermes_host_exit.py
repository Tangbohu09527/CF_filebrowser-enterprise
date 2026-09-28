"""Linux integration: abruptly exit an actual Hermes host, then join its worker.

Gateway DB/claims/HTTPS, official Hermes API/agent/plugins and the native worker
are real. Only the loopback model and upstream WeChat byte fetch are test doubles.
No HostBridge binding or lifecycle signal is manually constructed or injected.
Run explicitly with the pinned source snapshots and disposable joint-test venv.

Preparation audit (2026-09-28): the first local --verify-only used the disposable
venv and fixed snapshots but inherited HOME/HERMES_HOME before importing the
official API. That check is NOT isolation evidence; no active installation was
inspected to reconstruct its effects. The corrected --verify-only creates a
fresh HOME/Profile, strips inherited credentials and installs the audit guard
before any Gateway or Hermes import. Its successful rerun is recorded separately
from an actual Linux host-exit run, which cannot run on this Windows workstation.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import ctypes
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cf_joint_exit_helpers", HERE / "test_gateway_hermes_joint.py")
joint = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = joint
spec.loader.exec_module(joint)
SERVICE_ENV = "CF_FILEBRIDGE_HOST_EXIT_SERVICE"
HERMES_ENV = "CF_EXIT_HERMES_KEY"
KEY_ENV = "CF_EXIT_GRANT_KEY"


class _AuditDetails(list):
    """Only our guard's safe code/path diagnostics may enter failure JSON."""


# This observer registers a real downstream tool. Inspecting the already-created
# worker PID is test instrumentation only; it never issues authority or starts a
# worker. Holding this real stream prevents a normal end hook before SIGKILL.
OBSERVER = '''import hashlib, importlib, json, os, pathlib, sys, threading
def consume(args, **_context):
    from hermes_cli.plugins import get_plugin_manager
    module = get_plugin_manager()._plugins["cf-filebridge"].module
    host = importlib.import_module(module.__name__ + ".inbound_host")
    with host.open_workcopy(args["handle"]) as stream:
        data = stream.read()
        adapter, scope = host._active_host.get()
        dispatch = adapter.bridge._dispatches[scope.resolved.worker_binding["dispatch_id"]]
        receipt = {"host_pid": os.getpid(), "worker_pid": dispatch.process.pid,
            "bytes_read": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "stream_open": not stream.closed, "worker_alive": dispatch.process.poll() is None,
            "host_audit_violations_before_kill": len(sys.modules["__main__"]._host_guard_violations),
            "host_audit_details": list(sys.modules["__main__"]._host_guard_violations)}
        path = pathlib.Path(os.environ["CF_EXIT_STREAM_RECEIPT"])
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(receipt), encoding="utf-8")
        temporary.replace(path)
        threading.Event().wait(60)
    return json.dumps({"ok": False, "error": {"code": "host_exit_probe_timed_out"}})
def register(ctx):
    ctx.register_tool("probe_consume_workcopy", "cf_joint_probe", {
        "name": "probe_consume_workcopy", "description": "Isolated host-exit workcopy consumer",
        "parameters": {"type": "object", "required": ["handle"], "additionalProperties": False,
                       "properties": {"handle": {"type": "string"}}}}, consume)
'''


def _utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


async def _until(predicate, seconds=10):
    async with asyncio.timeout(seconds):
        while not predicate():
            await asyncio.sleep(0.025)


def _subreaper():
    # Test-process-local Linux setting, requiring no elevation. Orphaned native
    # children are reparented here so waitpid proves this exact child exited;
    # no PID-name search, process-group kill or possibly reused PID is involved.
    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise RuntimeError("Cannot configure isolated child reaping")


async def host_child(gateway, hermes, worker):
    global _host_guard_violations
    sandbox = Path(os.environ["HERMES_HOME"]).parent
    joint.bootstrap_system_metadata()
    _host_guard_violations = joint.isolated_guard(sandbox, (gateway, hermes), worker)
    sys.path.insert(0, str(hermes))
    from hermes_cli.plugins import discover_plugins, get_plugin_manager
    from gateway.config import PlatformConfig
    from gateway.platforms.api_server import APIServerAdapter
    discover_plugins()
    manager = get_plugin_manager()
    for name in ("cf-filebridge", "cf-a-exit-observer"):
        loaded = manager._plugins.get(name)
        assert loaded and loaded.enabled and loaded.error is None
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={
        "host": "127.0.0.1", "port": 0, "key": os.environ[HERMES_ENV], "model_name": "cf-hermes-api"}))
    try:
        assert await adapter.connect()
        port = adapter._site._server.sockets[0].getsockname()[1]
        ready = sandbox / "host-ready.json"
        temporary = ready.with_suffix(".tmp")
        assert _host_guard_violations == [], _AuditDetails(_host_guard_violations)
        temporary.write_text(json.dumps({"pid": os.getpid(), "origin": f"http://127.0.0.1:{port}"}))
        temporary.replace(ready)
        await asyncio.Event().wait()
    finally:
        await adapter.disconnect()
        manager.unload()


async def orchestrate(gateway, hermes, worker):
    sandbox = Path(os.environ["HERMES_HOME"]).parent
    home = sandbox / "profile"
    _subreaper()
    joint.bootstrap_system_metadata()
    model = joint.ModelServer()
    threading.Thread(target=model.serve_forever, daemon=True).start()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    origin = f"https://127.0.0.1:{listener.getsockname()[1]}"
    service_token, hermes_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    grant_key = base64.b64encode(secrets.token_bytes(32)).decode()
    test_secrets = [service_token, hermes_token, grant_key]
    os.environ.update({SERVICE_ENV: service_token, HERMES_ENV: hermes_token, KEY_ENV: grant_key})
    config = json.loads((home / "config.yaml").read_text())
    config["model"] = {"provider": "custom", "default": "cf-joint-model", "api_mode": "chat_completions",
        "base_url": f"http://127.0.0.1:{model.server_port}/v1", "context_length": 131072,
        "api_key": "public-isolated-model-not-a-credential"}
    config["plugins"]["entries"]["cf-filebridge"]["settings"]["inbound_host"] = {
        "gateway_origin": origin, "service_token_env": SERVICE_ENV, "profile_reference": joint.PROFILE,
        "profile_revision": 1, "work_root": str(sandbox / "work"), "client_path": str(worker),
        "client_sha256": hashlib.sha256(worker.read_bytes()).hexdigest(),
        "ca_file": str(sandbox / "cert.pem"), "ca_sha256": hashlib.sha256((sandbox / "cert.pem").read_bytes()).hexdigest(),
        "consumer_tools": [joint.CONSUME]}
    (home / "config.yaml").write_text(json.dumps(config))
    receipt_path = sandbox / "held-stream.json"
    child_env = {**os.environ, "CF_EXIT_STREAM_RECEIPT": str(receipt_path)}
    # The host receives only the two synthetic secrets its configured services
    # need. The Gateway's encryption key never enters the Hermes child.
    child_env.pop(KEY_ENV, None)
    log = (sandbox / "host-output.log").open("wb")
    host = subprocess.Popen([sys.executable, "-I", "-B", str(Path(__file__).resolve()),
        "--gateway-source", str(gateway), "--hermes-source", str(hermes), "--worker", str(worker), "--host-child"],
        cwd=sandbox, env=child_env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
    worker_pid = None
    native_reaped = False
    server = serving = hermes_client = pending = None
    violations = joint.isolated_guard(sandbox, (gateway, hermes), worker)
    sys.path[:0] = [str(hermes), str(gateway / "src")]
    try:
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
        from cf_agent_gateway.task.model.models import HermesDispatchRecord
    except BaseException:
        if host.poll() is None:
            host.kill()
        host.wait(timeout=5)
        listener.close()
        model.shutdown()
        model.server_close()
        log.close()
        raise
    try:
        ready_path = sandbox / "host-ready.json"
        await _until(lambda: ready_path.exists() or host.poll() is not None, 30)
        assert host.poll() is None and ready_path.exists(), "official Hermes child did not start"
        ready = json.loads(ready_path.read_text())
        assert ready["pid"] == host.pid
        settings = Settings(database=DatabaseSettings(f"sqlite:///{(sandbox / 'gateway.db').as_posix()}"),
            logging=LoggingSettings("WARNING"),
            inbound_media=InboundMediaSettings(enabled=True, staging_root=str(sandbox / "staging"), public_base_url=origin),
            host_binding=HostBindingSettings(enabled=True, dedicated_endpoint_confirmed=True,
                host_id="joint-exit-host", profile_reference=joint.PROFILE, profile_revision=1,
                service_token_env=SERVICE_ENV, encryption_key_env=KEY_ENV,
                runtime_model="cf-joint-model", runtime_provider="custom", legacy_runtime_confirmed=True),
            worker=WorkerSettings(enabled=True, concurrency=1, lease_seconds=60, retry_limit=0),
            hermes=HermesSettings(enabled=True, base_url=ready["origin"], api_key_env=HERMES_ENV, model="cf-joint-model"))
        app = create_app(settings)
        gateway_requests, owners = [], []
        async def observe(scope, receive, send):
            # Observe the actual non-secret resolve owner, without replacing its
            # request or keeping any Authorization header/response descriptor.
            chunks = bytearray()
            response_chunks = bytearray()
            response_status = None
            async def observed_receive():
                message = await receive()
                if scope.get("path", "").endswith("/resolve") and message["type"] == "http.request":
                    chunks.extend(message.get("body", b""))
                    assert len(chunks) <= 65536
                    if not message.get("more_body"):
                        owner = json.loads(chunks)
                        owners.append({key: owner[key] for key in
                            ("schema", "session_id", "task_id", "host_instance_id", "host_nonce")})
                return message
            async def observed_send(message):
                nonlocal response_status
                if scope["type"] == "http" and message["type"] == "http.response.start":
                    response_status = message["status"]
                    gateway_requests.append((scope["method"], scope["path"], message["status"]))
                if (scope.get("path", "").endswith("/resolve") and response_status == 200
                        and message["type"] == "http.response.body"):
                    # The actual grant is retained only for negative leak scans;
                    # never print it, write it to disk or modify its response.
                    response_chunks.extend(message.get("body", b""))
                    assert len(response_chunks) <= 1024 * 1024
                    if not message.get("more_body"):
                        payload = json.loads(response_chunks)
                        test_secrets.extend(item["authorization"] for item in payload["attachments"])
                await send(message)
            await app(scope, observed_receive, observed_send)
        server = uvicorn.Server(uvicorn.Config(observe, log_level="warning", access_log=False, loop="asyncio",
            ssl_certfile=str(sandbox / "cert.pem"), ssl_keyfile=str(sandbox / "key.pem")))
        serving = asyncio.create_task(server.serve(sockets=[listener]))
        await _until(lambda: server.started or serving.done(), 20)
        assert server.started, "actual Gateway did not start"
        sessions = app.state.database_session_factory
        with sessions() as session:
            identities = IdentityService(session)
            identity = identities.create_identity(employee_id="joint-host-exit")
            identities.create_mapping(platform="wechat", account_id="wxid-exit-gateway", sender_id="wxid-exit",
                                      enterprise_identity_id=identity.id)
            AccessPolicyService(session).upsert_user_policy(enterprise_identity_id=identity.id, enabled=True)
            AccessPolicyService(session).upsert_gateway_policy(enabled=True, allowed_risk_levels={RiskLevel.NORMAL})
        def admit(sequence, media):
            message = NormalizedWechatMessage.model_validate({"source_account_id": "wxid-exit-gateway",
                "source_message_id": str(sequence), "source_local_id": str(sequence), "source_server_id": str(sequence),
                "source_message_id_is_fallback": False, "event_id": "exit:" + str(sequence),
                "conversation_id": "wxid-exit", "conversation_type": "private", "conversation_name": "exit",
                "sender_type": "human", "sender_id": "wxid-exit", "sender_name": "exit",
                "message_type": "file" if media else "text", "raw_type": 49 if media else 1,
                "content": "joint-attachment-exit" if media else "joint-after-exit", "timestamp": datetime.now(timezone.utc),
                "is_mentioned": None, "is_self": False, "reply": None})
            with sessions() as session:
                return MessageAdmissionService(session, inbound_media=settings.inbound_media).process(message)
        expected = (HERE / "fixtures/sample.pdf").read_bytes()
        class WechatFetchStub:
            def fetch(self, source):
                return BoundMediaResult(source.fingerprint, parse_inbound_media({"type": "file",
                    "filename": "exit.pdf", "data": base64.b64encode(expected).decode()}))
        outcome = admit(1, True)
        intake = InboundMediaWorker(sessions, WechatFetchStub(), InboundMediaStaging(sandbox / "staging"))
        assert await asyncio.to_thread(intake.run_once) == "ready"
        hermes_client = HermesClient(ready["origin"], hermes_token, "cf-joint-model")
        dispatcher = build_dispatch_worker(settings, session_factory=sessions, hermes_client=hermes_client, sender_factory=None)
        claim = dispatcher.claim_once()
        assert claim and claim.record_id == outcome.dispatch_record_id
        pending = asyncio.create_task(asyncio.to_thread(dispatcher.process_claim, claim))
        await _until(lambda: receipt_path.exists() or host.poll() is not None or pending.done(), 25)
        assert receipt_path.exists() and host.poll() is None and not pending.done(), "workcopy consumer was not held open"
        receipt = json.loads(receipt_path.read_text())
        assert receipt["host_pid"] == host.pid and receipt["stream_open"] and receipt["worker_alive"]
        assert receipt["host_audit_violations_before_kill"] == 0, _AuditDetails(receipt["host_audit_details"])
        assert receipt["host_audit_details"] == [], _AuditDetails(receipt["host_audit_details"])
        assert receipt["bytes_read"] == len(expected) and receipt["sha256"] == hashlib.sha256(expected).hexdigest()
        worker_pid = receipt["worker_pid"]
        assert type(worker_pid) is int and worker_pid > 1 and worker_pid != host.pid
        files = list((sandbox / "work").glob("*/work-*"))
        assert len(files) == 1 and files[0].read_bytes() == expected
        def binding():
            with sessions() as session:
                return session.scalar(select(InboundHostBinding).where(InboundHostBinding.dispatch_id == claim.record_id))
        active = binding()
        assert active.state == "running" and active.closed_at is None and len(owners) == 1
        remaining = (_utc(active.host_lease_until) - datetime.now(timezone.utc)).total_seconds()
        assert remaining > 15, "probe must kill well before lease expiry"
        original_owner = dict(owners[0])
        admit(2, False)
        assert dispatcher.claim_once() is None, "queued same-thread work bypassed the active claim"
        killed_at = time.monotonic()
        host.kill()  # The exact Popen child created by this test, never a searched PID.
        await asyncio.to_thread(host.wait, 5)
        assert host.returncode == -signal.SIGKILL
        reaped = None
        def reap_worker():
            nonlocal reaped
            reaped = os.waitpid(worker_pid, os.WNOHANG)
            return reaped[0] == worker_pid
        await _until(reap_worker, 8)
        native_reaped = True
        worker_exit_seconds = time.monotonic() - killed_at
        assert os.waitstatus_to_exitcode(reaped[1]) == 0, "native worker did not exit cleanly on host pipe EOF"
        assert (_utc(active.host_lease_until) - datetime.now(timezone.utc)).total_seconds() > 5
        await _until(lambda: binding().state in ("revoked", "closed"), 5)
        revoked = binding()
        assert revoked.state == "revoked" and revoked.closed_at is None
        assert revoked.grant_ciphertext is None
        with sessions() as session:
            assert session.get(InboundMediaJob, revoked.job_id).read_token_hash is None
            assert session.get(HermesDispatchRecord, claim.record_id).status is HermesDispatchStatus.RUNNING
        assert not pending.done(), "Gateway completed without closed ACK or the finite lease barrier"
        tls = ssl.create_default_context(cafile=str(sandbox / "cert.pem"))
        async with ClientSession(connector=TCPConnector(ssl=tls), timeout=ClientTimeout(total=5)) as client:
            for body in (original_owner, {**original_owner, "host_instance_id": "different-exit-instance"},
                         {**original_owner, "host_nonce": "n" * 32}):
                async with client.post(origin + "/internal/hermes/inbound-bindings/resolve", json=body,
                                       headers={"Authorization": "Bearer " + service_token}) as response:
                    assert response.status == 403
        result = await asyncio.wait_for(pending, 40)
        assert result.status is HermesDispatchStatus.UNCERTAIN
        assert datetime.now(timezone.utc) >= _utc(active.host_lease_until)
        assert time.monotonic() - killed_at < 36
        assert not any(path.endswith("/closed") for _method, path, _status in gateway_requests)
        assert dispatcher.claim_once() is None, "uncertain history was automatically requeued"
        log.flush()
        materials = [json.dumps(model.requests).encode(), (sandbox / "host-output.log").read_bytes(),
                     receipt_path.read_bytes()]
        materials += [path.read_bytes() for path in home.rglob("*") if path.is_file()]
        assert len(test_secrets) == 4, "actual short attachment authorization was not included in leak checks"
        for secret in test_secrets:
            assert all(secret.encode() not in data for data in materials), "credential leaked in the isolated probe"
        assert "Bearer " not in json.dumps(model.requests)
        assert violations == [], _AuditDetails(violations)
        print(json.dumps({"ok": True, "gateway_commit": joint.GATEWAY_COMMIT,
            "hermes_commit": joint.verify_sources(gateway, hermes),
            "actual_separate_hermes_process_killed": True, "verified_workcopy_stream_held_at_exit": True,
            "native_worker_reaped_after_host_eof": True, "worker_exit_seconds": round(worker_exit_seconds, 3),
            "gateway_real_events_disconnect_revoked": True, "closed_ack_count": 0,
            "gateway_fixed_lease_barrier_then_uncertain": True, "old_owner_or_new_nonce_replays_403": 3,
            "same_thread_uncertain_fifo_preserved": True,
            "host_audit_violations_at_held_stream": 0, "gateway_audit_violations": 0,
            "stubs": ["loopback model HTTP", "upstream WeChat fetch"], "production_host_acceptance": False}))
    finally:
        if host.poll() is None:
            host.kill()
            await asyncio.to_thread(host.wait, 5)
        if worker_pid is not None and not native_reaped:
            try:
                child_pid, _status = os.waitpid(worker_pid, os.WNOHANG)
                if child_pid == 0:  # waitpid proved this PID is our own child.
                    os.kill(worker_pid, signal.SIGKILL)
                    await asyncio.to_thread(os.waitpid, worker_pid, 0)
            except ChildProcessError:
                pass
        if hermes_client:
            hermes_client.close()
        if pending and not pending.done():
            try:
                await asyncio.wait_for(asyncio.shield(pending), 35)
            except Exception:
                pass
        if server:
            server.should_exit = True
        if serving:
            try:
                await asyncio.wait_for(serving, 10)
            except asyncio.TimeoutError:
                serving.cancel()
        listener.close()
        model.shutdown()
        model.server_close()
        log.close()


def run(gateway, hermes, worker):
    if sys.platform != "linux":
        raise RuntimeError("This explicit real-process gate requires Linux Gateway staging and child reaping")
    with tempfile.TemporaryDirectory(prefix="cf-gateway-hermes-exit-") as temporary:
        sandbox = Path(temporary).resolve()
        home = sandbox / "profile"
        shutil.copytree(joint.PLUGIN, home / "plugins/cf-filebridge", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        observer = home / "plugins/cf-a-exit-observer"
        observer.mkdir()
        (observer / "plugin.yaml").write_text('name: cf-a-exit-observer\nversion: "1.0.0"\nkind: standalone\n')
        (observer / "__init__.py").write_text(OBSERVER)
        for name in ("work", "staging", "empty-bundled", "temp", "user"):
            (sandbox / name).mkdir(mode=0o700)
        for name in ("cert.pem", "key.pem"):
            shutil.copyfile(HERE / "fixtures" / name, sandbox / name)
        config = {"plugins": {"enabled": ["cf-filebridge", "cf-a-exit-observer"], "entries": {
            "cf-filebridge": {"settings": {"inbound_enabled": True, "inbound_host_enabled": True}}}},
            "platform_toolsets": {"api_server": ["cf_filebridge_inbound", "cf_joint_probe"]},
            "agent": {"max_iterations": 6, "environment_probe": False},
            "security": {"allow_lazy_installs": False},
            "memory": {"enabled": False}, "skills": {"enabled": False},
            "compression": {"enabled": False}}
        (home / "config.yaml").write_text(json.dumps(config))
        env = {key: value for key, value in os.environ.items() if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR"}}
        env.update({"HERMES_HOME": str(home), "HERMES_BUNDLED_PLUGINS": str(sandbox / "empty-bundled"),
            "HERMES_ENABLE_PROJECT_PLUGINS": "false", "HERMES_TEST_ISOLATION": "1",
            "HOME": str(sandbox / "user"), "USERPROFILE": str(sandbox / "user"),
            "APPDATA": str(sandbox / "user"), "LOCALAPPDATA": str(sandbox / "user"),
            "TEMP": str(sandbox / "temp"), "TMP": str(sandbox / "temp"), "TMPDIR": str(sandbox / "temp"),
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"})
        result = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()),
            "--gateway-source", str(gateway), "--hermes-source", str(hermes), "--worker", str(worker), "--orchestrator"],
            cwd=sandbox, env=env, capture_output=True, text=True, encoding="utf-8", timeout=130)
        lines = result.stdout.strip().splitlines()
        report = json.loads(lines[-1]) if lines else {"ok": False, "stage": "isolated_child_start"}
        print(json.dumps(report))
        if result.returncode or report.get("ok") is not True:
            raise SystemExit(1)


def verify_imports(gateway, hermes):
    """Even import-only verification gets a fresh HOME and credential-free env."""
    with tempfile.TemporaryDirectory(prefix="cf-gateway-host-exit-imports-") as temporary:
        sandbox = Path(temporary).resolve()
        home = sandbox / "profile"
        for path in (home, sandbox / "empty-bundled", sandbox / "user", sandbox / "temp"):
            path.mkdir(mode=0o700)
        (home / "config.yaml").write_text(json.dumps({"plugins": {"enabled": []},
            "agent": {"environment_probe": False}, "security": {"allow_lazy_installs": False}}))
        env = {key: value for key, value in os.environ.items() if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR"}}
        env.update({"HERMES_HOME": str(home), "HERMES_BUNDLED_PLUGINS": str(sandbox / "empty-bundled"),
            "HERMES_ENABLE_PROJECT_PLUGINS": "false", "HERMES_TEST_ISOLATION": "1",
            "HOME": str(sandbox / "user"), "USERPROFILE": str(sandbox / "user"),
            "APPDATA": str(sandbox / "user"), "LOCALAPPDATA": str(sandbox / "user"),
            "TEMP": str(sandbox / "temp"), "TMP": str(sandbox / "temp"), "TMPDIR": str(sandbox / "temp"),
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"})
        result = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()),
            "--gateway-source", str(gateway), "--hermes-source", str(hermes), "--verify-import-child"],
            cwd=sandbox, env=env, capture_output=True, text=True, encoding="utf-8", timeout=45)
        lines = result.stdout.strip().splitlines()
        report = json.loads(lines[-1]) if lines else {"ok": False, "stage": "isolated_import_start"}
        print(json.dumps(report))
        if result.returncode or report.get("source_verified") is not True:
            raise SystemExit(1)


def verify_import_child(gateway, hermes):
    sandbox = Path(os.environ["HERMES_HOME"]).parent
    joint.bootstrap_system_metadata()
    violations = joint.isolated_guard(sandbox, (gateway, hermes), None)
    sys.path[:0] = [str(hermes), str(gateway / "src")]
    from cf_agent_gateway.runtime.dispatch_worker import build_dispatch_worker
    from gateway.platforms.api_server import APIServerAdapter
    from hermes_state import SessionDB
    from hermes_state_registry import acquire, release_or_close
    # Exercise the actual SQLite constructor and the same public shared-handle
    # registry used by the official API. Imports alone cannot detect a lazy
    # database initialization failure. Both databases are disposable and the
    # audit boundary remains active throughout construction and closure.
    standalone = SessionDB(sandbox / "standalone-state.db")
    standalone.close()
    shared = acquire(sandbox / "profile" / "state.db")
    release_or_close(shared)
    asyncio.run(verify_public_model_lock())
    assert violations == [], _AuditDetails(violations)
    rejected_metadata = violations.platform_probes_denied
    assert not rejected_metadata or sys.platform == "win32"
    assert all(os.path.normcase(os.path.abspath(path)) ==
               os.path.normcase(os.path.abspath(f"/proc/{os.getpid()}/stat"))
               for path in rejected_metadata)
    print(json.dumps({"source_verified": True, "dependency_imports": True, "isolated_import_profile": True,
                      "session_db_initialized": True,
                      "public_model_lock_preflight": {"colliding_virtual_name": 409, "distinct_virtual_name": 200},
                      "platform_probes_denied": rejected_metadata,
                      "isolation_audit_violations": 0, "real_host_exit_executed": False,
                      "production_host_acceptance": False}))


async def verify_public_model_lock():
    """Probe the public HTTP contract without an LLM call or lock override."""
    from aiohttp import ClientSession, ClientTimeout
    from gateway.config import PlatformConfig
    from gateway.platforms.api_server import APIServerAdapter
    key = secrets.token_urlsafe(32)
    for virtual_name, expected in (("cf-joint-model", 409), ("cf-hermes-api", 200)):
        adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={
            "host": "127.0.0.1", "port": 0, "key": key, "model_name": virtual_name}))
        try:
            async with asyncio.timeout(15):
                assert await adapter.connect()
                port = adapter._site._server.sockets[0].getsockname()[1]
                origin = f"http://127.0.0.1:{port}"
                async with ClientSession(timeout=ClientTimeout(total=5), trust_env=False,
                                         headers={"Authorization": "Bearer " + key}) as client:
                    async with client.post(origin + "/api/sessions", json={}) as response:
                        assert response.status == 201
                        session_id = (await response.json())["session"]["id"]
                    async with client.post(origin + f"/api/sessions/{session_id}/model", json={
                            "model": "cf-joint-model", "provider": "custom", "require_model_lock": True}) as response:
                        assert response.status == expected
                        result = await response.json()
                        if expected == 409:
                            assert result["error"]["code"] == "model_lock_unavailable"
                        else:
                            runtime = result["runtime"]
                            assert runtime["model"] == "cf-joint-model"
                            assert runtime["provider"] == "custom"
                            assert runtime["route_source"] == "raw_request"
                            assert runtime["model_lock"] == "accepted"
        finally:
            await adapter.disconnect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-source", required=True, type=Path)
    parser.add_argument("--gateway-archive", type=Path)
    parser.add_argument("--hermes-source", required=True, type=Path)
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--verify-import-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--host-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--orchestrator", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    gateway, hermes = args.gateway_source.resolve(strict=True), args.hermes_source.resolve(strict=True)
    joint.verify_sources(gateway, hermes, args.gateway_archive)
    if args.verify_only:
        verify_imports(gateway, hermes)
    elif args.verify_import_child:
        try:
            verify_import_child(gateway, hermes)
        except Exception as error:
            report = {"ok": False, "error_type": type(error).__name__, "stage": "isolated_import",
                "locations": [f"{Path(item.filename).name}:{item.lineno}"
                              for item in traceback.extract_tb(error.__traceback__)]}
            if isinstance(error, ModuleNotFoundError):
                name = error.name or ""
                if name and all(part.isidentifier() for part in name.split(".")):
                    report["missing_module"] = name
            if isinstance(error, AssertionError) and error.args and isinstance(error.args[0], _AuditDetails):
                report["isolation_violations"] = error.args[0]
            print(json.dumps(report))
            raise SystemExit(1) from None
    else:
        worker = args.worker.resolve(strict=True) if args.worker else None
        if worker is None:
            parser.error("--worker is required")
        try:
            if args.host_child:
                asyncio.run(host_child(gateway, hermes, worker))
            elif args.orchestrator:
                asyncio.run(orchestrate(gateway, hermes, worker))
            else:
                run(gateway, hermes, worker)
        except Exception as error:
            # Do not echo arbitrary upstream exception text or captured logs;
            # source locations are enough to diagnose this isolated CI gate.
            frames = [f"{Path(item.filename).name}:{item.lineno}" for item in traceback.extract_tb(error.__traceback__)]
            report = {"ok": False, "error_type": type(error).__name__, "locations": frames}
            if isinstance(error, AssertionError) and error.args and isinstance(error.args[0], _AuditDetails):
                report["isolation_violations"] = error.args[0]
            print(json.dumps(report))
            raise SystemExit(1) from None
