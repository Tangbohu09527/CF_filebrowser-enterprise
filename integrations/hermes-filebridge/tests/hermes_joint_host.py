"""Separate official Hermes runtime for the explicit isolated integration probes.

This test host uses real public plugin loading and HTTP dispatch. Its files are
only readiness, shutdown and read-only observation signals, never credentials
or a way to issue/replace a Gateway binding.
"""
from __future__ import annotations

import argparse
import atexit
import asyncio
import errno
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

HERE = Path(__file__).resolve().parent
_audit_violations = []
_IPC_RETRY_SECONDS = 1.0


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _sharing_conflict(error):
    # CRT reads omit winerror; MoveFileEx reports access denied when an open
    # reader did not share DELETE. Persistent denial still raises unchanged.
    return (os.name == "nt" and error.errno == errno.EACCES
            and getattr(error, "winerror", None) in (None, 5, 32, 33))


async def _read_json(path):
    deadline = time.monotonic() + _IPC_RETRY_SECONDS
    while True:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except PermissionError as error:
            remaining = deadline - time.monotonic()
            if not _sharing_conflict(error) or remaining <= 0:
                raise
            await asyncio.sleep(min(0.02, remaining))


def _write(path, payload):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload), encoding="utf-8")
    deadline = time.monotonic() + _IPC_RETRY_SECONDS
    while True:
        try:
            temporary.replace(path)
            return
        except PermissionError as error:
            remaining = deadline - time.monotonic()
            if not _sharing_conflict(error) or remaining <= 0:
                raise
            time.sleep(min(0.02, remaining))


class ExternalHermesHost:
    def __init__(self, python, source, sandbox, worker, *, hermes_commit,
                 hermes_archive=None, hermes_key_env="CF_JOINT_HERMES_KEY",
                 observer="cf-a-joint-observer"):
        self.python, self.source = Path(python), Path(source)
        self.sandbox, self.worker = Path(sandbox), Path(worker)
        self.commit, self.archive = hermes_commit, hermes_archive
        self.key_env, self.observer = hermes_key_env, observer
        self.process = self.log = None
        self.ready = self.sandbox / "external-host-ready.json"
        self.status = self.sandbox / "external-host-status.json"
        self.stop_file = self.sandbox / "external-host-stop"

    async def start(self):
        assert Path(os.environ["HERMES_HOME"]).resolve().parent == self.sandbox.resolve()
        command = [str(self.python), "-I", "-X", "utf8", "-B", str(Path(__file__).resolve()),
                   "--hermes-source", str(self.source), "--hermes-commit", self.commit,
                   "--worker", str(self.worker), "--key-env", self.key_env,
                   "--observer", self.observer]
        if self.archive:
            command += ["--hermes-archive", str(self.archive)]
        env = dict(os.environ)
        for name in ("CF_JOINT_GRANT_KEY", "CF_EXIT_GRANT_KEY"):
            env.pop(name, None)
        env["CF_JOINT_RETAIN_STREAM_FLAG"] = str(self.sandbox / "retain-stream")
        self.log = (self.sandbox / "external-host.log").open("wb")
        self.process = subprocess.Popen(command, cwd=self.sandbox, env=env,
            stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        atexit.register(self._reap_owned_host)
        async with asyncio.timeout(30):
            while True:
                try:
                    ready = await _read_json(self.ready)
                    break
                except FileNotFoundError:
                    pass
                if self.process.poll() is not None:
                    diagnostic = self.sandbox / "external-host-failure.json"
                    try:
                        detail = await _read_json(diagnostic)
                    except FileNotFoundError:
                        detail = {}
                    raise AssertionError({"external_host_failed": detail})
                await asyncio.sleep(0.05)
        assert ready["hermes_commit"] == self.commit and ready["audit_violations"] == [], ready
        return ready["origin"]

    def _reap_owned_host(self):
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=5)

    async def snapshot(self):
        async with asyncio.timeout(5):
            while True:
                try:
                    return await _read_json(self.status)
                except FileNotFoundError:
                    await asyncio.sleep(0.05)

    async def stop(self):
        if self.process is None:
            return
        try:
            if self.process.poll() is None:
                self.stop_file.touch()
                try:
                    await asyncio.to_thread(self.process.wait, timeout=15)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    await asyncio.to_thread(self.process.wait, timeout=5)
                    raise AssertionError("official host failed to shut down") from None
            status = await self.snapshot()
            if self.process.returncode != 0:
                diagnostic = self.sandbox / "external-host-failure.json"
                try:
                    failure = await _read_json(diagnostic)
                except FileNotFoundError:
                    failure = {}
                raise AssertionError({"external_host_failed": failure, "final_status": status})
            assert status["closed"] is True and status["audit_violations"] == [], status
        finally:
            if self.log:
                self.log.close()
            if self.process is not None and self.process.poll() is not None:
                atexit.unregister(self._reap_owned_host)


def _snapshot(observer, violations, *, closed=False, registered_adapters=()):
    scopes = []
    adapters = list(registered_adapters)
    for adapter in getattr(observer, "host_adapters", []):
        if adapter not in adapters:
            adapters.append(adapter)
    for adapter in adapters:
        # Observe already-created real scopes; never construct or activate one.
        with adapter._lock:
            current = list(adapter._scopes.values())
            ended = sorted(adapter._ended_sessions)
        for scope in current:
            dispatch_id = scope.resolved.worker_binding["dispatch_id"] if scope.resolved else None
            with adapter.bridge._lock:
                dispatch = adapter.bridge._dispatches.get(dispatch_id)
            process = dispatch.process if dispatch is not None else None
            scopes.append({"session_id": scope.session_id, "task_id": scope.task_id,
                "stopped": scope.stopped.is_set(), "finished": scope.finished.is_set(),
                "worker_pid": process.pid if process else None,
                "worker_exit": process.poll() if process else None,
                "ended": scope.session_id in ended})
    return {"pid": os.getpid(), "closed": closed, "python_version": sys.version.split()[0], "audit_violations": list(violations),
        "platform_probes_denied": violations.platform_probes_denied,
        "scopes": scopes, "active_scopes": sum(not s["stopped"] for s in scopes),
        "retained_streams_closed": [stream.closed for _context, stream in getattr(observer, "retained_streams", [])],
        "retained_worker_exits": [process.poll() for process in getattr(observer, "native_processes", [])]}


async def serve(args):
    global _audit_violations
    sandbox = Path(os.environ["HERMES_HOME"]).resolve().parent
    assert Path(os.environ["HOME"]).resolve() == sandbox / "user"
    joint = _load("cf_external_joint_helpers", "test_gateway_hermes_joint.py")
    support = _load("cf_external_source_support", "hermes_probe_support.py")
    support.assert_isolated_environment(sandbox)
    # Pure immutable-file verification before any official module is imported.
    support.verify_source(args.hermes_source, args.hermes_commit, args.hermes_archive)
    joint.bootstrap_system_metadata()
    read_roots = (args.hermes_source,) + ((args.hermes_archive,) if args.hermes_archive else ())
    violations = joint.isolated_guard(sandbox, read_roots, args.worker)
    _audit_violations = violations
    # All official imports take place after the disposable HOME and strict
    # audit guard are active.
    sys.path[:0] = [str(HERE)]
    sys.path.insert(0, str(args.hermes_source))
    from hermes_cli.plugins import discover_plugins, get_plugin_manager
    from gateway.config import PlatformConfig
    from gateway.platforms.api_server import APIServerAdapter
    discover_plugins()
    manager = get_plugin_manager()
    for name in ("cf-filebridge", args.observer):
        loaded = manager._plugins.get(name)
        assert loaded and loaded.enabled and loaded.error is None, name
    observer = manager._plugins[args.observer].module
    # Read the bound instances which the real loader registered. This lets the
    # probe observe an in-flight download before a consumer tool has run; no
    # callback, scope activation or binding method is invoked here.
    host_module = manager._plugins["cf-filebridge"].module.__name__ + ".inbound_host"
    registered_adapters = tuple(owner for callback in manager._middleware.get("tool_execution", [])
        if (owner := getattr(callback, "__self__", None)) is not None
        and owner.__class__.__module__ == host_module and owner.__class__.__name__ == "HostAdapter")
    api = APIServerAdapter(PlatformConfig(enabled=True, extra={"host": "127.0.0.1", "port": 0,
        "key": os.environ[args.key_env], "model_name": "cf-hermes-api"}))
    try:
        assert await api.connect()
        origin = f"http://127.0.0.1:{api._site._server.sockets[0].getsockname()[1]}"
        _write(sandbox / "external-host-ready.json", {"pid": os.getpid(), "origin": origin,
            "hermes_commit": args.hermes_commit, "audit_violations": list(violations),
            "python_version": sys.version.split()[0]})
        while not (sandbox / "external-host-stop").exists():
            _write(sandbox / "external-host-status.json", _snapshot(observer, violations,
                registered_adapters=registered_adapters))
            await asyncio.sleep(0.05)
    finally:
        await api.disconnect()
        manager.unload()
        for context, _stream in getattr(observer, "retained_streams", []):
            context.__exit__(None, None, None)
        _write(sandbox / "external-host-status.json", _snapshot(observer, violations, closed=True,
            registered_adapters=registered_adapters))
    assert violations == [], violations


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hermes-source", required=True, type=Path)
    parser.add_argument("--hermes-commit", required=True)
    parser.add_argument("--hermes-archive", type=Path)
    parser.add_argument("--worker", required=True, type=Path)
    parser.add_argument("--key-env", default="CF_JOINT_HERMES_KEY")
    parser.add_argument("--observer", default="cf-a-joint-observer")
    arguments = parser.parse_args()
    try:
        asyncio.run(serve(arguments))
    except Exception as error:
        # No arbitrary upstream exception text, log contents or frame locals.
        report = {"ok": False, "error_type": type(error).__name__,
            "audit_violations": list(_audit_violations),
            "locations": [f"{Path(frame.filename).name}:{frame.lineno}"
                          for frame in traceback.extract_tb(error.__traceback__)]}
        if isinstance(error, ModuleNotFoundError):
            name = error.name or ""
            if name and all(part.isidentifier() for part in name.split(".")):
                report["missing_module"] = name
        _write(Path(os.environ["HERMES_HOME"]).parent / "external-host-failure.json", report)
        print(json.dumps(report))
        raise SystemExit(1) from None
