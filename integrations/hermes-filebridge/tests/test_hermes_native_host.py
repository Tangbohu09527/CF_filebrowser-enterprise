"""Native HTTP -> official Hermes -> HTTPS control -> worker -> handle probe.

The Gateway HTTPS service and model are explicitly synthetic fixtures. The
official HTTP adapter, Agent, loader, middleware and product plugin/worker are
real. This is Windows compatibility evidence, not Linux Gateway joint evidence
or production acceptance. No binding or lifecycle is injected into HostBridge.
Run explicitly; ordinary unittest discovery does not start upstream software.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
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

HERE = Path(__file__).resolve().parent


def local_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def events(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


async def until(predicate, timeout=12):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("native request condition timed out")
        await asyncio.sleep(0.025)


async def orchestrate(source, worker, commit, archive, plugin_source=None):
    # The parent has no upstream imports. Each real Hermes host has a separate,
    # audited interpreter/profile and uses the verified source only.
    sys.path.insert(0, str(HERE))
    from aiohttp import ClientSession, ClientTimeout
    from test_inbound_host import HostControlTests, SERVICE_ENV, SERVICE_SECRET, READ_SECRET, FIXTURES
    import test_gateway_hermes_joint as joint
    from hermes_joint_host import ExternalHermesHost
    from hermes_probe_support import isolated_environment

    HostControlTests.worker = worker
    HostControlTests.worker_hash = hashlib.sha256(worker.read_bytes()).hexdigest()
    HostControlTests.worker_launches = []
    reports = []

    async def scenario(name, *, jpeg=False):
        original_environment = dict(os.environ)
        fixture = HostControlTests()
        fixture.make_adapter = False
        fixture.setUp()
        model = joint.ModelServer()
        threading.Thread(target=model.serve_forever, daemon=True).start()
        sandbox = fixture.root
        home = sandbox / "profile"
        event_path = sandbox / "events.jsonl"
        api_secret = secrets.token_urlsafe(32)
        host = None
        pending = None
        owned_long_files = []
        if name == "long-path":
            assert os.name == "nt" and len(str(sandbox)) < 195
            long_root = sandbox / ("work-" + "w" * (202 - len(str(sandbox)) - 6))
            # Move only this fixture's newly created empty private directory.
            # Its DACL is retained; the real adapter allocates the task below it.
            fixture.work_root.rename(long_root)
            fixture.work_root = long_root
            fixture.raw["work_root"] = str(long_root)
            assert len(str(long_root)) == 202
        if jpeg:
            fixture.body = (FIXTURES / "sample.jpg").read_bytes()
            fixture.mime = "image/jpeg"
        if name == "model-error":
            fixture.lease_seconds = 6
        if name in {"cancel", "disconnect", "host-exit"}:
            fixture.mode = "slow-body"
        if name == "before-events":
            fixture.first_snapshot.clear()
        if name == "identity-mismatch":
            fixture.response_transform = lambda response: response["attachments"][0].update(
                enterprise_identity_id="90000000-0000-4000-8000-000000000099")
        if name == "retry":
            fixture.mode = "503_once"
        try:
            shutil.copytree(plugin_source or joint.PLUGIN, home / "plugins/cf-filebridge",
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            observer = home / "plugins/cf-a-joint-observer"
            observer.mkdir()
            (observer / "plugin.yaml").write_text('name: cf-a-joint-observer\nversion: "1.0.0"\nkind: standalone\n')
            (observer / "__init__.py").write_text(joint.OBSERVER, encoding="utf-8")
            for directory in ("empty-bundled", "user", "temp"):
                (sandbox / directory).mkdir(exist_ok=True)
            fixture.raw["consumer_tools"] = [joint.CONSUME]
            config = {"plugins": {"enabled": ["cf-filebridge", "cf-a-joint-observer"], "entries": {
                "cf-filebridge": {"settings": {"inbound_enabled": True, "inbound_host_enabled": True,
                                                   "inbound_host": fixture.raw}}}},
                "platform_toolsets": {"api_server": ["cf_filebridge_inbound", "cf_joint_probe"]},
                "model": {"provider": "custom", "default": "cf-joint-model", "api_mode": "chat_completions",
                          "base_url": f"http://127.0.0.1:{model.server_port}/v1", "context_length": 131072,
                          "api_key": "public-isolated-model-not-a-credential"},
                "agent": {"max_iterations": 6, "environment_probe": False},
                "security": {"allow_lazy_installs": False}, "memory": {"enabled": False},
                "skills": {"enabled": False}, "compression": {"enabled": False}}
            (home / "config.yaml").write_text(json.dumps(config), encoding="utf-8")
            # Only synthetic secrets are placed in the host's explicit child
            # environment. No caller's credentials/Profile are inherited.
            environment = isolated_environment(sandbox, {
                SERVICE_ENV: SERVICE_SECRET, "CF_JOINT_HERMES_KEY": api_secret,
                "CF_JOINT_EVENTS": str(event_path)})
            os.environ.clear()
            os.environ.update(environment)
            host = ExternalHermesHost(Path(sys.executable), source, sandbox, worker,
                                      hermes_commit=commit, hermes_archive=archive)
            origin = await host.start()
            async with ClientSession(timeout=ClientTimeout(total=45)) as client:
                async def request(session, text):
                    async with client.post(origin + "/v1/chat/completions",
                        headers={"Authorization": "Bearer " + api_secret, "X-Hermes-Session-Id": session},
                        json={"model": "cf-hermes-api", "stream": False,
                              "messages": [{"role": "user", "content": text}]}) as response:
                        return response.status, await response.json()

                text = 'joint-attachment-native {"attachment_id":5}'
                sessions = ["native-" + name]
                before = fixture.download_calls
                if name == "parallel":
                    sessions = ["native-alice", "native-bob"]
                    responses = await asyncio.gather(*[request(session,
                        f'joint-attachment-{label} {{"attachment_id":5}}')
                        for session, label in zip(sessions, ("alice", "bob"))])
                elif name == "model-error":
                    responses = [await request(sessions[0], 'joint-error {"attachment_id":5}')]
                elif name in {"cancel", "disconnect", "host-exit"}:
                    pending = asyncio.create_task(request(sessions[0], text))
                    await until(fixture.partial_body_sent.is_set)
                    await until(lambda: any(path.is_file() and path.stat().st_size > 0
                                            for path in fixture.work_root.rglob("*")))
                    if name == "host-exit":
                        import psutil
                        snapshot = await host.snapshot()
                        launcher = psutil.Process(host.process.pid)
                        processes = launcher.children(recursive=True)
                        workers = [process for process in processes
                                   if Path(process.exe()).resolve() == worker]
                        assert len(workers) == 1, "actual host had no unique native worker"
                        assert snapshot["audit_violations"] == []
                        # Windows venv python.exe can be a redirector with a
                        # separate runtime child. Kill the actual host that
                        # owns this observed worker, only after proving it is
                        # inside our Popen tree; never select a global PID/name.
                        actual_host = workers[0].parent()
                        assert actual_host is not None and actual_host.pid in {
                            launcher.pid, *(process.pid for process in processes)}
                        assert actual_host.pid == snapshot["pid"]
                        stopped_at = time.monotonic()
                        actual_host.kill()
                        await asyncio.to_thread(host.process.wait, timeout=5)
                        worker_exit = await asyncio.to_thread(workers[0].wait, timeout=5)
                        assert worker_exit == 0, "native worker did not complete EOF cleanup"
                        exit_seconds = time.monotonic() - stopped_at
                        host.log.close()
                        host = None
                        fixture.download_release.set()
                        await asyncio.gather(pending, return_exceptions=True)
                        assert fixture.download_calls == before + 1
                        assert fixture.closed_calls == 0, "abruptly killed host sent a closed acknowledgement"
                        assert fixture.control_headers_valid and fixture.media_headers_valid
                        assert not any(path.is_file() for path in fixture.work_root.rglob("*"))
                        reports.append({"case": name, "actual_host_stopped_during_download": True,
                                        "partial_file_observed_before_kill": True,
                                        "worker_exit_code": worker_exit, "worker_exit_seconds": round(exit_seconds, 3),
                                        "host_snapshot": snapshot})
                        return
                    with fixture.lock:
                        record = fixture.records[sessions[0]]
                        if name == "cancel":
                            record.update(sequence=2, state="revoked", reason="native_test_cancel")
                        else:
                            record["disconnect"] = True
                    await until(lambda: fixture.closed_calls == 1)
                    fixture.download_release.set()
                    responses = [await pending]
                elif name == "before-events":
                    pending = asyncio.create_task(request(sessions[0], text))
                    await until(fixture.events_entered.is_set)
                    await asyncio.sleep(0.2)
                    assert fixture.download_calls == before, "download preceded the first running event"
                    fixture.first_snapshot.set()
                    responses = [await pending]
                else:
                    responses = [await request(sessions[0], text)]

                if name != "identity-mismatch":
                    await until(lambda: fixture.closed_calls == len(sessions))
                tools = [item for item in events(event_path) if item["kind"] == "tool"]
                assert all(item["task_id"] == item["session_id"] for item in tools)
                assert {item["session_id"] for item in tools} == set(sessions)
                if name in {"cancel", "disconnect", "identity-mismatch"}:
                    assert all(not item["result"]["ok"] for item in tools), tools
                    assert not any(path.is_file() for path in fixture.work_root.rglob("*"))
                    expected_downloads = 0 if name == "identity-mismatch" else 1
                    assert fixture.download_calls == expected_downloads
                elif name != "model-error":
                    assert all(status == 200 for status, _body in responses), responses
                    handles = []
                    for session in sessions:
                        results = [item for item in tools if item["session_id"] == session]
                        downloads = [item["result"] for item in results if item["tool"] == joint.DOWNLOAD]
                        consumed = [item["result"] for item in results if item["tool"] == joint.CONSUME]
                        assert len(downloads) == 2 and len(consumed) == 1, results
                        assert downloads[0] == downloads[1], "repeated tool refreshed its worker/budget/workcopy"
                        assert downloads[0]["verified"] is True and downloads[0]["formal_archive"] is False
                        assert consumed[0] == {"ok": True, "bytes": len(fixture.body),
                            "sha256": hashlib.sha256(fixture.body).hexdigest(), "actual_stream_read": True}
                        handles.append(downloads[0]["handle"])
                    assert len(set(handles)) == len(sessions), "concurrent sessions shared a handle"
                    listing_root = (Path("\\\\?\\" + str(fixture.work_root))
                                    if name == "long-path" else fixture.work_root)
                    files = [path for path in listing_root.rglob("*") if path.is_file()]
                    if name == "long-path":
                        owned_long_files.extend(files)
                        assert len(files) == 1 and len(str(files[0])) - 4 > 260
                    assert len(files) == len(sessions) and all(path.read_bytes() == fixture.body for path in files)
                    assert len({path.parent for path in files}) == len(sessions), "sessions shared a task directory"
                    assert fixture.download_calls == len(sessions) + (1 if name == "retry" else 0)
                    # A new HTTP turn must not revive the ended handle or mint
                    # another binding. Real history is supplied by Hermes.
                    counters = (fixture.resolve_calls, fixture.event_calls, fixture.download_calls)
                    for session in sessions:
                        await request(session, "joint-after read the previous handle")
                    assert (fixture.resolve_calls, fixture.event_calls, fixture.download_calls) == counters
                    replays = [item for item in events(event_path) if item["kind"] == "tool"] [len(tools):]
                    assert len(replays) == len(sessions) and all(not item["result"]["ok"] for item in replays)
                else:
                    assert fixture.download_calls == 1
                    assert responses[0][0] != 200 or responses[0][1].get("hermes", {}).get("failed") is True
                    ends = [item for item in events(event_path) if item["kind"] == "end"]
                    # Observe the actual new/old hook behavior. Revocation above
                    # is mandatory whether the hook exists or the lease expires.
                    reports.append({"case": "model-error-hook", "end_events": ends})
                assert fixture.resolve_calls == len(sessions) and fixture.event_calls <= len(sessions)
                assert fixture.control_headers_valid and fixture.media_headers_valid
                # Windows status/session writers may hold an exclusive handle
                # briefly. Join the real host before reading every persisted
                # file; do not skip locked files or weaken the secret scan.
                await host.stop()
                final_snapshot = await host.snapshot()
                materials = [json.dumps(model.requests).encode(), event_path.read_bytes()]
                materials += [path.read_bytes() for path in home.rglob("*") if path.is_file()]
                assert all(secret.encode() not in material for secret in (SERVICE_SECRET, READ_SECRET, api_secret)
                           for material in materials), "synthetic authorization leaked into model/profile/history"
                reports.append({"case": name, "actual_http_agent_worker": True,
                                "download_requests": fixture.download_calls, "closed": fixture.closed_calls,
                                "expected_denied_housekeeping": final_snapshot["expected_denied_housekeeping"],
                                "expected_denied_housekeeping_count": len(final_snapshot["expected_denied_housekeeping"]),
                                "scratch_housekeeping_validated": False})
        except BaseException:
            diagnostic = {"case": name, "resolve": fixture.resolve_calls,
                "events": fixture.event_calls, "downloads": fixture.download_calls,
                "closed": fixture.closed_calls, "tool_events": events(event_path)}
            if host is not None and host.status.exists():
                diagnostic["host_status"] = await host.snapshot()
            print(json.dumps(diagnostic), file=sys.stderr)
            raise
        finally:
            fixture.download_release.set()
            fixture.first_snapshot.set()
            stop_error = None
            if host is not None:
                try:
                    await host.stop()
                except Exception as error:
                    stop_error = error
                    # The host's final JSON contains only error type and code
                    # locations; never print arbitrary upstream diagnostics.
                    diagnostic = sandbox / "external-host.log"
                    if diagnostic.exists():
                        for line in diagnostic.read_text(encoding="utf-8", errors="replace").splitlines():
                            try:
                                value = json.loads(line)
                            except ValueError:
                                continue
                            if type(value) is dict and value.get("ok") is False:
                                print(json.dumps({key: value[key] for key in ("error_type", "locations")
                                                  if key in value}), file=sys.stderr)
            model.shutdown()
            model.server_close()
            if pending is not None:
                if not pending.done():
                    pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)
            # Only remove exact files observed in our freshly allocated long
            # test directory. Product revocation itself preserves the copy.
            for path in owned_long_files:
                assert Path("\\\\?\\" + str(fixture.work_root)) in path.parents
                path.unlink()
            fixture.doCleanups()
            os.environ.clear()
            os.environ.update(original_environment)
            if stop_error is not None:
                raise stop_error

    cases = ["parallel", "jpeg", "retry", "before-events", "identity-mismatch",
             "model-error", "cancel", "disconnect", "host-exit"]
    if os.name == "nt" and plugin_source is None:
        cases.append("long-path")
    for name in cases:
        await scenario(name, jpeg=name == "jpeg")
    print(json.dumps({"ok": True, "hermes_commit": commit, "python": sys.version.split()[0],
        "platform": sys.platform, "cases": reports,
        "stubs": ["Gateway HTTPS control and attachment service", "loopback model"],
        "real_gateway_joint": False, "production_host_acceptance": False}))


def run(source, worker, commit, archive, plugin_source=None):
    support = local_module("native_probe_support", "hermes_probe_support.py")
    support.verify_source(source, commit, archive)
    with tempfile.TemporaryDirectory(prefix="cf-hermes-native-request-") as directory:
        sandbox = Path(directory).resolve()
        env = support.isolated_environment(sandbox, {"CF_FILEBRIDGE_INBOUND_TEST_EXE": str(worker)})
        command = [sys.executable, "-I", "-B", "-X", "utf8", str(Path(__file__).resolve()),
                   "--hermes-source", str(source), "--hermes-commit", commit,
                   "--worker", str(worker), "--orchestrator"]
        if archive:
            command += ["--hermes-archive", str(archive)]
        if plugin_source:
            command += ["--plugin-source", str(plugin_source)]
        result = subprocess.run(command, cwd=sandbox, env=env, capture_output=True,
                                text=True, encoding="utf-8", timeout=240)
        # Fixture authorizations are synthetic but still forbidden in output.
        protected = ("synthetic-only-host-service-secret-never-a-live-credential",
                     "Bearer synthetic-only-attachment-grant-never-a-live-credential")
        if any(value in result.stdout or value in result.stderr for value in protected):
            raise RuntimeError("native probe diagnostic contained synthetic authorization; withheld")
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        if result.returncode:
            raise SystemExit(result.returncode)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hermes-source", type=Path, required=True)
    parser.add_argument("--hermes-commit", required=True)
    parser.add_argument("--hermes-archive", type=Path)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--plugin-source", type=Path,
                        help="Explicit verified artifact plugin directory; defaults to this repository's plugin")
    parser.add_argument("--orchestrator", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.orchestrator:
        asyncio.run(orchestrate(args.hermes_source, args.worker, args.hermes_commit,
                                args.hermes_archive, args.plugin_source))
    else:
        run(args.hermes_source.resolve(strict=True), args.worker.resolve(strict=True),
            args.hermes_commit, args.hermes_archive.resolve(strict=True) if args.hermes_archive else None,
            args.plugin_source.resolve(strict=True) if args.plugin_source else None)
