#!/usr/bin/env python3
"""Disposable-guest Audit Store probe; never run on a deployment host.

Integration order (the existing VM harness owns SSH and formal stop/start):
prepare on client; copy its .control.json to server; server --mode observe in
a bounded worker; copy ready to client; control; write release with ready nonce;
require server success/detach; repeat server --mode inject + fault; require
success/detach; formal manage.sh stop then start at the identical image; verify.

State, controls and ready/release files stay root:root 0600 in the guests.
Only reports are publishable. No syscall text is written to disk, stdout or a
journal: raw register output is incrementally consumed from an anonymous pipe.
Coverage evidence is bounded /proc sampling plus strace -f, not proof of an
impossible transient FD reuse or of the absence of transient staging files.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import stat
import subprocess
import sys
import time

SPEC = importlib.util.spec_from_file_location("fault_api", Path(__file__).with_name("shared-host-api.py"))
api = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(api)
GUEST = Path("/root/cf-verification")
DATABASE = Path("/var/lib/cf-filebrowser-enterprise/database.db")
FILES = Path("/srv/storage/cf-filebrowser-enterprise/files")
WINDOW_SECONDS = 60
WATCHDOG_SECONDS = 70
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LC_ALL": "C"}


class FaultError(Exception):
    """Only literal, nonsecret check identifiers may be passed here."""


def require(condition, code):
    if not condition:
        raise FaultError(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def private_json(path):
    return json.loads(api.protected_path(path, secret=True).read_bytes())


def control_digest(control):
    return digest(json.dumps(control, sort_keys=True, separators=(",", ":")).encode())


def strace_command(pid, fds, inject):
    require(type(pid) is int and pid > 1 and fds and len(fds) <= 8
            and all(type(fd) is int and 0 <= fd <= 1048576 for fd in fds), "trace_selection_invalid")
    result = ["/usr/bin/strace", "-f", "-qq", "--detach-on=execve", "-e", "trace=pwrite64", "-e", "raw=all",
              "-e", "signal=none", "--trace-fds=" + ",".join(map(str, sorted(set(fds))))]
    if inject:
        result += ["-e", "inject=pwrite64:error=EIO:when=1+"]
    return result + ["-p", str(pid)]


class TraceCounts:
    """Reject unknown/truncated output. Never retain pointers, offsets or text."""
    number = r"(?:0x[0-9a-f]+|0)"
    arguments = re.compile(r"^pwrite64\((" + number + r"), " + number + r", " + number + r", " + number + r"\)(.*)$")
    prefix = re.compile(r"^(?:\[pid\s+(\d+)\]\s+|(\d+)\s+)?(.*)$")

    def __init__(self, pid, fds, *, thread_check=None):
        self.pid, self.fds = pid, set(fds)
        self.thread_check = thread_check
        self.buffer, self.pending = b"", set()
        self.writes = self.successful = self.injected_eio = 0

    def summary(self):
        return {"writes": self.writes, "successful": self.successful, "injected_eio": self.injected_eio}

    def feed(self, chunk):
        self.buffer += chunk
        require(len(self.buffer) <= 65536, "trace_buffer_limit")
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            require(0 < len(line) <= 4096, "trace_line_invalid")
            try:
                match = self.prefix.fullmatch(line.decode("ascii"))
            except UnicodeError:
                raise FaultError("trace_encoding_invalid") from None
            require(match is not None, "trace_prefix_invalid")
            tid = int(match[1] or match[2] or self.pid)
            call = match[3]
            if self.thread_check is not None:
                self.thread_check(tid)
            if call.startswith("<... pwrite64 resumed>"):
                require(tid in self.pending, "trace_unpaired_resume")
                self.pending.remove(tid)
                tail = call[len("<... pwrite64 resumed>"):]
                require(tail.startswith(")"), "trace_resume_invalid")
                tail = tail[1:]
            else:
                # strace emits unfinished before the closing parenthesis.
                unfinished = call.endswith(" <unfinished ...>")
                if unfinished:
                    call = call[:-len(" <unfinished ...>")]
                    if not call.endswith(")"):
                        call += ")"
                arguments = self.arguments.fullmatch(call)
                require(arguments is not None and tid not in self.pending, "trace_call_invalid")
                require(int(arguments[1], 16) in self.fds, "trace_wrong_descriptor")
                if unfinished:
                    self.pending.add(tid)
                    continue
                tail = arguments[2]
            tail = tail.strip()
            if re.fullmatch(r"= (?:0x[0-9a-f]+|0)", tail):
                self.successful += 1
            elif tail == "= -1 EIO (Input/output error) (INJECTED)":
                self.injected_eio += 1
            else:
                raise FaultError("trace_result_invalid")
            self.writes += 1
            require(self.writes <= 10000, "trace_count_limit")
        require(len(self.buffer) <= 4096, "trace_line_limit")

    def finish(self):
        require(not self.buffer and not self.pending, "trace_incomplete")
        return self.summary()


def check_counts(counts, inject):
    require(counts["writes"] > 0, "no_database_write_observed")
    require(counts["writes"] == counts["injected_eio" if inject else "successful"]
            and counts["successful" if inject else "injected_eio"] == 0, "write_window_not_uniform")


def check_snapshot(before, after, tracer_pid):
    for key in ("container", "image", "pid", "starttime", "init_pid", "restart_count", "database", "fds"):
        require(before[key] == after[key], "process_or_database_identity_changed")
    require(after["threads"] and all(value[1] == tracer_pid for value in after["threads"].values()),
            "thread_trace_coverage_incomplete")
    previous_threads = {str(tid): value for tid, value in before["threads"].items()}
    for tid, value in after["threads"].items():
        if str(tid) in previous_threads:
            require(value[0] == previous_threads[str(tid)][0], "thread_identity_changed")


def command(argv):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=5, env=ENV, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 1024 * 1024, "local_command_failed")
    return result.stdout


def process_info(pid):
    base = Path("/proc") / str(pid)
    fields = (base / "stat").read_text().rsplit(")", 1)[1].split()
    status = dict(line.split(":", 1) for line in (base / "status").read_text().splitlines() if ":" in line)
    return {"starttime": int(fields[19]), "ppid": int(fields[1]), "tracer": int(status["TracerPid"]),
            "uid": [int(item) for item in status["Uid"].split()], "tgid": int(status["Tgid"])}


def identify(container, image):
    require(re.fullmatch(r"[a-f0-9]{64}", container) and re.fullmatch(r"sha256:[a-f0-9]{64}", image), "container_input_invalid")
    docker = ["docker", "--host", "unix:///var/run/docker.sock"]
    ids = command(docker + ["ps", "-aq", "--no-trunc", "--filter", "label=com.docker.compose.project=cf-filebrowser"]).decode().split()
    require(ids == [container], "project_container_not_unique")
    inspected = json.loads(command(docker + ["inspect", container]))[0]
    labels, state = inspected["Config"]["Labels"], inspected["State"]
    require(inspected["Id"] == container and inspected["Image"] == image
            and labels.get("com.docker.compose.project") == "cf-filebrowser"
            and labels.get("com.docker.compose.service") == "filebrowser-enterprise"
            and state.get("Running") is True and not state.get("Restarting")
            and not state.get("OOMKilled"), "container_identity_invalid")
    init_pid = state["Pid"]
    # init:true runs tini. Its direct child must be the single fixed executable.
    children = (Path("/proc") / str(init_pid) / "task" / str(init_pid) / "children").read_text().split()
    candidates = []
    for child in children:
        pid = int(child)
        if os.readlink(f"/proc/{pid}/exe") == "/home/filebrowser/filebrowser":
            candidates.append(pid)
    require(len(candidates) == 1, "filebrowser_process_not_unique")
    pid = candidates[0]
    proc = process_info(pid)
    require(proc["ppid"] == init_pid and proc["uid"] == [10001] * 4
            and os.stat(f"/proc/{pid}/ns/mnt").st_ino == os.stat(f"/proc/{init_pid}/ns/mnt").st_ino,
            "filebrowser_process_identity_invalid")
    db = DATABASE.lstat()
    require(stat.S_ISREG(db.st_mode) and db.st_nlink == 1 and db.st_uid == db.st_gid == 10001
            and db.st_size > 0, "database_identity_invalid")
    inside = os.stat(f"/proc/{pid}/root/var/lib/filebrowser-enterprise/database.db")
    require(os.path.samestat(db, inside), "container_database_mount_mismatch")
    fds = []
    for entry in Path(f"/proc/{pid}/fd").iterdir():
        try:
            if os.path.samestat(db, entry.stat()):
                fds.append(int(entry.name))
        except FileNotFoundError:
            continue
    require(fds and len(fds) <= 8, "database_descriptors_missing")
    threads = {}
    for entry in Path(f"/proc/{pid}/task").iterdir():
        try:
            info = process_info(int(entry.name))
            threads[int(entry.name)] = [info["starttime"], info["tracer"]]
        except FileNotFoundError:
            continue
    return {"container": container, "image": image, "init_pid": init_pid, "pid": pid,
            "starttime": proc["starttime"], "restart_count": inspected["RestartCount"],
            "database": [db.st_dev, db.st_ino], "fds": sorted(fds), "threads": threads,
            "healthy": state.get("Health", {}).get("Status") == "healthy"}


def trace_thread_guard(before, tracer_pid, detaching):
    starts = {int(tid): value[0] for tid, value in before["threads"].items()}

    def check(tid):
        info = process_info(tid)
        require(info["tgid"] == before["pid"] and info["uid"] == [10001] * 4
                and info["tracer"] in ((tracer_pid, 0) if detaching[0] else (tracer_pid,)), "trace_thread_not_owned")
        if tid in starts:
            require(starts[tid] == info["starttime"], "trace_thread_replaced")
        for fd in before["fds"]:
            opened = os.stat(f"/proc/{tid}/fd/{fd}")
            require([opened.st_dev, opened.st_ino] == before["database"], "trace_thread_fd_changed")
        starts[tid] = info["starttime"]
    return check


def target_snapshot(control):
    require(control.get("version") == 1 and re.fullmatch(r"/cf-audit-fault-[a-f0-9]{12}", control.get("root", "")), "control_invalid")
    directory = FILES / control["root"].lstrip("/")
    before_dir = directory.lstat()
    require(stat.S_ISDIR(before_dir.st_mode) and before_dir.st_uid == before_dir.st_gid == 10001, "target_directory_invalid")
    target = directory / "target.bin"
    before = target.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == before.st_gid == 10001
            and before.st_size == 4096, "target_file_invalid")
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(4097)
        require(os.path.samestat(before, opened) and os.path.samestat(opened, target.lstat())
                and opened.st_size == len(raw) == 4096, "target_identity_changed")
    require(os.path.samestat(before_dir, directory.lstat()), "target_directory_changed")
    names = [entry.name for entry in directory.iterdir()]
    require(all(name == "target.bin" or name.startswith(".filebrowser-write-") for name in names), "target_directory_unexpected_entry")
    return {"size": len(raw), "sha256": digest(raw), "temporary_count": len(names) - 1,
            "inode": [opened.st_dev, opened.st_ino], "directory": [before_dir.st_dev, before_dir.st_ino]}


def pidfd_signal(fd, signum):
    try:
        signal.pidfd_send_signal(fd, signum)
    except ProcessLookupError:
        pass


def detach(process, pidfd):
    if process.poll() is not None:
        return
    pidfd_signal(pidfd, signal.SIGINT)
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pidfd_signal(pidfd, signal.SIGKILL)
        process.wait(timeout=2)


def detach_unregistered_child(process, expected_starttime):
    # Exceptional pidfd-setup failure only. An unreaped direct Popen child
    # cannot have its PID reused; additionally verify parent and starttime.
    if process.poll() is not None:
        return
    current = process_info(process.pid)
    if expected_starttime is None:
        expected_starttime = current["starttime"]
    require(current["ppid"] == os.getpid() and current["starttime"] == expected_starttime, "tracer_child_identity_changed")
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        current = process_info(process.pid)
        require(current["ppid"] == os.getpid() and current["starttime"] == expected_starttime, "tracer_child_identity_changed")
        process.kill()
        process.wait(timeout=2)


def watchdog_due(parent_alive, now, deadline):
    return not parent_alive or now >= deadline


def watchdog(parent_fd, tracer_fd, deadline):
    while True:
        ready, _, _ = select.select([parent_fd, tracer_fd], [], [], min(0.1, max(0, deadline - time.monotonic())))
        if tracer_fd in ready:
            return 0
        if watchdog_due(parent_fd not in ready, time.monotonic(), deadline):
            pidfd_signal(tracer_fd, signal.SIGKILL)
            return 1


def parent_death_guard(parent):
    # No threads exist in this helper when Popen forks. This closes the small
    # gap before the independent watchdog receives the tracer's pidfd.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(127)


def server_window(args):
    control = private_json(args.control_file)
    control_sha = control_digest(control)
    inject = args.mode == "inject"
    report = {"version": 1, "phase": "server", "mode": args.mode, "passed": False, "detached": False,
              "control_sha256": control_sha, "coverage_samples": 0, "failure": None, "stage": "preflight",
              "coverage_limit": "sampled_fd_identity_and_threads_plus_strace_follow; no_transient_file_claim"}
    process = guard = None
    tracer_fd = parent_fd = None
    counts = None
    detaching = [False]
    before = None
    try:
        version = command(["/usr/bin/strace", "--version"]).decode().splitlines()[0]
        require(version == "strace -- version 6.13", "strace_version_mismatch")
        report["strace_version"] = "6.13"
        report["stage"] = "identity"
        before = identify(args.expected_container, args.expected_image)
        require(before["healthy"] and before["threads"] and all(value[1] == 0 for value in before["threads"].values()), "existing_tracer_refused")
        if inject:
            observed = private_json(args.observation_file)
            require(observed.get("passed") is True and observed.get("detached") is True
                    and observed.get("mode") == "observe" and observed.get("control_sha256") == control_sha, "observation_required")
            check_counts(observed["counts"], False)
            # Same process and DB as the successful, observed ordinary PUT.
            check_snapshot(observed["identity"], before, 0)
        original = target_snapshot(control)
        require(original["sha256"] == control["original_sha256"] and original["temporary_count"] == 0, "original_target_required")
        report["target_before"] = original
        for path in (args.ready_file, args.release_file):
            api.protected_path(path, existing=False)
        require(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"), "pidfd_supervision_unavailable")
        parent_fd = os.pidfd_open(os.getpid())
        parent = os.getpid()
        report["stage"] = "attach"
        process = subprocess.Popen(strace_command(before["pid"], before["fds"], inject), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=ENV,
                                   preexec_fn=lambda: parent_death_guard(parent))
        report["tracer_starttime"] = process_info(process.pid)["starttime"]
        tracer_fd = os.pidfd_open(process.pid)
        deadline = time.monotonic() + WINDOW_SECONDS
        guard = subprocess.Popen([sys.executable, "-B", str(Path(__file__).resolve()), "_watchdog",
                                  str(parent_fd), str(tracer_fd), str(deadline + WATCHDOG_SECONDS - WINDOW_SECONDS)],
                                 pass_fds=(parent_fd, tracer_fd), stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, env=ENV)
        counts = TraceCounts(before["pid"], before["fds"],
                             thread_check=trace_thread_guard(before, process.pid, detaching))
        os.set_blocking(process.stderr.fileno(), False)
        ready = False
        nonce = secrets.token_hex(16)
        attach_deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            require(process.poll() is None and guard.poll() is None, "trace_supervisor_ended_early")
            readable, _, _ = select.select([process.stderr], [], [], 0.05)
            if readable:
                raw = os.read(process.stderr.fileno(), 65536)
                require(raw, "trace_pipe_closed_early")
                counts.feed(raw)
            current = identify(args.expected_container, args.expected_image)
            try:
                check_snapshot(before, current, process.pid)
            except FaultError:
                if not ready and time.monotonic() < attach_deadline:
                    continue
                raise
            report["coverage_samples"] += 1
            if not ready:
                # FD/thread sampling cannot prove atomic attach; no request may
                # start until this explicit ready file has been acknowledged.
                api.write_json(Path(args.ready_file), {"version": 1, "ready": True, "mode": args.mode,
                               "nonce": nonce, "control_sha256": control_sha,
                               "container": before["container"], "image": before["image"]})
                ready = True
                report["stage"] = "ready_window"
            if Path(args.release_file).exists():
                require(private_json(args.release_file) == {"version": 1, "nonce": nonce}, "release_identity_invalid")
                report["identity"] = current
                report["stage"] = "release"
                break
        else:
            raise FaultError("trace_window_deadline")
    except (FaultError, api.AcceptanceError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        # Never format caught exceptions, command output, URLs or syscall text.
        report["failure"] = "server_window_rejected"
    finally:
        if process is not None:
            detaching[0] = True
            try:
                if tracer_fd is not None:
                    detach(process, tracer_fd)
                else:
                    detach_unregistered_child(process, report.get("tracer_starttime"))
                # Drain only after strace has exited. No arbitrary stderr is retained.
                while True:
                    chunk = os.read(process.stderr.fileno(), 65536)
                    if not chunk:
                        break
                    if counts is not None:
                        counts.feed(chunk)
                current = identify(args.expected_container, args.expected_image)
                check_snapshot(before, current, 0)
                report["detached"] = True
            except (FaultError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                report["failure"] = "detach_or_final_identity_unverified"
            finally:
                process.stderr.close()
        if guard is not None:
            try:
                guard.wait(timeout=2)
            except subprocess.TimeoutExpired:
                report["failure"] = "watchdog_exit_unverified"
        for fd in (tracer_fd, parent_fd):
            if fd is not None:
                os.close(fd)
    if report["failure"] is None:
        try:
            report["counts"] = counts.finish()
            check_counts(report["counts"], inject)
            report["target_after"] = target_snapshot(control)
            require(report["target_after"]["sha256"] == control["original_sha256"]
                    and report["target_after"]["temporary_count"] == 0, "target_after_window_invalid")
            if inject:
                require(report["target_after"] == report["target_before"], "fault_target_changed")
            report["passed"] = report["detached"] is True
            report["stage"] = "complete"
        except (FaultError, OSError, ValueError, KeyError, TypeError):
            report["failure"] = "window_evidence_rejected"
    return report


def fault_reply(reply):
    require(reply.status == 503 and reply.json() == {"status": 503, "message": "audit unavailable"}, "fault_response_contract")
    request_id = reply.headers.get("x-request-id", "")
    require(re.fullmatch(r"[a-f0-9]{32}", request_id), "fault_request_identity_missing")
    return request_id


class FaultAcceptance(api.Acceptance):
    def items(self, request_id):
        account = self.state["users"]["fault"]
        reply = self.request("fault_audit_query", "GET", "/api/audit", token=self.admin,
                             query={"requestID": request_id, "actor": account["username"],
                                    "source": api.SOURCE, "path": self.state["root"] + "/target.bin",
                                    "action": "file.modify", "limit": "100"}).json()
        require(isinstance(reply, dict) and isinstance(reply.get("items"), list)
                and reply.get("hasMore") is False, "audit_query_not_complete")
        return reply["items"]

    def terminal(self, request_id):
        # Finalization occurs after handler completion; allow only a bounded
        # query of this exact request, never a repeated mutating PUT.
        deadline = time.monotonic() + 5
        while True:
            items = self.items(request_id)
            if items or time.monotonic() >= deadline:
                break
            time.sleep(0.1)
        require(len(items) == 1, "control_terminal_not_unique")
        event = items[0]
        account = self.state["users"]["fault"]
        expected_path = self.state["root"] + "/target.bin"
        require(event.get("requestId") == request_id and event.get("username") == account["username"]
                and event.get("userId") == account["id"] and event.get("source") == api.SOURCE
                and event.get("path") == expected_path and event.get("canonicalPath") == expected_path
                and event.get("action") == "file.modify" and event.get("origin") == "http"
                and event.get("authMethod") == "session" and not event.get("tokenRef") and not event.get("shareRef")
                and event.get("result") == "success" and event.get("httpStatus") == 200
                and not event.get("errorCode") and event.get("metadata", {}).get("schemaVersion") == 1
                and event.get("metadata", {}).get("method") == "PUT"
                and event.get("metadata", {}).get("overwrite") is True, "control_terminal_contract")

    def put(self, content, *, failing=False):
        reply = self.client.request("PUT", "/api/resources", token=self.state["fault"]["session"],
                                    query={"source": api.SOURCE, "path": "/target.bin"}, body=content)
        if failing:
            return fault_reply(reply)
        require(reply.status == 200, "control_put_not_successful")
        request_id = reply.headers.get("x-request-id", "")
        require(re.fullmatch(r"[a-f0-9]{32}", request_id), "control_request_identity_missing")
        self.terminal(request_id)
        return request_id

    def prepare(self):
        self.login_admin()
        self.resource("fault_directory_create", "POST", self.state["root"], self.admin, isDir="true", body=b"")
        grants = {name: name in ("api", "browse", "download", "create", "modify") for name in api.PERMISSIONS}
        session = self.create_user("fault", grants)
        original, attempted = secrets.token_bytes(4096), secrets.token_bytes(4096)
        self.state["fault"] = {"session": session, "original": base64.b64encode(original).decode(),
                               "attempted": base64.b64encode(attempted).decode()}
        self.checkpoint()
        self.resource("fault_target_create", "POST", "/target.bin", session, body=original)
        require(self.download("fault_original_read", "/target.bin", session).body == original, "original_read_mismatch")
        control = {"version": 1, "root": self.state["root"], "original_sha256": digest(original)}
        self.state["fault"]["control_sha256"] = control_digest(control)
        api.write_json(Path(self.args.state_file).with_suffix(".control.json"), control)
        self.state["fault"]["prepared"] = True
        self.checkpoint()

    def ready(self, mode):
        ready = private_json(self.args.ready_file)
        require(ready.get("version") == 1 and ready.get("ready") is True and ready.get("mode") == mode
                and ready.get("control_sha256") == self.state["fault"]["control_sha256"]
                and re.fullmatch(r"[a-f0-9]{32}", ready.get("nonce", "")), "server_not_ready")
        return ready

    def control(self):
        pending = self.state["fault"]
        require(pending.get("prepared") is True and not pending.get("control_complete"), "control_phase_invalid")
        self.ready("observe")
        self.login_admin()
        request_id = self.put(base64.b64decode(pending["attempted"], validate=True))
        require(self.download("control_write_read", "/target.bin", pending["session"]).body
                == base64.b64decode(pending["attempted"], validate=True), "control_bytes_mismatch")
        reset_id = self.put(base64.b64decode(pending["original"], validate=True))
        require(self.download("control_reset_read", "/target.bin", pending["session"]).body
                == base64.b64decode(pending["original"], validate=True), "control_reset_mismatch")
        pending.update(control_complete=True, control_ids=[request_id, reset_id])
        self.checkpoint()

    def fault(self):
        pending = self.state["fault"]
        require(pending.get("control_complete") is True and not pending.get("attempted_fault"), "fault_phase_invalid")
        self.ready("inject")
        pending["attempted_fault"] = True
        self.checkpoint()
        # Exactly one request. No login, audit read or renewed/replaced session.
        pending["request_id"] = self.put(base64.b64decode(pending["attempted"], validate=True), failing=True)
        pending["response_validated"] = True
        self.checkpoint()
        self.check("audit_store_exact_503_response", True)

    def verify(self):
        pending = self.state["fault"]
        require(pending.get("response_validated") is True and not pending.get("verified"), "verify_phase_invalid")
        server = private_json(self.args.server_report)
        require(server.get("passed") is True and server.get("detached") is True
                and server.get("mode") == "inject" and server.get("control_sha256") == pending["control_sha256"], "server_fault_evidence_required")
        check_counts(server["counts"], True)
        restart = private_json(self.args.restart_report)
        require(restart.get("passed") is True and restart.get("phase") == "restarted"
                and restart.get("control_sha256") == pending["control_sha256"]
                and restart.get("prior_identity") == server.get("identity"), "verified_restart_required")
        self.login_admin()
        require(self.download("after_restart_original_read", "/target.bin", pending["session"]).body
                == base64.b64decode(pending["original"], validate=True), "after_restart_original_mismatch")
        require(self.items(pending["request_id"]) == [], "failed_request_became_durable_terminal")
        for request_id in pending["control_ids"]:
            self.terminal(request_id)
        request_id = self.put(base64.b64decode(pending["attempted"], validate=True))
        require(self.download("after_restart_control_read", "/target.bin", pending["session"]).body
                == base64.b64decode(pending["attempted"], validate=True), "after_restart_control_mismatch")
        pending.update(verified=True, following_request_id=request_id)
        self.checkpoint()
        self.check("same_saved_session_write_and_terminal_after_formal_restart", True)
        self.check("failed_request_absent_after_startup_pending_recovery", True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "control", "fault", "verify", "server", "restarted", "detached"))
    parser.add_argument("--url", default="https://files.cf.test:18443")
    parser.add_argument("--ca-file")
    parser.add_argument("--admin-password-file")
    parser.add_argument("--state-file")
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--ready-file")
    parser.add_argument("--release-file")
    parser.add_argument("--control-file")
    parser.add_argument("--server-report")
    parser.add_argument("--restart-report")
    parser.add_argument("--mode", choices=("observe", "inject"))
    parser.add_argument("--observation-file")
    parser.add_argument("--expected-container")
    parser.add_argument("--expected-image")
    args = parser.parse_args(argv)
    require(sys.platform == "linux" and os.geteuid() == 0
            and Path("/etc/hostname").read_text().strip() in ("cf-verification-1", "cf-verification-2"), "isolated_guest_required")
    os.umask(0o077)
    require(args.url == "https://files.cf.test:18443", "isolated_url_required")
    for name in ("ca_file", "admin_password_file", "state_file", "evidence", "ready_file", "release_file",
                 "control_file", "server_report", "restart_report", "observation_file"):
        value = getattr(args, name)
        if value is not None:
            path = Path(value)
            require(path.parent == GUEST and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,100}", path.name), "guest_private_path_required")
    api.protected_path(args.evidence, existing=False)
    report = {"version": 1, "phase": args.phase, "passed": False, "failure": None}
    try:
        if args.phase == "server":
            require(all((args.control_file, args.ready_file, args.release_file, args.mode,
                         args.expected_container, args.expected_image)) and (args.mode != "inject" or args.observation_file), "server_arguments_required")
            report = server_window(args)
        elif args.phase == "detached":
            current = identify(args.expected_container, args.expected_image)
            require(current["threads"] and all(value[1] == 0 for value in current["threads"].values()), "remaining_tracer_detected")
            report.update(passed=True, detached=True, identity=current)
        elif args.phase == "restarted":
            prior = private_json(args.server_report)
            require(prior.get("passed") is True and prior.get("detached") is True and prior.get("mode") == "inject", "prior_fault_required")
            current = identify(args.expected_container, args.expected_image)
            old = prior["identity"]
            require(current["healthy"] and all(value[1] == 0 for value in current["threads"].values())
                    and current["container"] == old["container"] and current["image"] == old["image"]
                    and current["database"] == old["database"]
                    and (current["pid"], current["starttime"]) != (old["pid"], old["starttime"]), "same_image_restart_not_verified")
            report.update(passed=True, control_sha256=prior["control_sha256"], prior_identity=old, identity=current)
        else:
            require(all((args.ca_file, args.admin_password_file, args.state_file)), "client_arguments_required")
            if args.phase == "prepare":
                identifier = secrets.token_hex(6)
                state = {"version": 1, "id": identifier, "source": api.SOURCE, "root": "/cf-audit-fault-" + identifier,
                         "users": {}, "files": {}, "tokens": {}, "shares": {}}
                api.write_json(Path(args.state_file), state)
            else:
                state = private_json(args.state_file)
                require(state.get("version") == 1 and state.get("source") == api.SOURCE, "client_state_invalid")
            client = api.Client(args.url, api.protected_path(args.ca_file))
            test = FaultAcceptance(client, args, state)
            getattr(test, args.phase)()
            report.update(passed=True, requests=client.requests, checks=test.checks)
    except (FaultError, api.AcceptanceError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        report["failure"] = "fault_probe_rejected"
    api.write_json(Path(args.evidence), report)
    print(json.dumps({"phase": args.phase, "passed": report["passed"], "failure": report["failure"]}, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "_watchdog":
        raise SystemExit(watchdog(int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])))
    try:
        raise SystemExit(main())
    except (FaultError, api.AcceptanceError, OSError, ValueError, KeyError, TypeError):
        print('{"passed":false,"failure":"fault_probe_configuration_rejected"}')
        raise SystemExit(2)
