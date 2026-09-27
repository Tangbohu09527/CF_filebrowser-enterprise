"""Host-only Dispatch bridge to the isolated inbound download worker.

Nothing in this module derives authority from model arguments, handler kwargs
or prompt text. Authenticated metadata can carry authority, but must first be
verified and bound to the actual execution. Official tool_execution middleware
can scope activate(); the missing Gateway handoff is documented separately.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import stat
import subprocess
import threading
import time

_active_dispatch = ContextVar("cf_filebridge_inbound_dispatch", default=None)
_MAX_FRAME = 1024 * 1024


def failure(code):
    return {"ok": False, "error": {"code": code, "retryable": False}}


class BridgeError(Exception):
    """Only a fixed non-sensitive code may leave the bridge."""

    def __init__(self, code="inbound_unavailable"):
        self.code = code
        super().__init__(code)


def _client(raw, expected):
    if not isinstance(raw, str) or not Path(raw).is_absolute():
        raise BridgeError("client_inventory_invalid")
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise BridgeError("client_inventory_invalid")
    path = Path(raw)
    try:
        for part in (path, *path.parents):
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise BridgeError("client_inventory_invalid")
        if not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
            raise BridgeError("client_inventory_invalid")
        with path.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != expected:
            raise BridgeError("client_digest_mismatch")
    except BridgeError:
        raise
    except Exception:
        raise BridgeError("client_inventory_invalid") from None
    return path


class _Dispatch:
    def __init__(self, executable, binding):
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.responses = queue.Queue(maxsize=4)
        self.files_lock = threading.Lock()
        self.files = set()
        self.process = None
        self.binding_digest = hashlib.sha256(binding).digest()
        environment = {k: v for k, v in os.environ.items() if k.upper() not in {
            "FILEBROWSER_AGENT_TOKEN", "SSLKEYLOGFILE", "HTTP_PROXY", "HTTPS_PROXY",
            "ALL_PROXY", "FTP_PROXY", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
        }}
        try:
            self.process = subprocess.Popen(
                [str(executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, shell=False, env=environment,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            threading.Thread(target=self._read_responses, daemon=True).start()
            self.process.stdin.write(binding + b"\n")
            self.process.stdin.flush()
            response = self._wait(5)
            if response.get("ok") is not True:
                raise BridgeError("trusted_context_invalid")
        except Exception:
            self.stop()
            raise BridgeError("trusted_context_invalid") from None

    def _read_responses(self):
        try:
            while True:
                line = self.process.stdout.readline(_MAX_FRAME + 1)
                if not line or len(line) > _MAX_FRAME or not line.endswith(b"\n"):
                    break
                answer = json.loads(line)
                if not isinstance(answer, dict) or type(answer.get("ok")) is not bool:
                    break
                self.responses.put_nowait(answer)
        except Exception:
            pass
        finally:
            # EOF never allows an automatic worker restart with a fresh budget.
            try:
                self.responses.put_nowait(None)
            except queue.Full:
                pass
            # Lease expiry also terminates an idle native worker. Revoke Python
            # processing streams when its pipe closes, even without another call.
            self.stop()

    def _wait(self, seconds):
        deadline = time.monotonic() + seconds
        while not self.stopped.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.stop()
                raise BridgeError("deadline_exceeded")
            try:
                answer = self.responses.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                continue
            if answer is None:
                self.stop()
                raise BridgeError()
            if self.stopped.is_set():
                raise BridgeError("task_cancelled")
            return answer
        raise BridgeError("task_cancelled")

    def request(self, command):
        # One worker and one lock per authoritative Dispatch. Repeated/concurrent
        # model calls reach the same engine ledger; they never start new workers.
        with self.lock:
            if self.stopped.is_set():
                raise BridgeError("task_cancelled")
            try:
                encoded = json.dumps(command, allow_nan=False, separators=(",", ":")).encode()
                self.process.stdin.write(encoded + b"\n")
                self.process.stdin.flush()
                return self._wait(32)
            except BridgeError:
                raise
            except Exception:
                self.stop()
                raise BridgeError() from None

    def stop(self):
        # Does not acquire request.lock: end/cancel must interrupt an in-flight
        # HTTPS read, not wait until it returns. EOF is the worker revoke signal.
        self.stopped.set()
        with self.files_lock:
            for stream in list(self.files):
                try:
                    stream.close()
                except Exception:
                    pass
            self.files.clear()
        if self.process is None:
            return
        try:
            self.process.stdin.close()
        except Exception:
            pass
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        finally:
            if self.process.stdout:
                self.process.stdout.close()


class HostBridge:
    """Called ONLY by the authenticated host, never exposed as a model tool.

    The host owns ingress authentication, lease/end/cancel propagation and
    ContextVar propagation to tool execution threads. A process restart must
    revoke old Dispatches, not reconstruct them with refreshed download budgets.
    """

    def __init__(self, client_path, client_sha256):
        self.client_path = client_path
        self.client_sha256 = client_sha256
        self._lock = threading.Lock()
        self._dispatches = {}
        self._attachment_owners = {}

    def start_dispatch(self, binding):
        try:
            encoded = json.dumps(binding, allow_nan=False, separators=(",", ":")).encode()
            dispatch_id = binding["dispatch_id"]
            task_id = binding["task_id"]
            if not isinstance(dispatch_id, str) or not dispatch_id or not isinstance(task_id, str) or not task_id:
                raise ValueError()
            if len(encoded) > _MAX_FRAME:
                raise ValueError()
            pairs = [(task_id, item["attachment_id"]) for item in binding["attachments"]]
            if not pairs or any(type(pair[1]) is not int or pair[1] <= 0 for pair in pairs):
                raise ValueError()
        except Exception:
            raise BridgeError("trusted_context_invalid") from None
        with self._lock:
            if dispatch_id in self._dispatches:
                existing = self._dispatches[dispatch_id]
                if existing is None or existing.stopped.is_set():
                    raise BridgeError("task_cancelled")
                if existing.binding_digest != hashlib.sha256(encoded).digest():
                    raise BridgeError("trusted_context_conflict")
                return
            if any(pair in self._attachment_owners for pair in pairs):
                raise BridgeError("trusted_context_conflict")
            # Tombstones survive failure/end for this host lifetime. No retries of
            # failed initialization or new Dispatch IDs can renew the same task.
            self._dispatches[dispatch_id] = None
            for pair in pairs:
                self._attachment_owners[pair] = dispatch_id
            executable = _client(self.client_path, self.client_sha256)
            self._dispatches[dispatch_id] = _Dispatch(executable, encoded)

    @contextmanager
    def activate(self, dispatch_id):
        with self._lock:
            dispatch = self._dispatches.get(dispatch_id)
        if dispatch is None or dispatch.stopped.is_set():
            raise BridgeError("trusted_context_unavailable")
        token = _active_dispatch.set(dispatch)
        try:
            yield
        finally:
            _active_dispatch.reset(token)

    def end_dispatch(self, dispatch_id):
        with self._lock:
            dispatch = self._dispatches.get(dispatch_id)
            self._dispatches[dispatch_id] = None
        if dispatch is not None:
            dispatch.stop()

    def close(self):
        with self._lock:
            identifiers = list(self._dispatches)
        for dispatch_id in identifiers:
            self.end_dispatch(dispatch_id)

    def resolve_workcopy(self, handle):
        """Host processing API. Internal paths must never be forwarded to chat.

        The worker validates the active Dispatch, handle and on-disk integrity.
        Native Go processing tools can instead consume Engine.Resolve's open file.
        """
        dispatch = _active_dispatch.get()
        if dispatch is None:
            raise BridgeError("trusted_context_unavailable")
        if not isinstance(handle, str) or not handle or len(handle) > 256:
            raise BridgeError("invalid_handle")
        result = dispatch.request({"op": "resolve", "handle": handle})
        if result.get("ok") is not True:
            raise BridgeError("invalid_handle")
        return result

    @contextmanager
    def open_workcopy(self, handle):
        """Give an authorized downstream tool a real, verified read-only stream.

        The native worker retains its Windows read handle until Dispatch end,
        denying file replacement/writes. Consumers must remain inside this
        context and treat content as untrusted. End/cancel closes these streams.
        """
        dispatch = _active_dispatch.get()
        receipt = self.resolve_workcopy(handle)
        stream = None
        try:
            path = Path(receipt["path"])
            if not path.is_absolute():
                raise BridgeError("invalid_handle")
            for part in (path, *path.parents):
                info = part.lstat()
                if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                    raise BridgeError("invalid_handle")
            before = path.stat()
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
            stream = os.fdopen(descriptor, "rb")
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened) or opened.st_size != receipt["bytes_written"]:
                raise BridgeError("integrity_failed")
            digest = hashlib.sha256()
            while True:
                if dispatch.stopped.is_set():
                    raise BridgeError("task_cancelled")
                block = stream.read(64 * 1024)
                if not block:
                    break
                digest.update(block)
            if digest.hexdigest() != receipt["sha256"]:
                raise BridgeError("integrity_failed")
            stream.seek(0)
            with dispatch.files_lock:
                if dispatch.stopped.is_set():
                    raise BridgeError("task_cancelled")
                dispatch.files.add(stream)
            yield stream
        except BridgeError:
            raise
        except Exception:
            raise BridgeError("invalid_handle") from None
        finally:
            if stream is not None:
                with dispatch.files_lock:
                    dispatch.files.discard(stream)
                stream.close()


def _public_result(response):
    """Keep the private worker protocol separate from model-visible output."""
    if response.get("ok") is not True:
        allowed = {"not_authorized", "temporarily_unavailable", "deadline_exceeded",
                   "integrity_failed", "task_cancelled", "transport_failed",
                   "response_rejected", "invalid_descriptor", "storage_failed"}
        code = response.get("error", {}).get("code")
        return failure(code if code in allowed else "inbound_unavailable")
    fields = {"ok", "handle", "bytes_written", "sha256", "verified", "formal_archive",
              "dispatch_id", "task_id", "declared_quality", "original_comparison"}
    if (set(response) != fields or response.get("verified") is not True
            or response.get("formal_archive") is not False
            or type(response.get("bytes_written")) is not int or response["bytes_written"] < 1
            or not re.fullmatch(r"inbound:[0-9a-f]{48}", response.get("handle", ""))
            or not re.fullmatch(r"[0-9a-f]{64}", response.get("sha256", ""))
            or response.get("declared_quality") not in (None, "full", "standard", "thumbnail")
            or response.get("original_comparison") not in ("not_checked", "match", "different")):
        raise BridgeError("invalid_client_response")
    return response


def handler_for(ctx):
    def handle(args, **_untrusted_execution_hints):
        if not isinstance(args, dict) or set(args) != {"attachment_id"} or type(args.get("attachment_id")) is not int or args["attachment_id"] <= 0:
            return json.dumps(failure("invalid_tool_input"))
        if ctx.get_config("inbound_enabled", False) is not True:
            return json.dumps(failure("inbound_disabled"))
        dispatch = _active_dispatch.get()
        if dispatch is None:
            return json.dumps(failure("trusted_context_unavailable"))
        try:
            return json.dumps(_public_result(dispatch.request({"op": "download", "attachment_id": args["attachment_id"]})), ensure_ascii=True)
        except BridgeError as error:
            return json.dumps(failure(error.code))
        except Exception:
            return json.dumps(failure("inbound_unavailable"))
    return handle


def register_inbound(ctx):
    ctx.register_tool(
        name="filebrowser_download_inbound", toolset="cf_filebridge_inbound",
        schema={"name": "filebrowser_download_inbound", "description": (
            "Download a host-authorized inbound attachment to a private task working copy. "
            "Requires a live trusted Dispatch supplied by the host. Success means bytes were "
            "saved and verified, never formal archival or proof of original-image quality. "
            "Accepts only the attachment ID already authorized for the current Dispatch; "
            "no task context, URL, token, local path or shell commands."
        ), "parameters": {"type": "object", "additionalProperties": False,
            "required": ["attachment_id"], "properties": {
                "attachment_id": {"type": "integer", "minimum": 1},
            }}},
        handler=handler_for(ctx), description="Verified task working-copy download", override=False,
    )
