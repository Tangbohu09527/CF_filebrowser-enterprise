"""Official Hermes execution middleware for Gateway-authorized work copies.

Only framework session/task identifiers enter the control client. A resolve,
event connection and worker belong to one immutable process/nonce owner. Failed
or ended scopes stay tombstoned; neither model retries nor a new tool call can
obtain another worker or a renewed download budget.
"""
from __future__ import annotations

import atexit
from contextlib import contextmanager
from contextvars import ContextVar
import json
import logging
import re
import secrets
import threading
import time

from .inbound import BridgeError, HostBridge, failure


_DOWNLOAD = "filebrowser_download_inbound"
_IDENTIFIER = re.compile(r"[A-Za-z0-9_:-]{1,128}\Z")
_TOOL_NAME = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_MAX_SCOPES = 4096
_JOIN_SECONDS = 5.0
_LOGGER = logging.getLogger("cf_filebridge.inbound_host")
_DIAGNOSTIC_STAGES = frozenset({
    "register_config", "register_bridge", "register_client", "register_adapter", "register",
    "register_middleware", "register_hook", "register_unload", "register_handles", "register_success",
    "scope", "scope_active", "activate", "next_call", "resolve", "owner_checks", "lease",
    "events", "snapshot", "worker", "events_stream", "cleanup", "internal",
})
_DIAGNOSTIC_REASONS = frozenset({
    "ok", "trusted_context_unavailable", "trusted_context_invalid", "trusted_context_conflict",
    "task_cancelled", "deadline_exceeded", "host_control_rejected", "host_control_unavailable",
    "host_events_lost", "task_directory_unavailable", "client_inventory_invalid", "client_digest_mismatch",
    "invalid_client_response", "integrity_failed", "invalid_handle", "permission_error", "timeout",
    "os_error", "value_error", "type_error", "unexpected_error",
})


def _diagnostic(stage, error=None, *, scope=None, identifiers=None):
    """Fixed fields only; telemetry must never alter authorization or cleanup.

    Correlation comes only from a resolved host scope, never tool arguments.
    Raw identifiers, exception strings, paths and control replies are excluded.
    """
    try:
        stage = stage if type(stage) is str and stage in _DIAGNOSTIC_STAGES else "internal"
        reason = "ok"
        if isinstance(error, BridgeError):
            code = error.code
            reason = code if type(code) is str and code in _DIAGNOSTIC_REASONS else "unexpected_error"
        elif error is not None:
            reason = ("permission_error" if isinstance(error, PermissionError) else
                      "timeout" if isinstance(error, TimeoutError) else
                      "os_error" if isinstance(error, OSError) else
                      "value_error" if isinstance(error, ValueError) else
                      "type_error" if isinstance(error, TypeError) else "unexpected_error")
        dispatch_id = attachment_id = None
        resolved = scope.resolved if scope is not None else None
        if resolved is not None:
            value = getattr(resolved, "dispatch_id", None)
            if type(value) is int and 0 < value < 2**63:
                dispatch_id = value
            binding = resolved.worker_binding
            attachments = binding.get("attachments") if type(binding) is dict else None
            if type(attachments) is list and len(attachments) == 1 and type(attachments[0]) is dict:
                value = attachments[0].get("attachment_id")
                if type(value) is int and 0 < value < 2**63:
                    attachment_id = value
        present_session = present_task = valid = equal = None
        if identifiers is not None:
            session, task = identifiers
            present_session = isinstance(session, str) and bool(session)
            present_task = isinstance(task, str) and bool(task)
            valid = _valid_identifier(session) and _valid_identifier(task)
            equal = valid and task == session
        emit = _LOGGER.info if error is None else _LOGGER.warning
        emit("cf_filebridge_inbound_diagnostic_v1 stage=%s reason=%s dispatch_id=%s attachment_id=%s "
             "session_present=%s task_present=%s identifiers_valid=%s task_equals_session=%s",
             stage, reason, dispatch_id, attachment_id, present_session, present_task, valid, equal)
    except BaseException:
        # A broken handler/formatter must not change the original result.
        pass
_active_host = ContextVar("cf_filebridge_authorized_host", default=None)
_active_tool = ContextVar("cf_filebridge_authorized_tool", default=None)


def authorized_remaining_seconds():
    """Remaining authority for a consumer, never a fresh processing budget.

    Read only the middleware-bound scope. Tool kwargs, prompts and copied
    contexts cannot extend the original Gateway lease or revive an ended task.
    """
    active = _active_host.get()
    if active is None:
        raise BridgeError("trusted_context_unavailable")
    adapter, scope = active
    with scope.lock:
        if scope.stopped.is_set() or not scope.started or scope.resolved is None:
            raise BridgeError("task_cancelled")
        remaining = scope.resolved.deadline_monotonic - time.monotonic()
        dispatch_id = scope.resolved.worker_binding["dispatch_id"]
    with adapter.bridge._lock:
        dispatch = adapter.bridge._dispatches.get(dispatch_id)
    if remaining <= 0 or dispatch is None or dispatch.stopped.is_set():
        raise BridgeError("task_cancelled")
    return remaining


def ensure_active():
    """Reject consumer results when authority ended during parsing/vision."""
    authorized_remaining_seconds()


def capture_return_context(attachment_id):
    return _capture_context(attachment_id, "filebrowser_read_inbound")


def capture_product_inbound_context(attachment_id):
    return _capture_context(attachment_id, "filebrowser_ingest_product_zip")


def _capture_context(attachment_id, allowed_tool):
    """Capture the current reader's identity and original, non-renewable lease.

    This is an internal API, never model input. The returned guard remains tied
    to these exact objects when the return plugin checks it in a later tool call.
    """
    active, tool = _active_host.get(), _active_tool.get()
    if (active is None or tool is None or tool[0] != allowed_tool
            or not _valid_identifier(tool[1]) or type(attachment_id) is not int or attachment_id <= 0):
        raise BridgeError("trusted_context_unavailable")
    adapter, scope = active
    with scope.lock:
        resolved = scope.resolved
        if resolved is None or scope.stopped.is_set() or not scope.started:
            raise BridgeError("task_cancelled")
        deadline = resolved.deadline_monotonic
        dispatch_id = resolved.worker_binding["dispatch_id"]
        attachments = resolved.worker_binding["attachments"]
        if len(attachments) != 1 or attachments[0]["attachment_id"] != attachment_id:
            raise BridgeError("trusted_context_invalid")
        filename = attachments[0]["filename"]
        binding = {name: getattr(resolved, name) for name in (
            "dispatch_id", "message_id", "enterprise_identity_id", "thread_id",
            "profile_reference", "profile_revision", "session_id", "task_id")}
        binding["turn_id"] = tool[1]
    with adapter.bridge._lock:
        dispatch = adapter.bridge._dispatches.get(dispatch_id)

    def check_active():
        with scope.lock:
            if (scope.stopped.is_set() or not scope.started or scope.resolved is not resolved
                    or resolved.deadline_monotonic != deadline or time.monotonic() >= deadline):
                raise BridgeError("task_cancelled")
        with adapter.bridge._lock:
            if (dispatch is None or dispatch.stopped.is_set()
                    or adapter.bridge._dispatches.get(dispatch_id) is not dispatch):
                raise BridgeError("task_cancelled")

    check_active()
    return binding, filename, check_active


class _Scope:
    def __init__(self, session_id, task_id):
        self.session_id = session_id
        self.task_id = task_id
        self.nonce = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        # Serialize worker creation with teardown, without blocking cancellation
        # from setting stopped or interrupting the event socket.
        self.start_lock = threading.RLock()
        self.stopped = threading.Event()
        self.ready = threading.Event()
        self.snapshot = threading.Event()
        self.finished = threading.Event()
        self.setup_finished = threading.Event()
        self.calls_finished = threading.Event()
        self.calls_finished.set()
        self.active_calls = 0
        self.resolved = None
        self.stream = None
        self.event_thread = None
        self.timer = None
        self.terminating = False
        self.started = False
        self.error = "trusted_context_unavailable"


def _valid_identifier(value):
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


@contextmanager
def open_workcopy(handle):
    """Read a verified handle from an explicitly allowed downstream tool.

    The caller must run inside this adapter's official tool_execution scope.
    No path, descriptor, or credential is exposed to the model. Lease/revoke/end
    closes the returned stream through the existing HostBridge.
    """
    active = _active_host.get()
    if active is None:
        raise BridgeError("trusted_context_unavailable")
    adapter, scope = active
    if scope.stopped.is_set():
        raise BridgeError("task_cancelled")
    with adapter.bridge.open_workcopy(handle) as stream:
        if scope.stopped.is_set():
            raise BridgeError("task_cancelled")
        yield stream


class HostAdapter:
    """Own bindings obtained from a fixed authenticated Gateway control client.

    ``control`` validates the fixed v1 schema, origins, owner, sequence and lease.
    ``bridge`` is the existing native-worker bridge, not a second downloader.
    Neither dependency is supplied by model arguments or ordinary handler kwargs.
    """

    def __init__(self, control, bridge, *, downstream_tools=()):
        names = tuple(downstream_tools)
        if any(not isinstance(name, str) or not _TOOL_NAME.fullmatch(name) for name in names):
            raise BridgeError("trusted_context_invalid")
        self.control = control
        self.bridge = bridge
        self.host_instance_id = secrets.token_urlsafe(32)
        self._tools = frozenset((_DOWNLOAD, *names))
        self._lock = threading.Lock()
        self._scopes = {}
        self._ended_sessions = set()
        self._budget_owners = {}
        self._binding_owners = {}
        self._closed = False
        self._registered = False
        self._registrations = []
        atexit.register(self.close)

    def register(self, ctx):
        """Use only the public PluginContext lifecycle/extension methods."""
        with self._lock:
            if self._closed or self._registered:
                raise BridgeError("trusted_context_invalid")
            self._registered = True
        stage = "register_middleware"
        try:
            self._registrations.append(ctx.register_middleware("tool_execution", self.middleware))
            stage = "register_hook"
            self._registrations.append(ctx.register_hook("on_session_end", self.on_session_end))
            stage = "register_unload"
            self._registrations.append(ctx.on_unload(self.close))
            stage = "register_handles"
            if any(registration is None for registration in self._registrations):
                raise BridgeError("trusted_context_unavailable")
        except Exception as exc:
            _diagnostic(stage, exc)
            self.close()
            for registration in reversed(self._registrations):
                if registration is not None:
                    try:
                        registration.dispose()
                    except Exception:
                        pass
            raise BridgeError("trusted_context_unavailable") from None
        _diagnostic("register_success")
        return self

    def _scope(self, session_id, task_id):
        # This protocol pins the official API path where task == session. Do not
        # guess missing values, follow a session tip, or accept model task_context.
        if not _valid_identifier(session_id) or not _valid_identifier(task_id) or task_id != session_id:
            raise BridgeError("trusted_context_invalid")
        key = (session_id, task_id)
        with self._lock:
            if self._closed or session_id in self._ended_sessions:
                raise BridgeError("task_cancelled")
            scope = self._scopes.get(key)
            first = scope is None
            if first:
                # Never evict tombstones to admit fresh nonces after failures.
                if len(self._scopes) + len(self._ended_sessions) >= _MAX_SCOPES:
                    raise BridgeError("trusted_context_unavailable")
                scope = _Scope(session_id, task_id)
                self._scopes[key] = scope
        if first:
            self._initialize(scope)
        else:
            scope.ready.wait()
        with scope.lock:
            if scope.stopped.is_set() or not scope.started:
                raise BridgeError(scope.error)
        return scope

    def _initialize(self, scope):
        failed = False
        stage = "resolve"
        try:
            if scope.stopped.is_set():
                raise BridgeError("task_cancelled")
            resolved = self.control.resolve(scope.session_id, scope.task_id,
                                            self.host_instance_id, scope.nonce)
            with scope.lock:
                scope.resolved = resolved
            stage = "owner_checks"
            # Even a trusted control implementation cannot create a second
            # budget/worker for a previously consumed binding in this process.
            with self._lock:
                if (resolved.budget_scope in self._budget_owners
                        or resolved.binding_id in self._binding_owners):
                    raise BridgeError("trusted_context_conflict")
                self._budget_owners[resolved.budget_scope] = scope
                self._binding_owners[resolved.binding_id] = scope
            stage = "lease"
            remaining = resolved.deadline_monotonic - time.monotonic()
            if scope.stopped.is_set() or remaining <= 0:
                raise BridgeError("task_cancelled")
            timer = threading.Timer(remaining, self._terminate, args=(scope,))
            timer.daemon = True
            with scope.lock:
                scope.timer = timer
            timer.start()
            stage = "events"
            stream = self.control.events(resolved)
            with scope.lock:
                scope.stream = stream
                stopped = scope.stopped.is_set()
            if stopped:
                stream.close()
                raise BridgeError("task_cancelled")
            thread = threading.Thread(target=self._events, args=(scope,), daemon=True,
                                      name="cf-inbound-lease")
            with scope.lock:
                scope.event_thread = thread
            thread.start()
            stage = "snapshot"
            scope.snapshot.wait(max(0, resolved.deadline_monotonic - time.monotonic()))
            with scope.start_lock:
                if (not scope.snapshot.is_set() or scope.stopped.is_set()
                        or time.monotonic() >= resolved.deadline_monotonic):
                    raise BridgeError("task_cancelled")
                stage = "worker"
                self.bridge.start_dispatch(resolved.worker_binding)
                with scope.lock:
                    scope.started = not scope.stopped.is_set()
                if scope.stopped.is_set():
                    raise BridgeError("task_cancelled")
        except Exception as exc:
            _diagnostic(stage, exc, scope=scope)
            failed = True
        finally:
            scope.setup_finished.set()
            scope.ready.set()
        if failed:
            self._terminate(scope)

    def _events(self, scope):
        try:
            for state in scope.stream:
                if scope.stopped.is_set() or state != "running":
                    break
                if time.monotonic() >= scope.resolved.deadline_monotonic:
                    break
                scope.snapshot.set()
                # Repeated snapshots intentionally do not alter the timer.
        except Exception as exc:
            _diagnostic("events_stream", exc, scope=scope)
        finally:
            self._terminate(scope)

    def _terminate(self, scope):
        with scope.lock:
            if scope.terminating:
                return
            scope.terminating = True
            scope.stopped.set()
            scope.error = "task_cancelled"
            scope.snapshot.set()
            scope.ready.set()
            stream = scope.stream
            timer = scope.timer
        if timer is not None:
            timer.cancel()
        if stream is not None:
            try:
                stream.close()
            except Exception:
                pass
        joined = False
        try:
            # An end hook can race a bounded resolve/events request. Wait until
            # its result has been accounted for before collecting resources or
            # ACKing; the initializer observes stopped and cannot create a worker.
            setup_done = scope.setup_finished.wait(_JOIN_SECONDS)
            with scope.lock:
                late_stream = scope.stream
            if late_stream is not None and late_stream is not stream:
                late_stream.close()
            # start_lock prevents a cancellation racing initial worker creation
            # from acknowledging closed while a late worker is still starting.
            with scope.start_lock:
                resolved = scope.resolved
                if resolved is not None:
                    joined = self.bridge.end_dispatch(resolved.worker_binding["dispatch_id"]) is True
                else:
                    joined = True
                joined = joined and setup_done
            # Existing HostBridge closes processing streams and joins the worker.
            # Do not ACK a downstream callback still running after cancellation.
            joined = joined and scope.calls_finished.wait(_JOIN_SECONDS)
            thread = scope.event_thread
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=_JOIN_SECONDS)
                joined = joined and not thread.is_alive()
            if joined and resolved is not None:
                self.control.closed(resolved)
        except Exception as exc:
            _diagnostic("cleanup", exc, scope=scope)
            # ACK has one bounded attempt. A lost response cannot recreate the
            # binding, reconnect events, or claim a fresh download budget.
            pass
        finally:
            scope.finished.set()

    def middleware(self, tool_name, args, next_call, task_id=None, session_id=None, turn_id=None, **_context):
        if tool_name not in self._tools:
            return next_call(args)
        if tool_name == "cf_return_current_chat":
            # Returning an ordinary generated file must not create an inbound
            # binding. Staged inbound files retain their original guard in the
            # return plugin; an existing host scope still takes the checks below.
            with self._lock:
                existing = self._scopes.get((session_id, task_id))
            if existing is None:
                return next_call(args)
        scope = None
        entered = False
        failed = False
        stage = "scope"
        try:
            scope = self._scope(session_id, task_id)
            stage = "scope_active"
            with scope.lock:
                if scope.stopped.is_set() or time.monotonic() >= scope.resolved.deadline_monotonic:
                    raise BridgeError("task_cancelled")
                scope.active_calls += 1
                scope.calls_finished.clear()
                entered = True
            stage = "activate"
            with self.bridge.activate(scope.resolved.worker_binding["dispatch_id"]):
                token = _active_host.set((self, scope))
                tool_token = _active_tool.set((tool_name, turn_id))
                try:
                    stage = "next_call"
                    result = next_call(args)
                    if scope.stopped.is_set():
                        return json.dumps(failure("task_cancelled"))
                    return result
                finally:
                    _active_tool.reset(tool_token)
                    _active_host.reset(token)
        except Exception as exc:
            _diagnostic(stage, exc, scope=scope, identifiers=(session_id, task_id))
            failed = True
            # Official middleware skips callbacks that throw before next_call.
            # Return an explicit denial so an auth/control failure cannot fall
            # through. The handler independently retains its unbound denial.
            return json.dumps(failure("trusted_context_unavailable"))
        finally:
            if entered:
                with scope.lock:
                    scope.active_calls -= 1
                    if scope.active_calls == 0:
                        scope.calls_finished.set()
            if failed and scope is not None:
                self._terminate(scope)

    def on_session_end(self, session_id=None, task_id=None, **_context):
        # Best-effort official hook supplements (never replaces) events/lease.
        if not _valid_identifier(session_id):
            session_id = task_id
        if not _valid_identifier(session_id):
            return
        with self._lock:
            if len(self._ended_sessions) < _MAX_SCOPES:
                self._ended_sessions.add(session_id)
            scopes = [scope for (session, _task), scope in self._scopes.items()
                      if session == session_id]
        for scope in scopes:
            self._terminate(scope)

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            scopes = list(self._scopes.values())
        # Revoke every local scope before joining any one child. Closing each
        # event socket also wakes its existing cleanup thread; a slow consumer
        # must not leave other scopes downloading during host shutdown.
        for scope in scopes:
            with scope.lock:
                scope.stopped.set()
                scope.error = "task_cancelled"
                scope.snapshot.set()
                scope.ready.set()
                stream = scope.stream
            if stream is not None:
                try:
                    stream.close()
                except Exception:
                    pass
        for scope in scopes:
            self._terminate(scope)
        # Idempotently retain HostBridge's own attachment/Dispatch tombstones.
        self.bridge.close()
        atexit.unregister(self.close)


def register_host(ctx):
    """Optional host wiring; invalid opt-in never disables the existing tools."""
    stage = "register_config"
    try:
        if ctx.get_config("inbound_host_enabled", False) is not True:
            return None
        from .inbound_control import ControlClient, HostConfig
        config = HostConfig.from_context(ctx)
        stage = "register_bridge"
        bridge = HostBridge(config.client_path, config.client_sha256)
        stage = "register_client"
        control = ControlClient(config)
        stage = "register_adapter"
        adapter = HostAdapter(control, bridge, downstream_tools=config.consumer_tools)
        stage = "register"
        return adapter.register(ctx)
    except Exception as exc:
        _diagnostic(stage, exc)
        # Registration/configuration failure leaves the existing download handler
        # unbound (fail closed), while read-only/approved-create tools keep working.
        return None
