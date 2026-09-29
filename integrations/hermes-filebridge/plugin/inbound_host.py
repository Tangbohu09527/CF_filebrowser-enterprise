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
_active_host = ContextVar("cf_filebridge_authorized_host", default=None)


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
        try:
            self._registrations.append(ctx.register_middleware("tool_execution", self.middleware))
            self._registrations.append(ctx.register_hook("on_session_end", self.on_session_end))
            self._registrations.append(ctx.on_unload(self.close))
            if any(registration is None for registration in self._registrations):
                raise BridgeError("trusted_context_unavailable")
        except Exception:
            self.close()
            for registration in reversed(self._registrations):
                if registration is not None:
                    try:
                        registration.dispose()
                    except Exception:
                        pass
            raise BridgeError("trusted_context_unavailable") from None
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
        try:
            if scope.stopped.is_set():
                raise BridgeError("task_cancelled")
            resolved = self.control.resolve(scope.session_id, scope.task_id,
                                            self.host_instance_id, scope.nonce)
            with scope.lock:
                scope.resolved = resolved
            # Even a trusted control implementation cannot create a second
            # budget/worker for a previously consumed binding in this process.
            with self._lock:
                if (resolved.budget_scope in self._budget_owners
                        or resolved.binding_id in self._binding_owners):
                    raise BridgeError("trusted_context_conflict")
                self._budget_owners[resolved.budget_scope] = scope
                self._binding_owners[resolved.binding_id] = scope
            remaining = resolved.deadline_monotonic - time.monotonic()
            if scope.stopped.is_set() or remaining <= 0:
                raise BridgeError("task_cancelled")
            timer = threading.Timer(remaining, self._terminate, args=(scope,))
            timer.daemon = True
            with scope.lock:
                scope.timer = timer
            timer.start()
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
            scope.snapshot.wait(max(0, resolved.deadline_monotonic - time.monotonic()))
            with scope.start_lock:
                if (not scope.snapshot.is_set() or scope.stopped.is_set()
                        or time.monotonic() >= resolved.deadline_monotonic):
                    raise BridgeError("task_cancelled")
                self.bridge.start_dispatch(resolved.worker_binding)
                with scope.lock:
                    scope.started = not scope.stopped.is_set()
                if scope.stopped.is_set():
                    raise BridgeError("task_cancelled")
        except Exception:
            # Fixed output only: control response bodies, headers and exceptions
            # are never forwarded to Hermes telemetry or the model.
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
        except Exception:
            pass
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
        except Exception:
            # ACK has one bounded attempt. A lost response cannot recreate the
            # binding, reconnect events, or claim a fresh download budget.
            pass
        finally:
            scope.finished.set()

    def middleware(self, tool_name, args, next_call, task_id=None, session_id=None, **_context):
        if tool_name not in self._tools:
            return next_call(args)
        scope = None
        entered = False
        failed = False
        try:
            scope = self._scope(session_id, task_id)
            with scope.lock:
                if scope.stopped.is_set() or time.monotonic() >= scope.resolved.deadline_monotonic:
                    raise BridgeError("task_cancelled")
                scope.active_calls += 1
                scope.calls_finished.clear()
                entered = True
            with self.bridge.activate(scope.resolved.worker_binding["dispatch_id"]):
                token = _active_host.set((self, scope))
                try:
                    result = next_call(args)
                    if scope.stopped.is_set():
                        return json.dumps(failure("task_cancelled"))
                    return result
                finally:
                    _active_host.reset(token)
        except Exception:
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
    try:
        if ctx.get_config("inbound_host_enabled", False) is not True:
            return None
        from .inbound_control import ControlClient, HostConfig
        config = HostConfig.from_context(ctx)
        bridge = HostBridge(config.client_path, config.client_sha256)
        adapter = HostAdapter(ControlClient(config), bridge, downstream_tools=config.consumer_tools)
        return adapter.register(ctx)
    except Exception:
        # Registration/configuration failure leaves the existing download handler
        # unbound (fail closed), while read-only/approved-create tools keep working.
        return None
