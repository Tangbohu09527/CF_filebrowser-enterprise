"""Fixed, host-only cf-inbound-host-binding/v1 HTTPS control client.

No control response, credential or local path is a model tool argument. This
client deliberately has no refresh, redirect, retry or events reconnect path.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import queue
import re
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit
import uuid

from .inbound import BridgeError, _client
from .inbound_directory import create_task_directory

SCHEMA = "cf-inbound-host-binding/v1"
PREFIX = "/internal/hermes/inbound-bindings"
MAX_FRAME = 1024 * 1024


def _reject():
    raise BridgeError("host_control_rejected")


def _keys(value, expected):
    if type(value) is not dict or set(value) != set(expected.split()):
        _reject()


def _integer(value):
    if type(value) is not int or value < 1:
        _reject()
    return value


def _identifier(value, pattern=r"[A-Za-z0-9_:-]{1,128}"):
    if type(value) is not str or re.fullmatch(pattern, value) is None:
        _reject()
    return value


def _uuid(value):
    if type(value) is not str:
        _reject()
    try:
        if str(uuid.UUID(value)) != value:
            _reject()
    except (ValueError, AttributeError):
        _reject()
    return value


def _timestamp(value):
    try:
        if type(value) is not str or len(value) > 40:
            _reject()
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            _reject()
        return result.timestamp()
    except (ValueError, OverflowError):
        _reject()


def _json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _reject()
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: _reject())
    except (ValueError, UnicodeError):
        _reject()


@dataclass(frozen=True, repr=False)
class HostConfig:
    gateway_origin: str
    service_token: str = field(repr=False)
    profile_reference: str
    profile_revision: int
    work_root: str
    client_path: str
    client_sha256: str
    max_bytes: int = 64 * 1024 * 1024
    ca_file: str | None = None
    ca_sha256: str | None = None
    consumer_tools: frozenset = frozenset()

    @classmethod
    def from_context(cls, ctx):
        raw = ctx.get_config("inbound_host", {})
        required = {"gateway_origin", "service_token_env", "profile_reference", "profile_revision",
                    "work_root", "client_path", "client_sha256"}
        optional = {"max_bytes", "ca_file", "ca_sha256", "consumer_tools"}
        if type(raw) is not dict or not required <= set(raw) or set(raw) - required - optional:
            _reject()
        origin = raw["gateway_origin"]
        try:
            parsed = urlsplit(origin)
            if (type(origin) is not str or parsed.scheme != "https" or not parsed.hostname
                    or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment
                    or parsed.netloc != parsed.netloc.lower() or any(c.isspace() for c in origin)
                    or parsed.port == 0):
                _reject()
        except (ValueError, TypeError):
            _reject()
        env_name = _identifier(raw["service_token_env"], r"CF_FILEBRIDGE_HOST_[A-Z0-9_]{1,90}")
        token = os.environ.get(env_name, "")
        if not re.fullmatch(r"[\x21-\x7e]{32,4096}", token):
            _reject()
        profile = raw["profile_reference"]
        if type(profile) is not str or not 1 <= len(profile) <= 128 or any(ord(c) < 32 for c in profile):
            _reject()
        revision = _integer(raw["profile_revision"])
        maximum = _integer(raw.get("max_bytes", 64 * 1024 * 1024))
        if maximum > 64 * 1024 * 1024:
            _reject()
        root = raw["work_root"]
        if type(root) is not str or not Path(root).is_absolute():
            _reject()
        _client(raw["client_path"], raw["client_sha256"])
        ca, digest = raw.get("ca_file"), raw.get("ca_sha256")
        if (ca is None) != (digest is None):
            _reject()
        if ca is not None:
            _client(ca, digest)
        consumers = raw.get("consumer_tools", [])
        if type(consumers) is not list or len(consumers) > 32 or any(
                type(x) is not str or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", x) for x in consumers):
            _reject()
        return cls(origin, token, profile, revision, root, raw["client_path"], raw["client_sha256"],
                   maximum, ca, digest, frozenset(consumers))


@dataclass(frozen=True, repr=False)
class ResolvedBinding:
    binding_id: str
    session_id: str
    task_id: str
    host_instance_id: str
    host_nonce: str
    claim_epoch: str
    event_sequence: int
    budget_scope: str
    deadline_monotonic: float
    lease_valid_until: str
    worker_binding: dict = field(repr=False)

    def owner(self):
        return {"schema": SCHEMA, "session_id": self.session_id, "task_id": self.task_id,
                "host_instance_id": self.host_instance_id, "host_nonce": self.host_nonce}


class ControlClient:
    def __init__(self, config):
        self.config = config
        parsed = urlsplit(config.gateway_origin)
        self.host, self.port = parsed.hostname, parsed.port or 443
        # Unlike create_default_context this never reads SSLKEYLOGFILE.
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.tls.minimum_version = ssl.TLSVersion.TLSv1_2
        self.tls.check_hostname = True
        self.tls.verify_mode = ssl.CERT_REQUIRED
        if config.ca_file:
            path = _client(config.ca_file, config.ca_sha256)
            # Load exactly the verified bytes, never reopen the path inside SSL.
            # A replaced file cannot change the trust used with a service secret.
            with path.open("rb") as stream:
                certificate = stream.read(1024 * 1024 + 1)
            if (len(certificate) > 1024 * 1024
                    or hashlib.sha256(certificate).hexdigest() != config.ca_sha256):
                _reject()
            self.tls.load_verify_locations(cadata=certificate.decode("ascii"))
        else:
            self.tls.load_default_certs()

    def _open(self, method, path, body=None, headers=None, timeout=3):
        conn = http.client.HTTPSConnection(self.host, self.port, context=self.tls, timeout=timeout)
        conn.debuglevel = 0
        conn.auto_open = 0  # An aborted connection must never reconnect during request().
        aborted = threading.Event()
        completed = queue.Queue(maxsize=1)
        deadline = time.monotonic() + timeout

        def abort():
            aborted.set()
            try:
                if conn.sock:
                    conn.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()

        def connect_and_request():
            try:
                # System DNS can outlive socket timeouts. Keep caller bounded and
                # never send Authorization when late resolution finally returns.
                conn.connect()
                if aborted.is_set() or time.monotonic() >= deadline:
                    _reject()
                wire = None if body is None else json.dumps(body, separators=(",", ":")).encode()
                hdr = {"Authorization": "Bearer " + self.config.service_token,
                       "Accept": "application/json" if method == "POST" else "text/event-stream"}
                if wire is not None:
                    hdr["Content-Type"] = "application/json"
                hdr.update(headers or {})
                conn.request(method, path, body=wire, headers=hdr)
                response = conn.getresponse()
                if (aborted.is_set() or time.monotonic() >= deadline or response.status != 200
                        or response.getheader("Cache-Control", "").lower() != "no-store"):
                    _reject()
                expected = "application/json" if method == "POST" else "text/event-stream"
                if response.getheader("Content-Type", "").split(";")[0].strip().lower() != expected:
                    _reject()
                completed.put_nowait(response)
            except Exception:
                conn.close()
                completed.put_nowait(None)
        thread = threading.Thread(target=connect_and_request, daemon=True, name="cf-inbound-control")
        thread.start()
        try:
            response = completed.get(timeout=timeout)
            if response is not None and time.monotonic() < deadline:
                return conn, response
        except queue.Empty:
            pass
        abort()
        raise BridgeError("host_control_unavailable") from None

    def _post(self, path, body):
        conn, response = self._open("POST", path, body)
        # A socket timeout alone resets on each fragment. Bound the entire body
        # read, including a peer that keeps sending a byte before every timeout.
        sock = conn.sock or getattr(getattr(response.fp, "raw", None), "_sock", None)
        def abort():
            try:
                if sock:
                    sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        timer = threading.Timer(3, abort)
        timer.daemon = True
        timer.start()
        try:
            data = response.read(MAX_FRAME + 1)
            if len(data) > MAX_FRAME:
                _reject()
            return _json(data)
        except Exception:
            raise BridgeError("host_control_rejected") from None
        finally:
            timer.cancel()
            conn.close()

    def resolve(self, session_id, task_id, host_instance_id, host_nonce):
        started = time.monotonic()
        _identifier(session_id)
        _identifier(task_id)
        if session_id != task_id:
            _reject()
        _identifier(host_instance_id, r"[A-Za-z0-9_-]{1,128}")
        _identifier(host_nonce, r"[A-Za-z0-9_-]{32,128}")
        owner = {"schema": SCHEMA, "session_id": session_id, "task_id": task_id,
                 "host_instance_id": host_instance_id, "host_nonce": host_nonce}
        result = self._post(PREFIX + "/resolve", owner)
        _keys(result, "schema binding_id session_id task_id host_instance_id host_nonce dispatch_id claim_epoch "
              "message_id thread_id enterprise_identity_id profile_reference profile_revision lease_valid_until "
              "state budget_scope attachments event_sequence")
        if any(result[k] != v for k, v in owner.items()) or result["state"] != "running":
            _reject()
        for name in ("binding_id", "claim_epoch", "thread_id", "enterprise_identity_id"):
            _uuid(result[name])
        for name in ("dispatch_id", "message_id", "profile_revision", "event_sequence"):
            _integer(result[name])
        if (result["profile_reference"] != self.config.profile_reference
                or result["profile_revision"] != self.config.profile_revision):
            _reject()
        lease = _timestamp(result["lease_valid_until"])
        remaining = lease - time.time()
        if not 0 < remaining <= 30.5:
            _reject()
        deadline = min(started + 30, time.monotonic() + remaining)
        attachments = result["attachments"]
        # Gateway v1 binds exactly one attachment and one immutable budget scope.
        if type(attachments) is not list or len(attachments) != 1:
            _reject()
        attachment = self._attachment(attachments[0], result)
        scope = f"message:{result['message_id']}:attachment:{attachment['attachment_id']}"
        if result["budget_scope"] != scope or time.monotonic() >= deadline:
            _reject()
        directory = create_task_directory(self.config.work_root)
        binding = {"dispatch_id": "gateway:" + result["binding_id"], "task_id": task_id,
                   "thread_id": result["thread_id"], "enterprise_identity_id": result["enterprise_identity_id"],
                   "work_dir": directory, "gateway_origin": self.config.gateway_origin,
                   "expires_at": result["lease_valid_until"], "max_bytes": self.config.max_bytes,
                   "attachments": [attachment]}
        if self.config.ca_file:
            binding.update(ca_file=self.config.ca_file, ca_sha256=self.config.ca_sha256)
        return ResolvedBinding(result["binding_id"], session_id, task_id, host_instance_id, host_nonce,
                               result["claim_epoch"], result["event_sequence"], scope, deadline,
                               result["lease_valid_until"], binding)

    def _attachment(self, item, parent):
        _keys(item, "schema message_id attachment_id thread_id enterprise_identity_id url authorization expires_at "
              "download_policy size sha256 mime_type filename declared_quality original_comparison formal_archive")
        if (item["schema"] != "cf-inbound-read/v1" or item["formal_archive"] is not False
                or any(item[k] != parent[k] for k in ("message_id", "thread_id", "enterprise_identity_id"))):
            _reject()
        _integer(item["message_id"])
        _integer(item["attachment_id"])
        if _integer(item["size"]) > self.config.max_bytes:
            _reject()
        _identifier(item["sha256"], r"[0-9a-f]{64}")
        _identifier(item["authorization"], r"Bearer [\x21-\x7e]{1,121}")
        if item["authorization"] == "Bearer " + self.config.service_token:
            _reject()
        if type(item["url"]) is not str or not re.fullmatch(
                re.escape(self.config.gateway_origin) + r"/inbound-media/[1-9][0-9]*/content", item["url"]):
            _reject()
        if _timestamp(item["expires_at"]) < _timestamp(parent["lease_valid_until"]):
            _reject()
        if item["mime_type"] not in ("application/pdf", "image/jpeg", "image/png", "application/octet-stream"):
            _reject()
        if item["filename"] is not None and (type(item["filename"]) is not str or len(item["filename"]) > 1024):
            _reject()
        if (item["declared_quality"] not in (None, "full", "standard", "thumbnail")
                or item["original_comparison"] not in ("not_checked", "match", "different")):
            _reject()
        policy = item["download_policy"]
        _keys(policy, "max_attempts total_timeout_seconds retryable_status_codes retry_after_seconds")
        if (any(type(policy[k]) is not int for k in ("max_attempts", "total_timeout_seconds", "retry_after_seconds"))
                or policy != {"max_attempts": 4, "total_timeout_seconds": 30,
                              "retryable_status_codes": [503], "retry_after_seconds": 1}
                or type(policy["retryable_status_codes"]) is not list
                or type(policy["retryable_status_codes"][0]) is not int):
            _reject()
        # Explicit worker schema projection; server fields never select disk/origin/config.
        return {key: item[key] for key in ("schema", "message_id", "attachment_id", "thread_id",
                "enterprise_identity_id", "url", "authorization", "expires_at", "download_policy", "size",
                "sha256", "mime_type", "filename", "declared_quality", "original_comparison", "formal_archive")}

    def events(self, binding):
        remaining = binding.deadline_monotonic - time.monotonic()
        if remaining <= 0:
            _reject()
        headers = {"X-CF-Session-Id": binding.session_id, "X-CF-Task-Id": binding.task_id,
                   "X-CF-Host-Instance-Id": binding.host_instance_id, "X-CF-Host-Nonce": binding.host_nonce,
                   "X-CF-Claim-Epoch": binding.claim_epoch, "Last-Event-ID": str(binding.event_sequence)}
        conn, response = self._open("GET", PREFIX + "/" + binding.binding_id + "/events",
                                    headers=headers, timeout=min(3, remaining))
        return BindingEvents(conn, response, binding)

    def closed(self, binding):
        result = self._post(PREFIX + "/" + binding.binding_id + "/closed",
                            {**binding.owner(), "claim_epoch": binding.claim_epoch})
        _keys(result, "schema binding_id state")
        if result != {"schema": SCHEMA, "binding_id": binding.binding_id, "state": "closed"}:
            _reject()


class BindingEvents:
    def __init__(self, conn, response, binding):
        self.conn, self.response, self.binding = conn, response, binding
        self.previous = None
        self.sequence = binding.event_sequence
        self.stopped = False
        self.read_lock = threading.Lock()
        # HTTP/1.0 servers may detach conn.sock; retain the response-owned socket.
        self.socket = conn.sock or getattr(getattr(response.fp, "raw", None), "_sock", None)

    def __iter__(self):
        return self

    def close(self):
        self.stopped = True
        try:
            if self.socket:
                self.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.conn.close()
        # HTTP/1.0 may detach the response socket from the connection. Close its
        # file object too, but never wait for another thread's buffered read lock.
        if self.read_lock.acquire(blocking=False):
            try:
                self.response.close()
            finally:
                self.read_lock.release()

    def __next__(self):
        with self.read_lock:
            try:
                return self._next()
            finally:
                if self.stopped:
                    self.response.close()

    def _next(self):
        try:
            if self.stopped:
                raise StopIteration
            fields, total = {}, 0
            while True:
                remaining = self.binding.deadline_monotonic - time.monotonic()
                if remaining <= 0 or self.stopped:
                    _reject()
                if self.socket:
                    self.socket.settimeout(min(2, remaining))
                line = self.response.readline(8193)
                total += len(line)
                if not line or len(line) > 8192 or total > 65536 or not line.endswith(b"\n"):
                    _reject()
                line = line.rstrip(b"\r\n")
                if not line:
                    break
                name, separator, value = line.partition(b":")
                if not separator or name not in (b"id", b"event", b"data") or name in fields:
                    _reject()
                fields[name] = value.lstrip(b" ")
            if set(fields) != {b"id", b"event", b"data"} or fields[b"event"] != b"binding":
                _reject()
            value = _json(fields[b"data"])
            _keys(value, "schema binding_id claim_epoch host_instance_id host_nonce sequence state lease_valid_until reason")
            binding = self.binding
            for name in ("binding_id", "claim_epoch", "host_instance_id", "host_nonce", "lease_valid_until"):
                if value[name] != getattr(binding, name):
                    _reject()
            sequence = _integer(value["sequence"])
            if (value["schema"] != SCHEMA or fields[b"id"] != str(sequence).encode()
                    or value["state"] not in ("running", "revoked", "closed")
                    or (value["reason"] is not None and (type(value["reason"]) is not str or len(value["reason"]) > 128))):
                _reject()
            if self.previous is None:
                if sequence != self.sequence or value["state"] != "running" or value["reason"] is not None:
                    _reject()
            elif sequence == self.sequence:
                if value != self.previous:
                    _reject()
            elif sequence != self.sequence + 1 or value["state"] == "running":
                _reject()
            self.previous, self.sequence = value, sequence
            return value["state"]
        except StopIteration:
            raise
        except Exception:
            self.close()
            raise BridgeError("host_events_lost") from None
