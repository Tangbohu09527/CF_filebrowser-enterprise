"""Resolve-v2 clock contract. Synthetic responses; no network, worker or secrets."""
from datetime import datetime, timedelta, timezone
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

PLUGIN = Path(__file__).resolve().parents[1] / "plugin"
spec = importlib.util.spec_from_file_location("cf_clock_contract_test", PLUGIN / "__init__.py")
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)
control = __import__(spec.name + ".inbound_control", fromlist=["ControlClient"])
V2 = "cf-inbound-host-binding/resolve/v2"
ORIGIN = "https://127.0.0.1:9443"
UUID = "00000000-0000-4000-8000-000000000001"
NOW = datetime(2026, 10, 18, 5, 11, 45, tzinfo=timezone.utc)
OWNER = dict(schema=V2, session_id="synthetic", task_id="synthetic",
             host_instance_id="synthetic", host_nonce="x" * 32)


def response(offset=0, ttl=30):
    now = NOW + timedelta(seconds=offset)
    lease = now + timedelta(seconds=ttl)
    return {**OWNER, "binding_id": UUID, "dispatch_id": 1, "claim_epoch": UUID,
        "message_id": 1, "thread_id": UUID, "enterprise_identity_id": UUID,
        "profile_reference": "synthetic", "profile_revision": 1,
        "server_now": now.isoformat(), "lease_valid_until": lease.isoformat(), "state": "running",
        "budget_scope": "message:1:attachment:1", "event_sequence": 1,
        "attachments": [{"schema": "cf-inbound-read/v1", "message_id": 1, "attachment_id": 1,
            "thread_id": UUID, "enterprise_identity_id": UUID,
            "url": ORIGIN + "/inbound-media/1/content", "authorization": "Bearer synthetic-read-only-token",
            "expires_at": (lease + timedelta(hours=1)).isoformat(),
            "download_policy": {"max_attempts": 4, "total_timeout_seconds": 30,
                "retryable_status_codes": [503], "retry_after_seconds": 1},
            "size": 100, "sha256": "a" * 64, "mime_type": "application/pdf",
            "filename": "synthetic.pdf", "declared_quality": None,
            "original_comparison": "not_checked", "formal_archive": False}]}


class ClockContractTests(unittest.TestCase):
    def exercise(self, value, *, elapsed=1, directory_elapsed=0, wall_jump=0):
        client = object.__new__(control.ControlClient)
        client.config = types.SimpleNamespace(profile_reference="synthetic", profile_revision=1,
            max_bytes=64*1024*1024, gateway_origin=ORIGIN, service_token="synthetic-service-only",
            work_root="synthetic-unused", ca_file=None)
        self.requests = []
        tick = [100.0]
        def post(path, body):
            self.requests.append((path, body))
            tick[0] += elapsed
            return copy.deepcopy(value)
        def directory(_):
            tick[0] += directory_elapsed
            return "synthetic-unused"
        client._post = post
        with patch.object(control.time, "time", return_value=NOW.timestamp()+elapsed+directory_elapsed+wall_jump), \
             patch.object(control.time, "monotonic", side_effect=lambda: tick[0]), \
             patch.object(control, "create_task_directory", side_effect=directory) as create:
            self.created = create
            return client.resolve("synthetic", "synthetic", "synthetic", "x"*32)

    def test_request_v2_closed_and_events_remain_v1(self):
        result = self.exercise(response())
        self.assertEqual(self.requests, [(control.PREFIX + "/resolve", OWNER)])
        self.assertEqual(result.owner(), {**OWNER, "schema": control.SCHEMA})
        self.assertEqual(control.SCHEMA, "cf-inbound-host-binding/v1")

    def test_signed_clock_offsets_preserve_request_start_monotonic_limit(self):
        for offset in (-2, -0.8, 0, 0.8, 2):
            with self.subTest(offset=offset):
                original = response(offset)
                result = self.exercise(original, elapsed=1.25)
                self.assertEqual(result.deadline_monotonic, 130)
                self.assertEqual(result.lease_valid_until, original["lease_valid_until"])
                self.assertEqual(result.worker_binding["attachments"], original["attachments"])
                native = control._timestamp(result.worker_binding["expires_at"])
                self.assertLessEqual(native, control._timestamp(original["lease_valid_until"]))
                self.assertLessEqual(native, NOW.timestamp()+30)
                self.assertGreater(native, NOW.timestamp()+1.25)

    def test_observed_30_758051_condition_accepts_with_authoritative_server_clock(self):
        value = response(0.758051)
        result = self.exercise(value, elapsed=0)
        self.assertAlmostEqual(control._timestamp(value["lease_valid_until"])-NOW.timestamp(), 30.758051, places=5)
        self.assertEqual(result.deadline_monotonic, 130)
        self.assertLessEqual(control._timestamp(result.worker_binding["expires_at"]), NOW.timestamp()+30)
        self.assertGreaterEqual(control._timestamp(result.worker_binding["expires_at"]), NOW.timestamp()+30-0.000002)

    def test_native_microsecond_serialization_never_rounds_later(self):
        for ttl in (0.000002, 0.001001, 4.123457, 30):
            with self.subTest(ttl=ttl):
                original = response(2, ttl=ttl)
                result = self.exercise(original, elapsed=0)
                native = control._timestamp(result.worker_binding["expires_at"])
                self.assertLessEqual(native, NOW.timestamp() + result.deadline_monotonic - 100)
                self.assertLessEqual(native, control._timestamp(original["lease_valid_until"]))

    def test_shorter_original_lease_does_not_become_thirty_seconds(self):
        result = self.exercise(response(2, ttl=4), elapsed=1)
        self.assertEqual(result.deadline_monotonic, 104)
        self.assertLessEqual(control._timestamp(result.worker_binding["expires_at"]), NOW.timestamp()+4)

    def test_network_and_directory_time_are_deducted(self):
        result = self.exercise(response(2), elapsed=4, directory_elapsed=3)
        self.assertEqual(result.deadline_monotonic, 130)
        self.assertLessEqual(control._timestamp(result.worker_binding["expires_at"]), NOW.timestamp()+30)
        self.assertGreaterEqual(control._timestamp(result.worker_binding["expires_at"]), NOW.timestamp()+30-0.000002)

    def test_exhausted_response_cannot_create_directory(self):
        for elapsed in (30, 31):
            with self.subTest(elapsed=elapsed), self.assertRaises(control.BridgeError):
                try: self.exercise(response(2), elapsed=elapsed)
                finally: self.assertFalse(self.created.called)

    def test_directory_delay_cannot_return_expired_authority(self):
        with self.assertRaises(control.BridgeError):
            self.exercise(response(2), elapsed=1, directory_elapsed=30)
        self.assertTrue(self.created.called)

    def test_v1_response_cannot_downgrade_new_client(self):
        value = response()
        value.pop("server_now")
        value["schema"] = control.SCHEMA
        with self.assertRaises(control.BridgeError): self.exercise(value)
        self.assertEqual(len(self.requests), 1)
        self.assertFalse(self.created.called)

    def test_unknown_or_missing_fields_reject_before_directory(self):
        for change in (lambda x: x.update(extra=True), lambda x: x.pop("server_now")):
            value = response()
            change(value)
            with self.assertRaises(control.BridgeError): self.exercise(value)
            self.assertFalse(self.created.called)

    def test_invalid_server_timestamp_and_ttl_reject(self):
        values = [None, True, 1792300000, "bad", "2026-10-18T05:11:45"]
        for value in values:
            item = response(); item["server_now"] = value
            with self.subTest(value=value), self.assertRaises(control.BridgeError): self.exercise(item)
            self.assertFalse(self.created.called)
        for ttl in (-1, 0, 30.000001, 31):
            with self.subTest(ttl=ttl), self.assertRaises(control.BridgeError): self.exercise(response(ttl=ttl))
            self.assertFalse(self.created.called)

    def test_wall_clock_changes_never_extend_monotonic_or_original_native_deadline(self):
        for wall_jump in (-10, 10):
            with self.subTest(wall_jump=wall_jump):
                original = response(2)
                result = self.exercise(original, wall_jump=wall_jump)
                self.assertEqual(result.deadline_monotonic, 130)
                self.assertLessEqual(control._timestamp(result.worker_binding["expires_at"]),
                                     control._timestamp(original["lease_valid_until"]))

    def test_snapshot_checks_original_server_lease_without_refresh(self):
        result = self.exercise(response(2))
        event = {"schema": control.SCHEMA, "binding_id": result.binding_id,
                 "claim_epoch": result.claim_epoch, "host_instance_id": result.host_instance_id,
                 "host_nonce": result.host_nonce, "sequence": 1, "state": "running",
                 "lease_valid_until": result.lease_valid_until, "reason": None}
        wire = b"id: 1\nevent: binding\ndata: " + json.dumps(event).encode() + b"\n\n"
        connection = types.SimpleNamespace(sock=None, close=lambda: None)
        response_stream = io.BytesIO(wire+wire)
        response_stream.fp = None
        stream = control.BindingEvents(connection, response_stream, result)
        with patch.object(control.time, "monotonic", return_value=110):
            self.assertEqual(next(stream), "running")
            self.assertEqual(next(stream), "running")
        self.assertEqual(result.deadline_monotonic, 130)
        with patch.object(control.time, "monotonic", return_value=130):
            with self.assertRaises(control.BridgeError): next(stream)


if __name__ == "__main__": unittest.main()
