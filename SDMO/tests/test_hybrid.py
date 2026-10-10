import contextlib
import io
import json
import os
import random
import socket
import tempfile
import unittest
from collections import deque
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from sdmo import crypto, gateway, legacy_device
from sdmo.cloud import CloudState, ProtocolError, make_handler, state_from_env
from sdmo.provision import provision
from tests.helpers import FakeClock, get_text, post_raw, running_server

SECRET = bytes(range(32))
GATEWAY = "gw1"
DEFAULT = crypto.DEFAULT_SUITE
BIG = "X25519+ML-KEM-1024"


def make_reading(number=1):
    return {"device_id": "dev", "sequence": number, "temperature_c": 21.5, "observed_at": "2026-10-08T00:00:00+00:00"}


def make_state(clock, **overrides):
    options = {"identity_key": Ed25519PrivateKey.generate(), "gateways": {GATEWAY: SECRET}, "clock": clock}
    options.update(overrides)
    return CloudState(options.pop("shared_key", "legacy-key"), **options)


def make_client(url, state, clock, **overrides):
    options = {"clock": clock}
    options.update(overrides)
    return gateway.HybridClient(url, options.pop("gateway_id", GATEWAY), options.pop("secret", SECRET),
                                options.pop("public", state.identity_public if state.identity_key else bytes(32)),
                                **options)


def build_handshake(clock, *, suite=DEFAULT, gateway_id=GATEWAY, secret=SECRET, timestamp=None, ek=None,
                    x25519=None, nonce=None):
    if ek is None:
        ek = crypto.kem_generate(crypto.SUITES[suite])[1] if suite in crypto.SUITES else b"x"
    x25519 = x25519 or X25519PrivateKey.generate().public_key().public_bytes_raw()
    nonce = nonce or os.urandom(16)
    timestamp = int(clock()) if timestamp is None else timestamp
    mac = crypto.request_mac(secret, gateway_id, suite, ek, x25519, nonce, timestamp)
    return {"v": 2, "gateway_id": gateway_id, "suite": suite, "mlkem_ek": crypto.b64e(ek),
            "x25519": crypto.b64e(x25519), "nonce": crypto.b64e(nonce), "timestamp": timestamp,
            "mac": crypto.b64e(mac)}


def build_record(session, counter, plaintext=None):
    plaintext = plaintext if plaintext is not None else json.dumps(make_reading(counter)).encode()
    sealed = crypto.seal_record(session.keys.record_key, session.session_id, counter, plaintext)
    return {"session_id": session.session_id, "counter": counter, "ciphertext": crypto.b64e(sealed)}


class ServerError(BaseHTTPRequestHandler):
    def do_POST(self):
        # Read the body first: closing a socket with unread data makes Windows abort the connection.
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(503)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *args):
        pass


def free_port_url():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{sock.getsockname()[1]}"


class HybridTestCase(unittest.TestCase):
    state_options = {}

    def setUp(self):
        self.clock = FakeClock()
        self.state = make_state(self.clock, **self.state_options)
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.url = stack.enter_context(running_server(make_handler(self.state)))
        self.client = make_client(self.url, self.state, self.clock)

    def sample(self, name, **labels):
        return self.state.registry.get_sample_value(name, labels) or 0


class FlowTests(HybridTestCase):
    def test_hybrid_delivery_does_not_touch_the_legacy_path(self):
        self.client.send(make_reading())
        self.assertEqual(self.state.readings, [make_reading()])
        self.assertEqual(self.sample("cloud_legacy_requests_total"), 0)
        self.assertEqual(self.sample("cloud_handshakes_total", mode="hybrid", suite=DEFAULT, result="ok"), 1)

    def test_one_session_serves_many_readings(self):
        for number in range(1, 4):
            self.client.send(make_reading(number))
        self.assertEqual([r["sequence"] for r in self.state.readings], [1, 2, 3])
        self.assertEqual(self.sample("cloud_handshakes_total", mode="hybrid", suite=DEFAULT, result="ok"), 1)

    def test_dual_stack_cloud_still_accepts_the_static_key(self):
        status, _ = post_raw(f"{self.url}/v1/readings", make_reading(), {"X-Legacy-Shared-Key": "legacy-key"})
        self.assertEqual(status, 202)
        self.assertEqual(self.sample("cloud_legacy_requests_total"), 1)

    def test_1024_suite_is_selectable(self):
        state = make_state(self.clock, suites=(DEFAULT, BIG))
        with running_server(make_handler(state)) as url:
            make_client(url, state, self.clock, suites=(BIG,)).send(make_reading())
        self.assertEqual(len(state.readings), 1)
        self.assertEqual(state.registry.get_sample_value(
            "cloud_handshakes_total", {"mode": "hybrid", "suite": BIG, "result": "ok"}), 1)

    def test_client_moves_to_next_suite_when_the_first_is_unsupported(self):
        client = make_client(self.url, self.state, self.clock, suites=(BIG, DEFAULT))
        client.send(make_reading())
        self.assertEqual(self.sample("cloud_handshakes_total", mode="hybrid", suite=BIG, result="failed"), 1)
        self.assertEqual(self.sample("cloud_handshakes_total", mode="hybrid", suite=DEFAULT, result="ok"), 1)

    def test_forged_acknowledgement_is_detected(self):
        original = gateway._post_json

        def forge(url, payload, timeout):
            status, body = original(url, payload, timeout)
            if url.endswith("/v2/readings"):
                body["ack"] = crypto.b64e(bytes(32))
            return status, body

        with mock.patch.object(gateway, "_post_json", forge), self.assertRaises(gateway.GatewayError):
            self.client.send(make_reading())


class ModeMatrixTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)

    def serve(self, state):
        return self.stack.enter_context(running_server(make_handler(state)))

    def test_hybrid_only_cloud_rejects_the_static_key(self):
        state = make_state(self.clock, shared_key=None, accept_modes=("hybrid",))
        url = self.serve(state)
        status, _ = post_raw(f"{url}/v1/readings", make_reading(), {"X-Legacy-Shared-Key": "anything"})
        self.assertEqual(status, 410)
        self.assertEqual(state.readings, [])
        self.assertEqual(state.registry.get_sample_value("cloud_legacy_requests_total"), 1)

    def test_legacy_retires_on_the_configured_date(self):
        state = make_state(self.clock, legacy_until=self.clock() + 100)
        url = self.serve(state)
        headers = {"X-Legacy-Shared-Key": "legacy-key"}
        self.assertEqual(post_raw(f"{url}/v1/readings", make_reading(), headers)[0], 202)
        self.clock.advance(200)
        self.assertEqual(post_raw(f"{url}/v1/readings", make_reading(), headers)[0], 410)

    def test_invalid_configuration_is_refused(self):
        with self.assertRaises(ValueError):
            CloudState(None, accept_modes=("hybrid",))
        with self.assertRaises(ValueError):
            CloudState(None, accept_modes=("legacy",))
        with self.assertRaises(ValueError):
            CloudState("k", suites=("X25519+ML-KEM-512",))
        with self.assertRaises(ValueError):
            gateway.HybridClient("http://x", "g", SECRET, bytes(32), suites=("X25519+ML-KEM-512",))

    def legacy_only_forwarder(self, **options):
        state = CloudState("legacy-key", clock=self.clock)
        url = self.serve(state)
        metrics = gateway.GatewayMetrics("hybrid")
        hybrid = gateway.HybridClient(url, GATEWAY, SECRET, bytes(32), clock=self.clock, metrics=metrics)
        forwarder = gateway.Forwarder(metrics, cloud_url=f"{url}/v1/readings", shared_key="legacy-key",
                                      hybrid=hybrid, **options)
        return state, metrics, forwarder

    def test_fallback_is_used_only_when_allowed_and_is_counted(self):
        state, metrics, forwarder = self.legacy_only_forwarder(allow_legacy_fallback=True)
        forwarder.forward(make_reading())
        self.assertEqual(len(state.readings), 1)
        self.assertEqual(metrics.registry.get_sample_value("gateway_fallback_total"), 1)

    def test_no_silent_fallback_by_default(self):
        state, metrics, forwarder = self.legacy_only_forwarder()
        with self.assertRaises(gateway.V2Unsupported):
            forwarder.forward(make_reading())
        self.assertEqual(state.readings, [])
        self.assertEqual(metrics.registry.get_sample_value("gateway_fallback_total"), 0)

    def test_ratchet_blocks_fallback_after_a_successful_v2_handshake(self):
        hybrid_state = make_state(self.clock)
        hybrid_url = self.serve(hybrid_state)
        legacy_state, metrics, forwarder = self.legacy_only_forwarder(allow_legacy_fallback=True)
        legacy_url = forwarder.hybrid.base_url
        forwarder.hybrid.base_url = hybrid_url
        forwarder.hybrid.cloud_public_key = hybrid_state.identity_public
        forwarder.forward(make_reading(1))
        self.assertTrue(forwarder.ratchet.required)
        forwarder.hybrid.base_url, forwarder.hybrid.session = legacy_url, None
        with self.assertRaises(gateway.V2Unsupported):
            forwarder.forward(make_reading(2))
        self.assertEqual(legacy_state.readings, [])
        self.assertEqual(metrics.registry.get_sample_value("gateway_fallback_total"), 0)

    def test_ratchet_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "ratchet.json")
            gateway.Ratchet("http://cloud:8081", path).mark()
            self.assertTrue(gateway.Ratchet("http://cloud:8081", path).required)
            self.assertFalse(gateway.Ratchet("http://other:8081", path).required)

    def test_transient_server_error_never_downgrades(self):
        legacy_state = CloudState("legacy-key", clock=self.clock)
        legacy_url = self.serve(legacy_state)
        broken_url = self.stack.enter_context(running_server(ServerError))
        metrics = gateway.GatewayMetrics("hybrid")
        hybrid = gateway.HybridClient(broken_url, GATEWAY, SECRET, bytes(32), clock=self.clock, metrics=metrics)
        forwarder = gateway.Forwarder(metrics, cloud_url=f"{legacy_url}/v1/readings", shared_key="legacy-key",
                                      hybrid=hybrid, allow_legacy_fallback=True)
        with self.assertRaises(gateway.HandshakeError):
            forwarder.forward(make_reading())
        self.assertEqual(legacy_state.readings, [])
        self.assertEqual(metrics.registry.get_sample_value("gateway_fallback_total"), 0)


class AttackTests(HybridTestCase):
    state_options = {"suites": (DEFAULT, BIG)}

    def tamper(self, *, request=None, response=None):
        original = gateway._post_json

        def intercept(url, payload, timeout):
            if request and url.endswith("/v2/handshake"):
                payload = request(dict(payload))
            status, body = original(url, payload, timeout)
            if response and url.endswith("/v2/handshake") and status == 200:
                body = response(dict(body))
            return status, body

        return mock.patch.object(gateway, "_post_json", intercept)

    def flip(self, value):
        raw = crypto.b64d(value)
        return crypto.b64e(bytes([raw[0] ^ 1]) + raw[1:])

    def test_any_modified_handshake_response_is_rejected(self):
        for field in ("ct", "x25519", "nonce", "session_id", "signature", "confirm"):
            with self.subTest(field=field), self.tamper(response=lambda b, f=field: {**b, f: self.flip(b[f])}):
                with self.assertRaises(gateway.HandshakeError):
                    self.client.handshake()
        self.assertIsNone(self.client.session)

    def test_changed_suite_in_the_response_is_rejected(self):
        with self.tamper(response=lambda body: {**body, "suite": BIG}), self.assertRaises(gateway.HandshakeError):
            self.client.handshake()

    def test_modified_handshake_request_is_rejected(self):
        for field in ("nonce", "x25519", "mlkem_ek", "timestamp", "gateway_id"):
            def modify(payload, f=field):
                payload[f] = payload[f] + 1 if f == "timestamp" else (
                    "gw2" if f == "gateway_id" else self.flip(payload[f]))
                return payload
            with self.subTest(field=field), self.tamper(request=modify), self.assertRaises(gateway.HandshakeError):
                self.client.handshake()
        self.assertEqual(self.state.sessions, {})

    def test_suite_downgrade_in_flight_is_rejected(self):
        client = make_client(self.url, self.state, self.clock, suites=(BIG,))
        with self.tamper(request=lambda payload: {**payload, "suite": DEFAULT}), self.assertRaises(gateway.HandshakeError):
            client.handshake()
        self.assertEqual(self.state.sessions, {})

    def test_wrong_pinned_identity_is_rejected(self):
        client = make_client(self.url, self.state, self.clock, public=Ed25519PrivateKey.generate().public_key().public_bytes_raw())
        with self.assertRaisesRegex(gateway.HandshakeError, "signature"):
            client.handshake()

    def test_unknown_gateway_and_wrong_enrollment_secret_are_rejected(self):
        for label, overrides in {"unknown": {"gateway_id": "nobody"}, "secret": {"secret": bytes(32)}}.items():
            with self.subTest(case=label), self.assertRaises(gateway.HandshakeError):
                make_client(self.url, self.state, self.clock, **overrides).handshake()
        self.assertEqual(self.sample("cloud_handshake_failures_total", reason="unknown_gateway"), 1)
        self.assertEqual(self.sample("cloud_handshake_failures_total", reason="bad_mac"), 1)

    def test_replayed_handshake_request_is_rejected(self):
        request = build_handshake(self.clock)
        self.assertEqual(post_raw(f"{self.url}/v2/handshake", request)[0], 200)
        self.assertEqual(post_raw(f"{self.url}/v2/handshake", request)[0], 401)
        self.assertEqual(self.sample("cloud_handshake_failures_total", reason="replay"), 1)

    def test_stale_and_future_timestamps_are_rejected(self):
        for offset in (-1000, 1000):
            with self.subTest(offset=offset):
                request = build_handshake(self.clock, timestamp=int(self.clock()) + offset)
                self.assertEqual(post_raw(f"{self.url}/v2/handshake", request)[0], 401)
        self.assertEqual(self.sample("cloud_handshake_failures_total", reason="stale_timestamp"), 2)

    def test_replayed_and_reordered_records_are_rejected(self):
        self.client.handshake()
        session = self.client.session
        url = f"{self.url}/v2/readings"
        self.assertEqual(post_raw(url, build_record(session, 5))[0], 202)
        self.assertEqual(post_raw(url, build_record(session, 5))[0], 401)
        self.assertEqual(post_raw(url, build_record(session, 3))[0], 401)
        self.assertEqual(post_raw(url, build_record(session, 6))[0], 202)
        self.assertEqual(self.sample("cloud_records_rejected_total", reason="replay"), 2)
        self.assertEqual(len(self.state.readings), 2)

    def test_record_from_another_session_is_rejected(self):
        self.client.handshake()
        other = make_client(self.url, self.state, self.clock)
        other.handshake()
        record = build_record(self.client.session, 1)
        record["session_id"] = other.session.session_id
        self.assertEqual(post_raw(f"{self.url}/v2/readings", record)[0], 401)
        self.assertEqual(self.sample("cloud_records_rejected_total", reason="aead_fail"), 1)
        self.assertEqual(self.state.readings, [])

    def test_unknown_session_is_rejected(self):
        record = {"session_id": crypto.b64e(os.urandom(16)), "counter": 0, "ciphertext": crypto.b64e(os.urandom(32))}
        self.assertEqual(post_raw(f"{self.url}/v2/readings", record)[0], 401)
        self.assertEqual(self.sample("cloud_records_rejected_total", reason="unknown_session"), 1)

    def test_authentic_but_invalid_reading_is_rejected_and_consumes_the_counter(self):
        self.client.handshake()
        session = self.client.session
        url = f"{self.url}/v2/readings"
        self.assertEqual(post_raw(url, build_record(session, 1, b'{"device_id": "x"}'))[0], 400)
        self.assertEqual(post_raw(url, build_record(session, 1))[0], 401)
        self.assertEqual(self.state.readings, [])


class MalformedInputTests(HybridTestCase):
    def assert_rejected(self, path, body, expected=(400,)):
        status, _ = post_raw(f"{self.url}{path}", body)
        self.assertIn(status, expected, body if isinstance(body, bytes) else json.dumps(body)[:80])
        self.assertEqual(get_text(f"{self.url}/healthz"), '{"status": "ok"}')

    def test_malformed_handshakes_are_client_errors(self):
        good = build_handshake(self.clock)
        zeros = build_handshake(self.clock, x25519=bytes(32))
        cases = [b"not json", b"[]", b"{}", {"v": 1}, {**good, "v": 3}, {**good, "gateway_id": 7},
                 {**good, "suite": ["x"]}, {**good, "suite": "X25519+ML-KEM-512"},
                 {**good, "mlkem_ek": crypto.b64e(b"short")}, {**good, "mlkem_ek": "***"},
                 {**good, "nonce": crypto.b64e(b"short")}, {**good, "mac": None},
                 {**good, "timestamp": "1"}, {**good, "timestamp": True}, {**good, "timestamp": 1.5},
                 {**good, "timestamp": -1}, {k: v for k, v in good.items() if k != "mac"},
                 b"x" * 64_001, zeros]
        for body in cases:
            with self.subTest(body=str(body)[:60]):
                self.assert_rejected("/v2/handshake", body, expected=(400, 401))
        self.assertEqual(self.state.sessions, {})

    def test_low_order_x25519_point_with_valid_mac_is_rejected(self):
        self.assert_rejected("/v2/handshake", build_handshake(self.clock, x25519=bytes(32)))
        self.assertEqual(self.state.sessions, {})

    def test_garbage_encapsulation_key_never_causes_a_server_error(self):
        request = build_handshake(self.clock, ek=os.urandom(crypto.SUITES[DEFAULT].ek_len))
        self.assert_rejected("/v2/handshake", request, expected=(200, 400))

    def test_unsupported_suite_lists_what_is_supported(self):
        status, body = post_raw(f"{self.url}/v2/handshake", build_handshake(self.clock, suite=BIG))
        self.assertEqual((status, body["error"], body["supported"]), (400, "unsupported_suite", [DEFAULT]))

    def test_malformed_records_are_client_errors(self):
        good = {"session_id": "abc", "counter": 1, "ciphertext": crypto.b64e(os.urandom(32))}
        cases = [b"nope", b"[]", {}, {**good, "counter": "1"}, {**good, "counter": -1}, {**good, "counter": 2**64},
                 {**good, "counter": True}, {**good, "session_id": 5}, {**good, "ciphertext": "***"},
                 {**good, "ciphertext": crypto.b64e(b"tiny")}, {**good, "ciphertext": crypto.b64e(os.urandom(9000))},
                 {k: v for k, v in good.items() if k != "ciphertext"}]
        for body in cases:
            with self.subTest(body=str(body)[:60]):
                self.assert_rejected("/v2/readings", body, expected=(400,))

    def test_unknown_v2_paths_are_not_found(self):
        self.assertEqual(post_raw(f"{self.url}/v2/other", {})[0], 404)

    def test_v2_is_absent_when_hybrid_is_disabled(self):
        state = CloudState("k", clock=self.clock)
        with running_server(make_handler(state)) as url:
            self.assertEqual(post_raw(f"{url}/v2/handshake", {})[0], 404)
            self.assertEqual(post_raw(f"{url}/v2/readings", {})[0], 404)


class RotationTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()

    def run_with(self, state_options, client_options, action):
        state = make_state(self.clock, **state_options)
        with running_server(make_handler(state)) as url:
            metrics = gateway.GatewayMetrics("hybrid")
            client = make_client(url, state, self.clock, metrics=metrics, **client_options)
            action(client)
        return state, metrics

    def test_cloud_side_expiry_triggers_a_transparent_rekey(self):
        def action(client):
            client.send(make_reading(1))
            self.clock.advance(200)
            client.send(make_reading(2))

        state, metrics = self.run_with({"session_ttl": 100}, {}, action)
        self.assertEqual([r["sequence"] for r in state.readings], [1, 2])
        self.assertEqual(state.registry.get_sample_value("cloud_records_rejected_total", {"reason": "expired"}), 1)
        self.assertEqual(metrics.registry.get_sample_value("gateway_rekeys_total"), 1)

    def test_cloud_record_limit_triggers_a_rekey(self):
        def action(client):
            for number in range(1, 4):
                client.send(make_reading(number))

        state, metrics = self.run_with({"session_max_records": 2}, {}, action)
        self.assertEqual(len(state.readings), 3)
        self.assertEqual(metrics.registry.get_sample_value("gateway_handshakes_total", {"result": "ok"}), 2)

    def test_gateway_rekeys_before_the_cloud_limit(self):
        def action(client):
            for number in range(1, 6):
                client.send(make_reading(number))

        state, metrics = self.run_with({}, {"rekey_records": 2}, action)
        self.assertEqual(len(state.readings), 5)
        self.assertEqual(metrics.registry.get_sample_value("gateway_handshakes_total", {"result": "ok"}), 3)
        self.assertEqual(metrics.registry.get_sample_value("gateway_rekeys_total"), 2)
        self.assertFalse(state.registry.get_sample_value("cloud_records_rejected_total", {"reason": "expired"}))

    def test_gateway_rekeys_on_age(self):
        def action(client):
            client.send(make_reading(1))
            self.clock.advance(11)
            client.send(make_reading(2))

        _, metrics = self.run_with({}, {"rekey_seconds": 10}, action)
        self.assertEqual(metrics.registry.get_sample_value("gateway_rekeys_total"), 1)

    def test_every_session_gets_fresh_keys(self):
        state = make_state(self.clock)
        with running_server(make_handler(state)) as url:
            client = make_client(url, state, self.clock)
            client.handshake()
            first = client.session.keys
            client.handshake()
        self.assertNotEqual(first.record_key, client.session.keys.record_key)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.state = make_state(self.clock)
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.url = stack.enter_context(running_server(make_handler(self.state)))
        self.metrics = gateway.GatewayMetrics("hybrid")
        self.client = make_client(self.url, self.state, self.clock, metrics=self.metrics)
        self.forwarder = gateway.Forwarder(self.metrics, cloud_url=f"{self.url}/v1/readings", hybrid=self.client)

    def test_cloud_restart_loses_sessions_and_the_gateway_recovers(self):
        self.client.send(make_reading(1))
        self.state.sessions.clear()
        self.client.send(make_reading(2))
        self.assertEqual([r["sequence"] for r in self.state.readings], [1, 2])

    def test_queued_readings_survive_an_outage_and_arrive_in_order(self):
        live_url = self.client.base_url
        self.client.base_url = free_port_url()
        queue = deque()
        for number in range(1, 4):
            gateway.enqueue(queue, make_reading(number), self.metrics, 10)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(gateway.drain(queue, self.forwarder, self.metrics))
        self.assertEqual(len(queue), 3)
        self.assertEqual(self.metrics.registry.get_sample_value("gateway_queue_depth"), 3)
        self.client.base_url = live_url
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(gateway.drain(queue, self.forwarder, self.metrics))
        self.assertEqual([r["sequence"] for r in self.state.readings], [1, 2, 3])
        self.assertEqual(self.metrics.registry.get_sample_value("gateway_forwarded_total"), 3)
        self.assertEqual(self.metrics.registry.get_sample_value("gateway_queue_depth"), 0)

    def test_full_queue_drops_the_oldest_reading_and_counts_it(self):
        queue = deque()
        for number in range(1, 4):
            gateway.enqueue(queue, make_reading(number), self.metrics, 2)
        self.assertEqual([r["sequence"] for r in queue], [2, 3])
        self.assertEqual(self.metrics.registry.get_sample_value("gateway_dropped_total"), 1)


class ResourceLimitTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()

    def test_per_gateway_session_cap_evicts_the_oldest(self):
        state = make_state(self.clock, max_sessions_per_gateway=2)
        with running_server(make_handler(state)) as url:
            client = make_client(url, state, self.clock)
            client.handshake()
            first = client.session.session_id
            self.clock.advance(1)
            client.handshake()
            self.clock.advance(1)
            client.handshake()
        self.assertEqual(len(state.sessions), 2)
        self.assertNotIn(first, state.sessions)

    def test_handshake_rate_limit_is_per_gateway_and_recovers(self):
        state = make_state(self.clock, handshakes_per_minute=2)
        with running_server(make_handler(state)) as url:
            client = make_client(url, state, self.clock)
            client.handshake()
            client.handshake()
            with self.assertRaises(gateway.HandshakeError):
                client.handshake()
            self.assertEqual(state.registry.get_sample_value("cloud_handshake_failures_total",
                                                             {"reason": "rate_limited"}), 1)
            self.clock.advance(61)
            client.handshake()

    def test_total_session_capacity_is_enforced(self):
        state = make_state(self.clock, gateways={"gw1": SECRET, "gw2": SECRET}, max_sessions=1)
        with running_server(make_handler(state)) as url:
            make_client(url, state, self.clock).handshake()
            with self.assertRaises(gateway.HandshakeError):
                make_client(url, state, self.clock, gateway_id="gw2").handshake()
        self.assertEqual(state.registry.get_sample_value("cloud_handshake_failures_total", {"reason": "capacity"}), 1)

    def test_pending_sessions_expire_without_a_confirming_record(self):
        state = make_state(self.clock, pending_ttl=30)
        with running_server(make_handler(state)) as url:
            client = make_client(url, state, self.clock)
            client.handshake()
            self.clock.advance(31)
            with self.assertRaises(gateway.SessionRejected):
                client._send_record(make_reading())


class MonitoringTests(HybridTestCase):
    def test_metrics_endpoint_exposes_migration_and_crypto_state(self):
        self.client.send(make_reading())
        post_raw(f"{self.url}/v2/handshake", b"junk")
        text = get_text(f"{self.url}/metrics")
        for expected in ("crypto_selftest_ok 1.0", "crypto_backend_info{", 'library="cryptography"',
                         "cloud_sessions_active 1.0", "cloud_received_readings 1.0",
                         "cloud_handshake_duration_seconds_count 1.0", "cloud_legacy_requests_total 0.0",
                         'cloud_handshake_failures_total{reason="malformed"} 1.0'):
            self.assertIn(expected, text)

    def test_gateway_metrics_report_mode_and_selftest(self):
        metrics = gateway.GatewayMetrics("hybrid")
        self.assertEqual(metrics.registry.get_sample_value("gateway_mode"), 1)
        self.assertEqual(metrics.registry.get_sample_value("crypto_selftest_ok"), 1)
        self.assertEqual(gateway.GatewayMetrics("legacy").registry.get_sample_value("gateway_mode"), 0)

    def test_failed_selftest_stops_startup(self):
        with mock.patch.object(crypto, "selftest", side_effect=crypto.CryptoSelfTestError("boom")):
            with self.assertRaises(crypto.CryptoSelfTestError):
                make_state(self.clock)

    def test_secrets_never_reach_metrics_or_logs(self):
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            self.client.send(make_reading())
            self.client.send(make_reading(2))
            post_raw(f"{self.url}/v2/handshake", build_handshake(self.clock, secret=bytes(32)))
            text = get_text(f"{self.url}/metrics")
        keys = self.client.session.keys
        haystack = captured.getvalue() + text
        for secret in (SECRET, keys.record_key, keys.mac_key):
            for rendering in (secret.hex(), crypto.b64e(secret)):
                self.assertNotIn(rendering, haystack)


class FuzzTests(HybridTestCase):
    def mutate(self, rng, payload):
        payload = dict(payload)
        key = rng.choice(sorted(payload))
        choice = rng.randrange(5)
        if choice == 0:
            del payload[key]
        elif choice == 1:
            payload[key] = rng.choice([None, 1, -1, 2**70, "x", [], {}, True, 1.5, ""])
        elif isinstance(payload[key], str):
            text = payload[key]
            payload[key] = (text[:-1], text + "!", "!" + text[1:])[choice - 2]
        else:
            payload[key] = None
        return payload

    def test_mutated_handshakes_never_crash_or_create_state(self):
        rng = random.Random(1234)
        valid = build_handshake(self.clock)
        for _ in range(300):
            mutated = self.mutate(rng, valid)
            try:
                self.state.handshake(mutated)
            except ProtocolError as error:
                self.assertLess(error.status, 500)
        self.assertEqual(self.state.sessions, {})

    def test_mutated_records_never_crash_or_store_readings(self):
        rng = random.Random(99)
        self.client.handshake()
        valid = build_record(self.client.session, 7)
        for _ in range(300):
            mutated = self.mutate(rng, valid)
            try:
                self.state.record(mutated)
            except ProtocolError as error:
                self.assertLess(error.status, 500)
        self.assertEqual(self.state.readings, [])


class SizeBudgetTests(unittest.TestCase):
    def test_handshake_size_per_suite(self):
        clock = FakeClock()
        sizes = {}
        for name in (DEFAULT, BIG):
            state = make_state(clock, suites=(name,))
            request = build_handshake(clock, suite=name)
            response = state.handshake(request)
            sizes[name] = len(json.dumps(request)) + len(json.dumps(response))
        self.assertLess(sizes[DEFAULT], 4_500)
        self.assertLess(sizes[BIG], 6_500)
        self.assertGreater(sizes[BIG], sizes[DEFAULT])


class WiringTests(unittest.TestCase):
    def test_provisioned_stack_from_environment_delivers_a_reading(self):
        with tempfile.TemporaryDirectory() as directory:
            provision(directory)
            before = {path.name: path.read_text() for path in Path(directory).iterdir()}
            provision(directory)
            self.assertEqual(before, {path.name: path.read_text() for path in Path(directory).iterdir()})

            state = state_from_env({
                "CLOUD_IDENTITY_KEY_FILE": f"{directory}/cloud_identity.key",
                "GATEWAY_REGISTRY_FILE": f"{directory}/registry.json",
                "ACCEPT_MODES": "hybrid",
            })
            self.assertFalse(state.legacy_active())
            with running_server(make_handler(state)) as url:
                metrics = gateway.GatewayMetrics("hybrid")
                forwarder = gateway.forwarder_from_env(metrics, {
                    "PREFERRED_MODE": "hybrid",
                    "CLOUD_URL": f"{url}/v1/readings",
                    "ENROLLMENT_SECRET_FILE": f"{directory}/gateway-01.secret",
                    "CLOUD_IDENTITY_PUB_FILE": f"{directory}/cloud_identity.pub",
                    "RATCHET_FILE": f"{directory}/ratchet.json",
                })
                forwarder.forward(make_reading())
            self.assertEqual(state.readings, [make_reading()])
            self.assertTrue(Path(directory, "ratchet.json").exists())

    def test_legacy_mode_is_the_default_for_the_gateway(self):
        forwarder = gateway.forwarder_from_env(gateway.GatewayMetrics("legacy"), {"CLOUD_URL": "http://c/v1/readings"})
        self.assertIsNone(forwarder.hybrid)

    def test_fallback_without_a_shared_key_is_a_startup_error(self):
        with tempfile.TemporaryDirectory() as directory:
            provision(directory)
            with self.assertRaises(SystemExit):
                gateway.forwarder_from_env(gateway.GatewayMetrics("hybrid"), {
                    "PREFERRED_MODE": "hybrid", "ALLOW_LEGACY_FALLBACK": "true",
                    "ENROLLMENT_SECRET_FILE": f"{directory}/gateway-01.secret",
                    "CLOUD_IDENTITY_PUB_FILE": f"{directory}/cloud_identity.pub",
                })

    def test_device_frames_are_authenticated_end_to_end(self):
        master = b"m" * 32
        clock = FakeClock()
        state = make_state(clock)
        with running_server(legacy_device.make_handler(master)) as device, \
                running_server(make_handler(state)) as url:
            reading = gateway.fetch_reading(f"{device}/v1/reading", master)
            self.assertNotIn("mac", reading)
            metrics = gateway.GatewayMetrics("hybrid")
            forwarder = gateway.Forwarder(metrics, cloud_url=f"{url}/v1/readings",
                                          hybrid=make_client(url, state, clock, metrics=metrics))
            queue = deque()
            gateway.enqueue(queue, reading, metrics, 10)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(gateway.drain(queue, forwarder, metrics))
            self.assertEqual(state.readings, [reading])
            with self.assertRaises(crypto.DeviceAuthError):
                gateway.fetch_reading(f"{device}/v1/reading", b"n" * 32)
        with running_server(legacy_device.make_handler(None)) as device:
            with self.assertRaises(crypto.DeviceAuthError):
                gateway.fetch_reading(f"{device}/v1/reading", master)
            self.assertIn("device_id", gateway.fetch_reading(f"{device}/v1/reading"))


if __name__ == "__main__":
    unittest.main()
