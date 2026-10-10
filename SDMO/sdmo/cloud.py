import hmac
import json
import os
import secrets
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

from sdmo import crypto
from sdmo.common import read_json, send_json
from sdmo.metrics import register_crypto_metrics, send_metrics

REQUIRED_READING = {"device_id", "sequence", "temperature_c", "observed_at"}
MAX_RECORD_BYTES = 8192
NONCE_CACHE_SIZE = 4096
MAX_DEVICE_ID_LEN = 64
MIN_TEMPERATURE_C = -50.0
MAX_TEMPERATURE_C = 100.0
MAX_CLOCK_SKEW_FUTURE = timedelta(minutes=5)
MAX_CLOCK_SKEW_PAST = timedelta(days=365)


class ProtocolError(Exception):
    def __init__(self, status, reason, extra=None):
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.extra = extra or {}


@dataclass
class Session:
    session_id: str
    gateway_id: str
    suite: str
    record_key: bytes
    mac_key: bytes
    created: float
    last_counter: int = -1
    records: int = 0
    active: bool = False


def _valid_reading(reading):
    """Return the validated reading dict, or None if the reading is invalid."""
    if not isinstance(reading, dict) or not REQUIRED_READING.issubset(reading):
        return None

    device_id = reading["device_id"]
    if not isinstance(device_id, str) or not device_id or len(device_id) > MAX_DEVICE_ID_LEN:
        return None

    sequence = reading["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
        return None

    temperature = reading["temperature_c"]
    if isinstance(temperature, bool) or not isinstance(temperature, (int, float)):
        return None
    if not MIN_TEMPERATURE_C <= temperature <= MAX_TEMPERATURE_C:
        return None

    observed_at = reading["observed_at"]
    if not isinstance(observed_at, str):
        return None
    try:
        timestamp = datetime.fromisoformat(observed_at)
        if timestamp.utcoffset() is None:
            return None
        now = datetime.now(timezone.utc)
        if timestamp > now + MAX_CLOCK_SKEW_FUTURE or timestamp < now - MAX_CLOCK_SKEW_PAST:
            return None
    except (OverflowError, ValueError):
        return None

    return reading


class CloudState:
    def __init__(self, shared_key=None, *, identity_key=None, gateways=None, accept_modes=None,
                 suites=(crypto.DEFAULT_SUITE,), legacy_until=None, session_ttl=3600,
                 session_max_records=10_000, pending_ttl=30, max_sessions=1024,
                 max_sessions_per_gateway=4, handshakes_per_minute=30, clock_skew=60, clock=time.time):
        if accept_modes is None:
            accept_modes = ("legacy",) + (("hybrid",) if identity_key is not None else ())
        if not set(accept_modes) <= {"legacy", "hybrid"}:
            raise ValueError("accept_modes may only contain 'legacy' and 'hybrid'")
        if "hybrid" in accept_modes and (identity_key is None or not gateways):
            raise ValueError("hybrid mode needs an identity key and a gateway registry")
        if "legacy" in accept_modes and shared_key is None:
            raise ValueError("legacy mode needs a shared key")
        unknown = [name for name in suites if name not in crypto.SUITES]
        if unknown:
            raise ValueError(f"unsupported suites: {unknown}")

        self.shared_key = shared_key
        self.identity_key = identity_key
        self.gateways = dict(gateways or {})
        self.accept_modes = tuple(accept_modes)
        self.suites = tuple(suites)
        self.legacy_until = legacy_until
        self.session_ttl = session_ttl
        self.session_max_records = session_max_records
        self.pending_ttl = pending_ttl
        self.max_sessions = max_sessions
        self.max_sessions_per_gateway = max_sessions_per_gateway
        self.handshakes_per_minute = handshakes_per_minute
        self.clock_skew = clock_skew
        self.clock = clock

        self.readings = []
        self.rejected = 0
        self.seen_sequences = set()
        self.sessions = {}
        self.lock = threading.Lock()
        self._handshake_times = {}
        self._seen_nonces = OrderedDict()

        self.registry = CollectorRegistry()
        self.m_handshakes = Counter("cloud_handshakes", "Handshake attempts",
                                    ["mode", "suite", "result"], registry=self.registry)
        self.m_handshake_failures = Counter("cloud_handshake_failures", "Failed handshakes",
                                            ["reason"], registry=self.registry)
        self.m_legacy = Counter("cloud_legacy_requests", "Static-key requests (migration KPI)",
                                registry=self.registry)
        self.m_record_rejects = Counter("cloud_records_rejected", "Rejected v2 records",
                                        ["reason"], registry=self.registry)
        self.m_duplicates = Counter(
            "cloud_duplicate_readings", "Duplicate (device_id, sequence) pairs rejected",
            registry=self.registry)
        self.m_handshake_seconds = Histogram("cloud_handshake_duration_seconds", "Handshake duration",
                                             registry=self.registry)
        Gauge("cloud_received_readings", "Stored readings", registry=self.registry).set_function(
            lambda: len(self.readings))
        Gauge("cloud_rejected_requests", "Rejected legacy requests",
              registry=self.registry).set_function(lambda: self.rejected)
        Gauge("cloud_sessions_active", "Active v2 sessions", registry=self.registry).set_function(
            self._active_sessions)
        Gauge("cloud_session_age_seconds", "Age of the oldest active v2 session",
              registry=self.registry).set_function(self._oldest_session_age)
        if self.hybrid_enabled:
            register_crypto_metrics(self.registry)

    @property
    def hybrid_enabled(self):
        return "hybrid" in self.accept_modes

    @property
    def identity_public(self):
        return self.identity_key.public_key().public_bytes_raw()

    def legacy_active(self):
        if "legacy" not in self.accept_modes:
            return False
        return self.legacy_until is None or self.clock() < self.legacy_until

    def _active_sessions(self):
        now = self.clock()
        with self.lock:
            return sum(1 for s in self.sessions.values() if s.active and not self._is_expired(s, now))

    def _oldest_session_age(self):
        now = self.clock()
        with self.lock:
            created = [s.created for s in self.sessions.values() if s.active and not self._is_expired(s, now)]
        return now - min(created) if created else 0

    def _is_expired(self, session, now):
        limit = self.session_ttl if session.active else self.pending_ttl
        return now - session.created > limit or session.records >= self.session_max_records

    def handshake(self, request):
        name = request.get("suite") if isinstance(request, dict) else None
        label = name if isinstance(name, str) and name in crypto.SUITES else "unknown"
        started = time.perf_counter()
        try:
            response = self._handshake(request)
        except ProtocolError as error:
            self.m_handshake_failures.labels(error.reason).inc()
            self.m_handshakes.labels("hybrid", label, "failed").inc()
            raise
        self.m_handshakes.labels("hybrid", label, "ok").inc()
        self.m_handshake_seconds.observe(time.perf_counter() - started)
        return response

    def _handshake(self, request):
        if not isinstance(request, dict):
            raise ProtocolError(400, "malformed")
        if request.get("v") != crypto.PROTOCOL_VERSION:
            raise ProtocolError(400, "bad_version")
        gateway_id = request.get("gateway_id")
        if not isinstance(gateway_id, str):
            raise ProtocolError(400, "malformed")
        secret = self.gateways.get(gateway_id)
        if secret is None:
            raise ProtocolError(401, "unknown_gateway")
        suite_name = request.get("suite")
        if not isinstance(suite_name, str) or suite_name not in self.suites:
            raise ProtocolError(400, "unsupported_suite", {"supported": list(self.suites)})
        suite = crypto.SUITES[suite_name]
        try:
            ek = crypto.b64d(request["mlkem_ek"], suite.ek_len)
            x25519_g = crypto.b64d(request["x25519"], 32)
            nonce_g = crypto.b64d(request["nonce"], 16)
            mac = crypto.b64d(request["mac"], 32)
            timestamp = request["timestamp"]
            if type(timestamp) is not int or not 0 <= timestamp < 2**63:
                raise ValueError("bad timestamp")
        except (KeyError, ValueError, TypeError):
            raise ProtocolError(400, "malformed") from None

        # Authenticate before doing any KEM work or allocating session state.
        expected = crypto.request_mac(secret, gateway_id, suite_name, ek, x25519_g, nonce_g, timestamp)
        if not hmac.compare_digest(expected, mac):
            raise ProtocolError(401, "bad_mac")
        now = self.clock()
        if abs(now - timestamp) > self.clock_skew:
            raise ProtocolError(401, "stale_timestamp")

        with self.lock:
            self._check_replay(gateway_id, nonce_g, now)
            self._check_rate(gateway_id, now)
            self._make_room(gateway_id, now)
            try:
                ss_pq, ct = crypto.kem_encapsulate(suite, ek)
                x_private = X25519PrivateKey.generate()
                ss_ec = x_private.exchange(X25519PublicKey.from_public_bytes(x25519_g))
            except ValueError:
                raise ProtocolError(400, "malformed") from None
            x25519_c = x_private.public_key().public_bytes_raw()
            nonce_c = secrets.token_bytes(16)
            session_bytes = secrets.token_bytes(16)
            session_id = crypto.b64e(session_bytes)
            transcript = crypto.transcript_hash(gateway_id, suite_name, ek, x25519_g, nonce_g, timestamp,
                                                ct, x25519_c, nonce_c, session_bytes)
            keys = crypto.derive_keys(ss_pq, ss_ec, nonce_g, nonce_c, transcript)
            self.sessions[session_id] = Session(session_id, gateway_id, suite_name, keys.record_key,
                                                keys.mac_key, now)
        return {
            "v": crypto.PROTOCOL_VERSION,
            "session_id": session_id,
            "suite": suite_name,
            "ct": crypto.b64e(ct),
            "x25519": crypto.b64e(x25519_c),
            "nonce": crypto.b64e(nonce_c),
            "signature": crypto.b64e(crypto.sign_transcript(self.identity_key, transcript)),
            "confirm": crypto.b64e(crypto.confirm_tag(keys.mac_key, transcript)),
        }

    def _check_replay(self, gateway_id, nonce, now):
        while self._seen_nonces and next(iter(self._seen_nonces.values())) < now:
            self._seen_nonces.popitem(last=False)
        key = (gateway_id, nonce)
        if key in self._seen_nonces:
            raise ProtocolError(401, "replay")
        self._seen_nonces[key] = now + 2 * self.clock_skew
        if len(self._seen_nonces) > NONCE_CACHE_SIZE:
            self._seen_nonces.popitem(last=False)

    def _check_rate(self, gateway_id, now):
        times = self._handshake_times.setdefault(gateway_id, deque())
        while times and times[0] <= now - 60:
            times.popleft()
        if len(times) >= self.handshakes_per_minute:
            raise ProtocolError(429, "rate_limited")
        times.append(now)

    def _make_room(self, gateway_id, now):
        for session_id in [sid for sid, s in self.sessions.items() if self._is_expired(s, now)]:
            del self.sessions[session_id]
        own = [s for s in self.sessions.values() if s.gateway_id == gateway_id]
        while len(own) >= self.max_sessions_per_gateway:
            oldest = min(own, key=lambda s: s.created)
            own.remove(oldest)
            del self.sessions[oldest.session_id]
        if len(self.sessions) >= self.max_sessions:
            raise ProtocolError(503, "capacity")

    def record(self, request):
        try:
            session_id, counter, ciphertext = self._parse_record(request)
            ack = self._accept_record(session_id, counter, ciphertext)
        except ProtocolError as error:
            self.m_record_rejects.labels(error.reason).inc()
            raise
        return {"accepted": True, "counter": counter, "ack": crypto.b64e(ack)}

    @staticmethod
    def _parse_record(request):
        try:
            session_id, counter = request["session_id"], request["counter"]
            if not isinstance(session_id, str) or type(counter) is not int or not 0 <= counter < 2**64:
                raise ValueError("bad fields")
            ciphertext = crypto.b64d(request["ciphertext"])
            if not 16 <= len(ciphertext) <= MAX_RECORD_BYTES:
                raise ValueError("bad ciphertext size")
        except (KeyError, ValueError, TypeError):
            raise ProtocolError(400, "malformed") from None
        return session_id, counter, ciphertext

    def _accept_record(self, session_id, counter, ciphertext):
        now = self.clock()
        with self.lock:
            session = self.sessions.get(session_id)
            if session is None:
                raise ProtocolError(401, "unknown_session")
            if self._is_expired(session, now):
                del self.sessions[session_id]
                raise ProtocolError(401, "expired")
            if counter <= session.last_counter:
                raise ProtocolError(401, "replay")
            try:
                plaintext = crypto.open_record(session.record_key, session_id, counter, ciphertext)
            except InvalidTag:
                raise ProtocolError(401, "aead_fail") from None
            # The first authentic record is the gateway's key confirmation.
            session.active = True
            session.last_counter = counter
            session.records += 1
            try:
                reading = json.loads(plaintext)
            except ValueError:
                raise ProtocolError(400, "invalid_reading") from None
            validated = _valid_reading(reading)
            if validated is None:
                raise ProtocolError(400, "invalid_reading")
            key = (validated["device_id"], validated["sequence"])
            if key in self.seen_sequences:
                self.m_duplicates.inc()
                raise ProtocolError(409, "duplicate_sequence")
            self.seen_sequences.add(key)
            self.readings.append(validated)
            return crypto.ack_tag(session.mac_key, session_id, counter)


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/healthz":
                send_json(self, 200, {"status": "ok"})
            elif self.path == "/v1/readings":
                with state.lock:
                    send_json(self, 200, {"readings": list(state.readings)})
            elif self.path == "/metrics":
                send_metrics(self, state.registry)
            else:
                send_json(self, 404, {"error": "not found"})

        def do_POST(self):
            if self.path == "/v1/readings":
                self._legacy_reading()
            elif self.path == "/v2/handshake" and state.hybrid_enabled:
                self._v2(state.handshake, 200)
            elif self.path == "/v2/readings" and state.hybrid_enabled:
                self._v2(state.record, 202)
            else:
                send_json(self, 404, {"error": "not found"})

        def _v2(self, operation, success_status):
            try:
                payload = read_json(self)
            except ValueError:
                payload = None
            try:
                response = operation(payload)
            except ProtocolError as error:
                body = {"error": "unauthorized" if error.status == 401 else error.reason, **error.extra}
                send_json(self, error.status, body)
                return
            send_json(self, success_status, response)

        def _legacy_reading(self):
            state.m_legacy.inc()
            if not state.legacy_active():
                send_json(self, 410, {"error": "legacy mode retired"})
                return
            if state.hybrid_enabled:
                print("cloud: DEPRECATED static-key request")
            if not hmac.compare_digest(self.headers.get("X-Legacy-Shared-Key", ""), state.shared_key):
                with state.lock:
                    state.rejected += 1
                send_json(self, 401, {"error": "unauthorized"})
                return
            try:
                reading = read_json(self)
            except (ValueError, TypeError):
                send_json(self, 400, {"error": "invalid reading"})
                return

            validated = _valid_reading(reading)
            if validated is None:
                with state.lock:
                    state.rejected += 1
                send_json(self, 400, {"error": "invalid reading"})
                return

            with state.lock:
                key = (validated["device_id"], validated["sequence"])
                if key in state.seen_sequences:
                    state.rejected += 1
                    state.m_duplicates.inc()
                    duplicate = True
                else:
                    state.seen_sequences.add(key)
                    state.readings.append(validated)
                    duplicate = False
            if duplicate:
                send_json(self, 409, {"error": "duplicate sequence"})
                return
            send_json(self, 202, {"accepted": True})

        def log_message(self, format, *args):
            print(f"cloud: {format % args}")

    return Handler


def state_from_env(env=os.environ):
    identity_path = env.get("CLOUD_IDENTITY_KEY_FILE")
    identity_key = None
    gateways = None
    if identity_path:
        identity_key = Ed25519PrivateKey.from_private_bytes(crypto.load_hex_secret(identity_path, 32))
        with open(env["GATEWAY_REGISTRY_FILE"]) as registry:
            gateways = {gateway_id: bytes.fromhex(secret) for gateway_id, secret in json.load(registry).items()}
    default_modes = "legacy,hybrid" if identity_path else "legacy"
    modes = tuple(mode.strip() for mode in env.get("ACCEPT_MODES", default_modes).split(","))
    legacy_until = env.get("LEGACY_UNTIL")
    return CloudState(
        env.get("SHARED_KEY", "demo-only-change-me") if "legacy" in modes else None,
        identity_key=identity_key,
        gateways=gateways,
        accept_modes=modes,
        suites=tuple(suite.strip() for suite in env.get("KEM_SUITES", crypto.DEFAULT_SUITE).split(",")),
        legacy_until=datetime.fromisoformat(legacy_until).timestamp() if legacy_until else None,
    )


if __name__ == "__main__":
    port = int(os.environ.get("CLOUD_PORT", "8081"))
    cloud_state = state_from_env()
    print(f"cloud service listening on :{port}; accepting {','.join(cloud_state.accept_modes)}")
    ThreadingHTTPServer(("0.0.0.0", port), make_handler(cloud_state)).serve_forever()
