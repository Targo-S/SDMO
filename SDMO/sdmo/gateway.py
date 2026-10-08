import hmac
import json
import os
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

from sdmo import crypto
from sdmo.common import send_json
from sdmo.metrics import register_crypto_metrics, send_metrics

MODE_VALUES = {"legacy": 0, "hybrid": 1}


class GatewayError(Exception):
    pass


class V2Unsupported(GatewayError):
    """The cloud does not offer the /v2 protocol."""


class UnsupportedSuite(GatewayError):
    pass


class HandshakeError(GatewayError):
    pass


class SessionRejected(GatewayError):
    pass


class GatewayMetrics:
    def __init__(self, mode="legacy"):
        self.registry = CollectorRegistry()
        self.forwarded = Counter("gateway_forwarded", "Readings delivered", registry=self.registry)
        self.errors = Counter("gateway_errors", "Failed polls or deliveries", registry=self.registry)
        self.dropped = Counter("gateway_dropped", "Readings dropped from a full queue", registry=self.registry)
        self.fallbacks = Counter("gateway_fallback", "Deliveries that fell back to the static key",
                                 registry=self.registry)
        self.device_auth_failures = Counter("gateway_device_auth_failures", "Readings with a bad device MAC",
                                            registry=self.registry)
        self.handshakes = Counter("gateway_handshakes", "Handshake attempts", ["result"], registry=self.registry)
        self.rekeys = Counter("gateway_rekeys", "Sessions replaced by a new handshake", registry=self.registry)
        self.handshake_seconds = Histogram("gateway_handshake_duration_seconds", "Handshake duration",
                                           registry=self.registry)
        self.queue_depth = Gauge("gateway_queue_depth", "Readings waiting for delivery", registry=self.registry)
        Gauge("gateway_mode", "0 = legacy static key, 1 = hybrid ML-KEM", registry=self.registry).set(
            MODE_VALUES[mode])
        if mode == "hybrid":
            register_crypto_metrics(self.registry)


def fetch_reading(device_url, device_master=None):
    with urlopen(device_url, timeout=5) as response:
        reading = json.load(response)
    if device_master is not None:
        reading = crypto.verify_reading(device_master, reading)
    return reading


def forward_legacy(cloud_url, shared_key, reading):
    request = Request(
        cloud_url,
        data=json.dumps(reading).encode(),
        headers={"Content-Type": "application/json", "X-Legacy-Shared-Key": shared_key},
        method="POST",
    )
    with urlopen(request, timeout=5) as response:
        if response.status != 202:
            raise URLError(f"cloud returned HTTP {response.status}")


def poll_once(device_url, cloud_url, shared_key, device_master=None):
    reading = fetch_reading(device_url, device_master)
    forward_legacy(cloud_url, shared_key, reading)
    return reading


def _post_json(url, payload, timeout):
    request = Request(url, data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        try:
            body = json.load(error)
        except ValueError:
            body = {}
        finally:
            error.close()
        return error.code, body


class HybridSession:
    def __init__(self, session_id, keys, created):
        self.session_id = session_id
        self.keys = keys
        self.created = created
        self.counter = 0
        self.records = 0


class HybridClient:
    def __init__(self, base_url, gateway_id, enrollment_secret, cloud_public_key, suites=(crypto.DEFAULT_SUITE,),
                 *, rekey_seconds=1800, rekey_records=5000, timeout=5, clock=time.time, metrics=None):
        unknown = [name for name in suites if name not in crypto.SUITES]
        if unknown:
            raise ValueError(f"unsupported suites: {unknown}")
        self.base_url = base_url.rstrip("/")
        self.gateway_id = gateway_id
        self.secret = enrollment_secret
        self.cloud_public_key = cloud_public_key
        self.suites = tuple(suites)
        self.rekey_seconds = rekey_seconds
        self.rekey_records = rekey_records
        self.timeout = timeout
        self.clock = clock
        self.metrics = metrics or GatewayMetrics()
        self.session = None

    def handshake(self):
        started = time.perf_counter()
        had_session = self.session is not None
        result = "error"
        try:
            for name in self.suites:
                try:
                    self.session = self._handshake(name)
                    break
                except UnsupportedSuite:
                    continue
            else:
                raise HandshakeError("no mutually supported suite")
            result = "ok"
            if had_session:
                self.metrics.rekeys.inc()
        except V2Unsupported:
            result = "unsupported"
            raise
        except HandshakeError:
            result = "rejected"
            raise
        finally:
            self.metrics.handshakes.labels(result).inc()
            self.metrics.handshake_seconds.observe(time.perf_counter() - started)

    def _handshake(self, suite_name):
        suite = crypto.SUITES[suite_name]
        kem_private, ek = crypto.kem_generate(suite)
        x_private = X25519PrivateKey.generate()
        x25519_g = x_private.public_key().public_bytes_raw()
        nonce_g = os.urandom(16)
        timestamp = int(self.clock())
        mac = crypto.request_mac(self.secret, self.gateway_id, suite_name, ek, x25519_g, nonce_g, timestamp)
        status, body = _post_json(self.base_url + "/v2/handshake", {
            "v": crypto.PROTOCOL_VERSION,
            "gateway_id": self.gateway_id,
            "suite": suite_name,
            "mlkem_ek": crypto.b64e(ek),
            "x25519": crypto.b64e(x25519_g),
            "nonce": crypto.b64e(nonce_g),
            "timestamp": timestamp,
            "mac": crypto.b64e(mac),
        }, self.timeout)
        if status in (404, 405):
            raise V2Unsupported("cloud has no /v2 handshake")
        if status == 400 and body.get("error") == "unsupported_suite":
            raise UnsupportedSuite(suite_name)
        if status != 200:
            raise HandshakeError(f"handshake rejected with HTTP {status}")
        try:
            if body["suite"] != suite_name or body["v"] != crypto.PROTOCOL_VERSION:
                raise ValueError("suite or version changed")
            session_id = body["session_id"]
            session_bytes = crypto.b64d(session_id, 16)
            ct = crypto.b64d(body["ct"], suite.ct_len)
            x25519_c = crypto.b64d(body["x25519"], 32)
            nonce_c = crypto.b64d(body["nonce"], 16)
            signature = crypto.b64d(body["signature"], 64)
            confirm = crypto.b64d(body["confirm"], 32)
            transcript = crypto.transcript_hash(self.gateway_id, suite_name, ek, x25519_g, nonce_g, timestamp,
                                                ct, x25519_c, nonce_c, session_bytes)
            if not crypto.verify_transcript(self.cloud_public_key, transcript, signature):
                raise HandshakeError("cloud signature invalid")
            ss_pq = crypto.kem_decapsulate(suite, kem_private, ct)
            ss_ec = x_private.exchange(X25519PublicKey.from_public_bytes(x25519_c))
        except (KeyError, ValueError, TypeError) as error:
            raise HandshakeError(f"malformed handshake response: {error}") from error
        keys = crypto.derive_keys(ss_pq, ss_ec, nonce_g, nonce_c, transcript)
        if not hmac.compare_digest(crypto.confirm_tag(keys.mac_key, transcript), confirm):
            raise HandshakeError("key confirmation failed")
        return HybridSession(session_id, keys, self.clock())

    def _needs_rekey(self):
        session = self.session
        return (self.clock() - session.created >= self.rekey_seconds
                or session.records >= self.rekey_records)

    def send(self, reading):
        if self.session is None or self._needs_rekey():
            self.handshake()
        try:
            self._send_record(reading)
        except SessionRejected:
            self.handshake()
            self._send_record(reading)

    def _send_record(self, reading):
        session = self.session
        counter = session.counter
        session.counter += 1  # burn the counter even on failure so a retry never reuses a nonce
        ciphertext = crypto.seal_record(session.keys.record_key, session.session_id, counter,
                                        json.dumps(reading).encode())
        status, body = _post_json(self.base_url + "/v2/readings", {
            "session_id": session.session_id,
            "counter": counter,
            "ciphertext": crypto.b64e(ciphertext),
        }, self.timeout)
        if status == 401:
            raise SessionRejected("cloud rejected the session")
        if status != 202:
            raise GatewayError(f"cloud returned HTTP {status}")
        try:
            ack = crypto.b64d(body["ack"], 32)
        except (KeyError, ValueError, TypeError) as error:
            raise GatewayError("malformed acknowledgement") from error
        if not hmac.compare_digest(ack, crypto.ack_tag(session.keys.mac_key, session.session_id, counter)):
            raise GatewayError("acknowledgement authentication failed")
        session.records += 1


class Ratchet:
    """Once a peer has completed a v2 handshake, static-key fallback to it is refused."""

    def __init__(self, peer, path=None):
        self.peer = peer
        self.path = path
        self.required = self._load()

    def _load(self):
        if not self.path or not os.path.exists(self.path):
            return False
        with open(self.path) as stored:
            return self.peer in json.load(stored).get("v2_required", [])

    def mark(self):
        if self.required:
            return
        self.required = True
        if self.path:
            temporary = self.path + ".tmp"
            with open(temporary, "w") as stored:
                json.dump({"v2_required": [self.peer]}, stored)
            os.replace(temporary, self.path)


class Forwarder:
    def __init__(self, metrics, *, cloud_url, shared_key=None, hybrid=None, allow_legacy_fallback=False,
                 ratchet=None):
        self.metrics = metrics
        self.cloud_url = cloud_url
        self.shared_key = shared_key
        self.hybrid = hybrid
        self.allow_legacy_fallback = allow_legacy_fallback
        self.ratchet = ratchet or Ratchet(cloud_url)

    def forward(self, reading):
        if self.hybrid is None:
            forward_legacy(self.cloud_url, self.shared_key, reading)
            return
        try:
            self.hybrid.send(reading)
        except V2Unsupported:
            if not self.allow_legacy_fallback or self.ratchet.required:
                raise
            print("gateway: WARNING cloud has no v2; falling back to the static key")
            self.metrics.fallbacks.inc()
            forward_legacy(self.cloud_url, self.shared_key, reading)
            return
        self.ratchet.mark()


def drain(queue, forwarder, metrics):
    """Deliver queued readings in order; stop at the first failure and keep the rest queued."""
    while queue:
        try:
            forwarder.forward(queue[0])
        except (OSError, ValueError, GatewayError) as error:
            metrics.errors.inc()
            metrics.queue_depth.set(len(queue))
            print(f"delivery failed: {error}")
            return False
        reading = queue.popleft()
        metrics.forwarded.inc()
        print(f"forwarded {reading['device_id']} sequence={reading['sequence']}")
    metrics.queue_depth.set(0)
    return True


def enqueue(queue, reading, metrics, max_size):
    if len(queue) >= max_size:
        queue.popleft()
        metrics.dropped.inc()
    queue.append(reading)


def make_handler(registry):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/healthz":
                send_json(self, 200, {"status": "ok"})
            elif self.path == "/metrics":
                send_metrics(self, registry)
            else:
                send_json(self, 404, {"error": "not found"})

        def log_message(self, format, *args):
            print(f"gateway: {format % args}")

    return Handler


def _flag(value):
    return value.strip().lower() in {"1", "true", "yes"}


def forwarder_from_env(metrics, env=os.environ):
    cloud_url = env.get("CLOUD_URL", "http://localhost:8081/v1/readings")
    shared_key = env.get("SHARED_KEY")
    fallback = _flag(env.get("ALLOW_LEGACY_FALLBACK", "false"))
    hybrid = None
    if env.get("PREFERRED_MODE", "legacy") == "hybrid":
        parts = urlsplit(env.get("CLOUD_BASE_URL") or cloud_url)
        base_url = f"{parts.scheme}://{parts.netloc}"
        hybrid = HybridClient(
            base_url,
            env.get("GATEWAY_ID", "gateway-01"),
            crypto.load_hex_secret(env["ENROLLMENT_SECRET_FILE"]),
            crypto.load_hex_secret(env["CLOUD_IDENTITY_PUB_FILE"], 32),
            tuple(suite.strip() for suite in env.get("KEM_SUITES", crypto.DEFAULT_SUITE).split(",")),
            rekey_seconds=float(env.get("REKEY_SECONDS", "1800")),
            rekey_records=int(env.get("REKEY_RECORDS", "5000")),
            metrics=metrics,
        )
        if fallback and not shared_key:
            raise SystemExit("ALLOW_LEGACY_FALLBACK needs SHARED_KEY")
        return Forwarder(metrics, cloud_url=cloud_url, shared_key=shared_key, hybrid=hybrid,
                         allow_legacy_fallback=fallback,
                         ratchet=Ratchet(base_url, env.get("RATCHET_FILE")))
    return Forwarder(metrics, cloud_url=cloud_url, shared_key=shared_key or "demo-only-change-me")


if __name__ == "__main__":
    device = os.environ.get("DEVICE_URL", "http://localhost:8082/v1/reading")
    interval = float(os.environ.get("POLL_SECONDS", "5"))
    queue_size = int(os.environ.get("QUEUE_SIZE", "1000"))
    master_file = os.environ.get("DEVICE_MASTER_FILE")
    device_master = crypto.load_hex_secret(master_file) if master_file else None
    mode = os.environ.get("PREFERRED_MODE", "legacy")
    gateway_metrics = GatewayMetrics(mode)
    gateway_forwarder = forwarder_from_env(gateway_metrics)
    pending = deque()
    port = int(os.environ.get("GATEWAY_PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), make_handler(gateway_metrics.registry))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"gateway listening on :{port}; mode={mode}; polling every {interval:g}s")
    failures = 0
    while True:
        try:
            enqueue(pending, fetch_reading(device, device_master), gateway_metrics, queue_size)
        except (OSError, ValueError) as error:
            gateway_metrics.errors.inc()
            if isinstance(error, crypto.DeviceAuthError):
                gateway_metrics.device_auth_failures.inc()
            print(f"poll failed: {error}")
        failures = 0 if drain(pending, gateway_forwarder, gateway_metrics) else failures + 1
        time.sleep(min(interval * 2 ** min(failures, 6), 60) if failures else interval)
