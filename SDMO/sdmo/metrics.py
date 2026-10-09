from http.server import BaseHTTPRequestHandler

from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Gauge, Info, generate_latest

from sdmo import crypto


def send_metrics(handler: BaseHTTPRequestHandler, registry: CollectorRegistry) -> None:
    body = generate_latest(registry)
    handler.send_response(200)
    handler.send_header("Content-Type", CONTENT_TYPE_LATEST)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def register_crypto_metrics(registry: CollectorRegistry) -> None:
    """Expose the crypto inventory and run the startup self-test; raises if the self-test fails."""
    Info("crypto_backend", "Cryptographic backend in use", registry=registry).info(crypto.backend_info())
    selftest_ok = Gauge("crypto_selftest_ok", "1 if the ML-KEM startup self-test passed", registry=registry)
    selftest_ok.set(0)
    crypto.selftest()
    selftest_ok.set(1)
