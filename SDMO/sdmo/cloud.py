import hmac
import math
import os
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sdmo.common import read_json, send_json

REQUIRED_FIELDS = {"device_id", "sequence", "temperature_c", "observed_at"}
MAX_DEVICE_ID_LENGTH = 64
MIN_TEMPERATURE_C, MAX_TEMPERATURE_C = -60.0, 100.0

def validate_reading(reading):
    if not isinstance(reading, dict) or not REQUIRED_FIELDS.issubset(reading):
        raise ValueError("missing fields")
    device_id = reading["device_id"]
    if not isinstance(device_id, str) or not 1 <= len(device_id) <= MAX_DEVICE_ID_LENGTH:
        raise ValueError("invalid device_id")
    sequence = reading["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise ValueError("invalid sequence")
    temp = reading["temperature_c"]
    if isinstance(temp, bool) or not isinstance(temp, (int, float)) or not math.isfinite(temp):
        raise ValueError("invalid temperature_c")
    if not MIN_TEMPERATURE_C <= temp <= MAX_TEMPERATURE_C:
        raise ValueError("temperature_c out of range")
    observed_at = reading["observed_at"]
    if not isinstance(observed_at, str) or datetime.fromisoformat(observed_at).tzinfo is None:
        raise ValueError("observed_at must be an ISO 8601 timestamp with timezone")

def key_matches(provided, expected):
    if not expected:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))

class CloudState:
    def __init__(self, shared_key):
        self.shared_key = shared_key
        self.readings = []
        self.last_sequence = {}
        self.rejected = 0
        self.lock = threading.Lock()


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/healthz":
                send_json(self, 200, {"status": "ok"})
            elif self.path == "/v1/readings":
                with state.lock:
                    send_json(self, 200, {"readings": list(state.readings)})
            elif self.path == "/metrics":
                with state.lock:
                    body = (f"cloud_received_readings {len(state.readings)}\n"
                            f"cloud_rejected_requests {state.rejected}\n").encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                send_json(self, 404, {"error": "not found"})

        def do_POST(self):
            if self.path != "/v1/readings":
                send_json(self, 404, {"error": "not found"})
                return
            if not key_matches(self.headers.get("X-Legacy-Shared-Key", ""), state.shared_key):
                with state.lock:
                    state.rejected += 1
                send_json(self, 401, {"error": "unauthorized"})
                return
            try:
                reading = read_json(self)
                validate_reading(reading)
            except (ValueError, TypeError):
                send_json(self, 400, {"error": "invalid reading"})
                return
            with state.lock:
                last = state.last_sequence.get(reading["device_id"])
                is_replay = last is not None and reading["sequence"] <= last
                if not is_replay:
                    state.last_sequence[reading["device_id"]] = reading["sequence"]
                    state.readings.append(reading)
            if is_replay:
                send_json(self, 409, {"error": "duplicate or out-of-order sequence"})
                return
            send_json(self, 202, {"accepted": True})

        def log_message(self, format, *args):
            print(f"cloud: {format % args}")

    return Handler


if __name__ == "__main__":
    port = int(os.environ.get("CLOUD_PORT", "8081"))
    key = os.environ.get("SHARED_KEY", "demo-only-change-me")
    print(f"cloud service listening on :{port}")
    ThreadingHTTPServer(("0.0.0.0", port), make_handler(CloudState(key))).serve_forever()
