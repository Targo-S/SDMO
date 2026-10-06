import hmac
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sdmo.common import read_json, send_json


class CloudState:
    def __init__(self, shared_key):
        self.shared_key = shared_key
        self.readings = []
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
            if not hmac.compare_digest(self.headers.get("X-Legacy-Shared-Key", ""), state.shared_key):
                with state.lock:
                    state.rejected += 1
                send_json(self, 401, {"error": "unauthorized"})
                return
            try:
                reading = read_json(self)
                required = {"device_id", "sequence", "temperature_c", "observed_at"}
                if not isinstance(reading, dict) or not required.issubset(reading):
                    raise ValueError("missing fields")
            except (ValueError, TypeError):
                send_json(self, 400, {"error": "invalid reading"})
                return
            with state.lock:
                state.readings.append(reading)
            send_json(self, 202, {"accepted": True})

        def log_message(self, format, *args):
            print(f"cloud: {format % args}")

    return Handler


if __name__ == "__main__":
    port = int(os.environ.get("CLOUD_PORT", "8081"))
    key = os.environ.get("SHARED_KEY", "demo-only-change-me")
    print(f"cloud service listening on :{port}")
    ThreadingHTTPServer(("0.0.0.0", port), make_handler(CloudState(key))).serve_forever()
