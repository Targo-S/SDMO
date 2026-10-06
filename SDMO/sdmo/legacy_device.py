import itertools
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sdmo.common import send_json


def make_handler():
    sequence = itertools.count(1)
    device_id = os.environ.get("DEVICE_ID", "legacy-sensor-01")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/healthz":
                send_json(self, 200, {"status": "ok"})
            elif self.path == "/v1/reading":
                number = next(sequence)
                send_json(self, 200, {
                    "device_id": device_id,
                    "sequence": number,
                    "temperature_c": round(21.5 + ((number % 7) - 3) * 0.2, 1),
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                })
            else:
                send_json(self, 404, {"error": "not found"})

        def log_message(self, format, *args):
            print(f"device: {format % args}")

    return Handler


if __name__ == "__main__":
    port = int(os.environ.get("DEVICE_PORT", "8082"))
    print(f"legacy device listening on :{port}")
    ThreadingHTTPServer(("0.0.0.0", port), make_handler()).serve_forever()
