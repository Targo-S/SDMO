import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from sdmo.common import send_json


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = build_opener(NoRedirect)

def poll_once(device_url, cloud_url, shared_key):
    with _opener.open(device_url, timeout=5) as response:
        reading = json.load(response)
    request = Request(
        cloud_url,
        data=json.dumps(reading).encode(),
        headers={"Content-Type": "application/json", "X-Legacy-Shared-Key": shared_key},
        method="POST",
    )
    with _opener.open(request, timeout=5) as response:
        if response.status != 202:
            raise URLError(f"cloud returned HTTP {response.status}")
    return reading


def make_handler(metrics, lock):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/healthz":
                send_json(self, 200, {"status": "ok"})
            elif self.path == "/metrics":
                with lock:
                    body = "".join(f"gateway_{key} {value}\n" for key, value in metrics.items()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                send_json(self, 404, {"error": "not found"})

        def log_message(self, format, *args):
            print(f"gateway: {format % args}")

    return Handler


if __name__ == "__main__":
    device = os.environ.get("DEVICE_URL", "http://localhost:8082/v1/reading")
    cloud = os.environ.get("CLOUD_URL", "http://localhost:8081/v1/readings")
    key = os.environ.get("SHARED_KEY", "demo-only-change-me")
    interval = float(os.environ.get("POLL_SECONDS", "5"))
    metrics = {"forwarded_total": 0, "errors_total": 0}
    lock = threading.Lock()
    port = int(os.environ.get("GATEWAY_PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), make_handler(metrics, lock))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"gateway listening on :{port}; polling every {interval:g}s")
    while True:
        try:
            reading = poll_once(device, cloud, key)
            with lock:
                metrics["forwarded_total"] += 1
            print(f"forwarded {reading['device_id']} sequence={reading['sequence']}")
        except (OSError, ValueError, URLError) as error:
            with lock:
                metrics["errors_total"] += 1
            print(f"poll failed: {error}")
        time.sleep(interval)
