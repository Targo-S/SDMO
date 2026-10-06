import json
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from sdmo.cloud import CloudState, make_handler
from sdmo.gateway import poll_once


@contextmanager
def running_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class PipelineTests(unittest.TestCase):
    def test_gateway_forwards_reading_to_cloud(self):
        reading = {"device_id": "test", "sequence": 1,
                   "temperature_c": 22.0, "observed_at": "2026-10-06T12:00:00+00:00"}

        class DeviceHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps(reading).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        state = CloudState("test-key")
        with running_server(DeviceHandler) as device, running_server(make_handler(state)) as cloud:
            result = poll_once(f"{device}/v1/reading", f"{cloud}/v1/readings", "test-key")
        self.assertEqual(result, reading)
        self.assertEqual(state.readings, [reading])

    def test_cloud_rejects_wrong_key(self):
        state = CloudState("expected")
        with running_server(make_handler(state)) as cloud:
            request = Request(f"{cloud}/v1/readings", data=b"{}",
                              headers={"X-Legacy-Shared-Key": "wrong"}, method="POST")
            with self.assertRaises(HTTPError) as error:
                urlopen(request)
        self.assertEqual(error.exception.code, 401)
        error.exception.close()
        self.assertEqual(state.rejected, 1)


if __name__ == "__main__":
    unittest.main()
