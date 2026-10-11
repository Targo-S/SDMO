"""Shared fixtures for the test suite: in-process test servers, request
helpers and quiet logging.

Service request logs are hidden during test runs so the output shows only
test results. Set SDMO_TEST_LOGS=1 to see them.
"""
import http.client
import io
import json
import os
import socket
import sys
import threading
from contextlib import contextmanager, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

KEY = "test-key"
SHOW_LOGS = os.environ.get("SDMO_TEST_LOGS") == "1"
_quiet_contexts = []


def setUpModule():
    if not SHOW_LOGS:
        context = redirect_stdout(io.StringIO())
        context.__enter__()
        _quiet_contexts.append(context)


def tearDownModule():
    while _quiet_contexts:
        _quiet_contexts.pop().__exit__(None, None, None)


class TestServer(ThreadingHTTPServer):
    """Records exceptions raised inside request handlers so the test that
    triggered them fails with the server-side traceback attached."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handler_errors = []

    def handle_error(self, request, client_address):
        self.handler_errors.append(sys.exc_info()[1])
        if SHOW_LOGS:
            super().handle_error(request, client_address)


class ServerHandlerError(AssertionError):
    pass


@contextmanager
def running_server(handler):
    """Run `handler` on a free localhost port; yields the base URL."""
    server = TestServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    except BaseException as error:
        # The test already failed (e.g. connection dropped); attach the
        # server-side exception that caused it, if there was one.
        server.shutdown()
        if server.handler_errors and error.__cause__ is None:
            raise error from server.handler_errors[0]
        raise
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    if server.handler_errors:
        raise ServerHandlerError("request handler raised an exception") from server.handler_errors[0]


def valid_reading(**overrides):
    reading = {"device_id": "sensor-a", "sequence": 1,
               "temperature_c": 21.5, "observed_at": "2026-10-06T12:00:00+00:00"}
    reading.update(overrides)
    return reading


def raw_post(base_url, body, headers, path="/v1/readings"):
    """POST with full control over headers (urllib would add its own
    Content-Length). Returns the HTTP status code."""
    parts = urlsplit(base_url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=5)
    try:
        conn.putrequest("POST", path, skip_accept_encoding=True)
        for name, value in headers.items():
            conn.putheader(name, value)
        conn.endheaders()
        if body:
            conn.send(body)
        response = conn.getresponse()
        response.read()
        return response.status
    finally:
        conn.close()


def post_reading(base_url, reading, key=KEY):
    body = json.dumps(reading).encode()  # json.dumps emits NaN/Infinity literally
    return raw_post(base_url, body, {"X-Legacy-Shared-Key": key,
                                     "Content-Length": str(len(body))})


def stub_handler(status, body=b"", received=None, headers=None):
    """Handler answering every GET/POST with a fixed status, body and extra
    headers. If `received` is a list, each request's headers and body are
    appended to it."""
    class Handler(BaseHTTPRequestHandler):
        def _reply(self, data):
            if received is not None:
                received.append({"method": self.command, "headers": dict(self.headers), "body": data})
            self.send_response(status)
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._reply(b"")

        def do_POST(self):
            self._reply(self.rfile.read(int(self.headers.get("Content-Length", "0"))))

        def log_message(self, format, *args):
            pass
    return Handler


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def post_raw(url, body, headers=None):
    """POST raw bytes (or a JSON-serializable object) and return (status, parsed body or raw bytes)."""
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    request = Request(url, data=data, headers=headers or {}, method="POST")
    try:
        with urlopen(request, timeout=5) as response:
            status, raw = response.status, response.read()
    except HTTPError as error:
        status, raw = error.code, error.read()
        error.close()
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, raw


def get_text(url):
    with urlopen(url, timeout=5) as response:
        return response.read().decode()


class FakeClock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds
