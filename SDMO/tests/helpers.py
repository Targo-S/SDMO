import json
import threading
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen


@contextmanager
def running_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


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
