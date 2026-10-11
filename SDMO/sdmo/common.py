import json
from http.server import BaseHTTPRequestHandler


def send_json(handler: BaseHTTPRequestHandler, status: int, payload: object) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


MAX_BODY_BYTES = 64_000


def discard_body(handler: BaseHTTPRequestHandler) -> None:
    """Read and drop a request body the handler is not going to use.

    Closing a connection while request data is still unread makes the OS reset
    it, so the client sees a dropped connection instead of the status code.
    Bodies over MAX_BODY_BYTES are not read; the client is misbehaving anyway.
    """
    try:
        size = int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        return
    if 0 < size <= MAX_BODY_BYTES:
        handler.rfile.read(size)


def read_json(handler: BaseHTTPRequestHandler) -> object:
    size = int(handler.headers.get("Content-Length", "0"))
    if size <= 0 or size > MAX_BODY_BYTES:
        raise ValueError("invalid request size")
    return json.loads(handler.rfile.read(size))
