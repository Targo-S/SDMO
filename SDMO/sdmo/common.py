import json
from http.server import BaseHTTPRequestHandler


def send_json(handler: BaseHTTPRequestHandler, status: int, payload: object) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def read_json(handler: BaseHTTPRequestHandler) -> object:
    size = int(handler.headers.get("Content-Length", "0"))
    if size <= 0 or size > 64_000:
        raise ValueError("invalid request size")
    return json.loads(handler.rfile.read(size))
