"""Shared test fixtures: a small dummy HTTP server used by HTTPTarget tests.

Uses only the stdlib `http.server` (no new test dependency - see
CLAUDE.md's "minimal dependencies" rule).

IMPORTANT: `shutdown()` must always be called from a thread other than the
one running `serve_forever()` (calling it from the serving thread
deadlocks). The fixture below runs `serve_forever` on a daemon thread and
calls `shutdown()` from the (main) test thread during teardown.
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):  # stdlib signature; shadows builtin `format`
        pass  # keep pytest output readable

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError:
            return raw

    def _write_json(self, status: int, payload) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _write_text(self, status: int, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        body = self._read_body()

        self.server.requests.append(
            (self.command, path, dict(self.headers), query, body)
        )

        if path == "/status500":
            self._write_text(500, "internal server error")
            return

        if path == "/malformed":
            self._write_text(200, "not json {")
            return

        if path == "/no-answer":
            self._write_json(200, {"sources": []})
            return

        if path == "/slow":
            time.sleep(self.server.slow_delay)
            self._write_json(200, {"answer": "slow ok", "sources": []})
            return

        # default: /query (and anything else) uses the configurable response
        self._write_json(200, self.server.response)

    def do_GET(self):  # stdlib method name
        self._handle()

    def do_POST(self):  # stdlib method name
        self._handle()


class DummyServer:
    def __init__(self):
        # 127.0.0.1, not localhost: avoids IPv6-resolution flakiness in CI.
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        # The /slow timeout test causes the client to give up and close its
        # socket before the server finishes writing its (deliberately
        # delayed) response; the resulting BrokenPipeError is expected and
        # harmless, so don't let http.server print a traceback for it.
        self._httpd.handle_error = lambda request, client_address: None
        self._httpd.requests = []
        self._httpd.response = {"answer": "default answer", "sources": ["doc1.txt"]}
        self._httpd.slow_delay = 0.5
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def requests(self):
        """List of (method, path, headers, query, body) tuples, in order received."""
        return self._httpd.requests

    @property
    def slow_delay(self) -> float:
        return self._httpd.slow_delay

    @slow_delay.setter
    def slow_delay(self, value: float) -> None:
        self._httpd.slow_delay = value

    def url(self, path: str = "/query") -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}{path}"

    def set_response(self, payload) -> None:
        self._httpd.response = payload

    def shutdown(self) -> None:
        # Must be called from a different thread than serve_forever() runs on.
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


@pytest.fixture()
def dummy_server():
    server = DummyServer()
    try:
        yield server
    finally:
        server.shutdown()
