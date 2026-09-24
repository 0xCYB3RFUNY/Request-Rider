"""Loopback-only OAST fixture for Request Rider lifecycle tests.

This is deliberately not an Interactsh emulator. It implements the small
provider contract needed by the local OAST adapter: register a listener, expose
a callback URL, record callbacks, and poll/remove listener state.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class OASTFixtureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address):
        super().__init__(server_address, OASTFixtureHandler)
        self.lock = threading.Lock()
        self.listeners: dict[str, dict] = {}
        self.events: dict[str, list[dict]] = {}


class OASTFixtureHandler(BaseHTTPRequestHandler):
    server: OASTFixtureServer

    def log_message(self, *_args):
        return

    def send_json(self, status: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        try:
            value = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as error:
            raise ValueError("invalid JSON") from error
        if not isinstance(value, dict):
            raise ValueError("JSON object required")
        return value

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/health":
            self.send_json(200, {"ok": True, "service": "requestrider-oast-fixture"})
            return
        if parsed.path == "/poll":
            listener_id = parse_qs(parsed.query).get("listener_id", [""])[0]
            with self.server.lock:
                if listener_id not in self.server.listeners:
                    self.send_json(404, {"error": "listener not found"})
                    return
                events = list(self.server.events.get(listener_id, []))
            self.send_json(200, {"listener_id": listener_id, "events": events, "triggered": bool(events)})
            return
        if parsed.path.startswith("/hit/"):
            listener_id = parsed.path.removeprefix("/hit/")
            query = {key: values[-1] for key, values in parse_qs(parsed.query).items()}
            with self.server.lock:
                if listener_id not in self.server.listeners:
                    self.send_json(404, {"error": "listener not found"})
                    return
                event = {
                    "event_id": secrets.token_hex(8),
                    "protocol": "http",
                    "listener_id": listener_id,
                    "method": "GET",
                    "path": parsed.path,
                    "query": query,
                    "headers": {key.lower(): value for key, value in self.headers.items()},
                }
                self.server.events.setdefault(listener_id, []).append(event)
            self.send_json(200, {"ok": True})
            return
        self.send_json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlsplit(self.path)
        if parsed.path != "/register":
            self.send_json(404, {"error": "not found"})
            return
        try:
            payload = self.read_json()
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
            return
        listener_id = str(payload.get("listener_id") or secrets.token_hex(8)).strip()
        if not listener_id or len(listener_id) > 120:
            self.send_json(400, {"error": "invalid listener_id"})
            return
        base_url = f"http://127.0.0.1:{self.server.server_port}"
        with self.server.lock:
            self.server.listeners[listener_id] = {
                "listener_id": listener_id,
                "protocols": payload.get("protocols") or ["http"],
                "registered_at": time.time(),
            }
            self.server.events.setdefault(listener_id, [])
        self.send_json(200, {
            "listener_id": listener_id,
            "domain": f"{listener_id}.fixture.local",
            "base_url": base_url,
            "payload_url": f"{base_url}/hit/{listener_id}",
            "protocols": payload.get("protocols") or ["http"],
        })

    def do_DELETE(self):
        parsed = urlsplit(self.path)
        if not parsed.path.startswith("/listener/"):
            self.send_json(404, {"error": "not found"})
            return
        listener_id = parsed.path.removeprefix("/listener/")
        with self.server.lock:
            existed = listener_id in self.server.listeners
            self.server.listeners.pop(listener_id, None)
            self.server.events.pop(listener_id, None)
        self.send_json(200, {"deleted": existed})


def main():
    host = os.environ.get("OAST_FIXTURE_HOST", "127.0.0.1")
    port = int(os.environ.get("OAST_FIXTURE_PORT", "0"))
    server = OASTFixtureServer((host, port))
    print(f"oast fixture listening on http://{host}:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
