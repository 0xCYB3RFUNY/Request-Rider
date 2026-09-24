"""Loopback-only raw TCP fixture for Last-Byte Sync browser tests.

The fixture accepts one HTTP/1.1 request per connection, waits until the
complete body (including its final byte) arrives, and returns a deterministic
200 response. It is intentionally not a target emulator or an external
listener.
"""

from __future__ import annotations

import hashlib
import json
import os
import socketserver
import threading
import time


class LastByteFixtureHandler(socketserver.BaseRequestHandler):
    """Read a bounded raw HTTP request and reply with local evidence."""

    server: "LastByteFixtureServer"

    def handle(self) -> None:
        connection = self.request
        connection.settimeout(10)
        buffer = bytearray()
        header_end = -1
        while header_end < 0 and len(buffer) < 64 * 1024:
            chunk = connection.recv(4096)
            if not chunk:
                return
            buffer.extend(chunk)
            header_end = buffer.find(b"\r\n\r\n")
        if header_end < 0:
            return
        header_bytes = bytes(buffer[:header_end])
        content_length = 0
        for line in header_bytes.decode("iso-8859-1", errors="replace").split("\r\n")[1:]:
            name, separator, value = line.partition(":")
            if separator and name.strip().lower() == "content-length":
                try:
                    content_length = min(32 * 1024, max(0, int(value.strip())))
                except ValueError:
                    content_length = 0
                break
        body_start = header_end + 4
        while len(buffer) - body_start < content_length:
            chunk = connection.recv(4096)
            if not chunk:
                return
            buffer.extend(chunk)
        body = bytes(buffer[body_start : body_start + content_length])
        with self.server.lock:
            self.server.requests.append({
                "received_at": time.time(),
                "header_bytes": len(header_bytes),
                "body_bytes": len(body),
                "body_sha256": hashlib.sha256(body).hexdigest(),
            })
        response = json.dumps({"ok": True, "fixture": "last-byte", "body_bytes": len(body)}).encode("utf-8")
        connection.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(response)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + response
        )


class LastByteFixtureServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address):
        super().__init__(server_address, LastByteFixtureHandler)
        self.lock = threading.Lock()
        self.requests: list[dict] = []


def main() -> None:
    host = os.environ.get("LAST_BYTE_FIXTURE_HOST", "127.0.0.1")
    port = int(os.environ.get("LAST_BYTE_FIXTURE_PORT", "0"))
    server = LastByteFixtureServer((host, port))
    print(f"last-byte fixture listening on {host}:{server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
