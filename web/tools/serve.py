"""Threaded WSGI server for RequestRider's browser gateway.

Django's development server keeps a listen backlog of ten sockets and gives no
control over it, so a burst of parallel work — twenty workflows starting at once,
several folder scans, a browser tab per tool holding a live stream — overflows the
accept queue and the client sees `Connection reset by peer` even though the
application itself is fine. The measurements that motivated this: twenty
workflows of 25 nodes each completed with the gateway answering in 2-6 ms, while
forty simultaneous starts lost six connections to that backlog.

The server uses the standard library only, so the project gains no runtime
dependency:

* a wide accept queue, so simultaneous starts queue instead of being refused;
* one thread per connection, because long-lived SSE streams must not block
  ordinary requests;
* a bounded worker pool, so a client cannot spawn threads without end;
* a socket timeout, so a browser that disappears without closing cannot pin a
  thread forever;
* address reuse, so a restart does not wait for the previous socket.

It binds to the given host, which the project keeps on 127.0.0.1.
"""

from __future__ import annotations

import argparse
import os
import socket
import socketserver
import sys
import threading
import time
from pathlib import Path
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

# Enough simultaneous connections for a local operator with every tool open: one
# thread per live stream, one per in-flight request, and a wide margin.
DEFAULT_BACKLOG = 1024
DEFAULT_THREADS = 256
# A live stream sends an event whenever one arrives, so an idle connection is
# rare. This only reaps a client that vanished without a close frame.
SOCKET_TIMEOUT = 3600


class GatewayRequestHandler(WSGIRequestHandler):
    """One request: quiet access log, no banner, and a socket timeout."""

    timeout = SOCKET_TIMEOUT

    def handle(self) -> None:
        self.connection.settimeout(SOCKET_TIMEOUT)
        self._started_at = time.monotonic()
        super().handle()

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
        # The duration is logged with every request so a slow endpoint is
        # visible instead of guessed at.
        duration_ms = (time.monotonic() - self._started_at) * 1000
        sys.stderr.write(
            f"[{time.strftime('%H:%M:%S')}] {duration_ms:7.0f}ms {self.address_string()} "
            f"{format % args}\n"
        )
        sys.stderr.flush()

    def get_environ(self):
        environ = super().get_environ()
        # The gateway streams server-sent events; a proxy must not buffer them.
        environ["wsgi.multithread"] = "1"
        return environ


class ThreadedGatewayServer(socketserver.ThreadingMixIn, WSGIServer):
    """Thread-per-connection WSGI server with a wide accept queue."""

    daemon_threads = True
    allow_reuse_address = True
    # The whole point of this server: a burst of parallel work queues instead of
    # being refused. The value is set from the command line before binding.
    request_queue_size = DEFAULT_BACKLOG
    block_on_close = False

    def __init__(self, *args, max_threads: int = DEFAULT_THREADS, **kwargs):
        self.max_threads = max_threads
        self._thread_slots = threading.BoundedSemaphore(max_threads)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        # Wait for a free worker instead of refusing the connection outright.
        self._thread_slots.acquire()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._thread_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._thread_slots.release()

    def handle_error(self, request, client_address):
        """A dropped client is normal here and must not print a traceback."""
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError, socket.timeout, TimeoutError)):
            return
        super().handle_error(request, client_address)


def main() -> int:
    parser = argparse.ArgumentParser(description="RequestRider browser gateway")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    parser.add_argument("--backlog", type=int, default=DEFAULT_BACKLOG)
    args = parser.parse_args()

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
    import django

    django.setup()
    from django.core.wsgi import get_wsgi_application

    server_class = type(
        "ConfiguredGatewayServer",
        (ThreadedGatewayServer,),
        {"request_queue_size": args.backlog},
    )
    httpd = make_server(
        args.host,
        args.port,
        get_wsgi_application(),
        server_class=server_class,
        handler_class=GatewayRequestHandler,
    )
    httpd.max_threads = args.threads
    httpd._thread_slots = threading.BoundedSemaphore(args.threads)
    host, port = httpd.server_address[:2]
    print(
        f"RequestRider gateway on http://{host}:{port} "
        f"(backlog={args.backlog}, threads={args.threads})",
        flush=True,
    )
    started = time.time()
    try:
        httpd.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        print(f"stopped after {time.time() - started:.0f}s", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
