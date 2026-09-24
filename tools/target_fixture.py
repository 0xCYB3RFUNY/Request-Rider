"""Local browser-driven Target fixture for repeatable QA checks."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import time
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class FixtureHandler(BaseHTTPRequestHandler):
    def send_body(self, status, body, content_type="text/html; charset=utf-8"):
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path.startswith("/api/race"):
            time.sleep(0.02)
            self.send_body(200, json.dumps({"fixture": "race", "canary": True}), "application/json")
            return
        if self.path == "/":
            self.send_body(
                200,
                """<!doctype html>
<html><body>
<h1>RequestRider Target fixture</h1>
<a href="/next">Next page</a>
<form action="/search" method="get">
  <input name="q" aria-label="Query">
  <button id="submit" type="submit">Search</button>
</form>
<button id="load-data" type="button">Load data</button>
<script>
document.querySelector('#load-data').addEventListener('click', async () => {
  const response = await fetch('/api/data');
  document.body.dataset.loaded = await response.text();
});
</script>
</body></html>""",
            )
            return
        if self.path == "/next":
            self.send_body(200, "<!doctype html><html><body><h2>Next fixture page</h2></body></html>")
            return
        if self.path == "/api/data":
            self.send_body(200, json.dumps({"fixture": True}), "application/json")
            return
        if self.path.startswith("/search"):
            self.send_body(200, "<!doctype html><html><body><h2>Search result</h2></body></html>")
            return
        if self.path == "/health":
            self.send_body(200, "ok", "text/plain; charset=utf-8")
            return
        self.send_body(404, "not found", "text/plain; charset=utf-8")

    def do_POST(self):
        if urlsplit(self.path).path != "/xml":
            self.send_body(404, "not found", "text/plain; charset=utf-8")
            return
        try:
            length = min(64 * 1024, max(0, int(self.headers.get("Content-Length", "0"))))
        except ValueError:
            length = 0
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        match = re.search(r"SYSTEM\s+[\"']([^\"']+)[\"']", body, re.IGNORECASE)
        callback_status = 502
        if match:
            callback = urlsplit(match.group(1))
            if callback.scheme == "http" and callback.hostname in {"127.0.0.1", "localhost"} and callback.port:
                try:
                    with urlopen(Request(match.group(1), method="GET"), timeout=2):
                        callback_status = 200
                except Exception:  # noqa: BLE001 - fixture must report callback failure safely
                    callback_status = 502
        self.send_body(callback_status, json.dumps({"fixture": "xxe", "callback_status": callback_status}), "application/json")

    def log_message(self, *_):
        return


def main():
    host = os.environ.get("FIXTURE_HOST", "127.0.0.1")
    port = int(os.environ.get("FIXTURE_PORT", "8765"))
    ThreadingHTTPServer((host, port), FixtureHandler).serve_forever()


if __name__ == "__main__":
    main()
