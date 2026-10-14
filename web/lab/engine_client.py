"""HTTP client for the Go engine gateway."""

import hashlib
import json
import logging
import re
import socket
import time
from http.client import RemoteDisconnected
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


logger = logging.getLogger(__name__)

# A gateway request thread must never park forever on an engine socket. Without
# an explicit timeout, `urlopen` leaves the socket blocking, so a wedged engine
# handler pins the thread and its connection until the process exits. Every
# engine endpoint the gateway uses either answers immediately or returns a job
# handle, so a generous-but-finite default is safe.
#
# This is a transport deadline for the local gateway->engine hop, not an
# application execution budget: no job, request or target is rejected or capped
# because of it.
DEFAULT_ENGINE_TIMEOUT = 120.0

# Streaming endpoints must not be cut off mid-flight by the same deadline, so
# callers that hold a connection open pass their own value.
STREAM_CONNECT_TIMEOUT = 15.0


ENGINE_RAW_RESPONSE_LIMIT = 512


# Headers for every internal service call — the engine and the browser worker.
#
# `Host` is loopback on purpose. Both servers reject a request whose `Host` is
# anything else, as a DNS-rebinding guard against a page the analyst happens to
# have open (`engine/internal_auth.go:66`, `browser-worker/worker.py:2041`), and
# they answer 403 FORBIDDEN_HOST before they look at anything else. Under Docker
# the gateway addresses them by service name — `ENGINE_URL=http://engine:8081` —
# so `urllib` sends `Host: engine:8081` and every internal call is refused. The
# native stand never hit it because its `ENGINE_URL` is already
# `http://127.0.0.1:8081`, so the header sent here is byte-for-byte the one
# `urllib` sends anyway: a no-op locally, and the difference between working and
# 403 in a container.
#
# The value is deliberately bare (`127.0.0.1`, no port). The Go side splits the
# authority and falls back to the whole string when there is no port; the Python
# side truncates at the colon. Both accept it, so one value serves both without
# this module having to parse its own base URL.
INTERNAL_HOST_HEADER = "127.0.0.1"


def internal_service_headers(extra=None):
    """Headers every call to the engine or the browser worker must carry.

    One function for all three call sites - `EngineClient.request`,
    `open_engine_stream` and `_worker_headers` - because the loopback `Host` has
    to agree between them, and three copies of that one line drift.

    There is no service key here any more. `RR_INTERNAL_API_KEY` and
    `X-RequestRider-Internal-Key` were removed end to end, and the measured reason
    is why they should not return as a "compatibility mode": the engine compared
    the presented header against the value it read at boot, so two processes from
    one checkout agreed only when booted from the same environment. A leftover
    engine stayed on :8081, `start.sh` probed the by-design unauthenticated
    `/health`, saw 200 and adopted it as its own - and every internal call from
    the gateway then drew `403 FORBIDDEN_ORIGIN` while the status row read UP. A
    credential that works only between processes started in the same breath is a
    startup-ordering bug wearing a security control's clothes.

    What remains is geography, not identity: both servers refuse a request whose
    `Host` is not loopback, which closes DNS rebinding and costs nothing at
    startup.
    """
    headers = dict(extra or {})
    headers["Host"] = INTERNAL_HOST_HEADER
    return headers


def summarize_raw_response(raw_response: bytes) -> dict:
    """Reduce an unparseable engine response to something safe to hand to a browser.

    WHAT THIS IS FOR. Both failure paths used to pass `raw_response.decode(errors=
    "replace")` into the JSON payload in full. That is the engine's own bytes, and when
    the engine dies mid-request what it returns is not JSON but its HTML error page —
    which carries the binary's own filesystem paths and addresses. Those bytes then
    travel into the analyst's browser inside a JSON field.

    The contract of `502` + `ENGINE_UNAVAILABLE` / `ENGINE_INVALID_RESPONSE` is already
    correct and is not touched here: there is no invented success. Only the diagnostic
    blob is bounded.

    WHY MARKUP IS STRIPPED, NOT JUST TRUNCATED. Truncation alone leaves the opening
    `<html><head>…` of an error page, which is exactly the part that carries the path.
    And 512 bytes of markup rendered into the page is a second problem: it is content
    the operator reads as if it came from the target.

    WHY THE LENGTH AND THE HASH ARE KEPT. A truncated blob alone cannot answer "did the
    engine send 12 bytes or 12 megabytes?", and it cannot tell two identical failures
    apart from two different ones that happened to share a first 512 bytes. Both numbers
    are computed from the **original** bytes, so they describe what really arrived.
    """
    text = raw_response.decode(errors="replace")
    digest = hashlib.sha256(raw_response).hexdigest()
    # `<...>` and `</...>` first, then the remaining `<`/`>` that are not part of a tag:
    # a truncated error page can end mid-tag, and those two characters alone are enough
    # to break out of a `<pre>` and open a real element.
    stripped = re.sub(r"<[^>]*>", " ", text)
    stripped = stripped.replace("<", " ").replace(">", " ")
    stripped = re.sub(r"\s+", " ", stripped).strip()
    return {
        "raw_response": stripped[:ENGINE_RAW_RESPONSE_LIMIT],
        "raw_response_truncated": len(stripped) > ENGINE_RAW_RESPONSE_LIMIT,
        "raw_response_bytes": len(raw_response),
        "raw_response_sha256": digest,
    }


class EngineClient:
    """Call engine endpoints and return a stable ``(status, payload)`` tuple."""

    def __init__(self, base_url, opener=urlopen, default_timeout=DEFAULT_ENGINE_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.opener = opener
        self.default_timeout = default_timeout

    def request(self, method, path, payload=None, timeout=None, route_generation=None):
        started = time.monotonic()
        body = None if payload is None else json.dumps(payload).encode()
        # The loopback Host and the optional service key come from
        # `internal_service_headers`, which `open_engine_stream` and
        # `_worker_headers` use too — see the note there on why one function.
        headers = internal_service_headers(
            {"Content-Type": "application/json"} if body is not None else {}
        )
        if route_generation is not None:
            headers["X-RequestRider-Route-Generation"] = str(int(route_generation))
        request = Request(
            f"{self.base_url}{path}",
            data=body,
            headers=headers,
            method=method,
        )
        # `timeout=None` must never reach urlopen: it would disable the socket
        # deadline entirely and let a stuck engine pin this thread forever.
        effective_timeout = self.default_timeout if timeout is None else timeout
        try:
            with self.opener(request, timeout=effective_timeout) as response:
                payload = self._decode(response.read(), response.status, path)
                if isinstance(payload, dict) and payload.get("reason") == "ENGINE_INVALID_RESPONSE":
                    return 502, payload
                return response.status, payload
        except HTTPError as error:
            raw_response = error.read()
            payload = self._decode_http_error(raw_response, error.code, path)
            return error.code, payload
        except (URLError, TimeoutError, RemoteDisconnected, ConnectionError, socket.timeout) as error:
            reason = getattr(error, "reason", error)
            logger.error(
                "engine_request_unavailable path=%s duration_ms=%d reason=%s",
                path,
                int((time.monotonic() - started) * 1000),
                reason,
            )
            return 502, {
                "error": f"engine unavailable: {reason}",
                "reason": "ENGINE_UNAVAILABLE",
            }

    def _decode(self, raw_response, status, path):
        if not raw_response:
            return {
                "error": "engine returned an empty response",
                "reason": "ENGINE_INVALID_RESPONSE",
                "status": status,
            }
        try:
            payload = json.loads(raw_response)
        except (UnicodeDecodeError, json.JSONDecodeError):
            logger.error("engine_request_invalid_json path=%s status=%s", path, status)
            return {
                "error": "engine returned an invalid response",
                "reason": "ENGINE_INVALID_RESPONSE",
                "status": status,
                **summarize_raw_response(raw_response),
            }
        if not isinstance(payload, (dict, list)):
            logger.error("engine_request_invalid_shape path=%s status=%s", path, status)
            return {
                "error": "engine returned an invalid response",
                "reason": "ENGINE_INVALID_RESPONSE",
                "status": status,
            }
        return payload

    def _decode_http_error(self, raw_response, status, path):
        payload = self._decode(raw_response, status, path)
        if isinstance(payload, dict) and payload.get("reason") not in {
            "ENGINE_INVALID_RESPONSE",
            "ENGINE_UNAVAILABLE",
        }:
            payload.setdefault("reason", "ENGINE_HTTP_ERROR")
            return payload
        return {
            "error": f"engine returned HTTP {status}",
            "reason": "ENGINE_HTTP_ERROR",
            "status": status,
            **summarize_raw_response(raw_response),
        }


def engine_client(base_url, opener=urlopen, default_timeout=DEFAULT_ENGINE_TIMEOUT):
    """Build a client using the supplied opener for deterministic tests."""
    return EngineClient(base_url, opener=opener, default_timeout=default_timeout)
