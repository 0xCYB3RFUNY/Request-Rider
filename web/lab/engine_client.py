"""HTTP client for the Go engine gateway."""

import json
import logging
import time
from http.client import RemoteDisconnected
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


logger = logging.getLogger(__name__)


class EngineClient:
    """Call engine endpoints and return a stable ``(status, payload)`` tuple."""

    def __init__(self, base_url, opener=urlopen):
        self.base_url = base_url.rstrip("/")
        self.opener = opener

    def request(self, method, path, payload=None, timeout=None):
        started = time.monotonic()
        body = None if payload is None else json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"} if body is not None else {}
        request = Request(
            f"{self.base_url}{path}",
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with self.opener(request, **({"timeout": timeout} if timeout is not None else {})) as response:
                payload = self._decode(response.read(), response.status, path)
                if isinstance(payload, dict) and payload.get("reason") == "ENGINE_INVALID_RESPONSE":
                    return 502, payload
                return response.status, payload
        except HTTPError as error:
            raw_response = error.read()
            payload = self._decode_http_error(raw_response, error.code, path)
            return error.code, payload
        except (URLError, TimeoutError, RemoteDisconnected, ConnectionError) as error:
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
                "raw_response": raw_response.decode(errors="replace")[:4000],
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
            "raw_response": raw_response.decode(errors="replace")[:4000],
        }


def engine_client(base_url, opener=urlopen):
    """Build a client using the supplied opener for deterministic tests."""
    return EngineClient(base_url, opener=opener)
