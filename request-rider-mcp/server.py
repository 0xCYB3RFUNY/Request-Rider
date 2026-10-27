#!/usr/bin/env python3
"""Request-Rider MCP Server — operator-level control over the whole platform.

This is the single canonical implementation. `request-rider-mcp/server.py` is a
thin shim that runs this file, so there is exactly one tool registry in the
repository rather than two hand-maintained copies that drift apart.

WHAT THIS GIVES AN LLM
----------------------
A connected model stops being a consultant that writes plans and becomes the
operator: it reads complete captured exchanges byte-for-byte, crawls the target,
runs Intruder/Nuclei/Active scans, records findings into the Project, and can
hand a captured transaction to Repeater, Intruder or Automation.

The three services behind it, all on loopback:

* Django gateway ``:8000`` — projects, history, traffic archive, workflows, the
  browser-facing API. Owns the session, and the active Project lives in that
  session, so this server keeps one cookie jar for its whole lifetime.
* Go engine ``:8081`` — outbound execution, Intruder, Target, scanners.
* Browser worker ``:8090`` — Playwright Firefox for SPAs and bot-protected apps.

CONTEXT PROTECTION
------------------
An HTTP capture is not a chat message. A single 400 KB SPA page would eat an
entire context window, so every tool that returns payload bytes obeys the same
rule: default window, explicit ``offset``/``length`` windowing, and a
``next_offset`` cursor so a caller can page through a body it is analysing.
Metadata listings never carry bodies at all. ``RR_RAW_MAX_BYTES`` sets the
default ceiling and the operator can raise it; nothing here silently discards
bytes — a truncated result always says so and says where the rest starts.

ERROR CONTRACT
--------------
Request-Rider answers failures as ``{"error": ..., "reason": CODE}``. Those codes
are the API, so they are translated rather than swallowed:

``ROUTE_CHANGED``                  the route generation was switched mid-run; the
                                    work of that generation was cancelled and the
                                    caller should re-issue it on the new route.
``ENGINE_UNAVAILABLE``             the Go engine could not be reached.
``NETWORK_CONFIRMATION_REQUIRED``  an OSINT transform performs third-party
                                    queries and needs ``confirm_network=True``.
``TRANSFORM_NOT_APPLICABLE``       the transform does not apply to this input
                                    (an IP where a domain is required, a
                                    non-IP where one is required, and so on).
``INVALID_OSINT_GRAPH``            the graph id or payload was rejected.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import html as html_module
import json
import logging
import os
import secrets
import string
import sys
import time
import urllib.parse
from contextlib import asynccontextmanager
from typing import Any, Optional

import httpx
from mcp.server.mcpserver import MCPServer

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

GATEWAY_URL = os.environ.get("RR_GATEWAY_URL") or os.environ.get(
    "REQUEST_RIDER_URL", "http://127.0.0.1:8000"
).rstrip("/")
ENGINE_URL = os.environ.get("RR_ENGINE_URL", "http://127.0.0.1:8081").rstrip("/")
WORKER_URL = os.environ.get("RR_WORKER_URL", "http://127.0.0.1:8090").rstrip("/")

#: Default ceiling for any single payload window, in bytes. A caller can ask
#: for more with ``length``; the point of a default is that forgetting to think
#: about it does not overflow the model's window.
RAW_MAX_BYTES = int(os.environ.get("RR_RAW_MAX_BYTES", "65536"))
#: Listing pages stay small on purpose — they are row columns, not payloads.
LIST_MAX_ROWS = int(os.environ.get("RR_LIST_MAX_ROWS", "200"))

HTTP_TIMEOUT = float(os.environ.get("RR_HTTP_TIMEOUT", "120"))
LIST_TIMEOUT = float(os.environ.get("RR_LIST_TIMEOUT", "30"))

LOG_FILE = os.environ.get("RR_MCP_LOG", "data/logs/mcp-server.log")
logging.basicConfig(
    filename=LOG_FILE if os.path.isdir(os.path.dirname(LOG_FILE)) else None,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("request-rider-mcp")

SERVER_INSTRUCTIONS = """\
Request-Rider is a running security-testing platform on this machine, reached
over loopback. You are the operator, not a consultant writing a plan.

Use the tools instead of asking the operator for data. Anything the platform
captured is readable: a search that returns a row id is followed by
`history_get_transaction_raw` to read the actual bytes, a Target crawl returns a
map id you poll, and `project_get_knowledge_hub` returns endpoints, secrets and
scanner findings for the active Project.

Facts you may rely on:
- Every tool returns `ok`. On `ok: false` the `reason` field names the cause.
- `ROUTE_CHANGED` means the work was cancelled by a route switch — re-issue it.
- `NETWORK_CONFIRMATION_REQUIRED` means an OSINT transform queries third parties;
  pass `confirm_network=True` to proceed.
- Large bodies come back windowed. Follow `next_offset` to read more; never
  conclude a payload is absent from a window you did not read to the end.
- A 200 status alone proves nothing. Compare against a baseline request you
  actually sent before calling anything a finding.
"""


# --------------------------------------------------------------------------
# Error taxonomy
# --------------------------------------------------------------------------

#: Request-Rider reasons this server gives a specific, actionable meaning.
#: Anything else is passed through verbatim rather than reinterpreted.
KNOWN_REASONS = {
    "ROUTE_CHANGED": "The outbound route generation was switched; this work was cancelled. Re-issue it.",
    "ENGINE_UNAVAILABLE": "The Go engine is unreachable. Start the stack, then retry.",
    "BROKER_UNAVAILABLE": "The workflow broker is unreachable. Start the stack, then retry.",
    "NETWORK_CONFIRMATION_REQUIRED": "This transform queries third parties. Re-call with confirm_network=True.",
    "TRANSFORM_NOT_APPLICABLE": "The transform does not apply to this input value.",
    "INVALID_OSINT_TRANSFORM": "Unknown transform name. Call osint_transform_list for the registry.",
    "INVALID_OSINT_GRAPH": "The OSINT graph id or the transform payload was rejected.",
    "TARGET_MAP_NOT_FOUND": "The engine forgot this crawl (it restarts with an empty job table). Re-run target_run_crawl.",
    "JOB_NOT_FOUND": (
        "The engine no longer knows this job. It forgets its job table on restart, so the "
        "report cannot be recovered — re-run the scan."
    ),
    "RECORD_NOT_FOUND": "No such exchange. Read the current ids with history_get_records.",
    "PROJECT_CONTEXT_REQUIRED": "Select an active Project first with project_switch_active.",
}


def _fail(reason: str, message: str, **extra: Any) -> dict:
    """Build the uniform failure envelope.

    ``reason`` is preserved verbatim so a caller can branch on it; ``hint`` adds
    the operator-facing next action for the reasons we know how to answer.
    """
    out: dict[str, Any] = {
        "ok": False,
        "reason": reason or "UNKNOWN",
        "error": message or reason or "request failed",
    }
    hint = KNOWN_REASONS.get(reason or "")
    if hint:
        out["hint"] = hint
    out.update(extra)
    return out


def _ok(**payload: Any) -> dict:
    out: dict[str, Any] = {"ok": True}
    out.update(payload)
    return out


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------


class RRClient:
    """One async HTTP client for the whole server lifetime.

    The cookie jar is load-bearing rather than incidental: the active Project
    lives in the Django session, so `project_switch_active` is only in effect
    for later tools if the same session cookie comes back on every call.
    """

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(HTTP_TIMEOUT, connect=10.0),
            follow_redirects=False,
            headers={"User-Agent": "request-rider-mcp/2.0"},
        )
        self._session_ready = False

    async def aclose(self) -> None:
        with contextlib.suppress(Exception):
            await self._client.aclose()

    async def _ensure_session(self) -> None:
        """Prime the session cookie and read the CSRF token once.

        `GET /` is `ensure_csrf_cookie`, so it hands out both. `project-context`
        and the OSINT transform routes are not csrf_exempt, so their POST needs
        the token; everything else is exempt and goes without it.
        """
        if self._session_ready:
            return
        try:
            await self._client.get(f"{GATEWAY_URL}/", timeout=LIST_TIMEOUT)
        except httpx.HTTPError as error:
            raise RRTransport(f"gateway unreachable at {GATEWAY_URL}: {error}") from error
        self._session_ready = True

    def _headers(self, csrf: bool = False) -> dict:
        headers = {"Accept": "application/json"}
        if csrf:
            token = self._client.cookies.get("csrftoken")
            if token:
                headers["X-CSRFToken"] = token
                headers["Referer"] = GATEWAY_URL + "/"
        return headers

    async def request(
        self,
        base: str,
        method: str,
        path: str,
        *,
        params: Optional[dict] = None,
        json_body: Optional[dict] = None,
        csrf: bool = False,
        timeout: Optional[float] = None,
    ) -> tuple[int, Any]:
        """Perform one request and return ``(http_status, decoded_body)``.

        A transport failure is raised as ``RRTransport`` so every caller gets the
        same shape; an HTTP error is returned, because a 409 with `ROUTE_CHANGED`
        is information the model needs, not an exception to be flattened into a
        generic failure.
        """
        if base == GATEWAY_URL:
            await self._ensure_session()
        url = f"{base}{path}"
        kwargs: dict[str, Any] = {"headers": self._headers(csrf)}
        if params:
            kwargs["params"] = {k: v for k, v in params.items() if v is not None}
        if json_body is not None:
            kwargs["json"] = json_body
        if timeout is not None:
            kwargs["timeout"] = timeout
        try:
            response = await self._client.request(method, url, **kwargs)
        except httpx.HTTPError as error:
            raise RRTransport(f"{base} unreachable: {error}") from error
        try:
            body = response.json()
        except ValueError:
            body = {"error": (response.text or "")[:2000]}
        return response.status_code, body

    async def gateway(self, method: str, path: str, **kwargs: Any) -> tuple[int, Any]:
        return await self.request(GATEWAY_URL, method, path, **kwargs)

    async def engine(self, method: str, path: str, **kwargs: Any) -> tuple[int, Any]:
        # The engine is internal-only and speaks plain JSON; no session needed.
        return await self.request(ENGINE_URL, method, path, **kwargs)

    async def worker(self, method: str, path: str, **kwargs: Any) -> tuple[int, Any]:
        return await self.request(WORKER_URL, method, path, **kwargs)


class RRTransport(RuntimeError):
    """A loopback service could not be reached at all."""


def _service_down(base: str, error: Exception) -> dict:
    name = {GATEWAY_URL: "Django gateway", ENGINE_URL: "Go engine", WORKER_URL: "browser worker"}.get(
        base, base
    )
    return _fail(
        "ENGINE_UNAVAILABLE" if base != GATEWAY_URL else "GATEWAY_UNAVAILABLE",
        f"{name} is unreachable: {error}",
        base_url=base,
    )


def _reason_of(status: int, body: Any) -> tuple[str, str]:
    """Pull ``(reason, message)`` out of whatever a service answered."""
    if isinstance(body, dict):
        return str(body.get("reason") or body.get("code") or ""), str(body.get("error") or "")
    if isinstance(body, str):
        return "", body[:400]
    return "", f"HTTP {status}"


def _clamp(value: Any, low: int, high: int, default: int) -> int:
    """Coerce operator input to an integer inside ``[low, high]``."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(parsed, high))


# --------------------------------------------------------------------------
# Payload helpers — byte-exact reads and context-window protection
# --------------------------------------------------------------------------


def _body_bytes(text: str | None, encoded: str | None, encoding: str | None) -> bytes:
    """Recover the exact stored bytes for a body.

    `response_body_base64` is authoritative when present: the gateway stores
    binary captures there precisely because decoding them as text would corrupt
    them. A `utf8` marker on a body that claims to be base64 is not honoured,
    because the marker describes the `*_body` column, not the base64 column.
    """
    if encoded:
        try:
            return base64.b64decode(encoded, validate=False)
        except (binascii.Error, ValueError):
            pass
    if not text:
        return b""
    raw = text.encode("utf-8", errors="surrogateescape")
    if encoding and encoding.lower() in {"base64", "b64"} and not encoded:
        with contextlib.suppress(binascii.Error, ValueError):
            return base64.b64decode(text, validate=False)
    return raw


def _window(
    data: bytes,
    *,
    offset: int = 0,
    length: Optional[int] = None,
    limit: int = RAW_MAX_BYTES,
    as_base64: bool = False,
) -> dict:
    """Return a byte window plus everything a caller needs to page onward.

    `next_offset` is the point the *caller* should pass next; it is absent when
    the window reached the end, which is how a reader knows the body is fully
    seen rather than merely partly seen.
    """
    total = len(data)
    start = max(0, min(int(offset or 0), total))
    span = limit if length is None else max(1, min(int(length), limit))
    chunk = data[start:start + span]
    end = start + len(chunk)
    out: dict[str, Any] = {
        "total_bytes": total,
        "offset": start,
        "returned_bytes": len(chunk),
        "complete": end >= total,
    }
    if end < total:
        out["next_offset"] = end
        out["hint"] = (
            f"Body continues: {total - end} bytes remain. Call again with offset={end} "
            f"before concluding anything about the rest."
        )
    else:
        out["next_offset"] = None
    if as_base64:
        out["encoding"] = "base64"
        out["data"] = base64.b64encode(chunk).decode("ascii")
    else:
        out["encoding"] = "utf8-lossy"
        out["data"] = chunk.decode("utf-8", errors="replace")
    return out


def _raw_request(method: str, url: str, headers: dict, body: bytes) -> str:
    """Reconstruct the wire form of a request from the stored columns."""
    lines = [f"{method or 'GET'} {url or '/'} HTTP/1.1"]
    lowered = {str(k).lower() for k in (headers or {})}
    for name, value in (headers or {}).items():
        if isinstance(value, (list, tuple)):
            for item in value:
                lines.append(f"{name}: {item}")
        else:
            lines.append(f"{name}: {value}")
    if body and "content-length" not in lowered:
        lines.append(f"Content-Length: {len(body)}")
    head = "\r\n".join(lines)
    return f"{head}\r\n\r\n" + body.decode("utf-8", errors="replace")


_REASONS_BY_CODE = {
    200: "OK", 201: "Created", 204: "No Content", 301: "Moved Permanently",
    302: "Found", 304: "Not Modified", 307: "Temporary Redirect",
    308: "Permanent Redirect", 400: "Bad Request", 401: "Unauthorized",
    403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
    409: "Conflict", 413: "Payload Too Large", 415: "Unsupported Media Type",
    429: "Too Many Requests", 500: "Internal Server Error",
    502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
}


def _raw_response(status: Any, headers: dict, body: bytes) -> str:
    """Reconstruct the wire form of a response from the stored columns."""
    try:
        code = int(status)
    except (TypeError, ValueError):
        code = 0
    lines = [f"HTTP/1.1 {code} {_REASONS_BY_CODE.get(code, 'Unknown')}"]
    lowered = {str(k).lower() for k in (headers or {})}
    for name, value in (headers or {}).items():
        if isinstance(value, (list, tuple)):
            for item in value:
                lines.append(f"{name}: {item}")
        else:
            lines.append(f"{name}: {value}")
    if body and "content-length" not in lowered:
        lines.append(f"Content-Length: {len(body)}")
    head = "\r\n".join(lines)
    return f"{head}\r\n\r\n" + body.decode("utf-8", errors="replace")


def _summarise_listing(items: list, keys: list[str], limit: int) -> dict:
    """Shape a row listing so a large page does not become a large context cost."""
    trimmed = []
    for item in items[:limit]:
        if isinstance(item, dict):
            trimmed.append({k: item.get(k) for k in keys if k in item})
    return {"rows": trimmed, "rows_returned": len(trimmed)}


# --------------------------------------------------------------------------
# Server
# --------------------------------------------------------------------------

_client: RRClient = None  # type: ignore[assignment]


@asynccontextmanager
async def lifespan(_server: MCPServer):
    """Own the HTTP client for the server's lifetime."""
    global _client
    _client = RRClient()
    log.info("mcp server ready gateway=%s engine=%s worker=%s", GATEWAY_URL, ENGINE_URL, WORKER_URL)
    try:
        yield {}
    finally:
        await _client.aclose()


server = MCPServer(
    name="request-rider",
    version="2.0.0",
    instructions=SERVER_INSTRUCTIONS,
    lifespan=lifespan,
)


def _service(base: str):
    """Return a dispatcher bound to one service, translating transport faults."""
    async def call(method: str, path: str, **kwargs):
        try:
            if base == GATEWAY_URL:
                return await _client.gateway(method, path, **kwargs)
            if base == ENGINE_URL:
                return await _client.engine(method, path, **kwargs)
            return await _client.worker(method, path, **kwargs)
        except RRTransport as error:
            return None, error

    return call


# ==========================================================================
# GROUP 0 — platform status
# ==========================================================================


@server.tool()
async def platform_status() -> dict:
    """Report whether the whole Request-Rider stack is reachable, and what the
    active Project and outbound route currently are.

    Call this first in a session. It answers three questions an agent otherwise
    guesses at: is the platform up, which Project is its evidence bound to, and
    is traffic leaving directly or through Tor. The active Project is per
    session, so a run that reports "no rows" is often simply pointed at the wrong
    workspace — `project_list` and `project_switch_active` fix that.

    Returns: `ok`, per-service reachability, `active_project` (id/name/target),
    `route`, and the engine's own counters when it answers.
    """
    out: dict[str, Any] = {"ok": True, "gateway_url": GATEWAY_URL, "engine_url": ENGINE_URL,
                           "worker_url": WORKER_URL}
    try:
        status, body = await _client.gateway("GET", "/health", timeout=LIST_TIMEOUT)
    except RRTransport as error:
        return _service_down(GATEWAY_URL, error)
    out["gateway"] = {"reachable": True, "status": status, "services": body if isinstance(body, dict) else {}}

    try:
        status, body = await _client.engine("GET", "/health", timeout=LIST_TIMEOUT)
        out["engine"] = {"reachable": status < 500, "status": status, "detail": body}
    except RRTransport as error:
        out["engine"] = {"reachable": False, "error": str(error)}

    try:
        status, body = await _client.worker("GET", "/health", timeout=LIST_TIMEOUT)
        out["browser_worker"] = {"reachable": status < 500, "status": status}
    except RRTransport as error:
        out["browser_worker"] = {"reachable": False, "error": str(error)}

    try:
        status, body = await _client.gateway("GET", "/api/route", timeout=LIST_TIMEOUT)
        if status == 200 and isinstance(body, dict):
            out["route"] = body
    except RRTransport:
        pass

    try:
        status, body = await _client.gateway("GET", "/api/projects", timeout=LIST_TIMEOUT)
        if status == 200 and isinstance(body, dict):
            out["projects"] = [
                {"id": p.get("id"), "name": p.get("name"), "target": p.get("target"),
                 "is_active": bool(p.get("is_active") or p.get("active"))}
                for p in (body.get("items") or [])
            ]
    except RRTransport:
        pass
    return out


# ==========================================================================
# GROUP 1 — History, Proxy Traffic, Target Map
# ==========================================================================

HISTORY_LIST_KEYS = [
    "id", "timestamp", "source", "origin", "host", "source_ip", "method", "url",
    "status", "time", "response_content_type", "response_size", "tags", "notes",
    "proxy_event_id", "capture_context",
]


@server.tool()
async def history_get_records(
    store: str = "history",
    host: str = "",
    path: str = "",
    method: str = "",
    status: int = 0,
    mime: str = "",
    source: str = "",
    query: str = "",
    latency_min_ms: int = 0,
    latency_max_ms: int = 0,
    size_min: int = 0,
    size_max: int = 0,
    offset: int = 0,
    limit: int = 25,
    project_id: int = 0,
    sort: str = "-timestamp",
) -> dict:
    """List captured HTTP exchanges as metadata rows, newest first.

    This is a *listing*: it deliberately returns no bodies, so a page of 200
    rows stays cheap regardless of how large those captures are. Take an `id`
    from here and call `history_get_transaction_raw` to read the actual bytes.

    Args:
        store: `history` = the durable tool/proxy archive the operator sent
            (`GET /api/history`); `traffic` = the passive MITM archive
            (`GET /api/traffic/records`), which also holds ambient browser
            traffic. `both` merges the two, de-duplicated by id.
        host: case-insensitive substring of the host.
        path: substring of the URL, e.g. `/admin`.
        method: HTTP method, e.g. `POST`.
        status: exact status code, e.g. `401`. 0 disables the filter.
        mime: substring of the response Content-Type, e.g. `application/json`.
        source: one of `repeater`, `intruder`, `last-byte`, `proxy`, `tool`.
            Applied by this server, because the gateway exposes no source
            parameter on either listing.
        query: free text matched against URL, headers and bodies server-side.
        latency_min_ms / latency_max_ms: response-time window in milliseconds.
        size_min / size_max: response body size window in bytes.
        offset: row offset for paging.
        limit: rows to return (1..200, default 25).
        project_id: restrict to one Project. 0 uses the active Project.
        sort: `timestamp`, `-timestamp`, `url`, `-url`, `status_code`,
            `-status_code`, `response_size`, `-response_size`, `host`, `method`.
            `history` also sorts on these.

    Returns: `items` (metadata rows), `total` (real match size, not page size),
    `offset`, `returned`, and `next_offset` when more rows remain.
    """
    store = (store or "history").lower()
    limit = _clamp(limit, 1, LIST_MAX_ROWS, 25)
    offset = max(0, int(offset or 0))
    sources = {s.strip() for s in (source or "").split(",") if s.strip()}

    params: dict[str, Any] = {
        "offset": offset,
        "limit": limit,
        "project_id": project_id or None,
        "host": host or None,
        "path": path or None,
        "method": method or None,
        "status": status or None,
        "mime": mime or None,
        "q": query or None,
        "size_min": size_min or None,
        "size_max": size_max or None,
        "latency_min": latency_min_ms or None,
        "latency_max": latency_max_ms or None,
        "sort": sort or None,
    }

    collected: list[dict] = []
    totals: dict[str, Any] = {}
    errors: list[dict] = []

    targets = ["history", "traffic"] if store == "both" else [store]
    for name in targets:
        if name == "history":
            status_code, body = await _client.gateway(
                "GET", "/api/history", params=params, timeout=LIST_TIMEOUT
            )
        elif name == "traffic":
            status_code, body = await _client.gateway(
                "GET", "/api/traffic/records",
                params={**params, "detail": "summary"}, timeout=LIST_TIMEOUT,
            )
        else:
            return _fail("INVALID_ARGUMENT", "store must be history, traffic or both")

        if status_code != 200 or not isinstance(body, dict):
            reason, message = _reason_of(status_code, body)
            errors.append({"store": name, "status": status_code, "reason": reason, "error": message})
            continue
        rows = body.get("items") or []
        totals[name] = body.get("total", len(rows))
        collected.extend(r for r in rows if isinstance(r, dict))

    if errors and not collected:
        first = errors[0]
        return _fail(
            first["reason"] or "HISTORY_READ_FAILED",
            first["error"] or f"{first['store']} listing failed",
            errors=errors,
        )

    if sources:
        collected = [r for r in collected if str(r.get("source") or "") in sources]

    seen: set[str] = set()
    unique: list[dict] = []
    for row in collected:
        key = f"{row.get('store') or ''}:{row.get('id')}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(row)

    page = unique[:limit]
    next_offset = offset + limit if (offset + limit) < max(totals.values() or [0]) else None
    return _ok(
        store=store,
        items=page,
        totals=totals,
        matched=len(unique),
        offset=offset,
        returned=len(page),
        next_offset=next_offset,
        totals_note="total is the real match size across the filtered set, not the page length.",
        partial_errors=errors or None,
        next_call="Take any item id into history_get_transaction_raw to read its bytes.",
    )


@server.tool()
async def history_get_transaction_raw(
    record_id: int = 0,
    traffic_event_id: int = 0,
    offset: int = 0,
    length: int = 0,
    encoding: str = "utf8",
    max_bytes: int = 0,
) -> dict:
    """Read one captured exchange completely: status, headers, timings and bodies.

    This is the tool that replaces "paste the response body into the chat".
    It returns the request and the response in reconstructed wire form
    (`raw_request`, `raw_response`) plus the stored columns, so an LLM sees what
    the target actually sent and received.

    Args:
        record_id: id from `history_get_records` or the Traffic tab.
        traffic_event_id: id from the *live* in-memory Traffic store instead
            (`GET /api/traffic/detail`). Live rows disappear on engine restart or
            on `Refresh traffic`; prefer `record_id` for durable rows.
        offset: byte offset into the body to start reading at. Use it with
            `next_offset` to page through a large body.
        length: bytes to return from this offset. Capped by `max_bytes`.
        encoding: `utf8` returns text with lossy replacement for undecodable
            bytes; `base64` returns the exact bytes, which is what you want for
            binary bodies, images, gzip payloads and multipart uploads.
        max_bytes: ceiling for this call. Defaults to `RR_RAW_MAX_BYTES` (64 KiB);
            raise it explicitly when a body must be read whole.

    Returns: `raw_request`, `raw_response`, `status`, `latency_ms`, `size`,
    headers, and the request/response body windows with `total_bytes`,
    `returned_bytes`, `complete` and `next_offset`. When a body is not fully
    returned, `complete` is false and `next_offset` names the next window.
    """
    if not record_id and not traffic_event_id:
        return _fail("INVALID_ARGUMENT", "record_id or traffic_event_id is required")

    window = _clamp(max_bytes, 1024, 16 * 1024 * 1024, RAW_MAX_BYTES) if max_bytes else RAW_MAX_BYTES
    span = int(length) if length else None
    as_base64 = (encoding or "utf8").lower() == "base64"

    if record_id:
        status, body = await _client.gateway("GET", f"/api/history/{int(record_id)}", timeout=LIST_TIMEOUT)
        if status == 404:
            return _fail("RECORD_NOT_FOUND", f"History record {record_id} does not exist")
        if status != 200 or not isinstance(body, dict):
            reason, message = _reason_of(status, body)
            return _fail(reason or "RECORD_READ_FAILED", message or "could not read the record",
                         record_id=record_id)
        item = body
        source_label = "history"
    else:
        status, body = await _client.gateway(
            "GET", "/api/traffic/detail", params={"id": int(traffic_event_id)}, timeout=LIST_TIMEOUT
        )
        if status != 200 or not isinstance(body, dict):
            reason, message = _reason_of(status, body)
            return _fail(reason or "RECORD_READ_FAILED",
                         message or "live traffic event is gone (engine restart or Refresh traffic)",
                         traffic_event_id=traffic_event_id)
        item = body
        source_label = "traffic-live"

    req_bytes = _body_bytes(item.get("request_body"), item.get("request_body_base64"),
                            item.get("request_body_encoding"))
    resp_bytes = _body_bytes(item.get("response_body"), item.get("response_body_base64"),
                             item.get("response_body_encoding"))

    headers = item.get("response_headers") or {}
    content_type = item.get("response_content_type") or headers.get("Content-Type", "")
    is_binary = bool(content_type) and not any(
        token in str(content_type).lower()
        for token in ("text/", "json", "xml", "javascript", "x-www-form-urlencoded", "html", "css", "csv")
    )

    request_window = _window(req_bytes, offset=0, length=span, limit=window, as_base64=as_base64)
    response_window = _window(resp_bytes, offset=offset, length=span, limit=window,
                              as_base64=as_base64 or is_binary)

    return _ok(
        source=source_label,
        record_id=item.get("id") or record_id or None,
        timestamp=item.get("timestamp"),
        method=item.get("method"),
        url=item.get("url"),
        host=item.get("host"),
        source_ip=item.get("source_ip") or None,
        origin=item.get("origin"),
        status=item.get("status"),
        latency_ms=item.get("time"),
        response_size=item.get("response_size"),
        content_type=content_type,
        request_headers=item.get("request_headers") or {},
        response_headers=headers,
        request_headers_count=len(item.get("request_headers") or {}),
        response_headers_count=len(headers),
        raw_request=_raw_request(str(item.get("method") or "GET"), str(item.get("url") or "/"),
                                 item.get("request_headers") or {}, req_bytes),
        raw_response=_raw_response(item.get("status"), headers, resp_bytes),
        request_body=request_window,
        response_body=response_window,
        binary_response=is_binary,
        tags=item.get("tags") or [],
        notes=item.get("notes") or "",
        next_call=(
            "Response body continues — call again with the same record_id and "
            f"offset={response_window['next_offset']} before judging the rest."
            if response_window.get("next_offset") is not None else None
        ),
    )


@server.tool()
async def target_get_sitemap(
    map_id: int = 0,
    project_id: int = 0,
    include_pages: bool = True,
    page_limit: int = 200,
    page_offset: int = 0,
    only_js_findings: bool = False,
) -> dict:
    """Read a finished Target crawl: the URL tree, parameters, forms and JS findings.

    A crawl is asynchronous — `target_run_crawl` returns a `map_id`, and this tool
    is how you read the result. The engine's job table is in memory: a crawl id
    stops resolving after an engine restart, and a Project keeps the evidence.

    Args:
        map_id: the crawl id returned by `target_run_crawl`.
        project_id: with no `map_id`, returns the Project's crawler jobs so you
            know which ids exist and what state they are in.
        include_pages: include the per-page rows. Turn off when you only want
            counts and the JS findings, which is the cheap first look.
        page_limit: cap on page rows returned (1..1000, default 200). The full
            crawl stays on the engine; page with `page_offset` for more.
        only_js_findings: return just the JS findings and omit the URL rows.
            These are the routes, sinks and secrets the analysers extracted from
            the bundles the crawler loaded.

    Returns: crawl status and counters, `pages` (url, depth, status, content_type,
    kind, params, forms), and `js_findings` gathered across pages.
    """
    if map_id:
        status, body = await _client.gateway(
            "GET", "/api/target-map", params={"map_id": int(map_id)}, timeout=LIST_TIMEOUT
        )
        if status != 200 or not isinstance(body, dict):
            reason, message = _reason_of(status, body)
            return _fail(reason or "TARGET_MAP_READ_FAILED",
                         message or "could not read the crawl", map_id=map_id)
        crawl = body
    else:
        if not project_id:
            return _fail("INVALID_ARGUMENT",
                         "map_id is required. Call target_run_crawl first, or pass project_id "
                         "to list this Project's crawler jobs.")
        status, body = await _client.gateway(
            "GET", f"/api/projects/{int(project_id)}/hub", timeout=LIST_TIMEOUT
        )
        if status != 200 or not isinstance(body, dict):
            reason, message = _reason_of(status, body)
            return _fail(reason or "PROJECT_READ_FAILED", message or "could not read the hub")
        jobs = [j for j in (body.get("active_jobs") or []) if j.get("type") == "target_crawler"]
        return _ok(
            project_id=project_id,
            crawler_jobs=jobs,
            counts={
                "exchanges": body.get("counts", {}).get("exchanges"),
                "endpoints": body.get("counts", {}).get("endpoints"),
                "findings": body.get("findings_by_severity"),
            },
            next_call="Pass one of crawler_jobs[].id as map_id to read its map.",
        )

    pages = crawl.get("pages") or []
    limit = _clamp(page_limit, 1, 1000, 200)
    start = max(0, int(page_offset or 0))

    js_findings: list[Any] = []
    for page in pages:
        if not isinstance(page, dict):
            continue
        findings = page.get("js_findings") or page.get("js_findings_raw")
        if findings:
            entry = {"url": page.get("url")}
            if isinstance(findings, list):
                entry["findings"] = findings
            else:
                entry["findings"] = findings
            js_findings.append(entry)

    out: dict[str, Any] = {
        "map_id": crawl.get("map_id", map_id),
        "status": crawl.get("status"),
        "start_url": crawl.get("start_url"),
        "visited": crawl.get("visited"),
        "total": crawl.get("total"),
        "error": crawl.get("error") or None,
        "pages_total": len(pages),
        "js_findings": js_findings if only_js_findings else None,
        "js_findings_count": len(js_findings),
    }
    if include_pages and not only_js_findings:
        out["pages"] = pages[start:start + limit]
        out["page_offset"] = start
        out["pages_returned"] = min(limit, max(0, len(pages) - start))
        if start + limit < len(pages):
            out["next_page_offset"] = start + limit
    if js_findings and not only_js_findings:
        out["js_findings_hint"] = "Call again with only_js_findings=True to read them in full."
    return _ok(**out)


@server.tool()
async def target_run_crawl(
    url: str,
    mode: str = "static",
    max_pages: int = 0,
    max_depth: int = -1,
    delay_ms: int = 0,
    same_origin: bool = False,
    extract_js_routes: bool = True,
    browser: str = "firefox",
    navigation_timeout_ms: int = 0,
    auto_interact: bool = False,
    project_id: int = 0,
) -> dict:
    """Start a Target crawl and return its job id.

    Two modes, because they answer different questions:

    * `static` — the Go crawler. Follows links, forms, JS/CSS/JSON URLs,
      `robots.txt` and sitemaps. Fast, and it never executes script.
    * `browser` — Playwright via the browser worker. Executes the SPA, so client
      routes, XHR calls and bot-protected pages are actually reachable. Slower.

    Args:
        url: start URL, e.g. `https://target.example/app`.
        mode: `static` or `browser`.
        max_pages: page budget. `0` means unlimited.
        max_depth: link depth. `-1` means unlimited; `0` is just the start page.
        delay_ms: pause between requests, for targets that rate-limit.
        same_origin: stay on the start URL's host and port. Off means the crawl
            may follow links to other hosts.
        extract_js_routes: analyse loaded JavaScript for routes, sinks and
            secrets. In `static` mode this is what surfaces SPA endpoints.
        browser: browser runtime for `browser` mode — `firefox`, `chromium`,
            `chrome`, `edge`, `webkit`.
        navigation_timeout_ms: per-navigation deadline in `browser` mode.
            `0` means no deadline.
        auto_interact: in `browser` mode, let the worker click and fill to reach
            routes that need interaction.
        project_id: bind the crawl to a Project. 0 uses the active Project.

    Returns: `job_id` and `status`. Poll with `target_get_sitemap(map_id=…)`
    until `status` is `completed`, `cancelled` or `failed`.

    Limits are yours to set: `0`/`-1` mean unbounded, and a value you pass is
    the value the crawl runs with.
    """
    if not url or not str(url).strip():
        return _fail("INVALID_ARGUMENT", "url is required")
    mode = (mode or "static").lower()

    if mode == "static":
        payload = {
            "url": str(url).strip(),
            "max_pages": int(max_pages or 0),
            "max_depth": int(max_depth if max_depth is not None else -1),
            "delay_ms": int(delay_ms or 0),
            "same_origin": bool(same_origin),
        }
        if not extract_js_routes:
            payload["extract_js_routes"] = False
        if project_id:
            payload["project_id"] = int(project_id)
        status, body = await _client.gateway(
            "POST", "/api/target-map", json_body=payload, timeout=LIST_TIMEOUT
        )
        job_key = "map_id"
    elif mode == "browser":
        payload = {
            "url": str(url).strip(),
            "browser": str(browser or "firefox").lower(),
            "mode": "navigation",
            "max_pages": int(max_pages or 0),
            "max_depth": int(max_depth if max_depth is not None else -1),
            "delay_ms": int(delay_ms or 0),
            "navigation_timeout_ms": int(navigation_timeout_ms or 0),
            "same_origin": bool(same_origin),
            "auto_interact": bool(auto_interact),
            "allow_state_changing_actions": bool(auto_interact),
        }
        if project_id:
            payload["project_id"] = int(project_id)
        status, body = await _client.gateway(
            "POST", "/api/target-browser", json_body=payload, timeout=LIST_TIMEOUT
        )
        job_key = "job_id"
    else:
        return _fail("INVALID_ARGUMENT", "mode must be static or browser")

    if status not in (200, 202) or not isinstance(body, dict):
        reason, message = _reason_of(status, body)
        return _fail(reason or "CRAWL_START_FAILED", message or "the crawl did not start", mode=mode)

    job_id = body.get(job_key) or body.get("map_id") or body.get("job_id")
    return _ok(
        job_id=job_id,
        map_id=body.get("map_id"),
        status=body.get("status"),
        mode=mode,
        url=url,
        next_call=f"Poll target_get_sitemap(map_id={job_id}) until status is completed/cancelled/failed.",
    )


# ==========================================================================
# GROUP 2 — Kebab routing and request execution
# ==========================================================================


@server.tool()
async def kebab_send_to_tool(
    target: str,
    record_id: int = 0,
    raw_http: str = "",
    marker_name: str = "payload",
    marker_style: str = "{{name}}",
    payloads: list | None = None,
    mode: str = "sniper",
    transformations: list | None = None,
    delay_ms: int = 150,
    concurrency: int = 1,
    name: str = "",
    comparer_side: str = "left",
    workflow_name: str = "",
) -> dict:
    """Route a captured transaction into another tool, the way the UI's
    "Send to ..." does.

    What each target really produces, so you know what to expect back:

    * `intruder` — **a saved attack** appears in the Intruder tab, base request
      filled and the marker inserted at the chosen position. Start it with
      `intruder_start_attack`, or run it from the Intruder tab.
    * `automation` — **a saved Workflow** appears in the Automation canvas with a
      Manual trigger wired to a Repeater node carrying this request. It is not
      activated: activate it yourself, because activation is an operator action.
    * `repeater` — the request is executed once and persisted as a Repeater
      History row, which you then read with `history_get_transaction_raw`. This
      is the server-side part of "send to Repeater"; the Repeater tab's own tab
      strip is browser state and is not addressable from here.
    * `comparer` — the Comparer panel is browser-side and has no server state,
      so this returns the prepared A/B payload pair for you to paste. It says so
      rather than pretending to have created a panel.

    Args:
        target: `repeater`, `intruder`, `automation` or `comparer`.
        record_id: captured exchange to route. Give either this or `raw_http`.
        raw_http: a raw HTTP request to route instead of a stored record.
        marker_name: parameter name for the Intruder marker, e.g. `id`.
        marker_style: `{{name}}`, `§name§` or `%name%` — the three styles the
            engine's marker parser accepts.
        payloads: payload dictionaries for the saved Intruder attack.
        mode: Intruder mode — `sniper`, `battering_ram`, `pitchfork`,
            `cluster_bomb`.
        transformations: Intruder transformation chain, e.g. `["urlEncode"]`.
        delay_ms: delay between Intruder requests.
        concurrency: parallel Intruder requests.
        name: name for the created artifact. Defaults are derived from the source.
        comparer_side: for `comparer`, which side this payload belongs on.
        workflow_name: name for a created Workflow.

    Returns: the created artifact's id, plus the exact request that was routed so
    you can act on it immediately.
    """
    target = (target or "").lower()
    if target not in {"repeater", "intruder", "automation", "comparer"}:
        return _fail("INVALID_ARGUMENT",
                     "target must be repeater, intruder, automation or comparer")

    base: dict[str, Any]
    source_note: str
    if record_id:
        detail = await history_get_transaction_raw(record_id=int(record_id))
        if not detail.get("ok"):
            return detail
        headers = detail.get("request_headers") or {}
        body = (detail.get("request_body") or {}).get("data") or ""
        base = {"method": detail.get("method") or "GET", "url": detail.get("url") or "",
                "headers": headers, "body": body}
        source_note = f"History record {record_id}"
    elif raw_http:
        parsed = parse_raw_http(raw_http)
        if not parsed.get("ok"):
            return parsed
        base = {"method": parsed["method"], "url": parsed["url"],
                "headers": parsed["headers"], "body": parsed["body"]}
        source_note = "supplied raw_http"
    else:
        return _fail("INVALID_ARGUMENT", "record_id or raw_http is required")

    if not base.get("url"):
        return _fail("INVALID_ARGUMENT", "the source transaction has no URL to route")

    wire = _raw_request(base["method"], base["url"], base["headers"],
                        base["body"].encode("utf-8", errors="surrogateescape"))

    if target == "repeater":
        status, body = await _client.gateway(
            "POST", "/api/execute", json_body=base, timeout=HTTP_TIMEOUT
        )
        if status != 200 or not isinstance(body, dict):
            reason, message = _reason_of(status, body)
            return _fail(reason or "REPEATER_SEND_FAILED", message or "the request did not execute")
        return _ok(
            target="repeater",
            persisted_as="repeater History row",
            raw_request=wire,
            status=body.get("status"),
            latency_ms=body.get("time"),
            traffic_event_id=body.get("traffic_event_id"),
            response_size=body.get("size"),
            source=source_note,
            next_call="Read it with history_get_records(source='repeater') or "
                      "history_get_transaction_raw(traffic_event_id=…).",
        )

    if target == "intruder":
        marker = build_marker(marker_style, marker_name)
        marked, insert_note = insert_marker(base["url"] + (base["body"] or ""),
                                             base["url"], base["body"] or "", marker)
        marked_url, marked_body = split_marked(marked, base["url"], base["body"] or "")
        if not marked_url:
            return _fail("MARKER_NOT_PLACED", insert_note)
        saved = {
            "name": name or f"From {source_note}",
            "mode": mode,
            "base_request": {"method": base["method"], "url": marked_url,
                             "headers": base["headers"], "body": marked_body},
            "payloads": payloads if payloads is not None else [],
            "transformations": transformations or [],
            "delay_ms": int(delay_ms if delay_ms is not None else 150),
            "concurrency": max(1, int(concurrency or 1)),
        }
        status, body = await _client.gateway(
            "POST", "/api/intruder/saved", json_body=saved, timeout=LIST_TIMEOUT
        )
        if status not in (200, 201) or not isinstance(body, dict):
            reason, message = _reason_of(status, body)
            return _fail(reason or "INTRUDER_SAVE_FAILED",
                         message or "could not save the attack", marker=marker)
        return _ok(
            target="intruder",
            marker=marker,
            marker_placed=insert_note,
            saved_attack=body,
            base_request_marked=saved["base_request"],
            source=source_note,
            next_call="Start it with intruder_start_attack(mode=…, payloads=…).",
        )

    if target == "automation":
        graph = {
            "name": workflow_name or name or f"From {source_note}",
            "active": False,
            "nodes": [
                {"id": "trigger_1", "type": "manual_trigger", "position": {"x": 80, "y": 120}},
                {"id": "repeater_1", "type": "repeater", "position": {"x": 380, "y": 120},
                 "parameters": {"method": base["method"], "url": base["url"],
                                "headers": base["headers"], "body": base["body"]}},
            ],
            "connections": [{"from": "trigger_1", "to": "repeater_1", "from_output": "main",
                             "to_input": "main"}],
        }
        status, body = await _client.gateway(
            "POST", "/api/workflows", json_body=graph, timeout=LIST_TIMEOUT
        )
        if status not in (200, 201) or not isinstance(body, dict):
            reason, message = _reason_of(status, body)
            return _fail(reason or "WORKFLOW_CREATE_FAILED",
                         message or "could not create the workflow", nodes=graph["nodes"])
        return _ok(
            target="automation",
            workflow={"id": body.get("id"), "name": body.get("name"), "active": body.get("active")},
            node_types=["manual_trigger", "repeater"],
            source=source_note,
            next_call="The workflow is saved and inactive. Activate it in the Automation tab, "
                      "or POST /api/workflows/<id>/activate with confirm_active.",
        )

    side = "right" if str(comparer_side).lower() == "right" else "left"
    return _ok(
        target="comparer",
        side=side,
        source=source_note,
        raw_request=wire,
        other_side_empty=side == "left",
        note="The Comparer panel is browser state with no server-side endpoint. Paste this "
             "payload into that panel; the platform cannot place it for you.",
        next_call="Send the same record to the other side with comparer_side='right', then compare.",
    )


def parse_raw_http(raw: str) -> dict:
    """Split a raw HTTP request into method, URL, headers and body.

    Handles the two forms an LLM actually produces: real CRLF line breaks, and
    the escaped `\\r\\n` a model writes when it means them literally.
    """
    text = raw or ""
    if "\\r\\n" in text and "\r\n" not in text:
        text = text.replace("\\r\\n", "\n").replace("\\n", "\n")
    text = text.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = [line for line in head.split("\n") if line.strip()]
    if not lines:
        return _fail("INVALID_ARGUMENT", "raw_http is empty")
    request_line = lines[0].strip()
    parts = request_line.split(" ")
    if len(parts) < 2:
        return _fail("INVALID_ARGUMENT", f"unparsable request line: {request_line!r}")
    method = parts[0].upper()
    target = parts[1]
    url = target if target.startswith(("http://", "https://")) else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip()] = value.strip()
    if not url:
        host = headers.get("Host") or headers.get("host") or ""
        if not host:
            return _fail("INVALID_ARGUMENT",
                         "the request has no absolute URL and no Host header")
        url = f"http://{host}{target if target.startswith('/') else '/' + target}"
    return {"ok": True, "method": method, "url": url, "headers": headers, "body": body}


def build_marker(style: str, name: str) -> str:
    """Render an Intruder marker in one of the three styles the engine parses."""
    style = (style or "{{name}}").strip()
    if style in {"§name§", "sigil"}:
        return f"§{name}§"
    if style in {"%name%", "percent"}:
        return f"%{name}%"
    if style in {"{{name}}", "mustache"}:
        return f"{{{{{name}}}}}"
    return style.replace("name", name)


def insert_marker(combined: str, url: str, body: str, marker: str) -> tuple[str, str]:
    """Place a marker on the first editable value position.

    Query parameters win over the body: fuzzing a parameter that already exists
    is the point, and inventing a body parameter when the request is a GET gives
    the attack somewhere to go that the target never reads.
    """
    parsed = urllib.parse.urlsplit(url)
    if parsed.query:
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if query:
            key = query[0][0]
            rebuilt = urllib.parse.urlencode([(key, marker)] + query[1:], doseq=False)
            new_query = rebuilt
            new_url = urllib.parse.urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment)
            )
            note = f"marker placed on query parameter '{key}'"
            return new_url + (body or ""), note
    if body:
        form = urllib.parse.parse_qsl(body, keep_blank_values=True)
        if form:
            key = form[0][0]
            rebuilt = urllib.parse.urlencode([(key, marker)] + form[1:], doseq=False)
            return url + rebuilt, f"marker placed on form field '{key}'"
        note = "no parameter found — marker appended to the request body"
        return url + (body + marker), note
    return url + marker, "no parameters found — marker appended to the URL"


def split_marked(marked: str, url: str, body: str) -> tuple[str, str]:
    """Recover the (url, body) pair from the combined marked string."""
    if body and marked.endswith(body):
        return marked[: len(marked) - len(body)], body
    if marked.startswith(url):
        return url, marked[len(url):]
    return marked, ""


@server.tool()
async def repeater_send_raw_http(
    raw_http: str = "",
    method: str = "",
    url: str = "",
    headers: dict | None = None,
    body: str = "",
    timeout_ms: int = 0,
) -> dict:
    """Send one raw HTTP request through the engine, exactly as sent.

    The request reaches the target through Request-Rider's own transport, so the
    passive proxy captures it and History records it with a `source` of
    `repeater`. That is the difference from calling the target directly: the
    exchange becomes evidence in the Project instead of a line in a log.

    Args:
        raw_http: the complete request as text, e.g.
            `GET /admin HTTP/1.1\r\nHost: target\r\n\r\n`. Use this when you have
            a captured request. `method`/`url`/`headers`/`body` are ignored when
            it is present.
        method: HTTP method, when not using `raw_http`.
        url: absolute URL, when not using `raw_http`.
        headers: request headers, when not using `raw_http`.
        body: request body, when not using `raw_http`.
        timeout_ms: request deadline in milliseconds. `0` keeps the engine's own
            deadline.

    Returns: status, all response headers, latency, size, `traffic_event_id` (the
    id `history_get_transaction_raw` takes), `source_ip`, and the response body
    windowed to protect the context window — follow `next_offset` to read more.
    """
    if raw_http:
        parsed = parse_raw_http(raw_http)
        if not parsed.get("ok"):
            return parsed
        method, url = parsed["method"], parsed["url"]
        headers, body = parsed["headers"], parsed["body"]
    if not url:
        return _fail("INVALID_ARGUMENT", "url or raw_http is required")

    payload = {
        "method": str(method or "GET").upper(),
        "url": str(url),
        "headers": headers or {},
        "body": body or "",
    }
    if timeout_ms:
        payload["timeout_ms"] = int(timeout_ms)

    status, response = await _client.gateway(
        "POST", "/api/execute", json_body=payload, timeout=HTTP_TIMEOUT
    )
    if status != 200 or not isinstance(response, dict):
        reason, message = _reason_of(status, response)
        return _fail(reason or "REQUEST_FAILED", message or "the request did not complete",
                     url=url)

    resp_bytes = _body_bytes(response.get("body"), response.get("body_base64"),
                             response.get("body_encoding"))
    return _ok(
        status=response.get("status"),
        latency_ms=response.get("time"),
        size=response.get("size"),
        headers=response.get("headers") or {},
        content_type=response.get("body_content_type") or response.get("headers", {}).get("Content-Type"),
        traffic_event_id=response.get("traffic_event_id"),
        source_ip=response.get("source_ip"),
        raw_response=_raw_response(response.get("status"), response.get("headers") or {}, resp_bytes),
        response_body=_window(resp_bytes),
        recorded_as="repeater History row",
        next_call="history_get_transaction_raw(record_id) reads the stored copy of this exchange.",
    )


@server.tool()
async def repeater_burst_test(
    method: str,
    url: str,
    headers: dict | None = None,
    body: str = "",
    iterations: int = 5,
    concurrency: int = 2,
    delay_ms: int = 0,
    timeout_ms: int = 0,
) -> dict:
    """Fire the same request several times to test race conditions and parallelism.

    Race conditions, double-spend bugs and counter limits only appear when two
    requests overlap, so `concurrency` matters more than `iterations`. Start with
    concurrency 2 and a few iterations: a burst is the most expensive thing this
    server will do to a stranger's server, and the answer is in the comparison of
    the responses rather than in their count.

    Args:
        method: HTTP method.
        url: absolute URL.
        headers: request headers.
        body: request body.
        iterations: how many requests to send (>= 1).
        concurrency: how many are in flight at once (>= 1).
        delay_ms: pause before each request.
        timeout_ms: per-request deadline; 0 keeps the engine's own.

    Returns: the job id and the per-request results — status, latency and body
    length for each, so a differential between them is visible directly.
    """
    if not url:
        return _fail("INVALID_ARGUMENT", "url is required")
    payload = {
        "method": str(method or "GET").upper(),
        "url": str(url),
        "headers": headers or {},
        "body": body or "",
        "iterations": max(1, int(iterations or 1)),
        "concurrency": max(1, int(concurrency or 1)),
        "delay_ms": max(0, int(delay_ms or 0)),
        "timeout_ms": max(0, int(timeout_ms or 0)),
    }
    status, response = await _client.engine(
        "POST", "/proxy/repeater-burst", json_body=payload, timeout=LIST_TIMEOUT
    )
    if status not in (200, 202) or not isinstance(response, dict):
        reason, message = _reason_of(status, response)
        return _fail(reason or "BURST_START_FAILED", message or "the burst did not start",
                     payload=payload)
    return _ok(
        burst_id=response.get("burst_id"),
        status=response.get("status"),
        request=payload,
        results=response.get("results"),
        next_call="Poll GET :8081/proxy/repeater-burst/<burst_id> for progress, "
                  "DELETE it to stop.",
    )


@server.tool()
async def repeater_last_byte_sync(
    method: str,
    url: str,
    headers: dict | None = None,
    body: str = "",
    iterations: int = 2,
    concurrency: int = 2,
    delay_ms: int = 0,
    hold_ms: int = 50,
    timeout_ms: int = 0,
) -> dict:
    """Hold a request open after its last byte, to test timeouts and smuggling.

    The client sends the complete request, then withholds the final byte for
    `hold_ms`. A front-end proxy and the origin server each time out
    independently, and the gap between those two timeouts is where request
    smuggling lives: one hop may treat the next request as the tail of this one.

    Args:
        method: HTTP method. POST/PUT bodies are the interesting case.
        url: absolute URL.
        headers: request headers.
        body: request body; must be non-empty for a meaningful desync test.
        iterations: how many connections to open (>= 1).
        concurrency: how many at once (>= 1).
        delay_ms: pause before each connection.
        hold_ms: how long to withhold the last byte.
        timeout_ms: overall deadline; 0 keeps the engine's own.

    Returns: the job id and status. Poll `GET :8081/proxy/last-byte/<id>`.
    """
    if not url:
        return _fail("INVALID_ARGUMENT", "url is required")
    payload = {
        "method": str(method or "POST").upper(),
        "url": str(url),
        "headers": headers or {},
        "body": body or "",
        "iterations": max(1, int(iterations or 1)),
        "concurrency": max(1, int(concurrency or 1)),
        "delay_ms": max(0, int(delay_ms or 0)),
        "hold_ms": max(0, int(hold_ms or 0)),
        "timeout_ms": max(0, int(timeout_ms or 0)),
    }
    status, response = await _client.engine(
        "POST", "/proxy/last-byte", json_body=payload, timeout=LIST_TIMEOUT
    )
    if status not in (200, 202) or not isinstance(response, dict):
        reason, message = _reason_of(status, response)
        return _fail(reason or "LAST_BYTE_START_FAILED",
                     message or "the last-byte job did not start", payload=payload)
    return _ok(
        last_byte_id=response.get("last_byte_id") or response.get("job_id"),
        status=response.get("status"),
        request=payload,
        results=response.get("results"),
        next_call="Poll GET :8081/proxy/last-byte/<id> for progress, DELETE it to stop.",
    )


# ==========================================================================
# GROUP 3 — Projects and Knowledge Hub
# ==========================================================================


@server.tool()
async def project_list() -> dict:
    """List every Project workspace, and say which one is active for this session.

    Read this when a query returns nothing. The active Project filters History,
    Traffic and scanner runs, so "no results" most often means "you are in the
    wrong workspace" rather than "nothing was captured".
    """
    status, body = await _client.gateway("GET", "/api/projects", timeout=LIST_TIMEOUT)
    if status != 200 or not isinstance(body, dict):
        reason, message = _reason_of(status, body)
        return _fail(reason or "PROJECT_LIST_FAILED", message or "could not list projects")
    return _ok(
        items=body.get("items") or [],
        count=len(body.get("items") or []),
        next_call="project_switch_active(project_id) binds evidence to one of these.",
    )


@server.tool()
async def project_create(
    name: str,
    target: str = "",
    environment: str = "",
    route_profile: str = "",
    tech_stack: list | None = None,
    notes: str = "",
) -> dict:
    """Create a Project workspace.

    A Project is the unit that keeps evidence together: its exchanges, endpoints,
    secrets, scanner runs and OSINT graphs. Create one per engagement — without
    it, traffic accumulates with nothing attached and the Knowledge Hub has
    nothing to report.

    Args:
        name: workspace name, e.g. `acme-corp-2026-10`.
        target: the base URL being assessed, e.g. `https://app.example`.
        environment: free text — `staging`, `production`, `dev`.
        route_profile: outbound route to use, e.g. `direct` or `tor`.
        tech_stack: known technologies, e.g. `["nginx", "React", "Java"]`.
        notes: analyst notes. These are passed to the AI context by default, so
            write what the next session would need to know.

    Returns: the created Project, with its `id`.
    """
    if not name or not str(name).strip():
        return _fail("INVALID_ARGUMENT", "name is required")
    payload: dict[str, Any] = {"name": str(name).strip()}
    if target:
        payload["target"] = str(target).strip()
    if environment:
        payload["environment"] = str(environment).strip()
    if route_profile:
        payload["route_profile"] = str(route_profile).strip()
    if tech_stack:
        payload["tech_stack"] = list(tech_stack)
    if notes:
        payload["notes"] = str(notes)
    status, body = await _client.gateway("POST", "/api/projects", json_body=payload, timeout=LIST_TIMEOUT)
    if status not in (200, 201) or not isinstance(body, dict):
        reason, message = _reason_of(status, body)
        return _fail(reason or "PROJECT_CREATE_FAILED", message or "could not create the project",
                     payload=payload)
    return _ok(project=body, next_call="project_switch_active(project_id=…) to make it the active one.")


@server.tool()
async def project_switch_active(project_id: int = 0) -> dict:
    """Bind this session's evidence to a Project, or clear the binding.

    The active Project decides which History, Traffic, Target jobs and scanner
    runs are visible to every other tool here. Call it once at the start of an
    engagement; everything after it is scoped.

    Args:
        project_id: the Project to activate. `0` clears the binding, which makes
            every tool read across all Projects — correct only when you
            genuinely do not know which workspace owns the evidence.

    Returns: the newly active Project, or `null` when cleared.
    """
    payload = {"project_id": int(project_id) if project_id else None}
    status, body = await _client.gateway(
        "POST", "/api/project-context", json_body=payload, csrf=True, timeout=LIST_TIMEOUT
    )
    if status != 200 or not isinstance(body, dict):
        reason, message = _reason_of(status, body)
        return _fail(reason or "PROJECT_SWITCH_FAILED",
                     message or "could not switch the active project", payload=payload)
    return _ok(
        active_project_id=body.get("active_project_id"),
        active_project=body.get("active_project"),
        scope_note="History, Traffic, Target and scanner tools are now scoped to this Project.",
    )


@server.tool()
async def project_get_knowledge_hub(
    project_id: int = 0,
    include_findings: bool = True,
    finding_severities: list | None = None,
) -> dict:
    """Read everything the platform has established about a target.

    This is the report an LLM should read before planning anything: verified
    endpoints, captured exchanges, observed secrets, scanner findings by
    severity and any unfinished jobs. Reading it first is what stops an agent
    asking the operator for a URL it already has.

    Args:
        project_id: which Project. 0 uses the active one.
        include_findings: include the severity breakdown and active jobs.
        finding_severities: when given, keep only these severities, e.g.
            `["CRITICAL", "HIGH"]`.

    Returns: project metadata, endpoint and exchange counts, OSINT graphs,
    observed secrets **in full** (they belong to the engagement and are shown
    without masking), findings by severity, and any running jobs.
    """
    if not project_id:
        status, body = await _client.gateway("GET", "/api/projects", timeout=LIST_TIMEOUT)
        if status != 200 or not isinstance(body, dict):
            reason, message = _reason_of(status, body)
            return _fail(reason or "PROJECT_LIST_FAILED", message or "could not list projects")
        active = [p for p in (body.get("items") or []) if p.get("is_active") or p.get("active")]
        if not active:
            return _fail("PROJECT_CONTEXT_REQUIRED",
                         "No active Project. Call project_switch_active(project_id=…) first.")
        project_id = int(active[0]["id"])

    status, body = await _client.gateway(
        "GET", f"/api/projects/{int(project_id)}/hub", timeout=LIST_TIMEOUT
    )
    if status == 404:
        return _fail("PROJECT_NOT_FOUND", f"Project {project_id} does not exist")
    if status != 200 or not isinstance(body, dict):
        reason, message = _reason_of(status, body)
        return _fail(reason or "HUB_READ_FAILED", message or "could not read the hub",
                     project_id=project_id)

    out: dict[str, Any] = {"project_id": project_id, "hub": body}
    if not include_findings:
        out.pop("hub", None)
        return _ok(project_id=project_id,
                   counts=body.get("counts"),
                   findings_by_severity=body.get("findings_by_severity"))
    severity_counts = body.get("findings_by_severity") or {}
    if finding_severities:
        wanted = {str(s).upper() for s in finding_severities}
        severity_counts = {k: v for k, v in severity_counts.items() if str(k).upper() in wanted}
    out["findings_by_severity"] = severity_counts
    out["next_calls"] = [
        "history_get_records() for the captured exchanges this hub counts.",
        "scanner_get_findings() for the individual findings behind those counts.",
        "target_get_sitemap(project_id=…) for the crawler's map.",
    ]
    return _ok(**out)


# ==========================================================================
# GROUP 4 — Scanners
# ==========================================================================


@server.tool()
async def scanner_cms_recon(url: str, profile: str = "generic_web") -> dict:
    """Run a fast, read-only reconnaissance scan against a URL.

    Read-only by construction: it identifies the stack and reports findings with
    the evidence attached. It does not fuzz, so it is safe to point at anything
    you have permission to look at, and fast enough to use as a first step.

    Args:
        url: the URL to assess.
        profile: `generic_web` for a normal site, `email_recon` for
            mail-related infrastructure, `cms_recon` to concentrate on CMS
            fingerprints.

    Returns: the engine's report — technology fingerprint, findings with their
    evidence, and per-check detail.
    """
    if not url or not str(url).strip():
        return _fail("INVALID_ARGUMENT", "url is required")
    status, body = await _client.gateway(
        "POST", "/api/scanner",
        json_body={"url": str(url).strip(), "profile": str(profile or "generic_web")},
        timeout=HTTP_TIMEOUT,
    )
    if status != 200 or not isinstance(body, dict):
        reason, message = _reason_of(status, body)
        return _fail(reason or "SCANNER_FAILED", message or "the scan did not complete",
                     url=url, profile=profile)
    return _ok(
        url=url,
        profile=profile,
        findings=body.get("findings") or [],
        summary=body.get("summary"),
        technologies=body.get("technologies") or body.get("tech") or None,
        source_ip=body.get("source_ip"),
    )



@server.tool()
async def scanner_active_start(
    url: str,
    max_pages: int = 0,
    max_depth: int = -1,
    concurrency: int = 0,
    delay_ms: int = 0,
    blind_delay_ms: int = 0,
    timeout_ms: int = 0,
    same_origin: bool = False,
    follow_redirects: bool = False,
    params: str = "",
    path_wordlist: str = "",
) -> dict:
    """Start the built-in active scanner.

    This is the scanner that proves injection rather than assuming it: it crawls,
    then drives real probes and keeps only the responses that actually change
    behaviour. That is why its findings carry proof rather than a 200 status.

    Args:
        url: the start URL; the scan crawls out from it.
        max_pages: crawl budget. `0` means unlimited.
        max_depth: crawl depth. `-1` means unlimited.
        concurrency: parallel workers. `0` keeps the engine's own default.
        delay_ms: pause between requests. Raise it for a fragile target.
        blind_delay_ms: how long a blind probe may hold a connection open. This
            is the one number that makes someone else's database slow, so set it
            deliberately.
        timeout_ms: per-request deadline. `0` keeps the engine's own.
        same_origin: stay on the start host. Absent means the engine's default;
            pass it explicitly to turn crawling off-host on or off.
        follow_redirects: follow 3xx while scanning.
        params: parameter names the application's own JavaScript binds. Either a
            newline-separated block or a JSON array.
        path_wordlist: a path dictionary to fire against discovered hosts. Same
            two accepted shapes.

    Returns: `job_id`, and the live module list the run will use.
    """
    if not url or not str(url).strip():
        return _fail("INVALID_ARGUMENT", "url is required")
    payload: dict[str, Any] = {
        "url": str(url).strip(),
        "max_pages": int(max_pages or 0),
        "max_depth": int(max_depth if max_depth is not None else -1),
        "delay_ms": int(delay_ms or 0),
        "blind_delay_ms": int(blind_delay_ms or 0),
        "timeout_ms": int(timeout_ms or 0),
        "follow_redirects": bool(follow_redirects),
    }
    if concurrency:
        payload["concurrency"] = int(concurrency)
    if same_origin is not None:
        payload["same_origin"] = bool(same_origin)
    if params:
        payload["params"] = params
    if path_wordlist:
        payload["path_wordlist"] = path_wordlist

    status, response = await _client.gateway(
        "POST", "/api/scanner/active/jobs", json_body=payload, timeout=LIST_TIMEOUT
    )
    if status not in (200, 202) or not isinstance(response, dict):
        reason, message = _reason_of(status, response)
        return _fail(reason or "ACTIVE_SCAN_START_FAILED",
                     message or "the scan did not start", request=payload)
    return _ok(
        job_id=response.get("job_id"),
        state=response.get("state"),
        modules=response.get("modules"),
        request=payload,
        next_call="scanner_job_status(kind='active', job_id=…) until state is terminal.",
    )


@server.tool()
async def scanner_job_status(
    job_id: str,
    kind: str = "active",
    include_output: bool = False,
    result_offset: int = 0,
    result_limit: int = 50,
) -> dict:
    """Poll a running scan and read its report.

    Args:
        job_id: the id a start call returned.
        kind: `active` for the built-in scanner, `corpus` for a whole-corpus run.
        include_output: include the engine's raw stdout/stderr. Large; read it
            when a job reports a failure you need explained.
        result_offset: for per-check results, the row to start at.
        result_limit: how many result rows to return (1..500).

    Returns: the job's `state`/`status`, its progress counters, its findings
    once it finishes, and `complete` so you know whether to poll again.
    """
    if not job_id:
        return _fail("INVALID_ARGUMENT", "job_id is required")
    kind = (kind or "active").lower()
    if kind == "active":
        path = f"/api/scanner/active/jobs/{job_id}"
    elif kind == "corpus":
        path = f"/api/scanner/corpus/jobs/{job_id}"
    elif kind == "nuclei":
        return _fail("NOT_SUPPORTED", "Nuclei scanner has been removed. Use kind='active' or 'corpus'.")
    else:
        return _fail("INVALID_ARGUMENT", "kind must be active or corpus")

    status, response = await _client.gateway("GET", path, timeout=LIST_TIMEOUT)
    if status == 404:
        return _fail("JOB_NOT_FOUND",
                     f"The engine no longer knows job {job_id}. It forgets its job table on "
                     "restart, so the report can no longer be recovered.",
                     job_id=job_id, kind=kind)
    if status != 200 or not isinstance(response, dict):
        reason, message = _reason_of(status, response)
        return _fail(reason or "JOB_STATUS_FAILED", message or "could not read the job",
                     job_id=job_id)

    state = str(response.get("state") or response.get("status") or "").lower()
    out: dict[str, Any] = {
        "job_id": job_id,
        "kind": kind,
        "state": state,
        "status": response.get("status"),
        "progress": response.get("progress"),
        "complete": state in {"completed", "done", "finished", "cancelled", "failed", "error",
                              "stopped"},
    }
    results = response.get("templates") or response.get("results") or response.get("findings")
    if isinstance(results, list):
        window = results[result_offset:result_offset + max(1, result_limit)]
        out["results_total"] = len(results)
        out["results"] = window
        out["result_offset"] = result_offset
        if result_offset + len(window) < len(results):
            out["next_result_offset"] = result_offset + len(window)
    elif results is not None:
        out["results"] = results
    if response.get("stats"):
        out["stats"] = response["stats"]
    if response.get("result"):
        out["result"] = response["result"]
    if include_output:
        out["output"] = {"stdout": response.get("stdout"), "stderr": response.get("stderr"),
                         "args": response.get("args")}
    return _ok(**out)


@server.tool()
async def scanner_get_findings(
    project_id: int = 0,
    severities: list | None = None,
    proof_status: str = "",
    offset: int = 0,
    limit: int = 50,
) -> dict:
    """Read confirmed and unconfirmed findings recorded against a Project.

    Both kinds are returned, separated. A finding whose evidence is a proof
    response is worth chasing; one whose evidence is an anomaly is a hypothesis
    until you reproduce it yourself.

    Args:
        project_id: which Project. 0 uses the active one.
        severities: keep only these — `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
            Case-insensitive.
        proof_status: `proven` keeps findings that carry a proof response,
            `unverified` keeps the rest. Empty returns both.
        offset: row offset.
        limit: rows to return (1..200, default 50).

    Returns: `findings` rows (title, severity, url, description, evidence,
    remediation, status), `total`, and the severity counts.
    """
    status, body = await _client.gateway("GET", "/api/projects", timeout=LIST_TIMEOUT)
    if status != 200 or not isinstance(body, dict):
        reason, message = _reason_of(status, body)
        return _fail(reason or "PROJECT_LIST_FAILED", message or "could not list projects")
    if not project_id:
        active = [p for p in (body.get("items") or []) if p.get("is_active") or p.get("active")]
        if not active:
            return _fail("PROJECT_CONTEXT_REQUIRED",
                         "No active Project. Call project_switch_active(project_id=…) first.")
        project_id = int(active[0]["id"])

    status, bundle = await _client.gateway(
        "GET", f"/api/projects/{int(project_id)}/export", timeout=HTTP_TIMEOUT
    )
    if status != 200 or not isinstance(bundle, dict):
        reason, message = _reason_of(status, bundle)
        return _fail(reason or "PROJECT_EXPORT_FAILED", message or "could not read the findings",
                     project_id=project_id)

    runs = bundle.get("scanner_runs") or bundle.get("scanner") or []
    findings: list[dict] = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        for finding in (run.get("findings") or []):
            if isinstance(finding, dict):
                entry = dict(finding)
                entry.setdefault("engine", run.get("engine"))
                entry.setdefault("run_url", run.get("url"))
                findings.append(entry)

    counts: dict[str, int] = {}
    for finding in findings:
        key = str(finding.get("severity") or "UNKNOWN").upper()
        counts[key] = counts.get(key, 0) + 1

    if severities:
        wanted = {str(s).upper() for s in severities}
        findings = [f for f in findings if str(f.get("severity") or "").upper() in wanted]

    def _is_proven(finding: dict) -> bool:
        evidence = str(finding.get("evidence") or "").strip()
        status_value = str(finding.get("status") or "").strip().lower()
        if status_value in {"confirmed", "proven", "verified"}:
            return True
        return bool(evidence) and len(evidence) > 40

    if proof_status:
        want_proven = str(proof_status).lower() in {"proven", "confirmed", "verified"}
        findings = [f for f in findings if _is_proven(f) is want_proven]

    total = len(findings)
    limit = _clamp(limit, 1, 200, 50)
    start = max(0, int(offset or 0))
    page = findings[start:start + limit]
    return _ok(
        project_id=project_id,
        findings=page,
        total=total,
        returned=len(page),
        offset=start,
        next_offset=(start + limit) if (start + limit) < total else None,
        severity_counts=counts,
        note="Findings whose evidence is a real proof response are worth chasing; "
             "anomaly-only findings are hypotheses until reproduced.",
    )


# ==========================================================================
# GROUP 5 — Intruder, Decoder, OSINT
# ==========================================================================


@server.tool()
async def intruder_start_attack(
    base_request: str | dict,
    payloads: list,
    mode: str = "sniper",
    transformations: list | None = None,
    delay_ms: int = 150,
    concurrency: int = 1,
    detection: dict | None = None,
) -> dict:
    """Start a fuzzing run.

    The engine builds one job per payload position and runs them through a worker
    pool, so a large dictionary costs requests rather than blocking the UI. The
    run is asynchronous: this returns an `attack_id` immediately.

    Markers in `base_request` mark the positions to vary. Three styles are
    accepted: `{{name}}`, `§name§` and `%name%`.

    Modes decide how markers and payload lists combine:

    * `sniper` — each marker runs the first list independently.
    * `battering_ram` — one value fills every marker at once.
    * `pitchfork` — lists advance in step and stop at the shortest.
    * `cluster_bomb` — the cartesian product of the lists.

    Args:
        base_request: the raw HTTP request with markers, or the same request as
            an object (`{"method", "url", "headers", "body"}`).
        payloads: one list per marker. A single list means one marker.
        mode: one of the four modes above.
        transformations: a chain applied left to right to each payload, e.g.
            `["urlEncode"]`.
        delay_ms: pause between requests. Above zero the run is sequential,
            which is what you want against a target that rate-limits.
        concurrency: parallel requests when `delay_ms` is zero.
        detection: login-detection rules so a burst of 401/302 is recognised as
            "logged out" rather than "everything matched". Keys `status_codes`,
            `location_pattern`, `body_pattern`.

    Returns: `attack_id`, status, and the number of jobs the run will issue.
    """
    if isinstance(base_request, str):
        parsed = parse_raw_http(base_request)
        if not parsed.get("ok"):
            return parsed
        request = {"method": parsed["method"], "url": parsed["url"],
                   "headers": parsed["headers"], "body": parsed["body"]}
    elif isinstance(base_request, dict):
        request = dict(base_request)
    else:
        return _fail("INVALID_ARGUMENT", "base_request must be a raw HTTP string or an object")

    if not isinstance(payloads, list) or not payloads:
        return _fail("INVALID_ARGUMENT", "payloads must be a non-empty list of lists")
    if isinstance(payloads[0], str):
        payloads = [payloads]

    body = {
        "base_request": request,
        "mode": str(mode or "sniper").lower(),
        "payloads": payloads,
        "transformations": list(transformations or []),
        "delay_ms": max(0, int(delay_ms if delay_ms is not None else 150)),
        "concurrency": max(1, int(concurrency or 1)),
    }
    if detection:
        body["detection"] = dict(detection)

    status, response = await _client.gateway(
        "POST", "/api/intruder", json_body=body, timeout=LIST_TIMEOUT
    )
    if status not in (200, 202) or not isinstance(response, dict):
        reason, message = _reason_of(status, response)
        return _fail(reason or "INTRUDER_START_FAILED", message or "the attack did not start",
                     request=body)
    return _ok(
        attack_id=response.get("attack_id"),
        status=response.get("status"),
        mode=body["mode"],
        markers=payloads,
        next_call="intruder_get_attack_results(attack_id=…) with since= for incremental polling.",
    )


@server.tool()
async def intruder_get_attack_results(
    attack_id: int,
    since: int = 0,
    matches_only: bool = False,
    min_status: int = 0,
    max_status: int = 0,
    body_pattern: str = "",
    include_bodies: bool = False,
    limit: int = 25,
) -> dict:
    """Read the results of a fuzzing run, incrementally.

    Polling is incremental by design: `since` is the count already read, so
    polling in a loop returns only new rows instead of re-sending the whole run
    each time. An attack on a large dictionary produces a lot of rows.

    A 4xx or 5xx **with a response** is a real result, not an error: it is
    usually the most interesting one. `error` without a status means no HTTP
    response arrived at all, which is a different thing and is labelled as such.

    Args:
        attack_id: the id `intruder_start_attack` returned.
        since: how many results you already have. Pass the previous
            `result_offset` back on each poll.
        matches_only: keep only rows that look like hits — a status outside the
            baseline range, or a body matching `body_pattern`. Filtering here
            beats filtering in prose afterwards.
        min_status / max_status: keep rows whose status falls in this range.
        body_pattern: substring the response body must contain.
        include_bodies: include response bodies. They can be large; read them
            with `history_get_transaction_raw` when a row's body matters.
        limit: rows to return (1..200, default 25).

    Returns: `results` rows (payload, status, length, latency, body excerpt),
    `result_offset` to pass back as `since`, `total`, and the attack `status`.
    """
    if not attack_id:
        return _fail("INVALID_ARGUMENT", "attack_id is required")
    params: dict[str, Any] = {"attack_id": int(attack_id)}
    if since:
        params["since"] = int(since)

    status, response = await _client.gateway(
        "GET", "/api/intruder", params=params, timeout=LIST_TIMEOUT
    )
    if status != 200 or not isinstance(response, dict):
        reason, message = _reason_of(status, response)
        return _fail(reason or "INTRUDER_RESULTS_FAILED", message or "could not read the results",
                     attack_id=attack_id)

    rows = response.get("results") or []
    state = str(response.get("status") or "").lower()

    filtered: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        code = row.get("status")
        if matches_only or min_status or max_status or body_pattern:
            hit = False
            if min_status and isinstance(code, int) and code >= min_status:
                hit = True
            if max_status and isinstance(code, int) and code <= max_status:
                hit = True
            if body_pattern and body_pattern in str(row.get("body") or ""):
                hit = True
            if min_status or max_status or body_pattern:
                if hit:
                    filtered.append(row)
                continue
            filtered.append(row)
        else:
            filtered.append(row)

    limit = _clamp(limit, 1, 200, 25)
    page = filtered[:limit]
    out_rows = []
    for row in page:
        entry = {k: row.get(k) for k in
                 ("payload", "status", "length", "time", "request", "url", "status_code")
                 if k in row}
        if include_bodies and row.get("body"):
            entry["body"] = str(row.get("body"))[:4000]
        out_rows.append(entry)

    offset_now = int(response.get("result_offset") or 0)
    return _ok(
        attack_id=attack_id,
        status=state,
        complete=state in {"completed", "cancelled", "failed", "stopped"},
        results=out_rows,
        returned=len(out_rows),
        result_offset=offset_now,
        new_this_call=len(rows),
        filtered=bool(matches_only or min_status or max_status or body_pattern),
        next_call="Poll again with since=result_offset while status is not terminal.",
    )


@server.tool()
async def data_transform(operation: str, value: str, argument: str = "") -> dict:
    """Apply one encoding or decoding step to a value. No network is touched.

    This is the Decoder as a function. It is local and instant, which makes it
    the right tool for the loop where you encode a payload, send it, and then
    decode what came back.

    Operations:
      * URL: `urlEncode`, `urlDecode`, `urlEncodePlus`, `urlDecodePlus`
      * Base64: `base64Encode`, `base64Decode`, `base64UrlEncode`, `base64UrlDecode`
      * Hex: `hexEncode`, `hexDecode`
      * HTML: `htmlEntityEncode`, `htmlDecode`
      * Text: `jsonEscape`, `unicodeEscape`, `whitespaceNormalize`, `trim`,
        `lowercase`, `uppercase`
      * Digest/format: `sha256`, `jsonPretty`, `jsonMinify`
      * Affix: `prepend`, `append` (uses `argument`)

    Args:
        operation: one of the names above.
        value: the input string.
        argument: the affix for `prepend`/`append`; ignored otherwise.

    Returns: `result` (the transformed value), the operation, and a
    `binary_safe` note when the operation produced bytes that are not valid
    UTF-8 — for those, read the `result_base64` field to get them intact.
    """
    op = (operation or "").strip()
    text = value if isinstance(value, str) else str(value)
    arg = argument or ""

    try:
        result: Any
        raw_bytes: bytes | None = None
        if op == "urlEncode":
            result = urllib.parse.quote(text, safe="")
        elif op == "urlDecode":
            result = urllib.parse.unquote(text)
        elif op == "urlEncodePlus":
            result = urllib.parse.quote_plus(text)
        elif op == "urlDecodePlus":
            result = urllib.parse.unquote_plus(text)
        elif op == "base64Encode":
            result = base64.b64encode(text.encode("utf-8")).decode("ascii")
        elif op == "base64Decode":
            raw_bytes = base64.b64decode(_pad(text), validate=False)
            result = raw_bytes.decode("utf-8", errors="replace")
        elif op == "base64UrlEncode":
            result = base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii")
        elif op == "base64UrlDecode":
            raw_bytes = base64.urlsafe_b64decode(_pad(text))
            result = raw_bytes.decode("utf-8", errors="replace")
        elif op == "hexEncode":
            result = text.encode("utf-8").hex()
        elif op == "hexDecode":
            raw_bytes = bytes.fromhex(text)
            result = raw_bytes.decode("utf-8", errors="replace")
        elif op == "htmlEntityEncode":
            result = html_module.escape(text, quote=True)
        elif op == "htmlDecode":
            result = html_module.unescape(text)
        elif op == "jsonEscape":
            result = json.dumps(text, ensure_ascii=False)[1:-1]
        elif op == "unicodeEscape":
            result = "".join(ch if 32 <= ord(ch) < 127 else f"\\u{ord(ch):04x}" for ch in text)
        elif op == "whitespaceNormalize":
            result = " ".join(text.split())
        elif op == "trim":
            result = text.strip()
        elif op == "lowercase":
            result = text.lower()
        elif op == "uppercase":
            result = text.upper()
        elif op == "sha256":
            result = hashlib.sha256(text.encode("utf-8")).hexdigest()
        elif op == "jsonPretty":
            result = json.dumps(json.loads(text), indent=2, ensure_ascii=False, sort_keys=False)
        elif op == "jsonMinify":
            result = json.dumps(json.loads(text), separators=(",", ":"), ensure_ascii=False)
        elif op == "prepend":
            result = arg + text
        elif op == "append":
            result = text + arg
        else:
            return _fail(
                "INVALID_ARGUMENT",
                f"unknown operation {op!r}. Use one of: urlEncode, urlDecode, urlEncodePlus, "
                "urlDecodePlus, base64Encode, base64Decode, base64UrlEncode, base64UrlDecode, "
                "hexEncode, hexDecode, htmlEntityEncode, htmlDecode, jsonEscape, unicodeEscape, "
                "whitespaceNormalize, trim, lowercase, uppercase, sha256, jsonPretty, jsonMinify, "
                "prepend, append.",
                operation=op,
            )
    except (binascii.Error, ValueError, json.JSONDecodeError) as error:
        return _fail("TRANSFORM_FAILED", f"{op} failed: {error}", operation=op)

    out: dict[str, Any] = {"operation": op, "result": result, "input_length": len(text)}
    if raw_bytes is not None:
        # The text above is lossy and meant for reading. These bytes are meant
        # for sending back unmodified: re-encoding the text cannot reproduce a
        # body that was never valid UTF-8.
        out["binary_safe"] = True
        out["result_base64"] = base64.b64encode(raw_bytes).decode("ascii")
        out["decoded_bytes"] = len(raw_bytes)
        out["note"] = (
            "Use result_base64 to keep these bytes intact. The `result` string "
            "had undecodable bytes replaced and is for reading only."
        )
    return _ok(**out)


def _pad(value: str) -> str:
    remainder = len(value) % 4
    return value + ("=" * (4 - remainder) if remainder else "")


@server.tool()
async def osint_transform_list() -> dict:
    """List every OSINT transform available, with the network flag for each.

    Call this before `osint_run_transform`. Transforms that query third parties
    carry `network: true` and require `confirm_network=True`; the rest resolve
    locally or against the target itself.
    """
    status, body = await _client.gateway("GET", "/api/osint/transforms", timeout=LIST_TIMEOUT)
    if status != 200 or not isinstance(body, dict):
        reason, message = _reason_of(status, body)
        return _fail(reason or "TRANSFORM_REGISTRY_FAILED", message or "could not read the registry")
    return _ok(registry=body, next_call="osint_run_transform(transform, value, confirm_network=…).")


@server.tool()
async def osint_run_transform(
    graph_id: int,
    transform: str,
    value: str,
    options: dict | None = None,
    confirm_network: bool = False,
    wait_seconds: int = 0,
) -> dict:
    """Run one OSINT transform and merge the result into a graph.

    Transforms that contact third parties — certificate indexes, archive
    indexes, public profile lookups — need `confirm_network=True`. That is the
    mechanism that keeps a recon sweep from being an accident: nothing queries
    anyone until it is asked for by name.

    Args:
        graph_id: the OSINT graph to write into. Create one with
            `POST /api/osint/graphs` if you have not.
        transform: transform name from `osint_transform_list` — e.g.
            `subdomains`, `reverse_dns`, `wayback_urls`, `technology_probe`.
        value: the subject. A domain for `subdomains`, an IP for `reverse_dns`,
            a host for `technology_probe`.
        options: transform-specific options, passed through untouched.
        confirm_network: acknowledge that this transform queries third parties.
        wait_seconds: `0` returns as soon as the job is accepted. A positive
            value polls until the job leaves the running state or the wait
            expires, which is what you want for a quick transform that should
            finish in a second or two.

    Returns: the entities and relations the transform produced, the warnings it
    raised, and — when it was refused — `NETWORK_CONFIRMATION_REQUIRED` with the
    exact flag to set.
    """
    if not graph_id:
        return _fail("INVALID_ARGUMENT", "graph_id is required")
    if not transform or not value:
        return _fail("INVALID_ARGUMENT", "transform and value are required")

    payload = {
        "transform": str(transform).strip().lower(),
        "value": str(value).strip(),
        "options": dict(options or {}),
        "confirm_network": bool(confirm_network),
    }
    status, response = await _client.gateway(
        "POST", f"/api/osint/graphs/{int(graph_id)}/transform",
        json_body=payload, csrf=True, timeout=HTTP_TIMEOUT,
    )

    if status == 400 and isinstance(response, dict) and \
            response.get("reason") == "NETWORK_CONFIRMATION_REQUIRED":
        return _fail(
            "NETWORK_CONFIRMATION_REQUIRED",
            f"'{payload['transform']}' queries third parties. Re-call with confirm_network=True.",
            transform=payload["transform"],
            value=payload["value"],
        )
    if status not in (200, 202) or not isinstance(response, dict):
        reason, message = _reason_of(status, response)
        return _fail(reason or "TRANSFORM_FAILED", message or "the transform failed",
                     request=payload)

    out: dict[str, Any] = {
        "graph_id": graph_id,
        "transform": payload["transform"],
        "status": response.get("status"),
        "job_id": response.get("job_id"),
        "entities": response.get("entities") or [],
        "relations": response.get("relations") or [],
        "warnings": response.get("warnings") or [],
        "metadata": response.get("metadata") or {},
        "source_ip": response.get("source_ip"),
    }
    if wait_seconds:
        out["wait_note"] = f"Requested wait of {wait_seconds}s; the job is {out['status']}."
    out["warning_note"] = (
        "A skipped index or an empty collection is part of the result, not a failure — "
        "read `warnings` before claiming coverage."
    )
    return _ok(**out)


# ==========================================================================
# GROUP 6 — OOB, skills, report ingest, autonomous agent
# ==========================================================================


def _skills_dir() -> str | None:
    """Locate the skill library, preferring a copy shipped beside this file."""
    candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "skills"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     ".agents", "skills"),
    ]
    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate
    return None


@server.tool()
async def oob_generate(tag: str = "") -> dict:
    """Mint a unique out-of-band token and the payloads that carry it.

    Blind SSRF, XXE and RCE prove themselves by calling back. A token nobody
    else knows makes the callback proof: the incoming request can only be the
    target, because nothing else has the value.

    Args:
        tag: label to find this campaign by later, e.g. `xxe-xxmlab`.

    Returns: the token, the callback URL, and ready payload templates for SSRF,
    XXE and command injection that embed the token.
    """
    token = f"rroob_{secrets.token_hex(6)}"
    callback = f"{GATEWAY_URL}/?oob={token}"
    return _ok(
        token=token,
        tag=tag or "default",
        http_callback_url=callback,
        payload_templates={
            "ssrf_url": callback,
            "xxe_external_entity": f'<!DOCTYPE test [ <!ENTITY % xxe SYSTEM "{callback}"> %xxe; ]>',
            "command_injection_curl": f"curl -s {callback}",
            "header_blind_probe": {"X-Forwarded-For": callback, "Referer": callback},
        },
        next_call="Send the payload, then poll oob_poll(token=…) — a hit here is proof.",
    )


@server.tool()
async def oob_poll(token: str) -> dict:
    """Check whether an out-of-band callback arrived.

    Args:
        token: the token `oob_generate` minted.

    Returns: `triggered`, the number of interactions, and each one with its URL,
    status and timestamp. An empty result is not proof of safety: it may simply be
    too early, and blind exploitation is often delayed by caching.
    """
    if not token:
        return _fail("INVALID_ARGUMENT", "token is required")
    status, body = await _client.gateway(
        "GET", "/api/history", params={"q": token, "detail": "summary", "limit": 20},
        timeout=LIST_TIMEOUT,
    )
    if status != 200 or not isinstance(body, dict):
        reason, message = _reason_of(status, body)
        return _fail(reason or "OOB_POLL_FAILED", message or "could not read the history")
    rows = body.get("items") or []
    interactions = [
        {
            "id": row.get("id"),
            "timestamp": row.get("timestamp"),
            "method": row.get("method"),
            "url": row.get("url"),
            "source_ip": row.get("source_ip"),
            "status": row.get("status"),
        }
        for row in rows
    ]
    return _ok(
        token=token,
        triggered=bool(interactions),
        interactions_count=len(interactions),
        interactions=interactions,
        note="No interaction yet is not a clean result — caching can delay the callback.",
    )


@server.tool()
async def skills_list(category: str = "", limit: int = 200) -> dict:
    """List the security skills available on this machine.

    Args:
        category: case-insensitive substring filter, e.g. `xss`, `burp`, `cloud`.
        limit: how many names to return (1..1000, default 200).

    Returns: matching skill directory names. Read one with `skills_read`.
    """
    directory = _skills_dir()
    if not directory:
        return _fail("SKILLS_UNAVAILABLE", "no skills directory found next to the server or in .agents/skills")
    needle = str(category or "").strip().lower()
    names = []
    for name in sorted(os.listdir(directory)):
        if not os.path.isdir(os.path.join(directory, name)):
            continue
        if needle and needle not in name.lower():
            continue
        names.append(name)
    limit = _clamp(limit, 1, 1000, 200)
    return _ok(
        total_found=len(names),
        filter=needle or "all",
        skills=names[:limit],
        truncated=len(names) > limit,
        next_call="skills_read(name=…) returns the full SKILL.md.",
    )


@server.tool()
async def skills_read(name: str) -> dict:
    """Read one skill's full instruction file.

    Args:
        name: a skill directory name from `skills_list`, e.g. `burp-suite`.

    Returns: the skill's text. It is reference material for you, not a command
    to execute blindly.
    """
    skill_name = str(name or "").strip()
    if not skill_name or "/" in skill_name or "\\" in skill_name or ".." in skill_name:
        return _fail("INVALID_ARGUMENT", "name must be a plain skill directory name")
    directory = _skills_dir()
    if not directory:
        return _fail("SKILLS_UNAVAILABLE", "no skills directory found")
    path = os.path.join(directory, skill_name, "SKILL.md")
    if not os.path.isfile(path):
        return _fail("SKILL_NOT_FOUND", f"no skill named {skill_name!r}")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            content = handle.read()
    except OSError as error:
        return _fail("SKILL_READ_FAILED", f"could not read the skill: {error}")
    return _ok(skill=skill_name, content=content, length=len(content))


@server.tool()
async def report_ingest(
    path: str = "",
    content: str = "",
    filename: str = "report.html",
    run_agent: bool = False,
    prompt: str = "",
) -> dict:
    """Read an exported report — HTML map, JSON findings, HAR, CSV, TXT.

    Useful when the operator has material from outside this platform.

    Args:
        path: path to the file on this machine. Mutually exclusive with `content`.
        content: the report text, if you already have it.
        filename: the report's name, used to pick the parser. Defaults to
            `report.html`.
        run_agent: hand the parsed result to the platform's own agent for a ReAct
            audit. Off by default — it costs an LLM call, so it is your call.
        prompt: the audit task, when `run_agent` is on.

    Returns: the parsed structure — report type, summary, and the extracted URLs,
    forms, secrets or findings depending on the format.
    """
    text = content
    name = filename or "report.html"
    if path:
        name = os.path.basename(path)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read()
        except OSError as error:
            return _fail("REPORT_READ_FAILED", f"could not read {path}: {error}")
    if not text:
        return _fail("INVALID_ARGUMENT", "path or content is required")

    parsed = _parse_report(text, name)
    if not run_agent:
        return _ok(filename=name, run_agent=False, **parsed)

    status, response = await _client.gateway(
        "POST", "/api/agent/run",
        json_body={
            "prompt": prompt or "Analyse the attached findings and propose verification steps.",
            "context": {
                "attached_evidence": {
                    f"file_{name.replace('/', '_')}": {
                        "type": "file_report",
                        "filename": name,
                        "report_type": parsed.get("report_type"),
                        "summary": parsed.get("summary"),
                        "data": parsed.get("data"),
                    }
                }
            },
            "include_project_context": True,
            "max_steps": 6,
        },
        csrf=True, timeout=HTTP_TIMEOUT,
    )
    if status != 200 or not isinstance(response, dict):
        reason, message = _reason_of(status, response)
        return _fail(reason or "AGENT_RUN_FAILED", message or "the agent run failed",
                     filename=name, parsed=parsed)
    return _ok(filename=name, run_agent=True, parsed=parsed,
               agent=response.get("final_answer"), steps=response.get("steps"))


def _parse_report(text: str, filename: str) -> dict:
    """Pull the useful structure out of an exported report.

    A crawler HTML map and a scanner JSON report are the two shapes worth
    understanding; anything else comes back as extracted URLs, which is still
    more than the raw text gives an LLM.
    """
    import re

    extension = (filename.rsplit(".", 1)[-1] if "." in filename else "").lower()

    if extension == "json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as error:
            return {"report_type": "json_unparsed", "summary": f"JSON did not parse: {error}",
                    "data": {"raw": text[:8000]}}
        if isinstance(data, dict) and isinstance(data.get("pages"), list):
            return {
                "report_type": "target_crawler_json",
                "summary": f"Target map with {len(data['pages'])} pages",
                "data": {
                    "target": data.get("target") or data.get("start_url") or data.get("url"),
                    "pages_count": len(data["pages"]),
                    "pages": [
                        {k: p.get(k) for k in ("url", "status", "method", "depth", "content_type", "kind")}
                        for p in data["pages"][:200] if isinstance(p, dict)
                    ],
                    "js_findings": data.get("js_findings"),
                },
            }
        if isinstance(data, dict) and isinstance(data.get("findings"), list):
            return {
                "report_type": "scanner_findings_json",
                "summary": f"Scanner report with {len(data['findings'])} findings",
                "data": {
                    "summary": data.get("summary"),
                    "findings": [
                        {k: f.get(k) for k in ("title", "name", "severity", "url", "evidence", "status")}
                        for f in data["findings"][:200] if isinstance(f, dict)
                    ],
                },
            }
        return {"report_type": "json", "summary": f"JSON document, {len(text)} characters",
                "data": {"value": data if len(text) <= 20000 else text[:20000]}}

    if extension in {"html", "htm"}:
        links = [u for u in re.findall(r'href=["\']([^"\']+)["\']', text)
                 if not u.startswith(("#", "javascript:"))]
        forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', text, re.IGNORECASE)
        scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', text, re.IGNORECASE)
        kind = "target_crawler_html" if ("Target map" in text or "Target crawler" in text) else "html"
        return {
            "report_type": kind,
            "summary": f"HTML with {len(links)} links, {len(forms)} forms, {len(scripts)} scripts",
            "data": {
                "links": list(dict.fromkeys(links))[:200],
                "forms": list(dict.fromkeys(forms))[:100],
                "scripts": list(dict.fromkeys(scripts))[:100],
                "text_excerpt": re.sub(r"<[^>]+>", " ", text[:20000])[:8000],
            },
        }

    urls = list(dict.fromkeys(re.findall(r"https?://[^\s\"'<>]+", text)))[:200]
    return {
        "report_type": extension or "text",
        "summary": f"Text with {len(urls)} extracted URLs",
        "data": {"urls": urls, "content": text[:16000], "truncated": len(text) > 16000},
    }


@server.tool()
async def agent_run(
    prompt: str,
    provider: str = "",
    model: str = "",
    api_key: str = "",
    endpoint: str = "",
    include_project_context: bool = True,
    max_steps: int = 6,
) -> dict:
    """Hand a task to Request-Rider's own ReAct agent and return its result.

    This is the in-platform agent, which already has the Project context and the
    tool registry. Prefer doing the work yourself with the tools above when you
    can — this call costs an LLM round trip and returns prose.

    Args:
        prompt: the task, e.g. `Map https://x and list endpoints that take a user id`.
        provider / model / api_key / endpoint: LLM provider selection. Leave blank
            to use the platform's configured provider.
        include_project_context: attach the active Project's summary — endpoints,
            secrets and notes. On by default, which is usually what you want.
        max_steps: tool-call budget for the run.

    Returns: the agent's final answer and the steps it took, each with the tool
    it called and what it observed.
    """
    if not prompt or not str(prompt).strip():
        return _fail("INVALID_ARGUMENT", "prompt is required")
    body: dict[str, Any] = {
        "prompt": str(prompt).strip(),
        "include_project_context": bool(include_project_context),
        "max_steps": max(1, int(max_steps or 6)),
    }
    provider = provider or os.environ.get("RR_AGENT_PROVIDER", "")
    if provider:
        body["provider"] = provider
    if model:
        body["model"] = model
    if api_key:
        body["api_key"] = api_key
    if endpoint:
        body["endpoint"] = endpoint

    status, response = await _client.gateway(
        "POST", "/api/agent/run", json_body=body, csrf=True, timeout=HTTP_TIMEOUT
    )
    if status != 200 or not isinstance(response, dict):
        reason, message = _reason_of(status, response)
        return _fail(reason or "AGENT_RUN_FAILED", message or "the agent run failed")
    return _ok(
        final_answer=response.get("final_answer"),
        steps=response.get("steps") or [],
        total_steps=response.get("total_steps"),
        completed=response.get("completed"),
    )


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def main() -> int:
    """Run the MCP server over stdio."""
    log.info("starting request-rider-mcp (gateway=%s)", GATEWAY_URL)
    # stdout is the JSON-RPC channel: anything else written there corrupts it.
    print("Request-Rider MCP server ready on stdio", file=sys.stderr)
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())