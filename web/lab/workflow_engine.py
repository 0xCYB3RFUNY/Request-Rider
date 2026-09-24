"""Durable workflow graph validation and local execution primitives.

The editor deliberately uses a small, portable graph format instead of a
frontend-only runtime.  Workflows are persisted by Django, while this module
provides the same core concepts used by larger workflow platforms: typed
nodes, directed connections, trigger roots, active executions, schedules and
webhook runs.

The project is a local QA application, so the default runtime is an in-process
worker pool.  It is intentionally not presented as a distributed queue: a
single Django process owns active runs, and SQLite stores their durable state.
"""

from __future__ import annotations

import base64
import binascii
import difflib
import hashlib
import html
import json
import logging
import queue
import re
import sys
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import quote, unquote

from django.db import OperationalError, close_old_connections, transaction
from django.utils import timezone as django_timezone

from .models import Workflow, WorkflowRun
from .runtime_limits import (
    WORKFLOW_MAX_CONNECTIONS,
    WORKFLOW_MAX_DELAY_SECONDS,
    WORKFLOW_MAX_EVENT_LOG,
    WORKFLOW_MAX_NODES,
    WORKFLOW_MAX_NODE_ID_LENGTH,
    WORKFLOW_MAX_RESULT_BYTES,
    WORKFLOW_EVENT_QUEUE_SIZE,
    WORKFLOW_EVENT_MESSAGE_LENGTH,
)

logger = logging.getLogger(__name__)

MAX_WORKFLOW_NODES = WORKFLOW_MAX_NODES
MAX_WORKFLOW_CONNECTIONS = WORKFLOW_MAX_CONNECTIONS
MAX_EVENT_LOG = WORKFLOW_MAX_EVENT_LOG
MAX_RESULT_BYTES = WORKFLOW_MAX_RESULT_BYTES

NODE_TYPES: dict[str, dict[str, Any]] = {
    "manual_trigger": {
        "label": "Manual trigger",
        "inputs": [],
        "outputs": ["main"],
        "defaults": {},
        "trigger": True,
    },
    "schedule_trigger": {
        "label": "Schedule trigger",
        "inputs": [],
        "outputs": ["main"],
        "defaults": {"cron": "*/5 * * * *"},
        "trigger": True,
    },
    "webhook_trigger": {
        "label": "Webhook trigger",
        "inputs": [],
        "outputs": ["main"],
        "defaults": {"method": "POST"},
        "trigger": True,
    },
    "repeater": {
        "label": "Repeater",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"method": "GET", "url": "", "headers": {}, "body": ""},
    },
    "repeater_burst": {
        "label": "Repeater Burst",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"method": "GET", "url": "", "headers": {}, "iterations": 3, "concurrency": 2, "delay_ms": 0, "timeout_ms": 5000},
        "confirmation": True,
    },
    "last_byte_sync": {
        "label": "Last-Byte Sync",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"method": "POST", "url": "", "headers": {}, "body": "", "iterations": 1, "concurrency": 1, "delay_ms": 0, "hold_ms": 50, "timeout_ms": 5000},
        "confirmation": True,
    },
    "target": {
        "label": "Target map",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"url": "", "engine": "static", "max_pages": 100, "max_depth": 3, "delay_ms": 0, "same_origin": False},
    },
    "target_browser": {
        "label": "Target browser",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"url": "", "browser": "firefox", "mode": "navigation", "max_pages": 100, "max_depth": 3, "delay_ms": 0, "same_origin": False, "capture_context_id": "", "actions": [], "allow_state_changing_actions": False},
    },
    "oast_listener": {
        "label": "OAST Listener",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"server_url": "http://127.0.0.1:8766", "listener_id": "", "poll_interval_sec": 3, "timeout_sec": 30, "capture_protocols": ["http"]},
        "confirmation": True,
    },
    "oast_collect": {
        "label": "OAST Collect",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"poll_interval_sec": 1, "timeout_sec": 30},
    },
    "osint": {
        "label": "OSINT",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"url": "", "waf_check": False},
    },
    "scanner": {
        "label": "Scanner",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"url": "", "profile": "generic_web"},
    },
    "intruder": {
        "label": "Intruder",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"base_request": {}, "mode": "sniper", "payloads": [], "transformations": [], "delay_ms": 150, "concurrency": 1},
        "confirmation": True,
    },
    "decoder": {
        "label": "Decoder",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"operation": "urlEncode"},
    },
    "comparer": {
        "label": "Comparer",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"mode": "words"},
    },
    "condition": {
        "label": "Condition",
        "inputs": ["main"],
        "outputs": ["true", "false"],
        "defaults": {"field": "status", "operator": "equals", "value": ""},
    },
    "merge": {
        "label": "Merge",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {},
    },
    "set": {
        "label": "Set values",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"values": {}},
    },
    "template": {
        "label": "Template",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"text": "{{input}}"},
    },
    "delay": {
        "label": "Delay",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"seconds": 1},
    },
    "ai_agent": {
        "label": "AI Agent",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"prompt": "Analyze the attached QA evidence.", "provider": "ollama"},
    },
    "output": {
        "label": "Output",
        "inputs": ["main"],
        "outputs": [],
        "defaults": {"label": "Result", "format": "json"},
    },
}

NODE_FIELDS: dict[str, list[dict[str, Any]]] = {
    "manual_trigger": [],
    "schedule_trigger": [
        {"name": "cron", "kind": "text", "label": "Cron expression", "placeholder": "*/5 * * * *"},
    ],
    "webhook_trigger": [
        {"name": "method", "kind": "select", "label": "HTTP method", "options": ["POST", "GET", "PUT", "PATCH", "DELETE", "ANY"]},
    ],
    "repeater": [
        {"name": "method", "kind": "select", "label": "Method", "options": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]},
        {"name": "url", "kind": "text", "label": "URL", "placeholder": "https://example.test/path"},
        {"name": "headers", "kind": "json", "label": "Headers"},
        {"name": "body", "kind": "textarea", "label": "Body"},
        {"name": "urls", "kind": "json", "label": "Requests list / loop"},
        {"name": "delay_ms", "kind": "number", "label": "Delay between requests (ms)"},
    ],
    "repeater_burst": [
        {"name": "method", "kind": "text", "label": "Method", "placeholder": "GET"},
        {"name": "url", "kind": "text", "label": "URL", "placeholder": "https://example.test/path"},
        {"name": "headers", "kind": "json", "label": "Headers"},
        {"name": "iterations", "kind": "number", "label": "Iterations"},
        {"name": "concurrency", "kind": "number", "label": "Concurrency"},
        {"name": "delay_ms", "kind": "number", "label": "Delay between waves (ms)"},
        {"name": "timeout_ms", "kind": "number", "label": "Request timeout (ms)"},
    ],
    "last_byte_sync": [
        {"name": "method", "kind": "text", "label": "Method", "placeholder": "POST"},
        {"name": "url", "kind": "text", "label": "Target URL", "placeholder": "http://127.0.0.1:fixture/sync"},
        {"name": "headers", "kind": "json", "label": "Headers"},
        {"name": "body", "kind": "textarea", "label": "Request body"},
        {"name": "iterations", "kind": "number", "label": "Iterations"},
        {"name": "concurrency", "kind": "number", "label": "Concurrency"},
        {"name": "delay_ms", "kind": "number", "label": "Delay between waves (ms)"},
        {"name": "hold_ms", "kind": "number", "label": "Final-byte hold (ms)"},
        {"name": "timeout_ms", "kind": "number", "label": "Request timeout (ms)"},
    ],
    "target": [
        {"name": "url", "kind": "text", "label": "Start URL", "placeholder": "https://example.test/"},
        {"name": "engine", "kind": "select", "label": "Crawler", "options": ["static", "browser"]},
        {"name": "max_pages", "kind": "number", "label": "Max pages"},
        {"name": "max_depth", "kind": "number", "label": "Max depth"},
        {"name": "delay_ms", "kind": "number", "label": "Delay (ms)"},
        {"name": "same_origin", "kind": "boolean", "label": "Same origin only"},
    ],
    "target_browser": [
        {"name": "url", "kind": "text", "label": "Start URL", "placeholder": "https://example.test/"},
        {"name": "browser", "kind": "select", "label": "Browser", "options": ["firefox", "chromium", "chrome", "edge", "webkit"]},
        {"name": "mode", "kind": "select", "label": "Browser mode", "options": ["navigation", "form"]},
        {"name": "max_pages", "kind": "number", "label": "Max pages"},
        {"name": "max_depth", "kind": "number", "label": "Max depth"},
        {"name": "delay_ms", "kind": "number", "label": "Delay (ms)"},
        {"name": "same_origin", "kind": "boolean", "label": "Same origin only"},
        {"name": "actions", "kind": "json", "label": "Click / Fill actions"},
        {"name": "allow_state_changing_actions", "kind": "boolean", "label": "Allow state-changing actions"},
    ],
    "oast_listener": [
        {"name": "server_url", "kind": "text", "label": "OAST provider URL", "placeholder": "http://127.0.0.1:8766"},
        {"name": "listener_id", "kind": "text", "label": "Correlation/listener ID"},
        {"name": "poll_interval_sec", "kind": "number", "label": "Poll interval (sec)"},
        {"name": "timeout_sec", "kind": "number", "label": "Timeout (sec)"},
        {"name": "capture_protocols", "kind": "json", "label": "Capture protocols"},
    ],
    "oast_collect": [
        {"name": "poll_interval_sec", "kind": "number", "label": "Poll interval (sec)"},
        {"name": "timeout_sec", "kind": "number", "label": "Wait timeout (sec)"},
    ],
    "osint": [
        {"name": "url", "kind": "text", "label": "Target URL", "placeholder": "https://example.test/"},
        {"name": "waf_check", "kind": "boolean", "label": "Run benign WAF canary"},
    ],
    "scanner": [
        {"name": "url", "kind": "text", "label": "Target URL", "placeholder": "https://example.test/"},
        {"name": "profile", "kind": "select", "label": "Profile", "options": ["generic_web", "cms", "api", "security_headers"]},
    ],
    "intruder": [
        {"name": "base_request", "kind": "json", "label": "Raw request definition"},
        {"name": "mode", "kind": "select", "label": "Attack mode", "options": ["sniper", "batteringRam", "pitchfork", "clusterBomb"]},
        {"name": "payloads", "kind": "json", "label": "Dictionaries / payloads"},
        {"name": "transformations", "kind": "json", "label": "Transformations"},
        {"name": "delay_ms", "kind": "number", "label": "Delay (ms)"},
        {"name": "concurrency", "kind": "number", "label": "Concurrency"},
    ],
    "decoder": [
        {"name": "operation", "kind": "select", "label": "Operation", "options": ["urlEncode", "urlDecode", "base64Encode", "base64Decode", "base64UrlEncode", "base64UrlDecode", "htmlEncode", "htmlDecode", "hexEncode", "hexDecode", "byteEncode", "byteDecode", "jsonPretty", "jsonMinify", "sha256", "jwtDecode"]},
        {"name": "input", "kind": "textarea", "label": "Input value"},
    ],
    "comparer": [
        {"name": "mode", "kind": "select", "label": "Comparison", "options": ["words", "bytes"]},
        {"name": "left", "kind": "textarea", "label": "Left value"},
        {"name": "right", "kind": "textarea", "label": "Right value"},
    ],
    "condition": [
        {"name": "field", "kind": "text", "label": "Field / JSON path", "placeholder": "response.status"},
        {"name": "operator", "kind": "select", "label": "Operator", "options": ["equals", "not_equals", "contains", "not_contains", "exists", "not_exists", "greater_than", "less_than", "regex", "truthy"]},
        {"name": "value", "kind": "text", "label": "Expected value"},
    ],
    "merge": [],
    "set": [{"name": "values", "kind": "json", "label": "Values"}],
    "template": [{"name": "text", "kind": "textarea", "label": "Template", "placeholder": "{{input}}"}],
    "delay": [{"name": "seconds", "kind": "number", "label": "Seconds"}],
    "ai_agent": [
        {"name": "prompt", "kind": "textarea", "label": "Prompt"},
        {"name": "provider", "kind": "select", "label": "Provider", "options": ["ollama", "openai", "anthropic", "openrouter", "gemini", "groq", "mistral", "openai_compatible"]},
        {"name": "endpoint", "kind": "text", "label": "Endpoint"},
        {"name": "model", "kind": "text", "label": "Model"},
    ],
    "output": [
        {"name": "label", "kind": "text", "label": "Output label"},
        {"name": "format", "kind": "select", "label": "Format", "options": ["json", "markdown", "html"]},
    ],
}

ACTIVE_NODE_TYPES = {
    "intruder",
    "target_browser",
    "oast_listener",
    "repeater_burst",
    "last_byte_sync",
}

# Repeater Burst and Last-Byte Sync are intentionally manual operator actions.
# A graph that mixes either with an automatic trigger would otherwise turn a
# one-time confirmation into recurring unattended traffic.
MANUAL_ONLY_NODE_TYPES = {"repeater_burst", "last_byte_sync"}

_TERMINAL_STATUSES = {"completed", "failed", "cancelled", "interrupted"}
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.:-]+$")
_SECRET_KEYS = {"api_key", "apikey", "password", "access_token", "refresh_token", "auth_token"}


def _update_run(run_id: int, **fields: Any) -> int:
    """Update a run while tolerating short SQLite reader/write races."""

    for attempt in range(8):
        try:
            fields.setdefault("updated_at", django_timezone.now())
            return WorkflowRun.objects.filter(pk=run_id).update(**fields)
        except OperationalError as error:
            if "locked" not in str(error).lower() or attempt == 7:
                raise
            close_old_connections()
            time.sleep(0.02 * (attempt + 1))
    return 0


class WorkflowValidationError(ValueError):
    """Raised when a graph cannot be persisted or executed safely."""


class WorkflowCancelled(Exception):
    """Internal signal used to stop a run at the next safe boundary."""


class RunControl:
    """In-process control flags and cleanup hooks for a persisted run."""

    def __init__(self) -> None:
        self.cancel = threading.Event()
        self.pause = threading.Event()
        self._cleanup_lock = threading.Lock()
        self._cleanup_callbacks: list[Callable[[], None]] = []

    def add_cleanup(self, callback: Callable[[], None]) -> None:
        with self._cleanup_lock:
            self._cleanup_callbacks.append(callback)

    def run_cleanup(self) -> None:
        with self._cleanup_lock:
            callbacks = list(self._cleanup_callbacks)
            self._cleanup_callbacks.clear()
        for callback in callbacks:
            try:
                callback()
            except Exception:  # noqa: BLE001 - cleanup must not mask run result
                logger.warning("workflow cleanup callback failed", exc_info=True)


def node_catalog() -> list[dict[str, Any]]:
    """Return JSON-safe node metadata for the editor palette."""

    return [
        {
            "type": node_type,
            **definition,
            "fields": NODE_FIELDS.get(node_type, []),
        }
        for node_type, definition in NODE_TYPES.items()
    ]


def workflow_requires_confirmation(nodes: list[dict[str, Any]]) -> bool:
    """Return whether a graph contains an action that needs operator approval."""

    return any(
        node.get("type") in ACTIVE_NODE_TYPES
        or (
            node.get("type") == "target"
            and isinstance(node.get("params"), dict)
            and (
                str(node["params"].get("engine", "")).lower() == "browser"
                or bool(node["params"].get("actions"))
            )
        )
        or (
            isinstance(node.get("params"), dict)
            and bool(node["params"].get("__requires_confirmation"))
        )
        for node in nodes
        if isinstance(node, dict)
    )


def _clean_params(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _clean_params(child)
            for key, child in value.items()
            if str(key).lower() not in _SECRET_KEYS
        }
    if isinstance(value, list):
        return [_clean_params(child) for child in value]
    return value


def _position(value: Any) -> dict[str, float]:
    if not isinstance(value, dict):
        return {"x": 80.0, "y": 80.0}
    try:
        return {
            "x": max(0.0, min(4000.0, float(value.get("x", 80)))),
            "y": max(0.0, min(4000.0, float(value.get("y", 80)))),
        }
    except (TypeError, ValueError):
        return {"x": 80.0, "y": 80.0}


def _canonical_node_type(value: Any) -> str:
    raw = str(value or "").strip()
    lowered = raw.lower().replace(".", "")
    aliases = {
        "manualtrigger": "manual_trigger",
        "manualtrigger_node": "manual_trigger",
        "scheduletrigger": "schedule_trigger",
        "webhooktrigger": "webhook_trigger",
        "rider-nodes-basemanualtrigger": "manual_trigger",
        "rider-nodes-basescheduletrigger": "schedule_trigger",
        "rider-nodes-basewebhooktrigger": "webhook_trigger",
        "rider-nodes-baserepeater": "repeater",
        "rider-nodes-baserepeaterburst": "repeater_burst",
        "rider-nodes-baselastbytesync": "last_byte_sync",
        "rider-nodes-basetarget": "target",
        "rider-nodes-baseosint": "osint",
        "rider-nodes-basescanner": "scanner",
        "rider-nodes-baseintruder": "intruder",
        "rider-nodes-basedecoder": "decoder",
        "rider-nodes-basecomparer": "comparer",
        "rider-nodes-basecondition": "condition",
        "rider-nodes-basemerge": "merge",
        "rider-nodes-baseset": "set",
        "rider-nodes-basetemplate": "template",
        "rider-nodes-basedelay": "delay",
        "rider-nodes-baseaiagent": "ai_agent",
        "rider-nodes-baseoutput": "output",
    }
    if lowered in aliases:
        return aliases[lowered]
    if raw in NODE_TYPES:
        return raw
    # n8n-style names are often written with a version suffix.
    if raw.startswith("rider-nodes-base."):
        candidate = raw.split(".")[-1]
        candidate = re.sub(r"[^A-Za-z]+", "_", candidate).strip("_").lower()
        if candidate in NODE_TYPES:
            return candidate
    return raw


def _canonical_connections(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if not isinstance(value, dict):
        return []
    flattened: list[dict[str, Any]] = []
    for source, groups in value.items():
        if not isinstance(groups, dict):
            continue
        for source_handle, outputs in groups.items():
            output_groups = outputs if isinstance(outputs, list) else [outputs]
            for output_group in output_groups:
                destinations = output_group if isinstance(output_group, list) else [output_group]
                for destination in destinations:
                    if not isinstance(destination, dict) or not destination.get("node"):
                        continue
                    flattened.append({
                        "source": source,
                        "source_handle": "true" if str(source_handle).lower() == "true" else "false" if str(source_handle).lower() == "false" else "main",
                        "target": destination.get("node"),
                        "target_handle": "main",
                    })
    return flattened


def validate_workflow(
    nodes: Any,
    connections: Any,
    *,
    require_trigger: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Validate and normalize the portable graph representation.

    Empty graphs are valid drafts.  A run additionally requests
    ``require_trigger=True`` so an incomplete canvas cannot be executed.
    """

    if not isinstance(nodes, list) or len(nodes) > MAX_WORKFLOW_NODES:
        raise WorkflowValidationError(f"nodes must be a list with at most {MAX_WORKFLOW_NODES} items")
    if not isinstance(connections, (list, dict)) or len(connections) > MAX_WORKFLOW_CONNECTIONS:
        raise WorkflowValidationError(f"connections must be a list or n8n-style object with at most {MAX_WORKFLOW_CONNECTIONS} items")
    connection_items = _canonical_connections(connections)
    if len(connection_items) > MAX_WORKFLOW_CONNECTIONS:
        raise WorkflowValidationError(f"connections must contain at most {MAX_WORKFLOW_CONNECTIONS} items")

    normalized_nodes: list[dict[str, Any]] = []
    node_ids: set[str] = set()
    for raw_node in nodes:
        if not isinstance(raw_node, dict):
            raise WorkflowValidationError("each node must be an object")
        node_id = str(raw_node.get("id", "")).strip()
        node_type = _canonical_node_type(raw_node.get("type"))
        if len(node_id) > WORKFLOW_MAX_NODE_ID_LENGTH or not _SAFE_ID.fullmatch(node_id):
            raise WorkflowValidationError("node id contains unsupported characters")
        if node_id in node_ids:
            raise WorkflowValidationError(f"duplicate node id: {node_id}")
        if node_type not in NODE_TYPES:
            raise WorkflowValidationError(f"unsupported node type: {node_type}")
        params = raw_node.get("params", raw_node.get("data", raw_node.get("parameters", {})))
        if params is None:
            params = {}
        if not isinstance(params, dict):
            raise WorkflowValidationError(f"node {node_id} params must be an object")
        node_ids.add(node_id)
        raw_position = raw_node.get("position")
        if isinstance(raw_position, (list, tuple)) and len(raw_position) >= 2:
            raw_position = {"x": raw_position[0], "y": raw_position[1]}
        normalized_nodes.append({
            "id": node_id,
            "type": node_type,
            "name": str(raw_node.get("name") or NODE_TYPES[node_type]["label"])[:160],
            "position": _position(raw_position),
            "params": _clean_params(params),
            "disabled": bool(raw_node.get("disabled", False)),
        })

    normalized_connections: list[dict[str, str]] = []
    node_definitions = {node["id"]: NODE_TYPES[node["type"]] for node in normalized_nodes}
    adjacency: dict[str, list[str]] = defaultdict(list)
    for raw_edge in connection_items:
        if not isinstance(raw_edge, dict):
            raise WorkflowValidationError("each connection must be an object")
        source = str(raw_edge.get("source", raw_edge.get("from", ""))).strip()
        target = str(raw_edge.get("target", raw_edge.get("to", ""))).strip()
        source_handle = str(raw_edge.get("source_handle", raw_edge.get("sourceHandle", "main"))).strip() or "main"
        target_handle = str(raw_edge.get("target_handle", raw_edge.get("targetHandle", "main"))).strip() or "main"
        if source not in node_ids or target not in node_ids:
            raise WorkflowValidationError("connection references an unknown node")
        if source == target:
            raise WorkflowValidationError("self-connections are not supported")
        if source_handle not in set(node_definitions[source]["outputs"]):
            raise WorkflowValidationError(f"unsupported source handle: {source_handle}")
        if target_handle not in set(node_definitions[target]["inputs"] or ["main"]):
            raise WorkflowValidationError(f"unsupported target handle: {target_handle}")
        normalized_connections.append({
            "source": source,
            "target": target,
            "source_handle": source_handle,
            "target_handle": target_handle,
        })
        adjacency[source].append(target)

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node_id: str) -> None:
        if node_id in visiting:
            raise WorkflowValidationError("workflow connections must be acyclic")
        if node_id in visited:
            return
        visiting.add(node_id)
        for child in adjacency[node_id]:
            visit(child)
        visiting.remove(node_id)
        visited.add(node_id)

    for node_id in node_ids:
        visit(node_id)

    triggers = [
        node for node in normalized_nodes
        if not node["disabled"] and NODE_TYPES[node["type"]].get("trigger")
    ]
    if require_trigger and not triggers:
        raise WorkflowValidationError("workflow needs at least one trigger node")
    if any(node["type"] in MANUAL_ONLY_NODE_TYPES and not node["disabled"] for node in normalized_nodes):
        automatic_triggers = [node["type"] for node in triggers if node["type"] != "manual_trigger"]
        if automatic_triggers:
            raise WorkflowValidationError("Repeater Burst and Last-Byte Sync are manual-only and cannot use schedule or webhook triggers")
    for trigger in triggers:
        if trigger["type"] == "schedule_trigger":
            expression = str(trigger["params"].get("cron", "")).strip()
            if not expression:
                raise WorkflowValidationError("schedule trigger needs a cron expression")
            validate_cron(expression)
    return normalized_nodes, normalized_connections


def _parse_cron_field(field: str | int, minimum: int, maximum: int, value: int) -> bool:
    field = str(field).strip()
    if field == "*":
        return True
    for part in field.split(","):
        part = part.strip()
        if not part:
            return False
        step = 1
        if "/" in part:
            part, raw_step = part.split("/", 1)
            try:
                step = int(raw_step)
            except ValueError:
                return False
            if step < 1:
                return False
        if part in {"*", ""}:
            start, end = minimum, maximum
        elif "-" in part:
            raw_start, raw_end = part.split("-", 1)
            try:
                start, end = int(raw_start), int(raw_end)
            except ValueError:
                return False
        else:
            try:
                start = end = int(part)
            except ValueError:
                return False
        if start < minimum or end > maximum or start > end:
            return False
        if (value - start) % step == 0:
            return True
    return False


def validate_cron(expression: str) -> None:
    """Validate a standard five- or six-field cron expression."""

    fields = str(expression or "").split()
    if len(fields) not in {5, 6}:
        raise WorkflowValidationError("cron must contain five or six fields")
    ranges = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)]
    if len(fields) == 6:
        ranges.insert(0, (0, 59))
    for index, (field, (minimum, maximum)) in enumerate(zip(fields, ranges)):
        # Validate each comma-separated part with a harmless value.  The
        # bounds and syntax are the important part here; matching is done later.
        if not field:
            raise WorkflowValidationError("cron contains an empty field")
        for part in field.split(","):
            candidate = part.split("/", 1)[0]
            if "/" in part:
                try:
                    if int(part.split("/", 1)[1]) < 1:
                        raise WorkflowValidationError("cron step must be positive")
                except ValueError as error:
                    raise WorkflowValidationError("cron contains an invalid step") from error
            if candidate == "*":
                continue
            if "-" in candidate:
                left, right = candidate.split("-", 1)
                try:
                    left_value, right_value = int(left), int(right)
                except ValueError as error:
                    raise WorkflowValidationError("cron contains an invalid range") from error
                if left_value < minimum or right_value > maximum or left_value > right_value:
                    raise WorkflowValidationError("cron range is outside its allowed bounds")
            else:
                try:
                    number = int(candidate)
                except ValueError as error:
                    raise WorkflowValidationError("cron contains an invalid number") from error
                if number < minimum or number > maximum:
                    raise WorkflowValidationError("cron number is outside its allowed bounds")


def cron_matches(expression: str, moment: datetime) -> bool:
    fields = str(expression).split()
    if len(fields) == 5:
        second = 0
        minute, hour, day, month, weekday = fields
    elif len(fields) == 6:
        second, minute, hour, day, month, weekday = fields
    else:
        return False
    current = moment.astimezone(timezone.utc)
    cron_weekday = (current.weekday() + 1) % 7  # Python Monday=0 -> cron Sunday=0
    if not _parse_cron_field(second, 0, 59, current.second):
        return False
    if not _parse_cron_field(minute, 0, 59, current.minute):
        return False
    if not _parse_cron_field(hour, 0, 23, current.hour):
        return False
    if not _parse_cron_field(day, 1, 31, current.day):
        return False
    if not _parse_cron_field(month, 1, 12, current.month):
        return False
    return _parse_cron_field(weekday, 0, 7, cron_weekday)


def next_cron_time(expression: str, after: datetime | None = None) -> datetime | None:
    """Find the next UTC cron occurrence without adding a dependency."""

    validate_cron(expression)
    current = (after or django_timezone.now()).astimezone(timezone.utc)
    fields = str(expression).split()
    step = 1 if len(fields) == 5 else 1
    candidate = current.replace(microsecond=0) + timedelta(seconds=step)
    if len(fields) == 5:
        candidate = candidate.replace(second=0)
    deadline = current + timedelta(days=370)
    while candidate <= deadline:
        if cron_matches(expression, candidate):
            return candidate
        candidate += timedelta(seconds=step if len(fields) == 6 else 60)
    return None


def _lookup(value: Any, path: str) -> Any:
    path = str(path or "").strip()
    if path in {"", ".", "$"}:
        return value
    path = path.removeprefix("$").removeprefix(".")
    current = value
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return None
    return current


def _resolve_string(value: str, context: dict[str, Any]) -> Any:
    match = re.fullmatch(r"\{\{\s*([^}]+?)\s*\}\}", value)
    if match:
        return _lookup(context.get("input"), match.group(1))
    def replace(match: re.Match[str]) -> str:
        resolved = _lookup(context.get("input"), match.group(1).strip())
        if resolved is None:
            return ""
        if isinstance(resolved, (dict, list)):
            return json.dumps(resolved, ensure_ascii=False)
        return str(resolved)
    return re.sub(r"\{\{\s*([^}]+?)\s*\}\}", replace, value)


def resolve_value(value: Any, context: dict[str, Any]) -> Any:
    """Resolve safe ``{{path}}`` expressions without evaluating JavaScript."""

    if isinstance(value, str):
        return _resolve_string(value, context)
    if isinstance(value, list):
        return [resolve_value(item, context) for item in value]
    if isinstance(value, dict):
        return {str(key): resolve_value(child, context, ) for key, child in value.items()}
    return value


def _input_value(incoming: list[Any]) -> Any:
    if not incoming:
        return {}
    if len(incoming) == 1:
        return incoming[0]
    return incoming


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def decode_value(operation: str, value: Any) -> dict[str, Any]:
    text = _as_text(value)
    operation = str(operation or "urlEncode")
    if operation == "urlEncode":
        return {"operation": operation, "value": quote(text, safe="")}
    if operation == "urlDecode":
        return {"operation": operation, "value": unquote(text)}
    if operation == "base64Encode":
        return {"operation": operation, "value": base64.b64encode(text.encode()).decode()}
    if operation in {"base64Decode", "base64UrlDecode"}:
        encoded = text.strip()
        if operation == "base64UrlDecode":
            encoded = encoded.replace("-", "+").replace("_", "/")
            encoded += "=" * (-len(encoded) % 4)
        try:
            raw = base64.b64decode(encoded, validate=False)
        except (binascii.Error, ValueError) as error:
            raise WorkflowValidationError("invalid base64 input") from error
        try:
            return {"operation": operation, "value": raw.decode("utf-8"), "binary": False}
        except UnicodeDecodeError:
            return {
                "operation": operation,
                "value": "",
                "binary": True,
                "value_base64": base64.b64encode(raw).decode(),
            }
    if operation == "base64UrlEncode":
        return {"operation": operation, "value": base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")}
    if operation == "htmlEncode":
        return {"operation": operation, "value": html.escape(text, quote=True)}
    if operation == "htmlDecode":
        return {"operation": operation, "value": html.unescape(text)}
    if operation == "hexEncode":
        return {"operation": operation, "value": text.encode().hex()}
    if operation == "hexDecode":
        try:
            raw = bytes.fromhex(text.replace(" ", ""))
        except ValueError as error:
            raise WorkflowValidationError("hex input must contain complete byte pairs") from error
        try:
            return {"operation": operation, "value": raw.decode("utf-8"), "binary": False}
        except UnicodeDecodeError:
            return {"operation": operation, "value": "", "binary": True, "value_base64": base64.b64encode(raw).decode()}
    if operation == "byteEncode":
        return {"operation": operation, "value": " ".join(f"{byte:08b}" for byte in text.encode())}
    if operation == "byteDecode":
        tokens = text.strip().split()
        try:
            raw = bytes(int(token, 2) if re.fullmatch(r"[01]{8}", token) else int(token, 10) for token in tokens)
        except (ValueError, TypeError) as error:
            raise WorkflowValidationError("byte input must contain 8-bit groups or decimal bytes") from error
        return {"operation": operation, "value": raw.decode("utf-8", errors="replace")}
    if operation == "jsonPretty":
        try:
            return {"operation": operation, "value": json.dumps(json.loads(text), ensure_ascii=False, indent=2)}
        except json.JSONDecodeError as error:
            raise WorkflowValidationError("input is not valid JSON") from error
    if operation == "jsonMinify":
        try:
            return {"operation": operation, "value": json.dumps(json.loads(text), ensure_ascii=False, separators=(",", ":"))}
        except json.JSONDecodeError as error:
            raise WorkflowValidationError("input is not valid JSON") from error
    if operation == "jwtDecode":
        parts = text.split(".")
        if len(parts) != 3:
            raise WorkflowValidationError("JWT input must contain three dot-separated parts")
        decoded = []
        for index, part in enumerate(parts[:2]):
            padded = part + "=" * (-len(part) % 4)
            try:
                raw = base64.urlsafe_b64decode(padded)
                decoded.append(json.loads(raw.decode("utf-8")))
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError, binascii.Error) as error:
                raise WorkflowValidationError(f"JWT part {index + 1} is invalid") from error
        return {"operation": operation, "header": decoded[0], "payload": decoded[1], "signature": parts[2], "verified": False}
    if operation == "sha256":
        return {"operation": operation, "value": hashlib.sha256(text.encode()).hexdigest()}
    raise WorkflowValidationError(f"unsupported decoder operation: {operation}")


def compare_values(mode: str, left: Any, right: Any) -> dict[str, Any]:
    left_text = _as_text(left)
    right_text = _as_text(right)
    if str(mode or "words") == "bytes":
        left_bytes = left_text.encode()
        right_bytes = right_text.encode()
        equal = left_bytes == right_bytes
        diff = "\n".join(difflib.unified_diff(
            [f"{byte:02x}" for byte in left_bytes],
            [f"{byte:02x}" for byte in right_bytes],
            fromfile="left",
            tofile="right",
            lineterm="",
        ))
    else:
        equal = left_text == right_text
        diff = "\n".join(difflib.unified_diff(
            left_text.splitlines(), right_text.splitlines(), fromfile="left", tofile="right", lineterm="",
        ))
    return {"mode": str(mode or "words"), "equal": equal, "diff": diff, "left": left, "right": right}


def _condition_value(input_value: Any, params: dict[str, Any]) -> tuple[Any, Any, str, bool]:
    field = str(params.get("field", "")).strip()
    actual = _lookup(input_value, field) if field else input_value
    expected = resolve_value(params.get("value"), {"input": input_value})
    operator = str(params.get("operator", "equals")).strip().lower()
    if operator == "equals":
        result = actual == expected
    elif operator in {"not_equals", "neq"}:
        result = actual != expected
    elif operator == "contains":
        result = str(expected) in _as_text(actual)
    elif operator == "not_contains":
        result = str(expected) not in _as_text(actual)
    elif operator == "exists":
        result = actual is not None and actual != ""
    elif operator == "not_exists":
        result = actual is None or actual == ""
    elif operator in {"greater_than", "gt"}:
        try:
            result = float(actual) > float(expected)
        except (TypeError, ValueError):
            result = False
    elif operator in {"less_than", "lt"}:
        try:
            result = float(actual) < float(expected)
        except (TypeError, ValueError):
            result = False
    elif operator == "regex":
        try:
            result = re.search(str(expected), _as_text(actual), re.IGNORECASE) is not None
        except re.error:
            result = False
    elif operator in {"truthy", "true"}:
        result = bool(actual)
    else:
        raise WorkflowValidationError(f"unsupported condition operator: {operator}")
    return actual, expected, operator, result


def _safe_json(value: Any) -> Any:
    try:
        encoded = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return {"error": "result is not JSON serializable"}
    if len(encoded.encode()) <= MAX_RESULT_BYTES:
        return value
    return {
        "truncated": True,
        "original_size": len(encoded.encode()),
        "preview": encoded[:400_000],
    }


def _format_workflow_output(value: Any, params: dict[str, Any]) -> dict[str, Any]:
    output_format = str(params.get("format", "json")).lower()
    label = str(params.get("label", "Result"))[:160]
    if output_format == "json":
        content: Any = value
    elif output_format in {"markdown", "md"}:
        serialized = json.dumps(value, ensure_ascii=False, indent=2, default=str)
        content = f"# {label}\n\n```json\n{serialized}\n```"
    elif output_format == "html":
        serialized = html.escape(json.dumps(value, ensure_ascii=False, indent=2, default=str))
        content = f"<h1>{html.escape(label)}</h1><pre>{serialized}</pre>"
    else:
        raise WorkflowValidationError(f"unsupported output format: {output_format}")
    return {"label": label, "format": "json" if output_format == "json" else output_format, "content": content, "value": value}


def _default_tool_runner(node_type: str, params: dict[str, Any], context: dict[str, Any]) -> Any:
    # Import lazily so Django can finish loading the URL configuration before
    # a scheduler thread starts executing a workflow.
    from . import views

    return views.workflow_tool_runner(node_type, params, context)


class WorkflowRuntime:
    """Small process-local executor with durable run state."""

    def __init__(self, max_workers: int = 4) -> None:
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="requestrider-workflow")
        self.controls: dict[int, RunControl] = {}
        self.controls_lock = threading.RLock()
        self.listeners: dict[int, list[queue.Queue]] = {}
        self.listeners_lock = threading.RLock()

    def control_for(self, run_id: int) -> RunControl:
        with self.controls_lock:
            return self.controls.setdefault(run_id, RunControl())

    def remove_control(self, run_id: int) -> None:
        with self.controls_lock:
            self.controls.pop(run_id, None)

    def start(
        self,
        workflow: Workflow,
        *,
        mode: str,
        trigger_type: str,
        input_data: Any,
        trigger_node_id: str = "",
        project_id: int | None = None,
        tool_runner: Callable[[str, dict[str, Any], dict[str, Any]], Any] | None = None,
    ) -> WorkflowRun:
        run = WorkflowRun.objects.create(
            workflow=workflow,
            project_id=project_id if project_id is not None else workflow.project_id,
            status="queued",
            mode=mode,
            trigger_type=trigger_type,
            trigger_node_id=str(trigger_node_id or "")[:WORKFLOW_MAX_NODE_ID_LENGTH],
            input_data=_safe_json(input_data if isinstance(input_data, dict) else {"value": input_data}),
        )
        control = self.control_for(run.id)
        try:
            self.executor.submit(self._execute, run.id, tool_runner)
        except Exception:
            self.remove_control(run.id)
            _update_run(
                run.pk,
                status="failed",
                error="workflow worker could not be started",
                finished_at=django_timezone.now(),
            )
            raise
        return run

    def subscribe(self, run_id: int) -> queue.Queue:
        listener: queue.Queue = queue.Queue(maxsize=WORKFLOW_EVENT_QUEUE_SIZE)
        with self.listeners_lock:
            self.listeners.setdefault(run_id, []).append(listener)
        return listener

    def unsubscribe(self, run_id: int, listener: queue.Queue) -> None:
        with self.listeners_lock:
            listeners = self.listeners.get(run_id, [])
            if listener in listeners:
                listeners.remove(listener)
            if not listeners:
                self.listeners.pop(run_id, None)

    def publish(self, run_id: int, event: dict[str, Any]) -> None:
        with self.listeners_lock:
            listeners = list(self.listeners.get(run_id, ()))
        for listener in listeners:
            try:
                listener.put_nowait(event)
            except queue.Full:
                # A slow browser must not hold up the workflow worker.
                try:
                    listener.get_nowait()
                    listener.put_nowait(event)
                except queue.Empty:
                    pass

    def cancel(self, run_id: int) -> bool:
        with self.controls_lock:
            control = self.controls.get(run_id)
        if control is None:
            return False
        control.cancel.set()
        return True

    def pause(self, run_id: int) -> bool:
        with self.controls_lock:
            control = self.controls.get(run_id)
        if control is None:
            return False
        control.pause.set()
        _update_run(run_id, status="paused")
        return True

    def resume(self, run_id: int) -> bool:
        with self.controls_lock:
            control = self.controls.get(run_id)
        if control is None:
            return False
        control.pause.clear()
        _update_run(run_id, status="running")
        return True

    def _append_event(self, run_id: int, node_id: str, status: str, message: str = "") -> None:
        run = WorkflowRun.objects.filter(pk=run_id).first()
        if not run:
            return
        events = list(run.logs or [])
        events.append({
            "at": django_timezone.now().isoformat(),
            "node_id": node_id,
            "status": status,
            "message": str(message)[:WORKFLOW_EVENT_MESSAGE_LENGTH],
        })
        _update_run(run_id, logs=events[-MAX_EVENT_LOG:])
        self.publish(run_id, {"type": "node", "run_id": run_id, **events[-1]})

    def _wait_if_paused(self, run_id: int, control: RunControl) -> None:
        was_paused = False
        while control.pause.is_set():
            if control.cancel.is_set():
                raise WorkflowCancelled()
            if not was_paused:
                _update_run(run_id, status="paused")
                was_paused = True
            time.sleep(0.1)
        if was_paused:
            _update_run(run_id, status="running")

    def _reachable(self, roots: list[str], edges: list[dict[str, str]]) -> set[str]:
        children: dict[str, list[str]] = defaultdict(list)
        for edge in edges:
            children[edge["source"]].append(edge["target"])
        reachable = set(roots)
        queue = deque(roots)
        while queue:
            current = queue.popleft()
            for child in children[current]:
                if child not in reachable:
                    reachable.add(child)
                    queue.append(child)
        return reachable

    def _execute_node(
        self,
        node: dict[str, Any],
        incoming: list[Any],
        context: dict[str, Any],
        tool_runner: Callable[[str, dict[str, Any], dict[str, Any]], Any] | None,
    ) -> dict[str, Any]:
        node_type = node["type"]
        input_value = _input_value(incoming)
        params = resolve_value(node.get("params") or {}, {"input": input_value, **context})
        if node_type in {"manual_trigger", "schedule_trigger", "webhook_trigger"}:
            return {"main": context.get("input", input_value)}
        if node_type == "condition":
            _, _, _, result = _condition_value(input_value, params)
            return {"true": input_value if result else None, "false": None if result else input_value}
        if node_type == "merge":
            return {"main": incoming}
        if node_type == "set":
            values = params.get("values")
            return {"main": values if isinstance(values, dict) else {"value": values}}
        if node_type == "template":
            return {"main": params.get("text", "")}
        if node_type == "delay":
            try:
                seconds = max(0.0, min(float(WORKFLOW_MAX_DELAY_SECONDS), float(params.get("seconds", 1))))
            except (TypeError, ValueError) as error:
                raise WorkflowValidationError("delay seconds must be numeric") from error
            end = time.monotonic() + seconds
            control = context.get("control")
            while time.monotonic() < end:
                if control and control.cancel.is_set():
                    raise WorkflowCancelled()
                time.sleep(min(0.1, max(0.0, end - time.monotonic())))
            return {"main": input_value}
        if node_type == "decoder":
            return {"main": decode_value(params.get("operation", "urlEncode"), input_value)}
        if node_type == "comparer":
            left = params.get("left", input_value)
            right = params.get("right", "")
            return {"main": compare_values(params.get("mode", "words"), left, right)}
        if node_type in {
            "repeater", "repeater_burst", "last_byte_sync", "target", "target_browser", "oast_listener", "oast_collect", "osint", "scanner", "intruder", "ai_agent",
        }:
            runner = tool_runner or _default_tool_runner
            return {"main": runner(node_type, params, context)}
        if node_type == "output":
            return {"main": _format_workflow_output(input_value, params)}
        raise WorkflowValidationError(f"unsupported node type: {node_type}")

    def _execute(
        self,
        run_id: int,
        tool_runner: Callable[[str, dict[str, Any], dict[str, Any]], Any] | None,
    ) -> None:
        close_old_connections()
        control = self.control_for(run_id)
        run = WorkflowRun.objects.filter(pk=run_id).first()
        if not run:
            self.remove_control(run_id)
            return
        try:
            workflow = run.workflow
            nodes, edges = validate_workflow(workflow.nodes, workflow.connections, require_trigger=True)
            active_ids = {node["id"] for node in nodes if not node["disabled"]}
            nodes = [node for node in nodes if node["id"] in active_ids]
            edges = [edge for edge in edges if edge["source"] in active_ids and edge["target"] in active_ids]
            node_map = {node["id"]: node for node in nodes}
            if run.trigger_node_id:
                roots = [run.trigger_node_id] if run.trigger_node_id in node_map else []
            elif run.mode == "schedule":
                roots = [node["id"] for node in nodes if node["type"] == "schedule_trigger" and not node["disabled"]]
            elif run.mode == "webhook":
                roots = [node["id"] for node in nodes if node["type"] == "webhook_trigger" and not node["disabled"]]
            else:
                roots = [node["id"] for node in nodes if node["type"] == "manual_trigger" and not node["disabled"]]
            if not roots:
                raise WorkflowValidationError("no matching trigger for this run")
            reachable = self._reachable(roots, edges)
            incoming_count: dict[str, int] = {node_id: 0 for node_id in reachable}
            for edge in edges:
                if edge["source"] in reachable and edge["target"] in reachable:
                    incoming_count[edge["target"]] += 1
            for root in roots:
                incoming_count[root] = 0
            buffers: dict[str, list[Any]] = defaultdict(list)
            for root in roots:
                buffers[root].append(run.input_data)
            outgoing: dict[str, list[dict[str, str]]] = defaultdict(list)
            for edge in edges:
                if edge["source"] in reachable and edge["target"] in reachable:
                    outgoing[edge["source"]].append(edge)
            queue = deque(roots)
            processed: set[str] = set()
            skipped: set[str] = set()
            last_output: Any = run.input_data
            shared_context: dict[str, Any] = {}

            def propagate_skipped(node_id: str) -> None:
                if node_id in processed or node_id in skipped:
                    return
                skipped.add(node_id)
                for edge in outgoing.get(node_id, []):
                    target_id = edge["target"]
                    incoming_count[target_id] -= 1
                    if incoming_count[target_id] > 0:
                        continue
                    if buffers.get(target_id):
                        queue.append(target_id)
                    else:
                        propagate_skipped(target_id)
            _update_run(
                run_id,
                status="running",
                started_at=django_timezone.now(),
                current_node="",
            )
            Workflow.objects.filter(pk=workflow.pk).update(last_run_at=django_timezone.now())
            while queue:
                if control.cancel.is_set():
                    raise WorkflowCancelled()
                node_id = queue.popleft()
                if node_id in processed:
                    continue
                self._wait_if_paused(run_id, control)
                if control.cancel.is_set():
                    raise WorkflowCancelled()
                node = node_map[node_id]
                incoming = buffers.get(node_id, [])
                context = {
                    "input": _input_value(incoming),
                    "incoming": incoming,
                    "workflow": workflow,
                    "run": run,
                    "node": node,
                    "control": control,
                    "shared": shared_context,
                }
                _update_run(run_id, current_node=node_id)
                self._append_event(run_id, node_id, "running")
                try:
                    ports = self._execute_node(node, incoming, context, tool_runner)
                except Exception:
                    self._append_event(run_id, node_id, "failed")
                    raise
                self._append_event(run_id, node_id, "completed")
                processed.add(node_id)
                if ports.get("main") is not None:
                    last_output = ports["main"]
                for edge in outgoing[node_id]:
                    target_id = edge["target"]
                    value = ports.get(edge["source_handle"])
                    if value is not None:
                        buffers[target_id].append(value)
                    incoming_count[target_id] -= 1
                    if incoming_count[target_id] <= 0:
                        if buffers.get(target_id):
                            if target_id not in processed:
                                queue.append(target_id)
                        else:
                            propagate_skipped(target_id)
            _update_run(
                run_id,
                status="completed",
                current_node="",
                output_data=_safe_json(last_output),
                finished_at=django_timezone.now(),
            )
            self.publish(run_id, {"type": "complete", "run_id": run_id, "status": "completed"})
        except WorkflowCancelled:
            _update_run(
                run_id,
                status="cancelled",
                current_node="",
                error="run cancelled",
                finished_at=django_timezone.now(),
            )
            self.publish(run_id, {"type": "complete", "run_id": run_id, "status": "cancelled"})
            self._append_event(run_id, "", "cancelled", "run cancelled")
        except WorkflowValidationError as error:
            logger.warning("workflow_run_rejected run_id=%s reason=%s", run_id, error)
            _update_run(
                run_id,
                status="failed",
                current_node="",
                error=str(error)[:4000],
                finished_at=django_timezone.now(),
            )
            self.publish(run_id, {"type": "complete", "run_id": run_id, "status": "failed"})
            self._append_event(run_id, "", "failed", str(error))
        except Exception as error:
            logger.exception("workflow_run_failed run_id=%s", run_id)
            _update_run(
                run_id,
                status="failed",
                current_node="",
                error=str(error)[:4000],
                finished_at=django_timezone.now(),
            )
            self.publish(run_id, {"type": "complete", "run_id": run_id, "status": "failed"})
            self._append_event(run_id, "", "failed", str(error))
        finally:
            control.run_cleanup()
            self.remove_control(run_id)
            close_old_connections()


class WorkflowScheduler:
    """Poll active cron workflows in the local Django process."""

    def __init__(self, runtime: WorkflowRuntime, interval: float = 10.0) -> None:
        self.runtime = runtime
        self.interval = interval
        self.thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.lock = threading.Lock()

    def start(self) -> None:
        with self.lock:
            if self.thread and self.thread.is_alive():
                return
            self.stop_event.clear()
            self.thread = threading.Thread(target=self._loop, name="requestrider-workflow-scheduler", daemon=True)
            self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()

    def _recover_interrupted(self) -> None:
        WorkflowRun.objects.filter(status__in=["queued", "running", "paused"]).update(
            status="interrupted",
            error="web process restarted before the run completed",
            finished_at=django_timezone.now(),
            updated_at=django_timezone.now(),
        )

    def _loop(self) -> None:
        try:
            self._recover_interrupted()
        except OperationalError as error:
            logger.warning("workflow_scheduler_recovery_deferred reason=%s", error)
        while not self.stop_event.is_set():
            close_old_connections()
            now = django_timezone.now()
            try:
                due = Workflow.objects.filter(
                    active=True,
                    schedule__isnull=False,
                ).exclude(schedule="").filter(next_run_at__lte=now)
                for workflow in due:
                    try:
                        with transaction.atomic():
                            locked = Workflow.objects.select_for_update().get(pk=workflow.pk)
                            if not locked.active or not locked.schedule or not locked.next_run_at or locked.next_run_at > now:
                                continue
                            next_at = next_cron_time(locked.schedule, now)
                            locked.next_run_at = next_at
                            locked.save(update_fields=["next_run_at", "updated_at"])
                        trigger = next(
                            (node for node in locked.nodes if isinstance(node, dict) and node.get("type") == "schedule_trigger"),
                            None,
                        )
                        self.runtime.start(
                            locked,
                            mode="schedule",
                            trigger_type="schedule",
                            trigger_node_id=str((trigger or {}).get("id", "")),
                            input_data={"scheduled_at": now.isoformat(), "trigger": "schedule"},
                        )
                    except Exception:
                        logger.exception("workflow_schedule_failed workflow_id=%s", workflow.pk)
            except Exception:
                logger.exception("workflow_scheduler_poll_failed")
            self.stop_event.wait(self.interval)


_runtime: WorkflowRuntime | None = None
_scheduler: WorkflowScheduler | None = None
_runtime_lock = threading.RLock()


def get_runtime() -> WorkflowRuntime:
    global _runtime
    with _runtime_lock:
        if _runtime is None:
            _runtime = WorkflowRuntime()
        return _runtime


def ensure_scheduler() -> WorkflowScheduler | None:
    """Start the local cron poller, except during Django test commands."""

    global _scheduler
    if "test" in sys.argv or "pytest" in sys.argv:
        return None
    with _runtime_lock:
        if _scheduler is None:
            _scheduler = WorkflowScheduler(get_runtime())
        _scheduler.start()
        return _scheduler


def activate_workflow(workflow: Workflow) -> None:
    workflow.active = True
    if workflow.schedule:
        workflow.next_run_at = next_cron_time(workflow.schedule)
    else:
        workflow.next_run_at = None
    workflow.save(update_fields=["active", "next_run_at", "updated_at"])
    ensure_scheduler()


def deactivate_workflow(workflow: Workflow) -> None:
    workflow.active = False
    workflow.next_run_at = None
    workflow.save(update_fields=["active", "next_run_at", "updated_at"])


def run_item(run: WorkflowRun) -> dict[str, Any]:
    return {
        "id": run.id,
        "workflow_id": run.workflow_id,
        "project_id": run.project_id,
        "status": run.status,
        "mode": run.mode,
        "trigger_type": run.trigger_type,
        "trigger_node_id": run.trigger_node_id,
        "input": run.input_data,
        "output": run.output_data,
        "current_node": run.current_node,
        "logs": run.logs or [],
        "error": run.error,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "created_at": run.created_at.isoformat(),
        "updated_at": run.updated_at.isoformat(),
    }
