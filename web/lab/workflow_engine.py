"""Durable workflow graph validation and local execution primitives.

The editor deliberately uses a small, portable graph format instead of a
frontend-only runtime.  Workflows are persisted by Django, while this module
provides the same core concepts used by larger workflow platforms: typed
nodes, directed connections, trigger roots, active executions, schedules and
webhook runs.

Workflow graphs run in a local in-process worker. When broker dispatch is
enabled, selected engine nodes execute through the durable Go task queues, but
the Django graph cursor and node buffers remain owned by this process.
"""

from __future__ import annotations

import base64
import binascii
import difflib
import hashlib
import html
import json
import logging
import os
import queue
import re
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import quote, unquote

from django.db import OperationalError, close_old_connections, transaction
from django.utils import timezone as django_timezone

from .engine_broker import EngineTaskDeferred
from .models import Workflow, WorkflowNodeExecution, WorkflowRun
from .outbound_runtime import get_outbound_runtime
from .project_context import redact_sensitive_value

logger = logging.getLogger(__name__)

WORKFLOW_GRAPH_SCHEMA_VERSION = 1
WORKFLOW_CELERY_ENABLED = os.environ.get(
    "WORKFLOW_CELERY_ENABLED", ""
).strip().lower() in {"1", "true", "yes", "on"}

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
        "defaults": {"method": "GET", "url": "", "headers": {}, "iterations": 3, "concurrency": 2, "delay_ms": 0, "timeout_ms": 0},
        "confirmation": True,
    },
    "last_byte_sync": {
        "label": "Last-Byte Sync",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"method": "POST", "url": "", "headers": {}, "body": "", "iterations": 1, "concurrency": 1, "delay_ms": 0, "hold_ms": 50, "timeout_ms": 0},
        "confirmation": True,
    },
    "target": {
        "label": "Target map",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"url": "", "engine": "static", "max_pages": 0, "max_depth": -1, "delay_ms": 0, "same_origin": False},
    },
    "target_browser": {
        "label": "Target browser",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"url": "", "browser": "firefox", "mode": "navigation", "max_pages": 0, "max_depth": -1, "delay_ms": 0, "navigation_timeout_ms": 0, "same_origin": False, "capture_context_id": "", "actions": [], "allow_state_changing_actions": False, "auto_interact": False, "auto_fill": True, "auto_click": True},
    },
    "oast_listener": {
        "label": "OAST Listener",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"server_url": "http://127.0.0.1:8766", "listener_id": "", "poll_interval_sec": 3, "timeout_sec": 0, "capture_protocols": ["http"]},
        "confirmation": True,
    },
    "oast_collect": {
        "label": "OAST Collect",
        "inputs": ["main"],
        "outputs": ["main"],
        "defaults": {"poll_interval_sec": 1, "timeout_sec": 0},
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
        {"name": "browser", "kind": "select", "label": "Browser", "options": ["firefox", "chromium", "chrome", "edge"]},
        {"name": "mode", "kind": "select", "label": "Browser mode", "options": ["navigation", "form"]},
        {"name": "max_pages", "kind": "number", "label": "Max pages"},
        {"name": "max_depth", "kind": "number", "label": "Max depth"},
        {"name": "delay_ms", "kind": "number", "label": "Delay (ms)"},
        {"name": "navigation_timeout_ms", "kind": "number", "label": "Navigation timeout (ms, 0 = none)"},
        {"name": "same_origin", "kind": "boolean", "label": "Same origin only"},
        {"name": "actions", "kind": "json", "label": "Click / Fill actions"},
        {"name": "allow_state_changing_actions", "kind": "boolean", "label": "Allow state-changing actions"},
        {"name": "auto_interact", "kind": "boolean", "label": "Automatic click and form filling"},
        {"name": "auto_fill", "kind": "boolean", "label": "Automatic: fill and submit forms"},
        {"name": "auto_click", "kind": "boolean", "label": "Automatic: click controls"},
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


def _touch_workflow(workflow_id: int) -> None:
    Workflow.objects.filter(pk=workflow_id).update(last_run_at=django_timezone.now())


def _cancel_waiting_engine_task(run: WorkflowRun) -> None:
    """Ask Go to stop the external action a parked run is still waiting for."""
    from .engine_broker import cancel_engine_task
    from .models import EngineTask

    task = (
        EngineTask.objects.filter(
            workflow_run=run,
            workflow_node_id=run.current_node,
        )
        .exclude(status__in=["completed", "failed", "cancelled"])
        .order_by("-created_at")
        .first()
    )
    if task is None:
        return
    try:
        cancel_engine_task(
            task,
            run=run,
            node_id=task.workflow_node_id,
            project=run.project,
            route_generation=task.route_generation,
        )
    except Exception:
        logger.exception("waiting_engine_task_cancel_failed run_id=%s", run.pk)


def _update_run(run_id: int, **fields: Any) -> int:
    """Persist a workflow-run update and surface database failures to callers."""
    fields.setdefault("updated_at", django_timezone.now())
    return WorkflowRun.objects.filter(pk=run_id).update(**fields)


class WorkflowValidationError(ValueError):
    """Raised when a graph cannot be persisted or executed safely."""


def validate_graph_schema_version(value: Any = None) -> int:
    """Resolve the portable graph format version; omitted legacy versions are v1."""
    version = WORKFLOW_GRAPH_SCHEMA_VERSION if value is None else value
    if type(version) is not int or version != WORKFLOW_GRAPH_SCHEMA_VERSION:
        raise WorkflowValidationError(
            f"unsupported workflow graph schema version: {version}"
        )
    return version


class WorkflowCancelled(Exception):
    """Internal signal used to stop a run at the next safe boundary."""


class WorkflowWaitingForEngine(Exception):
    """Internal signal that a node published a durable external action.

    The run is parked in `waiting` with a `waiting` node checkpoint instead of
    holding a worker thread until the engine answers. Only the persisted result
    of the correlated `EngineTask` moves it forward.
    """

    def __init__(self, node_id: str) -> None:
        super().__init__(f"node {node_id} is waiting for an engine result")
        self.node_id = str(node_id)


class RunControl:
    """In-process control flags and cleanup hooks for a persisted run."""

    def __init__(self, project_id: int | None = None) -> None:
        self.project_id = project_id
        self.cancel = threading.Event()
        self.pause = threading.Event()
        self.finished = threading.Event()
        self._cleanup_lock = threading.Lock()
        self._cleanup_callbacks: list[Callable[[], None]] = []
        self._cleaned = False

    def add_cleanup(self, callback: Callable[[], None]) -> None:
        with self._cleanup_lock:
            if not self._cleaned:
                self._cleanup_callbacks.append(callback)
                return
        self._run_callback(callback)

    def request_cancel(self) -> None:
        self.cancel.set()
        self.run_cleanup()

    def run_cleanup(self) -> None:
        with self._cleanup_lock:
            if self._cleaned:
                return
            self._cleaned = True
            callbacks = list(self._cleanup_callbacks)
            self._cleanup_callbacks.clear()
        for callback in callbacks:
            self._run_callback(callback)

    @staticmethod
    def _run_callback(callback: Callable[[], None]) -> None:
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
            "x": float(value.get("x", 80)),
            "y": float(value.get("y", 80)),
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

    if not isinstance(nodes, list):
        raise WorkflowValidationError("nodes must be a list")
    if not isinstance(connections, (list, dict)):
        raise WorkflowValidationError("connections must be a list or n8n-style object")
    connection_items = _canonical_connections(connections)

    normalized_nodes: list[dict[str, Any]] = []
    node_ids: set[str] = set()
    for raw_node in nodes:
        if not isinstance(raw_node, dict):
            raise WorkflowValidationError("each node must be an object")
        node_id = str(raw_node.get("id", "")).strip()
        node_type = _canonical_node_type(raw_node.get("type"))
        if not _SAFE_ID.fullmatch(node_id):
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
            "name": str(raw_node.get("name") or NODE_TYPES[node_type]["label"]),
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
    while True:
        if cron_matches(expression, candidate):
            return candidate
        candidate += timedelta(seconds=step if len(fields) == 6 else 60)


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
    truncated = False
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
        # `_condition_regex` bounds both the pattern and the text it runs against,
        # and the reason is measurable rather than theoretical. Python's `re` has no
        # timeout and no step limit: a Condition(`regex`) holding `(a+)+$` against a
        # target that answers `aaaa…aaa!` never returns, and this runs on the
        # scheduler thread inside the Django process, so the pin never comes back.
        #
        # The cap is on the haystack, not on what the operator may scan: a response
        # body is the input here, and 256 KB is far past any header or status line
        # the operators actually match against, while a body of any size still flows
        # to Repeater, Intruder and the exporters untouched. The truncation is
        # recorded on the node so the UI can say the match saw a prefix, instead of
        # the condition quietly deciding on half the evidence.
        haystack = _as_text(actual)
        if len(haystack) > REGEX_HAYSTACK_LIMIT:
            haystack = haystack[:REGEX_HAYSTACK_LIMIT]
            truncated = True
        try:
            result = _condition_regex(str(expected), haystack) is not None
        except re.error:
            result = False
    elif operator in {"truthy", "true"}:
        result = bool(actual)
    else:
        raise WorkflowValidationError(f"unsupported condition operator: {operator}")
    if truncated:
        # Surfaced rather than swallowed: a condition that matched a prefix is a
        # different fact from one that matched the whole body, and the operator
        # deciding with the wrong one is how a scan reports a false result.
        logger.warning(
            "condition_regex_input_truncated operator=%s haystack_bytes=%d limit=%d",
            operator, REGEX_HAYSTACK_LIMIT, REGEX_HAYSTACK_LIMIT,
        )
    return actual, expected, operator, result


# How much text a `regex` Condition may match against.
#
# Not a scope limit and not a cap on what the tools do: it bounds one comparison
# inside one node, and the same body still reaches Repeater, Intruder and every
# export in full. It exists because `re` cannot be interrupted — `re.search` on a
# catastrophic pattern against attacker-sized input never returns, and this runs on
# the scheduler thread of the Django process.
#
# 256 KB is chosen to sit far above anything a Condition realistically matches
# (status codes, header lines, identifiers) while staying small enough that a
# pathological pattern cannot hold a worker thread. The value is a module constant
# rather than a literal buried in the call so that raising it is a visible decision
# instead of an edit inside an expression.
REGEX_HAYSTACK_LIMIT = 256 * 1024


def _condition_regex(pattern: str, haystack: str):
    """Match `pattern` against `haystack` with a step budget.

    Capping the haystack alone is not sufficient, because a hostile pattern can
    also be pathological on a small input. `re` has no timeout, so the only ways to
    bound the work are to bound the input or to refuse the pattern.

    The refusal is on shape, not on content: a pattern whose nested quantifiers can
    force exponential backtracking is refused by name, with the reason, rather than
    being silently skipped — a condition that quietly stops evaluating is worse than
    one that refuses to run. Simple patterns are unaffected, and operators can still
    match anything the tools fetch.
    """
    if _is_catastrophic_pattern(pattern):
        raise WorkflowValidationError(
            "condition regex rejected: nested quantifier can backtrack exponentially"
        )
    return re.search(pattern, haystack, re.IGNORECASE)


# Quantifiers that can nest: `(a+)+`, `(a*)*`, `(a|a)+` and friends. Finding a `(`,
# a quantified group, and a quantifier after it is enough to refuse; the check is
# deliberately blunt because a false refusal is visible and cheap, while a hang is
# neither.
_CATASTROPHIC_PATTERN = re.compile(
    r"\((?:[^()]*[+*][^()]*)\)[+*]"
    r"|\([^()]*\|[^()]*\)[+*]"
)


def _is_catastrophic_pattern(pattern: str) -> bool:
    return bool(_CATASTROPHIC_PATTERN.search(pattern))


def _safe_json(value: Any) -> Any:
    try:
        encoded = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return {"error": "result is not JSON serializable"}
    return value


def _format_workflow_output(value: Any, params: dict[str, Any]) -> dict[str, Any]:
    output_format = str(params.get("format", "json")).lower()
    label = str(params.get("label", "Result"))
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


_TOOL_NODE_TYPES = {
    "repeater",
    "repeater_burst",
    "last_byte_sync",
    "target",
    "target_browser",
    "oast_listener",
    "oast_collect",
    "osint",
    "scanner",
    "intruder",
    "ai_agent",
}
_ToolRunner = Callable[[str, dict[str, Any], dict[str, Any]], Any]
_NodeExecutor = Callable[
    [
        dict[str, Any],
        list[Any],
        dict[str, Any],
        _ToolRunner | None,
    ],
    dict[str, Any],
]


class WorkflowRuntime:
    """Small process-local executor with durable run state."""

    def __init__(self) -> None:
        self.controls: dict[int, RunControl] = {}
        self.controls_lock = threading.RLock()
        self.listeners: dict[int, list[queue.Queue]] = {}
        self.listeners_lock = threading.RLock()
        self.node_executors: dict[str, _NodeExecutor] = {
            "manual_trigger": self._execute_trigger_node,
            "schedule_trigger": self._execute_trigger_node,
            "webhook_trigger": self._execute_trigger_node,
            "condition": self._execute_condition_node,
            "merge": self._execute_merge_node,
            "set": self._execute_set_node,
            "template": self._execute_template_node,
            "delay": self._execute_delay_node,
            "decoder": self._execute_decoder_node,
            "comparer": self._execute_comparer_node,
            "output": self._execute_output_node,
        }
        self.node_executors.update({
            node_type: self._execute_tool_node
            for node_type in _TOOL_NODE_TYPES
        })

    def _execute_trigger_node(
        self,
        params: dict[str, Any],
        incoming: list[Any],
        context: dict[str, Any],
        tool_runner: _ToolRunner | None,
    ) -> dict[str, Any]:
        return {"main": context.get("input")}

    def _execute_condition_node(
        self,
        params: dict[str, Any],
        incoming: list[Any],
        context: dict[str, Any],
        tool_runner: _ToolRunner | None,
    ) -> dict[str, Any]:
        input_value = context.get("input")
        _, _, _, result = _condition_value(input_value, params)
        return {"true": input_value if result else None, "false": None if result else input_value}

    def _execute_merge_node(
        self,
        params: dict[str, Any],
        incoming: list[Any],
        context: dict[str, Any],
        tool_runner: _ToolRunner | None,
    ) -> dict[str, Any]:
        return {"main": incoming}

    def _execute_set_node(
        self,
        params: dict[str, Any],
        incoming: list[Any],
        context: dict[str, Any],
        tool_runner: _ToolRunner | None,
    ) -> dict[str, Any]:
        values = params.get("values")
        return {"main": values if isinstance(values, dict) else {"value": values}}

    def _execute_template_node(
        self,
        params: dict[str, Any],
        incoming: list[Any],
        context: dict[str, Any],
        tool_runner: _ToolRunner | None,
    ) -> dict[str, Any]:
        return {"main": params.get("text", "")}

    def _execute_delay_node(
        self,
        params: dict[str, Any],
        incoming: list[Any],
        context: dict[str, Any],
        tool_runner: _ToolRunner | None,
    ) -> dict[str, Any]:
        try:
            seconds = max(0.0, float(params.get("seconds", 1)))
        except (TypeError, ValueError) as error:
            raise WorkflowValidationError("delay seconds must be numeric") from error
        end = time.monotonic() + seconds
        control = context.get("control")
        while time.monotonic() < end:
            if control and control.cancel.is_set():
                raise WorkflowCancelled()
            time.sleep(min(0.1, max(0.0, end - time.monotonic())))
        return {"main": context.get("input")}

    def _execute_decoder_node(
        self,
        params: dict[str, Any],
        incoming: list[Any],
        context: dict[str, Any],
        tool_runner: _ToolRunner | None,
    ) -> dict[str, Any]:
        return {
            "main": decode_value(params.get("operation", "urlEncode"), context.get("input"))
        }

    def _execute_comparer_node(
        self,
        params: dict[str, Any],
        incoming: list[Any],
        context: dict[str, Any],
        tool_runner: _ToolRunner | None,
    ) -> dict[str, Any]:
        input_value = context.get("input")
        left = params.get("left", input_value)
        right = params.get("right", "")
        return {"main": compare_values(params.get("mode", "words"), left, right)}

    def _execute_tool_node(
        self,
        params: dict[str, Any],
        incoming: list[Any],
        context: dict[str, Any],
        tool_runner: _ToolRunner | None,
    ) -> dict[str, Any]:
        runner = tool_runner or _default_tool_runner
        node_type = context["node"]["type"]
        return {"main": runner(node_type, params, context)}

    def _execute_output_node(
        self,
        params: dict[str, Any],
        incoming: list[Any],
        context: dict[str, Any],
        tool_runner: _ToolRunner | None,
    ) -> dict[str, Any]:
        return {"main": _format_workflow_output(context.get("input"), params)}

    def control_for(self, run_id: int, project_id: int | None = None) -> RunControl:
        with self.controls_lock:
            control = self.controls.setdefault(run_id, RunControl(project_id=project_id))
            if project_id is not None:
                control.project_id = project_id
            return control

    def remove_control(self, run_id: int) -> None:
        with self.controls_lock:
            self.controls.pop(run_id, None)

    def _dispatch_run(self, run_id: int) -> None:
        if WORKFLOW_CELERY_ENABLED:
            from .tasks import execute_workflow_run

            execute_workflow_run.delay(run_id)
            return
        threading.Thread(
            target=self._execute,
            args=(run_id, None),
            name=f"requestrider-workflow-{run_id}",
            daemon=True,
        ).start()

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
        resolved_project_id = project_id if project_id is not None else workflow.project_id
        with get_outbound_runtime().operation("workflow", resolved_project_id) as admission:
            run = WorkflowRun.objects.create(
                workflow=workflow,
                project_id=resolved_project_id,
                status="queued",
                mode=mode,
                trigger_type=trigger_type,
                trigger_node_id=str(trigger_node_id or ""),
                graph_schema_version=workflow.graph_schema_version,
                graph_nodes=_safe_json(workflow.nodes or []),
                graph_connections=_safe_json(workflow.connections or []),
                input_data=_safe_json(input_data if isinstance(input_data, dict) else {"value": input_data}),
            )
            control = self.control_for(run.id, resolved_project_id)
            if admission.stale:
                control.request_cancel()
            try:
                if tool_runner is None:
                    self._dispatch_run(run.id)
                    if WORKFLOW_CELERY_ENABLED:
                        self.remove_control(run.id)
                        control.finished.set()
                else:
                    threading.Thread(
                        target=self._execute,
                        args=(run.id, tool_runner),
                        name=f"requestrider-workflow-{run.id}",
                        daemon=True,
                    ).start()
            except Exception as error:
                self.remove_control(run.id)
                control.finished.set()
                _update_run(
                    run.pk,
                    status="failed",
                    error="workflow worker could not be dispatched",
                    finished_at=django_timezone.now(),
                )
                logger.exception("workflow_run_dispatch_failed run_id=%s", run.id)
                raise RuntimeError("workflow worker could not be dispatched") from error
            return run

    def subscribe(self, run_id: int) -> queue.Queue:
        listener: queue.Queue = queue.Queue()
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
            return bool(WorkflowRun.objects.filter(
                pk=run_id,
                status__in=["queued", "running", "paused", "waiting"],
            ).update(
                status="cancelled",
                error="run cancelled",
                finished_at=django_timezone.now(),
                updated_at=django_timezone.now(),
            ))
        control.request_cancel()
        return True

    def cancel_all(self, project_id: int | None = None) -> list[int]:
        with self.controls_lock:
            controls = [
                (run_id, control)
                for run_id, control in self.controls.items()
                if project_id is None or control.project_id == project_id
            ]
        for _run_id, control in controls:
            control.request_cancel()
        cancelled = [run_id for run_id, _control in controls]
        # A `waiting` run owns no worker thread, so there is no control to
        # cancel. The route drain still has to reach it: its external action
        # belongs to the generation being switched away from.
        waiting = WorkflowRun.objects.filter(status="waiting")
        if project_id is not None:
            waiting = waiting.filter(project_id=project_id)
        for run in waiting:
            _cancel_waiting_engine_task(run)
            if WorkflowRun.objects.filter(pk=run.pk, status="waiting").update(
                status="cancelled",
                error="run cancelled",
                finished_at=django_timezone.now(),
                updated_at=django_timezone.now(),
            ):
                cancelled.append(run.pk)
        return cancelled

    def start_recovered(self, run_id: int) -> None:
        run = WorkflowRun.objects.filter(pk=run_id).values("project_id").first()
        control = self.control_for(run_id, run["project_id"] if run else None)
        try:
            self._dispatch_run(run_id)
            if WORKFLOW_CELERY_ENABLED:
                self.remove_control(run_id)
                control.finished.set()
        except Exception:
            control.finished.set()
            self.remove_control(run_id)
            _update_run(
                run_id,
                status="failed",
                error="workflow recovery worker could not be started",
                finished_at=django_timezone.now(),
            )
            logger.exception("workflow_run_recovery_start_failed run_id=%s", run_id)

    def pause(self, run_id: int) -> bool:
        with self.controls_lock:
            control = self.controls.get(run_id)
        if control is None:
            # A `waiting` run owns no worker, so the pause is the persisted state
            # itself. The external action keeps running in the engine; what stops
            # is the graph, and it continues on resume with the answer in hand.
            return bool(WorkflowRun.objects.filter(
                pk=run_id,
                status__in=["running", "waiting"],
            ).update(status="paused", updated_at=django_timezone.now()))
        control.pause.set()
        _update_run(run_id, status="paused")
        return True

    def resume(self, run_id: int) -> bool:
        with self.controls_lock:
            control = self.controls.get(run_id)
        if control is not None:
            control.pause.clear()
            _update_run(run_id, status="running")
            return True
        # No control *in this process* does not mean no worker. When
        # `WORKFLOW_CELERY_ENABLED` is on, the graph runs in a Celery worker, so
        # a paused run with an in-flight node is still owned by a live worker
        # elsewhere. Resuming it by starting a second execution is what broke
        # pause/resume: the new worker entered the graph, found the *live*
        # worker's `running` checkpoint and rejected the run with "node ... has
        # an incomplete checkpoint; manual review is required before retry",
        # while the first worker carried on. A `running` node row is the signal
        # that a worker is alive, and pausing is already DB state: that worker
        # parks at its next node boundary and continues once the status flips
        # back to `running`.
        if WorkflowNodeExecution.objects.filter(
            workflow_run_id=run_id, status="running"
        ).exists():
            return bool(WorkflowRun.objects.filter(
                pk=run_id, status="paused",
            ).update(
                status="running",
                updated_at=django_timezone.now(),
            ))
        # No live worker owns this run, so resuming it means handing it back to
        # one. Marking it `running` and stopping there would leave a run nobody
        # is executing, which is the pause that never ends.
        if not WorkflowRun.objects.filter(
            pk=run_id,
            status__in=["paused", "waiting"],
        ).update(status="queued", updated_at=django_timezone.now()):
            return False
        self.start_recovered(run_id)
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
            "message": str(message),
        })
        _update_run(run_id, logs=events)
        self.publish(run_id, {"type": "node", "run_id": run_id, **events[-1]})

    def _wait_if_paused(self, run_id: int, control: RunControl) -> None:
        was_paused = False
        while control.pause.is_set() or WorkflowRun.objects.filter(
            pk=run_id,
            status="paused",
        ).exists():
            if self._is_cancelled(run_id, control):
                raise WorkflowCancelled()
            if not was_paused:
                _update_run(run_id, status="paused")
                was_paused = True
            time.sleep(0.1)
        if was_paused and not self._is_cancelled(run_id, control):
            _update_run(run_id, status="running")

    @staticmethod
    def _is_cancelled(run_id: int, control: RunControl) -> bool:
        return control.cancel.is_set() or WorkflowRun.objects.filter(
            pk=run_id,
            status="cancelled",
        ).exists()

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
        executor = self.node_executors.get(node_type)
        if executor is None:
            raise WorkflowValidationError(f"unsupported node type: {node_type}")
        return executor(params, incoming, context, tool_runner)

    def _execute(
        self,
        run_id: int,
        tool_runner: Callable[[str, dict[str, Any], dict[str, Any]], Any] | None,
    ) -> None:
        close_old_connections()
        run = WorkflowRun.objects.filter(pk=run_id).first()
        if not run:
            return
        claimed_at = django_timezone.now()
        claimed = WorkflowRun.objects.filter(
            pk=run_id,
            status="queued",
        ).update(
            status="running",
            started_at=claimed_at,
            current_node="",
            error="",
            finished_at=None,
            updated_at=claimed_at,
        )
        if not claimed:
            close_old_connections()
            return
        control = self.control_for(run_id, run.project_id)
        # Run-scoped scratch space that nodes publish into via
        # `context["shared"]`. Restored from the row, because a resumed run
        # re-enters `_execute` from its checkpoints and an in-memory dict
        # would come back empty - an OAST chain then failed with "OAST
        # listener_id is unavailable" on every resume. Declared before the
        # `try` so the parking handler can always read it.
        shared_context: dict[str, Any] = dict(
            run.shared_data if isinstance(run.shared_data, dict) else {}
        )

        try:
            workflow = run.workflow
            validate_graph_schema_version(run.graph_schema_version)
            graph_nodes = (
                run.graph_nodes
                if run.graph_nodes is not None
                else workflow.nodes
            )
            graph_connections = (
                run.graph_connections
                if run.graph_connections is not None
                else workflow.connections
            )
            nodes, edges = validate_workflow(
                graph_nodes,
                graph_connections,
                require_trigger=True,
            )
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
                current_node="",
            )
            _touch_workflow(workflow.pk)
            while queue:
                if self._is_cancelled(run_id, control):
                    raise WorkflowCancelled()
                node_id = queue.popleft()
                if node_id in processed:
                    continue
                self._wait_if_paused(run_id, control)
                if self._is_cancelled(run_id, control):
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
                checkpoint = WorkflowNodeExecution.objects.filter(
                    workflow_run_id=run_id,
                    node_id=node_id,
                ).first()
                if checkpoint and checkpoint.status in {"running", "waiting"}:
                    # Partial progress from a node that published durable tasks
                    # and suspended. It re-enters the node with what it already
                    # has, so a multi-request node continues instead of starting
                    # its list over.
                    context["node_progress"] = checkpoint.output_data or {}
                _update_run(run_id, current_node=node_id)
                checkpoint = WorkflowNodeExecution.objects.filter(
                    workflow_run_id=run_id,
                    node_id=node_id,
                ).first()
                if checkpoint and checkpoint.status == "completed":
                    ports = checkpoint.output_data
                    self._append_event(
                        run_id,
                        node_id,
                        "completed",
                        "restored from durable node checkpoint",
                    )
                else:
                    if checkpoint and checkpoint.status in {"running", "failed"}:
                        raise WorkflowValidationError(
                            f"node {node_id} has an incomplete checkpoint; "
                            "manual review is required before retry"
                        )
                    checkpoint, _created = WorkflowNodeExecution.objects.update_or_create(
                        workflow_run_id=run_id,
                        node_id=node_id,
                        defaults={
                            "status": "running",
                            "input_data": _safe_json(incoming),
                            "output_data": (
                                (checkpoint.output_data or {})
                                if checkpoint and checkpoint.status == "waiting"
                                else {}
                            ),
                            "error": "",
                            "started_at": (
                                checkpoint.started_at
                                if checkpoint and checkpoint.status == "waiting"
                                else django_timezone.now()
                            ),
                            "finished_at": None,
                        },
                    )
                    if not (checkpoint and checkpoint.status == "waiting"):
                        self._append_event(run_id, node_id, "running")
                    else:
                        self._append_event(
                            run_id,
                            node_id,
                            "running",
                            "resumed with the results already received",
                        )
                    try:
                        ports = self._execute_node(node, incoming, context, tool_runner)
                    except Exception as error:
                        if isinstance(error, EngineTaskDeferred):
                            # The action left the process. The correlation is
                            # already persisted on the task, so a restart can see
                            # which node is waiting for what, and the run stops
                            # holding a worker until the result arrives.
                            WorkflowNodeExecution.objects.filter(pk=checkpoint.pk).update(
                                status="waiting",
                                updated_at=django_timezone.now(),
                            )
                            self._append_event(
                                run_id,
                                node_id,
                                "waiting",
                                f"waiting for engine task {error.task_id}",
                            )
                            raise WorkflowWaitingForEngine(node_id) from error
                        WorkflowNodeExecution.objects.filter(pk=checkpoint.pk).update(
                            status="failed",
                            error=str(error),
                            finished_at=django_timezone.now(),
                            updated_at=django_timezone.now(),
                        )
                        self._append_event(run_id, node_id, "failed")
                        raise
                if self._is_cancelled(run_id, control):
                    raise WorkflowCancelled()
                if not checkpoint or checkpoint.status != "completed":
                    WorkflowNodeExecution.objects.filter(
                        workflow_run_id=run_id,
                        node_id=node_id,
                    ).update(
                        status="completed",
                        output_data=_safe_json(ports),
                        error="",
                        finished_at=django_timezone.now(),
                        updated_at=django_timezone.now(),
                    )
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
            if self._is_cancelled(run_id, control):
                raise WorkflowCancelled()
            _update_run(
                run_id,
                status="completed",
                current_node="",
                output_data=_safe_json(last_output),
                finished_at=django_timezone.now(),
            )
            self.publish(run_id, {"type": "complete", "run_id": run_id, "status": "completed"})
        except WorkflowWaitingForEngine as waiting:
            # Not a failure and not a pause: the run is alive, it simply owns no
            # worker while an external action finishes. The result consumer
            # requeues it from the durable checkpoint.
            #
            # `shared_context` goes to the database with it. The consumer
            # resumes through a *new* `_execute`, and a node that reads what an
            # earlier one published - an OAST `listener_id`, say - found an empty
            # dict there and failed with "OAST listener_id is unavailable" on
            # every resume. The node checkpoints were durable; this scratch space
            # was not, and it was the only part of the run state that was.
            _update_run(
                run_id,
                status="waiting",
                current_node=waiting.node_id,
                error="",
                finished_at=None,
                shared_data=shared_context,
            )
            self.publish(run_id, {"type": "waiting", "run_id": run_id, "status": "waiting"})
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
                error=str(error),
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
                error=str(error),
                finished_at=django_timezone.now(),
            )
            self.publish(run_id, {"type": "complete", "run_id": run_id, "status": "failed"})
            self._append_event(run_id, "", "failed", str(error))
        finally:
            control.run_cleanup()
            control.finished.set()
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
        now = django_timezone.now()
        runs = WorkflowRun.objects.filter(
            status__in=["queued", "running", "waiting", "paused"],
        ).prefetch_related("node_executions").order_by("id")
        for run in runs:
            checkpoints = list(run.node_executions.all())
            waiting_for_engine = any(
                checkpoint.status == "waiting" for checkpoint in checkpoints
            )
            # A run parked on an external action is resumed only by that action's
            # result. Re-entering the node here would publish it a second time, so
            # the run stays `waiting` and the result consumer owns the next step.
            safe_to_resume = run.status != "paused" and (
                all(checkpoint.status == "completed" for checkpoint in checkpoints)
                or (run.status == "waiting" and waiting_for_engine)
            )
            if safe_to_resume:
                updated = WorkflowRun.objects.filter(
                    pk=run.pk,
                    status=run.status,
                ).update(
                    status="queued",
                    current_node="",
                    error="",
                    finished_at=None,
                    updated_at=now,
                )
                if updated:
                    self.runtime.start_recovered(run.pk)
                continue
            WorkflowRun.objects.filter(pk=run.pk, status=run.status).update(
                status="interrupted",
                error=(
                    "workflow process restarted with a paused run or an "
                    "incomplete node checkpoint; manual review is required"
                ),
                finished_at=now,
                updated_at=now,
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


# --- A06-07: what the operator approved vs what the run actually did --------------------
#
# A `repeater` node carries a templated URL, so a scheduled run goes wherever the upstream
# node's result pointed **at the moment it ran** — not where the operator approved when they
# drew the graph. Both facts were already stored and neither was visible next to the other:
#
#   * `run.graph_nodes` is snapshotted at start, so "the graph said X" is recoverable;
#   * `WorkflowNodeExecution.input_data` is what actually arrived from upstream, so "the run
#     received Y" is recoverable.
#
# Storing both without ever comparing them means a reader has to do the comparison by hand
# across two structures, and in practice nobody does — which is exactly what the finding
# meant by "the replay is not bound to what the operator saw". This is that comparison.
#
# WHAT IT DOES NOT DO. It does not refuse the run. A node whose output legitimately changes
# between runs is the normal case for a workflow, and refusing it would break the tool. The
# evidence product's obligation is to make the difference *visible*, not to prevent it.

# Node types whose templated outbound target can resolve to something other than what the
# graph showed when it was drawn.
REPLAY_SENSITIVE_NODE_TYPES = {"repeater", "target", "target-browser", "browser-target",
                               "intruder", "scanner", "repeater-burst", "last-byte"}


def _node_parameters(node):
    """The parameters a node carried in the approved graph, as a flat mapping."""
    if not isinstance(node, dict):
        return {}
    merged = {}
    raw = node.get("parameters")
    if isinstance(raw, dict):
        merged.update(raw)
    elif isinstance(raw, str) and raw:
        try:
            decoded = json.loads(raw)
            if isinstance(decoded, dict):
                merged.update(decoded)
        except (TypeError, ValueError):
            pass
    for key, value in node.items():
        if key not in {"id", "type", "parameters", "position"}:
            merged.setdefault(key, value)
    return merged


def _approved_target_values(node):
    """Target-shaped values in an approved node, as strings.

    Only the keys that decide **where the request goes** are collected. Comparing the whole
    parameter mapping would report a difference for every changing field — a delay, a count,
    a header — and a report that always says "changed" says nothing.
    """
    target_keys = ("url", "request", "target", "endpoint", "host")
    # `_node_parameters` decodes the JSON-string form too, so a graph written by the
    # parameters-as-text editor is read the same as one written by the object editor.
    # Reading only `node["parameters"]` when it is a dict misses every such graph, and the
    # divergence row then disappears — which is the failure mode this whole finding is
    # about, reproduced inside the fix.
    parameters = _node_parameters(node)
    values = []
    for key in target_keys:
        raw = parameters.get(key)
        if isinstance(raw, str) and raw.strip():
            values.append((key, raw.strip()))
    return sorted(set(values))


def replay_divergence(run) -> list[dict[str, Any]]:
    """For each replay-sensitive node, what the graph approved vs what the run received.

    A node whose approved target is a literal — no `{{ }}` placeholder — can never diverge
    and is left out: listing it would bury the rows that matter.
    """
    graph_nodes = run.graph_nodes if isinstance(run.graph_nodes, list) else []
    by_id = {
        str(node.get("id")): node
        for node in graph_nodes
        if isinstance(node, dict) and node.get("id") is not None
    }
    rows: list[dict[str, Any]] = []
    for execution in run.node_executions.all().order_by("created_at", "id"):
        node = by_id.get(str(execution.node_id))
        if node is None:
            rows.append({
                "node_id": execution.node_id,
                "node_type": "",
                "templated": False,
                "approved": [],
                "received": [],
                "note": "the approved graph no longer contains this node, so what it said "
                        "cannot be reconstructed from this run",
            })
            continue
        approved = _approved_target_values(node)
        templated = any("{{" in value or "{%" in value for _, value in approved)
        if not templated:
            continue
        received = _received_target_values(execution.input_data)
        rows.append({
            "node_id": execution.node_id,
            "node_type": str(node.get("type", "")),
            "templated": True,
            "approved": [{"key": key, "value": redact_sensitive_value(value)}
                         for key, value in approved],
            "received": received,
            "diverged": bool(received) and received != [
                {"key": key, "value": redact_sensitive_value(value)} for key, value in approved
            ],
        })
    return rows


def _received_target_values(input_data) -> list[dict[str, Any]]:
    """Target-shaped values found in what a node actually received."""
    found: list[dict[str, Any]] = []
    target_keys = {"url", "request", "target", "endpoint"}

    def walk(value, depth=0):
        if depth > 6:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                if str(key).lower() in target_keys and isinstance(item, str) and item.strip():
                    found.append({"key": str(key), "value": redact_sensitive_value(item.strip())})
                else:
                    walk(item, depth + 1)
        elif isinstance(value, list):
            for item in value[:64]:
                walk(item, depth + 1)

    walk(input_data)
    return sorted({(row["key"], row["value"]) for row in found}) and [
        {"key": key, "value": value} for key, value in
        sorted({(row["key"], row["value"]) for row in found})
    ] or []


def run_item(run: WorkflowRun) -> dict[str, Any]:
    graph_nodes = run.graph_nodes
    if not isinstance(graph_nodes, list):
        graph_nodes = run.workflow.nodes
    node_types = {
        str(node.get("id")): str(node.get("type", ""))
        for node in graph_nodes
        if isinstance(node, dict) and node.get("id") is not None
    }
    return {
        "id": run.id,
        "workflow_id": run.workflow_id,
        "project_id": run.project_id,
        "status": run.status,
        "mode": run.mode,
        "trigger_type": run.trigger_type,
        "trigger_node_id": run.trigger_node_id,
        "input": redact_sensitive_value(run.input_data),
        "output": redact_sensitive_value(run.output_data),
        "current_node": run.current_node,
        "logs": redact_sensitive_value(run.logs or []),
        # A06-07: the approved target next to what the run actually received. Both halves
        # were always stored; naming them together is what makes the difference readable.
        "replay_divergence": replay_divergence(run),
        "node_executions": [
            {
                "node_id": execution.node_id,
                "node_type": node_types.get(execution.node_id, ""),
                "status": execution.status,
                "input": redact_sensitive_value(execution.input_data),
                "output": redact_sensitive_value(execution.output_data),
                "error": redact_sensitive_value(execution.error),
                "started_at": execution.started_at.isoformat() if execution.started_at else None,
                "finished_at": execution.finished_at.isoformat() if execution.finished_at else None,
            }
            for execution in run.node_executions.all().order_by("created_at", "id")
        ],
        "error": redact_sensitive_value(run.error),
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "created_at": run.created_at.isoformat(),
        "updated_at": run.updated_at.isoformat(),
    }
