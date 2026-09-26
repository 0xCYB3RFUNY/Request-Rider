"""Django gateway views for the browser UI and Go execution engine."""

import json
import logging
import os
import queue
import secrets
import socket
import threading
import time
from http.client import RemoteDisconnected
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from django.db import OperationalError, close_old_connections
from django.http import HttpResponse, JsonResponse, StreamingHttpResponse
from django.db.models import Count, Q
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.csrf import ensure_csrf_cookie

from .models import IntruderAttack, OsintEntity, OsintGraph, OsintRelation, Project, ProjectEndpoint, ProjectSecret, ScannerRun, TargetJob, TrafficCaptureContext, TrafficRecord, Workflow, WorkflowRun
from .agent_services import AgentProviderError, AgentRequestCancelled, cancel_active_agent_requests, generate_agent_chat
from .engine_client import STREAM_CONNECT_TIMEOUT, engine_client
from .ingest import capture_contexts_by_token, ingest_traffic_batch
from .middleware import ACTIVE_PROJECT_SESSION_KEY
from .project_context import ProjectContextBuilder, ProjectContextError, normalize_project_notes, normalize_tech_stack
from .project_transfer import (
    ProjectTransferError,
    export_bundle,
    import_bundle,
    parse_bundle_body,
)
from .outbound_runtime import (
    OutboundOperationCancelled,
    current_outbound_operation,
    get_outbound_runtime,
)
from . import osint_exports
from .osint_graph import (
    OsintGraphError,
    clear_graph,
    create_graph,
    delete_entity,
    delete_relation,
    entity_item,
    graph_item,
    update_entity,
    upsert_graph,
)
from .workflow_engine import (
    WorkflowCancelled,
    WorkflowValidationError,
    activate_workflow,
    deactivate_workflow,
    ensure_scheduler,
    get_runtime,
    next_cron_time,
    node_catalog,
    run_item,
    validate_cron,
    validate_workflow,
    workflow_requires_confirmation,
)
from .workflow_templates import list_templates
from .ws_events import emit_project_event, project_event_hub

# The gateway talks to the engine over HTTP; Docker can override this address.
ENGINE_URL = os.environ.get("ENGINE_URL", "http://127.0.0.1:8081")
BROWSER_WORKER_URL = os.environ.get("BROWSER_WORKER_URL", "http://127.0.0.1:8090")
PASSIVE_PROXY_URL = os.environ.get("PASSIVE_PROXY_URL", "http://127.0.0.1:8080")

# A Playwright job legitimately runs for minutes (navigation, clicks, waiting for
# network idle), so the browser worker gets a longer transport deadline than the
# engine. It is a socket deadline on the local hop, not a cap on the crawl.
BROWSER_WORKER_TIMEOUT = float(os.environ.get("RR_BROWSER_WORKER_TIMEOUT", "900"))

# SSE proxy cadence. `SSE_READ_TIMEOUT` bounds how long one blocking read may
# stall before a keepalive comment is emitted; `SSE_MAX_LIFETIME` bounds how long
# a single proxied stream is held before the client is expected to reconnect with
# its cursor. Both are connection-lifecycle bounds, not event or traffic limits.
SSE_READ_TIMEOUT = float(os.environ.get("RR_SSE_READ_TIMEOUT", "20"))
SSE_MAX_LIFETIME = float(os.environ.get("RR_SSE_MAX_LIFETIME", "3600"))


def open_engine_stream(url, headers=None):
    """Open an engine SSE stream, or raise a JsonResponse with a real status.

    `urlopen` reports a connection-level failure in more than one way. A refused
    connection or an unreachable engine arrives as `URLError`, but a stream whose
    response headers never arrive arrives as `TimeoutError`, which derives from
    `OSError` and is therefore *not* a `URLError`. Catching only `URLError` let
    that case escape as an unhandled 500 with a traceback, so the browser saw a
    server error for a stream that simply had nothing to send yet.

    Both families are handled here and turned into an explicit 502 naming the
    engine, so a caller never has to distinguish them and a failure is never
    reported as a success-shaped empty stream.
    """
    try:
        return urlopen(Request(url, headers=headers or {}), timeout=SSE_READ_TIMEOUT)
    except HTTPError as error:
        return JsonResponse(
            {"error": f"engine stream rejected: {error}", "reason": "ENGINE_STREAM_REJECTED"},
            status=502,
        )
    except URLError as error:
        return JsonResponse(
            {"error": f"engine unavailable: {error.reason}", "reason": "ENGINE_UNAVAILABLE"},
            status=502,
        )
    except (TimeoutError, socket.timeout) as error:
        return JsonResponse(
            {
                "error": f"engine stream did not open within {SSE_READ_TIMEOUT:g}s",
                "reason": "ENGINE_STREAM_TIMEOUT",
            },
            status=502,
        )
    except OSError as error:
        return JsonResponse(
            {"error": f"engine stream failed: {error}", "reason": "ENGINE_STREAM_FAILED"},
            status=502,
        )

# The module logger records lifecycle metadata without request secrets.
logger = logging.getLogger(__name__)


def _outbound_runtime():
    return get_outbound_runtime()


def _route_switch_cancelled(kind):
    return JsonResponse(
        {
            "error": f"{kind} was cancelled by the route switch",
            "reason": "ROUTE_CHANGED",
        },
        status=409,
    )


# Django owns the browser-facing API; the Go engine owns outbound HTTP work.
@ensure_csrf_cookie
def index(request):
    """Render the single-page lab interface."""
    active_project = getattr(request, "active_project", None)
    return render(request, "lab/index.html", {
        "active_project_id": active_project.id if active_project else "",
    })


def project_event_status(request):
    """Report whether the current server can serve project WebSocket events."""
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    return JsonResponse({"websocket": project_event_hub.websocket_supported})


@csrf_exempt
def projects(request, project_id=None):
    """List, create, update and delete workspace projects."""
    if request.method == "GET":
        queryset = Project.objects.order_by("-updated_at")
        if project_id is not None:
            project = queryset.filter(id=project_id).first()
            if not project:
                return JsonResponse({"error": "project not found"}, status=404)
            return JsonResponse(project_item(project, include_notes=True))
        return JsonResponse({"items": [project_item(project) for project in queryset]})
    if request.method not in {"POST", "PATCH", "PUT", "DELETE"}:
        return JsonResponse({"error": "method not allowed"}, status=405)
    if request.method == "DELETE":
        if project_id is None:
            return JsonResponse({"error": "project_id is required"}, status=400)
        deleted, _ = Project.objects.filter(id=project_id).delete()
        return JsonResponse({"ok": True, "deleted": bool(deleted)})
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid project: {error}"}, status=400)
    project = Project.objects.filter(id=project_id).first() if project_id is not None else Project()
    if project_id is not None and not project:
        return JsonResponse({"error": "project not found"}, status=404)
    if "name" in payload:
        name = str(payload["name"]).strip()
        if not name:
            return JsonResponse({"error": "name is required"}, status=400)
        project.name = name
    elif project_id is None:
        return JsonResponse({"error": "name is required"}, status=400)
    try:
        if "target" in payload:
            project.target = str(payload["target"]).strip()
        for field in ("environment", "route_profile"):
            if field in payload:
                setattr(project, field, str(payload[field]).strip())
        if "tech_stack" in payload:
            project.tech_stack = normalize_tech_stack(payload["tech_stack"])
        if "notes" in payload:
            project.notes = normalize_project_notes(payload["notes"])
    except ProjectContextError as error:
        return JsonResponse({"error": str(error), "reason": "INVALID_PROJECT_CONTEXT"}, status=400)
    if "metadata" in payload:
        if not isinstance(payload["metadata"], dict):
            return JsonResponse({"error": "metadata must be an object"}, status=400)
        project.metadata = payload["metadata"]
    if "schema_version" in payload:
        try:
            project.schema_version = max(1, int(payload["schema_version"]))
        except (TypeError, ValueError):
            return JsonResponse({"error": "schema_version must be numeric"}, status=400)
    try:
        project.save()
    except Exception as error:
        logger.warning("project_save_failed reason=%s", error.__class__.__name__)
        return JsonResponse({"error": "project could not be saved"}, status=409)
    return JsonResponse(project_item(project, include_notes=True), status=201 if project_id is None else 200)


def project_hub(request, project_id):
    """Return the active Project knowledge-base dashboard without raw secrets."""
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    project = Project.objects.filter(id=project_id).first()
    if not project:
        return JsonResponse({"error": "project not found"}, status=404)
    for target_job in TargetJob.objects.filter(project=project).only(
        "id", "result", "status", "ingested"
    ):
        if target_job.status in {"completed", "cancelled", "failed", "error"}:
            _ingest_target_job(target_job)
    traffic = TrafficRecord.objects.filter(project=project)
    entities = list(
        OsintEntity.objects.filter(graph__project=project)
        .values("entity_type")
        .annotate(count=Count("id"))
        .order_by("entity_type")
    )
    graphs = list(
        OsintGraph.objects.filter(project=project)
        .values("id", "name", "version", "status", "updated_at")
        .order_by("-updated_at")
    )
    graph_ids = [item["id"] for item in graphs]
    graph_counts = {
        graph_id: {
            "entities": OsintEntity.objects.filter(graph_id=graph_id).count(),
            "relations": OsintRelation.objects.filter(graph_id=graph_id).count(),
        }
        for graph_id in graph_ids
    }
    endpoints = ProjectEndpoint.objects.filter(project=project).values(
        "id", "method", "path", "sample_url", "statuses", "parameters", "first_seen", "last_seen"
    )
    secret_refs = ProjectSecret.objects.filter(project=project).values(
        "id", "secret_type", "key_name", "value_ref", "source_url", "created_at", "updated_at"
    )
    endpoint_items = [
        {**item, "first_seen": item["first_seen"].isoformat(), "last_seen": item["last_seen"].isoformat()}
        for item in endpoints
    ]
    secret_items = [
        {**item, "created_at": item["created_at"].isoformat(), "updated_at": item["updated_at"].isoformat()}
        for item in secret_refs
    ]
    return JsonResponse({
        "project": project_item(project, include_notes=True),
        "metrics": {
            "traffic": traffic.count(),
            "endpoints": ProjectEndpoint.objects.filter(project=project).count(),
            "target_jobs": TargetJob.objects.filter(project=project).count(),
            "scans": ScannerRun.objects.filter(project=project).count(),
            "open_ports": sum(item["count"] for item in entities if item["entity_type"] == "port"),
        },
        "tech_stack": project.tech_stack or {},
        "endpoints": endpoint_items,
        "secret_references": secret_items,
        "scanner_runs": [scan_run_item(item) for item in ScannerRun.objects.filter(project=project).order_by("-created_at")],
        "workflows": [workflow_item(item) for item in Workflow.objects.filter(project=project).order_by("-updated_at")],
        "osint_entity_types": entities,
        "osint_graphs": [
            {
                **item,
                "updated_at": item["updated_at"].isoformat(),
                **graph_counts.get(item["id"], {"entities": 0, "relations": 0}),
            }
            for item in graphs
        ],
        "ai_snapshot": ProjectContextBuilder(project.id).build_summary_markdown(include_notes=False),
    })


@csrf_exempt
def project_export(request, project_id):
    """Export one Project and every record scoped to it as a transfer bundle.

    The document is a complete copy of the workspace rather than a sample, and
    it is the one export that carries raw request and response bodies: the whole
    point of a bundle is that the imported workspace still holds the evidence.
    """
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    project = Project.objects.filter(id=project_id).first()
    if not project:
        return JsonResponse({"error": "project not found"}, status=404)
    return JsonResponse(export_bundle(project))


@csrf_exempt
def project_import(request):
    """Recreate an exported Project bundle as a new workspace.

    The import always creates a sibling Project. A merge would have to decide per
    record type whether an incoming row overwrites an existing one or becomes a
    second one, and getting that wrong would rewrite evidence the workspace
    already held; a new Project leaves both sides verifiable.
    """
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = parse_bundle_body(request.body)
    except ProjectTransferError as error:
        return JsonResponse({"error": str(error), "reason": "INVALID_PROJECT_BUNDLE"}, status=400)
    try:
        project, report = import_bundle(payload)
    except ProjectTransferError as error:
        return JsonResponse({"error": str(error), "reason": "INVALID_PROJECT_BUNDLE"}, status=400)
    except Exception as error:  # noqa: BLE001 - a store failure must not read as a half-made import
        logger.warning("project_import_failed reason=%s", error.__class__.__name__)
        return JsonResponse({"error": "project bundle could not be imported", "reason": "PROJECT_IMPORT_FAILED"}, status=409)
    return JsonResponse({"project": project_item(project, include_notes=True), "report": report}, status=201)


def _active_project(request, explicit_id=None):
    """Use the validated session Project unless a durable record already names one."""
    if getattr(request, "active_project", None):
        return request.active_project
    if explicit_id not in (None, ""):
        return Project.objects.filter(id=explicit_id).first()
    return None


def _retry_sqlite_locked(operation):
    """Retry short SQLite writer contention without hiding other DB errors."""
    for attempt in range(6):
        try:
            return operation()
        except OperationalError as error:
            if "locked" not in str(error).lower() or attempt == 5:
                raise
            close_old_connections()
            time.sleep(0.05 * (attempt + 1))


def _ingest_target_result(project, result):
    _retry_sqlite_locked(lambda: _ingest_target_result_once(project, result))


def _ingest_target_job(job):
    """Index one finished Target job into its Project, exactly once.

    Reading the Project knowledge base must not rewrite it. Re-indexing every
    finished job on every dashboard read made a single read cost one write per
    page the crawl ever found, so a 500-page map pushed the Project hub past a
    second and a 1000-page map past two, growing with the crawl instead of with
    the read. The `ingested` flag keeps the fallback for a job that finished
    without being polled while a settled job costs nothing, and a failed ingest
    leaves the flag clear so the next read retries it.
    """
    if not job or job.ingested or not job.project:
        return
    _ingest_target_result(job.project, job.result)
    TargetJob.objects.filter(id=job.id).update(ingested=True)


def _ingest_target_result_once(project, result):
    """Index completed Target pages as endpoint metadata and OSINT URLs."""
    if not project or not isinstance(result, dict):
        return
    pages = result.get("pages") or result.get("resources") or []
    entities = []
    for page in pages:
        if not isinstance(page, dict):
            continue
        url = str(page.get("url") or "").strip()
        if not url:
            continue
        project.register_endpoint(url, page.get("method", "GET"), page.get("status"))
        entities.append({"type": "url", "identity": url, "properties": {"source": "target"}})
    if entities:
        graph, _ = OsintGraph.objects.get_or_create(
            project=project, version=1,
            defaults={"name": "Target observations", "source": "target"},
        )
        upsert_graph(graph, {"entities": entities, "relations": []})


def _ingest_osint_result(project, result):
    _retry_sqlite_locked(lambda: _ingest_osint_result_once(project, result))


def _ingest_osint_result_once(project, result):
    """Persist passive OSINT metadata in the active Project graph."""
    if not project or not isinstance(result, dict):
        return
    graph, _ = OsintGraph.objects.get_or_create(
        project=project, version=1,
        defaults={"name": "Passive OSINT observations", "source": "osint"},
    )
    entities = []
    target_url = str(result.get("url") or "").strip()
    if target_url:
        entities.append({"type": "url", "identity": target_url, "properties": {"source": "osint"}})
    host = str(result.get("host") or "").split(":", 1)[0]
    if host:
        entities.append({"type": "domain", "identity": host, "properties": {"source": "osint"}})
    dns = result.get("dns") or {}
    for ip in dns.get("host", []) if isinstance(dns, dict) else []:
        entities.append({"type": "ip", "identity": ip, "properties": {"source": "osint"}})
    for technology in result.get("technologies") or []:
        entities.append({"type": "technology", "identity": technology, "properties": {"source": "osint"}})
    if entities:
        upsert_graph(graph, {"entities": entities, "relations": []})
    for technology in result.get("technologies") or []:
        stack = dict(project.tech_stack or {})
        values = stack.get("osint", [])
        values = values if isinstance(values, list) else [values]
        if technology not in values:
            values.append(technology)
        stack["osint"] = values
        project.tech_stack = stack
    project.save(update_fields=["tech_stack", "updated_at"])


_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _ingest_scanner_run(project, engine, url, findings, stats, templates=None):
    _retry_sqlite_locked(
        lambda: _ingest_scanner_run_once(project, engine, url, findings, stats, templates)
    )


def _scanner_template_summary(templates):
    """Reduce the per-file template report to the durable per-file journal."""
    rows = []
    for item in templates or []:
        if not isinstance(item, dict):
            continue
        rows.append({
            "name": str(item.get("name", "")),
            "template_id": str(item.get("template_id", "")),
            "severity": str(item.get("severity") or "").upper(),
            "status": str(item.get("status", "")),
            "reason": str(item.get("reason", "")),
            "cve": [str(value) for value in item.get("cve") or []],
            "matches": int(item.get("matches") or 0),
        })
    return rows


def _durable_scanner_stats(stats):
    """Keep the durable facts of a run in the project journal.

    The binary's raw stdout and stderr stay in the run report the operator
    reads in the UI and in the API response, in full. They are not copied into
    the long-lived journal row, because a console log of a finished run is not
    project evidence and would grow the database without bound. Nothing is
    summarised or trimmed: the stream is either kept whole or not kept here.
    """
    if not isinstance(stats, dict):
        return {}
    durable = {key: value for key, value in stats.items() if key not in {"stdout", "stderr"}}
    if "stdout" in stats or "stderr" in stats:
        durable["full_output"] = "run report"
    return durable


def _ingest_scanner_run_once(project, engine, url, findings, stats, templates=None):
    """Append one scanner run to the project journal (evidence log, no triage)."""
    if not project:
        return
    items = []
    for item in findings or []:
        if not isinstance(item, dict):
            continue
        items.append({
            "title": str(item.get("title", "")),
            "severity": str(item.get("severity") or "INFO").upper(),
            "evidence": str(item.get("evidence", "")),
            "recommendation": str(item.get("recommendation", "")),
            "template_id": str(item.get("template_id", "")),
            "cve": [str(value) for value in item.get("cve") or []],
        })
    severities = sorted(
        {str(item.get("severity") or "INFO").upper() for item in items},
        key=lambda level: _SEVERITY_RANK.get(level, 9),
    )
    ScannerRun.objects.create(
        project=project,
        engine=engine,
        url=str(url or ""),
        summary={
            "findings_count": len(items),
            "highest_severity": severities[0] if severities else "INFO",
            "stats": _durable_scanner_stats(stats),
            "templates": _scanner_template_summary(templates),
        },
        findings=items,
    )


def _ingest_scanner_tech(project, result):
    """Persist scanner technology observations for the Project."""
    if not project or not isinstance(result, dict):
        return
    technologies = (result.get("details") or {}).get("technologies") or []
    if technologies:
        stack = dict(project.tech_stack or {})
        values = stack.get("scanner", [])
        values = values if isinstance(values, list) else [values]
        stack["scanner"] = sorted(set(values + [str(item) for item in technologies]))
        project.tech_stack = stack
        project.save(update_fields=["tech_stack", "updated_at"])


@csrf_protect
def project_context(request):
    """Set or clear the validated server-side active Project context."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid project context: {error}"}, status=400)
    raw_project_id = payload.get("project_id")
    project = None
    if raw_project_id not in (None, ""):
        if isinstance(raw_project_id, bool):
            return JsonResponse({"error": "project_id must be numeric or null"}, status=400)
        try:
            project_id = int(raw_project_id)
        except (TypeError, ValueError):
            return JsonResponse({"error": "project_id must be numeric or null"}, status=400)
        if project_id <= 0:
            return JsonResponse({"error": "project_id must be numeric or null"}, status=400)
        project = Project.objects.filter(id=project_id).first()
        if not project:
            return JsonResponse({"error": "project not found"}, status=404)
        request.session[ACTIVE_PROJECT_SESSION_KEY] = project.id
    else:
        request.session.pop(ACTIVE_PROJECT_SESSION_KEY, None)
    request.session.modified = True
    request.active_project = project
    return JsonResponse({
        "active_project_id": project.id if project else None,
        "active_project": project_item(project) if project else None,
    })


def scan_run_item(run):
    return {
        "id": run.id,
        "project_id": run.project_id,
        "engine": run.engine,
        "url": run.url,
        "summary": run.summary,
        "findings": run.findings,
        "created_at": run.created_at.isoformat(),
    }


def project_item(project, *, include_notes=False):
    data = {
        "id": project.id,
        "name": project.name,
        "target": project.target,
        "environment": project.environment,
        "route_profile": project.route_profile,
        "tech_stack": project.tech_stack or {},
        "metadata": project.metadata,
        "schema_version": project.schema_version,
        "created_at": project.created_at.isoformat(),
        "updated_at": project.updated_at.isoformat(),
    }
    if include_notes:
        data["notes"] = project.notes or ""
    return data


def history(request):
    """Return filtered and sorted durable History records.

    The response shape is unchanged: `{"items": [...]}`. `limit` and `offset` are
    optional and default to the full result set, so existing callers are
    unaffected. A record carries complete request and response bodies, so
    serialising an unbounded History costs time and bytes proportional to every
    stored body; `select_related` keeps the per-row capture-context access out
    of the query path, and callers that only need a page should pass `limit`.
    """
    # History is persisted in SQLite, unlike the in-memory passive Store.
    # `id` is the tiebreaker: a burst of exchanges shares a timestamp often
    # enough that ordering by time alone lets `limit`/`offset` pages repeat or
    # skip rows between two identical requests.
    records = TrafficRecord.objects.select_related("capture_context").filter(
        source__in=("repeater", "intruder", "last-byte")
    ).order_by("-timestamp", "-id")
    query = request.GET.get("q", "").strip()
    if query:
        records = records.filter(
            Q(url__icontains=query) | Q(request_body__icontains=query) |
            Q(response_body__icontains=query) | Q(host__icontains=query) |
            Q(notes__icontains=query) | Q(tags__icontains=query)
        )
    if request.GET.get("host"):
        records = records.filter(host__icontains=request.GET["host"].strip())
    if request.GET.get("path"):
        records = records.filter(url__icontains=request.GET["path"].strip())
    if request.GET.get("method"):
        records = records.filter(method__iexact=request.GET["method"].strip())
    if request.GET.get("status"):
        # An unparsable status must be a client error, not a lazy ValueError
        # escaping from queryset evaluation as HTTP 500.
        try:
            records = records.filter(status_code=int(request.GET["status"]))
        except (TypeError, ValueError):
            return JsonResponse({"error": "status must be numeric"}, status=400)
    if request.GET.get("mime"):
        records = records.filter(response_content_type__icontains=request.GET["mime"].strip())
    if request.GET.get("body"):
        records = records.filter(response_body__icontains=request.GET["body"])
    for parameter, field in (("size_min", "response_size__gte"), ("size_max", "response_size__lte"),
                             ("latency_min", "latency_ms__gte"), ("latency_max", "latency_ms__lte")):
        if request.GET.get(parameter):
            try:
                records = records.filter(**{field: int(request.GET[parameter])})
            except ValueError:
                return JsonResponse({"error": f"{parameter} must be numeric"}, status=400)
    sort = request.GET.get("sort", "-timestamp")
    if sort in {
        "timestamp", "-timestamp", "host", "-host", "method", "-method",
        "url", "-url", "status_code", "-status_code", "response_size",
        "-response_size",
    }:
        records = records.order_by(sort)

    # `detail=summary` lists the columns a table row shows and leaves the
    # captured payload to the inspector, which loads the complete record for the
    # row the operator opens. Anything other than `full` or `summary` is a client
    # error rather than a silently different payload.
    detail = request.GET.get("detail", "full").strip().lower()
    if detail not in {"full", "summary"}:
        return JsonResponse({"error": "detail must be full or summary"}, status=400)

    # Optional paging. Omitted parameters keep the historical full-list
    # behaviour; supplying them lets a caller fetch one window of History
    # without serialising every stored body.
    offset = 0
    limit = None
    if request.GET.get("offset"):
        try:
            offset = int(request.GET["offset"])
        except (TypeError, ValueError):
            return JsonResponse({"error": "offset must be numeric"}, status=400)
        if offset < 0:
            return JsonResponse({"error": "offset must not be negative"}, status=400)
    if request.GET.get("limit"):
        try:
            limit = int(request.GET["limit"])
        except (TypeError, ValueError):
            return JsonResponse({"error": "limit must be numeric"}, status=400)
        if limit < 0:
            return JsonResponse({"error": "limit must not be negative"}, status=400)
        records = records[offset:offset + limit] if limit else records.none()
    elif offset:
        records = records[offset:]

    return stream_history_items(records, omit_bodies=detail == "summary")


# The exact columns `history_item` reads. Selecting them explicitly lets Django
# build plain rows from the cursor instead of constructing one model instance per
# record, which is where almost all of the time went on a large History.
HISTORY_ITEM_FIELDS = (
    "id", "timestamp", "source", "host", "source_ip", "method", "url",
    "request_headers", "request_body", "status_code", "latency_ms",
    "response_headers", "response_body", "request_body_encoding",
    "request_body_base64", "response_body_encoding", "response_body_base64",
    "response_content_type", "response_size", "tags", "notes",
    "proxy_event_id", "proxy_session", "capture_context_id", "scope_status",
)


def history_item_from_row(row, omit_bodies: bool = False):
    """Serialize a `values()` row into the same shape as `history_item`.

    The payload columns are always present, so a consumer reads the same keys
    either way; `omit_bodies` only leaves them empty for a row it has not opened
    yet, and the row's `response_size` still reports how large the real body is.
    """
    empty = "" if omit_bodies else None
    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "source": row["source"],
        "host": row["host"],
        "source_ip": row["source_ip"] or "",
        "method": row["method"],
        "url": row["url"],
        "request_headers": empty if omit_bodies else row["request_headers"],
        "request_body": "" if omit_bodies else (row["request_body"] or ""),
        "status": row["status_code"],
        "time": row["latency_ms"],
        "response_headers": empty if omit_bodies else row["response_headers"],
        "response_body": "" if omit_bodies else (row["response_body"] or ""),
        "request_body_encoding": row["request_body_encoding"],
        "request_body_base64": empty if omit_bodies else row["request_body_base64"],
        "response_body_encoding": row["response_body_encoding"],
        "response_body_base64": empty if omit_bodies else row["response_body_base64"],
        "response_content_type": row["response_content_type"],
        "response_size": row["response_size"],
        "tags": row["tags"],
        "notes": row["notes"],
        "proxy_event_id": row["proxy_event_id"],
        "proxy_session": row["proxy_session"],
        "capture_context_id": row["capture_context_id"],
        "capture_context_name": row.get("capture_context__name") or "",
        "scope_status": row["scope_status"],
    }


# Above this many records History is streamed in batches. It is a transport
# choice, not a data limit: every record is still returned, and a smaller result
# is still returned in one response.
HISTORY_STREAM_THRESHOLD = 500
# How much serialised History is buffered before it is handed to the browser.
# Large enough to keep the number of writes low, small enough that the first
# records reach the UI without waiting for the whole document.
HISTORY_STREAM_CHUNK_BYTES = 512 * 1024


# The columns that carry the captured payload. A History row shows host, method,
# URL, status and time, so reading the payload for every listed row made the
# window cost the size of every stored body: five hundred rows of one burst came
# to 68 MB and the tab stopped responding. `detail=summary` leaves these out and
# the inspector loads the complete record for the row the operator opens, so
# nothing is hidden and only what is on screen is transferred.
HISTORY_BODY_FIELDS = (
    "request_headers", "request_body", "response_headers", "response_body",
    "request_body_base64", "response_body_base64",
)


def stream_history_items(records, batch_size: int = 2000, omit_bodies: bool = False):
    """Send History as a streamed `{"items": [...]}` document.

    The payload is identical to the previous single-response body, but the first
    records reach the browser as soon as the cursor produces them instead of
    after every stored body has been materialised and serialised. Rows are read
    in batches, so the process no longer holds the whole History in memory while
    it answers a request.

    A small result is still returned as one `JsonResponse`: streaming buys
    nothing there, and callers that read the body as text keep working.
    """
    fields = HISTORY_ITEM_FIELDS
    if omit_bodies:
        fields = tuple(
            name for name in HISTORY_ITEM_FIELDS if name not in HISTORY_BODY_FIELDS
        )
    rows = records.values(*fields, "capture_context__name")
    total = records.count()
    if total <= HISTORY_STREAM_THRESHOLD:
        return JsonResponse({
            "items": [history_item_from_row(row, omit_bodies) for row in rows],
            "bodies_omitted": omit_bodies,
        })

    def generate():
        # The flag is written into the document header so a streamed listing
        # tells the client exactly as much as a single-response listing does.
        yield b'{"bodies_omitted": ' + (b"true" if omit_bodies else b"false") + b', "items": ['
        # One buffer per batch: yielding per row would add two hundred thousand
        # small writes, which is slower than the single response it replaced.
        buffer = bytearray()
        for row in rows.iterator(chunk_size=batch_size):
            if buffer:
                buffer += b", "
            buffer += json.dumps(
                history_item_from_row(row, omit_bodies), ensure_ascii=False, default=str
            ).encode()
            if len(buffer) >= HISTORY_STREAM_CHUNK_BYTES:
                yield bytes(buffer)
                buffer = bytearray()
        if buffer:
            yield bytes(buffer)
        yield b"]}"

    result = StreamingHttpResponse(generate(), content_type="application/json")
    result["Cache-Control"] = "no-store"
    return result


@csrf_exempt
def history_detail(request, record_id=None):
    """Read, update or delete one History record through the browser-facing API."""
    if request.method == "GET":
        # The listing can be asked for row columns only, so the inspector asks
        # for the complete record here: the payload is never dropped, it is
        # simply read when a row is actually opened.
        try:
            record = TrafficRecord.objects.select_related("capture_context").get(id=record_id)
        except TrafficRecord.DoesNotExist:
            return JsonResponse({"error": "history record not found"}, status=404)
        return JsonResponse(history_item(record))
    if request.method == "DELETE":
        TrafficRecord.objects.filter(id=record_id).delete()
        return JsonResponse({"ok": True})
    if request.method in {"PATCH", "PUT"}:
        try:
            payload = json.loads(request.body)
            record = TrafficRecord.objects.get(id=record_id)
            if "tags" in payload:
                if not isinstance(payload["tags"], list):
                    raise ValueError("tags must be a list")
                record.tags = [str(tag) for tag in payload["tags"]]
            if "notes" in payload:
                record.notes = str(payload["notes"])
            record.save(update_fields=["tags", "notes"])
            return JsonResponse(history_item(record))
        except TrafficRecord.DoesNotExist:
            return JsonResponse({"error": "history record not found"}, status=404)
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            return JsonResponse({"error": f"invalid metadata: {error}"}, status=400)
    return JsonResponse({"error": "method not allowed"}, status=405)


def history_item(record):
    """Serialize a TrafficRecord into the stable UI/API representation."""
    return {
        "id": record.id,
        "timestamp": record.timestamp,
        "source": record.source,
        "host": record.host,
        "source_ip": record.source_ip or "",
        "method": record.method,
        "url": record.url,
        "request_headers": record.request_headers,
        "request_body": record.request_body or "",
        "status": record.status_code,
        "time": record.latency_ms,
        "response_headers": record.response_headers,
        "response_body": record.response_body or "",
        "request_body_encoding": record.request_body_encoding,
        "request_body_base64": record.request_body_base64,
        "response_body_encoding": record.response_body_encoding,
        "response_body_base64": record.response_body_base64,
        "response_content_type": record.response_content_type,
        "response_size": record.response_size,
        "tags": record.tags,
        "notes": record.notes,
        "proxy_event_id": record.proxy_event_id,
        "proxy_session": record.proxy_session,
        "capture_context_id": record.capture_context_id,
        "capture_context_name": record.capture_context.name if record.capture_context_id else "",
        "scope_status": record.scope_status,
    }


def persist_intruder_history(attack_id, results, result_offset=0, project_id=None):
    """Persist each completed Intruder exchange once for durable History.

    The engine returns an incremental slice, but every poll re-offers the same
    window, so the previous implementation issued one indexed `exists()` probe
    plus one `INSERT` per result on every poll. This version resolves the whole
    window with a single indexed query, writes the genuinely new rows in one
    `bulk_create`, and folds the knowledge-base work into one pass.
    """
    if not isinstance(results, list) or not results:
        return

    candidates = []
    for index, result in enumerate(results, start=result_offset):
        if not isinstance(result, dict):
            continue
        request_data = result.get("request") or {}
        if not isinstance(request_data, dict) or not request_data.get("url"):
            continue
        candidates.append((index, result, request_data))
    if not candidates:
        return

    # One indexed lookup for the entire window instead of one probe per result.
    known_ids = set(
        TrafficRecord.objects.filter(
            source="intruder",
            proxy_session=attack_id,
            proxy_event_id__in=[index for index, _, _ in candidates],
        ).values_list("proxy_event_id", flat=True)
    )

    pending = []
    for index, result, request_data in candidates:
        if index in known_ids:
            continue
        response_headers = result.get("headers") or {}
        pending.append(TrafficRecord(
            project_id=project_id,
            source="intruder",
            host=urlsplit(request_data["url"]).netloc,
            source_ip=result.get("source_ip") or None,
            proxy_event_id=index,
            proxy_session=attack_id,
            method=request_data.get("method", "GET"),
            url=request_data["url"],
            request_headers=request_data.get("headers") or {},
            request_body=request_data.get("body") or "",
            request_body_encoding=request_data.get("body_encoding", "utf8"),
            request_body_base64=request_data.get("body_base64", ""),
            response_headers=response_headers,
            response_body=result.get("body") or "",
            response_body_encoding=result.get("body_encoding", "utf8"),
            response_body_base64=result.get("body_base64", ""),
            response_content_type=result.get("body_content_type", response_headers.get("Content-Type", "")),
            status_code=result.get("status"),
            latency_ms=result.get("time"),
            response_size=result.get("size"),
        ))
    if not pending:
        return

    # bulk_create bypasses post_save, so the knowledge base is updated explicitly.
    TrafficRecord.objects.bulk_create(pending, batch_size=200)
    ingest_traffic_batch(pending)


def _capture_context_for_event(event, cache=None):
    """Resolve an explicit capture token without applying a URL policy.

    `cache` is an optional token -> context mapping. A Traffic snapshot calls
    this once per event, so the caller resolves every distinct token in a single
    query and passes the mapping down instead of re-querying per event.
    """
    token = str(event.get("capture_context") or "").strip()
    if not token:
        return None, "unscoped"
    if cache is not None and token in cache:
        context = cache[token]
    else:
        context = TrafficCaptureContext.objects.select_related("project").filter(token=token).first()
        if cache is not None:
            cache[token] = context
    if not context:
        return None, "invalid_context"
    return context, "project_linked" if context.project_id else "unscoped"


def public_traffic_event(event, cache=None):
    """Return UI-safe Traffic metadata without exposing the capture token."""
    if not isinstance(event, dict):
        return event
    context, scope_status = _capture_context_for_event(event, cache=cache)
    result = dict(event)
    result.pop("capture_context", None)
    result["scope_status"] = scope_status
    if context:
        result["capture_context_id"] = context.id
        result["capture_context_name"] = context.name
    else:
        result["capture_context_id"] = None
        result["capture_context_name"] = ""
    return result


def public_traffic_events(events):
    """Map a Traffic snapshot, resolving every distinct capture token once."""
    # A summary snapshot arrives wrapped so the engine can flag what it left out.
    # Unwrapping it here keeps one shape at the browser: always a list of events.
    if isinstance(events, dict) and isinstance(events.get("events"), list):
        events = events["events"]
    if not isinstance(events, list):
        return events
    cache = capture_contexts_by_token(
        event.get("capture_context") for event in events if isinstance(event, dict)
    )
    return [public_traffic_event(event, cache=cache) for event in events]


def persist_proxy_history(events, project_id=None):
    """Persist completed passive proxy exchanges once for durable History.

    `GET /api/traffic` hands this the engine's entire in-memory snapshot on every
    poll, so the previous per-event `filter().first()` probe and `create()` call
    scaled with the size of the live store rather than with the number of new
    events. The batch below costs three queries plus one `bulk_create`
    regardless of how large the snapshot is.
    """
    if not isinstance(events, list) or not events:
        return

    # Resolve every distinct capture token for the whole batch in one query.
    context_cache = capture_contexts_by_token(
        event.get("capture_context") for event in events if isinstance(event, dict)
    )

    candidates = []
    for event in events:
        if not isinstance(event, dict) or not event.get("url"):
            continue
        source = event.get("source") or "proxy"
        if source not in ("proxy", "route-check", "repeater"):
            continue
        if event.get("status") is None and not event.get("error"):
            continue
        candidates.append((event, source))
    if not candidates:
        return

    # One indexed lookup for every (source, session, event) key in the snapshot.
    sources = {source for _, source in candidates}
    sessions = {event.get("session") for event, _ in candidates if event.get("session") is not None}
    lookup = Q()
    for source in sources:
        for session in sessions:
            lookup |= Q(source=source, proxy_session=session)
    existing = {}
    if lookup:
        for record in TrafficRecord.objects.filter(lookup).values(
            "id", "source", "proxy_session", "proxy_event_id", "source_ip"
        ):
            existing[(record["source"], record["proxy_session"], record["proxy_event_id"])] = record

    pending = []
    ip_updates = []
    for event, source in candidates:
        event_id = event.get("id")
        session = event.get("session")
        if event_id is not None:
            found = existing.get((source, session, event_id))
            if found is not None:
                source_ip = event.get("source_ip") or None
                if source_ip and found["source_ip"] != source_ip:
                    ip_updates.append(TrafficRecord(id=found["id"], source_ip=source_ip))
                continue
        if source == "repeater":
            continue
        capture_context, scope_status = _capture_context_for_event(event, cache=context_cache)
        response_headers = event.get("response_headers") or {}
        pending.append(TrafficRecord(
            source=source,
            host=event.get("host", ""),
            source_ip=event.get("source_ip") or None,
            proxy_event_id=event_id,
            proxy_session=session,
            capture_context=capture_context,
            scope_status=scope_status,
            project_id=capture_context.project_id if capture_context else project_id,
            method=event.get("method", "GET"),
            url=event["url"],
            request_headers=event.get("request_headers") or {},
            request_body=event.get("request_body") or "",
            request_body_encoding=event.get("request_body_encoding", "utf8"),
            request_body_base64=event.get("request_body_base64", ""),
            response_headers=response_headers,
            response_body=event.get("response_body") or "",
            response_body_encoding=event.get("response_body_encoding", "utf8"),
            response_body_base64=event.get("response_body_base64", ""),
            response_content_type=event.get(
                "response_content_type", response_headers.get("Content-Type", "")
            ),
            status_code=event.get("status") or None,
            latency_ms=event.get("latency_ms") or None,
            response_size=event.get("response_size") if event.get("response_size") is not None else None,
            tags=event.get("tags") or [],
            notes=event.get("notes") or "",
        ))

    if ip_updates:
        TrafficRecord.objects.bulk_update(ip_updates, ["source_ip"], batch_size=200)
    if not pending:
        return

    # bulk_create bypasses post_save, so the knowledge base is updated explicitly.
    TrafficRecord.objects.bulk_create(pending, batch_size=200)
    ingest_traffic_batch(pending)


def history_export(request):
    """Download all History records as a portable JSON document."""
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    records = TrafficRecord.objects.filter(source__in=("repeater", "intruder", "last-byte")).order_by("timestamp", "id")
    ids = [value for value in request.GET.get("ids", "").split(",") if value.isdigit()]
    if ids:
        records = records.filter(id__in=ids)
    payload = {
        "format": "intruder-lab-history",
        "version": 1,
        "items": [history_item(record) for record in records],
    }
    response = HttpResponse(
        json.dumps(payload, ensure_ascii=False, default=str, indent=2),
        content_type="application/json",
    )
    response["Content-Disposition"] = 'attachment; filename="intruder-history.json"'
    return response


@csrf_exempt
def history_import(request):
    """Create new History records from an exported JSON document."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        # Accept both the documented object format and a raw list for compatibility.
        payload = json.loads(request.body)
        items = payload.get("items") if isinstance(payload, dict) else payload
        if not isinstance(items, list):
            raise ValueError("items must be a list")
        imported = 0
        # Import creates new IDs and timestamps rather than overwriting local rows.
        for item in items:
            if not isinstance(item, dict) or not item.get("url"):
                raise ValueError("each history item must contain a URL")
            TrafficRecord.objects.create(
                source=item.get("source", "repeater"),
                host=item.get("host", ""),
                source_ip=item.get("source_ip") or None,
                proxy_event_id=item.get("proxy_event_id"),
                proxy_session=item.get("proxy_session"),
                method=item.get("method", "GET"),
                url=item["url"],
                request_headers=item.get("request_headers") or {},
                request_body=item.get("request_body") or "",
                request_body_encoding=item.get("request_body_encoding", "utf8"),
                request_body_base64=item.get("request_body_base64", ""),
                response_headers=item.get("response_headers") or {},
                response_body=item.get("response_body") or "",
                response_body_encoding=item.get("response_body_encoding", "utf8"),
                response_body_base64=item.get("response_body_base64", ""),
                response_content_type=item.get("response_content_type", ""),
                status_code=item.get("status"),
                latency_ms=item.get("time"),
                response_size=item.get("response_size"),
                tags=item.get("tags") or [],
                notes=item.get("notes") or "",
            )
            imported += 1
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid history file: {error}"}, status=400)
    return JsonResponse({"ok": True, "imported": imported}, status=201)


def _current_route_generation():
    operation = current_outbound_operation()
    return operation.generation if operation is not None else None


def call_engine(path, payload, timeout=None):
    """POST JSON to Go and normalize transport errors into API responses."""
    return engine_client(ENGINE_URL).request(
        "POST",
        path,
        payload,
        timeout=timeout,
        route_generation=_current_route_generation(),
    )


# Snapshot and stream are separate so the UI can hydrate first, then stay live.
def call_engine_get(path, timeout=None):
    """GET a read-only engine endpoint such as the Traffic snapshot."""
    return engine_client(ENGINE_URL).request(
        "GET",
        path,
        timeout=timeout,
        route_generation=_current_route_generation(),
    )


def call_engine_delete(path, timeout=None):
    """DELETE an engine resource such as a running Intruder attack."""
    return engine_client(ENGINE_URL).request(
        "DELETE",
        path,
        timeout=timeout,
        route_generation=_current_route_generation(),
    )


def call_engine_action(path, payload):
    """POST an action to an existing engine resource."""
    return engine_client(ENGINE_URL).request(
        "POST",
        path,
        payload,
        route_generation=_current_route_generation(),
    )


def _resolve_active_project_for_oast(request, project_id=None):
    project = getattr(request, "active_project", None)
    if project_id in (None, ""):
        return project
    try:
        project_id_int = int(project_id)
    except (TypeError, ValueError):
        return project
    if project_id_int <= 0:
        return project
    return Project.objects.filter(id=project_id_int).first() or project


@csrf_exempt
def oast_callback(request):
    """Accept an incoming OAST callback and publish a live project event."""
    if request.method not in {"GET", "POST"}:
        return JsonResponse({"error": "method not allowed"}, status=405)

    payload = {}
    if request.method == "GET":
        payload = {"query": dict(request.GET.lists())}
    else:
        raw_body = request.body
        if raw_body:
            try:
                payload = json.loads(raw_body)
            except (TypeError, json.JSONDecodeError):
                payload = {"raw": raw_body.decode(errors="replace")}

    project_id = None
    if isinstance(payload, dict):
        project_id = payload.get("project_id") or request.GET.get("project_id")
    if project_id in (None, ""):
        project_id = getattr(request, "active_project", None).id if getattr(request, "active_project", None) else None
    project = _resolve_active_project_for_oast(request, project_id)

    message = "Incoming OAST callback received"
    if isinstance(payload, dict):
        source = payload.get("source") or payload.get("provider") or payload.get("host")
        if source:
            message = f"OAST callback from {source}"
        elif payload.get("event"):
            message = str(payload.get("event"))
    emit_project_event(
        getattr(project, "id", None),
        {
            "type": "oast",
            "title": "OAST callback",
            "message": message,
            "payload": payload,
        },
    )
    return JsonResponse({"ok": True, "project_id": getattr(project, "id", None), "received": True, "payload": payload}, status=200)


def call_browser_worker(path, payload):
    """Start a browser-driven Target job in the isolated Playwright worker.

    A browser job legitimately runs for minutes, so it gets its own generous
    transport deadline instead of the engine default. Without one, a hung
    Playwright process would pin this request thread indefinitely.
    """
    request = Request(
        f"{BROWSER_WORKER_URL}{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=BROWSER_WORKER_TIMEOUT) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, {"error": error.read().decode(errors="replace"), "reason": "BROWSER_WORKER_ERROR"}
    except (URLError, TimeoutError, RemoteDisconnected, ConnectionError, socket.timeout) as error:
        return 502, {"error": f"browser worker unavailable: {getattr(error, 'reason', error)}", "reason": "BROWSER_WORKER_UNAVAILABLE"}


def call_browser_worker_get(path):
    try:
        with urlopen(f"{BROWSER_WORKER_URL}{path}", timeout=BROWSER_WORKER_TIMEOUT) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, {"error": error.read().decode(errors="replace"), "reason": "BROWSER_WORKER_ERROR"}
    except (URLError, TimeoutError, RemoteDisconnected, ConnectionError, socket.timeout) as error:
        return 502, {"error": f"browser worker unavailable: {getattr(error, 'reason', error)}", "reason": "BROWSER_WORKER_UNAVAILABLE"}


def call_browser_worker_delete(path):
    request = Request(f"{BROWSER_WORKER_URL}{path}", method="DELETE")
    try:
        with urlopen(request, timeout=BROWSER_WORKER_TIMEOUT) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, {"error": error.read().decode(errors="replace"), "reason": "BROWSER_WORKER_ERROR"}
    except (URLError, TimeoutError, RemoteDisconnected, ConnectionError, socket.timeout) as error:
        return 502, {"error": f"browser worker unavailable: {getattr(error, 'reason', error)}", "reason": "BROWSER_WORKER_UNAVAILABLE"}


def traffic_capture_context_item(context):
    return {
        "id": context.id,
        "name": context.name,
        "project_id": context.project_id,
        "active": context.active,
        "record_count": context.traffic_records.count(),
        "created_at": context.created_at.isoformat(),
        "updated_at": context.updated_at.isoformat(),
    }


@csrf_protect
def traffic_capture_contexts(request, context_id=None):
    """Manage explicit local correlation contexts for passive Traffic."""
    if request.method == "GET":
        if context_id is not None:
            context = TrafficCaptureContext.objects.filter(id=context_id).first()
            if not context:
                return JsonResponse({"error": "traffic capture context not found"}, status=404)
            return JsonResponse(traffic_capture_context_item(context))
        contexts = TrafficCaptureContext.objects.select_related("project").order_by("-updated_at")
        return JsonResponse({"items": [traffic_capture_context_item(context) for context in contexts]})

    if request.method == "DELETE":
        if context_id is None:
            return JsonResponse({"error": "context id is required"}, status=400)
        updated = TrafficCaptureContext.objects.filter(id=context_id).update(active=False)
        if not updated:
            return JsonResponse({"error": "traffic capture context not found"}, status=404)
        return JsonResponse({"ok": True, "active": False})

    if request.method not in {"POST", "PATCH", "PUT"}:
        return JsonResponse({"error": "method not allowed"}, status=405)

    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict):
            raise ValueError("request body must be an object")
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid traffic capture context: {error}"}, status=400)

    if request.method == "POST":
        name = str(payload.get("name", "")).strip()
        if not name:
            return JsonResponse({"error": "name is required"}, status=400)
        if "project_id" not in payload:
            return JsonResponse({"error": "project_id is required; use null for unscoped capture"}, status=400)
        project = None
        raw_project_id = payload.get("project_id")
        if raw_project_id not in (None, ""):
            if isinstance(raw_project_id, bool):
                return JsonResponse({"error": "project_id must be numeric or null"}, status=400)
            try:
                project_id = int(raw_project_id)
            except (TypeError, ValueError):
                return JsonResponse({"error": "project_id must be numeric or null"}, status=400)
            if project_id <= 0:
                return JsonResponse({"error": "project_id must be numeric or null"}, status=400)
            project = Project.objects.filter(id=project_id).first()
            if not project:
                return JsonResponse({"error": "project not found"}, status=404)
        context = TrafficCaptureContext.objects.create(name=name, project=project)
        return JsonResponse(traffic_capture_context_item(context), status=201)

    if context_id is None:
        return JsonResponse({"error": "context id is required"}, status=400)
    context = TrafficCaptureContext.objects.filter(id=context_id).first()
    if not context:
        return JsonResponse({"error": "traffic capture context not found"}, status=404)
    if "name" in payload:
        name = str(payload["name"]).strip()
        if not name:
            return JsonResponse({"error": "name is required"}, status=400)
        context.name = name
    if "active" in payload:
        if not isinstance(payload["active"], bool):
            return JsonResponse({"error": "active must be boolean"}, status=400)
        context.active = payload["active"]
    context.save(update_fields=["name", "active", "updated_at"])
    return JsonResponse(traffic_capture_context_item(context))


@csrf_exempt
def traffic(request):
    """Return the current in-memory passive Traffic snapshot or toggle recording."""
    if request.method == "DELETE":
        status, result = call_engine_delete("/events")
        # An unreachable engine did not clear anything. Reporting `ok` here told
        # the operator the live snapshot had been reset when it had not, so the
        # failure is surfaced verbatim instead.
        return JsonResponse(result, status=status)
    if request.method == "POST":
        payload = {}
        if request.body:
            try:
                payload = json.loads(request.body)
            except (ValueError, TypeError):
                return JsonResponse({"error": "invalid JSON"}, status=400)
        action = str((request.GET.get("action") or payload.get("action") or "status")).strip().lower()
        if action not in {"pause", "resume", "status"}:
            return JsonResponse({"error": "action must be pause, resume or status"}, status=400)
        status, result = call_engine_action("/events", {"action": action})
        return JsonResponse(result, status=status)
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    # `detail=summary` asks the engine for the row columns only. The captured
    # payload stays in the engine Store and `/api/traffic/detail?id=` returns the
    # complete event, so nothing is hidden and only what is on screen travels.
    detail = request.GET.get("detail", "full").strip().lower()
    if detail not in {"full", "summary"}:
        return JsonResponse({"error": "detail must be full or summary"}, status=400)
    path = f"/events?detail={detail}" if detail == "summary" else "/events"
    status, result = call_engine_get(path)
    if status == 200:
        persist_proxy_history(result, getattr(request.active_project, "id", None))
        result = public_traffic_events(result)
    return JsonResponse(result, status=status, safe=isinstance(result, dict))


@csrf_exempt
def traffic_detail(request):
    """Return one complete passive Traffic event, payload included.

    The Traffic listing can be asked for row columns only, so opening an event
    reads it here instead of making the listing carry every captured body.
    """
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    event_id = str(request.GET.get("id", "")).strip()
    if not event_id.isdigit() or int(event_id) <= 0:
        return JsonResponse({"error": "id must be a positive integer"}, status=400)
    status, result = call_engine_get(f"/events/detail?id={event_id}")
    if status == 200 and isinstance(result, dict):
        result = public_traffic_event(result)
    return JsonResponse(result, status=status, safe=isinstance(result, dict))


def traffic_stream(request):
    """Proxy the engine SSE stream without buffering individual lines.

    An idle stream used to block in `readline()` forever with no output at all.
    The gateway never observed the browser's disconnect, so the request thread,
    the engine socket and the Python frame leaked for as long as the tab stayed
    open, and one thread was pinned per open tab. Two changes bound that:

      * a bounded read deadline, after which the proxy emits an SSE comment
        heartbeat, which keeps proxies from reaping an idle connection and gives
        the socket a regular write that surfaces a dead client;
      * an overall lifetime, after which the proxy closes and the browser's
        EventSource reconnects cleanly with its cursor.
    """
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    cursor = request.headers.get("Last-Event-ID") or request.GET.get("last_event_id", "")
    stream_url = f"{ENGINE_URL}/events/stream"
    if cursor:
        stream_url += f"?last_event_id={cursor}"
    # open_engine_stream already turns every connection-level failure into an
    # explicit 502, so nothing here has to be distinguished afterwards.
    response = open_engine_stream(stream_url, {"Last-Event-ID": cursor})
    if isinstance(response, JsonResponse):
        return response
    def stream():
        # Read one SSE line at a time so small events reach the browser immediately.
        started = time.monotonic()
        try:
            while time.monotonic() - started < SSE_MAX_LIFETIME:
                try:
                    chunk = response.readline()
                except (TimeoutError, socket.timeout):
                    # Idle upstream: emit a comment frame and keep the loop alive.
                    yield b": keepalive\n\n"
                    continue
                if not chunk:
                    break
                if chunk.startswith(b"data:"):
                    try:
                        event = json.loads(chunk[5:].strip())
                    except (ValueError, TypeError):
                        yield chunk
                        continue
                    yield f"data: {json.dumps(public_traffic_event(event), ensure_ascii=False)}\n".encode()
                else:
                    yield chunk
        except (OSError, ValueError):
            # The browser went away mid-stream; releasing the socket is the point.
            return
        finally:
            response.close()

    result = StreamingHttpResponse(stream(), content_type="text/event-stream")
    result["Cache-Control"] = "no-cache"
    result["X-Accel-Buffering"] = "no"
    return result


@csrf_exempt
def save_traffic(request):
    """Persist one selected passive event into durable History."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        events = payload.get("items") if isinstance(payload, dict) and isinstance(payload.get("items"), list) else [payload]
        persist_proxy_history(events, getattr(request.active_project, "id", None))
        event = events[0] if events else {}
        record = TrafficRecord.objects.filter(
            source="proxy",
            proxy_event_id=event.get("id"),
            proxy_session=event.get("session"),
        ).order_by("-id").first()
        if record is None:
            return JsonResponse({"error": "traffic event must contain a URL"}, status=400)
    except (json.JSONDecodeError, TypeError, ValueError):
        return JsonResponse({"error": "invalid traffic event"}, status=400)
    records = TrafficRecord.objects.filter(source="proxy", proxy_event_id__in=[
        item.get("id") for item in events if isinstance(item, dict) and item.get("id") is not None
    ])
    return JsonResponse({"ok": True, "id": record.id, "ids": list(records.values_list("id", flat=True))}, status=201)


@csrf_exempt
def annotate_traffic(request):
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload.get("tags", []), list):
            raise ValueError("tags must be a list")
        status, result = call_engine_action("/events/annotate", payload)
        return JsonResponse(result, status=status)
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": str(error)}, status=400)


@csrf_exempt
def history_bulk(request):
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        action = payload.get("action")
        if action == "clear":
            count, _ = TrafficRecord.objects.filter(source__in=("repeater", "intruder", "last-byte")).delete()
            return JsonResponse({"ok": True, "deleted": count})
        ids = [int(value) for value in payload.get("ids", [])]
        if not ids or action not in {"delete", "metadata"}:
            raise ValueError("ids and action are required")
        records = TrafficRecord.objects.filter(id__in=ids)
        if action == "delete":
            count, _ = records.delete()
            return JsonResponse({"ok": True, "deleted": count})
        tags = payload.get("tags", [])
        notes = payload.get("notes", "")
        records.update(tags=tags, notes=str(notes))
        return JsonResponse({"ok": True, "updated": records.count()})
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": str(error)}, status=400)


"""Merge UI query/cookie editors into the engine request shape."""
# Convert the UI's structured query/cookie editors into one engine request.
class InvalidRequestPayload(ValueError):
    """A client sent a body whose shape the editor contract does not allow."""


def normalize_payload(payload):
    """Validate and normalise a Repeater/Intruder request payload.

    The editor contract is a JSON object. Anything else - a bare string, a list,
    a number - must become an explicit client error rather than an unhandled
    `dict()`/`urlsplit()` failure, so shape and field types are checked here
    instead of being assumed.
    """
    if not isinstance(payload, dict):
        raise InvalidRequestPayload("request payload must be a JSON object")
    url = payload.get("url", "")
    if not isinstance(url, str):
        raise InvalidRequestPayload("url must be a string")
    payload = dict(payload)
    split = urlsplit(url)
    query = payload.pop("query", None)
    # Preserve existing URL query values, then apply editor values over them.
    if isinstance(query, dict):
        merged = dict(parse_qsl(split.query, keep_blank_values=True))
        merged.update({str(key): str(value) for key, value in query.items()})
        payload["url"] = urlunsplit((split.scheme, split.netloc, split.path, urlencode(merged), split.fragment))
    cookies = payload.pop("cookies", None)
    # Represent cookie editor values as one standard Cookie request header.
    if isinstance(cookies, dict):
        headers = payload.get("headers")
        if not isinstance(headers, dict):
            headers = {}
        headers = dict(headers)
        headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in cookies.items())
        payload["headers"] = headers
    return payload


@csrf_exempt
def execute(request):
    """Forward one Repeater request and persist successful responses."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    project = getattr(request, "active_project", None)
    try:
        payload = normalize_payload(json.loads(request.body))
        with _outbound_runtime().operation("repeater", project.id if project else None) as operation:
            status, result = call_engine("/proxy/request", payload)
            operation.raise_if_cancelled()
    except (ValueError, TypeError):
        return JsonResponse({"error": "invalid JSON"}, status=400)
    except InvalidRequestPayload as error:
        return JsonResponse({"error": str(error)}, status=400)
    except OutboundOperationCancelled:
        return _route_switch_cancelled("Repeater")
    # Persist every completed target HTTP response, including 4xx/5xx results.
    if status == 200 and isinstance(result, dict) and result.get("status") is not None:
        TrafficRecord.objects.create(
            project=project,
            source="repeater",
            proxy_event_id=result.get("traffic_event_id"),
            method=payload.get("method", "GET"),
            url=payload.get("url", ""),
            request_headers=payload.get("headers", {}),
            request_body=payload.get("body", ""),
            source_ip=result.get("source_ip") or None,
            response_headers=result.get("headers", {}),
            response_body=result.get("body", ""),
            response_body_encoding=result.get("body_encoding", "utf8"),
            response_body_base64=result.get("body_base64", ""),
            response_content_type=result.get("body_content_type", (result.get("headers") or {}).get("Content-Type", "")),
            status_code=result.get("status"),
            latency_ms=result.get("time"),
            response_size=result.get("size"),
        )
    return JsonResponse(result, status=status)


@csrf_exempt
def intruder(request):
    """Start or inspect an asynchronous Intruder attack."""
    if request.method == "GET":
        attack_id = request.GET.get("attack_id", "").strip()
        if not attack_id.isdigit():
            return JsonResponse({"error": "attack_id must be numeric"}, status=400)
        since = request.GET.get("since", "").strip()
        if since:
            try:
                since_value = int(since)
            except ValueError:
                return JsonResponse({"error": "since must be numeric"}, status=400)
            if since_value < 0:
                return JsonResponse({"error": "since must not be negative"}, status=400)
            engine_path = f"/proxy/intruder/{attack_id}?since={since_value}"
        else:
            engine_path = f"/proxy/intruder/{attack_id}"
        status, result = call_engine_get(engine_path)
        if status == 200 and isinstance(result, dict):
            attack = IntruderAttack.objects.filter(engine_attack_id=str(attack_id)).first()
            persist_intruder_history(
                int(attack_id),
                result.get("results"),
                result.get("result_offset", 0),
                attack.project_id if attack and attack.project_id else getattr(getattr(request, "active_project", None), "id", None),
            )
        return JsonResponse(result, status=status)


    if request.method == "DELETE":
        attack_id = request.GET.get("attack_id", "").strip()
        if not attack_id.isdigit():
            return JsonResponse({"error": "attack_id must be numeric"}, status=400)
        status, result = call_engine_delete(f"/proxy/intruder/{attack_id}")
        return JsonResponse(result, status=status)


    if request.method == "POST" and request.GET.get("attack_id"):
        attack_id = request.GET.get("attack_id", "").strip()
        if not attack_id.isdigit():
            return JsonResponse({"error": "attack_id must be numeric"}, status=400)
        action = request.GET.get("action", "").strip().lower()
        if action not in {"pause", "resume"}:
            return JsonResponse({"error": "action must be pause or resume"}, status=400)
        status, result = call_engine_action(
            f"/proxy/intruder/{attack_id}",
            {"action": action},
        )
        return JsonResponse(result, status=status)
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    project = getattr(request, "active_project", None)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict):
            raise InvalidRequestPayload("intruder payload must be a JSON object")
        payload["base_request"] = normalize_payload(payload.get("base_request", {}))
        logger.info(
            "intruder_start mode=%s payload_sets=%d transformations=%d",
            payload.get("mode", ""),
            len(payload.get("payloads") or payload.get("dictionaries") or []),
            len(payload.get("transformations") or []),
        )
        with _outbound_runtime().operation("intruder", project.id if project else None) as operation:
            status, result = call_engine("/proxy/intruder", payload)
            operation.raise_if_cancelled()
    except (ValueError, TypeError):
        return JsonResponse({"error": "invalid JSON"}, status=400)
    except InvalidRequestPayload as error:
        return JsonResponse({"error": str(error)}, status=400)
    except OutboundOperationCancelled:
        return _route_switch_cancelled("Intruder")
    logger.info(
        "intruder_complete status=%s results=%d",
        status,
        len((result.get("results") or [])) if isinstance(result, dict) else 0,
    )
    if status in {200, 202} and isinstance(result, dict) and result.get("attack_id"):
        IntruderAttack.objects.create(
            name="Intruder run",
            project=project,
            engine_attack_id=str(result["attack_id"]),
            attack_type=str(payload.get("mode", "sniper")),
            base_request=payload.get("base_request") or {},
            payloads=payload.get("payloads") or payload.get("dictionaries") or [],
            transformations=payload.get("transformations") or [],
            delay_ms=int(payload.get("delay_ms", 150) or 0),
            concurrency=int(payload.get("concurrency", 1) or 1),
            status=str(result.get("status", "running")),
        )
    return JsonResponse(result, status=status)


@csrf_exempt
def target_map(request):
    # Target jobs run asynchronously in Go so the browser can poll progress
    # and cancel a crawl without blocking the Django request worker.
    """Start or inspect an asynchronous same-origin site map crawl."""
    if request.method == "GET":
        map_id = request.GET.get("map_id", "").strip()
        if not map_id.isdigit():
            return JsonResponse({"error": "map_id must be numeric"}, status=400)
        status, result = call_engine_get(f"/proxy/target-map/{map_id}")
        if isinstance(result, dict):
            TargetJob.objects.filter(job_id=map_id).update(status=result.get("status", "unknown"), result=result)
            if str(result.get("status", "")).lower() in {"completed", "cancelled", "failed", "error"}:
                job = TargetJob.objects.filter(job_id=map_id).select_related("project").first()
                _ingest_target_job(job)
        return JsonResponse(result, status=status)
    if request.method == "DELETE":
        map_id = request.GET.get("map_id", "").strip()
        if not map_id.isdigit():
            return JsonResponse({"error": "map_id must be numeric"}, status=400)
        status, result = call_engine_delete(f"/proxy/target-map/{map_id}")
        return JsonResponse(result, status=status)
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
    except (ValueError, TypeError):
        return JsonResponse({"error": "invalid JSON"}, status=400)
    project_id = payload.pop("project_id", None)
    project = _active_project(request, project_id)
    try:
        with _outbound_runtime().operation("target", project.id if project else None) as operation:
            status, result = call_engine("/proxy/target-map", payload)
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("Target")
    if status in {200, 202} and isinstance(result, dict) and result.get("map_id"):
        TargetJob.objects.create(
            project=project,
            job_id=str(result["map_id"]),
            engine_kind="static",
            url=str(payload.get("url", "")),
            status=str(result.get("status", "running")),
            result=result,
        )
    return JsonResponse(result, status=status)


@csrf_exempt
def target_browser(request):
    """Start, inspect or cancel an isolated browser-driven Target job."""
    job_id = request.GET.get("job_id", "").strip()
    if request.method == "GET":
        if not job_id:
            return JsonResponse({"error": "job_id is required"}, status=400)
        status, result = call_browser_worker_get(f"/target/{job_id}")
        if isinstance(result, dict):
            TargetJob.objects.filter(job_id=job_id).update(status=result.get("status", "unknown"), result=result)
            if str(result.get("status", "")).lower() in {"completed", "cancelled", "failed", "error"}:
                job = TargetJob.objects.filter(job_id=job_id).select_related("project").first()
                _ingest_target_job(job)
        return JsonResponse(result, status=status)
    if request.method == "DELETE":
        if not job_id:
            return JsonResponse({"error": "job_id is required"}, status=400)
        status, result = call_browser_worker_delete(f"/target/{job_id}")
        return JsonResponse(result, status=status)
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
    except (ValueError, TypeError):
        return JsonResponse({"error": "invalid JSON"}, status=400)
    if not isinstance(payload, dict):
        return JsonResponse({"error": "invalid JSON: request body must be an object"}, status=400)
    capture_context = None
    raw_capture_context_id = payload.pop("capture_context_id", None)
    if raw_capture_context_id not in (None, ""):
        if isinstance(raw_capture_context_id, bool):
            return JsonResponse({"error": "capture_context_id must be numeric or null"}, status=400)
        try:
            capture_context_id = int(raw_capture_context_id)
        except (TypeError, ValueError):
            return JsonResponse({"error": "capture_context_id must be numeric or null"}, status=400)
        if capture_context_id <= 0:
            return JsonResponse({"error": "capture_context_id must be numeric or null"}, status=400)
        capture_context = TrafficCaptureContext.objects.filter(id=capture_context_id, active=True).first()
        if not capture_context:
            return JsonResponse({"error": "active traffic capture context not found"}, status=404)
        payload["capture_context"] = capture_context.token
    project_id = payload.pop("project_id", None)
    project = _active_project(request, project_id)
    if project_id in (None, "") and capture_context:
        project_id = capture_context.project_id
        project = project or capture_context.project
    result = None
    try:
        with _outbound_runtime().operation("browser-target", project.id if project else None) as operation:
            route_status, route = call_engine_get("/route")
            if route_status != 200 or not isinstance(route, dict):
                return JsonResponse(
                    {"error": "cannot resolve active route for browser worker", "reason": "ROUTE_UNAVAILABLE"},
                    status=502,
                )
            # Browser requests use the local recording proxy so the active
            # engine generation and per-exchange source IP are authoritative.
            payload["proxy_server"] = PASSIVE_PROXY_URL
            payload["proxy_mitm_ca"] = True
            operation.raise_if_cancelled()
            status, result = call_browser_worker("/target", payload)
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        if isinstance(result, dict) and result.get("job_id"):
            call_browser_worker_delete(f"/target/{result['job_id']}")
        return _route_switch_cancelled("Browser Target")
    if status in {200, 202} and isinstance(result, dict) and result.get("job_id"):
        TargetJob.objects.create(
            project=project,
            capture_context=capture_context,
            job_id=str(result["job_id"]),
            engine_kind="browser",
            url=str(payload.get("url", "")),
            status=str(result.get("status", "running")),
            result=result,
        )
    return JsonResponse(result, status=status)


def _osint_graph_error(error, status=400):
    return JsonResponse({"error": str(error), "reason": "INVALID_OSINT_GRAPH"}, status=status)


def _osint_request_origin(request):
    """Return the scheme and host the browser used to reach this gateway.

    A written result file is addressed by an absolute URL, because that is the
    only URL shape the graph stores. Building it from the live request keeps the
    stored identity equal to the address the analyst can actually open.
    """
    if request is None:
        return None
    try:
        host = request.get_host()
    except Exception:
        return None
    if not host:
        return None
    return f"{'https' if request.is_secure() else 'http'}://{host}"


@csrf_protect
def osint_graphs(request, graph_id=None):
    """List, create and inspect durable project-scoped OSINT graphs."""
    if request.method == "GET":
        if graph_id is not None:
            graph = OsintGraph.objects.filter(id=graph_id).first()
            if not graph:
                return JsonResponse({"error": "OSINT graph not found"}, status=404)
            return JsonResponse(graph_item(graph, include_contents=True))
        raw_project_id = request.GET.get("project_id", "")
        if not raw_project_id.isdigit() or int(raw_project_id) <= 0:
            return _osint_graph_error(OsintGraphError("project_id is required for graph listing"))
        project = Project.objects.filter(id=int(raw_project_id)).first()
        if not project:
            return JsonResponse({"error": "project not found"}, status=404)
        graphs = OsintGraph.objects.filter(project=project).order_by("-version")
        return JsonResponse({"items": [graph_item(graph) for graph in graphs]})

    if request.method != "POST" or graph_id is not None:
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict):
            raise OsintGraphError("request body must be an object")
        raw_project_id = payload.get("project_id")
        if isinstance(raw_project_id, bool):
            raise OsintGraphError("project_id must be numeric")
        project = Project.objects.filter(id=int(raw_project_id)).first() if raw_project_id is not None else None
        if not project:
            return JsonResponse({"error": "project not found"}, status=404)
        graph = create_graph(
            project,
            version=payload.get("version"),
            source=payload.get("source", "manual"),
            name=payload.get("name", "OSINT graph"),
            metadata=payload.get("metadata"),
        )
    except (json.JSONDecodeError, TypeError, ValueError, OsintGraphError) as error:
        return _osint_graph_error(error)
    return JsonResponse(graph_item(graph), status=201)


@csrf_protect
def osint_graph_upsert(request, graph_id):
    """Idempotently merge entities and relations into one graph."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    graph = OsintGraph.objects.filter(id=graph_id).first()
    if not graph:
        return JsonResponse({"error": "OSINT graph not found"}, status=404)
    try:
        payload = json.loads(request.body)
        counts = upsert_graph(graph, payload)
    except (json.JSONDecodeError, TypeError, ValueError, OsintGraphError) as error:
        return _osint_graph_error(error)
    response = graph_item(graph, include_contents=True)
    response["upserted"] = counts
    return JsonResponse(response)


@csrf_protect
def osint_graph_entity(request, graph_id, entity_id):
    """Edit or delete one stored entity inside a single graph."""
    if request.method not in {"PATCH", "DELETE"}:
        return JsonResponse({"error": "method not allowed"}, status=405)
    graph = OsintGraph.objects.filter(id=graph_id).first()
    if not graph:
        return JsonResponse({"error": "OSINT graph not found"}, status=404)
    if request.method == "DELETE":
        try:
            deleted = delete_entity(graph, entity_id)
        except (TypeError, ValueError, OsintGraphError) as error:
            return _osint_graph_error(error, status=404)
        response = graph_item(graph, include_contents=True)
        response["deleted"] = deleted
        return JsonResponse(response)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict):
            raise OsintGraphError("request body must be an object")
        entity = update_entity(graph, entity_id, payload)
    except (json.JSONDecodeError, TypeError, ValueError, OsintGraphError) as error:
        return _osint_graph_error(error)
    response = graph_item(graph, include_contents=True)
    response["entity"] = entity_item(entity)
    return JsonResponse(response)


@csrf_protect
def osint_graph_relation(request, graph_id, relation_id):
    """Delete one relation while preserving its endpoint entities."""
    if request.method != "DELETE":
        return JsonResponse({"error": "method not allowed"}, status=405)
    graph = OsintGraph.objects.filter(id=graph_id).first()
    if not graph:
        return JsonResponse({"error": "OSINT graph not found"}, status=404)
    try:
        deleted = delete_relation(graph, relation_id)
    except (TypeError, ValueError, OsintGraphError) as error:
        return _osint_graph_error(error, status=404)
    response = graph_item(graph, include_contents=True)
    response["deleted"] = deleted
    return JsonResponse(response)


@csrf_protect
def osint_graph_clear(request, graph_id):
    """Empty one graph so a fresh entity set can be collected into it."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    graph = OsintGraph.objects.filter(id=graph_id).first()
    if not graph:
        return JsonResponse({"error": "OSINT graph not found"}, status=404)
    try:
        payload = json.loads(request.body or b"{}")
    except json.JSONDecodeError:
        payload = {}
    if isinstance(payload, dict) and payload.get("confirm") is not True:
        return JsonResponse({
            "error": "explicit confirmation is required to clear this graph",
            "reason": "CLEAR_CONFIRMATION_REQUIRED",
        }, status=400)
    cleared = clear_graph(graph)
    response = graph_item(graph, include_contents=True)
    response["cleared"] = cleared
    return JsonResponse(response)


@csrf_protect
def osint_transform_registry(request):
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    status, result = call_engine_get("/proxy/osint/transforms")
    return JsonResponse(result, status=status, safe=isinstance(result, dict))


# _OSINT_NETWORK_TRANSFORMS are the transforms that reach the network and
# therefore need an explicit confirmation before they run.
_OSINT_NETWORK_TRANSFORMS = frozenset(
    {"subdomains", "github_recon", "reverse_dns", "dns_records", "wayback_urls", "s3_buckets"}
)


@csrf_protect
def osint_graph_transform(request, graph_id):
    """Run one explicitly selected transform and persist its graph output."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    graph = OsintGraph.objects.filter(id=graph_id).select_related("project").first()
    if not graph:
        return JsonResponse({"error": "OSINT graph not found"}, status=404)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict):
            raise OsintGraphError("request body must be an object")
        transform = str(payload.get("transform", "")).strip().lower()
        value = str(payload.get("value", "")).strip()
        options = payload.get("options", {})
        confirm_network = payload.get("confirm_network", False)
        if not transform or not value:
            raise OsintGraphError("transform and value are required")
        if not isinstance(options, dict):
            raise OsintGraphError("options must be an object")
        if not isinstance(confirm_network, bool):
            raise OsintGraphError("confirm_network must be boolean")
        network_transforms = _OSINT_NETWORK_TRANSFORMS
        if transform in network_transforms and not confirm_network:
            return JsonResponse({
                "error": "explicit network confirmation is required for this transform",
                "reason": "NETWORK_CONFIRMATION_REQUIRED",
            }, status=400)
    except (json.JSONDecodeError, TypeError, ValueError, OsintGraphError) as error:
        return _osint_graph_error(error)

    started_at = time.monotonic()
    try:
        with _outbound_runtime().operation("osint-transform", graph.project_id) as operation:
            status, result = call_engine("/proxy/osint/transform", {
                "transform": transform,
                "value": value,
                "options": options,
                "confirm_network": confirm_network,
            })
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("OSINT transform")
    duration_ms = int((time.monotonic() - started_at) * 1000)
    engine_result = result if isinstance(result, dict) else {}
    engine_warnings = engine_result.get("warnings") or []
    if status < 200 or status >= 300:
        # Report an explicit failed transform status so the UI can distinguish an
        # engine rejection from a transform that legitimately found nothing.
        failed = dict(engine_result) or {"error": "OSINT transform failed", "reason": "OSINT_TRANSFORM_FAILED"}
        failed.setdefault("error", "OSINT transform failed")
        failed.setdefault("reason", "OSINT_TRANSFORM_FAILED")
        failed["transform_result"] = {
            "transform": transform,
            "value": value,
            "status": "failed",
            "local_only": bool(engine_result.get("local_only")),
            "network_used": bool(engine_result.get("network_used")),
            "entity_count": 0,
            "relation_count": 0,
            "warnings": engine_warnings,
            "metadata": {},
            "duration_ms": duration_ms,
        }
        return JsonResponse(failed, status=status)
    try:
        response = _osint_transform_persist(graph, result, _osint_request_origin(request))
    except OperationalError as error:
        # The engine answered, so the outcome is still reportable: a local write
        # lock that never cleared is stated instead of raised as a server error.
        logger.warning("OSINT transform persist failed: %s", error)
        return JsonResponse({
            "error": "the transform result could not be stored because the local database stayed locked",
            "reason": "DATABASE_BUSY",
        }, status=503)
    except (TypeError, ValueError, OsintGraphError) as error:
        # The engine answered, so the outcome is still reportable: the transform
        # ran but its observations could not be stored in this graph.
        failed = {"error": str(error), "reason": "INVALID_OSINT_GRAPH"}
        failed["transform_result"] = {
            "transform": result.get("transform", transform),
            "value": value,
            "observed_at": result.get("observed_at"),
            "status": "failed",
            "local_only": bool(result.get("local_only")),
            "network_used": bool(result.get("network_used")),
            "entity_count": len(result.get("entities") or []),
            "relation_count": len(result.get("relations") or []),
            "warnings": engine_warnings,
            "metadata": result.get("metadata") or {},
            "duration_ms": duration_ms,
        }
        return JsonResponse(failed, status=400)
    counts = response.get("upserted") or {}
    rejected = counts.get("rejected") or []
    transform_result = response["transform_result"]
    transform_result["duration_ms"] = duration_ms
    transform_result["stored_entity_count"] = counts.get("entities", 0)
    transform_result["stored_relation_count"] = counts.get("relations", 0)
    transform_result["rejected_count"] = len(rejected)
    transform_result["rejected"] = rejected[:50]
    if rejected:
        transform_result["warnings"].append(
            f"{len(rejected)} observation(s) were not stored because the identity is not a usable graph value: "
            + ", ".join(sorted({str(item["identity"]) for item in rejected if item["identity"]})[:5])
        )
    return JsonResponse(response)


@csrf_protect
def osint_graph_transform_job(request, graph_id, job_id=None, action=None):
    """Start a transform as a background job, or poll and control a running one.

    A discovery over a large zone runs for minutes. As a background job the
    browser follows real counters and can pause, continue or cancel it, instead
    of holding one blocking request open for the whole run. The finished result
    is persisted into the graph by the same path the synchronous endpoint uses.
    """
    graph = OsintGraph.objects.filter(id=graph_id).select_related("project").first()
    if not graph:
        return JsonResponse({"error": "OSINT graph not found"}, status=404)

    if action:
        if action not in {"cancel", "pause", "resume"}:
            return JsonResponse({"error": f"unknown transform action: {action}"}, status=400)
        if not job_id:
            return JsonResponse({"error": "job_id is required"}, status=400)
        if request.method not in {"POST", "DELETE"}:
            return JsonResponse({"error": "method not allowed"}, status=405)
        status, result = call_engine(f"/proxy/osint/transform/jobs/{job_id}/{action}", {})
        return JsonResponse(result, status=status)

    if request.method == "GET":
        if not job_id:
            return JsonResponse({"error": "job_id is required"}, status=400)
        status, result = call_engine_get(f"/proxy/osint/transform/jobs/{job_id}")
        return _osint_transform_job_result(graph, status, result, _osint_request_origin(request))

    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict):
            raise OsintGraphError("request body must be an object")
        transform = str(payload.get("transform", "")).strip().lower()
        value = str(payload.get("value", "")).strip()
        options = payload.get("options", {})
        confirm_network = payload.get("confirm_network", False)
        if not transform or not value:
            raise OsintGraphError("transform and value are required")
        if not isinstance(options, dict):
            raise OsintGraphError("options must be an object")
        if not isinstance(confirm_network, bool):
            raise OsintGraphError("confirm_network must be boolean")
        if transform in _OSINT_NETWORK_TRANSFORMS and not confirm_network:
            return JsonResponse({
                "error": "explicit network confirmation is required for this transform",
                "reason": "NETWORK_CONFIRMATION_REQUIRED",
            }, status=400)
    except (json.JSONDecodeError, TypeError, ValueError, OsintGraphError) as error:
        return _osint_graph_error(error)

    started_at = time.monotonic()
    try:
        with _outbound_runtime().operation("osint-transform", graph.project_id) as operation:
            status, result = call_engine("/proxy/osint/transform/jobs", {
                "transform": transform,
                "value": value,
                "options": options,
                "confirm_network": confirm_network,
            })
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("OSINT transform")
    if status not in (200, 202) or not isinstance(result, dict):
        return JsonResponse(result if isinstance(result, dict) else {"error": "transform did not start"}, status=status)
    # The job outlives this request, so the browser has to come back for the
    # result. The graph and the transform it runs on are remembered here so the
    # completion poll can persist into the right graph.
    result = dict(result)
    result["transform_result"] = {"transform": transform, "value": value, "status": "running"}
    result["started_ms"] = int((time.monotonic() - started_at) * 1000)
    return JsonResponse(result, status=status)


def _osint_transform_job_result(graph, status, result, origin=None):
    """Turn one job poll into the browser-facing response, persisting on finish."""
    if status != 200 or not isinstance(result, dict):
        return JsonResponse(result if isinstance(result, dict) else {"error": "transform job is unavailable"}, status=status)
    state = result.get("state")
    if state not in {"completed", "failed", "cancelled"}:
        # A running or paused transform only carries progress, never a partial
        # result, so the browser cannot mistake a half-finished run for one.
        return JsonResponse(result, status=200)
    payload = result.get("result")
    if state != "completed" or not isinstance(payload, dict):
        failed = {
            "error": result.get("error") or "OSINT transform did not complete",
            "reason": result.get("reason") or f"OSINT_TRANSFORM_{str(state).upper()}",
        }
        if result.get("reason"):
            failed["reason"] = result["reason"]
        failed["state"] = state
        failed["progress"] = result.get("progress") or {}
        return JsonResponse(failed, status=409 if state == "failed" else 200)
    try:
        response = _osint_transform_persist(graph, payload, origin)
    except OsintGraphError as error:
        return _osint_graph_error(error)
    except OperationalError as error:
        # A finished transform must not be reported as a server error because
        # another local writer held the SQLite lock, and a lock that never
        # clears is stated instead of being retried forever.
        logger.warning("OSINT transform persist failed: %s", error)
        return JsonResponse({
            "error": "the transform result could not be stored because the local database stayed locked",
            "reason": "DATABASE_BUSY",
            "state": state,
        }, status=503)
    response["state"] = state
    progress = result.get("progress") or {}
    response["progress"] = progress
    # The transform result is built before the engine reports how long the run
    # took, so the real elapsed time of the job is carried over here instead of
    # the placeholder the synchronous path fills in afterwards.
    elapsed = progress.get("elapsed_ms")
    if isinstance(elapsed, (int, float)) and elapsed >= 0:
        response["transform_result"]["duration_ms"] = int(elapsed)
    return JsonResponse(response, status=200)


def _osint_transform_persist(graph, payload, origin=None):
    """Persist a finished transform result and return the graph item.

    A result with more rows than a graph can usefully hold is written to a
    complete file and stored as one pointer entity. Nothing is dropped: the file
    holds every row the transform produced.
    """
    transform = str(payload.get("transform") or "transform")
    value = str(payload.get("value") or "")
    stored = dict(payload)
    delivered_as_file = False
    file_info = None
    if osint_exports.needs_file_delivery(payload):
        file_info = osint_exports.write_result_files(graph, payload, transform, value)
        pointer = osint_exports.file_entity(graph, transform, value, file_info, file_info["rows"], origin)
        # The host entity stays in the graph; the rows behind it move to the
        # file so the graph keeps the context without the unusable row count.
        domain_rows = [item for item in payload.get("entities") or [] if isinstance(item, dict) and item.get("type") == "domain"]
        stored["entities"] = [*domain_rows, pointer]
        stored["relations"] = [
            item for item in payload.get("relations") or []
            if isinstance(item, dict) and item.get("target_type") == "domain"
        ]
        delivered_as_file = True

    # A transform result is paid for by the network work that produced it, so a
    # momentary local write lock must not lose it: the same retry the ingest
    # paths use waits the lock holder out, and the write is idempotent.
    counts = _retry_sqlite_locked(lambda: upsert_graph(graph, stored, skip_invalid=True))
    entity_count = len(stored.get("entities") or [])
    relation_count = len(stored.get("relations") or [])
    metadata = dict(stored.get("metadata") or {})
    if delivered_as_file:
        metadata["result_file"] = {
            "rows": file_info["rows"],
            "csv": file_info["csv"],
            "jsonl": file_info["jsonl"],
            "open_url": f"/api/osint/graphs/{graph.id}/files/{file_info['csv']}",
            "download_url": f"/api/osint/graphs/{graph.id}/files/{file_info['csv']}?download=1",
            "switched_at_rows": osint_exports.FILE_ENTITY_ROWS,
        }
    warnings = list(stored.get("warnings") or [])
    if delivered_as_file:
        # The switch is stated in the result, so nobody reads the file as a
        # silently shortened answer.
        warnings.append(
            f"the result has {file_info['rows']} rows, so every row was written to "
            f"{file_info['csv']} and {file_info['jsonl']} instead of one graph entity per row; "
            "the graph keeps one file entity pointing at the complete list"
        )
    # Reading the stored graph back is the same read the ingest paths do, so it
    # waits a local write lock out as well instead of failing the whole result.
    response = _retry_sqlite_locked(lambda: graph_item(graph, include_contents=True))
    response["transform_result"] = {
        "transform": payload.get("transform", transform),
        "value": value,
        "observed_at": payload.get("observed_at"),
        "status": "completed" if (entity_count or relation_count) else "empty",
        "local_only": bool(payload.get("local_only")),
        "network_used": bool(payload.get("network_used")),
        "entity_count": entity_count,
        "relation_count": relation_count,
        "warnings": warnings,
        "metadata": metadata,
        "delivered_as_file": delivered_as_file,
        "duration_ms": 0,
    }
    response["upserted"] = counts
    return response


@csrf_protect
def osint_graph_file(request, graph_id, name):
    """Serve one written result file: inline to read, or as a download.

    The browser opens the inline form in a new tab to read the list, and the
    download form hands the same bytes to the file system. Neither form invents
    or shortens content.
    """
    graph = OsintGraph.objects.filter(id=graph_id).select_related("project").first()
    if not graph:
        return JsonResponse({"error": "OSINT graph not found"}, status=404)
    try:
        path = osint_exports.resolve_export_path(graph.id, name, download="download" in request.GET)
    except OsintGraphError as error:
        return _osint_graph_error(error)
    payload = path.read_bytes()
    if "download" in request.GET:
        response = HttpResponse(payload, content_type="text/plain; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="{path.name}"'
        return response
    if path.suffix == ".jsonl":
        # The structured copy is served as plain text so the browser shows it
        # verbatim rather than trying to interpret it.
        return HttpResponse(payload, content_type="text/plain; charset=utf-8")
    return HttpResponse(payload, content_type="text/plain; charset=utf-8")


@csrf_exempt
def osint(request):
    # Keep validation and error formatting consistent with the other gateway
    # endpoints while preserving partial OSINT results from the engine.
    """Run the built-in passive OSINT and WAF fingerprint checks."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict) or not str(payload.get("url", "")).strip():
            raise ValueError("url is required")
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid OSINT request: {error}"}, status=400)
    project = getattr(request, "active_project", None)
    try:
        with _outbound_runtime().operation("osint", project.id if project else None) as operation:
            status, result = call_engine("/proxy/osint", {
                "url": str(payload["url"]).strip(),
                "waf_check": bool(payload.get("waf_check", False)),
            })
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("OSINT")
    _ingest_osint_result(project, result)
    return JsonResponse(result, status=status)


@csrf_exempt
def scanner(request):
    """Run a read-only reconnaissance scan with security findings and verifyable evidence."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict) or not str(payload.get("url", "")).strip():
            raise ValueError("url is required")
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid scanner request: {error}"}, status=400)
    profile = str(payload.get("profile", "generic_web")).strip() or "generic_web"
    project = getattr(request, "active_project", None)
    try:
        with _outbound_runtime().operation("scanner", project.id if project else None) as operation:
            status, result = call_engine("/proxy/scanner", {
                "url": str(payload["url"]).strip(),
                "profile": profile,
            })
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("Scanner")
    _ingest_scanner_tech(project, result)
    if status == 200 and isinstance(result, dict):
        _ingest_scanner_run(project, "builtin", payload["url"], result.get("findings"), result.get("summary"))
    return JsonResponse(result, status=status)


def _nuclei_string_lists(payload):
    """Validate the shared tag/severity/options block of a nuclei request."""
    tags = payload.get("tags", []) or []
    severity = payload.get("severity", []) or []
    if not isinstance(tags, list) or not isinstance(severity, list):
        raise ValueError("tags and severity must be lists")
    options = payload.get("options", {})
    if not isinstance(options, dict):
        raise ValueError("options must be an object")
    return tags, severity, options


def _nuclei_file_payload(files):
    """Validate one chunk of uploaded template documents."""
    if not isinstance(files, list) or not files:
        raise ValueError("files must be a non-empty list")
    cleaned = []
    for item in files:
        if not isinstance(item, dict) or not str(item.get("name", "")).strip():
            raise ValueError("each file needs a name")
        content = item.get("content", "")
        if not isinstance(content, str) or not content.strip():
            raise ValueError("each file needs YAML content")
        path = item.get("path", "")
        if path is not None and not isinstance(path, str):
            raise ValueError("each file path must be a string")
        cleaned.append({
            "name": str(item["name"]).strip(),
            "path": str(path or "").strip(),
            "content": content,
        })
    return cleaned


@csrf_exempt
def scanner_nuclei_upload(request):
    """Stage one chunk of uploaded templates and return an upload id.

    Chunking keeps a whole templates folder uploadable without a single
    oversized request; the engine owns the staging directory.
    """
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        files = _nuclei_file_payload(payload.get("files", []))
        upload_id = str(payload.get("upload_id", "") or "").strip()
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid scanner nuclei upload: {error}"}, status=400)
    project = getattr(request, "active_project", None)
    try:
        with _outbound_runtime().operation("nuclei_upload", project.id if project else None) as operation:
            status, result = call_engine("/proxy/scanner/nuclei/stage", {
                "upload_id": upload_id, "files": files,
            })
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("Nuclei upload")
    if status == 200 and isinstance(result, dict):
        _ingest_scanner_run(
            project, "nuclei_upload", "", [], {},
            templates=result.get("templates"),
        )
    return JsonResponse(result, status=status)


@csrf_exempt
def scanner_nuclei_run(request):
    """Run the templates staged under an upload id and return the per-file report."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict) or not str(payload.get("url", "")).strip():
            raise ValueError("url is required")
        if not str(payload.get("upload_id", "")).strip():
            raise ValueError("upload_id is required")
        tags, severity, options = _nuclei_string_lists(payload)
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid scanner nuclei run: {error}"}, status=400)
    project = getattr(request, "active_project", None)
    try:
        with _outbound_runtime().operation("nuclei", project.id if project else None) as operation:
            status, result = call_engine("/proxy/scanner/nuclei/run", {
                "url": str(payload["url"]).strip(),
                "upload_id": str(payload["upload_id"]).strip(),
                "tags": [str(item).strip() for item in tags],
                "severity": [str(item).strip() for item in severity],
                "options": options,
            })
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("Nuclei")
    if status == 200 and isinstance(result, dict):
        _ingest_scanner_run(
            project, "nuclei",
            payload["url"], result.get("findings"), result.get("stats"),
            templates=result.get("templates"),
        )
    return JsonResponse(result, status=status)


# nucleiScannerJobs remembers what a started job was for, so the finished report
# can be attached to the right Project and URL once the browser polls it.
nucleiScannerJobs = {}
_nucleiScannerJobLock = threading.Lock()


def _remember_nuclei_job(job_id, project, url):
    with _nucleiScannerJobLock:
        nucleiScannerJobs[str(job_id)] = {
            "project_id": project.id if project else None, "url": str(url or ""),
        }


def _forget_nuclei_job(job_id):
    with _nucleiScannerJobLock:
        return nucleiScannerJobs.pop(str(job_id), None)


@csrf_exempt
def scanner_nuclei_job_stream(request, job_id):
    """Proxy the engine's live scan stream without buffering individual lines.

    A folder scan streams one event per finished template, so results reach the
    browser while nuclei is still working instead of arriving all at once.

    The read deadline is the same one the passive traffic stream uses, and for
    the same reason. A paused scan writes no events at all, and a single slow
    template can go a long time without one, so a stream that only produced
    bytes on real progress looked dead to its own read deadline: the read raised
    `TimeoutError`, the proxy died, and the browser reported a transport failure
    for a job that was still running. Resuming the run then failed against a
    stream nobody was listening to any more. A bounded read with a keepalive
    comment keeps a quiet run connected, and an overall lifetime still lets the
    client reconnect with its cursor.
    """
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    cursor = request.headers.get("Last-Event-ID") or request.GET.get("last_event_id", "")
    stream_url = f"{ENGINE_URL}/proxy/scanner/nuclei/jobs/{job_id}/stream"
    if cursor:
        stream_url += f"?last_event_id={cursor}"
    # open_engine_stream already turns every connection-level failure into an
    # explicit 502, so nothing here has to be distinguished afterwards.
    response = open_engine_stream(stream_url, {"Last-Event-ID": cursor})
    if isinstance(response, JsonResponse):
        return response

    def stream():
        # Read one SSE line at a time so each result reaches the browser as it
        # happens, exactly like the passive traffic stream.
        started = time.monotonic()
        try:
            while time.monotonic() - started < SSE_MAX_LIFETIME:
                try:
                    chunk = response.readline()
                except (TimeoutError, socket.timeout):
                    # The run is quiet — most often because it is paused. Say so
                    # with a comment frame and keep waiting.
                    yield b": keepalive\n\n"
                    continue
                if not chunk:
                    break
                yield chunk
        except (OSError, ValueError):
            # The browser went away mid-stream; releasing the socket is the point.
            return
        finally:
            response.close()

    result = StreamingHttpResponse(stream(), content_type="text/event-stream")
    result["Cache-Control"] = "no-cache"
    result["X-Accel-Buffering"] = "no"
    return result


@csrf_exempt
def scanner_nuclei_jobs(request, job_id=None, action=None):
    """Start an asynchronous template run, or poll / control an existing one.

    A long folder scan is a background job so the browser can show live progress
    instead of waiting on one blocking request. The finished report is attached
    to the Project that started the run. `action` is one of cancel, pause and
    resume.
    """
    if action:
        if action not in {"cancel", "pause", "resume"}:
            return JsonResponse({"error": f"unknown job action: {action}"}, status=400)
        if request.method not in {"POST", "DELETE"}:
            return JsonResponse({"error": "method not allowed"}, status=405)
        status, result = call_engine(f"/proxy/scanner/nuclei/jobs/{job_id}/{action}", {})
        return JsonResponse(result, status=status)

    if request.method == "GET":
        if not job_id:
            return JsonResponse({"error": "job_id is required"}, status=400)
        status, result = call_engine_get(f"/proxy/scanner/nuclei/jobs/{job_id}")
        # The job record is kept across every poll and dropped only when its
        # finished report has actually been written to the journal, so a
        # running job does not lose the Project it belongs to.
        if status == 200 and isinstance(result, dict) and result.get("state") == "completed":
            started = _forget_nuclei_job(job_id)
            report = result.get("result")
            if started and isinstance(report, dict):
                project = Project.objects.filter(id=started["project_id"]).first() if started["project_id"] else None
                _ingest_scanner_run(
                    project, "nuclei", started["url"],
                    report.get("findings"), report.get("stats"),
                    templates=report.get("templates"),
                )
        return JsonResponse(result, status=status)

    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict) or not str(payload.get("url", "")).strip():
            raise ValueError("url is required")
        if not str(payload.get("upload_id", "")).strip():
            raise ValueError("upload_id is required")
        tags, severity, options = _nuclei_string_lists(payload)
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid scanner nuclei job: {error}"}, status=400)
    project = getattr(request, "active_project", None)
    try:
        with _outbound_runtime().operation("nuclei", project.id if project else None) as operation:
            status, result = call_engine("/proxy/scanner/nuclei/jobs", {
                "url": str(payload["url"]).strip(),
                "upload_id": str(payload["upload_id"]).strip(),
                "tags": [str(item).strip() for item in tags],
                "severity": [str(item).strip() for item in severity],
                "options": options,
            })
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("Nuclei")
    if status not in (200, 202) or not isinstance(result, dict):
        return JsonResponse(
            result if isinstance(result, dict) else {"error": "job did not start"},
            status=status,
        )
    _remember_nuclei_job(result.get("job_id", ""), project, payload["url"])
    return JsonResponse(result, status=status)


@csrf_exempt
def scanner_nuclei(request):
    """Run uploaded Nuclei templates with the external binary (display only)."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict) or not str(payload.get("url", "")).strip():
            raise ValueError("url is required")
        cleaned = _nuclei_file_payload(payload.get("files", []))
        tags, severity, options = _nuclei_string_lists(payload)
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid scanner nuclei request: {error}"}, status=400)
    project = getattr(request, "active_project", None)
    try:
        with _outbound_runtime().operation("nuclei", project.id if project else None) as operation:
            status, result = call_engine("/proxy/scanner/nuclei", {
                "url": str(payload["url"]).strip(),
                "files": cleaned,
                "tags": [str(item).strip() for item in tags],
                "severity": [str(item).strip() for item in severity],
                "options": options,
            })
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("Nuclei")
    if status == 200 and isinstance(result, dict):
        _ingest_scanner_run(
            project, "nuclei",
            payload["url"], result.get("findings"), result.get("stats"),
            templates=result.get("templates"),
        )
    return JsonResponse(result, status=status)


@csrf_protect
def route(request):
    """Read or update the shared SOCKS5 route and drain old work on mutation."""
    if request.method == "GET":
        status, result = call_engine_get("/route")
        if status == 200 and isinstance(result, dict) and result.get("generation") is not None:
            try:
                _outbound_runtime().sync_generation(int(result["generation"]))
            except (TypeError, ValueError):
                pass
        return JsonResponse(result, status=status)
    if request.method not in {"POST", "PUT"}:
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict):
            raise ValueError("route payload must be an object")
        address = str(payload.get("address", "")).strip()
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid route: {error}"}, status=400)

    with _outbound_runtime().route_switch() as switch:
        status, result = call_engine("/route", {"address": address})
        if 200 <= status < 300:
            # Publish the new local generation immediately after the engine
            # acknowledges the swap; cleanup must not race new admissions.
            switch.activate()
            workflow_runs = []
            browser_jobs = []
            agent_requests = 0
            cleanup_errors = []
            try:
                workflow_runs = get_runtime().cancel_all()
            except Exception as error:  # noqa: BLE001 - cleanup is reported below
                cleanup_errors.append(f"workflow cleanup: {error}")
            try:
                browser_status, browser_result = call_browser_worker_delete("/target")
            except Exception as error:  # noqa: BLE001 - cleanup is reported below
                browser_status, browser_result = 0, {}
                cleanup_errors.append(f"browser-worker cleanup: {error}")
            if browser_status == 200 and isinstance(browser_result, dict):
                browser_jobs = [str(job_id) for job_id in browser_result.get("job_ids", [])]
            elif not cleanup_errors or not cleanup_errors[-1].startswith("browser-worker cleanup:"):
                cleanup_errors.append(f"browser-worker cleanup: HTTP {browser_status}")
            try:
                agent_requests = cancel_active_agent_requests()
            except Exception as error:  # noqa: BLE001 - cleanup is reported below
                cleanup_errors.append(f"AI cleanup: {error}")
            switch.record_cleanup(
                workflow_runs=workflow_runs,
                browser_jobs=browser_jobs,
                agent_requests=agent_requests,
                errors=cleanup_errors,
            )
            if isinstance(result, dict):
                result = {**result, "kill_switch": switch.result_metadata()}
    return JsonResponse(result, status=status)


@csrf_protect
def route_check(request):
    """Check the current route against a target and an external IP endpoint."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict) or not str(payload.get("url", "")).strip():
            raise ValueError("url is required")
        target_url = str(payload["url"]).strip()
        timeout_ms = int(payload.get("timeout_ms", 0))
        if timeout_ms < 0:
            raise ValueError("timeout_ms must not be negative")
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid route check: {error}"}, status=400)
    try:
        with _outbound_runtime().operation("route-check") as operation:
            status, result = call_engine("/route/check", {
                "url": target_url,
                "timeout_ms": timeout_ms,
            })
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("Route check")
    return JsonResponse(result, status=status)


def _agent_error(message, reason, status=400):
    return JsonResponse({"error": message, "reason": reason}, status=status)









def _compact_chat_value(value, key=""):
    """Return a JSON-shaped copy without dropping user-supplied evidence."""
    if isinstance(value, list):
        return [_compact_chat_value(item, key) for item in value]
    if isinstance(value, dict):
        return {
            str(item_key): _compact_chat_value(item_value, str(item_key))
            for item_key, item_value in value.items()
        }
    return value


def _compact_chat_context(context):
    if not isinstance(context, dict):
        return {}
    if not context.get("attached_evidence") and not isinstance(context.get("project_context"), dict):
        return {}
    return _compact_chat_value(dict(context))


def _compact_chat_messages(messages):
    compact = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        content = message.get("content", "")
        if not isinstance(content, str):
            content = str(content)
        item = {
            "role": str(message.get("role", "user")),
            "content": content,
        }
        if message.get("name"):
            item["name"] = str(message["name"])
        compact.append(item)
    return compact


















@csrf_protect
def agent_chat(request):
    """Analyze only evidence explicitly attached by the operator."""
    if request.method != "POST":
        return _agent_error("method not allowed", "METHOD_NOT_ALLOWED", 405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict):
            raise ValueError("request must be an object")
        messages = payload.get("messages")
        if not isinstance(messages, list) or not messages:
            raise ValueError("messages must be a non-empty list")
        if "approved_tool_call" in payload or "execution_profile" in payload:
            raise ValueError("agent execution tools are not supported; use the UI evidence attachment buttons")
        supplied_context = payload.get("context")
        if supplied_context is None:
            supplied_context = {}
        if not isinstance(supplied_context, dict):
            raise ValueError("context must be an object")
        attached_evidence = supplied_context.get("attached_evidence", {})
        if not isinstance(attached_evidence, dict):
            raise ValueError("attached_evidence must be an object")
        include_project_context = payload.get("include_project_context", False)
        if not isinstance(include_project_context, bool):
            raise ValueError("include_project_context must be boolean")
        project_context = {}
        if include_project_context:
            active_project = getattr(request, "active_project", None)
            if active_project is None:
                return _agent_error(
                    "select an active Project before including Project context",
                    "PROJECT_CONTEXT_REQUIRED",
                )
            try:
                summary_markdown = ProjectContextBuilder(active_project.id).build_summary_markdown(
                    include_notes=False,
                )
            except ProjectContextError as error:
                raise ValueError(f"Project context is unavailable: {error}") from error
            project_context = {
                "project_id": active_project.id,
                "include_notes": False,
                "summary_markdown": summary_markdown,
            }
        context = {}
        if attached_evidence or project_context:
            context = {
                "kind": "request_rider_selected_evidence",
                "attached_evidence": attached_evidence,
            }
            if project_context:
                context["project_context"] = project_context
        messages = _compact_chat_messages(messages)
        context = _compact_chat_context(context)
        provider = str(payload.get("provider", "ollama"))
        config = {
            "endpoint": payload.get("endpoint"),
            "model": payload.get("model"),
            "api_key": payload.get("api_key"),
        }
        active_project = getattr(request, "active_project", None)
        try:
            with _outbound_runtime().operation("ai", active_project.id if active_project else None) as operation:
                result = generate_agent_chat(
                    messages,
                    provider=provider,
                    context=context,
                    cancel_event=operation.cancelled,
                    **config,
                )
                operation.raise_if_cancelled()
        except (OutboundOperationCancelled, AgentRequestCancelled):
            return _agent_error("AI request cancelled by the route switch", "ROUTE_CHANGED", 409)
        return JsonResponse({"provider": provider, "message": result["message"]})
    except (json.JSONDecodeError, TypeError, ValueError, RuntimeError, AgentProviderError) as error:
        return _agent_error(f"invalid agent chat: {error}", "INVALID_AGENT_CHAT")


def intruder_saved_item(attack):
        """Serialize a saved Intruder definition for the browser."""
        return {
            "id": attack.id,
            "name": attack.name,
            "mode": attack.attack_type,
            "base_request": attack.base_request,
            "payloads": attack.payloads,
            "transformations": attack.transformations,
            "delay_ms": attack.delay_ms,
            "concurrency": attack.concurrency,
            "status": attack.status,
            "created_at": attack.created_at,
        }


@csrf_exempt
def intruder_saved(request, attack_id=None):
        """List, save, or re-run persisted Intruder configurations."""
        if request.method == "GET" and attack_id is None:
            return JsonResponse({"items": [intruder_saved_item(item) for item in IntruderAttack.objects.order_by("-created_at")]})
        if attack_id is not None:
            try:
                attack = IntruderAttack.objects.get(id=attack_id)
            except IntruderAttack.DoesNotExist:
                return JsonResponse({"error": "saved attack not found"}, status=404)
            if request.method == "GET":
                return JsonResponse(intruder_saved_item(attack))
            if request.method == "POST":
                if attack.project_id is None and getattr(request, "active_project", None):
                    attack.project = request.active_project
                    attack.save(update_fields=["project"])
                engine_payload = {
                    "base_request": attack.base_request,
                    "mode": attack.attack_type,
                    "payloads": attack.payloads,
                    "transformations": attack.transformations,
                }
                if attack.delay_ms:
                    engine_payload["delay_ms"] = attack.delay_ms
                if attack.concurrency:
                    engine_payload["concurrency"] = attack.concurrency
                try:
                    with _outbound_runtime().operation("saved-intruder", attack.project_id) as operation:
                        status, result = call_engine("/proxy/intruder", engine_payload)
                        operation.raise_if_cancelled()
                except OutboundOperationCancelled:
                    return _route_switch_cancelled("Saved Intruder")
                if status in {200, 202}:
                    attack.status = result.get("status", "running")
                    update_fields = ["status"]
                    if result.get("attack_id"):
                        attack.engine_attack_id = str(result["attack_id"])
                        update_fields.append("engine_attack_id")
                    attack.save(update_fields=update_fields)
                return JsonResponse(result, status=status)
            return JsonResponse({"error": "method not allowed"}, status=405)
        if request.method != "POST":
            return JsonResponse({"error": "method not allowed"}, status=405)
        try:
            payload = json.loads(request.body)
            mode = payload.get("mode")
            base_request = payload.get("base_request")
            payloads = payload.get("payloads")
            transformations = payload.get("transformations") or []
            delay_ms = payload.get("delay_ms", 150)
            concurrency = payload.get("concurrency", 1)
            if mode not in dict(IntruderAttack.TYPE_CHOICES):
                raise ValueError("unsupported attack mode")
            if not isinstance(base_request, dict) or not isinstance(payloads, list) or not isinstance(transformations, list):
                raise ValueError("base_request, payloads, and transformations must be JSON values of the expected type")
            if isinstance(delay_ms, bool) or not isinstance(delay_ms, int) or delay_ms < 0:
                raise ValueError("delay_ms must be a non-negative integer")
            if isinstance(concurrency, bool) or not isinstance(concurrency, int) or concurrency < 1:
                raise ValueError("concurrency must be a positive integer")
            attack = IntruderAttack.objects.create(
                name=str(payload.get("name") or "Intruder attack"),
                project=getattr(request, "active_project", None),
                attack_type=mode,
                base_request=base_request,
                payloads=payloads,
                transformations=transformations,
                delay_ms=delay_ms,
                concurrency=concurrency,
            )
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            return JsonResponse({"error": f"invalid saved attack: {error}"}, status=400)
        return JsonResponse(intruder_saved_item(attack), status=201)


# ---------------------------------------------------------------------------
# Workflow automation
# ---------------------------------------------------------------------------


def _workflow_body(request):
    try:
        payload = json.loads(request.body or b"{}")
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        raise WorkflowValidationError(f"invalid JSON: {error}") from error
    if not isinstance(payload, dict):
        raise WorkflowValidationError("request body must be an object")
    return payload


def _workflow_project_id(value):
    if value in (None, "", "null"):
        return None
    try:
        project_id = int(value)
    except (TypeError, ValueError) as error:
        raise WorkflowValidationError("project_id must be numeric") from error
    if project_id and not Project.objects.filter(id=project_id).exists():
        raise WorkflowValidationError("project not found")
    return project_id or None


def _workflow_schedule(nodes):
    for node in nodes:
        if node.get("type") == "schedule_trigger" and not node.get("disabled"):
            expression = str((node.get("params") or {}).get("cron", "")).strip()
            if expression:
                validate_cron(expression)
                return expression
    return ""


def _workflow_slug(nodes, requested=""):
    has_webhook = any(node.get("type") == "webhook_trigger" and not node.get("disabled") for node in nodes)
    if not has_webhook:
        return None
    candidate = str(requested or "").strip()
    if not candidate:
        candidate = secrets.token_urlsafe(12).replace("-", "a").replace("_", "b")
    if not all(character.isalnum() or character in "-_" for character in candidate):
        raise WorkflowValidationError("webhook path contains unsupported characters")
    return candidate


def workflow_item(workflow, include_runs=False):
    data = {
        "id": workflow.id,
        "project_id": workflow.project_id,
        "name": workflow.name,
        "description": workflow.description,
        "nodes": workflow.nodes or [],
        "connections": workflow.connections or [],
        "settings": workflow.settings or {},
        "metadata": workflow.metadata or {},
        "version": workflow.version,
        "active": workflow.active,
        "schedule": workflow.schedule,
        "webhook_slug": workflow.webhook_slug,
        "webhook_url": f"/api/workflows/hooks/{workflow.webhook_slug}" if workflow.webhook_slug else "",
        "last_run_at": workflow.last_run_at.isoformat() if workflow.last_run_at else None,
        "next_run_at": workflow.next_run_at.isoformat() if workflow.next_run_at else None,
        "created_at": workflow.created_at.isoformat(),
        "updated_at": workflow.updated_at.isoformat(),
    }
    if include_runs:
        data["runs"] = [run_item(run) for run in workflow.runs.order_by("-created_at")]
    return data


@csrf_exempt
def workflow_node_types(request):
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    return JsonResponse({"items": node_catalog()})


@csrf_exempt
def workflow_templates(request):
    """Expose the built-in, non-executing Template Store catalog."""
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    return JsonResponse({"items": list_templates()})


@csrf_exempt
def workflows(request, workflow_id=None):
    """Create, list, update and delete durable visual workflows."""
    ensure_scheduler()
    if request.method == "GET":
        queryset = Workflow.objects.select_related("project").order_by("-updated_at")
        project_filter = request.GET.get("project_id", "").strip()
        if project_filter:
            try:
                queryset = queryset.filter(project_id=int(project_filter))
            except ValueError:
                return JsonResponse({"error": "project_id must be numeric"}, status=400)
        if workflow_id is not None:
            workflow = queryset.filter(id=workflow_id).first()
            if not workflow:
                return JsonResponse({"error": "workflow not found"}, status=404)
            return JsonResponse(workflow_item(workflow, include_runs=True))
        return JsonResponse({"items": [workflow_item(item) for item in queryset]})

    if request.method == "DELETE":
        if workflow_id is None:
            return JsonResponse({"error": "workflow_id is required"}, status=400)
        workflow = Workflow.objects.filter(id=workflow_id).first()
        if not workflow:
            return JsonResponse({"error": "workflow not found"}, status=404)
        workflow.delete()
        return JsonResponse({"ok": True})

    if request.method not in {"POST", "PATCH", "PUT"}:
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = _workflow_body(request)
        existing = Workflow.objects.filter(id=workflow_id).first() if workflow_id is not None else None
        if workflow_id is not None and not existing:
            return JsonResponse({"error": "workflow not found"}, status=404)
        raw_nodes = payload.get("nodes", existing.nodes if existing else [])
        raw_connections = payload.get("connections", payload.get("edges", existing.connections if existing else []))
        nodes, connections = validate_workflow(raw_nodes, raw_connections)
        name = str(payload.get("name", existing.name if existing else "Workflow")).strip()
        if not name:
            raise WorkflowValidationError("name is required")
        requested_project = payload.get("project_id", existing.project_id if existing else None)
        project_id = _workflow_project_id(requested_project)
        if existing is None and "project_id" not in payload:
            active_project = getattr(request, "active_project", None)
            project_id = active_project.id if active_project else None
        schedule = str(payload.get("schedule", _workflow_schedule(nodes))).strip()
        if schedule:
            validate_cron(schedule)
            if not any(node.get("type") == "schedule_trigger" and not node.get("disabled") for node in nodes):
                raise WorkflowValidationError("schedule requires a schedule trigger node")
        requested_slug = payload.get("webhook_slug", existing.webhook_slug if existing else "")
        webhook_slug = _workflow_slug(nodes, requested_slug)
        if webhook_slug and Workflow.objects.exclude(id=existing.id if existing else None).filter(
            webhook_slug=webhook_slug
        ).exists():
            raise WorkflowValidationError("webhook path is already in use")
        active = bool(payload.get("active", existing.active if existing else False))
        if active and workflow_requires_confirmation(nodes) and not bool(payload.get("confirm_active", False)):
            raise WorkflowValidationError("active workflow contains actions requiring confirmation")
        workflow = existing or Workflow(project_id=project_id)
        workflow.name = name
        workflow.description = str(payload.get("description", existing.description if existing else "")).strip()
        workflow.project_id = project_id
        workflow.nodes = nodes
        workflow.connections = connections
        workflow.settings = payload.get("settings", existing.settings if existing else {})
        workflow.metadata = payload.get("metadata", existing.metadata if existing else {})
        if not isinstance(workflow.settings, dict) or not isinstance(workflow.metadata, dict):
            raise WorkflowValidationError("settings and metadata must be objects")
        workflow.schedule = schedule
        workflow.webhook_slug = webhook_slug
        workflow.active = active
        workflow.next_run_at = next_cron_time(schedule) if active and schedule else None
        workflow.version = int(payload.get("version", existing.version + 1 if existing else 1))
        workflow.save()
        if active:
            ensure_scheduler()
        return JsonResponse(workflow_item(workflow, include_runs=True), status=200 if existing else 201)
    except WorkflowValidationError as error:
        return JsonResponse({"error": str(error), "reason": "INVALID_WORKFLOW"}, status=400)
    except (TypeError, ValueError) as error:
        return JsonResponse({"error": str(error), "reason": "INVALID_WORKFLOW"}, status=400)


@csrf_exempt
def workflow_export(request, workflow_id):
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    workflow = Workflow.objects.filter(id=workflow_id).first()
    if not workflow:
        return JsonResponse({"error": "workflow not found"}, status=404)
    return JsonResponse({
        "schema": "requestrider.workflow/v1",
        "workflow": workflow_item(workflow),
    })


@csrf_exempt
def workflow_import(request):
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = _workflow_body(request)
        source = payload.get("workflow") if isinstance(payload.get("workflow"), dict) else payload
        nodes, connections = validate_workflow(source.get("nodes", []), source.get("connections", source.get("edges", [])))
        name = str(source.get("name") or "Imported workflow").strip()
        project_id = _workflow_project_id(source.get("project_id"))
        schedule = str(source.get("schedule") or _workflow_schedule(nodes)).strip()
        if schedule:
            validate_cron(schedule)
        workflow = Workflow.objects.create(
            name=name,
            description=str(source.get("description") or ""),
            project_id=project_id,
            nodes=nodes,
            connections=connections,
            settings=source.get("settings") if isinstance(source.get("settings"), dict) else {},
            metadata={**(source.get("metadata") or {}), "imported": True} if isinstance(source.get("metadata") or {}, dict) else {"imported": True},
            schedule=schedule,
            active=False,
            webhook_slug=_workflow_slug(nodes),
        )
    except WorkflowValidationError as error:
        return JsonResponse({"error": str(error), "reason": "INVALID_WORKFLOW"}, status=400)
    return JsonResponse(workflow_item(workflow, include_runs=True), status=201)


@csrf_exempt
def workflow_run_export(request, run_id):
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    run = WorkflowRun.objects.filter(id=run_id).select_related("workflow").first()
    if not run:
        return JsonResponse({"error": "workflow run not found"}, status=404)
    export_format = str(request.GET.get("format", "json")).lower()
    if export_format in {"markdown", "md"}:
        lines = [
            f"# Workflow run {run.id}",
            "",
            f"- Workflow: {run.workflow.name}",
            f"- Status: {run.status}",
            f"- Mode: {run.mode}",
            f"- Error: {run.error or '-'}",
            "",
            "## Output",
            "```json",
            json.dumps(run.output_data, ensure_ascii=False, indent=2, default=str),
            "```",
        ]
        return HttpResponse("\n".join(lines), content_type="text/markdown; charset=utf-8")
    return JsonResponse(run_item(run))


@csrf_exempt
def workflow_run_stream(request, run_id):
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    run = WorkflowRun.objects.filter(id=run_id).first()
    if not run:
        return JsonResponse({"error": "workflow run not found"}, status=404)
    runtime = get_runtime()

    def stream():
        listener = runtime.subscribe(run_id)
        try:
            snapshot = run_item(WorkflowRun.objects.get(pk=run_id))
            yield f"event: snapshot\ndata: {json.dumps(snapshot, ensure_ascii=False)}\n\n"
            if snapshot["status"] in {"completed", "failed", "cancelled", "interrupted"}:
                return
            while True:
                try:
                    event = listener.get()
                except queue.Empty:
                    yield ": keepalive\n\n"
                    continue
                yield f"event: workflow\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"
                if event.get("type") == "complete":
                    break
        finally:
            runtime.unsubscribe(run_id, listener)

    response = StreamingHttpResponse(stream(), content_type="text/event-stream")
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return response


@csrf_exempt
def workflow_activation(request, workflow_id):
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    workflow = Workflow.objects.filter(id=workflow_id).first()
    if not workflow:
        return JsonResponse({"error": "workflow not found"}, status=404)
    try:
        payload = _workflow_body(request)
        nodes, _connections = validate_workflow(workflow.nodes, workflow.connections, require_trigger=True)
        if workflow_requires_confirmation(nodes) and not bool(payload.get("confirm_active", False)):
            raise WorkflowValidationError("workflow contains actions requiring explicit confirmation")
        activate_workflow(workflow)
    except WorkflowValidationError as error:
        return JsonResponse({"error": str(error), "reason": "INVALID_WORKFLOW"}, status=400)
    return JsonResponse(workflow_item(workflow))


@csrf_exempt
def workflow_deactivation(request, workflow_id):
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    workflow = Workflow.objects.filter(id=workflow_id).first()
    if not workflow:
        return JsonResponse({"error": "workflow not found"}, status=404)
    deactivate_workflow(workflow)
    return JsonResponse(workflow_item(workflow))


@csrf_exempt
def workflow_run(request, workflow_id):
    if request.method not in {"POST", "DELETE"}:
        return JsonResponse({"error": "method not allowed"}, status=405)
    workflow = Workflow.objects.filter(id=workflow_id).first()
    if not workflow:
        return JsonResponse({"error": "workflow not found"}, status=404)
    runtime = get_runtime()
    if request.method == "DELETE":
        try:
            payload = _workflow_body(request)
        except WorkflowValidationError as error:
            return JsonResponse({"error": str(error)}, status=400)
        run_id = payload.get("run_id")
        if not str(run_id or "").isdigit() or not runtime.cancel(int(run_id)):
            return JsonResponse({"error": "workflow run is not active in this process"}, status=409)
        return JsonResponse({"ok": True})
    try:
        payload = _workflow_body(request)
        nodes, _connections = validate_workflow(workflow.nodes, workflow.connections, require_trigger=True)
        if workflow_requires_confirmation(nodes) and not bool(payload.get("confirm", False)):
            return JsonResponse({
                "error": "workflow contains actions requiring explicit confirmation",
                "reason": "CONFIRMATION_REQUIRED",
            }, status=400)
        trigger_node_id = str(payload.get("trigger_node_id", "")).strip()
        if trigger_node_id and not any(node["id"] == trigger_node_id for node in nodes):
            raise WorkflowValidationError("trigger_node_id is not part of this workflow")
        input_data = payload.get("input", {})
        if not isinstance(input_data, dict):
            input_data = {"value": input_data}
        run = runtime.start(
            workflow,
            mode="manual",
            trigger_type="manual",
            trigger_node_id=trigger_node_id,
            input_data=input_data,
            project_id=workflow.project_id or getattr(getattr(request, "active_project", None), "id", None),
        )
    except WorkflowValidationError as error:
        return JsonResponse({"error": str(error), "reason": "INVALID_WORKFLOW"}, status=400)
    return JsonResponse(run_item(run), status=202)


@csrf_exempt
def workflow_runs(request, run_id=None):
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if run_id is not None:
        run = WorkflowRun.objects.filter(id=run_id).select_related("workflow").first()
        if not run:
            return JsonResponse({"error": "workflow run not found"}, status=404)
        return JsonResponse(run_item(run))
    queryset = WorkflowRun.objects.select_related("workflow").order_by("-created_at")
    if request.GET.get("workflow_id", "").isdigit():
        queryset = queryset.filter(workflow_id=int(request.GET["workflow_id"]))
    if request.GET.get("project_id", "").isdigit():
        queryset = queryset.filter(project_id=int(request.GET["project_id"]))
    return JsonResponse({"items": [run_item(item) for item in queryset]})


@csrf_exempt
def workflow_run_action(request, run_id, action):
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    run = WorkflowRun.objects.filter(id=run_id).first()
    if not run:
        return JsonResponse({"error": "workflow run not found"}, status=404)
    runtime = get_runtime()
    if action == "cancel":
        if not runtime.cancel(run_id) and run.status not in {"completed", "failed", "cancelled", "interrupted"}:
            return JsonResponse({"error": "run is not active in this process"}, status=409)
    elif action == "pause":
        if not runtime.pause(run_id):
            return JsonResponse({"error": "run is not active in this process"}, status=409)
    elif action == "resume":
        if not runtime.resume(run_id):
            return JsonResponse({"error": "run is not active in this process"}, status=409)
    else:
        return JsonResponse({"error": "unsupported run action"}, status=400)
    run.refresh_from_db()
    return JsonResponse(run_item(run))


@csrf_exempt
def workflow_webhook(request, slug):
    """Receive a local workflow webhook without requiring a browser session."""
    workflow = Workflow.objects.filter(active=True, webhook_slug=slug).first()
    if not workflow:
        return JsonResponse({"error": "workflow webhook not found"}, status=404)
    nodes, _connections = validate_workflow(workflow.nodes, workflow.connections, require_trigger=True)
    # The slug identifies the workflow; the node itself is selected by method.
    trigger = next(
        (node for node in nodes if node["type"] == "webhook_trigger" and not node.get("disabled")),
        None,
    )
    if not trigger:
        return JsonResponse({"error": "workflow has no webhook trigger"}, status=404)
    method = str((trigger.get("params") or {}).get("method", "POST")).upper()
    if method not in {"ANY", request.method.upper()}:
        return JsonResponse({"error": "webhook method does not match"}, status=405)
    raw_body = request.body.decode("utf-8", errors="replace")
    body: Any = raw_body
    if "json" in request.content_type.lower():
        try:
            body = json.loads(raw_body or "{}")
        except json.JSONDecodeError:
            body = {"raw": raw_body}
    elif request.content_type.startswith("application/x-www-form-urlencoded"):
        body = {key: values[-1] for key, values in request.POST.lists()}
    safe_headers = {
        key: value for key, value in request.headers.items()
        if key.lower() not in {"authorization", "cookie", "x-api-key"}
    }
    payload = {
        "method": request.method,
        "query": request.GET.dict(),
        "headers": safe_headers,
        "body": body,
    }
    run = get_runtime().start(
        workflow,
        mode="webhook",
        trigger_type="webhook",
        trigger_node_id=trigger["id"],
        input_data=payload,
    )
    return JsonResponse({"accepted": True, "run_id": run.id, "status": run.status}, status=202)


def _workflow_cancelled(context):
    control = context.get("control")
    return bool(control and control.cancel.is_set())


def _workflow_engine_failure(result, message):
    if isinstance(result, dict) and result.get("reason") == "ROUTE_CHANGED":
        raise WorkflowCancelled()
    detail = result.get("error", message) if isinstance(result, dict) else message
    raise WorkflowValidationError(str(detail or message))


def _workflow_wait(context, seconds):
    deadline = time.monotonic() + max(0.0, float(seconds))
    while time.monotonic() < deadline:
        if _workflow_cancelled(context):
            raise WorkflowCancelled()
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))


def _workflow_poll_engine(path, delete_path, terminal_states, context, browser=False):
    while True:
        if _workflow_cancelled(context):
            if browser:
                call_browser_worker_delete(delete_path)
            else:
                call_engine_delete(delete_path)
            raise WorkflowCancelled()
        status, result = (call_browser_worker_get(path) if browser else call_engine_get(path))
        if status < 200 or status >= 300:
            raise WorkflowValidationError(str(result.get("error") if isinstance(result, dict) else result))
        if isinstance(result, dict) and str(result.get("status", "")).lower() in terminal_states:
            if str(result.get("status", "")).lower() == "cancelled":
                raise WorkflowCancelled()
            return result
        time.sleep(0.35)


# Project metadata is descriptive only. URL policy is not applied here; the
# operator's node-level filters below remain explicit workflow parameters.



def _workflow_repeater_requests(params, input_value):
    raw_items = params.get("requests")
    if raw_items is None:
        raw_items = params.get("inputs")
    if raw_items is None and params.get("urls") is not None:
        raw_items = params.get("urls")
    if raw_items is None:
        return [params]
    if not isinstance(raw_items, list):
        raw_items = [raw_items]
    base = params.get("base_request") if isinstance(params.get("base_request"), dict) else {}
    requests = []
    for item in raw_items:
        if isinstance(item, dict):
            request_payload = {**base, **item}
        else:
            request_payload = {**base, "url": str(item)}
        request_payload.setdefault("method", params.get("method", "GET"))
        request_payload.setdefault("headers", params.get("headers") or {})
        request_payload.setdefault("body", params.get("body", ""))
        if not request_payload.get("url"):
            request_payload["url"] = str(_workflow_lookup(input_value, "url") or "")
        requests.append(request_payload)
    return requests
def workflow_tool_runner(node_type, params, context):
    """Admit one workflow tool node to the current route generation."""
    workflow = context.get("workflow")
    run = context.get("run")
    project_id = getattr(run, "project_id", None) or getattr(workflow, "project_id", None)
    if project_id is None and getattr(workflow, "project", None) is not None:
        project_id = getattr(workflow.project, "id", None)
    with _outbound_runtime().operation("workflow-tool", project_id) as operation:
        try:
            operation.raise_if_cancelled()
            operation_context = dict(context)
            operation_context["outbound_operation"] = operation
            return _workflow_tool_runner(node_type, params, operation_context)
        except OutboundOperationCancelled as error:
            raise WorkflowCancelled() from error


def _workflow_tool_runner(node_type, params, context):
    """Adapter from typed workflow nodes to existing RequestRider tools."""
    workflow = context.get("workflow")
    run = context.get("run")
    project_id = getattr(run, "project_id", None) or getattr(workflow, "project_id", None)
    if project_id is None and getattr(workflow, "project", None) is not None:
        project_id = getattr(workflow.project, "id", None)
    input_value = context.get("input")
    if node_type == "repeater":
        request_payloads = _workflow_repeater_requests(params, input_value)
        delay_ms = max(0, int(params.get("delay_ms", params.get("rate_limit_ms", 0))))
        results = []
        for index, request_payload in enumerate(request_payloads):
            if _workflow_cancelled(context):
                raise WorkflowCancelled()
            request_payload["method"] = str(request_payload.get("method", "GET")).upper()
            request_payload["url"] = str(request_payload.get("url", "")).strip()
            request_payload["headers"] = request_payload.get("headers") if isinstance(request_payload.get("headers"), dict) else {}
            request_payload["body"] = request_payload.get("body", "")
            if not request_payload["url"]:
                raise WorkflowValidationError("Repeater URL is required")
            status, result = call_engine("/proxy/request", request_payload)
            if _workflow_cancelled(context):
                raise WorkflowCancelled()
            if status < 200 or status >= 300:
                _workflow_engine_failure(result, "Repeater failed")
            if isinstance(result, dict) and result.get("status") is not None:
                TrafficRecord.objects.create(
                    project_id=project_id,
                    source="repeater",
                    proxy_event_id=result.get("traffic_event_id"),
                    method=request_payload["method"],
                    url=request_payload["url"],
                    request_headers=request_payload["headers"],
                    request_body=request_payload["body"],
                    source_ip=result.get("source_ip") or None,
                    response_headers=result.get("headers") or {},
                    response_body=result.get("body") or "",
                    response_body_encoding=result.get("body_encoding", "utf8"),
                    response_body_base64=result.get("body_base64", ""),
                    response_content_type=result.get("body_content_type", (result.get("headers") or {}).get("Content-Type", "")),
                    status_code=result.get("status"),
                    latency_ms=result.get("time"),
                    response_size=result.get("size"),
                )
            results.append({"request": request_payload, "response": result, "status": result.get("status") if isinstance(result, dict) else None})
            if delay_ms and index < len(request_payloads) - 1:
                _workflow_wait(context, delay_ms / 1000)
        if len(results) == 1:
            return results[0]
        return {"items": results, "count": len(results), "status": results[-1].get("status") if results else None}

    if node_type == "repeater_burst":
        try:
            iterations = int(params.get("iterations", 3))
            concurrency = int(params.get("concurrency", 2))
            delay_ms = int(params.get("delay_ms", 0))
            timeout_ms = int(params.get("timeout_ms", 0))
        except (TypeError, ValueError) as error:
            raise WorkflowValidationError("Repeater Burst numeric parameters are invalid") from error
        if iterations < 1 or concurrency < 1 or delay_ms < 0 or timeout_ms < 0:
            raise WorkflowValidationError("Repeater Burst parameters must be non-negative and iterations/conurrency must be positive")
        method = str(params.get("method") or _workflow_lookup(input_value, "method") or "GET").upper()
        request_payload = {
            "method": method,
            "url": str(params.get("url") or _workflow_lookup(input_value, "url") or "").strip(),
            "headers": params.get("headers") if isinstance(params.get("headers"), dict) else {},
            "body": str(params.get("body") or ""),
            "iterations": iterations,
            "concurrency": concurrency,
            "delay_ms": delay_ms,
            "timeout_ms": timeout_ms,
        }
        if not request_payload["url"]:
            raise WorkflowValidationError("Repeater Burst URL is required")
        status, started = call_engine("/proxy/repeater-burst", request_payload)
        if status < 200 or status >= 300 or not isinstance(started, dict) or not started.get("burst_id"):
            _workflow_engine_failure(started, "Repeater Burst could not start")
        burst_id = str(started["burst_id"])
        control = context.get("control")
        if control is not None:
            control.add_cleanup(lambda: call_engine_delete(f"/proxy/repeater-burst/{burst_id}"))
        latest = started
        while True:
            if control and control.cancel.is_set():
                call_engine_delete(f"/proxy/repeater-burst/{burst_id}")
                raise WorkflowCancelled()
            status, latest = call_engine_get(f"/proxy/repeater-burst/{burst_id}")
            if status < 200 or status >= 300 or not isinstance(latest, dict):
                _workflow_engine_failure(latest, "Repeater Burst status failed")
            state = str(latest.get("status") or "")
            if state == "completed":
                for item in latest.get("results") or []:
                    if not isinstance(item, dict) or item.get("error"):
                        continue
                    TrafficRecord.objects.create(
                        project_id=project_id,
                        source="repeater",
                        proxy_event_id=item.get("traffic_event_id"),
                        method=request_payload["method"],
                        url=request_payload["url"],
                        request_headers=request_payload["headers"],
                        request_body=request_payload["body"],
                        source_ip=item.get("source_ip") or None,
                        response_headers=item.get("headers") or {},
                        response_body=item.get("body") or "",
                        response_body_encoding=item.get("body_encoding", "utf8"),
                        response_body_base64=item.get("body_base64", ""),
                        response_content_type=item.get("body_content_type", (item.get("headers") or {}).get("Content-Type", "")),
                        status_code=item.get("status"),
                        latency_ms=item.get("time"),
                        response_size=item.get("size"),
                    )
                return latest
            if state == "failed":
                raise WorkflowValidationError(str(latest.get("error") or "Repeater Burst failed"))
            if state == "cancelled":
                raise WorkflowCancelled()
            time.sleep(0.2)

    if node_type == "last_byte_sync":
        try:
            iterations = int(params.get("iterations", 1))
            concurrency = int(params.get("concurrency", 1))
            delay_ms = int(params.get("delay_ms", 0))
            hold_ms = int(params.get("hold_ms", 50))
            timeout_ms = int(params.get("timeout_ms", 0))
        except (TypeError, ValueError) as error:
            raise WorkflowValidationError("Last-Byte Sync numeric parameters are invalid") from error
        if iterations < 1 or concurrency < 1 or delay_ms < 0 or hold_ms < 0 or timeout_ms < 0:
            raise WorkflowValidationError("Last-Byte Sync parameters must be non-negative and iterations/concurrency must be positive")
        method = str(params.get("method") or _workflow_lookup(input_value, "method") or "POST").upper()
        request_payload = {
            "method": method,
            "url": str(params.get("url") or _workflow_lookup(input_value, "url") or "").strip(),
            "headers": params.get("headers") if isinstance(params.get("headers"), dict) else {},
            "body": str(params.get("body") or ""),
            "iterations": iterations,
            "concurrency": concurrency,
            "delay_ms": delay_ms,
            "hold_ms": hold_ms,
            "timeout_ms": timeout_ms,
        }
        if not request_payload["url"]:
            raise WorkflowValidationError("Last-Byte Sync URL is required")
        if not request_payload["body"]:
            raise WorkflowValidationError("Last-Byte Sync requires a non-empty request body")
        status, started = call_engine("/proxy/last-byte", request_payload)
        if status < 200 or status >= 300 or not isinstance(started, dict) or not started.get("last_byte_id"):
            _workflow_engine_failure(started, "Last-Byte Sync could not start")
        last_byte_id = str(started["last_byte_id"])
        control = context.get("control")
        if control is not None:
            control.add_cleanup(lambda: call_engine_delete(f"/proxy/last-byte/{last_byte_id}"))
        latest = started
        while True:
            if control and control.cancel.is_set():
                call_engine_delete(f"/proxy/last-byte/{last_byte_id}")
                raise WorkflowCancelled()
            status, latest = call_engine_get(f"/proxy/last-byte/{last_byte_id}")
            if status < 200 or status >= 300 or not isinstance(latest, dict):
                _workflow_engine_failure(latest, "Last-Byte Sync status failed")
            state = str(latest.get("status") or "")
            if state == "completed":
                for item in latest.get("results") or []:
                    if not isinstance(item, dict) or item.get("error"):
                        continue
                    TrafficRecord.objects.create(
                        project_id=project_id,
                        source="last-byte",
                        method=request_payload["method"],
                        url=request_payload["url"],
                        request_headers=request_payload["headers"],
                        request_body=request_payload["body"],
                        source_ip=item.get("source_ip") or None,
                        response_headers=item.get("headers") or {},
                        response_body=item.get("body") or "",
                        response_body_encoding=item.get("body_encoding", "utf8"),
                        response_body_base64=item.get("body_base64", ""),
                        response_content_type=item.get("body_content_type", (item.get("headers") or {}).get("Content-Type", "")),
                        status_code=item.get("status"),
                        latency_ms=item.get("time"),
                        response_size=item.get("size"),
                    )
                return latest
            if state == "failed":
                raise WorkflowValidationError(str(latest.get("error") or "Last-Byte Sync failed"))
            if state == "cancelled":
                raise WorkflowCancelled()
            time.sleep(0.2)

    if node_type in {"target", "target_browser"}:
        browser = node_type == "target_browser" or str(params.get("engine", "")) == "browser"
        capture_context = None
        raw_capture_context_id = params.get("capture_context_id")
        if browser and raw_capture_context_id not in (None, ""):
            try:
                capture_context_id = int(raw_capture_context_id)
            except (TypeError, ValueError) as error:
                raise WorkflowValidationError("Target browser capture_context_id must be numeric") from error
            capture_context = TrafficCaptureContext.objects.filter(id=capture_context_id, active=True).first()
            if not capture_context:
                raise WorkflowValidationError("Target browser capture context is unavailable")
        payload = {
            "url": str(params.get("url") or _workflow_lookup(input_value, "url") or "").strip(),
            "max_pages": int(params.get("max_pages", 0)),
            "max_depth": int(params.get("max_depth", -1)),
            "delay_ms": int(params.get("delay_ms", 0)),
            "same_origin": bool(params.get("same_origin", False)),
        }
        if not payload["url"]:
            raise WorkflowValidationError("Target URL is required")
        if browser:
            payload.update({
                "browser": str(params.get("browser", "firefox")),
                "actions": params.get("actions") or [],
                "allow_state_changing_actions": bool(params.get("allow_state_changing_actions", bool(params.get("actions")))),
            })
            route_status, route = call_engine_get("/route")
            if route_status != 200 or not isinstance(route, dict):
                raise WorkflowValidationError("cannot resolve active route for browser Target")
            payload["proxy_server"] = PASSIVE_PROXY_URL
            payload["proxy_mitm_ca"] = True
            if capture_context:
                payload["capture_context"] = capture_context.token
            status, result = call_browser_worker("/target", payload)
            if _workflow_cancelled(context):
                if isinstance(result, dict) and result.get("job_id"):
                    call_browser_worker_delete(f"/target/{result['job_id']}")
                raise WorkflowCancelled()
            path = f"/target/{result.get('job_id')}" if isinstance(result, dict) and result.get("job_id") else ""
        else:
            status, result = call_engine("/proxy/target-map", payload)
            path = f"/proxy/target-map/{result.get('map_id')}" if isinstance(result, dict) and result.get("map_id") else ""
        if status < 200 or status >= 300 or not path:
            _workflow_engine_failure(result, "Target could not start")
        job_id = str(result.get("job_id") or result.get("map_id") or result.get("id") or path.rsplit("/", 1)[-1])
        control = context.get("control")
        if control is not None:
            def cleanup_target_job(delete_path=path, browser_worker=browser):
                if browser_worker:
                    call_browser_worker_delete(delete_path)
                else:
                    call_engine_delete(delete_path)

            control.add_cleanup(cleanup_target_job)
        TargetJob.objects.update_or_create(
            job_id=job_id,
            defaults={
                "project_id": project_id,
                "capture_context": capture_context,
                "engine_kind": "browser" if browser else "static",
                "url": payload["url"],
                "status": str(result.get("status", "running")),
                "result": result,
            },
        )
        result = _workflow_poll_engine(
            path,
            path,
            {"completed", "cancelled", "failed", "error"},
            context,
            browser=browser,
        )
        TargetJob.objects.filter(job_id=job_id).update(
            status=str(result.get("status", "completed")),
            result=result,
        )
        return result
    if node_type == "oast_listener":
        server_url = str(params.get("server_url") or "http://127.0.0.1:8766").strip()
        poll_interval = int(params.get("poll_interval_sec", 3))
        timeout_sec = int(params.get("timeout_sec", 0))
        if poll_interval < 1 or timeout_sec < 0:
            raise WorkflowValidationError("OAST poll interval must be positive and timeout must be non-negative")
        payload = {
            "server_url": server_url,
            "listener_id": str(params.get("listener_id") or "").strip(),
            "poll_interval_sec": poll_interval,
            "timeout_sec": timeout_sec,
            "capture_protocols": params.get("capture_protocols") or ["http"],
        }
        status, result = call_engine("/proxy/oast", payload)
        if status < 200 or status >= 300 or not isinstance(result, dict) or not result.get("listener_id"):
            _workflow_engine_failure(result, "OAST Listener could not start")
        shared = context.get("shared")
        if isinstance(shared, dict):
            shared["oast"] = {
                "listener_id": result.get("listener_id"),
                "payload_url": result.get("payload_url"),
                "domain": result.get("domain"),
            }
        control = context.get("control")
        if control is not None:
            listener_id = str(result.get("listener_id"))
            control.add_cleanup(lambda: call_engine_delete(f"/proxy/oast/{listener_id}"))
        return result

    if node_type == "oast_collect":
        shared = context.get("shared") if isinstance(context.get("shared"), dict) else {}
        oast_context = shared.get("oast") if isinstance(shared.get("oast"), dict) else {}
        listener_id = str(oast_context.get("listener_id") or _workflow_lookup(input_value, "listener_id") or "").strip()
        if not listener_id:
            raise WorkflowValidationError("OAST listener_id is unavailable; connect OAST Listener in the same workflow run")
        poll_interval = float(params.get("poll_interval_sec", 1))
        timeout = float(params.get("timeout_sec", 0))
        if poll_interval <= 0 or timeout < 0:
            raise WorkflowValidationError("OAST poll interval must be positive and timeout must be non-negative")
        deadline = time.monotonic() + timeout if timeout > 0 else None
        control = context.get("control")
        latest = {}
        while deadline is None or time.monotonic() < deadline:
            if control and control.cancel.is_set():
                call_engine_delete(f"/proxy/oast/{listener_id}")
                raise WorkflowCancelled()
            status, latest = call_engine_get(f"/proxy/oast/{listener_id}")
            if status < 200 or status >= 300 or not isinstance(latest, dict):
                call_engine_delete(f"/proxy/oast/{listener_id}")
                raise WorkflowValidationError(str(latest.get("error", "OAST listener status failed") if isinstance(latest, dict) else "OAST listener status failed"))
            if latest.get("status") == "failed":
                call_engine_delete(f"/proxy/oast/{listener_id}")
                raise WorkflowValidationError(str(latest.get("error") or "OAST provider failed"))
            if latest.get("status") == "cancelled":
                call_engine_delete(f"/proxy/oast/{listener_id}")
                raise WorkflowCancelled()
            if latest.get("triggered") or latest.get("status") == "completed":
                call_engine_delete(f"/proxy/oast/{listener_id}")
                return latest
            time.sleep(poll_interval)
        if isinstance(latest, dict):
            call_engine_delete(f"/proxy/oast/{listener_id}")
            return {**latest, "triggered": bool(latest.get("triggered")), "timed_out": True}
        return {"listener_id": listener_id, "triggered": False, "timed_out": True, "events": []}

    if node_type == "osint":
        payload = {
            "url": str(params.get("url") or _workflow_lookup(input_value, "url") or "").strip(),
            "waf_check": bool(params.get("waf_check", False)),
        }
        if not payload["url"]:
            raise WorkflowValidationError("OSINT URL is required")
        status, result = call_engine("/proxy/osint", payload)
        if _workflow_cancelled(context):
            raise WorkflowCancelled()
        if status < 200 or status >= 300:
            _workflow_engine_failure(result, "OSINT failed")
        _ingest_osint_result(Project.objects.filter(id=project_id).first(), result)
        return result
    if node_type == "scanner":
        payload = {
            "url": str(params.get("url") or _workflow_lookup(input_value, "url") or "").strip(),
            "profile": str(params.get("profile", "generic_web")),
        }
        if not payload["url"]:
            raise WorkflowValidationError("Scanner URL is required")
        status, result = call_engine("/proxy/scanner", payload)
        if _workflow_cancelled(context):
            raise WorkflowCancelled()
        if status < 200 or status >= 300:
            _workflow_engine_failure(result, "Scanner failed")
        _ingest_scanner_tech(Project.objects.filter(id=project_id).first(), result)
        return result
    if node_type == "intruder":
        payload = {
            "base_request": params.get("base_request") or {},
            "mode": params.get("mode", "sniper"),
            "payloads": params.get("payloads") or [],
            "transformations": params.get("transformations") or [],
            "delay_ms": int(params.get("delay_ms", 150)),
            "concurrency": int(params.get("concurrency", 1)),
        }
        status, result = call_engine("/proxy/intruder", payload)
        if _workflow_cancelled(context):
            raise WorkflowCancelled()
        if status < 200 or status >= 300 or not isinstance(result, dict) or not result.get("attack_id"):
            _workflow_engine_failure(result, "Intruder could not start")
        attack_id = result["attack_id"]
        control = context.get("control")
        if control is not None:
            control.add_cleanup(lambda: call_engine_delete(f"/proxy/intruder/{attack_id}"))
        final = _workflow_poll_engine(
            f"/proxy/intruder/{attack_id}",
            f"/proxy/intruder/{attack_id}",
            {"completed", "cancelled", "failed"},
            context,
        )
        persist_intruder_history(int(attack_id), final.get("results") or [], final.get("result_offset", 0), project_id)
        return final
    if node_type == "ai_agent":
        if _workflow_cancelled(context):
            raise WorkflowCancelled()
        prompt = str(params.get("prompt") or "Analyze the attached QA evidence.")
        messages = [{"role": "user", "content": prompt}]
        try:
            result = generate_agent_chat(
                messages,
                provider=str(params.get("provider", "ollama")),
                endpoint=params.get("endpoint"),
                model=params.get("model"),
                context={"attached_evidence": {"workflow_input": input_value}},
                cancel_event=(
                    context["outbound_operation"].cancelled
                    if context.get("outbound_operation") is not None
                    else getattr(context.get("control"), "cancel", None)
                ),
            )
        except AgentRequestCancelled as error:
            raise WorkflowCancelled() from error
        if _workflow_cancelled(context):
            raise WorkflowCancelled()
        return result
    raise WorkflowValidationError(f"unsupported tool node: {node_type}")


def _workflow_lookup(value, path):
    current = value
    for part in str(path or "").split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current
