"""Django gateway views for the browser UI and Go execution engine."""

import base64
import binascii
import json
import logging
import os
import queue
import secrets
import socket
import threading
import time
from collections import OrderedDict
from http.client import RemoteDisconnected
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from django.db import OperationalError, connection
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse, StreamingHttpResponse
from django.db.models import Count, Prefetch, Q
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.csrf import ensure_csrf_cookie

from .models import ActiveScanJob, IntruderAttack, OsintEntity, OsintGraph, OsintRelation, Project, ProjectEndpoint, ProjectExchange, ProjectSecret, ScannerRun, TargetJob, TrafficCaptureContext, TrafficRecord, Workflow, WorkflowNodeExecution, WorkflowRun
from .agent_services import AgentProviderError, AgentRequestCancelled, cancel_active_agent_requests, generate_agent_chat
from .agent_loop import run_agent_loop
from .engine_client import (
    STREAM_CONNECT_TIMEOUT,
    engine_client,
    internal_service_headers,
)
from .ingest import capture_contexts_by_token, ingest_traffic_batch
from .middleware import ACTIVE_PROJECT_SESSION_KEY
from .project_context import ProjectContextBuilder, ProjectContextError, normalize_project_notes, normalize_tech_stack
from .project_transfer import (
    ProjectTransferError,
    export_bundle,
    import_bundle,
    parse_bundle_body,
)
from .pg_json import pg_storable
from .outbound_runtime import (
    OutboundOperationCancelled,
    current_outbound_operation,
    get_outbound_runtime,
)
from . import osint_exports
from . import target_browser_js as browser_js
from .report_i18n import report_language, report_text, set_report_language_cookie
from .osint_graph import (
    OsintGraphError,
    clear_graph,
    create_graph,
    delete_entity,
    delete_graph,
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
    validate_graph_schema_version,
    validate_workflow,
    workflow_requires_confirmation,
)
from .workflow_templates import list_templates
from .ws_events import emit_project_event, project_event_hub

# The gateway talks to the engine over HTTP; Docker can override this address.
# Per-request transport bound for one OAST provider round trip through the Go
# engine. It bounds a single call, never the listener: `timeout_sec` in the node
# still decides how long the operator waits for a callback, and a value the
# operator sets is never shortened by this. Visible on purpose, and overridable
# with RR_OAST_GATEWAY_TIMEOUT_MS.
_OAST_GATEWAY_TIMEOUT_DEFAULT_MS = 20_000

ENGINE_URL = os.environ.get("ENGINE_URL", "http://127.0.0.1:8081")
BROWSER_WORKER_URL = os.environ.get("BROWSER_WORKER_URL", "http://127.0.0.1:8090")
PASSIVE_PROXY_URL = os.environ.get("PASSIVE_PROXY_URL", "http://127.0.0.1:8080")

# A Playwright job legitimately runs for minutes (navigation, clicks, waiting for
# network idle), so the browser worker gets a longer transport deadline than the
# engine. It is a socket deadline on the local hop, not a cap on the crawl.
BROWSER_WORKER_TIMEOUT = float(os.environ.get("RR_BROWSER_WORKER_TIMEOUT", "900"))

# `/health` is polled continuously, so its probes have to stay cheap: three
# services answering immediately plus one `SELECT 1`. Two seconds is well above
# what any of them needs on loopback and well below anything an operator would
# call a hung service. Overridable from the environment like every other deadline
# in this file, and it bounds only how long the probe waits — not what the
# services may do.
HEALTH_PROBE_TIMEOUT = float(os.environ.get("RR_HEALTH_PROBE_TIMEOUT", "2"))

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
        return urlopen(
            Request(url, headers=internal_service_headers(headers)),
            timeout=SSE_READ_TIMEOUT,
        )
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
    # One random nonce per page load, carried by the single inline script block
    # and required by the Content-Security-Policy below. A fresh value every
    # load is the point: a nonce an attacker can predict is no nonce.
    csp_nonce = secrets.token_urlsafe(16)
    response = render(request, "lab/index.html", {
        "active_project_id": active_project.id if active_project else "",
        "csp_nonce": csp_nonce,
    })
    # The page is fully self-contained (no CDN, no webfonts, no external
    # scripts), so `script-src` needs nothing but this load's nonce — and that
    # is what makes the policy a second layer behind `escapeHTML` rather than
    # decoration. Two deliberate exceptions, both documented:
    # - `style-src 'unsafe-inline'`: six `<style>` blocks plus dozens of
    #   `style=` attributes set by the page's own code. Noncing every style
    #   would mean touching every renderer; style injection does not execute
    #   script in modern browsers, so this is the accepted trade.
    # - `img-src data: blob:`: exports and screenshots are built as object URLs.
    # - `script-src 'self'` alongside the nonce: the page ships one vendored
    #   library from its own origin (`/static/vendor/cytoscape-*.min.js`), and a
    #   `script-src` with a nonce and nothing else blocks every script element
    #   that has no nonce — including same-origin ones. That was measured in the
    #   console, not assumed: the OSINT entity-graph canvas never loaded its
    #   renderer, so the export was a static picture of a graph with an empty
    #   stage. The nonce still governs the one inline block, and `'self'` cannot
    #   be used by anything off-origin, so the policy is not weakened where it
    #   matters.
    response["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{csp_nonce}'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    return response


def project_event_status(request):
    """Report whether the current server can serve project WebSocket events."""
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    return JsonResponse({"websocket": project_event_hub.websocket_supported})


def health(request):
    """Liveness of the gateway itself, with the state of the services behind it.

    Every service in the stack answers `/health`, and Django was the only one that
    did not: the route map had no such entry, so a monitor probing all four on one
    port list got `404 Not Found` from Django forever, logged every few seconds,
    and never said anything about the services it was meant to check. The engine
    (`engine/main.go:1087`) and the browser worker already publish theirs.

    The gateway's own answer is `200` whenever this view runs — a non-200 would
    mean the process cannot serve at all, and the HTTP status is the signal, so
    duplicating it in the body would be decoration. What a reader cannot otherwise
    learn is whether the two Go/Python services behind the gateway are reachable,
    and that is what the body carries.

    Reachability is reported, not asserted: each service is asked with a short
    deadline, and a service that does not answer is reported `unavailable` with
    the reason rather than being folded into a single boolean. Collapsing them
    would repeat the failure this view exists to remove — a caller told "not
    healthy" cannot tell which service to restart.

    The probes are bounded by `HEALTH_PROBE_TIMEOUT`, not by the general engine
    timeout: this is polled continuously, so it must stay cheap and must not
    inherit a 120-second deadline. Both services answer immediately by design, so
    a probe that has to wait is a probe that found a problem, and the deadline is
    how long to wait before saying so.

    The PostgreSQL round trip is the one database check worth doing here: History,
    Traffic and every workflow read it, so a gateway serving 200 while the cluster
    is gone would report the opposite of the truth an operator is asking for.
    """
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)

    services = {}

    engine_status, engine_payload, engine_decoded = _probe_internal_service(ENGINE_URL, "/health")
    services["engine"] = {
        "ok": engine_status == 200 and engine_decoded,
        "status": engine_status,
        "error": None if (engine_status == 200 and engine_decoded) else (engine_payload or {}).get("error"),
    }

    worker_status, worker_payload = call_browser_worker_get("/health")
    # The worker's own client already turns an unparseable body into an error
    # payload, so the worker side needs no separate decode flag: a 200 with a
    # payload that has no `browsers` key is already shaped like a failure.
    worker_ok = worker_status == 200
    services["browser_worker"] = {
        "ok": worker_ok,
        "status": worker_status,
        "error": None if worker_ok else (worker_payload or {}).get("error"),
        # The browser catalogue rides along because the worker's own `/health` is
        # the only place a runtime's availability is measured: it launches each
        # one and names a reason for the ones it cannot start. Dropping that here
        # would make this endpoint a strict subset of the worker's, and the
        # operator reading it would have to make a second request to learn which
        # runtimes this installation actually has.
        "browsers": [str(name) for name in (worker_payload or {}).get("browsers") or []],
        "unavailable": {
            str(k): str(v) for k, v in ((worker_payload or {}).get("unavailable") or {}).items()
        },
    }

    database_ok = True
    database_error = None
    try:
        # `SELECT 1` against the same connection the application uses: an
        # existence query would be answered from the catalogue and would succeed
        # with the cluster read-only or the database dropped.
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
    except Exception as error:  # noqa: BLE001 - any driver error is the answer
        database_ok = False
        database_error = str(error)

    return JsonResponse(
        {
            "ok": True,
            "service": "web",
            "database": {"ok": database_ok, "error": database_error},
            "services": services,
        }
    )


def _probe_internal_service(base_url, path):
    """GET a service's `/health` with a short deadline.

    Returns `(status, payload, decoded)`. The third value says whether the body
    was the JSON this endpoint was written to read, and it is not decoration: a
    service answering `200` with an HTML error page is reachable but is not
    reporting health, and folding the two into one boolean would report a
    misconfigured service as healthy — the same failure this view exists to
    remove, one level up.

    A separate helper rather than a call to `call_engine_get`, because that one
    carries the route generation and the general 120-second engine timeout: both
    are wrong for a liveness probe. The generation would make a health answer
    depend on which route generation the browser last applied, and the deadline
    would let one wedged engine hold a health request open for two minutes — on
    an endpoint that is polled every few seconds.
    """
    try:
        request = Request(f"{base_url}{path}", headers=internal_service_headers(), method="GET")
        with urlopen(request, timeout=HEALTH_PROBE_TIMEOUT) as response:
            body = response.read()
            status = response.status
        try:
            return status, json.loads(body), True
        except ValueError:
            # Reachable, answering something other than health. The status is
            # kept as it arrived and the reason is named, so the caller sees a
            # live service with a wrong answer rather than a dead one.
            return status, {"error": "health response is not JSON"}, False
    except HTTPError as error:
        return error.code, {"error": error.read().decode(errors="replace")[:200]}, False
    except (URLError, TimeoutError, RemoteDisconnected, ConnectionError, socket.timeout) as error:
        return None, {"error": f"unavailable: {getattr(error, 'reason', error)}"}, False


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
        # Deleting a Project takes its endpoints, workflows and secret references
        # with it, so the row count is the only measure of what went.
        logger.warning("project_deleted project_id=%s affected_rows=%d", project_id, deleted)
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
    for target_job in (
        TargetJob.objects.filter(
            project=project,
            ingested=False,
            status__in=("completed", "cancelled", "failed", "error"),
        )
        .select_related("project")
        .only("id", "result", "status", "ingested", "project_id", "project__id")
    ):
        _ingest_target_job(target_job)
    # An active scan that finished into a closed tab has the same shape of problem
    # as an unpolled Target job — one chance to be recorded, and the chance is the
    # poll — so it is swept on the same read. The sweep asks the engine, which is
    # the only place that knows whether the run ended, and `settled` stops it from
    # asking about the same run twice.
    #
    # The import is local because `active_scanner_views` imports this module; at
    # module level the two would import each other.
    from lab import active_scanner_views

    active_scanner_views.sweep_active_scan_jobs()
    # The hub counts the Project's own exchanges, not the capture archive: the
    # number on a project card is a statement about the workspace, and it must
    # not drop because somebody cleared the Traffic tab.
    traffic = ProjectExchange.objects.filter(project=project)
    entities = list(
        OsintEntity.objects.filter(graph__project=project)
        .values("entity_type")
        .annotate(count=Count("id"))
        .order_by("entity_type")
    )
    graphs = list(
        OsintGraph.objects.filter(project=project)
        .order_by("-updated_at")
        .annotate(
            entities_count=Count("entities", distinct=True),
            relations_count=Count("relations", distinct=True),
        )
        .values(
            "id", "name", "version", "status", "updated_at",
            "entities_count", "relations_count",
        )
    )
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
            # `open_ports` was removed with the `port` entity type on 2026-09-29.
            # Nothing ever wrote a `port` entity — not the engine, not the ingest
            # path — so the sum was a guaranteed zero behind a label that offered no
            # way to make it anything else. A metric that cannot be non-zero is not a
            # measurement.
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
                "entities": item["entities_count"],
                "relations": item["relations_count"],
            }
            for item in graphs
        ],
        "ai_snapshot": ProjectContextBuilder(project.id).build_summary_markdown(),
        "vulnerabilities_summary": {
            "CRITICAL": sum(1 for r in ScannerRun.objects.filter(project=project) for f in (r.findings or []) if isinstance(f, dict) and str(f.get("severity") or "").upper() == "CRITICAL"),
            "HIGH": sum(1 for r in ScannerRun.objects.filter(project=project) for f in (r.findings or []) if isinstance(f, dict) and str(f.get("severity") or "").upper() == "HIGH"),
            "MEDIUM": sum(1 for r in ScannerRun.objects.filter(project=project) for f in (r.findings or []) if isinstance(f, dict) and str(f.get("severity") or "").upper() == "MEDIUM"),
            "LOW": sum(1 for r in ScannerRun.objects.filter(project=project) for f in (r.findings or []) if isinstance(f, dict) and str(f.get("severity") or "").upper() == "LOW"),
            "INFO": sum(1 for r in ScannerRun.objects.filter(project=project) for f in (r.findings or []) if isinstance(f, dict) and str(f.get("severity") or "").upper() == "INFO"),
        },
        "active_jobs": [
            {
                "type": "active_scan",
                "id": str(j.job_id),
                "url": j.url,
                "status": j.status,
            }
            for j in ActiveScanJob.objects.filter(project=project, settled=False).order_by("-id")[:10]
        ] + [
            {
                "type": "target_crawler",
                "id": str(t.job_id or t.id),
                "url": t.url,
                "status": t.status,
            }
            for t in TargetJob.objects.filter(project=project, ingested=False).exclude(status__in=("completed", "cancelled", "failed", "error")).order_by("-id")[:10]
        ],
    })


@csrf_exempt
def project_export(request, project_id):
    """Export one Project and every record scoped to it as a transfer bundle.

    The document is a complete copy of the workspace rather than a sample, and
    it is the one export that carries raw request and response bodies: the whole
    point of a bundle is that the imported workspace still holds the evidence.
    When summary=1 or no_bodies=1 is specified, request/response bodies are omitted
    to deliver a lightweight bundle suitable for fast report generation in the browser.
    """
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    project = Project.objects.filter(id=project_id).first()
    if not project:
        return JsonResponse({"error": "project not found"}, status=404)
    include_bodies = request.GET.get("summary") != "1" and request.GET.get("no_bodies") != "1"
    bundle = export_bundle(project, include_bodies=include_bodies)
    if request.GET.get("download") == "1":
        import re
        slug = re.sub(r"[^a-z0-9]+", "-", (project.name or "project").lower()).strip("-")[:48] or "project"
        response = HttpResponse(json.dumps(bundle, ensure_ascii=False), content_type="application/json; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="project-{project.id}-{slug}.json"'
        return response
    return JsonResponse(bundle)


@csrf_exempt
def project_fusion_report(request, project_id):
    """Return or export the Unified 4-Level Security Fusion Report for the Project."""
    if request.method not in ("GET", "POST"):
        return JsonResponse({"error": "method not allowed"}, status=405)
    project = Project.objects.filter(id=project_id).first()
    if not project:
        return JsonResponse({"error": "project not found"}, status=404)

    from lab.fusion_report import build_unified_fusion, generate_fusion_sarif, generate_fusion_html_report

    fusion_data = build_unified_fusion(project)
    fmt = str(request.GET.get("format") or "json").lower().strip()
    lang = str(request.GET.get("lang") or request.COOKIES.get("requestrider-language") or "uk").strip().lower()
    if not lang.startswith("en"):
        lang = "uk"
    else:
        lang = "en"

    if fmt == "sarif":
        sarif_doc = generate_fusion_sarif(fusion_data)
        response = HttpResponse(json.dumps(sarif_doc, indent=2, ensure_ascii=False), content_type="application/sarif+json")
        response["Content-Disposition"] = f'attachment; filename="fusion-report-project-{project.id}.sarif"'
        return response
    elif fmt == "html":
        html_doc = generate_fusion_html_report(fusion_data, lang=lang)
        if request.GET.get("download") == "1":
            response = HttpResponse(html_doc, content_type="text/html; charset=utf-8")
            response["Content-Disposition"] = f'attachment; filename="fusion-report-project-{project.id}.html"'
            return response
        return HttpResponse(html_doc, content_type="text/html; charset=utf-8")

    if request.GET.get("download") == "1":
        response = HttpResponse(json.dumps(fusion_data, indent=2, ensure_ascii=False), content_type="application/json; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="fusion-report-project-{project.id}.json"'
        return response

    return JsonResponse(fusion_data, json_dumps_params={"indent": 2, "ensure_ascii": False})


@csrf_exempt

@csrf_exempt
def project_hub_task_action(request, project_id, job_id, action):
    """Control background tasks from the Project Hub (cancel or dismiss/delete)."""
    if request.method not in ("POST", "DELETE"):
        return JsonResponse({"error": "method not allowed"}, status=405)
    project = Project.objects.filter(id=project_id).first()
    if not project:
        return JsonResponse({"error": "project not found"}, status=404)

    action = action.lower().strip()
    if action not in ("cancel", "dismiss", "delete"):
        return JsonResponse({"error": f"unsupported action: {action}"}, status=400)

    # 1. TargetJob match
    target_job = TargetJob.objects.filter(project=project).filter(
        Q(job_id=job_id) | (Q(id=int(job_id)) if job_id.isdigit() else Q())
    ).first()
    if target_job:
        if str(target_job.status).lower() in ("running", "pending", "unknown"):
            if target_job.engine_kind == "browser":
                call_browser_worker_delete(f"/target/{target_job.job_id}")
            else:
                call_engine_delete(f"/proxy/target-map/{target_job.job_id}")
        if action == "cancel":
            target_job.status = "cancelled"
            target_job.ingested = True
            target_job.save(update_fields=["status", "ingested", "updated_at"])
            return JsonResponse({"ok": True, "job_id": job_id, "status": "cancelled"})
        else:
            target_job.delete()
            return JsonResponse({"ok": True, "job_id": job_id, "dismissed": True})

    # 2. ActiveScanJob match
    scan_job = ActiveScanJob.objects.filter(project=project).filter(
        Q(job_id=job_id) | (Q(id=int(job_id)) if job_id.isdigit() else Q())
    ).first()
    if scan_job:
        if action == "cancel":
            call_engine(f"/proxy/scanner/active/jobs/{scan_job.job_id}/cancel", {})
            scan_job.status = "cancelled"
            scan_job.settled = True
            scan_job.save(update_fields=["status", "settled", "updated_at"])
            return JsonResponse({"ok": True, "job_id": job_id, "status": "cancelled"})
        else:
            call_engine(f"/proxy/scanner/active/jobs/{scan_job.job_id}/cancel", {})
            scan_job.delete()
            return JsonResponse({"ok": True, "job_id": job_id, "dismissed": True})

    return JsonResponse({"ok": True, "job_id": job_id, "dismissed": True, "message": "job not found or already settled"})


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


def _ingest_target_result(project, result):
    _ingest_target_result_once(project, result)


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


def _analyze_browser_job_scripts(result, job):
    """Give a finished browser-driven Target job the analysis the static crawl has.

    A browser reports every script it loaded as a URL and reads none of them, so
    without this the map lists the bundles and says nothing about what is in
    them. The static crawler analyses the same files while it fetches them; here
    it happens once, after the job has stopped, and the answers arrive in the same
    page shape the static crawl produces — so the table, the counters, the tree
    and the exporters draw both modes through one renderer.

    The work runs inside an outbound operation, so `Apply route` cancels it rather
    than storing bytes that were fetched through a generation that no longer
    exists: the next poll re-runs the analysis under the route now in force. A
    cancelled operation returns the worker's own result untouched, which is a
    complete answer to the poll and a truthful one.
    """
    if not isinstance(result, dict) or not browser_js.is_terminal(result):
        return result
    previous = job.result if job is not None and isinstance(job.result, dict) else None
    project_id = getattr(job, "project_id", None)
    try:
        with _outbound_runtime().operation("browser-target-js", project_id) as operation:
            operation.raise_if_cancelled()
            return browser_js.enrich_browser_target_result(result, previous=previous)
    except OutboundOperationCancelled:
        logger.info("browser_target_js_cancelled project=%s", project_id)
        return result


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
        _index_javascript_endpoints(project, page, url)
        entities.extend(_ingest_target_enrichment(project, page, url))
    if entities:
        graph, _ = OsintGraph.objects.get_or_create(
            project=project, version=1,
            defaults={"name": "Target observations", "source": "target"},
        )
        upsert_graph(graph, {"entities": entities, "relations": []})


# A crawler's own severity bands, mapped onto the two secret kinds the Project
# already stores. `api_key` is the kind for a credential a vendor key looks like;
# `leak` is the kind for something that matched a rule but scored low, and calling
# that an `api_key` would overstate it in every surface that lists the project.
_ENRICH_SECRET_KINDS = (("critical", "api_key"), ("high", "api_key"), ("medium", "api_key"), ("low", "leak"))


def _ingest_target_enrichment(project, page, page_url):
    """Index one crawled page's enrichment: secrets, hosts, files, addresses.

    `ProjectSecret` holds the credential the analyser found, in full. The
    operator crawled this page themselves and the key is the whole result of
    the crawl: a truncated fingerprint tells them a key exists and leaves them
    to go and find it again. So `value_ref` carries `finding["value"]`, and the
    analyser's fingerprint is only a fallback for a finding that somehow has no
    value of its own.

    Returns graph entities rather than writing them, so the caller keeps writing
    the graph in one place.
    """
    analysis = page.get("enrich")
    if not isinstance(analysis, dict):
        return []

    entities = []

    secrets = analysis.get("secrets")
    if isinstance(secrets, dict):
        for finding in secrets.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            rule = str(finding.get("rule") or "").strip()
            if not rule:
                continue
            severity = str(finding.get("severity") or "low").strip().lower()
            secret_type = "leak"
            for band, kind in _ENRICH_SECRET_KINDS:
                if band == severity:
                    secret_type = kind
                    break
            existing_secret = ProjectSecret.objects.filter(
                project=project,
                secret_type=secret_type,
                key_name=rule,
                source_url=str(page_url or ""),
            ).first()
            secret_value = str(finding.get("value") or finding.get("fingerprint") or "")
            if existing_secret is None:
                ProjectSecret.objects.create(
                    project=project,
                    secret_type=secret_type,
                    key_name=rule,
                    source_url=str(page_url or ""),
                    value_ref=secret_value,
                )
            elif secret_value and existing_secret.value_ref != secret_value:
                existing_secret.value_ref = secret_value
                existing_secret.save(update_fields=["value_ref", "updated_at"])

            # No graph entity for the secret: `OsintEntity.ENTITY_TYPE_CHOICES`
            # has no such type, and the first version of this function invented
            # one and the whole ingest died on `unsupported OSINT entity type`.
            # `ProjectSecret` is already the project's secret record and already
            # flows into the export, so a second place for the same fact is the
            # parallel path the project rule forbids. The rule id is in
            # `key_name`, the band in `secret_type`, the credential in
            # `value_ref` and the page in `source_url`.

    # `subdomain` is its own entity type in this schema, not a `domain` with a
    # flag. Using the schema's own vocabulary is what lets a graph query ask
    # "subdomains of X" without knowing about a property this function invented.
    for host in analysis.get("subdomains") or []:
        host = str(host or "").strip()
        if host:
            entities.append({"type": "subdomain", "identity": host, "properties": {"source": "target"}})

    for host in analysis.get("external_hosts") or []:
        host = str(host or "").strip()
        if host:
            entities.append({"type": "domain", "identity": host, "properties": {"source": "target", "kind": "external"}})

    for item in analysis.get("info") or []:
        if not isinstance(item, dict) or str(item.get("kind") or "") != "email":
            continue
        address = str(item.get("value") or "").strip()
        if address:
            entities.append({"type": "email", "identity": address, "properties": {"source": "target"}})

    # A ranked file is a URL the crawler found but, for the extension the table
    # puts near the top, may not have requested. Indexing it as an endpoint is
    # what lets the project answer "which PHP files does this site serve" from
    # the endpoint list rather than only from the crawl's own table.
    #
    # The severity travels in the graph, not in `ProjectEndpoint.statuses`:
    # that column holds HTTP status codes, and writing a 1..7 file rank into it
    # would make "which status codes does this endpoint return" answer with the
    # extension ranking. The first version of this function did exactly that.
    for entry in analysis.get("notable_files") or []:
        if not isinstance(entry, dict):
            continue
        file_url = str(entry.get("url") or "").strip()
        if not file_url:
            continue
        project.register_endpoint(file_url, "GET", None, None)
        entities.append({
            "type": "url",
            "identity": file_url,
            "properties": {
                "source": "target",
                "file_extension": str(entry.get("extension") or ""),
                "file_severity": entry.get("severity"),
            },
        })

    return entities


def _index_javascript_endpoints(project, page, script_url):
    """Index the endpoints a crawled JavaScript file names into the Project.

    A static crawl only reaches what a document links to, so an API the program
    calls but no page advertises stays invisible: the crawler never requests it,
    never gets a status for it, and the Project has no row for it. The engine
    parses those calls now (`analyzeJavaScript` in the Go crawler) and reports
    them on the page record as `js.endpoints`, each with the method and the
    parameter names the call site declared.

    What is indexed is metadata only: a path, a method, parameter names. No
    request or response, and no secret — the engine reports a secret as a rule
    name and a fingerprint precisely so that it cannot be stored here.

    References holding an unknown expression are skipped rather than indexed as
    literal paths. `/api/users/EXPR` is not a URL; storing it would put a row in
    the Project that no request can ever match, which reads as a discovered
    endpoint and is not one.
    """
    analysis = page.get("js")
    if not isinstance(analysis, dict):
        return
    endpoints = analysis.get("endpoints")
    if not isinstance(endpoints, list):
        return
    origin = urlsplit(script_url)
    if origin.scheme not in {"http", "https"} or not origin.netloc:
        return
    for entry in endpoints:
        if not isinstance(entry, dict):
            continue
        reference = str(entry.get("url") or "").strip()
        if not reference or "EXPR" in reference:
            continue
        method = str(entry.get("method") or "").strip().upper()
        # A call site that does not declare a method is not a GET. Leaving it
        # blank would index it as a GET and answer a question nobody asked.
        if not method:
            method = "UNKNOWN"
        resolved = urljoin(script_url, reference)
        if urlsplit(resolved).scheme not in {"http", "https"}:
            continue
        # Both parameter lists are recorded, because `ProjectEndpoint.parameters`
        # is a single list of names and the caller needs to know which of them
        # the call site put in the query string and which in the body. Which is
        # which is a difference between a GET and a POST, and it is already
        # carried by the method; the names are what a request has to supply.
        parameters = [str(name) for name in (entry.get("query_params") or []) if name]
        parameters += [str(name) for name in (entry.get("body_params") or []) if name]
        project.register_endpoint(resolved, method, None, parameters)


def _ingest_osint_result(project, result):
    _ingest_osint_result_once(project, result)


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


def _persist_tool_history(project):
    """Write the exchanges a tool just made into durable History.

    The engine's shared Traffic store receives both passive-proxy events and
    direct tool captures. `persist_proxy_history` turns those events into
    `TrafficRecord` rows, and it is normally driven by the Traffic tab's poll.
    That is the wrong trigger here: an operator who runs a scan and opens History
    has never opened Traffic, so the evidence of the scan they just ran would be
    missing from the tab they are looking at.

    One snapshot read per run, through the same batched writer and the same
    deduplication, so there is one persistence implementation and a repeated poll
    writes nothing twice.
    """
    status, result = call_engine_get("/events?detail=full")
    if status != 200 or not isinstance(result, list):
        return 0
    return persist_proxy_history(
        result, project.id if project else None, origin="engine_capture"
    )


_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _ingest_scanner_run(project, engine, url, findings, stats, templates=None):
    _ingest_scanner_run_once(project, engine, url, findings, stats, templates)


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


# Scanner stat keys that belong to a run report and not to the project journal.
# A planned nuclei run is executed as several invocations, and each of them keeps
# its own stdout and stderr; the duplicate summary likewise lists up to two
# hundred file groups with every alias path. Both stay whole in the run report the
# operator reads in the UI and in the API response, and neither is copied into a
# long-lived journal row: a console log and a path list of a finished run are not
# project evidence, and they would grow the database without bound. Nothing is
# summarised or trimmed — the key is either kept whole here or not kept at all.
_SCANNER_RUN_ONLY_STATS = {
    "stdout", "stderr", "invocations", "batch_detail", "deduplication",
    "validation_diagnostics", "args", "validation_args",
}


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
    durable = {
        key: value for key, value in stats.items()
        if key not in _SCANNER_RUN_ONLY_STATS
    }
    if "stdout" in stats or "stderr" in stats or "invocations" in stats:
        durable["full_output"] = "run report"
    return durable


def _ingest_scanner_run_once(project, engine, url, findings, stats, templates=None):
    """Append or idempotently update a scanner run in the project journal."""
    if not project:
        return None
    from .models import compute_finding_identity

    clean_url = str(url or "")
    items = []
    for item in findings or []:
        if not isinstance(item, dict):
            continue
        title = str(
            item.get("title")
            or item.get("vulnerability")
            or item.get("name")
            or item.get("check_id")
            or item.get("template_id")
            or ""
        ).strip()
        identity_hash = str(item.get("identity_hash") or compute_finding_identity(item, clean_url))
        finding_id = str(item.get("id") or identity_hash)
        items.append(pg_storable({
            "id": finding_id,
            "identity_hash": identity_hash,
            "title": title,
            "severity": str(item.get("severity") or "INFO").upper(),
            "evidence": str(item.get("evidence", "")),
            "recommendation": str(item.get("recommendation") or item.get("remediation") or ""),
            "template_id": str(item.get("template_id") or item.get("check_id") or item.get("scanner") or ""),
            "cve": [str(value) for value in item.get("cve") or []],
            "target": str(item.get("matched_at") or item.get("target") or item.get("url") or clean_url),
            "method": str(item.get("method") or "").upper(),
            "param": str(item.get("param") or item.get("parameter") or ""),
            "description": str(item.get("description") or ""),
        }))

    existing_run = ScannerRun.objects.filter(
        project=project,
        engine=engine,
        url=clean_url,
    ).order_by("-created_at").first()

    if existing_run:
        return existing_run.upsert_findings(
            [pg_storable(row) for row in items],
            stats=_durable_scanner_stats(stats),
            templates=_scanner_template_summary(templates),
        )

    severities = sorted(
        {str(item.get("severity") or "INFO").upper() for item in items},
        key=lambda level: _SEVERITY_RANK.get(level, 9),
    )
    return ScannerRun.objects.create(
        project=project,
        engine=engine,
        url=clean_url,
        summary={
            "findings_count": len(items),
            "highest_severity": severities[0] if severities else "INFO",
            "stats": _durable_scanner_stats(stats),
            "templates": _scanner_template_summary(templates),
        },
        findings=[pg_storable(row) for row in items],
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


# Tool runs carry a correlation context and the local passive-proxy address.
# Go tools record directly through the selected route transport; external
# binaries that only accept a proxy continue to record through the passive proxy.
def tool_run_route(request, kind, target):
    """File one tool run's traffic under its own correlation context.

    A scan sends seventeen requests, a nuclei run one per template, and an OSINT
    transform a handful of index queries. Without a context those rows are
    indistinguishable from ambient browser traffic in the capture stream, and
    History — which is the operator's record of what was sent on purpose — has
    no reason to show them at all.

    The context is created per run rather than reused so a second scan of the
    same target does not merge into the first, and it carries the tool and the
    target in its name because that name is what the row shows.
    """
    project = getattr(request, "active_project", None)
    label = " · ".join(part for part in (kind, str(target or "").strip()) if part)[:200]
    context = TrafficCaptureContext.objects.create(name=label or kind, project=project)
    return {"proxy": PASSIVE_PROXY_URL, "capture_context": context.token}


# HISTORY_FILTER_Q is what History shows: everything a tool or the operator sent
# on purpose.
#
# The passive `proxy` archive stays out of it, because that is what the Traffic
# tab and `GET /api/traffic/records` are for — mixing a browser's ambient
# traffic into History would bury the requests the operator asked for. What *is*
# in it is proxy traffic that a tool filed under an explicit correlation context:
# a scan, a nuclei run and an OSINT transform are requests the operator sent on
# purpose, and their evidence belongs with the rest of it.
#
# It is a Q rather than a `source__in` tuple because the proxy source now has
# two populations, and a tuple cannot tell them apart.
HISTORY_FILTER_Q = (
    Q(source__in=("repeater", "intruder", "last-byte"))
    | Q(source="proxy", capture_context__isnull=False)
    | Q(source="tool", capture_context__isnull=False)
)


def history(request):
    """Return filtered and sorted durable History records.

    The response shape is unchanged: `{"items": [...]}`. `limit` and `offset` are
    optional and default to the full result set, so existing callers are
    unaffected. A record carries complete request and response bodies, so
    serialising an unbounded History costs time and bytes proportional to every
    stored body; `select_related` keeps the per-row capture-context access out
    of the query path, and callers that only need a page should pass `limit`.
    """
    # History is persisted in PostgreSQL, unlike the in-memory passive Store.
    # `id` is the tiebreaker: a burst of exchanges shares a timestamp often
    # enough that ordering by time alone lets `limit`/`offset` pages repeat or
    # skip rows between two identical requests.
    project = _active_project(request, request.GET.get("project_id"))
    records = TrafficRecord.objects.select_related("capture_context").filter(
        HISTORY_FILTER_Q
    )
    if project:
        records = records.filter(Q(project=project) | Q(capture_context__project=project))
    records = records.order_by("-timestamp", "-id")
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
        # `total` is the size of the whole match, so it is counted before the
        # window is applied. Counting afterwards would report the length of the
        # page — which is exactly the number the caller already has — and the
        # `Load more` control would then never know that more rows exist.
        total = records.count()
        records = records[offset:offset + limit] if limit else records.none()
    elif offset:
        total = records.count()
        records = records[offset:]
    else:
        total = None

    return stream_history_items(
        records, omit_bodies=detail == "summary", total=total
    )


# The exact columns `history_item` reads. Selecting them explicitly lets Django
# build plain rows from the cursor instead of constructing one model instance per
# record, which is where almost all of the time went on a large History.
HISTORY_ITEM_FIELDS = (
    "id", "timestamp", "source", "host", "source_ip", "method", "url",
    "request_headers", "request_body", "status_code", "latency_ms",
    "response_headers", "response_body", "request_body_encoding",
    "request_body_base64", "response_body_encoding", "response_body_base64",
    "response_content_type", "response_size", "tags", "notes",
    "proxy_event_id", "proxy_session", "capture_context_id", "scope_status", "origin",
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
        "origin": row["origin"] or "client_supplied",
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


def stream_history_items(records, batch_size: int = 2000, omit_bodies: bool = False, total=None):
    """Send History as a streamed `{"items": [...], "total": N}` document.

    The payload is identical to the previous single-response body, but the first
    records reach the browser as soon as the cursor produces them instead of
    after every stored body has been materialised and serialised. Rows are read
    in batches, so the process no longer holds the whole History in memory while
    it answers a request.

    `total` is how many records the query matched, independent of the window that
    was requested; a caller that already counted before slicing passes it in, and
    a caller that did not slice gets it counted here. The browser needs it to know
    whether more rows exist and to label the `Load more` control with real counters
    instead of the "there may be more" guess it used to show.

    A small result is still returned as one `JsonResponse`: streaming buys
    nothing there, and callers that read the body as text keep working.
    """
    fields = HISTORY_ITEM_FIELDS
    if omit_bodies:
        fields = tuple(
            name for name in HISTORY_ITEM_FIELDS if name not in HISTORY_BODY_FIELDS
        )
    rows = records.values(*fields, "capture_context__name")
    if total is None:
        total = records.count()
    if total <= HISTORY_STREAM_THRESHOLD:
        return JsonResponse({
            "items": [history_item_from_row(row, omit_bodies) for row in rows],
            "bodies_omitted": omit_bodies,
            "total": total,
        })

    def generate():
        # The flag and the count are written into the document header so a
        # streamed listing tells the client exactly as much as a single-response
        # listing does.
        yield (
            b'{"bodies_omitted": ' + (b"true" if omit_bodies else b"false")
            + b', "total": ' + str(total).encode()
            + b', "items": ['
        )
        # One buffer per batch: yielding per row would add two hundred thousand
        # small writes, which is slower than the single response it replaced.
        #
        # The separator is a separate flag rather than a check on the buffer
        # because the buffer is emptied at every chunk boundary. Deriving the
        # separator from the buffer meant the first record after each boundary
        # was written with no `, ` in front of it, so any result large enough to
        # span two chunks came back as malformed JSON — the listing only ever
        # parsed while it stayed under one chunk, which is the one size nobody
        # tested.
        buffer = bytearray()
        separator = b""
        for row in rows.iterator(chunk_size=batch_size):
            buffer += separator
            buffer += json.dumps(
                history_item_from_row(row, omit_bodies), ensure_ascii=False, default=str
            ).encode()
            separator = b", "
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
        removed, _ = TrafficRecord.objects.filter(id=record_id).delete()
        logger.warning("history_record_deleted record_id=%s affected_rows=%d", record_id, removed)
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
        # The evidence field: an analyst reading History must be able to tell a row the
        # engine captured from one the gateway was handed by a caller.
        "origin": record.origin or "client_supplied",
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
            proxy_event_id__in=[
                result.get("traffic_event_id")
                if result.get("traffic_event_id") is not None
                else index
                for index, result, _ in candidates
            ],
        ).values_list("proxy_event_id", flat=True)
    )

    pending = []
    for index, result, request_data in candidates:
        event_id = result.get("traffic_event_id")
        if event_id is None:
            event_id = index
        if event_id in known_ids:
            continue
        response_headers = result.get("headers") or {}
        pending.append(TrafficRecord(
            project_id=project_id,
            source="intruder",
            host=urlsplit(request_data["url"]).netloc,
            source_ip=result.get("source_ip") or None,
            proxy_event_id=event_id,
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


def _event_id_as_int(value):
    """An id from the engine's snapshot as the integer the columns hold.

    The engine serialises `Event.ID` and `Event.Session` as JSON strings, while
    `TrafficRecord.proxy_event_id` and `proxy_session` are integer columns. A
    snapshot key therefore compared `"11"` against `11`, never matched, and every
    poll read the whole store as new: the deduplication this batch exists for could
    not fire. Both sides of the key go through this function, so the comparison is
    between like types and a value that is not an integer is left alone rather than
    forced into one.
    """
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return value


def persist_proxy_history(events, project_id=None, origin="client_supplied"):
    """Persist captured exchanges once for durable History and Traffic.

    `GET /api/traffic` hands this the engine's entire in-memory snapshot on every
    poll, so the previous per-event `filter().first()` probe and `create()` call
    scaled with the size of the live store rather than with the number of new
    events. The batch below costs three queries plus one `bulk_create`
    regardless of how large the snapshot is.

    `origin` is the evidence field this function exists to keep honest. Both the
    engine poll and `POST /api/traffic/save` arrive here, and they are not the same
    thing: one is the engine's own capture, the other is a body the gateway was handed
    and stored verbatim. The default is the **conservative** one, so a call site added
    later and left undeclared is marked as client-supplied rather than quietly acquiring
    the authority of a capture.
    """
    if not isinstance(events, list) or not events:
        return 0

    # Resolve every distinct capture token for the whole batch in one query.
    context_cache = capture_contexts_by_token(
        event.get("capture_context") for event in events if isinstance(event, dict)
    )

    candidates = []
    for event in events:
        if not isinstance(event, dict) or not event.get("url"):
            continue
        source = event.get("source") or "proxy"
        if source not in ("proxy", "route-check", "repeater", "intruder", "tool"):
            continue
        if event.get("status") is None and not event.get("error"):
            continue
        candidates.append((event, source))
    if not candidates:
        return 0

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
    # Both sides of the key are normalised the same way, so the comparison below is
    # between the types the columns actually hold rather than between a string and
    # the integer it spells.
    existing = {
        (source, _event_id_as_int(session), _event_id_as_int(event_id)): record
        for (source, session, event_id), record in existing.items()
    }

    pending = []
    ip_updates = []
    for event, source in candidates:
        event_id = _event_id_as_int(event.get("id"))
        session = _event_id_as_int(event.get("session"))
        if event_id is not None:
            found = existing.get((source, session, event_id))
            if found is not None:
                source_ip = event.get("source_ip") or None
                if source_ip and found["source_ip"] != source_ip:
                    ip_updates.append(TrafficRecord(id=found["id"], source_ip=source_ip))
                continue
        capture_context, scope_status = _capture_context_for_event(event, cache=context_cache)
        response_headers = event.get("response_headers") or {}
        pending.append(TrafficRecord(
            source=source,
            origin=origin,
            host=event.get("host", ""),
            source_ip=event.get("source_ip") or None,
            # The store's `id` is a string; `proxy_event_id` is an integer column, so
            # the key below is only comparable when both sides are the same type.
            # Persisting it verbatim made every snapshot a first sighting of every
            # exchange: `"11"` never equals `11`, so `existing` stayed empty, and a
            # repeated poll inserted a second row for an exchange already stored —
            # measured on a live `http/iot` run settled from the stream, the run's
            # single exchange became 3 rows.
            proxy_event_id=_event_id_as_int(event_id),
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
            notes=event.get("error") or event.get("notes") or "",
        ))

    if ip_updates:
        TrafficRecord.objects.bulk_update(ip_updates, ["source_ip"], batch_size=200)
    if not pending:
        return 0

    # bulk_create bypasses post_save, so the knowledge base is updated explicitly.
    TrafficRecord.objects.bulk_create(pending, batch_size=200)
    ingest_traffic_batch(pending)
    return len(pending)


def history_export(request):
    """Download all History records as a portable JSON document."""
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    records = TrafficRecord.objects.filter(HISTORY_FILTER_Q).order_by("timestamp", "id")
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
                # A history import is a caller-supplied body by definition, and it must
                # not be able to declare itself otherwise: the field is not read from
                # the payload at all. Defaulting through the model would be enough, but
                # saying it here means a reader of this call site does not have to know
                # that.
                origin="client_supplied",
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


def _oast_gateway_timeout() -> int:
    """Deadline for one OAST provider round trip through the Go engine.

    An OAST provider is a third party: it can accept a connection and stop
    answering. Without a deadline the workflow node blocks on that socket with no
    error, the run stays `running`, and the operator cannot tell the provider
    apart from the scan. The value is a per-request transport bound, not a limit
    on the listener itself: `timeout_sec` still decides how long the operator
    waits for a callback.

    Overridable with `RR_OAST_GATEWAY_TIMEOUT_MS`, and reported by
    `runtime_limits` so the applied bound is visible rather than hidden.
    """
    raw = str(os.environ.get("RR_OAST_GATEWAY_TIMEOUT_MS", "")).strip()
    try:
        configured = int(raw)
    except (TypeError, ValueError):
        configured = 0
    return configured if configured > 0 else _OAST_GATEWAY_TIMEOUT_DEFAULT_MS


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
    """Resolve which Project an incoming OAST callback belongs to.

    A supplied `project_id` is a **claim**, not a fact, and it used to be treated as one:
    `Project.objects.filter(id=…).first()` returned whatever project the caller named,
    so any caller could make the gateway publish an event into an arbitrary workspace.
    Attribution is the whole point of this endpoint, so an unattributable event is the one
    outcome that must not be manufactured.

    It is now honoured only when it names **this request's own active project**. Anything
    else falls back to the active project, which is what the callback gets when the
    workspace is the one that was active.

    This narrows a claim nobody can back and breaks no first-party caller: nothing in this
    repository posts to `/api/oast` — the engine polls the OAST provider itself
    (`engine/oast.go: pollOAST`) and consumes the events, so there was never a legitimate
    path that had to name a project it did not own.
    """
    project = getattr(request, "active_project", None)
    if project_id in (None, "") or project is None:
        return project
    try:
        project_id_int = int(project_id)
    except (TypeError, ValueError):
        return project
    if project_id_int <= 0 or project_id_int != project.id:
        return project
    return project


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


def _worker_headers(extra=None):
    """Headers for every browser-worker call, in one place.

    Like the engine, the worker refuses a request whose `Host` is not loopback,
    and that `Host` comes from `internal_service_headers` — the same function the
    engine calls use, so the two cannot end up configured differently.

    There is no service key any more: `RR_INTERNAL_API_KEY` and
    `X-RequestRider-Internal-Key` were removed end to end.
    """
    return internal_service_headers(extra)


def call_browser_worker(path, payload):
    """Start a browser-driven Target job in the isolated Playwright worker.

    A browser job legitimately runs for minutes, so it gets its own generous
    transport deadline instead of the engine default. Without one, a hung
    Playwright process would pin this request thread indefinitely.
    """
    request = Request(
        f"{BROWSER_WORKER_URL}{path}",
        data=json.dumps(payload).encode(),
        headers=_worker_headers({"Content-Type": "application/json"}),
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
        request = Request(f"{BROWSER_WORKER_URL}{path}", headers=_worker_headers(), method="GET")
        with urlopen(request, timeout=BROWSER_WORKER_TIMEOUT) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, {"error": error.read().decode(errors="replace"), "reason": "BROWSER_WORKER_ERROR"}
    except (URLError, TimeoutError, RemoteDisconnected, ConnectionError, socket.timeout) as error:
        return 502, {"error": f"browser worker unavailable: {getattr(error, 'reason', error)}", "reason": "BROWSER_WORKER_UNAVAILABLE"}


def call_browser_worker_delete(path):
    request = Request(f"{BROWSER_WORKER_URL}{path}", headers=_worker_headers(), method="DELETE")
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
        if status != 200:
            return JsonResponse(result, status=status)
        # Clearing means clearing wherever results are cleared, so the durable
        # archive goes with the live snapshot. Without this, `Clear` emptied the
        # screen and `Load more from database` handed back the very rows the
        # operator had just deleted — and a tool run writes its exchanges here,
        # so a cleared scan came straight back.
        #
        # Traffic and History share captured exchanges. Clear what Traffic owns —
        # `proxy` and `tool` — so a request cannot reappear after refresh, and
        # leave the sources whose tab owns them (`TRAFFIC_CLEARABLE_SOURCES`).
        #
        # What a Project holds is not touched: it keeps its own `ProjectExchange`
        # copy of every exchange, which is what the bundle and the hub read, so
        # the workspace still holds the evidence after the archive is gone.
        project = _active_project(request, request.GET.get("project_id"))
        clear_filter = Q(source__in=TRAFFIC_CLEARABLE_SOURCES)
        if project:
            clear_filter = clear_filter & (Q(project=project) | Q(capture_context__project=project))
        deleted, _ = TrafficRecord.objects.filter(clear_filter).delete()
        # Same reason as `history_bulk`: clearing the archive is irreversible from
        # the UI, so it must leave a line that says how much went.
        logger.warning("traffic_archive_cleared affected_rows=%d project_id=%s", deleted, project.id if project else None)
        payload = dict(result) if isinstance(result, dict) else {}
        payload["deleted"] = deleted
        return JsonResponse(payload, status=status)
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
        # The envelope is unwrapped HERE, before persistence, and not one line
        # later. It is the whole bug this fixes.
        #
        # MEASURED, 2026-10-09, live stand, Nuclei run against
        # `nuclei-templates/http/cves/2024`:
        #
        #   GET /events                  -> JSON list  (1502 events)
        #   GET /events?detail=summary   -> JSON object {"bodies_omitted":…,
        #                                                        "events":[…]}
        #
        # `persist_proxy_history` accepts a list and returns 0 for anything else,
        # so it silently persisted nothing on the summary shape. The Traffic tab
        # polls with `detail=summary` — that is what the parameter is for, it
        # leaves the captured bodies out of the snapshot — so the archive was
        # never written during ordinary use. Measured on the same stand: after a
        # poll WITH `detail` the table held 0 rows; after a poll without it,
        # 1469 rows, every one of them with `capture_context` set and every one
        # of them matching `HISTORY_FILTER_Q`.
        #
        # That is the operator's symptom exactly: the scan was visible in Traffic,
        # which is the live engine snapshot, and absent from History, which is
        # the PostgreSQL archive this call is the only writer of.
        #
        # The unwrap is deliberately not `public_traffic_events(result)`: that
        # strips the capture token, and the token is what files the exchange
        # under its correlation context. Persisting the stripped shape would
        # write every row with `capture_context=None` and `scope_status=unscoped`
        # — the archive would be populated and History would still be empty.
        # Raw for the archive, stripped for the browser, in that order.
        raw_events = result
        if isinstance(raw_events, dict) and isinstance(raw_events.get("events"), list):
            raw_events = raw_events["events"]
        persist_proxy_history(
            raw_events,
            getattr(request.active_project, "id", None),
            origin="engine_capture",
        )
        result = public_traffic_events(result)
    return JsonResponse(result, status=status, safe=isinstance(result, dict))


# The durable Traffic archive includes passive-proxy exchanges and direct tool
# captures, using the same event shape as the live engine snapshot.
TRAFFIC_ARCHIVE_FIELDS = HISTORY_ITEM_FIELDS
# The durable Traffic archive is the captured evidence Traffic owns: the passive
# proxy's exchanges and a tool's direct captures (a scan, an OSINT transform), which
# is why `tool` is here as well as `proxy`.
#
# It is **not** `repeater`, `intruder` and `last-byte`. Those travel through the proxy
# too, so they *were* listed here, and the archive then answered for rows whose tab
# owns them: measured on a live stand 2026-10-07,
# `test_traffic_archive_lists_persisted_proxy_records` counted 3 where the contract
# requires 2, with the test's own words being «A Repeater record is History, not
# passive Traffic, and must not be here». `AGENTS.md` says the same of the window:
# «`GET /api/traffic/records` отдаёт окно долговечного пассивного архива
# (`source="proxy"`)». A Repeater row is in History, and it stays there.
TRAFFIC_ARCHIVE_SOURCES = ("proxy", "tool")

# What `Clear` in Traffic is allowed to delete, which is **not** everything the
# archive lists.
#
# The two sets differ, and the difference is the point: the archive *shows* an
# Intruder exchange because that exchange really did travel through the proxy, but
# the Intruder tab owns the row, and `repeater`, `intruder` and `last-byte` are
# History's results — `AGENTS.md` states it outright («Предел очистки — источник, а
# не вкладка … `repeater`, `intruder` и `last-byte` не трогаются: это результаты
# History, и каждая вкладка чистит своё»). Clearing Traffic therefore deleted an
# analyst's Intruder results, which is data loss caused by an unrelated tab.
#
# `proxy` and `tool` are what Traffic owns and stay clearable, which is also what
# the reason for widening the predicate was: a cleared scan came back after a
# refresh because its exchanges were still in the archive. Measured on a live
# stand 2026-10-07: `test_clear_leaves_repeater_and_intruder_rows_alone` answered
# `[]` where the contract requires `['intruder', 'repeater']`.
TRAFFIC_CLEARABLE_SOURCES = ("proxy", "tool")

# How many durable Traffic rows one `Load more` press asks for. It is a transport
# window like any other, not a limit on the archive: every press asks for the next
# window and the counter on the control always names the rows still behind it.
TRAFFIC_ARCHIVE_PAGE = 500


def traffic_archive_item(row, omit_bodies: bool = False):
    """Serialize a stored tool or passive row into the engine `Event` shape.

    The live Traffic table already knows how to render an engine event, so the
    durable row is presented as one rather than as a second, parallel record
    shape. `db_id` is the marker the browser namespaces its row key with: a
    stored row and a live event share a number space, and without it one would
    silently replace the other in the same map.
    """
    item = history_item_from_row(row, omit_bodies)
    item["db_id"] = item["id"]
    item["id"] = row.get("proxy_event_id") or 0
    item["session"] = row.get("proxy_session") or 0
    item["source"] = row.get("source") or "proxy"
    item["source_ip"] = row.get("source_ip") or ""
    item["scope_status"] = row.get("scope_status") or "unscoped"
    return item


@csrf_exempt
def traffic_records(request):
    """Return one window of the durable Traffic archive.

    The live snapshot in `GET /api/traffic` is the engine's in-memory Store, and
    that Store is bounded by the current session: it starts empty after a restart
    and `Refresh traffic` empties it on purpose. Everything it held is persisted,
    so `Load more` in the Traffic tab reads the older exchanges from PostgreSQL here
    instead of asking the Store for rows it no longer has.

    `detail=summary` returns the row columns only, the same contract History uses,
    and the complete payload comes from `traffic_record` for the row the operator
    opens. `total` is the real size of the archive so the control can report
    "N of M" rather than guessing that more rows exist.
    """
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    detail = request.GET.get("detail", "summary").strip().lower()
    if detail not in {"full", "summary"}:
        return JsonResponse({"error": "detail must be full or summary"}, status=400)
    project = _active_project(request, request.GET.get("project_id"))
    records = TrafficRecord.objects.filter(source__in=TRAFFIC_ARCHIVE_SOURCES).select_related(
        "capture_context"
    )
    if project:
        records = records.filter(Q(project=project) | Q(capture_context__project=project))
    records = records.order_by("-timestamp", "-id")
    try:
        offset = int(request.GET.get("offset") or 0)
        limit = int(request.GET.get("limit") or TRAFFIC_ARCHIVE_PAGE)
    except (TypeError, ValueError):
        return JsonResponse({"error": "offset and limit must be numeric"}, status=400)
    if offset < 0:
        return JsonResponse({"error": "offset must not be negative"}, status=400)
    if limit < 0:
        return JsonResponse({"error": "limit must not be negative"}, status=400)
    total = records.count()
    rows = records.values(*TRAFFIC_ARCHIVE_FIELDS, "capture_context__name")[offset:offset + limit]
    omit_bodies = detail == "summary"
    return JsonResponse({
        "items": [traffic_archive_item(row, omit_bodies) for row in rows],
        "bodies_omitted": omit_bodies,
        "total": total,
        "offset": offset,
    })


@csrf_exempt
def traffic_record(request):
    """Return one complete durable passive Traffic row, payload included.

    The counterpart of `traffic_detail` for an archive row: the listing carries
    the columns, the exchange is read here when the operator opens it.
    """
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    raw_id = str(request.GET.get("id", "")).strip()
    if not raw_id.isdigit() or int(raw_id) <= 0:
        return JsonResponse({"error": "id must be a positive integer"}, status=400)
    row = TrafficRecord.objects.filter(
        source__in=TRAFFIC_ARCHIVE_SOURCES, id=int(raw_id)
    ).select_related("capture_context").values(
        *TRAFFIC_ARCHIVE_FIELDS, "capture_context__name"
    ).first()
    if row is None:
        return JsonResponse({"error": "traffic record not found"}, status=404)
    return JsonResponse(traffic_archive_item(row, omit_bodies=False))


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
            project = _active_project(request, payload.get("project_id"))
            clear_filter = HISTORY_FILTER_Q
            if project:
                clear_filter = clear_filter & (Q(project=project) | Q(capture_context__project=project))
            count, _ = TrafficRecord.objects.filter(clear_filter).delete()
            # A wipe is the one action an operator cannot reconstruct afterwards,
            # so it is recorded before the response goes out. `affected_rows` is
            # what makes the entry useful: "History was cleared" and "History was
            # cleared, 0 rows" are different facts.
            logger.warning(
                "history_cleared affected_rows=%d project_id=%s",
                count, project.id if project else None,
            )
            return JsonResponse({"ok": True, "deleted": count})
        ids = [int(value) for value in payload.get("ids", [])]
        if not ids or action not in {"delete", "metadata"}:
            raise ValueError("ids and action are required")
        records = TrafficRecord.objects.filter(id__in=ids)
        if action == "delete":
            count, _ = records.delete()
            logger.warning("history_rows_deleted affected_rows=%d requested_ids=%d", count, len(ids))
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


# The states an Intruder attack stops in. A poll in any other state is a poll of a
# run that is still working, and its traffic is not written yet — see the call site
# in `intruder`.
_INTRUDER_TERMINAL_STATES = {"completed", "cancelled", "failed", "stopped"}


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
            origin="engine_capture",
            proxy_event_id=result.get("traffic_event_id"),
            proxy_session=0,
            host=urlsplit(payload.get("url", "")).netloc,
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
    _persist_tool_history(project)
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
            project = attack.project if attack and attack.project_id else getattr(request, "active_project", None)
            persist_intruder_history(
                int(attack_id),
                result.get("results"),
                result.get("result_offset", 0),
                project.id if project else None,
            )
            # The attack's proxy exchanges are written once the attack is over, not
            # on every status poll. The poll is the hottest call in the Intruder UI,
            # and each one used to drag the engine's entire in-memory Traffic store
            # over the wire to re-derive rows that are already stored — measured on a
            # live stand 2026-10-07 with a populated store: 7 142 866 bytes per poll
            # for a write that deduplicates to nothing. `persist_intruder_history`
            # above already carries the results themselves, incrementally.
            if str(result.get("status", "")).lower() in _INTRUDER_TERMINAL_STATES:
                _persist_tool_history(project)
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
        # The same allowlist the saved-attack path applies. This handler also
        # writes the run to `IntruderAttack`, so an unchecked list would reach
        # `intruder_saved_item` and the unescaped renderer exactly as a poisoned
        # saved definition would.
        if payload.get("transformations"):
            payload["transformations"] = _validate_saved_transformations(payload["transformations"])
        # The detection config decides which results the table marks as a
        # successful login, so it is checked on the gateway rather than trusted
        # from the browser: an unknown signal name reaching the engine would be
        # dropped there, and the run would report verdicts while comparing less
        # than the operator asked for.
        if "detection" in payload:
            payload["detection"] = _validate_detection_config(payload["detection"])
        logger.info(
            "intruder_start mode=%s payload_sets=%d transformations=%d",
            payload.get("mode", ""),
            len(payload.get("payloads") or payload.get("dictionaries") or []),
            len(payload.get("transformations") or []),
        )
        with _outbound_runtime().operation("intruder", project.id if project else None) as operation:
            status, result = call_engine("/proxy/intruder", payload)
            operation.raise_if_cancelled()
    except InvalidRequestPayload as error:
        # Checked before the bare ValueError clause on purpose. InvalidRequestPayload
        # subclasses ValueError, so with the order reversed every precise message
        # an allowlist produced was replaced by "invalid JSON" — an operator who
        # mistyped a rule name was told their JSON was malformed instead of which
        # field was wrong. The order was the bug, not the message.
        return JsonResponse({"error": str(error)}, status=400)
    except (ValueError, TypeError):
        return JsonResponse({"error": "invalid JSON"}, status=400)
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
def target_map(request, map_id=None, action=None):
    # Target jobs run asynchronously in Go so the browser can poll progress
    # and cancel a crawl without blocking the Django request worker.
    """Start, inspect or control an asynchronous same-origin site map crawl."""
    resolved_map_id = str(map_id or request.GET.get("map_id", "")).strip()
    if action:
        if action not in {"pause", "resume", "resend", "cancel"}:
            return JsonResponse({"error": f"unknown crawl action: {action}"}, status=400)
        if not resolved_map_id.isdigit():
            return JsonResponse({"error": "map_id must be numeric"}, status=400)
        if request.method not in {"POST", "DELETE"}:
            return JsonResponse({"error": "method not allowed"}, status=405)
        body = {}
        raw_body = (request.body or b"").strip()
        if raw_body and "application/json" in str(request.content_type or "").lower():
            try:
                parsed = json.loads(raw_body)
                if isinstance(parsed, dict):
                    body = parsed
            except (ValueError, TypeError):
                return JsonResponse({"error": "invalid JSON"}, status=400)
        status, result = call_engine(f"/proxy/target-map/{resolved_map_id}/{action}", body)
        if status in {200, 202} and isinstance(result, dict):
            checkpoint = result.get("checkpoint")
            update_fields = {}
            if action == "pause":
                update_fields["status"] = "paused"
            elif action == "resume":
                update_fields["status"] = "running"
            elif action == "cancel":
                update_fields["status"] = "cancelled"
                update_fields["ingested"] = True
            elif result.get("status"):
                update_fields["status"] = str(result.get("status"))
            if isinstance(checkpoint, dict):
                update_fields["checkpoint"] = pg_storable(checkpoint)
            if update_fields:
                TargetJob.objects.filter(job_id=resolved_map_id).update(**update_fields)
        return JsonResponse(result, status=status)
    if request.method == "GET":
        if not resolved_map_id.isdigit():
            return JsonResponse({"error": "map_id must be numeric"}, status=400)
        status, result = call_engine_get(f"/proxy/target-map/{resolved_map_id}")
        if isinstance(result, dict):
            job_status = str(result.get("status", "unknown"))
            is_terminal = job_status.lower() in {"completed", "cancelled", "failed", "error"}
            checkpoint = result.get("checkpoint")
            update_fields = {"status": job_status}
            if isinstance(checkpoint, dict):
                update_fields["checkpoint"] = pg_storable(checkpoint)
            if is_terminal:
                # Write the full crawl result snapshot only when the job reaches a
                # terminal state so 500ms UI polling does not rewrite megabytes of
                # JSONB into PostgreSQL on every tick.
                update_fields["result"] = pg_storable(result)
            TargetJob.objects.filter(job_id=resolved_map_id).update(**update_fields)
            if is_terminal:
                job = TargetJob.objects.filter(job_id=resolved_map_id).select_related("project").first()
                _ingest_target_job(job)
        return JsonResponse(result, status=status)
    if request.method == "DELETE":
        if not resolved_map_id.isdigit():
            return JsonResponse({"error": "map_id must be numeric"}, status=400)
        status, result = call_engine_delete(f"/proxy/target-map/{resolved_map_id}")
        TargetJob.objects.filter(job_id=resolved_map_id).update(status="cancelled", ingested=True)
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
        checkpoint = result.get("checkpoint")
        TargetJob.objects.create(
            project=project,
            job_id=str(result["map_id"]),
            engine_kind="static",
            url=str(payload.get("url", "")),
            status=str(result.get("status", "running")),
            result=pg_storable(result),
            checkpoint=pg_storable(checkpoint) if isinstance(checkpoint, dict) else {},
        )
    return JsonResponse(result, status=status)


@csrf_exempt
def target_browsers(request):
    """Which browser runtimes this installation can actually start.

    The worker's `/health` measures this once at startup and names a reason for
    every name it cannot start. Nothing in the browser used to read that
    measurement, so the Target runtime dropdown offered five options on a
    machine with two of them, and picking the third one failed at launch instead
    of at selection — the operator had already typed the URL and pressed Build
    map by then.

    Two shapes come back, and they are different questions:

    * the worker's own answer, passed through as measured (`browsers`,
      `unavailable`, `checked_at`, `error`);
    * a failure to reach the worker, which is **not** "no browsers". That would
      be a silent lie in the other direction — the dropdown would empty itself
      and read as an installation with nothing installed, when in fact nobody
      asked. So it answers 502 with `reason` and leaves `browsers` empty.

    The runtime list itself is not invented here. The worker owns the catalogue
    (`BROWSER_NAMES`), and the UI compares the dropdown against what comes back,
    so adding a runtime in one place cannot leave the other naming a browser
    that does not exist.
    """
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    status, payload = call_browser_worker_get("/health")
    if status != 200 or not isinstance(payload, dict):
        return JsonResponse(
            {
                "browsers": [],
                "unavailable": {},
                "checked_at": None,
                "reason": "BROWSER_WORKER_UNAVAILABLE",
                "error": (payload or {}).get("error", "browser worker health check failed"),
            },
            status=502,
        )
    return JsonResponse(
        {
            "browsers": [str(name) for name in payload.get("browsers") or []],
            # Reasons are kept verbatim: they are the worker's own measured
            # wording ("camoufox browser is not fetched; run `python -m camoufox
            # fetch`") and rewriting them here would be a second thing to drift
            # from the code that produced them.
            "unavailable": {str(k): str(v) for k, v in (payload.get("unavailable") or {}).items()},
            "checked_at": payload.get("checked_at"),
            "error": payload.get("error"),
        }
    )


@csrf_exempt
def target_browser(request):
    """Start, inspect or cancel an isolated browser-driven Target job."""
    job_id = request.GET.get("job_id", "").strip()
    if request.method == "GET":
        if not job_id:
            return JsonResponse({"error": "job_id is required"}, status=400)
        status, result = call_browser_worker_get(f"/target/{job_id}")
        if isinstance(result, dict):
            job_status = str(result.get("status", "unknown"))
            is_terminal = job_status.lower() in {"completed", "cancelled", "failed", "error"}
            if is_terminal:
                job = TargetJob.objects.filter(job_id=job_id).select_related("project").first()
                # A browser-driven job reports every script it loaded as a URL and
                # nobody reads any of them, so the map would show the bundles and
                # stay silent about what is inside them. The static crawler analyses
                # the same files while it fetches them; here the analysis happens once,
                # when the job has stopped, and the answers come back in the crawler's
                # own page shape. A finished job re-polls until the UI stops asking, so
                # the stored answer is handed back rather than paid for again.
                result = _analyze_browser_job_scripts(result, job)
                TargetJob.objects.filter(job_id=job_id).update(
                    status=job_status, result=pg_storable(result),
                )
                _ingest_target_job(job)
            else:
                TargetJob.objects.filter(job_id=job_id).exclude(status=job_status).update(
                    status=job_status,
                )
        return JsonResponse(result, status=status)
    if request.method == "DELETE":
        if not job_id:
            return JsonResponse({"error": "job_id is required"}, status=400)
        status, result = call_browser_worker_delete(f"/target/{job_id}")
        TargetJob.objects.filter(job_id=job_id).update(status="cancelled", ingested=True)
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
    # The navigation deadline is the analyst's, and 0 means "no deadline". It is
    # validated here so a bad value is a clear 400 from the gateway instead of a
    # failure surfacing later as a worker error. A negative value is refused
    # rather than clamped: a silently clamped bound is the hidden cap this
    # parameter exists to remove.
    if "navigation_timeout_ms" in payload:
        raw_timeout = payload["navigation_timeout_ms"]
        if isinstance(raw_timeout, bool) or not isinstance(raw_timeout, int):
            return JsonResponse(
                {"error": "navigation_timeout_ms must be 0 or a positive integer"},
                status=400,
            )
        if raw_timeout < 0:
            return JsonResponse(
                {
                    "error": "navigation_timeout_ms must be 0 (no deadline) or a positive number of milliseconds"
                },
                status=400,
            )
    # Same contract for the automatic pass: the wait for the page to render a
    # form is the analyst's, and a negative value is refused rather than clamped.
    if "auto_wait_timeout_ms" in payload:
        raw_wait = payload["auto_wait_timeout_ms"]
        if isinstance(raw_wait, bool) or not isinstance(raw_wait, int):
            return JsonResponse(
                {"error": "auto_wait_timeout_ms must be 0 or a positive integer"},
                status=400,
            )
        if raw_wait < 0:
            return JsonResponse(
                {
                    "error": "auto_wait_timeout_ms must be 0 (no wait) or a positive number of milliseconds"
                },
                status=400,
            )
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
            result=pg_storable(result),
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
    """List, create, inspect and delete durable OSINT graphs.

    A graph belongs to a Project when the analyst uses one and to no Project at
    all when they do not, so ``project_id`` is optional on both the list and the
    create path. Without it the list is the project-less scope, which is where a
    graph created before any Project existed lives.

    ``DELETE`` on one graph removes the container and everything inside it. It
    asks for ``{"confirm": true}`` the same way ``.../clear`` does: both are
    irreversible and neither can be undone from the UI, so a request that is not
    the one the confirm dialog produced must not destroy evidence by accident.
    """
    if request.method == "GET":
        if graph_id is not None:
            graph = OsintGraph.objects.filter(id=graph_id).first()
            if not graph:
                return JsonResponse({"error": "OSINT graph not found"}, status=404)
            return JsonResponse(graph_item(graph, include_contents=True))
        raw_project_id = str(request.GET.get("project_id", "")).strip()
        if not raw_project_id:
            graphs = OsintGraph.objects.filter(project__isnull=True).order_by("-version")
            return JsonResponse({"items": [graph_item(graph) for graph in graphs]})
        if not raw_project_id.isdigit() or int(raw_project_id) <= 0:
            return _osint_graph_error(OsintGraphError("project_id must be a positive integer"))
        project = Project.objects.filter(id=int(raw_project_id)).first()
        if not project:
            return JsonResponse({"error": "project not found"}, status=404)
        graphs = OsintGraph.objects.filter(project=project).order_by("-version")
        return JsonResponse({"items": [graph_item(graph) for graph in graphs]})

    if request.method == "DELETE" and graph_id is not None:
        graph = OsintGraph.objects.filter(id=graph_id).first()
        if not graph:
            return JsonResponse({"error": "OSINT graph not found"}, status=404)
        try:
            payload = json.loads(request.body or b"{}")
        except json.JSONDecodeError:
            payload = {}
        if not isinstance(payload, dict) or payload.get("confirm") is not True:
            return JsonResponse({
                "error": "explicit confirmation is required to delete this graph",
                "reason": "DELETE_CONFIRMATION_REQUIRED",
            }, status=400)
        return JsonResponse({"deleted": delete_graph(graph)})

    if request.method != "POST" or graph_id is not None:
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict):
            raise OsintGraphError("request body must be an object")
        raw_project_id = payload.get("project_id")
        project = None
        if raw_project_id not in (None, ""):
            if isinstance(raw_project_id, bool):
                raise OsintGraphError("project_id must be numeric")
            try:
                project_id = int(raw_project_id)
            except (TypeError, ValueError) as error:
                raise OsintGraphError("project_id must be numeric") from error
            if project_id <= 0:
                raise OsintGraphError("project_id must be numeric")
            project = Project.objects.filter(id=project_id).first()
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


@csrf_protect
def bypass_forms_registry(request):
    """Which 403 bypass forms the engine has, for the Target control that offers them.

    The list is the engine's, not a copy kept here. ``_bypass_forms`` validates
    whatever names the operator submits against nothing on this side, and a form
    the engine can walk but this view does not know about would then be a form the
    operator cannot switch on. One source, read twice.

    A GET with no side effects, so it records no tool run and takes no route
    context — the same reason ``osint_transform_registry`` takes none.
    """
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    status, result = call_engine_get("/proxy/bypass/forms")
    return JsonResponse(result, status=status, safe=isinstance(result, dict))


# _OSINT_NETWORK_TRANSFORMS are the transforms that reach the network and
# therefore need an explicit confirmation before they run.
#
# `email_recon` joined this set on 2026-10-16. It was missing while the engine
# already performed a sixty-platform probe, and the consequence was specific: the
# page asks its question from the engine registry's `network` flag and sends
# `confirm_network` from that same answer, so a transform absent here could not be
# run at all — the operator's dialog never appeared, the run went out local-only,
# and the answer said verification was disabled.
#
# This list is a second copy of the registry flag, kept so the gateway refuses
# before the engine is called. The engine enforces the same rule independently
# (`transformIsNetwork`), so the two cannot disagree about whether a run is
# allowed — only about whether the refusal is instant.
_OSINT_NETWORK_TRANSFORMS = frozenset(
    {"subdomains", "github_recon", "reverse_dns", "dns_records", "wayback_urls", "s3_buckets",
     "email_recon", "username_search", "git_secrets", "secret_scan", "breach_exposure",
     "identity_graph", "cidr_range", "asn_lookup", "technology_probe", "http_probe"}
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
                # The index queries a transform makes — certificate indexes, an
                # archive chain, a public profile — are recorded by the engine's
                # capture transport under this run's name.
                **tool_run_route(request, "OSINT", f"{transform}: {value}"),
            })
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("OSINT transform")
    duration_ms = int((time.monotonic() - started_at) * 1000)
    engine_result = result if isinstance(result, dict) else {}
    engine_warnings = engine_result.get("warnings") or []
    _persist_tool_history(graph.project)
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
        logger.warning("OSINT transform persist failed: %s", error)
        return JsonResponse({
            "error": "the transform result could not be stored",
            "reason": "DATABASE_WRITE_FAILED",
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
                **tool_run_route(request, "OSINT", f"{transform}: {value}"),
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


# A finished job is written into the graph exactly once. Measured 2026-10-02 on
# `wayback_urls` for `pravda.ru`: the engine returned 24 992 entities and 24 991
# relations, and that write takes minutes, so the browser's next poll of the same
# finished job started a second write over the same rows. The duplicates all
# serialised on the first entity, the poll returned nothing, and the operator saw a
# transform that had finished and produced nothing while the database carried
# eleven copies of the same work.
#
# The set is per graph and bounded, and it is process-local on purpose: this
# project's scheduler and active runs are already process-local, and the state
# here is a "has this job already been written" fact rather than evidence. A
# restart only means a later poll of the same job writes once more, which is
# idempotent by construction — the upsert is keyed by type and identity.
_OSINT_PERSISTED_JOBS: dict[int, "OrderedDict[str, tuple[int, int, int, int]]"] = {}
_OSINT_PERSISTED_JOBS_LIMIT = 64
_OSINT_PERSIST_LOCK = threading.Lock()
_OSINT_JOB_LOCKS: dict[tuple, threading.Lock] = {}
_OSINT_JOB_LOCKS_LIMIT = 128


def _osint_job_lock(graph, job_id):
    """One lock per (graph, job), held across the write.

    A poll that arrives while a slow write is still running must wait for it
    rather than start a second one over the same rows. Without the lock the
    already-persisted mark is set only after the write returns, so the late
    poll does not see it and duplicates the whole batch.
    """
    key = (graph.id, job_id)
    with _OSINT_PERSIST_LOCK:
        lock = _OSINT_JOB_LOCKS.get(key)
        if lock is None:
            lock = _OSINT_JOB_LOCKS[key] = threading.Lock()
            while len(_OSINT_JOB_LOCKS) > _OSINT_JOB_LOCKS_LIMIT:
                _OSINT_JOB_LOCKS.pop(next(iter(_OSINT_JOB_LOCKS)))
    return lock


def _osint_job_already_persisted(graph, job_id):
    """Return the stored counts when this job was already written, else None."""
    if not job_id:
        return None
    with _OSINT_PERSIST_LOCK:
        return _OSINT_PERSISTED_JOBS.get(graph.id, {}).get(job_id)


def _osint_mark_job_persisted(graph, job_id, job_entities, job_relations, graph_entities, graph_relations):
    """Remember that this job is written, and with which two different numbers.

    They are different claims and mixing them is what a repeat poll used to report:
    `upsert_graph` counts **the whole graph** after the write, which is what the tab
    shows as "the graph holds N", while `transform_result.entity_count` is **what
    this run produced**. Storing only the first and reusing it for the second is how
    a `secret_scan` that found nothing answered `entity_count: 578` — measured
    2026-10-02 on live jobs, byte-identical to the `s3_buckets` run beside it.

    Both are kept, because the repeat response publishes both: the tab's total and
    the run's own count are each true, and either one alone is the wrong answer to
    the other question.
    """
    if not job_id:
        return
    with _OSINT_PERSIST_LOCK:
        seen = _OSINT_PERSISTED_JOBS.setdefault(graph.id, OrderedDict())
        seen[job_id] = (int(job_entities), int(job_relations), int(graph_entities), int(graph_relations))
        while len(seen) > _OSINT_PERSISTED_JOBS_LIMIT:
            seen.popitem(last=False)


def _osint_transform_job_result(graph, status, result, origin=None):
    """Turn one job poll into the browser-facing response, persisting on finish.

    The result is written **once per job**, not once per poll. Measured
    2026-10-02 on `wayback_urls` for `pravda.ru`: the engine finished with 24 992
    entities and 24 991 relations — 11.9 MB of JSON — and writing that into the
    graph takes minutes. A finished job stays pollable, so the browser's next
    poll arrived while the first write was still running and started a second
    one over the same rows. Eleven of those piled up, every one of them waiting
    on the first row, and the graph never reached its final state: the poll
    returned nothing at all and the operator saw a transform that had finished
    and produced nothing.
    """
    if status != 200 or not isinstance(result, dict):
        return JsonResponse(result if isinstance(result, dict) else {"error": "transform job is unavailable"}, status=status)
    state = result.get("state")
    if state not in {"completed", "failed", "cancelled"}:
        # A running or paused transform only carries progress, never a partial
        # result, so the browser cannot mistake a half-finished run for one.
        return JsonResponse(result, status=200)
    _persist_tool_history(graph.project)
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
    job_id = str(result.get("job_id") or result.get("id") or "").strip()
    # The lock spans the write, not just the check. A poll that arrives *during* a
    # slow write is not yet marked as persisted, so a check-then-write guard alone
    # would let it start a second write over the same rows — which is exactly the
    # convoy this replaces. Holding the lock makes the late poll wait for the first
    # write to finish and then find the mark, so it answers from the stored graph.
    with _osint_job_lock(graph, job_id):
        already = _osint_job_already_persisted(graph, job_id)
        if already:
            return _osint_job_already_written_response(graph, payload, state, result, already)
        try:
            response = _osint_transform_persist(graph, payload, origin)
        except OsintGraphError as error:
            return _osint_graph_error(error)
        except OperationalError as error:
            logger.warning("OSINT transform persist failed: %s", error)
            return JsonResponse({
                "error": "the transform result could not be stored",
                "reason": "DATABASE_WRITE_FAILED",
                "state": state,
            }, status=503)
        written = (response.get("upserted") or {})
        produced = (response.get("transform_result") or {})
        _osint_mark_job_persisted(
            graph,
            job_id,
            produced.get("entity_count", 0),
            produced.get("relation_count", 0),
            written.get("entities", 0),
            written.get("relations", 0),
        )
    response["state"] = state
    progress = result.get("progress") or {}
    response["progress"] = progress
    elapsed = progress.get("elapsed_ms")
    if isinstance(elapsed, (int, float)) and elapsed >= 0:
        response["transform_result"]["duration_ms"] = int(elapsed)
    return JsonResponse(response, status=200)


def _osint_job_already_written_response(graph, payload, state, result, already):
    """The response for a job that was written on an earlier poll.

    The block is the same one `_osint_transform_persist` builds, because
    `onFinish` reads `result.transform_result`: a repeat poll that omitted it would
    leave the panel saying nothing on the very response that follows the first.
    """
    job_entities, job_relations, graph_entities, graph_relations = already
    response = graph_item(graph, include_contents=True)
    response["transform_result"] = {
        "transform": payload.get("transform"),
        "value": str(payload.get("value") or ""),
        "observed_at": payload.get("observed_at"),
        "status": "completed" if (job_entities or job_relations) else "empty",
        "local_only": bool(payload.get("local_only")),
        "network_used": bool(payload.get("network_used")),
        # What this run produced, matching the first poll. The graph total has its
        # own place below and must not be substituted for it.
        "entity_count": job_entities,
        "relation_count": job_relations,
        "warnings": list(payload.get("warnings") or []),
        "metadata": dict(payload.get("metadata") or {}),
        "duration_ms": 0,
    }
    response["upserted"] = {
        "entities": graph_entities, "relations": graph_relations, "rejected": []
    }
    response["state"] = state
    progress = result.get("progress") or {}
    response["progress"] = progress
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
    counts = upsert_graph(graph, stored, skip_invalid=True)
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
    response = graph_item(graph, include_contents=True)
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
def _report_context(request, **extra):
    """Build the context every server-rendered report page shares.

    The language and the labels come from one place, so a page cannot render
    half of its wording in one language. The `{% tr %}` tag resolves a key
    against this same `language`, which is why the two travel together.
    """
    language = report_language(request)
    other = "uk" if language == "en" else "en"
    return {
        "language": language,
        "other_language": other,
        "other_language_label": "Українська" if other == "uk" else "English",
        "t_result_files": report_text(language, "result_files"),
        **extra,
    }


def _report_page(request, template, context):
    """Render a report page, or record a one-shot language choice and redirect.

    The control that changes the language is a link, not a script, so the page
    needs no JavaScript to speak either language. `?lang=` is only a setter: it
    writes the cookie and redirects to the same URL without it, because the
    cookie is the single source of the report's language. A link that both set
    the cookie and stayed on the page would leave two sources that could
    disagree, which is the defect this change exists to remove.

    An unsupported value is ignored rather than redirected on, so a stray
    `?lang=` cannot turn into a redirect loop.
    """
    requested = str(request.GET.get("lang") or "").strip().lower()
    if requested.startswith(("en", "uk")):
        query = request.GET.copy()
        query.pop("lang", None)
        encoded = query.urlencode()
        target = f"{request.path}?{encoded}" if encoded else request.path
        # 303, not the 302 a redirect carries by default: the request only
        # recorded a preference, and "See Other" says the next GET of the
        # clean URL is the page to keep.
        redirect = HttpResponseRedirect(target)
        redirect.status_code = 303
        return set_report_language_cookie(redirect, requested)
    return render(request, template, context)


def osint_graph_files(request, graph_id):
    """List the written result files of one graph.

    The directory form of the file URL used to fall through to the framework's
    debug 404, which told an analyst nothing about what the endpoint is. It now
    answers with the same page the viewer links back to.
    """
    graph = OsintGraph.objects.filter(id=graph_id).select_related("project").first()
    if not graph:
        return JsonResponse({"error": "OSINT graph not found"}, status=404)
    files = osint_exports.list_graph_files(graph.id)
    return _report_page(request, "lab/osint_result_files.html", _report_context(
        request,
        graph=graph,
        files=files,
        rows_total=sum(item["rows"] for item in files),
    ))


def osint_graph_file(request, graph_id, name):
    """Serve one written result file in the form the caller asked for.

    Three forms, one file. The default is the paginated viewer, because that is
    what an analyst opens the link for; `?raw=1` is the file exactly as written
    and `?download=1` hands the same bytes to the file system. No form invents,
    shortens or reorders the stored rows: the viewer pages over all of them.
    """
    graph = OsintGraph.objects.filter(id=graph_id).select_related("project").first()
    if not graph:
        return JsonResponse({"error": "OSINT graph not found"}, status=404)
    try:
        path = osint_exports.resolve_export_path(graph.id, name, download="download" in request.GET)
    except OsintGraphError as error:
        return _osint_graph_error(error)
    if "download" in request.GET:
        payload = path.read_bytes()
        response = HttpResponse(payload, content_type="text/plain; charset=utf-8")
        response["Content-Disposition"] = f'attachment; filename="{path.name}"'
        return response
    if "raw" in request.GET:
        # The structured copy is served as plain text so the browser shows it
        # verbatim rather than trying to interpret it.
        return HttpResponse(path.read_bytes(), content_type="text/plain; charset=utf-8")
    return _osint_result_file_page(request, graph, path)


def _osint_result_file_page(request, graph, path):
    """Render one page of the result viewer for a written file."""
    columns, rows = osint_exports.load_result_rows(path)
    try:
        requested_size = int(request.GET.get("page_size", osint_exports.RESULT_PAGE_SIZE))
    except (TypeError, ValueError):
        requested_size = osint_exports.RESULT_PAGE_SIZE
    if requested_size not in osint_exports.RESULT_PAGE_SIZES:
        requested_size = osint_exports.RESULT_PAGE_SIZE
    selection = osint_exports.select_rows(
        columns,
        rows,
        query=request.GET.get("q", ""),
        kind=request.GET.get("type", ""),
        sort=request.GET.get("sort", ""),
        direction=request.GET.get("dir", "asc"),
        page=request.GET.get("page", 1),
        page_size=requested_size,
    )
    siblings = osint_exports.list_graph_files(graph.id)
    same_stem = [item for item in siblings if item["name"].rsplit(".", 1)[0] == path.name.rsplit(".", 1)[0]]
    visible = osint_exports.active_columns(columns, rows)
    return _report_page(request, "lab/osint_result_file.html", _report_context(
        request,
        graph=graph,
        file=path,
        file_name=path.name,
        file_kind=path.suffix.lower().lstrip("."),
        file_bytes=path.stat().st_size,
        siblings=siblings,
        companions=[item for item in same_stem if item["name"] != path.name],
        columns=columns,
        visible_columns=visible,
        hidden_columns=[column for column in columns if column not in visible],
        rows_total=len(rows),
        selection=selection,
        query=request.GET.get("q", ""),
        kind=request.GET.get("type", ""),
        sort=request.GET.get("sort", ""),
        direction=request.GET.get("dir", "asc"),
        page_size=requested_size,
        page_sizes=osint_exports.RESULT_PAGE_SIZES,
    ))


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
                # The page fetch and WAF canary are recorded by the capture
                # transport.
                **tool_run_route(request, "OSINT", payload["url"]),
            })
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("OSINT")
    _ingest_osint_result(project, result)
    _persist_tool_history(project)
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
                # The capture transport records every request under this run's
                # name in History.
                **tool_run_route(request, "Scanner", payload["url"]),
            })
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("Scanner")
    _ingest_scanner_tech(project, result)
    _persist_tool_history(project)
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


def _nuclei_max_template_bytes():
    """How large one uploaded template document may be.

    Kept next to the upload path rather than in `settings.py` because it is a
    property of this endpoint, and the engine enforces the same number on its
    side (`maxTemplateBytes` in `engine/pkg/scanner/nuclei_exec.go`) so a direct
    call to `:8081` meets the same bound. `RR_NUCLEI_MAX_TEMPLATE_BYTES` overrides
    both, and the refusal names the value, so the limit is visible rather than
    silent.

    The default is 64 MiB, not 8 MiB. Measured 2026-10-07 against the shipped
    `nuclei-templates` corpus: exactly one document is larger than 8 MiB —
    `http/technologies/wordpress/plugins/wordpress-plugin-detect.yaml`, 10 079 081
    bytes — and `_nuclei_file_payload` raises for the **whole chunk** that carries
    it, so the browser's upload of the 11 664-file `http` folder stopped at chunk
    18 of 26 with HTTP 400 and the other ~300 templates in that chunk were never
    staged. A bound that refuses the operator's own corpus reduces the tool
    instead of protecting it; 64 MiB clears the largest real template and leaves
    the value overridable, still refused with a named reason.
    """
    try:
        configured = int(os.environ.get("RR_NUCLEI_MAX_TEMPLATE_BYTES", "").strip() or 0)
    except (TypeError, ValueError):
        configured = 0
    return configured if configured > 0 else 64 * 1024 * 1024


def _nuclei_file_payload(files):
    """Validate a chunk of templates and their relative-path support files."""
    if not isinstance(files, list) or not files:
        raise ValueError("files must be a non-empty list")
    limit = _nuclei_max_template_bytes()
    cleaned = []
    for item in files:
        if not isinstance(item, dict) or not str(item.get("name", "")).strip():
            raise ValueError("each file needs a name")
        content = item.get("content", "")
        if not isinstance(content, str):
            raise ValueError("each file content must be a string")
        name = str(item["name"]).strip()
        path = item.get("path", "")
        if path is not None and not isinstance(path, str):
            raise ValueError("each file path must be a string")
        source_name = str(path or name).replace("\\", "/").rsplit("/", 1)[-1]
        is_template = source_name.lower().endswith((".yaml", ".yml"))
        encoding = str(item.get("encoding", "") or "").strip()
        if encoding == "base64":
            try:
                decoded = base64.b64decode(content, validate=True)
            except (binascii.Error, ValueError) as error:
                raise ValueError(f"file {name!r} has invalid base64 content") from error
            content_size = len(decoded)
            if is_template and not decoded.strip():
                raise ValueError(f"template {name!r} needs YAML content")
        elif encoding == "":
            content_size = len(content.encode("utf-8"))
            if is_template and not content.strip():
                raise ValueError(f"template {name!r} needs YAML content")
        else:
            raise ValueError(f"file {name!r} has unsupported content encoding {encoding!r}")
        if is_template and content_size > limit:
            raise ValueError(
                f"file {name!r} exceeds the "
                f"{limit}-byte limit (TEMPLATE_TOO_LARGE)"
            )
        cleaned.append({
            "name": name,
            "path": str(path or "").strip(),
            "content": content,
            "encoding": encoding,
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
def scanner_nuclei_local(request):
    """Run the templates staged under an upload id through the engine's own runner.

    This is the path for templates the binary will not execute — the ones with a
    top-level `flow:`. nuclei 3.11.1 loads such a file, finds no runnable body
    and exits with "no templates provided for scan", so without this route the
    13.7 % of the official corpus that declares a flow is never checked, and the
    only honest way to say so is a separate report rather than a silent drop.

    The requests are sent by the engine's recording transport, so the exchanges
    land in History in the order they were sent, exactly as a binary run does.
    """
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict) or not str(payload.get("url", "")).strip():
            raise ValueError("url is required")
        # Either an upload id or an inline template set is required. A scan that
        # split one staged set hands its `flow:` half over inline, and requiring
        # an id there would reject the exact call the split exists to make.
        templates = payload.get("templates")
        if not str(payload.get("upload_id", "")).strip() and not (
            isinstance(templates, list) and templates
        ):
            raise ValueError("upload_id or templates is required")
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid scanner nuclei local run: {error}"}, status=400)
    project = getattr(request, "active_project", None)
    forwarded = {
        "url": str(payload["url"]).strip(),
        # The Go runner records through its capture transport; binaries use the
        # proxy path, and both produce the same run-scoped evidence.
        **tool_run_route(request, "nuclei_local", payload["url"]),
    }
    if str(payload.get("upload_id", "")).strip():
        forwarded["upload_id"] = str(payload["upload_id"]).strip()
    # A scan that split one staged set hands its `flow:` half over inline. The
    # two halves belong to the same run, so they cannot each carry an upload id:
    # the first call would consume the directory and the second would find it
    # already consumed.
    templates = payload.get("templates")
    if isinstance(templates, list) and templates:
        forwarded["templates"] = templates
    try:
        with _outbound_runtime().operation("nuclei_local", project.id if project else None) as operation:
            status, result = call_engine("/proxy/scanner/nuclei/local", forwarded)
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("Nuclei local run")
    _persist_tool_history(project)
    return JsonResponse(result, status=status)


def scanner_nuclei_template_dirs(request):
    """List the template folders and Nuclei template types available locally.

    The gateway passes this through rather than answering it: the folder list is
    whatever is on the engine host's disk, so an answer built here would describe
    the gateway's filesystem instead of the one nuclei reads.

    `call_engine_get` and not `call_engine`: the engine handler for this path
    accepts GET only, and `call_engine` POSTs. The first version of this view
    called `call_engine` with no payload at all, which raised `TypeError:
    call_engine() missing 1 required positional argument: 'payload'` and answered
    500 on every load of the panel — so both dropdowns stayed empty on a machine
    whose engine was answering 200 with 905 folders and 11 types. `call_engine_get`
    already exists for exactly this shape of call.
    """
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    status, result = call_engine_get("/proxy/scanner/nuclei/dirs")
    return JsonResponse(result, status=status)


@csrf_exempt
def scanner_nuclei_template_inspect(request):
    """Report what one template folder contains, including what it cannot run.

    `@csrf_exempt` like every other state-changing gateway view here, and for the
    reason `web/lab/middleware.py` records: the UI's own fetch calls do not attach
    `X-CSRFToken`, so without the exemption Django answers 403 before the view
    runs. The protection that replaced the exemption is
    `SameOriginMutationMiddleware`, which refuses a cross-origin POST with
    `CROSS_ORIGIN_REFUSED` — measured on a live stand, not assumed.

    Without this decorator the folder picker answered 403 on `Inspect`, so the
    panel could list folders but never say what one of them holds.
    """
    if request.method not in ("GET", "POST"):
        return JsonResponse({"error": "method not allowed"}, status=405)
    selection = request.GET.get("dir", "") if request.method == "GET" else ""
    if request.method == "POST":
        try:
            payload = json.loads(request.body)
            if not isinstance(payload, dict):
                raise ValueError("payload must be an object")
            selection = str(payload.get("dir", "") or "")
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            return JsonResponse({"error": f"invalid scanner nuclei inspect: {error}"}, status=400)
    if not str(selection).strip():
        return JsonResponse({"error": "dir is required"}, status=400)
    status, result = call_engine("/proxy/scanner/nuclei/inspect", {"dir": str(selection).strip()})
    return JsonResponse(result, status=status)


@csrf_exempt
def scanner_nuclei_run_dir(request):
    """Run a template folder named on disk and return the per-file report.

    This is the folder counterpart of `scanner_nuclei_run`. The folder belongs to
    the operator, so the gateway does not copy it, does not stage it and does not
    delete it: the engine reads it in place and the plan splits it into the
    invocations that can execute every document in it.

    `@csrf_exempt` for the reason given on `scanner_nuclei_template_inspect`.
    """
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict) or not str(payload.get("url", "")).strip():
            raise ValueError("url is required")
        if not str(payload.get("dir", "")).strip():
            raise ValueError("dir is required")
        tags, severity, options = _nuclei_string_lists(payload)
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid scanner nuclei run-dir: {error}"}, status=400)
    project = getattr(request, "active_project", None)
    try:
        with _outbound_runtime().operation("nuclei", project.id if project else None) as operation:
            status, result = call_engine("/proxy/scanner/nuclei/run-dir", {
                "url": str(payload["url"]).strip(),
                "dir": str(payload["dir"]).strip(),
                "category_path": str(payload.get("category_path", "") or "").strip(),
                "tags": [str(item).strip() for item in tags],
                "severity": [str(item).strip() for item in severity],
                "options": options,
                # Every template request the binary sends is recorded by the
                # proxy, in the order it sends them.
                **tool_run_route(request, "nuclei", payload["url"]),
            })
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("Nuclei")
    _persist_tool_history(project)
    if status == 200 and isinstance(result, dict):
        _ingest_scanner_run(
            project, "nuclei",
            payload["url"], result.get("findings"), result.get("stats"),
            templates=result.get("templates"),
        )
    return JsonResponse(result, status=status)


@csrf_exempt
def scanner_nuclei_run(request):
    """Run the templates staged under an upload id and return the per-file report.

    `@csrf_exempt` for the reason given on `scanner_nuclei_template_inspect`. The
    UI does not currently call this route — the background job `scanner_nuclei_jobs`
    replaced it — but it is part of the documented API and answers 403 to every
    caller, which is a defect in the contract rather than in a caller.
    """
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
                "category_path": str(payload.get("category_path", "") or "").strip(),
                "tags": [str(item).strip() for item in tags],
                "severity": [str(item).strip() for item in severity],
                "options": options,
                # Every template request the binary sends is recorded by the
                # proxy, in the order it sends them.
                **tool_run_route(request, "nuclei", payload["url"]),
            })
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("Nuclei")
    _persist_tool_history(project)
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


def _settle_nuclei_job(job_id, result):
    """Close a finished template job's durable record, once, whoever noticed it.

    A scan's traffic reaches History when the run is written down, and it is
    written down from the job's terminal state — not from the request that started
    the job, which returned long before the run finished. Two callers can observe
    that state: the status poll and the live stream. Which one the browser happens
    to use is a UI decision, and the UI's decision was the whole of the defect:

    the page finishes a run from the stream's `done` frame and only falls back to
    the status endpoint when the stream *breaks*. On the ordinary path the status
    request was therefore never made, `_persist_tool_history` never ran, and a
    completed scan left no rows in History. Measured on a live Firefox at
    1356x652: `http/iot` reported `Finished · 100% · 0:01 · templates 67 · requests
    50/50`, and `TrafficRecord` gained **zero** rows for that run, while
    `GET /events?detail=full` on the engine held 2641 events for it, each already
    carrying its `capture_context` token.

    So the stream settles the job too, and the two paths share this one function
    rather than growing two copies of the persistence. The lookup is a pop, so
    whichever caller gets there first settles it and the other finds nothing to do
    — a job is written down once even if the browser polls *and* streams.
    """
    if not isinstance(result, dict):
        return
    state = result.get("state")
    if state not in {"completed", "failed", "cancelled"}:
        return
    # Every terminal outcome can have captured traffic, so the record is settled
    # even when the scan itself failed or was cancelled.
    started = _forget_nuclei_job(job_id)
    project_id = started["project_id"] if started else None
    project = Project.objects.filter(id=project_id).first() if project_id else None
    _persist_tool_history(project)
    if state == "completed":
        report = result.get("result")
        if started and isinstance(report, dict):
            _ingest_scanner_run(
                project, "nuclei", started["url"],
                report.get("findings"), report.get("stats"),
                templates=report.get("templates"),
            )


def _nuclei_done_payload(chunk):
    """Read the terminal state out of one SSE frame, or nothing if it has none.

    The frame is forwarded to the browser byte for byte; this only reads it, so a
    malformed frame settles nothing instead of raising inside the stream and
    taking the run's results with it.
    """
    for line in chunk.split(b"\n"):
        text = line.strip()
        if not text.startswith(b"data:"):
            continue
        try:
            payload = json.loads(text[5:].strip().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if isinstance(payload, dict) and payload.get("state"):
            return payload
    return None


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
        settled = False
        frame = b""
        is_done_frame = False
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
                # The terminal frame is the one moment this proxy knows the run is
                # over, and the browser finishes the run from it. Settling the job
                # here is what puts a completed scan's exchanges into History; the
                # frame itself is passed through untouched.
                #
                # An SSE frame is several lines and a blank one ends it, so the
                # terminal frame is read as a whole rather than line by line: the
                # engine writes `id:`/`event:`/`data:` on separate lines
                # (`main.go`: `id: %d\nevent: %s\ndata: %s\n\n`), and settling on
                # the line that carries the event name would pass a frame with no
                # payload in it. Bytes are forwarded as they arrive either way, so
                # the browser still sees the frame the moment it is complete.
                frame += chunk
                if b"event: done" in frame:
                    is_done_frame = True
                if not chunk.strip():
                    # A blank line ENDS an SSE frame — it is the terminator, not
                    # filler, and an `EventSource` dispatches nothing without it.
                    # It used to be swallowed here: only lines with content were
                    # forwarded, so every frame ran into the next one and the
                    # browser received the whole run as a single unsplittable
                    # event. Measured through a real Firefox on `javascript/`
                    # (131 documents) against a live target: the engine held 30
                    # progress and 45 per-file events, and the browser got **zero**
                    # of them — the panel stayed on its pre-scan label for the
                    # whole run while the scan itself ran fine.
                    #
                    # `traffic_stream` in this same file is the working reference:
                    # it forwards every line, terminator included.
                    if is_done_frame and not settled:
                        settled = True
                        _settle_nuclei_job(job_id, _nuclei_done_payload(frame))
                        is_done_frame = False
                    frame = b""
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
def scanner_nuclei_template_dir_job(request):
    """Start an asynchronous run of a template folder named on disk.

    A folder is a job for the same reason an upload is: the official corpus is
    tens of thousands of documents, and the browser follows live progress and
    per-template events. Polling, streaming and pause/cancel therefore stay on the
    routes the upload run already uses — `scanner_nuclei_jobs` — so a folder run
    and an uploaded run are observed the same way and cannot drift apart.
    """
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict) or not str(payload.get("url", "")).strip():
            raise ValueError("url is required")
        if not str(payload.get("dir", "")).strip():
            raise ValueError("dir is required")
        tags, severity, options = _nuclei_string_lists(payload)
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid scanner nuclei folder job: {error}"}, status=400)
    project = getattr(request, "active_project", None)
    try:
        with _outbound_runtime().operation("nuclei", project.id if project else None) as operation:
            status, result = call_engine("/proxy/scanner/nuclei/jobs-dir", {
                "url": str(payload["url"]).strip(),
                "dir": str(payload["dir"]).strip(),
                "category_path": str(payload.get("category_path", "") or "").strip(),
                "tags": [str(item).strip() for item in tags],
                "severity": [str(item).strip() for item in severity],
                "options": options,
                **tool_run_route(request, "nuclei", payload["url"]),
            })
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("Nuclei")
    if status == 202 and isinstance(result, dict) and result.get("job_id"):
        _remember_nuclei_job(result["job_id"], project, payload["url"])
    return JsonResponse(result, status=status)


@csrf_exempt
def scanner_nuclei_jobs(request, job_id=None, action=None):
    """Start an asynchronous template run, or poll / control an existing one.

    A long folder scan is a background job so the browser can show live progress
    instead of waiting on one blocking request. The finished report is attached
    to the Project that started the run. `action` is one of cancel, pause and
    resume.

    `@csrf_exempt` for the reason given on `scanner_nuclei_template_inspect`. This
    is the view every template run goes through — `Run templates` posts here for
    an uploaded folder, and pause, resume and cancel post here too — so without it
    the button answered 403 CSRF and the whole Scanner template surface was
    unreachable from the UI. Measured on a live stand: `POST
    /api/scanner/nuclei/jobs` returned 403 while its sibling `jobs-dir` returned
    202, because that sibling has the exemption and this one did not.
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
        # A terminal state settles the run's durable record. The live stream
        # settles it too, and only one of the two gets to: the lookup is a pop.
        if status == 200 and isinstance(result, dict):
            _settle_nuclei_job(job_id, result)
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
                "category_path": str(payload.get("category_path", "") or "").strip(),
                "tags": [str(item).strip() for item in tags],
                "severity": [str(item).strip() for item in severity],
                "options": options,
                # A job outlives the request, so the context is remembered with
                # it and the run's exchanges are written when it finishes.
                **tool_run_route(request, "nuclei", payload["url"]),
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
                **tool_run_route(request, "nuclei", payload["url"]),
            })
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("Nuclei")
    _persist_tool_history(project)
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
                summary_markdown = ProjectContextBuilder(active_project.id).build_summary_markdown()
            except ProjectContextError as error:
                raise ValueError(f"Project context is unavailable: {error}") from error
            project_context = {
                "project_id": active_project.id,
                "include_notes": True,
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
            "max_tokens": payload.get("max_tokens") or 4096,
        }
        active_project = getattr(request, "active_project", None)
        try:
            with _outbound_runtime().operation("ai", active_project.id if active_project else None) as operation:
                route_status, route_data = call_engine_get("/route")
                if route_status == 200 and isinstance(route_data, dict):
                    proxy_address = str(route_data.get("address") or "").strip()
                    if proxy_address:
                        config["proxy_address"] = proxy_address
                # Run through the same ReAct loop as /api/agent/run so that the
                # evidence-only chat path actually has tools. Without this, the
                # agent could only write plans, which is the defect that produced
                # the session in /home/kali/Desktop/chat-session: rows read as
                # "history_search only provides metadata" and then the loop asked
                # the operator to paste bodies, even though they were a tool call
                # away. The "messages" the UI sends are kept as attached evidence
                # rather than as raw turns, because the loop owns the
                # conversation and re-derives the tool chain itself.
                last_user = ""
                for message in reversed(messages or []):
                    if isinstance(message, dict) and message.get("role") == "user" and message.get("content"):
                        last_user = str(message.get("content"))
                        break
                if not last_user:
                    last_user = "Аналізуй наданий евиденс."
                agent_result = run_agent_loop(
                    user_prompt=last_user,
                    provider=provider,
                    context=context,
                    max_steps=10,
                    cancel_event=operation.cancelled,
                    **config,
                )
                result = {
                    "message": agent_result.get("final_answer") or "",
                    "steps": agent_result.get("steps") or [],
                    "total_steps": agent_result.get("total_steps"),
                    "completed": agent_result.get("completed"),
                    "provider": provider,
                }
                operation.raise_if_cancelled()
        except (OutboundOperationCancelled, AgentRequestCancelled):
            return _agent_error("AI request cancelled by the route switch", "ROUTE_CHANGED", 409)
        return JsonResponse({"provider": provider, "message": result["message"], "steps": result.get("steps")})
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


# The transformation names the engine implements. This is a storage-side
# allowlist, not a payload restriction: a name outside it cannot be executed by
# `intruder.TransformPayload`, so accepting one would store a row that renders in
# the browser but can never run.
#
# The reason this is validated is a measured stored XSS, not a hypothetical one.
# `transformations` was accepted as an arbitrary JSON list and `intruder_saved_item`
# returned it verbatim, so `POST /api/intruder/saved` with
# `{"operation": "<img src=x onerror=…>"}` stored the string and
# `renderTransformations()` in the page wrote it into `innerHTML` unescaped: the
# payload became a live element in the operator's session and ran on load of the
# saved attack. The fix is in two layers on purpose — the name is validated here
# so a poisoned row is never written, and the renderer escapes it so a row that
# predates this check, or arrives through an import, still cannot execute.
#
# The list must hold every operation `intruder.TransformPayload` implements, and
# every one the transformation control in the page offers. It held eight of them
# while the engine implemented nineteen and the control offered thirteen, so an
# operator who chose `prepend`, `append`, `trim`, `lowercase`, `uppercase`,
# `htmlEntityEncode`, `jsonEscape`, `unicodeEscape` or `whitespaceNormalize` was
# answered `invalid JSON` — a message about their request that was not what was
# wrong, on a choice the panel itself had made for them. Measured through the
# browser on 2026-10-02; `IntruderTransformationCoverageTests` holds both lists.
INTRUDER_TRANSFORM_OPERATIONS = frozenset(
    {
        "urlEncode",
        "urlDecode",
        "base64Encode",
        "base64Decode",
        "base64UrlEncode",
        "base64UrlDecode",
        "hexEncode",
        "hexDecode",
        "htmlEntityEncode",
        "jsonEscape",
        "unicodeEscape",
        "whitespaceNormalize",
        "trim",
        "lowercase",
        "uppercase",
        "prepend",
        "append",
    }
)


def _validate_saved_transformations(transformations):
    """Return the transformations after checking each entry is a known step.

    Rejects the whole list rather than dropping the unknown entries: a partial
    save would hand the operator an attack that silently runs fewer
    transformations than the request asked for, and the difference would only
    show up in the payloads.
    """
    validated = []
    for index, transform in enumerate(transformations):
        if not isinstance(transform, dict):
            raise ValueError(f"transformations[{index}] must be an object")
        operation = transform.get("operation")
        if not isinstance(operation, str) or operation not in INTRUDER_TRANSFORM_OPERATIONS:
            raise ValueError(
                f"transformations[{index}].operation must be one of "
                + ", ".join(sorted(INTRUDER_TRANSFORM_OPERATIONS))
            )
        value = transform.get("value", "")
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise ValueError(f"transformations[{index}].value must be a string")
        # Only the two fields the engine reads are kept, so a saved definition
        # cannot carry extra keys into the stored JSON and back out to the page.
        validated.append({"operation": operation, "value": value} if value else {"operation": operation})
    return validated


INTRUDER_DETECTION_SIGNALS = frozenset(
    {"status", "redirect", "cookie", "length", "body"}
)
INTRUDER_DETECTION_RULE_TYPES = frozenset(
    {"status_equals", "body_contains", "body_not_contains", "header_contains"}
)
# The comparison is operator-chosen, so the only honest ceiling is a number the
# operator can see and change. A hundred calibration answers is already more
# than a login page needs to stabilise, and the field is a plain number in the
# UI, so nothing here hides a limit from the person running the attack.
INTRUDER_DETECTION_MAX_CALIBRATION = 100


def _validate_detection_config(config):
    """Return the login-detection config after checking every field.

    Same reasoning as the transformations allowlist: reject the whole object
    rather than drop what is unknown. A silently dropped signal is the worst
    outcome here, because the run would still report verdicts while comparing
    less than the operator asked for, and a login that matched nothing would
    look like a page with no signal.
    """
    if config is None:
        return None
    if not isinstance(config, dict):
        raise InvalidRequestPayload("detection must be an object")
    unknown = set(config) - {"enabled", "signals", "tolerance", "calibration_requests", "rules"}
    if unknown:
        raise InvalidRequestPayload("detection has unknown fields: " + ", ".join(sorted(unknown)))
    enabled = config.get("enabled", False)
    if not isinstance(enabled, bool):
        raise InvalidRequestPayload("detection.enabled must be a boolean")

    signals = config.get("signals")
    if signals is None:
        signals = []
    if not isinstance(signals, list) or not all(isinstance(name, str) for name in signals):
        raise InvalidRequestPayload("detection.signals must be a list of strings")
    for name in signals:
        if name not in INTRUDER_DETECTION_SIGNALS:
            raise InvalidRequestPayload(
                "detection.signals must only contain: "
                + ", ".join(sorted(INTRUDER_DETECTION_SIGNALS))
            )

    tolerance = _validate_detection_int(
        config.get("tolerance"), "detection.tolerance", minimum=0
    )
    # An absent or zero calibration count means "the engine's documented default",
    # not "take no samples": a run with no baseline can only use rules, and the
    # operator would not find out why from the result.
    calibration = config.get("calibration_requests")
    if calibration not in (None, 0):
        calibration = _validate_detection_int(
            calibration, "detection.calibration_requests", minimum=1
        )
    else:
        calibration = 0

    rules = config.get("rules") or []
    if not isinstance(rules, list):
        raise InvalidRequestPayload("detection.rules must be a list")
    validated_rules = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise InvalidRequestPayload(f"detection.rules[{index}] must be an object")
        rule_type = rule.get("type")
        if not isinstance(rule_type, str) or rule_type not in INTRUDER_DETECTION_RULE_TYPES:
            raise InvalidRequestPayload(
                f"detection.rules[{index}].type must be one of "
                + ", ".join(sorted(INTRUDER_DETECTION_RULE_TYPES))
            )
        value = rule.get("value", "")
        if value is None:
            value = ""
        if not isinstance(value, str) or not value.strip():
            raise InvalidRequestPayload(f"detection.rules[{index}].value must be a non-empty string")
        name = rule.get("name", "")
        if name is None:
            name = ""
        if not isinstance(name, str):
            raise InvalidRequestPayload(f"detection.rules[{index}].name must be a string")
        use_regex = rule.get("regex", False)
        if not isinstance(use_regex, bool):
            raise InvalidRequestPayload(f"detection.rules[{index}].regex must be a boolean")
        entry = {"type": rule_type, "value": value, "regex": use_regex}
        if rule_type == "header_contains":
            if not name.strip():
                raise InvalidRequestPayload(f"detection.rules[{index}].name is required for header_contains")
            entry["name"] = name
        validated_rules.append(entry)

    validated = {"enabled": enabled, "signals": signals, "tolerance": tolerance, "rules": validated_rules}
    # The calibration count is only sent when it is not the default, so an attack
    # saved without touching the field stays byte-comparable with an old one.
    if calibration:
        validated["calibration_requests"] = calibration
    return validated


def _validate_detection_int(value, label, minimum):
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidRequestPayload(f"{label} must be an integer")
    if value < minimum:
        raise InvalidRequestPayload(f"{label} must be at least {minimum}")
    if value > INTRUDER_DETECTION_MAX_CALIBRATION:
        raise InvalidRequestPayload(f"{label} must not exceed {INTRUDER_DETECTION_MAX_CALIBRATION}")
    return value


@csrf_exempt
def intruder_saved(request, attack_id=None):
        """List, save, or re-run persisted Intruder configurations."""
        if request.method == "GET" and attack_id is None:
            project = _active_project(request, request.GET.get("project_id"))
            attacks = IntruderAttack.objects.all()
            if project:
                attacks = attacks.filter(project=project)
            return JsonResponse({"items": [intruder_saved_item(item) for item in attacks.order_by("-created_at")]})
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
            transformations = _validate_saved_transformations(transformations)
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
        "graph_schema_version": workflow.graph_schema_version,
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
        logger.warning(
            "workflow_deleted workflow_id=%s name=%s active=%s",
            workflow_id, workflow.name, workflow.active,
        )
        return JsonResponse({"ok": True})

    if request.method not in {"POST", "PATCH", "PUT"}:
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = _workflow_body(request)
        existing = Workflow.objects.filter(id=workflow_id).first() if workflow_id is not None else None
        if workflow_id is not None and not existing:
            return JsonResponse({"error": "workflow not found"}, status=404)
        graph_schema_version = validate_graph_schema_version(
            payload.get(
                "graph_schema_version",
                existing.graph_schema_version if existing else None,
            )
        )
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
        workflow.graph_schema_version = graph_schema_version
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
        graph_schema_version = validate_graph_schema_version(
            source.get("graph_schema_version")
        )
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
            graph_schema_version=graph_schema_version,
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
            try:
                snapshot = run_item(WorkflowRun.objects.get(pk=run_id))
            except WorkflowRun.DoesNotExist:
                # Deleted between the 404 check above and the first read. There
                # is no longer anything to report, and inventing a terminal
                # status here would be a lie, so the stream ends instead of
                # raising a DoesNotExist traceback into a live response.
                return
            yield f"event: snapshot\ndata: {json.dumps(snapshot, ensure_ascii=False)}\n\n"
            if snapshot["status"] in {"completed", "failed", "cancelled", "interrupted"}:
                return
            cursor = len(snapshot["logs"])
            while True:
                try:
                    listener.get(timeout=1)
                except queue.Empty:
                    pass
                try:
                    current = run_item(WorkflowRun.objects.get(pk=run_id))
                except WorkflowRun.DoesNotExist:
                    # The run was deleted while the operator was watching it -
                    # a cascade cleanup or an explicit delete. Polling a row
                    # that no longer exists is not an error of the run, it is
                    # the end of the stream; raising here killed the response
                    # mid-flight and left the UI on a dead stream.
                    return
                new_events = current["logs"][cursor:]
                for event in new_events:
                    yield (
                        "event: workflow\n"
                        f"data: {json.dumps({'type': 'node', 'run_id': run_id, **event}, ensure_ascii=False)}\n\n"
                    )
                cursor += len(new_events)
                if current["status"] in {
                    "completed", "failed", "cancelled", "interrupted"
                }:
                    yield (
                        "event: workflow\n"
                        f"data: {json.dumps({'type': 'complete', 'run_id': run_id, 'status': current['status']}, ensure_ascii=False)}\n\n"
                    )
                    break
                if not new_events:
                    yield ": keepalive\n\n"
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
        run = (
            WorkflowRun.objects.filter(id=run_id)
            .select_related("workflow")
            .prefetch_related("node_executions")
            .first()
        )
        if not run:
            return JsonResponse({"error": "workflow run not found"}, status=404)
        return JsonResponse(run_item(run))
    queryset = (
        WorkflowRun.objects.select_related("workflow")
        .prefetch_related(
            Prefetch(
                "node_executions",
                queryset=WorkflowNodeExecution.objects.order_by("created_at", "id"),
            )
        )
        .order_by("-created_at")
    )
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


# How many 403 forms one crawl may be told to try, and how long a form name may
# be.
#
# These are engineering bounds, not a policy: they exist so a malformed request
# cannot turn a crawl into an unbounded fan-out, and they are checked here so the
# refusal is a named validation error rather than a silently truncated list. The
# bound does not reduce what the ladder can do -- every form stays available, and
# the operator selects among them -- so it is raised here, in one place, rather
# than assumed.
BYPASS_FORMS_MAX = 512
BYPASS_FORM_NAME_MAX = 64


def _bypass_forms(params):
    """The operator's 403-ladder selection, as a list of form names.

    Absent means "no ladder", and it returns an empty list rather than ``None``
    so the engine receives an explicit empty selection instead of a missing key:
    the two are different on the wire, and only one of them means "off".

    A single string is accepted as one form, because a node's parameters arrive
    from a form field that submits text. Anything else is a validation error
    naming the parameter, rather than a value the engine has to guess at.
    """
    raw = params.get("bypass_forms")
    if raw in (None, ""):
        return []
    if isinstance(raw, str):
        names = [raw]
    elif isinstance(raw, (list, tuple)):
        names = list(raw)
    else:
        raise WorkflowValidationError("Target bypass_forms must be a list of form names")

    cleaned = []
    for name in names:
        if not isinstance(name, str):
            raise WorkflowValidationError("Target bypass_forms must contain only form names")
        text = name.strip()
        if not text:
            continue
        if len(text) > BYPASS_FORM_NAME_MAX:
            raise WorkflowValidationError(
                f"Target bypass form name must be at most {BYPASS_FORM_NAME_MAX} characters"
            )
        cleaned.append(text)
    if len(cleaned) > BYPASS_FORMS_MAX:
        raise WorkflowValidationError(
            f"Target bypass_forms accepts at most {BYPASS_FORMS_MAX} forms, got {len(cleaned)}"
        )
    # Duplicates would make the ladder send the same request twice and report it
    # as two attempts, so the count in the log would not match the shapes.
    seen = set()
    return [name for name in cleaned if not (name in seen or seen.add(name))]


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
def record_workflow_node_progress(context, progress):
    """Persist partial node state so a suspended run can continue from it.

    A node that publishes more than one durable task has to say how far it got:
    "the node was waiting" is not enough to tell a completed request from one
    whose answer never arrived, and guessing means either losing a result or
    sending it twice.
    """
    from .models import WorkflowNodeExecution

    run = context.get("run")
    node = context.get("node") or {}
    node_id = str(node.get("id", ""))
    if run is None or not node_id or not isinstance(progress, dict):
        return
    WorkflowNodeExecution.objects.filter(
        workflow_run_id=run.pk,
        node_id=node_id,
    ).exclude(status="completed").update(
        output_data=progress,
        updated_at=timezone.now(),
    )


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
    from .engine_broker import (
        EngineTaskCancelled,
        EngineTaskDeferred,
        EngineTaskDispatchError,
        WORKFLOW_ENGINE_BROKER_ENABLED,
        dispatch_workflow_engine_task,
    )

    def dispatch_engine_task(task_type, payload, task_id=""):
        try:
            return dispatch_workflow_engine_task(task_type, payload, context, task_id=task_id)
        except EngineTaskCancelled as error:
            raise WorkflowCancelled() from error
        except EngineTaskDeferred:
            # A suspended node is not a failure and not a bad request either.
            # `EngineTaskDeferred` subclasses `EngineTaskDispatchError`, so the
            # broad handler below swallows the suspension signal and re-raises
            # it as `WorkflowValidationError`. The run loop cannot tell those
            # apart: it parks a deferred node in `waiting` and the result
            # consumer resumes the graph, while a validation error rejects the
            # run outright. That turned every broker-dispatched node into a
            # permanent `failed` run whose message named the symptom
            # ("engine task ... is running outside the graph worker") instead
            # of the cause. Rethrown first so the type survives.
            raise
        except EngineTaskDispatchError as error:
            raise WorkflowValidationError(str(error)) from error

    workflow = context.get("workflow")
    run = context.get("run")
    project_id = getattr(run, "project_id", None) or getattr(workflow, "project_id", None)
    if project_id is None and getattr(workflow, "project", None) is not None:
        project_id = getattr(workflow.project, "id", None)
    input_value = context.get("input")
    # Durable partial state of this node, if it suspended on an external action
    # before. A resumed node continues from it instead of publishing that action
    # a second time.
    progress = context.get("node_progress") or {}
    if not isinstance(progress, dict):
        progress = {}
    progress_task_id = str(progress.get("task_id") or "")
    if node_type == "repeater":
        request_payloads = _workflow_repeater_requests(params, input_value)
        delay_ms = max(0, int(params.get("delay_ms", params.get("rate_limit_ms", 0))))
        done = progress.get("results")
        results = list(done) if isinstance(done, list) else []
        for index, request_payload in enumerate(request_payloads):
            if _workflow_cancelled(context):
                raise WorkflowCancelled()
            if index < len(results):
                continue
            request_payload["method"] = str(request_payload.get("method", "GET")).upper()
            request_payload["url"] = str(request_payload.get("url", "")).strip()
            request_payload["headers"] = request_payload.get("headers") if isinstance(request_payload.get("headers"), dict) else {}
            request_payload["body"] = request_payload.get("body", "")
            if not request_payload["url"]:
                raise WorkflowValidationError("Repeater URL is required")
            if WORKFLOW_ENGINE_BROKER_ENABLED:
                # The task ID of the request that was in flight when the node
                # suspended, so a resumed node waits for that same action instead
                # of publishing it again.
                resume_task_id = progress_task_id if index == len(results) else ""
                try:
                    result = dispatch_engine_task(
                        "request.execute",
                        request_payload,
                        task_id=resume_task_id,
                    )
                except EngineTaskDeferred as deferred:
                    record_workflow_node_progress(
                        context,
                        {"results": results, "task_id": deferred.task_id},
                    )
                    raise
                status = 200
            else:
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
            if WORKFLOW_ENGINE_BROKER_ENABLED and index < len(request_payloads) - 1:
                # The answer is durable now, so it is written before the next
                # request is published. Without this the resumed run would only
                # know that *some* request was in flight, not which ones are
                # already done, and would repeat the completed ones.
                record_workflow_node_progress(context, {"results": results})
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
            # Anti-detect only means something to a browser, so it is read here
            # and not sent to the static engine, which has no DOM to drive and
            # no JavaScript to run.
            payload["anti_detect"] = bool(params.get("anti_detect", True))
            # Form mode drives clicks and form filling on its own, so a node that
            # asks for it is asking for state-changing actions too. The worker
            # refuses the combination otherwise, and a silent downgrade would
            # report a coverage the node never had.
            allow_state_changing = bool(params.get(
                "allow_state_changing_actions",
                bool(params.get("actions")) or str(params.get("mode", "")) == "form",
            ))
            payload.update({
                "browser": str(params.get("browser", "firefox")),
                "actions": params.get("actions") or [],
                "allow_state_changing_actions": allow_state_changing,
                "auto_interact": bool(params.get("auto_interact", str(params.get("mode", "")) == "form")) and allow_state_changing,
                "auto_fill": bool(params.get("auto_fill", True)),
                "auto_click": bool(params.get("auto_click", True)),
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
            # The static crawler's own request shape. accept_language is
            # identity, so an absent key means no header at all rather than a
            # guessed one, and a negative retry count is refused rather than
            # clamped into a bound nobody asked for.
            try:
                retry_attempts = int(params.get("retry_attempts", 0))
            except (TypeError, ValueError) as error:
                raise WorkflowValidationError("Target retry_attempts must be a number") from error
            if retry_attempts < 0:
                raise WorkflowValidationError("Target retry_attempts must not be negative")
            accept_language = str(params.get("accept_language") or "").strip()
            if len(accept_language) > 120:
                raise WorkflowValidationError("Target accept_language must be at most 120 characters")
            if accept_language:
                payload["accept_language"] = accept_language
            payload["retry_attempts"] = retry_attempts
            payload["bypass_forms"] = _bypass_forms(params)
            if WORKFLOW_ENGINE_BROKER_ENABLED:
                # A resumed node passes back the task it published last time, so
                # the crawl is waited for rather than started a second time.
                try:
                    result = dispatch_engine_task("target.crawl", payload, task_id=progress_task_id)
                except EngineTaskDeferred as deferred:
                    record_workflow_node_progress(
                        context,
                        {"task_id": deferred.task_id},
                    )
                    raise
                status, path = 200, ""
            else:
                status, result = call_engine("/proxy/target-map", payload)
                path = f"/proxy/target-map/{result.get('map_id')}" if isinstance(result, dict) and result.get("map_id") else ""
        if status < 200 or status >= 300 or (not path and not (WORKFLOW_ENGINE_BROKER_ENABLED and not browser)):
            _workflow_engine_failure(result, "Target could not start")
        job_id = str(result.get("job_id") or result.get("map_id") or result.get("id") or path.rsplit("/", 1)[-1])
        control = context.get("control")
        if control is not None and path:
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
                "result": pg_storable(result),
            },
        )
        if not (WORKFLOW_ENGINE_BROKER_ENABLED and not browser):
            result = _workflow_poll_engine(
                path,
                path,
                {"completed", "cancelled", "failed", "error"},
                context,
                browser=browser,
            )
        TargetJob.objects.filter(job_id=job_id).update(
            status=str(result.get("status", "completed")),
            result=pg_storable(result),
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
        status, result = call_engine("/proxy/oast", payload, timeout=_oast_gateway_timeout())
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

            def drop_listener() -> None:
                # Same rule the broker's cancel now follows: a parked run owns
                # this listener and is waiting for it. The run loop's `finally`
                # runs cleanups on the way out of a park as well, so a plain
                # cleanup deleted the listener the run was waiting for - on
                # resume `OAST Collect` polled a listener the engine reported as
                # cancelled, and the run ended `cancelled` with an empty node
                # error. Cancellation for a genuinely abandoned run still
                # arrives while the run is `running`.
                if run is not None and WorkflowRun.objects.filter(
                    pk=run.pk, status="waiting"
                ).exists():
                    return
                call_engine_delete(f"/proxy/oast/{listener_id}")

            control.add_cleanup(drop_listener)
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
            status, latest = call_engine_get(f"/proxy/oast/{listener_id}", timeout=_oast_gateway_timeout())
            if status < 200 or status >= 300 or not isinstance(latest, dict):
                call_engine_delete(f"/proxy/oast/{listener_id}")
                # `or`, not `get(key, default)`: a dict that *has* `error`
                # with an empty value returns that empty value, so the
                # default was unreachable and the node failed with a blank
                # reason - measured as `err=` and nothing else.
                raise WorkflowValidationError(
                    str(latest.get("error") or "OAST listener status failed")
                    if isinstance(latest, dict)
                    else "OAST listener status failed"
                )
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
        proxy_address = ""
        route_status, route_data = call_engine_get("/route")
        if route_status == 200 and isinstance(route_data, dict):
            proxy_address = str(route_data.get("address") or "").strip()
        try:
            # The Workflow's AI node gets tools, not the evidence-only chat
            # reply: it is an agent step, so it must be able to read what was
            # produced upstream. Route through the ReAct loop instead of the
            # text-only chat.
            prompt = str(params.get("prompt") or "Analyze the attached QA evidence.")
            result = run_agent_loop(
                user_prompt=prompt,
                provider=str(params.get("provider", "ollama")),
                endpoint=params.get("endpoint"),
                model=params.get("model"),
                proxy_address=proxy_address,
                context={"attached_evidence": {"workflow_input": input_value}},
                max_steps=int(params.get("max_steps", 6) or 6),
                cancel_event=(
                    context["outbound_operation"].cancelled
                    if context.get("outbound_operation") is not None
                    else getattr(context.get("control"), "cancel", None)
                ),
            )
            result = {"message": result.get("final_answer") or "", "steps": result.get("steps") or []}
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


def scanner_corpus_stats(request):
    """Report what a corpus selection would evaluate, without sending anything.

    The size of a run is the number an operator needs before starting it: the
    corpus is a finite database of several thousand checks, and a bound without
    knowing the total is a guess. This answers it over the project's active route
    so the number describes the target the operator is about to scan.
    """
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    tags = [part.strip() for part in str(request.GET.get("tags", "")).split(",") if part.strip()]
    query = urlencode({"tags": ",".join(tags)}) if tags else ""
    raw_bounds = str(request.GET.get("max_checks", "")).strip()
    if query and raw_bounds:
        query = f"{query}&{urlencode({'max_checks': raw_bounds})}"
    elif raw_bounds:
        query = urlencode({"max_checks": raw_bounds})
    path = f"/proxy/scanner/corpus/stats{f'?' + query if query else ''}"
    status, result = call_engine_get(path)
    if status != 200 or not isinstance(result, dict):
        return JsonResponse({"error": "corpus stats unavailable", "detail": result}, status=status or 502)
    return JsonResponse(result)


def scanner_corpus_run(request):
    """Enumerate a target against the converted third-party check corpus.

    The corpus is thousands of checks derived from a published database, so a run
    is long by nature and the operator's own bounds — `max_checks`, `tags`,
    `concurrency`, `timeout_ms`, `delay_ms` — are passed through untouched. Every
    check the selection holds is evaluated; the bounds change how long the run
    takes and how wide it goes, not what it is allowed to look at.
    """
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict) or not str(payload.get("url", "")).strip():
            raise ValueError("url is required")
        tags = payload.get("tags") or []
        if not isinstance(tags, list):
            raise ValueError("tags must be a list")
        bounds = {}
        for key in ("max_checks", "concurrency", "timeout_ms", "delay_ms"):
            if key in payload and payload[key] not in (None, ""):
                value = int(payload[key])
                if value < 0:
                    raise ValueError(f"{key} must not be negative")
                bounds[key] = value
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid corpus run: {error}"}, status=400)
    project = getattr(request, "active_project", None)
    try:
        with _outbound_runtime().operation("corpus", project.id if project else None) as operation:
            status, result = call_engine("/proxy/scanner/corpus/run", {
                "url": str(payload["url"]).strip(),
                "tags": [str(item).strip() for item in tags],
                **bounds,
                **tool_run_route(request, "corpus", payload["url"]),
            }, timeout=_corpus_run_timeout(payload))
            operation.raise_if_cancelled()
    except OutboundOperationCancelled:
        return _route_switch_cancelled("Corpus")
    if status == 200 and isinstance(result, dict):
        _ingest_scanner_run(
            project, "corpus",
            payload["url"], _corpus_findings_as_journal(result.get("findings")),
            result.get("stats"),
        )
    _persist_tool_history(project)
    if status != 200 or not isinstance(result, dict):
        return JsonResponse({"error": "corpus run failed", "detail": result}, status=status or 502)
    return JsonResponse(result)


# corpusLongRunSeconds bounds one corpus run at the gateway.
corpusLongRunSeconds = 5400


def scanner_corpus_jobs(request):
    """Start, report on, or stop a corpus run.

    The corpus is several thousand requests, so it is a **job**, not one call: the
    operator's browser connection would otherwise be the ceiling, and that ceiling
    is invisible. Measured before this change: a live `.ru` target failed after
    361 seconds with `NetworkError`, while the very same run through the API took
    138 seconds and returned findings. The job answers immediately with an id and
    is then polled; nothing here bounds how long a run may take.
    """
    if request.method == "POST":
        try:
            payload = json.loads(request.body)
            if not isinstance(payload, dict) or not str(payload.get("url", "")).strip():
                raise ValueError("url is required")
            tags = payload.get("tags") or []
            if not isinstance(tags, list):
                raise ValueError("tags must be a list")
            bounds = {}
            for key in ("max_checks", "concurrency", "timeout_ms", "delay_ms"):
                if key in payload and payload[key] not in (None, ""):
                    value = int(payload[key])
                    if value < 0:
                        raise ValueError(f"{key} must not be negative")
                    bounds[key] = value
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            return JsonResponse({"error": f"invalid corpus run: {error}"}, status=400)
        project = getattr(request, "active_project", None)
        try:
            with _outbound_runtime().operation("corpus", project.id if project else None) as operation:
                status, result = call_engine("/proxy/scanner/corpus/jobs", {
                    "url": str(payload["url"]).strip(),
                    "tags": [str(item).strip() for item in tags],
                    **bounds,
                    **tool_run_route(request, "corpus", payload["url"]),
                })
                operation.raise_if_cancelled()
        except OutboundOperationCancelled:
            return _route_switch_cancelled("Corpus")
        return JsonResponse(result if isinstance(result, dict) else {"error": "engine did not answer"},
                            status=status or 502)

    if request.method not in ("GET", "DELETE"):
        return JsonResponse({"error": "method not allowed"}, status=405)
    job_id = str(request.GET.get("job_id", "")).strip()
    if not job_id:
        return JsonResponse({"error": "job_id is required"}, status=400)
    if "/" in job_id:
        return JsonResponse({"error": "job_id must not contain a path separator"}, status=400)
    call = call_engine_delete if request.method == "DELETE" else call_engine_get
    status, result = call(f"/proxy/scanner/corpus/jobs/{job_id}")
    if status != 200 or not isinstance(result, dict):
        return JsonResponse(result if isinstance(result, dict) else {"error": "job status unavailable"},
                            status=status or 502)
    if request.method == "DELETE":
        return JsonResponse({"job_id": job_id, "state": result.get("state", "cancelled")})
    if result.get("state") in {"completed", "failed", "cancelled"}:
        _persist_tool_history(getattr(request, "active_project", None))
    return JsonResponse(result)


def scanner_corpus_job_stream(request, job_id):
    """Proxy the engine's live corpus stream so findings reach the browser while the run continues.

    A corpus run is thousands of requests. Polling alone meant nothing appeared on
    screen until the last request answered, which on a slow target is indistinguishable
    from a hung scan — the operator had no way to see that anything was being found.

    The engine sends a `snapshot` first, so a browser that connects late or reconnects
    starts from the job's real state. Lines are forwarded whole, blank terminator
    included: an `EventSource` dispatches nothing without it, which is the same trap
    `scanner_nuclei_job_stream` documents.
    """
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    cursor = request.headers.get("Last-Event-ID") or request.GET.get("last_event_id", "")
    stream_url = f"{ENGINE_URL}/proxy/scanner/corpus/jobs/{job_id}/stream"
    if cursor:
        stream_url += f"?last_event_id={cursor}"
    # `open_engine_stream` turns every connection-level failure into an explicit 502,
    # so nothing downstream has to tell a dead engine from a dead run.
    response = open_engine_stream(stream_url, {"Last-Event-ID": cursor})
    if isinstance(response, JsonResponse):
        return response

    def stream():
        started = time.monotonic()
        settled = False
        frame = b""
        pending_done = b""
        try:
            while time.monotonic() - started < SSE_MAX_LIFETIME:
                try:
                    chunk = response.readline()
                except (TimeoutError, socket.timeout):
                    # A quiet stretch is a slow target, not a dead job. Say so and
                    # keep the connection rather than letting it look broken.
                    yield b": keepalive\n\n"
                    continue
                if not chunk:
                    break
                # The terminal frame is read as a whole: an SSE frame is several
                # lines and a blank one ends it, so settling on the line carrying
                # the event name would settle on a frame with no payload in it.
                frame += chunk
                if b"event: done" in frame:
                    pending_done = pending_done or frame
                if not chunk.strip():
                    if pending_done and not settled:
                        settled = True
                        _persist_tool_history(getattr(request, "active_project", None))
                    pending_done = b""
                    frame = b""
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


def _corpus_run_timeout(payload):
    """The gateway waits longer than one request may take, because a run is many.

    The default gateway timeout is sized for a single exchange. A corpus run is
    several thousand of them, so leaving the default in place turns a healthy long
    run into a client-side failure while the engine is still working — and the
    operator is left unable to tell that from the run having failed.
    """
    try:
        bounds = int(payload.get("max_checks") or 0)
    except (TypeError, ValueError):
        bounds = 0
    # Three seconds per check is generous for a request that answers in
    # milliseconds, and it is the ceiling rather than the estimate: the run reports
    # its own duration, so a timeout that is merely long enough does not need to be
    # short enough to be honest. The whole corpus gets the long ceiling because it
    # is the larger run by definition.
    return corpusLongRunSeconds if bounds <= 0 else max(120, min(corpusLongRunSeconds, bounds * 3))


def _corpus_findings_as_journal(findings):
    """Map corpus findings onto the journal shape the scanner run log reads.

    The engine reports what a check matched — its id, the request that answered,
    the status, the evidence. The journal reads in titles and evidence, so the
    corpus row's own description becomes the title. Severity stays `INFO`: the
    corpus is a set of existence and configuration checks, not a triage, and
    inventing a severity for them would put a ranking into a report that has none.
    """
    items = []
    for item in findings or []:
        if not isinstance(item, dict):
            continue
        method = str(item.get("method", "") or "").strip()
        path = str(item.get("path", "") or "").strip()
        title = " ".join(part for part in (method, path) if part) or str(item.get("check_id", ""))
        description = str(item.get("description", "") or "").strip()
        if description:
            title = f"{title} — {description}"
        items.append({
            "title": title,
            "severity": "INFO",
            "evidence": str(item.get("evidence", "") or ""),
            "recommendation": "",
            "template_id": str(item.get("check_id", "") or ""),
            "cve": [],
        })
    return items


@csrf_exempt
def agent_run(request):
    """Execute an autonomous ReAct loop with tools for deep analysis."""
    if request.method != "POST":
        return _agent_error("method not allowed", "METHOD_NOT_ALLOWED", 405)
    try:
        from .agent_loop import run_agent_loop
        payload = json.loads(request.body)
        if not isinstance(payload, dict):
            raise ValueError("request must be an object")
        prompt = str(payload.get("prompt") or "").strip()
        if not prompt:
            raise ValueError("prompt is required")
        provider = str(payload.get("provider") or os.environ.get("RR_AGENT_PROVIDER") or "ollama").strip()
        config = {
            "endpoint": payload.get("endpoint"),
            "model": payload.get("model"),
            "api_key": payload.get("api_key"),
            "max_tokens": payload.get("max_tokens") or 4096,
        }
        max_steps = int(payload.get("max_steps", 12) or 12)

        supplied_context = payload.get("context") or {}
        include_project_context = bool(payload.get("include_project_context", True))
        project_context = {}
        active_project = getattr(request, "active_project", None)
        if include_project_context and active_project:
            try:
                summary_markdown = ProjectContextBuilder(active_project.id).build_summary_markdown()
                project_context = {
                    "project_id": active_project.id,
                    "include_notes": True,
                    "summary_markdown": summary_markdown,
                }
            except Exception:
                pass

        context = {
            "active_project": active_project,
            "attached_evidence": supplied_context.get("attached_evidence", {}),
            "project_context": project_context,
        }

        with _outbound_runtime().operation("ai", active_project.id if active_project else None) as operation:
            route_status, route_data = call_engine_get("/route")
            if route_status == 200 and isinstance(route_data, dict):
                proxy_address = str(route_data.get("address") or "").strip()
                if proxy_address:
                    config["proxy_address"] = proxy_address

            result = run_agent_loop(
                user_prompt=prompt,
                provider=provider,
                context=context,
                max_steps=max_steps,
                cancel_event=operation.cancelled,
                **config,
            )
            operation.raise_if_cancelled()

        return JsonResponse({
            "ok": True,
            "provider": provider,
            "final_answer": result["final_answer"],
            "steps": result["steps"],
            "total_steps": result["total_steps"],
            "completed": result["completed"],
        })
    except (OutboundOperationCancelled, AgentRequestCancelled):
        return _agent_error("AI agent loop cancelled by the route switch", "ROUTE_CHANGED", 409)
    except (json.JSONDecodeError, TypeError, ValueError, RuntimeError, AgentProviderError) as error:
        return _agent_error(f"invalid agent run: {error}", "INVALID_AGENT_RUN")

