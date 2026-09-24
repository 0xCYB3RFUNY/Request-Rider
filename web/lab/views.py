"""Django gateway views for the browser UI and Go execution engine."""

import json
import logging
import os
import queue
import secrets
import time
from http.client import RemoteDisconnected
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from django.http import HttpResponse, JsonResponse, StreamingHttpResponse
from django.db.models import Count
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.csrf import ensure_csrf_cookie

from .models import Finding, IntruderAttack, OsintEntity, OsintGraph, OsintRelation, Project, ProjectEndpoint, ProjectSecret, TargetJob, TrafficCaptureContext, TrafficRecord, Workflow, WorkflowRun
from .agent_services import AgentProviderError, generate_agent_chat
from .engine_client import engine_client
from .middleware import ACTIVE_PROJECT_SESSION_KEY
from .project_context import ProjectContextBuilder, ProjectContextError, normalize_project_notes, normalize_tech_stack
from .osint_graph import (
    OsintGraphError,
    create_graph,
    graph_item,
    upsert_graph,
)
from .runtime_limits import (
    BURST_MAX_CONCURRENCY,
    BURST_MAX_DELAY_MS,
    BURST_MAX_ITERATIONS,
    BURST_MAX_TIMEOUT_MS,
    CHAT_CONTEXT_BODY_LIMIT,
    CHAT_CONTEXT_HISTORY_LIMIT,
    CHAT_CONTEXT_TRAFFIC_LIMIT,
    CHAT_MESSAGE_LIMIT,
    CHAT_MESSAGES_LIMIT,
    CHAT_PROJECT_CONTEXT_LIMIT,
    CHAT_REQUEST_LIMIT,
    CHAT_TOTAL_CONTEXT_LIMIT,
    HISTORY_LIST_LIMIT,
    WORKFLOW_LIST_LIMIT,
    WORKFLOW_RUN_LIST_LIMIT,
    OSINT_GRAPH_REQUEST_LIMIT,
    OSINT_TRANSFORM_REQUEST_LIMIT,
    ROUTE_CHECK_MAX_TIMEOUT_MS,
    OAST_MAX_POLL_INTERVAL_SEC,
    OAST_MAX_TIMEOUT_SEC,
    LAST_BYTE_MAX_CONCURRENCY,
    LAST_BYTE_MAX_DELAY_MS,
    LAST_BYTE_MAX_HOLD_MS,
    LAST_BYTE_MAX_ITERATIONS,
    LAST_BYTE_MAX_TIMEOUT_MS,
    TARGET_MAX_DEPTH,
    TARGET_MAX_PAGES,
    WORKFLOW_MAX_REPEATER_ITEMS,
    WORKFLOW_MAX_DELAY_SECONDS,
    WORKFLOW_MAX_TOOL_POLL_SECONDS,
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

# The gateway talks to the engine over HTTP; Docker can override this address.
ENGINE_URL = os.environ.get("ENGINE_URL", "http://127.0.0.1:8081")
BROWSER_WORKER_URL = os.environ.get("BROWSER_WORKER_URL", "http://127.0.0.1:8090")
# The module logger records lifecycle metadata without request secrets.
logger = logging.getLogger(__name__)


# Django owns the browser-facing API; the Go engine owns outbound HTTP work.
@ensure_csrf_cookie
def index(request):
    """Render the single-page lab interface."""
    active_project = getattr(request, "active_project", None)
    return render(request, "lab/index.html", {
        "active_project_id": active_project.id if active_project else "",
    })


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
    for target_job in TargetJob.objects.filter(project=project).only("result", "status"):
        if target_job.status in {"completed", "cancelled", "failed", "error"}:
            _ingest_target_result(project, target_job.result)
    traffic = TrafficRecord.objects.filter(project=project)
    findings = Finding.objects.filter(project=project)
    severity = {}
    for row in findings.values("severity").annotate(count=Count("id")):
        severity[str(row["severity"]).upper()] = row["count"]
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
            "findings": findings.count(),
            "target_jobs": TargetJob.objects.filter(project=project).count(),
            "open_ports": sum(item["count"] for item in entities if item["entity_type"] == "port"),
        },
        "severity": severity,
        "tech_stack": project.tech_stack or {},
        "endpoints": endpoint_items,
        "secret_references": secret_items,
        "findings": [finding_item(item) for item in findings.order_by("-updated_at")[:200]],
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


def _active_project(request, explicit_id=None):
    """Use the validated session Project unless a durable record already names one."""
    if getattr(request, "active_project", None):
        return request.active_project
    if explicit_id not in (None, ""):
        return Project.objects.filter(id=explicit_id).first()
    return None


def _ingest_target_result(project, result):
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


def _ingest_scanner_result(project, result):
    """Persist scanner findings and technology observations for the Project."""
    if not project or not isinstance(result, dict):
        return
    target = str(result.get("url") or "")
    for item in result.get("findings") or []:
        if not isinstance(item, dict) or not item.get("title"):
            continue
        fingerprint = f"scanner:{target}:{item.get('title')}"[:128]
        Finding.objects.update_or_create(
            project=project, fingerprint=fingerprint,
            defaults={
                "title": str(item["title"])[:240],
                "severity": str(item.get("severity") or "INFO").upper()[:20],
                "confidence": int(item.get("confidence_percent") or item.get("confidence") or 0),
                "target": target[:2048],
                "source": "scanner",
                "evidence_before": {"evidence": item.get("evidence", ""), "recommendation": item.get("recommendation", "")},
            },
        )
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


def finding_item(finding):
    return {
        "id": finding.id,
        "project_id": finding.project_id,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "verification_status": finding.verification_status,
        "status": finding.status,
        "target": finding.target,
        "source": finding.source,
        "evidence_before": finding.evidence_before,
        "evidence_after": finding.evidence_after,
        "fingerprint": finding.fingerprint,
        "created_at": finding.created_at.isoformat(),
        "updated_at": finding.updated_at.isoformat(),
    }


@csrf_exempt
def findings(request, finding_id=None):
    """Manage scanner findings and their verification lifecycle."""
    if request.method == "GET":
        queryset = Finding.objects.order_by("-updated_at")
        if request.GET.get("project_id", "").isdigit():
            queryset = queryset.filter(project_id=int(request.GET["project_id"]))
        if finding_id is not None:
            finding = queryset.filter(id=finding_id).first()
            return JsonResponse(finding_item(finding) if finding else {"error": "finding not found"},
                                  status=200 if finding else 404)
        return JsonResponse({"items": [finding_item(item) for item in queryset]})
    if request.method not in {"POST", "PATCH", "PUT", "DELETE"}:
        return JsonResponse({"error": "method not allowed"}, status=405)
    if request.method == "DELETE":
        deleted, _ = Finding.objects.filter(id=finding_id).delete()
        return JsonResponse({"ok": True, "deleted": bool(deleted)})
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid finding: {error}"}, status=400)
    finding = Finding.objects.filter(id=finding_id).first() if finding_id is not None else Finding()
    if finding_id is not None and not finding:
        return JsonResponse({"error": "finding not found"}, status=404)
    if finding_id is None and not str(payload.get("title", "")).strip():
        return JsonResponse({"error": "title is required"}, status=400)
    for field in ("title", "severity", "verification_status", "status", "target", "source", "fingerprint"):
        if field in payload:
            setattr(finding, field, str(payload[field]).strip())
    if "confidence" in payload:
        try:
            finding.confidence = max(0, min(100, int(payload["confidence"])))
        except (TypeError, ValueError):
            return JsonResponse({"error": "confidence must be numeric"}, status=400)
    for field in ("evidence_before", "evidence_after"):
        if field in payload:
            if not isinstance(payload[field], dict):
                return JsonResponse({"error": f"{field} must be an object"}, status=400)
            setattr(finding, field, payload[field])
    if "project_id" in payload:
        finding.project_id = payload["project_id"] or None
    if not finding.fingerprint:
        finding.fingerprint = f"{finding.source}:{finding.title}:{finding.target}"[:128]
    finding.save()
    return JsonResponse(finding_item(finding), status=201 if finding_id is None else 200)


@csrf_exempt
def attach_finding_to_active_project(request, finding_id):
    """Attach an existing finding to the server-side active Project."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    finding = Finding.objects.filter(id=finding_id).first()
    if not finding:
        return JsonResponse({"error": "finding not found"}, status=404)
    project = getattr(request, "active_project", None)
    if not project:
        return JsonResponse({"error": "active Project is required"}, status=409)
    finding.project = project
    finding.save(update_fields=["project", "updated_at"])
    return JsonResponse({"ok": True, "finding": finding_item(finding)})


def findings_export(request):
    """Export Findings Center data as Markdown or HTML."""
    items = [finding_item(item) for item in Finding.objects.order_by("-updated_at")]
    if request.GET.get("format", "markdown").lower() == "html":
        rows = "".join(
            f"<tr><td>{item['severity']}</td><td>{item['title']}</td>"
            f"<td>{item['status']}</td><td>{item['confidence']}%</td></tr>" for item in items
        )
        return HttpResponse(
            f"<table><thead><tr><th>Severity</th><th>Title</th><th>Status</th><th>Confidence</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>", content_type="text/html; charset=utf-8",
        )
    lines = ["# Findings", ""]
    for item in items:
        lines.extend([
            f"## [{item['severity']}] {item['title']}",
            f"- Status: {item['status']}",
            f"- Confidence: {item['confidence']}%",
            f"- Verification: {item['verification_status']}",
            f"- Target: {item['target']}",
            "",
        ])
    return HttpResponse("\n".join(lines), content_type="text/markdown; charset=utf-8")


@csrf_exempt
def verify_finding(request, finding_id):
    """Compare new finding evidence with the stored baseline."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    finding = Finding.objects.filter(id=finding_id).first()
    if not finding:
        return JsonResponse({"error": "finding not found"}, status=404)
    try:
        payload = json.loads(request.body)
        evidence_after = payload.get("evidence_after")
        if not isinstance(evidence_after, dict):
            raise ValueError("evidence_after must be an object")
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid verification: {error}"}, status=400)
    finding.evidence_after = evidence_after
    finding.verification_status = "changed" if evidence_after != finding.evidence_before else "unchanged"
    finding.save(update_fields=["evidence_after", "verification_status", "updated_at"])
    return JsonResponse({
        "finding": finding_item(finding),
        "changed": finding.verification_status == "changed",
    })


def history(request):
    """Return filtered and sorted durable History records."""
    # History is persisted in SQLite, unlike the in-memory passive Store.
    records = TrafficRecord.objects.filter(source__in=("repeater", "intruder", "last-byte")).order_by("-timestamp")
    query = request.GET.get("q", "").strip()
    if query:
        from django.db.models import Q
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
        records = records.filter(status_code=request.GET["status"])
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
    # Keep the response bounded for the current table view.
    records = records[:HISTORY_LIST_LIMIT]
    return JsonResponse({"items": [history_item(item) for item in records]})


@csrf_exempt
def history_detail(request, record_id=None):
    """Delete one History record through the browser-facing API."""
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
                record.tags = [str(tag)[:80] for tag in payload["tags"]]
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
    """Persist each completed Intruder exchange once for durable History."""
    if not isinstance(results, list):
        return
    for index, result in enumerate(results, start=result_offset):
        if not isinstance(result, dict):
            continue
        request_data = result.get("request") or {}
        if not isinstance(request_data, dict) or not request_data.get("url"):
            continue
        if TrafficRecord.objects.filter(
            source="intruder",
            proxy_session=attack_id,
            proxy_event_id=index,
        ).exists():
            continue
        response_headers = result.get("headers") or {}
        response_body = result.get("body") or ""
        TrafficRecord.objects.create(
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
            response_body=response_body,
            response_body_encoding=result.get("body_encoding", "utf8"),
            response_body_base64=result.get("body_base64", ""),
            response_content_type=result.get("body_content_type", response_headers.get("Content-Type", "")),
            status_code=result.get("status"),
            latency_ms=result.get("time"),
            response_size=result.get("size"),
        )


def _capture_context_for_event(event):
    """Resolve an explicit capture token without applying a URL policy."""
    token = str(event.get("capture_context") or "").strip()
    if not token:
        return None, "unscoped"
    context = TrafficCaptureContext.objects.select_related("project").filter(token=token).first()
    if not context:
        return None, "invalid_context"
    return context, "project_linked" if context.project_id else "unscoped"


def public_traffic_event(event):
    """Return UI-safe Traffic metadata without exposing the capture token."""
    if not isinstance(event, dict):
        return event
    context, scope_status = _capture_context_for_event(event)
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


def persist_proxy_history(events, project_id=None):
    """Persist completed passive proxy exchanges once for durable History."""
    if not isinstance(events, list):
        return
    for event in events:
        if not isinstance(event, dict) or not event.get("url"):
            continue
        if event.get("source") not in (None, "", "proxy", "route-check"):
            continue
        if event.get("status") is None and not event.get("error"):
            continue
        event_id = event.get("id")
        session = event.get("session")
        capture_context, scope_status = _capture_context_for_event(event)
        if event_id is not None and TrafficRecord.objects.filter(
            source=event.get("source") or "proxy",
            proxy_session=session,
            proxy_event_id=event_id,
        ).exists():
            continue
        TrafficRecord.objects.create(
            source=event.get("source") or "proxy",
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
            response_headers=event.get("response_headers") or {},
            response_body=event.get("response_body") or "",
            response_body_encoding=event.get("response_body_encoding", "utf8"),
            response_body_base64=event.get("response_body_base64", ""),
            response_content_type=event.get("response_content_type", (event.get("response_headers") or {}).get("Content-Type", "")),
            status_code=event.get("status") or None,
            latency_ms=event.get("latency_ms") or None,
            response_size=event.get("response_size") if event.get("response_size") is not None else None,
            tags=event.get("tags") or [],
            notes=event.get("notes") or "",
        )


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


def call_engine(path, payload, timeout=None):
    """POST JSON to Go and normalize transport errors into API responses."""
    return engine_client(ENGINE_URL).request("POST", path, payload, timeout=timeout)


# Snapshot and stream are separate so the UI can hydrate first, then stay live.
def call_engine_get(path, timeout=None):
    """GET a read-only engine endpoint such as the Traffic snapshot."""
    return engine_client(ENGINE_URL).request("GET", path, timeout=timeout)


def call_engine_delete(path, timeout=None):
    """DELETE an engine resource such as a running Intruder attack."""
    return engine_client(ENGINE_URL).request("DELETE", path, timeout=timeout)


def call_engine_action(path, payload):
    """POST an action to an existing engine resource."""
    return engine_client(ENGINE_URL).request("POST", path, payload)


def call_browser_worker(path, payload):
    """Start a browser-driven Target job in the isolated Playwright worker."""
    request = Request(
        f"{BROWSER_WORKER_URL}{path}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, {"error": error.read().decode(errors="replace")[:4000], "reason": "BROWSER_WORKER_ERROR"}
    except (URLError, TimeoutError, RemoteDisconnected, ConnectionError) as error:
        return 502, {"error": f"browser worker unavailable: {getattr(error, 'reason', error)}", "reason": "BROWSER_WORKER_UNAVAILABLE"}


def call_browser_worker_get(path):
    try:
        with urlopen(f"{BROWSER_WORKER_URL}{path}", timeout=15) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, {"error": error.read().decode(errors="replace")[:4000], "reason": "BROWSER_WORKER_ERROR"}
    except (URLError, TimeoutError, RemoteDisconnected, ConnectionError) as error:
        return 502, {"error": f"browser worker unavailable: {getattr(error, 'reason', error)}", "reason": "BROWSER_WORKER_UNAVAILABLE"}


def call_browser_worker_delete(path):
    request = Request(f"{BROWSER_WORKER_URL}{path}", method="DELETE")
    try:
        with urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, {"error": error.read().decode(errors="replace")[:4000], "reason": "BROWSER_WORKER_ERROR"}
    except (URLError, TimeoutError, RemoteDisconnected, ConnectionError) as error:
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
        if len(name) > 160:
            return JsonResponse({"error": "name cannot exceed 160 characters"}, status=400)
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
        if not name or len(name) > 160:
            return JsonResponse({"error": "name must contain 1-160 characters"}, status=400)
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
        if status == 502 and result.get("reason") == "ENGINE_UNAVAILABLE":
            return JsonResponse({"ok": True}, status=200)
        return JsonResponse(result, status=status)
    if request.method == "POST":
        payload = {}
        if request.body:
            try:
                payload = json.loads(request.body)
            except (json.JSONDecodeError, TypeError):
                return JsonResponse({"error": "invalid JSON"}, status=400)
        action = str((request.GET.get("action") or payload.get("action") or "status")).strip().lower()
        if action not in {"pause", "resume", "status"}:
            return JsonResponse({"error": "action must be pause, resume or status"}, status=400)
        status, result = call_engine_action("/events", {"action": action})
        return JsonResponse(result, status=status)
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    status, result = call_engine_get("/events")
    if status == 200:
        persist_proxy_history(result, getattr(request.active_project, "id", None))
        if isinstance(result, list):
            result = [public_traffic_event(event) for event in result]
    return JsonResponse(result, status=status, safe=isinstance(result, dict))


def traffic_stream(request):
    """Proxy the engine SSE stream without buffering individual lines."""
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        cursor = request.headers.get("Last-Event-ID") or request.GET.get("last_event_id", "")
        stream_url = f"{ENGINE_URL}/events/stream"
        if cursor:
            stream_url += f"?last_event_id={cursor}"
        upstream = Request(stream_url, headers={"Last-Event-ID": cursor})
        response = urlopen(upstream)
    except URLError as error:
        return JsonResponse({"error": f"engine unavailable: {error.reason}", "reason": "ENGINE_UNAVAILABLE"}, status=502)

    def stream():
        # Read one SSE line at a time so small events reach the browser immediately.
        try:
            while True:
                chunk = response.readline()
                if not chunk:
                    break
                if chunk.startswith(b"data:"):
                    try:
                        event = json.loads(chunk[5:].strip())
                    except (json.JSONDecodeError, TypeError):
                        yield chunk
                        continue
                    yield f"data: {json.dumps(public_traffic_event(event), ensure_ascii=False)}\n".encode()
                else:
                    yield chunk
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
def normalize_payload(payload):
    payload = dict(payload)
    split = urlsplit(payload.get("url", ""))
    query = payload.pop("query", None)
    # Preserve existing URL query values, then apply editor values over them.
    if isinstance(query, dict):
        merged = dict(parse_qsl(split.query, keep_blank_values=True))
        merged.update({str(key): str(value) for key, value in query.items()})
        payload["url"] = urlunsplit((split.scheme, split.netloc, split.path, urlencode(merged), split.fragment))
    cookies = payload.pop("cookies", None)
    # Represent cookie editor values as one standard Cookie request header.
    if isinstance(cookies, dict):
        headers = dict(payload.get("headers") or {})
        headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in cookies.items())
        payload["headers"] = headers
    return payload


@csrf_exempt
def execute(request):
    """Forward one Repeater request and persist successful responses."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = normalize_payload(json.loads(request.body))
        status, result = call_engine("/proxy/request", payload)
    except (json.JSONDecodeError, TypeError):
        return JsonResponse({"error": "invalid JSON"}, status=400)
    # Persist every completed target HTTP response, including 4xx/5xx results.
    if status == 200 and isinstance(result, dict) and result.get("status") is not None:
        TrafficRecord.objects.create(
            project=getattr(request, "active_project", None),
            source="repeater",
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
        limit = request.GET.get("limit", "").strip()
        if limit:
            try:
                limit_value = int(limit)
            except ValueError:
                return JsonResponse({"error": "limit must be numeric"}, status=400)
            if limit_value <= 0:
                return JsonResponse({"error": "limit must be positive"}, status=400)
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
        if limit:
            engine_path += f"{'&' if '?' in engine_path else '?'}limit={limit_value}"
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
    try:
        payload = json.loads(request.body)
        payload["base_request"] = normalize_payload(payload.get("base_request", {}))
        logger.info(
            "intruder_start mode=%s payload_sets=%d transformations=%d",
            payload.get("mode", ""),
            len(payload.get("payloads") or payload.get("dictionaries") or []),
            len(payload.get("transformations") or []),
        )
        status, result = call_engine("/proxy/intruder", payload)
    except (json.JSONDecodeError, TypeError):
        return JsonResponse({"error": "invalid JSON"}, status=400)
    logger.info(
        "intruder_complete status=%s results=%d",
        status,
        len((result.get("results") or [])) if isinstance(result, dict) else 0,
    )
    if status in {200, 202} and isinstance(result, dict) and result.get("attack_id"):
        IntruderAttack.objects.create(
            name="Intruder run",
            project=getattr(request, "active_project", None),
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
                _ingest_target_result(job.project if job else None, result)
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
    except (json.JSONDecodeError, TypeError):
        return JsonResponse({"error": "invalid JSON"}, status=400)
    project_id = payload.pop("project_id", None)
    project = _active_project(request, project_id)
    status, result = call_engine("/proxy/target-map", payload)
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
                _ingest_target_result(job.project if job else None, result)
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
    except (json.JSONDecodeError, TypeError):
        return JsonResponse({"error": "invalid JSON"}, status=400)
    if not isinstance(payload, dict):
        return JsonResponse({"error": "invalid JSON: request body must be an object"}, status=400)
    route_status, route = call_engine_get("/route")
    if route_status != 200:
        return JsonResponse(
            {"error": "cannot resolve active route for browser worker", "reason": "ROUTE_UNAVAILABLE"},
            status=502,
        )
    route_address = str(route.get("address", "")).strip()
    if route_address:
        payload["proxy_server"] = f"socks5://{route_address}"
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
    status, result = call_browser_worker("/target", payload)
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
    if len(request.body) > OSINT_GRAPH_REQUEST_LIMIT:
        return _osint_graph_error(OsintGraphError("OSINT graph request is too large"))
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
    """Idempotently merge bounded entities and relations into one graph."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if len(request.body) > OSINT_GRAPH_REQUEST_LIMIT:
        return _osint_graph_error(OsintGraphError("OSINT graph request is too large"))
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
def osint_transform_registry(request):
    if request.method != "GET":
        return JsonResponse({"error": "method not allowed"}, status=405)
    status, result = call_engine_get("/proxy/osint/transforms")
    return JsonResponse(result, status=status, safe=isinstance(result, dict))


@csrf_protect
def osint_graph_transform(request, graph_id):
    """Run one explicitly selected transform and persist its graph output."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    if len(request.body) > OSINT_TRANSFORM_REQUEST_LIMIT:
        return _osint_graph_error(OsintGraphError("OSINT transform request is too large"))
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
        network_transforms = {"subdomains", "github_recon", "reverse_dns", "dns_records", "wayback_urls", "s3_buckets"}
        if transform in network_transforms and not confirm_network:
            return JsonResponse({
                "error": "explicit network confirmation is required for this transform",
                "reason": "NETWORK_CONFIRMATION_REQUIRED",
            }, status=400)
    except (json.JSONDecodeError, TypeError, ValueError, OsintGraphError) as error:
        return _osint_graph_error(error)

    status, result = call_engine("/proxy/osint/transform", {
        "transform": transform,
        "value": value,
        "options": options,
        "confirm_network": confirm_network,
    })
    if status < 200 or status >= 300:
        return JsonResponse(result, status=status, safe=isinstance(result, dict))
    try:
        counts = upsert_graph(graph, result)
    except (TypeError, ValueError, OsintGraphError) as error:
        return _osint_graph_error(error)
    response = graph_item(graph, include_contents=True)
    response["transform_result"] = {
        "transform": result.get("transform", transform),
        "observed_at": result.get("observed_at"),
        "local_only": bool(result.get("local_only")),
        "network_used": bool(result.get("network_used")),
        "warnings": result.get("warnings") or [],
        "metadata": result.get("metadata") or {},
    }
    response["upserted"] = counts
    return JsonResponse(response)


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
    status, result = call_engine("/proxy/osint", {
        "url": str(payload["url"]).strip(),
        "waf_check": bool(payload.get("waf_check", False)),
    })
    _ingest_osint_result(getattr(request, "active_project", None), result)
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
    status, result = call_engine("/proxy/scanner", {
        "url": str(payload["url"]).strip(),
        "profile": profile,
    })
    _ingest_scanner_result(getattr(request, "active_project", None), result)
    return JsonResponse(result, status=status)


@csrf_exempt
def route(request):
    """Read or update the shared SOCKS5 route."""
    if request.method == "GET":
        status, result = call_engine_get("/route")
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
    status, result = call_engine("/route", {"address": address})
    return JsonResponse(result, status=status)


@csrf_exempt
def route_check(request):
    """Check the current route against a target and an external IP endpoint."""
    if request.method != "POST":
        return JsonResponse({"error": "method not allowed"}, status=405)
    try:
        payload = json.loads(request.body)
        if not isinstance(payload, dict) or not str(payload.get("url", "")).strip():
            raise ValueError("url is required")
        target_url = str(payload["url"]).strip()
        timeout_ms = int(payload.get("timeout_ms", 15000))
        if timeout_ms < 1 or timeout_ms > ROUTE_CHECK_MAX_TIMEOUT_MS:
            raise ValueError(f"timeout_ms must be between 1 and {ROUTE_CHECK_MAX_TIMEOUT_MS}")
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        return JsonResponse({"error": f"invalid route check: {error}"}, status=400)
    status, result = call_engine("/route/check", {
        "url": target_url,
        "timeout_ms": timeout_ms,
    })
    return JsonResponse(result, status=status)




def _agent_error(message, reason, status=400):
    return JsonResponse({"error": message, "reason": reason}, status=status)









def _truncate_chat_text(value, limit=CHAT_CONTEXT_BODY_LIMIT):
    text = str(value or "")
    if len(text) <= limit:
        return text
    suffix = f"\n[truncated; original_length={len(text)}]"
    return text[: max(0, limit - len(suffix))] + suffix


def _compact_chat_value(value, key=""):
    if isinstance(value, str):
        if key == "summary_markdown":
            return _truncate_chat_text(value, CHAT_PROJECT_CONTEXT_LIMIT)
        limit = CHAT_CONTEXT_BODY_LIMIT if any(
            marker in key.lower()
            for marker in ("body", "content", "request", "response", "message")
        ) else 2000
        return _truncate_chat_text(value, limit)
    if isinstance(value, list):
        return [_compact_chat_value(item, key) for item in value[:50]]
    if isinstance(value, dict):
        return {
            str(item_key): _compact_chat_value(item_value, str(item_key))
            for item_key, item_value in list(value.items())[:80]
        }
    return value


def _compact_chat_context(context):
    if not isinstance(context, dict):
        return {}
    project_context = context.get("project_context")
    if not context.get("attached_evidence") and not isinstance(project_context, dict):
        return {}
    compact = dict(context)
    if isinstance(project_context, dict):
        compact["project_context"] = {
            **project_context,
            "summary_markdown": _truncate_chat_text(
                project_context.get("summary_markdown", ""),
                CHAT_PROJECT_CONTEXT_LIMIT,
            ),
        }
    compact["history"] = [
        _compact_chat_value(item)
        for item in (context.get("history") or [])[:CHAT_CONTEXT_HISTORY_LIMIT]
        if isinstance(item, dict)
    ]
    compact["traffic"] = [
        _compact_chat_value(item)
        for item in (context.get("traffic") or [])[:CHAT_CONTEXT_TRAFFIC_LIMIT]
        if isinstance(item, dict)
    ]
    compact["saved_intruder"] = [
        _compact_chat_value(item)
        for item in (context.get("saved_intruder") or [])[:20]
        if isinstance(item, dict)
    ]
    compact = _compact_chat_value(compact)
    encoded = json.dumps(compact, ensure_ascii=False)
    while len(encoded) > CHAT_TOTAL_CONTEXT_LIMIT and (
        compact.get("traffic")
        or compact.get("history")
        or compact.get("saved_intruder")
        or compact.get("attached_evidence")
        or compact.get("project_context")
    ):
        if compact.get("traffic"):
            compact["traffic"] = compact["traffic"][: max(1, len(compact["traffic"]) // 2)]
        elif compact.get("history"):
            compact["history"] = compact["history"][: max(1, len(compact["history"]) // 2)]
        elif compact.get("saved_intruder"):
            compact["saved_intruder"] = compact["saved_intruder"][: max(1, len(compact["saved_intruder"]) // 2)]
        else:
            reduced = False
            for key, value in compact.get("attached_evidence", {}).items():
                if isinstance(value, list) and len(value) > 1:
                    compact["attached_evidence"][key] = value[: max(1, len(value) // 2)]
                    reduced = True
                    break
            if not reduced:
                compact["attached_evidence"] = {
                    "summary": "Attached evidence exceeded the chat context limit."
                }
        encoded = json.dumps(compact, ensure_ascii=False)
    if len(encoded) > CHAT_TOTAL_CONTEXT_LIMIT:
        compact["compaction"] = {
            "applied": True,
            "reason": "chat_context_size_limit",
            "max_chars": CHAT_TOTAL_CONTEXT_LIMIT,
        }
    return compact


def _compact_chat_messages(messages):
    compact = []
    for message in messages[-CHAT_MESSAGES_LIMIT:]:
        if not isinstance(message, dict):
            continue
        item = {
            "role": str(message.get("role", "user")),
            "content": _truncate_chat_text(
                message.get("content", ""),
                CHAT_MESSAGE_LIMIT,
            ),
        }
        if message.get("name"):
            item["name"] = str(message["name"])[:80]
        compact.append(item)
    return compact
















@csrf_protect
def agent_chat(request):
    """Analyze only evidence explicitly attached by the operator."""
    if request.method != "POST":
        return _agent_error("method not allowed", "METHOD_NOT_ALLOWED", 405)
    try:
        if len(request.body) > CHAT_REQUEST_LIMIT:
            raise ValueError("chat request is too large")
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
        result = generate_agent_chat(messages, provider=provider, context=context, **config)
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
                status, result = call_engine("/proxy/intruder", engine_payload)
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
                name=str(payload.get("name") or "Intruder attack")[:120],
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
    if not all(character.isalnum() or character in "-_" for character in candidate) or len(candidate) < 3:
        raise WorkflowValidationError("webhook path must contain at least three safe characters")
    return candidate[:96]


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
        data["runs"] = [run_item(run) for run in workflow.runs.order_by("-created_at")[:30]]
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
        return JsonResponse({"items": [workflow_item(item) for item in queryset[:WORKFLOW_LIST_LIMIT]]})

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
        workflow.name = name[:160]
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
        name = str(source.get("name") or "Imported workflow").strip()[:160]
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
                    event = listener.get(timeout=15)
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
    return JsonResponse({"items": [run_item(item) for item in queryset[:WORKFLOW_RUN_LIST_LIMIT]]})


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


def _workflow_wait(context, seconds):
    deadline = time.monotonic() + max(0.0, min(float(WORKFLOW_MAX_DELAY_SECONDS), float(seconds)))
    while time.monotonic() < deadline:
        if _workflow_cancelled(context):
            raise WorkflowCancelled()
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))


def _workflow_poll_engine(path, delete_path, terminal_states, context, browser=False):
    deadline = time.monotonic() + float(WORKFLOW_MAX_TOOL_POLL_SECONDS)
    while time.monotonic() < deadline:
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
            return result
        time.sleep(0.35)
    raise WorkflowValidationError("workflow tool timed out")


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
    if len(raw_items) > WORKFLOW_MAX_REPEATER_ITEMS:
        raise WorkflowValidationError(f"Repeater loop is limited to {WORKFLOW_MAX_REPEATER_ITEMS} items")
    base = params.get("base_request") if isinstance(params.get("base_request"), dict) else {}
    requests = []
    for item in raw_items[:WORKFLOW_MAX_REPEATER_ITEMS]:
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
    """Adapter from typed workflow nodes to existing RequestRider tools."""
    workflow = context.get("workflow")
    run = context.get("run")
    project_id = getattr(run, "project_id", None) or getattr(workflow, "project_id", None)
    if project_id is None and getattr(workflow, "project", None) is not None:
        project_id = getattr(workflow.project, "id", None)
    input_value = context.get("input")
    if node_type == "repeater":
        request_payloads = _workflow_repeater_requests(params, input_value)
        delay_ms = max(0, min(WORKFLOW_MAX_DELAY_SECONDS * 1000, int(params.get("delay_ms", params.get("rate_limit_ms", 0)))))
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
            if status < 200 or status >= 300:
                raise WorkflowValidationError(str(result.get("error", "Repeater failed") if isinstance(result, dict) else "Repeater failed"))
            if isinstance(result, dict) and result.get("status") is not None:
                TrafficRecord.objects.create(
                    project_id=project_id,
                    source="repeater",
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
            timeout_ms = int(params.get("timeout_ms", 5000))
        except (TypeError, ValueError) as error:
            raise WorkflowValidationError("Repeater Burst numeric parameters are invalid") from error
        if not 1 <= iterations <= BURST_MAX_ITERATIONS or not 1 <= concurrency <= BURST_MAX_CONCURRENCY or not 0 <= delay_ms <= BURST_MAX_DELAY_MS or not 1 <= timeout_ms <= BURST_MAX_TIMEOUT_MS:
            raise WorkflowValidationError("Repeater Burst parameters exceed the configured bounds")
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
        status, started = call_engine("/proxy/repeater-burst", request_payload, timeout=5)
        if status < 200 or status >= 300 or not isinstance(started, dict) or not started.get("burst_id"):
            raise WorkflowValidationError(str(started.get("error", "Repeater Burst could not start") if isinstance(started, dict) else "Repeater Burst could not start"))
        burst_id = str(started["burst_id"])
        control = context.get("control")
        if control is not None:
            control.add_cleanup(lambda: call_engine_delete(f"/proxy/repeater-burst/{burst_id}", timeout=5))
        # The engine bounds each request; the adapter's poll deadline also
        # accounts for all waves instead of assuming a three-request run.
        estimated_runtime = (iterations * timeout_ms / 1000.0 / concurrency) + (max(0, iterations - 1) * delay_ms / 1000.0)
        deadline = time.monotonic() + min(float(WORKFLOW_MAX_TOOL_POLL_SECONDS), max(30.0, estimated_runtime + 5.0))
        latest = started
        while time.monotonic() < deadline:
            if control and control.cancel.is_set():
                call_engine_delete(f"/proxy/repeater-burst/{burst_id}", timeout=5)
                raise WorkflowCancelled()
            status, latest = call_engine_get(f"/proxy/repeater-burst/{burst_id}", timeout=5)
            if status < 200 or status >= 300 or not isinstance(latest, dict):
                raise WorkflowValidationError(str(latest.get("error", "Repeater Burst status failed") if isinstance(latest, dict) else "Repeater Burst status failed"))
            state = str(latest.get("status") or "")
            if state == "completed":
                for item in latest.get("results") or []:
                    if not isinstance(item, dict) or item.get("error"):
                        continue
                    TrafficRecord.objects.create(
                        project_id=project_id,
                        source="repeater",
                        method=request_payload["method"],
                        url=request_payload["url"],
                        request_headers=request_payload["headers"],
                        request_body=request_payload["body"],
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
        call_engine_delete(f"/proxy/repeater-burst/{burst_id}", timeout=5)
        raise WorkflowValidationError("Repeater Burst timed out")

    if node_type == "last_byte_sync":
        try:
            iterations = int(params.get("iterations", 1))
            concurrency = int(params.get("concurrency", 1))
            delay_ms = int(params.get("delay_ms", 0))
            hold_ms = int(params.get("hold_ms", 50))
            timeout_ms = int(params.get("timeout_ms", 5000))
        except (TypeError, ValueError) as error:
            raise WorkflowValidationError("Last-Byte Sync numeric parameters are invalid") from error
        if not 1 <= iterations <= LAST_BYTE_MAX_ITERATIONS or not 1 <= concurrency <= LAST_BYTE_MAX_CONCURRENCY or not 0 <= delay_ms <= LAST_BYTE_MAX_DELAY_MS:
            raise WorkflowValidationError("Last-Byte Sync parameters exceed the configured bounds")
        if hold_ms == 0:
            hold_ms = 50
        if not 0 <= hold_ms <= LAST_BYTE_MAX_HOLD_MS or not 1 <= timeout_ms <= LAST_BYTE_MAX_TIMEOUT_MS:
            raise WorkflowValidationError("Last-Byte Sync timing parameters exceed the configured bounds")
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
        status, started = call_engine("/proxy/last-byte", request_payload, timeout=5)
        if status < 200 or status >= 300 or not isinstance(started, dict) or not started.get("last_byte_id"):
            raise WorkflowValidationError(str(started.get("error", "Last-Byte Sync could not start") if isinstance(started, dict) else "Last-Byte Sync could not start"))
        last_byte_id = str(started["last_byte_id"])
        control = context.get("control")
        if control is not None:
            control.add_cleanup(lambda: call_engine_delete(f"/proxy/last-byte/{last_byte_id}", timeout=5))
        estimated_runtime = (iterations * (timeout_ms + hold_ms) / 1000.0 / concurrency) + (max(0, iterations - 1) * delay_ms / 1000.0)
        deadline = time.monotonic() + min(float(WORKFLOW_MAX_TOOL_POLL_SECONDS), max(30.0, estimated_runtime + 5.0))
        latest = started
        while time.monotonic() < deadline:
            if control and control.cancel.is_set():
                call_engine_delete(f"/proxy/last-byte/{last_byte_id}", timeout=5)
                raise WorkflowCancelled()
            status, latest = call_engine_get(f"/proxy/last-byte/{last_byte_id}", timeout=5)
            if status < 200 or status >= 300 or not isinstance(latest, dict):
                raise WorkflowValidationError(str(latest.get("error", "Last-Byte Sync status failed") if isinstance(latest, dict) else "Last-Byte Sync status failed"))
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
        call_engine_delete(f"/proxy/last-byte/{last_byte_id}", timeout=5)
        raise WorkflowValidationError("Last-Byte Sync timed out")

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
            "max_pages": int(params.get("max_pages", TARGET_MAX_PAGES)),
            "max_depth": int(params.get("max_depth", TARGET_MAX_DEPTH)),
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
            if capture_context:
                payload["capture_context"] = capture_context.token
            status, result = call_browser_worker("/target", payload)
            path = f"/target/{result.get('job_id')}" if isinstance(result, dict) and result.get("job_id") else ""
        else:
            status, result = call_engine("/proxy/target-map", payload)
            path = f"/proxy/target-map/{result.get('map_id')}" if isinstance(result, dict) and result.get("map_id") else ""
        if status < 200 or status >= 300 or not path:
            raise WorkflowValidationError(str(result.get("error", "Target could not start") if isinstance(result, dict) else "Target could not start"))
        result = _workflow_poll_engine(
            path,
            path,
            {"completed", "cancelled", "failed", "error"},
            context,
            browser=browser,
        )
        job_id = str(result.get("job_id") or result.get("map_id") or result.get("id") or path.rsplit("/", 1)[-1])
        TargetJob.objects.update_or_create(
            job_id=job_id,
            defaults={
                "project_id": project_id,
                "capture_context": capture_context,
                "engine_kind": "browser" if browser else "static",
                "url": payload["url"],
                "status": str(result.get("status", "completed")),
                "result": result,
            },
        )
        return result
    if node_type == "oast_listener":
        server_url = str(params.get("server_url") or "http://127.0.0.1:8766").strip()
        payload = {
            "server_url": server_url,
            "listener_id": str(params.get("listener_id") or "").strip(),
            "poll_interval_sec": max(1, min(OAST_MAX_POLL_INTERVAL_SEC, int(params.get("poll_interval_sec", 3)))),
            "timeout_sec": max(1, min(OAST_MAX_TIMEOUT_SEC, int(params.get("timeout_sec", 30)))),
            "capture_protocols": params.get("capture_protocols") or ["http"],
        }
        status, result = call_engine("/proxy/oast", payload)
        if status < 200 or status >= 300 or not isinstance(result, dict) or not result.get("listener_id"):
            raise WorkflowValidationError(str(result.get("error", "OAST Listener could not start") if isinstance(result, dict) else "OAST Listener could not start"))
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
        poll_interval = max(0.2, min(float(OAST_MAX_POLL_INTERVAL_SEC), float(params.get("poll_interval_sec", 1))))
        timeout = max(1.0, min(float(OAST_MAX_TIMEOUT_SEC), float(params.get("timeout_sec", 30))))
        deadline = time.monotonic() + timeout
        control = context.get("control")
        latest = {}
        while time.monotonic() < deadline:
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
            time.sleep(min(poll_interval, max(0.0, deadline - time.monotonic())))
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
        if status < 200 or status >= 300:
            raise WorkflowValidationError(str(result.get("error", "OSINT failed")))
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
        if status < 200 or status >= 300:
            raise WorkflowValidationError(str(result.get("error", "Scanner failed")))
        _ingest_scanner_result(Project.objects.filter(id=project_id).first(), result)
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
        if status < 200 or status >= 300 or not isinstance(result, dict) or not result.get("attack_id"):
            raise WorkflowValidationError(str(result.get("error", "Intruder could not start") if isinstance(result, dict) else "Intruder could not start"))
        attack_id = result["attack_id"]
        final = _workflow_poll_engine(
            f"/proxy/intruder/{attack_id}",
            f"/proxy/intruder/{attack_id}",
            {"completed", "cancelled", "failed"},
            context,
        )
        persist_intruder_history(int(attack_id), final.get("results") or [], final.get("result_offset", 0), project_id)
        return final
    if node_type == "ai_agent":
        prompt = str(params.get("prompt") or "Analyze the attached QA evidence.")
        messages = [{"role": "user", "content": prompt}]
        return generate_agent_chat(
            messages,
            provider=str(params.get("provider", "ollama")),
            endpoint=params.get("endpoint"),
            model=params.get("model"),
            context={"attached_evidence": {"workflow_input": input_value}},
        )
    raise WorkflowValidationError(f"unsupported tool node: {node_type}")


def _workflow_lookup(value, path):
    current = value
    for part in str(path or "").split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current
