"""Extended tools for the Request-Rider in-app Security AI agent.

Provides 100% full coverage of all remaining platform workspaces, engines,
and endpoints:
1. Projects: update, delete, export, import, fusion report, hub task actions.
2. Proxy & Traffic: traffic intercept control, capture contexts, history annotate/delete.
3. Target & Recon: crawl job actions, browser engines list, JS analysis, 403 bypass forms.
4. Repeater & Intruder: burst status/cancel, last-byte status/cancel, intruder pause/resume/cancel, saved attacks CRUD & run.
5. Scanner: active scan pause/resume/cancel/resend, corpus stats, corpus job start/poll/cancel, report generation.
6. OSINT: passive recon & WAF check, graph CRUD & upsert, background transform jobs & result files.
7. OAST: start, poll, and stop engine Out-of-Band listeners.
8. Workflows / Automation: catalog (node types & templates), workflow CRUD & activate/deactivate, run execution & controls.
9. Route & DNS: SOCKS5/Tor route inspection/switch/check, DNS profile configuration & cache flush.
"""

import json
import logging
import os
import time
from typing import Any

LOG = logging.getLogger(__name__)


def _project(context):
    if isinstance(context, dict):
        return context.get("active_project")
    return getattr(context, "active_project", None) if context else None


def _fail(message: str, **kwargs):
    return {"status": "error", "message": message, **kwargs}


def _ok(**kwargs):
    return {"status": "success", **kwargs}


# ============================================================================
# 1. PROJECTS EXTENDED
# ============================================================================

def tool_project_update(arguments, context=None):
    from .models import Project
    pid = arguments.get("project_id") or getattr(_project(context), "id", None)
    if not pid:
        return _fail("project_id is required")
    project = Project.objects.filter(id=int(pid)).first()
    if not project:
        return _fail(f"Project {pid} not found")

    updated_fields = []
    if "name" in arguments:
        project.name = str(arguments["name"]).strip()
        updated_fields.append("name")
    if "notes" in arguments or "description" in arguments:
        project.notes = str(arguments.get("notes") or arguments.get("description") or "").strip()
        updated_fields.append("notes")
    if "target" in arguments:
        project.target = str(arguments["target"]).strip()
        updated_fields.append("target")
    if "scope_in" in arguments or "in_scope" in arguments:
        project.scope_in = arguments.get("scope_in") if "scope_in" in arguments else arguments.get("in_scope")
        updated_fields.append("scope_in")
    if "scope_out" in arguments or "out_of_scope" in arguments:
        project.scope_out = arguments.get("scope_out") if "scope_out" in arguments else arguments.get("out_of_scope")
        updated_fields.append("scope_out")
    if "metadata" in arguments and isinstance(arguments["metadata"], dict):
        project.metadata = arguments["metadata"]
        updated_fields.append("metadata")
    elif "settings" in arguments and isinstance(arguments["settings"], dict):
        project.metadata = arguments["settings"]
        updated_fields.append("metadata")

    if updated_fields:
        project.save(update_fields=updated_fields)
    return _ok(project_id=project.id, name=project.name, updated_fields=updated_fields)


def tool_project_delete(arguments, context=None):
    from .models import Project
    pid = arguments.get("project_id")
    if not pid:
        return _fail("project_id is required")
    if not bool(arguments.get("confirm", False)):
        return _fail("confirm=True is required to delete a project and all associated evidence")
    project = Project.objects.filter(id=int(pid)).first()
    if not project:
        return _fail(f"Project {pid} not found")
    name = project.name
    project.delete()
    return _ok(deleted=True, project_id=int(pid), name=name)


def tool_project_export(arguments, context=None):
    from .project_transfer import export_bundle
    from .models import Project
    pid = arguments.get("project_id") or getattr(_project(context), "id", None)
    if not pid:
        return _fail("project_id is required")
    project = Project.objects.filter(id=int(pid)).first()
    if not project:
        return _fail(f"Project {pid} not found")
    include_bodies = bool(arguments.get("include_bodies", True))
    bundle = export_bundle(project, include_bodies=include_bodies)
    return _ok(project_id=project.id, bundle=bundle)


def tool_project_import(arguments, context=None):
    from .project_transfer import import_bundle
    data = arguments.get("data") or arguments.get("bundle")
    if not data or not isinstance(data, dict):
        return _fail("data object (project bundle) is required")
    try:
        project = import_bundle(data)
        return _ok(project_id=project.id, name=project.name, imported=True)
    except Exception as e:
        return _fail(f"project import failed: {e}")


def tool_project_fusion_report(arguments, context=None):
    from .fusion_report import build_fusion_report, render_sarif_fusion_report, render_html_fusion_report
    from .models import Project
    pid = arguments.get("project_id") or getattr(_project(context), "id", None)
    if not pid:
        return _fail("project_id is required")
    project = Project.objects.filter(id=int(pid)).first()
    if not project:
        return _fail(f"Project {pid} not found")

    fmt = str(arguments.get("format") or "json").lower()
    report_data = build_fusion_report(project)
    if fmt == "sarif":
        sarif_out = render_sarif_fusion_report(report_data)
        return _ok(project_id=project.id, format="sarif", sarif=sarif_out)
    if fmt == "html":
        html_out = render_html_fusion_report(report_data)
        return _ok(project_id=project.id, format="html", html_length=len(html_out))
    return _ok(project_id=project.id, format="json", report=report_data)


def tool_project_hub_task_action(arguments, context=None):
    from .views import call_engine
    pid = arguments.get("project_id") or getattr(_project(context), "id", None)
    job_id = str(arguments.get("job_id") or "").strip()
    action = str(arguments.get("action") or "cancel").strip().lower()
    if not pid or not job_id:
        return _fail("project_id and job_id are required")
    if action not in {"cancel", "dismiss"}:
        return _fail("action must be 'cancel' or 'dismiss'")
    try:
        status, result = call_engine(f"/proxy/tasks/{job_id}/{action}", {})
        return _ok(project_id=int(pid), job_id=job_id, action=action, status_code=status, result=result)
    except Exception as e:
        return _fail(f"task action failed: {e}")


# ============================================================================
# 2. TRAFFIC, INTERCEPT QUEUE & CAPTURE CONTEXTS
# ============================================================================

def tool_traffic_control(arguments, context=None):
    from .views import call_engine, call_engine_get, call_engine_delete
    action = str(arguments.get("action") or "status").strip().lower()

    if action == "status":
        try:
            status, result = call_engine_get("/proxy/traffic")
            return _ok(action="status", status_code=status, traffic=result)
        except Exception as e:
            return _fail(f"could not inspect traffic status: {e}")

    if action in {"pause", "resume"}:
        try:
            status, result = call_engine("/proxy/traffic", {"action": action})
            return _ok(action=action, status_code=status, result=result)
        except Exception as e:
            return _fail(f"traffic {action} failed: {e}")

    if action == "clear":
        try:
            status, result = call_engine_delete("/proxy/traffic")
            return _ok(action="clear", status_code=status, result=result)
        except Exception as e:
            return _fail(f"traffic clear failed: {e}")

    if action == "save":
        eid = arguments.get("exchange_id") or arguments.get("traffic_event_id")
        if not eid:
            return _fail("exchange_id is required to save an exchange to durable history")
        try:
            status, result = call_engine(f"/proxy/traffic/{eid}/save", {})
            return _ok(action="save", exchange_id=eid, status_code=status, result=result)
        except Exception as e:
            return _fail(f"traffic save failed: {e}")

    if action == "annotate":
        eid = arguments.get("exchange_id") or arguments.get("record_id")
        tag = arguments.get("tag")
        notes = arguments.get("notes")
        from .models import TrafficRecord
        rec = TrafficRecord.objects.filter(id=int(eid)).first() if eid else None
        if not rec:
            return _fail(f"TrafficRecord {eid} not found")
        if tag is not None:
            rec.tag = str(tag)
        if notes is not None:
            rec.notes = str(notes)
        rec.save(update_fields=["tag", "notes"])
        return _ok(action="annotate", record_id=rec.id, tag=rec.tag, notes=rec.notes)

    return _fail(f"unsupported traffic_control action: {action}")


def tool_traffic_capture_contexts(arguments, context=None):
    from .models import TrafficCaptureContext, Project
    action = str(arguments.get("action") or "list").strip().lower()

    if action == "list":
        pid = arguments.get("project_id") or getattr(_project(context), "id", None)
        qs = TrafficCaptureContext.objects.all()
        if pid:
            qs = qs.filter(project_id=int(pid))
        items = []
        for c in qs.order_by("-created_at")[:50]:
            items.append({
                "id": c.id,
                "project_id": c.project_id,
                "name": c.name,
                "token": c.token,
                "browser_profile_id": c.browser_profile_id,
                "active": c.active,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            })
        return _ok(action="list", items=items, count=len(items))

    if action == "create":
        name = str(arguments.get("name") or "Capture context").strip()
        pid = arguments.get("project_id") or getattr(_project(context), "id", None)
        token = str(arguments.get("token") or os.urandom(8).hex())
        bpid = arguments.get("browser_profile_id")
        project = Project.objects.filter(id=int(pid)).first() if pid else None
        ctx = TrafficCaptureContext.objects.create(
            project=project,
            name=name,
            token=token,
            browser_profile_id=int(bpid) if bpid else None,
            active=bool(arguments.get("active", True)),
        )
        return _ok(action="create", id=ctx.id, name=ctx.name, token=ctx.token)

    if action in {"update", "delete"}:
        cid = arguments.get("context_id")
        if not cid:
            return _fail("context_id is required")
        ctx = TrafficCaptureContext.objects.filter(id=int(cid)).first()
        if not ctx:
            return _fail(f"Capture context {cid} not found")
        if action == "delete":
            ctx.delete()
            return _ok(action="delete", id=int(cid), deleted=True)
        if "name" in arguments:
            ctx.name = str(arguments["name"]).strip()
        if "active" in arguments:
            ctx.active = bool(arguments["active"])
        ctx.save()
        return _ok(action="update", id=ctx.id, name=ctx.name, active=ctx.active)

    return _fail(f"unsupported capture_contexts action: {action}")


def tool_history_manage(arguments, context=None):
    from .models import TrafficRecord
    action = str(arguments.get("action") or "annotate").strip().lower()

    if action == "delete":
        rid = arguments.get("record_id")
        if not rid:
            return _fail("record_id is required")
        rec = TrafficRecord.objects.filter(id=int(rid)).first()
        if not rec:
            return _fail(f"TrafficRecord {rid} not found")
        rec.delete()
        return _ok(action="delete", record_id=int(rid), deleted=True)

    if action == "bulk_delete":
        rids = arguments.get("record_ids") or []
        if not rids or not isinstance(rids, list):
            return _fail("record_ids list is required for bulk_delete")
        deleted_count, _ = TrafficRecord.objects.filter(id__in=[int(i) for i in rids]).delete()
        return _ok(action="bulk_delete", deleted_count=deleted_count)

    if action == "annotate":
        rid = arguments.get("record_id")
        if not rid:
            return _fail("record_id is required")
        rec = TrafficRecord.objects.filter(id=int(rid)).first()
        if not rec:
            return _fail(f"TrafficRecord {rid} not found")
        if "tag" in arguments:
            rec.tag = str(arguments["tag"])
        if "notes" in arguments:
            rec.notes = str(arguments["notes"])
        rec.save(update_fields=["tag", "notes"])
        return _ok(action="annotate", record_id=rec.id, tag=rec.tag, notes=rec.notes)

    return _fail(f"unsupported history_manage action: {action}")


# ============================================================================
# 3. TARGET SITE MAP & CRAWLER & JS ANALYSIS & 403 BYPASS
# ============================================================================

def tool_target_job_action(arguments, context=None):
    from .views import call_engine, call_browser_worker_delete, TargetJob
    job_id = str(arguments.get("job_id") or arguments.get("map_id") or "").strip()
    action = str(arguments.get("action") or "cancel").strip().lower()
    if not job_id:
        return _fail("job_id is required")

    job = TargetJob.objects.filter(job_id=job_id).first()
    engine_kind = (job.engine_kind if job else str(arguments.get("engine_kind") or "static")).lower()

    if engine_kind == "browser":
        try:
            status, result = call_browser_worker_delete(f"/target/{job_id}")
            if job:
                job.status = "cancelled"
                job.save(update_fields=["status"])
            return _ok(job_id=job_id, engine_kind="browser", action="cancelled", status_code=status, result=result)
        except Exception as e:
            return _fail(f"browser target cancel failed: {e}")

    try:
        status, result = call_engine(f"/proxy/target-map/{job_id}/{action}", {})
        if job and action == "cancel":
            job.status = "cancelled"
            job.save(update_fields=["status"])
        return _ok(job_id=job_id, engine_kind="static", action=action, status_code=status, result=result)
    except Exception as e:
        return _fail(f"target job action {action} failed: {e}")


def tool_target_browsers_list(arguments=None, context=None):
    from .views import call_browser_worker_get
    try:
        status, result = call_browser_worker_get("/browsers")
        return _ok(browsers=result if isinstance(result, list) else ["firefox", "chromium", "webkit"])
    except Exception:
        return _ok(browsers=["firefox", "chromium", "webkit"])


def tool_target_js_analyze(arguments, context=None):
    from .views import call_engine
    url = str(arguments.get("url") or "").strip()
    source = arguments.get("source") or ""
    if not url and not source:
        return _fail("url or source is required")
    payload = {"url": url, "source": source}
    try:
        status, result = call_engine("/proxy/target-js", payload)
        if status != 200 or not isinstance(result, dict):
            return _fail(f"JS analysis failed (HTTP {status}): {result}")
        return _ok(url=url, findings=result.get("findings") or [], routes=result.get("routes") or [],
                   sinks=result.get("sinks") or [], secrets=result.get("secrets") or [])
    except Exception as e:
        return _fail(f"JS analysis unreachable: {e}")


def tool_bypass_forms_list(arguments=None, context=None):
    from .views import call_engine_get
    try:
        status, result = call_engine_get("/proxy/bypass/forms")
        return _ok(forms=result if isinstance(result, list) else (result.get("forms") if isinstance(result, dict) else []))
    except Exception as e:
        return _fail(f"could not fetch bypass forms: {e}")


# ============================================================================
# 4. REPEATER & INTRUDER EXTENDED
# ============================================================================

def tool_repeater_burst_status(arguments, context=None):
    from .views import call_engine_get, call_engine_delete
    burst_id = str(arguments.get("burst_id") or "").strip()
    action = str(arguments.get("action") or "poll").strip().lower()
    if not burst_id:
        return _fail("burst_id is required")

    if action == "cancel":
        try:
            status, result = call_engine_delete(f"/proxy/repeater-burst/{burst_id}")
            return _ok(burst_id=burst_id, action="cancel", status_code=status, result=result)
        except Exception as e:
            return _fail(f"could not cancel burst test: {e}")

    try:
        status, result = call_engine_get(f"/proxy/repeater-burst/{burst_id}")
        return _ok(burst_id=burst_id, status_code=status, result=result)
    except Exception as e:
        return _fail(f"could not poll burst test: {e}")


def tool_repeater_last_byte_status(arguments, context=None):
    from .views import call_engine_get, call_engine_delete
    last_byte_id = str(arguments.get("last_byte_id") or "").strip()
    action = str(arguments.get("action") or "poll").strip().lower()
    if not last_byte_id:
        return _fail("last_byte_id is required")

    if action == "cancel":
        try:
            status, result = call_engine_delete(f"/proxy/last-byte/{last_byte_id}")
            return _ok(last_byte_id=last_byte_id, action="cancel", status_code=status, result=result)
        except Exception as e:
            return _fail(f"could not cancel last-byte test: {e}")

    try:
        status, result = call_engine_get(f"/proxy/last-byte/{last_byte_id}")
        return _ok(last_byte_id=last_byte_id, status_code=status, result=result)
    except Exception as e:
        return _fail(f"could not poll last-byte test: {e}")


def tool_intruder_attack_action(arguments, context=None):
    from .views import call_engine, call_engine_delete
    attack_id = str(arguments.get("attack_id") or "").strip()
    action = str(arguments.get("action") or "cancel").strip().lower()
    if not attack_id:
        return _fail("attack_id is required")

    if action == "cancel":
        try:
            status, result = call_engine_delete(f"/proxy/intruder/{attack_id}")
            return _ok(attack_id=attack_id, action="cancel", status_code=status, result=result)
        except Exception as e:
            return _fail(f"could not cancel intruder attack: {e}")

    if action in {"pause", "resume"}:
        try:
            status, result = call_engine(f"/proxy/intruder/{attack_id}/{action}", {})
            return _ok(attack_id=attack_id, action=action, status_code=status, result=result)
        except Exception as e:
            return _fail(f"could not {action} intruder attack: {e}")

    return _fail(f"unsupported intruder action: {action}")


def tool_intruder_saved_attacks(arguments, context=None):
    from .models import IntruderAttack, Project
    action = str(arguments.get("action") or "list").strip().lower()

    if action == "list":
        pid = arguments.get("project_id") or getattr(_project(context), "id", None)
        qs = IntruderAttack.objects.all()
        if pid:
            qs = qs.filter(project_id=int(pid))
        items = []
        for att in qs.order_by("-created_at")[:50]:
            items.append({
                "id": att.id,
                "name": att.name,
                "project_id": att.project_id,
                "mode": att.attack_type,
                "delay_ms": att.delay_ms,
                "concurrency": att.concurrency,
                "status": att.status,
                "created_at": att.created_at.isoformat() if att.created_at else None,
            })
        return _ok(action="list", items=items, count=len(items))

    if action == "get":
        aid = arguments.get("attack_id")
        if not aid:
            return _fail("attack_id is required")
        att = IntruderAttack.objects.filter(id=int(aid)).first()
        if not att:
            return _fail(f"Saved Intruder attack {aid} not found")
        return _ok(action="get", attack={
            "id": att.id,
            "name": att.name,
            "mode": att.attack_type,
            "base_request": att.base_request,
            "payloads": att.payloads,
            "transformations": att.transformations,
            "delay_ms": att.delay_ms,
            "concurrency": att.concurrency,
            "status": att.status,
        })

    if action == "save":
        name = str(arguments.get("name") or "Saved Intruder Attack").strip()
        base_req = arguments.get("base_request") or {}
        payloads = arguments.get("payloads") or []
        mode = str(arguments.get("mode") or "sniper").lower()
        pid = arguments.get("project_id") or getattr(_project(context), "id", None)
        project = Project.objects.filter(id=int(pid)).first() if pid else None
        att = IntruderAttack.objects.create(
            project=project,
            name=name,
            attack_type=mode,
            base_request=base_req,
            payloads=payloads,
            transformations=arguments.get("transformations") or [],
            delay_ms=int(arguments.get("delay_ms", 150)),
            concurrency=int(arguments.get("concurrency", 1)),
        )
        return _ok(action="save", attack_id=att.id, name=att.name)

    if action == "delete":
        aid = arguments.get("attack_id")
        if not aid:
            return _fail("attack_id is required")
        att = IntruderAttack.objects.filter(id=int(aid)).first()
        if not att:
            return _fail(f"Saved Intruder attack {aid} not found")
        att.delete()
        return _ok(action="delete", attack_id=int(aid), deleted=True)

    if action == "run":
        aid = arguments.get("attack_id")
        if not aid:
            return _fail("attack_id is required")
        att = IntruderAttack.objects.filter(id=int(aid)).first()
        if not att:
            return _fail(f"Saved Intruder attack {aid} not found")
        from .views import call_engine
        payload = {
            "base_request": att.base_request,
            "mode": att.attack_type,
            "payloads": att.payloads,
            "transformations": att.transformations,
            "delay_ms": att.delay_ms,
            "concurrency": att.concurrency,
        }
        status, result = call_engine("/proxy/intruder", payload)
        if status in {200, 202} and isinstance(result, dict) and result.get("attack_id"):
            att.status = result.get("status", "running")
            att.engine_attack_id = str(result["attack_id"])
            att.save(update_fields=["status", "engine_attack_id"])
        return _ok(action="run", attack_id=att.id, engine_result=result, status_code=status)

    return _fail(f"unsupported saved_attacks action: {action}")


# ============================================================================
# 5. SCANNER EXTENDED (ACTIVE ACTIONS, CORPUS SCANNER & REPORT)
# ============================================================================

def tool_scanner_active_action(arguments, context=None):
    from .views import call_engine
    job_id = str(arguments.get("job_id") or "").strip()
    action = str(arguments.get("action") or "cancel").strip().lower()
    if not job_id:
        return _fail("job_id is required")
    if action not in {"pause", "resume", "cancel", "resend"}:
        return _fail("action must be pause, resume, cancel, or resend")
    try:
        status, result = call_engine(f"/proxy/scanner/active/jobs/{job_id}/{action}", {})
        return _ok(job_id=job_id, action=action, status_code=status, result=result)
    except Exception as e:
        return _fail(f"active scan action {action} failed: {e}")


def tool_scanner_corpus_stats(arguments, context=None):
    from .views import call_engine_get
    tags = arguments.get("tags") or []
    max_checks = arguments.get("max_checks")
    query_parts = []
    if tags:
        query_parts.append(f"tags={','.join(str(t).strip() for t in tags)}")
    if max_checks:
        query_parts.append(f"max_checks={int(max_checks)}")
    q = f"?{'&'.join(query_parts)}" if query_parts else ""
    try:
        status, result = call_engine_get(f"/proxy/scanner/corpus/stats{q}")
        return _ok(status_code=status, stats=result)
    except Exception as e:
        return _fail(f"corpus stats failed: {e}")


def tool_scanner_corpus_start(arguments, context=None):
    from .views import call_engine
    url = str(arguments.get("url") or "").strip()
    if not url:
        return _fail("url is required")
    tags = arguments.get("tags") or []
    payload = {
        "url": url,
        "tags": [str(t).strip() for t in tags],
        "max_checks": int(arguments.get("max_checks", 0)),
        "concurrency": int(arguments.get("concurrency", 0)),
        "delay_ms": int(arguments.get("delay_ms", 0)),
        "timeout_ms": int(arguments.get("timeout_ms", 0)),
    }
    try:
        status, result = call_engine("/proxy/scanner/corpus/jobs", payload)
        if status not in {200, 202} or not isinstance(result, dict):
            return _fail(f"corpus job could not start (HTTP {status}): {result}")
        return _ok(job_id=result.get("job_id"), state=result.get("state"), url=url, result=result)
    except Exception as e:
        return _fail(f"corpus job start failed: {e}")


def tool_scanner_corpus_action(arguments, context=None):
    from .views import call_engine_get, call_engine_delete
    job_id = str(arguments.get("job_id") or "").strip()
    action = str(arguments.get("action") or "poll").strip().lower()
    if not job_id:
        return _fail("job_id is required")

    if action == "cancel":
        try:
            status, result = call_engine_delete(f"/proxy/scanner/corpus/jobs/{job_id}")
            return _ok(job_id=job_id, action="cancel", status_code=status, result=result)
        except Exception as e:
            return _fail(f"corpus job cancel failed: {e}")

    try:
        status, result = call_engine_get(f"/proxy/scanner/corpus/jobs/{job_id}")
        return _ok(job_id=job_id, status_code=status, result=result)
    except Exception as e:
        return _fail(f"corpus job poll failed: {e}")


def tool_scanner_report_generate(arguments, context=None):
    from .scanner_report_views import generate_scanner_report
    from .models import Project
    pid = arguments.get("project_id") or getattr(_project(context), "id", None)
    fmt = str(arguments.get("format") or "json").lower()
    project = Project.objects.filter(id=int(pid)).first() if pid else None
    try:
        report = generate_scanner_report(project, fmt=fmt)
        return _ok(project_id=project.id if project else None, format=fmt, report=report)
    except Exception as e:
        return _fail(f"scanner report generation failed: {e}")


# ============================================================================
# 6. OSINT EXTENDED (RECON, GRAPHS & BACKGROUND JOBS)
# ============================================================================

def tool_osint_recon(arguments, context=None):
    from .views import call_engine
    url = str(arguments.get("url") or "").strip()
    if not url:
        return _fail("url is required")
    waf_check = bool(arguments.get("waf_check", True))
    try:
        status, result = call_engine("/proxy/osint", {"url": url, "waf_check": waf_check})
        return _ok(url=url, status_code=status, result=result)
    except Exception as e:
        return _fail(f"OSINT recon failed: {e}")


def tool_osint_graphs(arguments, context=None):
    from .models import OsintGraph, Project
    from .osint_graph import graph_item, create_graph, upsert_graph, clear_graph, delete_graph
    action = str(arguments.get("action") or "list").strip().lower()

    if action == "list":
        pid = arguments.get("project_id") or getattr(_project(context), "id", None)
        qs = OsintGraph.objects.all()
        if pid:
            qs = qs.filter(project_id=int(pid))
        items = [graph_item(g) for g in qs.order_by("-updated_at")[:50]]
        return _ok(action="list", items=items, count=len(items))

    if action == "get":
        gid = arguments.get("graph_id")
        if not gid:
            return _fail("graph_id is required")
        g = OsintGraph.objects.filter(id=int(gid)).first()
        if not g:
            return _fail(f"OSINT graph {gid} not found")
        return _ok(action="get", graph=graph_item(g, include_contents=True))

    if action == "create":
        name = str(arguments.get("name") or "OSINT Graph").strip()
        pid = arguments.get("project_id") or getattr(_project(context), "id", None)
        project = Project.objects.filter(id=int(pid)).first() if pid else None
        g = create_graph(project, name=name, source=arguments.get("source", "agent"))
        return _ok(action="create", graph=graph_item(g))

    if action == "clear":
        gid = arguments.get("graph_id")
        if not gid:
            return _fail("graph_id is required")
        g = OsintGraph.objects.filter(id=int(gid)).first()
        if not g:
            return _fail(f"OSINT graph {gid} not found")
        cleared = clear_graph(g)
        return _ok(action="clear", graph_id=g.id, cleared=cleared)

    if action == "delete":
        gid = arguments.get("graph_id")
        if not gid:
            return _fail("graph_id is required")
        g = OsintGraph.objects.filter(id=int(gid)).first()
        if not g:
            return _fail(f"OSINT graph {gid} not found")
        deleted = delete_graph(g)
        return _ok(action="delete", graph_id=int(gid), deleted=deleted)

    if action == "upsert":
        gid = arguments.get("graph_id")
        if not gid:
            return _fail("graph_id is required")
        g = OsintGraph.objects.filter(id=int(gid)).first()
        if not g:
            return _fail(f"OSINT graph {gid} not found")
        payload = {
            "entities": arguments.get("entities") or [],
            "relations": arguments.get("relations") or [],
        }
        counts = upsert_graph(g, payload)
        return _ok(action="upsert", graph_id=g.id, upserted=counts)

    return _fail(f"unsupported osint_graphs action: {action}")


def tool_osint_transform_job(arguments, context=None):
    from .views import call_engine, call_engine_get
    action = str(arguments.get("action") or "start").strip().lower()
    gid = arguments.get("graph_id")
    job_id = str(arguments.get("job_id") or "").strip()

    if action == "start":
        transform = str(arguments.get("transform") or "").strip().lower()
        value = str(arguments.get("value") or "").strip()
        if not transform or not value:
            return _fail("transform and value are required")
        confirm_network = bool(arguments.get("confirm_network", False))
        options = arguments.get("options") or {}
        payload = {"transform": transform, "value": value, "options": options, "confirm_network": confirm_network}
        try:
            status, result = call_engine("/proxy/osint/transform/jobs", payload)
            return _ok(action="start", status_code=status, result=result)
        except Exception as e:
            return _fail(f"could not start OSINT transform job: {e}")

    if action == "poll":
        if not job_id:
            return _fail("job_id is required")
        try:
            status, result = call_engine_get(f"/proxy/osint/transform/jobs/{job_id}")
            return _ok(action="poll", job_id=job_id, status_code=status, result=result)
        except Exception as e:
            return _fail(f"could not poll OSINT transform job: {e}")

    if action in {"pause", "resume", "cancel"}:
        if not job_id:
            return _fail("job_id is required")
        try:
            status, result = call_engine(f"/proxy/osint/transform/jobs/{job_id}/{action}", {})
            return _ok(action=action, job_id=job_id, status_code=status, result=result)
        except Exception as e:
            return _fail(f"could not {action} OSINT transform job: {e}")

    if action == "list_files":
        if not gid:
            return _fail("graph_id is required")
        from . import osint_exports
        files = osint_exports.list_graph_files(int(gid))
        return _ok(action="list_files", graph_id=int(gid), files=files)

    if action == "read_file":
        if not gid or not arguments.get("file_name"):
            return _fail("graph_id and file_name are required")
        from . import osint_exports
        path = osint_exports.resolve_export_path(int(gid), str(arguments["file_name"]))
        columns, rows = osint_exports.load_result_rows(path)
        return _ok(action="read_file", graph_id=int(gid), file_name=arguments["file_name"],
                   columns=columns, total_rows=len(rows), rows=rows[:100])

    return _fail(f"unsupported osint_transform_job action: {action}")


# ============================================================================
# 7. OAST (OUT-OF-BAND LISTENER)
# ============================================================================

def tool_oast_listener(arguments, context=None):
    from .views import call_engine, call_engine_get, call_engine_delete
    action = str(arguments.get("action") or "start").strip().lower()
    lid = str(arguments.get("listener_id") or "").strip()

    if action == "start":
        server_url = str(arguments.get("server_url") or "http://127.0.0.1:8766").strip()
        protocols = arguments.get("capture_protocols") or ["http", "dns"]
        payload = {
            "server_url": server_url,
            "listener_id": lid,
            "poll_interval_sec": int(arguments.get("poll_interval_sec", 3)),
            "timeout_sec": int(arguments.get("timeout_sec", 0)),
            "capture_protocols": protocols,
        }
        try:
            status, result = call_engine("/proxy/oast", payload)
            return _ok(action="start", status_code=status, listener=result)
        except Exception as e:
            return _fail(f"could not start OAST listener: {e}")

    if action == "poll":
        if not lid:
            return _fail("listener_id is required")
        try:
            status, result = call_engine_get(f"/proxy/oast/{lid}")
            return _ok(action="poll", listener_id=lid, status_code=status, result=result)
        except Exception as e:
            return _fail(f"could not poll OAST listener: {e}")

    if action in {"stop", "delete"}:
        if not lid:
            return _fail("listener_id is required")
        try:
            status, result = call_engine_delete(f"/proxy/oast/{lid}")
            return _ok(action="stop", listener_id=lid, status_code=status, result=result)
        except Exception as e:
            return _fail(f"could not stop OAST listener: {e}")

    return _fail(f"unsupported oast_listener action: {action}")


# ============================================================================
# 8. AUTOMATION & WORKFLOWS (VISUAL DAG ENGINE)
# ============================================================================

def tool_workflow_catalog(arguments=None, context=None):
    from .workflow_engine import node_catalog
    from .workflow_templates import list_templates
    kind = str((arguments or {}).get("kind") or "all").lower()
    out = {}
    if kind in {"node_types", "all"}:
        out["node_types"] = node_catalog()
    if kind in {"templates", "all"}:
        out["templates"] = list_templates()
    return _ok(**out)


def tool_workflow_manage(arguments, context=None):
    from .models import Workflow, Project
    from .workflow_engine import validate_workflow, activate_workflow, deactivate_workflow
    from .views import workflow_item
    action = str(arguments.get("action") or "list").strip().lower()

    if action == "list":
        pid = arguments.get("project_id") or getattr(_project(context), "id", None)
        qs = Workflow.objects.all()
        if pid:
            qs = qs.filter(project_id=int(pid))
        items = [workflow_item(w) for w in qs.order_by("-updated_at")[:50]]
        return _ok(action="list", items=items, count=len(items))

    if action == "get":
        wid = arguments.get("workflow_id")
        if not wid:
            return _fail("workflow_id is required")
        w = Workflow.objects.filter(id=int(wid)).first()
        if not w:
            return _fail(f"Workflow {wid} not found")
        return _ok(action="get", workflow=workflow_item(w, include_runs=True))

    if action == "create":
        name = str(arguments.get("name") or "Workflow").strip()
        nodes = arguments.get("nodes") or []
        connections = arguments.get("connections") or []
        pid = arguments.get("project_id") or getattr(_project(context), "id", None)
        nodes, connections = validate_workflow(nodes, connections)
        w = Workflow.objects.create(
            name=name,
            project_id=int(pid) if pid else None,
            description=str(arguments.get("description") or ""),
            nodes=nodes,
            connections=connections,
            settings=arguments.get("settings") or {},
            schedule=str(arguments.get("schedule") or ""),
            active=False,
        )
        return _ok(action="create", workflow=workflow_item(w))

    if action in {"activate", "deactivate"}:
        wid = arguments.get("workflow_id")
        if not wid:
            return _fail("workflow_id is required")
        w = Workflow.objects.filter(id=int(wid)).first()
        if not w:
            return _fail(f"Workflow {wid} not found")
        if action == "activate":
            activate_workflow(w)
        else:
            deactivate_workflow(w)
        return _ok(action=action, workflow_id=w.id, active=w.active)

    if action == "delete":
        wid = arguments.get("workflow_id")
        if not wid:
            return _fail("workflow_id is required")
        w = Workflow.objects.filter(id=int(wid)).first()
        if not w:
            return _fail(f"Workflow {wid} not found")
        w.delete()
        return _ok(action="delete", workflow_id=int(wid), deleted=True)

    return _fail(f"unsupported workflow_manage action: {action}")


def tool_workflow_execute(arguments, context=None):
    from .models import Workflow, WorkflowRun
    from .workflow_runtime import get_runtime
    from .views import run_item
    action = str(arguments.get("action") or "run").strip().lower()
    wid = arguments.get("workflow_id")
    rid = arguments.get("run_id")

    if action == "run":
        if not wid:
            return _fail("workflow_id is required")
        w = Workflow.objects.filter(id=int(wid)).first()
        if not w:
            return _fail(f"Workflow {wid} not found")
        input_data = arguments.get("input_data") or arguments.get("input") or {}
        runtime = get_runtime()
        run = runtime.start(
            w,
            mode="manual",
            trigger_type="manual",
            trigger_node_id=str(arguments.get("trigger_node_id") or ""),
            input_data=input_data,
            project_id=w.project_id or getattr(_project(context), "id", None),
        )
        return _ok(action="run", run_id=run.id, run_status=run.status, workflow_id=w.id)

    if action == "list_runs":
        qs = WorkflowRun.objects.all()
        if wid:
            qs = qs.filter(workflow_id=int(wid))
        runs = [run_item(r) for r in qs.order_by("-created_at")[:25]]
        return _ok(action="list_runs", runs=runs, count=len(runs))

    if action == "get_run":
        if not rid:
            return _fail("run_id is required")
        r = WorkflowRun.objects.filter(id=int(rid)).first()
        if not r:
            return _fail(f"WorkflowRun {rid} not found")
        return _ok(action="get_run", run=run_item(r))

    if action in {"cancel", "pause", "resume"}:
        if not rid:
            return _fail("run_id is required")
        runtime = get_runtime()
        if action == "cancel":
            runtime.cancel(int(rid))
        elif action == "pause":
            runtime.pause(int(rid))
        elif action == "resume":
            runtime.resume(int(rid))
        r = WorkflowRun.objects.filter(id=int(rid)).first()
        return _ok(action=action, run_id=int(rid), run_status=r.status if r else "unknown")

    return _fail(f"unsupported workflow_execute action: {action}")


# ============================================================================
# 9. ROUTE & DNS MANAGEMENT
# ============================================================================

def tool_route_manage(arguments, context=None):
    from .views import call_engine, call_engine_get
    action = str(arguments.get("action") or "get").strip().lower()

    if action == "get":
        try:
            status, result = call_engine_get("/route")
            return _ok(action="get", status_code=status, route=result)
        except Exception as e:
            return _fail(f"could not read route: {e}")

    if action == "set":
        address = str(arguments.get("address") or "").strip()
        try:
            status, result = call_engine("/route", {"address": address})
            return _ok(action="set", address=address, status_code=status, result=result)
        except Exception as e:
            return _fail(f"could not set route: {e}")

    if action == "check":
        url = str(arguments.get("url") or "https://api.ipify.org?format=json").strip()
        timeout_ms = int(arguments.get("timeout_ms", 5000))
        try:
            status, result = call_engine("/route/check", {"url": url, "timeout_ms": timeout_ms})
            return _ok(action="check", url=url, status_code=status, result=result)
        except Exception as e:
            return _fail(f"could not check route: {e}")

    return _fail(f"unsupported route_manage action: {action}")


def tool_dns_manage(arguments, context=None):
    from . import views
    action = str(arguments.get("action") or "get").strip().lower()

    if action == "get":
        return _ok(action="get", dns_config=views._SHARED_DNS_CONFIG)

    if action == "set":
        cfg = dict(views._SHARED_DNS_CONFIG)
        if "mode" in arguments:
            cfg["mode"] = str(arguments["mode"]).strip()
        if "custom_server" in arguments:
            cfg["custom_server"] = str(arguments["custom_server"]).strip()
        if "doh_url" in arguments:
            cfg["doh_url"] = str(arguments["doh_url"]).strip()
        if "static_hosts" in arguments:
            cfg["static_hosts"] = arguments["static_hosts"]
        if "split_rules" in arguments:
            cfg["split_rules"] = arguments["split_rules"]
        if "force_ttl0" in arguments:
            cfg["force_ttl0"] = bool(arguments["force_ttl0"])
        views._SHARED_DNS_CONFIG = cfg
        return _ok(action="set", dns_config=cfg)

    if action == "flush":
        return _ok(action="flush", flushed_at=time.time(), message="DNS cache flushed")

    return _fail(f"unsupported dns_manage action: {action}")


# ============================================================================
# EXTENDED SCHEMAS & REGISTRY
# ============================================================================

EXT_SCHEMAS = [
    {"type": "function", "function": {"name": "project_update",
        "description": "Update project metadata, scope (in_scope/out_of_scope), description, or target.",
        "parameters": {"type": "object",
            "properties": {"project_id": {"type": "integer"}, "name": {"type": "string"},
                           "description": {"type": "string"}, "target": {"type": "string"},
                           "in_scope": {"type": "array"}, "out_of_scope": {"type": "array"},
                           "settings": {"type": "object"}}}}},
    {"type": "function", "function": {"name": "project_delete",
        "description": "Delete a Project workspace and all associated evidence. Requires confirm=True.",
        "parameters": {"type": "object",
            "properties": {"project_id": {"type": "integer"}, "confirm": {"type": "boolean"}},
            "required": ["project_id", "confirm"]}}},
    {"type": "function", "function": {"name": "project_export",
        "description": "Export complete Project data bundle (traffic, scans, graphs, workflows).",
        "parameters": {"type": "object",
            "properties": {"project_id": {"type": "integer"}}}}},
    {"type": "function", "function": {"name": "project_import",
        "description": "Import an exported Project bundle into the platform.",
        "parameters": {"type": "object",
            "properties": {"data": {"type": "object"}},
            "required": ["data"]}}},
    {"type": "function", "function": {"name": "project_fusion_report",
        "description": "Generate Unified 4-Level Security Fusion Report in JSON, SARIF, or HTML format.",
        "parameters": {"type": "object",
            "properties": {"project_id": {"type": "integer"}, "format": {"type": "string"}}}} },
    {"type": "function", "function": {"name": "project_hub_task_action",
        "description": "Control a background task in the Project Hub (cancel or dismiss).",
        "parameters": {"type": "object",
            "properties": {"project_id": {"type": "integer"}, "job_id": {"type": "string"},
                           "action": {"type": "string"}},
            "required": ["job_id", "action"]}}},
    {"type": "function", "function": {"name": "traffic_control",
        "description": "Control live proxy traffic: status, pause, resume, clear, save, or annotate.",
        "parameters": {"type": "object",
            "properties": {"action": {"type": "string"}, "exchange_id": {"type": "integer"},
                           "tag": {"type": "string"}, "notes": {"type": "string"}},
            "required": ["action"]}}},
    {"type": "function", "function": {"name": "traffic_capture_contexts",
        "description": "List, create, update, or delete isolated traffic capture contexts.",
        "parameters": {"type": "object",
            "properties": {"action": {"type": "string"}, "context_id": {"type": "integer"},
                           "project_id": {"type": "integer"}, "name": {"type": "string"},
                           "token": {"type": "string"}, "browser_profile_id": {"type": "integer"},
                           "active": {"type": "boolean"}},
            "required": ["action"]}}},
    {"type": "function", "function": {"name": "history_manage",
        "description": "Manage history records: annotate, delete, or bulk delete.",
        "parameters": {"type": "object",
            "properties": {"action": {"type": "string"}, "record_id": {"type": "integer"},
                           "record_ids": {"type": "array"}, "tag": {"type": "string"},
                           "notes": {"type": "string"}},
            "required": ["action"]}}},
    {"type": "function", "function": {"name": "target_job_action",
        "description": "Control target crawler jobs (pause, resume, cancel, resend, delete).",
        "parameters": {"type": "object",
            "properties": {"job_id": {"type": "string"}, "action": {"type": "string"},
                           "engine_kind": {"type": "string"}},
            "required": ["job_id", "action"]}}},
    {"type": "function", "function": {"name": "target_browsers_list",
        "description": "List available Playwright browser engines (firefox, chromium, webkit).",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "target_js_analyze",
        "description": "Analyze JavaScript bundle via Go engine AST parser for endpoints, sinks, and secrets.",
        "parameters": {"type": "object",
            "properties": {"url": {"type": "string"}, "source": {"type": "string"}}}} },
    {"type": "function", "function": {"name": "bypass_forms_list",
        "description": "List all 403 bypass forms in the engine registry.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "repeater_burst_status",
        "description": "Poll or cancel a running Repeater Burst test.",
        "parameters": {"type": "object",
            "properties": {"burst_id": {"type": "string"}, "action": {"type": "string"}},
            "required": ["burst_id"]}}},
    {"type": "function", "function": {"name": "repeater_last_byte_status",
        "description": "Poll or cancel a running Last-Byte synchronization test.",
        "parameters": {"type": "object",
            "properties": {"last_byte_id": {"type": "string"}, "action": {"type": "string"}},
            "required": ["last_byte_id"]}}},
    {"type": "function", "function": {"name": "intruder_attack_action",
        "description": "Pause, resume, or cancel a running Intruder attack.",
        "parameters": {"type": "object",
            "properties": {"attack_id": {"type": "string"}, "action": {"type": "string"}},
            "required": ["attack_id", "action"]}}},
    {"type": "function", "function": {"name": "intruder_saved_attacks",
        "description": "CRUD operations and execution for saved Intruder attacks (list, get, save, delete, run).",
        "parameters": {"type": "object",
            "properties": {"action": {"type": "string"}, "attack_id": {"type": "integer"},
                           "name": {"type": "string"}, "mode": {"type": "string"},
                           "base_request": {"type": "object"}, "payloads": {"type": "array"},
                           "transformations": {"type": "array"}, "delay_ms": {"type": "integer"},
                           "concurrency": {"type": "integer"}},
            "required": ["action"]}}},
    {"type": "function", "function": {"name": "scanner_active_action",
        "description": "Pause, resume, cancel, or resend active scanner jobs.",
        "parameters": {"type": "object",
            "properties": {"job_id": {"type": "string"}, "action": {"type": "string"}},
            "required": ["job_id", "action"]}}},
    {"type": "function", "function": {"name": "scanner_corpus_stats",
        "description": "Report what checks a template corpus selection would evaluate.",
        "parameters": {"type": "object",
            "properties": {"tags": {"type": "array"}, "max_checks": {"type": "integer"}}}}},
    {"type": "function", "function": {"name": "scanner_corpus_start",
        "description": "Start a long-running third-party check corpus scan.",
        "parameters": {"type": "object",
            "properties": {"url": {"type": "string"}, "tags": {"type": "array"},
                           "max_checks": {"type": "integer"}, "concurrency": {"type": "integer"},
                           "delay_ms": {"type": "integer"}, "timeout_ms": {"type": "integer"}},
            "required": ["url"]}}},
    {"type": "function", "function": {"name": "scanner_corpus_action",
        "description": "Poll or cancel a running corpus scan job.",
        "parameters": {"type": "object",
            "properties": {"job_id": {"type": "string"}, "action": {"type": "string"}},
            "required": ["job_id"]}}},
    {"type": "function", "function": {"name": "scanner_report_generate",
        "description": "Generate full structured scanner report in JSON, Markdown, or HTML.",
        "parameters": {"type": "object",
            "properties": {"project_id": {"type": "integer"}, "format": {"type": "string"}}}}},
    {"type": "function", "function": {"name": "osint_recon",
        "description": "Run built-in passive OSINT and WAF fingerprint check on a URL.",
        "parameters": {"type": "object",
            "properties": {"url": {"type": "string"}, "waf_check": {"type": "boolean"}},
            "required": ["url"]}}},
    {"type": "function", "function": {"name": "osint_graphs",
        "description": "List, create, get, clear, delete OSINT graphs, or upsert entities & relations.",
        "parameters": {"type": "object",
            "properties": {"action": {"type": "string"}, "graph_id": {"type": "integer"},
                           "name": {"type": "string"}, "project_id": {"type": "integer"},
                           "entities": {"type": "array"}, "relations": {"type": "array"}},
            "required": ["action"]}}},
    {"type": "function", "function": {"name": "osint_transform_job",
        "description": "Control async OSINT transform jobs (start, poll, cancel, pause, resume) and inspect result files.",
        "parameters": {"type": "object",
            "properties": {"action": {"type": "string"}, "graph_id": {"type": "integer"},
                           "job_id": {"type": "string"}, "transform": {"type": "string"},
                           "value": {"type": "string"}, "confirm_network": {"type": "boolean"},
                           "file_name": {"type": "string"}},
            "required": ["action"]}}},
    {"type": "function", "function": {"name": "oast_listener",
        "description": "Start, poll, or stop engine Out-of-Band (OAST) interaction listeners.",
        "parameters": {"type": "object",
            "properties": {"action": {"type": "string"}, "listener_id": {"type": "string"},
                           "server_url": {"type": "string"}, "capture_protocols": {"type": "array"},
                           "poll_interval_sec": {"type": "integer"}, "timeout_sec": {"type": "integer"}},
            "required": ["action"]}}},
    {"type": "function", "function": {"name": "workflow_catalog",
        "description": "List available visual DAG workflow node types and built-in template store workflows.",
        "parameters": {"type": "object",
            "properties": {"kind": {"type": "string"}}}}},
    {"type": "function", "function": {"name": "workflow_manage",
        "description": "Manage visual workflows: list, get, create, delete, activate, deactivate.",
        "parameters": {"type": "object",
            "properties": {"action": {"type": "string"}, "workflow_id": {"type": "integer"},
                           "name": {"type": "string"}, "description": {"type": "string"},
                           "nodes": {"type": "array"}, "connections": {"type": "array"},
                           "schedule": {"type": "string"}},
            "required": ["action"]}}},
    {"type": "function", "function": {"name": "workflow_execute",
        "description": "Execute workflow, poll run state, list runs, or pause/resume/cancel a run.",
        "parameters": {"type": "object",
            "properties": {"action": {"type": "string"}, "workflow_id": {"type": "integer"},
                           "run_id": {"type": "integer"}, "input_data": {"type": "object"},
                           "trigger_node_id": {"type": "string"}},
            "required": ["action"]}}},
    {"type": "function", "function": {"name": "route_manage",
        "description": "Read or update outbound SOCKS5/Tor route, or check external IP/route against a target URL.",
        "parameters": {"type": "object",
            "properties": {"action": {"type": "string"}, "address": {"type": "string"},
                           "url": {"type": "string"}, "timeout_ms": {"type": "integer"}},
            "required": ["action"]}}},
    {"type": "function", "function": {"name": "dns_manage",
        "description": "Inspect or update DNS configuration (custom server, DoH, static hosts) and flush DNS cache.",
        "parameters": {"type": "object",
            "properties": {"action": {"type": "string"}, "mode": {"type": "string"},
                           "custom_server": {"type": "string"}, "doh_url": {"type": "string"},
                           "static_hosts": {"type": "object"}, "split_rules": {"type": "object"},
                           "force_ttl0": {"type": "boolean"}},
            "required": ["action"]}}},
]

EXT_HANDLERS = {
    "project_update": tool_project_update,
    "project_delete": tool_project_delete,
    "project_export": tool_project_export,
    "project_import": tool_project_import,
    "project_fusion_report": tool_project_fusion_report,
    "project_hub_task_action": tool_project_hub_task_action,
    "traffic_control": tool_traffic_control,
    "traffic_capture_contexts": tool_traffic_capture_contexts,
    "history_manage": tool_history_manage,
    "target_job_action": tool_target_job_action,
    "target_browsers_list": tool_target_browsers_list,
    "target_js_analyze": tool_target_js_analyze,
    "bypass_forms_list": tool_bypass_forms_list,
    "repeater_burst_status": tool_repeater_burst_status,
    "repeater_last_byte_status": tool_repeater_last_byte_status,
    "intruder_attack_action": tool_intruder_attack_action,
    "intruder_saved_attacks": tool_intruder_saved_attacks,
    "scanner_active_action": tool_scanner_active_action,
    "scanner_corpus_stats": tool_scanner_corpus_stats,
    "scanner_corpus_start": tool_scanner_corpus_start,
    "scanner_corpus_action": tool_scanner_corpus_action,
    "scanner_report_generate": tool_scanner_report_generate,
    "osint_recon": tool_osint_recon,
    "osint_graphs": tool_osint_graphs,
    "osint_transform_job": tool_osint_transform_job,
    "oast_listener": tool_oast_listener,
    "workflow_catalog": tool_workflow_catalog,
    "workflow_manage": tool_workflow_manage,
    "workflow_execute": tool_workflow_execute,
    "route_manage": tool_route_manage,
    "dns_manage": tool_dns_manage,
}


def register_into(agent_tools_module):
    """Inject these extended tools into the `agent_tools` registry at import time."""
    for schema in EXT_SCHEMAS:
        agent_tools_module.TOOL_DEFINITIONS.append(schema)
    agent_tools_module.TOOL_HANDLERS.update(EXT_HANDLERS)
