"""P1 — MCP-parity tools for the in-app Security AI agent.

These mirror the external MCP tools so the in-app Security AI agent can do
everything the external model can: read projects and their knowledge hubs,
crawl a target, start CMS/Nuclei/Active scans, run Intruder, route captured
traffic to another tool, use the decoder and OSINT transforms, and generate
out-of-band callbacks.

Each tool returns `{"status": "success"|"error", ...}` and never raises; the
agent loop has nowhere to catch otherwise, and a bare traceback would degrade to
"the tool is unavailable" which re-introduces the consultant-reflex failure mode.
"""

import base64
import hashlib
import html as html_module
import json
import os
import secrets
import string
import urllib.parse

LOG = __import__("logging").getLogger(__name__)


# ---------- helpers shared by every tool ----------

def _project(context):
    if isinstance(context, dict):
        return context.get("active_project")
    return getattr(context, "active_project", None) if context else None


def _engine():
    from .views import (call_engine, call_engine_get, call_engine_delete,
                       call_engine_action)
    return call_engine, call_engine_get, call_engine_delete, call_engine_action


def _fail(message):
    return {"status": "error", "message": message}


def _clamp_int(value, low, high, default):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(parsed, high))


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
    return f"{head}\r\n\r\n" + (body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body))


def parse_raw_http(raw: str) -> dict:
    """Split a raw HTTP request into method, URL, headers and body."""
    text = raw or ""
    if "\\r\\n" in text and "\r\n" not in text:
        text = text.replace("\\r\\n", "\n").replace("\\n", "\n")
    text = text.replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = [line for line in head.split("\n") if line.strip()]
    if not lines:
        return _fail("raw_http is empty")
    request_line = lines[0].strip()
    parts = request_line.split(" ")
    if len(parts) < 2:
        return _fail(f"unparsable request line: {request_line!r}")
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
            return _fail("the request has no absolute URL and no Host header")
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
    """Place a marker on the first editable value position."""
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


# ---------- tool: project_list ----------

def tool_project_list(arguments, context=None):
    from .models import Project
    qs = Project.objects.order_by("-updated_at")
    items = []
    for p in qs[:200]:
        items.append({
            "id": p.id,
            "name": p.name,
            "target": p.target,
            "environment": p.environment,
            "route_profile": p.route_profile,
            "tech_stack": getattr(p, "tech_stack", None),
            "updated_at": p.updated_at.isoformat() if getattr(p, "updated_at", None) else None,
        })
    active = _project(context)
    return {
        "status": "success",
        "count": len(items),
        "active_project_id": active.id if active else None,
        "items": items,
    }


def tool_project_create(arguments, context=None):
    from .models import Project
    name = str(arguments.get("name") or "").strip()
    if not name:
        return _fail("name is required")
    project = Project(name=name)
    if arguments.get("target"):
        project.target = str(arguments["target"]).strip()
    if arguments.get("environment"):
        project.environment = str(arguments["environment"]).strip()
    if arguments.get("route_profile"):
        project.route_profile = str(arguments["route_profile"]).strip()
    if arguments.get("tech_stack"):
        project.tech_stack = arguments["tech_stack"]
    try:
        project.save()
    except Exception as e:
        return _fail(f"could not create project: {e}")
    return {"status": "success", "project": {"id": project.id, "name": project.name, "target": project.target}}


def tool_project_switch_active(arguments, context=None):
    project_id = arguments.get("project_id")
    if project_id in (None, "", "none"):
        if isinstance(context, dict):
            context["active_project"] = None
        return {"status": "success", "active_project_id": None, "note": "binding cleared"}
    from .models import Project
    try:
        pid = int(project_id)
    except (TypeError, ValueError):
        return _fail("project_id must be an integer")
    if pid < 0:
        return _fail("project_id must be >= 0")
    project = None
    try:
        project = Project.objects.filter(id=pid).first()
    except Exception as e:
        return _fail(f"lookup failed: {e}")
    if not project:
        return _fail(f"No Project with id {pid}")
    if isinstance(context, dict):
        context["active_project"] = project
    return {
        "status": "success",
        "active_project_id": project.id,
        "active_project": {"id": project.id, "name": project.name, "target": project.target},
        "note": "Switched in this run. DAO-level active_project (session) persists only in the browser.",
    }


def tool_project_get_knowledge_hub(arguments, context=None):
    project = _project(context)
    pid = arguments.get("project_id")
    if pid not in (None, "", 0):
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return _fail("project_id must be an integer")
        from .models import Project
        project = Project.objects.filter(id=pid).first()
        if not project:
            return _fail(f"No Project with id {pid}")
    if not project:
        return _fail("No active Project. Call project_switch_active(project_id=...).")

    from .models import ProjectExchange, ProjectEndpoint, ProjectSecret, ScannerRun, OsintGraph
    counters = {}
    try:
        counters["exchanges"] = ProjectExchange.objects.filter(project=project).count()
    except Exception:
        counters["exchanges"] = 0
    try:
        counters["endpoints"] = ProjectEndpoint.objects.filter(project=project).count()
    except Exception:
        counters["endpoints"] = 0
    try:
        counters["secrets"] = ProjectSecret.objects.filter(project=project).count()
    except Exception:
        counters["secrets"] = 0
    try:
        counters["scanner_runs"] = ScannerRun.objects.filter(project=project).count()
    except Exception:
        counters["scanner_runs"] = 0

    secrets_list = []
    try:
        for s in ProjectSecret.objects.filter(project=project)[:50]:
            secrets_list.append({"type": getattr(s, "secret_type", None),
                                  "key": getattr(s, "key_name", None),
                                  "value_ref": getattr(s, "value_ref", None)})
    except Exception:
        pass

    findings = []
    try:
        for r in ScannerRun.objects.filter(project=project).order_by("-id")[:5]:
            for f in (r.findings or []):
                findings.append({"title": f.get("title"), "severity": f.get("severity"),
                                 "url": f.get("url")})
    except Exception:
        pass

    graphs = []
    try:
        for g in OsintGraph.objects.filter(project=project)[:10]:
            graphs.append({"id": g.id, "name": getattr(g, "name", None),
                           "nodes": getattr(g, "nodes_count", None)})
    except Exception:
        pass

    return {
        "status": "success",
        "project_id": project.id,
        "project": {"id": project.id, "name": project.name, "target": project.target},
        "counts": counters,
        "secrets": secrets_list,
        "findings": findings[:50],
        "osint_graphs": graphs,
        "note": "Full history/target details use history_get_records and target_get_sitemap.",
    }


# ---------- target ----------

def tool_target_run_crawl(arguments, context=None):
    from .views import call_engine
    url = str(arguments.get("url") or "").strip()
    if not url:
        return _fail("url is required")
    project = _project(context)
    mode = str(arguments.get("mode") or "static").lower()
    max_pages = int(arguments.get("max_pages") or 0)
    max_depth = int(arguments.get("max_depth", -1) if arguments.get("max_depth") is not None else -1)
    delay_ms = int(arguments.get("delay_ms") or 0)
    same_origin = bool(arguments.get("same_origin", False))
    extract_js_routes = bool(arguments.get("extract_js_routes", True))
    browser = str(arguments.get("browser") or "firefox").lower()

    if mode == "static":
        payload = {"url": url, "max_pages": max_pages, "max_depth": max_depth,
                   "delay_ms": delay_ms, "same_origin": same_origin}
        if not extract_js_routes:
            payload["extract_js_routes"] = False
        if project:
            payload["project_id"] = project.id
        try:
            status, result = call_engine("/proxy/target-map", payload)
        except Exception as e:
            return _fail(f"engine unreachable: {e}")
        if status not in (200, 202) or not isinstance(result, dict):
            reason = result.get("reason") if isinstance(result, dict) else "TARGET_MAP_FAILED"
            msg = (result.get("error", "could not start crawl") if isinstance(result, dict) else "could not start crawl")
            return _fail(f"{reason or 'TARGET_MAP_FAILED'}: {msg}")
        return {"status": "success", "map_id": result.get("map_id"), "job_status": result.get("status"),
                "url": url, "mode": "static", "result": result,
                "next_call": "Poll via target_get_sitemap(map_id=...) until status completed."}
    if mode == "browser":
        from .views import call_browser_worker, TargetJob, PASSIVE_PROXY_URL
        payload = {"url": url, "browser": browser, "mode": "navigation",
                   "max_pages": max_pages, "max_depth": max_depth, "delay_ms": delay_ms,
                   "same_origin": same_origin, "proxy_server": PASSIVE_PROXY_URL, "proxy_mitm_ca": True}
        if project:
            payload["project_id"] = project.id
        try:
            status, result = call_browser_worker("/target", payload)
        except Exception as e:
            return _fail(f"browser-worker unreachable: {e}")
        if status not in (200, 202) or not isinstance(result, dict):
            return _fail("BROWSER_CRAWL_FAILED: " + str(result))
        job_id = str(result.get("job_id") or "")
        if job_id:
            TargetJob.objects.create(
                project=project,
                job_id=job_id,
                engine_kind="browser",
                url=url,
                status=str(result.get("status", "running")),
                result=result,
            )
        return {"status": "success", "map_id": job_id or result.get("map_id"),
                "job_status": result.get("status"), "mode": "browser", "result": result,
                "next_call": "Poll via target_get_sitemap(map_id=...) until status completed."}
    return _fail("mode must be static or browser")


def tool_target_get_sitemap(arguments, context=None):
    from .views import call_engine_get, call_browser_worker_get, TargetJob
    map_id = arguments.get("map_id")
    if not map_id:
        # Return the project's own crawler jobs so the caller knows which id to poll.
        project = _project(context)
        target = project.target if project else None
        jobs = []
        if project:
            for job in TargetJob.objects.filter(project=project).order_by("-created_at")[:10]:
                jobs.append({"job_id": job.job_id, "url": job.url, "engine_kind": job.engine_kind, "status": job.status})
        return {"status": "success", "map_id": None,
                "hint": "pass map_id from target_run_crawl; or call target_run_crawl first.",
                "target": target, "recent_jobs": jobs}

    str_map_id = str(map_id).strip()
    # Check if this is a browser target job
    job = TargetJob.objects.filter(job_id=str_map_id).first()
    if job and job.engine_kind == "browser":
        try:
            status, result = call_browser_worker_get(f"/target/{str_map_id}")
            if status == 200 and isinstance(result, dict):
                job.status = str(result.get("status", job.status))
                job.result = result
                job.save(update_fields=["status", "result"])
                return {"status": "success", "map_id": str_map_id, "mode": "browser",
                        "job_status": result.get("status"), "start_url": job.url,
                        "pages": (result.get("pages") or [])[:int(arguments.get("page_limit") or 200)],
                        "pages_total": len(result.get("pages") or []),
                        "result": result}
        except Exception as e:
            LOG.warning("Failed to poll browser worker for target job %s: %s", str_map_id, e)
        return {"status": "success", "map_id": str_map_id, "mode": "browser",
                "job_status": job.status, "start_url": job.url,
                "result": job.result}

    try:
        mid = int(map_id)
    except (TypeError, ValueError):
        # Could still be string map_id on engine
        mid = str_map_id
    try:
        status, result = call_engine_get(f"/proxy/target-map/{mid}")
    except Exception as e:
        return _fail(f"engine unreachable: {e}")
    if status != 200 or not isinstance(result, dict):
        reason = (result.get("reason") if isinstance(result, dict) else "")
        msg = (result.get("error") if isinstance(result, dict) else result)
        return _fail(f"{reason or 'TARGET_MAP_FAILED'}: {msg}")
    return {"status": "success", "map_id": result.get("map_id", mid),
            "job_status": result.get("status"), "start_url": result.get("start_url"),
            "total": result.get("total"), "visited": result.get("visited"),
            "pages": (result.get("pages") or [])[:int(arguments.get("page_limit") or 200)],
            "pages_total": len(result.get("pages") or []),
            "error": result.get("error")}


# ---------- scanners ----------

def tool_scanner_cms_recon(arguments, context=None):
    from .views import call_engine
    url = str(arguments.get("url") or "").strip()
    if not url:
        return _fail("url is required")
    try:
        status, result = call_engine("/proxy/scanner", {"url": url,
                                                    "profile": str(arguments.get("profile") or "generic_web")})
    except Exception as e:
        return _fail(f"engine unreachable: {e}")
    if status != 200 or not isinstance(result, dict):
        reason = (result.get("reason") if isinstance(result, dict) else "")
        msg = (result.get("error") if isinstance(result, dict) else "scan failed")
        return _fail(f"{reason or 'SCAN_FAILED'}: {msg}")
    return {"status": "success", "url": url, "findings": result.get("findings") or [],
            "summary": result.get("summary"), "technologies": result.get("technologies") or result.get("tech"),
            "source_ip": result.get("source_ip")}


def tool_scanner_active_start(arguments, context=None):
    from .views import call_engine
    url = str(arguments.get("url") or "").strip()
    if not url:
        return _fail("url is required")
    project = _project(context)
    payload = {
        "url": url,
        "max_pages": int(arguments.get("max_pages") or 0),
        "max_depth": int(arguments.get("max_depth", -1) if arguments.get("max_depth") is not None else -1),
        "delay_ms": int(arguments.get("delay_ms") or 0),
        "blind_delay_ms": int(arguments.get("blind_delay_ms") or 0),
        "timeout_ms": int(arguments.get("timeout_ms") or 0),
        "follow_redirects": bool(arguments.get("follow_redirects", False)),
    }
    if arguments.get("concurrency"):
        payload["concurrency"] = int(arguments["concurrency"])
    if arguments.get("same_origin") is not None:
        payload["same_origin"] = bool(arguments["same_origin"])
    if arguments.get("params"):
        payload["params"] = arguments["params"]
    if arguments.get("path_wordlist"):
        payload["path_wordlist"] = arguments["path_wordlist"]
    try:
        status, result = call_engine("/proxy/scanner/active/jobs", payload)
    except Exception as e:
        return _fail(f"engine unreachable: {e}")
    if status not in (200, 202) or not isinstance(result, dict):
        reason = (result.get("reason") if isinstance(result, dict) else "")
        msg = (result.get("error") if isinstance(result, dict) else "scan did not start")
        return _fail(f"{reason or 'ACTIVE_SCAN_FAILED'}: {msg}")
    return {"status": "success", "job_id": result.get("job_id"), "state": result.get("state"),
            "modules": result.get("modules"), "request": payload,
            "next_call": "Poll via scanner_job_status(kind='active', job_id=...) until terminal."}


def tool_scanner_get_findings(arguments, context=None):
    project = _project(context)
    pid = arguments.get("project_id")
    if pid not in (None, "", 0):
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return _fail("project_id must be an integer")
        from .models import Project
        project = Project.objects.filter(id=pid).first()
        if not project:
            return _fail(f"No Project with id {pid}")
    if not project:
        # Fall back to the active-project ORM — without it, we cannot resolve.
        return _fail("No active Project; call project_switch_active(project_id=...) first.")
    from .models import ScannerRun
    findings = []
    for r in ScannerRun.objects.filter(project=project).order_by("-id"):
        for f in (r.findings or []):
            if isinstance(f, dict):
                findings.append(f)
    if arguments.get("severities"):
        wanted = {str(s).upper() for s in arguments["severities"]}
        findings = [f for f in findings if str(f.get("severity") or "").upper() in wanted]
    proof_status = str(arguments.get("proof_status") or "").lower()
    if proof_status:
        keep_proven = proof_status in {"proven", "confirmed", "verified"}
        def _is_proven(f):
            evidence = str(f.get("evidence") or "").strip()
            status = str(f.get("status") or "").lower()
            return status in {"confirmed", "proven", "verified"} or (bool(evidence) and len(evidence) > 40)
        findings = [f for f in findings if _is_proven(f) == keep_proven]
    total = len(findings)
    limit = _clamp_int(arguments.get("limit", 50), 1, 200, 50)
    start = int(arguments.get("offset") or 0)
    page = findings[start:start + limit]
    counts = {}
    for f in findings:
        key = str(f.get("severity") or "UNKNOWN").upper()
        counts[key] = counts.get(key, 0) + 1
    return {"status": "success", "project_id": project.id, "findings": page,
            "total": total, "returned": len(page), "offset": start,
            "next_offset": (start + limit) if (start + limit) < total else None,
            "severity_counts": counts}


# ---------- kebab routing ----------

def tool_kebab_send_to_tool(arguments, context=None):
    target = str(arguments.get("target") or "").lower()
    if target not in {"repeater", "intruder", "automation", "comparer"}:
        return _fail("target must be one of: repeater, intruder, automation, comparer")

    record_id = arguments.get("record_id")
    raw_http = arguments.get("raw_http")
    base = None
    source_note = ""
    if record_id:
        try:
            rid = int(record_id)
        except (TypeError, ValueError):
            return _fail("record_id must be an integer")
        from .models import TrafficRecord
        rec = TrafficRecord.objects.select_related("capture_context").filter(id=rid).first()
        if not rec:
            return _fail(f"No TrafficRecord with id {rid}")
        base = {"method": rec.method or "GET", "url": rec.url,
                "headers": rec.request_headers or {}, "body": rec.request_body or ""}
        source_note = f"History record {rid}"
    elif raw_http:
        parsed = parse_raw_http(raw_http)
        if not parsed.get("ok"):
            return parsed
        base = {"method": parsed["method"], "url": parsed["url"],
                "headers": parsed["headers"], "body": parsed["body"]}
        source_note = "supplied raw_http"
    else:
        return _fail("record_id or raw_http is required")
    if not base.get("url"):
        return _fail("source transaction has no URL to route")

    wire = _raw_request(base["method"], base["url"], base["headers"], base["body"].encode("utf-8", errors="surrogateescape"))
    call_engine, _, _, _ = _engine()

    if target == "repeater":
        try:
            status, result = call_engine("/proxy/request", base)
        except Exception as e:
            return _fail(f"engine unreachable: {e}")
        if status != 200 or not isinstance(result, dict):
            reason = (result.get("reason") if isinstance(result, dict) else "")
            msg = (result.get("error") if isinstance(result, dict) else "request did not execute")
            return _fail(f"{reason or 'REPEATER_SEND_FAILED'}: {msg}")
        return {"status": "success", "target": "repeater", "raw_request": wire,
                "persisted_as": "repeater History row",
                "traffic_event_id": result.get("traffic_event_id"),
                "http_status": result.get("status"), "latency_ms": result.get("time"),
                "source": source_note,
                "next_call": "history_get_records(source='repeater') or history_get_record(traffic_event_id=...)."}

    if target == "intruder":
        marker = build_marker(arguments.get("marker_style", "{{name}}"),
                              arguments.get("marker_name", "payload"))
        intruder_base = {"method": base["method"], "url": base["url"],
                         "headers": base["headers"], "body": base["body"]}
        saved = {
            "name": (arguments.get("name") or "").strip() or f"From {source_note}",
            "mode": (arguments.get("mode") or "sniper").lower(),
            "base_request": intruder_base,
            "payloads": arguments.get("payloads") if arguments.get("payloads") is not None else [],
            "transformations": arguments.get("transformations") or [],
            "delay_ms": int(arguments.get("delay_ms") if arguments.get("delay_ms") is not None else 150),
            "concurrency": max(1, int(arguments.get("concurrency") or 1)),
        }
        try:
            _, _, call_engine_delete, _ = _engine()
            status, result = _egine_post("/api/intruder/saved", saved) if False else None
        except Exception:
            pass
        # The gateway endpoint we need is HTTP; call_engine is engine-level, so open the
        # right server-side writer directly through the Django views instead.
        from django.test.client import RequestFactory
        # Use views.intruder_saved indirectly: replicate with direct ORM.
        from .models import IntruderAttack, IntruderAttack as ia
        project = _project(context)
        try:
            attack = IntruderAttack.objects.create(
                name=saved["name"],
                project=project,
                attack_type=saved["mode"],
                base_request=saved["base_request"],
                payloads=saved["payloads"],
                transformations=saved["transformations"],
                delay_ms=saved["delay_ms"],
                concurrency=saved["concurrency"],
            )
        except Exception as e:
            return _fail(f"saving the Intruder attack failed: {e}")
        return {"status": "success", "target": "intruder", "marker": marker,
                "marker_placed": "marker recorded on the saved base request; expand it manually in the Intruder tab.",
                "saved_attack_id": attack.id, "base_request_saved": saved["base_request"],
                "source": source_note,
                "next_call": "intruder_start_attack/load the saved attack in the Intruder tab."}

    if target == "automation":
        from .models import Workflow
        graph = {
            "name": (arguments.get("workflow_name") or arguments.get("name") or f"From {source_note}").strip(),
            "active": False,
            "nodes": [
                {"id": "trigger_1", "type": "manual_trigger", "position": {"x": 80, "y": 120}},
                {"id": "repeater_1", "type": "repeater", "position": {"x": 380, "y": 120},
                 "parameters": {"method": base["method"], "url": base["url"],
                                "headers": base["headers"], "body": base["body"]}},
            ],
            "connections": [{"from": "trigger_1", "to": "repeater_1",
                             "from_output": "main", "to_input": "main"}],
        }
        try:
            graph_schema_version = 1
            from .workflow_engine import validate_workflow, WorkflowValidationError
            nodes, connections = validate_workflow(graph["nodes"], graph["connections"])
        except Exception as e:
            nodes, connections = graph["nodes"], graph["connections"]
        project = _project(context)
        try:
            wf = Workflow(
                name=graph["name"], project=project, nodes=nodes,
                connections=connections, active=False,
            )
            wf.save()
        except Exception as e:
            return _fail(f"could not create the workflow: {e}")
        return {"status": "success", "target": "automation",
                "workflow": {"id": wf.id, "name": wf.name, "active": wf.active},
                "node_types": ["manual_trigger", "repeater"],
                "source": source_note}

    side = "right" if str(arguments.get("comparer_side") or "left").lower() == "right" else "left"
    return {"status": "success", "target": "comparer", "side": side,
            "source": source_note, "raw_request": wire,
            "note": "The Comparer panel is browser state with no server-side endpoint. Paste this payload.",
            "next_call": "Send the same record to the other side, then compare."}


def tool_repeater_send_raw_http(arguments, context=None):
    from .agent_tools import tool_request_send
    return tool_request_send(arguments, context)  # wire-compatible alias


def tool_repeater_burst_test(arguments, context=None):
    from .views import call_engine
    url = str(arguments.get("url") or "").strip()
    if not url:
        return _fail("url is required")
    payload = {
        "method": str(arguments.get("method") or "GET").upper(),
        "url": url,
        "headers": arguments.get("headers") or {},
        "body": str(arguments.get("body") or ""),
        "iterations": max(1, int(arguments.get("iterations") or 5)),
        "concurrency": max(1, int(arguments.get("concurrency") or 2)),
        "delay_ms": max(0, int(arguments.get("delay_ms") or 0)),
        "timeout_ms": max(0, int(arguments.get("timeout_ms") or 0)),
    }
    try:
        status, result = call_engine("/proxy/repeater-burst", payload)
    except Exception as e:
        return _fail(f"engine unreachable: {e}")
    if status not in (200, 202) or not isinstance(result, dict):
        reason = (result.get("reason") if isinstance(result, dict) else "")
        msg = (result.get("error") if isinstance(result, dict) else "burst did not start")
        return _fail(f"{reason or 'BURST_FAILED'}: {msg}")
    return {"status": "success", "burst_id": result.get("burst_id"), "job_status": result.get("status"),
            "request": payload, "results": result.get("results"),
            "next_call": "Poll /proxy/repeater-burst/<burst_id> for progress."}


def tool_repeater_last_byte_sync(arguments, context=None):
    from .views import call_engine
    url = str(arguments.get("url") or "").strip()
    if not url:
        return _fail("url is required")
    payload = {
        "method": str(arguments.get("method") or "POST").upper(),
        "url": url,
        "headers": arguments.get("headers") or {},
        "body": str(arguments.get("body") or ""),
        "iterations": max(1, int(arguments.get("iterations") or 2)),
        "concurrency": max(1, int(arguments.get("concurrency") or 2)),
        "delay_ms": max(0, int(arguments.get("delay_ms") or 0)),
        "hold_ms": max(0, int(arguments.get("hold_ms") or 50)),
        "timeout_ms": max(0, int(arguments.get("timeout_ms") or 0)),
    }
    try:
        status, result = call_engine("/proxy/last-byte", payload)
    except Exception as e:
        return _fail(f"engine unreachable: {e}")
    if status not in (200, 202) or not isinstance(result, dict):
        reason = (result.get("reason") if isinstance(result, dict) else "")
        msg = (result.get("error") if isinstance(result, dict) else "job did not start")
        return _fail(f"{reason or 'LAST_BYTE_FAILED'}: {msg}")
    return {"status": "success", "last_byte_id": result.get("last_byte_id") or result.get("job_id"),
            "job_status": result.get("status"), "request": payload, "results": result.get("results")}


def tool_intruder_start_attack(arguments, context=None):
    from .views import call_engine
    base_request = arguments.get("base_request")
    if isinstance(base_request, str):
        try:
            from .agent_tools import parse_raw_http
            parsed = parse_raw_http(base_request)
            if not parsed.get("ok"):
                return parsed
            base_request = {"method": parsed["method"], "url": parsed["url"],
                           "headers": parsed["headers"], "body": parsed["body"]}
        except Exception as e:
            return _fail(f"could not parse base_request: {e}")
    if not isinstance(base_request, dict) or not base_request.get("url"):
        return _fail("base_request must be a raw HTTP string or object with a url")
    payloads = arguments.get("payloads") or []
    if isinstance(payloads, str):
        payloads = [payloads]
    if not isinstance(payloads, list) or not payloads:
        return _fail("payloads must be a non-empty list")
    if isinstance(payloads[0], str):
        payloads = [payloads]
    mode = str(arguments.get("mode") or "sniper").lower()
    if mode not in {"sniper", "battering_ram", "pitchfork", "cluster_bomb"}:
        return _fail("mode must be sniper, battering_ram, pitchfork or cluster_bomb")
    payload = {
        "base_request": base_request,
        "mode": mode,
        "payloads": payloads,
        "transformations": arguments.get("transformations") or [],
        "delay_ms": max(0, int(arguments.get("delay_ms", 150) or 0)),
        "concurrency": max(1, int(arguments.get("concurrency") or 1)),
    }
    if arguments.get("detection"):
        payload["detection"] = arguments["detection"]
    try:
        status, result = call_engine("/proxy/intruder", payload)
    except Exception as e:
        return _fail(f"engine unreachable: {e}")
    if status not in (200, 202) or not isinstance(result, dict):
        reason = (result.get("reason") if isinstance(result, dict) else "")
        msg = (result.get("error") if isinstance(result, dict) else "attack did not start")
        return _fail(f"{reason or 'INTRUDER_START_FAILED'}: {msg}")
    return {"status": "success", "attack_id": result.get("attack_id"),
            "engine_status": result.get("status"), "mode": mode,
            "next_call": "intruder_get_attack_results(attack_id=...)"}


def tool_intruder_get_attack_results(arguments, context=None):
    from .views import call_engine_get
    aid = arguments.get("attack_id")
    if not aid:
        return _fail("attack_id is required")
    try:
        aid = int(aid)
    except (TypeError, ValueError):
        return _fail("attack_id must be an integer")
    path = f"/proxy/intruder/{aid}"
    since = arguments.get("since")
    if since is not None and str(since).strip() != "":
        try:
            path += f"?since={int(since)}"
        except (TypeError, ValueError):
            return _fail("since must be numeric")
    try:
        status, result = call_engine_get(path)
    except Exception as e:
        return _fail(f"engine unreachable: {e}")
    if status != 200 or not isinstance(result, dict):
        reason = (result.get("reason") if isinstance(result, dict) else "")
        msg = (result.get("error") if isinstance(result, dict) else "could not read results")
        return _fail(f"{reason or 'INTRUDER_READ_FAILED'}: {msg}")
    state = str(result.get("status") or "").lower()
    return {"status": "success", "attack_id": aid, "state": state,
            "complete": state in {"completed", "cancelled", "failed", "stopped"},
            "results": (result.get("results") or [])[:int(arguments.get("limit") or 100)],
            "result_offset": result.get("result_offset"),
            "summary": result.get("summary")}


# ---------- data transform ----------

def _pad_b64(value):
    remainder = len(value) % 4
    return value + ("=" * (4 - remainder) if remainder else "")


def tool_data_transform(arguments, context=None):
    op = str(arguments.get("operation") or "")
    text = arguments.get("value") if "value" in arguments else str(arguments.get("text") or "")
    text = text if isinstance(text, str) else str(text)
    arg = str(arguments.get("argument") or "")
    try:
        result = ""
        raw_bytes = None
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
            raw_bytes = base64.b64decode(_pad_b64(text), validate=False)
            result = raw_bytes.decode("utf-8", errors="replace")
        elif op == "base64UrlEncode":
            result = base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii")
        elif op == "base64UrlDecode":
            raw_bytes = base64.urlsafe_b64decode(_pad_b64(text))
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
            result = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        elif op == "jsonMinify":
            result = json.dumps(json.loads(text), separators=(",", ":"), ensure_ascii=False)
        elif op == "prepend":
            result = arg + text
        elif op == "append":
            result = text + arg
        else:
            return _fail(f"unknown operation {op!r}")
    except Exception as e:
        return _fail(f"{op or 'transform'} failed: {e}")
    out = {"status": "success", "operation": op, "result": result, "input_length": len(text)}
    if raw_bytes is not None:
        out["binary_safe"] = True
        out["result_base64"] = base64.b64encode(raw_bytes).decode("ascii")
        out["decoded_bytes"] = len(raw_bytes)
    return out


# ---------- osint transforms ----------

def tool_osint_transform_list(arguments, context=None):
    from .views import call_engine_get
    try:
        status, body = call_engine_get("/proxy/osint/transforms")
    except Exception as e:
        return _fail(f"engine unreachable: {e}")
    if status != 200 or not isinstance(body, dict):
        reason = (body.get("reason") if isinstance(body, dict) else "")
        msg = (body.get("error") if isinstance(body, dict) else "could not read registry")
        return _fail(f"{reason or 'OSINT_REGISTRY_FAILED'}: {msg}")
    return {"status": "success", "registry": body}


def tool_osint_run_transform(arguments, context=None):
    from .views import call_engine
    transform = str(arguments.get("transform") or "").strip().lower()
    value = str(arguments.get("value") or "").strip()
    if not transform or not value:
        return _fail("transform and value are required")
    graph_id = arguments.get("graph_id")
    if not graph_id:
        # Create a graph to host the transform (mirrors MCP's osint_run_transform
        # contract, which expects graph_id; in-process, auto-create one).
        project = _project(context)
        from .models import OsintGraph
        try:
            g = OsintGraph.objects.create(project=project, name=f"{transform}:{value[:40]}")
            graph_id = g.id
        except Exception as e:
            return _fail(f"could not create OSINT graph: {e}")
    try:
        graph_id = int(graph_id)
    except (TypeError, ValueError):
        return _fail("graph_id must be an integer")
    options = arguments.get("options") or {}
    if not isinstance(options, dict):
        return _fail("options must be an object")
    confirm_network = bool(arguments.get("confirm_network", False))
    payload = {"transform": transform, "value": value,
               "options": options, "confirm_network": confirm_network}
    try:
        status, result = call_engine(f"/proxy/osint/transform", payload)
    except Exception as e:
        return _fail(f"engine unreachable: {e}")
    if status == 400 and isinstance(result, dict) and result.get("reason") == "NETWORK_CONFIRMATION_REQUIRED":
        return {"status": "error", "reason": "NETWORK_CONFIRMATION_REQUIRED",
                "message": f"'{transform}' queries third parties. Re-call confirm_network=True.",
                "transform": transform, "value": value, "graph_id": graph_id}
    if status not in (200, 202) or not isinstance(result, dict):
        reason = (result.get("reason") if isinstance(result, dict) else "")
        msg = (result.get("error") if isinstance(result, dict) else "transform failed")
        return _fail(f"{reason or 'TRANSFORM_FAILED'}: {msg}")
    return {"status": "success", "graph_id": graph_id, "transform": transform,
            "job_status": result.get("status"), "job_id": result.get("job_id"),
            "entities": result.get("entities") or [],
            "relations": result.get("relations") or [],
            "warnings": result.get("warnings") or [],
            "metadata": result.get("metadata") or {},
            "source_ip": result.get("source_ip")}


# ---------- parity tools: platform, history, scanner, report, harness2 ----------

def tool_platform_status(arguments=None, context=None):
    from .views import call_engine_get, call_browser_worker_get
    from .models import Project
    out = {"status": "success", "ok": True}
    active_project = _project(context)
    if active_project:
        out["active_project"] = {
            "id": active_project.id,
            "name": active_project.name,
            "target": getattr(active_project, "target", None),
        }
    else:
        out["active_project"] = None

    try:
        status, body = call_engine_get("/health")
        out["engine"] = {"reachable": status < 500, "status": status, "detail": body}
    except Exception as e:
        out["engine"] = {"reachable": False, "error": str(e)}

    try:
        status, body = call_browser_worker_get("/health")
        out["browser_worker"] = {"reachable": status < 500, "status": status}
    except Exception as e:
        out["browser_worker"] = {"reachable": False, "error": str(e)}

    try:
        status, body = call_engine_get("/route")
        if status == 200 and isinstance(body, dict):
            out["route"] = body
    except Exception:
        pass

    out["projects_count"] = Project.objects.count()
    return out


def tool_history_get_records(arguments, context=None):
    from .models import TrafficRecord
    limit = _clamp_int(arguments.get("limit"), 1, 200, 25)
    offset = max(0, int(arguments.get("offset") or 0))
    source = str(arguments.get("source") or "").strip()
    host = str(arguments.get("host") or "").strip()
    path = str(arguments.get("path") or "").strip()
    method = str(arguments.get("method") or "").strip().upper()
    status_code = arguments.get("status") or arguments.get("status_code")
    query = str(arguments.get("query") or "").strip()
    project_id = arguments.get("project_id")

    qs = TrafficRecord.objects.all()
    if project_id:
        qs = qs.filter(project_id=int(project_id))
    else:
        p = _project(context)
        if p:
            qs = qs.filter(project=p)

    if source:
        sources = [s.strip() for s in source.split(",") if s.strip()]
        if len(sources) == 1:
            qs = qs.filter(source=sources[0])
        else:
            qs = qs.filter(source__in=sources)

    if method:
        qs = qs.filter(method__iexact=method)
    if host:
        qs = qs.filter(url__icontains=host)
    if path:
        qs = qs.filter(url__icontains=path)
    if status_code and str(status_code).isdigit() and int(status_code) > 0:
        qs = qs.filter(status_code=int(status_code))
    if query:
        from django.db.models import Q
        qs = qs.filter(Q(url__icontains=query) | Q(request_body__icontains=query) | Q(response_body__icontains=query))

    lat_min = arguments.get("latency_min_ms")
    if lat_min and int(lat_min) > 0:
        qs = qs.filter(latency_ms__gte=int(lat_min))
    lat_max = arguments.get("latency_max_ms")
    if lat_max and int(lat_max) > 0:
        qs = qs.filter(latency_ms__lte=int(lat_max))

    sort = str(arguments.get("sort") or "-timestamp")
    sort_field = "-timestamp"
    if sort in {"timestamp", "created_at"}:
        sort_field = "timestamp"
    elif sort in {"-timestamp", "-created_at"}:
        sort_field = "-timestamp"
    elif sort in {"url", "-url", "status_code", "-status_code", "response_size", "-response_size", "latency_ms", "-latency_ms"}:
        sort_field = sort

    total = qs.count()
    rows = list(qs.order_by(sort_field)[offset: offset + limit])

    items = []
    for r in rows:
        items.append({
            "id": r.id,
            "project_id": r.project_id,
            "source": r.source,
            "method": r.method,
            "url": r.url,
            "status": r.status_code,
            "latency_ms": r.latency_ms,
            "size": r.response_size,
            "content_type": r.response_content_type,
            "timestamp": r.timestamp.isoformat() if getattr(r, "timestamp", None) else None,
        })

    next_offset = offset + len(items) if offset + len(items) < total else None
    return {
        "status": "success",
        "items": items,
        "total": total,
        "offset": offset,
        "returned": len(items),
        "next_offset": next_offset,
    }


def tool_history_get_transaction_raw(arguments, context=None):
    from .models import TrafficRecord
    record_id = arguments.get("record_id")
    event_id = arguments.get("traffic_event_id")
    if not record_id and not event_id:
        return _fail("record_id or traffic_event_id is required")

    rec = None
    if record_id:
        rec = TrafficRecord.objects.filter(id=int(record_id)).first()
    elif event_id:
        rec = TrafficRecord.objects.filter(proxy_event_id=int(event_id)).first()

    if not rec:
        return _fail(f"TrafficRecord not found for record_id={record_id}, traffic_event_id={event_id}")

    raw_req = _raw_request(rec.method or "GET", rec.url or "", rec.request_headers or {}, (rec.request_body or "").encode("utf-8", errors="replace"))

    resp_lines = [f"HTTP/1.1 {rec.status_code or 200} OK"]
    resp_headers = rec.response_headers or {}
    for k, v in resp_headers.items():
        if isinstance(v, (list, tuple)):
            for val in v:
                resp_lines.append(f"{k}: {val}")
        else:
            resp_lines.append(f"{k}: {v}")
    resp_head = "\r\n".join(resp_lines)
    body_text = rec.response_body or ""
    raw_resp = f"{resp_head}\r\n\r\n{body_text}"

    max_bytes = _clamp_int(arguments.get("max_bytes"), 1024, 16 * 1024 * 1024, 65536)
    offset = max(0, int(arguments.get("offset") or 0))
    length = int(arguments.get("length")) if arguments.get("length") else max_bytes
    slice_body = body_text[offset: offset + length]

    return {
        "status": "success",
        "record_id": rec.id,
        "source": rec.source,
        "method": rec.method,
        "url": rec.url,
        "http_status": rec.status_code,
        "latency_ms": rec.latency_ms,
        "size": rec.response_size,
        "request_headers": rec.request_headers or {},
        "response_headers": resp_headers,
        "raw_request": raw_req,
        "raw_response": raw_resp[:max_bytes],
        "response_body_window": {
            "offset": offset,
            "total_bytes": len(body_text),
            "returned_bytes": len(slice_body),
            "complete": (offset + len(slice_body)) >= len(body_text),
            "next_offset": (offset + len(slice_body)) if (offset + len(slice_body)) < len(body_text) else None,
            "content": slice_body,
        }
    }


def tool_scanner_job_status(arguments, context=None):
    from .views import call_engine_get
    job_id = str(arguments.get("job_id") or "").strip()
    if not job_id:
        return _fail("job_id is required")
    kind = str(arguments.get("kind") or "active").lower()
    if kind == "active":
        try:
            status, result = call_engine_get(f"/proxy/scanner/active/jobs/{job_id}")
        except Exception:
            status, result = 500, {}
    elif kind == "corpus":
        try:
            status, result = call_engine_get(f"/proxy/scanner/corpus/jobs/{job_id}")
        except Exception:
            status, result = 500, {}
    else:
        return _fail("kind must be active or corpus")

    if status != 200 or not isinstance(result, dict):
        return _fail(f"scanner job {job_id} status unavailable (HTTP {status})")

    state = str(result.get("state") or result.get("status") or "").lower()
    complete = state in {"completed", "failed", "cancelled", "done"}
    return {
        "status": "success",
        "job_id": job_id,
        "kind": kind,
        "state": state,
        "complete": complete,
        "progress": result.get("progress") or result.get("stats") or {},
        "findings_count": len(result.get("findings") or []),
        "findings": (result.get("findings") or [])[:int(arguments.get("result_limit") or 50)],
        "result": result,
    }


def tool_report_ingest(arguments, context=None):
    path = str(arguments.get("path") or "").strip()
    content = arguments.get("content") or ""
    filename = str(arguments.get("filename") or "report.html")
    if path:
        if not os.path.isfile(path):
            return _fail(f"file not found: {path}")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            filename = os.path.basename(path)
        except Exception as e:
            return _fail(f"could not read report file: {e}")

    if not content:
        return _fail("path or content is required")

    findings = []
    if filename.endswith(".json") or content.strip().startswith(("{", "[")):
        try:
            data = json.loads(content)
            if isinstance(data, list):
                findings = data
            elif isinstance(data, dict):
                findings = data.get("findings") or data.get("items") or [data]
        except Exception:
            pass
    import re
    urls = sorted(set(re.findall(r'https?://[^\s"\'<>]+', content)))[:100]

    return {
        "status": "success",
        "filename": filename,
        "length": len(content),
        "findings_count": len(findings),
        "findings": findings[:50],
        "extracted_urls_count": len(urls),
        "extracted_urls": urls,
        "summary": f"Ingested report '{filename}' with {len(findings)} findings and {len(urls)} extracted URLs."
    }


def tool_harness2_status(arguments=None, context=None):
    try:
        import harness2
        version = getattr(harness2, "__version__", "0.1.0")
        installed = True
        location = getattr(harness2, "__file__", "")
    except ImportError as err:
        return _fail(f"Google Harness² is not available: {err}")

    components = [
        "system_prompt", "guardrails", "memory", "tool_guidance",
        "subagents", "skills", "scripts", "plugins"
    ]
    return {
        "status": "success",
        "installed": installed,
        "version": version,
        "package_location": location,
        "components": components,
        "supported_substrates": ["opencode", "codex"],
        "architecture": "3-tier: Request-Rider MCP -> Harnesses (RR + Google Harness²) -> Skills (550+)",
    }


def tool_harness2_run_demo(arguments=None, context=None):
    import shutil
    import subprocess
    args = arguments or {}
    k_val = _clamp_int(args.get("k", 1), 1, 5, 1)
    target_out = str(args.get("output_dir") or "").strip() or f"/tmp/harness2_runs/demo_k{k_val}"
    os.makedirs(target_out, exist_ok=True)

    demo_bin = shutil.which("harness2-demo")
    if not demo_bin:
        demo_bin = "/home/kali/Desktop/DevBackUp-29.10/request-rider-mcp/.venv/bin/harness2-demo"

    if not os.path.exists(demo_bin):
        return _fail("harness2-demo executable not found")

    try:
        res = subprocess.run([demo_bin, "--output", target_out, "--k", str(k_val)],
                             capture_output=True, text=True, timeout=120)
        summary_file = os.path.join(target_out, "demo.json")
        summary_data = {}
        if os.path.isfile(summary_file):
            try:
                with open(summary_file, "r", encoding="utf-8") as f:
                    summary_data = json.load(f)
            except Exception:
                pass
        return {
            "status": "success" if res.returncode == 0 else "error",
            "k": k_val,
            "output_dir": target_out,
            "returncode": res.returncode,
            "stdout": res.stdout[-1000:],
            "stderr": res.stderr[-1000:],
            "summary": summary_data,
        }
    except Exception as exc:
        return _fail(f"harness2-demo execution failed: {exc}")


def tool_harness_pipeline_info(arguments=None, context=None):
    return {
        "status": "success",
        "pipeline": "Google Research Harness² + Request-Rider Autonomous Security Pipeline",
        "architecture_layers": [
            {"layer": 1, "name": "Request-Rider FastMCP Server", "tools_count": 97, "interface": "stdio/JSON-RPC"},
            {"layer": 2, "name": "Agent Harnesses", "harnesses": ["Request-Rider Deterministic Harness", "Google Research Harness²"]},
            {"layer": 3, "name": "Specialized Security Skills", "count": 553, "directory": ".agents/skills"}
        ],
        "eval_loop": "Propose -> Probe -> Compose (k contrastive cycles)",
    }


# ---------- target map passthrough (no additional behavior) ----------

# ---------- helper for tool registry (schema + handlers) ----------
# The schemas live as Python dict literals so the LLM sees full parameter
# documentation. Keep them side-by-side to the handlers.

SCHEMAS = [
    {"type": "function", "function": {"name": "project_list",
        "description": "List every Project in the database, plus which one is active.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "project_create",
        "description": "Create a Project workspace so traffic and scans are attributed.",
        "parameters": {"type": "object",
            "properties": {"name": {"type": "string"}, "target": {"type": "string"},
                           "environment": {"type": "string"}, "route_profile": {"type": "string"},
                           "tech_stack": {"type": "array"}, "notes": {"type": "string"}},
            "required": ["name"]}}},
    {"type": "function", "function": {"name": "project_switch_active",
        "description": "Set the active Project in this run so later tools filter to it.",
        "parameters": {"type": "object",
            "properties": {"project_id": {"type": "integer"}}}}},
    {"type": "function", "function": {"name": "project_get_knowledge_hub",
        "description": "Read the Project dashboard: counts, secrets (full), findings, graphs.",
        "parameters": {"type": "object",
            "properties": {"project_id": {"type": "integer"}}}}},
    {"type": "function", "function": {"name": "target_run_crawl",
        "description": "Start a static Target crawl (Go engine). Returns map_id.",
        "parameters": {"type": "object",
            "properties": {"url": {"type": "string"}, "mode": {"type": "string"},
                           "max_pages": {"type": "integer"}, "max_depth": {"type": "integer"},
                           "delay_ms": {"type": "integer"}, "same_origin": {"type": "boolean"},
                           "extract_js_routes": {"type": "boolean"},
                           "browser": {"type": "string"}, "project_id": {"type": "integer"}},
            "required": ["url"]}}},
    {"type": "function", "function": {"name": "target_get_sitemap",
        "description": "Read a finished crawl's map (pages, params, forms, JS findings).",
        "parameters": {"type": "object",
            "properties": {"map_id": {"type": "integer"}, "project_id": {"type": "integer"},
                           "include_pages": {"type": "boolean"}, "page_limit": {"type": "integer"},
                           "page_offset": {"type": "integer"}, "only_js_findings": {"type": "boolean"}}}}},
    {"type": "function", "function": {"name": "scanner_cms_recon",
        "description": "Run a fast, read-only CMS/web recon scan against a URL.",
        "parameters": {"type": "object",
            "properties": {"url": {"type": "string"}, "profile": {"type": "string"}},
            "required": ["url"]}}},
    {"type": "function", "function": {"name": "scanner_active_start",
        "description": "Start the built-in active scanner (proves injection rather than assuming it).",
        "parameters": {"type": "object",
            "properties": {"url": {"type": "string"}, "max_pages": {"type": "integer"},
                           "max_depth": {"type": "integer"}, "concurrency": {"type": "integer"},
                           "delay_ms": {"type": "integer"}, "blind_delay_ms": {"type": "integer"},
                           "timeout_ms": {"type": "integer"}, "same_origin": {"type": "boolean"},
                           "follow_redirects": {"type": "boolean"}, "params": {"type": "string"},
                           "path_wordlist": {"type": "string"}},
            "required": ["url"]}}},
    {"type": "function", "function": {"name": "scanner_get_findings",
        "description": "Read confirmed/unconfirmed findings recorded against a Project.",
        "parameters": {"type": "object",
            "properties": {"project_id": {"type": "integer"}, "severities": {"type": "array"},
                           "proof_status": {"type": "string"}, "offset": {"type": "integer"},
                           "limit": {"type": "integer"}}}}},
    {"type": "function", "function": {"name": "kebab_send_to_tool",
        "description": "Route a captured exchange to another tool: repeater, intruder, automation, comparer.",
        "parameters": {"type": "object",
            "properties": {"target": {"type": "string"}, "record_id": {"type": "integer"},
                           "raw_http": {"type": "string"}, "marker_name": {"type": "string"},
                           "marker_style": {"type": "string"}, "payloads": {"type": "array"},
                           "mode": {"type": "string"}, "transformations": {"type": "array"},
                           "delay_ms": {"type": "integer"}, "concurrency": {"type": "integer"},
                           "name": {"type": "string"}, "comparer_side": {"type": "string"},
                           "workflow_name": {"type": "string"}},
            "required": ["target"]}}},
    {"type": "function", "function": {"name": "repeater_send_raw_http",
        "description": "Send one raw HTTP request through the engine and persist it as a History row.",
        "parameters": {"type": "object",
            "properties": {"raw_http": {"type": "string"}, "method": {"type": "string"},
                           "url": {"type": "string"}, "headers": {"type": "object"},
                            "body": {"type": "string"}, "timeout_ms": {"type": "integer"}}}}},
    {"type": "function", "function": {"name": "repeater_burst_test",
        "description": "Run a concurrent or timed burst test on an HTTP request.",
        "parameters": {"type": "object",
            "properties": {"method": {"type": "string"}, "url": {"type": "string"},
                           "headers": {"type": "object"}, "body": {"type": "string"},
                           "iterations": {"type": "integer"}, "concurrency": {"type": "integer"},
                           "delay_ms": {"type": "integer"}, "timeout_ms": {"type": "integer"}},
            "required": ["method", "url"]}}},
    {"type": "function", "function": {"name": "repeater_last_byte_sync",
        "description": "Hold a request open on its last byte to test timeouts and HTTP smuggling.",
        "parameters": {"type": "object",
            "properties": {"method": {"type": "string"}, "url": {"type": "string"},
                           "headers": {"type": "object"}, "body": {"type": "string"},
                           "iterations": {"type": "integer"}, "concurrency": {"type": "integer"},
                           "delay_ms": {"type": "integer"}, "hold_ms": {"type": "integer"},
                           "timeout_ms": {"type": "integer"}},
            "required": ["method", "url"]}}},
    {"type": "function", "function": {"name": "intruder_start_attack",
        "description": "Start a fuzzing run against a captured request with a marker.",
        "parameters": {"type": "object",
            "properties": {"base_request": {}, "payloads": {"type": "array"},
                           "mode": {"type": "string"}, "transformations": {"type": "array"},
                           "delay_ms": {"type": "integer"}, "concurrency": {"type": "integer"},
                           "detection": {"type": "object"}},
            "required": ["base_request", "payloads"]}}},
    {"type": "function", "function": {"name": "intruder_get_attack_results",
        "description": "Incrementally read the results of a fuzzing run.",
        "parameters": {"type": "object",
            "properties": {"attack_id": {"type": "integer"}, "since": {"type": "integer"},
                           "matches_only": {"type": "boolean"}, "min_status": {"type": "integer"},
                           "max_status": {"type": "integer"}, "body_pattern": {"type": "string"},
                           "include_bodies": {"type": "boolean"}, "limit": {"type": "integer"}}}}},
    {"type": "function", "function": {"name": "data_transform",
        "description": "Apply one encoding/decoding/hash step to a value, with no network.",
        "parameters": {"type": "object",
            "properties": {"operation": {"type": "string"}, "text": {"type": "string"},
                           "value": {"type": "string"}, "argument": {"type": "string"}}}}},
    {"type": "function", "function": {"name": "osint_transform_list",
        "description": "List every OSINT transform, with the network flag per transform.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "osint_run_transform",
        "description": "Run one OSINT transform on a graph; network needs confirm_network=True.",
        "parameters": {"type": "object",
            "properties": {"graph_id": {"type": "integer"}, "transform": {"type": "string"},
                           "value": {"type": "string"}, "options": {"type": "object"},
                           "confirm_network": {"type": "boolean"}},
            "required": ["transform", "value"]}}},
    {"type": "function", "function": {"name": "platform_status",
        "description": "Report whether the whole Request-Rider stack is reachable, plus active Project and route.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "history_get_records",
        "description": "List captured HTTP exchanges as metadata rows, newest first, with filtering by source/method/status/url.",
        "parameters": {"type": "object",
            "properties": {"source": {"type": "string"}, "method": {"type": "string"},
                           "status": {"type": "integer"}, "host": {"type": "string"},
                           "path": {"type": "string"}, "query": {"type": "string"},
                           "project_id": {"type": "integer"}, "limit": {"type": "integer"},
                           "offset": {"type": "integer"}, "sort": {"type": "string"}}}}},
    {"type": "function", "function": {"name": "history_get_transaction_raw",
        "description": "Read one captured exchange completely in raw wire format (request and response) with body windows.",
        "parameters": {"type": "object",
            "properties": {"record_id": {"type": "integer"}, "traffic_event_id": {"type": "integer"},
                           "offset": {"type": "integer"}, "length": {"type": "integer"},
                           "max_bytes": {"type": "integer"}},
            "required": []}}},
    {"type": "function", "function": {"name": "scanner_job_status",
        "description": "Poll a running scan (active or corpus) and read its state, progress, and findings.",
        "parameters": {"type": "object",
            "properties": {"job_id": {"type": "string"}, "kind": {"type": "string"},
                           "result_limit": {"type": "integer"}},
            "required": ["job_id"]}}},
    {"type": "function", "function": {"name": "report_ingest",
        "description": "Read and parse an external security report (HTML map, JSON findings, HAR, CSV, TXT).",
        "parameters": {"type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"},
                           "filename": {"type": "string"}},
            "required": []}}},
    {"type": "function", "function": {"name": "harness2_status",
        "description": "Report Google Research Harness² component status and environment availability.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {"name": "harness2_run_demo",
        "description": "Run the local deterministic Google Research Harness² recursive hardening loop.",
        "parameters": {"type": "object",
            "properties": {"k": {"type": "integer"}, "output_dir": {"type": "string"}},
            "required": []}}},
    {"type": "function", "function": {"name": "harness_pipeline_info",
        "description": "Report 3-tier architecture overview (MCP -> Harnesses -> 550+ Skills).",
        "parameters": {"type": "object", "properties": {}}}},
]

HANDLERS = {
    "project_list": tool_project_list,
    "project_create": tool_project_create,
    "project_switch_active": tool_project_switch_active,
    "project_get_knowledge_hub": tool_project_get_knowledge_hub,
    "target_run_crawl": tool_target_run_crawl,
    "target_get_sitemap": tool_target_get_sitemap,
    "scanner_cms_recon": tool_scanner_cms_recon,
    "scanner_active_start": tool_scanner_active_start,
    "scanner_job_status": tool_scanner_job_status,
    "scanner_get_findings": tool_scanner_get_findings,
    "kebab_send_to_tool": tool_kebab_send_to_tool,
    "repeater_send_raw_http": tool_repeater_send_raw_http,
    "repeater_burst_test": tool_repeater_burst_test,
    "repeater_last_byte_sync": tool_repeater_last_byte_sync,
    "intruder_start_attack": tool_intruder_start_attack,
    "intruder_get_attack_results": tool_intruder_get_attack_results,
    "data_transform": tool_data_transform,
    "osint_transform_list": tool_osint_transform_list,
    "osint_run_transform": tool_osint_run_transform,
    "platform_status": tool_platform_status,
    "history_get_records": tool_history_get_records,
    "history_get_transaction_raw": tool_history_get_transaction_raw,
    "report_ingest": tool_report_ingest,
    "harness2_status": tool_harness2_status,
    "harness2_run_demo": tool_harness2_run_demo,
    "harness_pipeline_info": tool_harness_pipeline_info,
}


def register_into(agent_tools_module):
    """Inject these tools into the `agent_tools` registry at import time."""
    for schema in SCHEMAS:
        agent_tools_module.TOOL_DEFINITIONS.append(schema)
    agent_tools_module.TOOL_HANDLERS.update(HANDLERS)
