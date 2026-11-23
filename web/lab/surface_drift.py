"""Attack Surface Drift & Shadow API Radar engine (F6 ROADMAP)."""
from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .models import (
    OsintEntity,
    OsintRelation,
    Project,
    ProjectEndpoint,
    ProjectSurfaceSnapshot,
    ScannerRun,
    TrafficRecord,
    compute_finding_identity,
)

_SECURITY_HEADER_NAMES = {
    "content-security-policy",
    "strict-transport-security",
    "access-control-allow-origin",
    "x-frame-options",
    "x-content-type-options",
}

_SHADOW_PATH_RE = re.compile(
    r"(/internal/|/admin/|/debug/|/graphql|/export|/backup|/actuator|/swagger|/v\d+/)",
    re.IGNORECASE,
)
_API_VERSION_RE = re.compile(r"^(.*?/api/v)(\d+)(/.*)$", re.IGNORECASE)


def capture_project_snapshot(project: Project, label: str = "") -> ProjectSurfaceSnapshot:
    """Capture an immutable point-in-time snapshot of a Project's attack surface."""
    endpoint_map: dict[tuple[str, str], dict[str, Any]] = {}

    for ep in ProjectEndpoint.objects.filter(project=project):
        parsed = urlsplit(ep.sample_url or "")
        path = ep.path or parsed.path or "/"
        method = (ep.method or "GET").upper()
        params = {str(p) for p in (ep.parameters or []) if p}
        for qk, _ in parse_qsl(parsed.query):
            params.add(qk)
        ep_statuses = [int(s) for s in (ep.statuses or []) if isinstance(s, (int, float)) or str(s).isdigit()]
        latest_status = ep_statuses[-1] if ep_statuses else None
        key = (method, path)
        endpoint_map[key] = {
            "method": method,
            "path": path,
            "url": ep.sample_url or path,
            "params": sorted(params),
            "status": latest_status,
        }

    js_bundles: dict[str, str] = {}
    sec_headers: dict[str, dict[str, str]] = {}

    for rec in TrafficRecord.objects.filter(project=project).order_by("-timestamp", "-id")[:1000]:
        parsed = urlsplit(rec.url or "")
        origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""
        path = parsed.path or "/"
        method = (rec.method or "GET").upper()

        # Track security headers per origin (latest observed)
        if origin and origin not in sec_headers and isinstance(rec.response_headers, dict):
            extracted_hdrs = {}
            for hk, hv in rec.response_headers.items():
                hl = str(hk).strip().lower()
                if hl in _SECURITY_HEADER_NAMES:
                    extracted_hdrs[hl] = str(hv)
            sec_headers[origin] = extracted_hdrs

        # Track JS bundles & SourceMaps SHA-256
        ctype = str(rec.response_content_type or "").lower()
        if path.endswith((".js", ".js.map", ".mjs")) or "javascript" in ctype:
            if rec.url and rec.url not in js_bundles and rec.response_body:
                js_bundles[rec.url] = hashlib.sha256(
                    rec.response_body.encode("utf-8", errors="replace")
                ).hexdigest()

        # Enrich endpoint status & query params
        key = (method, path)
        if key not in endpoint_map:
            params = sorted({qk for qk, _ in parse_qsl(parsed.query)})
            endpoint_map[key] = {
                "method": method,
                "path": path,
                "url": rec.url or path,
                "params": params,
                "status": rec.status_code,
            }
        elif endpoint_map[key].get("status") is None and rec.status_code is not None:
            endpoint_map[key]["status"] = rec.status_code

    identities_set: set[str] = set()
    for run in ScannerRun.objects.filter(project=project):
        for row in run.findings or []:
            if not isinstance(row, dict):
                continue
            ident = row.get("identity_hash") or compute_finding_identity(row, run.url)
            if ident:
                identities_set.add(str(ident))
    identities = sorted(identities_set)
    osint_summary = {
        "entities_count": OsintEntity.objects.filter(graph__project=project).count(),
        "relations_count": OsintRelation.objects.filter(graph__project=project).count(),
    }

    snap_count = ProjectSurfaceSnapshot.objects.filter(project=project).count() + 1
    return ProjectSurfaceSnapshot.objects.create(
        project=project,
        label=label.strip() or f"Snapshot #{snap_count}",
        endpoints_data=list(endpoint_map.values()),
        js_bundles=js_bundles,
        security_headers=sec_headers,
        finding_identities=identities,
        osint_summary=osint_summary,
    )


def _is_shadow_api(path: str, all_s1_paths: set[str]) -> bool:
    if _SHADOW_PATH_RE.search(path):
        m = _API_VERSION_RE.match(path)
        if m:
            prefix, _ver, suffix = m.group(1), m.group(2), m.group(3)
            # If any other version existed in S1 for the same resource path, flag as Shadow/Zombie API
            for old_path in all_s1_paths:
                old_m = _API_VERSION_RE.match(old_path)
                if old_m and old_m.group(1).lower() == prefix.lower() and old_m.group(3).lower() == suffix.lower():
                    return True
        if any(tok in path.lower() for tok in ("/internal/", "/admin/", "/debug/", "/export", "/backup", "/actuator")):
            return True
    return False


def compute_surface_drift(snap1: ProjectSurfaceSnapshot, snap2: ProjectSurfaceSnapshot) -> dict[str, Any]:
    """Compute deterministic surface diff between snapshot S1 (baseline) and S2 (target)."""
    s1_eps = {(e["method"], e["path"]): e for e in (snap1.endpoints_data or []) if isinstance(e, dict)}
    s2_eps = {(e["method"], e["path"]): e for e in (snap2.endpoints_data or []) if isinstance(e, dict)}
    s1_paths = {p for _m, p in s1_eps}

    new_endpoints: list[dict[str, Any]] = []
    shadow_apis: list[dict[str, Any]] = []
    removed_endpoints: list[dict[str, Any]] = []
    new_params: list[dict[str, Any]] = []
    regressions: list[dict[str, Any]] = []
    delta_urls: list[str] = []

    for key, ep2 in sorted(s2_eps.items()):
        if key not in s1_eps:
            new_endpoints.append(ep2)
            if ep2.get("url"):
                delta_urls.append(ep2["url"])
            if _is_shadow_api(ep2["path"], s1_paths):
                shadow_apis.append(ep2)
        else:
            ep1 = s1_eps[key]
            p1 = set(ep1.get("params") or [])
            p2 = set(ep2.get("params") or [])
            added_p = sorted(p2 - p1)
            if added_p:
                new_params.append({
                    "method": ep2["method"],
                    "path": ep2["path"],
                    "url": ep2.get("url"),
                    "added_params": added_p,
                })
                if ep2.get("url"):
                    delta_urls.append(ep2["url"])
            st1 = ep1.get("status")
            st2 = ep2.get("status")
            if st1 in {401, 403} and st2 is not None and 200 <= st2 < 300:
                regressions.append({
                    "type": "auth_regression",
                    "target": f"{ep2['method']} {ep2['path']}",
                    "detail": f"Status changed from {st1} to {st2}",
                })

    for key, ep1 in sorted(s1_eps.items()):
        if key not in s2_eps:
            removed_endpoints.append(ep1)

    # JS bundle changes
    js1 = snap1.js_bundles or {}
    js2 = snap2.js_bundles or {}
    changed_js: list[dict[str, Any]] = []
    for url, sha2 in sorted(js2.items()):
        sha1 = js1.get(url)
        if sha1 is None:
            changed_js.append({"url": url, "change": "added", "sha256": sha2})
        elif sha1 != sha2:
            changed_js.append({"url": url, "change": "modified", "old_sha256": sha1, "sha256": sha2})

    # Security header regressions
    hdrs1 = snap1.security_headers or {}
    hdrs2 = snap2.security_headers or {}
    for origin, h1 in sorted(hdrs1.items()):
        h2 = hdrs2.get(origin, {})
        for sec_hdr in ("content-security-policy", "strict-transport-security"):
            if sec_hdr in h1 and sec_hdr not in h2:
                regressions.append({
                    "type": "header_regression",
                    "target": origin,
                    "detail": f"Security header '{sec_hdr}' disappeared in S2",
                })

    # New scanner finding identities
    ids1 = set(snap1.finding_identities or [])
    ids2 = set(snap2.finding_identities or [])
    new_finding_ids = sorted(ids2 - ids1)

    return {
        "ok": True,
        "s1": snap1.to_summary_dict(),
        "s2": snap2.to_summary_dict(),
        "new_endpoints": new_endpoints,
        "shadow_apis": shadow_apis,
        "removed_endpoints": removed_endpoints,
        "new_params": new_params,
        "changed_js": changed_js,
        "regressions": regressions,
        "new_finding_identities": new_finding_ids,
        "delta_scan_urls": sorted(set(delta_urls)),
        "counts": {
            "new_endpoints": len(new_endpoints),
            "shadow_apis": len(shadow_apis),
            "new_params": len(new_params),
            "changed_js": len(changed_js),
            "regressions": len(regressions),
            "new_findings": len(new_finding_ids),
        },
    }
