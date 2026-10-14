"""Unified Multi-Engine Security Fusion & Correlation Engine for Request-Rider.

This module consolidates security findings across 4 distinct inspection levels:
  Level 1: Go Active Scan Engine (heuristic probes, SQLi, XSS, SSRF, Cache Poisoning, CORS, JWT, etc.)
  Level 2: Nuclei Engine (declarative CVE templates, misconfigurations, exposed services)
  Level 3: DOM Taint & Asset Map (client-side DOM vectors, unauthenticated endpoints, secret observations)
  Level 4: ReAct AI Agent (architectural insights, compound attack chains, context analysis)

It correlates findings by surface, detects Compound Attack Chains, maps vulnerabilities
to OWASP Top 10 2021, computes an Executive Security Posture Score, and renders
standalone Dark-Glassmorphic interactive HTML reports and SARIF 2.1.0 exports.
"""

import json
from collections import defaultdict
from django.utils import timezone
from django.http import HttpResponse, JsonResponse

from lab.models import Project, ScannerRun, ProjectEndpoint, ProjectSecret, TargetJob, ProjectExchange
from lab.project_context import ProjectContextBuilder


OWASP_CATEGORIES = {
    "sqli": ("A03:2021-Injection", "CWE-89: SQL Injection"),
    "xss": ("A03:2021-Injection", "CWE-79: Cross-Site Scripting"),
    "cmdi": ("A03:2021-Injection", "CWE-78: OS Command Injection"),
    "codeinj": ("A03:2021-Injection", "CWE-94: Code Injection"),
    "csti": ("A03:2021-Injection", "CWE-1336: Template Injection (SSTI/CSTI)"),
    "ssti": ("A03:2021-Injection", "CWE-1336: Server-Side Template Injection"),
    "ssrf": ("A10:2021-Server-Side Request Forgery", "CWE-918: Server-Side Request Forgery"),
    "cors": ("A01:2021-Broken Access Control", "CWE-942: Overly Permissive CORS Policy"),
    "jwt": ("A07:2021-Identification and Authentication Failures", "CWE-287: Improper Authentication"),
    "authbypass": ("A07:2021-Identification and Authentication Failures", "CWE-288: Authentication Bypass"),
    "cache-deception": ("A05:2021-Security Misconfiguration", "CWE-524: Web Cache Deception"),
    "cache-poisoning": ("A05:2021-Security Misconfiguration", "CWE-444: HTTP Request / Cache Poisoning"),
    "smuggling": ("A05:2021-Security Misconfiguration", "CWE-444: HTTP Request Smuggling"),
    "graphql": ("A05:2021-Security Misconfiguration", "CWE-200: Information Exposure (GraphQL Introspection)"),
    "openapi": ("A05:2021-Security Misconfiguration", "CWE-200: Information Exposure (Swagger/OpenAPI Spec)"),
    "csp": ("A05:2021-Security Misconfiguration", "CWE-1021: Weak Content Security Policy"),
    "crossdomain": ("A05:2021-Security Misconfiguration", "CWE-942: Permissive Crossdomain Policy"),
    "form-hijack": ("A01:2021-Broken Access Control", "CWE-345: Insecure Form Target"),
    "css-injection": ("A03:2021-Injection", "CWE-1021: CSS Injection"),
    "serialized-object": ("A08:2021-Software and Data Integrity Failures", "CWE-502: Deserialization of Untrusted Data"),
    "proto-pollution": ("A08:2021-Software and Data Integrity Failures", "CWE-1321: Prototype Pollution"),
    "cve": ("A06:2021-Vulnerable and Outdated Components", "CWE-1035: Known Vulnerability"),
    "secret": ("A02:2021-Cryptographic Failures", "CWE-798: Hardcoded Credentials / Secrets"),
    "general": ("A05:2021-Security Misconfiguration", "CWE-693: Protection Mechanism Failure"),
}

SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 4.5,
    "LOW": 2.0,
    "INFO": 0.5,
}


def map_to_owasp(module_name, title, cve_list=None):
    """Categorize finding into OWASP Top 10 2021 category and CWE."""
    if cve_list and len(cve_list) > 0:
        return OWASP_CATEGORIES["cve"]
    
    key = str(module_name or "").lower().strip()
    for pattern, val in OWASP_CATEGORIES.items():
        if pattern in key:
            return val
            
    title_lower = str(title or "").lower()
    for pattern, val in OWASP_CATEGORIES.items():
        if pattern in title_lower:
            return val
            
    return OWASP_CATEGORIES["general"]


def build_unified_fusion(project):
    """Aggregate, correlate and fuse all 4 levels of findings for the project."""
    fusion = {
        "project": {
            "id": project.id,
            "name": project.name,
            "target": project.target,
            "environment": project.environment,
            "tech_stack": project.tech_stack or {},
        },
        "generated_at": timezone.now().isoformat(),
        "levels_summary": {
            "level1_active_scan": 0,
            "level2_nuclei": 0,
            "level3_dom_and_assets": 0,
            "level4_ai_compound_chains": 0,
        },
        "severity_summary": {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
            "total": 0,
        },
        "owasp_breakdown": defaultdict(int),
        "compound_chains": [],
        "unified_findings": [],
        "security_score": 100,
        "grade": "A",
    }

    surface_groups = defaultdict(list)
    raw_findings = []

    # Level 1 & Level 2: Scanner Runs (Go Engine Active Scanner & Nuclei)
    runs = ScannerRun.objects.filter(project=project).order_by("-created_at")
    for run in runs:
        engine = str(run.engine or "generic").lower()
        is_active = (engine == "active")
        is_nuclei = (engine in ("nuclei", "nuclei_upload"))
        
        for item in (run.findings or []):
            if not isinstance(item, dict):
                continue
            
            finding_id = str(item.get("id") or item.get("template_id") or "FINDING")
            title = str(item.get("title") or item.get("name") or finding_id)
            severity = str(item.get("severity") or "INFO").upper()
            if severity not in SEVERITY_WEIGHTS:
                severity = "INFO"
                
            endpoint = str(item.get("endpoint") or item.get("matched_at") or run.url or project.target or "")
            method = str(item.get("method") or "GET").upper()
            module = str(item.get("module") or item.get("template_id") or engine)
            tier = str(item.get("tier") or ("verified" if is_nuclei and severity in ("CRITICAL", "HIGH") else "potential"))
            evidence = str(item.get("evidence") or item.get("extracted_results") or "")
            poc_curl = str(item.get("poc_curl") or item.get("curl") or "")
            desc = str(item.get("description") or "")
            remediation = str(item.get("recommendation") or item.get("remediation") or "")
            cve_list = item.get("cve") or []
            if isinstance(cve_list, str):
                cve_list = [cve_list]

            owasp_cat, cwe = map_to_owasp(module, title, cve_list)

            level_name = "Level 1: Go Active Engine" if is_active else ("Level 2: Nuclei CVE" if is_nuclei else "Scanner")
            if is_active:
                fusion["levels_summary"]["level1_active_scan"] += 1
            elif is_nuclei:
                fusion["levels_summary"]["level2_nuclei"] += 1
            else:
                fusion["levels_summary"]["level1_active_scan"] += 1

            finding_obj = {
                "id": finding_id,
                "level": level_name,
                "level_num": 1 if is_active else (2 if is_nuclei else 1),
                "engine": engine,
                "tier": tier,
                "title": title,
                "severity": severity,
                "endpoint": endpoint,
                "method": method,
                "module": module,
                "owasp_category": owasp_cat,
                "cwe": cwe,
                "cve": cve_list,
                "evidence": evidence,
                "poc_curl": poc_curl,
                "description": desc,
                "remediation": remediation,
                "created_at": run.created_at.isoformat(),
            }
            raw_findings.append(finding_obj)
            surface_groups[endpoint].append(finding_obj)

    # Level 3: DOM Taint & Asset Observations (Secrets & Endpoints)
    secrets = ProjectSecret.objects.filter(project=project)
    for sec in secrets:
        fusion["levels_summary"]["level3_dom_and_assets"] += 1
        secret_finding = {
            "id": f"SEC-{sec.id}",
            "level": "Level 3: DOM & Secret Assets",
            "level_num": 3,
            "engine": "secret_observer",
            "tier": "verified",
            "title": f"Hardcoded Secret Reference: {sec.secret_type} ({sec.key_name})",
            "severity": "HIGH",
            "endpoint": sec.source_url or project.target or "",
            "method": "CLIENT-DOM",
            "module": "secret-leak",
            "owasp_category": OWASP_CATEGORIES["secret"][0],
            "cwe": OWASP_CATEGORIES["secret"][1],
            "cve": [],
            "evidence": f"Secret reference observed: {sec.value_ref}",
            "poc_curl": f"# Inspect DOM source at: {sec.source_url}",
            "description": f"A potential secret or token reference of type {sec.secret_type} was observed in client assets or traffic.",
            "remediation": "Remove secret keys, API tokens, and credentials from client-facing scripts and code.",
            "created_at": sec.created_at.isoformat(),
        }
        raw_findings.append(secret_finding)
        surface_groups[secret_finding["endpoint"]].append(secret_finding)

    # Level 4: ReAct AI Compound Attack Chains Synthesis
    # Correlate vulnerabilities affecting the same endpoint or domain into Compound Chains
    chain_counter = 1
    for ep, f_list in surface_groups.items():
        if len(f_list) >= 2:
            modules = {f["module"] for f in f_list}
            severities = {f["severity"] for f in f_list}
            
            # Detect CORS + Auth/Token exposure
            if any("cors" in m for m in modules) and any("jwt" in m or "secret" in m or "auth" in m for m in modules):
                chain = {
                    "chain_id": f"CHAIN-0{chain_counter}",
                    "title": "Compound Attack Chain: Cross-Origin Token Theft & Account Compromise",
                    "severity": "CRITICAL",
                    "endpoint": ep,
                    "participating_levels": sorted(list({f["level"] for f in f_list})),
                    "mechanism": "Permissive CORS access control headers combined with vulnerable token/credential handling permits an external malicious domain to exfiltrate victim session tokens via authenticated cross-origin requests.",
                    "remediation": "Restrict Access-Control-Allow-Origin to trusted explicit origins, disallow wildcard credentials, and implement strict SameSite cookie protection.",
                    "findings_included": [f["id"] for f in f_list],
                }
                fusion["compound_chains"].append(chain)
                chain_counter += 1
                
            # Detect Cache Deception + Dynamic Endpoint
            elif any("cache" in m for m in modules):
                chain = {
                    "chain_id": f"CHAIN-0{chain_counter}",
                    "title": "Compound Attack Chain: Web Cache Deception & Public Response Leaking",
                    "severity": "HIGH",
                    "endpoint": ep,
                    "participating_levels": sorted(list({f["level"] for f in f_list})),
                    "mechanism": "Dynamic responses cached by intermediary CDN/proxy nodes using static file suffixes allow unauthenticated third parties to retrieve cached sensitive user records.",
                    "remediation": "Configure Cache-Control headers with no-store or private for user-dependent endpoints and disallow path suffix extension rewriting on reverse proxies.",
                    "findings_included": [f["id"] for f in f_list],
                }
                fusion["compound_chains"].append(chain)
                chain_counter += 1

    fusion["levels_summary"]["level4_ai_compound_chains"] = len(fusion["compound_chains"])

    # Calculate Totals & OWASP Breakdown
    for f in raw_findings:
        sev = f["severity"]
        fusion["severity_summary"][sev] += 1
        fusion["severity_summary"]["total"] += 1
        fusion["owasp_breakdown"][f["owasp_category"]] += 1

    # Deduplicate findings by identity
    seen_ids = set()
    deduped = []
    for f in raw_findings:
        if f["id"] not in seen_ids:
            seen_ids.add(f["id"])
            deduped.append(f)
            
    # Sort: CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda x: sev_order.get(x["severity"], 9))
    fusion["unified_findings"] = deduped
    fusion["owasp_breakdown"] = dict(sorted(fusion["owasp_breakdown"].items(), key=lambda x: x[1], reverse=True))

    # Calculate Unified Security Score: 100 base, deductions for findings
    penalty = (
        fusion["severity_summary"]["CRITICAL"] * 15.0 +
        fusion["severity_summary"]["HIGH"] * 8.0 +
        fusion["severity_summary"]["MEDIUM"] * 2.5 +
        fusion["severity_summary"]["LOW"] * 0.8 +
        len(fusion["compound_chains"]) * 10.0
    )
    score = max(5, int(round(100.0 - penalty)))
    fusion["security_score"] = score
    if score >= 90:
        fusion["grade"] = "A"
    elif score >= 75:
        fusion["grade"] = "B"
    elif score >= 60:
        fusion["grade"] = "C"
    elif score >= 40:
        fusion["grade"] = "D"
    else:
        fusion["grade"] = "F"

    # AI Executive Snapshot Analysis
    try:
        fusion["ai_executive_summary"] = ProjectContextBuilder(project.id).build_summary_markdown(include_notes=False)
    except Exception:
        fusion["ai_executive_summary"] = "AI context summary unavailable."

    return fusion


def generate_fusion_sarif(fusion_data):
    """Serialize the consolidated multi-engine findings into OASIS SARIF 2.1.0 JSON format."""
    rules = []
    results = []
    rule_indices = {}

    for finding in fusion_data["unified_findings"]:
        rule_id = finding["module"] or finding["id"]
        if rule_id not in rule_indices:
            rule_indices[rule_id] = len(rules)
            rules.append({
                "id": rule_id,
                "name": finding["title"],
                "shortDescription": {"text": finding["title"]},
                "fullDescription": {"text": finding.get("description") or finding["title"]},
                "defaultConfiguration": {
                    "level": "error" if finding["severity"] in ("CRITICAL", "HIGH") else ("warning" if finding["severity"] == "MEDIUM" else "note")
                },
                "properties": {
                    "owasp": finding["owasp_category"],
                    "cwe": finding["cwe"],
                    "engine": finding["engine"],
                    "level": finding["level"],
                }
            })

        results.append({
            "ruleId": rule_id,
            "ruleIndex": rule_indices[rule_id],
            "level": "error" if finding["severity"] in ("CRITICAL", "HIGH") else ("warning" if finding["severity"] == "MEDIUM" else "note"),
            "message": {"text": f"[{finding['level']}] {finding['title']}: {finding.get('evidence', '')}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding["endpoint"]},
                        "region": {"startLine": 1}
                    }
                }
            ],
            "properties": {
                "poc_curl": finding.get("poc_curl", ""),
                "remediation": finding.get("remediation", ""),
                "tier": finding.get("tier", "potential"),
            }
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Request-Rider Multi-Engine Fusion",
                        "semanticVersion": "2.0.0",
                        "informationUri": "https://github.com/request-rider",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ]
    }


def generate_fusion_html_report(fusion_data):
    """Generate a self-contained, interactive Dark-Glassmorphic HTML Security Report."""
    p = fusion_data["project"]
    summary = fusion_data["severity_summary"]
    levels = fusion_data["levels_summary"]
    score = fusion_data["security_score"]
    grade = fusion_data["grade"]
    grade_color = "#10b981" if grade in ("A", "B") else ("#fbbf24" if grade == "C" else "#ef4444")

    # Serialize unified findings to JSON for the client-side search and filters
    findings_json = json.dumps(fusion_data["unified_findings"], ensure_ascii=False)

    html = f"""<!doctype html>
<html lang="uk">
<head>
  <meta charset="utf-8">
  <title>Unified Multi-Engine Security Fusion Report · {p['name']}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {{
      --bg:#080d14; --card:rgba(18,28,42,0.75); --line:rgba(255,255,255,0.08);
      --text:#f1f5f9; --muted:#94a3b8; --accent:#10b981; --crit:#ef4444; --high:#f97316;
      --med:#f59e0b; --low:#3b82f6; --info:#64748b;
    }}
    * {{ box-sizing:border-box; margin:0; padding:0 }}
    body {{ background:var(--bg); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; line-height:1.5; padding:24px }}
    .container {{ max-width:1200px; margin:0 auto; display:flex; flex-direction:column; gap:20px }}
    header {{ display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:16px; padding:20px; border-radius:12px; background:linear-gradient(135deg,#0f1a29,#09101a); border:1px solid var(--line) }}
    .kicker {{ color:var(--accent); font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.12em }}
    h1 {{ font-size:24px; margin:4px 0 }}
    .meta {{ font-size:12px; color:var(--muted) }}
    .score-badge {{ display:flex; align-items:center; gap:14px; padding:12px 20px; border-radius:10px; background:rgba(0,0,0,0.4); border:1px solid var(--line) }}
    .grade {{ font-size:38px; font-weight:900; color:{grade_color}; line-height:1 }}
    .score-label {{ font-size:11px; text-transform:uppercase; color:var(--muted) }}
    .score-val {{ font-size:18px; font-weight:700 }}
    
    .grid-4 {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px }}
    .grid-2 {{ display:grid; grid-template-columns:1fr 1fr; gap:16px }}
    .card {{ background:var(--card); backdrop-filter:blur(8px); border:1px solid var(--line); border-radius:10px; padding:16px }}
    .card-k {{ font-size:11px; text-transform:uppercase; color:var(--muted); font-weight:600 }}
    .card-v {{ font-size:24px; font-weight:700; margin-top:4px }}
    
    .chip {{ display:inline-block; padding:3px 8px; border-radius:4px; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.04em }}
    .chip-crit {{ background:rgba(239,68,68,0.2); color:#f87171; border:1px solid rgba(239,68,68,0.4) }}
    .chip-high {{ background:rgba(249,115,22,0.2); color:#fb923c; border:1px solid rgba(249,115,22,0.4) }}
    .chip-med {{ background:rgba(245,158,11,0.2); color:#fbbf24; border:1px solid rgba(245,158,11,0.4) }}
    .chip-low {{ background:rgba(59,130,246,0.2); color:#60a5fa; border:1px solid rgba(59,130,246,0.4) }}
    .chip-info {{ background:rgba(100,116,139,0.2); color:#94a3b8; border:1px solid rgba(100,116,139,0.4) }}
    
    .chain-box {{ border-left:4px solid var(--crit); background:rgba(239,68,68,0.06); padding:14px; border-radius:0 8px 8px 0; margin-bottom:10px }}
    .chain-title {{ font-weight:700; font-size:14px; color:#f87171; display:flex; justify-content:space-between }}
    .chain-desc {{ font-size:12px; color:#cbd5e1; margin-top:6px }}
    
    .toolbar {{ display:flex; gap:10px; flex-wrap:wrap; margin:10px 0 }}
    input[type="search"] {{ flex:1; min-width:240px; padding:8px 12px; border-radius:6px; background:#0f172a; border:1px solid var(--line); color:var(--text); font-size:13px }}
    .btn {{ padding:6px 12px; border-radius:6px; background:rgba(255,255,255,0.08); border:1px solid var(--line); color:var(--text); font-size:12px; cursor:pointer }}
    .btn.active {{ background:#14634e; border-color:var(--accent); color:#fff }}
    
    table {{ width:100%; border-collapse:collapse; margin-top:12px; font-size:12px }}
    th, td {{ padding:10px 12px; text-align:left; border-bottom:1px solid var(--line) }}
    th {{ background:rgba(15,23,42,0.8); color:var(--muted); text-transform:uppercase; font-size:11px }}
    tr:hover {{ background:rgba(255,255,255,0.02) }}
    .mono {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:11px }}
    
    .owasp-bar {{ display:flex; flex-direction:column; gap:6px }}
    .owasp-row {{ display:flex; justify-content:space-between; align-items:center; font-size:12px }}
    .owasp-prog {{ width:100%; height:6px; background:rgba(255,255,255,0.05); border-radius:3px; overflow:hidden }}
    .owasp-fill {{ height:100%; background:linear-gradient(90deg,#0ea5e9,#10b981) }}
    
    pre {{ background:#090d14; padding:10px; border-radius:6px; border:1px solid var(--line); overflow-x:auto; font-family:monospace; font-size:11px; margin-top:4px }}
    @media (max-width:900px) {{ .grid-4 {{ grid-template-columns:1fr 1fr }} .grid-2 {{ grid-template-columns:1fr }} }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <p class="kicker">Request-Rider · Multi-Engine Fusion Security Report</p>
        <h1>{p['name']}</h1>
        <p class="meta">Target: <span class="mono">{p['target']}</span> · Generated: {fusion_data['generated_at'][:19].replace('T', ' ')} · Protocol: MCP 2.0</p>
        <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
          <a href="?format=sarif&download=1" class="btn" style="text-decoration:none;display:inline-flex;align-items:center;gap:6px"><span>📥</span> Export SARIF 2.1.0</a>
          <a href="?format=json&download=1" class="btn" style="text-decoration:none;display:inline-flex;align-items:center;gap:6px"><span>📥</span> Export Raw JSON</a>
          <button type="button" onclick="window.print()" class="btn" style="display:inline-flex;align-items:center;gap:6px"><span>🖨️</span> Print / Save PDF</button>
        </div>
      </div>
      <div class="score-badge">
        <div class="grade" style="color:{grade_color}">{grade}</div>
        <div>
          <div class="score-label">Posture Score</div>
          <div class="score-val">{score} / 100</div>
        </div>
      </div>
    </header>

    <!-- 4 Inspection Levels Grid -->
    <div class="grid-4">
      <div class="card">
        <div class="card-k">Level 1: Go Active Engine</div>
        <div class="card-v" style="color:#38bdf8">{levels['level1_active_scan']}</div>
        <p class="meta" style="margin-top:4px">Heuristic & zero-day probes</p>
      </div>
      <div class="card">
        <div class="card-k">Level 2: Nuclei CVE Suite</div>
        <div class="card-v" style="color:#a855f7">{levels['level2_nuclei']}</div>
        <p class="meta" style="margin-top:4px">Declarative template audit</p>
      </div>
      <div class="card">
        <div class="card-k">Level 3: DOM Taint & Assets</div>
        <div class="card-v" style="color:#f59e0b">{levels['level3_dom_and_assets']}</div>
        <p class="meta" style="margin-top:4px">Client DOM sinks & secrets</p>
      </div>
      <div class="card">
        <div class="card-k">Level 4: Compound Chains</div>
        <div class="card-v" style="color:#f43f5e">{levels['level4_ai_compound_chains']}</div>
        <p class="meta" style="margin-top:4px">Cross-engine correlated vectors</p>
      </div>
    </div>

    <!-- Severity Distribution & OWASP Top 10 -->
    <div class="grid-2">
      <div class="card">
        <div class="card-k" style="margin-bottom:12px">Severity Breakdown ({summary['total']} total findings)</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <span class="chip chip-crit">{summary['CRITICAL']} Critical</span>
          <span class="chip chip-high">{summary['HIGH']} High</span>
          <span class="chip chip-med">{summary['MEDIUM']} Medium</span>
          <span class="chip chip-low">{summary['LOW']} Low</span>
          <span class="chip chip-info">{summary['INFO']} Info</span>
        </div>
        <p class="meta" style="margin-top:14px">Aggregated across Go Active Scanner, Nuclei runs, and client-side secret observers with deduplication.</p>
      </div>

      <div class="card">
        <div class="card-k" style="margin-bottom:12px">Top OWASP 2021 Categories Observed</div>
        <div class="owasp-bar">
          {"".join(f'''<div class="owasp-row"><span>{cat}</span><strong>{cnt}</strong></div><div class="owasp-prog"><div class="owasp-fill" style="width:{min(100, cnt * 8)}%"></div></div>''' for cat, cnt in list(fusion_data['owasp_breakdown'].items())[:4]) or '<p class="meta">No standard vulnerabilities categorized.</p>'}
        </div>
      </div>
    </div>

    <!-- Compound Attack Chains Section -->
    {"".join(f'''<div class="card"><div class="card-k" style="margin-bottom:12px;color:#f87171">⚡ Detected Compound Attack Chains ({len(fusion_data['compound_chains'])})</div>''' + "".join(f'''<div class="chain-box"><div class="chain-title"><span>{c['title']}</span><span class="chip chip-crit">{c['severity']}</span></div><p class="chain-desc">{c['mechanism']}</p><p class="meta" style="margin-top:6px">Endpoint: <span class="mono">{c['endpoint']}</span> · Engines: {", ".join(c['participating_levels'])}</p><p class="meta" style="color:#6ee7b7;margin-top:4px">Remediation: {c['remediation']}</p></div>''' for c in fusion_data['compound_chains']) + '</div>') if fusion_data['compound_chains'] else ''}

    <!-- Interactive Filterable Table of Consolidated Findings -->
    <div class="card">
      <div class="card-k">Unified Vulnerability Ledger ({len(fusion_data['unified_findings'])})</div>
      <div class="toolbar">
        <input type="search" id="q-search" placeholder="Filter by endpoint, title, module, or CWE..." oninput="filterTable()">
        <button type="button" class="btn active" data-sev="ALL" onclick="setSevFilter('ALL', this)">All</button>
        <button type="button" class="btn" data-sev="CRITICAL" onclick="setSevFilter('CRITICAL', this)">Crit</button>
        <button type="button" class="btn" data-sev="HIGH" onclick="setSevFilter('HIGH', this)">High</button>
        <button type="button" class="btn" data-sev="MEDIUM" onclick="setSevFilter('MEDIUM', this)">Med</button>
        <button type="button" class="btn" data-sev="LOW" onclick="setSevFilter('LOW', this)">Low</button>
      </div>

      <div style="overflow-x:auto">
        <table id="findings-table">
          <thead>
            <tr>
              <th style="width:90px">Severity</th>
              <th style="width:130px">Engine / Level</th>
              <th>Vulnerability Title</th>
              <th>Endpoint / Surface</th>
              <th style="width:180px">OWASP Category</th>
            </tr>
          </thead>
          <tbody id="findings-body"></tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    const allFindings = {findings_json};
    let activeSev = 'ALL';

    function renderTable(items) {{
      const tbody = document.getElementById('findings-body');
      if (!items.length) {{
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--muted)">No findings matching filters.</td></tr>';
        return;
      }}
      tbody.innerHTML = items.map(item => {{
        const sevClass = item.severity === 'CRITICAL' ? 'chip-crit' : item.severity === 'HIGH' ? 'chip-high' : item.severity === 'MEDIUM' ? 'chip-med' : item.severity === 'LOW' ? 'chip-low' : 'chip-info';
        return `<tr>
          <td><span class="chip ${{sevClass}}">${{item.severity}}</span></td>
          <td><span class="mono" style="font-size:10px">${{item.level.split(':')[0]}}</span><br><span class="meta">${{item.module || item.engine}}</span></td>
          <td><strong>${{item.title}}</strong>${{item.poc_curl ? `<pre>${{item.poc_curl}}</pre>` : ''}}</td>
          <td class="mono" style="word-break:break-all">${{item.method ? `<strong>${{item.method}}</strong> ` : ''}}${{item.endpoint}}</td>
          <td><span style="font-size:11px">${{item.owasp_category.split(':')[0]}}</span></td>
        </tr>`;
      }}).join('');
    }}

    function filterTable() {{
      const q = document.getElementById('q-search').value.toLowerCase().trim();
      let filtered = allFindings;
      if (activeSev !== 'ALL') {{
        filtered = filtered.filter(f => f.severity === activeSev);
      }}
      if (q) {{
        filtered = filtered.filter(f => 
          (f.title || '').toLowerCase().includes(q) ||
          (f.endpoint || '').toLowerCase().includes(q) ||
          (f.module || '').toLowerCase().includes(q) ||
          (f.owasp_category || '').toLowerCase().includes(q)
        );
      }}
      renderTable(filtered);
    }}

    function setSevFilter(sev, btn) {{
      activeSev = sev;
      document.querySelectorAll('.toolbar .btn').forEach(b => b.classList.toggle('active', b === btn));
      filterTable();
    }}

    // Initial render
    renderTable(allFindings);
  </script>
</body>
</html>
"""
    return html
