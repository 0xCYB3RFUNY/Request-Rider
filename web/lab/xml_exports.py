"""Universal XML and Metasploit (<MetasploitV4>) exporters for Request-Rider.

Provides:
- Safe generic XML serialization for projects, scanner runs, history, OSINT,
  traffic, intruder results, and workflows.
- Metasploit-compatible `<MetasploitV4>` XML generation for `msfconsole`
  `db_import` (hosts, services, vulns, notes, web_sites, web_vulns).
- Optional direct `msfconsole` import helper using `shell=False`.
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

_INVALID_XML_CHARS_RE = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x84\x86-\x9f]"
)
_XML_TAG_SANITIZE_RE = re.compile(r"[^A-Za-z0-9_.-]")


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    return _INVALID_XML_CHARS_RE.sub("", text)


def _safe_tag(name: str, fallback: str = "item") -> str:
    cleaned = _XML_TAG_SANITIZE_RE.sub("_", (name or "").strip())
    if not cleaned or cleaned[0].isdigit() or cleaned[0] in (".", "-"):
        cleaned = f"{fallback}_{cleaned}" if cleaned else fallback
    if cleaned.lower().startswith("xml"):
        cleaned = f"n_{cleaned}"
    return cleaned


def _append_value(parent: ET.Element, key: str, value: Any) -> None:
    tag = _safe_tag(key)
    if isinstance(value, dict):
        el = ET.SubElement(parent, tag)
        for k, v in value.items():
            _append_value(el, str(k), v)
    elif isinstance(value, (list, tuple, set)):
        container = ET.SubElement(parent, tag)
        item_tag = tag[:-1] if tag.endswith("s") and len(tag) > 1 else "item"
        for item in value:
            _append_value(container, item_tag, item)
    else:
        el = ET.SubElement(parent, tag)
        el.text = _clean_text(value)


def serialize_xml_document(root_tag: str, payload: Any, attrs: dict[str, str] | None = None) -> str:
    """Serialize arbitrary Python structures into a clean UTF-8 XML document."""
    root = ET.Element(_safe_tag(root_tag, "request_rider"))
    for k, v in (attrs or {}).items():
        root.set(_safe_tag(k, "attr"), _clean_text(v))

    if isinstance(payload, dict):
        for k, v in payload.items():
            _append_value(root, str(k), v)
    elif isinstance(payload, (list, tuple)):
        for item in payload:
            _append_value(root, "item", item)
    else:
        root.text = _clean_text(payload)

    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except ValueError:
        return False


def _parse_host_port_scheme(raw_url_or_host: str) -> tuple[str, int | None, str]:
    raw = (raw_url_or_host or "").strip()
    if not raw:
        return "", None, ""
    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        scheme = (parsed.scheme or "http").lower()
        port = parsed.port or (443 if scheme == "https" else 80 if scheme == "http" else None)
        return host, port, scheme
    if ":" in raw and raw.count(":") == 1:
        host_part, port_part = raw.split(":", 1)
        try:
            return host_part.strip(), int(port_part.split("/")[0]), "tcp"
        except ValueError:
            return host_part.strip(), None, "tcp"
    return raw.split("/")[0].strip(), None, "tcp"


def _risk_number(severity: str) -> str:
    sev = (severity or "").strip().lower()
    mapping = {"critical": "4", "high": "3", "medium": "2", "low": "1", "info": "0"}
    return mapping.get(sev, "1")


def export_metasploit_xml(
    project: Any,
    scanner_runs: list[Any] | None = None,
    osint_entities: list[Any] | None = None,
    endpoints: list[Any] | None = None,
    traffic_records: list[Any] | None = None,
    project_hosts: list[Any] | None = None,
) -> str:
    """Build a Metasploit `<MetasploitV4>` XML document compatible with `db_import`."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    root = ET.Element("MetasploitV4")
    ET.SubElement(
        root,
        "generated",
        {
            "time": now_str,
            "user": "request-rider",
            "project": _clean_text(getattr(project, "name", "default")),
        },
    )

    hosts_map: dict[str, dict[str, Any]] = {}

    def ensure_host(host_key: str) -> dict[str, Any] | None:
        clean = (host_key or "").strip().lower()
        if not clean:
            return None
        if clean not in hosts_map:
            hosts_map[clean] = {
                "address": clean,
                "name": clean,
                "services": {},
                "vulns": [],
                "notes": [],
                "os_name": "Unknown",
                "mac": "",
            }
        return hosts_map[clean]

    # Seed from project target
    proj_host, proj_port, proj_scheme = _parse_host_port_scheme(getattr(project, "target", "") or "")
    if proj_host:
        h = ensure_host(proj_host)
        if h and proj_port:
            h["services"][(proj_port, "tcp")] = {
                "port": proj_port,
                "proto": "tcp",
                "name": proj_scheme or "http",
                "state": "open",
                "info": "Project target",
            }

    # Seed from OSINT entities (hosts, IPs, domains, open ports)
    for ent in osint_entities or []:
        etype = (getattr(ent, "entity_type", "") or "").lower()
        val = (getattr(ent, "identity", "") or getattr(ent, "display_value", "") or getattr(ent, "value", "") or "").strip()
        if etype in ("ip", "domain", "subdomain", "host", "url") and val:
            host, port, scheme = _parse_host_port_scheme(val)
            h = ensure_host(host)
            if h and port:
                h["services"][(port, "tcp")] = {
                    "port": port,
                    "proto": "tcp",
                    "name": scheme or "http",
                    "state": "open",
                    "info": f"OSINT ({etype})",
                }

    # Seed from endpoints & traffic
    web_sites: dict[tuple[str, int, bool], dict[str, Any]] = {}
    web_vulns: list[dict[str, Any]] = []

    def ensure_web_site(host: str, port: int, ssl_flag: bool) -> None:
        key = (host.lower(), port, ssl_flag)
        if key not in web_sites:
            web_sites[key] = {"host": host.lower(), "port": port, "ssl": ssl_flag, "vhost": host.lower()}

    for ep in endpoints or []:
        url_val = getattr(ep, "sample_url", "") or getattr(ep, "url", "") or getattr(ep, "path", "") or ""
        host, port, scheme = _parse_host_port_scheme(url_val)
        if host:
            h = ensure_host(host)
            if h and port:
                h["services"][(port, "tcp")] = {
                    "port": port,
                    "proto": "tcp",
                    "name": scheme or "http",
                    "state": "open",
                    "info": "Discovered endpoint",
                }
                ensure_web_site(host, port, scheme == "https")

    for rec in traffic_records or []:
        url_val = getattr(rec, "url", "") or ""
        host, port, scheme = _parse_host_port_scheme(url_val)
        if host:
            h = ensure_host(host)
            if h and port:
                h["services"][(port, "tcp")] = {
                    "port": port,
                    "proto": "tcp",
                    "name": scheme or "http",
                    "state": "open",
                    "info": "Captured HTTP traffic",
                }
                ensure_web_site(host, port, scheme == "https")

    # Seed from ScannerRun findings
    for run in scanner_runs or []:
        run_url = getattr(run, "url", "") or ""
        run_engine = getattr(run, "engine", "") or "scanner"
        run_host, run_port, run_scheme = _parse_host_port_scheme(run_url)

        for finding in getattr(run, "findings", None) or []:
            if not isinstance(finding, dict):
                continue
            f_target = (
                finding.get("endpoint")
                or finding.get("url")
                or finding.get("host")
                or run_url
            )
            f_host, f_port, f_scheme = _parse_host_port_scheme(str(f_target))
            host_key = f_host or run_host
            if not host_key:
                continue
            h = ensure_host(host_key)
            assert h is not None

            port_num = f_port or run_port
            if not port_num and finding.get("port"):
                port_raw = str(finding.get("port")).split("/")[0].strip()
                if port_raw.isdigit():
                    port_num = int(port_raw)

            if port_num:
                svc_name = f_scheme or run_scheme or "tcp"
                existing_svc = h["services"].get((port_num, "tcp"))
                if not existing_svc:
                    h["services"][(port_num, "tcp")] = {
                        "port": port_num,
                        "proto": "tcp",
                        "name": svc_name,
                        "state": "open",
                        "info": f"Detected via {run_engine}",
                    }
                elif not existing_svc.get("info") or existing_svc["info"] in ("Discovered endpoint", "Project target"):
                    existing_svc["info"] = f"Detected via {run_engine}"

            title = str(finding.get("title") or finding.get("name") or finding.get("template_id") or "Vulnerability")
            severity = str(finding.get("severity") or "info")
            desc = str(finding.get("description") or finding.get("details") or finding.get("matcher_name") or "")
            info_text = f"[{severity.upper()} | {run_engine}] {desc}".strip()

            refs: list[str] = []
            cves = finding.get("cve") or finding.get("cves") or []
            if isinstance(cves, str):
                cves = [c.strip() for c in cves.split(",") if c.strip()]
            for cve in cves:
                refs.append(str(cve))
            if finding.get("nvt_oid"):
                refs.append(f"OID-{finding['nvt_oid']}")

            h["vulns"].append(
                {
                    "name": title,
                    "info": info_text,
                    "refs": refs,
                }
            )
            h["notes"].append(
                {
                    "ntype": f"request-rider.{run_engine}",
                    "data": f"{title} ({severity}) at {f_target}",
                }
            )

            # Also add web_vuln if HTTP/HTTPS URL is present
            if isinstance(f_target, str) and f_target.startswith(("http://", "https://")):
                parsed = urlparse(f_target)
                w_port = parsed.port or (443 if parsed.scheme == "https" else 80)
                w_ssl = parsed.scheme == "https"
                ensure_web_site(host_key, w_port, w_ssl)
                web_vulns.append(
                    {
                        "host": host_key,
                        "port": w_port,
                        "ssl": w_ssl,
                        "vhost": host_key,
                        "path": parsed.path or "/",
                        "method": str(finding.get("method") or "GET").upper(),
                        "pname": str(finding.get("parameter") or finding.get("param") or ""),
                        "proof": str(finding.get("payload") or finding.get("poc_curl") or desc)[:500],
                        "name": title,
                        "description": info_text,
                        "risk": _risk_number(severity),
                        "category": str(finding.get("category") or run_engine),
                    }
                )

    # Seed from ProjectHost models (highest priority for accurate host/service/version/vuln inventory)
    for ph in project_hosts or []:
        ip = getattr(ph, "ip_address", "") or ""
        hname = getattr(ph, "hostname", "") or ""
        key = (ip or hname).strip().lower()
        if not key:
            continue
        h = ensure_host(key)
        if not h:
            continue
        if ip:
            h["address"] = ip
        if hname:
            h["name"] = hname
        os_n = getattr(ph, "os_name", "") or ""
        if os_n:
            h["os_name"] = os_n
        mac = getattr(ph, "mac_address", "") or ""
        if mac:
            h["mac"] = mac

        svcs = getattr(ph, "services", []) or []
        for s in svcs:
            if isinstance(s, dict):
                p_num = s.get("port")
                if p_num:
                    proto = (s.get("proto") or "tcp").lower()
                    prod_ver = f"{s.get('product', '')} {s.get('version', '')}".strip()
                    info_val = s.get("banner") or prod_ver or s.get("info") or s.get("product") or s.get("version") or ""
                    h["services"][(p_num, proto)] = {
                        "port": p_num,
                        "proto": proto,
                        "name": s.get("name") or "unknown",
                        "state": s.get("state") or "open",
                        "info": info_val,
                    }
                    for v in s.get("vulns") or []:
                        if isinstance(v, dict):
                            h["vulns"].append({
                                "name": v.get("title") or v.get("id") or "Vulnerability",
                                "info": v.get("description") or f"Port {p_num} vulnerability",
                                "port": p_num,
                                "proto": proto,
                                "refs": v.get("refs") or ([v["id"]] if v.get("id") else []),
                            })

        for v in (getattr(ph, "vulns", []) or []):
            if isinstance(v, dict):
                h["vulns"].append({
                    "name": v.get("title") or v.get("id") or "Host Vulnerability",
                    "info": v.get("description") or "Host vulnerability",
                    "refs": v.get("refs") or ([v["id"]] if v.get("id") else []),
                })

    hosts_el = ET.SubElement(root, "hosts")
    for hdata in hosts_map.values():
        host_el = ET.SubElement(hosts_el, "host")
        ET.SubElement(host_el, "created-at").text = now_str
        ET.SubElement(host_el, "updated-at").text = now_str
        ET.SubElement(host_el, "address").text = _clean_text(hdata["address"])
        ET.SubElement(host_el, "mac").text = _clean_text(hdata.get("mac", ""))
        ET.SubElement(host_el, "comm").text = ""
        ET.SubElement(host_el, "name").text = _clean_text(hdata["name"])
        ET.SubElement(host_el, "state").text = "alive"
        ET.SubElement(host_el, "os-name").text = _clean_text(hdata.get("os_name", "Unknown"))
        ET.SubElement(host_el, "os-flavor").text = ""
        ET.SubElement(host_el, "os-sp").text = ""
        ET.SubElement(host_el, "os-lang").text = ""
        ET.SubElement(host_el, "purpose").text = "server" if _is_ip(hdata["address"]) else "device"

        svcs_el = ET.SubElement(host_el, "services")
        for svc in hdata["services"].values():
            svc_el = ET.SubElement(svcs_el, "service")
            ET.SubElement(svc_el, "created-at").text = now_str
            ET.SubElement(svc_el, "updated-at").text = now_str
            ET.SubElement(svc_el, "port").text = str(svc["port"])
            ET.SubElement(svc_el, "proto").text = _clean_text(svc["proto"])
            ET.SubElement(svc_el, "state").text = _clean_text(svc["state"])
            ET.SubElement(svc_el, "name").text = _clean_text(svc["name"])
            ET.SubElement(svc_el, "info").text = _clean_text(svc["info"])

        vulns_el = ET.SubElement(host_el, "vulns")
        for vuln in hdata["vulns"]:
            v_el = ET.SubElement(vulns_el, "vuln")
            ET.SubElement(v_el, "created-at").text = now_str
            ET.SubElement(v_el, "updated-at").text = now_str
            if vuln.get("port"):
                ET.SubElement(v_el, "port").text = str(vuln["port"])
            ET.SubElement(v_el, "name").text = _clean_text(vuln["name"])
            ET.SubElement(v_el, "info").text = _clean_text(vuln["info"])
            refs_el = ET.SubElement(v_el, "refs")
            for ref in vuln["refs"]:
                ET.SubElement(refs_el, "ref").text = _clean_text(ref)

        notes_el = ET.SubElement(host_el, "notes")
        for note in hdata["notes"]:
            n_el = ET.SubElement(notes_el, "note")
            ET.SubElement(n_el, "created-at").text = now_str
            ET.SubElement(n_el, "updated-at").text = now_str
            ET.SubElement(n_el, "ntype").text = _clean_text(note["ntype"])
            ET.SubElement(n_el, "critical").text = "false"
            ET.SubElement(n_el, "seen").text = "false"
            ET.SubElement(n_el, "data").text = _clean_text(note["data"])

    ws_el = ET.SubElement(root, "web_sites")
    for ws in web_sites.values():
        site_el = ET.SubElement(ws_el, "web_site")
        ET.SubElement(site_el, "created-at").text = now_str
        ET.SubElement(site_el, "updated-at").text = now_str
        ET.SubElement(site_el, "vhost").text = _clean_text(ws["vhost"])
        ET.SubElement(site_el, "host").text = _clean_text(ws["host"])
        ET.SubElement(site_el, "port").text = str(ws["port"])
        ET.SubElement(site_el, "ssl").text = "true" if ws["ssl"] else "false"

    wv_el = ET.SubElement(root, "web_vulns")
    for wv in web_vulns:
        vuln_el = ET.SubElement(wv_el, "web_vuln")
        ET.SubElement(vuln_el, "created-at").text = now_str
        ET.SubElement(vuln_el, "updated-at").text = now_str
        for field in ("host", "port", "vhost", "path", "method", "pname", "proof", "name", "description", "risk", "category"):
            ET.SubElement(vuln_el, field).text = _clean_text(wv[field])
        ET.SubElement(vuln_el, "params").text = ""
        ET.SubElement(vuln_el, "ssl").text = "true" if wv["ssl"] else "false"

    ET.indent(root, space="  ")
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


def import_xml_into_metasploit(xml_content: str, workspace: str = "default") -> dict[str, Any]:
    """Import a `<MetasploitV4>` XML document into local `msfconsole` via `db_import`."""
    safe_ws = re.sub(r"[^A-Za-z0-9_.-]", "_", (workspace or "default").strip()) or "default"
    tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".xml",
            prefix="rr_msf_",
            encoding="utf-8",
            delete=False,
        ) as handle:
            handle.write(xml_content)
            tmp_path = handle.name

        cmd = [
            "msfconsole",
            "-q",
            "-x",
            f"workspace -a {safe_ws}; db_import {tmp_path}; exit",
        ]
        proc = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        combined_out = f"{proc.stdout}\n{proc.stderr}".lower()
        db_disconnected = (
            "database not connected" in combined_out
            or "failed to connect to the database" in combined_out
        )
        import_failed = "error while running command db_import" in combined_out
        ok = proc.returncode == 0 and not db_disconnected and not import_failed
        result: dict[str, Any] = {
            "ok": ok,
            "returncode": proc.returncode,
            "workspace": safe_ws,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-2000:],
        }
        if db_disconnected:
            result["error"] = "Metasploit database is not connected. Run: sudo msfdb init"
        elif import_failed:
            result["error"] = "msfconsole db_import reported an error (see stdout)"
        elif not ok:
            result["error"] = f"msfconsole exited with code {proc.returncode}"
        return result
    except FileNotFoundError:
        return {"ok": False, "error": "msfconsole binary not found on PATH"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "msfconsole db_import timed out"}
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _cvss_to_severity(cvss_val: Any) -> str:
    try:
        val = float(cvss_val)
        if val >= 9.0:
            return "critical"
        if val >= 7.0:
            return "high"
        if val >= 4.0:
            return "medium"
        if val > 0.0:
            return "low"
    except (TypeError, ValueError):
        pass
    return "info"


def _parse_vulners_output(script_el: ET.Element) -> list[dict[str, Any]]:
    vulns: list[dict[str, Any]] = []
    seen: set[str] = set()

    for table in script_el.findall(".//table"):
        cve_id = ""
        cvss = 0.0
        cve_type = ""
        is_exploit = False
        for elem in table.findall("./elem"):
            k = (elem.get("key") or "").strip().lower()
            v = (elem.text or "").strip()
            if k == "id":
                cve_id = v
            elif k == "cvss":
                try:
                    cvss = float(v)
                except ValueError:
                    pass
            elif k == "type":
                cve_type = v
            elif k == "is_exploit":
                is_exploit = v.lower() in ("true", "1", "yes")

        if cve_id and cve_id not in seen:
            seen.add(cve_id)
            vulns.append({
                "id": cve_id,
                "title": cve_id,
                "severity": _cvss_to_severity(cvss),
                "cvss": cvss,
                "type": cve_type,
                "is_exploit": is_exploit,
                "description": f"Vulnerability {cve_id} detected via nmap-vulners (CVSS {cvss})",
                "refs": [f"https://vulners.com/{cve_type or 'cve'}/{cve_id}"],
            })

    out = (script_el.get("output") or script_el.text or "").strip()
    if out:
        for match in re.finditer(r"([A-Z0-9_\-\.\/]+:[^\s]+|CVE-\d{4}-\d+|SSV:\d+)\s+([\d.]+)\s+(https?://\S+)", out):
            vid, cvss_str, url = match.group(1), match.group(2), match.group(3)
            if vid not in seen:
                seen.add(vid)
                try:
                    cvss_f = float(cvss_str)
                except ValueError:
                    cvss_f = 0.0
                vulns.append({
                    "id": vid,
                    "title": vid,
                    "severity": _cvss_to_severity(cvss_f),
                    "cvss": cvss_f,
                    "description": f"Vulnerability {vid} (CVSS {cvss_f})",
                    "refs": [url],
                })
    return vulns


def parse_metasploit_xml(xml_text: str) -> dict[str, Any]:
    """Parse a Metasploit <MetasploitV4> XML export into findings, endpoints, and network_hosts."""
    from .openvas_client import safe_fromstring

    root = safe_fromstring(xml_text)
    if root.tag != "MetasploitV4" and root.find(".//hosts") is None:
        raise ValueError("Expected MetasploitV4 XML document")

    findings: list[dict[str, Any]] = []
    endpoints: list[dict[str, Any]] = []
    seen_endpoints: set[tuple[str, str]] = set()
    hosts: list[str] = []
    network_hosts: list[dict[str, Any]] = []

    def _sev_from_info(info_text: str, risk: str = "") -> str:
        low = info_text.lower()
        for lvl in ("critical", "high", "medium", "low", "info"):
            if f"[{lvl}" in low:
                return lvl
        try:
            r = int(risk)
            if r >= 5:
                return "critical"
            if r >= 4:
                return "high"
            if r >= 3:
                return "medium"
            if r >= 2:
                return "low"
        except (TypeError, ValueError):
            pass
        return "medium"

    for host_el in root.findall("./hosts/host"):
        addr = (host_el.findtext("address") or "").strip()
        name = (host_el.findtext("name") or "").strip()
        state = (host_el.findtext("state") or "alive").strip()
        os_name = (host_el.findtext("os-name") or "").strip()
        os_flavor = (host_el.findtext("os-flavor") or "").strip()
        os_sp = (host_el.findtext("os-sp") or "").strip()
        full_os = " ".join(filter(None, [os_name, os_flavor, os_sp])).strip()
        mac = (host_el.findtext("mac") or "").strip()

        host_key = addr or name
        if host_key and host_key not in hosts:
            hosts.append(host_key)

        services_map: dict[str, dict[str, Any]] = {}
        for svc_el in host_el.findall("./services/service"):
            svc_id = (svc_el.findtext("id") or "").strip()
            port_str = (svc_el.findtext("port") or "").strip()
            try:
                port_num = int(port_str)
            except ValueError:
                port_num = 0
            proto = (svc_el.findtext("proto") or "tcp").strip().lower()
            svc_name = (svc_el.findtext("name") or "").strip()
            svc_state = (svc_el.findtext("state") or "open").strip()
            svc_info = (svc_el.findtext("info") or "").strip()

            if addr and port_num:
                scheme = "https" if port_num == 443 or "https" in svc_name else "http"
                ep_url = f"{scheme}://{addr}:{port_num}"
                key = ("GET", ep_url)
                if key not in seen_endpoints:
                    seen_endpoints.add(key)
                    endpoints.append({"method": "GET", "url": ep_url, "source": f"metasploit:{proto}"})

            svc_record = {
                "id": svc_id,
                "port": port_num,
                "proto": proto,
                "name": svc_name,
                "state": svc_state,
                "info": svc_info,
                "product": svc_name,
                "version": svc_info,
                "banner": svc_info,
                "vulns": [],
                "scripts": [],
            }
            if svc_id:
                services_map[svc_id] = svc_record
            services_map[f"{port_num}/{proto}"] = svc_record

        host_vulns: list[dict[str, Any]] = []
        for vuln_el in host_el.findall("./vulns/vuln"):
            vuln_name = (vuln_el.findtext("name") or "Metasploit Vulnerability").strip()
            info = (vuln_el.findtext("info") or "").strip()
            svc_id_ref = (vuln_el.findtext("service-id") or "").strip()
            port_ref_str = (vuln_el.findtext("port") or "").strip()
            refs = [
                (r.text or "").strip()
                for r in vuln_el.findall("./refs/ref")
                if (r.text or "").strip()
            ]
            cves = [r for r in refs if r.upper().startswith("CVE-")]
            nvt_oid = next((r[4:] for r in refs if r.upper().startswith("OID-")), "")
            sev = _sev_from_info(info)

            vuln_obj = {
                "id": vuln_name,
                "title": vuln_name,
                "severity": sev,
                "description": info,
                "host": addr or name,
                "cve": cves,
                "nvt_oid": nvt_oid,
                "refs": refs,
            }

            matched_svc = services_map.get(svc_id_ref) or services_map.get(f"{port_ref_str}/tcp")
            if matched_svc:
                matched_svc["vulns"].append(vuln_obj)
            else:
                host_vulns.append(vuln_obj)

            findings.append(
                {
                    "title": vuln_name,
                    "severity": sev,
                    "description": info,
                    "host": addr or name,
                    "endpoint": f"{addr}:{port_ref_str}" if port_ref_str else (addr or name),
                    "cve": cves,
                    "nvt_oid": nvt_oid,
                    "refs": refs,
                    "engine": "metasploit",
                }
            )

        for note_el in host_el.findall("./notes/note"):
            ntype = (note_el.findtext("ntype") or "").strip()
            ndata = (note_el.findtext("data") or "").strip()
            svc_id_ref = (note_el.findtext("service-id") or "").strip()
            if "vulners" in ntype.lower():
                for match in re.finditer(r"(CVE-\d{4}-\d+|[A-Za-z0-9_\-\.\/]+:[^\s]+)\s+([\d.]+)\s+(https?://\S+)", ndata):
                    vid, cvss_str, url = match.group(1), match.group(2), match.group(3)
                    try:
                        cvss_f = float(cvss_str)
                    except ValueError:
                        cvss_f = 0.0
                    parsed_v = {
                        "id": vid,
                        "title": vid,
                        "severity": _cvss_to_severity(cvss_f),
                        "cvss": cvss_f,
                        "description": f"Vulnerability {vid} (CVSS {cvss_f})",
                        "refs": [url],
                    }
                    matched_svc = services_map.get(svc_id_ref)
                    if matched_svc:
                        if not any(v.get("id") == vid for v in matched_svc["vulns"]):
                            matched_svc["vulns"].append(parsed_v)
                    else:
                        if not any(v.get("id") == vid for v in host_vulns):
                            host_vulns.append(parsed_v)

        unique_services = []
        seen_svcs = set()
        for s in services_map.values():
            key = f"{s['port']}/{s['proto']}"
            if key not in seen_svcs:
                seen_svcs.add(key)
                unique_services.append(s)

        if addr or name:
            network_hosts.append({
                "ip_address": addr or name,
                "hostname": name if addr else "",
                "status": "up" if state in ("alive", "up", "") else state,
                "os_name": full_os,
                "os_accuracy": "",
                "mac_address": mac,
                "services": sorted(unique_services, key=lambda x: x["port"]),
                "vulns": host_vulns,
                "extra_data": {"source": "metasploit_xml"},
            })

    for wv in root.findall("./web_vulns/web_vuln"):
        host = (wv.findtext("host") or wv.findtext("vhost") or "").strip()
        port = (wv.findtext("port") or "80").strip()
        ssl_flag = (wv.findtext("ssl") or "").strip().lower() in {"true", "1", "yes"}
        path = (wv.findtext("path") or "/").strip() or "/"
        method = (wv.findtext("method") or "GET").strip().upper()
        scheme = "https" if ssl_flag else "http"
        ep_url = f"{scheme}://{host}:{port}{path if path.startswith('/') else '/' + path}" if host else path
        if host and (method, ep_url) not in seen_endpoints:
            seen_endpoints.add((method, ep_url))
            endpoints.append({"method": method, "url": ep_url, "source": "metasploit:web_vuln"})
        findings.append(
            {
                "title": (wv.findtext("name") or "Metasploit Web Vulnerability").strip(),
                "severity": _sev_from_info(wv.findtext("description") or "", wv.findtext("risk") or ""),
                "description": (wv.findtext("description") or "").strip(),
                "host": host,
                "endpoint": ep_url,
                "method": method,
                "parameter": (wv.findtext("pname") or "").strip(),
                "payload": (wv.findtext("proof") or "").strip(),
                "engine": "metasploit",
            }
        )

    return {
        "hosts": hosts,
        "endpoints": endpoints,
        "findings": findings,
        "network_hosts": network_hosts,
    }


def parse_nmap_xml(xml_text: str) -> dict[str, Any]:
    """Parse Nmap XML (<nmaprun>) including open ports, banners, and vulners script."""
    from .openvas_client import safe_fromstring

    cleaned_xml = re.sub(r'<!DOCTYPE\s+nmaprun[^>]*>', '', xml_text, flags=re.IGNORECASE)
    root = safe_fromstring(cleaned_xml)
    if root.tag != "nmaprun" and root.find(".//host") is None:
        raise ValueError("Expected nmaprun XML document")

    findings: list[dict[str, Any]] = []
    endpoints: list[dict[str, Any]] = []
    seen_endpoints: set[tuple[str, str]] = set()
    hosts: list[str] = []
    network_hosts: list[dict[str, Any]] = []

    for host_el in root.findall(".//host"):
        status_el = host_el.find("status")
        status = (status_el.get("state") if status_el is not None else "up") or "up"

        addr = ""
        mac = ""
        for a in host_el.findall("./address"):
            atype = (a.get("addrtype") or "").lower()
            if atype in ("ipv4", "ipv6") and not addr:
                addr = (a.get("addr") or "").strip()
            elif atype == "mac" and not mac:
                mac = (a.get("addr") or "").strip()

        hostnames: list[str] = []
        for h in host_el.findall("./hostnames/hostname"):
            hname = (h.get("name") or "").strip()
            if hname and hname not in hostnames:
                hostnames.append(hname)
        hostname = hostnames[0] if hostnames else ""

        os_match_el = host_el.find(".//osmatch")
        os_name = (os_match_el.get("name") if os_match_el is not None else "") or ""
        os_acc = (os_match_el.get("accuracy") if os_match_el is not None else "") or ""

        host_label = addr or hostname
        if host_label and host_label not in hosts:
            hosts.append(host_label)

        services: list[dict[str, Any]] = []
        host_vulns: list[dict[str, Any]] = []

        for port_el in host_el.findall(".//ports/port"):
            proto = (port_el.get("protocol") or "tcp").strip().lower()
            port_str = (port_el.get("portid") or "").strip()
            try:
                port_num = int(port_str)
            except ValueError:
                continue

            state_el = port_el.find("state")
            state = (state_el.get("state") if state_el is not None else "open") or "open"

            svc_el = port_el.find("service")
            svc_name = (svc_el.get("name") if svc_el is not None else "") or "unknown"
            product = (svc_el.get("product") if svc_el is not None else "") or ""
            version = (svc_el.get("version") if svc_el is not None else "") or ""
            extrainfo = (svc_el.get("extrainfo") if svc_el is not None else "") or ""

            full_version = " ".join(filter(None, [product, version, extrainfo])).strip() or version or product

            if state in ("open", "open|filtered"):
                scheme = "https" if port_num == 443 or "https" in svc_name or "ssl" in svc_name else "http"
                ep_url = f"{scheme}://{host_label}:{port_num}"
                key = ("GET", ep_url)
                if key not in seen_endpoints:
                    seen_endpoints.add(key)
                    endpoints.append({"method": "GET", "url": ep_url, "source": f"nmap:{proto}"})

            port_vulns: list[dict[str, Any]] = []
            scripts: list[dict[str, Any]] = []
            for sc in port_el.findall("./script"):
                sc_id = (sc.get("id") or "").strip()
                sc_out = (sc.get("output") or sc.text or "").strip()
                scripts.append({"id": sc_id, "output": sc_out})
                if sc_id.lower() == "vulners":
                    parsed_vulns = _parse_vulners_output(sc)
                    port_vulns.extend(parsed_vulns)
                    for pv in parsed_vulns:
                        findings.append({
                            "title": pv["title"],
                            "severity": pv["severity"],
                            "description": pv["description"],
                            "host": host_label,
                            "endpoint": f"{host_label}:{port_num}",
                            "cve": [pv["id"]] if pv["id"].startswith("CVE-") else [],
                            "refs": pv.get("refs") or [],
                            "engine": "nmap-vulners",
                        })

            services.append({
                "port": port_num,
                "proto": proto,
                "state": state,
                "name": svc_name,
                "product": product,
                "version": version or full_version,
                "extra_info": extrainfo,
                "banner": full_version,
                "info": full_version or version or product,
                "vulns": port_vulns,
                "scripts": scripts,
            })

        if addr or hostname:
            network_hosts.append({
                "ip_address": addr or hostname,
                "hostname": hostname if addr else "",
                "status": status,
                "os_name": os_name,
                "os_accuracy": f"{os_acc}%" if os_acc else "",
                "mac_address": mac,
                "services": sorted(services, key=lambda x: x["port"]),
                "vulns": host_vulns,
                "extra_data": {"source": "nmap_xml"},
            })

    return {
        "hosts": hosts,
        "endpoints": endpoints,
        "findings": findings,
        "network_hosts": network_hosts,
    }


def parse_network_scan_xml(xml_text: str) -> dict[str, Any]:
    """Auto-detect and parse Metasploit, Nmap or GVM XML."""
    from .openvas_client import safe_fromstring

    cleaned_xml = re.sub(r'<!DOCTYPE\s+nmaprun[^>]*>', '', xml_text, flags=re.IGNORECASE)
    root = safe_fromstring(cleaned_xml)
    tag = (root.tag or "").lower()
    if tag == "nmaprun" or root.find(".//ports") is not None:
        return parse_nmap_xml(cleaned_xml)
    if tag == "metasploitv4" or root.find(".//hosts/host") is not None:
        return parse_metasploit_xml(cleaned_xml)
    if tag in ("report", "get_reports_response") or root.find(".//report") is not None:
        from .openvas_client import parse_openvas_report_xml
        raw_findings = parse_openvas_report_xml(cleaned_xml)
        hosts: list[str] = []
        endpoints: list[dict[str, Any]] = []
        net_hosts_map: dict[str, dict[str, Any]] = {}
        findings: list[dict[str, Any]] = []
        for f in raw_findings:
            h = f.get("host") or ""
            p = f.get("port") or ""
            if h and h not in hosts:
                hosts.append(h)
            port_num = 0
            proto = "tcp"
            if "/" in p:
                parts = p.split("/", 1)
                try:
                    port_num = int(parts[0])
                    proto = parts[1].lower()
                except ValueError:
                    pass
            elif p.isdigit():
                port_num = int(p)

            if h not in net_hosts_map:
                net_hosts_map[h] = {
                    "ip_address": h,
                    "hostname": "",
                    "status": "up",
                    "os_name": "",
                    "os_accuracy": "",
                    "mac_address": "",
                    "services": [],
                    "vulns": [],
                    "extra_data": {"source": "gvm_xml"},
                }
            vuln_item = {
                "id": f.get("title") or "GVM Finding",
                "title": f.get("title") or "GVM Finding",
                "severity": f.get("severity") or "medium",
                "cvss": f.get("cvss") or 0.0,
                "description": f.get("description") or "",
                "cve": f.get("cve") or [],
                "nvt_oid": f.get("nvt_oid") or "",
                "refs": f.get("refs") or [],
            }
            if port_num:
                svcs = net_hosts_map[h]["services"]
                target_svc = next((s for s in svcs if s["port"] == port_num and s["proto"] == proto), None)
                if not target_svc:
                    target_svc = {
                        "port": port_num,
                        "proto": proto,
                        "state": "open",
                        "name": f"port-{port_num}",
                        "product": "",
                        "version": "",
                        "extra_info": "",
                        "banner": "",
                        "vulns": [],
                        "scripts": [],
                    }
                    svcs.append(target_svc)
                target_svc["vulns"].append(vuln_item)
                scheme = "https" if port_num == 443 else "http"
                endpoints.append({"method": "GET", "url": f"{scheme}://{h}:{port_num}", "source": f"gvm:{proto}"})
            else:
                net_hosts_map[h]["vulns"].append(vuln_item)

            findings.append(f)

        return {
            "hosts": hosts,
            "endpoints": endpoints,
            "findings": findings,
            "network_hosts": list(net_hosts_map.values()),
        }

    return parse_metasploit_xml(xml_text)


def save_project_network_hosts(project, network_hosts: list[dict[str, Any]]) -> dict[str, int]:
    """Upsert ProjectHost records and merge services & vulns."""
    from .models import ProjectHost
    created_count = 0
    updated_count = 0
    total_services = 0
    total_vulns = 0

    for item in network_hosts:
        ip = str(item.get("ip_address") or "").strip()
        if not ip:
            continue
        host_obj, created = ProjectHost.objects.get_or_create(
            project=project,
            ip_address=ip,
            defaults={
                "hostname": str(item.get("hostname") or "").strip(),
                "status": str(item.get("status") or "up").strip(),
                "os_name": str(item.get("os_name") or "").strip(),
                "os_accuracy": str(item.get("os_accuracy") or "").strip(),
                "mac_address": str(item.get("mac_address") or "").strip(),
                "services": item.get("services") or [],
                "vulns": item.get("vulns") or [],
                "extra_data": item.get("extra_data") or {},
            }
        )
        if created:
            created_count += 1
        else:
            existing_services = {
                f"{s.get('port')}/{s.get('proto', 'tcp')}": s
                for s in (host_obj.services or [])
                if isinstance(s, dict)
            }
            for s in (item.get("services") or []):
                if isinstance(s, dict):
                    key = f"{s.get('port')}/{s.get('proto', 'tcp')}"
                    if key in existing_services:
                        ex_s = existing_services[key]
                        if s.get("version") and not ex_s.get("version"):
                            ex_s["version"] = s["version"]
                        if s.get("product") and not ex_s.get("product"):
                            ex_s["product"] = s["product"]
                        if s.get("extra_info") and not ex_s.get("extra_info"):
                            ex_s["extra_info"] = s["extra_info"]
                        ex_vuln_ids = {
                            v.get("id") or v.get("title")
                            for v in ex_s.get("vulns", [])
                            if isinstance(v, dict)
                        }
                        for v in (s.get("vulns") or []):
                            if isinstance(v, dict) and (v.get("id") or v.get("title")) not in ex_vuln_ids:
                                ex_s.setdefault("vulns", []).append(v)
                                ex_vuln_ids.add(v.get("id") or v.get("title"))
                    else:
                        existing_services[key] = s
            host_obj.services = list(existing_services.values())
            if item.get("hostname") and not host_obj.hostname:
                host_obj.hostname = item["hostname"]
            if item.get("os_name") and not host_obj.os_name:
                host_obj.os_name = item["os_name"]
            if item.get("mac_address") and not host_obj.mac_address:
                host_obj.mac_address = item["mac_address"]
            host_obj.save(update_fields=["hostname", "os_name", "mac_address", "services", "vulns", "extra_data", "updated_at"])
            updated_count += 1

        total_services += host_obj.open_ports_count
        total_vulns += host_obj.vulns_count

    return {
        "created_hosts": created_count,
        "updated_hosts": updated_count,
        "total_hosts": ProjectHost.objects.filter(project=project).count(),
        "total_services": total_services,
        "total_vulns": total_vulns,
    }

