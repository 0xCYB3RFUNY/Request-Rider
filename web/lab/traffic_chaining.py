"""Stateful Traffic Correlation & Auto-Chaining for Request-Rider Automation."""
from __future__ import annotations

import base64
import html
import json
import re
from typing import Any
from urllib.parse import parse_qsl, quote, urlsplit

_MIN_TOKEN_LEN = 4
_INTERESTING_HEADERS = {
    "x-csrf-token",
    "x-xsrf-token",
    "csrf-token",
    "authorization",
    "x-auth-token",
    "x-session-id",
    "etag",
    "x-request-id",
}

_INPUT_TAG_RE = re.compile(r"<input\b([^>]+)>", re.IGNORECASE)
_META_TAG_RE = re.compile(r"<meta\b([^>]+)>", re.IGNORECASE)
_ATTR_RE = re.compile(r'([a-zA-Z0-9_:-]+)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))')


def _parse_attrs(attr_str: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for match in _ATTR_RE.finditer(attr_str):
        key = match.group(1).lower()
        val = match.group(2) if match.group(2) is not None else (
            match.group(3) if match.group(3) is not None else (match.group(4) or "")
        )
        attrs[key] = html.unescape(val)
    return attrs


def _sanitize_key(raw: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_]+", "_", raw.strip()).strip("_").lower()
    return cleaned or "val"


def _parse_set_cookie_pairs(headers: dict[str, Any]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for key, raw_val in headers.items():
        if str(key).strip().lower() != "set-cookie":
            continue
        items = raw_val if isinstance(raw_val, list) else [str(raw_val)]
        for header_val in items:
            # Handle comma-joined Set-Cookie headers while avoiding Expires=Mon, ...
            chunks = re.split(r",(?=\s*[A-Za-z0-9_.-]+=)", str(header_val))
            for chunk in chunks:
                first_part = chunk.split(";", 1)[0].strip()
                if "=" in first_part:
                    c_name, c_val = first_part.split("=", 1)
                    c_name = c_name.strip()
                    c_val = c_val.strip()
                    if c_name and c_val:
                        pairs.append((c_name, c_val))
    return pairs


def _flatten_json(obj: Any, prefix: str = "", depth: int = 0) -> list[tuple[str, str]]:
    if depth > 5:
        return []
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            next_prefix = f"{prefix}.{k}" if prefix else str(k)
            out.extend(_flatten_json(v, next_prefix, depth + 1))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj[:5]):
            next_prefix = f"{prefix}[{idx}]"
            out.extend(_flatten_json(item, next_prefix, depth + 1))
    elif isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
        text = str(obj)
        key_lower = prefix.lower()
        is_id_field = key_lower.endswith(("id", "token", "key", "secret", "csrf", "nonce", "session", "code"))
        if len(text) >= _MIN_TOKEN_LEN or (is_id_field and len(text) >= 1):
            out.append((prefix, text))
    return out


def extract_response_artifacts(exchange: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract candidate tokens, cookies, headers, JSON fields, and hidden inputs from an exchange response."""
    headers = exchange.get("response_headers") or exchange.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    body = str(exchange.get("response_body") or exchange.get("body") or "")

    artifacts: list[dict[str, Any]] = []
    seen_keys: set[str] = set()

    def add_artifact(key: str, source: str, path: str, value: str) -> None:
        val = str(value or "").strip()
        if not val:
            return
        safe_key = _sanitize_key(key)
        base_key = safe_key
        counter = 2
        while safe_key in seen_keys:
            safe_key = f"{base_key}_{counter}"
            counter += 1
        seen_keys.add(safe_key)
        b64_val = base64.b64encode(val.encode("utf-8", errors="replace")).decode("ascii")
        url_val = quote(val, safe="")
        artifacts.append({
            "key": safe_key,
            "source": source,
            "path": path,
            "value": val,
            "variants": [
                (val, "raw"),
                (url_val, "url"),
                (b64_val, "base64"),
            ],
        })

    # 1. Set-Cookie
    for c_name, c_val in _parse_set_cookie_pairs(headers):
        add_artifact(f"cookie_{c_name}", "set_cookie", c_name, c_val)

    # 2. Interesting Headers & Location query params
    for h_name, h_val in headers.items():
        h_lower = str(h_name).strip().lower()
        h_text = str(h_val or "").strip()
        if not h_text:
            continue
        if h_lower in _INTERESTING_HEADERS and len(h_text) >= _MIN_TOKEN_LEN:
            add_artifact(f"hdr_{h_lower}", "header", str(h_name), h_text)
        elif h_lower == "location":
            parsed_loc = urlsplit(h_text)
            for qk, qv in parse_qsl(parsed_loc.query):
                if len(qv) >= _MIN_TOKEN_LEN:
                    add_artifact(f"loc_{qk}", "location_query", qk, qv)

    # 3. JSON body fields
    stripped = body.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            parsed_json = json.loads(stripped)
            for j_path, j_val in _flatten_json(parsed_json):
                add_artifact(j_path, "json", j_path, j_val)
        except (ValueError, TypeError):
            pass

    # 4. HTML hidden inputs & meta csrf-token
    if "<input" in body.lower() or "<meta" in body.lower():
        for match in _INPUT_TAG_RE.finditer(body):
            attrs = _parse_attrs(match.group(1))
            if attrs.get("type", "").lower() == "hidden" and attrs.get("name") and attrs.get("value"):
                add_artifact(attrs["name"], "html_input", attrs["name"], attrs["value"])
        for match in _META_TAG_RE.finditer(body):
            attrs = _parse_attrs(match.group(1))
            meta_name = attrs.get("name", "").lower()
            if "csrf" in meta_name or "token" in meta_name:
                if attrs.get("content"):
                    add_artifact(meta_name, "html_meta", attrs["name"], attrs["content"])

    # Prefer longer, more specific values first to avoid accidental substring collisions
    artifacts.sort(key=lambda item: len(item["value"]), reverse=True)
    return artifacts


def _extract_json_path(obj: Any, path: str) -> Any:
    current = obj
    tokens = re.findall(r"([^.\[\]]+)|\[(\d+)\]", path)
    for key_part, idx_part in tokens:
        if key_part:
            if isinstance(current, dict) and key_part in current:
                current = current[key_part]
            else:
                return None
        elif idx_part:
            idx = int(idx_part)
            if isinstance(current, list) and 0 <= idx < len(current):
                current = current[idx]
            else:
                return None
    return current


def apply_response_extractors(response_data: dict[str, Any], extract_rules: list[dict[str, Any]]) -> dict[str, str]:
    """Evaluate extraction rules against a live HTTP response during workflow execution."""
    if not isinstance(response_data, dict) or not isinstance(extract_rules, list):
        return {}
    headers = response_data.get("headers") or response_data.get("response_headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    body = str(response_data.get("body") or response_data.get("response_body") or "")

    extracted: dict[str, str] = {}
    parsed_json: Any = None
    json_loaded = False

    for rule in extract_rules:
        if not isinstance(rule, dict):
            continue
        key = str(rule.get("key") or "").strip()
        source = str(rule.get("source") or "").strip()
        path = str(rule.get("path") or "").strip()
        if not key or not source or not path:
            continue

        if source == "set_cookie":
            for c_name, c_val in _parse_set_cookie_pairs(headers):
                if c_name == path:
                    extracted[key] = c_val
                    break
        elif source == "header":
            for hk, hv in headers.items():
                if str(hk).strip().lower() == path.lower():
                    extracted[key] = str(hv)
                    break
        elif source == "location_query":
            for hk, hv in headers.items():
                if str(hk).strip().lower() == "location":
                    for qk, qv in parse_qsl(urlsplit(str(hv)).query):
                        if qk == path:
                            extracted[key] = qv
                            break
        elif source == "json":
            if not json_loaded:
                json_loaded = True
                try:
                    parsed_json = json.loads(body)
                except (ValueError, TypeError):
                    parsed_json = None
            if parsed_json is not None:
                val = _extract_json_path(parsed_json, path)
                if val is not None:
                    extracted[key] = str(val)
        elif source == "html_input":
            for match in _INPUT_TAG_RE.finditer(body):
                attrs = _parse_attrs(match.group(1))
                if attrs.get("name") == path and "value" in attrs:
                    extracted[key] = attrs["value"]
                    break
        elif source == "html_meta":
            for match in _META_TAG_RE.finditer(body):
                attrs = _parse_attrs(match.group(1))
                if attrs.get("name", "").lower() == path.lower() and "content" in attrs:
                    extracted[key] = attrs["content"]
                    break

    return extracted


def _replace_with_expr(text: str, variants: list[tuple[str, str]], expr: str) -> tuple[str, bool]:
    if not text:
        return text, False
    for variant, _encoding in variants:
        if len(variant) >= _MIN_TOKEN_LEN and variant in text:
            return text.replace(variant, expr), True
    return text, False


def build_workflow_from_exchanges(exchanges: list[dict[str, Any]], workflow_name: str = "Auto-Chained Flow") -> dict[str, Any]:
    """Correlate a sequence of HTTP exchanges into a parameterized Automation Workflow DAG."""
    if len(exchanges) < 2:
        raise ValueError("at least 2 exchanges are required to build a correlated chain")
    if len(exchanges) > 15:
        exchanges = exchanges[:15]

    nodes: list[dict[str, Any]] = [
        {
            "id": "trigger_1",
            "type": "manual_trigger",
            "name": "Manual Trigger",
            "position": {"x": 80, "y": 140},
            "params": {},
            "disabled": False,
        }
    ]
    connections: list[dict[str, Any]] = []
    correlations: list[dict[str, Any]] = []

    step_artifacts: list[list[dict[str, Any]]] = []
    step_extractors: list[list[dict[str, Any]]] = [[] for _ in exchanges]
    step_extractor_keys: list[set[str]] = [set() for _ in exchanges]

    for idx, exch in enumerate(exchanges):
        step_id = f"step_{idx + 1}"
        method = str(exch.get("method") or "GET").upper()
        url = str(exch.get("url") or "").strip()
        raw_headers = exch.get("request_headers") or exch.get("headers") or {}
        headers = {str(k): str(v) for k, v in raw_headers.items()} if isinstance(raw_headers, dict) else {}
        body = str(exch.get("request_body") if exch.get("request_body") is not None else (exch.get("body") or ""))

        # Correlate against all prior steps' response artifacts (most recent step first)
        for prev_idx in range(idx - 1, -1, -1):
            prev_step_id = f"step_{prev_idx + 1}"
            for art in step_artifacts[prev_idx]:
                expr = f"{{{{nodes.{prev_step_id}.extracted.{art['key']}}}}}"
                used = False

                new_url, hit_url = _replace_with_expr(url, art["variants"], expr)
                if hit_url:
                    url = new_url
                    used = True

                for hk, hv in list(headers.items()):
                    new_hv, hit_hdr = _replace_with_expr(hv, art["variants"], expr)
                    if hit_hdr:
                        headers[hk] = new_hv
                        used = True

                new_body, hit_body = _replace_with_expr(body, art["variants"], expr)
                if hit_body:
                    body = new_body
                    used = True

                if used:
                    if art["key"] not in step_extractor_keys[prev_idx]:
                        step_extractor_keys[prev_idx].add(art["key"])
                        step_extractors[prev_idx].append({
                            "key": art["key"],
                            "source": art["source"],
                            "path": art["path"],
                        })
                    correlations.append({
                        "from_step": prev_step_id,
                        "to_step": step_id,
                        "key": art["key"],
                        "source": art["source"],
                        "path": art["path"],
                    })

        parsed_url = urlsplit(url)
        short_label = f"{method} {parsed_url.path or '/'}"
        node = {
            "id": step_id,
            "type": "repeater",
            "name": short_label[:48],
            "position": {"x": 320 + idx * 260, "y": 140},
            "params": {
                "method": method,
                "url": url,
                "headers": headers,
                "body": body,
                "delay_ms": 0,
                "extract": [],
            },
            "disabled": False,
        }
        nodes.append(node)
        step_artifacts.append(extract_response_artifacts(exch))

        prev_node_id = "trigger_1" if idx == 0 else f"step_{idx}"
        connections.append({
            "source": prev_node_id,
            "target": step_id,
            "source_handle": "main",
            "target_handle": "main",
        })

    # Populate extract rules onto source repeater nodes
    for idx, extract_list in enumerate(step_extractors):
        if extract_list:
            nodes[idx + 1]["params"]["extract"] = extract_list

    return {
        "name": workflow_name,
        "nodes": nodes,
        "connections": connections,
        "correlations": correlations,
    }
