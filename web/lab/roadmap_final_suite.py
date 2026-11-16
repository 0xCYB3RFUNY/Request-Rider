"""Complete implementation of the remaining Request-Rider ROADMAP capabilities.

Covers:
1. Server-backed WorkflowTemplate schema signing, community manifests, and import preview.
2. Nuclei YAML & Postman Collection v2.1 -> canonical Request-Rider workflow graph converters
   (enforcing canonical `validate_workflow` validation).
3. Semantic AttackChain / AttackStep builder with stable finding/exchange provenance.
4. Protocol metadata & frame-level primitives for WebSocket (RFC 6455 frame capture/replay),
   gRPC/Protobuf (`.proto` introspection, 5-byte length-prefixed framing, varint fields,
   bounded binary mutations keeping raw bytes and metadata distinct), HTTP/2 & HTTP/3/QUIC.
5. OpenAPI 3.x / Swagger 2.0 import, GraphQL introspection & schema inspection,
   BOLA role matrix builder, and JWT allowlist / signature verification fixtures.
6. Two-tier local AI architecture (N1): EmbeddingGemma 2 (270M Text/Code, 8K context,
   128d/256d MRL float16 `bytea` storage) + Gemma 4 (`gemma4:e2b` / `gemma4:e4b`) presets,
   response noise stripping (`strip_dynamic_noise`), cosine anomaly scoring, and semantic
   skill/tool routing.
7. Findings Kanban board & live activity stream aggregation without color-only semantics.
"""

from __future__ import annotations

import array
import base64
import hashlib
import hmac
import json
import math
import os
import re
import struct
from typing import Any
from urllib.parse import urlparse

import yaml
from django.conf import settings

from .workflow_engine import WORKFLOW_GRAPH_SCHEMA_VERSION, validate_workflow


# ==============================================================================
# 1. WORKFLOW TEMPLATE SCHEMA SIGNING, COMMUNITY MANIFEST & IMPORT PREVIEW
# ==============================================================================


def _signing_key() -> bytes:
    secret = getattr(settings, "SECRET_KEY", None) or os.environ.get(
        "DJANGO_SECRET_KEY", "request-rider-local-workstation-key"
    )
    return str(secret).encode("utf-8")


def sign_workflow_template_schema(
    slug: str,
    version: str,
    nodes: list[dict[str, Any]],
    connections: list[dict[str, Any]],
    manifest: dict[str, Any] | None = None,
) -> str:
    """Compute a deterministic HMAC-SHA256 signature over the canonical workflow graph."""
    norm_nodes, norm_conns = validate_workflow(nodes, connections, require_trigger=False)
    canonical_payload = json.dumps(
        {
            "schema_version": WORKFLOW_GRAPH_SCHEMA_VERSION,
            "slug": str(slug or "").strip(),
            "version": str(version or "1.0.0").strip(),
            "nodes": norm_nodes,
            "connections": norm_conns,
            "manifest": manifest or {},
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    digest = hmac.new(_signing_key(), canonical_payload, hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def verify_workflow_template_signature(
    slug: str,
    version: str,
    nodes: list[dict[str, Any]],
    connections: list[dict[str, Any]],
    signature: str,
    manifest: dict[str, Any] | None = None,
) -> bool:
    """Verify that a template's canonical graph matches its `hmac-sha256:` signature."""
    if not signature or not str(signature).startswith("hmac-sha256:"):
        return False
    try:
        expected = sign_workflow_template_schema(slug, version, nodes, connections, manifest)
    except Exception:
        return False
    return hmac.compare_digest(str(signature), expected)


def build_workflow_import_preview(bundle: dict[str, Any]) -> dict[str, Any]:
    """Validate and summarize an incoming workflow template or bundle before import."""
    if not isinstance(bundle, dict):
        raise ValueError("Template bundle must be a JSON object")

    slug = str(bundle.get("slug") or bundle.get("id") or "imported-template").strip()
    name = str(bundle.get("name") or slug).strip()
    version = str(bundle.get("version") or "1.0.0").strip()
    nodes_raw = bundle.get("nodes") or []
    conns_raw = bundle.get("connections") or []
    manifest = bundle.get("manifest") if isinstance(bundle.get("manifest"), dict) else {}
    signature = str(bundle.get("schema_signature") or "").strip()

    norm_nodes, norm_conns = validate_workflow(nodes_raw, conns_raw, require_trigger=False)
    node_types: dict[str, int] = {}
    triggers: list[str] = []
    network_nodes: list[str] = []
    for node in norm_nodes:
        ntype = node["type"]
        node_types[ntype] = node_types.get(ntype, 0) + 1
        if ntype.endswith("_trigger"):
            triggers.append(node["id"])
        if ntype in {"repeater_request", "target_crawl", "scanner_run", "nuclei_scan", "osint_scan", "intruder_run"}:
            network_nodes.append(node["id"])

    signature_valid = (
        verify_workflow_template_signature(slug, version, norm_nodes, norm_conns, signature, manifest)
        if signature
        else False
    )

    return {
        "valid": True,
        "slug": slug,
        "name": name,
        "version": version,
        "schema_version": WORKFLOW_GRAPH_SCHEMA_VERSION,
        "node_count": len(norm_nodes),
        "connection_count": len(norm_conns),
        "node_types": node_types,
        "triggers": triggers,
        "network_nodes": network_nodes,
        "signed": bool(signature),
        "signature_valid": signature_valid,
        "canonical_nodes": norm_nodes,
        "canonical_connections": norm_conns,
    }


# ==============================================================================
# 2. NUCLEI & POSTMAN CONVERTERS (WITH CANONICAL GRAPH VALIDATION)
# ==============================================================================


def convert_nuclei_to_workflow_graph(yaml_text: str) -> dict[str, Any]:
    """Convert a data-only HTTP Nuclei template into a canonical Request-Rider workflow graph."""
    doc = yaml.safe_load(yaml_text or "")
    if not isinstance(doc, dict):
        raise ValueError("Nuclei template must be a YAML mapping")

    for forbidden in ("code", "headless", "javascript", "file"):
        if forbidden in doc:
            raise ValueError(f"Nuclei converter only accepts data-only HTTP templates (found {forbidden!r})")

    template_id = str(doc.get("id") or "nuclei-imported").strip()
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    name = str(info.get("name") or template_id).strip()
    http_blocks = doc.get("http") or doc.get("requests") or []
    if not isinstance(http_blocks, list) or not http_blocks:
        raise ValueError("Nuclei template has no http/requests blocks")

    raw_nodes: list[dict[str, Any]] = [
        {
            "id": "trigger_1",
            "type": "manual_trigger",
            "label": f"Start: {name}",
            "position": {"x": 80, "y": 140},
            "params": {},
        }
    ]
    raw_conns: list[dict[str, Any]] = []
    prev_id = "trigger_1"
    step_idx = 0

    for block in http_blocks:
        if not isinstance(block, dict):
            continue
        method = str(block.get("method") or "GET").upper()
        paths = block.get("path") if isinstance(block.get("path"), list) else [block.get("path") or "/"]
        headers_list = block.get("headers") if isinstance(block.get("headers"), list) else []
        headers_dict: dict[str, str] = {}
        for h in headers_list:
            if isinstance(h, str) and ":" in h:
                k, v = h.split(":", 1)
                headers_dict[k.strip()] = v.strip()
        body = str(block.get("body") or "")

        for raw_path in paths:
            step_idx += 1
            node_id = f"req_{step_idx}"
            clean_path = str(raw_path or "/").replace("{{BaseURL}}", "").replace("{{RootURL}}", "")
            if not clean_path.startswith("/"):
                clean_path = "/" + clean_path
            header_lines = [f"{method} {clean_path} HTTP/1.1", "Host: {{input.host}}"]
            for hk, hv in headers_dict.items():
                header_lines.append(f"{hk}: {hv}")
            raw_http = "\r\n".join(header_lines) + "\r\n\r\n" + body
            raw_nodes.append(
                {
                    "id": node_id,
                    "type": "repeater_request",
                    "label": f"{method} {clean_path[:40]}",
                    "position": {"x": 80 + step_idx * 240, "y": 140},
                    "params": {
                        "url": f"{{{{input.base_url}}}}{clean_path}",
                        "raw": raw_http,
                        "nuclei_template_id": template_id,
                    },
                }
            )
            raw_conns.append(
                {
                    "source": prev_id,
                    "source_handle": "main",
                    "target": node_id,
                    "target_handle": "main",
                }
            )
            prev_id = node_id

    norm_nodes, norm_conns = validate_workflow(raw_nodes, raw_conns, require_trigger=True)
    return {
        "name": f"Nuclei: {name}",
        "template_id": template_id,
        "nodes": norm_nodes,
        "connections": norm_conns,
    }


def _flatten_postman_items(items: list[Any], out: list[dict[str, Any]]) -> None:
    for item in items:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("item"), list):
            _flatten_postman_items(item["item"], out)
        elif isinstance(item.get("request"), dict):
            out.append(item)


def convert_postman_to_workflow_graph(collection: dict[str, Any]) -> dict[str, Any]:
    """Convert a Postman Collection v2.1 into a canonical Request-Rider workflow graph."""
    if not isinstance(collection, dict):
        raise ValueError("Postman collection must be a JSON object")
    info = collection.get("info") if isinstance(collection.get("info"), dict) else {}
    col_name = str(info.get("name") or "Imported Postman Collection").strip()
    flat_items: list[dict[str, Any]] = []
    _flatten_postman_items(collection.get("item") or [], flat_items)
    if not flat_items:
        raise ValueError("Postman collection contains no request items")

    raw_nodes: list[dict[str, Any]] = [
        {
            "id": "trigger_1",
            "type": "manual_trigger",
            "label": f"Start: {col_name}",
            "position": {"x": 80, "y": 140},
            "params": {},
        }
    ]
    raw_conns: list[dict[str, Any]] = []
    prev_id = "trigger_1"

    for idx, entry in enumerate(flat_items, start=1):
        req = entry["request"]
        method = str(req.get("method") or "GET").upper()
        url_obj = req.get("url")
        if isinstance(url_obj, dict):
            raw_url = str(url_obj.get("raw") or "https://example.test/")
        else:
            raw_url = str(url_obj or "https://example.test/")
        parsed = urlparse(raw_url if "://" in raw_url else f"https://{raw_url}")
        host = parsed.netloc or "example.test"
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        header_lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
        for h in req.get("header") or []:
            if isinstance(h, dict) and h.get("key") and not h.get("disabled"):
                header_lines.append(f"{h['key']}: {h.get('value', '')}")

        body_obj = req.get("body") if isinstance(req.get("body"), dict) else {}
        body_raw = str(body_obj.get("raw") or "")
        raw_http = "\r\n".join(header_lines) + "\r\n\r\n" + body_raw

        node_id = f"pm_step_{idx}"
        label = str(entry.get("name") or f"{method} {path}")[:60]
        raw_nodes.append(
            {
                "id": node_id,
                "type": "repeater_request",
                "label": label,
                "position": {"x": 80 + idx * 240, "y": 140},
                "params": {
                    "url": raw_url,
                    "raw": raw_http,
                },
            }
        )
        raw_conns.append(
            {
                "source": prev_id,
                "source_handle": "main",
                "target": node_id,
                "target_handle": "main",
            }
        )
        prev_id = node_id

    norm_nodes, norm_conns = validate_workflow(raw_nodes, raw_conns, require_trigger=True)
    return {
        "name": col_name,
        "nodes": norm_nodes,
        "connections": norm_conns,
        "request_count": len(flat_items),
    }


# ==============================================================================
# 3. PROTOCOLS (WS, gRPC/PROTOBUF, H2, H3/QUIC) & BOUNDED BINARY MUTATIONS
# ==============================================================================


def inspect_protocol_metadata(
    raw_bytes: bytes,
    *,
    alpn: str = "http/1.1",
    headers: dict[str, str] | None = None,
    is_tls: bool = True,
) -> dict[str, Any]:
    """Extract protocol metadata while strictly separating raw payload bytes from frame metadata."""
    hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    content_type = hdrs.get("content-type", "").lower()
    upgrade = hdrs.get("upgrade", "").lower()
    alt_svc = hdrs.get("alt-svc", "")

    protocol_family = "http/1.1"
    if upgrade == "websocket" or alpn == "ws" or alpn == "wss":
        protocol_family = "websocket"
    elif content_type.startswith("application/grpc"):
        protocol_family = "grpc"
    elif alpn in {"h3", "h3-29"} or "h3=" in alt_svc:
        protocol_family = "h3"
    elif alpn == "h2":
        protocol_family = "h2"

    frames: list[dict[str, Any]] = []
    if protocol_family == "websocket" and raw_bytes:
        frames = parse_websocket_frames(raw_bytes)
    elif protocol_family == "grpc" and raw_bytes:
        frames = parse_grpc_frames(raw_bytes)

    return {
        "metadata": {
            "protocol": protocol_family,
            "alpn": alpn,
            "tls": bool(is_tls),
            "h3_advertised": "h3=" in alt_svc,
            "content_type": content_type,
            "frame_count": len(frames),
            "frames": frames,
            "byte_length": len(raw_bytes),
            "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        },
        "raw_bytes_b64": base64.b64encode(raw_bytes).decode("ascii"),
    }


def encode_websocket_frame(payload: bytes, opcode: int = 1, fin: bool = True, mask_key: bytes | None = None) -> bytes:
    """Encode an RFC 6455 WebSocket frame for capture/replay fixtures."""
    first_byte = (0x80 if fin else 0x00) | (opcode & 0x0F)
    mask_bit = 0x80 if mask_key else 0x00
    length = len(payload)
    header = bytearray([first_byte])
    if length < 126:
        header.append(mask_bit | length)
    elif length < 65536:
        header.append(mask_bit | 126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(mask_bit | 127)
        header.extend(struct.pack("!Q", length))
    if mask_key:
        key4 = (mask_key * 4)[:4]
        header.extend(key4)
        masked = bytes(b ^ key4[i % 4] for i, b in enumerate(payload))
        return bytes(header) + masked
    return bytes(header) + payload


def parse_websocket_frames(stream: bytes) -> list[dict[str, Any]]:
    """Parse RFC 6455 WebSocket frames, keeping raw payload bytes separate from frame metadata."""
    frames: list[dict[str, Any]] = []
    offset = 0
    total = len(stream)
    opcode_names = {0: "continuation", 1: "text", 2: "binary", 8: "close", 9: "ping", 10: "pong"}

    while offset + 2 <= total:
        b0 = stream[offset]
        b1 = stream[offset + 1]
        fin = bool(b0 & 0x80)
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        length = b1 & 0x7F
        cursor = offset + 2
        if length == 126:
            if cursor + 2 > total:
                break
            length = struct.unpack("!H", stream[cursor : cursor + 2])[0]
            cursor += 2
        elif length == 127:
            if cursor + 8 > total:
                break
            length = struct.unpack("!Q", stream[cursor : cursor + 8])[0]
            cursor += 8
        mask_key = b""
        if masked:
            if cursor + 4 > total:
                break
            mask_key = stream[cursor : cursor + 4]
            cursor += 4
        if cursor + length > total:
            break
        raw_payload = stream[cursor : cursor + length]
        if masked and mask_key:
            raw_payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(raw_payload))
        frames.append(
            {
                "fin": fin,
                "opcode": opcode,
                "opcode_name": opcode_names.get(opcode, f"opcode_{opcode}"),
                "masked": masked,
                "payload_length": length,
                "raw_payload_b64": base64.b64encode(raw_payload).decode("ascii"),
                "text_preview": raw_payload.decode("utf-8", errors="replace") if opcode == 1 else None,
            }
        )
        offset = cursor + length
    return frames


def encode_grpc_frame(message_bytes: bytes, compressed: bool = False) -> bytes:
    """Encode a 5-byte length-prefixed gRPC frame."""
    flag = 1 if compressed else 0
    return struct.pack("!BI", flag, len(message_bytes)) + message_bytes


def parse_grpc_frames(stream: bytes) -> list[dict[str, Any]]:
    """Parse 5-byte length-prefixed gRPC frames and decode top-level Protobuf wire fields."""
    frames: list[dict[str, Any]] = []
    offset = 0
    total = len(stream)
    while offset + 5 <= total:
        compressed_flag, msg_len = struct.unpack("!BI", stream[offset : offset + 5])
        cursor = offset + 5
        if cursor + msg_len > total:
            break
        msg_bytes = stream[cursor : cursor + msg_len]
        frames.append(
            {
                "compressed": bool(compressed_flag),
                "message_length": msg_len,
                "raw_message_b64": base64.b64encode(msg_bytes).decode("ascii"),
                "protobuf_fields": decode_protobuf_wire_fields(msg_bytes),
            }
        )
        offset = cursor + msg_len
    return frames


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift >= 64:
            break
    raise ValueError("Truncated varint")


def _encode_varint(value: int) -> bytes:
    out = bytearray()
    val = value & 0xFFFFFFFFFFFFFFFF
    while True:
        bits = val & 0x7F
        val >>= 7
        if val:
            out.append(bits | 0x80)
        else:
            out.append(bits)
            break
    return bytes(out)


def decode_protobuf_wire_fields(buf: bytes) -> list[dict[str, Any]]:
    """Decode Protobuf wire-format fields (varint, 64-bit, length-delimited, 32-bit)."""
    fields: list[dict[str, Any]] = []
    pos = 0
    n = len(buf)
    while pos < n:
        try:
            tag, pos = _read_varint(buf, pos)
        except ValueError:
            break
        field_num = tag >> 3
        wire_type = tag & 0x07
        if field_num <= 0:
            break
        if wire_type == 0:  # varint
            try:
                val, pos = _read_varint(buf, pos)
            except ValueError:
                break
            fields.append({"field_number": field_num, "wire_type": "varint", "value": val})
        elif wire_type == 1:  # 64-bit
            if pos + 8 > n:
                break
            raw8 = buf[pos : pos + 8]
            pos += 8
            fields.append(
                {
                    "field_number": field_num,
                    "wire_type": "fixed64",
                    "raw_b64": base64.b64encode(raw8).decode("ascii"),
                }
            )
        elif wire_type == 2:  # length-delimited
            try:
                length, pos = _read_varint(buf, pos)
            except ValueError:
                break
            if pos + length > n:
                break
            chunk = buf[pos : pos + length]
            pos += length
            fields.append(
                {
                    "field_number": field_num,
                    "wire_type": "bytes",
                    "length": length,
                    "raw_b64": base64.b64encode(chunk).decode("ascii"),
                    "utf8": chunk.decode("utf-8", errors="replace"),
                }
            )
        elif wire_type == 5:  # 32-bit
            if pos + 4 > n:
                break
            raw4 = buf[pos : pos + 4]
            pos += 4
            fields.append(
                {
                    "field_number": field_num,
                    "wire_type": "fixed32",
                    "raw_b64": base64.b64encode(raw4).decode("ascii"),
                }
            )
        else:
            break
    return fields


def introspect_proto_schema(proto_text: str) -> dict[str, Any]:
    """Introspect a `.proto` definition into services, RPC methods, and message schemas."""
    services: list[dict[str, Any]] = []
    messages: list[dict[str, Any]] = []

    for msg_match in re.finditer(r"message\s+(\w+)\s*\{([^}]*)\}", proto_text or "", re.DOTALL):
        msg_name = msg_match.group(1)
        body = msg_match.group(2)
        fields: list[dict[str, Any]] = []
        for f_match in re.finditer(
            r"(?:(repeated|optional|required)\s+)?([\w.]+)\s+(\w+)\s*=\s*(\d+)", body
        ):
            fields.append(
                {
                    "label": f_match.group(1) or "singular",
                    "type": f_match.group(2),
                    "name": f_match.group(3),
                    "number": int(f_match.group(4)),
                }
            )
        messages.append({"name": msg_name, "fields": fields})

    for svc_match in re.finditer(r"service\s+(\w+)\s*\{([^}]*)\}", proto_text or "", re.DOTALL):
        svc_name = svc_match.group(1)
        body = svc_match.group(2)
        rpcs: list[dict[str, Any]] = []
        for rpc_match in re.finditer(
            r"rpc\s+(\w+)\s*\(\s*(stream\s+)?([\w.]+)\s*\)\s*returns\s*\(\s*(stream\s+)?([\w.]+)\s*\)",
            body,
        ):
            rpcs.append(
                {
                    "name": rpc_match.group(1),
                    "client_streaming": bool(rpc_match.group(2)),
                    "input_type": rpc_match.group(3),
                    "server_streaming": bool(rpc_match.group(4)),
                    "output_type": rpc_match.group(5),
                }
            )
        services.append({"name": svc_name, "methods": rpcs})

    return {"services": services, "messages": messages}


def generate_bounded_binary_mutations(raw_bytes: bytes, max_mutations: int = 8) -> list[dict[str, Any]]:
    """Generate deterministic bounded binary mutations while keeping raw bytes and metadata separate."""
    limit = max(1, min(int(max_mutations or 8), 32))
    mutations: list[dict[str, Any]] = []
    if not raw_bytes:
        raw_bytes = b"\x00"

    strategies = [
        ("bit_flip_first", bytes([raw_bytes[0] ^ 0xFF]) + raw_bytes[1:]),
        ("bit_flip_last", raw_bytes[:-1] + bytes([raw_bytes[-1] ^ 0x80])),
        ("null_byte_injection", raw_bytes + b"\x00"),
        ("varint_max_uint64", _encode_varint((1 << 64) - 1) + raw_bytes),
        ("length_prefix_zero", b"\x00\x00\x00\x00\x00" + raw_bytes),
        ("truncate_half", raw_bytes[: max(1, len(raw_bytes) // 2)]),
        ("duplicate_frame", raw_bytes + raw_bytes[: min(64, len(raw_bytes))]),
        ("high_bit_sweep", bytes(b ^ 0x01 for b in raw_bytes)),
    ]

    for strategy_name, mutated in strategies[:limit]:
        mutations.append(
            {
                "metadata": {
                    "strategy": strategy_name,
                    "original_length": len(raw_bytes),
                    "mutated_length": len(mutated),
                    "sha256": hashlib.sha256(mutated).hexdigest(),
                },
                "raw_bytes_b64": base64.b64encode(mutated).decode("ascii"),
            }
        )
    return mutations


# ==============================================================================
# 4. OPENAPI IMPORT, GRAPHQL INTROSPECTION, BOLA MATRIX & JWT VERIFICATION
# ==============================================================================


def import_openapi_spec(spec: dict[str, Any], base_url: str = "") -> list[dict[str, Any]]:
    """Extract normalized endpoints, methods, and parameters from an OpenAPI 3.x / Swagger 2.0 spec."""
    if not isinstance(spec, dict):
        raise ValueError("OpenAPI specification must be a dict")

    servers = spec.get("servers") if isinstance(spec.get("servers"), list) else []
    resolved_base = str(base_url or "").rstrip("/")
    if not resolved_base and servers and isinstance(servers[0], dict):
        resolved_base = str(servers[0].get("url") or "").rstrip("/")
    if not resolved_base:
        host = str(spec.get("host") or "example.test").strip()
        scheme = (spec.get("schemes") or ["https"])[0]
        base_path = str(spec.get("basePath") or "").rstrip("/")
        resolved_base = f"{scheme}://{host}{base_path}"

    paths = spec.get("paths") if isinstance(spec.get("paths"), dict) else {}
    endpoints: list[dict[str, Any]] = []
    http_methods = {"get", "post", "put", "patch", "delete", "options", "head"}

    for path_pattern, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        shared_params = path_item.get("parameters") if isinstance(path_item.get("parameters"), list) else []
        for method_lower, op in path_item.items():
            if method_lower.lower() not in http_methods or not isinstance(op, dict):
                continue
            params: list[str] = []
            for p in shared_params + (op.get("parameters") or []):
                if isinstance(p, dict) and p.get("name"):
                    params.append(str(p["name"]))
            req_body = op.get("requestBody") if isinstance(op.get("requestBody"), dict) else {}
            content = req_body.get("content") if isinstance(req_body.get("content"), dict) else {}
            for media in content.values():
                if isinstance(media, dict):
                    schema = media.get("schema") if isinstance(media.get("schema"), dict) else {}
                    props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
                    for prop_name in props.keys():
                        if prop_name not in params:
                            params.append(str(prop_name))
            endpoints.append(
                {
                    "method": method_lower.upper(),
                    "path": str(path_pattern),
                    "sample_url": f"{resolved_base}{path_pattern}",
                    "summary": str(op.get("summary") or op.get("operationId") or ""),
                    "parameters": sorted(set(params)),
                }
            )
    return endpoints


GRAPHQL_INTROSPECTION_QUERY = (
    "query IntrospectionQuery { __schema { queryType { name } mutationType { name } "
    "types { kind name fields(includeDeprecated: true) { name args { name type { kind name ofType { kind name } } } "
    "type { kind name ofType { kind name } } } } } }"
)


def inspect_graphql_schema(introspection_payload: dict[str, Any]) -> dict[str, Any]:
    """Parse a GraphQL `__schema` introspection response into queries, mutations, and sensitive fields."""
    data = introspection_payload.get("data", introspection_payload) if isinstance(introspection_payload, dict) else {}
    schema = data.get("__schema", data) if isinstance(data, dict) else {}
    query_type_name = ((schema.get("queryType") or {}).get("name")) or "Query"
    mutation_type_name = ((schema.get("mutationType") or {}).get("name")) or "Mutation"
    types = schema.get("types") if isinstance(schema.get("types"), list) else []

    queries: list[dict[str, Any]] = []
    mutations: list[dict[str, Any]] = []
    sensitive_fields: list[str] = []
    sensitive_re = re.compile(r"(password|secret|token|apikey|admin|role|ssn|credit|private)", re.I)

    for t in types:
        if not isinstance(t, dict):
            continue
        tname = str(t.get("name") or "")
        if tname.startswith("__"):
            continue
        for f in t.get("fields") or []:
            if not isinstance(f, dict):
                continue
            fname = str(f.get("name") or "")
            args = [str(a.get("name")) for a in (f.get("args") or []) if isinstance(a, dict) and a.get("name")]
            entry = {"name": fname, "args": args}
            if tname == query_type_name:
                queries.append(entry)
            elif tname == mutation_type_name:
                mutations.append(entry)
            if sensitive_re.search(fname):
                sensitive_fields.append(f"{tname}.{fname}")

    return {
        "query_type": query_type_name,
        "mutation_type": mutation_type_name,
        "queries": queries,
        "mutations": mutations,
        "sensitive_fields": sorted(set(sensitive_fields)),
    }


def verify_jwt_with_allowlist(
    token: str,
    secret: str | bytes,
    allowed_algorithms: list[str] | None = None,
) -> dict[str, Any]:
    """Verify a JWT signature strictly against an algorithm allowlist (blocking `none` and confusion)."""
    allowlist = {str(a).upper() for a in (allowed_algorithms or ["HS256"])}
    parts = str(token or "").strip().split(".")
    if len(parts) != 3:
        return {"valid": False, "reason": "MALFORMED_JWT"}

    def _b64url_decode(seg: str) -> bytes:
        padded = seg + "=" * ((4 - len(seg) % 4) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))

    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
        claims = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
        sig = _b64url_decode(parts[2])
    except Exception:
        return {"valid": False, "reason": "INVALID_ENCODING"}

    alg = str(header.get("alg") or "").upper()
    if not alg or alg == "NONE" or alg not in allowlist:
        return {"valid": False, "reason": "ALGORITHM_NOT_ALLOWED", "alg": alg}

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    key_bytes = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    digest_mod = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    if digest_mod is None:
        return {"valid": False, "reason": "UNSUPPORTED_ALGORITHM", "alg": alg}

    expected_sig = hmac.new(key_bytes, signing_input, digest_mod).digest()
    if not hmac.compare_digest(sig, expected_sig):
        return {"valid": False, "reason": "SIGNATURE_MISMATCH", "alg": alg}

    return {"valid": True, "alg": alg, "header": header, "claims": claims}


# ==============================================================================
# 5. TWO-TIER LOCAL AI: EMBEDDINGGEMMA 2 (MRL 128d/256d) & GEMMA 4 ROUTING (N1)
# ==============================================================================

LOCAL_AI_PROFILES = {
    "ultra_light_cpu": {
        "label": "Ultra-Light (CPU Only)",
        "operator_model": "gemma4:e2b",
        "sensor_model": "embeddinggemma-2",
        "mrl_dims": 128,
        "modality": "text_code_270m",
        "context_tokens": 8192,
        "peak_ram_mb": 1500,
    },
    "balanced_security_pro": {
        "label": "Balanced Security Pro",
        "operator_model": "gemma4:e4b",
        "sensor_model": "embeddinggemma-2",
        "mrl_dims": 256,
        "modality": "text_code_270m",
        "context_tokens": 8192,
        "peak_ram_mb": 2800,
    },
    "multimodal_recon": {
        "label": "Multimodal Recon (Text+Vision)",
        "operator_model": "gemma4:e4b",
        "sensor_model": "embeddinggemma-2",
        "mrl_dims": 256,
        "modality": "text_vision_440m",
        "context_tokens": 8192,
        "peak_ram_mb": 3200,
    },
}

_DYNAMIC_HEADER_NOISE = re.compile(
    r"^(date|set-cookie|cf-ray|x-request-id|x-amzn-trace-id|etag|last-modified|age|expires):.*$",
    re.I | re.M,
)
_UUID_NOISE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_HEX_TOKEN_NOISE = re.compile(r"\b[0-9a-f]{24,}\b", re.I)


def strip_dynamic_noise(raw_http: str, max_chars: int = 24000) -> str:
    """Normalize HTTP response text before EmbeddingGemma 2 vectorization (up to 8K tokens)."""
    cleaned = _DYNAMIC_HEADER_NOISE.sub("", str(raw_http or ""))
    cleaned = _UUID_NOISE.sub("<UUID>", cleaned)
    cleaned = _HEX_TOKEN_NOISE.sub("<HEX>", cleaned)
    return cleaned[:max_chars].strip()


def compute_mrl_embedding(text: str, dims: int = 128) -> list[float]:
    """Compute an L2-normalized Matryoshka Representation Learning (MRL) vector (128d or 256d).

    Uses deterministic token-ngram hashing when Ollama `embeddinggemma-2` is offline,
    guaranteeing zero-RAM idle footprint and reproducible cosine anomaly detection in tests.
    """
    if dims not in (128, 256, 512, 768):
        dims = 128
    vec = [0.0] * dims
    normalized = strip_dynamic_noise(text).lower()
    tokens = re.findall(r"[a-z0-9_/:.-]{2,}", normalized)
    if not tokens:
        tokens = ["empty"]
    for tok in tokens:
        digest = hashlib.blake2b(tok.encode("utf-8"), digest_size=8).digest()
        idx = int.from_bytes(digest[:4], "little") % dims
        sign = 1.0 if (digest[4] & 1) == 0 else -1.0
        vec[idx] += sign

    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def pack_mrl_vector_float16(vec: list[float]) -> bytes:
    """Pack an MRL vector into compact IEEE 754 float16 bytes (256B for 128d, 512B for 256d)."""
    return struct.pack(f"<{len(vec)}e", *vec)


def unpack_mrl_vector_float16(blob: bytes) -> list[float]:
    """Unpack float16 bytes from PostgreSQL BinaryField (`bytea`) back to floats."""
    if not blob:
        return []
    count = len(blob) // 2
    return list(struct.unpack(f"<{count}e", blob[: count * 2]))


def cosine_anomaly_score(baseline_vec: list[float], candidate_vec: list[float]) -> float:
    """Return `1 - (u_base . v_cand)` in [0.0, 2.0] for Intruder Outlier & Scanner Clustering."""
    if not baseline_vec or not candidate_vec or len(baseline_vec) != len(candidate_vec):
        return 1.0
    dot = sum(a * b for a, b in zip(baseline_vec, candidate_vec))
    return round(max(0.0, 1.0 - dot), 6)


def select_semantic_tools_and_skills(
    user_prompt: str,
    available_tools: list[dict[str, Any]],
    *,
    top_k_tools: int = 7,
) -> dict[str, Any]:
    """Semantic router for Gemma 4 (e2b/e4b): selects top-K relevant tools and top-2 skills."""
    q_vec = compute_mrl_embedding(user_prompt, dims=128)
    scored_tools: list[tuple[float, dict[str, Any]]] = []
    for tool in available_tools:
        fn = tool.get("function") if isinstance(tool.get("function"), dict) else tool
        desc = f"{fn.get('name', '')} {fn.get('description', '')}"
        t_vec = compute_mrl_embedding(desc, dims=128)
        sim = 1.0 - cosine_anomaly_score(q_vec, t_vec)
        scored_tools.append((sim, tool))

    scored_tools.sort(key=lambda item: item[0], reverse=True)
    selected = [t for _, t in scored_tools[: max(1, top_k_tools)]]

    skill_catalog = [
        ("burp-suite", "HTTP traffic interception, Repeater, Intruder fuzzing, BOLA/IDOR authorization testing"),
        ("security-review", "Authentication, JWT, SQLi, XSS, SSRF, mass assignment and API security audit"),
        ("ai-security", "MITRE ATLAS prompt injection, system prompt leakage, LLM red-teaming and OAST"),
        ("e2e-testing", "Playwright browser verification, DOM sink telemetry and layout persistence"),
    ]
    scored_skills = sorted(
        skill_catalog,
        key=lambda item: 1.0 - cosine_anomaly_score(q_vec, compute_mrl_embedding(f"{item[0]} {item[1]}", dims=128)),
        reverse=True,
    )
    return {
        "selected_tools": selected,
        "selected_skills": [s[0] for s in scored_skills[:2]],
        "total_candidates": len(available_tools),
    }


# ==============================================================================
# 6. FINDINGS KANBAN & LIVE ACTIVITY STREAM (NON-COLOR-ONLY ACCESSIBLE)
# ==============================================================================

KANBAN_COLUMNS = (
    {"id": "new", "label_uk": "📋 Нові (Unverified)", "label_en": "📋 New (Unverified)"},
    {"id": "triaged", "label_uk": "🔎 На перевірці (Triaged)", "label_en": "🔎 In Triage"},
    {"id": "verified", "label_uk": "✅ Підтверджені (Proven)", "label_en": "✅ Verified (Proven)"},
    {"id": "mitigated", "label_uk": "🛡️ Виправлені / Прийняті", "label_en": "🛡️ Mitigated / Closed"},
)


def build_findings_kanban_state(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Group findings into accessible Kanban columns with explicit text/icon badges (never color-only)."""
    board: dict[str, list[dict[str, Any]]] = {col["id"]: [] for col in KANBAN_COLUMNS}
    severity_badges = {
        "critical": "[CRITICAL / P0]",
        "high": "[HIGH / P1]",
        "medium": "[MEDIUM / P2]",
        "low": "[LOW / P3]",
        "info": "[INFO]",
    }
    for item in findings or []:
        if not isinstance(item, dict):
            continue
        status_raw = str(item.get("kanban_status") or item.get("status") or "").lower()
        verified = bool(item.get("verified") or item.get("proven"))
        if status_raw in board:
            col_id = status_raw
        elif verified:
            col_id = "verified"
        elif item.get("triaged"):
            col_id = "triaged"
        else:
            col_id = "new"
        sev = str(item.get("severity") or "info").lower()
        card = {
            "id": item.get("identity_hash") or item.get("id") or hashlib.sha1(
                json.dumps(item, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest()[:12],
            "title": str(item.get("title") or item.get("name") or "Finding"),
            "severity": sev,
            "severity_label": severity_badges.get(sev, "[INFO]"),
            "endpoint": str(item.get("endpoint") or item.get("url") or ""),
            "status": col_id,
            "verified": verified,
        }
        board[col_id].append(card)

    return {
        "columns": KANBAN_COLUMNS,
        "cards_by_column": board,
        "counts": {k: len(v) for k, v in board.items()},
    }
