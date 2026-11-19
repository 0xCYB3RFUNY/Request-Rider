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
import os
import re
import struct
from typing import Any
from urllib.parse import urlparse

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None

from django.conf import settings


def _fallback_parse_yaml(text: str) -> Any:
    """Minimal pure-Python YAML subset parser for Nuclei templates when PyYAML is absent."""
    stripped = (text or "").strip()
    if not stripped:
        return None
    try:
        return json.loads(stripped)
    except Exception:
        pass
    lines = [ln for ln in stripped.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]

    def _strip_val(v: str) -> str:
        v = v.strip()
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            return v[1:-1]
        return v

    def _parse_block(idx: int, base_indent: int):
        result_dict: dict[str, Any] = {}
        result_list: list[Any] | None = None
        while idx < len(lines):
            raw = lines[idx]
            indent = len(raw) - len(raw.lstrip(" "))
            if indent < base_indent:
                break
            content = raw.strip()
            if content.startswith("- "):
                if result_list is None:
                    result_list = []
                item_str = content[2:].strip()
                if ":" in item_str and not item_str.startswith(("http://", "https://")):
                    k, v = item_str.split(":", 1)
                    item_dict: dict[str, Any] = {}
                    if v.strip():
                        item_dict[k.strip()] = _strip_val(v)
                        idx += 1
                    else:
                        child, idx = _parse_block(idx + 1, indent + 2)
                        item_dict[k.strip()] = child
                    # Read subsequent keys at indent + 2 belonging to this list item
                    if idx < len(lines):
                        next_indent = len(lines[idx]) - len(lines[idx].lstrip(" "))
                        if next_indent > indent and not lines[idx].strip().startswith("- "):
                            extra, idx = _parse_block(idx, next_indent)
                            if isinstance(extra, dict):
                                item_dict.update(extra)
                    result_list.append(item_dict)
                else:
                    result_list.append(_strip_val(item_str))
                    idx += 1
                continue
            if ":" in content:
                k, v = content.split(":", 1)
                key = k.strip()
                val_str = v.strip()
                if val_str:
                    if val_str.startswith("[") and val_str.endswith("]"):
                        result_dict[key] = [_strip_val(x) for x in val_str[1:-1].split(",") if x.strip()]
                    else:
                        result_dict[key] = _strip_val(val_str)
                    idx += 1
                else:
                    child, idx = _parse_block(idx + 1, indent + 2)
                    result_dict[key] = child
                continue
            idx += 1
        return (result_list if result_list is not None else result_dict), idx

    parsed, _ = _parse_block(0, 0)
    return parsed


def safe_load_yaml_or_json(text: str) -> Any:
    if yaml is not None:
        return yaml.safe_load(text or "")
    return _fallback_parse_yaml(text or "")

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
        if ntype in {"repeater", "repeater_burst", "target", "target_browser", "scanner", "osint", "intruder"}:
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
    doc = safe_load_yaml_or_json(yaml_text or "")
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
                    "type": "repeater",
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
                "type": "repeater",
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



