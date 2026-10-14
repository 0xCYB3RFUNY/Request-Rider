"""Tool Registry and JSON Schemas for the Request-Rider Autonomous AI Agent.

Implements MCP / OpenAI-compatible tool specifications and execution handlers
connecting the agent loop with Request-Rider proxy, traffic history, intruder, and project hub.
"""

import base64
import json
import logging
import secrets
import string
import urllib.parse
from urllib.parse import urlsplit

from django.utils import timezone

logger = logging.getLogger(__name__)

# --- Tool JSON Schemas (MCP / OpenAI function calling standard) ---

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "history_search",
            "description": "Пошук перехоплених HTTP-запитів та відповідей у базі історії трафіку проекту за ключовими словами, методом або статусом.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Рядок для пошуку в URL, заголовках чи тілі запиту/відповіді."
                    },
                    "method": {
                        "type": "string",
                        "description": "HTTP метод (GET, POST, PUT, DELETE тощо)."
                    },
                    "status_code": {
                        "type": "integer",
                        "description": "HTTP статус-код (наприклад 200, 302, 401, 500)."
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Максимальна кількість результатів (за замовчуванням 10, максимум 50).",
                        "default": 10
                    }
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "request_send",
            "description": "Відправка сирого HTTP-запиту через рушій Request-Rider та збереження відповіді в історії. Чутлива дія.",
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {
                        "type": "string",
                        "description": "HTTP метод (GET, POST, PUT тощо).",
                        "default": "GET"
                    },
                    "url": {
                        "type": "string",
                        "description": "Повний цільовий URL (наприклад https://example.com/api/v1/user)."
                    },
                    "headers": {
                        "type": "object",
                        "description": "Словник HTTP-заголовків (наприклад {'Authorization': 'Bearer ...'}).",
                        "additionalProperties": {"type": "string"}
                    },
                    "body": {
                        "type": "string",
                        "description": "Тіло запиту (POST/PUT payload).",
                        "default": ""
                    }
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "finding_record",
            "description": "Фіксація підтвердженої або потенційної вразливості в Project Hub / Findings.",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Коротка та чітка назва знахідки (наприклад 'IDOR in /api/user/profile' або 'Missing Rate Limiting')."
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        "description": "Рівень критичності вразливості."
                    },
                    "description": {
                        "type": "string",
                        "description": "Детальний опис виявленої проблеми, вектор атаки та спостережувана аномалія."
                    },
                    "evidence_url": {
                        "type": "string",
                        "description": "URL або ендпоінт, де підтверджено вразливість."
                    },
                    "remediation": {
                        "type": "string",
                        "description": "Рекомендації щодо усунення вразливості."
                    }
                },
                "required": ["title", "severity", "description"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "url_encode",
            "description": "URL-кодування тексту або спецсимволів пейлоаду.",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Текст для кодування"},
                    "plus": {"type": "boolean", "description": "Використовувати '+' замість '%20'", "default": False}
                },
                "required": ["text"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "url_decode",
            "description": "URL-декодування рядка або пейлоаду.",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "URL-закодований рядок"},
                    "plus": {"type": "boolean", "description": "Декодувати '+' як пробіл", "default": False}
                },
                "required": ["text"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "base64_encode",
            "description": "Base64 кодування тексту або пейлоаду.",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Текст для кодування"},
                    "url_safe": {"type": "boolean", "description": "Використовувати URL-безпечний Base64", "default": False}
                },
                "required": ["text"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "base64_decode",
            "description": "Base64 декодування рядка в текст.",
            "parameters": {
                "type": "object",
                "properties": {
                    "encoded": {"type": "string", "description": "Base64 рядок"},
                    "url_safe": {"type": "boolean", "description": "Чи закодовано в URL-безпечному форматі", "default": False}
                },
                "required": ["encoded"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "random_string",
            "description": "Генерація криптостійкого випадкового рядка потрібної довжини (токени, маркери ін'єкцій).",
            "parameters": {
                "type": "object",
                "properties": {
                    "length": {"type": "integer", "description": "Довжина рядка", "default": 16},
                    "charset": {
                        "type": "string",
                        "enum": ["alphanumeric", "hex", "alpha", "digits", "special"],
                        "description": "Символьний набір",
                        "default": "alphanumeric"
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "normalize_http",
            "description": "Нормалізація сирого HTTP запиту: заголовки отримують правильні CRLF переноси, а тіло зберігається без спотворень.",
            "parameters": {
                "type": "object",
                "properties": {
                    "raw_http": {"type": "string", "description": "Сирий текст HTTP запиту"}
                },
                "required": ["raw_http"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "oob_generate",
            "description": "Генерація Out-of-Band (OOB) колбека та пейлоадів для виявлення Blind SSRF/XXE/RCE.",
            "parameters": {
                "type": "object",
                "properties": {
                    "tag": {"type": "string", "description": "Мітка тесту"}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "oob_poll",
            "description": "Перевірка зворотних викликів (interactions) в історії трафіку для вказаного OOB-токена.",
            "parameters": {
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "OOB токен"}
                },
                "required": ["token"]
            }
        }
    }
]


# --- Tool Implementation Handlers ---

def tool_history_search(arguments, context=None):
    """Search traffic records in the database."""
    from .models import TrafficRecord, ProjectExchange

    query = str(arguments.get("query") or "").strip()
    method = str(arguments.get("method") or "").strip().upper()
    status_code = arguments.get("status_code")
    limit = min(max(1, int(arguments.get("limit") or 10)), 50)

    project = getattr(context, "active_project", None) if context else None

    # Filter TrafficRecord
    qs = TrafficRecord.objects.all()
    if project:
        qs = qs.filter(project=project)
    if method:
        qs = qs.filter(method=method)
    if status_code is not None:
        try:
            qs = qs.filter(status_code=int(status_code))
        except (TypeError, ValueError):
            pass
    if query:
        from django.db.models import Q
        qs = qs.filter(Q(url__icontains=query) | Q(host__icontains=query) | Q(request_body__icontains=query))

    records = list(qs.order_by("-timestamp", "-id")[:limit])

    results = []
    for r in records:
        results.append({
            "id": r.id,
            "method": r.method,
            "url": r.url,
            "status_code": r.status_code,
            "latency_ms": r.latency_ms,
            "response_size": r.response_size,
            "host": r.host,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        })

    return {
        "status": "success",
        "count": len(results),
        "results": results,
    }


def tool_request_send(arguments, context=None):
    """Execute raw HTTP request via Request-Rider engine and record traffic."""
    from .models import TrafficRecord
    from .views import call_engine, normalize_payload, InvalidRequestPayload

    url = str(arguments.get("url") or "").strip()
    if not url:
        return {"status": "error", "message": "URL is required"}

    method = str(arguments.get("method") or "GET").strip().upper()
    headers = arguments.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    body = str(arguments.get("body") or "")

    raw_payload = {
        "method": method,
        "url": url,
        "headers": headers,
        "body": body,
    }

    try:
        normalized = normalize_payload(raw_payload)
        project = getattr(context, "active_project", None) if context else None

        status, engine_res = call_engine("/proxy/request", normalized)
        if not isinstance(engine_res, dict):
            return {"status": "error", "engine_status": status, "message": "Engine returned non-dict response"}

        # Persist response in TrafficRecord if status present
        if status == 200 and engine_res.get("status") is not None:
            TrafficRecord.objects.create(
                project=project,
                source="ai_agent",
                origin="agent_tool",
                host=urlsplit(url).netloc,
                method=method,
                url=url,
                request_headers=normalized.get("headers", {}),
                request_body=normalized.get("body", ""),
                source_ip=engine_res.get("source_ip") or None,
                response_headers=engine_res.get("headers", {}),
                response_body=engine_res.get("body", ""),
                response_body_encoding=engine_res.get("body_encoding", "utf8"),
                status_code=engine_res.get("status"),
                latency_ms=engine_res.get("time"),
                response_size=engine_res.get("size"),
            )

        return {
            "status": "success",
            "http_status": engine_res.get("status"),
            "latency_ms": engine_res.get("time"),
            "size": engine_res.get("size"),
            "headers": engine_res.get("headers", {}),
            "body": engine_res.get("body", "")[:2000],  # truncated summary for context
            "body_truncated": len(engine_res.get("body", "")) > 2000,
        }
    except Exception as exc:
        logger.exception("Error executing agent tool request_send: %s", exc)
        return {"status": "error", "message": str(exc)}


def tool_finding_record(arguments, context=None):
    """Record a finding into Project / Scanner findings."""
    from .models import ScannerRun, compute_finding_identity

    title = str(arguments.get("title") or "").strip()
    severity = str(arguments.get("severity") or "INFO").strip().upper()
    description = str(arguments.get("description") or "").strip()
    evidence_url = str(arguments.get("evidence_url") or "").strip()
    remediation = str(arguments.get("remediation") or "").strip()

    if not title or not description:
        return {"status": "error", "message": "title and description are required"}

    project = getattr(context, "active_project", None) if context else None

    finding_data = {
        "title": title,
        "severity": severity,
        "description": description,
        "url": evidence_url,
        "evidence": description,
        "remediation": remediation,
        "source": "AI Agent",
        "created_at": timezone.now().isoformat(),
    }
    identity_hash = compute_finding_identity(finding_data, evidence_url)
    finding_data["identity_hash"] = identity_hash

    # Save to or update the latest Project ScannerRun if project exists
    if project:
        run = ScannerRun.objects.filter(project=project).order_by("-created_at").first()
        if not run:
            run = ScannerRun.objects.create(
                project=project,
                engine="builtin",
                url=evidence_url or project.target or "",
                findings=[],
                summary={"findings_count": 0, "highest_severity": severity},
            )
        run.upsert_findings([finding_data])

    return {
        "status": "success",
        "identity_hash": identity_hash,
        "title": title,
        "severity": severity,
        "saved_to_project": bool(project),
    }


def tool_url_encode(arguments, context=None):
    text = str(arguments.get("text") or "")
    plus = bool(arguments.get("plus", False))
    encoded = urllib.parse.quote_plus(text) if plus else urllib.parse.quote(text)
    return {"status": "success", "text": text, "encoded": encoded, "plus": plus}


def tool_url_decode(arguments, context=None):
    text = str(arguments.get("text") or "")
    plus = bool(arguments.get("plus", False))
    decoded = urllib.parse.unquote_plus(text) if plus else urllib.parse.unquote(text)
    return {"status": "success", "encoded": text, "decoded": decoded, "plus": plus}


def tool_base64_encode(arguments, context=None):
    text = str(arguments.get("text") or "")
    url_safe = bool(arguments.get("url_safe", False))
    raw = text.encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw).decode("ascii") if url_safe else base64.b64encode(raw).decode("ascii")
    return {"status": "success", "text": text, "encoded": encoded, "url_safe": url_safe}


def tool_base64_decode(arguments, context=None):
    encoded = str(arguments.get("encoded") or "")
    url_safe = bool(arguments.get("url_safe", False))
    try:
        pad_len = len(encoded) % 4
        padded = encoded + ("=" * (4 - pad_len) if pad_len else "")
        raw = base64.urlsafe_b64decode(padded) if url_safe else base64.b64decode(padded)
        return {"status": "success", "encoded": encoded, "decoded": raw.decode("utf-8", errors="replace"), "url_safe": url_safe}
    except Exception as exc:
        return {"status": "error", "message": f"Base64 decode error: {exc}"}


def tool_random_string(arguments, context=None):
    length = max(1, min(int(arguments.get("length") or 16), 1024))
    charset = str(arguments.get("charset") or "alphanumeric")
    if charset == "hex":
        chars = string.hexdigits.lower()
    elif charset == "digits":
        chars = string.digits
    elif charset == "alpha":
        chars = string.ascii_letters
    elif charset == "special":
        chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    else:
        chars = string.ascii_letters + string.digits
    res = "".join(secrets.choice(chars) for _ in range(length))
    return {"status": "success", "length": length, "charset": charset, "random_string": res}


def tool_normalize_http(arguments, context=None):
    content = str(arguments.get("raw_http") or "")
    if not content:
        return {"status": "success", "normalized": ""}

    if "\r\n\r\n" in content:
        head, body = content.split("\r\n\r\n", 1)
        delim = True
    elif "\n\n" in content:
        head, body = content.split("\n\n", 1)
        delim = True
    elif "\\r\\n\\r\\n" in content:
        head, body = content.split("\\r\\n\\r\\n", 1)
        head = head.replace("\\r\\n", "\n")
        delim = True
    else:
        head, body = content, ""
        delim = False

    head = head.replace("\\r\\n", "\n")
    lines = [line.strip("\r\n") for line in head.splitlines() if line.strip("\r\n")]
    normalized_prelude = "\r\n".join(lines)
    result = f"{normalized_prelude}\r\n\r\n{body}" if delim or body else f"{normalized_prelude}\r\n"
    return {"status": "success", "normalized": result}


def tool_oob_generate(arguments, context=None):
    tag = str(arguments.get("tag") or "default")
    token = f"rroob_{secrets.token_hex(6)}"
    base_cb = f"http://127.0.0.1:8000/?oob={token}"
    return {
        "status": "success",
        "token": token,
        "tag": tag,
        "http_callback_url": base_cb,
        "payload_templates": {
            "ssrf_url": base_cb,
            "xxe_external_entity": f'<!DOCTYPE test [ <!ENTITY % xxe SYSTEM "{base_cb}"> %xxe; ]>',
            "command_injection_curl": f"curl -s {base_cb}"
        }
    }


def tool_oob_poll(arguments, context=None):
    from .models import TrafficRecord
    token = str(arguments.get("token") or "").strip()
    if not token:
        return {"status": "error", "message": "token is required"}
    qs = TrafficRecord.objects.filter(url__icontains=token).order_by("-timestamp", "-id")[:20]
    interactions = []
    for r in qs:
        interactions.append({
            "id": r.id,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "method": r.method,
            "url": r.url,
            "source_ip": r.source_ip,
            "status_code": r.status_code
        })
    return {
        "status": "success",
        "token": token,
        "interactions_count": len(interactions),
        "triggered": len(interactions) > 0,
        "interactions": interactions
    }


TOOL_HANDLERS = {
    "history_search": tool_history_search,
    "request_send": tool_request_send,
    "finding_record": tool_finding_record,
    "url_encode": tool_url_encode,
    "url_decode": tool_url_decode,
    "base64_encode": tool_base64_encode,
    "base64_decode": tool_base64_decode,
    "random_string": tool_random_string,
    "normalize_http": tool_normalize_http,
    "oob_generate": tool_oob_generate,
    "oob_poll": tool_oob_poll,
}


def get_available_tools():
    """Return JSON schema definitions for all registered tools."""
    return TOOL_DEFINITIONS


def execute_agent_tool(name: str, arguments: dict, context=None):
    """Execute a single agent tool by name with arguments."""
    handler = TOOL_HANDLERS.get(name)
    if not handler:
        return {
            "status": "error",
            "message": f"Unknown tool: {name}. Available tools: {list(TOOL_HANDLERS.keys())}",
        }
    try:
        return handler(arguments, context=context)
    except Exception as exc:
        logger.exception("Error executing tool %s: %s", name, exc)
        return {"status": "error", "message": f"Execution error in {name}: {str(exc)}"}
