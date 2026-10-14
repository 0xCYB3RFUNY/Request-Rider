#!/usr/bin/env python3
"""
Request-Rider Model Context Protocol (MCP) Server.

Enables Claude Desktop, Antigravity IDE, Cursor, OpenCode, and Codex
to communicate with and control a running Request-Rider instance via standard JSON-RPC 2.0 over stdio.

Supported tools:
- request_rider_status: Check health & connectivity of Request-Rider services.
- request_rider_history_search: Search captured traffic history.
- request_rider_request_send: Send HTTP/HTTPS requests via the proxy engine.
- request_rider_request_send_h2: Send HTTP/2 requests with pseudo-header support.
- request_rider_normalize_http: Normalize raw HTTP requests with RFC CRLF preludes.
- request_rider_url_encode / request_rider_url_decode: URL encoding/decoding helper.
- request_rider_base64_encode / request_rider_base64_decode: Base64 encoding/decoding helper.
- request_rider_random_string: Cryptographic random token/nonce generator.
- request_rider_oob_generate / request_rider_oob_poll: Out-of-band callback (Collaborator) testing.
- request_rider_agent_run: Trigger an autonomous ReAct investigation in Request-Rider.
- request_rider_skills_list / request_rider_skills_read: Access 540+ curated security, testing, pentest & dev skills.
- request_rider_report_ingest: Ingest and auto-audit crawler/scanner reports.
"""

import sys
import os
import json
import logging
import base64
import secrets
import string
import time
import urllib.parse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

try:
    import httpx
except ImportError:
    httpx = None

# Logging for debugging MCP connections
logging.basicConfig(
    filename="/tmp/request-rider-mcp.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("request-rider-mcp")

DEFAULT_GATEWAY_URL = os.environ.get("REQUEST_RIDER_URL", "http://127.0.0.1:8000").rstrip("/")


def call_request_rider_api(endpoint: str, method: str = "GET", payload: dict = None) -> dict:
    """Make an HTTP call to the local Request-Rider Django gateway."""
    url = f"{DEFAULT_GATEWAY_URL}{endpoint}"
    data = json.dumps(payload).encode("utf-8") if payload else None
    headers = {"Content-Type": "application/json"}
    
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=30) as response:
            body = response.read().decode("utf-8")
            return json.loads(body)
    except HTTPError as err:
        err_body = err.read().decode("utf-8", errors="replace")
        logger.error(f"HTTPError calling {url}: {err.code} {err_body}")
        try:
            return {"error": True, "http_status": err.code, "details": json.loads(err_body)}
        except Exception:
            return {"error": True, "http_status": err.code, "details": err_body}
    except URLError as err:
        logger.error(f"URLError connecting to Request-Rider at {url}: {err.reason}")
        return {
            "error": True,
            "message": f"Не вдалося з'єднатися з Request-Rider ({url}): {err.reason}. Переконайтеся, що сервер запущено на {DEFAULT_GATEWAY_URL}."
        }
    except Exception as exc:
        logger.error(f"Unexpected error: {exc}")
        return {"error": True, "message": str(exc)}


def normalize_http_content(content: str) -> str:
    """Normalize raw HTTP request separating prelude (CRLF) and payload body.

    PortSwigger MCP style: ensures headers use RFC standard \\r\\n line endings
    even if an LLM returned literal escaped \\r\\n or mixed \\n endings,
    while keeping the body/payload completely byte-intact.
    """
    if not content:
        return ""

    if "\r\n\r\n" in content:
        head, body = content.split("\r\n\r\n", 1)
        delimiter_found = True
    elif "\n\n" in content:
        head, body = content.split("\n\n", 1)
        delimiter_found = True
    elif "\\r\\n\\r\\n" in content:
        head, body = content.split("\\r\\n\\r\\n", 1)
        head = head.replace("\\r\\n", "\n")
        delimiter_found = True
    else:
        head, body = content, ""
        delimiter_found = False

    head = head.replace("\\r\\n", "\n")
    lines = [line.strip("\r\n") for line in head.splitlines() if line.strip("\r\n")]
    normalized_prelude = "\r\n".join(lines)

    if delimiter_found or body:
        return f"{normalized_prelude}\r\n\r\n{body}"
    return f"{normalized_prelude}\r\n"


def helper_url_encode(text: str, plus: bool = False) -> dict:
    encoded = urllib.parse.quote_plus(text) if plus else urllib.parse.quote(text)
    return {"text": text, "encoded": encoded, "plus": plus}


def helper_url_decode(text: str, plus: bool = False) -> dict:
    decoded = urllib.parse.unquote_plus(text) if plus else urllib.parse.unquote(text)
    return {"encoded": text, "decoded": decoded, "plus": plus}


def helper_base64_encode(text: str, url_safe: bool = False) -> dict:
    raw = text.encode("utf-8")
    encoded = base64.urlsafe_b64encode(raw).decode("ascii") if url_safe else base64.b64encode(raw).decode("ascii")
    return {"text": text, "encoded": encoded, "url_safe": url_safe}


def helper_base64_decode(encoded: str, url_safe: bool = False) -> dict:
    try:
        pad_len = len(encoded) % 4
        padded = encoded + ("=" * (4 - pad_len) if pad_len else "")
        raw = base64.urlsafe_b64decode(padded) if url_safe else base64.b64decode(padded)
        return {"encoded": encoded, "decoded": raw.decode("utf-8", errors="replace"), "url_safe": url_safe}
    except Exception as exc:
        return {"error": f"Base64 decode error: {exc}"}


def helper_random_string(length: int = 16, charset: str = "alphanumeric") -> dict:
    length = max(1, min(int(length or 16), 1024))
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
    return {"length": length, "charset": charset, "random_string": res}


def helper_send_h2(url: str, method: str = "GET", headers: dict = None, pseudo_headers: dict = None, body: str = "", timeout: float = 15.0) -> dict:
    if httpx is None:
        return {"error": "httpx бібліотека не встановлена в поточному середовищі"}
    method = (method or "GET").upper()
    req_headers = dict(headers or {})
    if pseudo_headers and isinstance(pseudo_headers, dict):
        if ":authority" in pseudo_headers:
            req_headers["Host"] = pseudo_headers[":authority"]

    t0 = time.perf_counter()
    try:
        with httpx.Client(http2=True, verify=False, timeout=timeout) as client:
            resp = client.request(
                method=method,
                url=url,
                headers=req_headers,
                content=body.encode("utf-8") if body else None,
            )
            elapsed_ms = int((time.perf_counter() - t0) * 1000)
            return {
                "ok": True,
                "http_version": resp.http_version,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body_snippet": resp.text[:4000],
                "latency_ms": elapsed_ms,
                "size": len(resp.content),
            }
    except Exception as exc:
        return {"error": f"HTTP/2 request failed: {exc}"}


def helper_oob_generate(tag: str = "") -> dict:
    token = f"rroob_{secrets.token_hex(6)}"
    base_cb = f"{DEFAULT_GATEWAY_URL}/?oob={token}"
    return {
        "ok": True,
        "token": token,
        "tag": tag or "default",
        "http_callback_url": base_cb,
        "payload_templates": {
            "ssrf_url": base_cb,
            "xxe_external_entity": f'<!DOCTYPE test [ <!ENTITY % xxe SYSTEM "{base_cb}"> %xxe; ]>',
            "command_injection_curl": f"curl -s {base_cb}",
            "header_blind_probe": {"X-Forwarded-For": base_cb, "Referer": base_cb}
        },
        "instructions": f"Використовуйте цей токен/URL у сліпих ін'єкціях. Коли цільовий сервер звернеться до шлюзу Request-Rider, викличте request_rider_oob_poll(token='{token}') для перевірки результату."
    }


def helper_oob_poll(token: str) -> dict:
    if not token:
        return {"error": "Потрібно вказати token"}
    res = call_request_rider_api(f"/api/history?path={urllib.parse.quote(token)}&detail=summary&limit=20", method="GET")
    items = res.get("items", []) if isinstance(res, dict) else []
    interactions = []
    for item in items:
        interactions.append({
            "id": item.get("id"),
            "timestamp": item.get("timestamp"),
            "method": item.get("method"),
            "url": item.get("url"),
            "source_ip": item.get("source_ip"),
            "status_code": item.get("status_code"),
            "user_agent": (item.get("request_headers") or {}).get("User-Agent")
        })
    return {
        "ok": True,
        "token": token,
        "interactions_count": len(interactions),
        "triggered": len(interactions) > 0,
        "interactions": interactions
    }


MCP_TOOLS = [
    {
        "name": "request_rider_status",
        "description": "Перевірка стану та з'єднання з локальним сервісом Request-Rider.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "request_rider_history_search",
        "description": "Пошук перехоплених HTTP-запитів та відповідей у базі історії трафіку Request-Rider за пошуковим словом.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Рядок для фільтрації URL чи тіла (наприклад 'admin' або 'token')"},
                "limit": {"type": "integer", "description": "Кількість результатів (за замовчуванням 10)", "default": 10}
            }
        }
    },
    {
        "name": "request_rider_request_send",
        "description": "Відправка сирого HTTP-запиту через проксі-рушій Request-Rider із збереженням в історії.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Цільовий URL (наприклад https://target.com/api/test)"},
                "method": {"type": "string", "description": "HTTP метод (GET, POST тощо)", "default": "GET"},
                "headers": {"type": "object", "description": "Заголовки запиту", "additionalProperties": {"type": "string"}},
                "body": {"type": "string", "description": "Тіло запиту", "default": ""}
            },
            "required": ["url"]
        }
    },
    {
        "name": "request_rider_request_send_h2",
        "description": "Відправка справжнього HTTP/2 запиту з можливістю тестування псевдо-заголовків (:path, :authority, :scheme) та H2-розбіжностей.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Цільовий URL (наприклад https://target.com/path)"},
                "method": {"type": "string", "description": "HTTP метод", "default": "GET"},
                "headers": {"type": "object", "description": "Заголовки запиту", "additionalProperties": {"type": "string"}},
                "pseudo_headers": {"type": "object", "description": "HTTP/2 псевдо-заголовки (наприклад {':path': '/admin', ':authority': 'internal'})", "additionalProperties": {"type": "string"}},
                "body": {"type": "string", "description": "Тіло запиту", "default": ""},
                "timeout": {"type": "number", "description": "Таймаут у секундах", "default": 15.0}
            },
            "required": ["url"]
        }
    },
    {
        "name": "request_rider_normalize_http",
        "description": "Нормалізація сирого HTTP запиту з розділенням прелюдії заголовків (гарантований перенос рядків CRLF \\r\\n) та недоторканого тіла (payload).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "raw_http": {"type": "string", "description": "Сирий текст HTTP запиту"}
            },
            "required": ["raw_http"]
        }
    },
    {
        "name": "request_rider_url_encode",
        "description": "URL-кодування тексту або пейлоаду (аналог Burp Decoder / PortSwigger MCP).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Текст для кодування"},
                "plus": {"type": "boolean", "description": "Використовувати '+' замість '%20' для пробілів", "default": False}
            },
            "required": ["text"]
        }
    },
    {
        "name": "request_rider_url_decode",
        "description": "URL-декодування рядка або пейлоаду.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "URL-закодований рядок"},
                "plus": {"type": "boolean", "description": "Декодувати '+' як пробіл", "default": False}
            },
            "required": ["text"]
        }
    },
    {
        "name": "request_rider_base64_encode",
        "description": "Base64-кодування тексту або бінарного пейлоаду.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Текст для кодування"},
                "url_safe": {"type": "boolean", "description": "Використовувати URL-безпечний Base64 алфавіт (-_)", "default": False}
            },
            "required": ["text"]
        }
    },
    {
        "name": "request_rider_base64_decode",
        "description": "Base64-декодування рядка в UTF-8 текст.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "encoded": {"type": "string", "description": "Base64 рядок"},
                "url_safe": {"type": "boolean", "description": "Чи закодовано в URL-безпечному форматі", "default": False}
            },
            "required": ["encoded"]
        }
    },
    {
        "name": "request_rider_random_string",
        "description": "Генерація випадкового криптостійкого рядка для токенів, унікальних маркерів та пейлоадів (аналог GenerateRandomString у Burp MCP).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "length": {"type": "integer", "description": "Довжина рядка (за замовчуванням 16)", "default": 16},
                "charset": {
                    "type": "string",
                    "enum": ["alphanumeric", "hex", "alpha", "digits", "special"],
                    "description": "Набір символів",
                    "default": "alphanumeric"
                }
            }
        }
    },
    {
        "name": "request_rider_oob_generate",
        "description": "Генерація унікального OOB (Out-of-Band) маркера та URL-колбеків для виявлення Blind SSRF, Blind XXE та Blind RCE (аналог Burp Collaborator).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tag": {"type": "string", "description": "Мітка для ідентифікації тесту (наприклад 'ssrf-search')"}
            }
        }
    },
    {
        "name": "request_rider_oob_poll",
        "description": "Перевірка надходження зворотних викликів (interactions) для згенерованого OOB-маркера в історії трафіку Request-Rider.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "Згенерований OOB-маркер (наприклад rroob_a1b2c3d4e5f6)"}
            },
            "required": ["token"]
        }
    },
    {
        "name": "request_rider_agent_run",
        "description": "Запуск автономного ReAct циклу дослідження цілі або трафіку всередині Request-Rider.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "prompt": {"type": "string", "description": "Завдання для автономного агента"},
                "provider": {"type": "string", "description": "Провайдер LLM (ollama, openai, anthropic, openrouter, gemini, groq, mistral, openai_compatible)", "enum": ["ollama", "openai", "anthropic", "openrouter", "gemini", "groq", "mistral", "openai_compatible"]},
                "model": {"type": "string", "description": "Назва моделі (наприклад llama3.1, gpt-4o-mini, claude-3-5-haiku-latest, openrouter/free)"},
                "api_key": {"type": "string", "description": "API-ключ провайдера (якщо не вказано, автоматично береться з відповідної змінної середовища, для ollama ключ не потрібен)"},
                "endpoint": {"type": "string", "description": "URL endpoint провайдера (якщо відрізняється від стандартного)"},
                "include_project_context": {"type": "boolean", "description": "Включити контекст активного проекту", "default": True},
                "max_steps": {"type": "integer", "description": "Максимальна кількість кроків ReAct циклу", "default": 6}
            },
            "required": ["prompt"]
        }
    },
    {
        "name": "request_rider_skills_list",
        "description": "Пошук та перегляд доступних скілів з тестування, безпеки, пентесту, аудиту та розробки (540+ відібраних технічних скілів).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "Фільтр за ключовим словом (наприклад: 'security', 'burp', 'fuzz', 'pentest', 'audit', 'osint', 'cloud')"}
            }
        }
    },
    {
        "name": "request_rider_skills_read",
        "description": "Отримання повної інструкції та методології вибраного скіла (SKILL.md).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Назва скіла (наприклад: 'burp-suite', 'burpsuite-expert', 'cloud-pentest', 'red-team')"}
            },
            "required": ["name"]
        }
    },
    {
        "name": "request_rider_report_ingest",
        "description": "Завантаження та аналіз експортованих звітів (HTML-карта краулера, JSON-знахідки сканера, HAR, TXT, CSV) з можливістю автономного ReAct аудиту за виявленими ендпоінтами.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Шлях до файлу звіту на диску (наприклад /home/kali/Downloads/target-map.html або report.json)"},
                "content": {"type": "string", "description": "Сирий вміст звіту (якщо передається рядком замість шляху)"},
                "filename": {"type": "string", "description": "Ім'я файлу (наприклад target-map.html)", "default": "report.html"},
                "prompt": {"type": "string", "description": "Завдання для автономного агента з аудиту знахідок (якщо run_agent=True)", "default": "Проаналізуй знахідки зі звіту та перевір потенційні вразливості."},
                "run_agent": {"type": "boolean", "description": "Чи запускати автономний ReAct аудит одразу", "default": True}
            }
        }
    }
]


def _parse_report_content(raw_text: str, filename: str) -> dict:
    """Parse HTML/JSON/HAR/TXT report into structured findings."""
    import re
    ext = (filename.split(".")[-1] or "").lower()

    if ext == "json":
        try:
            data = json.loads(raw_text)
            if isinstance(data, dict):
                if "pages" in data and isinstance(data["pages"], list):
                    return {
                        "report_type": "target_crawler_json",
                        "summary": f"Target Map: {len(data['pages'])} сторінок, статус {data.get('status', 'ok')}",
                        "data": {
                            "target": data.get("target") or data.get("url"),
                            "pages_count": len(data["pages"]),
                            "pages": [{"url": p.get("url"), "status": p.get("status"), "method": p.get("method")} for p in data["pages"][:100]],
                            "js_findings": data.get("js_findings") or data.get("secrets", [])
                        }
                    }
                elif "findings" in data and isinstance(data["findings"], list):
                    return {
                        "report_type": "scanner_findings_json",
                        "summary": f"Scanner Report: {len(data['findings'])} знахідок",
                        "data": {
                            "summary": data.get("summary"),
                            "findings_count": len(data["findings"]),
                            "findings": [{"name": f.get("name"), "severity": f.get("severity"), "url": f.get("url"), "param": f.get("param")} for f in data["findings"][:50]]
                        }
                    }
            return {
                "report_type": "json_data",
                "summary": f"JSON Data ({len(data) if isinstance(data, dict) else len(data)} записів)",
                "data": data
            }
        except Exception:
            return {"report_type": "json_raw", "summary": "Raw JSON text", "data": {"raw": raw_text[:8000]}}

    if ext in ("html", "htm"):
        links = re.findall(r'href=["\']([^"\']+)["\']', raw_text)
        links = [l for l in links if not l.startswith("#") and not l.startswith("javascript:")][:150]
        forms = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', raw_text, re.IGNORECASE)[:30]
        secrets = re.findall(r'class=["\'](?:js-findings|js-secret-value)["\'][^>]*>(.*?)<', raw_text)[:30]
        is_crawler = "Target map" in raw_text or "Target crawler" in raw_text
        return {
            "report_type": "target_crawler_html" if is_crawler else "html_report",
            "summary": f"HTML звіт: {len(links)} посилань, {len(forms)} форм, {len(secrets)} секретів/нотаток",
            "data": {
                "discovered_urls_count": len(links),
                "discovered_urls": list(dict.fromkeys(links))[:80],
                "forms_actions": forms,
                "secrets_findings": secrets,
                "text_excerpt": re.sub(r'<[^>]+>', ' ', raw_text[:6000])[:3000]
            }
        }

    urls = list(dict.fromkeys(re.findall(r'https?://[^\s"\'<>]+', raw_text)))[:60]
    return {
        "report_type": ext or "text",
        "summary": f"Текстовий файл ({len(urls)} виявлених URL)",
        "data": {
            "extracted_urls": urls,
            "content": raw_text[:8000]
        }
    }


def _get_skills_dir():
    local_skills = os.path.join(os.path.dirname(__file__), "skills")
    if os.path.isdir(local_skills):
        return local_skills
    repo_skills = "/home/kali/Downloads/Request-Rider v1.2/.agents/skills"
    if os.path.isdir(repo_skills):
        return repo_skills
    return None


def handle_tool_call(name: str, arguments: dict) -> dict:
    """Execute the requested tool against Request-Rider."""
    if name == "request_rider_status":
        return call_request_rider_api("/health", method="GET")

    if name == "request_rider_normalize_http":
        return {"normalized": normalize_http_content(arguments.get("raw_http", ""))}

    if name == "request_rider_url_encode":
        return helper_url_encode(arguments.get("text", ""), arguments.get("plus", False))

    if name == "request_rider_url_decode":
        return helper_url_decode(arguments.get("text", ""), arguments.get("plus", False))

    if name == "request_rider_base64_encode":
        return helper_base64_encode(arguments.get("text", ""), arguments.get("url_safe", False))

    if name == "request_rider_base64_decode":
        return helper_base64_decode(arguments.get("encoded", ""), arguments.get("url_safe", False))

    if name == "request_rider_random_string":
        return helper_random_string(arguments.get("length", 16), arguments.get("charset", "alphanumeric"))

    if name == "request_rider_request_send_h2":
        return helper_send_h2(
            url=arguments.get("url", ""),
            method=arguments.get("method", "GET"),
            headers=arguments.get("headers"),
            pseudo_headers=arguments.get("pseudo_headers"),
            body=arguments.get("body", ""),
            timeout=float(arguments.get("timeout", 15.0)),
        )

    if name == "request_rider_oob_generate":
        return helper_oob_generate(arguments.get("tag", ""))

    if name == "request_rider_oob_poll":
        return helper_oob_poll(arguments.get("token", ""))

    if name == "request_rider_skills_list":
        sdir = _get_skills_dir()
        if not sdir:
            return {"error": "Папка зі скілами не знайдена"}
        cat = str(arguments.get("category") or "").strip().lower()
        items = []
        for sname in sorted(os.listdir(sdir)):
            spath = os.path.join(sdir, sname)
            if os.path.isdir(spath):
                if not cat or cat in sname.lower():
                    items.append(sname)
        return {
            "total_found": len(items),
            "filter": cat or "all",
            "skills": items[:150]
        }

    if name == "request_rider_skills_read":
        sname = str(arguments.get("name") or "").strip()
        sdir = _get_skills_dir()
        if not sdir:
            return {"error": "Папка зі скілами не знайдена"}
        skill_file = os.path.join(sdir, sname, "SKILL.md")
        if not os.path.isfile(skill_file):
            return {"error": f"Скіл '{sname}' не знайдено за шляхом {skill_file}"}
        try:
            with open(skill_file, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            return {"skill": sname, "content": content}
        except Exception as exc:
            return {"error": f"Помилка читання скіла: {exc}"}

    if name == "request_rider_history_search":
        query = arguments.get("query", "")
        limit = arguments.get("limit", 10)
        endpoint = f"/api/history?limit={limit}"
        if query:
            endpoint += f"&q={urllib.parse.quote(query)}"
        return call_request_rider_api(endpoint, method="GET")

    if name == "request_rider_request_send":
        body = arguments.get("body", "")
        payload = {
            "url": arguments.get("url"),
            "method": arguments.get("method", "GET"),
            "headers": arguments.get("headers", {}),
            "body": body
        }
        return call_request_rider_api("/api/execute", method="POST", payload=payload)

    if name == "request_rider_agent_run":
        payload = {
            "prompt": arguments.get("prompt"),
            "include_project_context": arguments.get("include_project_context", True),
            "max_steps": arguments.get("max_steps", 6)
        }
        if arguments.get("provider"):
            payload["provider"] = arguments.get("provider")
        elif os.environ.get("RR_AGENT_PROVIDER"):
            payload["provider"] = os.environ.get("RR_AGENT_PROVIDER")
        if arguments.get("model"):
            payload["model"] = arguments.get("model")
        elif os.environ.get("RR_AGENT_MODEL"):
            payload["model"] = os.environ.get("RR_AGENT_MODEL")
        if arguments.get("api_key"):
            payload["api_key"] = arguments.get("api_key")
        if arguments.get("endpoint"):
            payload["endpoint"] = arguments.get("endpoint")
        return call_request_rider_api("/api/agent/run", method="POST", payload=payload)

    if name == "request_rider_report_ingest":
        file_path = arguments.get("file_path")
        content = arguments.get("content")
        fname = arguments.get("filename") or "report.html"

        if file_path:
            fname = os.path.basename(file_path)
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except Exception as exc:
                return {"error": f"Не вдалося прочитати файл {file_path}: {exc}"}

        if not content:
            return {"error": "Потрібно передати file_path або content"}

        parsed = _parse_report_content(content, fname)
        run_agent = arguments.get("run_agent", True)
        prompt = arguments.get("prompt") or "Проаналізуй знахідки зі звіту та перевір потенційні вразливості."

        if not run_agent:
            return {
                "ok": True,
                "filename": fname,
                "report_type": parsed.get("report_type"),
                "summary": parsed.get("summary"),
                "extracted_data": parsed.get("data")
            }

        safe_key = f"file_{fname.replace('/', '_')}"
        payload = {
            "prompt": prompt,
            "context": {
                "attached_evidence": {
                    safe_key: {
                        "type": "file_report",
                        "filename": fname,
                        "report_type": parsed.get("report_type"),
                        "summary": parsed.get("summary"),
                        "data": parsed.get("data")
                    }
                }
            },
            "include_project_context": True,
            "max_steps": arguments.get("max_steps", 6)
        }
        if arguments.get("provider"):
            payload["provider"] = arguments.get("provider")
        elif os.environ.get("RR_AGENT_PROVIDER"):
            payload["provider"] = os.environ.get("RR_AGENT_PROVIDER")
        if arguments.get("model"):
            payload["model"] = arguments.get("model")
        elif os.environ.get("RR_AGENT_MODEL"):
            payload["model"] = os.environ.get("RR_AGENT_MODEL")
        if arguments.get("api_key"):
            payload["api_key"] = arguments.get("api_key")
        if arguments.get("endpoint"):
            payload["endpoint"] = arguments.get("endpoint")
        agent_res = call_request_rider_api("/api/agent/run", method="POST", payload=payload)
        return {
            "ok": True,
            "filename": fname,
            "summary": parsed.get("summary"),
            "agent_audit": agent_res
        }

    return {"error": f"Невідомий інструмент: {name}"}


def send_response(response_dict: dict):
    """Write JSON-RPC message to stdout."""
    raw = json.dumps(response_dict)
    sys.stdout.write(raw + "\n")
    sys.stdout.flush()


def main():
    logger.info("Request-Rider MCP Server started.")
    
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as exc:
            logger.error(f"Failed to parse JSON: {exc}")
            continue

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "request-rider-mcp",
                        "version": "1.2.0"
                    }
                }
            })
        elif method == "notifications/initialized":
            pass
        elif method == "tools/list":
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": MCP_TOOLS
                }
            })
        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            try:
                tool_result = handle_tool_call(tool_name, tool_args)
                send_response({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(tool_result, ensure_ascii=False, indent=2)
                            }
                        ]
                    }
                })
            except Exception as exc:
                send_response({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32603,
                        "message": str(exc)
                    }
                })
        else:
            send_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method {method} not found"
                }
            })


if __name__ == "__main__":
    main()
