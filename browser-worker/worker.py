"""Isolated Firefox/Playwright worker for JavaScript-rendered Target routes."""

import asyncio
import base64
import json
import logging
import os
import random
import re
import signal
import sys
import threading
import time
import uuid
from proxy_pool import ProxyPool, pool_from_payload
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urldefrag, urljoin, urlparse

import anti_detect
import chromium_fonts
import human_input


# --- logging -------------------------------------------------------------------
#
# The worker had none: no `logging` import and `log_message` returned nothing, so job
# state existed only in process memory and vanished with it. `data/logs/browser-worker.log`
# contained two startup crashes, both without a timestamp or a PID. A crash loop is
# exactly the case an operator needs a record of, and it was invisible.
#
# stderr, not a file: `start.sh` already redirects this process's output into
# `data/logs/browser-worker.log`, so a second writer would only produce two interleaved
# copies of the same lines and a second thing to rotate.
#
# The format is fixed rather than left at the default, because the thing that made the
# old file useless was precisely that lines carried no time.
LOG = logging.getLogger("browser_worker")


def _configure_logging():
    root = logging.getLogger()
    if root.handlers:
        return  # Something already configured logging; do not stack handlers.
    handler = logging.StreamHandler()  # defaults to stderr
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s %(levelname)s pid=%(process)d %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    ))
    root.addHandler(handler)
    root.setLevel(os.environ.get("RR_BROWSER_WORKER_LOG_LEVEL", "INFO").upper() or "INFO")


_configure_logging()

DOM_SINK_TELEMETRY_INIT_SCRIPT = r"""
(() => {
  if (window.__rrDomSinkInstalled) return;
  window.__rrDomSinkInstalled = true;
  const sinks = [];
  window.__rrDomSinks = sinks;
  let lastFetchUrl = "";

  const getTaintSources = () => {
    const tokens = [];
    try {
      const sp = new URLSearchParams(window.location.search || "");
      sp.forEach((v) => { if (v && v.length >= 3) tokens.push(v); });
    } catch {}
    try {
      if (window.location.hash && window.location.hash.length >= 4) {
        tokens.push(window.location.hash.slice(1));
      }
    } catch {}
    try {
      if (window.name && window.name.length >= 3) tokens.push(window.name);
    } catch {}
    return tokens;
  };

  const recordSink = (sinkName, rawVal) => {
    try {
      if (sinks.length >= 250) return;
      const val = String(rawVal == null ? "" : rawVal);
      if (!val) return;
      const sources = getTaintSources();
      const tainted = sources.some((src) => val.includes(src));
      let stack = "";
      try { stack = String((new Error()).stack || ""); } catch {}
      sinks.push({
        sink: sinkName,
        value: val.slice(0, 500),
        url: String(window.location.href || ""),
        stack: stack.slice(0, 1200),
        last_fetch: lastFetchUrl,
        tainted: tainted,
        ts: Date.now()
      });
    } catch {}
  };

  // Track fetch / XHR URLs for network correlation
  if (typeof window.fetch === "function") {
    const origFetch = window.fetch;
    window.fetch = function(input, init) {
      try { lastFetchUrl = typeof input === "string" ? input : (input && input.url) || ""; } catch {}
      return origFetch.apply(this, arguments);
    };
  }
  if (typeof window.XMLHttpRequest === "function") {
    const origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
      try { lastFetchUrl = String(url || ""); } catch {}
      return origOpen.apply(this, arguments);
    };
  }

  // Code execution sinks
  const origEval = window.eval;
  window.eval = function(code) { recordSink("eval", code); return origEval.apply(this, arguments); };

  const origSetTimeout = window.setTimeout;
  window.setTimeout = function(fn) {
    if (typeof fn === "string") recordSink("setTimeout", fn);
    return origSetTimeout.apply(this, arguments);
  };
  const origSetInterval = window.setInterval;
  window.setInterval = function(fn) {
    if (typeof fn === "string") recordSink("setInterval", fn);
    return origSetInterval.apply(this, arguments);
  };

  // DOM markup sinks
  for (const prop of ["innerHTML", "outerHTML"]) {
    const desc = Object.getOwnPropertyDescriptor(Element.prototype, prop);
    if (desc && desc.set) {
      Object.defineProperty(Element.prototype, prop, {
        configurable: true,
        get: desc.get,
        set(val) {
          recordSink(`Element.${prop}`, val);
          return desc.set.call(this, val);
        }
      });
    }
  }
  const origWrite = document.write;
  document.write = function(...args) { recordSink("document.write", args.join("")); return origWrite.apply(this, args); };
  const origWriteln = document.writeln;
  document.writeln = function(...args) { recordSink("document.writeln", args.join("")); return origWriteln.apply(this, args); };

  // Navigation & postMessage channels
  const origPostMessage = window.postMessage;
  window.postMessage = function(msg, targetOrigin) {
    recordSink("window.postMessage", typeof msg === "string" ? msg : JSON.stringify(msg));
    return origPostMessage.apply(this, arguments);
  };
  const origAddEvent = window.addEventListener;
  window.addEventListener = function(type, listener, opts) {
    if (type === "message") recordSink("addEventListener:message", String(listener || "").slice(0, 200));
    return origAddEvent.apply(this, arguments);
  };

  // Storage & cookies
  try {
    const origSetItem = Storage.prototype.setItem;
    Storage.prototype.setItem = function(k, v) {
      recordSink(this === window.sessionStorage ? "sessionStorage.setItem" : "localStorage.setItem", `${k}=${v}`);
      return origSetItem.apply(this, arguments);
    };
  } catch {}
})();
"""


async def read_dom_sinks(page):
    try:
        data = await page.evaluate("() => Array.isArray(window.__rrDomSinks) ? window.__rrDomSinks : []")
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _log_job_finished(job_id, status, error):
    """One line per terminal job state: id, status, how long it took, error type.

    The duration comes from the job's own start time, so a run that died still reports
    how long it lasted — which is the number an operator actually wants from a crash
    loop, and the one the old file could not give.
    """
    with JOBS_LOCK:
        job = JOBS.get(job_id) or {}
        started = job.get("started_monotonic")
    duration_ms = None
    if isinstance(started, (int, float)):
        duration_ms = int((time.monotonic() - started) * 1000)
    if status == "failed":
        LOG.error(
            "target_job_finished job_id=%s status=%s duration_ms=%s error_type=%s",
            job_id, status, duration_ms, type(error).__name__ if error is not None else "unknown",
        )
        return
    LOG.info(
        "target_job_finished job_id=%s status=%s duration_ms=%s", job_id, status, duration_ms
    )


# --- request body limit -------------------------------------------------------
#
# `read_json` used `int(self.headers["Content-Length"])` and read whatever it said.
# A non-numeric header raised `ValueError` into a 500 with a traceback, and a declared
# length this server has no reason to accept was read without complaint — including one
# the client may never send, which pins the reading thread on a socket.
#
# This is a resource guard on one HTTP body, not a restriction on what may be crawled:
# it is many times the size of any crawl configuration, it is overridable so that nothing
# here is a hidden constant, and it is refused explicitly rather than truncated.
DEFAULT_MAX_REQUEST_BODY_BYTES = 8 * 1024 * 1024


def _max_request_body_bytes():
    raw = os.environ.get("RR_BROWSER_WORKER_MAX_BODY_BYTES", "").strip()
    if not raw:
        return DEFAULT_MAX_REQUEST_BODY_BYTES
    try:
        value = int(raw)
    except ValueError:
        LOG.warning(
            "invalid RR_BROWSER_WORKER_MAX_BODY_BYTES=%r, using the default %d",
            raw, DEFAULT_MAX_REQUEST_BODY_BYTES,
        )
        return DEFAULT_MAX_REQUEST_BODY_BYTES
    return value if value > 0 else DEFAULT_MAX_REQUEST_BODY_BYTES


MAX_REQUEST_BODY_BYTES = _max_request_body_bytes()


class RequestBodyError(ValueError):
    """The declared length cannot be trusted; the body was not read at all."""


class RequestBodyTooLarge(RequestBodyError):
    """The declared length is larger than this server accepts."""

JOBS = {}
JOBS_LOCK = threading.Lock()
BROWSER_RUNTIME = None

# The generator every human-like gesture draws its jitter from. One stream
# for the whole process, not one per action, so the gestures of a single crawl
# share a sequence instead of each restarting a private one. Measured on this
# Python, a bare `random.Random()` seeds from `os.urandom` and so already
# differs between calls — this is about a single continuous stream, not about
# avoiding duplicates.
_human_rng = random.Random()

# Automatic form mode: a DOM-evaluated pass that finds every visible form and
# standalone control, then drives it without the analyst naming a selector.
# The click timeout below is a technical bound, not an exploration limit: it
# stops one unresponsive control from stalling a crawl, and it is reported per
# interaction in the job result so the bound is never invisible.
AUTO_ACTION_TIMEOUT_MS = 5000
AUTO_SETTLE_MS = 150
# How long the candidate set has to stay identical before the page counts as
# settled. Measured, not guessed: a real .ru login renders its form ~900 ms
# after the chrome, and two readings 150 ms apart were identical long before
# that. Network silence alone does not catch it either, because that page draws
# the form from a timer and issues no request — so the window is a real wait,
# and it is reported back as `stable_ms` rather than applied silently. The
# analyst's own `auto_wait_timeout_ms` still bounds the whole thing and still
# overrides it.
AUTO_SETTLE_STABLE_MS = 1000
AUTO_ATTRIBUTE = "data-rr-auto"

# How long the automatic pass waits for a page to render something it can act
# on, before it concludes the page has no form or control. This is the analyst's
# value: it is exposed as `auto_wait_timeout_ms`, shown in the UI, and reported
# back in the job result, so the wait is never an invisible deadline.
#
# The default is generous because the thing being waited for is an app answering
# its own API call, which is seconds of work, not milliseconds. A page that
# genuinely has nothing to offer still returns immediately: the wait ends at the
# first candidate, not after the bound.
DEFAULT_AUTO_WAIT_TIMEOUT_MS = 15000

# How many times the automatic pass re-reads a page to act on what an earlier
# step revealed. Two is what a two-step login needs; the bound exists so a page
# that keeps producing new controls cannot keep the job alive, and the number of
# rounds that ran is reported in the job result.
MAX_AUTO_ROUNDS = 3

# Navigation deadline for one crawled page. Playwright's own default is 30s, and
# it used to be what a crawl actually ran under, because the goto call passed
# no timeout. That is a hidden cap: nothing in the UI, the API or the engine
# mentioned it, and it truncated crawls of exactly the pages an analyst runs
# this tool for — a heavy site behind Tor measured a 30s timeout where the
# same page loaded in full without the route.
#
# The default is therefore no deadline at all. A page that never finishes is
# still bounded by the two things the analyst can see and use: the `Cancel`
# control on the job, and an explicit `navigation_timeout_ms` in the request.
DEFAULT_NAVIGATION_TIMEOUT_MS = 0


def check_browser_runtime():
    runtime = BrowserRuntime()
    runtime.start()
    return runtime


def normalize_input(payload):
    if not isinstance(payload, dict):
        raise ValueError("request body must be an object")
    start_url = str(payload.get("url", "")).strip()
    parsed = urlparse(start_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("url must be an absolute http(s) URL")
    capture_context = str(payload.get("capture_context", "")).strip()
    proxy_mitm_ca = payload.get("proxy_mitm_ca", False)
    if not isinstance(proxy_mitm_ca, bool):
        raise ValueError("proxy_mitm_ca must be boolean")
    if any(
        not (character.isascii() and (character.isalnum() or character in "-_"))
        for character in capture_context
    ):
        raise ValueError("capture_context must be an opaque token")
    result = {
        "url": start_url,
        "capture_context": capture_context,
        "max_pages": int(payload.get("max_pages", 0)),
        "max_depth": int(payload.get("max_depth", -1)),
        "delay_ms": int(payload.get("delay_ms", 0)),
        "navigation_timeout_ms": int(
            payload.get("navigation_timeout_ms", DEFAULT_NAVIGATION_TIMEOUT_MS)
        ),
        # Anti-automation layer. Both switches are on by default because the
        # feature exists to be used, and both are reported back per job, so a
        # crawl always says which fingerprint it presented and which it was
        # given. `anti_detect: false` is a real mode, not a degenerate one: it
        # is how an analyst compares a site's behaviour with and without the
        # layer. The layer synthesises the whole identity, User-Agent included:
        # the operator's decision, 2026-09-29. What the page is told is reported
        # per job as `synthetic_values`, so nothing here is passed off as a
        # measurement of the machine. The Go crawler is the opposite case and
        # stays as it is: it sends a descriptive `RequestRider-*` and never
        # pretends to be a browser.
        "anti_detect": bool(payload.get("anti_detect", True)),
        # Values the page is told about, and the identity the analyst pins.
        # Empty means "keep what the browser runtime already reports", which is
        # the pre-existing behaviour, so adding these fields changes nothing
        # until somebody sets one.
        # Which synthetic identity the page is given. Empty means "draw one",
        # which is the normal case; a name pins it, which is what makes a crawl
        # reproducible and what lets a test assert an exact identity. It has to
        # be an explicit field rather than something read straight off the
        # payload, otherwise naming it silently does nothing.
        "identity": str(payload.get("identity") or "").strip(),
        "webgl_vendor": str(payload.get("webgl_vendor") or "").strip(),
        "webgl_renderer": str(payload.get("webgl_renderer") or "").strip(),
        "hardware_concurrency": int(payload.get("hardware_concurrency") or 0),
        "device_memory": float(payload.get("device_memory") or 0),
        "locale": str(payload.get("locale") or "").strip(),
        "timezone_id": str(payload.get("timezone_id") or "").strip(),
        "concurrency": int(payload.get("concurrency", 4)),
        "same_origin": bool(payload.get("same_origin", False)),
        "actions": payload.get("actions") or [],
        "allow_state_changing_actions": bool(payload.get("allow_state_changing_actions", False)),
        "auto_interact": bool(payload.get("auto_interact", False)),
        "auto_fill": bool(payload.get("auto_fill", True)),
        "auto_click": bool(payload.get("auto_click", True)),
        "auto_wait_timeout_ms": int(
            payload.get("auto_wait_timeout_ms", DEFAULT_AUTO_WAIT_TIMEOUT_MS)
        ),
        "proxy_server": str(payload.get("proxy_server", "")).strip(),
        # Пул ендпоінтів: здатність, портована з creepyCrawler
        # (`prepare_fireprox_url` / `manage_fp`) без привʼязки до постачальника.
        # `proxy_server` лишається повним і означає пул з одного ендпоинта.
        "proxy_pool": pool_from_payload(payload),
        "proxy_distribution": str(payload.get("proxy_distribution") or payload.get("distribution_mode") or "split").strip().lower(),
        "proxy_mitm_ca": proxy_mitm_ca,
        "browser": str(payload.get("browser", "firefox")).strip().lower(),
        # Профіль браузера: каталог, з якого піднімається сесія. Порожнє
        # значення — звичайний запуск без профілю, тобто поведінка до цієї
        # можливості лишається точно такою ж.
        "browser_profile": str(payload.get("browser_profile", "")).strip(),
        "cookies": str(payload.get("cookies") or "").strip(),
        "custom_headers": payload.get("custom_headers") if isinstance(payload.get("custom_headers"), dict) else {},
        "live_view": bool(payload.get("live_view", False)),
    }
    if result["max_pages"] < 0:
        result["max_pages"] = 0
    if result["max_depth"] < -1 or result["delay_ms"] < 0 or result["concurrency"] < 1:
        raise ValueError("max_depth, delay_ms and concurrency must be valid; max_pages <= 0 means unlimited")
    # 0 means "no navigation deadline", which is the default. A negative value
    # is rejected rather than clamped, because a silently clamped bound is the
    # hidden cap this parameter exists to remove.
    if result["navigation_timeout_ms"] < 0:
        raise ValueError("navigation_timeout_ms must be 0 (no deadline) or a positive number of milliseconds")
    if result["browser"] not in set(BROWSER_NAMES):
        # The message is built from the catalogue rather than written out,
        # so the error always matches BROWSER_NAMES.
        raise ValueError(f"browser must be one of {', '.join(BROWSER_NAMES)}")
    if result["auto_interact"] and not result["allow_state_changing_actions"]:
        # Automatic clicking and form filling submits requests on its own, so it
        # may only run where the analyst already allowed state-changing actions.
        # Failing loudly is the point: silently skipping would report a coverage
        # the crawl never had.
        raise ValueError("auto_interact requires allow_state_changing_actions")
    if result["auto_interact"] and not (result["auto_fill"] or result["auto_click"]):
        raise ValueError("auto_interact needs auto_fill or auto_click to do anything")
    if result["identity"] and result["identity"] not in anti_detect.IDENTITY_PROFILE_NAMES:
        # A name nobody recognises is the analyst's typo, and falling back to a
        # different identity would hide it: the crawl would run under a
        # fingerprint the operator did not ask for and did not read.
        raise ValueError(
            "identity must be one of: %s" % ", ".join(anti_detect.IDENTITY_PROFILE_NAMES)
        )
    if result["auto_wait_timeout_ms"] < 0:
        raise ValueError("auto_wait_timeout_ms must be 0 (no wait) or a positive number of milliseconds")
    # 0 means "wait until the analyst cancels the job", the same reading
    # navigation_timeout_ms has had since it stopped defaulting to Playwright's
    # own 30 seconds. A negative value is refused rather than clamped, because
    # a silently clamped bound is a hidden cap.
    if result["hardware_concurrency"] < 0:
        raise ValueError("hardware_concurrency must be 0 (keep the runtime value) or a positive number of cores")
    if result["device_memory"] < 0:
        raise ValueError("device_memory must be 0 (keep the runtime value) or a positive number of gigabytes")
    for name in ("locale", "timezone_id", "webgl_vendor", "webgl_renderer"):
        if len(result[name]) > 120:
            raise ValueError(f"{name} must be at most 120 characters")
    return result


def same_origin(candidate, origin):
    if not candidate or not origin:
        return False
    cand_parsed = urlparse(candidate)
    cand_scheme = cand_parsed.scheme.lower()
    if cand_scheme not in {"http", "https"}:
        return False
    cand_host = cand_parsed.netloc.lower()

    origins = [origin] if isinstance(origin, str) else list(origin)
    for orig in origins:
        if not orig:
            continue
        orig_parsed = urlparse(orig)
        orig_scheme = orig_parsed.scheme.lower()
        orig_host = orig_parsed.netloc.lower()
        if not orig_host:
            continue
        # Exact origin match
        if f"{cand_scheme}://{cand_host}" == f"{orig_scheme}://{orig_host}":
            return True
        # Scheme upgrade / transition between http and https on the same host
        if cand_host == orig_host and cand_scheme in {"http", "https"} and orig_scheme in {"http", "https"}:
            return True
        # www prefix equivalence (e.g. example.com vs www.example.com)
        cand_bare = cand_host[4:] if cand_host.startswith("www.") else cand_host
        orig_bare = orig_host[4:] if orig_host.startswith("www.") else orig_host
        if cand_bare == orig_bare and cand_scheme in {"http", "https"} and orig_scheme in {"http", "https"}:
            return True
    return False


async def route_browser_request(route):
    """Keep the crawl's bandwidth down.

    Fonts and images are the bulk of a page's bytes and the crawler reads
    neither, so they are dropped. Media is kept: a video or audio element is
    part of the page the analyst asked for, and it is a small share of the
    transfer next to the images.
    """
    if route.request.resource_type in ("font", "image"):
        await route.abort()
    else:
        await route.continue_()


def parse_cookie_header(header_str, target_url):
    """Parse a Cookie header string (e.g. 'PHPSESSID=123; user=admin') into Playwright cookie dicts."""
    if not header_str:
        return []
    cookies = []
    parsed = urlparse(target_url)
    domain = parsed.hostname or "127.0.0.1"
    for part in str(header_str).split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, val = part.split("=", 1)
        name = name.strip()
        val = val.strip()
        if name:
            cookies.append({
                "name": name,
                "value": val,
                "domain": domain,
                "path": "/",
            })
    return cookies


async def extract_links(page, current_url):
    for attempt in range(3):
        try:
            links = await page.eval_on_selector_all(
                "a[href], area[href], iframe[src], form[action], [routerlink], [ng-reflect-router-link], [data-route], [data-href]",
                """(nodes) => nodes.map(node => {
                    try {
                        if (node.tagName === 'FORM') {
                            const act = node.getAttribute('action');
                            return typeof act === 'string' && act ? act : (typeof node.action === 'string' ? node.action : '');
                        }
                        const rlink = node.getAttribute('routerlink') || node.getAttribute('ng-reflect-router-link') || node.getAttribute('data-route') || node.getAttribute('data-href');
                        if (typeof rlink === 'string' && rlink.trim()) {
                            const trimmed = rlink.trim();
                            return trimmed.startsWith('/') ? '#' + trimmed : '#/' + trimmed;
                        }
                        const href = node.getAttribute('href');
                        if (typeof href === 'string' && href) return href;
                        if (typeof node.href === 'string' && node.href) return node.href;
                        const src = node.getAttribute('src');
                        if (typeof src === 'string' && src) return src;
                        if (typeof node.src === 'string' && node.src) return node.src;
                        return '';
                    } catch (e) {
                        return '';
                    }
                }).filter(Boolean)""",
            )
            result = []
            seen = set()
            page_url = getattr(page, "url", None)
            base_url = page_url if isinstance(page_url, str) and page_url else current_url
            for link in links:
                if not isinstance(link, str) or not link.strip():
                    continue
                clean = link.strip()
                if clean.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
                    continue
                # Support SPA hash routes like #/basket, #/score-board, #!/home
                is_spa_hash = clean.startswith(("#/", "#!/"))
                if clean.startswith("#") and not is_spa_hash:
                    continue

                if is_spa_hash:
                    absolute = urljoin(base_url, clean)
                else:
                    absolute = urldefrag(urljoin(base_url, clean))[0]

                parsed = urlparse(absolute)
                if parsed.scheme in {"http", "https"}:
                    ext = os.path.splitext(parsed.path.lower())[1]
                    if ext in {
                        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
                        ".css", ".woff", ".woff2", ".ttf", ".eot",
                        ".mp4", ".mp3", ".webm", ".ogg", ".avi",
                        ".zip", ".tar", ".gz", ".rar", ".7z", ".pdf",
                    }:
                        continue
                    if absolute not in seen:
                        seen.add(absolute)
                        result.append(absolute)
            return result
        except Exception as error:
            err_str = str(error)
            if attempt < 2 and (
                "Execution context was destroyed" in err_str
                or "navigating" in err_str.lower()
                or "Target closed" in err_str
            ):
                try:
                    await page.wait_for_load_state("domcontentloaded", timeout=4000)
                except Exception:
                    await asyncio.sleep(0.4)
                continue
            LOG.debug("extract_links_failed url=%s error=%s", current_url, error)
            return []
    return []


async def extract_subresources(page, current_url):
    for attempt in range(3):
        try:
            items = await page.eval_on_selector_all(
                "link[href], script[src], img[src]",
                """(nodes) => nodes.map(node => {
                    try {
                        const tag = (node.tagName || '').toLowerCase();
                        const href = node.getAttribute('href');
                        const src = node.getAttribute('src');
                        const val = (tag === 'link' ? (href || node.href) : (src || node.src)) || '';
                        return { tag: tag, url: val };
                    } catch (e) {
                        return { tag: '', url: '' };
                    }
                }).filter(item => item.url)""",
            )
            result = []
            seen = set()
            page_url = getattr(page, "url", None)
            base_url = page_url if isinstance(page_url, str) and page_url else current_url
            for item in items:
                u = item.get("url")
                if not isinstance(u, str) or not u.strip():
                    continue
                clean = u.strip()
                if clean.lower().startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                    continue
                absolute = urldefrag(urljoin(base_url, clean))[0]
                parsed = urlparse(absolute)
                if parsed.scheme in {"http", "https"}:
                    if absolute not in seen:
                        seen.add(absolute)
                        tag = item.get("tag", "")
                        kind = "script" if tag == "script" else ("css" if tag == "link" else "image")
                        result.append({"url": absolute, "kind": kind})
            return result
        except Exception:
            return []
    return []


async def extract_page_enrichment(page, current_url):
    try:
        data = await page.evaluate(r"""() => {
            const forms = Array.from(document.querySelectorAll('form'));
            let insecureForms = 0;
            const formList = forms.map(f => {
                const action = f.getAttribute('action') || '';
                const method = (f.getAttribute('method') || 'GET').toUpperCase();
                const inputs = Array.from(f.querySelectorAll('input, select, textarea')).map(i => ({
                    name: i.getAttribute('name') || '',
                    type: i.getAttribute('type') || i.tagName.toLowerCase()
                }));
                const hasCsrf = inputs.some(i => /csrf|token|_token|xsrf/i.test(i.name));
                if (method === 'POST' && !hasCsrf) insecureForms++;
                return { action, method, inputs, has_csrf: hasCsrf };
            });
            const pwdInputs = Array.from(document.querySelectorAll('input[type="password"]'));
            const credentials = pwdInputs.length;

            return {
                csrf: { forms: formList },
                insecure_forms: insecureForms,
                credentials: credentials,
                notable_files: [],
                patterns: [],
                info: credentials > 0 ? [{ kind: 'login-form', detail: 'Password input detected' }] : [],
                external_hosts: [],
                subdomains: [],
                secrets: { findings: [], rejected: [] }
            };
        }""")
        if not isinstance(data, dict):
            return None, None
        insecure = data.pop("insecure_forms", 0)
        creds = data.pop("credentials", 0)
        counts = {
            "notable": 0,
            "patterns": 0,
            "info": len(data.get("info", [])),
            "hosts": 0,
            "subdomains": 0,
            "insecureForms": insecure,
            "credentials": creds,
            "secrets": 0,
            "rejectedSecrets": 0,
        }
        return data, counts
    except Exception:
        return None, None



AUTO_DISCOVERY_SCRIPT = """() => {
  const attribute = '__AUTO_ATTRIBUTE__';

  // A component that renders into a shadow root is invisible to
  // document.querySelectorAll, and web components are ordinary in modern apps.
  // Every open root is therefore walked, and each is queried on its own because
  // closest() does not cross the boundary either.
  const roots = [];
  const collectRoots = (root) => {
    roots.push(root);
    let all = [];
    try { all = root.querySelectorAll('*'); } catch (error) { return; }
    for (const node of all) {
      if (node.shadowRoot) collectRoots(node.shadowRoot);
    }
  };
  collectRoots(document);

  const tagged = new Set();
  const mark = (node, meta) => {
    if (!node || tagged.has(node)) return null;
    tagged.add(node);
    const index = tagged.size;
    node.setAttribute(attribute, String(index));
    return Object.assign({selector: '[' + attribute + '="' + index + '"]'}, meta);
  };
  const visibleLayout = (node) => {
    if (!node || !node.getAttribute) return false;
    const type = (node.getAttribute('type') || '').toLowerCase();
    if (type === 'hidden') return false;
    const style = window.getComputedStyle(node);
    if (!style || style.display === 'none' || style.visibility === 'hidden') return false;
    if (style.opacity === '0') return false;
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  };
  const visible = (node) => {
    if (!node || !node.getAttribute) return false;
    if (node.disabled) return false;
    return visibleLayout(node);
  };
  const label = (node) => {
    const text = (node.innerText || node.textContent || '').trim().replace(/\\s+/g, ' ');
    if (text) return text.slice(0, 80);
    const fallback = node.getAttribute('aria-label')
      || node.getAttribute('title')
      || node.getAttribute('name')
      || node.getAttribute('placeholder')
      || '';
    return fallback.trim().slice(0, 80);
  };
  const looksLikeAsset = (value) => {
    // An icon wrapper is named by what it draws, not by what it does. Measured
    // on a real .ru site: a navigation bar produced `18/ico_home_18` next to
    // `Home`, and the pass clicked both — two candidates, one destination, and
    // one of them named after a file. A name that is an asset reference is not
    // something a report can speak about, so such a control is decoration and
    // the control that carries the readable text is the one that gets clicked.
    if (!value) return false;
    const name = value.trim();
    // The backslash is written as a character code on purpose: this whole script
    // travels inside a Python string, where a literal backslash escape would
    // arrive in the browser as a broken string literal. A swallowed syntax error
    // here returns an empty plan, and an empty plan reads as "the page has
    // nothing to offer" — the pass would report zero candidates on every page.
    if (name.includes('/') || name.includes(String.fromCharCode(92))) return true;
    if (/[.](svg|png|gif|jpg|jpeg|webp|ico|css|woff2?)$/i.test(name)) return true;
    // `ico_tribune_16` has neither a slash nor an extension: it is named by the
    // icon convention itself, an `ico_` prefix. A bare `_16` suffix was tried as
    // a signal too and dropped: it never caught anything the `ico_` rule had
    // not, and it read a plain name like `a_1` as an asset.
    if (/(^|[-_ ])ico[-_]/i.test(name)) return true;
    return false;
  };
  const controlLabel = (node) => {
    // A control is reported by the name its author gave it. A wrapper carrying
    // `aria-label="Minimize search"` and holding a one-letter icon span was
    // reported as that letter, which is not a thing a report can speak about.
    // The visible text stays the fallback, so a control with no accessible name
    // is still named by what it shows, and an asset name never wins over it.
    for (const name of [node.getAttribute('aria-label'), node.getAttribute('title')]) {
      if (name && name.trim() && !looksLikeAsset(name)) return name.trim().slice(0, 80);
    }
    const text = label(node);
    if (text && !looksLikeAsset(text)) return text;
    return '';
  };
  const fieldKind = (node) => {
    if (node.isContentEditable) return 'text';
    const tag = node.tagName.toLowerCase();
    if (tag === 'select') return 'select';
    if (tag === 'textarea') return 'textarea';
    // A button carries no value to type, whatever it declares. A <button> with
    // no type attribute used to read as type "text" and become the form's only
    // field, which could then never be filled. Measured on a real admin login:
    // the toolbar logo button became the field, the fill failed, and the form
    // was still reported as submitted. Submit buttons are collected separately
    // by SUBMIT_SELECTOR, which covers `button:not([type])` too, so refusing
    // to type into a button loses nothing that has to be clicked.
    if (tag === 'button') return '';
    const type = (node.getAttribute('type') || 'text').toLowerCase();
    if (['checkbox', 'radio', 'email', 'url', 'tel', 'password', 'search', 'color', 'file'].includes(type)) return type;
    if (['number', 'range', 'date', 'datetime-local', 'time', 'month', 'week'].includes(type)) return type;
    if (['submit', 'button', 'reset', 'image', 'hidden'].includes(type)) return '';
    return 'text';
  };
  const within = (node, root) => {
    let current = node;
    while (current) {
      if (current === root) return true;
      current = current.parentNode || (current.host || null);
    }
    return false;
  };
  const hasPointerCursor = (node) => {
    // A framework button carries no handler attribute: React and Svelte bind at
    // the root listener, Vue leaves "@click". What every one of them does leave
    // behind is a pointer cursor, so that is the signal that finds them.
    const style = window.getComputedStyle(node);
    return Boolean(style) && style.cursor === 'pointer';
  };
  const CONTROL_TAGS = {button: true, summary: true};
  const CONTROL_INPUT_TYPES = {button: true, reset: true, submit: true, image: true};
  const CONTROL_ROLES = ['button', 'menuitem', 'tab', 'switch'];
  const SUBMIT_SELECTOR = 'button[type="submit"], input[type="submit"], input[type="image"],'
    + ' button:not([type])';
  const isControl = (node) => {
    const tag = node.tagName.toLowerCase();
    if (CONTROL_TAGS[tag]) return true;
    if (tag === 'input' && CONTROL_INPUT_TYPES[(node.getAttribute('type') || '').toLowerCase()]) return true;
    if (CONTROL_ROLES.includes(node.getAttribute('role'))) return true;
    // A framework binding is an attribute of its own dialect: Vue and Svelte
    // write "@click" or "v-on:click", a hand-rolled component "onclick".
    for (const name of node.getAttributeNames()) {
      const attribute = name.toLowerCase();
      if (attribute === 'onclick' || attribute.endsWith(':click') || attribute.startsWith('@')) return true;
    }
    return node.hasAttribute('tabindex') || hasPointerCursor(node);
  };
  const isField = (node) => {
    if (node.isContentEditable) return true;
    const tag = node.tagName.toLowerCase();
    return tag === 'input' || tag === 'textarea' || tag === 'select';
  };
  const isDecoration = (node) => {
    // A pointer cursor is evidence of interactivity, but on its own it is not
    // enough. An icon `<div>` or `<span>` in a site toolbar carries
    // cursor:pointer, has no text, no role and no name, and clicking it can only
    // ever time out. Measured on a real admin login: 240 candidates, and the
    // ones that failed were exactly these — a bare `div.toolbar_logo_img`.
    //
    // The test is deliberately the same one that produces the label, so the two
    // can never disagree. Asking "does it have a name?" separately let an
    // asset name pass the first question while the second question discarded it,
    // and the control then reached the report with an empty label.
    const tag = node.tagName.toLowerCase();
    if (CONTROL_TAGS[tag]) return false;
    if (CONTROL_ROLES.includes(node.getAttribute('role'))) return false;
    for (const name of node.getAttributeNames()) {
      const attribute = name.toLowerCase();
      if (attribute === 'onclick' || attribute.endsWith(':click') || attribute.startsWith('@')) return false;
    }
    return !controlLabel(node);
  };

  const forms = [];
  const freeFields = [];
  const controls = [];
  const controlNodes = [];
  const inForm = new Set();

  for (const root of roots) {
    const all = Array.from(root.querySelectorAll('*'));
    for (const form of all.filter(node => node.tagName.toLowerCase() === 'form')) {
      // A form box can be zero-sized while its own controls are laid out, so
      // form visibility is decided per control and never on the form element.
      // The form is still marked first, because a form with no submit control is
      // submitted through the DOM and needs to be addressed as itself.
      const formEntry = mark(form, {label: label(form)});
      const fields = [];
      // form.elements is the canonical collection: it also holds controls that
      // live outside the element and are associated with it by form="id".
      for (const node of Array.from(form.elements || [])) {
        const kind = fieldKind(node);
        if (!kind || !visible(node)) continue;
        const entry = mark(node, {
          kind: kind,
          name: node.getAttribute('name') || node.id || '',
          label: label(node),
        });
        if (!entry) continue;
        inForm.add(node);
        fields.push(entry);
      }
      const submits = [];
      for (const node of Array.from(form.querySelectorAll(SUBMIT_SELECTOR))) {
        const canUse = fields.length > 0 ? visibleLayout(node) : visible(node);
        if (tagged.has(node) || !canUse) continue;
        const entry = mark(node, {label: label(node)});
        if (!entry) continue;
        inForm.add(node);
        submits.push(entry);
      }
      const pre = [];
      for (const node of all) {
        // A handler inside a form often reveals or enables the fields above it,
        // so it runs before the fields are filled. Never include anchors (<a>)
        // here: clicking "Forgot your password?" navigates away from the form
        // before any field is filled.
        const tag = node.tagName.toLowerCase();
        if (tag === 'a' || tagged.has(node) || !within(node, form) || !isControl(node)) continue;
        if (!visible(node)) continue;
        const entry = mark(node, {label: label(node), tag: tag});
        if (!entry) continue;
        inForm.add(node);
        pre.push(entry);
      }
      if (!fields.length && !submits.length && !pre.length) continue;
      forms.push({
        selector: formEntry.selector,
        label: formEntry.label,
        method: (form.getAttribute('method') || 'get').toLowerCase(),
        action: form.getAttribute('action') || '',
        fields: fields,
        submits: submits,
        pre: pre,
      });
    }

    for (const node of all) {
      if (inForm.has(node) || tagged.has(node) || !isField(node)) continue;
      const kind = fieldKind(node);
      if (!kind || !visible(node)) continue;
      const entry = mark(node, {
        kind: kind,
        name: node.getAttribute('name') || node.id || '',
        label: label(node),
      });
      if (entry) freeFields.push(entry);
    }

    for (const node of all) {
      if (inForm.has(node) || tagged.has(node) || !isControl(node)) continue;
      const tag = node.tagName.toLowerCase();
      if (tag === 'option' || tag === 'html' || tag === 'body') continue;
      // Anchors are the crawler's own frontier: they are already queued as
      // pages, and clicking them would only reload a URL it is going to visit.
      if (node.hasAttribute('href') && (tag === 'a' || tag === 'area')) continue;
      if (!visible(node)) continue;
      if (isDecoration(node)) continue;
      // A child of a control is part of that control, not a control of its own.
      // A `div[role=button]` wrapping an icon span used to yield two
      // candidates — the wrapper and the span — and the span could only time
      // out. Nodes come in document order, so an ancestor is always seen first.
      if (controlNodes.some(seen => within(node, seen))) continue;
      const entry = mark(node, {label: controlLabel(node), tag: tag});
      if (entry) {
        controls.push(entry);
        controlNodes.push(node);
      }
    }
  }
  return {forms: forms, fields: freeFields, controls: controls};
}"""


async def discover_interactions(page):
    """Read the live DOM and return the automatic form/control plan.

    Every candidate is tagged with a throwaway ``data-rr-auto`` attribute
    instead of a synthesised CSS path. A generated selector has to survive
    markup that re-renders between discovery and the click, and a per-pass
    index is the only addressing that is both short and unambiguous.
    """
    script = AUTO_DISCOVERY_SCRIPT.replace("__AUTO_ATTRIBUTE__", AUTO_ATTRIBUTE)
    plan = await page.evaluate(script)
    if not isinstance(plan, dict):
        return {"forms": [], "fields": [], "controls": []}

    def entries(key):
        return [item for item in plan.get(key) or [] if isinstance(item, dict)]

    return {"forms": entries("forms"), "fields": entries("fields"), "controls": entries("controls")}


AUTO_ACTIVITY_ATTR = "_rr_inflight"


def track_page_activity(page):
    """Count the requests the page still has in flight.

    A single-page app paints its form from the response to its own API call, so
    reading the DOM while that call is open reads the previous screen. The count
    lives on the page object because that is the one object both the crawler and
    the wait share; it is set up once per page and never reset mid-wait, so a
    request that started during navigation is still visible afterwards.
    """
    counter = {"open": 0}
    setattr(page, AUTO_ACTIVITY_ATTR, counter)

    def opened(_request):
        counter["open"] += 1

    def closed(_request=None):
        if counter["open"] > 0:
            counter["open"] -= 1

    page.on("request", opened)
    page.on("requestfinished", closed)
    page.on("requestfailed", closed)
    page.on("close", closed)
    return counter


def page_activity_pending(page):
    """Whether any request this page started is still running."""
    counter = getattr(page, AUTO_ACTIVITY_ATTR, None)
    if not isinstance(counter, dict):
        return False
    return int(counter.get("open") or 0) > 0


def plan_candidate_count(plan):
    """How many things the automatic pass could act on in this plan."""
    if not isinstance(plan, dict):
        return 0
    return sum(len(plan.get(key) or []) for key in ("forms", "fields", "controls"))


async def await_auto_plan(page, wait_ms, settle_ms=AUTO_SETTLE_MS,
                          stable_window_ms=AUTO_SETTLE_STABLE_MS):
    """Wait until the page has something to act on, then return that plan.

    The automatic pass used to read the DOM a fixed 150 ms after
    `domcontentloaded`. On a single-page app that is before the app has
    answered its own API call and rendered its form, so the pass found nothing
    and reported a coverage the crawl never had: a login page produced zero
    actions and zero captured fetch requests.

    Polling for the first candidate is what makes an app-rendered form
    reachable. The bound is the analyst's, it is reported back in the job
    result, and a page that never renders anything does not hang the crawl — it
    is reported as a timeout together with the milliseconds actually spent.

    The first candidate is not the same as a settled page, and on a real login
    the difference is the whole job. Measured on an admin login of a large .ru
    site: the site toolbar is there the instant the DOM is ready, so the wait
    returned after 206 ms with 38 candidates that were all chrome, and the login
    form that arrived a second later was never seen. Waiting for the *first*
    candidate locks the pass onto whatever the page had while it was still
    loading.

    Settled means three things together, and each of them was earned by a
    measurement rather than by taste:

    * the candidate set is identical to the previous reading;
    * it has been identical for `AUTO_SETTLE_STABLE_MS`, because a 150 ms gap
      is not evidence of anything on a page that draws its form a second later;
    * nothing is in flight, because the app usually paints its form from a
      response, and reading the DOM during the request reads the old one.

    A page that stays empty still waits the whole bound and is still reported as
    a timeout, so an empty page can never be mistaken for a settled one.
    """
    started = time.monotonic()
    deadline = started + max(0, wait_ms) / 1000.0
    stable_ms = max(0, stable_window_ms) / 1000.0
    attempts = 0
    previous = None
    unchanged_since = None
    while True:
        attempts += 1
        plan = await discover_interactions(page)
        found = plan_candidate_count(plan)
        signature = plan_signature(plan)
        now = time.monotonic()
        if signature == previous and found > 0:
            if unchanged_since is None:
                unchanged_since = now
        else:
            unchanged_since = None
        previous = signature
        busy = page_activity_pending(page)
        settled = (
            found > 0
            and unchanged_since is not None
            and (now - unchanged_since) >= stable_ms
            and not busy
        )
        if settled:
            return plan, {
                "waited_ms": int((now - started) * 1000),
                "attempts": attempts,
                "candidates": found,
                "timed_out": False,
                "stable_ms": int((now - unchanged_since) * 1000),
            }
        if now >= deadline:
            return plan, {
                "waited_ms": int((now - started) * 1000),
                "attempts": attempts,
                "candidates": found,
                "timed_out": wait_ms > 0,
                "stable_ms": 0,
            }
        if settle_ms:
            await page.wait_for_timeout(settle_ms)
        else:
            await asyncio.sleep(0.05)


def plan_signature(plan):
    """A comparable summary of everything the pass could act on.

    Two readings with the same signature mean the page offered the same work
    twice in a row, which is the only evidence available that it has stopped
    changing. It is built from `candidate_signature`, so a page is "settled"
    exactly when the same candidates are still there — not when a counter
    happens to match.
    """
    if not isinstance(plan, dict):
        return ()
    parts = []
    for kind, key in (("form", "forms"), ("field", "fields"), ("control", "controls")):
        for candidate in plan.get(key) or []:
            parts.append(candidate_signature(kind, candidate))
    return tuple(parts)


def candidate_signature(kind, candidate):
    """Identify a candidate across discovery rounds.

    The per-pass `data-rr-auto` index is re-assigned on every discovery, so it
    cannot identify anything across rounds. What does stay the same is the
    candidate's own identity: what it posts to, what it is named, what it says.
    """
    if kind == "form":
        return ("form", candidate.get("action", ""), candidate.get("method", ""),
                tuple(sorted(str(field.get("name") or "") for field in (candidate.get("fields") or []))))
    if kind == "field":
        return ("field", candidate.get("name", ""), candidate.get("label", ""),
                candidate.get("kind", ""))
    return ("control", candidate.get("tag", ""), candidate.get("label", ""))


def auto_field_value(field):
    """Build a recognisable placeholder value for one discovered form field.

    The value carries its own field name, so an exchange that reaches the
    passive proxy can be traced back to the control that produced it without
    the analyst having written the selector.
    """
    name = str(field.get("name") or "").strip()
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:32] or "field"
    prefix = f"rr-auto-{slug}"
    kind = field.get("kind")
    if kind == "email":
        return f"{prefix}@example.test"
    if kind == "url":
        return f"https://{prefix}.example.test/"
    if kind == "tel":
        return "+380000000000"
    if kind == "password":
        return prefix
    if kind == "number":
        return "1"
    if kind == "range":
        return "50"
    if kind == "date":
        return "2000-01-01"
    if kind == "datetime-local":
        return "2000-01-01T10:00"
    if kind == "time":
        return "10:00"
    if kind == "month":
        return "2000-01"
    if kind == "week":
        return "2000-W01"
    if kind == "color":
        return "#43d9a3"
    return prefix


# --- Live browser view (Burp-style real-time viewport + action telemetry) ------
#
# Captures JPEG viewport frames via Playwright's `page.screenshot` (works identically
# across Firefox and Chromium without injecting anything into the target DOM, so
# `anti_detect` and page integrity stay untouched). Frames live under the private
# `_live` key on the in-memory job dict and are never serialized into `snapshot()`
# or persisted into Django's `TargetJob.result`.
LIVE_VIEW_JPEG_QUALITY = 50
LIVE_VIEW_SCREENSHOT_TIMEOUT_MS = 2500
LIVE_VIEW_AUTO_SCREENSHOT_TIMEOUT_MS = 900
LIVE_VIEW_AUTO_MIN_INTERVAL = 0.75
LIVE_VIEW_HISTORY_LIMIT = 25
LIVE_VIEW_TICK_SECONDS = 0.65
MANUAL_CONTROL_TICK_SECONDS = 0.25
ALLOWED_CONTROL_ACTIONS = frozenset({
    "take_control",
    "release_control",
    "click",
    "drag",
    "wheel",
    "type",
    "key",
    "reload",
    "back",
    # Typed actions for the in-app AI agent. Selector-based rather than
    # coordinate-based so an agent can repeat a QA step deterministically.
    "fill",
    "click_selector",
    "navigate",
})


def _ensure_control_state(job, loop=None):
    ctrl = job.get("_control")
    if not isinstance(ctrl, dict):
        ctrl = {
            "resume_event": None,
            "pages": {},
            "page_configs": {},
            "page_guards": {},
            "control_worker_id": None,
        }
        job["_control"] = ctrl
    if loop is not None and ctrl.get("resume_event") is None:
        ev = asyncio.Event()
        if not job.get("manual_control"):
            ev.set()
        ctrl["resume_event"] = ev
    return ctrl


def _is_manual_control(job_id):
    with JOBS_LOCK:
        return bool(JOBS.get(job_id, {}).get("manual_control"))


async def _wait_if_manual_control(job_id):
    """Pause the calling crawler worker while operator has manual browser control.

    Returns True if the worker actually paused for operator interaction (e.g.
    solving a captcha), so the caller can re-read the unlocked page URL/links.
    """
    waited = False
    while True:
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if job is None or job.get("cancelled"):
                return waited
            if not job.get("manual_control"):
                return waited
            ctrl = _ensure_control_state(job, asyncio.get_running_loop())
            ev = ctrl["resume_event"]
        waited = True
        await ev.wait()


def _unblock_manual_control(job, loop=None):
    ctrl = job.get("_control")
    if not isinstance(ctrl, dict):
        return
    ev = ctrl.get("resume_event")
    if ev is None:
        return
    target_loop = loop or job.get("_loop")
    if target_loop is not None and target_loop.is_running():
        try:
            target_loop.call_soon_threadsafe(ev.set)
        except Exception:
            pass


def _select_control_page(job, worker_id=None):
    ctrl = job.get("_control") or {}
    pages = ctrl.get("pages") or {}
    if not pages:
        return None, None, None, None
    live_state = job.get("_live") or {}
    candidates = [
        str(worker_id) if worker_id else None,
        ctrl.get("control_worker_id"),
        live_state.get("active_worker_id"),
        sorted(pages.keys(), key=lambda item: (len(item), item))[0],
    ]
    for cid in candidates:
        if cid and cid in pages:
            return (
                cid,
                pages[cid],
                (ctrl.get("page_configs") or {}).get(cid) or {"live_view": True},
                (ctrl.get("page_guards") or {}).get(cid),
            )
    return None, None, None, None


async def _execute_live_control_async(job_id, payload):
    action = str(payload.get("action") or "").strip().lower()
    if action not in ALLOWED_CONTROL_ACTIONS:
        return 400, {"error": f"unsupported control action: {action}"}
    req_worker_id = str(payload.get("worker_id") or "").strip() or None

    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            return 404, {"error": "target job not found"}
        if job.get("status") in {"completed", "failed", "cancelled"}:
            return 409, {"error": f"target job is already {job.get('status')}"}
        ctrl = _ensure_control_state(job, asyncio.get_running_loop())
        ev = ctrl["resume_event"]
        if action == "take_control":
            job["manual_control"] = True
            job["live_view"] = True
            ev.clear()
            if req_worker_id:
                ctrl["control_worker_id"] = req_worker_id
        elif action == "release_control":
            job["manual_control"] = False
            ctrl["control_worker_id"] = None
        wid, page, page_cfg, guard = _select_control_page(job, req_worker_id)
        if action == "take_control" and wid:
            ctrl["control_worker_id"] = wid

    if action == "take_control":
        if page is not None:
            await _capture_live_frame(
                job_id,
                wid,
                page,
                {**page_cfg, "live_view": True},
                action={"type": "manual", "label": "Manual control active — solve captcha"},
                inflight_guard=guard,
                force=True,
            )
        snap = live_snapshot(job_id, worker_id=wid) or {}
        snap["ok"] = True
        snap["manual_control"] = True
        return 200, snap

    if action == "release_control":
        if page is not None:
            await _capture_live_frame(
                job_id,
                wid,
                page,
                {**page_cfg, "live_view": True},
                action={"type": "resume", "label": "Resuming crawler with updated session"},
                inflight_guard=guard,
                force=True,
            )
        ev.set()
        snap = live_snapshot(job_id, worker_id=wid) or {}
        snap["ok"] = True
        snap["manual_control"] = False
        return 200, snap

    if page is None:
        return 409, {"error": "no active browser tab available for manual control"}

    action_meta = {"type": "manual"}
    try:
        if action == "click":
            x = float(payload.get("x", 0))
            y = float(payload.get("y", 0))
            button = str(payload.get("button") or "left").lower()
            if button not in {"left", "right", "middle"}:
                button = "left"
            click_count = max(1, min(3, int(payload.get("click_count", 1))))
            await page.mouse.click(x, y, button=button, click_count=click_count)
            action_meta = {"type": "click", "label": f"Manual click ({int(x)}, {int(y)})", "x": round(x, 1), "y": round(y, 1)}
            await asyncio.sleep(0.18)
        elif action == "drag":
            sx = float(payload.get("start_x", 0))
            sy = float(payload.get("start_y", 0))
            ex = float(payload.get("end_x", sx))
            ey = float(payload.get("end_y", sy))
            steps = max(4, min(40, int(payload.get("steps", 16))))
            await page.mouse.move(sx, sy)
            await page.mouse.down()
            await page.mouse.move(ex, ey, steps=steps)
            await page.mouse.up()
            action_meta = {"type": "click", "label": f"Manual drag ({int(sx)},{int(sy)}) → ({int(ex)},{int(ey)})", "x": round(ex, 1), "y": round(ey, 1)}
            await asyncio.sleep(0.22)
        elif action == "wheel":
            x = float(payload.get("x", 640))
            y = float(payload.get("y", 360))
            dx = float(payload.get("delta_x", 0))
            dy = float(payload.get("delta_y", 0))
            await page.mouse.move(x, y)
            await page.mouse.wheel(dx, dy)
            action_meta = {"type": "frame", "label": "Manual scroll", "x": round(x, 1), "y": round(y, 1)}
            await asyncio.sleep(0.12)
        elif action == "type":
            text = str(payload.get("text") or "")[:500]
            if text:
                await page.keyboard.type(text, delay=20)
            action_meta = {"type": "fill", "label": "Manual input", "value": text[:40]}
            await asyncio.sleep(0.12)
        elif action == "key":
            key = str(payload.get("key") or "").strip()[:40]
            if not key:
                return 400, {"error": "key is required"}
            await page.keyboard.press(key)
            action_meta = {"type": "fill", "label": f"Key: {key}"}
            await asyncio.sleep(0.15)
        elif action == "fill":
            selector = str(payload.get("selector") or "").strip()[:240]
            if not selector:
                return 400, {"error": "selector is required"}
            value = str(payload.get("value") or "")[:500]
            target = page.locator(selector).first
            await target.fill(value, timeout=8000)
            # A credential typed into a password field must never reach the
            # live history, the agent context or a log line.
            try:
                input_type = str(await target.get_attribute("type") or "").lower()
            except Exception:
                input_type = ""
            if input_type == "password" or "password" in selector.lower():
                shown = "••••"
            else:
                shown = value[:40]
            action_meta = {"type": "fill", "label": f"Fill {selector[:60]}", "selector": selector[:120], "value": shown}
            await asyncio.sleep(0.12)
        elif action == "click_selector":
            selector = str(payload.get("selector") or "").strip()[:240]
            if not selector:
                return 400, {"error": "selector is required"}
            button = str(payload.get("button") or "left").lower()
            if button not in {"left", "right", "middle"}:
                button = "left"
            await page.locator(selector).first.click(button=button, timeout=8000)
            action_meta = {"type": "click", "label": f"Click {selector[:60]}", "selector": selector[:120]}
            await asyncio.sleep(0.18)
        elif action == "navigate":
            destination = str(payload.get("url") or "").strip()[:2048]
            parsed = urlparse(destination)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                return 400, {"error": "url must be an absolute http(s) URL"}
            await page.goto(destination, wait_until="domcontentloaded", timeout=15000)
            action_meta = {"type": "navigate", "label": f"Navigate {destination[:90]}", "url": destination[:240]}
            await asyncio.sleep(0.25)
        elif action == "reload":
            await page.reload(wait_until="domcontentloaded", timeout=15000)
            action_meta = {"type": "navigate", "label": f"Reload {str(page.url or '')[:90]}"}
            await asyncio.sleep(0.25)
        elif action == "back":
            await page.go_back(wait_until="domcontentloaded", timeout=10000)
            action_meta = {"type": "navigate", "label": f"Back {str(page.url or '')[:90]}"}
            await asyncio.sleep(0.25)
    except Exception as err:
        return 502, {"error": f"manual control action failed: {one_line(str(err))}"}

    await _capture_live_frame(
        job_id,
        wid,
        page,
        {**page_cfg, "live_view": True},
        action=action_meta,
        record_history=(action != "wheel"),
        inflight_guard=guard,
        force=True,
    )
    snap = live_snapshot(job_id, worker_id=wid) or {}
    snap["ok"] = True
    return 200, snap


def execute_live_control(job_id, payload, timeout=18.0):
    """Bridge synchronous HTTP handler to the job's asyncio event loop."""
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            return 404, {"error": "target job not found"}
        loop = job.get("_loop")
    if loop is None or not loop.is_running():
        return 409, {"error": "browser crawler event loop is not running"}
    future = asyncio.run_coroutine_threadsafe(
        _execute_live_control_async(job_id, payload),
        loop,
    )
    try:
        return future.result(timeout=timeout)
    except TimeoutError:
        return 504, {"error": "manual control action timed out"}
    except Exception as err:
        return 502, {"error": one_line(str(err))}


def _ensure_live_state(job):
    state = job.get("_live")
    if not isinstance(state, dict):
        state = {
            "seq": 0,
            "active_worker_id": None,
            "workers": {},
            "history": [],
            "last_capture_monotonic": 0.0,
        }
        job["_live"] = state
    return state


async def _capture_live_frame(
    job_id,
    worker_id,
    page,
    config,
    action=None,
    locator=None,
    record_history=True,
    inflight_guard=None,
    force=False,
):
    """Capture one viewport frame and action metadata for Live View (best-effort).

    During automated crawling (`force=False` and `manual_control=False`), frames
    are rate-limited per job (`LIVE_VIEW_AUTO_MIN_INTERVAL`) so high-concurrency
    crawls never stall on back-to-back screenshots across multiple tabs.
    """
    if not config.get("live_view"):
        return
    manual_now = _is_manual_control(job_id)
    now_mono = time.monotonic()
    if not force and not manual_now:
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if job is None:
                return
            state = _ensure_live_state(job)
            last_cap = float(state.get("last_capture_monotonic") or 0.0)
            if (now_mono - last_cap) < LIVE_VIEW_AUTO_MIN_INTERVAL:
                return
            # Reserve the slot immediately so parallel workers do not pile up screenshots.
            state["last_capture_monotonic"] = now_mono
    if inflight_guard is not None:
        if inflight_guard.get("busy"):
            return
        inflight_guard["busy"] = True
    try:
        box = None
        if locator is not None:
            try:
                raw_box = await locator.bounding_box(timeout=250)
                if isinstance(raw_box, dict):
                    box = {
                        "x": round(float(raw_box.get("x", 0.0)), 1),
                        "y": round(float(raw_box.get("y", 0.0)), 1),
                        "width": round(float(raw_box.get("width", 0.0)), 1),
                        "height": round(float(raw_box.get("height", 0.0)), 1),
                    }
            except Exception:
                box = None

        action_payload = dict(action) if isinstance(action, dict) else {"type": "frame"}
        if box is not None:
            action_payload["box"] = box
            action_payload.setdefault("x", round(box["x"] + box["width"] / 2.0, 1))
            action_payload.setdefault("y", round(box["y"] + box["height"] / 2.0, 1))

        shot_timeout = (
            LIVE_VIEW_SCREENSHOT_TIMEOUT_MS
            if (force or manual_now)
            else LIVE_VIEW_AUTO_SCREENSHOT_TIMEOUT_MS
        )
        try:
            raw_jpeg = await page.screenshot(
                type="jpeg",
                quality=LIVE_VIEW_JPEG_QUALITY,
                timeout=shot_timeout,
                animations="disabled",
            )
        except TypeError:
            raw_jpeg = await page.screenshot(
                type="jpeg",
                quality=LIVE_VIEW_JPEG_QUALITY,
                timeout=shot_timeout,
            )
        image_b64 = base64.b64encode(raw_jpeg).decode("ascii")
        viewport = page.viewport_size or {"width": 1280, "height": 720}
        try:
            title = (await page.title()) or ""
        except Exception:
            title = ""
        url = str(getattr(page, "url", "") or "")
        now = time.time()
        worker_key = str(worker_id)

        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if job is None:
                return
            state = _ensure_live_state(job)
            state["seq"] += 1
            seq = state["seq"]
            job["live_seq"] = seq
            state["active_worker_id"] = worker_key
            frame = {
                "seq": seq,
                "ts": now,
                "worker_id": worker_key,
                "url": url,
                "title": title[:160],
                "viewport": {
                    "width": int(viewport.get("width") or 1280),
                    "height": int(viewport.get("height") or 720),
                },
                "action": action_payload,
                "image_b64": image_b64,
                "mime": "image/jpeg",
            }
            state["workers"][worker_key] = frame
            if record_history and action_payload.get("type") not in {None, "frame"}:
                entry = {
                    "seq": seq,
                    "ts": now,
                    "worker_id": worker_key,
                    "type": str(action_payload.get("type") or ""),
                    "label": str(action_payload.get("label") or "")[:100],
                    "selector": str(action_payload.get("selector") or "")[:120],
                    "url": url[:240],
                    "value": action_payload.get("value"),
                }
                state["history"].append(entry)
                if len(state["history"]) > LIVE_VIEW_HISTORY_LIMIT:
                    del state["history"][:-LIVE_VIEW_HISTORY_LIMIT]
    except Exception:
        # Live preview is purely observational and must never break or stall a crawl.
        return
    finally:
        if inflight_guard is not None:
            inflight_guard["busy"] = False
            inflight_guard["last_ts"] = time.monotonic()


def live_snapshot(job_id, worker_id=None, since=0):
    """Return the latest Live View frame + action log for a browser job."""
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            return None
        status = str(job.get("status", "unknown"))
        live_enabled = bool(job.get("live_view", False))
        state = job.get("_live") or {}
        seq = int(state.get("seq") or 0)
        workers_map = state.get("workers") or {}
        worker_ids = sorted(workers_map.keys(), key=lambda item: (len(item), item))
        active_id = state.get("active_worker_id")
        selected_id = str(worker_id) if worker_id and str(worker_id) in workers_map else active_id
        frame = workers_map.get(selected_id) if selected_id else None
        history = list(state.get("history") or [])
        base = {
            "job_id": job_id,
            "status": status,
            "live_view": live_enabled,
            "manual_control": bool(job.get("manual_control", False)),
            "seq": seq,
            "active_worker_id": active_id,
            "worker_id": selected_id,
            "workers": worker_ids,
            "visited": int(job.get("visited") or 0),
            "total": int(job.get("total") or 0),
            "history": history,
        }
        if frame is None:
            base["has_frame"] = False
            return base
        frame_seq = int(frame.get("seq") or 0)
        if since and since >= frame_seq and not (worker_id and str(worker_id) != active_id):
            base["has_frame"] = True
            base["unchanged"] = True
            return base
        base["has_frame"] = True
        base["unchanged"] = False
        base["frame"] = dict(frame)
        return base


_LOGOUT_PATH_RE = re.compile(
    r"(^|/)(logout|log-out|log_out|signout|sign-out|sign_out|disconnect)(\.[a-z0-9]+)?(/|$)",
    re.I,
)
_LOGOUT_LABEL_RE = re.compile(
    r"\b(log\s*out|sign\s*out|вийти|выйти)\b",
    re.I,
)

# Valid 1x1 transparent PNG (67 bytes) for safe <input type="file"> testing.
MINIMAL_PNG_BYTES = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01"
    b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)

MAX_AUTO_CONTROLS_PER_PAGE = 12

_OVERLAY_DISMISS_SELECTORS = (
    'button[aria-label*="Close Welcome Banner" i]',
    'button[aria-label*="Dismiss" i]',
    'a[aria-label*="dismiss cookie" i]',
    '.cc-dismiss',
    'button:has-text("Dismiss")',
    'button:has-text("Me want it")',
    'button:has-text("Accept all")',
    'button:has-text("Accept cookies")',
    '[role="dialog"] button[aria-label*="Close" i]',
    '.cdk-overlay-pane button[aria-label*="Close" i]',
)


def is_logout_url(url):
    """Return True if URL looks like a destructive logout endpoint."""
    try:
        parsed = urlparse(str(url or ""))
    except Exception:
        return False
    path = (parsed.path or "").strip()
    frag = (parsed.fragment or "").strip()
    query = (parsed.query or "").strip()
    if _LOGOUT_PATH_RE.search(path):
        return True
    if frag.startswith("/") and _LOGOUT_PATH_RE.search(frag):
        return True
    if re.search(r"(^|&)(action|cmd|op)=logout(&|$)", query, re.I):
        return True
    return False


def is_logout_label(label):
    return bool(_LOGOUT_LABEL_RE.search(str(label or "")))


def _normalize_crawl_url(url):
    """Strip anchor fragments (#section) while preserving SPA hash routes (#/...)."""
    raw = str(url or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    if parsed.fragment and (parsed.fragment.startswith("/") or parsed.fragment.startswith("!/")):
        return raw
    return urldefrag(raw)[0]


async def _page_html_fingerprint(page):
    """Compact fingerprint of page HTML shell for SPA soft-404 detection."""
    try:
        info = await page.evaluate(
            """() => {
              const title = document.title || '';
              const text = (document.body ? document.body.innerText : '') || '';
              const rootHtml = (document.documentElement ? document.documentElement.innerHTML : '') || '';
              return {
                title: title.slice(0, 120),
                textLen: text.trim().length,
                textHead: text.trim().slice(0, 300),
                htmlHead: rootHtml.slice(0, 600),
              };
            }"""
        )
        if isinstance(info, dict):
            return (
                info.get("title", ""),
                int(info.get("textLen") or 0),
                info.get("textHead", ""),
                info.get("htmlHead", ""),
            )
    except Exception:
        return None
    return None


def _looks_like_spa_soft_404(fp, root_fp):
    if not fp or not root_fp:
        return False
    # Same title and nearly identical visible text / HTML head as the SPA root
    if fp[0] != root_fp[0]:
        return False
    if fp[2] and fp[2] == root_fp[2]:
        return True
    if fp[3] and fp[3] == root_fp[3] and abs(fp[1] - root_fp[1]) <= 40:
        return True
    return False


async def _dismiss_blocking_overlays(page):
    """Best-effort fast (~2ms) dismissal of welcome modals and cookie banners."""
    try:
        dismissed = await page.evaluate(
            """() => {
              const isVis = (el) => {
                if (!el || el.disabled) return false;
                const st = window.getComputedStyle(el);
                if (!st || st.display === 'none' || st.visibility === 'hidden' || st.opacity === '0') return false;
                const r = el.getBoundingClientRect();
                return r.width > 0 && r.height > 0;
              };
              let clicked = 0;
              const directSelectors = [
                'button[aria-label*="Close Welcome Banner" i]',
                'button[aria-label*="Dismiss" i]',
                'a[aria-label*="dismiss cookie" i]',
                '.cc-dismiss',
                '[role="dialog"] button[aria-label*="Close" i]',
                '.cdk-overlay-pane button[aria-label*="Close" i]',
              ];
              for (const sel of directSelectors) {
                const el = document.querySelector(sel);
                if (el && isVis(el)) {
                  try { el.click(); clicked++; } catch (e) {}
                }
              }
              const textRe = /^(dismiss|me want it!?|accept all|accept cookies|got it|close welcome banner)$/i;
              for (const el of document.querySelectorAll('button, a.cc-btn, [role="dialog"] button, .cdk-overlay-pane button')) {
                if (!isVis(el)) continue;
                const txt = (el.innerText || el.textContent || '').trim().replace(/\\s+/g, ' ');
                if (txt.length <= 40 && textRe.test(txt)) {
                  try { el.click(); clicked++; } catch (e) {}
                }
              }
              return clicked;
            }"""
        )
        if dismissed:
            await page.wait_for_timeout(150)
        return int(dismissed or 0)
    except Exception:
        return 0


async def fill_auto_field(page, field, live_hook=None):
    """Drive one discovered field and report what the DOM actually received."""
    locator = page.locator(field["selector"]).first
    kind = field["kind"]
    field_label = field.get("label") or field.get("name") or field.get("selector") or kind

    async def _emit_fill(val):
        if live_hook is None:
            return
        shown_val = "••••" if kind == "password" else str(val or "")[:40]
        await live_hook(
            {
                "type": "fill",
                "label": str(field_label)[:80],
                "selector": str(field.get("selector") or "")[:120],
                "kind": kind,
                "value": shown_val,
            },
            locator=locator,
        )

    if kind == "file":
        await _emit_fill("rr_probe.png")
        await locator.set_input_files(
            {
                "name": "rr_probe.png",
                "mimeType": "image/png",
                "buffer": MINIMAL_PNG_BYTES,
            }
        )
        return {"interaction": "upload", "value": "rr_probe.png"}
    if kind == "checkbox":
        was_checked = await locator.is_checked()
        await _emit_fill("checked" if not was_checked else "already checked")
        if not was_checked:
            await locator.check(force=True)
        return {"interaction": "check", "value": "checked" if not was_checked else "already checked"}
    if kind == "radio":
        await _emit_fill("selected")
        await locator.check(force=True)
        return {"interaction": "check", "value": "selected"}
    if kind == "select":
        options = await locator.locator("option").all()
        for option in options:
            if await option.is_disabled():
                continue
            value = await option.get_attribute("value")
            if value not in (None, ""):
                await _emit_fill(value)
                await locator.select_option(value)
                return {"interaction": "select", "value": value}
            text = (await option.inner_text() or "").strip()
            if text:
                await _emit_fill(text)
                await locator.select_option(label=text)
                return {"interaction": "select", "value": text}
        await _emit_fill("first option")
        await locator.select_option(index=0)
        return {"interaction": "select", "value": "first option"}
    if kind == "range":
        # Playwright refuses to type into a range input, so the value is set
        # and the same input/change events a real drag would fire are dispatched.
        value = auto_field_value(field)
        await _emit_fill(value)
        await locator.evaluate(
            """(node, value) => {
              node.value = value;
              node.dispatchEvent(new Event('input', {bubbles: true}));
              node.dispatchEvent(new Event('change', {bubbles: true}));
            }""",
            value,
        )
        return {"interaction": "set", "value": value}
    value = auto_field_value(field)
    # Playwright waits out its full actionability timeout on an input it can
    # never type into: 30 s per field, measured on a real admin toolbar where
    # a readonly box is a permanent part of the chrome. Editability is knowable
    # now, so the pass says why instead of waiting to learn the same way. This
    # is not a shorter budget for the operator — the fill still happens, in full,
    # whenever the field is editable.
    if not await locator.is_editable(timeout=3000):
        raise RuntimeError(
            "field cannot be edited: it is readonly, disabled, or not rendered"
        )
    await _emit_fill(value)
    await human_input.type_into(locator, value, _human_rng, clear=False)
    return {"interaction": "fill", "value": value}


async def click_auto_control(page, control, timeout_ms=AUTO_ACTION_TIMEOUT_MS, live_hook=None):
    locator = page.locator(control["selector"]).first
    if live_hook is not None:
        await live_hook(
            {
                "type": "click",
                "label": str(control.get("label") or control.get("tag") or control.get("selector") or "control")[:80],
                "selector": str(control.get("selector") or "")[:120],
            },
            locator=locator,
        )
    await human_input.click_control(
        page, locator, timeout_ms, _human_rng
    )


async def perform_auto_interactions(page, config, job_id, reset_url, live_hook=None):
    """Drive every form, field and control the automatic pass found on a page.

    Returns ``(actions, wait_report)``. The wait report is deliberately not an
    entry in ``actions``: that list is what a consumer reads as "what the pass
    did to this page", and a bookkeeping row about waiting would show up as an
    action that was never taken.

    The plan is not read once. It is read after waiting for the page to render
    something to act on, and read again after every reload, because an app
    reveals a second step — a password field after an email step, a control
    that only exists once a form is valid — and a pass that only ever looked
    once would report the first screen of the app and call it the page.

    Each candidate still runs in isolation: the page is reloaded before it, so
    a form submit cannot remove the selectors the remaining candidates depend
    on, and a page that changed under the crawler is reported as such instead
    of being silently skipped. ``auto_fill`` and ``auto_click`` narrow the pass
    to forms or to controls; by default both run.
    """
    results = []
    fill_forms = config["auto_fill"]
    click_controls = config["auto_click"]
    wait_ms = config.get("auto_wait_timeout_ms", DEFAULT_AUTO_WAIT_TIMEOUT_MS)
    has_auth = bool(config.get("cookies") or config.get("custom_headers"))
    # Dismiss welcome dialogs / cookie banners (e.g. OWASP Juice Shop modal) before
    # discovering forms so inputs underneath are visible and interactable.
    await _dismiss_blocking_overlays(page)
    discovered, wait_report = await await_auto_plan(page, wait_ms)
    form_count = len(discovered["forms"]) if fill_forms else 0
    field_count = len(discovered["fields"]) if fill_forms else 0
    control_count = min(len(discovered["controls"]), MAX_AUTO_CONTROLS_PER_PAGE) if click_controls else 0
    if not form_count and not field_count and not control_count:
        return results, wait_report
    # A submit or a button click can navigate away, which invalidates every
    # selector of the plan taken before it. This flag says whether the current
    # `discovered` plan still describes the page in front of us.
    plan_is_fresh = True
    # The plan as the page looked immediately after the last submit or click.
    #
    # This exists because the isolation reload and a multi-step flow pull in
    # opposite directions: the reload is what stops one candidate from breaking
    # the next, and it also throws away the very state a second step lives in
    # (a password field that only appears after the email step was submitted).
    # So the plan is read while it is still true, right after the action that
    # produced it, and the next round works from that.
    plan_after_action = None
    # Set when the page can no longer be reloaded between candidates. Everything
    # already collected stays in `results`: a reload that fails at the end of the
    # pass must not erase the evidence of the actions that did run.
    plan_unavailable = None

    async def current_plan():
        nonlocal plan_is_fresh, discovered, plan_unavailable
        # A plan we already hold comes first, and that order is load-bearing.
        # The reload guard is about re-reading a stale plan; when the plan in
        # hand is the one the last action produced, it is still the truth about
        # the page, and short-circuiting on the failed reload instead would throw
        # away the only plan that can reach a second step at all.
        if plan_is_fresh:
            return discovered
        if plan_unavailable is not None:
            return {"forms": [], "fields": [], "controls": []}
        # If the previous action stayed on the same URL (typical in SPAs like
        # Angular/React when toggling menus or submitting XHR forms), re-read the
        # live DOM directly instead of paying a full 3-8s SPA page reload per control.
        if _normalize_crawl_url(page.url or "") == _normalize_crawl_url(reset_url):
            await _dismiss_blocking_overlays(page)
            discovered = await discover_interactions(page)
            plan_is_fresh = True
            return discovered
        try:
            await page.goto(
                reset_url,
                wait_until="domcontentloaded",
                # The same deadline the crawl navigates with. A separate, shorter
                # hardcoded bound here meant a pass could fill a form and then
                # lose the record of it to a timeout the analyst never set.
                timeout=config["navigation_timeout_ms"],
            )
        except Exception as error:  # noqa: BLE001 - a dead page is evidence, not a lost pass
            plan_unavailable = str(error)
            # A timed-out goto does not cancel the navigation: it keeps running,
            # and whatever it finally delivers replaces the DOM. Measured on a
            # two-step login — the password field was found, and then destroyed
            # mid-fill by the reset that had already timed out. window.stop()
            # ends the in-flight load and leaves the page as the last action
            # actually left it, which is the state the next round reads.
            try:
                await page.evaluate("() => window.stop()")
            except Exception:  # noqa: BLE001 - the navigation may already be gone
                pass
            results.append({
                "kind": "auto_reset",
                "status": "failed",
                "error": plan_unavailable,
            })
            return {"forms": [], "fields": [], "controls": []}
        # The reload gets the same treatment as the first read: the app starts
        # over and has to answer its API call again before the form is back.
        await _dismiss_blocking_overlays(page)
        discovered, _report = await await_auto_plan(page, wait_ms)
        plan_is_fresh = True
        return discovered

    async def capture(record):
        record["result_url"] = page.url
        try:
            record["result_title"] = (await page.title())[:120]
        except Exception:  # noqa: BLE001 - a title is evidence, never a blocker
            record["result_title"] = ""
        record["links"] = await extract_links(page, page.url or reset_url)
        return record

    async def _plan_after_action():
        """Read the page right after an action, while the new state holds.

        A failure here is not the pass failing: the action already happened and
        is already recorded. The next round finds whatever it finds.
        """
        try:
            post_wait_ms = min(wait_ms, 1200)
            plan, _report = await await_auto_plan(page, post_wait_ms)
            return plan
        except Exception:  # noqa: BLE001 - the action is already recorded
            return None

    def missing(kind, index):
        return {
            "kind": kind,
            "index": index,
            "label": "",
            "status": "missing",
            "error": f"{kind} is no longer present after the page reload",
        }

    seen = set()
    interact_deadline = time.monotonic() + max(15.0, min(25.0, (wait_ms / 1000.0) * 4.0))

    async def run_pass():
        # The wrapped loops assign both of these, so without `nonlocal` they
        # would be locals of this function and every write would be lost: the
        # reload between candidates and the plan captured after an action both
        # live in the enclosing scope.
        nonlocal plan_is_fresh, plan_after_action
        for index in range(form_count):
            if is_cancelled(job_id):
                break
            await _wait_if_manual_control(job_id)
            if is_cancelled(job_id):
                break
            plan = await current_plan()
            if index >= len(plan["forms"]):
                if plan_unavailable is None:
                    results.append(missing("form", index))
                break
            form = plan["forms"][index]
            if candidate_signature("form", form) in seen:
                continue
            if config.get("same_origin"):
                raw_action = (form.get("action") or "").strip()
                if raw_action:
                    resolved_action = urldefrag(urljoin(page.url or reset_url, raw_action))[0]
                    start_parsed = urlparse(config["url"])
                    start_origin = f"{start_parsed.scheme}://{start_parsed.netloc}"
                    if urlparse(resolved_action).scheme in {"http", "https"} and not same_origin(resolved_action, start_origin):
                        seen.add(candidate_signature("form", form))
                        continue
            record = {
                "kind": "form",
                "index": index,
                "label": form.get("label", ""),
                "method": form.get("method", "get"),
                "action": form.get("action", ""),
                "fields": [
                    {"kind": field["kind"], "name": field.get("name", ""), "label": field.get("label", "")}
                    for field in form.get("fields", [])
                ],
                "clicked": 0,
                "filled": 0,
                "errors": [],
                "status": "pending",
            }
            if is_cancelled(job_id):
                record["status"] = "cancelled"
                results.append(record)
                break
            try:
                # A handler inside the form often reveals or enables the fields, so
                # it runs first and its own navigation invalidates nothing because
                # the next step re-resolves every selector from the live DOM.
                for handler in form.get("pre", []):
                    if is_cancelled(job_id):
                        record["status"] = "cancelled"
                        break
                    try:
                        await click_auto_control(page, handler, live_hook=live_hook)
                        record["clicked"] += 1
                    except Exception as error:  # noqa: BLE001 - one handler must not stop the form
                        record["errors"].append(f"click {handler.get('label') or handler['selector']}: {error}")
                for field, reported in zip(form.get("fields", []), record["fields"]):
                    if is_cancelled(job_id):
                        record["status"] = "cancelled"
                        break
                    try:
                        outcome = await fill_auto_field(page, field, live_hook=live_hook)
                        reported.update(outcome)
                        record["filled"] += 1
                    except Exception as error:  # noqa: BLE001 - one field must not stop the form
                        reported["error"] = str(error)
                        record["errors"].append(f"{field['kind']} {field.get('name') or field['selector']}: {error}")
                if record["status"] == "pending":
                    fillable = form.get("fields") or []
                    if not fillable or record["filled"] == 0:
                        # Measured on a real admin login: a form whose only
                        # "field" is a <button> without an explicit type is
                        # classified as a text field, the fill fails, and the
                        # form was still recorded as submitted. The report then
                        # counted a form that was never sent, and the reason sat
                        # in `errors` where nothing reads it. A form that took no
                        # value was not tested, so it is not submitted and it is
                        # reported as the failure it is — the same status a real
                        # failure already uses, so the summary counts it as
                        # failed instead of silently dropping it.
                        #
                        # The empty case is that same defect one step earlier, and
                        # the old guard missed it because it required `fields` to
                        # be non-empty. Site chrome is a form with a submit button
                        # and nothing to type into, so the pass submitted it on the
                        # way to the page's real form, the submit navigated away,
                        # and the form the analyst asked about was no longer on the
                        # page at all. Measured 2026-10-03 on the
                        # `/late-form-fetch` fixture: the record came back as
                        # `action: '/chrome', submit: 'requestSubmit',
                        # result_url: '/chrome?'`, and the API form was reported
                        # `missing after the page reload`.
                        #
                        # Nothing is lost by not submitting it here. A submit
                        # control is also collected as a **control**, so a button
                        # the analyst wants pressed is still pressed by the
                        # `auto_click` pass — the form pass is for forms that can
                        # actually take a value.
                        record["status"] = "error"
                        if not fillable:
                            record["error"] = (
                                "the form has no field to fill, so nothing was "
                                "submitted: submitting it would navigate away and "
                                "destroy the page under examination"
                            )
                        else:
                            record["error"] = (
                                f"no field of {len(fillable)} could be filled, "
                                f"so nothing was submitted: "
                                + (record["errors"][0] if record["errors"]
                                   else "no reason reported")
                            )
                    else:
                        if form.get("submits"):
                            await click_auto_control(page, form["submits"][0], live_hook=live_hook)
                            record["submit"] = "click"
                        else:
                            # A form with no visible submit control is still a reachable
                            # endpoint, so it is submitted through the DOM rather than
                            # reported as untested.
                            if live_hook is not None:
                                await live_hook(
                                    {
                                        "type": "submit",
                                        "label": str(form.get("label") or form.get("action") or "form")[:80],
                                        "selector": str(form.get("selector") or "")[:120],
                                    },
                                    locator=page.locator(form["selector"]).first if form.get("selector") else None,
                                )
                            await page.evaluate(
                                "(selector) => { const form = document.querySelector(selector);"
                                " if (form && typeof form.requestSubmit === 'function') form.requestSubmit(); }",
                                form["selector"],
                            )
                            record["submit"] = "requestSubmit"
                        record["status"] = "submitted"
                        plan_is_fresh = False
                        plan_after_action = await _plan_after_action()
                await page.wait_for_timeout(AUTO_SETTLE_MS)
                if live_hook is not None:
                    await live_hook(
                        {"type": "frame", "label": str(form.get("label") or "")[:80]},
                        record_history=False,
                    )
                await capture(record)
            except Exception as error:  # noqa: BLE001 - a failing form is evidence too
                record["status"] = "error"
                record["error"] = str(error)
                plan_is_fresh = False
            results.append(record)
            seen.add(candidate_signature("form", form))

        for index in range(field_count):
            if is_cancelled(job_id):
                break
            await _wait_if_manual_control(job_id)
            if is_cancelled(job_id):
                break
            plan = await current_plan()
            if index >= len(plan["fields"]):
                if plan_unavailable is None:
                    results.append(missing("field", index))
                break
            field = plan["fields"][index]
            if candidate_signature("field", field) in seen:
                continue
            record = {
                "kind": "field",
                "index": index,
                "label": field.get("label", ""),
                "type": field.get("kind", ""),
                "name": field.get("name", ""),
                "status": "pending",
            }
            try:
                record.update(await fill_auto_field(page, field, live_hook=live_hook))
                record["status"] = "filled"
            except Exception as error:  # noqa: BLE001 - a failing field is evidence too
                record["status"] = "error"
                record["error"] = str(error)
            results.append(record)
            seen.add(candidate_signature("field", field))

        for index in range(control_count):
            if is_cancelled(job_id):
                break
            await _wait_if_manual_control(job_id)
            if is_cancelled(job_id) or time.monotonic() >= interact_deadline:
                break
            plan = await current_plan()
            controls = plan["controls"]
            if index >= len(controls):
                if plan_unavailable is None:
                    results.append(missing("control", index))
                break
            control = controls[index]
            if candidate_signature("control", control) in seen:
                continue
            if has_auth and is_logout_label(control.get("label")):
                seen.add(candidate_signature("control", control))
                continue
            record = {
                "kind": "control",
                "index": index,
                "label": control.get("label", ""),
                "tag": control.get("tag", ""),
                "status": "pending",
            }
            try:
                await click_auto_control(page, control, live_hook=live_hook)
                record["status"] = "clicked"
                plan_is_fresh = False
                plan_after_action = await _plan_after_action()
                await page.wait_for_timeout(AUTO_SETTLE_MS)
                if live_hook is not None:
                    await live_hook(
                        {"type": "frame", "label": str(control.get("label") or "")[:80]},
                        record_history=False,
                    )
                await capture(record)
            except Exception as error:  # noqa: BLE001 - a failing control is evidence too
                record["status"] = "error"
                record["error"] = str(error)
                plan_is_fresh = False
            results.append(record)
            seen.add(candidate_signature("control", control))

    # An app can reveal a second step only after the first one was submitted: a
    # login that asks for an email and shows a password field afterwards. A pass
    # that reads the page once reports the first screen of the app and calls it
    # the page, so the pass goes round again and acts on what the previous round
    # brought into existence. Rounds are bounded and counted, and the count is
    # reported, so this is not an open-ended loop on a page that keeps
    # inventing controls.
    rounds = 0
    # `plan_unavailable` does not stop the rounds. It means the page can no
    # longer be reloaded, which is exactly the situation a second round is for:
    # the plan it needs was captured while the page still held that state, and
    # a failed reload must not take the next step down with it.
    while rounds < MAX_AUTO_ROUNDS:
        rounds += 1
        if rounds > 1:
            # The next round works from the plan that was read while the page
            # still held the state the previous action produced. It deliberately
            # neither reloads nor re-reads: the reload exists to isolate one
            # candidate from the next, and a second step exists only in the state
            # the first submit created, so both of them would destroy it.
            if plan_after_action is None:
                break
            discovered = plan_after_action
            form_count = len(discovered["forms"]) if fill_forms else 0
            field_count = len(discovered["fields"]) if fill_forms else 0
            control_count = min(len(discovered["controls"]), MAX_AUTO_CONTROLS_PER_PAGE) if click_controls else 0
            fresh = any(
                candidate_signature(kind, candidate) not in seen
                for kind, candidates in (
                    ("form", discovered["forms"]),
                    ("field", discovered["fields"]),
                    ("control", discovered["controls"]),
                )
                for candidate in candidates
            )
            if not fresh:
                break
            plan_is_fresh = True
        await run_pass()
        if is_cancelled(job_id):
            break
    wait_report["rounds"] = rounds
    return results, wait_report


# Chromium-family launch arguments that make every ICE interface use the proxy.
#
# Measured, not assumed. A page on a routed crawl reached a STUN server
# directly and adopted the address that server reported, which is the machine's
# own address rather than the route's — the crawl goes through the proxy, and
# WebRTC (UDP) simply went around it. This switch forces every candidate
# through the proxy, so there is no door beside the front one.
#
# What it deliberately does NOT do is remove anything: with the switch applied,
# RTCPeerConnection, RTCDataChannel and a completed gathering are all still
# present and observable. The alternative — deleting the constructor from the
# page — also stopped the leak but announced itself, because a real Chrome
# always has it, so a detector learned "WebRTC is disabled here" in one line.
# Measured on the same page: leak closed and undetectable with the switch, leak
# closed and trivially detectable without it.
#
# Applied only when a proxy is configured. On a direct crawl there is no route
# to protect, and adding it would break WebRTC for no reason.
#
# The cost is real and measured: WebRTC stops working entirely on a routed
# crawl. Pages with live video calls will not work; that is the owner's
# decision of 2026-10-01, taken knowing the price.
#
# Scope is the Chromium family only, and that limit is measured too: Firefox's
# media.peerconnection.ice.proxy_only_if_behind_proxy was tried with and
# without a proxy configured and changed nothing — the server-reflexive address
# still came back and the STUN server was still contacted once per probe. Firefox
# keeps today's behaviour, and the gap is recorded rather than covered with an
# unmeasured flag.
WEBRTC_PROXY_ONLY_ARGS = ("--force-webrtc-ip-handling-policy=disable_non_proxied_udp",)

# How often a dead Playwright driver may be rebuilt, in seconds.
#
# One rebuild per job is enough for the incident this exists for and is also the
# worst case: a driver that cannot be brought up would then be rebuilt on every
# request, each rebuild paying a process start and a browser measurement. Thirty
# seconds keeps a genuinely broken driver from turning into a rebuild storm while
# still recovering on the next job an operator runs.
_DRIVER_RECOVERY_INTERVAL = 30.0


# Every name `normalize_input` accepts, in the order the Target UI lists them.
# Only firefox and chromium are supported and installed in Request-Rider.
BROWSER_NAMES = ("firefox", "chromium")

CHROMIUM_CHANNEL_PATHS = {}
BROWSER_CHANNEL_BY_NAME = {}


def driver_platform(system=None):
    """The key the driver uses for this platform, or an explicit one for tests."""
    if system is not None:
        return system
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform.startswith("win"):
        return "win32"
    return sys.platform


def channel_executable_present(channel, system=None):
    """Whether the driver would find this Chromium channel on this machine."""
    path = CHROMIUM_CHANNEL_PATHS.get(channel, {}).get(driver_platform(system))
    return bool(path) and os.path.isfile(path)


async def _launch_probe(playwright, name, timeout):
    """Start `name`, open one page on it, and close everything. `(started, reason)`.

    Presence on disk is not the same question as "can this worker run it", and
    starting it is not the same question again as "can it open a page". Both steps
    were needed because each one hid a real failure on this machine.

    *Presence.* The first browser measured this way was `webkit`, which downloaded
    cleanly to `webkit_ubuntu20.04_x64_special-2092/pw_run.sh` — present and
    executable — and could not start at all, because Playwright serves a frozen
    `ubuntu20.04` build and it needed seven libraries the system did not have
    (`libicudata.so.66`, `libicui18n.so.66`, `libicuuc.so.66`, `libxml2.so.2`,
    `libjpeg.so.8`, `libwebp.so.6`, `libffi.so.7`). An answer built on
    `os.path.isfile` would have called that browser available and moved the failure
    into a running crawl.

    *Starting.* After those libraries were supplied, `webkit.launch()` returned and
    reported version 26.0 — while `new_page()` never returned. A launch-only probe
    reported it as available and browser-driven Target could not use it, so the probe
    opens a page before it calls a browser usable. (That browser has since been
    removed from the catalogue; the reasoning is kept because the failure is the
    reason the probe has three steps rather than one.)

    The probe closes everything and keeps nothing, so it does not reintroduce the
    warm browser the idle worker deliberately avoids holding. It runs once at
    startup, not per request, because `/health` is polled continuously.
    """
    try:
        browser = await asyncio.wait_for(
            launch_browser(playwright, name), timeout=timeout
        )
    except asyncio.TimeoutError:
        return False, f"{name} did not start within {timeout:g}s"
    except Exception as error:  # noqa: BLE001 - the reason is the payload
        return False, _launch_failure_reason(name, error)
    # Starting is not being usable. A browser that launches and then never opens
    # a page passes a launch-only probe and fails every real job — the health
    # answer would be the thing that moved the failure out of sight.
    #
    # Measured on this machine: `webkit.launch()` returned and reported version 26.0,
    # `new_context()` returned in 0.0s, and `new_page()` never returned (killed at
    # 240s, with no browser-side output at all). A probe that stopped at launch
    # called it available while browser-driven Target could not use it.
    try:
        # The same deadline as the launch: `/health` is polled continuously, and a
        # probe without one would hang the health endpoint rather than report.
        context = await asyncio.wait_for(browser.new_context(), timeout=timeout)
        page = await asyncio.wait_for(context.new_page(), timeout=timeout)
    except asyncio.TimeoutError:
        return False, f"{name} started but did not open a page within {timeout:g}s"
    except Exception as error:  # noqa: BLE001 - the reason is the payload
        return False, f"{name} started but could not open a page: {_launch_failure_reason(name, error)}"
    try:
        await page.close()
        await context.close()
        await browser.close()
    except Exception as error:  # noqa: BLE001 - it worked; that is the answer
        return True, f"{name} started but did not close cleanly: {error}"
    return True, None



def _launch_failure_reason(name, error):
    """One line an operator can act on, with the driver's own list when it has one.

    The driver's message arrives inside a box drawing and is often truncated on
    the way, so the missing libraries — the part that decides whether `sudo` is
    needed — are extracted rather than clipped.
    """
    text = str(error).strip()
    marker = "Missing libraries:"
    if marker in text:
        tail = text.split(marker, 1)[1]
        libraries = []
        for line in tail.splitlines():
            candidate = line.strip("║│ ").strip()
            if candidate and not candidate.startswith("╚"):
                libraries.append(candidate)
        if libraries:
            return f"{name} cannot start: missing system libraries {', '.join(libraries)}"
    first = text.splitlines()[0].strip() if text else type(error).__name__
    return f"{name} cannot start: {first}"


async def available_browsers(playwright, system=None, verify=True, timeout=30.0):
    """`{name: None | reason}` for every name in `BROWSER_NAMES`.

    A name is absent when the driver could not start it, and the value is why.
    The reason is not decoration: "not installed" and "installed but missing seven
    system libraries" call for different actions from the operator, and silence
    would make them indistinguishable — which is the state the original
    hardcoded list produced.

    For the Playwright-installed browsers presence is resolved through the
    driver's own `executable_path` rather than by globbing the cache, because the
    glob is wrong twice over: a directory for a revision this Playwright does not
    expect is not runnable, and the driver resolves some revisions through
    `revisionOverrides` — measured here for `webkit`, `browsers.json` said 2203
    while `executable_path` resolved 2092 — so a hand-rolled revision lookup cannot
    agree with what `launch()` would do.

    `verify=False` answers the cheaper question ("is it on disk") and exists for
    callers that only need to avoid pointless launches.
    """
    report = {}
    for name in BROWSER_NAMES:
        channel = BROWSER_CHANNEL_BY_NAME.get(name)
        if channel:
            if not channel_executable_present(channel, system):
                report[name] = (
                    f"no {channel} at the path the driver checks"
                )
                continue
        else:
            executable = getattr(playwright, name).executable_path
            if not os.path.isfile(executable):
                report[name] = f"not downloaded at {executable}"
                continue
        if not verify:
            report[name] = None
            continue
        started, reason = await _launch_probe(playwright, name, timeout)
        report[name] = None if started else reason
    return report


def available_names(report):
    """The usable half of an `available_browsers` report, in catalogue order."""
    return [name for name in BROWSER_NAMES if report.get(name) is None]


def runtime_available_browsers():
    """The live availability measurement, or a well-formed answer without one.

    `/health` must answer even when the runtime has not finished starting or has
    died, so this never raises: without a runtime the honest answer is an empty
    list plus the reason, which is what the seed in `BrowserRuntime.__init__`
    already carries.
    """
    if BROWSER_RUNTIME is None:
        return {
            "browsers": [],
            "unavailable": {},
            "checked_at": None,
            "error": "browser runtime is not started",
        }
    return BROWSER_RUNTIME.browser_report()


def browser_key(browser_name, proxy_server, profile=""):
    """What makes two browser sessions different.

    The profile belongs in here. A session started from a profile and a clean
    one are different sessions even for the same browser through the same
    proxy, and caching them under a shared key would hand the second caller
    the first caller's state — the profile's cookies, its container, whatever
    it was opened for.
    """
    return (browser_name, proxy_server, profile or "")


class ProfileSession:
    """A browser session started from an on-disk profile.

    Playwright's `launch_persistent_context` returns a context, not a browser,
    and the settings a profile is supposed to own — locale, timezone, extra
    headers — can only be set when that context starts. The crawl asks a
    browser for exactly one context per launch, so the options are passed on
    that call; a second call is refused rather than answered with the first
    context, because the caller wanted a separate session and would silently
    have shared cookies with it instead.

    A profile is one live session, so `is_connected` reports `False` once the
    context has been handed out: the crawl closes it, and reusing a closed
    context fails later, inside the navigation, where nothing explains why.
    """

    def __init__(self, playwright, browser_name, profile_dir, proxy=None):
        self.playwright = playwright
        self.browser_name = browser_name
        self.profile = profile_dir
        self.proxy = proxy
        self.context = None

    def is_connected(self):
        return self.context is None

    async def new_context(self, **options):
        if self.context is not None:
            raise RuntimeError(
                "profile %r already handed out its context; a profile holds one "
                "session, so a second one would share its cookies instead of "
                "isolating them" % self.profile)
        if not os.path.isdir(self.profile):
            raise ValueError("browser_profile is not a directory: %s" % self.profile)
        launch = {"headless": True, "user_data_dir": self.profile}
        launch.update(options)
        if self.proxy:
            launch["proxy"] = self.proxy
        if self.browser_name == "firefox":
            self.context = await self.playwright.firefox.launch_persistent_context(
                **launch)
        elif self.browser_name == "chromium":
            # Те саме, що й `launch_browser`: без перемикача WebRTC зливає
            # локальні адреси враз з проксі, тобто проксі перестає бути
            # єдиним шляхом виходу; без `--ignore-certificate-errors` Chromium 140
            # обриває TLS-рукостискання через MITM-проксі з `ERR_TOO_MANY_RETRIES`.
            chromium_args = list(WEBRTC_PROXY_ONLY_ARGS)
            if self.proxy or launch.get("ignore_https_errors"):
                chromium_args.append("--ignore-certificate-errors")
            launch["args"] = chromium_args
            env = await chromium_fonts.launch_env(self.playwright)
            if env is not None:
                launch["env"] = env
            self.context = await self.playwright.chromium.launch_persistent_context(
                **launch)
        else:
            raise ValueError(
                "browser_profile is not supported for %s; it works for firefox "
                "and for the chromium family" % self.browser_name)
        return self.context


FIREFOX_LOW_MEMORY_PREFS = {
    # Bound Firefox content processes and in-memory caches so headless crawls
    # do not expand to 2+ GB RAM on desktop/VM hosts.
    "dom.ipc.processCount": 2,
    "browser.cache.memory.capacity": 65536,
    "browser.cache.disk.enable": False,
    "browser.sessionhistory.max_total_viewers": 0,
    "media.autoplay.default": 5,
}

CHROMIUM_LOW_MEMORY_ARGS = (
    "--disable-dev-shm-usage",
    "--renderer-process-limit=2",
)


async def launch_browser(playwright, browser_name, proxy=None):
    options = {"headless": True}
    executable_path = os.environ.get("FIREFOX_EXECUTABLE_PATH", "").strip()
    if browser_name == "firefox" and executable_path:
        options["executable_path"] = executable_path
    if proxy:
        options["proxy"] = proxy
    if browser_name == "firefox":
        options["firefox_user_prefs"] = dict(FIREFOX_LOW_MEMORY_PREFS)
        return await playwright.firefox.launch(**options)
    # No `webkit` branch: it is gone from `BROWSER_NAMES` because it cannot start a
    # page on this host, and a branch that cannot run is worse than no branch — it
    # promises a browser the caller will never get.
    # Everything past this point is the Chromium family, the only family the
    # WebRTC switch has been measured on.
    chromium_args = list(CHROMIUM_LOW_MEMORY_ARGS)
    if proxy:
        # Chromium 140 aborts the proxy CONNECT TLS handshake with
        # `net::ERR_TOO_MANY_RETRIES` (engine logs `tls: unknown certificate`)
        # before Playwright's context-level `ignore_https_errors` is consulted,
        # unless `--ignore-certificate-errors` is also passed at browser launch.
        chromium_args = [*WEBRTC_PROXY_ONLY_ARGS, "--ignore-certificate-errors", *chromium_args]
    options["args"] = chromium_args
    # Chromium draws no glyphs on this host while reading the system fontconfig,
    # so a capture taken through the Chromium family is a photograph of an empty
    # rectangle — measured, and documented in `chromium_fonts`. The helper
    # measures once per process and answers `None` on a host where the system
    # configuration already works, so Firefox and a healthy host are untouched.
    env = await chromium_fonts.launch_env(playwright)
    if env is not None:
        options["env"] = env
    return await playwright.chromium.launch(**options)


def _looks_like_dead_connection(error):
    """Whether this error says the driver went away, rather than a browser failing.

    The strings are Playwright's own, and they are what the driver reports when its
    pipe closed: `Connection closed while reading from the driver` is the exact text
    this stand produced, and `pipe closed by peer` is what its log showed. Anything
    that is not about the connection — a missing executable, a missing shared
    library — must keep failing fast, because for those the useful answer is the
    reason, not a rebuilt driver.
    """
    text = str(error).lower()
    return any(
        marker in text
        for marker in (
            "connection closed",
            "pipe closed",
            "browser has been closed",
            "target page, context or browser has been closed",
            "driver failed",
        )
    )


class BrowserRuntime:
    """Keep one Playwright loop and browser processes alive across jobs."""

    def __init__(self):
        self.loop = None
        self.thread = None
        self.playwright = None
        self.browsers = {}
        self.job_tasks = {}
        self.ready = threading.Event()
        self.startup_error = None
        self.browser_lock = None
        # Whether the driver has ever answered since this process started, and
        # when the last recovery was attempted.
        #
        # Both exist because of one measured incident. The driver's pipe closed
        # (`asyncio pipe closed by peer`), and from that moment every job failed in
        # **2 ms** with `BrowserType.launch: Connection closed while reading from
        # the driver` — forever, until a human restarted the process. `start()`
        # could not help: its guard is `thread.is_alive()`, and the thread was
        # alive; it was the driver *inside* that thread that was gone.
        # `_browser_for` could not help either: it re-launches when
        # `browser.is_connected()` is false, which is a statement about a browser
        # this process had already launched, not about the driver every launch
        # goes through. The same launch from a fresh process worked, so the tool
        # was fine and only this runtime was dead.
        #
        # `driver_was_healthy` keeps the recovery for a driver that has proven it
        # can work, so "this browser is not installed" keeps failing fast and
        # honestly instead of turning into a restart loop. The interval keeps one
        # dead driver from becoming a rebuild per job.
        self.driver_was_healthy = False
        self.last_driver_recovery = 0.0
        # Seeded so a `/health` poll arriving before the driver is up reads a
        # well-formed answer instead of raising: `browsers` empty, and `error`
        # saying the measurement has not happened yet.
        self.availability = {
            "browsers": [],
            "unavailable": {},
            "checked_at": None,
            "error": "browser availability has not been measured yet",
        }

    def browser_report(self):
        """The availability measurement and when it was taken.

        Measured once when the driver came up, not per request: `/health` is polled
        continuously, and a per-request probe that started a browser would pay a
        process and its content processes on every poll — the idle worker that
        deliberately holds no browser would then hold one per name.

        A browser installed after startup is not reported until the worker is
        restarted, so `checked_at` travels with the answer: an operator reading a
        stale list can see how stale it is rather than trusting it as current. When
        the measurement itself failed, `browsers` is empty and `error` says why —
        an empty list plus silence would read as "nothing is installed".
        """
        return dict(self.availability)

    async def _measure_browsers(self):
        try:
            report = await available_browsers(self.playwright)
        except Exception as error:  # noqa: BLE001 - surfaced in /health, never swallowed
            self.availability = {
                "browsers": [],
                "unavailable": {},
                "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "error": f"{type(error).__name__}: {error}",
            }
            return
        self.availability = {
            "browsers": available_names(report),
            "unavailable": {name: reason for name, reason in report.items() if reason},
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "error": None,
        }

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.thread = threading.Thread(
            target=self._run_loop,
            name="request-rider-browser-runtime",
            daemon=True,
        )
        self.thread.start()
        self.ready.wait()
        if self.startup_error:
            raise RuntimeError("browser runtime could not start") from self.startup_error

    def _run_loop(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._start())
        except Exception as error:
            self.startup_error = error
            try:
                if self.playwright is not None:
                    self.loop.run_until_complete(self.playwright.stop())
                    self.playwright = None
            except Exception as cleanup_error:
                error.add_note(f"Playwright startup cleanup failed: {cleanup_error}")
            finally:
                self.ready.set()
                self.loop.close()
            return
        self.ready.set()
        try:
            self.loop.run_forever()
        finally:
            self.loop.run_until_complete(self._shutdown())
            self.loop.close()

    async def _start(self):
        from playwright.async_api import async_playwright

        self.browser_lock = asyncio.Lock()
        self.playwright = await async_playwright().start()
        await self._measure_browsers()
        # No browser is launched here. It used to be warmed up at startup and kept
        # for the life of the process, which meant a worker that never ran a job
        # still held a browser — and its content processes — open indefinitely.
        # Readiness means the driver is up, which is what `ready` is waited on
        # for; `_browser_for` launches a browser on the first job and
        # `_run_job` releases it after the last one, so an idle worker holds
        # nothing.

    async def _browser_for(self, config, slot=0):
        browser_name = config["browser"]
        pool = config.get("proxy_pool")
        if isinstance(pool, ProxyPool) and pool.enabled:
            endpoints = pool.slots(max(1, int(config.get("concurrency", 1) or 1)))
            proxy_server = endpoints[slot % len(endpoints)]
        else:
            proxy_server = config["proxy_server"]
        profile = config.get("browser_profile") or ""
        key = browser_key(browser_name, proxy_server, profile)
        async with self.browser_lock:
            browser = self.browsers.get(key)
            if browser is None or not browser.is_connected():
                proxy = {"server": proxy_server} if proxy_server else None
                if profile:
                    LOG.info("browser_profile_launched browser=%s profile=%s "
                             "proxy=%s", browser_name, profile,
                             proxy["server"] if proxy else "")
                    browser = ProfileSession(self.playwright, browser_name,
                                             profile, proxy)
                else:
                    browser = await self._launch(browser_name, proxy)
                self.browsers[key] = browser
            return browser

    async def _launch(self, browser_name, proxy):
        """Launch a browser, rebuilding the driver once if the launch cannot.

        The recovery exists because the driver's pipe died once on this machine and
        nothing rebuilt it: the thread stayed alive, so `start()` was a no-op, and
        `is_connected()` said nothing about the driver. Every job after that
        failed in milliseconds, and a fresh process launched the same browser
        without trouble.

        It is attempted only when the driver had already proven it works, or when
        the failure names a dead connection, so a genuinely missing browser still
        fails on the first try and says so; and at most once per
        `_DRIVER_RECOVERY_INTERVAL`, so one dead driver cannot become a rebuild per
        job. The reason goes into the availability report rather than only into
        the log, because the log is where an operator discovers this took a restart.
        """
        try:
            browser = await launch_browser(self.playwright, browser_name, proxy)
        except Exception as error:  # noqa: BLE001 - a refused launch is an answer
            if not self._driver_recovery_allowed(error):
                raise
            await self._recover_driver(error)
            browser = await launch_browser(self.playwright, browser_name, proxy)
        self.driver_was_healthy = True
        return browser

    def _driver_recovery_allowed(self, error):
        """Whether this failure may be answered by rebuilding the driver.

        Two conditions, and both are needed — measuring each one showed the other
        is not enough:

        - the interval, so one dead driver cannot become a rebuild per job;
        - the driver having worked, **or** the failure naming a dead connection.
          The second half is what closes a measured hole: on a worker that had run
          no job yet, `driver_was_healthy` is false, so a driver that died before
          its first launch would have failed every job forever — the same brick,
          reached one step earlier in the life of the process.

        A browser that is simply not installed fails as
        `Executable doesn't exist at …`, which is not a connection error, so it
        still fails on the first try and still says the real reason.
        """
        if (time.monotonic() - self.last_driver_recovery) < _DRIVER_RECOVERY_INTERVAL:
            return False
        if self.driver_was_healthy:
            return True
        return _looks_like_dead_connection(error)

    async def _recover_driver(self, cause):
        """Replace a dead Playwright connection and re-measure what it can drive."""
        self.last_driver_recovery = time.monotonic()
        LOG.warning("browser_driver_recovering cause=%s", cause)
        stale, self.playwright = self.playwright, None
        # Every browser this runtime handed out went through the connection that
        # just died, so each cached entry is a promise that cannot be kept.
        self.browsers.clear()
        if stale is not None:
            try:
                await stale.stop()
            except Exception as stop_error:  # noqa: BLE001 - it is already dead
                LOG.debug("browser_driver_stop_failed error=%s", stop_error)
        from playwright.async_api import async_playwright

        self.playwright = await async_playwright().start()
        await self._measure_browsers()
        report = self.availability
        report["error"] = f"driver recovered after: {cause}"[:300]
        LOG.info("browser_driver_recovered")

    def submit_job(self, job_id, config):
        if not self.loop or not self.loop.is_running():
            raise RuntimeError("browser runtime is not running")
        return asyncio.run_coroutine_threadsafe(
            self._run_job(job_id, config),
            self.loop,
        )

    async def _run_job(self, job_id, config):
        task = asyncio.current_task()
        self.job_tasks[job_id] = task
        try:
            # Проксі задається на старті браузера, тому «ротація» всередині
            # одного браузера — це один вихід на весь обхід. Живий прогін
            # живой прогон показал это числами: configured 2, used 1,
            # первый эндпоинт 2 запроса, второй 0.
            # Тому браузерів стільки ж, скільки різних ендпоинтів, і кожен
            # тягне зі спільної черги — розподіл виходить від черги, а не від
            # лічильника.
            pool = config.get("proxy_pool")
            fleet_endpoints = []
            if isinstance(pool, ProxyPool) and pool.enabled:
                fleet_endpoints = [e for e in dict.fromkeys(pool.slots(config["concurrency"])) if e]
            if len(fleet_endpoints) > 1:
                fleet = [await self._browser_for(config, index)
                         for index in range(len(fleet_endpoints))]
                for endpoint in fleet_endpoints:
                    if endpoint not in pool.used:
                        pool.used.append(endpoint)
                await run_async_job(job_id, config, browsers=fleet,
                                    endpoints=fleet_endpoints, defer_finish=True)
            else:
                browser = await self._browser_for(config)
                await run_async_job(job_id, config, browser=browser, defer_finish=True)
            self.job_tasks.pop(job_id, None)
            if not self.job_tasks:
                await self._release_browsers()
            finish_job(job_id, "cancelled" if is_cancelled(job_id) else "completed")
        except asyncio.CancelledError:
            self.job_tasks.pop(job_id, None)
            if not self.job_tasks:
                await self._release_browsers()
            finish_job(job_id, "cancelled")
            raise
        except Exception as error:
            self.job_tasks.pop(job_id, None)
            if not self.job_tasks:
                await self._release_browsers()
            finish_job(job_id, "failed", error=str(error))
        finally:
            self.job_tasks.pop(job_id, None)
            # The browser is released as soon as the last job is done, rather
            # than living for the rest of the process. Measured on this machine:
            # four idle worker processes were each holding a Firefox and its five
            # content processes, 2.4 GB in total, hours after any job had
            # finished. A crawler that is not crawling should not be holding a
            # browser open — the next job launches one in a second or two, and
            # until then nothing is spent.
            if not self.job_tasks:
                await self._release_browsers()

    async def _release_browsers(self):
        """Drop every cached browser and close it, tolerating a dead one."""
        # The entries are taken out under the lock first. A job that starts while
        # this runs then launches a fresh browser instead of being handed one
        # that is halfway through closing, which is the race a plain close would
        # leave open.
        async with self.browser_lock:
            closing = [
                browser for browser in self.browsers.values()
                if browser.is_connected()
            ]
            self.browsers.clear()
        if closing:
            await asyncio.gather(
                *(browser.close() for browser in closing), return_exceptions=True
            )

    async def _shutdown(self):
        tasks = list(self.job_tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await self._release_browsers()
        shutdown_error = None
        if self.playwright is not None:
            try:
                await self.playwright.stop()
            except Exception as error:
                shutdown_error = shutdown_error or error
            finally:
                self.playwright = None
        if shutdown_error is not None:
            raise RuntimeError("browser runtime failed to close cleanly") from shutdown_error

    def stop(self):
        if not self.loop or not self.loop.is_running():
            return
        self.loop.call_soon_threadsafe(self.loop.stop)
        if self.thread:
            self.thread.join()


def run_job(job_id, config):
    runtime = BROWSER_RUNTIME
    if runtime is not None:
        try:
            runtime.submit_job(job_id, config)
        except Exception as error:
            finish_job(job_id, "failed", error=str(error))
        return
    try:
        from playwright.async_api import async_playwright
    except ImportError as error:
        finish_job(job_id, "failed", error=str(error))
        return
    try:
        asyncio.run(run_async_job(job_id, config, async_playwright))
    except asyncio.CancelledError:
        finish_job(job_id, "cancelled")
    except Exception as error:  # noqa: BLE001 - worker thread must persist terminal failure
        finish_job(job_id, "failed", error=str(error))


async def run_async_job(job_id, config, async_playwright=None, browser=None,
                       browsers=None, endpoints=None, defer_finish=False):
    if is_cancelled(job_id):
        if not defer_finish:
            finish_job(job_id, "cancelled")
        return
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    cancel_event = asyncio.Event()
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return
        job["_loop"] = loop
        job["_task"] = task
        job["_cancel_event"] = cancel_event
    start_origin = f"{urlparse(config['url']).scheme}://{urlparse(config['url']).netloc}"
    allowed_origins = {start_origin}
    origin = start_origin
    is_replicate = bool(
        isinstance(config.get("proxy_pool"), ProxyPool)
        and config["proxy_pool"].enabled
        and config.get("proxy_distribution") == "replicate"
        and browsers
        and len(browsers) > 1
    )
    seed_suffixes = [
        "/robots.txt",
        "/sitemap.xml",
        "/.gitignore",
        "/README.md",
        "/config/",
        "/docs/",
        "/login.php",
        "/setup.php",
        "/icons/README",
        "/.env",
        "/.git/HEAD",
        "/admin/",
        "/api/",
    ]
    speculative_seeds = {
        urldefrag(urljoin(start_origin, s))[0]
        for s in seed_suffixes
        if s not in ("/robots.txt", "/sitemap.xml")
    }
    shared_queue = asyncio.Queue()
    start_normalized = _normalize_crawl_url(config["url"])
    await shared_queue.put((start_normalized, 0))
    shared_seen = {start_normalized}
    if not config["auto_interact"] and (config["max_pages"] <= 0 or config["max_pages"] >= 20):
        for s in ("/robots.txt", "/sitemap.xml"):
            su = urldefrag(urljoin(start_origin, s))[0]
            if su not in shared_seen:
                shared_seen.add(su)
                await shared_queue.put((su, 0))
    state_lock = asyncio.Lock()
    spa_state = {"root_fp": None, "soft_404": False, "seeds_queued": False}
    has_auth = bool(config.get("cookies") or config.get("custom_headers"))
    async def crawl_with_browser(browser_instance, endpoint=""):
        # `endpoint` — вихід, з яким ЦЕЙ браузер запущено. Маршрутизація вже
        # зафіксована на старті браузера; тут endpoint потрібен для заголовка
        # контексту захоплення, щоб він не загубився на другому браузері флоту.
        proxy_server = endpoint or config["proxy_server"]
        proxy = {"server": proxy_server} if proxy_server else None
        context_options = {"ignore_https_errors": True}
        if config["capture_context"] and proxy:
            context_options["extra_http_headers"] = {
                "X-RequestRider-Capture-Context": config["capture_context"],
            }
        # Locale and timezone are identity, not automation artefacts, so they
        # are never invented: an empty value keeps whatever the runtime already
        # reports, which is what the crawl did before this option existed. A
        # container default of UTC against an exit IP somewhere else is a
        # mismatch an analyst may want to close, and this is the field that
        # closes it — as a stated choice, not a hidden correction.
        if config.get("locale"):
            context_options["locale"] = config["locale"]
        if config.get("timezone_id"):
            context_options["timezone_id"] = config["timezone_id"]
        context = await browser_instance.new_context(**context_options)
        await context.add_init_script(DOM_SINK_TELEMETRY_INIT_SCRIPT)

        # Authenticated crawling: apply operator cookies and custom headers
        if config.get("cookies"):
            try:
                parsed_cookies = parse_cookie_header(config["cookies"], config.get("url", ""))
                if parsed_cookies:
                    await context.add_cookies(parsed_cookies)
            except Exception as cookie_err:
                LOG.warning("Failed to add cookies to context: %s", cookie_err)

        if config.get("custom_headers") and isinstance(config["custom_headers"], dict):
            try:
                await context.set_extra_http_headers(config["custom_headers"])
            except Exception as header_err:
                LOG.warning("Failed to set extra HTTP headers: %s", header_err)
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if job is not None:
                job.setdefault("_contexts", []).append(context)
        # The runtime is named, not read back out of the payload: this call sits
        # under both launch branches, and passing the name is what keeps the
        # anti-detect layer off a browser that carries its own fingerprint
        # instead of stacking a second identity on top of it. See
        # `anti_detect.NATIVE_FINGERPRINT_BROWSERS` for the measurement that
        # made this necessary.
        anti_detect_plan = await anti_detect.install(
            context, config, browser=config["browser"]
        )

        # У режимі replicate кожен виділений браузер зі своїм проксі проходить
        # повний список цілей незалежно від інших. У режимі split (дефолт)
        # воркери ділять спільну чергу між собою.
        if is_replicate:
            queue = asyncio.Queue()
            await queue.put((config["url"], 0))
            seen = {config["url"]}
            worker_lock = asyncio.Lock()
        else:
            queue = shared_queue
            seen = shared_seen
            worker_lock = state_lock

        try:
            async def crawl_worker(worker_id=1):
                page = await context.new_page()
                # Set up once per page. The wait and the crawler both read this
                # count, and it has to span the whole life of the page: a request
                # opened during navigation is still running when the pass starts
                # looking, and that is exactly the request the form is drawn from.
                track_page_activity(page)

                inflight_guard = {"busy": False, "last_ts": 0.0}
                worker_key = str(worker_id)
                with JOBS_LOCK:
                    job_ref = JOBS.get(job_id)
                    if job_ref is not None:
                        ctrl = _ensure_control_state(job_ref, asyncio.get_running_loop())
                        ctrl["pages"][worker_key] = page
                        ctrl["page_configs"][worker_key] = config
                        ctrl["page_guards"][worker_key] = inflight_guard

                async def live_hook(action=None, locator=None, record_history=True):
                    if not (config.get("live_view") or _is_manual_control(job_id)) or is_cancelled(job_id):
                        return
                    await _capture_live_frame(
                        job_id,
                        worker_id,
                        page,
                        {**config, "live_view": True},
                        action=action,
                        locator=locator,
                        record_history=record_history,
                        inflight_guard=inflight_guard,
                    )

                async def _live_ticker():
                    # Background ticker ONLY runs while operator holds manual control
                    # (for smooth captcha/slider interaction). During automated crawling,
                    # frames are captured strictly at safe event boundaries (post-goto,
                    # pre-click, pre-fill) so screenshots never race with page.goto() or
                    # extract_links() in Firefox/Chromium.
                    while not is_cancelled(job_id):
                        manual_now = _is_manual_control(job_id)
                        await asyncio.sleep(MANUAL_CONTROL_TICK_SECONDS if manual_now else 0.5)
                        if is_cancelled(job_id) or not _is_manual_control(job_id):
                            continue
                        with JOBS_LOCK:
                            ctrl_wid = (JOBS.get(job_id) or {}).get("_control", {}).get("control_worker_id")
                        if ctrl_wid and str(ctrl_wid) != worker_key:
                            continue
                        if inflight_guard["busy"]:
                            continue
                        if (time.monotonic() - inflight_guard["last_ts"]) < (MANUAL_CONTROL_TICK_SECONDS * 0.85):
                            continue
                        if not getattr(page, "url", "") or str(page.url).startswith("about:"):
                            continue
                        await live_hook({"type": "frame"}, record_history=False)

                live_ticker_task = asyncio.create_task(_live_ticker())

                await page.route("**/*", route_browser_request)
                try:
                    while True:
                        if is_cancelled(job_id):
                            break
                        await _wait_if_manual_control(job_id)
                        if is_cancelled(job_id):
                            break
                        current_url, depth = await queue.get()
                        try:
                            if is_cancelled(job_id):
                                break
                            if current_url in speculative_seeds and spa_state["soft_404"]:
                                continue
                            if has_auth and is_logout_url(current_url):
                                continue
                            await _wait_if_manual_control(job_id)
                            if is_cancelled(job_id):
                                break
                            requests = []
                            request_listener = lambda request: requests.append({
                                "url": request.url,
                                "method": request.method,
                                "resource_type": request.resource_type,
                            })
                            page.on("request", request_listener)
                            responses = []
                            def _on_response(resp):
                                try:
                                    responses.append({
                                        "url": resp.url,
                                        "status": resp.status,
                                        "content_type": resp.headers.get("content-type", ""),
                                        "resource_type": resp.request.resource_type,
                                    })
                                except Exception:
                                    pass
                            page.on("response", _on_response)
                            started = time.monotonic()
                            try:
                                # 0 is Playwright's "no timeout". The value is
                                # passed explicitly so the deadline in force is
                                # the one the request asked for, and not a
                                # library default nobody in this project chose.
                                pool = config.get("proxy_pool")
                                effective_proxy = endpoint or proxy_server or ""
                                if not endpoint and isinstance(pool, ProxyPool) and pool.enabled:
                                    host_endpoint = pool.endpoint_for(current_url)
                                    if host_endpoint:
                                        effective_proxy = host_endpoint
                                        if host_endpoint not in pool.used:
                                            pool.used.append(host_endpoint)
                                elif endpoint and isinstance(pool, ProxyPool) and pool.enabled:
                                    if endpoint not in pool.used:
                                        pool.used.append(endpoint)
                                response = await page.goto(
                                    current_url,
                                    wait_until="domcontentloaded",
                                    timeout=config["navigation_timeout_ms"],
                                )
                                try:
                                    await page.wait_for_load_state(
                                        "load",
                                        timeout=min(5000, config["navigation_timeout_ms"] or 5000),
                                    )
                                except Exception:
                                    pass
                                await page.wait_for_timeout(300)
                                await live_hook(
                                    {
                                        "type": "navigate",
                                        "label": str(page.url or current_url)[:120],
                                        "depth": depth,
                                    }
                                )
                                if await _wait_if_manual_control(job_id):
                                    # Operator solved captcha / interacted manually; refresh URL & frame
                                    await live_hook(
                                        {
                                            "type": "navigate",
                                            "label": str(page.url or current_url)[:120],
                                            "depth": depth,
                                        },
                                        record_history=False,
                                    )
                                if depth == 0 and current_url == start_normalized and page.url:
                                    await _dismiss_blocking_overlays(page)
                                    landing_parsed = urlparse(page.url)
                                    if landing_parsed.scheme in {"http", "https"} and landing_parsed.netloc:
                                        allowed_origins.add(f"{landing_parsed.scheme}://{landing_parsed.netloc}")
                                    spa_state["root_fp"] = await _page_html_fingerprint(page)
                                final_page_url = _normalize_crawl_url(page.url or current_url)
                                async with worker_lock:
                                    seen.add(final_page_url)
                                status = response.status if response else None
                                is_speculative = current_url in speculative_seeds
                                if is_speculative and (status == 404 or status is None or (isinstance(status, int) and status >= 500)):
                                    continue
                                if is_speculative and status == 200 and spa_state["root_fp"] is not None:
                                    spec_fp = await _page_html_fingerprint(page)
                                    if _looks_like_spa_soft_404(spec_fp, spa_state["root_fp"]):
                                        spa_state["soft_404"] = True
                                        continue
                                page_result = {
                                    "requested_url": current_url,
                                    "url": final_page_url,
                                    "depth": depth,
                                    "status": status,
                                    "kind": "browser-page",
                                    "content_type": await response.header_value("content-type") if response else "",
                                    "time": round((time.monotonic() - started) * 1000),
                                    "proxy_used": effective_proxy,
                                    "network": dedupe_requests(requests),
                                    # The declared plan and the measurement are
                                    # reported side by side: a patch that
                                    # silently failed to apply must not read as
                                    # a working one.
                                    "anti_detect": {
                                        "plan": anti_detect_plan,
                                        "measured": await anti_detect.read_report(page),
                                    },
                                    # How the page was actually driven, as the
                                    # page itself counted it. A press landing
                                    # proves the click landed, not how it got
                                    # there, so the gesture is reported as its
                                    # own evidence and judged separately.
                                }
                                # Links describe the page that was actually
                                # crawled, so they are read before any action
                                # navigates the page away from it.
                                page_result["links"] = await extract_links(
                                    page, final_page_url
                                )
                                page_result["subresources"] = await extract_subresources(
                                    page, final_page_url
                                )
                                if final_page_url.endswith("/.gitignore") or final_page_url.endswith(".gitignore"):
                                    try:
                                        git_text = await page.evaluate("() => document.body ? document.body.innerText : ''")
                                        for g_line in (git_text or "").splitlines():
                                            g_line = g_line.strip()
                                            if not g_line or g_line.startswith(("#", "!")) or "*" in g_line or "?" in g_line:
                                                continue
                                            clean_g = g_line.lstrip("/")
                                            if not clean_g:
                                                continue
                                            parts = clean_g.split("/")
                                            if len(parts) > 1:
                                                dir_u = urldefrag(urljoin(start_origin, "/" + parts[0] + "/"))[0]
                                                async with worker_lock:
                                                    if dir_u not in seen:
                                                        seen.add(dir_u)
                                                        await queue.put((dir_u, depth + 1))
                                            file_u = urldefrag(urljoin(start_origin, "/" + clean_g))[0]
                                            async with worker_lock:
                                                if file_u not in seen:
                                                    seen.add(file_u)
                                                    await queue.put((file_u, depth + 1))
                                    except Exception:
                                        pass
                                if any(final_page_url.lower().endswith(x) for x in ("/swagger.json", "/openapi.json", "/api-docs")):
                                    try:
                                        api_text = await page.evaluate("() => document.body ? document.body.innerText : ''")
                                        api_routes = []
                                        try:
                                            parsed_spec = json.loads(api_text)
                                            if isinstance(parsed_spec, dict) and isinstance(parsed_spec.get("paths"), dict):
                                                api_routes = list(parsed_spec["paths"].keys())
                                        except Exception:
                                            api_routes = re.findall(r"""(?m)^\s{2,4}(/[a-zA-Z0-9_\-\/\{\}]+):\s*$""", api_text)
                                        for route in api_routes:
                                            clean_route = re.sub(r"""\{[a-zA-Z0-9_\-]+\}""", "1", route.strip())
                                            resolved_api = urldefrag(urljoin(start_origin, clean_route))[0]
                                            async with worker_lock:
                                                if resolved_api not in seen and (config["max_pages"] <= 0 or len(seen) < config["max_pages"]):
                                                    seen.add(resolved_api)
                                                    await queue.put((resolved_api, depth + 1))
                                    except Exception:
                                        pass
                                page_result["dom_sinks"] = await read_dom_sinks(page)
                                enrich_data, enrich_counts = await extract_page_enrichment(page, final_page_url)
                                if enrich_data is not None:
                                    page_result["enrich"] = enrich_data
                                    page_result["enrich_counts"] = enrich_counts
                                if depth == 0 and current_url == config["url"]:
                                    try:
                                        await perform_actions(page, config, live_hook=live_hook)
                                    except Exception as action_err:
                                        LOG.warning("perform_actions_failed url=%s error=%s", current_url, action_err)
                                if config["auto_interact"]:
                                    try:
                                        auto_actions, auto_wait = await perform_auto_interactions(
                                            page,
                                            config,
                                            job_id,
                                            reset_url=page.url or current_url,
                                            live_hook=live_hook,
                                        )
                                        page_result["auto_actions"] = auto_actions
                                        page_result["auto_wait"] = auto_wait
                                        page_result["auto_links"] = [
                                            link
                                            for item in auto_actions
                                            for link in item.get("links", [])
                                        ]
                                    except Exception as auto_err:
                                        LOG.warning("perform_auto_interactions_failed url=%s error=%s", current_url, auto_err)
                                if await _wait_if_manual_control(job_id):
                                    # Re-extract links after manual captcha solve so unlocked links enter the queue
                                    try:
                                        try:
                                            await page.wait_for_load_state("domcontentloaded", timeout=3000)
                                        except Exception:
                                            pass
                                        unlocked_url = urldefrag(page.url or final_page_url)[0]
                                        unlocked_parsed = urlparse(unlocked_url)
                                        if unlocked_parsed.scheme in {"http", "https"} and unlocked_parsed.netloc:
                                            allowed_origins.add(f"{unlocked_parsed.scheme}://{unlocked_parsed.netloc}")
                                        page_result["url"] = unlocked_url
                                        fresh_links = await extract_links(page, unlocked_url)
                                        existing_links = set(page_result.get("links") or [])
                                        for lnk in fresh_links:
                                            if lnk not in existing_links:
                                                page_result.setdefault("links", []).append(lnk)
                                                existing_links.add(lnk)
                                    except Exception:
                                        pass
                                page_result["network"] = dedupe_requests(requests)
                                # How the page was actually driven, as the page
                                # itself counted it — read AFTER the actions,
                                # because that is the only point at which the
                                # page has been driven at all.
                                try:
                                    page_result["pointer_events"] = await _pointer_evidence(page)
                                except Exception:
                                    page_result["pointer_events"] = {}
                            except Exception as error:
                                page_result = {
                                    "requested_url": current_url,
                                    "url": current_url,
                                    "depth": depth,
                                    "status": None,
                                    "kind": "browser-page",
                                    "time": round((time.monotonic() - started) * 1000),
                                    "proxy_used": effective_proxy,
                                    "error": str(error),
                                    "network": dedupe_requests(requests),
                                }
                            finally:
                                page.remove_listener("request", request_listener)
                                page.remove_listener("response", _on_response)
                            append_page(job_id, page_result)
                            # Record discovered subresources and network responses into job pages
                            async with worker_lock:
                                existing_urls = {
                                    p.get("url")
                                    for p in JOBS.get(job_id, {}).get("pages", [])
                                    if isinstance(p, dict)
                                }
                                for nr in responses:
                                    nr_url = urldefrag(nr.get("url", ""))[0]
                                    if not nr_url or nr_url.startswith(("data:", "blob:", "javascript:")):
                                        continue
                                    if config["same_origin"] and not same_origin(nr_url, allowed_origins):
                                        continue
                                    if nr_url not in existing_urls:
                                        existing_urls.add(nr_url)
                                        r_type = nr.get("resource_type", "")
                                        c_type = (nr.get("content_type") or "").lower()
                                        kind = "api" if r_type in ("xhr", "fetch") or "json" in c_type else (
                                            "css" if "css" in c_type or nr_url.endswith(".css") else (
                                                "script" if r_type == "script" or "javascript" in c_type or nr_url.endswith(".js") else (
                                                    "image" if r_type == "image" or nr_url.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico")) else (
                                                        "font" if r_type == "font" or nr_url.endswith((".woff", ".woff2", ".ttf")) else "document"
                                                    )
                                                )
                                            )
                                        )
                                        append_page(job_id, {
                                            "requested_url": nr_url,
                                            "url": nr_url,
                                            "depth": depth + 1,
                                            "status": nr.get("status", 200),
                                            "kind": kind,
                                            "content_type": c_type,
                                            "time": 0,
                                        })
                                for sr in page_result.get("subresources", []):
                                    sr_url = urldefrag(sr.get("url", ""))[0]
                                    if not sr_url or sr_url.startswith(("data:", "blob:", "javascript:")):
                                        continue
                                    if config["same_origin"] and not same_origin(sr_url, allowed_origins):
                                        continue
                                    if sr_url not in existing_urls:
                                        existing_urls.add(sr_url)
                                        append_page(job_id, {
                                            "requested_url": sr_url,
                                            "url": sr_url,
                                            "depth": depth + 1,
                                            "status": 200,
                                            "kind": sr.get("kind", "document"),
                                            "content_type": "",
                                            "time": 0,
                                        })
                            if is_cancelled(job_id):
                                break
                            if config["max_depth"] < 0 or depth < config["max_depth"]:
                                # A submitted form or a clicked button reaches
                                # endpoints no anchor on the page points at, so
                                # the automatic pass feeds the crawler too.
                                discovered_links = list(page_result.get("links", []))
                                discovered_links.extend(page_result.get("auto_links", []))
                                async with worker_lock:
                                    for link in discovered_links:
                                        link = _normalize_crawl_url(link)
                                        if has_auth and is_logout_url(link):
                                            continue
                                        if config["same_origin"] and not same_origin(link, allowed_origins):
                                            continue
                                        if link not in seen and (
                                            config["max_pages"] <= 0
                                            or len(seen) < config["max_pages"]
                                        ):
                                            seen.add(link)
                                            await queue.put((link, depth + 1))
                                    # Queue speculative seeds AFTER real start_url links so
                                    # they never crowd out real routes under max_pages budgets.
                                    if (
                                        depth == 0
                                        and current_url == start_normalized
                                        and not spa_state["seeds_queued"]
                                        and not config["auto_interact"]
                                    ):
                                        spa_state["seeds_queued"] = True
                                        for s in seed_suffixes:
                                            if has_auth and s == "/login.php":
                                                continue
                                            su = urldefrag(urljoin(start_origin, s))[0]
                                            if su not in seen and (
                                                config["max_pages"] <= 0
                                                or len(seen) < config["max_pages"]
                                            ):
                                                seen.add(su)
                                                await queue.put((su, 0))
                            if not is_cancelled(job_id) and config["delay_ms"]:
                                await asyncio.sleep(config["delay_ms"] / 1000)
                        finally:
                            queue.task_done()
                except asyncio.CancelledError:
                    raise
                finally:
                    with JOBS_LOCK:
                        job_ref = JOBS.get(job_id)
                        if job_ref is not None:
                            ctrl = job_ref.get("_control")
                            if isinstance(ctrl, dict):
                                ctrl.get("pages", {}).pop(worker_key, None)
                                ctrl.get("page_configs", {}).pop(worker_key, None)
                                ctrl.get("page_guards", {}).pop(worker_key, None)
                    if live_ticker_task is not None:
                        live_ticker_task.cancel()
                        await asyncio.gather(live_ticker_task, return_exceptions=True)
                    await page.close()

            # Коли флот складається з кількох браузерів, загальна паралельність
            # (concurrency) ділиться між браузерами флоту порівну, щоб не
            # перевантажувати систему множенням workers. При одному браузері або
            # direct-обході це точно config["concurrency"].
            fleet_size = len(browsers) if browsers else 1
            workers_per_browser = max(1, config["concurrency"] // fleet_size) if fleet_size > 1 else config["concurrency"]
            workers = [
                asyncio.create_task(crawl_worker(idx + 1))
                for idx in range(workers_per_browser)
            ]

            async def cancel_workers():
                await cancel_event.wait()
                for worker in workers:
                    worker.cancel()
                while True:
                    try:
                        queue.get_nowait()
                    except asyncio.QueueEmpty:
                        return
                    queue.task_done()

            cancel_watcher = asyncio.create_task(cancel_workers())
            try:
                await queue.join()
            finally:
                cancel_watcher.cancel()
                await asyncio.gather(cancel_watcher, return_exceptions=True)
                for worker in workers:
                    worker.cancel()
                await asyncio.gather(*workers, return_exceptions=True)
        finally:
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                if job is not None and "_contexts" in job:
                    try:
                        job["_contexts"].remove(context)
                    except ValueError:
                        pass
            await context.close()

    try:
        # `browsers` — те саме, що `browser`, тільки флот: по браузеру на
        # ендпоинт пулу. Перевірка має враховувати обидва, бо гілка нижче
        # піднімає власний браузер з `config["proxy_server"]`, а в режимі пулу
        # він порожній — і весь обхід пішов би напряму, без жодного ендпоинта.
        # Живий прогін це показав: `goto url=… endpoint='' browser=…`, тобто
        # ендпоинт не дійшов навіть до навігації.
        if browser is not None or browsers:
            if browsers:
                await asyncio.gather(*(
                    crawl_with_browser(one, endpoint)
                    for one, endpoint in zip(browsers, endpoints or [])
                ))
            else:
                await crawl_with_browser(browser)
        else:
            if async_playwright is None:
                from playwright.async_api import async_playwright
            async with async_playwright() as playwright:
                proxy = {"server": config["proxy_server"]} if config["proxy_server"] else None
                browser = await launch_browser(playwright, config["browser"], proxy)
                try:
                    if browsers:
                        await asyncio.gather(*(
                            crawl_with_browser(one, endpoint)
                            for one, endpoint in zip(browsers, endpoints or [])
                        ))
                    else:
                        await crawl_with_browser(browser)
                finally:
                    await browser.close()
        if not defer_finish:
            finish_job(job_id, "cancelled" if is_cancelled(job_id) else "completed")
    except asyncio.CancelledError:
        if not defer_finish:
            finish_job(job_id, "cancelled")
        raise
    except Exception as error:
        if defer_finish:
            raise
        finish_job(job_id, "failed", error=str(error))


async def perform_actions(page, config, live_hook=None):
    for action in config["actions"]:
        if not isinstance(action, dict) or action.get("type") not in {"click", "fill"}:
            raise ValueError("only click and fill actions are supported")

        selector = str(action.get("selector", "")).strip()
        if not selector:
            raise ValueError(f"{action.get('type')} action requires selector")
        locator = page.locator(selector).first
        if action["type"] == "click":
            if live_hook is not None:
                await live_hook(
                    {"type": "click", "label": selector[:80], "selector": selector[:120]},
                    locator=locator,
                )
            # Travelled press, not a teleport: see human_input for why the event
            # stream is the signature a behavioural detector reads.
            await human_input.click_control(page, locator, 5000, _human_rng)
        else:
            val = str(action.get("value", ""))
            if live_hook is not None:
                await live_hook(
                    {
                        "type": "fill",
                        "label": selector[:80],
                        "selector": selector[:120],
                        "value": val[:40],
                    },
                    locator=locator,
                )
            await human_input.type_into(locator, val, _human_rng)
        await human_input.human_delay(_human_rng)


async def _pointer_evidence(page):
    """Read back how the page was actually driven, as the page counted it.

    Returns ``{}`` when no page reported a tally, rather than a zero. The
    difference matters: zero pointer events is a claim about the run, while an
    absent tally only says this page did not instrument itself, and reporting
    the second as the first would have every page that never counted anything
    look like a page that was teleported onto.

    Read after the interaction rather than subscribed to it, because a
    behavioural detector works the same way: it looks at the event stream the
    page accumulated, not at the intention behind it.
    """
    try:
        evidence = await page.evaluate(
            "() => ({tally: window.__rrPointerEvents, "
            "path: window.__rrPointerPath})"
        )
    except Exception:  # noqa: BLE001 - a closed or navigated page has no tally
        return {}
    if not isinstance(evidence, dict):
        return {}
    tally = evidence.get("tally")
    # The page may report a bare number, a tally object, or nothing at all
    # depending on how it instrumented itself, so all three are read here
    # rather than one shape being assumed. A shape this code does not expect is
    # "no evidence", never a fabricated zero.
    if isinstance(tally, dict):
        reported = tally.get("count")
        result = {} if reported is None else {"count": int(reported)}
        for name in ("down", "up"):
            if tally.get(name) is not None:
                result[name] = int(tally[name])
    elif isinstance(tally, (int, float)):
        result = {"count": int(tally)}
    else:
        return {}
    if evidence.get("path"):
        result["path"] = str(evidence["path"])
    return result


def dedupe_requests(requests):
    result = []
    seen = set()
    for request in requests:
        key = (request["method"], request["url"], request["resource_type"])
        if key not in seen:
            seen.add(key)
            result.append(request)
    return result


def append_page(job_id, page):
    with JOBS_LOCK:
        job = JOBS[job_id]
        job["pages"].append(page)
        job["visited"] = len(job["pages"])


def finish_job(job_id, status, error=None):
    """The one terminal path for every job, so this is where the lifecycle is logged.

    WHY HERE AND NOT IN THE HANDLER. `run_job` returns through several branches — a
    missing Playwright, a submit that raised, a normal completion — and a log line added
    per branch is a log line a future branch forgets. There was no log at all before:
    `log_message` returned nothing and the module imported no `logging`, so job state
    lived only in process memory and `data/logs/browser-worker.log` held two startup
    crashes with no timestamp and no PID.

    WHAT IS LOGGED. Lifecycle only: job id, terminal status, duration, error type. Never
    the config, the URL, headers or bodies — those are the analyst's target data, and the
    project's rule is that payloads do not go into diagnostics.
    """
    _log_job_finished(job_id, status, error)
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job:
            job["status"] = status
            # Доказ виходу: які ендпоинти пулу реально обслужили обхід.
            # Без цього «ротація» — це твердження в коді, а не спостережена
            # величина в результаті роботи.
            pool = job.get("_pool")
            if isinstance(pool, ProxyPool):
                job["proxy_pool"] = pool.report()
            job["manual_control"] = False
            _unblock_manual_control(job)
            job.pop("_control", None)
            job.pop("_loop", None)
            job.pop("_task", None)
            job.pop("_cancel_event", None)
            if error:
                job["error"] = error


def cancel_job(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return None
        job["cancelled"] = True
        job["manual_control"] = False
        job["status"] = "cancelling"
        loop = job.get("_loop")
        cancel_event = job.get("_cancel_event")
        task = job.get("_task")
        contexts = list(job.get("_contexts", []))
        _unblock_manual_control(job, loop)
    if loop is not None and loop.is_running():
        if cancel_event is not None:
            loop.call_soon_threadsafe(cancel_event.set)
        for ctx in contexts:
            try:
                loop.call_soon_threadsafe(lambda c=ctx: asyncio.create_task(c.close()))
            except Exception:
                pass
        if task is not None and not task.done():
            loop.call_soon_threadsafe(task.cancel)
    runtime = BROWSER_RUNTIME
    if runtime is not None and runtime.loop and runtime.loop.is_running():
        rt_task = runtime.job_tasks.get(job_id)
        if rt_task is not None and not rt_task.done():
            runtime.loop.call_soon_threadsafe(rt_task.cancel)
    return snapshot(job_id)


def cancel_all_jobs():
    with JOBS_LOCK:
        job_ids = [
            job_id
            for job_id, job in JOBS.items()
            if job.get("status") not in {"completed", "failed", "cancelled"}
        ]
    for job_id in job_ids:
        cancel_job(job_id)
    return job_ids


def is_cancelled(job_id):
    with JOBS_LOCK:
        return bool(JOBS.get(job_id, {}).get("cancelled"))


def snapshot(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            return None
        return {
            key: value
            for key, value in job.items()
            if key != "cancelled" and not key.startswith("_")
        }


class Handler(BaseHTTPRequestHandler):
    def _internal_request_ok(self):
        """Refuse a request whose `Host` is not loopback.

        This is geography, not identity: it closes DNS rebinding, where an
        attacker domain resolves to 127.0.0.1 and the browser sends
        `Host: evil.example`. It is the whole check now.

        The service key that used to sit here - `RR_INTERNAL_API_KEY` and
        `X-RequestRider-Internal-Key` - was removed end to end, and this is the
        measured reason it should not come back as an optional "compatibility
        mode". The key was compared against the value read at boot, so the worker
        only answered the engine when both had been started from the same
        environment; a leftover process on the port answered the by-design
        unauthenticated `/health`, `start.sh` adopted it as its own, and every
        later call drew 403. A credential scoped to one boot is a startup-ordering
        bug dressed as a security control.
        """
        host = (self.headers.get("Host") or "").split(":")[0].strip().lower().strip("[]")
        if host not in {"127.0.0.1", "localhost", "::1"}:
            self.send_json(403, {"error": "request host is not loopback"})
            return False
        return True

    def send_json(self, status, payload):
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def read_json(self):
        """Read the JSON body, refusing a declared length this server will not accept.

        `int(self.headers["Content-Length"])` raised `ValueError` on a non-numeric
        header, which surfaced as a 500 with a traceback, and a well-formed but enormous
        length was read without complaint — a declared length the client may never send
        pins this thread on a socket read.

        The limit is a resource guard, not a restriction on what may be crawled: it is a
        generous multiple of any crawl configuration, it is overridable through the
        environment so nothing is hidden, and exceeding it answers `413` with a named
        reason rather than truncating the body — a truncated JSON document would be a
        confusing parse error instead of a clear refusal.
        """
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except (TypeError, ValueError) as error:
            raise RequestBodyError("content-length header is not a number") from error
        if length < 0:
            raise RequestBodyError("content-length header is negative")
        limit = MAX_REQUEST_BODY_BYTES
        if length > limit:
            raise RequestBodyTooLarge(f"request body of {length} bytes exceeds the {limit} byte limit")
        body = self.rfile.read(length) if length else b""
        return json.loads(body)

    def do_POST(self):
        if not self._internal_request_ok():
            return
        parsed_path = urlparse(self.path)
        route_path = parsed_path.path
        if route_path == "/headless/probe":
            self._headless_probe()
            return
        if route_path.startswith("/target/") and route_path.endswith("/control"):
            job_id = route_path.removeprefix("/target/").removesuffix("/control").strip("/")
            try:
                body = self.read_json()
            except RequestBodyTooLarge as error:
                self.send_json(413, {"error": str(error), "reason": "REQUEST_BODY_TOO_LARGE"})
                return
            except (RequestBodyError, ValueError, TypeError, json.JSONDecodeError) as error:
                self.send_json(400, {"error": str(error)})
                return
            if not isinstance(body, dict):
                self.send_json(400, {"error": "request body must be an object"})
                return
            status_code, answer = execute_live_control(job_id, body)
            self.send_json(status_code, answer)
            return
        if route_path != "/target":
            self.send_json(404, {"error": "not found"})
            return
        try:
            config = normalize_input(self.read_json())
        except RequestBodyTooLarge as error:
            LOG.warning("target_job_refused job_path=%s reason=%s", self.path, error)
            self.send_json(413, {"error": str(error), "reason": "REQUEST_BODY_TOO_LARGE"})
            return
        except RequestBodyError as error:
            LOG.warning("target_job_refused job_path=%s reason=%s", self.path, error)
            self.send_json(400, {"error": str(error), "reason": "INVALID_CONTENT_LENGTH"})
            return
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error)})
            return
        job_id = uuid.uuid4().hex
        with JOBS_LOCK:
            JOBS[job_id] = {
                "job_id": job_id,
                "status": "running",
                "start_url": config["url"],
                "total": config["max_pages"],
                "same_origin": bool(config.get("same_origin", False)),
                "visited": 0,
                "pages": [],
                "live_view": bool(config.get("live_view", False)),
                "live_seq": 0,
                "manual_control": False,
                "cancelled": False,
                # For the log line in `finish_job`, and never serialised into a response:
                # `snapshot` builds its own dict, so a monotonic clock cannot leak out
                # as a meaningless number to the UI.
                "started_monotonic": time.monotonic(),
                # Пул живе на записі job під приватним ключем: `snapshot`
                # відкидає підкреслені, тож оператор бачить лише звіт про
                # використані ендпоинти, а не сам об'єкт у відповіді JSON.
                "_pool": config.get("proxy_pool"),
            }
        LOG.info(
            "target_job_started job_id=%s actions=%d browser=%s",
            job_id,
            len(config.get("actions") or []),
            (config.get("browser") or "default"),
        )
        threading.Thread(target=run_job, args=(job_id, config), daemon=True).start()
        self.send_json(202, snapshot(job_id))

    def _headless_probe(self):
        """One navigation, answered with what the page did.

        Additive, and separate from `/target` on purpose: a nuclei `headless:` step
        is a single navigation whose result is a dialog message and a DOM, while a
        `/target` job is a crawl with its own lifecycle, its own cancellation and its
        own result shape. Reusing the job machinery would have meant either a job per
        payload — 198 corpus templates carry `fuzzing:` blocks, so the job table
        would have been the protocol — or a second contract inside it.

        The limits below are resource guards with documented defaults, and each is
        named in the answer when it bites, so a refusal is never mistaken for a page
        that simply had nothing to say.
        """
        try:
            config = self.read_json()
        except RequestBodyTooLarge as error:
            self.send_json(413, {"error": str(error), "reason": "REQUEST_BODY_TOO_LARGE"})
            return
        except (RequestBodyError, ValueError, TypeError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error)})
            return
        url = str(config.get("url") or "").strip()
        if not url:
            self.send_json(400, {"error": "the probe needs a `url`"})
            return
        timeout_ms = _positive_int(config.get("timeout_ms"), HEADLESS_PROBE_TIMEOUT_MS)
        dialog_ms = _positive_int(config.get("dialog_timeout_ms"), HEADLESS_DIALOG_TIMEOUT_MS)
        wait_load = bool(config.get("wait_load", True))
        headers = config.get("headers") if isinstance(config.get("headers"), dict) else None
        try:
            answer = headless_probe_sync(
                url,
                timeout_ms=timeout_ms,
                dialog_timeout_ms=dialog_ms,
                wait_load=wait_load,
                headers=headers,
            )
        except Exception as error:  # noqa: BLE001 - the answer must name the failure
            LOG.warning("headless_probe_failed url_path=%s error=%s", _url_path(url), error)
            self.send_json(502, {"error": one_line(str(error)), "url": url})
            return
        self.send_json(200, answer)

    def do_GET(self):
        if not self._internal_request_ok():
            return
        parsed_path = urlparse(self.path)
        route_path = parsed_path.path
        if route_path == "/health":
            # `browsers` used to be the hardcoded catalogue of every name
            # `normalize_input` accepts, so it advertised `webkit` on a machine
            # where it was never downloaded and the job died on launch with a path
            # that did not exist. It now carries only what this worker measured it
            # can start, with `checked_at` so the answer is not mistaken for live
            # and `error` so a failed measurement is not read as an empty machine.
            payload = {"ok": True, "service": "browser-worker"}
            payload.update(runtime_available_browsers())
            self.send_json(200, payload)
            return
        if route_path.startswith("/target/") and route_path.endswith("/live"):
            job_id = route_path.removeprefix("/target/").removesuffix("/live").strip("/")
            query = parse_qs(parsed_path.query or "")
            worker_id = (query.get("worker_id") or [""])[0].strip() or None
            raw_since = (query.get("since") or ["0"])[0].strip()
            try:
                since = max(0, int(raw_since))
            except (TypeError, ValueError):
                since = 0
            result = live_snapshot(job_id, worker_id=worker_id, since=since)
            self.send_json(200 if result else 404, result or {"error": "target job not found"})
            return
        job_id = route_path.removeprefix("/target/")
        result = snapshot(job_id)
        self.send_json(200 if result else 404, result or {"error": "target job not found"})

    def do_DELETE(self):
        if not self._internal_request_ok():
            return
        if self.path == "/target":
            job_ids = cancel_all_jobs()
            self.send_json(200, {"cancelled": len(job_ids), "job_ids": job_ids})
            return
        job_id = self.path.removeprefix("/target/")
        result = cancel_job(job_id)
        self.send_json(202 if result else 404, result or {"error": "target job not found"})

    def log_message(self, format, *args):
        """One line per HTTP exchange, instead of silence.

        Deliberately without the request line: `BaseHTTPRequestHandler` passes the full
        request line here, and this worker's only GET path embeds a job id while its only
        POST body is not logged at all — but a query string on any future path would end
        up in the log, and the project does not put target data into diagnostics. Method
        and status are enough to tell "the worker is being hammered" from "the worker is
        answering 500".
        """
        LOG.info("http %s %s", self.command, args[1] if len(args) > 1 else "?")



# --- nuclei `headless:` probe ------------------------------------------------------
#
# 222 documents of the official corpus drive a browser directly. Measured over
# them: `navigate` in 229 blocks, `waitdialog` in 203, `script` in 47, `waitload` in
# 28, and matcher parts `query` 194 / `header` 192 / `body` 19 / `alerts` 6.
#
# `waitdialog` is the reason this endpoint exists at all: nuclei's headless protocol
# captures the text of the `alert()` a page fires, and a DOM-XSS template judges on
# exactly that string. A crawler that returns a DOM cannot see it.

HEADLESS_PROBE_TIMEOUT_MS = int(os.environ.get("RR_HEADLESS_PROBE_TIMEOUT_MS", "20000"))
HEADLESS_DIALOG_TIMEOUT_MS = int(os.environ.get("RR_HEADLESS_DIALOG_TIMEOUT_MS", "3000"))
HEADLESS_MAX_BODY_BYTES = 1 << 20


def _positive_int(value, default):
    """An integer the caller chose, or the documented default.

    The clamp is a guard against a body that is not an integer at all; it never
    narrows what a template may ask for, because `0` and a negative number fall
    back to the default rather than becoming a zero timeout that would fail the
    navigation for a reason the answer could not name.
    """
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _url_path(url):
    """A URL's path, for a log line.

    The worker's logs never carry target data — see `log_message` — so a failure
    names where the browser went without naming the query string it was sent.
    """
    try:
        from urllib.parse import urlparse

        return urlparse(url).path or "/"
    except Exception:  # noqa: BLE001 - logging must not raise
        return "?"


def one_line(text):
    return " ".join(str(text).split())


def headless_probe_sync(url, timeout_ms, dialog_timeout_ms, wait_load, headers=None):
    """Run one probe from a request thread.

    The runtime's own loop is used when it is running, and only then. Calling
    `asyncio.run` here instead starts a **second** Playwright driver on a second
    loop while the runtime's driver holds the browser — and measured, that hangs
    past every timeout in this function and past curl's own, so the request never
    came back at all. The direct coroutine call takes 4.8 s; the same call from the
    request thread did not return in 400 s.

    The fallback exists for a worker started without the runtime: there is then no
    other loop, and one created here is the only one.
    """
    coroutine = run_headless_probe(
        url,
        timeout_ms=timeout_ms,
        dialog_timeout_ms=dialog_timeout_ms,
        wait_load=wait_load,
        headers=headers,
    )
    runtime = BROWSER_RUNTIME
    if runtime is not None and getattr(runtime, "loop", None) is not None and runtime.loop.is_running():
        try:
            future = asyncio.run_coroutine_threadsafe(coroutine, runtime.loop)
            # The bound is the browser's own deadlines plus its teardown; past it the
            # answer is a named refusal rather than a thread that never returns.
            return future.result(timeout=(timeout_ms + dialog_timeout_ms) / 1000.0 + 30)
        except Exception as error:  # noqa: BLE001 - the answer names the failure
            return {
                "url": url,
                "dialog": False,
                "dialog_message": "",
                "dialog_type": "",
                "dialogs": 0,
                "status": 0,
                "body": "",
                "final_url": url,
                "error": f"the browser runtime did not answer: {one_line(error)}",
            }
    return asyncio.run(coroutine)


async def run_headless_probe(url, timeout_ms, dialog_timeout_ms, wait_load, headers=None):
    """Navigate once and report the page's answer.

    Returns a dict, never raises for a page that misbehaves: a navigation error is
    an outcome of the check, and the caller has to be able to say so rather than
    report a transport failure.
    """
    from playwright.async_api import async_playwright

    captured = {"dialog": None, "dialogs": 0, "type": ""}
    answer = {
        "url": url,
        "dialog": False,
        "dialog_message": "",
        "dialog_type": "",
        "dialogs": 0,
        "status": 0,
        "body": "",
        "final_url": url,
        "error": "",
    }
    playwright = await async_playwright().start()
    browser = None
    try:
        browser = await launch_browser(playwright, "firefox")
        context = await browser.new_context(ignore_https_errors=True)
        if headers:
            try:
                await context.set_extra_http_headers(headers)
            except Exception as error:  # noqa: BLE001 - reported, not raised
                answer["error"] = f"the page refused these extra headers: {one_line(error)}"
        page = await context.new_page()

        async def on_dialog(dialog):
            # `dismiss()` is a coroutine. Calling it without awaiting left the dialog
            # open, and an open dialog blocks the page: `page.content()` then waited
            # forever on a page whose script was still inside `alert()`. Measured — the
            # probe hung past its own 15 s navigation timeout and was killed, and the
            # only evidence was Python's «coroutine 'Dialog.dismiss' was never
            # awaited».
            captured["dialogs"] += 1
            if captured["dialog"] is None:
                captured["dialog"] = dialog.message
                captured["type"] = str(getattr(dialog, "type", "") or "")
            try:
                await dialog.dismiss()
            except Exception:  # noqa: BLE001 - dismissal is best effort
                pass

        page.on("dialog", on_dialog)
        try:
            response = await page.goto(url, timeout=timeout_ms, wait_until="load" if wait_load else "commit")
        except Exception as error:  # noqa: BLE001 - the failure belongs in the answer
            answer["error"] = f"navigation failed: {one_line(error)}"
            return answer
        if response is not None:
            try:
                answer["status"] = response.status
            except Exception:  # noqa: BLE001 - a missing status is not a reason to stop
                answer["status"] = 0
        try:
            answer["final_url"] = page.url
        except Exception:  # noqa: BLE001
            pass
        if dialog_timeout_ms > 0 and captured["dialog"] is None:
            # The dialog may fire a moment after `load` — a template that waits for
            # it and does not get it must be told the page never spoke, not that the
            # browser was slow.
            #
            # There is no `wait_for_event` here on purpose: a page that never opens a
            # dialog would then wait the whole window on every single probe, and 198
            # corpus templates carry `fuzzing:` blocks, so that wait is paid
            # thousands of times for a `false` that one already-known answer gives.
            await asyncio.sleep(min(dialog_timeout_ms, 1000) / 1000.0)
        try:
            body = await page.content()
        except Exception as error:  # noqa: BLE001
            body = ""
            if not answer["error"]:
                answer["error"] = f"the page's DOM could not be read: {one_line(error)}"
        if len(body.encode("utf-8", "replace")) > HEADLESS_MAX_BODY_BYTES:
            body = body.encode("utf-8", "replace")[:HEADLESS_MAX_BODY_BYTES].decode("utf-8", "replace")
            answer["error"] = join_note(answer["error"], f"the DOM was truncated at {HEADLESS_MAX_BODY_BYTES} bytes")
        answer["body"] = body
        answer["dialog"] = captured["dialog"] is not None
        answer["dialog_message"] = captured["dialog"] or ""
        answer["dialog_type"] = captured["type"]
        answer["dialogs"] = captured["dialogs"]
        return answer
    finally:
        if browser is not None:
            try:
                await browser.close()
            except Exception:  # noqa: BLE001 - teardown must not mask the answer
                pass
        try:
            await playwright.stop()
        except Exception:  # noqa: BLE001
            pass


def join_note(first, second):
    first = (first or "").strip()
    second = (second or "").strip()
    if not first:
        return second
    if not second or second in first:
        return first
    return first + "; " + second

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    # Binding a control-plane listener to a reachable interface is a deliberate,
    # visible act — never a typo in HOST. The engine enforces the same rule on
    # its own listeners (requireLoopbackBind in engine/internal_auth.go).
    if host.strip().lower().strip("[]") not in {"127.0.0.1", "localhost", "::1"}:
        if os.environ.get("RR_ALLOW_NON_LOOPBACK_BIND", "").strip() != "1":
            raise SystemExit(
                f"browser-worker refuses to bind {host}: not loopback "
                "(set RR_ALLOW_NON_LOOPBACK_BIND=1 to override deliberately)"
            )
    server = ThreadingHTTPServer((host, int(os.environ.get("PORT", "8090"))), Handler)
    try:
        BROWSER_RUNTIME = check_browser_runtime()
    except Exception as error:
        server.server_close()
        raise SystemExit(f"browser runtime unavailable: {error}") from error

    def request_shutdown(_signum, _frame):
        threading.Thread(
            target=server.shutdown,
            name="request-rider-browser-server-shutdown",
            daemon=True,
        ).start()

    signal.signal(signal.SIGINT, request_shutdown)
    signal.signal(signal.SIGTERM, request_shutdown)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        cancel_all_jobs()
        BROWSER_RUNTIME.stop()
