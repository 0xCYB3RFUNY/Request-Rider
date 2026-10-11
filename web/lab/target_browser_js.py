"""JavaScript analysis for the browser-driven Target crawler.

# What is missing without this module

The Target crawler has two modes and only one of them can read a program.

The static crawler fetches bytes, so the engine parses them inside the crawl and
the page record carries `js` — endpoints, DOM-write sinks, embedded secrets.
Measured on a live target: 19 endpoints and 21 findings out of one 150 KB
bundle.

The browser-driven mode never reads a body. `browser-worker` drives a real
browser and reports the pages it navigated plus the requests those pages made, so
every `.js` the site loaded appears **as a URL** and is read **as a program** by
nobody. The analyst sees the script in the network list and gets no endpoints, no
sinks and no secrets from it. The same file, a different answer, and nothing on
the screen that says why.

# What this module does about it

Once a browser-driven job reaches a terminal state, the script URLs it reported
are handed to the engine (`POST /proxy/target-js`), which reads and analyses them
with the crawler transport and the same analyser the static crawl uses. The
answers come back in the crawler's own page-record shape and are appended to
`pages`, so the map table, the status counter, the tree and the exporters draw
them through the code that already draws a statically crawled bundle. No second
renderer, no second report, and no "browser mode has no JS analysis" gap in the
middle of a tool whose two modes are supposed to be the same tool.

# Three decisions that belong here rather than in the view

- **Analysis waits for a terminal state.** A running job re-reports its network
  list on every poll. Analysing on each poll would re-download and re-parse every
  bundle once a second for the whole crawl; waiting pays the cost once.
- **The answer is cached on the job's own result** under `js_analysis`, keyed by
  the URL list it was produced from. A second poll of the same finished job
  re-uses it instead of fetching every bundle again, and a changed URL list — a
  late script, a redirect that resolved elsewhere — re-analyses rather than
  reporting a stale answer as a fresh one.
- **A failed analysis is stated, not hidden.** If the engine refuses, times out or
  answers with something unexpected, the reason lands in `js_analysis.error` and
  the page rows are simply absent. Dropping the error would make a broken engine
  indistinguishable from a site with no JavaScript.

The module holds no Django models and no database access on purpose: the wiring
in `views.target_browser` owns the job, and this file is the part that can be
tested without a database.
"""

from __future__ import annotations

from urllib.parse import urlsplit

# The statuses a browser job can stop at. Analysis runs at any of them: a
# cancelled crawl still saw the scripts it had already loaded, and those are
# answers the analyst paid for.
BROWSER_TERMINAL_STATUSES = frozenset({"completed", "cancelled", "failed", "error"})

# Script media and suffixes. The browser worker's network log carries only
# `url`, `method` and `resource_type`, so the extension is what survives for a
# script served from a path that has none — the content type is the engine's
# call, not this file's.
SCRIPT_SUFFIXES = (".js", ".mjs", ".cjs")
SCRIPT_RESOURCE_TYPES = frozenset({"script"})

# The key the answer is cached under, and the marker that distinguishes a page
# derived from the network log from a page the browser actually navigated. The
# marker is what makes re-attachment idempotent: pages carrying it are replaced,
# pages without it are never touched.
JS_ANALYSIS_KEY = "js_analysis"
SCRIPT_PAGE_SOURCE = "browser-network"

# How many script URLs go into one engine call.
#
# The whole batch used to go in a single call, and that is what made the analysis
# invisible. Measured on ria.ru with a real browser job: the browser reported 85
# script URLs, the engine needed **248 s** for all of them (HTTP 200, 81 analysed,
# 437 endpoints, 301 findings), and Django's engine client cuts the socket at
# `DEFAULT_ENGINE_TIMEOUT = 120.0` (`web/lab/engine_client.py:26`). The call died
# at 120 s, the gateway answered `502 engine unavailable: timed out`,
# `js_analysis.records` became `[]`, and `attach_script_pages` therefore attached
# nothing — so the map showed the bundles in the network list and zero findings,
# with nothing on screen saying why. Raising the timeout would only move the
# cliff: any site with more scripts than the deadline allows loses the whole
# analysis again, and it loses it *silently*, which is the one outcome this whole
# module exists to prevent.
#
# Batching fixes the cause instead of the symptom: every call finishes inside the
# deadline, and a batch that does fail costs only its own scripts. The size is a
# measured default, not a limit on the crawl — the URL list itself is never
# truncated, it is only split into calls, so a page with 500 scripts is analysed
# completely, just in more than one round trip.
#
# The size is measured, not guessed, against the deadline it has to survive.
# Same 85 URLs from the live ria.ru job, real calls, real wall clock:
#
#   chunk  batches  slowest call  records  error
#   85         1        >120 s        0   engine unavailable: timed out   (original)
#   24         4        ~120 s       61   scripts 49-72 … timed out
#   10         9      106.1 s        85   none
#    5        17       23.2 s        85   none
#
# The mean is a poor guide here: the cost is CDN latency, not parse time, so the
# slow bundles cluster and one unlucky batch dominates. Worst case tracks the
# batch size almost linearly, and 5 keeps a fivefold margin under the deadline
# while still finishing every script. It is a batching size, never a limit on
# what gets analysed — 500 scripts produce 100 calls, not a truncated list.
JS_ANALYSIS_CHUNK = 5


def is_terminal(result) -> bool:
    """Report whether a browser job has stopped."""
    if not isinstance(result, dict):
        return False
    return str(result.get("status", "")).strip().lower() in BROWSER_TERMINAL_STATUSES


def looks_like_script(url: str, resource_type: str = "") -> bool:
    """Report whether a network entry is worth handing to the analyser.

    Two signals, and both are used because each covers what the other cannot: a
    browser knows a request was a script even when the URL carries no extension
    (`/bundle?hash=…`), and a suffix identifies a script in a log written by
    something that did not classify it.
    """
    if str(resource_type or "").strip().lower() in SCRIPT_RESOURCE_TYPES:
        return True
    path = urlsplit(str(url or "")).path.lower()
    return path.endswith(SCRIPT_SUFFIXES)


def browser_script_urls(result) -> list[str]:
    """Collect the script URLs a finished browser job reported.

    Order is the order the browser requested them, and each URL appears once: a
    single page commonly requests the same framework bundle from several of its
    own modules, and the engine reads each distinct URL exactly once anyway.
    """
    if not isinstance(result, dict):
        return []
    pages = result.get("pages")
    if not isinstance(pages, list):
        return []
    urls: list[str] = []
    seen: set[str] = set()
    for page in pages:
        if not isinstance(page, dict):
            continue
        network = page.get("network")
        if not isinstance(network, list):
            continue
        for request in network:
            if not isinstance(request, dict):
                continue
            url = str(request.get("url") or "").strip()
            if not url or url in seen:
                continue
            if not looks_like_script(url, str(request.get("resource_type") or "")):
                continue
            scheme = urlsplit(url).scheme.lower()
            if scheme not in {"http", "https"}:
                # A browser cannot have requested this, so it came from somewhere
                # else in the record and the engine would only refuse it.
                continue
            seen.add(url)
            urls.append(url)
    return urls


def _script_depths(result) -> dict:
    """Map each script URL to the depth of the page that requested it.

    The depth belongs to the page, not to the script: a bundle has no level of
    its own, and the row would otherwise show a dash where the map has a depth
    for everything else. The shallowest page wins, because that is the first
    place the script was reached from.
    """
    depths: dict = {}
    pages = result.get("pages") if isinstance(result, dict) else None
    if not isinstance(pages, list):
        return depths
    for page in pages:
        if not isinstance(page, dict):
            continue
        network = page.get("network")
        if not isinstance(network, list):
            continue
        depth = page.get("depth")
        for request in network:
            if not isinstance(request, dict):
                continue
            url = str(request.get("url") or "").strip()
            if not url or url in depths:
                continue
            if not looks_like_script(url, str(request.get("resource_type") or "")):
                continue
            if isinstance(depth, int):
                depths[url] = depth
    return depths


def script_page(record, depth=None) -> dict:
    """Turn one engine answer into the crawler's own page record.

    The shape is the static crawler's, deliberately: the renderer, the tree, the
    counters and the exporters already know these fields, and a record of a
    different shape would need a second version of all of them.
    """
    page = {
        "url": str(record.get("url") or ""),
        "kind": str(record.get("kind") or "javascript"),
        "status": record.get("status"),
        "content_type": str(record.get("content_type") or ""),
        "time": record.get("time"),
        "bytes": record.get("bytes"),
        "depth": depth,
        "js_source": SCRIPT_PAGE_SOURCE,
    }
    analysis = record.get("js")
    if isinstance(analysis, dict):
        page["js"] = analysis
    error = str(record.get("error") or "").strip()
    if error:
        page["error"] = error
    return page


def attach_script_pages(result, records, depths=None) -> int:
    """Put the analysis answers into the result's page list.

    Idempotent by construction: pages carrying the derived marker are removed
    first, so a second poll cannot double the rows. Returns how many rows were
    added by this call.
    """
    if not isinstance(result, dict):
        return 0
    pages = result.get("pages")
    if not isinstance(pages, list):
        pages = []
        result["pages"] = pages
    kept = [
        page
        for page in pages
        if not (isinstance(page, dict) and page.get("js_source") == SCRIPT_PAGE_SOURCE)
    ]
    depths = depths if isinstance(depths, dict) else {}
    added = 0
    for record in records or []:
        if not isinstance(record, dict):
            continue
        page = script_page(record, depths.get(str(record.get("url") or "")))
        if not page["url"]:
            continue
        kept.append(page)
        added += 1
    result["pages"] = kept
    return added


def _describe_engine_failure(status, payload) -> str:
    """Say what the engine did instead of pretending the site had no scripts."""
    if isinstance(payload, dict):
        reason = str(payload.get("error") or payload.get("reason") or "").strip()
        if reason:
            return f"engine answered {status}: {reason}"[:400]
    if isinstance(payload, str) and payload.strip():
        return f"engine answered {status}: {payload.strip()}"[:400]
    return f"engine answered {status} with no results"[:400]


def enrich_browser_target_result(result, previous=None, call=None) -> dict:
    """Analyse the scripts a finished browser job reported.

    `previous` is the result as it was stored the last time this job was polled,
    and it is what keeps a finished job from re-downloading every bundle on every
    poll. `call` is the engine caller, injected by the tests; production uses
    `views.call_engine`.
    """
    if not isinstance(result, dict) or not is_terminal(result):
        return result
    urls = browser_script_urls(result)
    if not urls:
        return result
    cached = previous.get(JS_ANALYSIS_KEY) if isinstance(previous, dict) else None
    records: list = []
    error = ""
    if isinstance(cached, dict) and cached.get("urls") == urls:
        reused = cached.get("records")
        records = reused if isinstance(reused, list) else []
        error = str(cached.get("error") or "")
    else:
        caller = call
        if caller is None:
            from .views import call_engine  # local import: views imports this module

            caller = call_engine
        records, error = _analyze_in_batches(caller, urls, result)
    result[JS_ANALYSIS_KEY] = {
        "urls": urls,
        "records": records,
        "error": error,
        # Visible by rule: the analyst sees how the list was split, so a batch that
        # failed is attributable to a named range rather than to "the site".
        "batches": _batch_count(len(urls)),
        "batch_size": JS_ANALYSIS_CHUNK,
    }
    attach_script_pages(result, records, _script_depths(result))
    return result


def _batch_count(total: int) -> int:
    """How many engine calls a list of this size costs."""
    return (max(0, int(total)) + JS_ANALYSIS_CHUNK - 1) // JS_ANALYSIS_CHUNK


def _analyze_in_batches(caller, urls, result):
    """Analyse the scripts in batches, and keep what succeeded when one does not.

    Order is preserved, because `records` is the order the engine reported in and
    the page list is built from it.

    A failed batch costs only its own scripts. Stopping at the first `502` is what
    made one slow CDN lose the other eighty bundles, so the failure is recorded and
    the next batch still runs. Every failure reason reaches `error`, joined — the
    answer has to name what was not analysed, not just that something was.
    """
    records: list = []
    failures: list = []
    for start in range(0, len(urls), JS_ANALYSIS_CHUNK):
        batch = urls[start:start + JS_ANALYSIS_CHUNK]
        try:
            status, payload = caller("/proxy/target-js", _script_request(batch, result))
        except Exception as exc:  # noqa: BLE001 - a refused analysis is an answer
            status, payload = 0, {"error": f"{type(exc).__name__}: {exc}"}
        if status == 200 and isinstance(payload, dict) and isinstance(payload.get("results"), list):
            records.extend(payload["results"])
            warning = str(payload.get("warning") or "").strip()
            if warning:
                failures.append(f"engine dropped an entry: {warning}"[:400])
        else:
            # The range is named only when there is more than one batch. With a
            # single batch there is nothing for a range to disambiguate, and the
            # bare reason reads better — it is also the exact string a job with a
            # single script reported before batching existed, so the answer for
            # that case does not change.
            reason = _describe_engine_failure(status, payload)
            if _batch_count(len(urls)) > 1:
                reason = f"scripts {start + 1}-{start + len(batch)}: {reason}"
            failures.append(reason)
    return records, "; ".join(failures)[:400]


def _script_request(urls, result) -> dict:
    """Build the engine request, carrying the page each script was loaded from.

    The per-script referrer is not decoration. A CDN that serves a bundle only to
    its own site answers a request that claims to come from nowhere with a 403,
    and the same site read by the same gateway with a referrer reads fine — so a
    bare URL list would make "browser mode found no JavaScript" a statement about
    how the request looked rather than about the site.
    """
    pages = result.get("pages") if isinstance(result, dict) else None
    referrers: dict = {}
    if isinstance(pages, list):
        for page in pages:
            if not isinstance(page, dict):
                continue
            page_url = str(page.get("url") or page.get("requested_url") or "").strip()
            if not page_url:
                continue
            network = page.get("network")
            if not isinstance(network, list):
                continue
            for request in network:
                if not isinstance(request, dict):
                    continue
                url = str(request.get("url") or "").strip()
                if url and looks_like_script(url, str(request.get("resource_type") or "")) and url not in referrers:
                    referrers[url] = page_url
    start = ""
    if isinstance(pages, list) and pages and isinstance(pages[0], dict):
        start = str(pages[0].get("url") or "").strip()
    return {
        "urls": [{"url": url, "referer": referrers.get(url) or start} for url in urls],
        "referer": start,
    }