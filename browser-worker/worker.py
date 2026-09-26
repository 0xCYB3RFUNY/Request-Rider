"""Isolated Firefox/Playwright worker for JavaScript-rendered Target routes."""

import json
import os
import asyncio
import threading
import time
import uuid
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urldefrag, urljoin, urlparse


JOBS = {}
JOBS_LOCK = threading.Lock()


def check_browser_runtime():
    import asyncio
    from playwright.async_api import async_playwright

    async def probe():
        async with async_playwright() as playwright:
            browser = await launch_browser(playwright, os.environ.get("BROWSER", "firefox"))
            await browser.close()

    asyncio.run(probe())


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
        "concurrency": int(payload.get("concurrency", 4)),
        "same_origin": bool(payload.get("same_origin", False)),
        "actions": payload.get("actions") or [],
        "allow_state_changing_actions": bool(payload.get("allow_state_changing_actions", False)),
        "proxy_server": str(payload.get("proxy_server", "")).strip(),
        "proxy_mitm_ca": proxy_mitm_ca,
        "browser": str(payload.get("browser", "firefox")).strip().lower(),
    }
    if result["max_pages"] < 0:
        result["max_pages"] = 0
    if result["max_depth"] < -1 or result["delay_ms"] < 0 or result["concurrency"] < 1:
        raise ValueError("max_depth, delay_ms and concurrency must be valid; max_pages <= 0 means unlimited")
    if result["browser"] not in {"firefox", "chromium", "chrome", "edge", "webkit"}:
        raise ValueError("browser must be firefox, chromium, chrome, edge or webkit")
    return result


def same_origin(candidate, origin):
    parsed = urlparse(candidate)
    return f"{parsed.scheme}://{parsed.netloc}" == origin


async def extract_links(page, current_url):
    links = await page.eval_on_selector_all(
        "a[href], area[href], link[href], script[src], img[src], iframe[src], form[action]",
        """(nodes) => nodes.map(node =>
          node.href || node.src || node.action || '').filter(Boolean)""",
    )
    result = []
    for link in links:
        absolute = urldefrag(urljoin(current_url, link))[0]
        if urlparse(absolute).scheme in {"http", "https"}:
            result.append(absolute)
    return result


async def launch_browser(playwright, browser_name, proxy=None):
    options = {"headless": True}
    executable_path = os.environ.get("FIREFOX_EXECUTABLE_PATH", "").strip()
    if browser_name == "firefox" and executable_path:
        options["executable_path"] = executable_path
    if proxy:
        options["proxy"] = proxy
    if browser_name == "firefox":
        return await playwright.firefox.launch(**options)
    if browser_name == "webkit":
        return await playwright.webkit.launch(**options)
    if browser_name == "chrome":
        options["channel"] = "chrome"
        return await playwright.chromium.launch(**options)
    if browser_name == "edge":
        options["channel"] = "msedge"
        return await playwright.chromium.launch(**options)
    return await playwright.chromium.launch(**options)


def run_job(job_id, config):
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


async def run_async_job(job_id, config, async_playwright):
    if is_cancelled(job_id):
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
    origin = f"{urlparse(config['url']).scheme}://{urlparse(config['url']).netloc}"
    queue = asyncio.Queue()
    await queue.put((config["url"], 0))
    seen = {config["url"]}
    state_lock = asyncio.Lock()
    try:
        async with async_playwright() as playwright:
            proxy = None
            if config["proxy_server"]:
                proxy = {"server": config["proxy_server"]}
            browser = await launch_browser(playwright, config["browser"], proxy)
            page_options = {}
            if config.get("proxy_mitm_ca"):
                # The local passive proxy verifies upstream TLS with the engine
                # CA; the isolated browser must trust that explicitly for MITM.
                page_options["ignore_https_errors"] = True
            if config["capture_context"] and proxy:
                page_options["extra_http_headers"] = {
                    "X-RequestRider-Capture-Context": config["capture_context"],
                }
            async def crawl_worker():
                page = await browser.new_page(**page_options)
                async def route_request(route):
                    if route.request.resource_type in {"image", "font", "media"}:
                        await route.abort()
                    else:
                        await route.continue_()
                await page.route("**/*", route_request)
                try:
                    while True:
                        current_url, depth = await queue.get()
                        try:
                            if is_cancelled(job_id):
                                continue
                            requests = []
                            request_listener = lambda request: requests.append({
                                "url": request.url,
                                "method": request.method,
                                "resource_type": request.resource_type,
                            })
                            page.on("request", request_listener)
                            started = time.monotonic()
                            try:
                                response = await page.goto(current_url, wait_until="domcontentloaded")
                                await page.wait_for_timeout(50)
                                status = response.status if response else None
                                page_result = {
                                    "requested_url": current_url,
                                    "url": page.url or current_url,
                                    "depth": depth,
                                    "status": status,
                                    "kind": "browser-page",
                                    "content_type": await response.header_value("content-type") if response else "",
                                    "time": round((time.monotonic() - started) * 1000),
                                    "network": dedupe_requests(requests),
                                }
                                if depth == 0 and current_url == config["url"]:
                                    await perform_actions(page, config)
                                page_result["network"] = dedupe_requests(requests)
                                page_result["links"] = await extract_links(page, page.url or current_url)
                            except Exception as error:
                                page_result = {
                                    "requested_url": current_url,
                                    "url": current_url,
                                    "depth": depth,
                                    "status": None,
                                    "kind": "browser-page",
                                    "time": round((time.monotonic() - started) * 1000),
                                    "error": str(error),
                                    "network": dedupe_requests(requests),
                                }
                            finally:
                                page.remove_listener("request", request_listener)
                            append_page(job_id, page_result)
                            if config["max_depth"] < 0 or depth < config["max_depth"]:
                                async with state_lock:
                                    for link in page_result.get("links", []):
                                        if config["same_origin"] and not same_origin(link, origin):
                                            continue
                                        if link not in seen and (config["max_pages"] <= 0 or len(seen) < config["max_pages"]):
                                            seen.add(link)
                                            await queue.put((link, depth + 1))
                            if config["delay_ms"]:
                                await asyncio.sleep(config["delay_ms"] / 1000)
                        finally:
                            queue.task_done()
                except asyncio.CancelledError:
                    raise
                finally:
                    await page.close()

            workers = [asyncio.create_task(crawl_worker()) for _ in range(config["concurrency"])]

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
                await browser.close()
        finish_job(job_id, "cancelled" if is_cancelled(job_id) else "completed")
    except asyncio.CancelledError:
        finish_job(job_id, "cancelled")
        raise
    except Exception as error:
        finish_job(job_id, "failed", error=str(error))


async def perform_actions(page, config):
    for action in config["actions"]:
        if not isinstance(action, dict) or action.get("type") not in {"click", "fill"}:
            raise ValueError("only click and fill actions are supported")

        selector = str(action.get("selector", "")).strip()
        if not selector:
            raise ValueError(f"{action.get('type')} action requires selector")
        locator = page.locator(selector).first
        if action["type"] == "click":
            await locator.click()
        else:
            await locator.fill(str(action.get("value", "")))
        await page.wait_for_timeout(250)


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
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job:
            job["status"] = status
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
        job["status"] = "cancelling"
        loop = job.get("_loop")
        cancel_event = job.get("_cancel_event")
    if loop is not None and cancel_event is not None and loop.is_running():
        loop.call_soon_threadsafe(cancel_event.set)
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
    def send_json(self, status, payload):
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length))

    def do_POST(self):
        if self.path != "/target":
            self.send_json(404, {"error": "not found"})
            return
        try:
            config = normalize_input(self.read_json())
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error)})
            return
        job_id = uuid.uuid4().hex
        with JOBS_LOCK:
            JOBS[job_id] = {
                "job_id": job_id,
                "status": "running",
                "start_url": config["url"],
                "visited": 0,
                "pages": [],
                "cancelled": False,
            }
        threading.Thread(target=run_job, args=(job_id, config), daemon=True).start()
        self.send_json(202, snapshot(job_id))

    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, {"ok": True, "service": "browser-worker", "browsers": ["firefox", "chromium", "chrome", "edge", "webkit"]})
            return
        job_id = self.path.removeprefix("/target/")
        result = snapshot(job_id)
        self.send_json(200 if result else 404, result or {"error": "target job not found"})

    def do_DELETE(self):
        if self.path == "/target":
            job_ids = cancel_all_jobs()
            self.send_json(200, {"cancelled": len(job_ids), "job_ids": job_ids})
            return
        job_id = self.path.removeprefix("/target/")
        result = cancel_job(job_id)
        self.send_json(202 if result else 404, result or {"error": "target job not found"})

    def log_message(self, *_):
        return


if __name__ == "__main__":
    try:
        check_browser_runtime()
    except Exception as error:
        raise SystemExit(f"browser runtime unavailable: {error}") from error
    host = os.environ.get("HOST", "127.0.0.1")
    server = ThreadingHTTPServer((host, int(os.environ.get("PORT", "8090"))), Handler)
    server.serve_forever()
