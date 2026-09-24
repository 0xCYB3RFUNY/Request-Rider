"""Live Firefox scenarios for the RequestRider Automation editor.

Run from the repository root with the browser-worker virtualenv:

    browser-worker/.venv/bin/python tests/e2e/test_automation_ui.py

The tests use only the local Django/Go services and tools/target_fixture.py.
They create uniquely named workflows and remove them during teardown.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError, sync_playwright
except ImportError as error:  # pragma: no cover - exercised only without browser deps
    raise SystemExit("Playwright is required: use browser-worker/.venv/bin/python") from error


ROOT = Path(__file__).resolve().parents[2]
WEB_DIR = ROOT / "web"
DEFAULT_BASE_URL = os.environ.get("REQUESTRIDER_BASE_URL", "http://127.0.0.1:8000/")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request_json(url: str, method: str = "GET", payload=None, timeout: float = 10):
    body = None
    headers = {}
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return json.loads(raw.decode("utf-8") or "{}")
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", errors="replace")
        raise AssertionError(f"{method} {url}: HTTP {error.code}: {raw}") from error


def wait_http(url: str, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if 200 <= response.status < 300:
                    return
        except Exception as error:  # noqa: BLE001 - startup diagnostics
            last_error = error
        time.sleep(0.1)
    raise RuntimeError(f"Service did not become ready: {url}: {last_error}")


def wait_tcp(host: str, port: int, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError as error:  # noqa: BLE001 - startup diagnostics
            last_error = error
        time.sleep(0.1)
    raise RuntimeError(f"TCP service did not become ready: {host}:{port}: {last_error}")


class FakeLLMHandler(BaseHTTPRequestHandler):
    """Local OpenAI-compatible response used to test explicit AI handoffs."""

    def log_message(self, *_args):
        return

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        self.server.requests.append(payload)
        response = {
            "choices": [{
                "message": {
                    "content": json.dumps({"message": self.server.response}, ensure_ascii=False)
                }
            }]
        }
        raw = json.dumps(response, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class AutomationUiTests(unittest.TestCase):
    fixture_process = None
    oast_fixture_process = None
    oast_fixture_port = 0
    last_byte_fixture_process = None
    last_byte_fixture_port = 0
    playwright = None
    browser = None
    fixture_port = 0
    llm_server = None
    llm_thread = None
    llm_port = 0

    @classmethod
    def setUpClass(cls):
        request_json(DEFAULT_BASE_URL + "api/workflows/node-types")
        cls.fixture_port = free_port()
        cls.fixture_process = subprocess.Popen(
            [sys.executable, str(ROOT / "tools" / "target_fixture.py")],
            cwd=ROOT,
            env={**os.environ, "FIXTURE_PORT": str(cls.fixture_port), "FIXTURE_HOST": "127.0.0.1"},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wait_http(f"http://127.0.0.1:{cls.fixture_port}/health")
        cls.oast_fixture_port = free_port()
        cls.oast_fixture_process = subprocess.Popen(
            [sys.executable, str(ROOT / "tools" / "oast_fixture.py")],
            cwd=ROOT,
            env={**os.environ, "OAST_FIXTURE_PORT": str(cls.oast_fixture_port), "OAST_FIXTURE_HOST": "127.0.0.1"},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wait_http(f"http://127.0.0.1:{cls.oast_fixture_port}/health")
        cls.last_byte_fixture_port = free_port()
        cls.last_byte_fixture_process = subprocess.Popen(
            [sys.executable, str(ROOT / "tools" / "last_byte_fixture.py")],
            cwd=ROOT,
            env={**os.environ, "LAST_BYTE_FIXTURE_PORT": str(cls.last_byte_fixture_port), "LAST_BYTE_FIXTURE_HOST": "127.0.0.1"},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wait_tcp("127.0.0.1", cls.last_byte_fixture_port)
        cls.llm_server = ThreadingHTTPServer(("127.0.0.1", 0), FakeLLMHandler)
        cls.llm_server.requests = []
        cls.llm_server.response = (
            "FACT: the attached evidence is bounded and local. "
            f"Recommended next crawl: http://127.0.0.1:{cls.fixture_port}/next"
        )
        cls.llm_port = cls.llm_server.server_port
        cls.llm_thread = threading.Thread(target=cls.llm_server.serve_forever, daemon=True)
        cls.llm_thread.start()
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.firefox.launch(headless=True)

    @classmethod
    def tearDownClass(cls):
        if cls.browser:
            cls.browser.close()
        if cls.playwright:
            cls.playwright.stop()
        if cls.llm_server:
            cls.llm_server.shutdown()
            cls.llm_server.server_close()
        if cls.llm_thread:
            cls.llm_thread.join(timeout=2)
        if cls.fixture_process:
            cls.fixture_process.terminate()
            try:
                cls.fixture_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.fixture_process.kill()
        if cls.oast_fixture_process:
            cls.oast_fixture_process.terminate()
            try:
                cls.oast_fixture_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.oast_fixture_process.kill()
        if cls.last_byte_fixture_process:
            cls.last_byte_fixture_process.terminate()
            try:
                cls.last_byte_fixture_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.last_byte_fixture_process.kill()
        cls.cleanup_fixture_database()

    @classmethod
    def cleanup_fixture_database(cls):
        """Remove records created by this suite without touching user data."""
        web_python = WEB_DIR / ".venv" / "bin" / "python"
        if not web_python.exists():
            return
        port = cls.fixture_port
        last_byte_port = cls.last_byte_fixture_port
        code = (
            "from lab.models import TargetJob, TrafficRecord; "
            f"TargetJob.objects.filter(url__contains='127.0.0.1:{port}').delete(); "
            f"TrafficRecord.objects.filter(url__contains='127.0.0.1:{port}').delete(); "
            f"TrafficRecord.objects.filter(url__contains='127.0.0.1:{last_byte_port}').delete()"
        )
        subprocess.run(
            [str(web_python), "manage.py", "shell", "-c", code],
            cwd=WEB_DIR,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def setUp(self):
        self.context = self.browser.new_context(viewport={"width": 1366, "height": 900})
        self.page = self.context.new_page()
        self.page_errors = []
        self.failed_requests = []
        self.workflow_ids = []
        self.project_ids = []
        self.capture_context_ids = []
        self.page.on("pageerror", lambda error: self.page_errors.append(str(error)))
        self.page.on(
            "requestfailed",
            lambda request: self.failed_requests.append({
                "url": request.url,
                "error": request.failure,
            }),
        )
        try:
            self.page.goto(DEFAULT_BASE_URL, wait_until="commit", timeout=30000)
            self.page.locator("#workflow-new").wait_for(state="attached", timeout=30000)
        except PlaywrightTimeoutError:
            # Firefox can briefly retain a saturated connection after an
            # earlier SSE-heavy scenario; retry the same isolated page once.
            self.page.goto(DEFAULT_BASE_URL, wait_until="commit", timeout=30000)
            self.page.locator("#workflow-new").wait_for(state="attached", timeout=30000)
        self.page.wait_for_timeout(700)
        # Each scenario gets an isolated local Project for durable metadata;
        # Project selection does not restrict outbound tool URLs.
        self.default_project_id = self.create_project(
            self.unique_name("default-project"),
            f"http://127.0.0.1:{self.fixture_port}/",
        )

    def tearDown(self):
        for context_id in reversed(self.capture_context_ids):
            try:
                self.page.evaluate(
                    """async id => {
                        const token = document.cookie.split(';').map(item => item.trim())
                            .find(item => item.startsWith('csrftoken='))?.slice('csrftoken='.length) || '';
                        const response = await fetch(`/api/traffic/capture-contexts/${id}`, {
                            method: 'DELETE', headers: {'X-CSRFToken': token}
                        });
                        if (!response.ok) throw new Error(`capture context cleanup HTTP ${response.status}`);
                    }""",
                    context_id,
                )
            except Exception:  # noqa: BLE001 - cleanup must not mask assertion
                pass
        for workflow_id in reversed(self.workflow_ids):
            try:
                request_json(f"{DEFAULT_BASE_URL}api/workflows/{workflow_id}", method="DELETE")
            except Exception:  # noqa: BLE001 - cleanup must not mask assertion
                pass
        for project_id in reversed(self.project_ids):
            try:
                request_json(f"{DEFAULT_BASE_URL}api/projects/{project_id}", method="DELETE")
            except Exception:  # noqa: BLE001
                pass
        self.context.close()

    # ---- browser helpers -------------------------------------------------

    def unique_name(self, prefix: str) -> str:
        return f"e2e-{prefix}-{int(time.time())}-{uuid.uuid4().hex[:6]}"

    def goto_tab(self, kind: str) -> None:
        self.page.locator(f'nav button[data-tab="{kind}"]').click()
        self.page.locator(f"#{kind}.active").wait_for(state="visible", timeout=5000)

    def reload_page(self) -> None:
        last_error = None
        for attempt in range(3):
            try:
                self.page.reload(wait_until="domcontentloaded", timeout=30000)
                self.page.locator("#workflow-new").wait_for(state="attached", timeout=30000)
                return
            except PlaywrightTimeoutError as error:
                last_error = error
                if attempt < 2:
                    time.sleep(1)
        raise last_error

    def new_workflow(self, prefix: str) -> str:
        name = self.unique_name(prefix)
        self.goto_tab("automation")
        self.page.locator("#workflow-new").click()
        self.page.locator("#workflow-name").fill(name)
        return name

    def add_node(self, label: str) -> str:
        before = self.page.locator(".workflow-node").count()
        self.page.locator("#workflow-palette button").filter(has_text=label).first.click()
        self.page.wait_for_timeout(80)
        self.assertEqual(self.page.locator(".workflow-node").count(), before + 1)
        return self.page.locator(".workflow-node").last.get_attribute("data-node-id")

    def node(self, node_id: str):
        return self.page.locator(f'.workflow-node[data-node-id="{node_id}"]')

    def select_node(self, node_id: str) -> None:
        self.node(node_id).click()
        self.page.wait_for_timeout(80)

    def connect(self, source_id: str, target_id: str, source_handle: str = "main", target_handle: str = "main") -> None:
        self.node(source_id).locator(f'[data-output-handle="{source_handle}"]').click()
        self.node(target_id).locator(f'[data-input-handle="{target_handle}"]').click()
        self.page.wait_for_timeout(80)

    def set_param(self, node_id: str, name: str, value, *, check: bool = False) -> None:
        self.select_node(node_id)
        field = self.page.locator(f'#workflow-inspector [data-workflow-param="{name}"]')
        self.assertEqual(field.count(), 1, f"Missing inspector field {name}")
        if check:
            field.set_checked(bool(value))
        elif field.evaluate("element => element.tagName") == "SELECT":
            field.select_option(str(value))
        else:
            field.fill(str(value))
            field.blur()
        self.page.wait_for_timeout(50)

    def save_workflow(self, name: str) -> int:
        self.page.locator("#workflow-name").fill(name)
        self.page.locator("#workflow-save").click()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            items = request_json(f"{DEFAULT_BASE_URL}api/workflows").get("items", [])
            match = next((item for item in items if item.get("name") == name), None)
            if match:
                if match["id"] not in self.workflow_ids:
                    self.workflow_ids.append(match["id"])
                return int(match["id"])
            time.sleep(0.1)
        self.fail(f"Workflow was not saved through the UI: {name}")

    def wait_run(self, workflow_id: int, timeout: float = 30):
        deadline = time.monotonic() + timeout
        latest = None
        while time.monotonic() < deadline:
            items = request_json(f"{DEFAULT_BASE_URL}api/workflows/runs?workflow_id={workflow_id}").get("items", [])
            if items:
                latest = items[0]
                if latest["status"] in {"completed", "failed", "cancelled", "interrupted"}:
                    return latest
            time.sleep(0.15)
        self.fail(f"Workflow run did not finish: {latest}")

    def wait_new_run(self, workflow_id: int, previous_ids: set[int], timeout: float = 30):
        deadline = time.monotonic() + timeout
        latest = None
        while time.monotonic() < deadline:
            items = request_json(f"{DEFAULT_BASE_URL}api/workflows/runs?workflow_id={workflow_id}").get("items", [])
            fresh = next((item for item in items if int(item["id"]) not in previous_ids), None)
            if fresh:
                latest = fresh
                if fresh["status"] in {"completed", "failed", "cancelled", "interrupted"}:
                    return fresh
            time.sleep(0.1)
        self.fail(f"New workflow run did not finish: {latest}")

    def run_workflow(self, workflow_id: int, *, confirm: bool = False, timeout: float = 30):
        previous_ids = {
            int(item["id"])
            for item in request_json(f"{DEFAULT_BASE_URL}api/workflows/runs?workflow_id={workflow_id}").get("items", [])
        }
        self.page.locator("#workflow-run").click()
        if confirm:
            dialog = self.page.locator("dialog[open]")
            self.assertEqual(dialog.count(), 1)
            dialog.locator('button[value="confirm"]').click()
        return self.wait_new_run(workflow_id, previous_ids, timeout)

    def import_template_and_run(self, query: str, variables: dict[str, str], timeout: float = 45):
        self.goto_tab("automation")
        self.page.locator("#workflow-template-store").click()
        self.page.locator("#template-store-dialog").wait_for(state="visible", timeout=5000)
        self.page.locator("#template-store-search").fill(query)
        self.assertEqual(self.page.locator("#template-store-dialog [data-template-id]").count(), 1)
        self.page.locator("#template-store-dialog [data-template-id]").first.click()
        for key, value in variables.items():
            field = self.page.locator(f'[data-template-variable="{key}"]')
            self.assertEqual(field.count(), 1, f"Missing template variable {key}")
            field.fill(value)
        scope = self.page.locator("#template-store-scope-confirm")
        if not scope.is_checked():
            scope.check()
        self.page.locator("#template-preview-import").click()
        self.assertFalse(self.page.locator("#template-store-dialog").is_visible())
        name = self.page.locator("#workflow-name").input_value()
        workflow_id = self.save_workflow(name)
        return self.run_workflow(workflow_id, confirm=True, timeout=timeout)

    def assert_clean_browser(self):
        self.assertEqual(self.page_errors, [], f"page errors: {self.page_errors}")
        relevant_failures = [
            item for item in self.failed_requests
            if not any(marker in str(item.get("error", "")).upper() for marker in ("ABORTED", "NS_ERROR_ABORT"))
        ]
        self.assertEqual(relevant_failures, [], f"failed requests: {relevant_failures}")

    def create_project(self, name: str, target: str) -> int:
        # The New Project dialog is a local name prompt; the target is read
        # from the Target workspace by the existing UI contract.
        self.page.locator('nav button[data-tab="target"]').click()
        self.page.locator("#target-url").fill(target)
        self.page.locator('nav button[data-tab="projects"]').click()
        self.page.locator("#project-new").click()
        dialog = self.page.locator("dialog[open]")
        self.assertEqual(dialog.count(), 1)
        dialog.locator('[name="value"]').fill(name)
        dialog.locator('button[value="save"]').click()
        self.page.wait_for_timeout(700)
        match = next(item for item in request_json(f"{DEFAULT_BASE_URL}api/projects").get("items", []) if item.get("name") == name)
        project_id = int(match["id"])
        self.project_ids.append(project_id)
        self.page.wait_for_function(
            "id => document.body.dataset.activeProjectId === String(id)",
            arg=project_id,
        )
        self.page.wait_for_function(
            "name => document.querySelector('#workflow-project')?.textContent.includes(name)",
            arg=name,
        )
        return project_id

    def current_workflow(self, name: str) -> dict:
        items = request_json(f"{DEFAULT_BASE_URL}api/workflows").get("items", [])
        return next(item for item in items if item.get("name") == name)

    def activate_workflow(self) -> None:
        self.page.locator("#workflow-activate").click()
        self.page.wait_for_timeout(500)

    def deactivate_workflow(self) -> None:
        self.page.locator("#workflow-activate").click()
        self.page.wait_for_timeout(500)

    def wait_current_ui_status(self, status: str, timeout: float = 10) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if status.lower() in self.page.locator("#workflow-log").inner_text().lower():
                return
            time.sleep(0.15)
        self.fail(f"UI did not show workflow status {status}: {self.page.locator('#workflow-log').inner_text()}")

    def configure_local_llm(self):
        self.goto_tab("ai")
        self.page.locator("#agent-provider").select_option("ollama")
        self.page.locator("#agent-endpoint").fill(f"http://127.0.0.1:{self.llm_port}/v1/chat/completions")
        self.page.locator("#agent-model").fill("local-test-model")
        self.page.locator("#agent-chat-input").fill("Analyze the attached evidence and propose the next safe QA step.")
        self.page.locator("#agent-chat-send").click()
        self.page.wait_for_timeout(600)
        self.assertIn("Recommended next crawl", self.page.locator("#agent-chat-log").inner_text())

    def assert_attached_evidence(self, label: str):
        attached = self.page.locator("#agent-attached-evidence")
        self.assertIn(label, attached.inner_text())

    def recommended_fixture_url(self, message: str) -> str:
        match = re.search(r"http://127\.0\.0\.1:\d+/[^\s]+", message)
        self.assertIsNotNone(match, message)
        return match.group(0).rstrip(".,)")

    def download_json(self, selector: str):
        with self.page.expect_download() as download_info:
            self.page.locator(selector).click()
        path = download_info.value.path()
        self.assertTrue(path)
        with open(path, encoding="utf-8") as downloaded:
            return json.load(downloaded)

    def latest_run(self, workflow_id: int):
        items = request_json(f"{DEFAULT_BASE_URL}api/workflows/runs?workflow_id={workflow_id}").get("items", [])
        return items[0] if items else None

    def wait_run_status(self, workflow_id: int, status: str, timeout: float = 15):
        deadline = time.monotonic() + timeout
        latest = None
        while time.monotonic() < deadline:
            latest = self.latest_run(workflow_id)
            if latest and latest.get("status") == status:
                return latest
            time.sleep(0.1)
        self.fail(f"Workflow did not reach {status}: {latest}")

    def wait_run_node(self, workflow_id: int, node_id: str, timeout: float = 15):
        deadline = time.monotonic() + timeout
        latest = None
        while time.monotonic() < deadline:
            latest = self.latest_run(workflow_id)
            if latest and latest.get("current_node") == node_id:
                return latest
            time.sleep(0.1)
        self.fail(f"Workflow did not enter node {node_id}: {latest}")

    def build_delay_workflow(self, prefix: str, seconds: int):
        name = self.new_workflow(prefix)
        trigger = self.add_node("Manual trigger")
        delay = self.add_node("Delay")
        output = self.add_node("Output")
        self.connect(trigger, delay)
        self.connect(delay, output)
        self.set_param(delay, "seconds", seconds)
        workflow_id = self.save_workflow(name)
        return name, workflow_id, delay

    # ---- scenarios -------------------------------------------------------

    def test_manual_logic_graph_runs_through_canvas(self):
        name = self.new_workflow("logic")
        trigger = self.add_node("Manual trigger")
        values = self.add_node("Set values")
        output = self.add_node("Output")
        self.connect(trigger, values)
        self.connect(values, output)
        self.set_param(values, "values", '{"status":"ready","answer":42}')
        self.set_param(output, "label", "Logic result")
        workflow_id = self.save_workflow(name)
        run = self.run_workflow(workflow_id)
        self.assertEqual(run["status"], "completed", run)
        self.assertEqual(run["output"]["value"]["status"], "ready")
        self.assertEqual(run["output"]["value"]["answer"], 42)
        self.wait_current_ui_status("completed")
        self.assertIn("completed", self.page.locator("#workflow-runs-list").inner_text().lower())
        self.assertIn('"answer": 42', self.page.locator("#workflow-log").inner_text())
        self.assert_clean_browser()

    def test_repeater_transfer_runs_and_appears_in_history(self):
        name = self.new_workflow("repeater")
        self.goto_tab("repeater")
        url = f"http://127.0.0.1:{self.fixture_port}/health"
        self.page.locator("#repeater-raw-request").fill(
            f"GET /health HTTP/1.1\nHost: 127.0.0.1:{self.fixture_port}\nAccept: text/plain\n\n"
        )
        self.page.locator("#repeater-send-automation").click()
        self.page.wait_for_timeout(700)
        items = request_json(f"{DEFAULT_BASE_URL}api/workflows").get("items", [])
        match = next(item for item in items if item.get("name") == name)
        workflow_id = int(match["id"])
        self.workflow_ids.append(workflow_id)
        repeater = next(node["id"] for node in match["nodes"] if node["type"] == "repeater")
        output = self.add_node("Output")
        self.connect(repeater, output)
        self.save_workflow(name)
        run = self.run_workflow(workflow_id)
        self.assertEqual(run["status"], "completed", run)
        self.assertEqual(run["output"]["value"]["response"]["status"], 200)
        self.assertEqual(run["output"]["value"]["response"]["body"], "ok")
        self.goto_tab("history")
        self.page.wait_for_timeout(600)
        self.assertIn(f"127.0.0.1:{self.fixture_port}/health", self.page.locator(".history-table").inner_text())
        self.assert_clean_browser()

    def test_tool_workspace_open_and_use_current_roundtrip(self):
        name = self.new_workflow("workspace-roundtrip")
        self.goto_tab("repeater")
        self.page.locator("#repeater-raw-request").fill(
            f"GET /health HTTP/1.1\nHost: 127.0.0.1:{self.fixture_port}\nX-Roundtrip: yes\n\n"
        )
        self.page.locator("#repeater-send-automation").click()
        self.page.wait_for_timeout(600)
        workflow = self.current_workflow(name)
        workflow_id = int(workflow["id"])
        self.workflow_ids.append(workflow_id)
        repeater = next(node["id"] for node in workflow["nodes"] if node["type"] == "repeater")
        self.select_node(repeater)
        self.page.locator("#workflow-open-tool").click()
        self.page.wait_for_timeout(250)
        self.assertEqual(self.page.locator("#repeater-raw-request").input_value().split("\n", 1)[0], "GET /health HTTP/1.1")
        self.goto_tab("automation")
        self.select_node(repeater)
        self.page.locator("#workflow-use-current").click()
        self.page.wait_for_timeout(700)
        self.assertEqual(self.page.locator(".workflow-node").count(), 2)
        self.assert_clean_browser()

    def test_repeater_loop_over_multiple_selected_urls(self):
        name = self.new_workflow("repeater-loop")
        trigger = self.add_node("Manual trigger")
        repeater = self.add_node("Repeater")
        output = self.add_node("Output")
        self.connect(trigger, repeater)
        self.connect(repeater, output)
        urls = [
            f"http://127.0.0.1:{self.fixture_port}/health",
            f"http://127.0.0.1:{self.fixture_port}/next",
            f"http://127.0.0.1:{self.fixture_port}/api/data",
        ]
        self.set_param(repeater, "urls", json.dumps(urls))
        self.set_param(repeater, "delay_ms", 0)
        workflow_id = self.save_workflow(name)
        run = self.run_workflow(workflow_id, timeout=45)
        self.assertEqual(run["status"], "completed", run)
        result = run["output"]["value"]
        self.assertEqual(result["count"], 3)
        self.assertTrue(all(item["status"] == 200 for item in result["items"]), result)
        self.assert_clean_browser()

    def test_repeater_burst_runs_bounded_parallel_fixture_requests(self):
        self.create_project(self.unique_name("burst-project"), f"http://127.0.0.1:{self.fixture_port}/health")
        name = self.new_workflow("repeater-burst")
        trigger = self.add_node("Manual trigger")
        burst = self.add_node("Repeater Burst")
        output = self.add_node("Output")
        self.connect(trigger, burst)
        self.connect(burst, output)
        self.set_param(burst, "method", "GET")
        self.set_param(burst, "url", f"http://127.0.0.1:{self.fixture_port}/health")
        self.set_param(burst, "headers", "{}")
        self.set_param(burst, "iterations", 3)
        self.set_param(burst, "concurrency", 2)
        self.set_param(burst, "delay_ms", 0)
        self.set_param(burst, "timeout_ms", 5000)
        workflow_id = self.save_workflow(name)
        run = self.run_workflow(workflow_id, confirm=True, timeout=30)
        self.assertEqual(run["status"], "completed", run)
        result = run["output"]["value"]
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["total"], 3)
        self.assertEqual(result["completed"], 3)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(len(result["results"]), 3)
        self.assertGreaterEqual(sum(1 for item in request_json(f"{DEFAULT_BASE_URL}api/history").get("items", []) if item.get("url", "").endswith("/health")), 3)
        self.assert_clean_browser()


    def test_last_byte_sync_runs_against_local_raw_fixture(self):
        target = f"http://127.0.0.1:{self.last_byte_fixture_port}/sync"
        self.create_project(self.unique_name("last-byte-project"), target)
        name = self.new_workflow("last-byte")
        trigger = self.add_node("Manual trigger")
        last_byte = self.add_node("Last-Byte Sync")
        output = self.add_node("Output")
        self.connect(trigger, last_byte)
        self.connect(last_byte, output)
        self.set_param(last_byte, "method", "POST")
        self.set_param(last_byte, "url", target)
        self.set_param(last_byte, "headers", '{"Content-Type":"application/json"}')
        self.set_param(last_byte, "body", '{"canary":"e2e"}')
        self.set_param(last_byte, "iterations", 2)
        self.set_param(last_byte, "concurrency", 1)
        self.set_param(last_byte, "delay_ms", 0)
        self.set_param(last_byte, "hold_ms", 40)
        self.set_param(last_byte, "timeout_ms", 2000)
        self.set_param(output, "label", "Last-Byte evidence")
        workflow_id = self.save_workflow(name)
        self.assertIn("Last-Byte Sync", self.page.locator('.workflow-node[data-node-id="' + last_byte + '"]').inner_text())
        run = self.run_workflow(workflow_id, confirm=True, timeout=30)
        self.assertEqual(run["status"], "completed", run)
        result = run["output"]["value"]
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["completed"], 2)
        self.assertEqual(result["failed"], 0)
        self.assertTrue(all(item.get("status") == 200 for item in result["results"]), result)
        history = request_json(f"{DEFAULT_BASE_URL}api/history").get("items", [])
        self.assertGreaterEqual(sum(1 for item in history if item.get("url") == target), 2)
        self.assert_clean_browser()

    def test_high_risk_canary_templates_run_against_local_fixtures(self):
        target = f"http://127.0.0.1:{self.fixture_port}/"
        self.create_project(self.unique_name("canary-templates-project"), target)
        scenarios = [
            ("BOLA/IDOR differential evidence", {"target_url": target}),
            ("Race-condition timing observation", {"target_url": target}),
            ("WAF rule differential", {"target_url": target}),
            ("JWT claim mutation differential", {"target_url": target}),
            ("CI/CD exposure review", {"target_url": target}),
            ("XXE/OAST local canary chain", {"target_url": f"http://127.0.0.1:{self.fixture_port}/xml", "oast_server_url": f"http://127.0.0.1:{self.oast_fixture_port}"}),
        ]
        for query, variables in scenarios:
            run = self.import_template_and_run(query, variables, timeout=45)
            self.assertEqual(run["status"], "completed", (query, run))
            value = run.get("output", {}).get("value")
            self.assertIsNotNone(value, (query, run))
            if query.startswith("Race"):
                self.assertEqual(value.get("completed"), 4, (query, run))
            elif query.startswith("XXE"):
                self.assertTrue(value.get("triggered"), (query, run))
            elif query.startswith("CI/CD"):
                self.assertEqual(value.get("count"), 4, (query, run))
            else:
                self.assertIn("equal", value, (query, run))
        self.assert_clean_browser()

    def test_repeater_burst_can_target_a_different_local_origin(self):
        self.create_project(self.unique_name("burst-open-project"), f"http://127.0.0.1:{self.fixture_port}/health")
        name = self.new_workflow("repeater-burst-open-target")
        trigger = self.add_node("Manual trigger")
        burst = self.add_node("Repeater Burst")
        self.connect(trigger, burst)
        self.set_param(burst, "method", "GET")
        self.set_param(burst, "url", f"http://127.0.0.1:{self.fixture_port}/api/echo?source=burst")
        self.set_param(burst, "iterations", 2)
        self.set_param(burst, "concurrency", 1)
        self.set_param(burst, "delay_ms", 0)
        self.set_param(burst, "timeout_ms", 1000)
        workflow_id = self.save_workflow(name)
        run = self.run_workflow(workflow_id, confirm=True, timeout=15)
        self.assertEqual(run["status"], "completed", run)
        self.assert_clean_browser()

    def test_decoder_comparer_and_condition_branch(self):
        name = self.new_workflow("logic-tools")
        trigger = self.add_node("Manual trigger")
        values = self.add_node("Set values")
        condition = self.add_node("Condition")
        decoder = self.add_node("Decoder")
        comparer = self.add_node("Comparer")
        output = self.add_node("Output")
        self.connect(trigger, values)
        self.connect(values, condition)
        self.connect(condition, decoder, source_handle="true")
        self.connect(decoder, comparer)
        self.connect(comparer, output)
        self.set_param(values, "values", '{"status":"ready","text":"hello"}')
        self.set_param(condition, "field", "status")
        self.set_param(condition, "operator", "equals")
        self.set_param(condition, "value", "ready")
        self.set_param(decoder, "operation", "base64Encode")
        self.set_param(comparer, "mode", "words")
        self.set_param(comparer, "left", "aGVsbG8=")
        self.set_param(comparer, "right", "aGVsbG8=")
        self.set_param(output, "label", "Tool result")
        workflow_id = self.save_workflow(name)
        run = self.run_workflow(workflow_id)
        self.assertEqual(run["status"], "completed", run)
        self.assertTrue(run["output"]["value"]["equal"])
        self.assert_clean_browser()

    def test_active_project_selector_is_server_backed_and_survives_reload(self):
        first_project_id = self.default_project_id
        second_project_id = self.create_project(
            self.unique_name("secondary-project"),
            f"http://127.0.0.1:{self.fixture_port}/next",
        )
        self.goto_tab("projects")
        with self.page.expect_response(lambda response: response.url.endswith("/api/project-context") and response.request.method == "POST") as response_info:
            self.page.locator("#project-select").select_option(str(first_project_id))
        self.assertEqual(response_info.value.status, 200)
        self.page.wait_for_function(
            "id => document.body.dataset.activeProjectId === String(id)",
            arg=first_project_id,
        )
        self.page.evaluate("id => localStorage.setItem('requestrider-project', id)", str(second_project_id))
        self.reload_page()
        self.page.locator("button[data-tab='projects']").click()
        self.page.wait_for_function(
            "id => document.body.dataset.activeProjectId === String(id) && document.querySelector('#project-select')?.value === String(id)",
            arg=first_project_id,
        )
        self.assert_clean_browser()

    def test_projectless_workflow_can_run_without_project_gate(self):
        self.goto_tab("projects")
        with self.page.expect_response(lambda response: response.url.endswith("/api/project-context") and response.request.method == "POST") as response_info:
            self.page.locator("#project-select").select_option("")
        self.assertEqual(response_info.value.status, 200)
        self.page.wait_for_function("document.body.dataset.activeProjectId === ''")
        name = self.new_workflow("project-required")
        trigger = self.add_node("Manual trigger")
        repeater = self.add_node("Repeater")
        self.connect(trigger, repeater)
        self.set_param(repeater, "url", f"http://127.0.0.1:{self.fixture_port}/health")
        workflow_id = self.save_workflow(name)
        before = request_json(f"{DEFAULT_BASE_URL}api/workflows/runs?workflow_id={workflow_id}").get("items", [])
        self.page.locator("#workflow-run").click()
        self.page.wait_for_timeout(300)
        after = request_json(f"{DEFAULT_BASE_URL}api/workflows/runs?workflow_id={workflow_id}").get("items", [])
        self.assertEqual(len(after), len(before) + 1)
        run_id = int(after[0]["id"])
        deadline = time.monotonic() + 10
        run = {}
        while time.monotonic() < deadline:
            run = request_json(f"{DEFAULT_BASE_URL}api/workflows/runs/{run_id}")
            if run.get("status") in {"completed", "failed", "cancelled"}:
                break
            time.sleep(0.1)
        self.assertEqual(run.get("status"), "completed", run)
        self.assert_clean_browser()

    def test_target_selected_url_can_be_sent_to_repeater_automation(self):
        name = self.new_workflow("target-selected-url")
        self.goto_tab("target")
        self.page.locator("#target-url").fill(f"http://127.0.0.1:{self.fixture_port}/")
        self.page.locator("#target-start").click()
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if "completed" in self.page.locator("#target-status").inner_text().lower():
                break
            time.sleep(0.25)
        self.assertIn("completed", self.page.locator("#target-status").inner_text().lower())
        self.page.locator("#target-results [data-target-repeater]").first.click()
        self.page.wait_for_timeout(400)
        self.assertEqual(self.page.locator('[data-tab="repeater"]').get_attribute("class").find("active") >= 0, True)
        self.assertIn(f"127.0.0.1:{self.fixture_port}", self.page.locator("#repeater-raw-request").input_value())
        self.page.locator("#repeater-send-automation").click()
        self.page.wait_for_timeout(600)
        workflow_id = int(self.current_workflow(name)["id"])
        self.workflow_ids.append(workflow_id)
        repeater = next(node["id"] for node in self.current_workflow(name)["nodes"] if node["type"] == "repeater")
        output = self.add_node("Output")
        self.connect(repeater, output)
        self.save_workflow(name)
        run = self.run_workflow(workflow_id)
        self.assertEqual(run["status"], "completed", run)
        self.assert_clean_browser()

    def test_target_browser_capture_context_is_explicit_and_persisted(self):
        self.goto_tab("target")
        self.page.locator("#target-engine").select_option("browser")
        self.page.locator("#target-url").fill(f"http://127.0.0.1:{self.fixture_port}/")
        self.page.locator("#target-capture-name").fill(self.unique_name("capture-context"))
        self.page.locator("#target-capture-project").select_option(str(self.default_project_id))
        with self.page.expect_response(lambda response: response.url.endswith("/api/traffic/capture-contexts")) as response_info:
            self.page.locator("#target-capture-create").click()
        self.assertEqual(response_info.value.status, 201)
        context = response_info.value.json()
        self.assertNotIn("token", context)
        self.capture_context_ids.append(int(context["id"]))
        self.page.wait_for_function(
            "id => document.querySelector('#target-capture-context')?.value === String(id)",
            arg=context["id"],
        )
        self.assertIn(context["name"], self.page.locator("#target-capture-hint").inner_text())

        with self.page.expect_request(lambda request: request.url.endswith("/api/target-browser") and request.method == "POST") as request_info:
            self.page.locator("#target-start").click()
        payload = json.loads(request_info.value.post_data or "{}")
        self.assertEqual(payload.get("capture_context_id"), context["id"])
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if "completed" in self.page.locator("#target-status").inner_text().lower():
                break
            time.sleep(0.25)
        self.assertIn("completed", self.page.locator("#target-status").inner_text().lower())

        self.page.locator("#target-engine").select_option("static")
        self.assertTrue(self.page.locator("#target-capture-context").is_disabled())
        self.page.locator("#target-engine").select_option("browser")
        self.assertEqual(self.page.locator("#target-capture-context").input_value(), str(context["id"]))
        self.assert_clean_browser()

    def test_target_static_fixture_lifecycle(self):
        name = self.new_workflow("target-static")
        trigger = self.add_node("Manual trigger")
        target = self.add_node("Target map")
        output = self.add_node("Output")
        self.connect(trigger, target)
        self.connect(target, output)
        self.set_param(target, "url", f"http://127.0.0.1:{self.fixture_port}/")
        self.set_param(target, "max_pages", 3)
        self.set_param(target, "max_depth", 1)
        workflow_id = self.save_workflow(name)
        run = self.run_workflow(workflow_id, timeout=45)
        self.assertEqual(run["status"], "completed", run)
        urls = {page.get("url") for page in run["output"]["value"].get("pages", [])}
        self.assertIn(f"http://127.0.0.1:{self.fixture_port}/", urls)
        self.assert_clean_browser()

    def test_target_browser_fixture_requires_confirmation_and_collects_network(self):
        name = self.new_workflow("target-browser")
        trigger = self.add_node("Manual trigger")
        target = self.add_node("Browser Target")
        output = self.add_node("Output")
        self.connect(trigger, target)
        self.connect(target, output)
        self.set_param(target, "url", f"http://127.0.0.1:{self.fixture_port}/")
        self.set_param(target, "browser", "firefox")
        self.set_param(target, "mode", "navigation")
        self.set_param(target, "max_pages", 2)
        self.set_param(target, "max_depth", 1)
        self.set_param(target, "actions", '[{"type":"click","selector":"#load-data","value":""}]')
        self.set_param(target, "allow_state_changing_actions", False, check=True)
        workflow_id = self.save_workflow(name)
        run = self.run_workflow(workflow_id, confirm=True, timeout=90)
        self.assertEqual(run["status"], "completed", run)
        result = run["output"]["value"]
        self.assertIn("pages", result)
        self.assertTrue(result.get("pages") or result.get("network") or result.get("network_events"), result)
        self.assert_clean_browser()

    def test_intruder_fixture_requires_confirmation_and_generates_results(self):
        name = self.new_workflow("intruder")
        self.goto_tab("intruder")
        self.page.locator("#intruder-raw-request").fill(
            f"GET /search?q=§payload§ HTTP/1.1\nHost: 127.0.0.1:{self.fixture_port}\n\n"
        )
        self.page.locator(".dictionary-values").first.fill("one\ntwo")
        self.page.locator("#intruder-send-automation").click()
        self.page.wait_for_timeout(700)
        workflow = self.current_workflow(name)
        workflow_id = int(workflow["id"])
        self.workflow_ids.append(workflow_id)
        intruder = next(node["id"] for node in workflow["nodes"] if node["type"] == "intruder")
        output = self.add_node("Output")
        self.connect(intruder, output)
        self.save_workflow(name)
        before_runs = request_json(f"{DEFAULT_BASE_URL}api/workflows/runs?workflow_id={workflow_id}").get("items", [])
        self.page.locator("#workflow-run").click()
        dialog = self.page.locator("dialog[open]")
        self.assertEqual(dialog.count(), 1)
        dialog.locator('button[value="cancel"]').click()
        self.page.wait_for_timeout(300)
        self.assertEqual(len(request_json(f"{DEFAULT_BASE_URL}api/workflows/runs?workflow_id={workflow_id}").get("items", [])), len(before_runs))
        run = self.run_workflow(workflow_id, confirm=True, timeout=90)
        self.assertEqual(run["status"], "completed", run)
        result = run["output"]["value"]
        self.assertGreaterEqual(result.get("completed", 0), 2, result)
        self.page.locator("#workflow-activate").click()
        dialog = self.page.locator("dialog[open]")
        self.assertEqual(dialog.count(), 1)
        dialog.locator('button[value="cancel"]').click()
        self.assertFalse(request_json(f"{DEFAULT_BASE_URL}api/workflows/{workflow_id}")["active"])
        self.assert_clean_browser()

    def test_workflow_can_target_outside_project_target(self):
        project_name = self.unique_name("project")
        project_target = f"http://127.0.0.1:{self.fixture_port}/allowed"
        self.create_project(project_name, project_target)
        name = self.new_workflow("cross-target")
        self.goto_tab("repeater")
        self.page.locator("#repeater-raw-request").fill(
            f"GET /outside HTTP/1.1\nHost: 127.0.0.1:{self.fixture_port}\n\n"
        )
        self.page.locator("#repeater-send-automation").click()
        self.page.wait_for_timeout(700)
        workflow_id = int(self.current_workflow(name)["id"])
        self.workflow_ids.append(workflow_id)
        run = self.run_workflow(workflow_id)
        self.assertEqual(run["status"], "completed", run)
        history_items = request_json(f"{DEFAULT_BASE_URL}api/history").get("items", [])
        self.assertTrue(any(f"127.0.0.1:{self.fixture_port}/outside" in item.get("url", "") for item in history_items))
        self.assert_clean_browser()

    def test_repeater_exchange_handoff_to_ai_and_target_followup(self):
        self.goto_tab("repeater")
        self.page.locator("#repeater-raw-request").fill(
            f"GET /health HTTP/1.1\nHost: 127.0.0.1:{self.fixture_port}\n\n"
        )
        self.page.locator("#send").click()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            response_text = self.page.locator("#response").inner_text()
            if "Sending" not in response_text and "ok" in response_text:
                break
            time.sleep(0.2)
        self.assertIn("ok", self.page.locator("#response").inner_text())
        self.page.locator("#repeater-send-ai").click()
        self.assert_attached_evidence("Repeater exchange")
        self.configure_local_llm()
        followup_url = self.recommended_fixture_url(self.page.locator("#agent-chat-log").inner_text())
        name = self.new_workflow("ai-repeater-followup")
        self.goto_tab("target")
        self.page.locator("#target-url").fill(followup_url)
        self.page.locator("#target-send-automation").click()
        self.page.wait_for_timeout(600)
        workflow_id = int(self.current_workflow(name)["id"])
        self.workflow_ids.append(workflow_id)
        target = next(node["id"] for node in self.current_workflow(name)["nodes"] if node["type"] == "target")
        output = self.add_node("Output")
        self.connect(target, output)
        self.save_workflow(name)
        run = self.run_workflow(workflow_id, timeout=60)
        self.assertEqual(run["status"], "completed", run)
        self.assert_clean_browser()

    def test_target_map_handoff_to_ai_and_repeater_followup(self):
        self.goto_tab("target")
        self.page.locator("#target-url").fill(f"http://127.0.0.1:{self.fixture_port}/")
        self.page.locator("#target-start").click()
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if "completed" in self.page.locator("#target-status").inner_text().lower():
                break
            time.sleep(0.25)
        self.assertIn("completed", self.page.locator("#target-status").inner_text().lower())
        target_export = self.download_json("#target-export-json")
        self.assertTrue(target_export.get("pages"))
        self.page.locator("#target-send-ai").click()
        self.assert_attached_evidence("Target Map")
        self.configure_local_llm()
        self.assertIn("target_map", json.dumps(self.llm_server.requests[-1]).lower())
        recommendation = self.page.locator("#agent-chat-log").inner_text()
        followup_url = self.recommended_fixture_url(recommendation)
        name = self.new_workflow("ai-target-followup")
        self.goto_tab("repeater")
        self.page.locator("#repeater-raw-request").fill(
            f"GET /next HTTP/1.1\nHost: 127.0.0.1:{self.fixture_port}\n\n"
        )
        self.page.locator("#repeater-send-automation").click()
        self.page.wait_for_timeout(600)
        workflow_id = int(self.current_workflow(name)["id"])
        self.workflow_ids.append(workflow_id)
        repeater = next(node["id"] for node in self.current_workflow(name)["nodes"] if node["type"] == "repeater")
        output = self.add_node("Output")
        self.connect(repeater, output)
        self.save_workflow(name)
        run = self.run_workflow(workflow_id)
        self.assertEqual(run["status"], "completed", run)
        self.assert_clean_browser()

    def test_osint_graph_canvas_renders_details_menu_and_500_node_budget(self):
        self.goto_tab("osint")
        self.page.locator("#osint-graph-select").wait_for(state="attached")
        with self.page.expect_response(lambda response: response.url.endswith("/api/osint/graphs") and response.request.method == "POST") as create_info:
            self.page.locator("#osint-graph-create").click()
            dialog = self.page.locator("dialog[open]")
            dialog.locator('[name="value"]').fill(self.unique_name("graph"))
            dialog.locator('button[value="save"]').click()
        self.assertEqual(create_info.value.status, 201)
        graph_id = create_info.value.json()["id"]
        self.page.wait_for_function("id => document.querySelector('#osint-graph-select')?.value === String(id)", arg=graph_id)

        def add_entity(entity_type: str, identity: str, risk: int = 0):
            with self.page.expect_response(lambda response: response.url.endswith(f"/api/osint/graphs/{graph_id}/upsert") and response.request.method == "POST") as upsert_info:
                self.page.locator("#osint-graph-add").click()
                dialog = self.page.locator("dialog[open]")
                dialog.locator('[name="type"]').select_option(entity_type)
                dialog.locator('[name="identity"]').fill(identity)
                dialog.locator('[name="risk"]').fill(str(risk))
                dialog.locator('button[value="save"]').click()
            self.assertEqual(upsert_info.value.status, 200)

        add_entity("domain", "graph.example.test", 35)
        add_entity("email", "analyst@graph.example.test", 60)
        self.page.locator('[data-osint-graph-node]').first.click()
        self.assertFalse(self.page.locator("#osint-graph-details").is_hidden())
        self.assertIn("graph.example.test", self.page.locator("#osint-graph-details-content").inner_text())
        domain_node = self.page.locator('[data-osint-graph-node]').filter(has_text="graph.example.test").first
        domain_node.click(button="right")
        self.assertFalse(self.page.locator("#osint-graph-menu").is_hidden())
        self.assertIn("Subdomain discovery", self.page.locator("#osint-graph-menu").inner_text())
        self.page.keyboard.press("Escape")

        entities = [{"type": "domain", "identity": f"node-{index}.example.test", "risk_score": index % 100} for index in range(500)]
        self.page.evaluate(
            """async ({id, entities}) => {
                const token = document.cookie.split('; ').find(item => item.startsWith('csrftoken='))?.split('=')[1] || '';
                const response = await fetch(`/api/osint/graphs/${id}/upsert`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', 'X-CSRFToken': token},
                    body: JSON.stringify({entities})
                });
                if (!response.ok) throw new Error(await response.text());
                return response.json();
            }""",
            {"id": graph_id, "entities": entities},
        )
        self.page.locator("#osint-graph-refresh").click()
        self.page.wait_for_function("count => document.querySelectorAll('[data-osint-graph-node]').length === count", arg=502)
        self.page.locator("#osint-graph-filter").fill("analyst@")
        self.assertEqual(self.page.locator("[data-osint-graph-node]").count(), 1)
        self.page.locator("#osint-graph-filter").fill("")
        self.page.locator("#osint-graph-layout").click()
        self.page.wait_for_function(
            """id => JSON.parse(localStorage.getItem('requestrider-workspaces-v1') || '[]')
                .some(context => context.kind === 'osint' && context.state?.graphId === String(id))""",
            arg=graph_id,
        )
        self.reload_page()
        self.goto_tab("osint")
        self.page.wait_for_function("id => document.querySelector('#osint-graph-select')?.value === String(id)", arg=graph_id)
        self.assert_clean_browser()

    def test_osint_handoff_to_ai_and_scanner_followup(self):
        self.goto_tab("osint")
        self.page.locator("#osint-url").fill(f"http://127.0.0.1:{self.fixture_port}/")
        self.page.locator("#osint-run").click()
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            status = self.page.locator("#osint-status").inner_text()
            if status and "Running" not in status and "running" not in status:
                break
            time.sleep(0.25)
        self.assertNotIn("Running", self.page.locator("#osint-status").inner_text())
        osint_export = self.download_json("#osint-export")
        self.assertEqual(osint_export.get("url"), f"http://127.0.0.1:{self.fixture_port}/")
        self.page.locator("#osint-send-ai").click()
        self.assert_attached_evidence("OSINT results")
        self.configure_local_llm()
        self.assertTrue(self.llm_server.requests)
        self.assertIn("osint", json.dumps(self.llm_server.requests[-1]).lower())
        followup_url = self.recommended_fixture_url(self.page.locator("#agent-chat-log").inner_text())
        name = self.new_workflow("ai-osint-followup")
        self.goto_tab("scanner")
        self.page.locator("#scanner-url").fill(followup_url)
        self.page.locator("#scanner-send-automation").click()
        self.page.wait_for_timeout(600)
        workflow_id = int(self.current_workflow(name)["id"])
        self.workflow_ids.append(workflow_id)
        scanner = next(node["id"] for node in self.current_workflow(name)["nodes"] if node["type"] == "scanner")
        output = self.add_node("Output")
        self.connect(scanner, output)
        self.save_workflow(name)
        run = self.run_workflow(workflow_id, timeout=60)
        self.assertEqual(run["status"], "completed", run)
        self.assert_clean_browser()

    def test_scanner_handoff_to_ai_and_target_followup(self):
        self.goto_tab("scanner")
        self.page.locator("#scanner-url").fill(f"http://127.0.0.1:{self.fixture_port}/")
        self.page.locator("#scanner-run").click()
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            findings = self.page.locator("#scanner-findings").inner_text()
            if findings and "Enter an authorized URL" not in findings:
                break
            time.sleep(0.25)
        scanner_export = self.download_json("#scanner-export")
        self.assertEqual(scanner_export.get("url"), f"http://127.0.0.1:{self.fixture_port}/")
        self.page.locator("#scanner-send-ai").click()
        self.assert_attached_evidence("Scanner results")
        self.configure_local_llm()
        self.assertIn("scanner", json.dumps(self.llm_server.requests[-1]).lower())
        followup_url = self.recommended_fixture_url(self.page.locator("#agent-chat-log").inner_text())
        name = self.new_workflow("ai-scanner-followup")
        self.goto_tab("target")
        self.page.locator("#target-url").fill(followup_url)
        self.page.locator("#target-send-automation").click()
        self.page.wait_for_timeout(600)
        workflow_id = int(self.current_workflow(name)["id"])
        self.workflow_ids.append(workflow_id)
        target = next(node["id"] for node in self.current_workflow(name)["nodes"] if node["type"] == "target")
        output = self.add_node("Output")
        self.connect(target, output)
        self.save_workflow(name)
        run = self.run_workflow(workflow_id, timeout=60)
        self.assertEqual(run["status"], "completed", run)
        self.assert_clean_browser()

    def test_intruder_results_handoff_to_ai_and_operator_approved_target_followup(self):
        self.goto_tab("intruder")
        self.page.locator("#intruder-raw-request").fill(
            f"GET /search?q=§payload§ HTTP/1.1\nHost: 127.0.0.1:{self.fixture_port}\n\n"
        )
        self.page.locator(".dictionary-values").first.fill("one\ntwo")
        self.page.locator("#attack").click()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if "completed" in self.page.locator("#attack-status").inner_text().lower() and self.page.locator('#attack-results tr[data-attack-result]').count() >= 2:
                break
            time.sleep(0.2)
        self.assertIn("completed", self.page.locator("#attack-status").inner_text().lower())
        intruder_export = self.download_json("#export-attack-json")
        self.assertGreaterEqual(len(intruder_export.get("results", [])), 2)
        self.page.locator("#intruder-send-ai").click()
        self.assert_attached_evidence("Intruder results")
        self.configure_local_llm()
        self.assertTrue(self.llm_server.requests)
        self.assertIn("intruder", json.dumps(self.llm_server.requests[-1]).lower())

        # AI only recommends the next step; the operator explicitly creates and
        # runs the follow-up Target workflow.
        recommendation = self.page.locator("#agent-chat-log").inner_text()
        followup_url = self.recommended_fixture_url(recommendation)
        name = self.new_workflow("ai-intruder-followup")
        self.goto_tab("target")
        self.page.locator("#target-url").fill(followup_url)
        self.page.locator("#target-send-automation").click()
        self.page.wait_for_timeout(600)
        workflow_id = int(self.current_workflow(name)["id"])
        self.workflow_ids.append(workflow_id)
        target = next(node["id"] for node in self.current_workflow(name)["nodes"] if node["type"] == "target")
        output = self.add_node("Output")
        self.connect(target, output)
        self.save_workflow(name)
        run = self.run_workflow(workflow_id, timeout=60)
        self.assertEqual(run["status"], "completed", run)
        self.assert_clean_browser()

    def test_dirty_graph_is_saved_before_run(self):
        name = self.new_workflow("dirty-save")
        trigger = self.add_node("Manual trigger")
        values = self.add_node("Set values")
        output = self.add_node("Output")
        self.connect(trigger, values)
        self.connect(values, output)
        self.set_param(values, "values", '{"version":1}')
        workflow_id = self.save_workflow(name)
        self.set_param(values, "values", '{"version":2}')
        # Deliberately do not click Save: Run must persist the current draft.
        run = self.run_workflow(workflow_id)
        self.assertEqual(run["status"], "completed", run)
        self.assertEqual(run["output"]["value"]["version"], 2)
        self.assert_clean_browser()

    def test_decoder_error_is_visible_as_failed_run(self):
        name = self.new_workflow("decoder-error")
        trigger = self.add_node("Manual trigger")
        values = self.add_node("Template")
        decoder = self.add_node("Decoder")
        output = self.add_node("Output")
        self.connect(trigger, values)
        self.connect(values, decoder)
        self.connect(decoder, output)
        self.set_param(values, "text", "not-a-byte")
        self.set_param(decoder, "operation", "byteDecode")
        workflow_id = self.save_workflow(name)
        run = self.run_workflow(workflow_id)
        self.assertEqual(run["status"], "failed", run)
        self.assertIn("byte input", run["error"])
        self.assert_clean_browser()

    def test_workflow_ai_node_receives_repeater_evidence(self):
        name = self.new_workflow("workflow-ai")
        trigger = self.add_node("Manual trigger")
        repeater = self.add_node("Repeater")
        ai_node = self.add_node("AI Agent")
        output = self.add_node("Output")
        self.connect(trigger, repeater)
        self.connect(repeater, ai_node)
        self.connect(ai_node, output)
        self.set_param(repeater, "url", f"http://127.0.0.1:{self.fixture_port}/health")
        self.set_param(repeater, "headers", "{}")
        self.set_param(repeater, "body", "")
        self.set_param(ai_node, "prompt", "Summarize the attached Repeater evidence and recommend the next safe check.")
        self.set_param(ai_node, "provider", "ollama")
        self.set_param(ai_node, "endpoint", f"http://127.0.0.1:{self.llm_port}/v1/chat/completions")
        self.set_param(ai_node, "model", "local-test-model")
        workflow_id = self.save_workflow(name)
        run = self.run_workflow(workflow_id, timeout=45)
        self.assertEqual(run["status"], "completed", run)
        self.assertIn("Recommended next crawl", run["output"]["value"]["message"])
        self.assertTrue(self.llm_server.requests)
        self.assertIn("workflow_input", json.dumps(self.llm_server.requests[-1]))
        self.assert_clean_browser()

    def test_ai_project_context_is_explicit_and_one_shot(self):
        self.goto_tab("ai")
        checkbox = self.page.locator("#agent-use-project-context")
        self.assertFalse(checkbox.is_disabled())
        self.assertFalse(checkbox.is_checked())
        self.assertIn("Project:", self.page.locator("#agent-project-context-hint").inner_text())
        self.page.locator("#agent-provider").select_option("ollama")
        self.page.locator("#agent-endpoint").fill(f"http://127.0.0.1:{self.llm_port}/v1/chat/completions")
        self.page.locator("#agent-model").fill("local-test-model")
        self.page.locator("#agent-chat-input").fill("Summarize the active Project context.")
        checkbox.check()
        before_messages = self.page.locator("#agent-chat-log .agent-chat-message").count()
        before_requests = len(self.llm_server.requests)
        self.page.locator("#agent-chat-send").click()
        self.page.wait_for_function(
            "before => document.querySelectorAll('#agent-chat-log .agent-chat-message').length > before",
            arg=before_messages,
        )
        self.page.locator("#agent-chat-log").filter(has_text="Recommended next crawl").wait_for(state="visible")
        request_payload = self.llm_server.requests[before_requests]
        evidence_message = request_payload["messages"][1]["content"]
        self.assertIn("RequestRider Project Context", evidence_message)
        self.assertIn("e2e-default-project-", evidence_message)
        self.assertFalse(checkbox.is_checked())
        self.assert_clean_browser()

    def test_ai_project_context_is_disabled_without_active_project(self):
        self.goto_tab("projects")
        with self.page.expect_response(lambda response: response.url.endswith("/api/project-context") and response.request.method == "POST") as response_info:
            self.page.locator("#project-select").select_option("")
        self.assertEqual(response_info.value.status, 200)
        self.page.locator("button[data-tab='ai']").click()
        checkbox = self.page.locator("#agent-use-project-context")
        self.assertTrue(checkbox.is_disabled())
        self.assertFalse(checkbox.is_checked())
        self.assertIn("Select a Project", self.page.locator("#agent-project-context-hint").inner_text())
        self.assert_clean_browser()

    def test_condition_true_false_merge_runs_and_branch_changes(self):
        name = self.new_workflow("branch-merge")
        trigger = self.add_node("Manual trigger")
        values = self.add_node("Set values")
        condition = self.add_node("Condition")
        true_values = self.add_node("Set values")
        false_values = self.add_node("Set values")
        merge = self.add_node("Merge")
        output = self.add_node("Output")
        self.connect(trigger, values)
        self.connect(values, condition)
        self.connect(condition, true_values, source_handle="true")
        self.connect(condition, false_values, source_handle="false")
        self.connect(true_values, merge)
        self.connect(false_values, merge)
        self.connect(merge, output)
        self.set_param(values, "values", '{"route":"ok"}')
        self.set_param(condition, "field", "route")
        self.set_param(condition, "operator", "equals")
        self.set_param(condition, "value", "ok")
        self.set_param(true_values, "values", '{"branch":"true"}')
        self.set_param(false_values, "values", '{"branch":"false"}')
        workflow_id = self.save_workflow(name)
        first = self.run_workflow(workflow_id)
        self.assertEqual(first["status"], "completed", first)
        self.assertEqual(first["output"]["value"], [{"branch": "true"}])

        self.page.wait_for_timeout(800)
        self.set_param(values, "values", '{"route":"not-ok"}')
        # Run must auto-save the dirty branch before executing it.
        second = self.run_workflow(workflow_id)
        self.assertEqual(second["status"], "completed", second)
        self.assertEqual(second["output"]["value"], [{"branch": "false"}])
        self.assert_clean_browser()

    def test_pause_resume_and_cancel_controls(self):
        name, workflow_id, delay = self.build_delay_workflow("pause-resume", 4)
        self.page.locator("#workflow-run").click()
        self.wait_run_node(workflow_id, delay)
        self.page.locator("#workflow-run-pause").click()
        paused = self.wait_run_status(workflow_id, "paused")
        self.assertFalse(any(event.get("node_id") == delay and event.get("status") == "completed" for event in paused.get("logs", [])))
        self.page.locator("#workflow-run-resume").click()
        completed = self.wait_run(workflow_id, timeout=20)
        self.assertEqual(completed["status"], "completed", completed)
        self.assert_clean_browser()

        cancel_name, cancel_id, cancel_delay = self.build_delay_workflow("cancel", 12)
        self.page.locator("#workflow-run").click()
        self.wait_run_node(cancel_id, cancel_delay)
        self.page.locator("#workflow-run-cancel").click()
        cancelled = self.wait_run(cancel_id, timeout=20)
        self.assertEqual(cancelled["status"], "cancelled", cancelled)
        self.assertFalse(any(event.get("node_id") == cancel_delay and event.get("status") == "completed" for event in cancelled.get("logs", [])))
        self.assert_clean_browser()

    def test_workflow_export_import_and_rerun_through_ui(self):
        name = self.new_workflow("export-import")
        trigger = self.add_node("Manual trigger")
        values = self.add_node("Set values")
        output = self.add_node("Output")
        self.connect(trigger, values)
        self.connect(values, output)
        self.set_param(values, "values", '{"exported":true}')
        workflow_id = self.save_workflow(name)
        self.set_param(values, "values", '{"exported":"dirty-autosave"}')
        with self.page.expect_download() as download_info:
            self.page.locator("#workflow-export").click()
        download = download_info.value
        path = download.path()
        self.assertTrue(path)
        with open(path, encoding="utf-8") as exported_file:
            exported = json.load(exported_file)
        self.assertEqual(exported["schema"], "requestrider.workflow/v1")
        self.assertEqual(len(exported["workflow"]["nodes"]), 3)
        self.assertEqual(len(exported["workflow"]["connections"]), 2)

        before_ids = {item["id"] for item in request_json(f"{DEFAULT_BASE_URL}api/workflows").get("items", [])}
        self.page.locator("#workflow-import-file").set_input_files(path)
        deadline = time.monotonic() + 8
        imported = None
        while time.monotonic() < deadline:
            items = request_json(f"{DEFAULT_BASE_URL}api/workflows").get("items", [])
            imported = next((item for item in items if item["id"] not in before_ids and item.get("name") == name), None)
            if imported:
                break
            time.sleep(0.1)
        self.assertIsNotNone(imported)
        imported_id = int(imported["id"])
        self.workflow_ids.append(imported_id)
        self.page.wait_for_timeout(400)
        self.assertEqual(self.page.locator(".workflow-node").count(), 3)
        run = self.run_workflow(imported_id)
        self.assertEqual(run["status"], "completed", run)
        self.assertEqual(run["output"]["value"]["exported"], "dirty-autosave")
        self.assert_clean_browser()

    def test_oast_listener_starts_callback_and_collects_evidence(self):
        name = self.new_workflow("oast-local")
        trigger = self.add_node("Manual trigger")
        listener = self.add_node("OAST Listener")
        repeater = self.add_node("Repeater")
        collector = self.add_node("OAST Collect")
        output = self.add_node("Output")
        self.connect(trigger, listener)
        self.connect(listener, repeater)
        self.connect(repeater, collector)
        self.connect(collector, output)
        self.set_param(listener, "server_url", f"http://127.0.0.1:{self.oast_fixture_port}")
        self.set_param(listener, "poll_interval_sec", 1)
        self.set_param(listener, "timeout_sec", 15)
        self.set_param(listener, "capture_protocols", '["http"]')
        self.set_param(repeater, "method", "GET")
        self.set_param(repeater, "url", "{{payload_url}}")
        self.set_param(repeater, "headers", "{}")
        self.set_param(repeater, "body", "")
        self.set_param(repeater, "delay_ms", 0)
        self.set_param(collector, "poll_interval_sec", 1)
        self.set_param(collector, "timeout_sec", 20)
        workflow_id = self.save_workflow(name)
        run = self.run_workflow(workflow_id, confirm=True, timeout=45)
        self.assertEqual(run["status"], "completed", run)
        result = run["output"]["value"]
        self.assertTrue(result.get("triggered"), result)
        self.assertGreaterEqual(result.get("events_count", 0), 1, result)
        self.assert_clean_browser()


    def test_oast_timeout_returns_explicit_no_callback_result(self):
        name = self.new_workflow("oast-timeout")
        trigger = self.add_node("Manual trigger")
        listener = self.add_node("OAST Listener")
        collector = self.add_node("OAST Collect")
        output = self.add_node("Output")
        self.connect(trigger, listener)
        self.connect(listener, collector)
        self.connect(collector, output)
        self.set_param(listener, "server_url", f"http://127.0.0.1:{self.oast_fixture_port}")
        self.set_param(listener, "poll_interval_sec", 1)
        self.set_param(listener, "timeout_sec", 1)
        self.set_param(listener, "capture_protocols", '["http"]')
        self.set_param(collector, "poll_interval_sec", 1)
        self.set_param(collector, "timeout_sec", 4)
        workflow_id = self.save_workflow(name)
        run = self.run_workflow(workflow_id, confirm=True, timeout=20)
        self.assertEqual(run["status"], "completed", run)
        result = run["output"]["value"]
        self.assertFalse(result.get("triggered"), result)
        self.assertTrue(result.get("timed_out"), result)
        self.assert_clean_browser()


    def test_template_store_search_preview_and_canvas_import(self):
        original_name = self.new_workflow("template-original")
        trigger = self.add_node("Manual trigger")
        values = self.add_node("Set values")
        output = self.add_node("Output")
        self.connect(trigger, values)
        self.connect(values, output)
        self.set_param(values, "values", '{"original":true}')
        original_id = self.save_workflow(original_name)
        custom_template_name = self.unique_name("saved-template")
        self.page.locator("#workflow-save-template").click()
        dialog = self.page.locator("dialog[open]")
        self.assertEqual(dialog.count(), 1)
        dialog.locator('[name="name"]').fill(custom_template_name)
        dialog.locator('[name="category"]').select_option("compliance_devsecops")
        dialog.locator('[name="description"]').fill("Local custom QA template")
        dialog.locator('button[value="save"]').click()
        self.page.wait_for_timeout(250)

        self.goto_tab("automation")
        self.page.locator("#workflow-template-store").click()
        self.page.locator("#template-store-dialog").wait_for(state="visible", timeout=5000)
        self.assertTrue(self.page.locator("#template-store-dialog").is_visible())
        self.assertEqual(self.page.locator("#template-store-dialog [data-template-id]").count(), 24)
        self.page.locator("#template-store-search").fill(custom_template_name)
        self.assertEqual(self.page.locator("#template-store-dialog [data-template-id]").count(), 1)
        self.reload_page()
        self.page.wait_for_timeout(700)
        self.goto_tab("automation")
        self.page.locator("#workflow-template-store").click()
        self.page.locator("#template-store-dialog").wait_for(state="visible", timeout=5000)
        self.page.locator("#template-store-search").fill(custom_template_name)
        self.assertEqual(self.page.locator("#template-store-dialog [data-template-id]").count(), 1)
        self.page.locator("#template-store-search").fill("logic graph baseline")
        self.assertEqual(self.page.locator("#template-store-dialog [data-template-id]").count(), 1)
        self.page.locator('#template-store-dialog [data-template-id]').first.click()
        self.assertEqual(self.page.locator("#template-preview-title").inner_text(), "Logic graph baseline")
        self.assertIn("Manual trigger", self.page.locator("#template-preview-graph").inner_text())
        self.page.locator("#template-store-close").click()

        self.page.locator("#workflow-template-store").click()
        self.page.locator("#template-store-dialog").wait_for(state="visible", timeout=5000)
        self.page.locator("#template-store-search").fill("")
        self.page.locator("#template-store-category").select_option("api_microservices")
        self.assertGreaterEqual(self.page.locator("#template-store-dialog [data-template-id]").count(), 1)
        self.page.locator("#template-store-search").fill("intruder")
        self.assertEqual(self.page.locator("#template-store-dialog [data-template-id]").count(), 0)
        self.page.locator("#template-store-category").select_option("")
        self.page.locator("#template-store-search").fill("intruder")
        self.page.locator("#template-store-dialog [data-template-id]").first.click()
        self.assertFalse(self.page.locator("#template-preview-import").is_enabled())
        self.page.locator('[data-template-variable="target_url"]').fill(f"http://127.0.0.1:{self.fixture_port}/")
        self.page.locator("#template-store-scope-confirm").check()
        self.assertTrue(self.page.locator("#template-preview-import").is_enabled())
        self.page.locator("#template-store-close").click()

        self.page.locator("#workflow-template-store").click()
        self.page.locator("#template-store-dialog").wait_for(state="visible", timeout=5000)
        self.page.locator("#template-store-search").fill("schema endpoint discovery")
        self.assertEqual(self.page.locator("#template-store-dialog [data-template-id]").count(), 1)
        self.page.locator("#template-store-dialog [data-template-id]").first.click()
        self.assertEqual(self.page.locator("#template-preview-title").inner_text(), "Schema endpoint discovery")
        self.page.locator("#template-store-close").click()

        high_risk_previews = {
            "BOLA/IDOR differential evidence": "BOLA/IDOR differential evidence",
            "Race-condition timing observation": "Race-condition timing observation",
            "WAF rule differential": "WAF rule differential",
            "JWT claim mutation differential": "JWT claim mutation differential",
            "XXE/OAST local canary chain": "XXE/OAST local canary chain",
            "CI/CD exposure review": "CI/CD exposure review",
        }
        for query, expected_title in high_risk_previews.items():
            self.page.locator("#workflow-template-store").click()
            self.page.locator("#template-store-dialog").wait_for(state="visible", timeout=5000)
            self.page.locator("#template-store-search").fill(query)
            self.assertEqual(self.page.locator("#template-store-dialog [data-template-id]").count(), 1)
            self.page.locator("#template-store-dialog [data-template-id]").first.click()
            self.assertEqual(self.page.locator("#template-preview-title").inner_text(), expected_title)
            self.page.locator("#template-store-close").click()

        self.page.locator("#workflow-template-store").click()
        self.page.locator("#template-store-dialog").wait_for(state="visible", timeout=5000)
        self.page.locator("#template-store-search").fill("logic graph baseline")
        self.page.locator('#template-store-dialog [data-template-id]').first.click()
        self.page.locator("#template-preview-import").click()
        self.assertFalse(self.page.locator("#template-store-dialog").is_visible())
        imported_name = self.page.locator("#workflow-name").input_value()
        self.assertEqual(self.page.locator(".workflow-node").count(), 4)
        workflow_items = request_json(f"{DEFAULT_BASE_URL}api/workflows").get("items", [])
        self.assertTrue(any(item.get("id") == original_id for item in workflow_items))
        imported_id = self.save_workflow(imported_name)
        workflow_items = request_json(f"{DEFAULT_BASE_URL}api/workflows").get("items", [])
        self.assertTrue(any(item.get("id") == imported_id for item in workflow_items))
        run = self.run_workflow(imported_id)
        self.assertEqual(run["status"], "completed", run)
        self.assertEqual(run["output"]["value"]["status"], "ready")
        self.assertTrue(any(item["id"] == original_id for item in request_json(f"{DEFAULT_BASE_URL}api/workflows").get("items", [])))
        self.assert_clean_browser()


    def test_workflow_and_run_state_survive_reload(self):
        name = self.new_workflow("reload")
        trigger = self.add_node("Manual trigger")
        values = self.add_node("Set values")
        output = self.add_node("Output")
        self.connect(trigger, values)
        self.connect(values, output)
        self.set_param(values, "values", '{"persisted":true}')
        workflow_id = self.save_workflow(name)
        first = self.run_workflow(workflow_id)
        self.assertEqual(first["status"], "completed", first)
        self.reload_page()
        self.page.wait_for_timeout(900)
        self.goto_tab("automation")
        workflow_button = self.page.locator("#workflow-list button").filter(has_text=name)
        self.assertEqual(workflow_button.count(), 1)
        workflow_button.click()
        self.page.wait_for_timeout(400)
        self.assertEqual(self.page.locator(".workflow-node").count(), 3)
        self.page.locator(".workflow-node").filter(has_text="Set values").click()
        self.assertEqual(json.loads(self.page.locator('#workflow-inspector [data-workflow-param="values"]').input_value()), {"persisted": True})
        self.assertIn("completed", self.page.locator("#workflow-runs-list").inner_text().lower())
        self.assert_clean_browser()

    def test_webhook_activation_and_schedule_activation_through_ui(self):
        webhook_name = self.new_workflow("webhook")
        hook = self.add_node("Webhook trigger")
        values = self.add_node("Set values")
        output = self.add_node("Output")
        self.connect(hook, values)
        self.connect(values, output)
        self.set_param(values, "values", '{"source":"ui-webhook","accepted":true}')
        webhook_id = self.save_workflow(webhook_name)
        self.set_param(values, "values", '{"source":"ui-webhook-dirty","accepted":true}')
        self.activate_workflow()
        webhook_workflow = request_json(f"{DEFAULT_BASE_URL}api/workflows/{webhook_id}")
        self.assertTrue(webhook_workflow["active"])
        self.assertTrue(webhook_workflow["webhook_slug"])
        request_json(
            f"{DEFAULT_BASE_URL}api/workflows/hooks/{webhook_workflow['webhook_slug']}",
            method="POST",
            payload={"event": "fixture"},
        )
        webhook_run = self.wait_run(webhook_id, timeout=20)
        self.assertEqual(webhook_run["status"], "completed", webhook_run)
        self.assertEqual(webhook_run["output"]["value"]["source"], "ui-webhook-dirty")
        self.deactivate_workflow()
        self.assertFalse(request_json(f"{DEFAULT_BASE_URL}api/workflows/{webhook_id}")["active"])

        schedule_name = self.new_workflow("schedule")
        schedule = self.add_node("Schedule trigger")
        values = self.add_node("Set values")
        output = self.add_node("Output")
        self.connect(schedule, values)
        self.connect(values, output)
        self.set_param(schedule, "cron", "*/5 * * * *")
        schedule_id = self.save_workflow(schedule_name)
        self.activate_workflow()
        schedule_workflow = request_json(f"{DEFAULT_BASE_URL}api/workflows/{schedule_id}")
        self.assertTrue(schedule_workflow["active"])
        self.assertEqual(schedule_workflow["schedule"], "*/5 * * * *")
        self.deactivate_workflow()
        self.assertFalse(request_json(f"{DEFAULT_BASE_URL}api/workflows/{schedule_id}")["active"])
        self.assert_clean_browser()

    def test_invalid_graph_is_rejected_through_run_button(self):
        name = self.new_workflow("invalid")
        self.add_node("Output")
        workflow_id = self.save_workflow(name)
        self.page.locator("#workflow-run").click()
        self.page.wait_for_timeout(300)
        self.assertIn("incomplete", self.page.locator("#session-status").inner_text().lower())
        self.assert_clean_browser()



if __name__ == "__main__":
    unittest.main(verbosity=2)
