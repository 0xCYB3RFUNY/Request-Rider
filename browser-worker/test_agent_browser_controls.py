"""Unit tests for the typed control actions used by the in-app AI agent.

These actions are the boundary between a model-produced tool call and a real
browser action, so the tests hold the input validation and the password mask.
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import worker  # noqa: E402


class FakeLocator:
    def __init__(self, input_type=""):
        self.input_type = input_type
        self.filled = []
        self.clicked = []

    @property
    def first(self):
        return self

    async def fill(self, value, timeout=None):
        self.filled.append(value)

    async def click(self, button="left", timeout=None):
        self.clicked.append(button)

    async def get_attribute(self, name):
        return self.input_type if name == "type" else None


class FakePage:
    def __init__(self, locator):
        self._locator = locator
        self.navigated = []
        self.url = "http://example.test/"

    def locator(self, selector):
        return self._locator

    async def goto(self, url, wait_until=None, timeout=None):
        self.navigated.append(url)
        self.url = url


def _context(page):
    job = {
        "status": "running",
        "manual_control": False,
        "live_view": True,
        "_control": {"resume_event": asyncio.Event(), "pages": {}, "control_worker_id": None},
    }
    return job, {"wid": "w1", "page": page, "page_cfg": {}, "guard": None}


def _run(job_id, payload):
    # The job lookup happens before action dispatch; a minimal running job is
    # enough to reach the selector validation.
    job = {"status": "running", "_control": {"resume_event": asyncio.Event()}}
    page = FakePage(FakeLocator())
    with patch.object(worker, "JOBS", {job_id: job}), \
         patch.object(worker, "_select_control_page", return_value=("w1", page, {}, None)):
        return asyncio.run(worker._execute_live_control_async(job_id, payload))


@pytest.mark.parametrize("action", ["fill", "click_selector"])
def test_selector_actions_require_a_selector(action):
    status, result = _run("job1", {"action": action})
    assert status == 400
    assert result["error"] == "selector is required"


def test_fill_masks_password_values_in_live_history():
    locator = FakeLocator(input_type="password")
    page = FakePage(locator)
    job, selected = _context(page)
    captured = {}

    async def fake_capture(job_id, wid, page, cfg, action=None, **kwargs):
        captured.update(action or {})

    with patch.object(worker, "JOBS", {"job1": job}), \
         patch.object(worker, "_select_control_page", return_value=("w1", page, {}, None)), \
         patch.object(worker, "_capture_live_frame", side_effect=fake_capture), \
         patch.object(worker, "live_snapshot", return_value={"seq": 1}):
        status, result = asyncio.run(worker._execute_live_control_async(
            "job1", {"action": "fill", "selector": "#password", "value": "super-secret"}))

    assert status == 200
    assert locator.filled == ["super-secret"]
    assert captured["value"] == "••••"
    assert "super-secret" not in str(result)


def test_click_selector_uses_the_requested_button():
    locator = FakeLocator()
    page = FakePage(locator)
    job, _ = _context(page)
    with patch.object(worker, "JOBS", {"job1": job}), \
         patch.object(worker, "_select_control_page", return_value=("w1", page, {}, None)), \
         patch.object(worker, "_capture_live_frame", new_callable=AsyncMock), \
         patch.object(worker, "live_snapshot", return_value={"seq": 2}):
        status, result = asyncio.run(worker._execute_live_control_async(
            "job1", {"action": "click_selector", "selector": "#submit", "button": "right"}))
    assert status == 200
    assert locator.clicked == ["right"]


@pytest.mark.parametrize("url", ["javascript:alert(1)", "example.test", "file:///etc/passwd", ""])
def test_navigate_rejects_non_http_urls(url):
    page = FakePage(FakeLocator())
    job, _ = _context(page)
    with patch.object(worker, "JOBS", {"job1": job}), \
         patch.object(worker, "_select_control_page", return_value=("w1", page, {}, None)):
        status, result = asyncio.run(worker._execute_live_control_async(
            "job1", {"action": "navigate", "url": url}))
    assert status == 400
    assert page.navigated == []


def test_navigate_accepts_absolute_http_url():
    page = FakePage(FakeLocator())
    job, _ = _context(page)
    with patch.object(worker, "JOBS", {"job1": job}), \
         patch.object(worker, "_select_control_page", return_value=("w1", page, {}, None)), \
         patch.object(worker, "_capture_live_frame", new_callable=AsyncMock), \
         patch.object(worker, "live_snapshot", return_value={"seq": 3}):
        status, result = asyncio.run(worker._execute_live_control_async(
            "job1", {"action": "navigate", "url": "http://example.test/dashboard"}))
    assert status == 200
    assert page.navigated == ["http://example.test/dashboard"]
