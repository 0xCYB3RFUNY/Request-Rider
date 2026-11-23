"""Unit tests for Burp-style Live View in browser-worker."""

import asyncio
import base64
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import worker  # noqa: E402


class FakeLocator:
    def __init__(self, box=None, editable=True):
        self._box = box
        self._editable = editable
        self.typed = []

    @property
    def first(self):
        return self

    async def bounding_box(self, timeout=None):
        return self._box

    async def is_editable(self, timeout=None):
        return self._editable

    async def type(self, char, delay=0):
        self.typed.append(char)

    async def click(self, timeout=None):
        return None


class FakeMouse:
    def __init__(self):
        self.events = []

    async def click(self, x, y, button="left", click_count=1):
        self.events.append(("click", x, y, button, click_count))

    async def move(self, x, y, steps=1):
        self.events.append(("move", x, y, steps))

    async def down(self):
        self.events.append(("down",))

    async def up(self):
        self.events.append(("up",))

    async def wheel(self, dx, dy):
        self.events.append(("wheel", dx, dy))


class FakeKeyboard:
    def __init__(self):
        self.events = []

    async def type(self, text, delay=0):
        self.events.append(("type", text))

    async def press(self, key):
        self.events.append(("press", key))


class FakePage:
    def __init__(self, url="https://example.test/login", title="Login", viewport=None):
        self.url = url
        self._title = title
        self.viewport_size = viewport or {"width": 1280, "height": 720}
        self._locators = {}
        self.mouse = FakeMouse()
        self.keyboard = FakeKeyboard()

    async def screenshot(self, type="jpeg", quality=55, timeout=2500):
        return b"\xff\xd8\xffFAKEJPEG"

    async def title(self):
        return self._title

    def locator(self, selector):
        return self._locators.setdefault(selector, FakeLocator({"x": 100, "y": 200, "width": 120, "height": 40}))


def test_normalize_input_live_view_default_and_enabled():
    cfg_default = worker.normalize_input({"url": "https://example.test/"})
    assert cfg_default["live_view"] is False

    cfg_enabled = worker.normalize_input({"url": "https://example.test/", "live_view": True})
    assert cfg_enabled["live_view"] is True


def test_capture_live_frame_and_snapshot_isolation():
    job_id = "live-test-job-1"
    with worker.JOBS_LOCK:
        worker.JOBS[job_id] = {
            "job_id": job_id,
            "status": "running",
            "start_url": "https://example.test/",
            "total": 10,
            "visited": 1,
            "pages": [],
            "live_view": True,
            "live_seq": 0,
            "cancelled": False,
        }
    try:
        page = FakePage()
        locator = FakeLocator({"x": 100.0, "y": 200.0, "width": 80.0, "height": 40.0})
        config = {"live_view": True}

        asyncio.run(
            worker._capture_live_frame(
                job_id,
                1,
                page,
                config,
                action={"type": "click", "label": "Sign in", "selector": "button.login"},
                locator=locator,
            )
        )

        # Regular snapshot MUST NOT include base64 frames (_live is private)
        snap = worker.snapshot(job_id)
        assert "_live" not in snap
        assert snap["live_view"] is True
        assert snap["live_seq"] == 1

        # Live snapshot returns the frame, bounding box, center coordinates, and history
        live = worker.live_snapshot(job_id)
        assert live["has_frame"] is True
        assert live["unchanged"] is False
        assert live["seq"] == 1
        assert live["workers"] == ["1"]
        frame = live["frame"]
        assert frame["mime"] == "image/jpeg"
        assert base64.b64decode(frame["image_b64"]) == b"\xff\xd8\xffFAKEJPEG"
        assert frame["action"]["type"] == "click"
        assert frame["action"]["x"] == 140.0
        assert frame["action"]["y"] == 220.0
        assert frame["action"]["box"] == {"x": 100.0, "y": 200.0, "width": 80.0, "height": 40.0}
        assert len(live["history"]) == 1
        assert live["history"][0]["label"] == "Sign in"

        # Polling with since == seq avoids resending image payload
        unchanged = worker.live_snapshot(job_id, since=1)
        assert unchanged["has_frame"] is True
        assert unchanged["unchanged"] is True
        assert "frame" not in unchanged

        # Second worker updates active_worker_id, but worker_id="1" can still be requested
        page2 = FakePage(url="https://example.test/dashboard", title="Dashboard")
        asyncio.run(
            worker._capture_live_frame(
                job_id,
                2,
                page2,
                config,
                action={"type": "navigate", "label": "https://example.test/dashboard"},
                force=True,
            )
        )
        live_auto = worker.live_snapshot(job_id)
        assert live_auto["active_worker_id"] == "2"
        assert live_auto["workers"] == ["1", "2"]
        assert live_auto["frame"]["url"] == "https://example.test/dashboard"

        live_tab1 = worker.live_snapshot(job_id, worker_id="1")
        assert live_tab1["worker_id"] == "1"
        assert live_tab1["frame"]["url"] == "https://example.test/login"
    finally:
        with worker.JOBS_LOCK:
            worker.JOBS.pop(job_id, None)


def test_fill_auto_field_masks_password_in_live_hook():
    page = FakePage()
    captured = []

    async def live_hook(action, locator=None):
        captured.append(action)

    field = {
        "selector": "input[name='pwd']",
        "kind": "password",
        "name": "pwd",
        "label": "Password",
    }
    outcome = asyncio.run(worker.fill_auto_field(page, field, live_hook=live_hook))
    assert outcome["interaction"] == "fill"
    assert len(captured) == 1
    assert captured[0]["type"] == "fill"
    assert captured[0]["value"] == "••••"


def test_manual_control_take_click_drag_type_and_resume():
    async def scenario():
        job_id = "live-manual-job-1"
        page = FakePage(url="https://example.test/captcha", title="Captcha")
        loop = asyncio.get_running_loop()
        with worker.JOBS_LOCK:
            worker.JOBS[job_id] = {
                "job_id": job_id,
                "status": "running",
                "start_url": "https://example.test/",
                "total": 10,
                "visited": 1,
                "pages": [],
                "live_view": True,
                "live_seq": 0,
                "manual_control": False,
                "cancelled": False,
                "_loop": loop,
            }
            ctrl = worker._ensure_control_state(worker.JOBS[job_id], loop)
            ctrl["pages"]["1"] = page
            ctrl["page_configs"]["1"] = {"live_view": True}
            ctrl["page_guards"]["1"] = {"busy": False, "last_ts": 0.0}
        try:
            code, res = await worker._execute_live_control_async(job_id, {"action": "take_control"})
            assert code == 200
            assert res["manual_control"] is True
            assert worker._is_manual_control(job_id) is True

            # A worker calling _wait_if_manual_control pauses until release_control
            waiter = asyncio.create_task(worker._wait_if_manual_control(job_id))
            await asyncio.sleep(0.02)
            assert not waiter.done()

            # Operator clicks captcha checkbox, drags slider, types text
            c1, r1 = await worker._execute_live_control_async(
                job_id, {"action": "click", "x": 320, "y": 240}
            )
            assert c1 == 200
            assert ("click", 320.0, 240.0, "left", 1) in page.mouse.events
            assert r1["frame"]["action"]["x"] == 320.0

            c2, _ = await worker._execute_live_control_async(
                job_id,
                {"action": "drag", "start_x": 100, "start_y": 300, "end_x": 380, "end_y": 302, "steps": 10},
            )
            assert c2 == 200
            assert ("down",) in page.mouse.events
            assert ("up",) in page.mouse.events

            c3, _ = await worker._execute_live_control_async(
                job_id, {"action": "type", "text": "AB12"}
            )
            assert c3 == 200
            assert ("type", "AB12") in page.keyboard.events

            # Release control -> waiter unblocks and returns True
            c4, r4 = await worker._execute_live_control_async(job_id, {"action": "release_control"})
            assert c4 == 200
            assert r4["manual_control"] is False
            waited = await asyncio.wait_for(waiter, timeout=1.0)
            assert waited is True
        finally:
            with worker.JOBS_LOCK:
                worker.JOBS.pop(job_id, None)

    asyncio.run(scenario())
