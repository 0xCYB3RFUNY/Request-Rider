"""End-to-end lifecycle checks for the local browser Target worker."""

import asyncio
import threading
import time
import unittest
from http.server import ThreadingHTTPServer

from tools.target_fixture import FixtureHandler
from worker import JOBS, JOBS_LOCK, cancel_all_jobs, cancel_job, normalize_input, run_async_job, run_job


class SlowFixtureHandler(FixtureHandler):
    def do_GET(self):
        if self.path == "/slow":
            time.sleep(5)
            try:
                self.send_body(200, "slow", "text/plain")
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        super().do_GET()


class BrowserTargetLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.fixture_thread = threading.Thread(target=cls.fixture.serve_forever, daemon=True)
        cls.fixture_thread.start()
        cls.url = f"http://127.0.0.1:{cls.fixture.server_port}/"

    @classmethod
    def tearDownClass(cls):
        cls.fixture.shutdown()
        cls.fixture.server_close()
        cls.fixture_thread.join(timeout=2)

    def test_normalize_requires_http_url(self):
        with self.assertRaises(ValueError):
            normalize_input({"url": "file:///tmp/fixture.html"})

    def test_normalize_accepts_only_opaque_capture_context(self):
        config = normalize_input({"url": self.url, "capture_context": "abc_123-xyz"})
        self.assertEqual(config["capture_context"], "abc_123-xyz")
        with self.assertRaises(ValueError):
            normalize_input({"url": self.url, "capture_context": "bad value"})

    def test_navigation_and_form_actions_complete(self):
        from playwright.async_api import async_playwright

        async def run():
            async with async_playwright() as playwright:
                job_id = "lifecycle-test"
                config = normalize_input({
                    "url": self.url,
                    "max_pages": 3,
                    "max_depth": 1,
                    "browser": "firefox",
                    "actions": [
                        {"type": "fill", "selector": "input[name=q]", "value": "requestrider"},
                        {"type": "click", "selector": "#load-data"},
                    ],
                    "allow_state_changing_actions": True,
                })
                with JOBS_LOCK:
                    JOBS[job_id] = {
                        "job_id": job_id,
                        "status": "running",
                        "start_url": config["url"],
                        "visited": 0,
                        "pages": [],
                        "cancelled": False,
                    }
                await run_async_job(job_id, config, async_playwright)

        asyncio.run(run())
        with JOBS_LOCK:
            job = dict(JOBS["lifecycle-test"])
        self.assertEqual(job["status"], "completed")
        self.assertGreaterEqual(job["visited"], 2)
        self.assertTrue(any("/api/data" in item["url"] for page in job["pages"] for item in page.get("network", [])))
        self.assertTrue(any(page["url"].endswith("/next") for page in job["pages"]))

    def test_bulk_cancel_interrupts_inflight_navigation(self):
        fixture = ThreadingHTTPServer(("127.0.0.1", 0), SlowFixtureHandler)
        fixture_thread = threading.Thread(target=fixture.serve_forever, daemon=True)
        fixture_thread.start()
        job_id = "cancel-inflight-test"
        config = normalize_input({
            "url": f"http://127.0.0.1:{fixture.server_port}/slow",
            "max_pages": 1,
            "max_depth": 0,
            "concurrency": 1,
            "browser": "firefox",
        })
        with JOBS_LOCK:
            JOBS[job_id] = {
                "job_id": job_id,
                "status": "running",
                "start_url": config["url"],
                "visited": 0,
                "pages": [],
                "cancelled": False,
            }
        thread = threading.Thread(target=run_job, args=(job_id, config), daemon=True)
        try:
            thread.start()
            deadline = time.monotonic() + 3
            active = False
            while time.monotonic() < deadline:
                with JOBS_LOCK:
                    active = JOBS[job_id].get("_task") is not None
                if active:
                    break
                time.sleep(0.02)
            self.assertTrue(active)
            self.assertEqual(cancel_all_jobs(), [job_id])
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            with JOBS_LOCK:
                job = dict(JOBS[job_id])
            self.assertEqual(job["status"], "cancelled")
        finally:
            cancel_job(job_id)
            fixture.shutdown()
            fixture.server_close()
            fixture_thread.join(timeout=2)
            with JOBS_LOCK:
                JOBS.pop(job_id, None)


if __name__ == "__main__":
    unittest.main()
