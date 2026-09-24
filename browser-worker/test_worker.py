"""End-to-end lifecycle checks for the local browser Target worker."""

import asyncio
import threading
import unittest
from http.server import ThreadingHTTPServer

from tools.target_fixture import FixtureHandler
from worker import JOBS, JOBS_LOCK, normalize_input, run_async_job


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


if __name__ == "__main__":
    unittest.main()
