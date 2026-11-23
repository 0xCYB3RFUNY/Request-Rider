"""Tests for Browser Crawler Live View Django gateway endpoint and UI wiring."""

from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase


class TargetBrowserLiveViewTests(SimpleTestCase):
    def test_requires_get_method(self):
        response = self.client.post("/api/target-browser/live?job_id=abc123")
        self.assertEqual(response.status_code, 405)

    def test_requires_job_id(self):
        response = self.client.get("/api/target-browser/live")
        self.assertEqual(response.status_code, 400)
        self.assertIn("job_id", response.json().get("error", ""))

    def test_rejects_path_traversal_job_id(self):
        response = self.client.get("/api/target-browser/live", {"job_id": "../health"})
        self.assertEqual(response.status_code, 400)

    def test_rejects_invalid_worker_id_and_since(self):
        resp_worker = self.client.get(
            "/api/target-browser/live", {"job_id": "abc123", "worker_id": "../1"}
        )
        self.assertEqual(resp_worker.status_code, 400)

        resp_since = self.client.get(
            "/api/target-browser/live", {"job_id": "abc123", "since": "-5"}
        )
        self.assertEqual(resp_since.status_code, 400)

    @patch("lab.views.call_browser_worker_get")
    def test_proxies_valid_live_request_to_browser_worker(self, mock_get):
        mock_get.return_value = (
            200,
            {
                "job_id": "job42",
                "status": "running",
                "live_view": True,
                "seq": 7,
                "has_frame": True,
                "unchanged": False,
                "workers": ["1", "2"],
                "frame": {
                    "seq": 7,
                    "worker_id": "2",
                    "url": "https://example.test/login",
                    "viewport": {"width": 1280, "height": 720},
                    "action": {"type": "click", "x": 400, "y": 300, "label": "Sign in"},
                    "image_b64": "ZmFrZQ==",
                    "mime": "image/jpeg",
                },
                "history": [],
            },
        )
        response = self.client.get(
            "/api/target-browser/live",
            {"job_id": "job42", "worker_id": "2", "since": "6"},
        )
        self.assertEqual(response.status_code, 200)
        mock_get.assert_called_once_with("/target/job42/live?worker_id=2&since=6")
        body = response.json()
        self.assertEqual(body["seq"], 7)
        self.assertEqual(body["frame"]["action"]["type"], "click")

    def test_target_template_contains_live_view_elements(self):
        template = (
            Path(__file__).resolve().parents[1]
            / "templates"
            / "lab"
            / "tabs"
            / "_target.html"
        ).read_text(encoding="utf-8")
        for element_id in (
            'id="target-live-view"',
            'id="target-preview-tab-map"',
            'id="target-preview-tab-live"',
            'id="target-live-pane"',
            'id="target-live-img"',
            'id="target-live-box"',
            'id="target-live-cursor"',
            'id="target-live-log"',
            'id="target-live-take-control"',
            'id="target-live-resume-crawl"',
            'id="target-live-control-bar"',
        ):
            self.assertIn(element_id, template)

    def test_control_rejects_get_and_invalid_inputs(self):
        self.assertEqual(self.client.get("/api/target-browser/control").status_code, 405)
        self.assertEqual(
            self.client.post(
                "/api/target-browser/control",
                data={"job_id": "../evil", "action": "take_control"},
                content_type="application/json",
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                "/api/target-browser/control",
                data={"job_id": "job42", "action": "eval_js"},
                content_type="application/json",
            ).status_code,
            400,
        )

    @patch("lab.views.call_browser_worker")
    def test_control_proxies_take_click_and_resume(self, mock_post):
        mock_post.return_value = (200, {"ok": True, "manual_control": True, "seq": 9})
        resp = self.client.post(
            "/api/target-browser/control",
            data={"job_id": "job42", "action": "click", "x": 150, "y": 210},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        mock_post.assert_called_once_with(
            "/target/job42/control",
            {"action": "click", "x": 150, "y": 210},
        )
        self.assertTrue(resp.json()["manual_control"])
