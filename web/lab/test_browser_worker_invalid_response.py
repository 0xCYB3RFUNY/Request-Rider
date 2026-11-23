"""Regression: browser-worker answering with an empty / non-JSON body must not crash the gateway (500)."""

import io
from unittest.mock import patch

from django.test import SimpleTestCase

from lab import views


class _FakeResponse(io.BytesIO):
    def __init__(self, body, status=200):
        super().__init__(body)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class BrowserWorkerInvalidResponseTests(SimpleTestCase):
    def test_get_helper_maps_empty_body_to_502(self):
        with patch("lab.views.urlopen", return_value=_FakeResponse(b"")):
            status, payload = views.call_browser_worker_get("/health")
        self.assertEqual(status, 502)
        self.assertEqual(payload["reason"], "BROWSER_WORKER_INVALID_RESPONSE")

    def test_post_helper_maps_html_body_to_502(self):
        with patch("lab.views.urlopen", return_value=_FakeResponse(b"<html>not json</html>")):
            status, payload = views.call_browser_worker("/target", {"url": "http://x.test"})
        self.assertEqual(status, 502)
        self.assertEqual(payload["reason"], "BROWSER_WORKER_INVALID_RESPONSE")

    def test_delete_helper_maps_empty_body_to_502(self):
        with patch("lab.views.urlopen", return_value=_FakeResponse(b"")):
            status, payload = views.call_browser_worker_delete("/target/abc")
        self.assertEqual(status, 502)
        self.assertEqual(payload["reason"], "BROWSER_WORKER_INVALID_RESPONSE")

    def test_target_browsers_endpoint_returns_502_on_empty_worker_body(self):
        with patch("lab.views.urlopen", return_value=_FakeResponse(b"")):
            response = self.client.get("/api/target-browsers")
        self.assertEqual(response.status_code, 502)
        body = response.json()
        self.assertEqual(body["browsers"], [])
        self.assertEqual(body["reason"], "BROWSER_WORKER_UNAVAILABLE")
        self.assertIn("non-JSON", body["error"])

    def test_target_browsers_endpoint_survives_non_object_json(self):
        with patch("lab.views.urlopen", return_value=_FakeResponse(b"[1, 2, 3]")):
            response = self.client.get("/api/target-browsers")
        self.assertEqual(response.status_code, 502)
        body = response.json()
        self.assertEqual(body["browsers"], [])
        self.assertEqual(body["reason"], "BROWSER_WORKER_UNAVAILABLE")
