"""The template-run endpoints must answer the UI's own request shape.

WHY THIS FILE EXISTS. Every Scanner template endpoint the browser calls posts
JSON without an `X-CSRFToken` header — measured in `index.html`: the `jobs`,
`jobs-dir` and `inspect` calls send only `Content-Type`. Django's
`CsrfViewMiddleware` is installed, so a view without `@csrf_exempt` answers **403
CSRF verification failed** before its first line runs.

Measured on a live isolated stand before this test existed:

    POST /api/scanner/nuclei/jobs       -> 403  CSRF verification failed
    POST /api/scanner/nuclei/run-dir    -> 403  CSRF verification failed
    POST /api/scanner/nuclei/run        -> 403  CSRF verification failed
    POST /api/scanner/nuclei/inspect    -> 403  CSRF verification failed
    POST /api/scanner/nuclei/jobs-dir   -> 202  (had the exemption)

So `Run templates` could not start a run and `Inspect` could not report what a
folder holds. Django's own test `Client()` hides this: `enforce_csrf_checks`
defaults to `False`, which is why `python manage.py test` was green while the
button was dead in the browser. Every client in this file therefore sets
`enforce_csrf_checks=True`, so the test sees the shape the browser sends.

WHAT IS NOT BEING GIVEN UP. `@csrf_exempt` is the documented arrangement of this
gateway — see the comment block in `web/lab/middleware.py`, which records why the
exemptions exist and what replaced them: `SameOriginMutationMiddleware` refuses a
state-changing request whose `Origin` is not the tool's own address. The two
tests below are the pair that matters: the endpoint answers the UI's request, and
it still refuses a foreign origin. Removing the exemption therefore removes CSRF
and this file goes red, which is the point.
"""

import json
from unittest.mock import patch

from django.test import Client, TestCase


class NucleiTemplateRunCsrfTests(TestCase):
    """The endpoints the Scanner panel calls, tested the way the panel calls them."""

    def setUp(self):
        # `enforce_csrf_checks=True` is the whole reason this file exists: without
        # it Django never checks a token and every test below passes on a view
        # that answers 403 to the real browser.
        self.client = Client(enforce_csrf_checks=True)
        self.client.get("/")

    def post_json(self, path, payload, **extra):
        return self.client.post(
            path, data=json.dumps(payload), content_type="application/json", **extra
        )

    @patch("lab.views.call_engine")
    def test_starting_a_template_job_answers_the_request_the_ui_sends(self, call_engine):
        call_engine.return_value = (202, {"job_id": "job-1", "state": "queued"})
        response = self.post_json(
            "/api/scanner/nuclei/jobs",
            {"url": "http://127.0.0.1:9/", "upload_id": "up-1", "options": {}},
        )
        self.assertEqual(response.status_code, 202, response.content[:200])

    @patch("lab.views.call_engine")
    def test_running_a_named_folder_answers_the_request_the_ui_sends(self, call_engine):
        call_engine.return_value = (202, {"job_id": "job-2", "state": "queued"})
        response = self.post_json(
            "/api/scanner/nuclei/jobs-dir",
            {"url": "http://127.0.0.1:9/", "dir": "http/cves", "tags": [], "severity": []},
        )
        self.assertEqual(response.status_code, 202, response.content[:200])

    @patch("lab.views.call_engine")
    def test_inspecting_a_folder_answers_the_request_the_ui_sends(self, call_engine):
        call_engine.return_value = (200, {"path": "/c/http/cves", "total": 3, "valid": 3})
        response = self.post_json("/api/scanner/nuclei/inspect", {"dir": "http/cves"})
        self.assertEqual(response.status_code, 200, response.content[:200])
        self.assertEqual(response.json()["total"], 3)

    @patch("lab.views.call_engine")
    def test_the_synchronous_folder_run_answers_the_request_the_ui_sends(self, call_engine):
        call_engine.return_value = (200, {"templates": []})
        response = self.post_json(
            "/api/scanner/nuclei/run-dir", {"url": "http://127.0.0.1:9/", "dir": "http/cves"}
        )
        self.assertEqual(response.status_code, 200, response.content[:200])

    @patch("lab.views.call_engine")
    def test_the_upload_folder_run_answers_the_request_the_ui_sends(self, call_engine):
        call_engine.return_value = (200, {"templates": []})
        response = self.post_json(
            "/api/scanner/nuclei/run", {"url": "http://127.0.0.1:9/", "upload_id": "up-1"}
        )
        self.assertEqual(response.status_code, 200, response.content[:200])

    @patch("lab.views.call_engine")
    def test_pausing_a_running_job_answers_the_request_the_ui_sends(self, call_engine):
        call_engine.return_value = (200, {"ok": True})
        response = self.post_json("/api/scanner/nuclei/jobs/job-1/pause", {})
        self.assertEqual(response.status_code, 200, response.content[:200])

    # --- the gate that the exemption must not cost ---------------------------
    #
    # These are the negative half. `SameOriginMutationMiddleware` is what replaced
    # the token check, so "the endpoint answers" is only half the claim; the other
    # half is that a hostile page still cannot drive it.

    @patch("lab.views.call_engine")
    def test_a_foreign_origin_cannot_start_a_template_job(self, call_engine):
        call_engine.return_value = (202, {"job_id": "job-1"})
        response = self.post_json(
            "/api/scanner/nuclei/jobs",
            {"url": "http://127.0.0.1:9/", "upload_id": "up-1", "options": {}},
            HTTP_ORIGIN="https://evil.example",
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["reason"], "CROSS_ORIGIN_REFUSED")
        # The engine was never asked: a refused request must not start a scan.
        call_engine.assert_not_called()

    @patch("lab.views.call_engine")
    def test_a_foreign_origin_cannot_run_a_named_folder(self, call_engine):
        call_engine.return_value = (202, {"job_id": "job-2"})
        response = self.post_json(
            "/api/scanner/nuclei/jobs-dir",
            {"url": "http://127.0.0.1:9/", "dir": "http/cves", "tags": [], "severity": []},
            HTTP_ORIGIN="https://evil.example",
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["reason"], "CROSS_ORIGIN_REFUSED")
        call_engine.assert_not_called()

    @patch("lab.views.call_engine")
    def test_a_foreign_origin_cannot_cancel_a_running_job(self, call_engine):
        call_engine.return_value = (200, {"ok": True})
        response = self.post_json(
            "/api/scanner/nuclei/jobs/job-1/cancel",
            {},
            HTTP_ORIGIN="https://evil.example",
        )
        self.assertEqual(response.status_code, 403)
        call_engine.assert_not_called()

    @patch("lab.views.call_engine")
    def test_a_foreign_origin_cannot_inspect_a_folder(self, call_engine):
        call_engine.return_value = (200, {"total": 3})
        response = self.post_json(
            "/api/scanner/nuclei/inspect", {"dir": "http/cves"}, HTTP_ORIGIN="https://evil.example"
        )
        self.assertEqual(response.status_code, 403)
        call_engine.assert_not_called()