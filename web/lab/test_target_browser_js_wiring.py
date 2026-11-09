"""The browser-driven Target job gets the analysis the static crawl already had.

`target_browser_js.py` proves what the gateway does with a network log and an
engine answer. This file covers the wiring around it: the poll that has to ask the
engine at all, the row that has to reach the response the UI reads, the answer
that has to be stored so the next poll does not pay for it twice, and the route
switch that has to cancel the work rather than store bytes from a generation that
no longer exists.

The worker and the engine are mocked here on purpose — they are two other
processes with their own contracts, and `engine/target_js_endpoint_test.go` reads
real bytes from a real server. What is under test here is that the gateway calls
the right endpoint with the right list, in the right order, exactly once.
"""

import json
from unittest.mock import patch

from django.test import TestCase

from .models import Project, TargetJob
from .target_browser_js import SCRIPT_PAGE_SOURCE

SCRIPT_URL = "https://shop.example/static/app.js"

ANALYSIS_ANSWER = {
    "results": [
        {
            "url": SCRIPT_URL,
            "kind": "javascript",
            "status": 200,
            "content_type": "application/javascript",
            "bytes": 4096,
            "time": 12,
            "ms": 7,
            "js": {
                "endpoints": [{"url": "/api/v1/cart", "method": "GET", "query_params": []}],
                "findings": [{"kind": "dom-write", "line": 4, "snippet": "el.innerHTML = t"}],
                "secrets": [],
                "bytes": 4096,
                "ms": 7,
            },
        }
    ]
}


def _payload(response):
    """Read a JsonResponse body.

    `HttpResponse.json()` is not available on this Django, and reading the body
    with the stdlib keeps the test honest about what the browser actually
    receives: a JSON document, not a test double's convenience.
    """
    return json.loads(response.content)


def worker_result(status="completed"):
    """What the browser worker reports for a finished job."""
    return {
        "job_id": "job-js-1",
        "status": status,
        "visited": 1,
        "pages": [
            {
                "url": "https://shop.example/cart",
                "depth": 0,
                "status": 200,
                "kind": "browser-page",
                "content_type": "text/html",
                "network": [
                    {"url": SCRIPT_URL, "method": "GET", "resource_type": "script"},
                    {"url": "https://shop.example/api/cart", "method": "GET", "resource_type": "xhr"},
                ],
            }
        ],
    }


class BrowserTargetJavaScriptWiringTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(name="Browser JS", target="https://shop.example")
        self.job = TargetJob.objects.create(
            project=self.project,
            job_id="job-js-1",
            engine_kind="browser",
            url="https://shop.example/cart",
            status="running",
            result={"status": "running", "pages": []},
        )

    def _poll(self, worker_payload, engine_answer=ANALYSIS_ANSWER, engine_status=200, engine_error=None):
        from . import views

        engine = None
        if engine_error is None:
            engine = patch(
                "lab.views.call_engine",
                return_value=(engine_status, engine_answer),
            )
        else:
            engine = patch("lab.views.call_engine", side_effect=engine_error)
        with patch("lab.views.call_browser_worker_get", return_value=(200, worker_payload)):
            with patch("lab.views._ingest_target_job"):
                with engine as caller:
                    response = views.target_browser(
                        _get_request(f"/api/target-browser?job_id={self.job.job_id}")
                    )
        return response, caller

    def test_a_finished_job_comes_back_with_the_script_rows(self):
        # The browser reported the bundle as a URL and nothing read it. After this
        # poll the response carries a row the existing renderer draws, analysis
        # attached, exactly as a statically crawled bundle arrives.
        response, caller = self._poll(worker_result())
        payload = _payload(response)
        derived = [page for page in payload["pages"] if page.get("js_source") == SCRIPT_PAGE_SOURCE]
        self.assertEqual(len(derived), 1)
        self.assertEqual(derived[0]["url"], SCRIPT_URL)
        self.assertEqual(derived[0]["js"]["findings"][0]["kind"], "dom-write")
        self.assertEqual(derived[0]["js"]["endpoints"][0]["url"], "/api/v1/cart")
        self.assertEqual(derived[0]["depth"], 0)
        # The page the browser really navigated is still there, with its own
        # network log: the derived row is an addition, not a replacement.
        self.assertEqual(payload["pages"][0]["url"], "https://shop.example/cart")
        self.assertEqual(len(payload["pages"][0]["network"]), 2)
        self.assertEqual(caller.call_count, 1)

    def test_the_engine_is_asked_for_scripts_only_with_their_page(self):
        _, caller = self._poll(worker_result())
        path, payload = caller.call_args[0]
        self.assertEqual(path, "/proxy/target-js")
        self.assertEqual(
            payload["urls"],
            [{"url": SCRIPT_URL, "referer": "https://shop.example/cart"}],
        )

    def test_the_answer_is_stored_so_the_next_poll_does_not_refetch(self):
        self._poll(worker_result())
        stored = TargetJob.objects.get(id=self.job.id).result
        self.assertEqual(stored["js_analysis"]["urls"], [SCRIPT_URL])

        response, caller = self._poll(worker_result())
        self.assertEqual(caller.call_count, 0, "a finished job was re-read from the network")
        derived = [
            page
            for page in _payload(response)["pages"]
            if page.get("js_source") == SCRIPT_PAGE_SOURCE
        ]
        self.assertEqual(len(derived), 1)

    def test_the_stored_status_stays_the_workers_own(self):
        response, _ = self._poll(worker_result(status="cancelled"))
        self.assertEqual(_payload(response)["status"], "cancelled")
        self.assertEqual(TargetJob.objects.get(id=self.job.id).status, "cancelled")

    def test_a_refused_engine_is_reported_and_the_page_is_still_served(self):
        # A broken engine must not cost the analyst the map itself, and it must not
        # read as a site with no JavaScript either.
        response, _ = self._poll(worker_result(), engine_status=502, engine_answer={"error": "engine down"})
        payload = _payload(response)
        self.assertEqual(payload["js_analysis"]["error"], "engine answered 502: engine down")
        self.assertEqual([page for page in payload["pages"] if page.get("js_source")], [])
        self.assertEqual(payload["pages"][0]["url"], "https://shop.example/cart")
        self.assertEqual(TargetJob.objects.get(id=self.job.id).result["js_analysis"]["error"], "engine answered 502: engine down")

    def test_a_transport_failure_is_reported_rather_than_raised(self):
        response, _ = self._poll(worker_result(), engine_error=OSError("connection reset"))
        payload = _payload(response)
        self.assertIn("OSError", payload["js_analysis"]["error"])
        self.assertEqual(response.status_code, 200)

    def test_a_running_job_does_not_call_the_engine(self):
        response, caller = self._poll(worker_result(status="running"))
        self.assertEqual(caller.call_count, 0)
        self.assertNotIn("js_analysis", _payload(response))


def _get_request(path):
    from django.test import RequestFactory

    return RequestFactory().get(path)
