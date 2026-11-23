"""Gateway contract for the crawler's anti-detect parameter.

The browser crawler and the static crawler carry different parameters, and the
failure this file guards against is one of them silently receiving the other's.
A browser job with `retry_attempts` in it, or a static job with `anti_detect`,
would both be requests the engine has no field for — one of them would be
dropped, and the job would run with a default the analyst never chose.

The static crawler is also checked for refusing a negative retry count instead
of clamping it. A clamped bound is a cap nobody asked for, and the engine
refuses it too, so the gateway has to refuse it first.
"""

from unittest.mock import patch

import json

from django.test import TestCase

from .models import Workflow, WorkflowRun


def _context():
    workflow = Workflow.objects.create(name="Target params")
    run = WorkflowRun.objects.create(workflow=workflow, status="running")
    return {"run": run, "workflow": workflow, "node": {"id": "target-1"}, "input": {}}


class TargetBrowserParameterTests(TestCase):
    def _run_browser(self, params):
        from . import views

        context = _context()
        with patch("lab.views.call_engine_get", return_value=(200, {"address": ""})):
            with patch(
                "lab.views.call_browser_worker",
                return_value=(202, {"job_id": "job-1", "status": "running"}),
            ) as worker:
                with patch(
                    "lab.views.call_browser_worker_get",
                    return_value=(200, {"job_id": "job-1", "status": "completed", "pages": []}),
                ):
                    views._workflow_tool_runner(
                        "target_browser",
                        {"url": "http://127.0.0.1:9/fixture", **params},
                        context,
                    )
        return worker.call_args[0][1]

    def test_browser_node_sends_the_anti_detect_flag(self):
        payload = self._run_browser({"anti_detect": False})
        self.assertIs(payload["anti_detect"], False)
        # These belong to the browser worker alone. The static engine has no
        # field for them, and sending them would be a request with keys the
        # engine silently drops.
        self.assertNotIn("retry_attempts", payload)
        self.assertNotIn("accept_language", payload)

    def test_browser_node_defaults_anti_detect_on(self):
        payload = self._run_browser({})
        self.assertIs(payload["anti_detect"], True)

    def test_browser_node_carries_no_challenge_parameters(self):
        """The crawler drives pages as a person and does not answer challenges.

        Asserted as an absence rather than as a removed-key list: a field the
        worker no longer reads would be accepted here and dropped in silence,
        and the node would appear configured while changing nothing.
        """
        payload = self._run_browser({})
        for name in ("solve_challenges", "challenge_timeout_ms", "challenge_attempts"):
            self.assertNotIn(name, payload, name)


class TargetStaticParameterTests(TestCase):
    def _run_static(self, params):
        from . import views

        with patch(
            "lab.views.call_engine",
            return_value=(202, {"map_id": 7, "status": "running", "pages": []}),
        ) as engine:
            with patch(
                "lab.views.call_engine_get",
                return_value=(200, {"map_id": 7, "status": "completed", "pages": []}),
            ):
                views._workflow_tool_runner("target", params, _context())
        return engine.call_args[0][1]

    def test_static_node_sends_retry_attempts_and_no_language_by_default(self):
        payload = self._run_static({"url": "http://127.0.0.1:9/fixture"})
        self.assertEqual(payload["retry_attempts"], 0)
        # Identity is never invented: without an explicit language the header
        # is simply not sent, which is what the crawler did before the field
        # existed.
        self.assertNotIn("accept_language", payload)
        # The browser-only parameters must not leak into a static job.
        self.assertNotIn("anti_detect", payload)

    def test_static_node_carries_no_challenge_parameters(self):
        payload = self._run_static({"url": "http://127.0.0.1:9/fixture"})
        for name in ("solve_challenges", "challenge_timeout_ms", "challenge_attempts"):
            self.assertNotIn(name, payload, name)

    def test_static_node_sends_the_language_the_node_named(self):
        payload = self._run_static({
            "url": "http://127.0.0.1:9/fixture",
            "accept_language": "  uk-UA,uk;q=0.9  ",
            "retry_attempts": 2,
        })
        self.assertEqual(payload["accept_language"], "uk-UA,uk;q=0.9")
        self.assertEqual(payload["retry_attempts"], 2)

    def test_static_node_refuses_a_negative_retry_count(self):
        from . import views
        from .workflow_engine import WorkflowValidationError

        with self.assertRaises(WorkflowValidationError):
            views._workflow_tool_runner(
                "target",
                {"url": "http://127.0.0.1:9/fixture", "retry_attempts": -1},
                _context(),
            )

    def test_static_node_refuses_an_overlong_language(self):
        from . import views
        from .workflow_engine import WorkflowValidationError

        with self.assertRaises(WorkflowValidationError):
            views._workflow_tool_runner(
                "target",
                {"url": "http://127.0.0.1:9/fixture", "accept_language": "x" * 121},
                _context(),
            )


class TargetBrowserAvailabilityTests(TestCase):
    """The runtime dropdown must be able to tell the truth before a job fails.

    The browser worker has measured which runtimes this installation can start
    since 2026-10-02 and published it on `/health`. Nothing read it, so the
    Target dropdown offered five runtimes on a machine with two of them and the
    operator learned about the third one from a failed job, after typing the URL
    and pressing Build map.

    The contract these tests hold: the worker's measurement is passed through
    with its reasons intact, and a worker that cannot be reached is reported as
    a transport failure rather than as an installation with nothing in it.
    """

    def _get(self, status, payload):
        from . import views

        with patch("lab.views.call_browser_worker_get", return_value=(status, payload)) as worker:
            response = views.target_browsers(_get_request())
        return response, worker

    def test_the_measured_answer_is_passed_through_with_its_reasons(self):
        response, worker_call = self._get(
            200,
            {
                "ok": True,
                "browsers": ["firefox", "chromium"],
                "unavailable": {
                    "edge": "no edge at the path the driver checks",
                    "chrome": "no chrome at the path the driver checks",
                },
                "checked_at": "2026-10-03T12:04:29+00:00",
                "error": None,
            },
        )
        body = json.loads(response.content)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(worker_call.call_args[0][0], "/health")
        self.assertEqual(body["browsers"], ["firefox", "chromium"])
        self.assertIn("no edge", body["unavailable"]["edge"])
        self.assertEqual(body["checked_at"], "2026-10-03T12:04:29+00:00")

    def test_an_unreachable_worker_is_not_reported_as_an_empty_machine(self):
        """A transport failure must not read as "nothing is installed".

        Both answers are an empty `browsers` list, and they mean opposite things:
        one is an installation with no runtimes, the other is a question nobody
        managed to ask. The UI disables options from this payload, so collapsing
        them would empty a working dropdown because a poll failed.
        """
        response, _ = self._get(502, {"error": "browser worker unavailable", "reason": "X"})
        body = json.loads(response.content)
        self.assertEqual(response.status_code, 502)
        self.assertEqual(body["browsers"], [])
        self.assertEqual(body["reason"], "BROWSER_WORKER_UNAVAILABLE")
        self.assertIn("browser worker unavailable", body["error"])

    def test_a_failed_measurement_is_carried_as_the_workers_own_error(self):
        # The worker answers 200 with `browsers: []` and an `error` when its own
        # measurement raised. That is not a healthy machine and must not be
        # passed on as one, so the error travels.
        response, _ = self._get(200, {"browsers": [], "unavailable": {}, "error": "RuntimeError: x"})
        body = json.loads(response.content)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["error"], "RuntimeError: x")

    def test_non_string_names_cannot_reach_the_browser(self):
        """Every name and reason is stringified on the way out.

        The endpoint builds a JSON response straight from the worker's payload.
        A non-string key would raise `TypeError` inside `json.dumps` and turn a
        health answer into a 500, and a non-string value would render as
        `[object Object]` in the hint that exists to be read.
        """
        response, _ = self._get(200, {"browsers": [1, None], "unavailable": {2: 3}})
        body = json.loads(response.content)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body["browsers"], ["1", "None"])
        self.assertEqual(body["unavailable"], {"2": "3"})

    def test_a_non_get_method_is_refused(self):
        from . import views
        from django.test import RequestFactory

        response = views.target_browsers(
            RequestFactory().post("/api/target-browsers", data={}, content_type="application/json")
        )
        self.assertEqual(response.status_code, 405)
        json.loads(response.content)


def _get_request():
    from django.test import RequestFactory

    return RequestFactory().get("/api/target-browsers")