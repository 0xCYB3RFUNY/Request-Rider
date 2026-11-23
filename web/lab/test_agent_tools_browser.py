"""Regression tests for the typed browser tools of the in-app AI agent.

The tools are the only path from model output to a browser action, so the tests
hold three invariants: they are registered in the shared registry, they fail
closed without explicit operator consent, and their observations never carry
raw page bytes back into the model context.
"""

import unittest
from unittest import mock

from django.test import TestCase

from . import agent_tools
from . import agent_tools_browser as browser_tools

CONSENT = {"allow_browser_tools": True}


class BrowserToolRegistrationTests(unittest.TestCase):
    def test_all_browser_tools_are_registered(self):
        names = set(browser_tools.HANDLERS)
        self.assertEqual(len(names), 16)
        self.assertTrue(names.issubset(set(agent_tools.TOOL_HANDLERS)))
        schemas = {
            item.get("function", {}).get("name")
            for item in agent_tools.TOOL_DEFINITIONS
            if item.get("type") == "function"
        }
        self.assertTrue(names.issubset(schemas))


class BrowserToolBoundaryTests(unittest.TestCase):
    def test_open_fails_closed_without_consent(self):
        with mock.patch("lab.views.call_browser_worker") as worker:
            result = browser_tools.tool_browser_open(
                {"url": "http://example.test/"}, context=None)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], browser_tools.CONSENT_REASON)
        worker.assert_not_called()

    def test_control_fails_closed_without_consent(self):
        with mock.patch("lab.views.call_browser_worker") as worker:
            result = browser_tools.tool_browser_click(
                {"job_id": "job1", "selector": "#submit"}, context={})
        self.assertEqual(result["reason"], browser_tools.CONSENT_REASON)
        worker.assert_not_called()

    def test_open_rejects_non_http_url_before_any_side_effect(self):
        with mock.patch("lab.views.call_browser_worker") as worker:
            result = browser_tools.tool_browser_open(
                {"url": "javascript:alert(1)"}, context=CONSENT)
        self.assertEqual(result["reason"], "INVALID_URL")
        worker.assert_not_called()

    def test_open_rejects_unknown_browser(self):
        with mock.patch("lab.views.call_browser_worker") as worker:
            result = browser_tools.tool_browser_open(
                {"url": "http://example.test/", "browser": "safari"}, context=CONSENT)
        self.assertEqual(result["reason"], "INVALID_BROWSER")
        worker.assert_not_called()

    def test_open_uses_the_recording_proxy(self):
        with mock.patch("lab.views.call_browser_worker", return_value=(202, {"job_id": "job1"})) as worker, \
             mock.patch("lab.views.TargetJob.objects.create"):
            result = browser_tools.tool_browser_open(
                {"url": "http://example.test/"}, context=CONSENT)
        self.assertEqual(result["status"], "success")
        payload = worker.call_args.args[1]
        self.assertTrue(payload["proxy_mitm_ca"])
        self.assertTrue(payload["proxy_server"])
        self.assertTrue(payload["live_view"])

    def test_fill_bounds_and_never_echoes_the_value(self):
        secret = "s3cr3t-payload-" + "x" * 600
        with mock.patch("lab.views.call_browser_worker", return_value=(200, {"seq": 3})) as worker:
            result = browser_tools.tool_browser_fill(
                {"job_id": "job1", "selector": "s" * 300, "value": secret}, context=CONSENT)
        self.assertEqual(result["status"], "success")
        self.assertNotIn(secret, result["summary"])
        control = worker.call_args.args[1]
        self.assertEqual(len(control["selector"]), browser_tools.SELECTOR_MAX)
        self.assertEqual(len(control["value"]), browser_tools.VALUE_MAX)

    def test_screenshot_returns_artifact_without_base64(self):
        frame = {"seq": 7, "url": "http://example.test/", "mime": "image/jpeg", "image_b64": "QUJD" * 100}
        with mock.patch("lab.views.call_browser_worker_get", return_value=(200, {"frame": frame})):
            result = browser_tools.tool_browser_screenshot({"job_id": "job1"}, context=CONSENT)
        self.assertEqual(result["status"], "success")
        self.assertNotIn("image_b64", result)
        self.assertNotIn("QUJD", str(result))
        self.assertEqual(result["artifacts"][0]["type"], "live_frame")
        self.assertEqual(result["artifacts"][0]["seq"], 7)

    def test_invalid_job_id_is_rejected(self):
        with mock.patch("lab.views.call_browser_worker") as worker:
            result = browser_tools.tool_browser_key(
                {"job_id": "../evil", "key": "Enter"}, context=CONSENT)
        self.assertEqual(result["reason"], "INVALID_JOB_ID")
        worker.assert_not_called()

    def test_verified_finding_requires_a_poc(self):
        project = mock.MagicMock(id=1, target="http://example.test")
        with mock.patch("lab.models.ScannerRun") as run:
            result = browser_tools.tool_browser_finding_record(
                {"title": "XSS", "severity": "HIGH", "description": "reflected", "verification": "verified"},
                context={**CONSENT, "active_project": project})
        self.assertEqual(result["reason"], "PROOF_REQUIRED")
        run.objects.filter.assert_not_called()

    def test_finding_record_binds_browser_evidence(self):
        project = mock.MagicMock(id=1, target="http://example.test")
        run = mock.MagicMock()
        with mock.patch("lab.models.ScannerRun") as model:
            model.objects.filter.return_value.order_by.return_value.first.return_value = run
            result = browser_tools.tool_browser_finding_record(
                {"title": "XSS", "severity": "HIGH", "description": "reflected",
                 "verification": "verified", "poc": "GET /?q=<img>", "browser_job_id": "jobQA1",
                 "url": "http://example.test"},
                context={**CONSENT, "active_project": project})
        self.assertEqual(result["status"], "success")
        finding = run.upsert_findings.call_args.args[0][0]
        self.assertEqual(finding["poc"], "GET /?q=<img>")
        self.assertEqual(finding["verification"], "verified")
        self.assertEqual(finding["browser_job_id"], "jobQA1")

    def test_coverage_reads_project_records_without_a_new_endpoint(self):
        project = mock.MagicMock(id=1)
        with mock.patch("lab.models.TargetJob") as jobs, \
             mock.patch("lab.models.ScannerRun") as runs, \
             mock.patch("lab.models.ProjectEndpoint") as endpoints, \
             mock.patch("lab.models.OsintGraph") as graphs:
            jobs.objects.filter.return_value.values.return_value.__getitem__.return_value = [
                {"status": "completed", "engine_kind": "browser"}]
            run_qs = runs.objects.filter.return_value.only.return_value.order_by.return_value
            run_qs.__getitem__.return_value = [mock.MagicMock(findings=[{"verification": "verified"}])]
            endpoints.objects.filter.return_value.count.return_value = 4
            graphs.objects.filter.return_value.count.return_value = 2
            result = browser_tools.tool_browser_coverage({}, context={**CONSENT, "active_project": project})
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["endpoints"], 4)
        self.assertEqual(result["verification"]["verified"], 1)
        self.assertEqual(result["osint_graphs"], 2)

    def test_every_observation_has_the_agent_contract(self):
        for handler in browser_tools.HANDLERS.values():
            with self.subTest(handler=handler.__name__):
                result = handler({}, context=None)
                for key in ("status", "summary", "next_actions", "artifacts"):
                    self.assertIn(key, result)


class IntentQueueTests(TestCase):
    """The planner/worker queue reuses Workflow models without changing their API."""

    def _project(self):
        from .models import Project
        return Project.objects.create(name="QA plan", target="http://example.test")

    def test_plan_claim_complete_and_trace(self):
        project = self._project()
        planned = browser_tools.tool_goal_plan(
            {"goal": "перевірити вхід", "intents": [{"goal": "login"}, {"goal": "idor"}]},
            context={**CONSENT, "active_project": project})
        self.assertEqual(planned["status"], "success")
        plan_id = planned["plan_id"]

        first = browser_tools.tool_intent_claim({"plan_id": plan_id}, context=CONSENT)
        second = browser_tools.tool_intent_claim({"plan_id": plan_id}, context=CONSENT)
        self.assertEqual(first["intent"], "login")
        self.assertEqual(second["intent"], "idor")
        self.assertNotEqual(first["node_id"], second["node_id"])

        done1 = browser_tools.tool_intent_complete(
            {"plan_id": plan_id, "node_id": first["node_id"], "result": {"found": "form"}},
            context=CONSENT)
        self.assertFalse(done1["plan_completed"])
        done2 = browser_tools.tool_intent_complete(
            {"plan_id": plan_id, "node_id": second["node_id"], "result": {"found": "idor"}},
            context=CONSENT)
        self.assertTrue(done2["plan_completed"])

        trace = browser_tools.tool_worker_trace_search(
            {"plan_id": plan_id, "query": "idor"}, context=CONSENT)
        self.assertGreaterEqual(len(trace["rows"]), 1)
        # No third intent to claim.
        empty = browser_tools.tool_intent_claim({"plan_id": plan_id}, context=CONSENT)
        self.assertIn("No pending", empty["summary"])

    def test_plan_fails_closed_without_consent(self):
        with mock.patch("lab.models.Workflow.objects.create") as create:
            result = browser_tools.tool_goal_plan(
                {"goal": "x", "intents": [{"goal": "y"}]}, context=None)
        self.assertEqual(result["reason"], browser_tools.CONSENT_REASON)
        create.assert_not_called()


class AllBrowserToolsContractTests(unittest.TestCase):
    """Every exposed browser tool must honour the observation contract.

    Handlers are called with no consent, so the only reachable path is the
    fail-closed one — no network, no browser job is started. This proves each
    name resolves to a real callable and returns a bounded envelope.
    """

    def test_every_handler_is_callable_and_bounded(self):
        from .agent_ref_tools import HANDLERS as REF_HANDLERS
        registry = {**browser_tools.HANDLERS, **REF_HANDLERS}
        for name, handler in registry.items():
            with self.subTest(tool=name):
                result = handler({}, context=None)
                self.assertIsInstance(result, dict)
                for key in ("status", "summary", "next_actions", "artifacts"):
                    self.assertIn(key, result)
                self.assertLessEqual(len(result["summary"]), 500)

    def test_navigate_read_dom_close_retest_names_resolve(self):
        for name in ("browser_navigate", "browser_read_dom", "browser_close", "browser_retest"):
            with self.subTest(tool=name):
                self.assertIn(name, browser_tools.HANDLERS)
                self.assertTrue(callable(browser_tools.HANDLERS[name]))


if __name__ == "__main__":
    unittest.main()
