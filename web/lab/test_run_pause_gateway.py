"""Tests for pausing, resuming and resending through the gateway.

The gateway is where a long run is made recoverable from: it is the layer that
survives a browser reload, and the layer that has to write down where a run broke
while the run is still going. The engine hop is mocked in its own namespace for the
same reason the rest of this suite mocks it that way — patching `lab.views` would
leave the real call in `lab.active_scanner_views` untouched and the test green
against code that never runs.
"""

import json

from django.test import Client, TestCase
from unittest import mock

from lab.models import ActiveScanJob, Project, TargetJob


def engine_snapshot(state="running", **extra):
    """A poll answer shaped like the engine's, with a frontier in it."""
    checkpoint = {
        "paused": state == "paused",
        "pause_reason": extra.pop("pause_reason", ""),
        "dropped_probes": extra.pop("dropped_probes", 0),
        "failure_pause": extra.pop("failure_pause", 20),
        "consecutive_failures": extra.pop("consecutive_failures", 0),
        "failures_total": extra.pop("failures_total", 0),
        "failure_classes": extra.pop("failure_classes", {}),
        "recorded_failures": extra.pop("recorded_failures", 0),
    }
    snapshot = {"job_id": "active-1", "state": state, "checkpoint": checkpoint}
    snapshot.update(extra)
    return snapshot


class ActiveScanPauseGatewayTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.project = Project.objects.create(name="QA", target="fixture.local")
        session = self.client.session
        session["active_project_id"] = self.project.id
        session.save()
        ActiveScanJob.objects.all().delete()
        self.job = ActiveScanJob.objects.create(
            project=self.project, job_id="active-1", url="https://fixture.local/"
        )

    def _post(self, action, body=None):
        with mock.patch("lab.active_scanner_views.call_engine") as engine:
            engine.return_value = (200, engine_snapshot())
            response = self.client.post(
                f"/api/scanner/active/jobs/active-1/{action}",
                data=json.dumps(body or {}),
                content_type="application/json",
            )
        return response, engine

    def test_pause_is_forwarded_and_recorded_as_a_pause(self):
        response, engine = self._post("pause")
        self.assertEqual(response.status_code, 200)
        forwarded = engine.call_args[0][1]
        self.assertEqual(forwarded, {})
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, "paused")

    def test_resume_puts_the_row_back_to_running(self):
        response, _ = self._post("resume")
        self.assertEqual(response.status_code, 200)
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, "running")

    def test_a_resend_reaches_the_engine_with_the_operators_limit(self):
        response, engine = self._post("resend", {"limit": 25, "reason": "route fixed"})
        self.assertEqual(response.status_code, 200)
        url, body = engine.call_args[0][0], engine.call_args[0][1]
        self.assertTrue(url.endswith("/active-1/resend"))
        self.assertEqual(body["limit"], 25)
        self.assertEqual(body["reason"], "route fixed")

    def test_a_refused_bound_reaches_the_operator_unchanged(self):
        # The engine owns the bound and refuses a negative one. The gateway's job is
        # to pass that refusal through rather than reinterpret the number — a
        # gateway that "helpfully" clamped it would be spending requests nobody
        # asked for while showing the operator a resend that never ran.
        with mock.patch("lab.active_scanner_views.call_engine") as engine:
            engine.return_value = (400, {"error": "limit must not be negative",
                                         "reason": "INVALID_RESEND"})
            response = self.client.post(
                "/api/scanner/active/jobs/active-1/resend",
                data=json.dumps({"limit": -5}),
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["reason"], "INVALID_RESEND")
        forwarded = engine.call_args[0][1]
        self.assertEqual(forwarded["limit"], -5, "the gateway rewrote the operator's number")

    def test_an_unknown_action_never_reaches_the_engine(self):
        with mock.patch("lab.active_scanner_views.call_engine") as engine:
            response = self.client.post("/api/scanner/active/jobs/active-1/detonate")
        self.assertEqual(response.status_code, 400)
        engine.assert_not_called()

    def test_the_frontier_is_written_while_the_run_is_still_going(self):
        with mock.patch("lab.active_scanner_views.call_engine_get") as engine_get:
            engine_get.return_value = (
                200,
                engine_snapshot(
                    state="paused",
                    pause_reason="auto: 20 consecutive transport failures",
                    consecutive_failures=20,
                    failures_total=248,
                    failure_classes={"timeout": 185, "pool_exhausted": 63},
                ),
            )
            response = self.client.get("/api/scanner/active/jobs/active-1")
        self.assertEqual(response.status_code, 200)
        self.job.refresh_from_db()
        checkpoint = self.job.checkpoint
        self.assertTrue(checkpoint["paused"], "the stored frontier does not say the run is paused")
        self.assertIn("consecutive transport failures", checkpoint["pause_reason"])
        self.assertEqual(checkpoint["failures_total"], 248)
        self.assertEqual(checkpoint["failure_classes"]["pool_exhausted"], 63)

    def test_the_threshold_the_run_is_using_travels_with_the_start(self):
        with mock.patch("lab.active_scanner_views.call_engine") as engine:
            engine.return_value = (202, {"job_id": "active-2", "state": "queued"})
            response = self.client.post(
                "/api/scanner/active/jobs",
                data=json.dumps(
                    {
                        "url": "https://fixture.local/",
                        "failure_pause": 5,
                        "recorded_failures": 50,
                    }
                ),
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 202)
        forwarded = engine.call_args[0][1]
        self.assertEqual(forwarded["failure_pause"], 5)
        self.assertEqual(forwarded["recorded_failures"], 50)


class TargetPauseGatewayTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.project = Project.objects.create(name="QA", target="fixture.local")
        session = self.client.session
        session["active_project_id"] = self.project.id
        session.save()
        TargetJob.objects.all().delete()
        TargetJob.objects.create(
            project=self.project,
            job_id="42",
            engine_kind="static",
            url="https://fixture.local/",
            status="running",
        )

    def _post(self, action):
        with mock.patch("lab.views.call_engine") as engine:
            engine.return_value = (200, {"map_id": 42, "status": "paused", "visited": 7,
                                         "checkpoint": {"paused": True, "pause_reason": "operator",
                                                        "failures_total": 3}})
            response = self.client.post(f"/api/target-map/42/{action}")
        return response, engine

    def test_pause_and_resume_are_forwarded_and_recorded(self):
        response, engine = self._post("pause")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(engine.call_args[0][0].endswith("/proxy/target-map/42/pause"))
        job = TargetJob.objects.get(job_id="42")
        self.assertEqual(job.status, "paused")
        self.assertTrue(job.checkpoint["paused"])

        response, engine = self._post("resume")
        self.assertEqual(response.status_code, 200)
        job.refresh_from_db()
        self.assertEqual(job.status, "running")

    def test_an_unknown_crawl_action_is_refused(self):
        with mock.patch("lab.views.call_engine") as engine:
            response = self.client.post("/api/target-map/42/detonate")
        self.assertEqual(response.status_code, 400)
        engine.assert_not_called()

    def test_the_poll_stores_the_frontier_so_a_reload_can_show_it(self):
        with mock.patch("lab.views.call_engine_get") as engine_get:
            engine_get.return_value = (
                200,
                {
                    "map_id": 42,
                    "status": "paused",
                    "visited": 7,
                    "pages": [],
                    "checkpoint": {
                        "paused": True,
                        "pause_reason": "auto: 20 consecutive transport failures",
                        "failures_total": 20,
                        "failure_classes": {"timeout": 20},
                        "first_failure": {"url": "https://fixture.local/a", "class": "timeout"},
                    },
                },
            )
            response = self.client.get("/api/target-map/42")
        self.assertEqual(response.status_code, 200)
        job = TargetJob.objects.get(job_id="42")
        self.assertEqual(job.status, "paused")
        self.assertEqual(job.checkpoint["failures_total"], 20)
        self.assertEqual(
            job.checkpoint["first_failure"]["url"], "https://fixture.local/a"
        )

    def test_non_terminal_poll_does_not_rewrite_full_result_blob(self):
        job = TargetJob.objects.get(job_id="42")
        job.result = {"initial": True}
        job.save(update_fields=["result"])
        with mock.patch("lab.views.call_engine_get") as engine_get:
            engine_get.return_value = (
                200,
                {
                    "map_id": 42,
                    "status": "running",
                    "visited": 15,
                    "pages": [{"url": "https://fixture.local/heavy"}],
                    "checkpoint": {"paused": False, "failures_total": 1},
                },
            )
            response = self.client.get("/api/target-map?map_id=42")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["visited"], 15)
        job.refresh_from_db()
        self.assertEqual(job.result, {"initial": True})
        self.assertEqual(job.checkpoint["failures_total"], 1)

        with mock.patch("lab.views.call_engine_get") as engine_get:
            engine_get.return_value = (
                200,
                {
                    "map_id": 42,
                    "status": "completed",
                    "visited": 15,
                    "pages": [{"url": "https://fixture.local/heavy"}],
                    "checkpoint": {"paused": False, "failures_total": 1},
                },
            )
            response = self.client.get("/api/target-map?map_id=42")
        self.assertEqual(response.status_code, 200)
        job.refresh_from_db()
        self.assertEqual(job.status, "completed")
        self.assertEqual(job.result["visited"], 15)

    def test_browser_crawl_poll_writes_full_result_only_on_terminal_state(self):
        browser_job = TargetJob.objects.create(
            project=self.project,
            job_id="b-1",
            engine_kind="browser",
            url="https://fixture.local/",
            status="running",
            result={"initial": True},
        )
        with mock.patch("lab.views.call_browser_worker_get") as worker_get, mock.patch(
            "lab.views._analyze_browser_job_scripts"
        ) as analyze_scripts:
            worker_get.return_value = (
                200,
                {"job_id": "b-1", "status": "running", "pages": [{"url": "https://fixture.local/"}]},
            )
            response = self.client.get("/api/target-browser?job_id=b-1")
            self.assertEqual(response.status_code, 200)
            analyze_scripts.assert_not_called()
            browser_job.refresh_from_db()
            self.assertEqual(browser_job.result, {"initial": True})

            worker_get.return_value = (
                200,
                {"job_id": "b-1", "status": "completed", "pages": [{"url": "https://fixture.local/"}]},
            )
            analyze_scripts.side_effect = lambda res, _job: res
            response = self.client.get("/api/target-browser?job_id=b-1")
            self.assertEqual(response.status_code, 200)
            analyze_scripts.assert_called_once()
            browser_job.refresh_from_db()
            self.assertEqual(browser_job.status, "completed")
            self.assertEqual(browser_job.result["status"], "completed")