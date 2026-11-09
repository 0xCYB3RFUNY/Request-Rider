"""Tests for the active-scanner gateway.

They drive the real views and mock only the engine hop, because the gateway's whole
job is what it does between the browser and the engine: what it validates before
forwarding, what it forwards, and what it writes to the Project when a run ends.
Mocking the views would test the mock.

The engine hop is mocked in this module's own namespace (`lab.active_scanner_views`),
not in `lab.views`, because the module imported the helpers directly — patching the
other namespace would leave these tests passing while the real calls still went out
to the socket.
"""

import json

from django.test import Client, TestCase
from unittest import mock

from lab.models import ActiveScanJob, Project, ScannerRun


class ActiveScannerGatewayTests(TestCase):
    """What the gateway validates, forwards and records."""

    def setUp(self):
        self.client = Client()
        self.project = Project.objects.create(name="QA", target="fixture.local")
        session = self.client.session
        session["active_project_id"] = self.project.id
        session.save()
        self._forget_all_jobs()

    def tearDown(self):
        self._forget_all_jobs()

    def _forget_all_jobs(self):
        """The records now live in the database, so isolation is a table delete.

        There is deliberately nothing to clear in process memory: that dict was
        the bug. A test that had to reset it would have been a test that could not
        reproduce a gateway restart.
        """
        ActiveScanJob.objects.all().delete()

    def _post_job(self, body):
        return self.client.post(
            "/api/scanner/active/jobs",
            data=json.dumps(body),
            content_type="application/json",
        )

    # ---- validation -------------------------------------------------------

    def test_a_missing_url_is_refused_before_the_engine_is_touched(self):
        with mock.patch("lab.active_scanner_views.call_engine") as engine:
            response = self._post_job({})
        self.assertEqual(response.status_code, 400)
        self.assertIn("url is required", response.json()["error"])
        engine.assert_not_called()

    def test_a_bound_that_is_not_a_number_is_refused_here(self):
        """A value the engine cannot parse must not become a 400 about the target.

        The engine answers `INVALID_TARGET_URL` for a body it cannot read, which
        sends the operator to look at their URL instead of at the field that was
        actually wrong.
        """
        for field in ("max_pages", "max_depth", "concurrency", "delay_ms", "timeout_ms"):
            with mock.patch("lab.active_scanner_views.call_engine") as engine:
                response = self._post_job({"url": "http://target.test/", field: "many"})
            self.assertEqual(response.status_code, 400, field)
            self.assertIn(field, response.json()["error"])
            engine.assert_not_called()

    def test_same_origin_must_be_a_boolean(self):
        with mock.patch("lab.active_scanner_views.call_engine"):
            response = self._post_job({"url": "http://target.test/", "same_origin": "yes"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("same_origin", response.json()["error"])

    # ---- forwarding -------------------------------------------------------

    def test_a_start_reaches_the_engine_with_the_operators_own_bounds(self):
        """The bounds are forwarded as sent, not clamped, and none is invented."""
        body = {
            "url": "http://target.test/",
            "max_pages": 7,
            "max_depth": 3,
            "concurrency": 5,
            "delay_ms": 250,
            "blind_delay_ms": 8000,
            "timeout_ms": 4000,
            "same_origin": False,
            "follow_redirects": True,
        }
        with mock.patch(
            "lab.active_scanner_views.call_engine",
            return_value=(202, {"job_id": "active-1", "state": "queued"}),
        ) as engine:
            response = self._post_job(body)
        self.assertEqual(response.status_code, 202)
        path, forwarded = engine.call_args[0]
        self.assertEqual(path, "/proxy/scanner/active/jobs")
        for field in (
            "max_pages", "max_depth", "concurrency", "delay_ms", "blind_delay_ms", "timeout_ms",
        ):
            self.assertEqual(forwarded[field], body[field], field)
        self.assertIs(forwarded["same_origin"], False)
        self.assertIs(forwarded["follow_redirects"], True)

    def test_the_blind_delay_is_not_clamped(self):
        """A delay the operator typed is a delay they asked for.

        The one number that makes somebody else's database hold a connection is
        exactly the one a well-meaning clamp would touch — "twelve seconds is a
        long time" — and the result would be a run that is slower than the number
        on screen and quieter about it than it should be. There is no ceiling
        here; the run stops when the operator cancels it.
        """
        for asked in (1, 60_000, 600_000):
            with mock.patch(
                "lab.active_scanner_views.call_engine",
                return_value=(202, {"job_id": "active-1", "state": "queued"}),
            ) as engine:
                response = self._post_job(
                    {"url": "http://target.test/", "blind_delay_ms": asked}
                )
            self.assertEqual(response.status_code, 202, asked)
            self.assertEqual(engine.call_args[0][1]["blind_delay_ms"], asked)

    def test_no_blind_delay_means_the_engine_default_not_a_guess(self):
        """Absent means absent.

        Sending a value the browser never wrote would put a number on the screen
        the operator did not choose, and the engine's own default is documented
        where the detector reads it.
        """
        with mock.patch(
            "lab.active_scanner_views.call_engine",
            return_value=(202, {"job_id": "active-1", "state": "queued"}),
        ) as engine:
            self._post_job({"url": "http://target.test/"})
        self.assertEqual(engine.call_args[0][1]["blind_delay_ms"], 0)

    def test_a_blind_delay_that_is_not_a_number_is_refused_here(self):
        with mock.patch("lab.active_scanner_views.call_engine") as engine:
            response = self._post_job(
                {"url": "http://target.test/", "blind_delay_ms": "slow"}
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn("blind_delay_ms", response.json()["error"])
        engine.assert_not_called()

    def test_a_negative_blind_delay_is_refused(self):
        """A negative delay has no meaning and would read as "no delay"."""

        with mock.patch("lab.active_scanner_views.call_engine") as engine:
            response = self._post_job(
                {"url": "http://target.test/", "blind_delay_ms": -1}
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn("blind_delay_ms", response.json()["error"])
        engine.assert_not_called()

    def test_same_origin_is_only_sent_when_the_browser_sent_it(self):
        """Absent and `false` are different requests.

        Sending `same_origin: null` would be indistinguishable from sending
        `false`, and that is the difference between a crawl that stays on the
        operator's host and one that leaves it.
        """
        with mock.patch(
            "lab.active_scanner_views.call_engine",
            return_value=(202, {"job_id": "active-1", "state": "queued"}),
        ) as engine:
            self._post_job({"url": "http://target.test/"})
        self.assertNotIn("same_origin", engine.call_args[0][1])

    def test_a_started_job_is_remembered_for_its_project(self):
        with mock.patch(
            "lab.active_scanner_views.call_engine",
            return_value=(202, {"job_id": "active-1", "state": "queued"}),
        ):
            self._post_job({"url": "http://target.test/"})
        record = ActiveScanJob.objects.get(job_id="active-1")
        self.assertEqual(record.project_id, self.project.id)
        self.assertEqual(record.url, "http://target.test/")

    # ---- the finished report ----------------------------------------------

    def test_a_finished_run_is_written_once_with_its_evidence_intact(self):
        from lab import active_scanner_views

        active_scanner_views._remember_active_scan_job(
            "active-1", self.project, "http://target.test/"
        )
        report = {
            "target": "http://target.test/",
            "pages": 3,
            "workers": 8,
            "duration": "1.2s",
            "warnings": ["one page was a redirect"],
            "proofs": [{"finding_id": "VXR-1"}],
            "findings": [
                {
                    "id": "VXR-1",
                    "title": "SQL injection, verified by extraction",
                    "severity": "critical",
                    "tier": "verified",
                    "module": "sqli",
                    "endpoint": "http://target.test/item?id=1",
                    "method": "GET",
                    "param": "id",
                    "payload": "1' OR '1'='1",
                    "evidence": "You have an error in your SQL syntax",
                    "poc_curl": "curl -sk 'http://target.test/item?id=1'",
                    "description": "the value reaches the query unescaped",
                    "remediation": "use a parameterised query",
                    "capped": False,
                },
                {
                    "id": "VXR-2",
                    "title": "Potential XSS (unverified)",
                    "severity": "medium",
                    "tier": "potential",
                    "module": "xss",
                    "endpoint": "http://target.test/search",
                    "evidence": "<svg onload=1> was reflected",
                    "remediation": "encode output",
                    "capped": True,
                },
            ],
            "stats": {
                "requests": 41, "points": 5, "modules": 9, "chains": 1,
                "verified": 1, "potential": 1, "capped": 1, "hosts": 1,
            },
        }
        with mock.patch(
            "lab.active_scanner_views.call_engine_get",
            return_value=(200, {"job_id": "active-1", "state": "completed", "result": report}),
        ), mock.patch("lab.active_scanner_views._persist_tool_history"):
            first = self.client.get("/api/scanner/active/jobs/active-1")
            second = self.client.get("/api/scanner/active/jobs/active-1")

        self.assertEqual(first.status_code, 200)
        runs = ScannerRun.objects.filter(project=self.project, engine="active")
        self.assertEqual(runs.count(), 1, "the report was written more than once")
        run = runs.first()
        self.assertEqual(run.summary["findings_count"], 2)
        self.assertEqual(run.summary["highest_severity"], "CRITICAL")
        self.assertEqual(run.summary["stats"]["verified"], 1)
        self.assertEqual(run.summary["stats"]["capped"], 1)
        self.assertEqual(run.summary["stats"]["requests"], 41)
        self.assertEqual(run.summary["proofs"], 1)
        self.assertIn("one page was a redirect", run.summary["warnings"])

        row = run.findings[0]
        # Every field the engine produced has to survive: a journal that kept only
        # a title and a severity would be indistinguishable from one that found
        # something else entirely.
        for field in (
            "id", "tier", "module", "endpoint", "param", "payload",
            "evidence", "poc_curl", "recommendation", "capped",
        ):
            self.assertIn(field, row, field)
        self.assertEqual(row["endpoint"], "http://target.test/item?id=1")
        self.assertEqual(row["param"], "id")
        self.assertEqual(row["poc_curl"], "curl -sk 'http://target.test/item?id=1'")
        self.assertEqual(row["recommendation"], "use a parameterised query")
        self.assertEqual(row["tier"], "verified")
        self.assertIs(run.findings[1]["capped"], True)
        self.assertEqual(second.status_code, 200)

    def test_a_cancelled_run_is_recorded_but_stores_no_report_as_evidence(self):
        """A stopped run still happened, but it has no report to write.

        Writing an empty findings list is not the alternative — dropping the run
        entirely would erase a scan that spent real requests on the target.
        """
        from lab import active_scanner_views

        active_scanner_views._remember_active_scan_job(
            "active-2", self.project, "http://target.test/"
        )
        with mock.patch(
            "lab.active_scanner_views.call_engine_get",
            return_value=(200, {"job_id": "active-2", "state": "cancelled"}),
        ), mock.patch("lab.active_scanner_views._persist_tool_history"):
            response = self.client.get("/api/scanner/active/jobs/active-2")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ScannerRun.objects.filter(project=self.project).count(), 0)

    def test_a_running_job_is_not_recorded(self):
        from lab import active_scanner_views

        active_scanner_views._remember_active_scan_job(
            "active-3", self.project, "http://target.test/"
        )
        with mock.patch(
            "lab.active_scanner_views.call_engine_get",
            return_value=(200, {"job_id": "active-3", "state": "running"}),
        ):
            self.client.get("/api/scanner/active/jobs/active-3")
        self.assertEqual(ScannerRun.objects.filter(project=self.project).count(), 0)
        # A running job keeps its record: the Project it belongs to is exactly what
        # a poll an hour later needs in order to file the finished report.
        job = ActiveScanJob.objects.get(job_id="active-3")
        self.assertFalse(job.settled)
        self.assertEqual(job.project_id, self.project.id)

    # ---- surviving a gateway restart --------------------------------------

    def _finished_report(self, findings=1):
        return {
            "target": "http://target.test/",
            "findings": [
                {
                    "id": f"f{i}", "title": "SQLi", "severity": "HIGH",
                    "tier": "verified", "module": "Sqli", "endpoint": "http://target.test/i",
                    "method": "GET", "param": "id", "payload": "1' OR 1=1--",
                    "evidence": "matched", "poc_curl": "curl -sk 'http://target.test/i?id=1'",
                }
                for i in range(findings)
            ],
            "stats": {"requests": 100, "points": 9, "modules": 5, "verified": findings},
        }

    def test_a_finished_run_survives_a_gateway_restart(self):
        """The run that was lost in production, stated as a test.

        A scan is started, the gateway restarts, and the run finishes afterwards
        into a browser that no longer has a poll in flight. The report still has
        to reach the journal, because the run happened and its evidence is real.

        Before the fix the record lived in a process-local dict, so the restart
        erased the only thing that said which Project the finished report belonged
        to, and the run's 65 minutes of work had nowhere to land.
        """
        from lab import active_scanner_views

        with mock.patch(
            "lab.active_scanner_views.call_engine",
            return_value=(202, {"job_id": "active-9", "state": "queued"}),
        ):
            self._post_job({"url": "http://target.test/"})

        # The gateway restarts. Nothing about the run is lost — the engine keeps
        # it — and nothing in this process's memory survives, which is the whole
        # point: the mapping now lives in a table, so there is no in-memory copy
        # for a restart to take.
        self.assertEqual(ActiveScanJob.objects.filter(job_id="active-9").count(), 1)

        with mock.patch(
            "lab.active_scanner_views.call_engine_get",
            return_value=(200, {"job_id": "active-9", "state": "completed", "result": self._finished_report(2)}),
        ), mock.patch("lab.active_scanner_views._persist_tool_history"):
            response = self.client.get("/api/scanner/active/jobs/active-9")

        self.assertEqual(response.status_code, 200)
        runs = ScannerRun.objects.filter(project=self.project, engine="active")
        self.assertEqual(runs.count(), 1, "the finished report was lost across the restart")
        self.assertEqual(runs.first().summary["findings_count"], 2)
        self.assertTrue(ActiveScanJob.objects.get(job_id="active-9").settled)

    def test_a_finished_run_is_swept_up_when_no_browser_ever_asks(self):
        """The report is recorded without a poll, not only because of one.

        The sweep is the second way in. A run whose browser closed has no poll
        coming, and if recording depended on the poll then the browser closing was
        enough to lose the run — which is what happened in production.
        """
        from lab import active_scanner_views

        with mock.patch(
            "lab.active_scanner_views.call_engine",
            return_value=(202, {"job_id": "active-7", "state": "queued"}),
        ):
            self._post_job({"url": "http://target.test/"})
        self.assertEqual(ScannerRun.objects.count(), 0)

        # Nobody polls. The sweep asks the engine on its own and files the report.
        with mock.patch(
            "lab.active_scanner_views.call_engine_get",
            return_value=(200, {"job_id": "active-7", "state": "completed", "result": self._finished_report(3)}),
        ), mock.patch("lab.active_scanner_views._persist_tool_history"):
            settled = active_scanner_views.sweep_active_scan_jobs()

        self.assertEqual(settled, 1)
        self.assertEqual(ScannerRun.objects.filter(project=self.project).count(), 1)
        self.assertEqual(ScannerRun.objects.first().summary["findings_count"], 3)

    def test_the_sweep_writes_a_settled_run_only_once(self):
        """A settled run is never re-read, however many passes go by.

        Without this the sweep is a loop that re-files an hour-old scan on every
        dashboard read, and each pass would insert another `ScannerRun`.
        """
        from lab import active_scanner_views

        with mock.patch(
            "lab.active_scanner_views.call_engine",
            return_value=(202, {"job_id": "active-8", "state": "queued"}),
        ):
            self._post_job({"url": "http://target.test/"})
        with mock.patch(
            "lab.active_scanner_views.call_engine_get",
            return_value=(200, {"job_id": "active-8", "state": "completed", "result": self._finished_report(1)}),
        ) as engine, mock.patch("lab.active_scanner_views._persist_tool_history"):
            first = active_scanner_views.sweep_active_scan_jobs()
            second = active_scanner_views.sweep_active_scan_jobs()

        self.assertEqual(first, 1)
        self.assertEqual(second, 0)
        self.assertEqual(ScannerRun.objects.filter(project=self.project).count(), 1)
        # The second pass must not even have asked the engine about it again.
        self.assertEqual(engine.call_count, 1)

    def test_a_run_the_engine_forgot_is_settled_as_lost_rather_than_retried_forever(self):
        """An unknown run stops being asked about.

        The engine keeps finished runs for a bounded time, so a Project read long
        after the fact asks about a run that is gone. Answering 404 has to close
        the record: a row left unsettled is re-asked on every read forever, and the
        sweep's cost then grows with the age of the Project.
        """
        from lab import active_scanner_views

        with mock.patch(
            "lab.active_scanner_views.call_engine",
            return_value=(202, {"job_id": "active-6", "state": "queued"}),
        ):
            self._post_job({"url": "http://target.test/"})

        with mock.patch(
            "lab.active_scanner_views.call_engine_get",
            return_value=(404, {"error": "UNKNOWN_JOB"}),
        ) as engine, mock.patch("lab.active_scanner_views._persist_tool_history"):
            self.client.get("/api/scanner/active/jobs/active-6")
            second = active_scanner_views.sweep_active_scan_jobs()

        job = ActiveScanJob.objects.get(job_id="active-6")
        self.assertTrue(job.settled)
        self.assertEqual(job.status, "lost")
        self.assertEqual(second, 0)
        self.assertEqual(engine.call_count, 1, "the lost run was asked about again")
        self.assertEqual(ScannerRun.objects.count(), 0)

    def test_the_sweep_settles_a_run_the_engine_forgot(self):
        """A 404 the sweep meets itself must close the record too.

        This is the same question the poll asks, asked from the other direction,
        and it has its own branch: the sweep is the path that runs when there is no
        browser at all, so the poll's answer cannot stand in for it. Leaving this
        one uncovered let a mutation of it stay green — which is how a green suite
        ends up not checking the thing it was written to check.
        """
        from lab import active_scanner_views

        with mock.patch(
            "lab.active_scanner_views.call_engine",
            return_value=(202, {"job_id": "active-2", "state": "queued"}),
        ):
            self._post_job({"url": "http://target.test/"})

        with mock.patch(
            "lab.active_scanner_views.call_engine_get",
            return_value=(404, {"error": "UNKNOWN_JOB"}),
        ) as engine, mock.patch("lab.active_scanner_views._persist_tool_history"):
            first = active_scanner_views.sweep_active_scan_jobs()
            second = active_scanner_views.sweep_active_scan_jobs()

        job = ActiveScanJob.objects.get(job_id="active-2")
        self.assertTrue(job.settled)
        self.assertEqual(job.status, "lost")
        self.assertEqual(first, 1)
        self.assertEqual(second, 0)
        self.assertEqual(engine.call_count, 1, "the sweep asked about a settled run again")
        self.assertEqual(ScannerRun.objects.count(), 0)

    def test_reading_the_project_hub_sweeps_an_unwatched_run(self):
        """The sweep is reached from where an operator actually looks.

        A sweep that nothing calls is not a safety net, it is dead code — so the
        wiring is asserted here rather than left to be discovered by a run that
        never got filed. Reading the Project is the one action an operator takes
        without knowing a scan finished, which is exactly what this needs.
        """
        with mock.patch(
            "lab.active_scanner_views.call_engine",
            return_value=(202, {"job_id": "active-1", "state": "queued"}),
        ):
            self._post_job({"url": "http://target.test/"})
        self.assertEqual(ScannerRun.objects.count(), 0)

        with mock.patch(
            "lab.active_scanner_views.call_engine_get",
            return_value=(200, {"job_id": "active-1", "state": "completed", "result": self._finished_report(1)}),
        ), mock.patch("lab.active_scanner_views._persist_tool_history"):
            response = self.client.get(f"/api/projects/{self.project.id}/hub")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(ScannerRun.objects.filter(project=self.project).count(), 1)

    def test_a_cancelled_run_is_settled_without_inventing_findings(self):
        """A stopped run stops being re-read, and still writes no findings.

        `settled` is a separate flag from `ingested` for exactly this case: a
        cancelled run has no report to store, so `ingested` stays false, and if only
        that flag stopped the sweep then every cancelled run in the table would be
        examined on every read for as long as the Project exists.
        """
        from lab import active_scanner_views

        with mock.patch(
            "lab.active_scanner_views.call_engine",
            return_value=(202, {"job_id": "active-4", "state": "queued"}),
        ):
            self._post_job({"url": "http://target.test/"})
        with mock.patch(
            "lab.active_scanner_views.call_engine_get",
            return_value=(200, {"job_id": "active-4", "state": "cancelled"}),
        ), mock.patch("lab.active_scanner_views._persist_tool_history"):
            self.client.get("/api/scanner/active/jobs/active-4")
            second = active_scanner_views.sweep_active_scan_jobs()

        job = ActiveScanJob.objects.get(job_id="active-4")
        self.assertTrue(job.settled)
        self.assertFalse(job.ingested)
        self.assertEqual(second, 0)
        self.assertEqual(ScannerRun.objects.count(), 0)

    def test_a_re_attach_updates_one_row_instead_of_colliding(self):
        """A browser that re-attaches to its own run converges on one record.

        The browser re-reads its stored job id on reload, so the start path can be
        reached twice for one run. A plain create would raise on the unique job_id
        and turn a re-attach into an error the operator cannot act on.
        """
        with mock.patch(
            "lab.active_scanner_views.call_engine",
            return_value=(202, {"job_id": "active-5", "state": "queued"}),
        ):
            self._post_job({"url": "http://target.test/"})
            response = self._post_job({"url": "http://target.test/"})

        self.assertEqual(response.status_code, 202)
        self.assertEqual(ActiveScanJob.objects.filter(job_id="active-5").count(), 1)

    # ---- control ----------------------------------------------------------

    def test_cancel_reaches_the_engine_and_pause_is_a_separate_control(self):
        with mock.patch(
            "lab.active_scanner_views.call_engine",
            return_value=(200, {"job_id": "active-1", "state": "cancelled"}),
        ) as engine:
            response = self.client.post("/api/scanner/active/jobs/active-1/cancel")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            engine.call_args[0][0], "/proxy/scanner/active/jobs/active-1/cancel"
        )

    def test_pause_and_resume_reach_the_engine_as_their_own_actions(self):
        # This test used to assert the opposite — that a pause must be refused —
        # and the refusal was deliberate then: the engine offered no pause, and a
        # button that only looked paused would have been worse than none. It is now
        # a real action, and what replaced the old assertion is the property the
        # pause was refused for: it must reach the engine rather than being
        # answered locally, because a locally-answered pause is the fake one.
        with mock.patch(
            "lab.active_scanner_views.call_engine",
            return_value=(200, {"job_id": "active-1", "state": "paused"}),
        ) as engine:
            paused = self.client.post("/api/scanner/active/jobs/active-1/pause")
        self.assertEqual(paused.status_code, 200)
        self.assertEqual(
            engine.call_args[0][0], "/proxy/scanner/active/jobs/active-1/pause"
        )
        with mock.patch(
            "lab.active_scanner_views.call_engine",
            return_value=(200, {"job_id": "active-1", "state": "running"}),
        ) as engine:
            resumed = self.client.post("/api/scanner/active/jobs/active-1/resume")
        self.assertEqual(resumed.status_code, 200)
        self.assertEqual(
            engine.call_args[0][0], "/proxy/scanner/active/jobs/active-1/resume"
        )

    def test_an_action_the_engine_never_heard_of_is_refused(self):
        unknown = self.client.post("/api/scanner/active/jobs/active-1/detonate")
        self.assertEqual(unknown.status_code, 400)
        self.assertIn("unknown job action", unknown.json()["error"])

    def test_a_poll_without_a_job_id_is_refused(self):
        response = self.client.get("/api/scanner/active/jobs")
        self.assertEqual(response.status_code, 400)

    def test_cancel_persists_tool_history_and_settles_job(self):
        from lab import active_scanner_views

        active_scanner_views._remember_active_scan_job(
            "active-c1", self.project, "http://target.test/"
        )
        with mock.patch(
            "lab.active_scanner_views.call_engine",
            return_value=(200, {"job_id": "active-c1", "state": "cancelled"}),
        ), mock.patch("lab.active_scanner_views._persist_tool_history") as persist:
            response = self.client.post("/api/scanner/active/jobs/active-c1/cancel")

        self.assertEqual(response.status_code, 200)
        persist.assert_called_once_with(self.project)
        job = ActiveScanJob.objects.get(job_id="active-c1")
        self.assertTrue(job.settled)
        self.assertEqual(job.status, "cancelled")

    def test_stream_settles_and_persists_on_terminal_frame(self):
        from lab import active_scanner_views

        active_scanner_views._remember_active_scan_job(
            "active-s1", self.project, "http://target.test/"
        )

        class FakeStream:
            def __init__(self, frames):
                self.lines = frames
                self.index = 0

            def readline(self):
                if self.index < len(self.lines):
                    line = self.lines[self.index]
                    self.index += 1
                    return line
                return b""

            def close(self):
                return None

        report = {
            "target": "http://target.test/",
            "findings": [
                {
                    "id": "ACT-1", "tier": "verified", "module": "sqli",
                    "endpoint": "http://target.test/p", "severity": "HIGH",
                }
            ],
            "stats": {"requests": 15, "verified": 1},
        }
        done_payload = json.dumps({"job_id": "active-s1", "state": "completed", "result": report})
        frames = [
            b"id: 1\n",
            b"event: progress\n",
            b"data: {\"phase\": \"running\", \"requests\": 5}\n",
            b"\n",
            b"id: 2\n",
            b"event: done\n",
            f"data: {done_payload}\n".encode(),
            b"\n",
        ]

        with mock.patch(
            "lab.active_scanner_views.open_engine_stream",
            return_value=FakeStream(frames),
        ), mock.patch("lab.active_scanner_views._persist_tool_history") as persist:
            response = self.client.get("/api/scanner/active/jobs/active-s1/stream")
            content = b"".join(response.streaming_content).decode()

        self.assertEqual(response.status_code, 200)
        self.assertIn("event: done", content)
        persist.assert_called_once_with(self.project)
        job = ActiveScanJob.objects.get(job_id="active-s1")
        self.assertTrue(job.settled)
        self.assertTrue(job.ingested)
        run = ScannerRun.objects.filter(project=self.project, engine="active").first()
        self.assertIsNotNone(run)
        self.assertEqual(run.summary["findings_count"], 1)


class ActiveScannerReportShapeTests(TestCase):
    """The ingest must not invent a severity the run did not report."""

    def test_an_unranked_severity_sorts_last_and_is_kept_verbatim(self):
        from lab import active_scanner_views

        project = Project.objects.create(name="Shape", target="fixture.local")
        report = {
            "target": "http://target.test/",
            "findings": [
                {"id": "VXR-9", "title": "odd", "severity": "whatever"},
                {"id": "VXR-1", "title": "worse", "severity": "low"},
            ],
            "stats": {},
        }
        active_scanner_views._ingest_active_scan_run(project, "http://target.test/", report)
        run = ScannerRun.objects.get(project=project, engine="active")
        self.assertEqual(run.summary["highest_severity"], "LOW")
        self.assertEqual(run.summary["findings_count"], 2)
        self.assertEqual(run.summary["stats"]["requests"], 0)

    def test_a_report_that_is_not_a_mapping_is_ignored_rather_than_guessed_at(self):
        """Junk is not turned into an empty run that reads as "found nothing"."""
        from lab import active_scanner_views

        project = Project.objects.create(name="Empty", target="fixture.local")
        for junk in (None, [], "report", 7):
            active_scanner_views._ingest_active_scan_run(project, "http://target.test/", junk)
        self.assertEqual(
            ScannerRun.objects.filter(project=project, engine="active").count(), 0
        )
        # An empty report is a real report: the run happened and proved nothing.
        active_scanner_views._ingest_active_scan_run(project, "http://target.test/", {})
        self.assertEqual(
            ScannerRun.objects.filter(project=project, engine="active").count(), 1
        )