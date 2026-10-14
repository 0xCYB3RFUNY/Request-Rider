"""Tests for the corpus enumeration gateway views.

The engine side of this feature is covered in Go, against a live `httptest` stand.
What is left for these tests is the gateway's own job, and every one of them is a
place where the gateway can fail while the engine is perfectly correct:

  * a bad bound must be refused **before** the engine is touched, so the operator
    is sent to the field they got wrong rather than to a request that was doomed;
  * a long run must not be cut off by the gateway's single-exchange timeout, which
    is the failure that reports "the run failed" while the engine is still working;
  * a corpus finding must reach the project journal in the shape the journal
    reads, or the run exists and the evidence does not.
"""

import json
from unittest import mock

from django.test import Client, TestCase

from lab import views


class ScannerCorpusStatsTests(TestCase):
    """`GET /api/scanner/corpus/stats` — what a run would evaluate."""

    def test_it_asks_the_engine_what_a_selection_would_evaluate(self):
        with mock.patch("lab.views.call_engine_get") as engine:
            engine.return_value = (200, {"stats": {"total": 6521, "selected": 6521, "unique_paths": 5832}})
            response = Client().get("/api/scanner/corpus/stats")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["stats"]["selected"], 6521)
        engine.assert_called_once()
        # A tag filter that is dropped here would leave the operator reading the
        # size of the whole corpus as the size of their selection.
        self.assertEqual(engine.call_args[0][0], "/proxy/scanner/corpus/stats")

    def test_a_tag_filter_is_forwarded(self):
        with mock.patch("lab.views.call_engine_get") as engine:
            engine.return_value = (200, {"stats": {"total": 6521, "selected": 10}})
            Client().get("/api/scanner/corpus/stats?tags=x,%20y&max_checks=5")
        path = engine.call_args[0][0]
        self.assertIn("tags=x%2Cy", path)
        self.assertIn("max_checks=5", path)

    def test_an_engine_failure_is_reported_as_a_failure(self):
        """A stats endpoint that answers 200 with nothing leaves the operator
        believing the corpus is empty, which is a clean report about nothing."""
        with mock.patch("lab.views.call_engine_get") as engine:
            engine.return_value = (502, {"error": "corpus unreadable"})
            response = Client().get("/api/scanner/corpus/stats")
        self.assertEqual(response.status_code, 502)

    def test_a_get_request_is_the_only_one_it_answers(self):
        response = Client().post("/api/scanner/corpus/stats", data="{}", content_type="application/json")
        self.assertEqual(response.status_code, 405)


class ScannerCorpusRunTests(TestCase):
    """`POST /api/scanner/corpus/run` — enumerate a target."""

    def _post(self, payload):
        return Client().post(
            "/api/scanner/corpus/run",
            data=json.dumps(payload),
            content_type="application/json",
        )

    def test_it_refuses_a_missing_url_before_the_engine_is_touched(self):
        with mock.patch("lab.views.call_engine") as engine:
            for payload in ({}, {"url": ""}, {"url": "   "}):
                response = self._post(payload)
            self.assertEqual(response.status_code, 400)
            engine.assert_not_called()

    def test_it_refuses_a_bound_it_cannot_honour_before_the_engine_is_touched(self):
        """The engine would refuse these too, but a bound that reaches the engine
        has already spent a request and told the operator something is wrong with
        the target rather than with the number they typed."""
        with mock.patch("lab.views.call_engine") as engine:
            for field in ("max_checks", "concurrency", "timeout_ms", "delay_ms"):
                response = self._post({"url": "http://target.test/", field: -1})
                self.assertEqual(response.status_code, 400, field)
                self.assertIn(field, response.json()["error"])
            engine.assert_not_called()

    def test_it_refuses_a_tag_list_that_is_not_a_list(self):
        with mock.patch("lab.views.call_engine") as engine:
            response = self._post({"url": "http://target.test/", "tags": "x"})
        self.assertEqual(response.status_code, 400)
        engine.assert_not_called()

    def test_it_answers_only_a_post(self):
        response = Client().get("/api/scanner/corpus/run")
        self.assertEqual(response.status_code, 405)

    def test_the_gateway_waits_longer_than_one_request_for_a_long_run(self):
        """The gateway timeout is sized for a single exchange. Applied unchanged to
        a run of several thousand requests, it reports failure while the engine is
        still working — and the operator cannot tell that from a run that died."""
        bounded = views._corpus_run_timeout({"max_checks": 400})
        whole = views._corpus_run_timeout({})
        self.assertGreater(bounded, 120)
        self.assertEqual(whole, views.corpusLongRunSeconds)
        self.assertLess(bounded, whole, "a bounded run must not be given more time than the whole corpus")

    def test_a_bound_gets_a_timeout_that_grows_with_it_and_stays_under_the_ceiling(self):
        small = views._corpus_run_timeout({"max_checks": 2})
        large = views._corpus_run_timeout({"max_checks": 400})
        absurd = views._corpus_run_timeout({"max_checks": 10_000_000})
        self.assertEqual(small, 120, "a tiny run still gets the floor")
        self.assertGreater(large, small, "a bigger run gets more time")
        self.assertEqual(absurd, views.corpusLongRunSeconds, "a bound cannot buy time past the ceiling")

    def test_an_unreadable_bound_does_not_measure_the_run_as_unbounded_silently(self):
        """`max_checks` arrives as whatever JSON held. A string that is not a number
        falls back to the whole-corpus ceiling rather than raising, so a typo costs
        the operator a long wait instead of an error."""
        self.assertEqual(views._corpus_run_timeout({"max_checks": "many"}), 5400)

    def test_a_corpus_finding_becomes_a_journal_row_the_journal_can_read(self):
        mapped = views._corpus_findings_as_journal([{
            "check_id": "000013", "method": "GET", "path": "/.env", "status_code": 200,
            "description": "Unix environment file", "evidence": "DB_PASSWORD=1",
        }, "not a dict", None])
        self.assertEqual(len(mapped), 1, "a non-dict entry must be skipped, not crash the run")
        row = mapped[0]
        self.assertIn("/.env", row["title"])
        self.assertIn("Unix environment file", row["title"])
        self.assertEqual(row["evidence"], "DB_PASSWORD=1")
        self.assertEqual(row["template_id"], "000013")
        # The corpus ranks nothing, so the journal must not invent a severity that
        # would then be sorted as if it were a triage.
        self.assertEqual(row["severity"], "INFO")

    def test_a_finding_with_no_method_still_gets_a_title(self):
        mapped = views._corpus_findings_as_journal([{"check_id": "000013", "path": "/.env"}])
        self.assertTrue(mapped[0]["title"].strip(), "an empty title is invisible in the journal")
