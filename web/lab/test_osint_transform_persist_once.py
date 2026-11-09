"""A finished transform result is written into the graph exactly once.

Measured 2026-10-02 on `wayback_urls` for `pravda.ru`: the engine returned 24 992
entities and 24 991 relations — 11.9 MB — and writing that takes minutes. A
finished job stays pollable, so the browser's next poll arrived while the first
write was still running and started a second one over the same rows. Eleven piled
up, every one waiting on the first entity, and the poll returned nothing at all:
the operator saw a transform that had finished and produced nothing while the
database carried eleven copies of the same write.

The guard is per job id, and the second poll of the same job must not touch a row.
"""

import json
import threading
import unittest

from django.db import connections
from unittest.mock import patch

from django.test import RequestFactory, TestCase, TransactionTestCase

from lab import views
from lab.models import OsintEntity, OsintGraph


def _finished_result(job_id, entities=3, relations=2):
    return {
        "job_id": job_id,
        "state": "completed",
        "progress": {"elapsed_ms": 1234, "phase": "completed"},
        "result": {
            "transform": "domain_normalize",
            "value": "pravda.ru",
            "status": "completed",
            # The subdomains have to exist as entities: a relation whose source is
            # not in the graph is rejected, and a rejected relation would make the
            # fixture look like a transform that stored nothing.
            "entities": [
                *[{"type": "domain", "identity": "pravda.ru"}],
                *[
                    {"type": "subdomain", "identity": f"n{index}.pravda.ru"}
                    for index in range(entities)
                ],
            ],
            "relations": [
                {"type": "subdomain_of", "source_type": "subdomain", "source": f"n{i}.pravda.ru",
                 "target_type": "domain", "target": "pravda.ru"}
                for i in range(relations)
            ],
            "warnings": [],
            "metadata": {},
        },
    }


class OsintTransformPersistOnceTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        version = OsintGraph.objects.count() + 1
        self.graph = OsintGraph.objects.create(name=f"persist-once-{version}", status="active", version=version)
        # A fresh guard per test: the state is process-local by design, and one
        # test's job id must not decide another test's answer.
        views._OSINT_PERSISTED_JOBS.pop(self.graph.id, None)

    def _poll(self, job_id):
        request = self.factory.get(f"/api/osint/graphs/{self.graph.id}/transform/jobs/{job_id}")
        with patch.object(views, "_persist_tool_history"), patch.object(
            views, "_osint_request_origin", return_value="http://127.0.0.1:8100"
        ):
            return views._osint_transform_job_result(
                self.graph, 200, _finished_result(job_id), "http://127.0.0.1:8100"
            )

    def test_a_second_poll_of_the_same_job_does_not_write_again(self):
        first = json.loads(self._poll("job-once").content)
        self.assertEqual(first["state"], "completed")
        entities_after_first = self.graph.entities.count()

        with patch.object(
            views, "_osint_transform_persist", side_effect=AssertionError("persisted twice")
        ):
            second = json.loads(self._poll("job-once").content)

        self.assertEqual(second["state"], "completed")
        self.assertEqual(self.graph.entities.count(), entities_after_first)
        self.assertIn("upserted", second)

    def test_the_second_poll_still_reports_the_counts_the_browser_reads(self):
        """`onFinish` reads `stored_entity_count` and `stored_relation_count`, so a
        skipped write must not leave the panel saying zero."""
        self._poll("job-counts")
        second = json.loads(self._poll("job-counts").content)
        result = second.get("transform_result") or {}
        self.assertTrue(result, "the second poll returned no transform_result")
        self.assertGreaterEqual(result.get("entity_count", 0), 1)
        self.assertGreaterEqual(result.get("relation_count", 0), 1)
        self.assertGreaterEqual((second.get("upserted") or {}).get("entities", 0), 1)

    def test_the_second_poll_reports_this_job_not_the_whole_graph(self):
        """`entity_count` on a transform result is what this run produced.

        Measured 2026-10-02 on live jobs: `secret_scan` over `vc.ru` finished with
        `metadata.secrets_found: 0` and a repeat poll answered
        `entity_count: 578, relation_count: 481` — the **whole graph's** totals,
        identical to the `s3_buckets` run beside it. `upsert_graph` returns the graph
        totals by design (the tab shows "the graph holds N"), and the persist mark
        was storing those, so the repeat poll reported the workspace as this job's
        finding. A panel that says "578" under a run that found nothing is worse
        than a panel that says zero.
        """
        # Rows that belong to no job under test, so a graph total and a job total
        # cannot coincide.
        for index in range(5):
            OsintEntity.objects.create(
                graph=self.graph,
                entity_type="domain",
                identity=f"preexisting-{index}.example",
                display_value=f"preexisting-{index}.example",
            )

        self._poll("job-scoped")
        second = json.loads(self._poll("job-scoped").content)
        result = second.get("transform_result") or {}
        graph_entities = self.graph.entities.count()

        self.assertGreaterEqual(graph_entities, 5, "the fixture did not enlarge the graph")
        self.assertLess(
            result.get("entity_count", 0),
            graph_entities,
            "entity_count on a repeat poll is the graph total, not this job's result",
        )
        # The graph total still has to be reachable: that is what the tab shows, and
        # dropping it would lose information rather than fix a wrong number.
        self.assertEqual((second.get("upserted") or {}).get("entities"), graph_entities)

    def test_a_different_job_is_still_written(self):
        """The guard is per job, so a second run in the same graph must not be
        mistaken for the first one and skipped — that would lose the result."""
        self._poll("job-a")
        with patch.object(views, "upsert_graph", wraps=views.upsert_graph) as upsert:
            self._poll("job-b")
            self.assertTrue(upsert.called, "a different job was skipped, so its result was lost")

    def test_the_guard_is_bounded(self):
        """Process-local memory that grows with every job is a leak, and this
        project runs for days."""
        self.assertLessEqual(views._OSINT_PERSISTED_JOBS_LIMIT, 256)
        for index in range(views._OSINT_PERSISTED_JOBS_LIMIT + 5):
            views._osint_mark_job_persisted(self.graph, f"job-{index}", 1, 1, 1, 1)
        stored = views._OSINT_PERSISTED_JOBS[self.graph.id]
        self.assertEqual(len(stored), views._OSINT_PERSISTED_JOBS_LIMIT)
        self.assertNotIn("job-0", stored, "the oldest entries must be the ones dropped")

    def test_a_running_job_still_never_writes(self):
        running = {"job_id": "job-run", "state": "running", "progress": {"phase": "running"}}
        with patch.object(
            views, "_osint_transform_persist", side_effect=AssertionError("a running job was written")
        ):
            views._osint_transform_job_result(self.graph, 200, running, "http://127.0.0.1:8100")


class OsintTransformConcurrentPollTests(TransactionTestCase):
    """A poll that arrives *during* a slow write must not start a second one.

    This is the gap the first version of the guard left. The mark is set after the
    write returns, so a poll landing mid-write did not see it and duplicated the
    whole batch — eleven of those is exactly what the measured lock convoy was.

    It is a `TransactionTestCase`, not a `TestCase`, because the second poll runs
    on its own thread and therefore its own database connection. `TestCase` wraps
    each test in one transaction that a second connection cannot see, so the graph
    row it reads is invisible and the run fails on "Save with update_fields did
    not affect any rows" — a failure about the test harness, not about the guard.
    """

    def setUp(self):
        self.factory = RequestFactory()
        version = OsintGraph.objects.count() + 1
        self.graph = OsintGraph.objects.create(
            name=f"persist-race-{version}", status="active", version=version
        )
        views._OSINT_PERSISTED_JOBS.pop(self.graph.id, None)

    def test_a_poll_during_the_write_waits_and_reports_the_stored_graph(self):
        entered = threading.Event()
        release = threading.Event()
        writes = []
        # Captured before patching: calling `views._osint_transform_persist` from
        # inside its own replacement would re-enter the mock and recurse.
        real_persist = views._osint_transform_persist

        def slow_persist(graph, payload, origin=None):
            writes.append(payload)
            entered.set()
            release.wait(10)
            return real_persist(graph, payload, origin)

        with patch.object(views, "_persist_tool_history"), patch.object(
            views, "_osint_request_origin", return_value="http://127.0.0.1:8100"
        ), patch.object(views, "_osint_transform_persist", side_effect=slow_persist):
            def _first_poll():
                try:
                    views._osint_transform_job_result(
                        self.graph, 200, _finished_result("race"), "http://127.0.0.1:8100"
                    )
                finally:
                    # A thread's connection belongs to that thread; leaving it open
                    # leaks it and the test process keeps it after the test ends.
                    connections.close_all()

            first = threading.Thread(target=_first_poll)
            first.start()
            self.assertTrue(entered.wait(5), "the first write never started")

            second = {}

            def late_poll():
                try:
                    second["response"] = views._osint_transform_job_result(
                        self.graph, 200, _finished_result("race"), "http://127.0.0.1:8100"
                    )
                finally:
                    connections.close_all()

            late = threading.Thread(target=late_poll)
            late.start()
            # The late poll must still be waiting while the first write runs.
            late.join(0.5)
            self.assertTrue(late.is_alive(), "the second poll did not wait for the write")
            self.assertEqual(len(writes), 1, "a second write started while the first was running")

            release.set()
            first.join(10)
            late.join(10)

        self.assertEqual(len(writes), 1, f"the result was written {len(writes)} times")
        body = json.loads(second["response"].content)
        self.assertEqual(body["state"], "completed")
        self.assertIn("transform_result", body, "the waiting poll must still report the result")

