"""Regression tests for batched Project knowledge-base ingestion.

The per-row `post_save` path and the `bulk_create` batch path must be
interchangeable: `bulk_create` does not emit `post_save`, so `lab.ingest`
re-implements the same rules in a folded form. These tests pin that equivalence
so a future optimisation cannot silently drop endpoints, technology hints or
secret references.

They also pin the write-amplification contract: a burst of N exchanges to the
same handful of endpoints must cost a bounded number of statements, not one
statement per exchange.
"""

from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.db import connection

from lab.ingest import capture_contexts_by_token, ingest_traffic_batch
from lab.models import Project, ProjectEndpoint, ProjectSecret, TrafficCaptureContext, TrafficRecord
from lab.views import persist_intruder_history, persist_proxy_history, public_traffic_events


def knowledge_base_snapshot(project):
    """Ordered, comparable view of everything ingestion is allowed to write.

    The project row is re-read because ingestion writes `tech_stack` through
    `QuerySet.update()`, which deliberately does not refresh the in-memory
    instance the caller is holding.
    """
    project.refresh_from_db()
    return {
        "endpoints": sorted(
            (endpoint.method, endpoint.path, tuple(sorted(endpoint.statuses or [])), tuple(sorted(endpoint.parameters or [])))
            for endpoint in ProjectEndpoint.objects.filter(project=project)
        ),
        "tech_stack": {
            key: sorted(value if isinstance(value, list) else [value])
            for key, value in (project.tech_stack or {}).items()
        },
        "secrets": sorted(
            ProjectSecret.objects.filter(project=project).values_list(
                "secret_type", "key_name", "source_url"
            )
        ),
    }


class IngestEquivalenceTests(TestCase):
    """The batch path must land on exactly the state the per-row path produces."""

    def setUp(self):
        self.project = Project.objects.create(name="Equivalence", target="fixture.local")

    def _records(self):
        """A batch that deliberately repeats endpoints, headers and secrets."""
        rows = []
        for index in range(12):
            path = f"/api/item/{index % 3}"
            rows.append(TrafficRecord(
                project=self.project,
                source="proxy",
                method="GET",
                url=f"http://fixture.local{path}?page={index % 2}",
                request_headers={"Authorization": "Bearer token-abc", "X-Trace": str(index)},
                response_headers={"Server": "nginx/1.25", "Set-Cookie": "sid=1", "Via": "edge"},
                status_code=200 if index % 4 else 404,
                response_body="x" * 32,
            ))
        return rows

    def test_batch_matches_per_row_end_state(self):
        per_row = self._records()
        for record in per_row:
            # post_save -> ingest_traffic_record
            record.save()
        expected = knowledge_base_snapshot(self.project)

        self.project.tech_stack = {}
        ProjectEndpoint.objects.filter(project=self.project).delete()
        ProjectSecret.objects.filter(project=self.project).delete()

        batched = self._records()
        TrafficRecord.objects.bulk_create(batched, batch_size=50)
        ingest_traffic_batch(batched)
        actual = knowledge_base_snapshot(self.project)

        self.assertEqual(expected, actual)
        # Sanity: the fixture must actually exercise every rule.
        self.assertTrue(expected["endpoints"])
        self.assertTrue(expected["secrets"])
        self.assertIn("server", expected["tech_stack"])

    def test_batch_registers_repeated_endpoint_once(self):
        rows = self._records()
        TrafficRecord.objects.bulk_create(rows, batch_size=50)
        ingest_traffic_batch(rows)
        # 12 exchanges collapse onto 3 distinct paths, not 12 rows.
        self.assertEqual(ProjectEndpoint.objects.filter(project=self.project).count(), 3)

    def test_batch_collects_status_codes_per_endpoint(self):
        rows = [
            TrafficRecord(
                project=self.project, source="proxy", method="GET",
                url="http://fixture.local/a", status_code=200, response_body="",
            ),
            TrafficRecord(
                project=self.project, source="proxy", method="GET",
                url="http://fixture.local/a", status_code=500, response_body="",
            ),
        ]
        TrafficRecord.objects.bulk_create(rows, batch_size=50)
        ingest_traffic_batch(rows)
        endpoint = ProjectEndpoint.objects.get(project=self.project, path="/a")
        self.assertEqual(sorted(endpoint.statuses), [200, 500])

    def test_records_without_project_are_ignored(self):
        rows = [TrafficRecord(source="proxy", method="GET", url="http://fixture.local/x", response_body="")]
        TrafficRecord.objects.bulk_create(rows, batch_size=50)
        counters = ingest_traffic_batch(rows)
        self.assertEqual(counters["projects"], 0)
        self.assertEqual(ProjectEndpoint.objects.count(), 0)

    def test_empty_batch_is_a_no_op(self):
        self.assertEqual(ingest_traffic_batch([])["projects"], 0)
        self.assertEqual(ProjectEndpoint.objects.count(), 0)

    def test_batch_statement_count_does_not_scale_with_rows(self):
        """The real contract: statements must be bounded, not per-exchange.

        A 200-exchange burst touches 4 distinct endpoints, one technology hint
        and one Authorization header per distinct URL. SQLite splits bulk
        inserts on its bound-parameter limit, so the absolute count is a small
        constant; the property worth pinning is that quadrupling the number of
        exchanges over the same endpoints does not quadruple the statements.
        """
        def build(count):
            return [
                TrafficRecord(
                    project=self.project, source="proxy", method="GET",
                    url=f"http://fixture.local/p/{index % 4}",
                    request_headers={"Authorization": "Bearer t"},
                    response_headers={"Server": "nginx"},
                    status_code=200, response_body="",
                )
                for index in range(count)
            ]

        def measure(count):
            rows = build(count)
            with CaptureQueriesContext(connection) as captured:
                TrafficRecord.objects.bulk_create(rows, batch_size=200)
                ingest_traffic_batch(rows)
            return len(captured.captured_queries)

        small = measure(50)
        large = measure(200)
        # Four times the exchanges, well under four times the statements.
        self.assertLessEqual(large, small * 2)
        # And an absolute ceiling that a per-row implementation could not meet.
        self.assertLessEqual(large, 40)
        self.assertEqual(ProjectEndpoint.objects.filter(project=self.project).count(), 4)
        self.assertEqual(ProjectSecret.objects.filter(project=self.project).count(), 4)


class PersistIntruderHistoryTests(TestCase):
    """Intruder sync must be idempotent and must not re-probe every result."""

    def setUp(self):
        self.project = Project.objects.create(name="Intruder", target="fixture.local")
        self.attack_id = "424242"
        self.results = [
            {
                "request": {
                    "method": "GET",
                    "url": f"http://fixture.local/item/{index}",
                    "headers": {"X-Probe": str(index)},
                    "body": "",
                },
                "headers": {"Content-Type": "text/html"},
                "body": "body-" + str(index),
                "status": 200,
                "time": 5,
                "size": 10,
            }
            for index in range(25)
        ]

    def test_persists_each_result_once(self):
        persist_intruder_history(self.attack_id, self.results, project_id=self.project.id)
        self.assertEqual(TrafficRecord.objects.filter(source="intruder").count(), 25)

        # The engine re-offers the same window on every poll; nothing is duplicated.
        persist_intruder_history(self.attack_id, self.results, project_id=self.project.id)
        self.assertEqual(TrafficRecord.objects.filter(source="intruder").count(), 25)

    def test_honours_result_offset(self):
        persist_intruder_history(self.attack_id, self.results[10:], result_offset=10, project_id=self.project.id)
        rows = TrafficRecord.objects.filter(source="intruder").order_by("proxy_event_id")
        self.assertEqual([row.proxy_event_id for row in rows], list(range(10, 25)))

    def test_second_poll_costs_few_queries_than_first(self):
        persist_intruder_history(self.attack_id, self.results, project_id=self.project.id)
        with CaptureQueriesContext(connection) as captured:
            persist_intruder_history(self.attack_id, self.results, project_id=self.project.id)
        # A fully-known window resolves with one indexed lookup and no writes.
        self.assertEqual(len(captured.captured_queries), 1)

    def test_registers_endpoints_for_intruder_evidence(self):
        persist_intruder_history(self.attack_id, self.results, project_id=self.project.id)
        self.assertEqual(ProjectEndpoint.objects.filter(project=self.project).count(), 25)

    def test_malformed_results_are_skipped(self):
        persist_intruder_history(
            self.attack_id,
            [None, "text", {}, {"request": None}, {"request": {"url": ""}}],
            project_id=self.project.id,
        )
        self.assertEqual(TrafficRecord.objects.filter(source="intruder").count(), 0)

    def test_non_list_input_is_ignored(self):
        persist_intruder_history(self.attack_id, None, project_id=self.project.id)
        persist_intruder_history(self.attack_id, {"not": "a list"}, project_id=self.project.id)
        self.assertEqual(TrafficRecord.objects.count(), 0)


class PersistProxyHistoryTests(TestCase):
    """Passive snapshot sync must scale with new events, not snapshot size."""

    def setUp(self):
        self.project = Project.objects.create(name="Proxy", target="fixture.local")
        self.context = TrafficCaptureContext.objects.create(name="ctx", project=self.project)

    def _events(self, count, session=7, start=1):
        return [
            {
                "id": index,
                "session": session,
                "source": "proxy",
                "host": "fixture.local",
                "method": "GET",
                "url": f"http://fixture.local/r/{index}",
                "status": 200,
                "latency_ms": 4,
                "response_size": 2,
                "response_headers": {"Content-Type": "text/plain"},
                "response_body": "ok",
                "capture_context": self.context.token,
            }
            for index in range(start, start + count)
        ]

    def test_persists_snapshot_once(self):
        events = self._events(30)
        persist_proxy_history(events, self.project.id)
        self.assertEqual(TrafficRecord.objects.filter(source="proxy").count(), 30)
        persist_proxy_history(events, self.project.id)
        self.assertEqual(TrafficRecord.objects.filter(source="proxy").count(), 30)

    def test_links_capture_context_and_scope_status(self):
        persist_proxy_history(self._events(2), None)
        row = TrafficRecord.objects.get(proxy_event_id=1)
        self.assertEqual(row.project_id, self.project.id)
        self.assertEqual(row.capture_context_id, self.context.id)
        self.assertEqual(row.scope_status, "project_linked")

    def test_backfills_source_ip_without_duplicating(self):
        events = self._events(1)
        persist_proxy_history(events, self.project.id)
        self.assertIsNone(TrafficRecord.objects.get(proxy_event_id=1).source_ip)

        events[0]["source_ip"] = "203.0.113.9"
        persist_proxy_history(events, self.project.id)
        rows = TrafficRecord.objects.filter(proxy_event_id=1)
        self.assertEqual(rows.count(), 1)
        self.assertEqual(rows.first().source_ip, "203.0.113.9")

    def test_incomplete_and_foreign_sources_are_skipped(self):
        persist_proxy_history(
            [
                {"id": 1, "source": "proxy", "url": "http://fixture.local/a"},  # no status
                {"id": 2, "source": "intruder", "url": "http://fixture.local/b", "status": 200},
                {"id": 3, "source": "proxy", "status": 200},  # no url
                "not-a-dict",
            ],
            self.project.id,
        )
        self.assertEqual(TrafficRecord.objects.count(), 0)

    def test_repeated_snapshot_costs_bounded_queries(self):
        events = self._events(200)
        persist_proxy_history(events, self.project.id)
        with CaptureQueriesContext(connection) as captured:
            persist_proxy_history(events, self.project.id)
        # One context resolution + one batched dedup lookup, and no writes.
        self.assertLessEqual(len(captured.captured_queries), 2)
        self.assertEqual(TrafficRecord.objects.filter(source="proxy").count(), 200)

    def test_non_list_input_is_ignored(self):
        persist_proxy_history(None, self.project.id)
        persist_proxy_history({"not": "a list"}, self.project.id)
        self.assertEqual(TrafficRecord.objects.count(), 0)


class PublicTrafficEventTests(TestCase):
    """Snapshot mapping must resolve every distinct token in one query."""

    def setUp(self):
        self.project = Project.objects.create(name="Public", target="fixture.local")
        self.bound = TrafficCaptureContext.objects.create(name="bound", project=self.project)
        self.loose = TrafficCaptureContext.objects.create(name="loose", project=None)

    def test_batch_resolves_tokens_in_one_query(self):
        events = [
            {
                "id": index,
                "url": f"http://fixture.local/{index}",
                "capture_context": self.bound.token if index % 2 else self.loose.token,
            }
            for index in range(40)
        ]
        with CaptureQueriesContext(connection) as captured:
            mapped = public_traffic_events(events)
        self.assertEqual(len(captured.captured_queries), 1)
        self.assertEqual(len(mapped), 40)

    def test_scope_status_per_context_binding(self):
        mapped = public_traffic_events([
            {"id": 1, "url": "http://fixture.local/a", "capture_context": self.bound.token},
            {"id": 2, "url": "http://fixture.local/b", "capture_context": self.loose.token},
            {"id": 3, "url": "http://fixture.local/c"},
            {"id": 4, "url": "http://fixture.local/d", "capture_context": "not-a-real-token"},
        ])
        self.assertEqual(mapped[0]["scope_status"], "project_linked")
        self.assertEqual(mapped[0]["capture_context_id"], self.bound.id)
        self.assertEqual(mapped[1]["scope_status"], "unscoped")
        self.assertEqual(mapped[2]["scope_status"], "unscoped")
        self.assertEqual(mapped[3]["scope_status"], "invalid_context")

    def test_capture_token_is_never_exposed(self):
        mapped = public_traffic_events([
            {"id": 1, "url": "http://fixture.local/a", "capture_context": self.bound.token},
        ])
        self.assertNotIn("capture_context", mapped[0])
        self.assertNotIn(self.bound.token, str(mapped[0]))

    def test_non_dict_events_pass_through(self):
        self.assertEqual(public_traffic_events(["text", 5]), ["text", 5])

    def test_token_lookup_helper_ignores_blanks(self):
        self.assertEqual(capture_contexts_by_token([None, "", "   "]), {})
