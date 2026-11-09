"""History evidence for tool traffic captured by the engine.

Go tools record through the selected route transport; external binaries use the
passive proxy. The gateway gives each run a correlation context so its exchanges
can be found again. These tests hold the gateway half of that contract — the run
is named, its rows land in History, ambient browser traffic does not, and a
repeated poll writes nothing twice.
"""

import json
from unittest.mock import patch

from django.test import RequestFactory, TestCase

from . import views
from .models import OsintGraph, Project, TrafficCaptureContext, TrafficRecord


def proxied_event(
    event_id, url, capture_context="", status=200, tags=None, source="proxy", error=""
):
    """One engine traffic event as the gateway reads it out of a snapshot."""
    event = {
        "id": event_id,
        "session": 0,
        "source": source,
        "method": "GET",
        "url": url,
        "host": url.split("/", 3)[2],
        "request_headers": {"User-Agent": "RequestRider-Scanner/1.0"},
        "request_body": "",
        "request_body_encoding": "utf8",
        "status": status,
        "response_headers": {"Content-Type": "text/html"},
        "response_body": "<html>ok</html>",
        "response_body_encoding": "utf8",
        "response_content_type": "text/html",
        "response_size": 15,
        "latency_ms": 12,
        "tags": tags or [],
    }
    if error:
        event["error"] = error
    if capture_context:
        event["capture_context"] = capture_context
    return event


class ToolRunContextTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.project = Project.objects.create(name="target project", target="http://target.test")

    def request_for(self):
        request = self.factory.post("/api/scanner")
        request.active_project = self.project
        return request

    def test_a_tool_run_is_filed_under_its_own_named_context(self):
        # The context is what makes a scan's seventeen rows findable: without a
        # name they are proxied requests, indistinguishable from the operator's
        # own browsing.
        route = views.tool_run_route(self.request_for(), "Scanner", "http://target.test/wp-login.php")

        self.assertEqual(route["proxy"], views.PASSIVE_PROXY_URL)
        context = TrafficCaptureContext.objects.get(token=route["capture_context"])
        self.assertEqual(context.project_id, self.project.id)
        self.assertEqual(context.name, "Scanner · http://target.test/wp-login.php")

    def test_two_runs_do_not_merge_into_one_context(self):
        # A second scan of the same target is a second run. Sharing a context
        # would make the first run's rows look like part of the second.
        first = views.tool_run_route(self.request_for(), "nuclei", "http://target.test")
        second = views.tool_run_route(self.request_for(), "nuclei", "http://target.test")

        self.assertNotEqual(first["capture_context"], second["capture_context"])
        self.assertEqual(TrafficCaptureContext.objects.count(), 2)

    def test_a_run_without_a_project_is_still_named(self):
        # Traffic is not gated on a project: an operator with no project selected
        # still runs scans, and their evidence must still be findable.
        request = self.factory.post("/api/scanner")
        request.active_project = None

        route = views.tool_run_route(request, "OSINT", "subdomains: example.ru")

        context = TrafficCaptureContext.objects.get(token=route["capture_context"])
        self.assertIsNone(context.project_id)
        self.assertEqual(context.name, "OSINT · subdomains: example.ru")


class HistoryShowsToolTrafficTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(name="target project", target="http://target.test")
        self.run = TrafficCaptureContext.objects.create(
            name="Scanner · http://target.test", project=self.project
        )
        self.browsing = TrafficCaptureContext.objects.create(
            name="manual browsing", project=self.project
        )

    def test_history_shows_tool_traffic_and_keeps_unlinked_traffic_out(self):
        # A correlation context is the operator saying "this traffic is mine":
        # a tool run creates one automatically, and a browsing session gets one
        # by hand. Traffic with no context at all is ambient, and ambient traffic
        # is what History is not for — it belongs to the Traffic tab.
        TrafficRecord.objects.create(
            source="proxy", method="GET", url="http://target.test/wp-admin/",
            capture_context=self.run, project=self.project, scope_status="project_linked",
        )
        TrafficRecord.objects.create(
            source="proxy", method="GET", url="http://target.test/reading-a-blog",
            capture_context=self.browsing, project=self.project, scope_status="project_linked",
        )
        TrafficRecord.objects.create(
            source="tool", method="GET", url="http://target.test/from-tool",
            capture_context=self.run, project=self.project, scope_status="project_linked",
        )
        TrafficRecord.objects.create(
            source="proxy", method="GET", url="http://target.test/no-context"
        )
        TrafficRecord.objects.create(
            source="repeater", method="GET", url="http://target.test/manual"
        )

        response = self.client.get("/api/history")

        self.assertEqual(response.status_code, 200)
        urls = {item["url"] for item in response.json()["items"]}
        self.assertIn("http://target.test/wp-admin/", urls)
        self.assertIn("http://target.test/reading-a-blog", urls)
        self.assertIn("http://target.test/from-tool", urls)
        self.assertIn("http://target.test/manual", urls)
        self.assertNotIn("http://target.test/no-context", urls)

    def test_a_history_row_names_the_run_it_came_from(self):
        # The source alone says `proxy` for a scan, a nuclei run and the
        # operator's own browsing alike. The run name is what makes the row
        # identifiable, so it has to survive into the payload the table reads.
        TrafficRecord.objects.create(
            source="proxy", method="GET", url="http://target.test/wp-admin/",
            capture_context=self.run, project=self.project,
        )

        response = self.client.get("/api/history")

        row = response.json()["items"][0]
        self.assertEqual(row["source"], "proxy")
        self.assertEqual(row["capture_context_name"], "Scanner · http://target.test")

    def test_history_export_uses_the_same_rule(self):
        TrafficRecord.objects.create(
            source="proxy", method="GET", url="http://target.test/wp-admin/",
            capture_context=self.run, project=self.project,
        )
        TrafficRecord.objects.create(
            source="proxy", method="GET", url="http://target.test/ambient"
        )

        response = self.client.get("/api/history/export")

        exported = json.loads(response.content)["items"]
        self.assertEqual([item["url"] for item in exported], ["http://target.test/wp-admin/"])

    def test_clear_history_removes_tool_rows_and_keeps_ambient_traffic(self):
        TrafficRecord.objects.create(
            source="proxy", method="GET", url="http://target.test/wp-admin/",
            capture_context=self.run, project=self.project,
        )
        TrafficRecord.objects.create(
            source="proxy", method="GET", url="http://target.test/ambient"
        )

        response = self.client.post(
            "/api/history/bulk", data={"action": "clear"}, content_type="application/json"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["deleted"], 1)
        self.assertEqual([row.url for row in TrafficRecord.objects.all()], ["http://target.test/ambient"])

    def test_the_traffic_archive_still_reads_every_proxied_row(self):
        # Traffic is the operator's live view of the same stream, and a tool run
        # is a legitimate part of it: filtering the archive would hide the scan
        # from the tab that is watching it.
        TrafficRecord.objects.create(
            source="proxy", method="GET", url="http://target.test/wp-admin/",
            capture_context=self.run, project=self.project,
        )

        response = self.client.get("/api/traffic/records?limit=0&detail=summary")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["total"], 1)


class PersistToolHistoryTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(name="target project", target="http://target.test")
        self.run = TrafficCaptureContext.objects.create(
            name="nuclei · http://target.test", project=self.project
        )

    @patch("lab.views.call_engine_get")
    def test_a_tool_runs_exchanges_are_written_without_waiting_for_traffic(self, call_engine_get):
        # An operator who runs a scan and opens History has never opened Traffic,
        # so the Traffic poll cannot be what writes the scan's evidence.
        #
        # All three rows are written, including the unlinked one: persisting
        # every completed exchange is the archive's job, and the Traffic tab
        # needs the ambient traffic too. What History shows is a separate
        # decision, made by its own filter.
        call_engine_get.return_value = (200, [
            proxied_event(41, "http://target.test/", self.run.token),
            proxied_event(42, "http://target.test/wp-admin/", self.run.token),
            proxied_event(43, "http://target.test/ambient"),
        ])

        written = views._persist_tool_history(self.project)

        self.assertEqual(written, 3)
        rows = TrafficRecord.objects.order_by("proxy_event_id")
        self.assertEqual([row.url for row in rows], [
            "http://target.test/", "http://target.test/wp-admin/", "http://target.test/ambient",
        ])
        # The context resolves the run's project, so the run's rows are filed
        # under it rather than under whatever project happened to be active.
        # The ambient row has no context, so it falls back to the run that was
        # being persisted — which is what keeps it reachable from Traffic.
        self.assertEqual({row.project_id for row in rows}, {self.project.id})
        self.assertEqual(
            {row.scope_status for row in rows[:2]}, {"project_linked"},
        )
        self.assertEqual(rows[2].scope_status, "unscoped")
        self.assertEqual(rows[1].response_body, "<html>ok</html>")
        self.assertEqual(rows[1].response_size, 15)
        self.assertEqual(rows[1].latency_ms, 12)
        # And History shows the two run rows, not the ambient one.
        history = self.client.get("/api/history").json()["items"]
        self.assertNotIn("http://target.test/ambient", {item["url"] for item in history})

    @patch("lab.views.call_engine_get")
    def test_persisting_the_same_run_twice_writes_each_exchange_once(self, call_engine_get):
        # A nuclei job is polled until the operator moves on, and every poll
        # re-reads the snapshot. Without deduplication a scan of a few thousand
        # templates would be written once per poll.
        call_engine_get.return_value = (200, [
            proxied_event(51, "http://target.test/", self.run.token),
            proxied_event(52, "http://target.test/.env", self.run.token),
        ])

        views._persist_tool_history(self.project)
        views._persist_tool_history(self.project)

        self.assertEqual(TrafficRecord.objects.count(), 2)

    @patch("lab.views.call_engine_get")
    def test_an_unreachable_engine_leaves_history_untouched(self, call_engine_get):
        call_engine_get.return_value = (502, {"error": "engine unavailable"})
        TrafficRecord.objects.create(source="repeater", method="GET", url="http://target.test/keep")

        self.assertEqual(views._persist_tool_history(self.project), 0)
        self.assertEqual(TrafficRecord.objects.count(), 1)

    @patch("lab.views.call_engine_get")
    def test_a_request_that_never_got_a_response_is_still_recorded(self, call_engine_get):
        # A refused connection is what a scan of a closed port looks like, and it
        # is evidence: the operator asked and nothing answered. Dropping it would
        # make a target that refused every probe look like one never probed.
        call_engine_get.return_value = (200, [
            proxied_event(61, "http://target.test:81/", self.run.token, status=0),
        ])

        views._persist_tool_history(self.project)

        row = TrafficRecord.objects.get(proxy_event_id=61)
        self.assertIsNone(row.status_code)
        self.assertEqual(row.capture_context_id, self.run.id)

    @patch("lab.views.call_engine_get")
    def test_direct_tool_events_and_network_errors_reach_history_and_traffic(self, call_engine_get):
        call_engine_get.return_value = (200, [
            proxied_event(
                71, "http://target.test/direct", self.run.token, source="tool",
                status=None, error="Get target: EOF",
            ),
        ])

        self.assertEqual(views._persist_tool_history(self.project), 1)

        row = TrafficRecord.objects.get(source="tool", proxy_event_id=71)
        self.assertIsNone(row.status_code)
        self.assertEqual(row.notes, "Get target: EOF")
        self.assertEqual(row.capture_context_id, self.run.id)
        history_urls = {
            item["url"] for item in self.client.get("/api/history").json()["items"]
        }
        traffic_urls = {
            item["url"] for item in self.client.get("/api/traffic/records").json()["items"]
        }
        self.assertIn("http://target.test/direct", history_urls)
        self.assertIn("http://target.test/direct", traffic_urls)


class ScannerFailurePersistenceTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.project = Project.objects.create(name="scanner project", target="http://target.test")

    @patch("lab.views._persist_tool_history")
    @patch("lab.views.call_engine")
    @patch("lab.views._outbound_runtime")
    def test_failed_synchronous_scanner_persists_captured_network_errors(
        self, outbound_runtime, call_engine, persist_history
    ):
        operation = outbound_runtime.return_value.operation.return_value
        operation.__enter__.return_value = operation
        call_engine.return_value = (502, {"error": "scan returned EOF"})
        request = self.factory.post(
            "/api/scanner", data=json.dumps({"url": "http://target.test"}),
            content_type="application/json",
        )
        request.active_project = self.project

        response = views.scanner(request)

        self.assertEqual(response.status_code, 502)
        persist_history.assert_called_once_with(self.project)

    @patch("lab.views._persist_tool_history")
    @patch("lab.views.call_engine_get")
    def test_failed_corpus_job_poll_persists_captured_requests(
        self, call_engine_get, persist_history
    ):
        call_engine_get.return_value = (200, {
            "job_id": "corpus-test", "state": "failed", "error": "run failed",
        })
        request = self.factory.get("/api/scanner/corpus/jobs?job_id=corpus-test")
        request.active_project = self.project

        response = views.scanner_corpus_jobs(request)

        self.assertEqual(response.status_code, 200)
        persist_history.assert_called_once_with(self.project)


class OSINTFailurePersistenceTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(name="OSINT project", target="http://target.test")
        self.graph = OsintGraph.objects.create(project=self.project, name="OSINT graph")

    @patch("lab.views._persist_tool_history")
    @patch("lab.views.call_engine")
    @patch("lab.views._outbound_runtime")
    def test_failed_synchronous_transform_persists_captured_requests(
        self, outbound_runtime, call_engine, persist_history
    ):
        operation = outbound_runtime.return_value.operation.return_value
        operation.__enter__.return_value = operation
        call_engine.return_value = (502, {"error": "upstream request returned EOF"})
        response = self.client.post(
            f"/api/osint/graphs/{self.graph.id}/transform",
            data=json.dumps({
                "transform": "reverse_dns",
                "value": "target.test",
                "confirm_network": True,
            }),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 502)
        persist_history.assert_called_once_with(self.project)
