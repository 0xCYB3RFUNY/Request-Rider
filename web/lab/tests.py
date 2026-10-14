import base64
import io
import json
import os
import re
import tempfile
import threading
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen
from http.client import RemoteDisconnected
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock
from unittest.mock import patch

from django.db import OperationalError, connection
from django.http import StreamingHttpResponse
from django.test import Client, TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from . import views
from .agent_services import AgentProviderError, AgentRequestCancelled, OpenAICompatibleProvider, cancel_active_agent_requests, get_agent_provider
from .engine_client import EngineClient
from .middleware import ACTIVE_PROJECT_SESSION_KEY
from .models import IntruderAttack, OsintEntity, OsintGraph, OsintRelation, Project, ProjectEndpoint, ProjectSecret, ScannerRun, TargetJob, TrafficRecord, Workflow, WorkflowRun
from .views import _osint_transform_persist
from .ws_events import project_event_hub


def engine_is_running(base_url: str | None = None, timeout: float = 1.0) -> bool:
    """Whether the Go engine this gateway proxies to answers right now.

    A few gateway tests are integration tests in substance: the behaviour they
    assert lives in the engine, not in Django, so they cannot be made hermetic
    by mocking without asserting nothing. Those tests skip with this reason
    instead of failing with a 502, because "the engine is not running" and "the
    gateway is broken" must not look the same in a test report.
    """
    url = (base_url or ENGINE_URL_FOR_TESTS).rstrip("/") + "/health"
    try:
        with urlopen(url, timeout=timeout) as response:  # noqa: S310 - fixed 127.0.0.1 URL
            return 200 <= response.status < 300
    except (URLError, OSError, ValueError):
        return False


ENGINE_URL_FOR_TESTS = os.environ.get("ENGINE_URL", "http://127.0.0.1:8081")
REQUIRES_ENGINE = "requires a running Go engine on {url}"


class _VisibleText(HTMLParser):
    """Collect what a reader actually sees, in reading order.

    Attribute values, the stylesheet and the script are not visible text, and
    searching raw HTML for a wording finds both a translated label and an
    English word in a file name. Reading text nodes only is what makes "this
    page speaks Ukrainian" a statement about the page rather than about its
    markup.
    """

    SKIP = {"style", "script", "head", "title"}
    # A placeholder, a title or a label is read on screen, so it is visible text
    # that lives in an attribute. Leaving it out would let a search field keep
    # an English placeholder on a Ukrainian page and the check would not notice.
    SEEN = ("placeholder", "aria-label", "title", "alt")

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self._skipped = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self._skipped += 1
        if not self._skipped:
            for name, value in attrs:
                if name in self.SEEN and value and value.strip():
                    self.parts.append(" ".join(value.split()))

    def handle_endtag(self, tag):
        if tag in self.SKIP and self._skipped:
            self._skipped -= 1

    def handle_data(self, data):
        if not self._skipped and data.strip():
            self.parts.append(" ".join(data.split()))


def visible_text(markup):
    """Return the normalized visible text of a rendered page."""
    parser = _VisibleText()
    parser.feed(markup)
    parser.close()
    return " ".join(parser.parts)


def shows_wording(text, wording):
    """Whether a wording appears in visible text as a whole word or phrase.

    A plain substring search is not the question being asked. The data the
    report prints legitimately contains these letters — a `subdomain_of`
    relation holds `of`, and a graph named «Мова звіту» holds `з` — and a
    substring match would report that data as untranslated chrome. Word
    boundaries are what separate "the page says of" from "the page prints a
    relation whose name ends in of".
    """
    return re.search(rf"(?<![\w]){re.escape(wording)}(?![\w])", text) is not None


class ProjectEventStatusTests(TestCase):
    def test_project_event_status_reports_transport_capability(self):
        response = self.client.get('/api/project-events/status')
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json().get('websocket'), bool)


class OastCallbackTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_oast_post_callback_is_accepted_without_project(self):
        response = self.client.post(
            "/api/oast",
            data=json.dumps({"source": "fixture-listener", "event": "dns-lookup"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload.get("ok"))
        self.assertTrue(payload.get("received"))

    def test_oast_get_callback_is_accepted(self):
        response = self.client.get("/api/oast?project_id=")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json().get("ok"))

    def test_oast_callback_emits_project_event_when_project_active(self):
        project = Project.objects.create(name="OAST project")
        session = self.client.session
        session[ACTIVE_PROJECT_SESSION_KEY] = project.id
        session.save()
        seen = []
        original_emit = project_event_hub.emit
        project_event_hub.emit = lambda project_id, event: seen.append((project_id, event))
        try:
            response = self.client.post(
                "/api/oast",
                data=json.dumps({"source": "fixture-listener"}),
                content_type="application/json",
            )
        finally:
            project_event_hub.emit = original_emit
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json().get("project_id"), project.id)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][0], project.id)
        self.assertEqual(seen[0][1].get("type"), "oast")


class HistoryAndSettingsTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_project_hub_ingests_endpoint_technology_and_secret_metadata(self):
        project = Project.objects.create(name="Hub workspace", target="http://fixture.test/")
        record = TrafficRecord.objects.create(
            project=project,
            source="repeater",
            method="POST",
            url="http://fixture.test/api/items?id=7",
            request_headers={"Authorization": "Bearer eyJheader.payload.signature"},
            response_headers={"Server": "fixture", "Content-Type": "application/json"},
            status_code=500,
        )
        self.assertTrue(ProjectEndpoint.objects.filter(project=project, path="/api/items", method="POST").exists())
        self.assertTrue(ProjectSecret.objects.filter(project=project, secret_type="api_key").exists())
        response = self.client.get(f"/api/projects/{project.id}/hub")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["metrics"]["endpoints"], 1)
        self.assertNotIn("eyJheader", response.content.decode())

    def test_project_hub_lists_osint_graph_counts(self):
        project = Project.objects.create(name="Graph hub", target="https://graph.test/")
        expected = {}
        for index in range(4):
            graph = OsintGraph.objects.create(
                project=project,
                version=index + 1,
                name=f"Graph snapshot {index}",
                source="ui",
            )
            source = OsintEntity.objects.create(
                project=project,
                graph=graph,
                entity_type="domain",
                identity=f"graph-{index}.test",
            )
            target = OsintEntity.objects.create(
                project=project,
                graph=graph,
                entity_type="ip",
                identity=f"192.0.2.{index + 1}",
            )
            if index == 0:
                OsintRelation.objects.create(
                    project=project,
                    graph=graph,
                    relation_type="resolves_to",
                    source_entity=source,
                    target_entity=target,
                )
            expected[graph.name] = {
                "entities": 2,
                "relations": 1 if index == 0 else 0,
            }

        with CaptureQueriesContext(connection) as captured:
            response = self.client.get(f"/api/projects/{project.id}/hub")
        self.assertEqual(response.status_code, 200)
        actual = {
            item["name"]: {
                "entities": item["entities"],
                "relations": item["relations"],
            }
            for item in response.json()["osint_graphs"]
        }
        self.assertEqual(actual, expected)
        graph_count_queries = [
            query["sql"].upper()
            for query in captured.captured_queries
            if OsintEntity._meta.db_table.upper() in query["sql"].upper()
            and OsintRelation._meta.db_table.upper() in query["sql"].upper()
            and "COUNT(" in query["sql"].upper()
        ]
        self.assertEqual(
            len(graph_count_queries),
            1,
            msg="entity/relation counts should be fetched in one grouped query",
        )

    @patch("lab.views.call_engine")
    def test_osint_run_auto_attaches_to_active_project(self, call_engine):
        project = Project.objects.create(name="OSINT auto project")
        self.client.post("/api/project-context", data=json.dumps({"project_id": project.id}), content_type="application/json")
        call_engine.return_value = (200, {
            "url": "https://example.test/",
            "host": "example.test",
            "dns": {"host": ["203.0.113.10"]},
            "technologies": ["nginx"],
        })
        response = self.client.post("/api/osint", data=json.dumps({"url": "https://example.test/"}), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(OsintGraph.objects.filter(project=project).exists())
        self.assertTrue(OsintEntity.objects.filter(project=project, entity_type="ip", identity="203.0.113.10").exists())

    @patch("lab.views.call_engine")
    def test_scanner_run_journals_project_scan(self, call_engine):
        from .models import ScannerRun
        project = Project.objects.create(name="Scan journal")
        self.client.post("/api/project-context", data=json.dumps({"project_id": project.id}), content_type="application/json")
        call_engine.return_value = (200, {
            "url": "https://example.test/",
            "findings": [{"title": "Probe issue", "severity": "HIGH", "evidence": "e"}],
            "summary": {"findings_count": 1},
            "details": {},
        })
        response = self.client.post("/api/scanner", data=json.dumps({"url": "https://example.test/"}), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        run = ScannerRun.objects.filter(project=project).first()
        self.assertIsNotNone(run)
        self.assertEqual(run.engine, "builtin")
        self.assertEqual(run.summary["highest_severity"], "HIGH")
        hub = self.client.get(f"/api/projects/{project.id}/hub").json()
        self.assertEqual(hub["metrics"]["scans"], 1)
        self.assertEqual(hub["scanner_runs"][0]["findings"][0]["title"], "Probe issue")

    @patch("lab.views.call_engine")
    def test_osint_graph_transform_persists_archive_urls_and_metadata(self, call_engine):
        project = Project.objects.create(name="Archive graph project")
        graph = OsintGraph.objects.create(project=project, name="Archive graph", source="ui")
        # The archive index is attacker-controllable input: captured credential
        # URLs, fragments and duplicate captures must not become identities.
        call_engine.return_value = (200, {
            "transform": "wayback_urls",
            "observed_at": "2026-01-01T00:00:00Z",
            "local_only": False,
            "network_used": True,
            "entities": [
                {"type": "domain", "identity": "yandex.ru", "provenance": {"source": "transform_input"}},
                {"type": "url", "identity": "https://yandex.ru/a", "provenance": {"source": "wayback", "archive_index": "timemap"}},
                {"type": "url", "identity": "https://yandex.ru/a"},
                {"type": "url", "identity": "https://yandex.ru/b", "provenance": {"source": "wayback"}},
            ],
            "relations": [
                {"type": "observed_at", "source_type": "url", "source": "https://yandex.ru/a", "target_type": "domain", "target": "yandex.ru"},
            ],
            "warnings": ["the timemap archive index stream ended early after 2 rows; the collected URLs are a partial view"],
            "metadata": {"archive_index": "timemap", "archive_rows": 3, "archive_urls": 2, "archive_stream_complete": False},
        })
        response = self.client.post(
            f"/api/osint/graphs/{graph.id}/transform",
            data=json.dumps({"transform": "wayback_urls", "value": "yandex.ru", "confirm_network": True}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        result = response.json()["transform_result"]
        self.assertEqual(result["status"], "completed")
        # Four reported entities, three stored identities: the repeated capture
        # of one URL collapses into a single graph identity.
        self.assertEqual(result["entity_count"], 4)
        self.assertEqual(result["metadata"]["archive_index"], "timemap")
        self.assertEqual(result["metadata"]["archive_stream_complete"], False)
        self.assertTrue(result["warnings"])
        # A repeated capture of one URL stays one identity in the graph.
        identities = set(OsintEntity.objects.filter(graph=graph).values_list("identity", flat=True))
        self.assertEqual(identities, {"yandex.ru", "https://yandex.ru/a", "https://yandex.ru/b"})
        stored_graph = OsintGraph.objects.get(id=graph.id)
        self.assertEqual(stored_graph.metadata["archive_index"], "timemap")
        self.assertEqual(stored_graph.metadata["archive_stream_complete"], False)

    @patch("lab.views.call_engine")
    def test_osint_graph_transform_surfaces_every_failed_archive_index(self, call_engine):
        project = Project.objects.create(name="Archive failure project")
        graph = OsintGraph.objects.create(project=project, name="Archive failure", source="ui")
        call_engine.return_value = (400, {
            "error": "WAYBACK_LOOKUP_FAILED: no public archive index answered for yandex.ru: "
                     "cdx index: archive returned HTTP 429; timemap index: archive returned HTTP 503",
            "reason": "OSINT_TRANSFORM_FAILED",
        })
        response = self.client.post(
            f"/api/osint/graphs/{graph.id}/transform",
            data=json.dumps({"transform": "wayback_urls", "value": "yandex.ru", "confirm_network": True}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        payload = response.json()
        # Both attempted indexes stay visible instead of one opaque code.
        self.assertIn("HTTP 429", payload["error"])
        self.assertIn("HTTP 503", payload["error"])
        self.assertEqual(payload["transform_result"]["status"], "failed")
        self.assertEqual(payload["transform_result"]["entity_count"], 0)
        self.assertEqual(OsintEntity.objects.filter(graph=graph).count(), 0)

    @patch("lab.views.call_engine")
    def test_osint_graph_transform_persists_certificate_index_coverage(self, call_engine):
        project = Project.objects.create(name="Certificate graph project")
        graph = OsintGraph.objects.create(project=project, name="Certificate graph", source="ui")
        # The certificate chain merges every index that answered, so the
        # operator can see the coverage behind a result without repeating it.
        call_engine.return_value = (200, {
            "transform": "subdomains",
            "observed_at": "2026-01-01T00:00:00Z",
            "local_only": False,
            "network_used": True,
            "entities": [
                {"type": "domain", "identity": "yandex.ru"},
                {"type": "subdomain", "identity": "www.yandex.ru", "provenance": {"source": "certificate_transparency"}},
                {"type": "subdomain", "identity": "api.yandex.ru", "provenance": {"source": "certificate_transparency"}},
            ],
            "relations": [
                {"type": "subdomain_of", "source_type": "subdomain", "source": "www.yandex.ru", "target_type": "domain", "target": "yandex.ru"},
            ],
            "warnings": [
                "the certspotter certificate index was read for 7 page(s); stopped where the index reported 0 of 10 requests left",
            ],
            "metadata": {
                "cert_indexes": {"crt.sh": 1300, "crt.name": 176936, "certspotter": 843},
                "cert_names": 176937,
            },
        })
        response = self.client.post(
            f"/api/osint/graphs/{graph.id}/transform",
            data=json.dumps({"transform": "subdomains", "value": "yandex.ru", "confirm_network": True}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        result = response.json()["transform_result"]
        self.assertEqual(result["status"], "completed")
        # A DNS guess and an index name stay distinguishable in provenance.
        self.assertEqual(
            OsintEntity.objects.get(graph=graph, identity="www.yandex.ru").provenance["source"],
            "certificate_transparency",
        )
        self.assertEqual(result["metadata"]["cert_names"], 176937)
        self.assertEqual(result["metadata"]["cert_indexes"]["crt.name"], 176936)
        self.assertTrue(result["warnings"])
        self.assertIn("certspotter", result["warnings"][0])

    @patch("lab.views.call_engine_get")
    @patch("lab.views.call_engine")
    def test_osint_transform_job_polls_progress_and_persists_on_completion(self, call_engine, call_engine_get):
        project = Project.objects.create(name="Transform job project")
        graph = OsintGraph.objects.create(project=project, name="Transform job", source="ui")
        # A running transform only carries progress, never a partial result, so
        # the browser cannot mistake a half-finished run for a finished one.
        call_engine_get.return_value = (200, {
            "job_id": "osint-1", "state": "running",
            "progress": {"phase": "running", "names": 1200, "indexes": 2, "indexes_total": 5, "elapsed_ms": 4200},
        })
        running = self.client.get(f"/api/osint/graphs/{graph.id}/transform/jobs/osint-1")
        self.assertEqual(running.status_code, 200)
        self.assertEqual(running.json()["state"], "running")
        self.assertNotIn("result", running.json())
        self.assertEqual(running.json()["progress"]["names"], 1200)

        call_engine_get.return_value = (200, {
            "job_id": "osint-1", "state": "completed",
            "progress": {"phase": "completed", "names": 9, "elapsed_ms": 5000},
            "result": {
                "transform": "subdomains", "value": "example.test", "observed_at": "2026-01-01T00:00:00Z",
                "local_only": False, "network_used": True,
                "entities": [
                    {"type": "domain", "identity": "example.test"},
                    {"type": "subdomain", "identity": "www.example.test", "provenance": {"source": "certificate_transparency"}},
                ],
                "relations": [
                    {"type": "subdomain_of", "source_type": "subdomain", "source": "www.example.test", "target_type": "domain", "target": "example.test"},
                ],
                "warnings": [], "metadata": {"cert_names": 1},
            },
        })
        finished = self.client.get(f"/api/osint/graphs/{graph.id}/transform/jobs/osint-1")
        self.assertEqual(finished.status_code, 200)
        self.assertEqual(finished.json()["state"], "completed")
        self.assertEqual(finished.json()["transform_result"]["status"], "completed")
        self.assertTrue(OsintEntity.objects.filter(graph=graph, identity="www.example.test").exists())
        self.assertTrue(OsintRelation.objects.filter(graph=graph).exists())

    @patch("lab.views.call_engine_get")
    @patch("lab.views.call_engine")
    def test_osint_transform_job_reports_the_real_elapsed_time(self, call_engine, call_engine_get):
        project = Project.objects.create(name="Transform elapsed project")
        graph = OsintGraph.objects.create(project=project, name="Transform elapsed", source="ui")
        call_engine_get.return_value = (200, {
            "job_id": "osint-time", "state": "completed",
            "progress": {"phase": "completed", "names": 9, "elapsed_ms": 38756},
            "result": {
                "transform": "subdomains", "value": "example.test", "observed_at": "2026-01-01T00:00:00Z",
                "local_only": False, "network_used": True,
                "entities": [{"type": "subdomain", "identity": "www.example.test"}],
                "relations": [], "warnings": [],
                "metadata": {"cert_zone": "example.test"},
            },
        })
        response = self.client.get(f"/api/osint/graphs/{graph.id}/transform/jobs/osint-time")
        self.assertEqual(response.status_code, 200)
        # The duration is how long the run really took, not the zero the persist
        # path fills in before the engine has reported it.
        self.assertEqual(response.json()["transform_result"]["duration_ms"], 38756)
        self.assertEqual(response.json()["transform_result"]["metadata"]["cert_zone"], "example.test")

    @patch("lab.views.call_engine_get")
    @patch("lab.views.call_engine")
    def test_osint_transform_job_reports_database_write_failure(self, call_engine, call_engine_get):
        project = Project.objects.create(name="Transform busy project")
        graph = OsintGraph.objects.create(project=project, name="Transform busy", source="ui")
        call_engine_get.return_value = (200, {
            "job_id": "osint-busy", "state": "completed",
            "progress": {"phase": "completed", "names": 1},
            "result": {
                "transform": "subdomains", "value": "example.test", "observed_at": "2026-01-01T00:00:00Z",
                "local_only": False, "network_used": True,
                "entities": [{"type": "subdomain", "identity": "www.example.test"}],
                "relations": [], "warnings": [], "metadata": {},
            },
        })
        with patch("lab.views.upsert_graph", side_effect=OperationalError("database unavailable")):
            response = self.client.get(f"/api/osint/graphs/{graph.id}/transform/jobs/osint-busy")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["reason"], "DATABASE_WRITE_FAILED")
        self.assertNotIn("transform_result", response.json())
        self.assertEqual(OsintEntity.objects.filter(graph=graph).count(), 0)

    @patch("lab.views.call_engine_get")
    @patch("lab.views.call_engine")
    def test_osint_transform_job_reports_cancel_without_a_result(self, call_engine, call_engine_get):
        project = Project.objects.create(name="Transform cancel project")
        graph = OsintGraph.objects.create(project=project, name="Transform cancel", source="ui")
        # A cancelled transform must not present its partial work as completed.
        call_engine_get.return_value = (200, {
            "job_id": "osint-2", "state": "cancelled",
            "progress": {"phase": "cancelled", "names": 640},
            "reason": "ROUTE_CHANGED",
        })
        response = self.client.get(f"/api/osint/graphs/{graph.id}/transform/jobs/osint-2")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["state"], "cancelled")
        self.assertEqual(response.json()["reason"], "ROUTE_CHANGED")
        self.assertNotIn("transform_result", response.json())
        self.assertEqual(OsintEntity.objects.filter(graph=graph).count(), 0)

    @patch("lab.views.call_engine")
    def test_osint_transform_job_actions_are_forwarded(self, call_engine):
        project = Project.objects.create(name="Transform action project")
        graph = OsintGraph.objects.create(project=project, name="Transform action", source="ui")
        for action, expected in (("pause", "paused"), ("resume", "running"), ("cancel", "cancelled")):
            call_engine.return_value = (200, {"job_id": "osint-3", "state": expected})
            response = self.client.post(f"/api/osint/graphs/{graph.id}/transform/jobs/osint-3/{action}", data="{}", content_type="application/json")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["state"], expected)
            self.assertIn(f"/proxy/osint/transform/jobs/osint-3/{action}", call_engine.call_args[0][0])

    @patch("lab.views.call_engine")
    def test_osint_transform_job_requires_network_confirmation(self, call_engine):
        project = Project.objects.create(name="Transform confirm project")
        graph = OsintGraph.objects.create(project=project, name="Transform confirm", source="ui")
        response = self.client.post(
            f"/api/osint/graphs/{graph.id}/transform/jobs",
            data=json.dumps({"transform": "subdomains", "value": "example.test"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["reason"], "NETWORK_CONFIRMATION_REQUIRED")
        call_engine.assert_not_called()

    def test_osint_large_result_is_delivered_as_a_complete_file(self):
        project = Project.objects.create(name="File delivery project")
        graph = OsintGraph.objects.create(project=project, name="File delivery", source="ui")
        from lab import osint_exports
        from django.test import override_settings
        with tempfile.TemporaryDirectory() as directory, override_settings(OSINT_EXPORT_DIR=directory):
            rows = osint_exports.FILE_ENTITY_ROWS + 500
            payload = {
                "transform": "subdomains", "value": "example.test", "observed_at": "2026-01-01T00:00:00Z",
                "local_only": False, "network_used": True,
                "entities": [
                    {"type": "domain", "identity": "example.test"},
                    *({"type": "subdomain", "identity": f"host{index}.example.test"} for index in range(rows)),
                ],
                "relations": [],
                "warnings": [], "metadata": {},
            }
            response = _osint_transform_persist(graph, payload, "http://testserver")
            result = response["transform_result"]
            # Nothing is dropped: the file holds every row the transform found.
            self.assertTrue(result["delivered_as_file"])
            self.assertEqual(result["metadata"]["result_file"]["rows"], rows + 1)
            self.assertTrue(any("written to" in warning for warning in result["warnings"]))
            stored = OsintEntity.objects.filter(graph=graph)
            self.assertEqual(stored.count(), 2)
            pointer = stored.get(entity_type="url")
            self.assertEqual(pointer.properties["rows"], rows + 1)
            # The pointer points at the readable page, and both the raw form and
            # the download still carry every row, so paging the viewer never
            # becomes a way of losing evidence.
            name = pointer.properties["csv"]
            self.assertEqual(pointer.properties["open_url"], f"/api/osint/graphs/{graph.id}/files/{name}")
            opened = self.client.get(f"/api/osint/graphs/{graph.id}/files/{name}")
            self.assertEqual(opened.status_code, 200)
            self.assertContains(opened, "host0.example.test")
            raw = self.client.get(f"/api/osint/graphs/{graph.id}/files/{name}?raw=1")
            self.assertEqual(raw.status_code, 200)
            self.assertIn("host0.example.test", raw.content.decode())
            self.assertIn(f"host{rows - 1}.example.test", raw.content.decode())
            downloaded = self.client.get(f"/api/osint/graphs/{graph.id}/files/{name}?download=1")
            self.assertEqual(downloaded.status_code, 200)
            self.assertIn("attachment", downloaded["Content-Disposition"])
            self.assertIn(f"host{rows - 1}.example.test", downloaded.content.decode())

    def test_osint_result_files_directory_answers_in_both_slash_forms(self):
        # The directory form used to fall through to the framework debug 404,
        # which told an analyst nothing. APPEND_SLASH only ever adds a slash, so
        # the route carries one and the slashless form is redirected onto it.
        project = Project.objects.create(name="Files listing project")
        graph = OsintGraph.objects.create(project=project, name="Files listing", source="ui")
        with_slash = self.client.get(f"/api/osint/graphs/{graph.id}/files/")
        self.assertEqual(with_slash.status_code, 200)
        self.assertContains(with_slash, "Result files")
        without_slash = self.client.get(f"/api/osint/graphs/{graph.id}/files")
        self.assertEqual(without_slash.status_code, 301)
        self.assertTrue(without_slash["Location"].endswith("/files/"))
        followed = self.client.get(without_slash["Location"])
        self.assertEqual(followed.status_code, 200)
        self.assertEqual(self.client.get("/api/osint/graphs/999999/files/").status_code, 404)

    def test_osint_small_result_stays_in_the_graph(self):
        project = Project.objects.create(name="Small result project")
        graph = OsintGraph.objects.create(project=project, name="Small result", source="ui")
        from lab import osint_exports
        self.assertFalse(osint_exports.needs_file_delivery({
            "entities": [{"type": "subdomain", "identity": f"host{index}.example.test"} for index in range(10)],
        }))

    def test_osint_export_root_never_resolves_to_the_working_directory(self):
        # A `Path` is always truthy, so an unset setting must be checked as a
        # string: otherwise the exports land wherever the server was started.
        from lab import osint_exports
        for unset in (None, "", "   "):
            with override_settings(OSINT_EXPORT_DIR=unset):
                root = osint_exports.export_root()
                self.assertTrue(root.is_absolute(), f"{unset!r} resolved to {root}")
                self.assertIn("osint-exports", str(root))

    def test_osint_file_name_cannot_escape_the_export_directory(self):
        project = Project.objects.create(name="Traversal project")
        OsintGraph.objects.create(project=project, name="Traversal", source="ui")
        from lab import osint_exports
        from lab.osint_graph import OsintGraphError
        with tempfile.TemporaryDirectory() as directory, override_settings(OSINT_EXPORT_DIR=directory):
            for hostile in ("../secret.csv", "..%2Fsecret.csv", "/etc/passwd", "sub/dir.csv", ".."):
                with self.assertRaises(OsintGraphError):
                    osint_exports.resolve_export_path(1, hostile)

    @patch("lab.views.call_engine")
    def test_scanner_run_updates_project_tech_stack(self, call_engine):
        project = Project.objects.create(name="Scanner auto project")
        self.client.post("/api/project-context", data=json.dumps({"project_id": project.id}), content_type="application/json")
        call_engine.return_value = (200, {
            "url": "https://example.test/",
            "findings": [{"title": "Fixture issue", "severity": "HIGH", "confidence_percent": 90, "evidence": "fixture"}],
            "details": {"technologies": ["Django"]},
        })
        response = self.client.post("/api/scanner", data=json.dumps({"url": "https://example.test/"}), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Django", Project.objects.get(id=project.id).tech_stack["scanner"])

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_forwards_uploaded_files(self, call_engine):
        call_engine.return_value = (200, {"url": "https://example.test/", "findings": [{"title": "[CVE-2024-0001] X", "severity": "HIGH", "cve": ["CVE-2024-0001"]}], "stats": {"engine": "nuclei"}})
        response = self.client.post(
            "/api/scanner/nuclei",
            data=json.dumps({"url": "https://example.test/", "files": [{"name": "a.yaml", "content": "id: a\n"}]}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("CVE-2024-0001", response.json()["findings"][0]["title"])
        # An absent path stays empty; the engine falls back to the file name.
        # `encoding` travels with every file and says how to read it: an upload of
        # a whole folder sends its non-YAML support files base64-encoded, and the
        # engine refuses a name it does not recognise rather than storing raw
        # bytes that are really binary. The empty string is therefore "plain text",
        # and it has to be forwarded as it stands: dropping the key would make the
        # two sides disagree about how to read the same body.
        self.assertEqual(
            call_engine.call_args.args[1]["files"],
            [{"name": "a.yaml", "path": "", "content": "id: a\n", "encoding": ""}],
        )

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_preserves_folder_paths(self, call_engine):
        """A directory upload must keep its layout: nuclei templates repeat the
        same file name in different folders, and a flat upload drops them."""
        call_engine.return_value = (200, {"url": "https://example.test/", "findings": [], "stats": {"engine": "nuclei"}})
        response = self.client.post(
            "/api/scanner/nuclei",
            data=json.dumps({
                "url": "https://example.test/",
                "files": [
                    {"name": "CVE-2024-1.yaml", "path": "http/cves/2024/CVE-2024-1.yaml", "content": "id: a\n"},
                    {"name": "CVE-2024-1.yaml", "path": "ssl/2024/CVE-2024-1.yaml", "content": "id: b\n"},
                ],
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        forwarded = call_engine.call_args.args[1]["files"]
        self.assertEqual([item["path"] for item in forwarded], ["http/cves/2024/CVE-2024-1.yaml", "ssl/2024/CVE-2024-1.yaml"])
        self.assertNotEqual(forwarded[0]["path"], forwarded[1]["path"])

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_returns_per_file_report(self, call_engine):
        call_engine.return_value = (200, {
            "url": "https://example.test/",
            "findings": [{"title": "[CVE-2024-0001] X", "severity": "HIGH", "cve": ["CVE-2024-0001"]}],
            "templates": [
                {"name": "a.yaml", "template_id": "CVE-2024-0001", "severity": "HIGH", "status": "matched", "cve": ["CVE-2024-0001"], "matches": 1},
                {"name": "b.yaml", "template_id": "quiet", "severity": "INFO", "status": "not_matched", "matches": 0},
                {"name": "c.yaml", "status": "invalid", "reason": "missing info.author", "matches": 0},
            ],
            "stats": {"engine": "nuclei", "files": 3, "matched": 1, "not_matched": 1, "invalid": 1},
        })
        response = self.client.post(
            "/api/scanner/nuclei",
            data=json.dumps({"url": "https://example.test/", "files": [{"name": "a.yaml", "content": "id: a\n"}]}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        templates = response.json()["templates"]
        self.assertEqual([item["status"] for item in templates], ["matched", "not_matched", "invalid"])
        self.assertIn("info.author", templates[2]["reason"])

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_passes_the_run_plan_through(self, call_engine):
        """A planned run reports how it was split and why.

        The number of nuclei invocations is the first thing an operator needs when
        a large collection takes longer than expected, and the reason it is that
        number is the only thing that makes the wait explicable. Both travel
        through the gateway untouched.
        """
        call_engine.return_value = (200, {
            "url": "https://example.test/",
            "findings": [],
            "templates": [
                {"name": "a.yaml", "template_id": "one", "status": "not_matched", "matches": 0},
                {"name": "b.yaml", "template_id": "two", "status": "duplicate",
                 "reason": "Not run separately: this file is byte-identical to a.yaml", "matches": 0},
            ],
            "stats": {
                "engine": "nuclei", "files": 2, "not_matched": 1, "duplicate": 1,
                "batches": 2, "planned_files": 1, "not_planned": 1, "id_multiplicity": 2,
                "invocation_reason": "2 invocations are required because 2 uploaded files declare the same template id, and Nuclei loads exactly one file per template id",
                "deduplication": {"files_uploaded": 2, "unique_content": 1, "collapsed": 1},
                "validation": {"refused": 0},
            },
        })
        response = self.client.post(
            "/api/scanner/nuclei",
            data=json.dumps({"url": "https://example.test/", "files": [{"name": "a.yaml", "content": "id: a\n"}]}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual([item["status"] for item in payload["templates"]], ["not_matched", "duplicate"])
        stats = payload["stats"]
        self.assertEqual(stats["batches"], 2)
        self.assertEqual(stats["not_planned"], 1)
        self.assertEqual(stats["deduplication"]["collapsed"], 1)
        self.assertIn("one file per template id", stats["invocation_reason"])

    def test_durable_scanner_stats_keep_the_plan_and_drop_the_run_output(self):
        """The plan is project evidence; a console log and a path list are not.

        A planned run keeps stdout, stderr and the per-invocation output for every
        nuclei call, and the duplicate summary lists up to two hundred file groups
        with all of their alias paths. Those stay whole in the run report the
        operator reads, and none of it is copied into a journal row that would
        then grow with every scan.
        """
        from lab.views import _durable_scanner_stats

        stats = {
            "engine": "nuclei", "files": 2, "matched": 1,
            "batches": 2, "planned_files": 2, "not_planned": 0, "id_multiplicity": 2,
            "invocation_reason": "2 invocations are required because 2 uploaded files declare the same template id, and Nuclei loads exactly one file per template id",
            "stdout": "batch 1\n[INF] Scanning", "stderr": "batch 1\n[WRN] ...",
            "args": ["batch 1: nuclei -duc -silent"],
            "invocations": [{"batch": 1, "stdout": "..."}],
            "batch_detail": [{"index": 1, "files": 1}],
            "deduplication": {"files_uploaded": 2, "unique_content": 1, "collapsed": 1,
                              "groups": [{"kept": "a.yaml", "paths": ["b.yaml"]}]},
            "validation_diagnostics": "[FTL] ...",
        }
        durable = _durable_scanner_stats(stats)
        self.assertEqual(durable["batches"], 2)
        self.assertEqual(durable["id_multiplicity"], 2)
        self.assertIn("one file per template id", durable["invocation_reason"])
        self.assertEqual(durable["full_output"], "run report")
        for key in ("stdout", "stderr", "args", "invocations", "batch_detail",
                    "deduplication", "validation_diagnostics"):
            self.assertNotIn(key, durable)
        self.assertEqual(_durable_scanner_stats(None), {})

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_records_per_file_report_in_project(self, call_engine):
        project = Project.objects.create(name="Nuclei journal")
        self.client.post("/api/project-context", data=json.dumps({"project_id": project.id}), content_type="application/json")
        call_engine.return_value = (200, {
            "url": "https://example.test/",
            "findings": [{"title": "[CVE-2024-0001] X", "severity": "HIGH", "cve": ["CVE-2024-0001"]}],
            "templates": [
                {"name": "a.yaml", "template_id": "CVE-2024-0001", "severity": "HIGH", "status": "matched", "cve": ["CVE-2024-0001"], "matches": 1},
                {"name": "c.yaml", "status": "invalid", "reason": "missing info.author", "matches": 0},
            ],
            "stats": {"engine": "nuclei", "files": 2},
        })
        response = self.client.post(
            "/api/scanner/nuclei",
            data=json.dumps({"url": "https://example.test/", "files": [{"name": "a.yaml", "content": "id: a\n"}]}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        run = ScannerRun.objects.get(project_id=project.id)
        self.assertEqual([item["name"] for item in run.summary["templates"]], ["a.yaml", "c.yaml"])
        self.assertEqual(run.summary["templates"][0]["status"], "matched")
        self.assertEqual(run.summary["templates"][1]["status"], "invalid")
        self.assertEqual(run.findings[0]["cve"], ["CVE-2024-0001"])

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_passes_rejection_report_through(self, call_engine):
        """A fully rejected upload is a client error, and the per-file reasons
        must survive the non-2xx response."""
        call_engine.return_value = (400, {
            "error": "no uploaded template is valid for nuclei",
            "reason": "SCANNER_NUCLEI_NO_VALID_TEMPLATES",
            "templates": [{"name": "a.yaml", "status": "invalid", "reason": "missing info.author", "matches": 0}],
        })
        response = self.client.post(
            "/api/scanner/nuclei",
            data=json.dumps({"url": "https://example.test/", "files": [{"name": "a.yaml", "content": "id: a\n"}]}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["reason"], "SCANNER_NUCLEI_NO_VALID_TEMPLATES")
        self.assertIn("info.author", response.json()["templates"][0]["reason"])

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_upload_accumulates_chunks(self, call_engine):
        """A whole folder arrives over many requests; every chunk after the
        first must reuse the open session id."""
        call_engine.return_value = (200, {"upload_id": "abc123", "templates": [], "staged": 2, "staged_all": 2})
        first = self.client.post(
            "/api/scanner/nuclei/upload",
            data=json.dumps({"files": [{"name": "a.yaml", "content": "id: a\n"}]}),
            content_type="application/json",
        )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(call_engine.call_args.args[1]["upload_id"], "")
        second = self.client.post(
            "/api/scanner/nuclei/upload",
            data=json.dumps({"upload_id": "abc123", "files": [{"name": "b.yaml", "path": "sub/b.yaml", "content": "id: b\n"}]}),
            content_type="application/json",
        )
        self.assertEqual(second.status_code, 200)
        forwarded = call_engine.call_args.args[1]
        self.assertEqual(forwarded["upload_id"], "abc123")
        self.assertEqual(forwarded["files"][0]["path"], "sub/b.yaml")
        self.assertEqual(first.json()["upload_id"], "abc123")

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_upload_forwards_binary_support_files(self, call_engine):
        call_engine.return_value = (200, {"upload_id": "abc123", "templates": [], "staged": 1, "staged_all": 1})
        content = base64.b64encode(b"\x00\x7f\x80\xff").decode("ascii")
        response = self.client.post(
            "/api/scanner/nuclei/upload",
            data=json.dumps({
                "files": [{
                    "name": "payload.bin",
                    "path": "templates/http/helpers/payload.bin",
                    "content": content,
                    "encoding": "base64",
                }],
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        forwarded = call_engine.call_args.args[1]["files"][0]
        self.assertEqual(forwarded["path"], "templates/http/helpers/payload.bin")
        self.assertEqual(forwarded["content"], content)
        self.assertEqual(forwarded["encoding"], "base64")

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_upload_rejects_invalid_binary_encoding(self, call_engine):
        response = self.client.post(
            "/api/scanner/nuclei/upload",
            data=json.dumps({
                "files": [{"name": "payload.bin", "content": "%%%invalid%%%", "encoding": "base64"}],
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("invalid base64", response.json()["error"])
        self.assertFalse(call_engine.called)

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_upload_rejects_invalid_input(self, call_engine):
        for payload in [{}, {"files": []}, {"files": [{"content": "id: a\n"}]}, {"files": [{"name": "a.yaml"}]}]:
            response = self.client.post("/api/scanner/nuclei/upload", data=json.dumps(payload), content_type="application/json")
            self.assertEqual(response.status_code, 400, payload)
        self.assertFalse(call_engine.called)

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_local_forwards_upload_and_target(self, call_engine):
        """The local route is what runs the `flow:` templates the binary refuses.

        It is a separate route rather than a flag on `run` because the two
        consume the same staging directory: sending one upload through both
        would find the second call's directory already consumed, which is a
        confusing error for something that is really two separate runs.
        """
        call_engine.return_value = (200, {"url": "https://example.test/", "templates": [], "count": 0})
        response = self.client.post(
            "/api/scanner/nuclei/local",
            data=json.dumps({"url": "https://example.test/", "upload_id": "abc123"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        path, forwarded = call_engine.call_args.args[0], call_engine.call_args.args[1]
        self.assertEqual(path, "/proxy/scanner/nuclei/local")
        self.assertEqual(forwarded["upload_id"], "abc123")
        self.assertEqual(forwarded["url"], "https://example.test/")

    def test_scanner_nuclei_local_rejects_invalid_input(self):
        for payload in [
            {},
            {"url": "https://example.test/"},
            {"upload_id": "abc123"},
        ]:
            response = self.client.post(
                "/api/scanner/nuclei/local",
                data=json.dumps(payload),
                content_type="application/json",
            )
            self.assertEqual(response.status_code, 400, payload)

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_run_forwards_upload_and_options(self, call_engine):
        call_engine.return_value = (200, {
            "url": "https://example.test/", "findings": [], "templates": [],
            "stats": {"engine": "nuclei", "files": 0},
        })
        response = self.client.post(
            "/api/scanner/nuclei/run",
            data=json.dumps({
                "url": "https://example.test/",
                "upload_id": "abc123",
                "category_path": "templates/code",
                "options": {"severity": ["high"], "concurrency": 25, "rate_limit": 150, "no_color": True},
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        forwarded = call_engine.call_args.args[1]
        self.assertEqual(forwarded["upload_id"], "abc123")
        self.assertEqual(forwarded["category_path"], "templates/code")
        self.assertEqual(forwarded["options"]["severity"], ["high"])
        self.assertEqual(forwarded["options"]["concurrency"], 25)
        self.assertTrue(forwarded["options"]["no_color"])

    def test_scanner_nuclei_run_rejects_invalid_input(self):
        for payload in [
            {},
            {"url": "https://example.test/"},
            {"upload_id": "abc123"},
            {"url": "https://example.test/", "upload_id": "abc", "options": []},
        ]:
            response = self.client.post("/api/scanner/nuclei/run", data=json.dumps(payload), content_type="application/json")
            self.assertEqual(response.status_code, 400, payload)

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_run_dir_forwards_the_selected_folder(self, call_engine):
        call_engine.return_value = (200, {
            "url": "https://example.test/", "findings": [], "templates": [],
            "stats": {"engine": "nuclei", "batches": 2},
        })
        response = self.client.post(
            "/api/scanner/nuclei/run-dir",
            data=json.dumps({
                "url": "https://example.test/",
                "dir": "/home/user/nuclei-templates/http/cves",
                "category_path": "http/cves",
                "options": {"debug": True, "rate_limit": 5, "rate_limit_duration": 60},
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        forwarded = call_engine.call_args.args[1]
        # The folder is forwarded by the path the operator chose, not by anything
        # the gateway resolved: a rewrite here would scan a folder nobody picked.
        self.assertEqual(forwarded["dir"], "/home/user/nuclei-templates/http/cves")
        self.assertEqual(forwarded["category_path"], "http/cves")
        # The two flags the operator asked for by name have to reach the binary.
        self.assertTrue(forwarded["options"]["debug"])
        self.assertEqual(forwarded["options"]["rate_limit"], 5)
        self.assertEqual(forwarded["options"]["rate_limit_duration"], 60)

    def test_scanner_nuclei_run_dir_requires_a_target_and_a_folder(self):
        # Either half missing is refused: a folder with no target cannot be
        # scanned, and a target with no folder has nothing to run against it.
        for payload in [
            {},
            {"url": "https://example.test/"},
            {"dir": "/home/user/templates"},
            {"url": "https://example.test/", "dir": "", "options": []},
        ]:
            response = self.client.post(
                "/api/scanner/nuclei/run-dir", data=json.dumps(payload), content_type="application/json"
            )
            self.assertEqual(response.status_code, 400, payload)

    # `call_engine_get`, not `call_engine`: the engine's handler for this path
    # (`main.go`, `scannerNucleiTemplateDirs`) accepts GET only, so the gateway
    # has to reach it the same way. Patching `call_engine` here left the real
    # HTTP client in place and this test measured the client, not the view — it
    # answered 502 and failed for a reason that had nothing to do with the view.
    @patch("lab.views.call_engine_get")
    def test_scanner_nuclei_dirs_passes_the_engines_own_list_through(self, call_engine):
        call_engine.return_value = (200, {
            "dirs": [{"path": "/c/http/cves", "name": "http/cves", "files": 4320}],
            "types": [{"value": "http", "label": "http"}],
        })
        response = self.client.get("/api/scanner/nuclei/dirs")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        # The list describes the engine host's filesystem, so the gateway
        # forwards it rather than answering from its own view of the world.
        self.assertEqual(call_engine.call_args.args[0], "/proxy/scanner/nuclei/dirs")
        self.assertEqual(body["dirs"][0]["files"], 4320)
        self.assertEqual(body["types"][0]["value"], "http")

    def test_scanner_nuclei_dirs_is_read_only(self):
        self.assertEqual(self.client.post("/api/scanner/nuclei/dirs").status_code, 405)

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_inspect_requires_a_folder(self, call_engine):
        call_engine.return_value = (200, {"path": "/c/http", "total": 3, "valid": 3})
        response = self.client.post(
            "/api/scanner/nuclei/inspect", data=json.dumps({"dir": "/c/http"}), content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(call_engine.call_args.args[1], {"dir": "/c/http"})
        # An empty selection is refused before the engine is asked, because
        # "inspect everything" is not a question this endpoint can answer.
        self.assertEqual(
            self.client.post("/api/scanner/nuclei/inspect", data="{}", content_type="application/json").status_code, 400
        )

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_folder_job_starts_a_job(self, call_engine):
        call_engine.return_value = (202, {"job_id": "job-1", "state": "queued"})
        response = self.client.post(
            "/api/scanner/nuclei/jobs-dir",
            data=json.dumps({
                "url": "https://example.test/",
                "dir": "http/cves",
                "category_path": "http/cves",
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["job_id"], "job-1")
        # A folder run polls and streams through the routes the upload run uses,
        # so it must return a job id rather than a finished report.
        self.assertEqual(call_engine.call_args.args[0], "/proxy/scanner/nuclei/jobs-dir")
        self.assertEqual(call_engine.call_args.args[1]["dir"], "http/cves")
        self.assertEqual(call_engine.call_args.args[1]["category_path"], "http/cves")

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_forwards_scan_options(self, call_engine):
        call_engine.return_value = (200, {"url": "https://example.test/", "findings": [], "stats": {}, "templates": []})
        response = self.client.post(
            "/api/scanner/nuclei",
            data=json.dumps({
                "url": "https://example.test/",
                "files": [{"name": "a.yaml", "content": "id: a\n"}],
                "tags": ["cve"],
                "severity": ["high"],
                "options": {"exclude_tags": ["fuzz"], "follow_redirects": True, "headless": True},
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        forwarded = call_engine.call_args.args[1]
        self.assertEqual(forwarded["tags"], ["cve"])
        self.assertEqual(forwarded["severity"], ["high"])
        self.assertTrue(forwarded["options"]["follow_redirects"])

    @patch("lab.views.call_engine_get")
    @patch("lab.views.call_engine")
    def test_scanner_nuclei_job_lifecycle(self, call_engine, call_engine_get):
        """A long run is a pollable job, and its finished report is attached to
        the Project that started it exactly once."""
        project = Project.objects.create(name="Nuclei job project")
        self.client.post("/api/project-context", data=json.dumps({"project_id": project.id}), content_type="application/json")
        call_engine.return_value = (202, {"job_id": "job-1", "state": "queued"})
        start = self.client.post(
            "/api/scanner/nuclei/jobs",
            data=json.dumps({
                "url": "https://example.test/",
                "upload_id": "up-1",
                "category_path": "templates/code",
                "options": {"concurrency": 5},
            }),
            content_type="application/json",
        )
        self.assertEqual(start.status_code, 202)
        self.assertEqual(call_engine.call_args.args[1]["category_path"], "templates/code")
        self.assertEqual(start.json()["job_id"], "job-1")
        forwarded = call_engine.call_args.args[1]
        self.assertEqual(forwarded["upload_id"], "up-1")
        self.assertEqual(forwarded["options"]["concurrency"], 5)

        running = {"job_id": "job-1", "state": "running", "progress": {"percent": 42, "templates": 316, "requests_done": 120, "requests_total": 300}}
        call_engine_get.return_value = (200, running)
        poll = self.client.get("/api/scanner/nuclei/jobs/job-1")
        self.assertEqual(poll.status_code, 200)
        self.assertEqual(poll.json()["state"], "running")
        self.assertEqual(poll.json()["progress"]["percent"], 42)
        self.assertEqual(ScannerRun.objects.filter(project=project).count(), 0)

        finished = {
            "job_id": "job-1", "state": "completed",
            "progress": {"percent": 100, "templates": 316},
            "result": {
                "findings": [{"title": "[CVE-2024-1] X", "severity": "HIGH", "cve": ["CVE-2024-1"]}],
                "templates": [{"name": "a.yaml", "status": "matched", "matches": 1, "cve": ["CVE-2024-1"]}],
                "stats": {"engine": "nuclei", "files": 1},
            },
        }
        call_engine_get.return_value = (200, finished)
        done = self.client.get("/api/scanner/nuclei/jobs/job-1")
        self.assertEqual(done.status_code, 200)
        run = ScannerRun.objects.get(project=project)
        self.assertEqual(run.url, "https://example.test/")
        self.assertEqual(run.summary["templates"][0]["name"], "a.yaml")
        self.assertEqual(run.findings[0]["cve"], ["CVE-2024-1"])
        # The durable journal keeps the run facts, not a copy of the binary's
        # console output; the full stream stays in the run report itself.
        self.assertNotIn("stderr", run.summary["stats"])
        self.assertNotIn("stdout", run.summary["stats"])

        # A second poll must not write a duplicate journal entry.
        call_engine_get.return_value = (200, finished)
        self.client.get("/api/scanner/nuclei/jobs/job-1")
        self.assertEqual(ScannerRun.objects.filter(project=project).count(), 1)

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_job_cancel(self, call_engine):
        call_engine.return_value = (200, {"job_id": "job-1", "state": "cancelled"})
        response = self.client.post("/api/scanner/nuclei/jobs/job-1/cancel")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["state"], "cancelled")
        self.assertEqual(call_engine.call_args.args[0], "/proxy/scanner/nuclei/jobs/job-1/cancel")

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_job_pause_and_resume(self, call_engine):
        """Pause and resume are forwarded to the engine under their own action."""
        call_engine.return_value = (200, {"job_id": "job-1", "state": "paused"})
        paused = self.client.post("/api/scanner/nuclei/jobs/job-1/pause")
        self.assertEqual(paused.status_code, 200)
        self.assertEqual(paused.json()["state"], "paused")
        self.assertEqual(call_engine.call_args.args[0], "/proxy/scanner/nuclei/jobs/job-1/pause")

        call_engine.return_value = (200, {"job_id": "job-1", "state": "running"})
        resumed = self.client.post("/api/scanner/nuclei/jobs/job-1/resume")
        self.assertEqual(resumed.status_code, 200)
        self.assertEqual(resumed.json()["state"], "running")
        self.assertEqual(call_engine.call_args.args[0], "/proxy/scanner/nuclei/jobs/job-1/resume")

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_job_pause_surfaces_engine_error(self, call_engine):
        """A rejected pause is reported as an error, never as a silent success."""
        call_engine.return_value = (400, {"error": "the scan is not running yet", "code": "INVALID_JOB_STATE"})
        response = self.client.post("/api/scanner/nuclei/jobs/job-1/pause")
        self.assertEqual(response.status_code, 400)
        self.assertIn("not running", response.json()["error"])

    @patch("lab.views.call_engine")
    def test_scanner_nuclei_job_pause_rejects_unknown_action(self, call_engine):
        """An unknown action is refused instead of being forwarded blindly."""
        response = self.client.post("/api/scanner/nuclei/jobs/job-1/rewind")
        self.assertEqual(response.status_code, 400)
        call_engine.assert_not_called()

    @patch("lab.views.urlopen")
    def test_scanner_nuclei_job_stream_passes_lines_through(self, urlopen):
        """The stream proxy forwards engine events one line at a time."""
        payload = (
            b"id: 1\nevent: template\ndata: {\"kind\":\"template\",\"name\":\"a.yaml\"}\n\n"
            b"id: 2\nevent: done\ndata: {\"kind\":\"done\",\"state\":\"completed\"}\n\n"
        )

        class FakeResponse:
            def __init__(self, body):
                self._buffer = io.BytesIO(body)

            def readline(self):
                return self._buffer.readline()

            def close(self):
                return None

        urlopen.return_value = FakeResponse(payload)
        response = self.client.get("/api/scanner/nuclei/jobs/job-9/stream")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/event-stream")
        self.assertEqual(response["X-Accel-Buffering"], "no")
        body = b"".join(response.streaming_content).decode()
        self.assertIn("event: template", body)
        self.assertIn('"name":"a.yaml"', body)
        self.assertIn("event: done", body)

    @patch("lab.views.urlopen")
    def test_scanner_nuclei_job_stream_reports_engine_failure(self, urlopen):
        urlopen.side_effect = URLError("connection refused")
        response = self.client.get("/api/scanner/nuclei/jobs/job-9/stream")
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["reason"], "ENGINE_UNAVAILABLE")

    def test_scanner_nuclei_job_stream_rejects_writes(self):
        response = self.client.post("/api/scanner/nuclei/jobs/job-9/stream")
        self.assertEqual(response.status_code, 405)

    def test_scanner_nuclei_job_rejects_invalid_input(self):
        for payload in [{}, {"url": "https://example.test/"}, {"upload_id": "up-1"}]:
            response = self.client.post("/api/scanner/nuclei/jobs", data=json.dumps(payload), content_type="application/json")
            self.assertEqual(response.status_code, 400, payload)

    def test_scanner_nuclei_rejects_invalid_input(self):
        # The rejection is the engine's, so this asserts the whole hop: Django
        # forwards the payload and surfaces the engine's answer.
        if not engine_is_running():
            self.skipTest(REQUIRES_ENGINE.format(url=ENGINE_URL_FOR_TESTS))
        for payload in [{}, {"url": "https://example.test/"}, {"url": "https://example.test/", "files": []}, {"url": "https://example.test/", "files": [{"name": "a.yaml", "content": "x", "path": 7}]}]:
            response = self.client.post("/api/scanner/nuclei", data=json.dumps(payload), content_type="application/json")
            self.assertEqual(response.status_code, 400, payload)

    def test_scanner_nuclei_surfaces_the_engine_refusal_for_a_folder_with_no_templates(self):
        """A folder of support files alone is the engine's refusal, not the gateway's.

        A non-YAML file is a *support* file and is deliberately staged — a template
        folder keeps its helpers, and the binary needs them byte for byte. So an
        upload carrying only `evil.sh` passes the gateway's validation on purpose,
        and the refusal comes from the engine, which reports
        `SCANNER_NUCLEI_FAILED: selected folder contains no YAML templates`. That is
        what the gateway then answers. Measured on a live engine on 2026-10-07:
        `POST :8081/proxy/scanner/nuclei` with that body answers `502` with exactly
        that reason, and the gateway passes the status through.
        """
        if not engine_is_running():
            self.skipTest(REQUIRES_ENGINE.format(url=ENGINE_URL_FOR_TESTS))
        response = self.client.post(
            "/api/scanner/nuclei",
            data=json.dumps({"url": "https://example.test/", "files": [{"name": "evil.sh", "content": "x"}]}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 502, response.content)
        self.assertEqual(response.json().get("reason"), "SCANNER_NUCLEI_FAILED")
        self.assertIn("no YAML templates", response.json().get("error", ""))

    @patch("lab.views.call_engine")
    def test_intruder_run_is_bound_to_active_project(self, call_engine):
        project = Project.objects.create(name="Intruder destination")
        self.client.post(
            "/api/project-context",
            data=json.dumps({"project_id": project.id}),
            content_type="application/json",
        )
        call_engine.return_value = (202, {"attack_id": 812, "status": "running"})
        response = self.client.post(
            "/api/intruder",
            data=json.dumps({
                "mode": "sniper",
                "base_request": {"method": "GET", "url": "https://example.test/"},
                "payloads": [{"values": ["one"]}],
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(IntruderAttack.objects.get(engine_attack_id="812").project_id, project.id)

    def test_workflow_created_without_project_uses_active_project(self):
        project = Project.objects.create(name="Workflow destination")
        self.client.post(
            "/api/project-context",
            data=json.dumps({"project_id": project.id}),
            content_type="application/json",
        )
        response = self.client.post(
            "/api/workflows",
            data=json.dumps({
                "name": "Project workflow",
                "nodes": [{"id": "trigger", "type": "manual_trigger", "params": {}}],
                "connections": [],
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["project_id"], project.id)

    @patch("lab.views.call_engine_get")
    @patch("lab.views.call_engine")
    def test_completed_target_map_indexes_pages_in_active_project(self, call_engine, call_engine_get):
        project = Project.objects.create(name="Target auto project")
        self.client.post(
            "/api/project-context",
            data=json.dumps({"project_id": project.id}),
            content_type="application/json",
        )
        call_engine.return_value = (202, {"map_id": 731, "status": "running"})
        started = self.client.post(
            "/api/target-map",
            data=json.dumps({"url": "https://example.test/", "max_pages": 2, "max_depth": 1}),
            content_type="application/json",
        )
        self.assertEqual(started.status_code, 202)
        self.assertEqual(TargetJob.objects.get(job_id="731").project_id, project.id)
        call_engine_get.return_value = (200, {
            "map_id": 731,
            "status": "completed",
            "pages": [
                {"url": "https://example.test/", "method": "GET", "status": 200},
                {"url": "https://example.test/api/items?id=1", "method": "GET", "status": 404},
            ],
        })
        completed = self.client.get("/api/target-map?map_id=731")
        self.assertEqual(completed.status_code, 200)
        self.assertEqual(ProjectEndpoint.objects.filter(project=project).count(), 2)
        self.assertEqual(TargetJob.objects.get(job_id="731").status, "completed")

    def test_projects_store_workspace_metadata_and_can_be_updated(self):
        created = self.client.post(
            "/api/projects",
            data=json.dumps({
                "name": "Fixture workspace",
                "target": "http://fixture.test/",
                "environment": "local",
                "route_profile": "direct",
                "metadata": {"owner": "qa"},
            }),
            content_type="application/json",
        )
        self.assertEqual(created.status_code, 201)
        project = created.json()
        self.assertEqual(project["metadata"]["owner"], "qa")
        self.assertEqual(Project.objects.count(), 1)
        updated = self.client.patch(
            f"/api/projects/{project['id']}",
            data=json.dumps({"schema_version": 2, "metadata": {"owner": "security"}}),
            content_type="application/json",
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["schema_version"], 2)
        self.assertEqual(updated.json()["metadata"]["owner"], "security")
        project_model = Project.objects.get(id=project["id"])
        TargetJob.objects.create(
            project=project_model,
            job_id="project-job",
            engine_kind="browser",
            url="http://fixture.test/",
        )
        TrafficRecord.objects.create(
            project=project_model,
            method="GET",
            url="http://fixture.test/",
        )
        IntruderAttack.objects.create(
            project=project_model,
            attack_type="sniper",
            base_request={},
            payloads=[],
        )
        workflow = Workflow.objects.create(
            project=project_model,
            name="Cascade workflow",
            nodes=[{"id": "trigger", "type": "manual_trigger", "params": {}}],
        )
        WorkflowRun.objects.create(workflow=workflow, project=project_model, status="completed")
        deleted = self.client.delete(f"/api/projects/{project['id']}")
        self.assertEqual(deleted.status_code, 200)
        self.assertTrue(deleted.json()["deleted"])
        self.assertFalse(Project.objects.filter(id=project["id"]).exists())
        self.assertFalse(TargetJob.objects.filter(project_id=project["id"]).exists())
        self.assertFalse(TrafficRecord.objects.filter(project_id=project["id"]).exists())
        self.assertFalse(IntruderAttack.objects.filter(project_id=project["id"]).exists())
        self.assertFalse(Workflow.objects.filter(project_id=project["id"]).exists())
        self.assertFalse(WorkflowRun.objects.filter(project_id=project["id"]).exists())

    def test_history_returns_saved_records(self):
        record = TrafficRecord.objects.create(
            method="GET",
            url="http://localhost:3000",
            request_headers={"Accept": "application/json"},
            request_body="",
            response_headers={"Content-Type": "application/json"},
            response_body='{"ok":true}',
            status_code=200,
            latency_ms=12,
        )
        response = self.client.get("/api/history")
        self.assertEqual(response.status_code, 200)
        item = response.json()["items"][0]
        self.assertEqual(item["id"], record.id)
        self.assertEqual(item["request_headers"]["Accept"], "application/json")
        self.assertEqual(item["response_body"], '{"ok":true}')
        self.assertEqual(item["time"], 12)

    @patch("lab.views.cancel_active_agent_requests", return_value=1)
    @patch("lab.views.call_browser_worker_delete")
    @patch("lab.views.get_runtime")
    @patch("lab.views.call_engine")
    def test_route_mutation_drains_old_operations(self, call_engine, get_runtime, browser_delete, _cancel_agents):
        call_engine.return_value = (200, {"address": "127.0.0.1:9050", "generation": 2})
        get_runtime.return_value.cancel_all.return_value = [17]
        browser_delete.return_value = (200, {"job_ids": ["browser-1"]})
        response = self.client.put(
            "/api/route",
            data=json.dumps({"address": "127.0.0.1:9050"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["kill_switch"]["cancelled_workflow_runs"], [17])
        self.assertEqual(payload["kill_switch"]["cancelled_browser_jobs"], ["browser-1"])
        self.assertEqual(payload["kill_switch"]["cancelled_agent_requests"], 1)
        browser_delete.assert_called_once_with("/target")

    @patch("lab.views.call_engine_get", return_value=(200, {"address": ""}))
    def test_route_get_does_not_start_a_drain(self, call_engine_get):
        response = self.client.get("/api/route")
        self.assertEqual(response.status_code, 200)
        call_engine_get.assert_called_once_with("/route")

    @patch("lab.views.call_engine")
    def test_invalid_route_does_not_cancel_operations(self, call_engine):
        call_engine.return_value = (400, {"error": "invalid route"})
        response = self.client.put(
            "/api/route",
            data=json.dumps({"address": "%"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("kill_switch", response.json())

    # The asserted proxy URL is an *input* to this path, not the thing under
    # test, and the test used to read it off whatever `PASSIVE_PROXY_URL` the
    # ambient environment happened to carry. That made it pass on a bare
    # checkout and fail on any run where the variable is set the way a real
    # deployment sets it, which is exactly the kind of dependency that turns
    # into "it works on my machine". Pinning the constant states the
    # precondition here instead of inheriting it.
    @patch("lab.views.PASSIVE_PROXY_URL", "http://127.0.0.1:8080")
    @patch("lab.views.call_engine_get")
    @patch("lab.views.call_browser_worker")
    def test_browser_target_start_uses_generation_aware_passive_proxy(self, call_browser_worker, call_engine_get):
        call_browser_worker.return_value = (202, {"job_id": "abc", "status": "running", "pages": []})
        call_engine_get.return_value = (200, {"address": "127.0.0.1:9050"})
        response = self.client.post(
            "/api/target-browser",
            data={"url": "http://fixture.test/", "max_pages": 3, "max_depth": 1},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 202)
        call_engine_get.assert_called_once_with("/route")
        call_browser_worker.assert_called_once_with(
            "/target",
            {
                "url": "http://fixture.test/",
                "max_pages": 3,
                "max_depth": 1,
                "proxy_server": "http://127.0.0.1:8080",
                "proxy_mitm_ca": True,
            },
        )
        self.assertTrue(TargetJob.objects.filter(job_id="abc", engine_kind="browser").exists())

    @patch("lab.views.call_engine_get", return_value=(200, {"address": ""}))
    @patch("lab.views.call_browser_worker")
    def test_browser_target_forwards_explicit_actions(self, call_browser_worker, _call_engine_get):
        call_browser_worker.return_value = (202, {"job_id": "actions", "status": "running", "pages": []})
        response = self.client.post(
            "/api/target-browser",
            data=json.dumps({
                "url": "http://fixture.test/",
                "actions": [
                    {"type": "click", "selector": "#menu"},
                    {"type": "fill", "selector": "input[name=q]", "value": "routes"},
                ],
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 202)
        payload = call_browser_worker.call_args.args[1]
        self.assertEqual(payload["actions"][1]["value"], "routes")

    @patch("lab.views.call_engine_get", return_value=(200, {"address": ""}))
    @patch("lab.views.call_browser_worker")
    def test_browser_target_forwards_navigation_timeout(self, call_browser_worker, _call_engine_get):
        """The deadline the analyst sets is the deadline the worker receives.

        A crawl used to run under Playwright's own 30s default because no value
        was ever sent, so this asserts both that 0 survives as an explicit "no
        deadline" and that a real value is passed through untouched.
        """
        for value in (0, 45000):
            with self.subTest(navigation_timeout_ms=value):
                call_browser_worker.reset_mock()
                call_browser_worker.return_value = (
                    202,
                    {"job_id": f"nav-{value}", "status": "running", "pages": []},
                )
                response = self.client.post(
                    "/api/target-browser",
                    data=json.dumps({
                        "url": "http://fixture.test/",
                        "navigation_timeout_ms": value,
                    }),
                    content_type="application/json",
                )
                self.assertEqual(response.status_code, 202)
                payload = call_browser_worker.call_args.args[1]
                self.assertEqual(payload["navigation_timeout_ms"], value)

    @patch("lab.views.call_engine_get", return_value=(200, {"address": ""}))
    @patch("lab.views.call_browser_worker")
    def test_browser_target_rejects_invalid_navigation_timeout(self, call_browser_worker, _call_engine_get):
        """A bad deadline is a 400 from the gateway, never a silent clamp.

        Clamping a negative value into some positive bound would put a hidden
        cap back exactly where this parameter was added to remove it.
        """
        for value in (-1, "soon", True):
            with self.subTest(navigation_timeout_ms=value):
                response = self.client.post(
                    "/api/target-browser",
                    data=json.dumps({
                        "url": "http://fixture.test/",
                        "navigation_timeout_ms": value,
                    }),
                    content_type="application/json",
                )
                self.assertEqual(response.status_code, 400)
                self.assertIn("navigation_timeout_ms", response.json()["error"])
        call_browser_worker.assert_not_called()

    @patch("lab.views.call_engine_get", return_value=(200, {"address": ""}))
    @patch("lab.views.call_browser_worker")
    def test_browser_target_forwards_auto_wait_and_rejects_a_negative_one(
        self, call_browser_worker, _call_engine_get
    ):
        """The automatic pass waits for the analyst's bound, and only that one.

        The pass used to read the DOM a fixed 150 ms in, which is before a
        single-page app has rendered its form, so a live login page reported
        zero actions. The bound is now explicit, and a negative value is
        refused instead of being clamped into an invisible deadline.
        """
        call_browser_worker.return_value = (
            202, {"job_id": "wait-0", "status": "running", "pages": []},
        )
        response = self.client.post(
            "/api/target-browser",
            data=json.dumps({
                "url": "http://fixture.test/",
                "auto_interact": True,
                "allow_state_changing_actions": True,
                "auto_wait_timeout_ms": 20000,
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(
            call_browser_worker.call_args.args[1]["auto_wait_timeout_ms"], 20000
        )

        for value in (-1, "soon", True):
            with self.subTest(auto_wait_timeout_ms=value):
                call_browser_worker.reset_mock()
                response = self.client.post(
                    "/api/target-browser",
                    data=json.dumps({
                        "url": "http://fixture.test/",
                        "auto_interact": True,
                        "allow_state_changing_actions": True,
                        "auto_wait_timeout_ms": value,
                    }),
                    content_type="application/json",
                )
                self.assertEqual(response.status_code, 400)
                self.assertIn("auto_wait_timeout_ms", response.json()["error"])

    @patch("lab.views.call_browser_worker_delete")
    @patch("lab.views.call_browser_worker_get")
    def test_browser_target_status_and_cancel_forward_job_id(self, call_get, call_delete):
        call_get.return_value = (200, {"job_id": "abc", "status": "running", "pages": []})
        call_delete.return_value = (202, {"job_id": "abc", "status": "cancelling", "pages": []})
        self.assertEqual(self.client.get("/api/target-browser?job_id=abc").status_code, 200)
        self.assertEqual(self.client.delete("/api/target-browser?job_id=abc").status_code, 202)
        call_get.assert_called_once_with("/target/abc")
        call_delete.assert_called_once_with("/target/abc")

    @patch("lab.views.urlopen", side_effect=RemoteDisconnected("worker closed connection"))
    def test_browser_target_status_returns_json_when_worker_disconnects(self, _urlopen):
        response = self.client.get("/api/target-browser?job_id=abc")
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()["reason"], "BROWSER_WORKER_UNAVAILABLE")


    def test_history_can_be_cleared(self):
        TrafficRecord.objects.create(method="GET", url="http://example.test/one")
        TrafficRecord.objects.create(method="POST", url="http://example.test/two")
        TrafficRecord.objects.create(source="proxy", method="GET", url="http://example.test/traffic")

        response = self.client.post(
            "/api/history/bulk",
            data={"action": "clear"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["deleted"], 2)
        self.assertFalse(TrafficRecord.objects.filter(source__in=("repeater", "intruder")).exists())
        self.assertTrue(TrafficRecord.objects.filter(source="proxy").exists())

    def test_traffic_can_be_refreshed_without_csrf_cookie(self):
        # Refreshing traffic clears the engine's live in-memory store, so the
        # assertion is about the whole hop and about CSRF, not about Django.
        if not engine_is_running():
            self.skipTest(REQUIRES_ENGINE.format(url=ENGINE_URL_FOR_TESTS))
        response = self.client.delete("/api/traffic")
        self.assertEqual(response.status_code, 200)
        # `DELETE /api/traffic` also reports how many durable rows it removed,
        # so the whole payload is compared instead of `{"ok": True}` alone -
        # an exact-match assertion on a subset fails the moment the endpoint
        # says anything more, and the failure then reads like a product bug.
        body = response.json()
        self.assertIs(body["ok"], True)
        self.assertEqual(body["deleted"], 0)

    @patch("lab.views.call_engine_action")
    def test_traffic_capture_can_be_paused_and_resumed(self, call_engine_action):
        call_engine_action.return_value = (200, {"ok": True, "recording": False})
        response = self.client.post("/api/traffic", data={"action": "pause"}, content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["recording"])
        call_engine_action.assert_called_once_with("/events", {"action": "pause"})

        call_engine_action.reset_mock()
        call_engine_action.return_value = (200, {"ok": True, "recording": True})
        response = self.client.post("/api/traffic", data={"action": "resume"}, content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["recording"])
        call_engine_action.assert_called_once_with("/events", {"action": "resume"})

    def test_history_excludes_proxy_records(self):
        TrafficRecord.objects.create(source="proxy", method="GET", url="http://example.test/traffic")
        TrafficRecord.objects.create(source="repeater", method="GET", url="http://example.test/repeater")
        response = self.client.get("/api/history")
        self.assertEqual(response.status_code, 200)
        self.assertEqual([item["source"] for item in response.json()["items"]], ["repeater"])

    def test_history_reports_the_full_total_for_a_paged_window(self):
        # `total` is what the `Load more` control is built from, so it has to be
        # the size of the whole match and not the length of the window: counting
        # after the slice reported the page size, and the control could then never
        # tell that more rows existed.
        for index in range(7):
            TrafficRecord.objects.create(
                method="GET", url=f"http://example.test/{index}", source="repeater"
            )
        first = self.client.get("/api/history?limit=3&offset=0&detail=summary").json()
        self.assertEqual(len(first["items"]), 3)
        self.assertEqual(first["total"], 7)
        second = self.client.get("/api/history?limit=3&offset=3&detail=summary").json()
        self.assertEqual(len(second["items"]), 3)
        self.assertEqual(second["total"], 7)
        # The windows must not overlap, or a record is drawn twice and another is
        # never shown at all.
        first_ids = {item["id"] for item in first["items"]}
        second_ids = {item["id"] for item in second["items"]}
        self.assertEqual(first_ids & second_ids, set())
        beyond = self.client.get("/api/history?limit=3&offset=99&detail=summary").json()
        self.assertEqual(beyond["items"], [])
        self.assertEqual(beyond["total"], 7)

    def test_streamed_history_is_valid_json_across_a_chunk_boundary(self):
        # A result large enough to span two stream chunks used to come back
        # malformed: the buffer is emptied at every boundary, and the record
        # separator was derived from whether the buffer had content, so the first
        # record after each boundary was written without a comma. Only a result
        # over one chunk ever hit it, which is the size nothing tested.
        with mock.patch("lab.views.HISTORY_STREAM_THRESHOLD", 5), \
                mock.patch("lab.views.HISTORY_STREAM_CHUNK_BYTES", 512):
            for index in range(40):
                TrafficRecord.objects.create(
                    method="GET",
                    url=f"http://example.test/streamed/{index}",
                    source="repeater",
                    response_body="x" * 64,
                )
            response = self.client.get("/api/history?detail=summary")
            self.assertEqual(response.status_code, 200)
            self.assertIsInstance(response, StreamingHttpResponse)
            body = b"".join(response.streaming_content).decode()
        payload = json.loads(body)
        self.assertEqual(payload["total"], 40)
        ids = [item["id"] for item in payload["items"]]
        self.assertEqual(len(ids), 40)
        self.assertEqual(len(set(ids)), 40)

    def test_traffic_archive_lists_persisted_proxy_records(self):
        TrafficRecord.objects.create(
            source="proxy", method="GET", url="http://example.test/p/1",
            host="example.test", proxy_event_id=11, proxy_session=2,
            status_code=200, response_body="<html>one</html>", response_size=17,
        )
        TrafficRecord.objects.create(
            source="proxy", method="GET", url="http://example.test/p/2",
            host="example.test", proxy_event_id=12, proxy_session=2,
            status_code=200, response_body="<html>two</html>", response_size=17,
        )
        # A Repeater record is History, not passive Traffic, and must not be here.
        TrafficRecord.objects.create(source="repeater", method="GET", url="http://example.test/r/1")

        response = self.client.get("/api/traffic/records?limit=1&detail=summary")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["total"], 2)
        self.assertEqual(len(payload["items"]), 1)
        self.assertTrue(payload["bodies_omitted"])
        newest = payload["items"][0]
        # The durable row is presented in the engine event shape, so one table can
        # draw a live event and a stored one, and it carries the marker the browser
        # namespaces its row key with.
        self.assertEqual(newest["source"], "proxy")
        self.assertIn("db_id", newest)
        self.assertEqual(newest["id"], 12)
        # A summary row is columns only; the payload is read for the opened row.
        self.assertEqual(newest["response_body"], "")

        page = self.client.get("/api/traffic/records?limit=1&offset=1&detail=summary").json()
        self.assertEqual(page["items"][0]["url"], "http://example.test/p/1")

        record = self.client.get(f"/api/traffic/record?id={newest['db_id']}")
        self.assertEqual(record.status_code, 200)
        self.assertEqual(record.json()["response_body"], "<html>two</html>")

    def test_traffic_archive_rejects_a_bad_window_and_a_missing_record(self):
        for query in ("offset=-1", "limit=-1", "limit=nope", "offset=nope", "detail=weird"):
            response = self.client.get(f"/api/traffic/records?{query}")
            self.assertEqual(response.status_code, 400, query)
        for query in ("id=0", "id=-3", "id=abc", "id="):
            self.assertEqual(self.client.get(f"/api/traffic/record?{query}").status_code, 400, query)
        repeater = TrafficRecord.objects.create(
            source="repeater", method="GET", url="http://example.test/r/1"
        )
        # A Repeater record is not part of the passive archive, so asking for it by
        # id has to be a miss rather than a row the Traffic table cannot use.
        self.assertEqual(self.client.get(f"/api/traffic/record?id={repeater.id}").status_code, 404)
        self.assertEqual(self.client.get("/api/traffic/record?id=99999").status_code, 404)

    def test_traffic_archive_count_only_window_reads_no_rows(self):
        # The `Load more` control needs the size of the archive before it decides
        # to offer itself, and that must not cost a page of rows.
        for index in range(5):
            TrafficRecord.objects.create(
                source="proxy", method="GET", url=f"http://example.test/p/{index}"
            )
        response = self.client.get("/api/traffic/records?limit=0&detail=summary")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["items"], [])
        self.assertEqual(payload["total"], 5)

    def test_proxy_traffic_can_be_saved_to_history(self):
        response = self.client.post(
            "/api/traffic/save",
            data={
                "id": 7,
                "session": 3,
                "method": "GET",
                "host": "localhost:3000",
                "url": "http://localhost:3000/health",
                "request_headers": {},
                "request_body": "",
                "status": 200,
                "response_headers": {},
                "response_body": "ok",
                "response_size": 2,
                "latency_ms": 1,
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201)
        record = TrafficRecord.objects.get(source="proxy")
        self.assertEqual(record.host, "localhost:3000")

    @patch("lab.views.call_engine_get")
    def test_proxy_snapshot_backfills_source_ip_after_pending_update(self, call_engine_get):
        base_event = {
            "id": 22,
            "session": 5,
            "timestamp": "2026-09-12T22:00:00Z",
            "method": "GET",
            "url": "http://target.test/source",
            "host": "target.test",
            "request_headers": {},
            "request_body": "",
            "status": 200,
            "response_headers": {},
            "response_body": "ok",
            "response_size": 2,
            "latency_ms": 3,
        }
        call_engine_get.side_effect = [
            (200, [base_event]),
            (200, [{**base_event, "source_ip": "198.51.100.90"}]),
        ]
        self.assertEqual(self.client.get("/api/traffic").status_code, 200)
        self.assertEqual(self.client.get("/api/traffic").status_code, 200)
        record = TrafficRecord.objects.get(source="proxy", proxy_event_id=22)
        self.assertEqual(record.source_ip, "198.51.100.90")

    @patch("lab.views.call_engine_get")
    def test_proxy_snapshot_is_persisted_to_history(self, call_engine_get):
        call_engine_get.return_value = (200, [{
            "id": 21,
            "session": 4,
            "timestamp": "2026-09-12T22:00:00Z",
            "method": "GET",
            "url": "http://target.test/health",
            "host": "target.test",
            "request_headers": {"Accept": "*/*"},
            "request_body": "",
            "status": 204,
            "response_headers": {"X-Test": "ok"},
            "response_body": "",
            "response_size": 0,
            "latency_ms": 7,
        }])

        first = self.client.get("/api/traffic")
        second = self.client.get("/api/traffic")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(TrafficRecord.objects.filter(source="proxy").count(), 1)
        record = TrafficRecord.objects.get(source="proxy")
        self.assertEqual(record.request_headers["Accept"], "*/*")
        self.assertEqual(record.response_headers["X-Test"], "ok")
        self.assertEqual(record.response_size, 0)


class AgentChatTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_legacy_agent_runtime_routes_are_removed(self):
        for path in ("/api/agent/context", "/api/agent/plan", "/api/agent/runs"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 404, path)

    def test_agent_chat_requires_csrf_for_browser_requests(self):
        client = Client(enforce_csrf_checks=True)
        response = client.post(
            "/api/agent/chat",
            data={"messages": [{"role": "user", "content": "hello"}]},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)

    @patch("lab.views.generate_agent_chat")
    def test_agent_chat_returns_provider_message_only(self, generate_chat):
        generate_chat.return_value = {"message": "evidence analyzed"}
        response = self.client.post(
            "/api/agent/chat",
            data={
                "provider": "ollama",
                "messages": [{"role": "user", "content": "Inspect the target"}],
                "context": {"attached_evidence": {"history": [{"url": "http://target.test/"}]}},
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"provider": "ollama", "message": "evidence analyzed"})
        self.assertEqual(
            generate_chat.call_args.kwargs["context"]["attached_evidence"]["history"][0]["url"],
            "http://target.test/",
        )

    @patch("lab.views.generate_agent_chat")
    def test_agent_chat_includes_project_context_only_after_explicit_opt_in(self, generate_chat):
        generate_chat.return_value = {"message": "project analyzed"}
        project = Project.objects.create(
            name="AI context project",
            target="https://ai-context.example.test/",
        )
        TrafficRecord.objects.create(
            project=project,
            method="GET",
            url="https://ai-context.example.test/api/data?token=raw-query-secret",
            request_headers={"Authorization": "Bearer raw-header-secret"},
            response_body="raw response secret",
            status_code=200,
        )
        session = self.client.session
        session[ACTIVE_PROJECT_SESSION_KEY] = project.id
        session.save()

        default_response = self.client.post(
            "/api/agent/chat",
            data={"messages": [{"role": "user", "content": "Analyze"}]},
            content_type="application/json",
        )
        self.assertEqual(default_response.status_code, 200)
        self.assertNotIn("project_context", generate_chat.call_args.kwargs["context"])

        opted_in = self.client.post(
            "/api/agent/chat",
            data={
                "messages": [{"role": "user", "content": "Analyze"}],
                "include_project_context": True,
            },
            content_type="application/json",
        )
        self.assertEqual(opted_in.status_code, 200)
        project_context = generate_chat.call_args.kwargs["context"]["project_context"]
        self.assertEqual(project_context["project_id"], project.id)
        self.assertIn("https://ai-context.example.test/api/data", project_context["summary_markdown"])
        self.assertNotIn("raw-query-secret", project_context["summary_markdown"])
        self.assertNotIn("raw-header-secret", project_context["summary_markdown"])
        self.assertNotIn("raw response secret", project_context["summary_markdown"])

    @patch("lab.views.generate_agent_chat")
    def test_agent_chat_requires_active_project_for_context_opt_in(self, generate_chat):
        response = self.client.post(
            "/api/agent/chat",
            data={
                "messages": [{"role": "user", "content": "Analyze"}],
                "include_project_context": True,
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["reason"], "PROJECT_CONTEXT_REQUIRED")
        generate_chat.assert_not_called()

        invalid = self.client.post(
            "/api/agent/chat",
            data={
                "messages": [{"role": "user", "content": "Analyze"}],
                "include_project_context": "true",
            },
            content_type="application/json",
        )
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(invalid.json()["reason"], "INVALID_AGENT_CHAT")

    def test_legacy_agent_tools_route_is_removed(self):
        response = self.client.get("/api/agent/tools")
        self.assertEqual(response.status_code, 404)

    @patch("lab.views.generate_agent_chat")
    def test_agent_chat_rejects_execution_payload(self, generate_chat):
        response = self.client.post(
            "/api/agent/chat",
            data={
                "messages": [{"role": "user", "content": "run it"}],
                "approved_tool_call": {"tool": "run_repeater", "arguments": {}},
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        generate_chat.assert_not_called()

    @patch("lab.views.generate_agent_chat")
    def test_agent_chat_drops_unattached_context(self, generate_chat):
        generate_chat.return_value = {"message": "chat only"}
        response = self.client.post(
            "/api/agent/chat",
            data={
                "messages": [{"role": "user", "content": "hello"}],
                "context": {"history": [{"url": "http://should-not-be-forwarded"}]},
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(generate_chat.call_args.kwargs["context"], {})

    @patch("lab.views.generate_agent_chat")
    def test_agent_chat_preserves_attached_context_and_messages(self, generate_chat):
        generate_chat.return_value = {"message": "bounded"}
        huge = "x" * 4000
        context = {"attached_evidence": {"history": [{"response_body": huge} for _ in range(30)]}}
        messages = [{"role": "user", "content": huge} for _ in range(40)]
        response = self.client.post(
            "/api/agent/chat",
            data={"messages": messages, "context": context, "provider": "ollama"},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        sent_messages, = generate_chat.call_args.args
        sent_context = generate_chat.call_args.kwargs["context"]
        self.assertEqual(len(sent_messages), 40)
        self.assertEqual(len(sent_messages[-1]["content"]), len(huge))
        self.assertGreater(len(json.dumps(sent_context, ensure_ascii=False)), 120000)

    @patch("lab.views.generate_agent_chat")
    def test_agent_chat_preserves_project_and_attached_context_together(self, generate_chat):
        generate_chat.return_value = {"message": "bounded project context"}
        project = Project.objects.create(name="Bounded AI project", target="https://bounded.example.test/")
        session = self.client.session
        session[ACTIVE_PROJECT_SESSION_KEY] = project.id
        session.save()
        response = self.client.post(
            "/api/agent/chat",
            data={
                "messages": [{"role": "user", "content": "Analyze"}],
                "include_project_context": True,
                "context": {"attached_evidence": {"history": [{"response_body": "x" * 4000} for _ in range(30)]}},
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        sent_context = generate_chat.call_args.kwargs["context"]
        self.assertIn("project_context", sent_context)
        self.assertGreater(len(json.dumps(sent_context, ensure_ascii=False)), 120000)

    def test_history_filters_binary_metadata_and_annotations(self):
        record = TrafficRecord.objects.create(
            method="GET",
            url="http://binary.test/image",
            host="binary.test",
            response_headers={"Content-Type": "image/png"},
            response_body_encoding="base64",
            response_body_base64="iVBORwD/",
            response_content_type="image/png",
            response_size=6,
            tags=["binary"],
            notes="fixture",
        )
        response = self.client.get("/api/history?mime=image/png&size_min=6&q=fixture")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["items"][0]["id"], record.id)
        annotated = self.client.patch(
            f"/api/history/{record.id}",
            data={"tags": ["image", "qa"], "notes": "updated"},
            content_type="application/json",
        )
        self.assertEqual(annotated.status_code, 200)
        self.assertEqual(annotated.json()["response_body_encoding"], "base64")
        self.assertEqual(annotated.json()["tags"], ["image", "qa"])

    def test_history_can_be_exported_and_imported(self):
        TrafficRecord.objects.create(method="POST", url="http://example.test/api", request_body="{}")
        response = self.client.get("/api/history/export")
        self.assertEqual(response.status_code, 200)
        self.assertIn("intruder-history.json", response["Content-Disposition"])
        imported = self.client.post(
            "/api/history/import",
            data=response.content,
            content_type="application/json",
        )
        self.assertEqual(imported.status_code, 201)
        self.assertEqual(imported.json()["imported"], 1)

    @patch("lab.views.call_engine")
    def test_intruder_start_accepts_empty_result_snapshot(self, call_engine):
        call_engine.return_value = (
            202,
            {
                "attack_id": 7,
                "status": "running",
                "total": 2,
                "completed": 0,
                "failed": 0,
                "results": [],
            },
        )
        response = self.client.post(
            "/api/intruder",
            data={
                "base_request": {
                    "method": "GET",
                    "url": "http://example.test/?id=§id§",
                    "headers": {},
                    "body": "",
                },
                "mode": "batteringRam",
                "payloads": [["one", "two"]],
                "transformations": [],
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["results"], [])

    @patch("lab.views.call_engine_delete")
    @patch("lab.views.call_engine_get")
    def test_intruder_status_and_cancel_forward_attack_id(self, call_engine_get, call_engine_delete):
        call_engine_get.return_value = (200, {"attack_id": 7, "status": "running", "results": []})
        call_engine_delete.return_value = (202, {"attack_id": 7, "status": "cancelled", "results": []})

        status = self.client.get("/api/intruder?attack_id=7")
        incremental = self.client.get("/api/intruder?attack_id=7&since=3")
        cancelled = self.client.delete("/api/intruder?attack_id=7")

        self.assertEqual(status.status_code, 200)
        self.assertEqual(incremental.status_code, 200)
        self.assertEqual(cancelled.status_code, 202)
        self.assertEqual(
            call_engine_get.call_args_list,
            [
                (( "/proxy/intruder/7",),),
                (( "/proxy/intruder/7?since=3",),),
            ],
        )
        call_engine_delete.assert_called_once_with("/proxy/intruder/7")

    @patch("lab.views.call_engine_action")
    def test_intruder_pause_and_resume_forward_action(self, call_engine_action):
        call_engine_action.return_value = (202, {"attack_id": 7, "status": "paused", "results": []})
        response = self.client.post("/api/intruder?attack_id=7&action=pause", data={"action": "pause"}, content_type="application/json")
        self.assertEqual(response.status_code, 202)
        call_engine_action.assert_called_once_with("/proxy/intruder/7", {"action": "pause"})

    @patch("lab.views.call_engine_get")
    def test_completed_intruder_results_are_saved_to_history_once(self, call_engine_get):
        result = {
            "attack_id": 8,
            "status": "completed",
            "results": [{
                "status": 201,
                "headers": {"Content-Type": "application/json"},
                "body": '{"created":true}',
                "time": 14,
                "size": 16,
                "payloads": ["alpha"],
                "request": {
                    "method": "POST",
                    "url": "http://target.test/api/items",
                    "headers": {"Content-Type": "application/json"},
                    "body": '{"name":"alpha"}',
                },
            }],
        }
        call_engine_get.return_value = (200, result)

        first = self.client.get("/api/intruder?attack_id=8")
        second = self.client.get("/api/intruder?attack_id=8")

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(TrafficRecord.objects.filter(source="intruder").count(), 1)
        record = TrafficRecord.objects.get(source="intruder")
        self.assertEqual(record.status_code, 201)
        self.assertEqual(record.request_body, '{"name":"alpha"}')
        self.assertEqual(record.response_body, '{"created":true}')

    @patch("lab.views.call_engine_get")
    def test_running_intruder_results_are_saved_to_history_live(self, call_engine_get):
        call_engine_get.return_value = (200, {
            "attack_id": 9,
            "status": "running",
            "result_offset": 4,
            "results": [{
                "status": 403,
                "headers": {"Content-Type": "text/plain"},
                "body": "blocked",
                "time": 8,
                "size": 7,
                "request": {
                    "method": "GET",
                    "url": "http://target.test/blocked",
                    "headers": {},
                    "body": "",
                },
            }],
        })

        response = self.client.get("/api/intruder?attack_id=9")

        self.assertEqual(response.status_code, 200)
        record = TrafficRecord.objects.get(source="intruder")
        self.assertEqual(record.proxy_event_id, 4)
        self.assertEqual(record.status_code, 403)
        self.assertEqual(record.response_body, "blocked")

    def test_intruder_attack_can_be_saved_and_listed(self):
        payload = {
            "name": "README IDs",
            "mode": "batteringRam",
            "base_request": {"method": "GET", "url": "http://example.test/?id=§id§", "headers": {}, "body": ""},
            "payloads": [["one", "two"]],
            "transformations": [],
        }
        created = self.client.post("/api/intruder/saved", data=payload, content_type="application/json")
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["name"], "README IDs")
        self.assertEqual(IntruderAttack.objects.count(), 1)

        listed = self.client.get("/api/intruder/saved")
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.json()["items"][0]["mode"], "batteringRam")

    @patch("lab.views.call_engine")
    def test_saved_intruder_attack_can_be_re_run(self, call_engine):
        attack = IntruderAttack.objects.create(
            name="Repeat me",
            attack_type="batteringRam",
            base_request={"method": "GET", "url": "http://example.test/?id=§id§", "headers": {}, "body": ""},
            payloads=[["one"]],
            transformations=[],
        )
        call_engine.return_value = (202, {"attack_id": 12, "status": "running", "results": []})

        response = self.client.post(f"/api/intruder/saved/{attack.id}/run")

        self.assertEqual(response.status_code, 202)
        call_engine.assert_called_once_with(
            "/proxy/intruder",
            {
                "base_request": attack.base_request,
                "mode": "batteringRam",
                "payloads": attack.payloads,
                "transformations": [],
                "delay_ms": attack.delay_ms,
                "concurrency": attack.concurrency,
            },
        )
        attack.refresh_from_db()
        self.assertEqual(attack.status, "running")


class EngineStreamOpenerTests(TestCase):
    """Opening an engine SSE stream must never surface as an unhandled 500.

    A stream whose response headers never arrive raises `TimeoutError`, which
    derives from `OSError` and is not a `URLError`. Catching only `URLError` let
    that case escape as a server error with a traceback, so an idle traffic feed
    reported a failure instead of a quiet stream.
    """

    class FakeResponse:
        def close(self):
            pass

    def _open_with(self, error):
        with patch.object(views, "urlopen", side_effect=error):
            return views.open_engine_stream("http://engine.test/events/stream")

    def test_a_working_stream_is_returned_untouched(self):
        response = self.FakeResponse()
        with patch.object(views, "urlopen", return_value=response):
            self.assertIs(
                views.open_engine_stream("http://engine.test/events/stream"), response
            )

    def test_header_timeout_becomes_an_explicit_502(self):
        result = self._open_with(TimeoutError("timed out"))
        self.assertEqual(result.status_code, 502)
        payload = json.loads(result.content)
        self.assertEqual(payload["reason"], "ENGINE_STREAM_TIMEOUT")
        # The reason has to name the bound, otherwise the operator cannot tell a
        # slow engine from a dead one.
        self.assertIn(f"{views.SSE_READ_TIMEOUT:g}", payload["error"])

    def test_socket_timeout_becomes_an_explicit_502(self):
        import socket

        # `socket.timeout` is an alias of `TimeoutError` on modern Python; the
        # test pins the behaviour either way.
        result = self._open_with(socket.timeout("timed out"))
        self.assertEqual(result.status_code, 502)

    def test_refused_connection_keeps_the_engine_unavailable_reason(self):
        result = self._open_with(URLError("connection refused"))
        self.assertEqual(result.status_code, 502)
        self.assertEqual(json.loads(result.content)["reason"], "ENGINE_UNAVAILABLE")

    def test_a_rejected_stream_is_not_reported_as_unavailable(self):
        from urllib.error import HTTPError

        result = self._open_with(
            HTTPError(
                "http://engine.test/events/stream",
                404,
                "not found",
                {},
                self.FakeResponse(),
            )
        )
        self.assertEqual(result.status_code, 502)
        self.assertEqual(json.loads(result.content)["reason"], "ENGINE_STREAM_REJECTED")

    def test_any_other_socket_failure_is_still_an_explicit_502(self):
        result = self._open_with(ConnectionResetError("connection reset by peer"))
        self.assertEqual(result.status_code, 502)
        self.assertEqual(json.loads(result.content)["reason"], "ENGINE_STREAM_FAILED")


class EngineClientTests(TestCase):
    class FakeResponse:
        def __init__(self, status=200, body=b"{}"):
            self.status = status
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return self.body

        def close(self):
            pass

    def test_http_error_has_stable_reason(self):
        from urllib.error import HTTPError

        def opener(_request, **_kwargs):
            raise HTTPError(
                "http://engine.test/proxy/request",
                400,
                "bad request",
                {},
                self.FakeResponse(body=b"not-json"),
            )

        status, payload = EngineClient("http://engine.test", opener=opener).request(
            "POST", "/proxy/request", {}
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["reason"], "ENGINE_HTTP_ERROR")
        self.assertEqual(payload["status"], 400)

    def test_route_generation_header_is_forwarded(self):
        captured = {}

        def opener(request, **_kwargs):
            captured["headers"] = dict(request.header_items())
            return self.FakeResponse()

        status, _ = EngineClient("http://engine.test", opener=opener).request(
            "POST",
            "/proxy/request",
            {},
            route_generation=7,
        )
        self.assertEqual(status, 200)
        self.assertEqual(captured["headers"]["X-requestrider-route-generation"], "7")

    def test_empty_response_is_invalid(self):
        status, payload = EngineClient(
            "http://engine.test",
            opener=lambda _request, **_kwargs: self.FakeResponse(body=b""),
        ).request("GET", "/events")
        self.assertEqual(status, 502)
        self.assertEqual(payload["reason"], "ENGINE_INVALID_RESPONSE")

    def test_malformed_json_is_invalid(self):
        status, payload = EngineClient(
            "http://engine.test",
            opener=lambda _request, **_kwargs: self.FakeResponse(body=b"{"),
        ).request("GET", "/events")
        self.assertEqual(status, 502)
        self.assertEqual(payload["reason"], "ENGINE_INVALID_RESPONSE")

    def test_network_error_is_unavailable(self):
        from urllib.error import URLError

        status, payload = EngineClient(
            "http://engine.test",
            opener=lambda _request, **_kwargs: (_ for _ in ()).throw(URLError("offline")),
        ).request("GET", "/events")
        self.assertEqual(status, 502)
        self.assertEqual(payload["reason"], "ENGINE_UNAVAILABLE")


class AgentProviderTests(TestCase):
    def test_provider_accepts_https_and_loopback_http(self):
        """The previous version of this test asserted that a **remote** plaintext endpoint
        was accepted, which is the behaviour A04-08 closed: the request carries the provider
        API key and the analyst's raw target exchanges, so `http` to a remote host puts both
        on the wire in clear.

        The name changed with the contract, because a test called "accepts http and loopback"
        that no longer accepts remote http misleads its next reader."""
        for endpoint in ("http://127.0.0.1:11434/v1/chat/completions",
                         "https://collector.test/v1/chat/completions",
                         "https://127.0.0.1/v1/chat/completions"):
            with self.subTest(endpoint=endpoint):
                provider = get_agent_provider("openai_compatible", endpoint=endpoint, model="test")
                self.assertEqual(provider.endpoint, endpoint)

    def test_provider_refuses_remote_plaintext(self):
        from .agent_services import AgentProviderError

        with self.assertRaises(AgentProviderError):
            get_agent_provider(
                "openai_compatible", endpoint="http://collector.test/v1/chat/completions",
                model="test",
            )

    def test_openrouter_defaults_to_configured_deepseek_free_model(self):
        from .agent_services import PROVIDER_PRESETS

        self.assertEqual(
            PROVIDER_PRESETS["openrouter"][2],
            "deepseek/deepseek-v4-flash-0731:free",
        )

    @patch("lab.agent_services._read_provider_response")
    def test_pre_cancelled_provider_never_opens_transport(self, read_response):
        cancelled = threading.Event()
        cancelled.set()
        provider = OpenAICompatibleProvider(
            endpoint="http://collector.test/v1/chat/completions",
            model="test",
        )
        with self.assertRaises(AgentRequestCancelled):
            provider.chat([{ "role": "user", "content": "cancel"}], cancel_event=cancelled)
        read_response.assert_not_called()

    @patch("lab.agent_services._read_provider_response")
    def test_chat_accepts_fenced_json_with_reasoning_prefix(self, read_response):
        content = (
            "I will inspect the evidence first.\n"
            "```json\n"
            '{"message":"I need to inspect History."}\n'
            "```"
        )
        read_response.return_value = {"choices": [{"message": {"content": content}}]}
        provider = OpenAICompatibleProvider(
            endpoint="https://llm.test/v1/chat/completions",
            model="deepseek/deepseek-v4-flash-0731:free",
            api_key="secret-token",
        )
        self.assertEqual(
            provider.chat([{"role": "user", "content": "Inspect History"}]),
            {"message": "I need to inspect History."},
        )

    @patch("lab.agent_services._read_provider_response")
    def test_chat_accepts_plain_text_provider_response(self, read_response):
        read_response.return_value = {"choices": [{"message": {"content": "Plain answer"}}]}
        provider = OpenAICompatibleProvider(
            endpoint="https://llm.test/v1/chat/completions",
            model="local-model",
        )
        self.assertEqual(
            provider.chat([{"role": "user", "content": "Inspect evidence"}]),
            {"message": "Plain answer"},
        )

    @patch("lab.agent_services._read_provider_response")
    def test_openai_compatible_provider_sends_api_key_in_header_only(self, read_response):
        read_response.return_value = {"choices": [{"message": {"content": "ok"}}]}
        provider = OpenAICompatibleProvider(
            endpoint="https://llm.test/v1/chat/completions",
            model="local-model",
            api_key="secret-token",
        )
        provider.chat([{"role": "user", "content": "Inspect evidence"}])
        request = read_response.call_args.args[0]
        self.assertEqual(request.headers["Authorization"], "Bearer secret-token")
        self.assertNotIn("secret-token", request.data.decode())

    @patch("lab.agent_services._read_provider_response")
    def test_chat_prompt_preserves_user_pentest_prompt(self, read_response):
        read_response.return_value = {"choices": [{"message": {"content": "ok"}}]}
        provider = OpenAICompatibleProvider(
            endpoint="https://llm.test/v1/chat/completions",
            model="local-model",
        )
        provider.chat([{"role": "user", "content": "Analyze attached response"}])
        request_body = json.loads(read_response.call_args.args[0].data)
        self.assertIn("специализирующийся на Burp Suite Professional/Community", request_body["messages"][0]["content"])
        self.assertIn("Prioritized Test Plan", request_body["messages"][0]["content"])
        self.assertIn("Proxy и HTTP history", request_body["messages"][0]["content"])

    def test_route_switch_interrupts_inflight_provider_request(self):
        started = threading.Event()
        release = threading.Event()
        errors = []

        class SlowProvider(BaseHTTPRequestHandler):
            def do_POST(self):
                started.set()
                release.wait(5)
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"choices":[{"message":{"content":"ok"}}]}')
                except OSError:
                    pass

            def log_message(self, *_):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), SlowProvider)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        provider = OpenAICompatibleProvider(
            endpoint=f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
            model="local-model",
            timeout=5,
        )

        def run_chat():
            try:
                provider.chat([{"role": "user", "content": "Inspect evidence"}])
            except AgentRequestCancelled as error:
                errors.append(error)

        chat_thread = threading.Thread(target=run_chat, daemon=True)
        chat_thread.start()
        self.assertTrue(started.wait(2))
        self.assertEqual(cancel_active_agent_requests(), 1)
        chat_thread.join(timeout=2)
        release.set()
        try:
            self.assertFalse(chat_thread.is_alive())
            self.assertEqual(len(errors), 1)
        finally:
            release.set()
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)


class OsintResultViewerTests(TestCase):
    """The result viewer and the file listing it links back to.

    The contract these lock is that paging is a window and never a truncation:
    every row stays reachable through the search, the filter, the raw form and
    both downloads, and nothing an index returned is rendered as markup.
    """

    def setUp(self):
        self.project = Project.objects.create(name="Viewer project")
        self.graph = OsintGraph.objects.create(project=self.project, name="Viewer graph", source="ui")
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.settings = override_settings(OSINT_EXPORT_DIR=self.directory.name)
        self.settings.enable()
        self.addCleanup(self.settings.disable)
        from lab import osint_exports
        osint_exports._ROW_CACHE.clear()
        self.addCleanup(osint_exports._ROW_CACHE.clear)
        self.folder = osint_exports.export_directory(self.graph.id)
        self.folder.mkdir(parents=True, exist_ok=True)
        self.csv_name = "subdomains-example.csv"
        self.jsonl_name = "subdomains-example.jsonl"
        self.rows = [
            {"type": "domain", "identity": "example.test", "relation": "", "source": "", "target": "", "provenance": '{"source": "transform_input"}'},
            *(
                {"type": "subdomain", "identity": f"host{index:03d}.example.test", "relation": "", "source": "", "target": "", "provenance": '{"source": "certificate_transparency"}'}
                for index in range(60)
            ),
            *(
                {"type": "", "identity": "", "relation": "subdomain_of", "source": f"host{index:03d}.example.test", "target": "example.test", "provenance": '{"source": "certificate_transparency"}'}
                for index in range(60)
            ),
        ]
        self._write(self.folder / self.csv_name, self.rows)
        self._write(self.folder / self.jsonl_name, self.rows)

    def _write(self, path, rows):
        if path.suffix == ".jsonl":
            path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
            return
        import csv
        columns = ["type", "identity", "relation", "source", "target", "provenance"]
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            for row in rows:
                writer.writerow({column: row.get(column, "") for column in columns})

    def get_viewer(self, query="", name=None):
        return self.client.get(f"/api/osint/graphs/{self.graph.id}/files/{name or self.csv_name}{query}")

    def test_viewer_reports_the_real_row_count_and_pages(self):
        response = self.get_viewer()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["rows_total"], 121)
        self.assertEqual(response.context["selection"]["total"], 121)
        # The default page is 200 rows, so all 121 fit on one page.
        self.assertEqual(response.context["selection"]["pages"], 1)
        self.assertEqual(response.context["selection"]["first"], 1)
        self.assertEqual(response.context["selection"]["last"], 121)
        self.assertContains(response, "121")
        self.assertEqual(len(response.context["selection"]["rows"]), 121)

    def test_viewer_paginates_when_the_file_is_longer_than_one_page(self):
        response = self.get_viewer("?page_size=50")
        selection = response.context["selection"]
        self.assertEqual(selection["pages"], 3)
        self.assertEqual(selection["first"], 1)
        self.assertEqual(selection["last"], 50)
        second = self.get_viewer("?page_size=50&page=2").context["selection"]
        self.assertEqual((second["first"], second["last"]), (51, 100))
        last = self.get_viewer("?page_size=50&page=3").context["selection"]
        self.assertEqual((last["first"], last["last"]), (101, 121))

    def test_viewer_clamps_a_page_beyond_the_end_and_rejects_a_bad_size(self):
        beyond = self.get_viewer("?page=9999")
        self.assertEqual(beyond.context["selection"]["page"], beyond.context["selection"]["pages"])
        for query in ("?page_size=7", "?page_size=abc", "?page_size=-1"):
            self.assertEqual(self.get_viewer(query).context["selection"]["page_size"], 200, query)

    def test_every_row_stays_reachable_through_the_search(self):
        # The last subdomain of the file has to be findable even though it is
        # never rendered on the first page.
        response = self.get_viewer("?q=host059")
        self.assertEqual(response.context["selection"]["total"], 2)
        self.assertContains(response, "host059.example.test")
        self.assertEqual(response.context["rows_total"], 121)

    def test_type_filter_and_chips_use_the_same_label(self):
        # A relation row has no `type`, and labelling it by that empty value
        # would offer a chip that matches nothing.
        response = self.get_viewer("?type=link")
        self.assertEqual(response.context["selection"]["total"], 60)
        self.assertTrue(all(row["relation"] for row in response.context["selection"]["rows"]))
        counts = dict(response.context["selection"]["counts"])
        self.assertEqual(counts, {"link": 60, "subdomain": 60, "domain": 1})

    def test_sort_never_opens_on_rows_without_a_value(self):
        # Sorting by identity ascending must not put the 60 relation rows, whose
        # identity is empty, ahead of every name.
        response = self.get_viewer("?sort=identity&dir=asc")
        first = response.context["selection"]["rows"][0]
        self.assertEqual(first["identity"], "example.test")
        descending = self.get_viewer("?sort=identity&dir=desc")
        self.assertEqual(descending.context["selection"]["rows"][0]["identity"], "host059.example.test")

    def test_hidden_columns_are_dropped_and_reported(self):
        from lab import osint_exports
        self._write(self.folder / "empty-columns.csv", [
            {"type": "domain", "identity": "only.test", "relation": "", "source": "", "target": "", "provenance": ""},
        ])
        response = self.client.get(f"/api/osint/graphs/{self.graph.id}/files/empty-columns.csv")
        self.assertNotIn("relation", response.context["visible_columns"])
        self.assertIn("relation", response.context["hidden_columns"])
        self.assertContains(response, "Hidden because no row uses them")
        self.assertIsInstance(osint_exports.active_columns(["type", "relation"], [{"type": "a", "relation": ""}]), list)

    def test_raw_and_download_carry_every_row(self):
        for suffix in ("?raw=1", "?download=1"):
            response = self.get_viewer(suffix)
            self.assertEqual(response.status_code, 200, suffix)
            body = response.content.decode()
            self.assertIn("host000.example.test", body)
            self.assertIn("host059.example.test", body, suffix)
        self.assertIn("attachment", self.get_viewer("?download=1")["Content-Disposition"])

    def test_viewer_escapes_a_value_that_arrived_from_an_index(self):
        payload = "</td><script>window.__viewerXss=1</script>"
        self._write(self.folder / "hostile.csv", [
            {"type": "subdomain", "identity": payload, "relation": "", "source": "", "target": "", "provenance": payload},
        ])
        response = self.client.get(f"/api/osint/graphs/{self.graph.id}/files/hostile.csv")
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        self.assertNotIn("<script>window.__viewerXss", body)
        self.assertIn("&lt;script&gt;", body)

    def test_listing_shows_both_forms_of_the_result(self):
        response = self.client.get(f"/api/osint/graphs/{self.graph.id}/files/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual({item["name"] for item in response.context["files"]}, {self.csv_name, self.jsonl_name})
        for item in response.context["files"]:
            self.assertEqual(item["rows"], 121)
        self.assertContains(response, "View")
        self.assertContains(response, "?raw=1")
        self.assertContains(response, "?download=1")

    def test_viewer_reads_the_jsonl_copy_too(self):
        response = self.client.get(f"/api/osint/graphs/{self.graph.id}/files/{self.jsonl_name}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["rows_total"], 121)
        # The other format of the same result is offered from the page, so the
        # analyst does not have to go back to the directory to reach it.
        self.assertEqual([item["name"] for item in response.context["companions"]], [self.csv_name])
        self.assertEqual([item["kind"] for item in response.context["companions"]], ["csv"])

    def test_a_rewritten_file_is_read_again(self):
        # The row cache is keyed on the file identity, so a file that a later
        # transform overwrote must not be served from the earlier parse.
        from lab import osint_exports
        path = self.folder / self.csv_name
        self.assertEqual(len(osint_exports.load_result_rows(path)[1]), 121)
        self._write(path, self.rows[:5])
        self.assertEqual(len(osint_exports.load_result_rows(path)[1]), 5)
        self.assertEqual(self.get_viewer().context["rows_total"], 5)

    def test_count_data_rows_agrees_with_the_parse_for_both_formats(self):
        from lab import osint_exports
        for name in (self.csv_name, self.jsonl_name):
            path = self.folder / name
            self.assertEqual(osint_exports.count_data_rows(path), len(osint_exports.load_result_rows(path)[1]), name)

    def test_a_missing_file_is_refused_without_listing_the_directory(self):
        response = self.get_viewer(name="not-there.csv")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["reason"], "INVALID_OSINT_GRAPH")

    def test_the_reports_reuse_the_application_palette(self):
        # A report that drifts to a second palette stops looking like part of
        # the tool, so the shared token values are asserted rather than assumed.
        page = self.get_viewer().content.decode()
        include = Path(__file__).resolve().parent.parent / "templates" / "lab" / "_report_base.html"
        tokens = include.read_text(encoding="utf-8")
        for token in ("--bg:#080c12", "--panel:#101722", "--line:#263548", "--accent:#43d9a3", "--purple:#a970ff", "--radius:7px"):
            self.assertIn(token, tokens, token)
        self.assertIn("--bg:#080c12", page)
        self.assertIn("linear-gradient(180deg,#244b68 0,#162d43 38%,#080c12 78%)", page)
        # The report is rendered in the workspace language, so it carries no
        # script and no second wording to swap: the language control is a link
        # the server answers with a redirect and a cookie.
        self.assertNotIn("<script", page)
        self.assertIn("?lang=uk", page)


class ReportLanguageTests(TestCase):
    """A report speaks exactly the language the workspace speaks.

    The rule is enforced twice: no label the report owns may be the same string
    in both languages, and a page rendered in Ukrainian may not contain an
    English interface word. Data the report does not own — a column name, an
    entity type, a provenance source — is identical in both by design and is
    never translated, because translating it would mislabel what it stands for.
    """

    def setUp(self):
        self.project = Project.objects.create(name="Report language project")
        self.graph = OsintGraph.objects.create(project=self.project, name="Мова звіту", source="ui")
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.settings = override_settings(OSINT_EXPORT_DIR=self.directory.name)
        self.settings.enable()
        self.addCleanup(self.settings.disable)
        from lab import osint_exports
        osint_exports._ROW_CACHE.clear()
        self.addCleanup(osint_exports._ROW_CACHE.clear)
        folder = osint_exports.export_directory(self.graph.id)
        folder.mkdir(parents=True, exist_ok=True)
        self.name = "subdomains-mova.csv"
        # The fixture is deliberately wide enough to drive every control the page
        # owns. A three-row file would leave the pagination, the companion-file
        # link and the hidden-column note unrendered, and an unrendered label is
        # an untranslated label nobody notices.
        lines = ["type,identity,relation,source,target,provenance,notes"]
        lines.append('domain,mova.test,,,,\"{\"source\": \"transform_input\"}\",')
        for index in range(60):
            host = f"host{index:02d}.mova.test"
            lines.append(f'subdomain,{host},,,,\"{{\"source\": \"certificate_transparency\"}}\",')
            lines.append(f',,subdomain_of,{host},mova.test,\"{{\"source\": \"certificate_transparency\"}}\",')
        (folder / self.name).write_text("\n".join(lines) + "\n", encoding="utf-8")
        # A companion with the same stem is what makes the "open the other copy"
        # control appear, so the fixture carries one.
        (folder / "subdomains-mova.jsonl").write_text(
            "".join(json.dumps({"type": "subdomain", "identity": f"host{index:02d}.mova.test"}) + "\n" for index in range(60)),
            encoding="utf-8",
        )
        # A second graph with nothing written to it, so the empty state of the
        # listing is rendered by a test rather than assumed. It lives in its own
        # project because the graph version is unique per project.
        self.empty_graph = OsintGraph.objects.create(
            project=Project.objects.create(name="Report empty project"),
            name="Без файлів",
            source="ui",
        )

    def empty_listing(self, language=None):
        self._language(language)
        return self.client.get(f"/api/osint/graphs/{self.empty_graph.id}/files/")

    def paged(self, language=None):
        # A second page of a 50-row window is the only state in which the
        # previous and next controls, the page counter and the sort arrow exist.
        self._language(language)
        return self.client.get(f"/api/osint/graphs/{self.graph.id}/files/{self.name}?page_size=50&page=2&sort=identity&dir=desc")

    def _language(self, code):
        """Put the workspace language cookie on the test client.

        The test client's cookie jar is the only way to set a cookie for one
        request, and it is also what the browser does, so the view is exercised
        through the same path a report is really opened by.
        """
        if code is None:
            self.client.cookies.pop("requestrider-language", None)
        else:
            self.client.cookies["requestrider-language"] = code
        return self

    def viewer(self, language=None):
        self._language(language)
        return self.client.get(f"/api/osint/graphs/{self.graph.id}/files/{self.name}")

    def listing(self, language=None):
        self._language(language)
        return self.client.get(f"/api/osint/graphs/{self.graph.id}/files/")

    def test_no_report_label_is_the_same_string_in_both_languages(self):
        from lab.report_i18n import REPORT_LABELS
        shared = [key for key, (english, ukrainian) in REPORT_LABELS.items() if english == ukrainian]
        self.assertEqual(shared, [], f"labels identical in both languages: {shared}")

    def test_every_label_is_used_by_a_rendered_page(self):
        # A label nobody renders is a label nobody checks, and the next edit
        # would add one without translating it. A clean page hides the labels
        # that only appear once a filter is active, so both states are rendered.
        from lab.report_i18n import REPORT_LABELS
        rendered = " ".join(
            visible_text(page.content.decode())
            for page in (
                self.viewer("en"),
                self.paged("en"),
                self.filtered("en"),
                self.listing("en"),
                self.empty_listing("en"),
            )
        )
        for key, (english, _) in REPORT_LABELS.items():
            self.assertTrue(shows_wording(rendered, english), key)

    def filtered(self, language=None):
        # A search that matches nothing is the state that shows the empty-state
        # label and the filter chips; a query keeps the Reset control present.
        self._language(language)
        return self.client.get(f"/api/osint/graphs/{self.graph.id}/files/{self.name}?q=zzz&page=2")

    def test_a_page_renders_in_the_workspace_language(self):
        from lab.report_i18n import report_text
        english = self.viewer("en").content.decode()
        ukrainian = self.viewer("uk").content.decode()
        self.assertIn('<html lang="en">', english)
        self.assertIn('<html lang="uk">', ukrainian)
        # The wording is read from the dictionary, so this test cannot drift away
        # from the capitalization the page actually uses.
        self.assertIn(report_text("en", "rows_in_file"), english)
        self.assertIn(report_text("uk", "rows_in_file"), ukrainian)
        self.assertNotIn(report_text("uk", "rows_in_file"), english)
        self.assertNotIn(report_text("en", "rows_in_file"), ukrainian)

    def test_the_invented_link_label_is_translated(self):
        ukrainian = self.viewer("uk").content.decode()
        english = self.viewer("en").content.decode()
        # `link` is the one visible word the report itself invents, so it is the
        # one that has to follow the page language: in the row and in the chip.
        self.assertIn("зв’язок", ukrainian)
        self.assertNotIn(">link<", ukrainian)
        self.assertIn(">link<", english)
        # The filter value stays the canonical key, so a saved ?type= link keeps
        # working after the language changes.
        self.assertIn("type=link", ukrainian)

    def test_no_english_interface_word_survives_on_a_ukrainian_page(self):
        from lab.report_i18n import REPORT_LABELS
        ukrainian = " ".join(visible_text(page.content.decode()) for page in (
            self.viewer("uk"),
            self.paged("uk"),
            self.filtered("uk"),
            self.listing("uk"),
            self.empty_listing("uk"),
        ))
        # Every English wording the report owns must be absent from the visible
        # text of a Ukrainian page. This is the whole rule in one assertion, and
        # it covers the states a single clean page would hide.
        for key, (english, _) in REPORT_LABELS.items():
            self.assertFalse(shows_wording(ukrainian, english), f"{key}: {english}")

    def test_the_english_page_carries_no_ukrainian_wording(self):
        from lab.report_i18n import REPORT_LABELS
        english = visible_text(self.viewer("en").content.decode())
        for key, (_, ukrainian) in REPORT_LABELS.items():
            self.assertFalse(shows_wording(english, ukrainian), f"{key}: {ukrainian}")

    def test_the_listing_renders_in_the_workspace_language_too(self):
        self.assertIn("Файл", self.listing("uk").content.decode())
        self.assertIn("File", self.listing("en").content.decode())
        self.assertIn("Переглянути", self.listing("uk").content.decode())

    def test_data_values_stay_identical_in_both_languages(self):
        from lab.report_i18n import report_text
        # A column name, an entity type and a provenance source are data. They
        # are the same in both pages, and the page says so by not translating
        # them, because a translated column name would no longer match the file.
        for value in ("identity", "type", "subdomain", "certificate_transparency", "subdomain_of"):
            self.assertIn(value, self.viewer("uk").content.decode(), value)
        self.assertEqual(report_text("uk", "link"), "зв’язок")
        self.assertEqual(report_text("en", "link"), "link")

    def test_an_absent_cookie_falls_back_to_english(self):
        # Accept-Language is deliberately not consulted: a Ukrainian browser
        # locale must not put a Ukrainian report under an English workspace.
        self.assertIn('<html lang="en">', self.viewer().content.decode())
        self.client.cookies["HTTP_ACCEPT_LANGUAGE"] = "uk-UA"
        self.assertIn('<html lang="en">', self.viewer().content.decode())
        self.assertIn('<html lang="uk">', self.viewer("uk").content.decode())

    def test_a_junk_cookie_is_normalized_rather_than_rendered(self):
        for junk in ("UK-ua", "Ukrainian", "  uk  ", "de", "", "x-none"):
            response = self.viewer(junk)
            self.assertEqual(response.status_code, 200, junk)
            self.assertIn('<html lang="uk">' if junk.strip().lower().startswith("uk") else '<html lang="en">',
                          response.content.decode(), junk)

    def test_the_switch_writes_the_language_the_server_reads(self):
        # The control is a link, so neither language needs JavaScript. It sets
        # the cookie the server reads and redirects to the same URL without the
        # setter, because the cookie is the only source of the report language.
        page = self.viewer("en").content.decode()
        self.assertIn("?lang=uk", page)
        self.assertNotIn("<script", page)
        self.assertEqual(visible_text(page).count("Українська"), 1)

        response = self.client.get(f"/api/osint/graphs/{self.graph.id}/files/{self.name}?lang=uk")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["Location"], f"/api/osint/graphs/{self.graph.id}/files/{self.name}")
        self.assertEqual(response.cookies["requestrider-language"].value, "uk")
        # Following the redirect renders Ukrainian, which is the whole point.
        ukrainian = self.client.get(f"/api/osint/graphs/{self.graph.id}/files/{self.name}")
        self.assertIn('<html lang="uk">', ukrainian.content.decode())

    def test_the_switch_keeps_the_reader_where_they_were(self):
        # Losing a filter because a reader changed the language would be the
        # same defect in a new place: the language control may only change the
        # language.
        target = f"/api/osint/graphs/{self.graph.id}/files/{self.name}?lang=uk&q=zzz&type=domain&page=2&page_size=50"
        response = self.client.get(target)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            response.headers["Location"],
            f"/api/osint/graphs/{self.graph.id}/files/{self.name}?q=zzz&type=domain&page=2&page_size=50",
        )

    def test_an_unsupported_language_in_the_url_is_ignored_rather_than_looped(self):
        # Redirecting on a value the server does not support would let a stray
        # `?lang=` become a redirect loop; it renders in the current language.
        for junk in ("de", "", "x", "%20"):
            response = self.client.get(f"/api/osint/graphs/{self.graph.id}/files/{self.name}?lang={junk}")
            self.assertEqual(response.status_code, 200, junk)
            self.assertIn('<html lang="en">', response.content.decode(), junk)

    def test_the_report_needs_no_javascript_at_all(self):
        # A server-rendered page with no script is what makes the first byte
        # correct, and it is the reason the language is a cookie and not a pair
        # of wordings in the markup.
        for markup in (self.viewer("en").content.decode(), self.listing("en").content.decode()):
            self.assertNotIn("<script", markup)
        template = Path(__file__).resolve().parent.parent / "templates" / "lab"
        self.assertFalse((template / "_report_lang.html").exists())

    def test_the_workspace_writes_the_language_cookie_the_reports_read(self):
        # The application keeps the choice in localStorage, which the server
        # cannot see, so it mirrors it into a cookie on boot, on toggle and on a
        # restored session. Without all three, a report opened after a restart
        # would answer in the wrong language.
        template = (Path(__file__).resolve().parent.parent / "templates" / "lab" / "index.html").read_text(encoding="utf-8")
        self.assertIn("function rememberLanguage(code)", template)
        self.assertIn("rememberLanguage(language);", template)
        self.assertGreaterEqual(template.count("rememberLanguage("), 4)


class GatewayHealthTests(TestCase):
    """`/health` has to exist, and what it says has to be true.

    The route map had no `health` entry while the engine and the browser worker
    both published one, so a probe walking the stack's services on one path list
    got `404` from Django on every poll: a log line claiming the gateway was down
    while the gateway was the process answering the request. The route is the
    defect, so the route is what these tests pin first.

    The rest pins the part that is easy to get wrong in the other direction. A
    liveness endpoint that reports `ok: true` and folds every dependency into it
    is worse than no endpoint, because it converts an outage into a green light.
    So the body has to separate the gateway from the services behind it, and a
    service that does not answer has to be named as down rather than omitted.
    """

    def test_the_route_exists_and_answers_json(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["ok"])
        # The gateway answering is not the interesting half; identifying which
        # service answered is what makes the endpoint usable by a caller that
        # cannot tell the four apart from the port alone.
        self.assertEqual(payload["service"], "web")

    def test_it_is_the_only_non_api_route_the_monitoring_can_use(self) -> None:
        # Every other route the browser talks to lives under `/api/`. A monitor
        # probing a fixed service path list would otherwise have to know that
        # Django answers `/` and the other two answer `/health`.
        from django.urls import resolve

        self.assertEqual(resolve("/health").view_name, "health")

    def test_a_reachable_stack_reports_each_service_up(self) -> None:
        response = self._probe(engine=200, worker=200)
        payload = response.json()
        self.assertTrue(payload["database"]["ok"])
        self.assertIsNone(payload["database"]["error"])
        self.assertTrue(payload["services"]["engine"]["ok"])
        self.assertEqual(payload["services"]["engine"]["status"], 200)
        self.assertTrue(payload["services"]["browser_worker"]["ok"])
        self.assertEqual(payload["services"]["browser_worker"]["status"], 200)

    def test_a_dead_engine_is_named_and_does_not_flip_the_status_code(self) -> None:
        # The gateway is genuinely alive here — it is answering this request — so
        # the HTTP status stays 200 and the dead service is reported in the body.
        # Reporting 5xx here would be a lie in the other direction: it would tell
        # a supervisor to restart the one process that is working.
        payload = self._probe(engine=None, worker=200).json()
        engine = payload["services"]["engine"]
        self.assertFalse(engine["ok"])
        self.assertIsNone(engine["status"])
        self.assertIn("unavailable", engine["error"])
        self.assertTrue(payload["services"]["browser_worker"]["ok"])

    def test_a_dead_browser_worker_is_named(self) -> None:
        payload = self._probe(engine=200, worker=502).json()
        worker = payload["services"]["browser_worker"]
        self.assertFalse(worker["ok"])
        self.assertEqual(worker["status"], 502)

    def test_the_browser_catalogue_and_its_reasons_are_passed_through(self) -> None:
        # The worker's `/health` is the only place a runtime's availability is
        # measured, and it names a reason per runtime. An endpoint that dropped
        # that would make the operator make a second request to learn which
        # browsers this installation can actually start.
        payload = self._probe(
            engine=200,
            worker=200,
            worker_body={
                "browsers": ["firefox", "camoufox"],
                "unavailable": {"chromium": "not downloaded at /cache/chromium"},
            },
        ).json()
        worker = payload["services"]["browser_worker"]
        self.assertEqual(worker["browsers"], ["firefox", "camoufox"])
        self.assertEqual(
            worker["unavailable"], {"chromium": "not downloaded at /cache/chromium"}
        )

    def test_an_unreachable_database_is_reported_rather_than_hidden(self) -> None:
        with patch.object(views.connection, "cursor", side_effect=OperationalError("cluster gone")):
            payload = self._probe(engine=200, worker=200).json()
        self.assertFalse(payload["database"]["ok"])
        self.assertIn("cluster gone", payload["database"]["error"])
        # The gateway itself still answers: a database outage is not a gateway
        # outage, and restarting the web process would not fix it.
        self.assertTrue(payload["ok"])

    def test_a_service_that_is_not_listening_is_not_a_transport_crash(self) -> None:
        # `URLError` is the ordinary shape of "nothing is listening". Left
        # uncaught it would turn a stopped engine into a 500 traceback on the
        # endpoint whose entire job is to say that engine is stopped.
        payload = self._probe(engine=URLError("connection refused"), worker=200).json()
        self.assertFalse(payload["services"]["engine"]["ok"])

    def test_a_non_json_health_body_is_reachable_but_not_reporting_health(self) -> None:
        # A 200 with an unexpected body means the service is up and answering
        # something other than health — a reverse proxy's error page, a stale
        # binary from another checkout. Reporting `ok: true` there would put a
        # green light on a service that reported nothing, which is the same class
        # of lie this endpoint exists to remove one level up. So the status stays
        # 200 (it really did answer) and `ok` goes false with the reason named.
        payload = self._probe(engine=200, worker=200, engine_body=b"<html>hi</html>").json()
        engine = payload["services"]["engine"]
        self.assertFalse(engine["ok"])
        self.assertEqual(engine["status"], 200)
        self.assertEqual(engine["error"], "health response is not JSON")

    def test_a_write_method_is_refused(self) -> None:
        # Health is read-only and unauthenticated, like the other two services',
        # so it must not answer anything that could change state.
        self.assertEqual(self.client.post("/health").status_code, 405)

    def _probe(self, engine, worker, engine_body=None, worker_body=None) -> None:
        """Answer `/health` with the two internal services pinned.

        The database is left real on purpose: it is reachable in the test runner,
        and a test that mocked it too would not tell whether the view reads it at
        all.
        """

        from urllib.error import HTTPError

        def engine_urlopen(request, timeout=None):
            # `None` is the ordinary shape of "nothing is listening", so it
            # becomes the same `URLError` a closed port produces rather than a
            # value the helper has to special-case in the assertion.
            if engine is None:
                raise URLError("connection refused")
            if isinstance(engine, Exception):
                raise engine
            if isinstance(engine, int) and engine != 200:
                raise HTTPError(request.full_url, engine, "boom", {}, None)
            body = engine_body if engine_body is not None else b'{"ok":true}'
            return _FakeUrlopenResponse(engine if isinstance(engine, int) else 200, body)

        def worker_call(path):
            if isinstance(worker, Exception):
                return 502, {"error": str(worker)}
            if worker != 200:
                return worker, {"error": "worker health check failed"}
            return 200, worker_body or {"browsers": ["firefox"], "unavailable": {}}

        with patch.object(views, "urlopen", side_effect=engine_urlopen), patch.object(
            views, "call_browser_worker_get", side_effect=worker_call
        ):
            return self.client.get("/health")


class _FakeUrlopenResponse:
    """The minimum `urlopen` result the health probe reads."""

    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> bool:
        return False


class TestDatabaseEncodingTests(TestCase):
    """The test database has to be able to store the evidence the tool captures.

    This exists because the failure it guards against is invisible until one
    particular test fails for an unrelated-looking reason. The Intruder marker
    `§` is part of the documented payload syntax, so a database that cannot
    encode it does not fail loudly on a setup check — it fails with a DataError
    inside whichever test happened to save a marked payload, and the error names
    the server encoding rather than the missing setting.
    """

    def test_database_can_store_the_intruder_marker(self) -> None:
        with connection.cursor() as cursor:
            cursor.execute("SHOW server_encoding")
            encoding = str(cursor.fetchone()[0]).upper()
        self.assertIn(
            encoding,
            {"UTF8", "UTF-8"},
            f"the test database encoding is {encoding}, so non-ASCII evidence cannot be stored; "
            "build the test database from a UTF-8 template (POSTGRES_TEST_TEMPLATE)",
        )

    def test_database_round_trips_a_non_ascii_marker(self) -> None:
        # The assertion above reads a server setting; this one proves the
        # connection can actually carry the character the tool depends on.
        with connection.cursor() as cursor:
            cursor.execute("SELECT %s::text", ["\u00a7marker \u00e9"])
            stored = str(cursor.fetchone()[0])
        self.assertEqual(stored, "\u00a7marker \u00e9")


class ScannerFindingIdentityTests(TestCase):
    """Verify stable evidence-aware identity and idempotent ScannerRun upsert."""

    def test_compute_finding_identity_deterministic_and_unique(self):
        from lab.models import compute_finding_identity

        item1 = {
            "vulnerability": "Missing Security Header",
            "url": "https://example.test/",
            "method": "GET",
            "param": "",
            "evidence": "Strict-Transport-Security missing",
        }
        item2 = {
            "title": "missing security header",
            "matched_at": "https://example.test/",
            "method": "get",
            "parameter": "",
            "evidence": "Strict-Transport-Security missing",
        }
        item3 = {
            "vulnerability": "Missing Security Header",
            "url": "https://example.test/",
            "method": "GET",
            "param": "",
            "evidence": "Content-Security-Policy missing",
        }

        h1 = compute_finding_identity(item1)
        h2 = compute_finding_identity(item2)
        h3 = compute_finding_identity(item3)

        self.assertEqual(len(h1), 64)
        self.assertEqual(h1, h2, "Equivalent findings with title vs vulnerability must produce identical identity")
        self.assertNotEqual(h1, h3, "Different evidence must produce distinct identity")

    def test_scanner_run_idempotent_upsert_merges_without_duplicates(self):
        from lab.models import Project, ScannerRun
        from lab.views import _ingest_scanner_run_once

        project = Project.objects.create(name="Identity Test Project")
        url = "https://app.test/"
        findings_v1 = [
            {
                "vulnerability": "Sensitive Path Disclosed",
                "evidence": "/.env returned 200 OK",
                "severity": "MEDIUM",
                "recommendation": "Restrict access to .env",
            },
            {
                "vulnerability": "Exposed Server Banner",
                "evidence": "Server: Apache/2.4",
                "severity": "INFO",
            },
        ]

        run1 = _ingest_scanner_run_once(project, "builtin", url, findings_v1, {"pages": 1})
        self.assertIsNotNone(run1)
        self.assertEqual(ScannerRun.objects.filter(project=project, url=url).count(), 1)
        self.assertEqual(len(run1.findings), 2)
        self.assertEqual(run1.summary["findings_count"], 2)
        self.assertEqual(run1.summary["highest_severity"], "MEDIUM")
        self.assertTrue(all(f.get("identity_hash") for f in run1.findings))

        # Re-running on the same target with enriched evidence and updated severity
        findings_v2 = [
            {
                "vulnerability": "Sensitive Path Disclosed",
                "evidence": "/.env returned 200 OK with AWS_SECRET_ACCESS_KEY disclosed",
                "severity": "HIGH",
                "recommendation": "Restrict access to .env immediately",
            },
            {
                "vulnerability": "New Finding SQLi",
                "evidence": "error in SQL syntax",
                "severity": "CRITICAL",
                "recommendation": "Use parameter binding",
            },
        ]

        run2 = _ingest_scanner_run_once(project, "builtin", url, findings_v2, {"pages": 2})
        self.assertEqual(ScannerRun.objects.filter(project=project, url=url).count(), 1, "Idempotent upsert must not create duplicate ScannerRun")
        self.assertEqual(run1.id, run2.id)

        run2.refresh_from_db()
        self.assertEqual(len(run2.findings), 3, "2 original + 1 new finding merged by identity")
        self.assertEqual(run2.summary["findings_count"], 3)
        self.assertEqual(run2.summary["highest_severity"], "CRITICAL")

        # Check that Sensitive Path Disclosed was upgraded to HIGH with enriched evidence
        sensitive_finding = next(f for f in run2.findings if "Sensitive Path" in f["title"])
        self.assertEqual(sensitive_finding["severity"], "HIGH")
        self.assertIn("AWS_SECRET_ACCESS_KEY", sensitive_finding["evidence"])

