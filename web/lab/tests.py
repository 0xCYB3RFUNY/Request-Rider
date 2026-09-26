import io
import json
import tempfile
import threading
from urllib.error import URLError
from http.client import RemoteDisconnected
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from django.db import OperationalError
from django.test import Client, TestCase, override_settings

from . import views
from .agent_services import AgentProviderError, AgentRequestCancelled, OpenAICompatibleProvider, cancel_active_agent_requests, get_agent_provider
from .engine_client import EngineClient
from .middleware import ACTIVE_PROJECT_SESSION_KEY
from .models import IntruderAttack, OsintEntity, OsintGraph, OsintRelation, Project, ProjectEndpoint, ProjectSecret, ScannerRun, TargetJob, TrafficRecord, Workflow, WorkflowRun
from .views import _osint_transform_persist
from .ws_events import project_event_hub


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
        graph = OsintGraph.objects.create(project=project, name="Graph snapshot", source="ui")
        OsintEntity.objects.create(project=project, graph=graph, entity_type="domain", identity="graph.test")
        response = self.client.get(f"/api/projects/{project.id}/hub")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["osint_graphs"][0]["name"], "Graph snapshot")
        self.assertEqual(response.json()["osint_graphs"][0]["entities"], 1)

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
    def test_osint_transform_job_survives_a_locked_database(self, call_engine, call_engine_get):
        project = Project.objects.create(name="Transform lock project")
        graph = OsintGraph.objects.create(project=project, name="Transform lock", source="ui")
        call_engine_get.return_value = (200, {
            "job_id": "osint-lock", "state": "completed",
            "progress": {"phase": "completed", "names": 1},
            "result": {
                "transform": "subdomains", "value": "example.test", "observed_at": "2026-01-01T00:00:00Z",
                "local_only": False, "network_used": True,
                "entities": [{"type": "subdomain", "identity": "www.example.test"}],
                "relations": [], "warnings": [], "metadata": {},
            },
        })
        # A finished transform is paid for by the network work behind it, so a
        # momentary local write lock must not lose the result.
        real_upsert = views.upsert_graph
        attempts = []

        def locked_once(*args, **kwargs):
            attempts.append(1)
            if len(attempts) == 1:
                raise OperationalError("database is locked")
            return real_upsert(*args, **kwargs)

        with patch("lab.views.upsert_graph", side_effect=locked_once):
            response = self.client.get(f"/api/osint/graphs/{graph.id}/transform/jobs/osint-lock")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["state"], "completed")
        self.assertEqual(len(attempts), 2)
        self.assertTrue(OsintEntity.objects.filter(graph=graph, identity="www.example.test").exists())

    @patch("lab.views.call_engine_get")
    @patch("lab.views.call_engine")
    def test_osint_transform_job_reports_a_lock_that_never_clears(self, call_engine, call_engine_get):
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
        # A lock that never clears is an explicit error, not a silent success
        # and not a server traceback.
        with patch("lab.views.upsert_graph", side_effect=OperationalError("database is locked")):
            response = self.client.get(f"/api/osint/graphs/{graph.id}/transform/jobs/osint-busy")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["reason"], "DATABASE_BUSY")
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
            # The file is readable in the browser and downloadable.
            name = pointer.properties["csv"]
            opened = self.client.get(f"/api/osint/graphs/{graph.id}/files/{name}")
            self.assertEqual(opened.status_code, 200)
            self.assertIn("host0.example.test", opened.content.decode())
            self.assertIn(f"host{rows - 1}.example.test", opened.content.decode())
            downloaded = self.client.get(f"/api/osint/graphs/{graph.id}/files/{name}?download=1")
            self.assertEqual(downloaded.status_code, 200)
            self.assertIn("attachment", downloaded["Content-Disposition"])

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
        self.assertEqual(call_engine.call_args.args[1]["files"], [{"name": "a.yaml", "path": "", "content": "id: a\n"}])

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
    def test_scanner_nuclei_upload_rejects_invalid_input(self, call_engine):
        for payload in [{}, {"files": []}, {"files": [{"content": "id: a\n"}]}, {"files": [{"name": "a.yaml"}]}]:
            response = self.client.post("/api/scanner/nuclei/upload", data=json.dumps(payload), content_type="application/json")
            self.assertEqual(response.status_code, 400, payload)
        self.assertFalse(call_engine.called)

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
                "options": {"severity": ["high"], "concurrency": 25, "rate_limit": 150, "no_color": True},
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        forwarded = call_engine.call_args.args[1]
        self.assertEqual(forwarded["upload_id"], "abc123")
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
            data=json.dumps({"url": "https://example.test/", "upload_id": "up-1", "options": {"concurrency": 5}}),
            content_type="application/json",
        )
        self.assertEqual(start.status_code, 202)
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
        for payload in [{}, {"url": "https://example.test/"}, {"url": "https://example.test/", "files": []}, {"url": "https://example.test/", "files": [{"name": "evil.sh", "content": "x"}]}, {"url": "https://example.test/", "files": [{"name": "a.yaml", "content": "x", "path": 7}]}]:
            response = self.client.post("/api/scanner/nuclei", data=json.dumps(payload), content_type="application/json")
            self.assertEqual(response.status_code, 400, payload)

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
        response = self.client.delete("/api/traffic")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"ok": True})

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
    def test_provider_accepts_http_and_loopback_endpoints(self):
        for endpoint in ("http://collector.test/v1/chat/completions", "https://127.0.0.1/v1/chat/completions"):
            provider = get_agent_provider("openai_compatible", endpoint=endpoint, model="test")
            self.assertEqual(provider.endpoint, endpoint)

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
