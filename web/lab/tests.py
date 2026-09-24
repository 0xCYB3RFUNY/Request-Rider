import json
from http.client import RemoteDisconnected
from unittest.mock import patch

from django.test import Client, TestCase

from .agent_services import AgentProviderError, OpenAICompatibleProvider, get_agent_provider
from .engine_client import EngineClient
from .middleware import ACTIVE_PROJECT_SESSION_KEY
from .models import Finding, IntruderAttack, OsintEntity, OsintGraph, Project, ProjectEndpoint, ProjectSecret, TargetJob, TrafficRecord, Workflow, WorkflowRun


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
    def test_scanner_run_auto_saves_project_findings(self, call_engine):
        project = Project.objects.create(name="Scanner auto project")
        self.client.post("/api/project-context", data=json.dumps({"project_id": project.id}), content_type="application/json")
        call_engine.return_value = (200, {
            "url": "https://example.test/",
            "findings": [{"title": "Fixture issue", "severity": "HIGH", "confidence_percent": 90, "evidence": "fixture"}],
            "details": {"technologies": ["Django"]},
        })
        response = self.client.post("/api/scanner", data=json.dumps({"url": "https://example.test/"}), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(Finding.objects.filter(project=project, title="Fixture issue").exists())
        self.assertIn("Django", Project.objects.get(id=project.id).tech_stack["scanner"])

    def test_manual_finding_attach_uses_active_project(self):
        project = Project.objects.create(name="Finding destination")
        finding = Finding.objects.create(title="Unassigned issue", fingerprint="manual-issue")
        self.client.post(
            "/api/project-context",
            data=json.dumps({"project_id": project.id}),
            content_type="application/json",
        )
        response = self.client.post(f"/api/findings/{finding.id}/attach")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["finding"]["project_id"], project.id)
        self.assertEqual(Finding.objects.get(id=finding.id).project_id, project.id)

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
        Finding.objects.create(project=project_model, title="Project finding", fingerprint="project-finding")
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
        self.assertFalse(Finding.objects.filter(project_id=project["id"]).exists())
        self.assertFalse(TargetJob.objects.filter(project_id=project["id"]).exists())
        self.assertFalse(TrafficRecord.objects.filter(project_id=project["id"]).exists())
        self.assertFalse(IntruderAttack.objects.filter(project_id=project["id"]).exists())
        self.assertFalse(Workflow.objects.filter(project_id=project["id"]).exists())
        self.assertFalse(WorkflowRun.objects.filter(project_id=project["id"]).exists())

    def test_findings_support_status_confidence_evidence_and_export(self):
        response = self.client.post(
            "/api/findings",
            data=json.dumps({
                "title": "Missing security header",
                "severity": "MEDIUM",
                "confidence": 80,
                "verification_status": "verified",
                "evidence_before": {"headers": {"X-Test": "missing"}},
                "target": "http://fixture.test/",
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201)
        finding = response.json()
        self.assertEqual(finding["confidence"], 80)
        self.assertEqual(Finding.objects.count(), 1)
        updated = self.client.patch(
            f"/api/findings/{finding['id']}",
            data=json.dumps({"status": "confirmed", "evidence_after": {"headers": {"X-Test": "present"}}}),
            content_type="application/json",
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["status"], "confirmed")
        export = self.client.get("/api/findings/export?format=markdown")
        self.assertEqual(export.status_code, 200)
        self.assertIn("Missing security header", export.content.decode())
        verified = self.client.post(
            f"/api/findings/{finding['id']}/verify",
            data=json.dumps({"evidence_after": {"headers": {"X-Test": "present"}}}),
            content_type="application/json",
        )
        self.assertEqual(verified.status_code, 200)
        self.assertTrue(verified.json()["changed"])
        self.assertEqual(verified.json()["finding"]["verification_status"], "changed")

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

    @patch("lab.views.call_engine_get")
    @patch("lab.views.call_browser_worker")
    def test_browser_target_start_forwards_active_socks_route(self, call_browser_worker, call_engine_get):
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
                "proxy_server": "socks5://127.0.0.1:9050",
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
    def test_agent_chat_bounds_attached_context_and_messages(self, generate_chat):
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
        self.assertLessEqual(len(sent_messages), 24)
        self.assertLessEqual(len(sent_messages[-1]["content"]), 12000)
        self.assertLessEqual(len(json.dumps(sent_context, ensure_ascii=False)), 120000)

    @patch("lab.views.generate_agent_chat")
    def test_agent_chat_bounds_project_and_attached_context_together(self, generate_chat):
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
        self.assertLessEqual(len(json.dumps(sent_context, ensure_ascii=False)), 120000)

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

        def opener(_request):
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

    def test_empty_response_is_invalid(self):
        status, payload = EngineClient(
            "http://engine.test",
            opener=lambda _request: self.FakeResponse(body=b""),
        ).request("GET", "/events")
        self.assertEqual(status, 502)
        self.assertEqual(payload["reason"], "ENGINE_INVALID_RESPONSE")

    def test_malformed_json_is_invalid(self):
        status, payload = EngineClient(
            "http://engine.test",
            opener=lambda _request: self.FakeResponse(body=b"{"),
        ).request("GET", "/events")
        self.assertEqual(status, 502)
        self.assertEqual(payload["reason"], "ENGINE_INVALID_RESPONSE")

    def test_network_error_is_unavailable(self):
        from urllib.error import URLError

        status, payload = EngineClient(
            "http://engine.test",
            opener=lambda _request: (_ for _ in ()).throw(URLError("offline")),
        ).request("GET", "/events")
        self.assertEqual(status, 502)
        self.assertEqual(payload["reason"], "ENGINE_UNAVAILABLE")


class AgentProviderTests(TestCase):
    def test_remote_provider_requires_secure_non_loopback_endpoint(self):
        with self.assertRaises(AgentProviderError):
            get_agent_provider(
                "openai_compatible",
                endpoint="http://collector.test/v1/chat/completions",
                model="test",
            )
        with self.assertRaises(AgentProviderError):
            get_agent_provider(
                "openai_compatible",
                endpoint="https://127.0.0.1/v1/chat/completions",
                model="test",
            )

    def test_openrouter_defaults_to_configured_deepseek_free_model(self):
        from .agent_services import PROVIDER_PRESETS

        self.assertEqual(
            PROVIDER_PRESETS["openrouter"][2],
            "deepseek/deepseek-v4-flash-0731:free",
        )

    @patch("lab.agent_services.urlopen")
    def test_chat_accepts_fenced_json_with_reasoning_prefix(self, urlopen):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                content = (
                    "I will inspect the evidence first.\n"
                    "```json\n"
                    '{"message":"I need to inspect History."}\n'
                    "```"
                )
                return json.dumps({"choices": [{"message": {"content": content}}]}).encode()

        urlopen.return_value = FakeResponse()
        provider = OpenAICompatibleProvider(
            endpoint="https://llm.test/v1/chat/completions",
            model="deepseek/deepseek-v4-flash-0731:free",
            api_key="secret-token",
        )
        self.assertEqual(
            provider.chat([{"role": "user", "content": "Inspect History"}]),
            {"message": "I need to inspect History."},
        )

    @patch("lab.agent_services.urlopen")
    def test_chat_accepts_plain_text_provider_response(self, urlopen):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return json.dumps({"choices": [{"message": {"content": "Plain answer"}}]}).encode()

        urlopen.return_value = FakeResponse()
        provider = OpenAICompatibleProvider(
            endpoint="https://llm.test/v1/chat/completions",
            model="local-model",
        )
        self.assertEqual(
            provider.chat([{"role": "user", "content": "Inspect evidence"}]),
            {"message": "Plain answer"},
        )

    @patch("lab.agent_services.urlopen")
    def test_openai_compatible_provider_sends_api_key_in_header_only(self, urlopen):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()

        urlopen.return_value = FakeResponse()
        provider = OpenAICompatibleProvider(
            endpoint="https://llm.test/v1/chat/completions",
            model="local-model",
            api_key="secret-token",
        )
        provider.chat([{"role": "user", "content": "Inspect evidence"}])
        request = urlopen.call_args.args[0]
        self.assertEqual(request.headers["Authorization"], "Bearer secret-token")
        self.assertNotIn("secret-token", request.data.decode())

    @patch("lab.agent_services.urlopen")
    def test_chat_prompt_preserves_user_pentest_prompt(self, urlopen):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode()

        urlopen.return_value = FakeResponse()
        provider = OpenAICompatibleProvider(
            endpoint="https://llm.test/v1/chat/completions",
            model="local-model",
        )
        provider.chat([{"role": "user", "content": "Analyze attached response"}])
        request_body = json.loads(urlopen.call_args.args[0].data)
        self.assertIn("специализирующийся на Burp Suite Professional/Community", request_body["messages"][0]["content"])
        self.assertIn("Prioritized Test Plan", request_body["messages"][0]["content"])
        self.assertIn("Proxy и HTTP history", request_body["messages"][0]["content"])
