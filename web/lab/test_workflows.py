import json
import time
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from django.test import Client, TestCase, TransactionTestCase

from .models import Project, TrafficRecord, Workflow, WorkflowRun
from .workflow_engine import (
    WorkflowValidationError,
    decode_value,
    next_cron_time,
    validate_cron,
    validate_workflow,
)


class WorkflowGraphTests(TestCase):
    def test_graph_validation_normalizes_nodes_and_rejects_cycles(self):
        nodes, connections = validate_workflow(
            [
                {"id": "start", "type": "manual_trigger", "params": {}},
                {"id": "done", "type": "output", "params": {"label": "Done"}},
            ],
            [{"source": "start", "target": "done"}],
            require_trigger=True,
        )
        self.assertEqual(nodes[0]["position"], {"x": 80.0, "y": 80.0})
        self.assertEqual(connections[0]["source_handle"], "main")
        with self.assertRaises(WorkflowValidationError):
            validate_workflow(
                [
                    {"id": "start", "type": "manual_trigger", "params": {}},
                    {"id": "loop", "type": "output", "params": {}},
                ],
                [
                    {"source": "start", "target": "loop"},
                    {"source": "loop", "target": "start"},
                ],
                require_trigger=True,
            )

    def test_n8n_style_graph_aliases_are_normalized(self):
        nodes, connections = validate_workflow(
            [
                {"id": "start", "type": "rider-nodes-base.manualTrigger", "position": [10, 20], "data": {"value": 1}},
                {"id": "done", "type": "rider-nodes-base.output", "parameters": {"label": "Done"}},
            ],
            {"start": {"main": [[{"node": "done", "type": "main", "index": 0}]]}},
            require_trigger=True,
        )
        self.assertEqual(nodes[0]["type"], "manual_trigger")
        self.assertEqual(nodes[0]["position"], {"x": 10.0, "y": 20.0})
        self.assertEqual(connections[0]["target"], "done")

    def test_jwt_decoder_does_not_claim_signature_verification(self):
        token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.signature"
        result = decode_value("jwtDecode", token)
        self.assertEqual(result["payload"], {"sub": "1"})
        self.assertFalse(result["verified"])

    def test_repeater_burst_is_manual_only(self):
        with self.assertRaises(WorkflowValidationError):
            validate_workflow(
                [
                    {"id": "schedule", "type": "schedule_trigger", "params": {"cron": "*/5 * * * *"}},
                    {"id": "burst", "type": "repeater_burst", "params": {"url": "http://127.0.0.1:8765/health"}},
                ],
                [{"source": "schedule", "target": "burst"}],
                require_trigger=True,
            )

    def test_last_byte_sync_is_manual_only_and_confirmation_gated(self):
        from .workflow_engine import workflow_requires_confirmation

        with self.assertRaises(WorkflowValidationError):
            validate_workflow(
                [
                    {"id": "schedule", "type": "schedule_trigger", "params": {"cron": "*/5 * * * *"}},
                    {"id": "last_byte", "type": "last_byte_sync", "params": {"url": "http://127.0.0.1:8765/sync", "body": "canary"}},
                ],
                [{"source": "schedule", "target": "last_byte"}],
                require_trigger=True,
            )
        nodes, _ = validate_workflow(
            [
                {"id": "manual", "type": "manual_trigger", "params": {}},
                {"id": "last_byte", "type": "last_byte_sync", "params": {"url": "http://127.0.0.1:8765/sync", "body": "canary"}},
            ],
            [{"source": "manual", "target": "last_byte"}],
            require_trigger=True,
        )
        self.assertTrue(workflow_requires_confirmation(nodes))

    def test_route_drain_cancels_all_active_workflow_controls(self):
        from .workflow_engine import RunControl, WorkflowRuntime

        runtime = WorkflowRuntime()
        first = RunControl(project_id=7)
        second = RunControl(project_id=None)
        runtime.controls[11] = first
        runtime.controls[12] = second
        callback_called = []
        first.add_cleanup(lambda: callback_called.append(11))

        self.assertEqual(runtime.cancel_all(), [11, 12])
        self.assertTrue(first.cancel.is_set())
        self.assertTrue(second.cancel.is_set())
        self.assertEqual(callback_called, [11])

    def test_cron_validation_and_next_occurrence(self):
        validate_cron("*/5 * * * *")
        after = datetime(2026, 1, 1, 12, 1, tzinfo=timezone.utc)
        self.assertEqual(next_cron_time("*/5 * * * *", after).isoformat(), "2026-01-01T12:05:00+00:00")
        with self.assertRaises(WorkflowValidationError):
            validate_cron("61 * * * *")

    def test_template_catalog_exposes_valid_unique_manifests(self):
        from .workflow_templates import TEMPLATE_SCHEMA, list_templates

        templates = list_templates()
        self.assertGreaterEqual(len(templates), 8)
        ids = [item["template_id"] for item in templates]
        self.assertEqual(len(ids), len(set(ids)))
        for item in templates:
            self.assertEqual(item["$schema"], TEMPLATE_SCHEMA)
            self.assertIn(item["meta"]["category"], {
                "recon_asset_discovery", "api_microservices", "fuzzing_injection",
                "ai_llm_security", "compliance_devsecops", "oast_security", "business_logic", "auth_sessions",
            })
            nodes, connections = validate_workflow(
                item["workflow"]["nodes"], item["workflow"]["connections"]
            )
            self.assertTrue(nodes)
            self.assertTrue(connections)

    def test_template_target_defaults_are_unlimited(self):
        from .workflow_templates import list_templates

        for item in list_templates():
            for node in item["workflow"]["nodes"]:
                if node.get("type") not in {"target", "target_browser"}:
                    continue
                params = node.get("params", {})
                self.assertEqual(params.get("max_pages"), 0, item["template_id"])
                self.assertEqual(params.get("max_depth"), -1, item["template_id"])

    def test_node_catalog_exposes_tool_specific_editor_fields(self):
        from .workflow_engine import node_catalog

        catalog = {item["type"]: item for item in node_catalog()}
        repeater_fields = {field["name"] for field in catalog["repeater"]["fields"]}
        self.assertTrue({"method", "url", "headers", "body", "delay_ms"} <= repeater_fields)
        self.assertTrue({"url", "max_pages", "max_depth", "same_origin"} <= {
            field["name"] for field in catalog["target"]["fields"]
        })
        self.assertTrue({"mode", "payloads", "transformations", "concurrency"} <= {
            field["name"] for field in catalog["intruder"]["fields"]
        })
        self.assertTrue({"server_url", "listener_id", "poll_interval_sec", "timeout_sec", "capture_protocols"} <= {
            field["name"] for field in catalog["oast_listener"]["fields"]
        })
        self.assertIn("oast_collect", catalog)
        self.assertTrue({"iterations", "concurrency", "delay_ms", "timeout_ms"} <= {
            field["name"] for field in catalog["repeater_burst"]["fields"]
        })
        self.assertTrue(catalog["repeater_burst"].get("confirmation"))
        self.assertTrue({"method", "url", "headers", "body", "iterations", "concurrency", "hold_ms", "timeout_ms"} <= {
            field["name"] for field in catalog["last_byte_sync"]["fields"]
        })
        self.assertTrue(catalog["last_byte_sync"].get("confirmation"))

    def test_node_catalog_timeout_defaults_are_unlimited(self):
        from .workflow_engine import node_catalog

        catalog = {item["type"]: item for item in node_catalog()}
        self.assertEqual(catalog["repeater_burst"]["defaults"]["timeout_ms"], 0)
        self.assertEqual(catalog["last_byte_sync"]["defaults"]["timeout_ms"], 0)
        self.assertEqual(catalog["oast_listener"]["defaults"]["timeout_sec"], 0)
        self.assertEqual(catalog["oast_collect"]["defaults"]["timeout_sec"], 0)


class WorkflowApiTests(TransactionTestCase):
    def setUp(self):
        self.client = Client()
        self.project = Project.objects.create(name="Automation project")

    def create_workflow(self, **extra):
        payload = {
            "name": "Fixture workflow",
            "project_id": self.project.id,
            "nodes": [
                {"id": "trigger", "type": "manual_trigger", "name": "Start", "params": {}},
                {"id": "result", "type": "set", "name": "Set result", "params": {"values": {"answer": 42}}},
                {"id": "output", "type": "output", "name": "Result", "params": {"label": "Done"}},
            ],
            "connections": [
                {"source": "trigger", "target": "result"},
                {"source": "result", "target": "output"},
            ],
        }
        payload.update(extra)
        return self.client.post("/api/workflows", data=json.dumps(payload), content_type="application/json")

    def test_template_store_api_returns_builtin_catalog(self):
        response = self.client.get("/api/workflow-templates")
        self.assertEqual(response.status_code, 200)
        items = response.json()["items"]
        self.assertEqual(len(items), 23)
        self.assertEqual(items[0]["template_id"], "logic-baseline")
        safe_batch = {
            "read-only-api-headers",
            "js-asset-inventory",
            "debug-surface-readonly",
            "schema-endpoint-discovery",
            "perimeter-asset-inventory",
            "request-evidence-ai-triage",
        }
        self.assertTrue(safe_batch.issubset({item["template_id"] for item in items}))
        safe_items = [item for item in items if item["template_id"] in safe_batch]
        self.assertTrue(all(item["meta"]["requires_confirmation"] for item in safe_items))
        high_risk_batch = {
            "last-byte-sync-review",
            "bola-idor-differential",
            "race-condition-observation",
            "waf-rule-differential",
            "jwt-claim-mutation-differential",
            "xxe-oast-canary",
            "ci-cd-exposure-review",
        }
        self.assertTrue(high_risk_batch.issubset({item["template_id"] for item in items}))
        high_risk_items = [item for item in items if item["template_id"] in high_risk_batch]
        self.assertTrue(all(item["meta"]["execution"] == "active" for item in high_risk_items))
        self.assertTrue(all(item["meta"]["requires_confirmation"] for item in high_risk_items))
        self.assertTrue(all(
            any(node.get("params", {}).get("__requires_confirmation") for node in item["workflow"]["nodes"] if node.get("type") == "manual_trigger")
            for item in high_risk_items
        ))
        self.assertEqual(self.client.post("/api/workflow-templates").status_code, 405)

    def test_workflow_crud_and_project_association(self):
        response = self.create_workflow()
        self.assertEqual(response.status_code, 201)
        workflow = response.json()
        self.assertEqual(workflow["project_id"], self.project.id)
        self.assertEqual(Workflow.objects.count(), 1)
        loaded = self.client.get(f"/api/workflows/{workflow['id']}")
        self.assertEqual(loaded.status_code, 200)
        self.assertEqual(loaded.json()["nodes"][1]["params"]["values"]["answer"], 42)
        deleted = self.client.delete(f"/api/workflows/{workflow['id']}")
        self.assertEqual(deleted.status_code, 200)
        self.assertFalse(Workflow.objects.filter(id=workflow["id"]).exists())

    def test_manual_run_executes_graph_and_persists_run(self):
        workflow_id = self.create_workflow().json()["id"]
        response = self.client.post(
            f"/api/workflows/{workflow_id}/run",
            data={"input": {"value": "from trigger"}},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 202)
        run_id = response.json()["id"]
        deadline = time.monotonic() + 3
        item = {}
        while time.monotonic() < deadline:
            item = self.client.get(f"/api/workflows/runs/{run_id}").json()
            if item["status"] in {"completed", "failed", "cancelled"}:
                break
            time.sleep(0.05)
        self.assertEqual(item["status"], "completed", item)
        self.assertEqual(item["output"]["value"], {"answer": 42})
        self.assertEqual(item["output"]["label"], "Done")
        self.assertTrue(WorkflowRun.objects.filter(id=run_id).exists())

    def test_workflow_export_import_and_terminal_stream(self):
        created = self.create_workflow()
        workflow_id = created.json()["id"]
        exported = self.client.get(f"/api/workflows/{workflow_id}/export")
        self.assertEqual(exported.status_code, 200)
        imported = self.client.post(
            "/api/workflows/import",
            data=exported.json(),
            content_type="application/json",
        )
        self.assertEqual(imported.status_code, 201)
        self.assertNotEqual(imported.json()["id"], workflow_id)
        run = self.client.post(
            f"/api/workflows/{workflow_id}/run",
            data={},
            content_type="application/json",
        )
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            snapshot = self.client.get(f"/api/workflows/runs/{run.json()['id']}").json()
            if snapshot["status"] == "completed":
                break
            time.sleep(0.05)
        stream = self.client.get(f"/api/workflows/runs/{run.json()['id']}/stream")
        content = b"".join(stream.streaming_content).decode()
        self.assertIn("event: snapshot", content)
        self.assertIn('"status": "completed"', content)

    @patch("lab.views.call_engine")
    def test_repeater_node_can_iterate_a_bounded_input_list(self, call_engine):
        call_engine.return_value = (200, {"status": 200, "body": "ok", "headers": {}, "time": 1, "size": 2})
        response = self.create_workflow(
            nodes=[
                {"id": "trigger", "type": "manual_trigger", "params": {}},
                {"id": "request", "type": "repeater", "params": {"urls": ["https://one.test/", "https://two.test/"], "delay_ms": 0}},
                {"id": "output", "type": "output", "params": {"label": "Responses"}},
            ],
            connections=[
                {"source": "trigger", "target": "request"},
                {"source": "request", "target": "output"},
            ],
        )
        run = self.client.post(
            f"/api/workflows/{response.json()['id']}/run",
            data={},
            content_type="application/json",
        )
        deadline = time.monotonic() + 3
        item = {}
        while time.monotonic() < deadline:
            item = self.client.get(f"/api/workflows/runs/{run.json()['id']}").json()
            if item["status"] in {"completed", "failed", "cancelled"}:
                break
            time.sleep(0.05)
        self.assertEqual(item["status"], "completed", item)
        self.assertEqual(call_engine.call_count, 2)
        self.assertEqual(item["output"]["value"]["count"], 2)

    @patch("lab.views.call_engine")
    @patch("lab.views.call_engine_get")
    def test_repeater_burst_is_parallel_orchestration(self, call_engine_get, call_engine):
        from .views import workflow_tool_runner

        self.project.target = "http://127.0.0.1:8765/health"
        self.project.save(update_fields=["target", "updated_at"])
        call_engine.return_value = (202, {"burst_id": 9, "status": "running", "total": 3, "completed": 0, "failed": 0, "results": []})
        call_engine_get.return_value = (200, {"burst_id": 9, "status": "completed", "total": 3, "completed": 3, "failed": 0, "results": [{"iteration": 0, "status": 200, "body": "ok", "headers": {}, "time": 1, "size": 2, "source_ip": "198.51.100.44"}]})
        result = workflow_tool_runner("repeater_burst", {
            "method": "GET",
            "url": "http://127.0.0.1:8765/health",
            "iterations": 3,
            "concurrency": 2,
            "delay_ms": 0,
        }, {"input": {}, "workflow": SimpleNamespace(project=self.project), "control": None})
        self.assertEqual(call_engine.call_count, 1)
        call_engine_get.assert_called_once_with("/proxy/repeater-burst/9")
        self.assertEqual(result["burst_id"], 9)
        self.assertEqual(result["completed"], 3)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(TrafficRecord.objects.get(source="repeater").source_ip, "198.51.100.44")

    @patch("lab.views.call_engine")
    def test_repeater_burst_requires_url_before_engine_call(self, call_engine):
        from .views import workflow_tool_runner

        with self.assertRaisesRegex(WorkflowValidationError, "URL is required"):
            workflow_tool_runner("repeater_burst", {
                "method": "GET",
                "url": "",
                "iterations": 1,
                "concurrency": 1,
                "delay_ms": 0,
                "timeout_ms": 1000,
            }, {"input": {}, "workflow": None, "control": None})
        call_engine.assert_not_called()

    @patch("lab.views.call_engine_get")
    @patch("lab.views.call_engine")
    def test_repeater_burst_accepts_arbitrary_method_and_body(self, call_engine, call_engine_get):
        from .views import workflow_tool_runner

        call_engine.return_value = (202, {"burst_id": 19, "status": "running", "total": 1, "completed": 0, "failed": 0, "results": []})
        call_engine_get.return_value = (200, {"burst_id": 19, "status": "completed", "total": 1, "completed": 1, "failed": 0, "results": []})
        result = workflow_tool_runner("repeater_burst", {
            "method": "DELETE",
            "url": "http://127.0.0.1:8765/health",
            "body": "state=change",
            "iterations": 1,
            "concurrency": 1,
            "delay_ms": 0,
            "timeout_ms": 1000,
        }, {"input": {}, "workflow": SimpleNamespace(project=self.project), "control": None})
        self.assertEqual(result["status"], "completed")
        call_engine.assert_called_once()
        self.assertEqual(call_engine.call_args.args[1]["method"], "DELETE")
        self.assertEqual(call_engine.call_args.args[1]["body"], "state=change")

    def test_confirmation_marker_gates_repeater_only_template_graph(self):
        response = self.create_workflow(
            nodes=[
                {"id": "trigger", "type": "manual_trigger", "params": {"__requires_confirmation": True}},
                {"id": "request", "type": "repeater", "params": {"url": "http://127.0.0.1:8765/health"}},
            ],
            connections=[{"source": "trigger", "target": "request"}],
        )
        run = self.client.post(
            f"/api/workflows/{response.json()['id']}/run",
            data={},
            content_type="application/json",
        )
        self.assertEqual(run.status_code, 400)
        self.assertEqual(run.json()["reason"], "CONFIRMATION_REQUIRED")

    @patch("lab.views.call_engine_get")
    @patch("lab.views.call_engine")
    def test_last_byte_sync_runs_and_persists_completed_evidence(self, call_engine, call_engine_get):
        from .views import workflow_tool_runner

        self.project.target = "http://127.0.0.1:8765/sync"
        self.project.save(update_fields=["target", "updated_at"])
        call_engine.return_value = (202, {"last_byte_id": 17, "status": "running", "total": 2, "completed": 0, "failed": 0, "results": []})
        call_engine_get.return_value = (200, {
            "last_byte_id": 17,
            "status": "completed",
            "total": 2,
            "completed": 1,
            "failed": 0,
            "results": [{"iteration": 0, "status": 200, "body": "ok", "headers": {"Content-Type": "text/plain"}, "time": 7, "size": 2}],
        })
        result = workflow_tool_runner("last_byte_sync", {
            "method": "POST",
            "url": "http://127.0.0.1:8765/sync",
            "headers": {"X-Fixture": "canary"},
            "body": "canary",
            "iterations": 2,
            "concurrency": 1,
            "delay_ms": 0,
            "hold_ms": 25,
            "timeout_ms": 2000,
        }, {"input": {}, "workflow": SimpleNamespace(project=self.project), "control": None})
        self.assertEqual(call_engine.call_count, 1)
        call_engine.assert_called_once_with("/proxy/last-byte", {
            "method": "POST",
            "url": "http://127.0.0.1:8765/sync",
            "headers": {"X-Fixture": "canary"},
            "body": "canary",
            "iterations": 2,
            "concurrency": 1,
            "delay_ms": 0,
            "hold_ms": 25,
            "timeout_ms": 2000,
        })
        call_engine_get.assert_called_once_with("/proxy/last-byte/17")
        self.assertEqual(result["last_byte_id"], 17)
        self.assertEqual(TrafficRecord.objects.filter(source="last-byte", project=self.project).count(), 1)

    @patch("lab.views.call_engine")
    def test_last_byte_sync_requires_body_before_engine_call(self, call_engine):
        from .views import workflow_tool_runner

        self.project.target = "http://127.0.0.1:8765/sync"
        self.project.save(update_fields=["target", "updated_at"])
        with self.assertRaisesRegex(WorkflowValidationError, "non-empty request body"):
            workflow_tool_runner("last_byte_sync", {
                "method": "POST",
                "url": "http://127.0.0.1:8765/sync",
                "body": "",
                "iterations": 1,
                "concurrency": 1,
                "hold_ms": 25,
                "timeout_ms": 2000,
            }, {"input": {}, "workflow": SimpleNamespace(project=self.project), "control": None})
        call_engine.assert_not_called()

    @patch("lab.views.call_engine")
    def test_repeater_can_use_a_url_outside_project_target(self, call_engine):
        self.project.target = "https://allowed.test/api"
        self.project.save(update_fields=["target", "updated_at"])
        call_engine.return_value = (200, {"status": 200, "body": "ok", "headers": {}, "time": 1, "size": 2})
        response = self.create_workflow(
            nodes=[
                {"id": "trigger", "type": "manual_trigger", "params": {}},
                {"id": "request", "type": "repeater", "params": {"url": "https://outside.test/"}},
            ],
            connections=[{"source": "trigger", "target": "request"}],
        )
        run = self.client.post(
            f"/api/workflows/{response.json()['id']}/run",
            data={},
            content_type="application/json",
        )
        deadline = time.monotonic() + 3
        item = {}
        while time.monotonic() < deadline:
            item = self.client.get(f"/api/workflows/runs/{run.json()['id']}").json()
            if item["status"] in {"failed", "completed", "cancelled"}:
                break
            time.sleep(0.05)
        self.assertEqual(item["status"], "completed", item)
        call_engine.assert_called_once()

    def test_oast_listener_requires_confirmation_and_does_not_persist_auth(self):
        response = self.create_workflow(
            nodes=[
                {"id": "trigger", "type": "manual_trigger", "params": {}},
                {"id": "listener", "type": "oast_listener", "params": {"server_url": "http://127.0.0.1:8766", "auth_token": "do-not-store"}},
            ],
            connections=[{"source": "trigger", "target": "listener"}],
        )
        self.assertEqual(response.status_code, 201)
        self.assertNotIn("auth_token", response.json()["nodes"][1]["params"])
        run = self.client.post(
            f"/api/workflows/{response.json()['id']}/run",
            data={},
            content_type="application/json",
        )
        self.assertEqual(run.status_code, 400)
        self.assertEqual(run.json()["reason"], "CONFIRMATION_REQUIRED")

    @patch("lab.views.call_engine")
    @patch("lab.views.call_engine_get")
    @patch("lab.views.call_engine_delete")
    def test_oast_start_and_collect_use_engine_contract(self, call_engine_delete, call_engine_get, call_engine):
        from .views import workflow_tool_runner

        call_engine.return_value = (202, {
            "listener_id": 17,
            "payload_url": "http://127.0.0.1:8766/hit/rr-17",
            "domain": "rr-17.fixture.local",
            "status": "listening",
        })
        shared = {}
        started = workflow_tool_runner("oast_listener", {
            "server_url": "http://127.0.0.1:8766",
            "poll_interval_sec": 1,
            "timeout_sec": 2,
            "capture_protocols": ["http"],
        }, {"input": {}, "shared": shared, "workflow": None, "control": None})
        self.assertEqual(started["listener_id"], 17)
        self.assertEqual(shared["oast"]["payload_url"], "http://127.0.0.1:8766/hit/rr-17")
        call_engine_get.return_value = (200, {
            "listener_id": 17,
            "status": "listening",
            "triggered": True,
            "events": [{"event_id": "evt-1", "protocol": "http"}],
        })
        collected = workflow_tool_runner("oast_collect", {
            "poll_interval_sec": 1,
            "timeout_sec": 2,
        }, {"input": {}, "shared": shared, "workflow": None, "control": None})
        self.assertTrue(collected["triggered"])
        self.assertEqual(collected["events"][0]["event_id"], "evt-1")
        call_engine.assert_called_once()
        call_engine_get.assert_called_once_with("/proxy/oast/17")
        call_engine_delete.assert_called_once_with("/proxy/oast/17")

    def test_intruder_graph_requires_confirmation(self):
        response = self.create_workflow(
            nodes=[
                {"id": "trigger", "type": "manual_trigger", "params": {}},
                {"id": "attack", "type": "intruder", "params": {"base_request": {}, "payloads": []}},
            ],
            connections=[{"source": "trigger", "target": "attack"}],
        )
        workflow_id = response.json()["id"]
        run = self.client.post(
            f"/api/workflows/{workflow_id}/run",
            data={},
            content_type="application/json",
        )
        self.assertEqual(run.status_code, 400)
        self.assertEqual(run.json()["reason"], "CONFIRMATION_REQUIRED")

    def test_condition_only_runs_the_active_branch_before_merge(self):
        response = self.create_workflow(
            nodes=[
                {"id": "trigger", "type": "manual_trigger", "params": {}},
                {"id": "set", "type": "set", "params": {"values": {"route": "ok"}}},
                {"id": "condition", "type": "condition", "params": {"field": "route", "operator": "equals", "value": "ok"}},
                {"id": "true", "type": "set", "params": {"values": {"branch": "true"}}},
                {"id": "false", "type": "set", "params": {"values": {"branch": "false"}}},
                {"id": "merge", "type": "merge", "params": {}},
                {"id": "output", "type": "output", "params": {"label": "Branch"}},
            ],
            connections=[
                {"source": "trigger", "target": "set"},
                {"source": "set", "target": "condition"},
                {"source": "condition", "target": "true", "source_handle": "true"},
                {"source": "condition", "target": "false", "source_handle": "false"},
                {"source": "true", "target": "merge"},
                {"source": "false", "target": "merge"},
                {"source": "merge", "target": "output"},
            ],
        )
        run = self.client.post(
            f"/api/workflows/{response.json()['id']}/run",
            data={},
            content_type="application/json",
        )
        deadline = time.monotonic() + 3
        item = {}
        while time.monotonic() < deadline:
            item = self.client.get(f"/api/workflows/runs/{run.json()['id']}").json()
            if item["status"] in {"completed", "failed", "cancelled"}:
                break
            time.sleep(0.05)
        self.assertEqual(item["status"], "completed", item)
        self.assertEqual(item["output"]["value"], [{"branch": "true"}])
        self.assertNotIn("false", [event["node_id"] for event in item["logs"] if event["status"] == "completed"])

    def test_webhook_starts_an_active_workflow(self):
        response = self.create_workflow(
            nodes=[
                {"id": "hook", "type": "webhook_trigger", "params": {"method": "POST"}},
                {"id": "set", "type": "set", "params": {"values": {"received": True}}},
            ],
            connections=[{"source": "hook", "target": "set"}],
            webhook_slug="fixture-hook",
            active=True,
        )
        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.json()["active"])
        webhook = self.client.post(
            "/api/workflows/hooks/fixture-hook",
            data=json.dumps({"hello": "world"}),
            content_type="application/json",
        )
        self.assertEqual(webhook.status_code, 202)
        self.assertTrue(webhook.json()["accepted"])
        run_id = webhook.json()["run_id"]
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            run = self.client.get(f"/api/workflows/runs/{run_id}").json()
            if run["status"] in {"completed", "failed", "cancelled"}:
                break
            time.sleep(0.05)
        self.assertEqual(run["status"], "completed", run)
        self.assertEqual(run["output"], {"received": True})
