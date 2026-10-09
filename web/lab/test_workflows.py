import json
import os
import threading
import time
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from django.test import Client, TestCase, TransactionTestCase

from .models import (
    EngineTask,
    Project,
    TrafficRecord,
    Workflow,
    WorkflowNodeExecution,
    WorkflowRun,
)
from .workflow_engine import (
    WorkflowValidationError,
    decode_value,
    next_cron_time,
    validate_cron,
    validate_workflow,
)


class WorkflowGraphTests(TestCase):
    def test_runtime_executor_registry_covers_every_validated_node_type(self):
        from .workflow_engine import NODE_TYPES, WorkflowRuntime

        self.assertEqual(set(WorkflowRuntime().node_executors), set(NODE_TYPES))

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

    def test_graph_validation_rejects_invalid_nodes_and_handles(self):
        valid_nodes = [
            {"id": "start", "type": "manual_trigger", "params": {}},
            {"id": "condition", "type": "condition", "params": {}},
            {"id": "done", "type": "output", "params": {}},
        ]
        cases = [
            (
                "unknown node type",
                [{"id": "start", "type": "not_a_node", "params": {}}],
                [],
                "unsupported node type",
            ),
            (
                "duplicate node id",
                [
                    {"id": "start", "type": "manual_trigger", "params": {}},
                    {"id": "start", "type": "output", "params": {}},
                ],
                [],
                "duplicate node id",
            ),
            (
                "malformed params",
                [{"id": "start", "type": "manual_trigger", "params": []}],
                [],
                "params must be an object",
            ),
            (
                "unknown edge endpoint",
                valid_nodes,
                [{"source": "missing", "target": "done"}],
                "connection references an unknown node",
            ),
            (
                "invalid condition source handle",
                valid_nodes,
                [{"source": "condition", "target": "done", "source_handle": "main"}],
                "unsupported source handle",
            ),
            (
                "invalid target handle",
                valid_nodes,
                [{"source": "start", "target": "done", "target_handle": "false"}],
                "unsupported target handle",
            ),
        ]
        for label, nodes, connections, message in cases:
            with self.subTest(label=label), self.assertRaisesRegex(
                WorkflowValidationError, message
            ):
                validate_workflow(nodes, connections, require_trigger=True)

    def test_graph_validation_preserves_disconnected_nodes_as_draftable_graph(self):
        nodes, connections = validate_workflow(
            [
                {"id": "start", "type": "manual_trigger", "params": {}},
                {"id": "done", "type": "output", "params": {}},
                {"id": "disconnected", "type": "set", "params": {"values": {"key": "value"}}},
            ],
            [{"source": "start", "target": "done"}],
            require_trigger=True,
        )
        self.assertEqual([node["id"] for node in nodes], ["start", "done", "disconnected"])
        self.assertEqual(len(connections), 1)

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
        self.assertEqual(workflow["graph_schema_version"], 1)
        self.assertEqual(Workflow.objects.count(), 1)
        loaded = self.client.get(f"/api/workflows/{workflow['id']}")
        self.assertEqual(loaded.status_code, 200)
        self.assertEqual(loaded.json()["nodes"][1]["params"]["values"]["answer"], 42)
        self.assertEqual(loaded.json()["graph_schema_version"], 1)
        deleted = self.client.delete(f"/api/workflows/{workflow['id']}")
        self.assertEqual(deleted.status_code, 200)
        self.assertFalse(Workflow.objects.filter(id=workflow["id"]).exists())

    def test_workflow_graph_schema_version_rejects_unknown_versions(self):
        for value in (0, 2, "1", True):
            with self.subTest(version=value):
                response = self.create_workflow(graph_schema_version=value)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["reason"], "INVALID_WORKFLOW")
        self.assertEqual(Workflow.objects.count(), 0)

    def test_workflow_import_accepts_legacy_graph_without_schema_version(self):
        response = self.create_workflow()
        legacy_workflow = response.json()
        legacy_workflow.pop("graph_schema_version")
        imported = self.client.post(
            "/api/workflows/import",
            data=json.dumps({"workflow": legacy_workflow}),
            content_type="application/json",
        )
        self.assertEqual(imported.status_code, 201)
        self.assertEqual(imported.json()["graph_schema_version"], 1)

    def test_workflow_import_rejects_unknown_graph_schema_version(self):
        response = self.create_workflow()
        source = response.json()
        source["graph_schema_version"] = 2
        imported = self.client.post(
            "/api/workflows/import",
            data=json.dumps({"workflow": source}),
            content_type="application/json",
        )
        self.assertEqual(imported.status_code, 400)
        self.assertEqual(imported.json()["reason"], "INVALID_WORKFLOW")
        self.assertEqual(Workflow.objects.count(), 1)

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
        self.assertEqual(
            set(WorkflowNodeExecution.objects.filter(workflow_run_id=run_id).values_list(
                "node_id", flat=True
            )),
            {"trigger", "result", "output"},
        )

    def test_run_api_includes_ordered_redacted_node_timeline(self):
        workflow = Workflow.objects.create(
            project=self.project,
            nodes=[
                {"id": "trigger", "type": "manual_trigger", "params": {}},
                {"id": "request", "type": "repeater", "params": {}},
            ],
            connections=[],
        )
        run = WorkflowRun.objects.create(
            workflow=workflow,
            project=self.project,
            status="completed",
            input_data={"access_token": "root-secret"},
            output_data={"message": "Authorization: Bearer output-secret"},
        )
        WorkflowNodeExecution.objects.create(
            workflow_run=run,
            node_id="request",
            status="completed",
            input_data={"headers": {"Authorization": "Bearer input-secret"}},
            output_data={"api_key": "node-secret", "result": "ok"},
        )

        response = self.client.get(f"/api/workflows/runs/{run.id}")
        self.assertEqual(response.status_code, 200)
        item = response.json()
        self.assertEqual(len(item["node_executions"]), 1)
        execution = item["node_executions"][0]
        self.assertEqual(execution["node_type"], "repeater")
        self.assertEqual(execution["status"], "completed")
        self.assertEqual(execution["input"]["headers"]["Authorization"], "[REDACTED]")
        self.assertEqual(execution["output"]["api_key"], "[REDACTED]")
        self.assertEqual(item["input"]["access_token"], "[REDACTED]")
        response_text = json.dumps(item)
        for secret in ("root-secret", "input-secret", "node-secret", "output-secret"):
            self.assertNotIn(secret, response_text)

    def test_completed_node_checkpoints_are_reused_without_repeating_actions(self):
        from .workflow_engine import WorkflowRuntime

        workflow = Workflow.objects.create(
            project=self.project,
            nodes=[
                {"id": "trigger", "type": "manual_trigger", "params": {}},
                {"id": "probe", "type": "target", "params": {"url": "https://fixture.test/"}},
                {"id": "output", "type": "output", "params": {}},
            ],
            connections=[
                {"source": "trigger", "target": "probe"},
                {"source": "probe", "target": "output"},
            ],
        )
        run = WorkflowRun.objects.create(
            workflow=workflow,
            project=self.project,
            status="queued",
            input_data={"fixture": True},
        )
        side_effects = []

        def tool_runner(node_type, params, context):
            side_effects.append((node_type, params["url"]))
            return {"pages": [{"url": params["url"]}]}

        runtime = WorkflowRuntime()
        runtime._execute(run.id, tool_runner)
        self.assertEqual(len(side_effects), 1)
        self.assertEqual(
            WorkflowNodeExecution.objects.get(
                workflow_run=run,
                node_id="probe",
            ).output_data,
            {"main": {"pages": [{"url": "https://fixture.test/"}]}},
        )

        WorkflowRun.objects.filter(pk=run.pk).update(status="queued")
        runtime._execute(run.id, tool_runner)
        self.assertEqual(len(side_effects), 1)
        self.assertEqual(WorkflowRun.objects.get(pk=run.pk).status, "completed")

    def test_incomplete_node_checkpoint_is_not_retried_automatically(self):
        from .workflow_engine import WorkflowRuntime

        workflow = Workflow.objects.create(
            project=self.project,
            nodes=[
                {"id": "trigger", "type": "manual_trigger", "params": {}},
                {"id": "probe", "type": "target", "params": {"url": "https://fixture.test/"}},
            ],
            connections=[{"source": "trigger", "target": "probe"}],
        )
        run = WorkflowRun.objects.create(
            workflow=workflow,
            project=self.project,
            status="queued",
            input_data={},
        )
        attempts = []

        def uncertain_runner(node_type, params, context):
            attempts.append(node_type)
            raise RuntimeError("result lost after dispatch")

        runtime = WorkflowRuntime()
        runtime._execute(run.id, uncertain_runner)
        self.assertEqual(attempts, ["target"])
        self.assertEqual(
            WorkflowNodeExecution.objects.get(workflow_run=run, node_id="probe").status,
            "failed",
        )

        WorkflowRun.objects.filter(pk=run.pk).update(status="queued")
        runtime._execute(run.id, uncertain_runner)
        self.assertEqual(attempts, ["target"])
        self.assertIn(
            "manual review is required before retry",
            WorkflowRun.objects.get(pk=run.pk).error,
        )

    def test_a_durable_node_suspends_the_run_instead_of_holding_a_worker(self):
        from .engine_broker import EngineTaskDeferred
        from .workflow_engine import WorkflowRuntime

        workflow = Workflow.objects.create(
            project=self.project,
            nodes=[
                {"id": "trigger", "type": "manual_trigger", "params": {}},
                {"id": "probe", "type": "target", "params": {"url": "https://fixture.test/"}},
                {"id": "out", "type": "output", "params": {}},
            ],
            connections=[
                {"source": "trigger", "target": "probe"},
                {"source": "probe", "target": "out"},
            ],
        )
        run = WorkflowRun.objects.create(
            workflow=workflow,
            project=self.project,
            status="queued",
        )
        task_id = uuid4()

        def durable_runner(node_type, params, context):
            if node_type != "target":
                return {"main": context.get("input")}
            raise EngineTaskDeferred(task_id, context["node"]["id"])

        runtime = WorkflowRuntime()
        runtime._execute(run.id, durable_runner)

        run.refresh_from_db()
        checkpoint = WorkflowNodeExecution.objects.get(workflow_run=run, node_id="probe")
        self.assertEqual(run.status, "waiting")
        self.assertEqual(run.current_node, "probe")
        self.assertEqual(run.error, "")
        # The node is parked, not finished: nothing downstream may have run on a
        # result that does not exist yet.
        self.assertEqual(checkpoint.status, "waiting")
        self.assertFalse(
            WorkflowNodeExecution.objects.filter(workflow_run=run, node_id="out").exists()
        )
        self.assertIsNone(run.finished_at)

    def test_a_suspended_run_continues_when_the_engine_result_arrives(self):
        from .engine_broker import EngineTaskDeferred
        from .workflow_engine import WorkflowRuntime

        workflow = Workflow.objects.create(
            project=self.project,
            nodes=[
                {"id": "trigger", "type": "manual_trigger", "params": {}},
                {"id": "probe", "type": "target", "params": {"url": "https://fixture.test/"}},
                {"id": "out", "type": "output", "params": {}},
            ],
            connections=[
                {"source": "trigger", "target": "probe"},
                {"source": "probe", "target": "out"},
            ],
        )
        run = WorkflowRun.objects.create(
            workflow=workflow,
            project=self.project,
            status="queued",
        )
        task_id = uuid4()
        published = []

        def durable_runner(node_type, params, context):
            if node_type == "target":
                # The first pass publishes and leaves; the second pass gets the
                # answer, exactly as a resumed run would.
                published.append(context["node"]["id"])
                if len(published) == 1:
                    raise EngineTaskDeferred(task_id, context["node"]["id"])
                return {"main": {"status": "completed", "pages": 3}}
            return {"main": context.get("input")}

        runtime = WorkflowRuntime()
        runtime._execute(run.id, durable_runner)
        self.assertEqual(WorkflowRun.objects.get(pk=run.pk).status, "waiting")
        self.assertEqual(published, ["probe"])

        # The engine answered. The consumer records it and requeues the run; the
        # same runtime continues from the durable checkpoint.
        task = EngineTask.objects.create(
            task_type="target.crawl",
            payload={},
            workflow_run=run,
            workflow_node_id="probe",
            status="completed",
            result={"status": "completed", "pages": 3},
        )
        with patch(
            "lab.engine_broker.resume_waiting_workflow_run",
            side_effect=lambda run_id: runtime._execute(run_id, durable_runner),
        ):
            from .engine_broker import apply_engine_result_to_workflow

            apply_engine_result_to_workflow(task)

        run.refresh_from_db()
        self.assertEqual(run.status, "completed")
        # The engine answer travelled the edge into the Output node, so the run
        # result is what the operator sees rather than a raw engine payload.
        self.assertEqual(run.output_data["value"]["main"]["pages"], 3)
        checkpoint = WorkflowNodeExecution.objects.get(workflow_run=run, node_id="probe")
        self.assertEqual(checkpoint.status, "completed")
        # The suspended node was published once and answered once, so the run
        # never sent the external action a second time.
        self.assertEqual(published, ["probe", "probe"])

    def test_a_waiting_run_is_resumed_by_its_result_not_by_a_restart(self):
        from .workflow_engine import WorkflowRuntime, WorkflowScheduler

        workflow = Workflow.objects.create(
            project=self.project,
            nodes=[{"id": "trigger", "type": "manual_trigger", "params": {}}],
            connections=[],
        )
        run = WorkflowRun.objects.create(
            workflow=workflow,
            project=self.project,
            status="waiting",
            current_node="probe",
        )
        WorkflowNodeExecution.objects.create(
            workflow_run=run,
            node_id="trigger",
            status="completed",
        )
        WorkflowNodeExecution.objects.create(
            workflow_run=run,
            node_id="probe",
            status="waiting",
        )
        task = EngineTask.objects.create(
            task_type="target.crawl",
            payload={},
            workflow_run=run,
            workflow_node_id="probe",
        )

        runtime = WorkflowRuntime()
        scheduler = WorkflowScheduler(runtime)
        with patch.object(runtime, "start_recovered") as start_recovered:
            scheduler._recover_interrupted()

        run.refresh_from_db()
        self.assertEqual(run.status, "queued")
        start_recovered.assert_called_once_with(run.id)
        self.assertEqual(
            WorkflowNodeExecution.objects.get(workflow_run=run, node_id="probe").status,
            "waiting",
        )
        # The parked run is not republished as a fresh crawl: the correlation
        # from before the restart is what the resumed node waits on.
        self.assertEqual(EngineTask.objects.filter(workflow_run=run).count(), 1)
        self.assertEqual(task.workflow_node_id, "probe")

    def test_route_drain_cancels_a_waiting_run_and_its_engine_task(self):
        from .engine_broker import create_engine_task
        from .workflow_engine import WorkflowRuntime

        workflow = Workflow.objects.create(
            project=self.project,
            nodes=[{"id": "trigger", "type": "manual_trigger", "params": {}}],
            connections=[],
        )
        run = WorkflowRun.objects.create(
            workflow=workflow,
            project=self.project,
            status="waiting",
            current_node="probe",
        )
        task = EngineTask.objects.create(
            task_type="target.crawl",
            payload={},
            workflow_run=run,
            workflow_node_id="probe",
        )

        # The cancel task is published through Celery on commit; the assertion is
        # about the correlation it carries, not about the broker being reachable.
        with patch("lab.tasks.publish_engine_task.delay"):
            with patch("lab.engine_broker.create_engine_task", wraps=create_engine_task) as create:
                cancelled = WorkflowRuntime().cancel_all(self.project.id)

        run.refresh_from_db()
        self.assertIn(run.id, cancelled)
        self.assertEqual(run.status, "cancelled")
        cancel_types = [call.args[0] for call in create.call_args_list]
        self.assertIn("engine.task.cancel", cancel_types)
        cancel_task = EngineTask.objects.get(task_type="engine.task.cancel")
        self.assertEqual(cancel_task.payload["task_id"], str(task.task_id))

    def test_a_waiting_run_can_be_paused_and_resumed_without_resending_its_action(self):
        from .workflow_engine import WorkflowRuntime

        workflow = Workflow.objects.create(
            project=self.project,
            nodes=[{"id": "trigger", "type": "manual_trigger", "params": {}}],
            connections=[],
        )
        run = WorkflowRun.objects.create(
            workflow=workflow,
            project=self.project,
            status="waiting",
            current_node="probe",
        )
        WorkflowNodeExecution.objects.create(
            workflow_run=run,
            node_id="probe",
            status="waiting",
            output_data={"task_id": "22222222-2222-4222-8222-222222222222"},
        )
        runtime = WorkflowRuntime()

        self.assertTrue(runtime.pause(run.id))
        run.refresh_from_db()
        self.assertEqual(run.status, "paused")

        with patch.object(runtime, "_dispatch_run") as dispatch:
            self.assertTrue(runtime.resume(run.id))

        run.refresh_from_db()
        # Resuming a parked run hands it back to a worker instead of only
        # renaming the state: a run nobody executes is a pause that never ends.
        self.assertEqual(run.status, "queued")
        dispatch.assert_called_once_with(run.id)
        # The parked node still points at the task it published, so the resumed
        # run waits for that answer instead of sending the request again.
        self.assertEqual(
            WorkflowNodeExecution.objects.get(workflow_run=run, node_id="probe").output_data["task_id"],
            "22222222-2222-4222-8222-222222222222",
        )

    def test_scheduler_resumes_only_runs_between_completed_nodes(self):
        from .workflow_engine import WorkflowRuntime, WorkflowScheduler

        workflow = Workflow.objects.create(
            project=self.project,
            nodes=[{"id": "trigger", "type": "manual_trigger", "params": {}}],
            connections=[],
        )
        recoverable = WorkflowRun.objects.create(
            workflow=workflow,
            project=self.project,
            status="running",
        )
        uncertain = WorkflowRun.objects.create(
            workflow=workflow,
            project=self.project,
            status="running",
        )
        WorkflowNodeExecution.objects.create(
            workflow_run=uncertain,
            node_id="trigger",
            status="running",
        )

        runtime = WorkflowRuntime()
        scheduler = WorkflowScheduler(runtime)
        with patch.object(runtime, "start_recovered") as start_recovered:
            scheduler._recover_interrupted()

        recoverable.refresh_from_db()
        uncertain.refresh_from_db()
        self.assertEqual(recoverable.status, "queued")
        start_recovered.assert_called_once_with(recoverable.id)
        self.assertEqual(uncertain.status, "interrupted")
        self.assertIn("incomplete node checkpoint", uncertain.error)

    def test_execution_order_comes_from_edges_not_node_array_order(self):
        from .workflow_engine import WorkflowRuntime

        workflow = Workflow.objects.create(
            project=self.project,
            nodes=[
                {"id": "output", "type": "output", "params": {}},
                {"id": "probe", "type": "target", "params": {"url": "https://fixture.test/"}},
                {"id": "trigger", "type": "manual_trigger", "params": {}},
            ],
            connections=[
                {"source": "probe", "target": "output"},
                {"source": "trigger", "target": "probe"},
            ],
        )
        run = WorkflowRun.objects.create(
            workflow=workflow,
            project=self.project,
            status="queued",
            input_data={},
        )
        runtime = WorkflowRuntime()
        runtime._execute(
            run.id,
            lambda _node_type, _params, _context: {"pages": []},
        )
        completed = [
            event["node_id"]
            for event in WorkflowRun.objects.get(pk=run.pk).logs
            if event["status"] == "completed"
        ]
        self.assertEqual(completed, ["trigger", "probe", "output"])

    def test_run_executes_the_graph_snapshot_not_a_later_workflow_edit(self):
        from .workflow_engine import WorkflowRuntime

        original_nodes = [
            {"id": "trigger", "type": "manual_trigger", "params": {}},
            {"id": "set", "type": "set", "params": {"values": {"version": "original"}}},
            {"id": "output", "type": "output", "params": {}},
        ]
        original_connections = [
            {"source": "trigger", "target": "set"},
            {"source": "set", "target": "output"},
        ]
        workflow = Workflow.objects.create(
            project=self.project,
            nodes=original_nodes,
            connections=original_connections,
        )
        run = WorkflowRun.objects.create(
            workflow=workflow,
            project=self.project,
            status="queued",
            graph_schema_version=workflow.graph_schema_version,
            graph_nodes=original_nodes,
            graph_connections=original_connections,
        )
        workflow.nodes = [
            {"id": "trigger", "type": "manual_trigger", "params": {}},
            {"id": "set", "type": "set", "params": {"values": {"version": "edited"}}},
            {"id": "output", "type": "output", "params": {}},
        ]
        workflow.save(update_fields=["nodes"])

        WorkflowRuntime()._execute(run.id, None)

        run.refresh_from_db()
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.output_data["value"], {"version": "original"})

    def test_duplicate_worker_delivery_does_not_execute_a_queued_run_twice(self):
        from .workflow_engine import WorkflowRuntime

        workflow = Workflow.objects.create(
            project=self.project,
            nodes=[
                {"id": "trigger", "type": "manual_trigger", "params": {}},
                {"id": "probe", "type": "target", "params": {"url": "https://fixture.test/"}},
            ],
            connections=[{"source": "trigger", "target": "probe"}],
        )
        run = WorkflowRun.objects.create(
            workflow=workflow,
            project=self.project,
            status="queued",
            graph_schema_version=workflow.graph_schema_version,
            graph_nodes=workflow.nodes,
            graph_connections=workflow.connections,
        )
        entered = threading.Event()
        release = threading.Event()
        invocations = []

        def blocking_runner(node_type, params, context):
            invocations.append(node_type)
            entered.set()
            self.assertTrue(release.wait(timeout=5))
            return {"pages": []}

        runtime = WorkflowRuntime()
        worker = threading.Thread(
            target=runtime._execute,
            args=(run.id, blocking_runner),
        )
        worker.start()
        self.assertTrue(entered.wait(timeout=5))
        runtime._execute(run.id, blocking_runner)
        release.set()
        worker.join(timeout=5)

        self.assertFalse(worker.is_alive())
        self.assertEqual(invocations, ["target"])
        self.assertEqual(WorkflowRun.objects.get(pk=run.pk).status, "completed")

    def test_celery_run_dispatch_and_remote_controls_use_persisted_state(self):
        from .workflow_engine import WorkflowRuntime

        workflow = Workflow.objects.create(
            project=self.project,
            nodes=[{"id": "trigger", "type": "manual_trigger", "params": {}}],
            connections=[],
        )
        runtime = WorkflowRuntime()
        with (
            patch("lab.workflow_engine.WORKFLOW_CELERY_ENABLED", True),
            patch("lab.tasks.execute_workflow_run.delay") as dispatch,
        ):
            run = runtime.start(
                workflow,
                mode="manual",
                trigger_type="manual",
                input_data={},
            )

        dispatch.assert_called_once_with(run.id)
        self.assertNotIn(run.id, runtime.controls)
        WorkflowRun.objects.filter(pk=run.pk).update(status="running")
        self.assertTrue(runtime.pause(run.id))
        run.refresh_from_db()
        self.assertEqual(run.status, "paused")
        with (
            patch("lab.workflow_engine.WORKFLOW_CELERY_ENABLED", True),
            patch("lab.tasks.execute_workflow_run.delay") as resume_dispatch,
        ):
            self.assertTrue(runtime.resume(run.id))
        run.refresh_from_db()
        # A run with no worker in this process is resumed by handing it back to
        # one. Leaving it merely `running` would be a pause that never ends.
        self.assertEqual(run.status, "queued")
        resume_dispatch.assert_called_once_with(run.id)
        WorkflowRun.objects.filter(pk=run.pk).update(status="running")
        self.assertTrue(runtime.cancel(run.id))
        run.refresh_from_db()
        self.assertEqual(run.status, "cancelled")

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

    def test_workflow_stream_reads_events_written_by_another_process(self):
        workflow = Workflow.objects.create(
            project=self.project,
            nodes=[{"id": "trigger", "type": "manual_trigger", "params": {}}],
            connections=[],
        )
        run = WorkflowRun.objects.create(
            workflow=workflow,
            project=self.project,
            status="running",
        )
        response = self.client.get(f"/api/workflows/runs/{run.id}/stream")
        stream = iter(response.streaming_content)
        self.assertIn(b"event: snapshot", next(stream))
        WorkflowRun.objects.filter(pk=run.pk).update(
            status="completed",
            logs=[{
                "at": datetime.now(timezone.utc).isoformat(),
                "node_id": "trigger",
                "status": "completed",
                "message": "",
            }],
        )
        event = next(stream)
        complete = next(stream)
        self.assertIn(b'"node_id": "trigger"', event)
        self.assertIn(b'"status": "completed"', complete)

    def test_workflow_stream_ends_when_the_run_is_deleted_underneath_it(self):
        """A run deleted mid-stream ends the stream; it does not raise.

        The generator polls the run row once a second, so a cascade cleanup or
        an explicit delete while the operator is watching turns the poll into
        `WorkflowRun.DoesNotExist`. Unhandled, it kills the response mid-flight
        and leaves the browser on a dead stream - measured as 18 tracebacks in
        the container log during one E2E run.

        There is no honest terminal event to send: the row that would carry the
        status is gone, and reporting `completed` would be a lie the UI would
        act on. So the generator returns, and the stream closes cleanly.
        """
        workflow = Workflow.objects.create(
            project=self.project,
            nodes=[{"id": "trigger", "type": "manual_trigger", "params": {}}],
            connections=[],
        )
        run = WorkflowRun.objects.create(
            workflow=workflow,
            project=self.project,
            status="running",
        )
        response = self.client.get(f"/api/workflows/runs/{run.id}/stream")
        stream = iter(response.streaming_content)
        self.assertIn(b"event: snapshot", next(stream))
        WorkflowRun.objects.filter(pk=run.pk).delete()
        # Draining must terminate instead of raising DoesNotExist. A `for` loop
        # swallows StopIteration by design, so the drain is written as repeated
        # `next()` and the ceiling turns a stream that never ends into a named
        # failure instead of a hang.
        chunks = 0
        with self.assertRaises(StopIteration):
            while True:
                next(stream)
                chunks += 1
                self.assertLess(
                    chunks, 10,
                    "the stream kept producing events after the run was deleted",
                )

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
        from .views import _OAST_GATEWAY_TIMEOUT_DEFAULT_MS, workflow_tool_runner
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
        # Every provider round trip carries the bound, so an unresponsive OAST
        # provider ends the node with an error instead of a stuck run.
        self.assertEqual(call_engine.call_args.kwargs["timeout"], _OAST_GATEWAY_TIMEOUT_DEFAULT_MS)
        self.assertEqual(call_engine_get.call_args.kwargs["timeout"], _OAST_GATEWAY_TIMEOUT_DEFAULT_MS)
        call_engine_delete.assert_called_once_with("/proxy/oast/17")

    def test_oast_gateway_bound_is_overridable_and_never_silent(self):
        from .views import _OAST_GATEWAY_TIMEOUT_DEFAULT_MS, _oast_gateway_timeout

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("RR_OAST_GATEWAY_TIMEOUT_MS", None)
            self.assertEqual(_oast_gateway_timeout(), _OAST_GATEWAY_TIMEOUT_DEFAULT_MS)
            # A value the operator cannot read would be a hidden cap, so an
            # unreadable one falls back to the documented default rather than
            # silently shortening or removing the bound.
            os.environ["RR_OAST_GATEWAY_TIMEOUT_MS"] = "not-a-number"
            self.assertEqual(_oast_gateway_timeout(), _OAST_GATEWAY_TIMEOUT_DEFAULT_MS)
            os.environ["RR_OAST_GATEWAY_TIMEOUT_MS"] = "0"
            self.assertEqual(_oast_gateway_timeout(), _OAST_GATEWAY_TIMEOUT_DEFAULT_MS)
            os.environ["RR_OAST_GATEWAY_TIMEOUT_MS"] = "2500"
            self.assertEqual(_oast_gateway_timeout(), 2500)
            os.environ.pop("RR_OAST_GATEWAY_TIMEOUT_MS", None)

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
