"""Tests for F4 Stateful Traffic Correlation & Auto-Chaining."""
import base64
import json
from urllib.parse import quote

from django.test import Client, TestCase

from lab.models import Project, TrafficRecord, Workflow
from lab.traffic_chaining import (
    apply_response_extractors,
    build_workflow_from_exchanges,
    extract_response_artifacts,
)
from lab.workflow_engine import WorkflowRuntime


class TrafficChainingTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.project, _ = Project.objects.get_or_create(name="TrafficChainingProject")

    def test_login_csrf_session_json_id_auto_chaining(self):
        exchanges = [
            {
                "method": "GET",
                "url": "https://target.local/login",
                "request_headers": {"Host": "target.local"},
                "request_body": "",
                "response_headers": {"Content-Type": "text/html"},
                "response_body": '<form><input type="hidden" name="csrf_token" value="csrf_abc_999"></form>',
            },
            {
                "method": "POST",
                "url": "https://target.local/login",
                "request_headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "request_body": "user=alice&pass=secret&csrf_token=csrf_abc_999",
                "response_headers": {
                    "Content-Type": "application/json",
                    "Set-Cookie": "session=sess_xyz_777; Path=/; HttpOnly",
                },
                "response_body": json.dumps({"ok": True, "user": {"profile_id": "prof_4200"}}),
            },
            {
                "method": "POST",
                "url": "https://target.local/api/profile/update?pid=prof_4200",
                "request_headers": {
                    "Content-Type": "application/json",
                    "Cookie": "session=sess_xyz_777",
                },
                "request_body": json.dumps({"id": "prof_4200", "bio": "updated"}),
                "response_headers": {"Content-Type": "application/json"},
                "response_body": '{"updated": true}',
            },
        ]

        built = build_workflow_from_exchanges(exchanges, workflow_name="Login Update Chain")
        nodes = {n["id"]: n for n in built["nodes"]}
        self.assertEqual(len(nodes), 4)
        self.assertIn("trigger_1", nodes)

        # Step 2 must reference Step 1's CSRF token
        self.assertIn("{{nodes.step_1.extracted.csrf_token}}", nodes["step_2"]["params"]["body"])
        self.assertEqual(nodes["step_1"]["params"]["extract"][0]["source"], "html_input")

        # Step 3 must reference Step 2's Set-Cookie and JSON profile_id
        self.assertIn("{{nodes.step_2.extracted.cookie_session}}", nodes["step_3"]["params"]["headers"]["Cookie"])
        self.assertIn("{{nodes.step_2.extracted.user_profile_id}}", nodes["step_3"]["params"]["url"])
        self.assertIn("{{nodes.step_2.extracted.user_profile_id}}", nodes["step_3"]["params"]["body"])
        self.assertGreaterEqual(len(built["correlations"]), 3)

    def test_url_and_base64_encoded_correlation(self):
        raw_token = "tok+slash/eq="
        exchanges = [
            {
                "method": "GET",
                "url": "https://target.local/token",
                "response_headers": {"X-CSRF-Token": raw_token},
                "response_body": "",
            },
            {
                "method": "POST",
                "url": f"https://target.local/submit?t={quote(raw_token, safe='')}",
                "request_headers": {
                    "X-B64": base64.b64encode(raw_token.encode()).decode(),
                },
                "request_body": "ok=1",
                "response_headers": {},
                "response_body": "",
            },
        ]
        built = build_workflow_from_exchanges(exchanges)
        step2 = built["nodes"][2]["params"]
        self.assertIn("{{nodes.step_1.extracted.hdr_x_csrf_token}}", step2["url"])
        self.assertIn("{{nodes.step_1.extracted.hdr_x_csrf_token}}", step2["headers"]["X-B64"])

    def test_workflow_engine_runtime_extraction_and_substitution(self):
        exchanges = [
            {
                "method": "GET",
                "url": "https://target.local/login",
                "response_headers": {},
                "response_body": '<input type="hidden" name="csrf" value="old_csrf_1234">',
            },
            {
                "method": "POST",
                "url": "https://target.local/login",
                "request_body": "csrf=old_csrf_1234",
                "response_headers": {},
                "response_body": "ok",
            },
        ]
        built = build_workflow_from_exchanges(exchanges)
        wf = Workflow.objects.create(
            project=self.project,
            name="Runtime Extract Test",
            nodes=built["nodes"],
            connections=built["connections"],
            active=True,
        )

        observed_step2_bodies = []

        def mock_runner(node_type, params, context):
            node_id = context["node"]["id"]
            if node_id == "step_1":
                return {"status": 200, "headers": {}, "body": '<input type="hidden" name="csrf" value="fresh_live_9876">'}
            observed_step2_bodies.append(params.get("body"))
            return {"status": 200, "headers": {}, "body": "logged_in"}

        from unittest.mock import patch
        from lab.models import WorkflowRun
        runtime = WorkflowRuntime()
        run = WorkflowRun.objects.create(
            workflow=wf,
            project=self.project,
            status="queued",
            mode="manual",
            trigger_type="manual_trigger",
            graph_schema_version=wf.graph_schema_version,
            graph_nodes=wf.nodes,
            graph_connections=wf.connections,
            input_data={},
        )
        with patch("lab.workflow_engine.close_old_connections"):
            runtime._execute(run.id, mock_runner)
        run.refresh_from_db()
        self.assertEqual(run.status, "completed")
        self.assertEqual(observed_step2_bodies, ["csrf=fresh_live_9876"])

    def test_auto_chain_api_endpoint_with_traffic_records(self):
        r1 = TrafficRecord.objects.create(
            project=self.project,
            source="proxy",
            method="GET",
            url="https://target.local/init",
            response_headers={"Set-Cookie": "sid=auto_sid_5555; Path=/"},
            response_body="",
            status_code=200,
        )
        r2 = TrafficRecord.objects.create(
            project=self.project,
            source="proxy",
            method="POST",
            url="https://target.local/action",
            request_headers={"Cookie": "sid=auto_sid_5555"},
            request_body='{"x":1}',
            response_headers={},
            response_body='{"done":true}',
            status_code=200,
        )
        resp = self.client.post(
            "/api/workflows/auto-chain",
            data=json.dumps({
                "project_id": self.project.id,
                "record_ids": [r1.id, r2.id],
                "name": "API Auto Chain",
                "save": True,
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["ok"])
        self.assertGreaterEqual(data["correlation_count"], 1)
        self.assertIsNotNone(data["workflow_id"])
        self.assertTrue(Workflow.objects.filter(id=data["workflow_id"]).exists())
