"""Tests for Phase 5.1 (Finding Webhooks), Phase 6.2 (Broker Workflow Recovery), and Repeater Pretty/Raw."""
import json
from unittest.mock import MagicMock, patch

from django.test import Client, TestCase

from lab.models import (
    EngineTask,
    Project,
    ScannerRun,
    Workflow,
    WorkflowNodeExecution,
    WorkflowRun,
)
from lab.workflow_engine import WorkflowRuntime, WorkflowScheduler


class RoadmapP1ClosersTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.project, _ = Project.objects.get_or_create(
            name="P1ClosersProject",
            defaults={"metadata": {"finding_webhook_url": "https://hooks.local/secops"}},
        )
        self.project.metadata = {"finding_webhook_url": "https://hooks.local/secops"}
        self.project.save()

    @patch("urllib.request.urlopen")
    def test_phase51_finding_webhook_fires_only_on_new_findings(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        run = ScannerRun.objects.create(
            project=self.project,
            url="https://target.local/api",
            engine="active",
        )
        finding = {
            "type": "sqli",
            "title": "SQL Injection in id",
            "severity": "CRITICAL",
            "url": "https://target.local/api?id=1",
            "method": "GET",
            "param": "id",
            "evidence": "syntax error near PG",
        }
        run.upsert_findings([finding])
        self.assertEqual(mock_urlopen.call_count, 1)
        req_obj = mock_urlopen.call_args[0][0]
        sent_body = json.loads(req_obj.data.decode("utf-8"))
        self.assertEqual(sent_body["event"], "scanner.finding.discovered")
        self.assertEqual(sent_body["new_count"], 1)

        # Idempotent re-upsert of the same finding must NOT re-trigger webhook
        run.upsert_findings([finding])
        self.assertEqual(mock_urlopen.call_count, 1)

    def test_phase62_broker_workflow_run_is_recovered_not_interrupted(self):
        wf = Workflow.objects.create(
            project=self.project,
            name="Brokered Flow",
            nodes=[
                {"id": "t1", "type": "manual_trigger", "name": "Start", "position": {"x": 0, "y": 0}, "params": {}},
                {"id": "s1", "type": "scanner", "name": "Scan", "position": {"x": 200, "y": 0}, "params": {"url": "https://target.local"}},
            ],
            connections=[{"source": "t1", "target": "s1", "source_handle": "main", "target_handle": "main"}],
        )
        run = WorkflowRun.objects.create(
            workflow=wf,
            project=self.project,
            status="running",
            mode="manual",
            trigger_type="manual_trigger",
            graph_nodes=wf.nodes,
            graph_connections=wf.connections,
        )
        WorkflowNodeExecution.objects.create(
            workflow_run=run,
            node_id="s1",
            status="running",
        )
        EngineTask.objects.create(
            task_type="scanner.active",
            status="accepted",
            workflow_run=run,
            workflow_node_id="s1",
            project=self.project,
        )

        runtime = WorkflowRuntime()
        scheduler = WorkflowScheduler(runtime)
        with patch.object(runtime, "start_recovered") as mock_recover:
            scheduler._recover_interrupted()
            mock_recover.assert_called_once_with(run.id)

        run.refresh_from_db()
        self.assertNotEqual(run.status, "interrupted")
        cp = WorkflowNodeExecution.objects.get(workflow_run=run, node_id="s1")
        self.assertEqual(cp.status, "waiting")

    def test_repeater_pretty_raw_buttons_present(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.content.decode("utf-8")
        self.assertIn("repeater-view-pretty", html)
        self.assertIn("repeater-view-raw", html)
        self.assertIn("currentRepeaterViewMode", html)
