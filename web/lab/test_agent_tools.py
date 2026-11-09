"""Unit tests for the Request-Rider Autonomous AI Agent tool registry."""

from unittest.mock import patch, MagicMock
from django.test import TestCase

from .models import Project, TrafficRecord, ScannerRun
from .agent_tools import (
    get_available_tools,
    execute_agent_tool,
    tool_history_search,
    tool_finding_record,
    tool_request_send,
)


class AgentToolsTestCase(TestCase):
    def setUp(self):
        self.project = Project.objects.create(name="AgentTestProject", target="https://example.com")

    def test_get_available_tools(self):
        tools = get_available_tools()
        self.assertIsInstance(tools, list)
        self.assertGreaterEqual(len(tools), 3)
        tool_names = [t["function"]["name"] for t in tools]
        self.assertIn("history_search", tool_names)
        self.assertIn("request_send", tool_names)
        self.assertIn("finding_record", tool_names)

    def test_history_search_empty(self):
        result = execute_agent_tool("history_search", {"query": "login"}, context=None)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["count"], 0)

    def test_history_search_with_records(self):
        TrafficRecord.objects.create(
            project=self.project,
            method="POST",
            url="https://example.com/api/login",
            status_code=200,
            host="example.com",
        )
        context = MagicMock()
        context.active_project = self.project
        result = execute_agent_tool("history_search", {"query": "login"}, context=context)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["results"][0]["method"], "POST")

    def test_finding_record(self):
        context = MagicMock()
        context.active_project = self.project
        result = execute_agent_tool(
            "finding_record",
            {
                "title": "SQL Injection in /api/search",
                "severity": "HIGH",
                "description": "Parameter 'q' vulnerable to boolean-based blind SQLi.",
                "evidence_url": "https://example.com/api/search?q=1'",
            },
            context=context,
        )
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["severity"], "HIGH")
        self.assertTrue(result["saved_to_project"])

        # Check ScannerRun
        run = ScannerRun.objects.filter(project=self.project).first()
        self.assertIsNotNone(run)
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(run.findings[0]["title"], "SQL Injection in /api/search")

    @patch("lab.views.call_engine")
    def test_request_send(self, mock_call_engine):
        mock_call_engine.return_value = (200, {
            "status": 200,
            "time": 45,
            "size": 128,
            "headers": {"Content-Type": "application/json"},
            "body": '{"ok": true}',
        })
        context = MagicMock()
        context.active_project = self.project

        result = execute_agent_tool(
            "request_send",
            {"url": "https://example.com/api/test", "method": "GET"},
            context=context,
        )
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["http_status"], 200)

        # Verify traffic record created
        record = TrafficRecord.objects.filter(source="tool").first()
        self.assertIsNotNone(record)
        self.assertEqual(record.url, "https://example.com/api/test")

    def test_finding_record_multiple_accumulate(self):
        context = MagicMock()
        context.active_project = self.project

        # Add 1st finding
        execute_agent_tool(
            "finding_record",
            {"title": "Finding 1", "severity": "MEDIUM", "description": "Desc 1"},
            context=context,
        )
        # Add 2nd finding
        execute_agent_tool(
            "finding_record",
            {"title": "Finding 2", "severity": "CRITICAL", "description": "Desc 2"},
            context=context,
        )

        run = ScannerRun.objects.filter(project=self.project).first()
        self.assertIsNotNone(run)
        self.assertEqual(len(run.findings), 2)
        titles = [f["title"] for f in run.findings]
        self.assertIn("Finding 1", titles)
        self.assertIn("Finding 2", titles)

    def test_finding_record_default_severity(self):
        context = MagicMock()
        context.active_project = self.project

        result = execute_agent_tool(
            "finding_record",
            {"title": "Info Finding", "description": "Informational finding"},
            context=context,
        )
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["severity"], "INFO")

    def test_url_encode_and_decode(self):
        payload = "<script>alert('xss & sqli')</script>"
        enc = execute_agent_tool("url_encode", {"text": payload, "plus": False})
        self.assertEqual(enc["status"], "success")
        self.assertNotIn(" ", enc["encoded"])
        self.assertIn("%3Cscript%3E", enc["encoded"])

        dec = execute_agent_tool("url_decode", {"text": enc["encoded"], "plus": False})
        self.assertEqual(dec["status"], "success")
        self.assertEqual(dec["decoded"], payload)

    def test_base64_encode_and_decode(self):
        secret = "admin:supersecret123!@#"
        enc = execute_agent_tool("base64_encode", {"text": secret})
        self.assertEqual(enc["status"], "success")
        self.assertTrue(len(enc["encoded"]) > 0)

        dec = execute_agent_tool("base64_decode", {"encoded": enc["encoded"]})
        self.assertEqual(dec["status"], "success")
        self.assertEqual(dec["decoded"], secret)

    def test_data_transform_url_encode(self):
        res = execute_agent_tool("data_transform", {"operation": "urlEncode", "value": "a b&c"})
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["result"], "a%20b%26c")

    def test_data_transform_base64_roundtrip(self):
        secret = "hello world!"
        enc = execute_agent_tool("data_transform", {"operation": "base64Encode", "value": secret})
        self.assertEqual(enc["status"], "success")
        dec = execute_agent_tool("data_transform", {"operation": "base64Decode", "value": enc["result"]})
        self.assertEqual(dec["status"], "success")
        self.assertEqual(dec["result"], secret)

    def test_data_transform_sha256(self):
        res = execute_agent_tool("data_transform", {"operation": "sha256", "value": "abc"})
        self.assertEqual(res["status"], "success")
        self.assertEqual(
            res["result"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_data_transform_case_and_trim(self):
        res = execute_agent_tool("data_transform", {"operation": "uppercase", "value": "HeLLo"})
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["result"], "HELLO")
        res = execute_agent_tool("data_transform", {"operation": "trim", "value": "  x  "})
        self.assertEqual(res["result"], "x")

    def test_data_transform_unknown_operation(self):
        res = execute_agent_tool("data_transform", {"operation": "noSuchOp", "value": "x"})
        self.assertEqual(res["status"], "error")

    def test_random_string(self):
        res = execute_agent_tool("random_string", {"length": 24, "charset": "hex"})
        self.assertEqual(res["status"], "success")
        self.assertEqual(len(res["random_string"]), 24)
        self.assertTrue(all(c in "0123456789abcdef" for c in res["random_string"]))

    def test_normalize_http(self):
        raw_input = "POST /api/test HTTP/1.1\\r\\nHost: example.com\\r\\nContent-Type: application/json\\r\\n\\r\\n{\"test\": 1}"
        res = execute_agent_tool("normalize_http", {"raw_http": raw_input})
        self.assertEqual(res["status"], "success")
        normalized = res["normalized"]
        self.assertIn("\r\n\r\n{\"test\": 1}", normalized)
        self.assertIn("Host: example.com\r\n", normalized)

    def test_oob_generate_and_poll(self):
        gen = execute_agent_tool("oob_generate", {"tag": "sqli-test"})
        self.assertEqual(gen["status"], "success")
        self.assertTrue(gen["token"].startswith("rroob_"))
        self.assertIn(gen["token"], gen["http_callback_url"])

        # Poll before any traffic
        poll_empty = execute_agent_tool("oob_poll", {"token": gen["token"]})
        self.assertEqual(poll_empty["status"], "success")
        self.assertEqual(poll_empty["interactions_count"], 0)
        self.assertFalse(poll_empty["triggered"])

        # Simulate incoming interaction
        TrafficRecord.objects.create(
            project=self.project,
            method="GET",
            url=gen["http_callback_url"],
            status_code=200,
            host="127.0.0.1",
            source_ip="192.168.1.50",
        )

        poll_active = execute_agent_tool("oob_poll", {"token": gen["token"]})
        self.assertEqual(poll_active["status"], "success")
        self.assertEqual(poll_active["interactions_count"], 1)
        self.assertTrue(poll_active["triggered"])
        self.assertEqual(poll_active["interactions"][0]["source_ip"], "192.168.1.50")

    def test_extended_tools_availability(self):
        tools = get_available_tools()
        names = [t["function"]["name"] for t in tools]
        self.assertGreaterEqual(len(names), 60)
        expected = [
            "platform_status", "history_get_records", "history_get_transaction_raw",
            "scanner_job_status", "report_ingest", "harness2_status",
            "project_update", "project_delete", "project_export", "project_import",
            "project_fusion_report", "traffic_control", "traffic_capture_contexts",
            "history_manage", "target_job_action", "target_browsers_list",
            "target_js_analyze", "bypass_forms_list", "repeater_burst_status",
            "repeater_last_byte_status", "intruder_attack_action", "intruder_saved_attacks",
            "scanner_active_action", "scanner_corpus_stats", "scanner_corpus_start",
            "scanner_corpus_action", "scanner_report_generate", "osint_recon",
            "osint_graphs", "osint_transform_job", "oast_listener",
            "workflow_catalog", "workflow_manage", "workflow_execute",
            "route_manage", "dns_manage",
        ]
        for name in expected:
            self.assertIn(name, names, f"Expected {name} to be in available tools")

    def test_platform_status_tool(self):
        with patch("lab.views.call_engine_get", return_value=(200, {"status": "ok"})):
            with patch("lab.views.call_browser_worker_get", return_value=(200, {"status": "ok"})):
                res = execute_agent_tool("platform_status", {}, context={"active_project": self.project})
                self.assertEqual(res["status"], "success")
                self.assertTrue(res["ok"])
                self.assertEqual(res["active_project"]["id"], self.project.id)

    def test_history_get_records_and_raw(self):
        rec = TrafficRecord.objects.create(
            project=self.project,
            method="GET",
            url="https://example.com/api/test",
            status_code=200,
            request_body="test_req",
            response_body="test_resp",
            source="repeater",
        )
        res = execute_agent_tool("history_get_records", {"source": "repeater"}, context={"active_project": self.project})
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["total"], 1)
        self.assertEqual(res["items"][0]["id"], rec.id)

        raw_res = execute_agent_tool("history_get_transaction_raw", {"record_id": rec.id})
        self.assertEqual(raw_res["status"], "success")
        self.assertIn("GET https://example.com/api/test HTTP/1.1", raw_res["raw_request"])
        self.assertIn("test_resp", raw_res["raw_response"])

    def test_project_update_and_export(self):
        up_res = execute_agent_tool("project_update", {"project_id": self.project.id, "description": "Updated desc"})
        self.assertEqual(up_res["status"], "success")
        self.project.refresh_from_db()
        self.assertEqual(self.project.notes, "Updated desc")

        exp_res = execute_agent_tool("project_export", {"project_id": self.project.id})
        self.assertEqual(exp_res["status"], "success")
        self.assertIn("bundle", exp_res)

    def test_workflow_catalog_and_manage(self):
        cat_res = execute_agent_tool("workflow_catalog", {"kind": "all"})
        self.assertEqual(cat_res["status"], "success")
        self.assertIn("node_types", cat_res)
        self.assertIn("templates", cat_res)

        manage_res = execute_agent_tool("workflow_manage", {"action": "list"})
        self.assertEqual(manage_res["status"], "success")
        self.assertIn("items", manage_res)

    def test_route_and_dns_manage(self):
        d_get = execute_agent_tool("dns_manage", {"action": "get"})
        self.assertEqual(d_get["status"], "success")
        self.assertIn("dns_config", d_get)

        d_flush = execute_agent_tool("dns_manage", {"action": "flush"})
        self.assertEqual(d_flush["status"], "success")
        self.assertIn("flushed_at", d_flush)

        with patch("lab.views.call_engine_get", return_value=(200, {"address": "direct"})):
            r_get = execute_agent_tool("route_manage", {"action": "get"})
            self.assertEqual(r_get["status"], "success")


