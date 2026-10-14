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
        record = TrafficRecord.objects.filter(source="ai_agent").first()
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

