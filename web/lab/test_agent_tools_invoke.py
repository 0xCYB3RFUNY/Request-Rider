"""Tests for the single gateway endpoint that exposes agent tools to MCP."""

import unittest
from unittest import mock

from django.test import TestCase
from django.test import Client as DjangoClient

from . import agent_tools


class AgentToolsInvokeTests(TestCase):
    def setUp(self):
        self.client = DjangoClient()

    def test_invoke_known_tool_returns_result(self):
        with mock.patch.dict(agent_tools.TOOL_HANDLERS,
                             {"browser_coverage": lambda args, context=None: {"status": "success", "endpoints": 3}}):
            response = self.client.post(
                "/api/agent/tools/invoke",
                data={"name": "browser_coverage", "arguments": {}},
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["result"]["endpoints"], 3)

    def test_invoke_unknown_tool_is_rejected(self):
        response = self.client.post(
            "/api/agent/tools/invoke",
            data={"name": "drop_database", "arguments": {}},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["reason"], "UNKNOWN_TOOL")

    def test_invoke_passes_explicit_consent_only(self):
        captured = {}

        def handler(args, context=None):
            captured.update(context or {})
            return {"status": "success"}

        with mock.patch.dict(agent_tools.TOOL_HANDLERS, {"browser_open": handler}):
            self.client.post(
                "/api/agent/tools/invoke",
                data={"name": "browser_open", "arguments": {"url": "http://x"}, "allow_browser_tools": True},
                content_type="application/json",
            )
        self.assertTrue(captured["allow_browser_tools"])

        with mock.patch.dict(agent_tools.TOOL_HANDLERS, {"browser_open": handler}):
            self.client.post(
                "/api/agent/tools/invoke",
                data={"name": "browser_open", "arguments": {"url": "http://x"}},
                content_type="application/json",
            )
        self.assertFalse(captured["allow_browser_tools"])

    def test_invoke_requires_post(self):
        self.assertEqual(self.client.get("/api/agent/tools/invoke").status_code, 405)

    def test_invoke_rejects_non_object_arguments(self):
        response = self.client.post(
            "/api/agent/tools/invoke",
            data={"name": "browser_coverage", "arguments": "not-an-object"},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["reason"], "TOOL_INVOCATION_FAILED")


if __name__ == "__main__":
    unittest.main()
