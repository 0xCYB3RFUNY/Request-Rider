"""Unit tests for the Request-Rider Autonomous AI Agent ReAct loop."""

import json
import unittest
from unittest.mock import MagicMock, patch

try:
    from . import agent_loop
    from .agent_loop import run_agent_loop, AgentStep
    from . import views
except ImportError:
    from web.lab import agent_loop
    from web.lab.agent_loop import run_agent_loop, AgentStep
    from web.lab import views


class AgentLoopTestCase(unittest.TestCase):
    @patch.object(agent_loop, "get_agent_provider")
    @patch.object(agent_loop, "execute_agent_tool")
    def test_single_turn_final_answer(self, mock_exec_tool, mock_get_provider):
        mock_provider = MagicMock()
        mock_provider.model = "llama3"
        mock_provider.endpoint = "http://localhost:11434/v1/chat/completions"
        mock_provider.api_key = ""
        mock_get_provider.return_value = mock_provider

        # Mock LLM direct response without tool calls
        mock_provider._request_json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "Аналіз завершено. Вразливостей не виявлено.",
                        "tool_calls": []
                    }
                }
            ]
        }

        result = run_agent_loop("Перевір безпеку", provider="ollama")

        self.assertTrue(result["completed"])
        self.assertEqual(result["total_steps"], 1)
        self.assertIn("Аналіз завершено", result["final_answer"])
        mock_exec_tool.assert_not_called()

    @patch.object(agent_loop, "get_agent_provider")
    @patch.object(agent_loop, "execute_agent_tool")
    def test_react_loop_with_tool_call(self, mock_exec_tool, mock_get_provider):
        mock_provider = MagicMock()
        mock_provider.model = "llama3"
        mock_provider.endpoint = "http://localhost:11434/v1/chat/completions"
        mock_provider.api_key = ""
        mock_get_provider.return_value = mock_provider

        # Mock 1st turn: LLM calls history_search
        # Mock 2nd turn: LLM receives observation and outputs conclusion
        mock_provider._request_json.side_effect = [
            {
                "choices": [
                    {
                        "message": {
                            "content": "Шукаю запити входу в історії...",
                            "tool_calls": [
                                {
                                    "id": "call_123",
                                    "function": {
                                        "name": "history_search",
                                        "arguments": json.dumps({"query": "login"})
                                    }
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "choices": [
                    {
                        "message": {
                            "content": "Знайдено 1 запит /api/login, передаю висновок.",
                            "tool_calls": []
                        }
                    }
                ]
            }
        ]

        # Mock tool execution
        mock_exec_tool.return_value = {
            "status": "success",
            "results": [{"id": 1, "url": "https://target.local/api/login", "method": "POST"}]
        }

        result = run_agent_loop("Знайди ендпоінти логіну", provider="ollama")

        self.assertTrue(result["completed"])
        self.assertEqual(result["total_steps"], 2)
        self.assertIn("Знайдено 1 запит", result["final_answer"])
        self.assertEqual(len(result["steps"]), 2)
        self.assertEqual(result["steps"][0]["tool_name"], "history_search")

    @patch.object(agent_loop, "run_agent_loop")
    def test_agent_run_view_endpoint(self, mock_loop):
        from django.test import RequestFactory
        from lab.views import agent_run

        mock_loop.return_value = {
            "final_answer": "Успішно перевірено",
            "steps": [{"step": 1, "thought": "Тест", "tool_name": "none", "observation": "ok"}],
            "total_steps": 1,
            "completed": True,
        }

        factory = RequestFactory()
        req = factory.post(
            "/api/agent/run",
            data=json.dumps({"prompt": "Тестовий запит"}),
            content_type="application/json",
        )
        # Mock csrf check bypass for unit test
        setattr(req, "_dont_enforce_csrf_checks", True)

        resp = agent_run(req)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertTrue(data["ok"])
        self.assertEqual(data["final_answer"], "Успішно перевірено")
        self.assertEqual(data["total_steps"], 1)

    def test_agent_step_serialization(self):
        step = AgentStep(
            step_number=1,
            thought="Exploring target",
            tool_name="request_send",
            tool_args={"url": "https://example.com"},
            observation={"status": 200}
        )
        data = step.to_dict()
        self.assertEqual(data["step"], 1)
        self.assertEqual(data["thought"], "Exploring target")
        self.assertEqual(data["tool_name"], "request_send")
        self.assertEqual(data["tool_args"]["url"], "https://example.com")
        self.assertEqual(data["observation"]["status"], 200)

    @patch.object(agent_loop, "get_agent_provider")
    @patch.object(agent_loop, "execute_agent_tool")
    def test_react_loop_max_steps_limit(self, mock_exec_tool, mock_get_provider):
        mock_provider = MagicMock()
        mock_provider.model = "llama3"
        mock_provider.endpoint = "http://localhost:11434/v1/chat/completions"
        mock_provider.api_key = ""
        mock_get_provider.return_value = mock_provider

        # Always return a tool call
        mock_provider._request_json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "Running next tool...",
                        "tool_calls": [
                            {
                                "id": "call_loop",
                                "function": {
                                    "name": "history_search",
                                    "arguments": json.dumps({"query": "test"})
                                }
                            }
                        ]
                    }
                }
            ]
        }
        mock_exec_tool.return_value = {"status": "success", "results": []}

        result = run_agent_loop("Нескінченний пошук", provider="ollama", max_steps=3)

        # Loop must stop at max_steps (3)
        self.assertEqual(result["total_steps"], 3)
        self.assertEqual(len(result["steps"]), 3)
        self.assertTrue(result["completed"])
        self.assertEqual(result["final_answer"], "Running next tool...")


if __name__ == "__main__":
    unittest.main()
