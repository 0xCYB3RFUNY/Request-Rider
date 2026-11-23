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


class UntrustedOutputBoundaryTests(unittest.TestCase):
    def test_frame_helper_uses_the_run_nonce(self):
        framed = agent_loop.frame_untrusted_output({"status": "success"}, "abc123")
        self.assertIn('<<<UNTRUSTED_OUTPUT nonce="abc123">>>', framed)
        self.assertIn('<<<END_UNTRUSTED_OUTPUT nonce="abc123">>>', framed)
        self.assertIn('"status": "success"', framed)

    @patch.object(agent_loop, "get_agent_provider")
    @patch.object(agent_loop, "execute_agent_tool")
    def test_tool_results_are_framed_in_model_context(self, mock_exec_tool, mock_get_provider):
        provider = MagicMock()
        provider.model = "llama3"
        provider.endpoint = "http://localhost:11434/v1/chat/completions"
        provider.api_key = ""
        mock_get_provider.return_value = provider
        mock_exec_tool.return_value = {"status": "success", "summary": "ok"}
        provider._request_json.side_effect = [
            {"choices": [{"message": {"content": "run", "tool_calls": [{
                "id": "c1", "function": {"name": "history_search", "arguments": "{}"}
            }]}}]},
            {"choices": [{"message": {"content": "done", "tool_calls": []}}]},
        ]

        result = run_agent_loop("перевір", provider="ollama")

        self.assertEqual(result["steps"][0]["observation"], {"status": "success", "summary": "ok"})
        payloads = [call.args[0] for call in provider._request_json.call_args_list]
        second_messages = json.loads(payloads[1].data.decode())["messages"]
        boundary = [m for m in second_messages if m.get("role") == "tool"]
        self.assertEqual(len(boundary), 1)
        content = boundary[0]["content"]
        self.assertRegex(content, r'<<<UNTRUSTED_OUTPUT nonce="[0-9a-f]{16}">>>')
        self.assertIn("END_UNTRUSTED_OUTPUT", content)
        # The steps returned to the UI keep the structured observation, not the framed string.
        self.assertEqual(mock_exec_tool.call_count, 1)


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

        # Loop must stop at max_steps (3) when the operator sets it explicitly
        self.assertEqual(result["total_steps"], 3)
        self.assertEqual(len(result["steps"]), 3)
        self.assertTrue(result["completed"])
        self.assertEqual(result["final_answer"], "Running next tool...")

    @patch.object(agent_loop, "get_agent_provider")
    @patch.object(agent_loop, "execute_agent_tool")
    def test_react_loop_runs_unbounded_by_default(self, mock_exec_tool, mock_get_provider):
        """The default run passes the old 12-step cap and stops on conclusion."""
        provider = MagicMock()
        provider.model = "llama3"
        provider.endpoint = "http://localhost:11434/v1/chat/completions"
        provider.api_key = ""
        mock_get_provider.return_value = provider

        def tool_turn(step):
            return {"choices": [{"message": {
                "content": f"Крок {step}",
                "tool_calls": [{
                    "id": f"call_{step}",
                    "function": {"name": "history_search", "arguments": "{}"},
                }],
            }}]}

        # 15 autonomous tool steps — more than the old hardcoded cap of 12 —
        # followed by the model's natural final answer with no tool call.
        provider._request_json.side_effect = (
            [tool_turn(index) for index in range(1, 16)]
            + [{"choices": [{"message": {"content": "Фінальна відповідь", "tool_calls": []}}]}]
        )
        mock_exec_tool.return_value = {"status": "success"}

        result = run_agent_loop("Дослідити ціль", provider="ollama")

        self.assertEqual(result["total_steps"], 16)
        self.assertEqual(len(result["steps"]), 16)
        self.assertEqual(result["final_answer"], "Фінальна відповідь")
        self.assertTrue(result["completed"])

    @patch.object(agent_loop, "get_agent_provider")
    @patch.object(agent_loop, "execute_agent_tool")
    def test_explicit_cap_reports_exact_numbers(self, mock_exec_tool, mock_get_provider):
        """An operator cap stays supported and is reported without vague wording."""
        provider = MagicMock()
        provider.model = "llama3"
        provider.endpoint = "http://localhost:11434/v1/chat/completions"
        provider.api_key = ""
        mock_get_provider.return_value = provider
        provider._request_json.return_value = {"choices": [{"message": {
            "content": "",
            "tool_calls": [{
                "id": "call_capped",
                "function": {"name": "history_search", "arguments": "{}"},
            }],
        }}]}
        mock_exec_tool.return_value = {"status": "success"}

        result = run_agent_loop("Нескінченний пошук", provider="ollama", max_steps=3)

        self.assertEqual(result["total_steps"], 3)
        self.assertIn("явно заданого ліміту 3 кроків", result["final_answer"])
        self.assertIn("виконано 3", result["final_answer"])
        self.assertIn("Наступний крок", result["final_answer"])
        self.assertNotIn("Дослідження завершено", result["final_answer"])


class AgentMaxStepsParsingTests(unittest.TestCase):
    def test_missing_and_unlimited_values_mean_no_cap(self):
        for value in (None, 0, "0", "", "   ", "none", "unlimited", "UNLIMITED"):
            with self.subTest(value=value):
                self.assertIsNone(views._parse_agent_max_steps(value))

    def test_positive_cap_has_no_upper_ceiling(self):
        for value in (1, 3, 30, 100000):
            with self.subTest(value=value):
                self.assertEqual(views._parse_agent_max_steps(value), value)
        self.assertEqual(views._parse_agent_max_steps("30"), 30)

    def test_invalid_values_fail_explicitly(self):
        for value in (-1, True, "abc"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    views._parse_agent_max_steps(value)


class AgentToolProfileTests(unittest.TestCase):
    def test_tool_groups_cover_all_registered_tools(self):
        from lab.agent_tools import TOOL_GROUPS, get_available_tools

        all_names = {item["function"]["name"] for item in get_available_tools()}
        grouped_names = {name for names in TOOL_GROUPS.values() for name in names}
        self.assertEqual(all_names - grouped_names, set())

    def test_auto_profile_is_compact_for_ollama_and_full_for_cloud(self):
        from lab.agent_tools import get_available_tools, select_tools_for_run

        full_count = len(get_available_tools())
        ollama_tools, ollama_meta = select_tools_for_run(
            provider="ollama",
            user_prompt="Декодуй рядок base64",
        )
        cloud_tools, cloud_meta = select_tools_for_run(
            provider="gemini",
            user_prompt="Декодуй рядок base64",
        )

        ollama_names = {t["function"]["name"] for t in ollama_tools}
        self.assertEqual(ollama_meta["tool_profile"], "compact")
        self.assertTrue(ollama_meta["dynamic_loader"])
        self.assertIn("base64_decode", ollama_names)
        self.assertIn("tools_load", ollama_names)
        self.assertLess(len(ollama_tools), 25)

        self.assertEqual(cloud_meta["tool_profile"], "full")
        self.assertFalse(cloud_meta["dynamic_loader"])
        self.assertEqual(len(cloud_tools), full_count)

    def test_compact_profile_adds_keyword_matched_group_and_respects_browser_consent(self):
        from lab.agent_tools import select_tools_for_run

        tools_no_browser, meta_no_browser = select_tools_for_run(
            provider="ollama",
            user_prompt="Проведи osint розвідку та відкрий browser для screenshot",
            allow_browser_tools=False,
        )
        names_no_browser = {t["function"]["name"] for t in tools_no_browser}
        self.assertIn("osint", meta_no_browser["categories"])
        self.assertIn("osint_recon", names_no_browser)
        self.assertNotIn("browser_open", names_no_browser)

        tools_with_browser, meta_with_browser = select_tools_for_run(
            provider="ollama",
            user_prompt="Відкрий browser для screenshot",
            allow_browser_tools=True,
        )
        names_with_browser = {t["function"]["name"] for t in tools_with_browser}
        self.assertIn("browser", meta_with_browser["categories"])
        self.assertIn("browser_open", names_with_browser)

    def test_explicit_full_and_env_override_and_invalid_profile(self):
        import os
        from lab.agent_tools import get_available_tools, select_tools_for_run

        full_count = len(get_available_tools())
        tools_full, meta_full = select_tools_for_run(
            provider="ollama",
            user_prompt="test",
            tool_profile="full",
        )
        self.assertEqual(meta_full["tool_profile"], "full")
        self.assertEqual(len(tools_full), full_count)

        with patch.dict(os.environ, {"RR_AGENT_TOOL_PROFILE": "full"}):
            tools_env, meta_env = select_tools_for_run(provider="ollama", user_prompt="test")
            self.assertEqual(meta_env["tool_profile"], "full")
            self.assertEqual(len(tools_env), full_count)

        with self.assertRaises(ValueError):
            select_tools_for_run(provider="ollama", user_prompt="test", tool_profile="nonexistent_group")

    @patch.object(agent_loop, "get_agent_provider")
    @patch.object(agent_loop, "execute_agent_tool")
    def test_dynamic_tools_load_expands_schemas_mid_loop(self, mock_exec_tool, mock_get_provider):
        provider = MagicMock()
        provider.model = "qwen2.5:3b"
        provider.endpoint = "http://127.0.0.1:11434/v1/chat/completions"
        provider.api_key = ""
        mock_get_provider.return_value = provider

        provider._request_json.side_effect = [
            {
                "choices": [
                    {
                        "message": {
                            "content": "Підвантажую OSINT-інструменти...",
                            "tool_calls": [
                                {
                                    "id": "call_load",
                                    "function": {
                                        "name": "tools_load",
                                        "arguments": json.dumps({"categories": ["osint"]}),
                                    },
                                }
                            ],
                        }
                    }
                ]
            },
            {
                "choices": [
                    {
                        "message": {
                            "content": "Викликаю osint_recon...",
                            "tool_calls": [
                                {
                                    "id": "call_osint",
                                    "function": {
                                        "name": "osint_recon",
                                        "arguments": json.dumps({"domain": "example.local"}),
                                    },
                                }
                            ],
                        }
                    }
                ]
            },
            {
                "choices": [
                    {
                        "message": {
                            "content": "Готово.",
                            "tool_calls": [],
                        }
                    }
                ]
            },
        ]
        mock_exec_tool.return_value = {"status": "success", "hosts": ["example.local"]}

        result = run_agent_loop("Перевір домен example.local", provider="ollama")

        self.assertTrue(result["completed"])
        self.assertEqual(result["tool_profile"], "compact")
        payloads = [json.loads(call.args[0].data.decode()) for call in provider._request_json.call_args_list]
        turn1_tool_names = {t["function"]["name"] for t in payloads[0]["tools"]}
        turn2_tool_names = {t["function"]["name"] for t in payloads[1]["tools"]}
        self.assertNotIn("osint_recon", turn1_tool_names)
        self.assertIn("tools_load", turn1_tool_names)
        self.assertIn("osint_recon", turn2_tool_names)
        self.assertGreater(len(turn2_tool_names), len(turn1_tool_names))
        mock_exec_tool.assert_called_once_with("osint_recon", {"domain": "example.local"}, context=unittest.mock.ANY)

    @patch.object(agent_loop, "run_agent_loop")
    def test_agent_run_view_passes_tool_profile(self, mock_loop):
        from django.test import RequestFactory
        from lab.views import agent_run

        mock_loop.return_value = {
            "final_answer": "OK",
            "steps": [],
            "total_steps": 1,
            "completed": True,
            "tool_profile": "compact",
            "active_tools_count": 15,
        }
        factory = RequestFactory()
        req = factory.post(
            "/api/agent/run",
            data=json.dumps({"prompt": "Тест", "provider": "ollama", "tool_profile": "compact"}),
            content_type="application/json",
        )
        setattr(req, "_dont_enforce_csrf_checks", True)

        resp = agent_run(req)
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertEqual(data["tool_profile"], "compact")
        self.assertEqual(data["active_tools_count"], 15)
        self.assertEqual(mock_loop.call_args.kwargs.get("tool_profile"), "compact")


if __name__ == "__main__":
    unittest.main()
