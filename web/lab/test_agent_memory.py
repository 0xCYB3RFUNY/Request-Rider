"""Tests for durable project-scoped agent memory and the usage ledger."""

import json
import unittest
from datetime import date
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.test import TestCase

from . import agent_loop
from . import agent_memory
from .agent_tools import execute_agent_tool, get_available_tools
from .models import AgentMemoryAtom, AgentRunUsage, Project


class MemoryHelpersTests(unittest.TestCase):
    def test_scope_for_project_and_global(self):
        self.assertEqual(agent_memory.scope_for_project(None), "global")
        project = MagicMock()
        project.id = 42
        self.assertEqual(agent_memory.scope_for_project(project), "project:42")

    def test_normalize_key_is_stable_and_bounded(self):
        first = agent_memory.normalize_key("  PHP   Type Juggling  ")
        second = agent_memory.normalize_key("php type juggling")
        self.assertEqual(first, "php type juggling")
        self.assertEqual(first, second)
        long_key = agent_memory.normalize_key("x" * 500)
        self.assertLessEqual(len(long_key), 180)
        self.assertIn("#", long_key)

    def test_sensitive_filter_flags_without_altering_value(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"
        self.assertTrue(agent_memory.detect_sensitive(jwt))
        self.assertFalse(agent_memory.detect_sensitive("endpoint /api/v1/users returns 200"))
        stored = agent_memory.remember(
            key="token observation",
            value=jwt,
            citation="test:step:1",
            source_session="s1",
        )
        # AGENTS.md §5.6: the whole secret value is preserved, not masked.
        self.assertEqual(stored["value"], jwt)
        self.assertTrue(stored["redacted"])

    def test_format_memory_context_tags_contested_and_sensitive(self):
        text = agent_memory.format_memory_context(
            [
                {
                    "tier": "L2",
                    "scope_key": "fact",
                    "value": "value",
                    "source_citation": "test:1",
                    "contested": True,
                    "redacted": False,
                }
            ]
        )
        self.assertIn("[L2]", text)
        self.assertIn("CONTESTED", text)
        self.assertIn("test:1", text)


class MemoryPersistenceTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(name="agent-memory-tests")

    def test_repeated_sessions_increase_recurrence_without_overwriting(self):
        agent_memory.remember(
            project=self.project,
            key="stack",
            value="nginx",
            citation="run:1:step:1",
            source_session="s1",
        )
        second = agent_memory.remember(
            project=self.project,
            key="stack",
            value="nginx",
            citation="run:2:step:1",
            source_session="s2",
        )
        third = agent_memory.remember(
            project=self.project,
            key="stack",
            value="nginx",
            citation="run:3:step:1",
            source_session="s3",
        )
        self.assertEqual(third["occurrences"], 3)
        self.assertEqual(third["distinct_sessions"], 3)
        self.assertEqual(third["value"], "nginx")
        self.assertEqual(second["distinct_sessions"], 2)

    def test_conflicting_claim_is_contested_and_incumbent_survives(self):
        agent_memory.remember(
            project=self.project, key="framework", value="Django", citation="r1", source_session="s1"
        )
        updated = agent_memory.remember(
            project=self.project, key="framework", value="Flask", citation="r2", source_session="s2"
        )
        atom = AgentMemoryAtom.objects.get(scope=f"project:{self.project.id}", scope_key="framework")
        self.assertTrue(updated["contested"])
        self.assertEqual(atom.value, "Django")
        self.assertIn("Flask", atom.contested_note)

    def test_recall_injects_l2_always_and_l1_only_on_relevance(self):
        agent_memory.remember(
            project=self.project, key="always fact", value="project uses TLS", citation="r1", source_session="s1"
        )
        atom = AgentMemoryAtom.objects.get(scope_key="always fact")
        atom.tier = "L2"
        atom.save(update_fields=["tier"])
        agent_memory.remember(
            project=self.project, key="sqli payload", value="UNION SELECT", citation="r2", source_session="s2"
        )
        unrelated = agent_memory.recall(project=self.project, query="nothing matching")
        self.assertEqual([item["scope_key"] for item in unrelated], ["always fact"])
        relevant = agent_memory.recall(project=self.project, query="sqli")
        keys = [item["scope_key"] for item in relevant]
        self.assertIn("always fact", keys)
        self.assertIn("sqli payload", keys)

    def test_proposals_are_never_applied_without_explicit_adoption(self):
        agent_memory.remember(
            project=self.project, key="verified fact", value="port 443 open", citation="r1",
            source_session="s1", verified=True,
        )
        proposals = agent_memory.propose_promotions(project=self.project)
        self.assertEqual(len(proposals), 1)
        atom = AgentMemoryAtom.objects.get(scope_key="verified fact")
        self.assertEqual(atom.tier, "L1")
        self.assertEqual(atom.proposed_tier, "L2")

        with self.assertRaises(ValueError):
            agent_memory.adopt_promotion(atom_id=atom.id, operator="")
        promoted = agent_memory.adopt_promotion(atom_id=atom.id, operator="operator-a")
        self.assertEqual(promoted["tier"], "L2")
        atom.refresh_from_db()
        self.assertEqual(atom.tier, "L2")
        self.assertEqual(atom.proposed_tier, "")
        self.assertIn("adopted-by:operator-a", atom.source_citation)

    def test_redacted_and_contested_never_promote(self):
        agent_memory.remember(
            project=self.project, key="secret", value="sk-abcdefghijklmnopqrstuvwxyz",
            citation="r1", source_session="s1", verified=True,
        )
        agent_memory.remember(
            project=self.project, key="debated", value="A", citation="r2", source_session="s2"
        )
        agent_memory.remember(
            project=self.project, key="debated", value="B", citation="r3", source_session="s3"
        )
        proposals = agent_memory.propose_promotions(project=self.project)
        self.assertEqual(proposals, [])

    def test_forget_removes_only_active_scope(self):
        agent_memory.remember(project=self.project, key="temp", value="x", citation="r1")
        self.assertTrue(agent_memory.forget(project=self.project, key="temp"))
        self.assertFalse(AgentMemoryAtom.objects.filter(scope_key="temp").exists())

    def test_usage_ledger_records_tokens_and_visible_cost(self):
        row = agent_memory.record_usage(
            run_id="run-1",
            project=self.project,
            provider="ollama",
            model="llama3",
            prompt_tokens=1_000_000,
            completion_tokens=500_000,
            steps=3,
            completed=True,
            input_rate_per_million=Decimal("2"),
            output_rate_per_million=Decimal("4"),
        )
        self.assertEqual(row["total_tokens"], 1_500_000)
        self.assertEqual(Decimal(row["estimated_cost_usd"]), Decimal("4.000000"))
        self.assertEqual(AgentRunUsage.objects.count(), 1)
        again = agent_memory.record_usage(
            run_id="run-1", project=self.project, prompt_tokens=10, completed=True
        )
        self.assertEqual(again["prompt_tokens"], 10)
        self.assertEqual(AgentRunUsage.objects.count(), 1)

    def test_continuity_tools_are_registered_once(self):
        names = {item["function"]["name"] for item in get_available_tools()}
        for expected in (
            "memory_remember", "memory_recall", "memory_propose_promotions",
            "memory_adopt_promotion", "memory_forget",
            "find_verify_start", "find_verify_attack", "find_verify_conclude",
        ):
            self.assertIn(expected, names)
        result = execute_agent_tool("memory_remember", {"key": "via tool", "value": "works"}, context={"active_project": self.project})
        self.assertEqual(result["status"], "success")
        self.assertEqual(len([item for item in get_available_tools() if item["function"]["name"] == "memory_remember"]), 1)


class AgentLoopUsageTests(unittest.TestCase):
    @patch.object(agent_loop, "record_usage")
    @patch.object(agent_loop, "get_agent_provider")
    @patch.object(agent_loop, "execute_agent_tool")
    def test_provider_usage_is_accounted_in_ledger(self, _mock_exec, mock_get_provider, mock_record):
        provider = MagicMock()
        provider.model = "llama3"
        provider.endpoint = "http://127.0.0.1:11434/v1/chat/completions"
        provider.api_key = ""
        mock_get_provider.return_value = provider
        provider._request_json.return_value = {
            "choices": [{"message": {"content": "done", "tool_calls": []}}],
            "usage": {"prompt_tokens": 120, "completion_tokens": 30},
        }
        result = agent_loop.run_agent_loop("перевірка")
        self.assertEqual(result["usage"], mock_record.return_value)
        kwargs = mock_record.call_args.kwargs
        self.assertEqual(kwargs["prompt_tokens"], 120)
        self.assertEqual(kwargs["completion_tokens"], 30)
        self.assertTrue(kwargs["completed"])
        self.assertTrue(result["session_id"])
