#!/usr/bin/env python3
"""
Unit tests for rr_agent_harness.py
"""

import tempfile
import unittest
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

try:
    from rr_agent_harness import AgentHarness, Observation
except ImportError:
    from tools.rr_agent_harness import AgentHarness, Observation


class TestAgentHarness(unittest.TestCase):
    def setUp(self):
        self.harness = AgentHarness()

    def test_observation_contract(self):
        """Перевірка дотримання специфікації Observation за agent-harness-construction."""
        obs = Observation(
            status="error",
            summary="Тест не пройшов",
            details={"code": 1},
            root_cause_hint="Синтаксична помилка",
            safe_retry_instruction="Запустити flake8",
            explicit_stop_condition="Зупинитися при падінні лінтера",
            next_actions=["Виправити файл"],
            artifacts=["file:///tmp/err.log"],
        )
        d = obs.to_dict()
        self.assertEqual(d["status"], "error")
        self.assertEqual(d["summary"], "Тест не пройшов")
        self.assertEqual(d["root_cause_hint"], "Синтаксична помилка")
        self.assertEqual(d["safe_retry_instruction"], "Запустити flake8")
        self.assertEqual(d["explicit_stop_condition"], "Зупинитися при падінні лінтера")
        self.assertIn("Виправити файл", d["next_actions"])
        self.assertIn("file:///tmp/err.log", d["artifacts"])

    @patch("subprocess.run")
    def test_check_scope_compliant(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=" M tools/rr_agent_harness.py\n?? tools/test_rr_agent_harness.py\n",
            returncode=0,
        )
        obs = self.harness.check_scope(
            allowed_files=["tools/rr_agent_harness.py", "tools/test_rr_agent_harness.py"]
        )
        self.assertEqual(obs.status, "success")
        self.assertIn("відповідають дозволеному списку", obs.summary)

    @patch("subprocess.run")
    def test_check_scope_disallowed_detected(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout=" M engine/main.go\n M tools/rr_agent_harness.py\n",
            returncode=0,
        )
        obs = self.harness.check_scope(
            allowed_files=["tools/rr_agent_harness.py"]
        )
        self.assertEqual(obs.status, "error")
        self.assertIn("несанкціонованих змін", obs.summary)
        self.assertIn("engine/main.go", obs.details["disallowed"])
        self.assertIsNotNone(obs.root_cause_hint)
        self.assertIsNotNone(obs.safe_retry_instruction)
        self.assertIsNotNone(obs.explicit_stop_condition)

    def test_verdict_guards(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            rec_dir = tmppath / "engine" / "reconciliation"
            rec_dir.mkdir(parents=True)
            bad_file = rec_dir / "bad_reg.md"
            bad_file.write_text("Рядок 1: улушшено функціонал", encoding="utf-8")

            local_harness = AgentHarness(repo_root=tmppath)
            obs = local_harness.check_verdict_guards()
            self.assertEqual(obs.status, "error")
            self.assertEqual(len(obs.details["findings"]), 1)
            self.assertEqual(obs.details["findings"][0]["typo"], "улушшено")

    def test_verdict_guards_clean_workspace(self):
        """Перевірка реального робочого простору проєкту на відсутність помилкових вердиктів."""
        obs = self.harness.check_verdict_guards()
        self.assertEqual(obs.status, "success", f"Знайдено помилкові вердикти: {obs.details}")

    def test_unknown_suite_error_recovery(self):
        obs = self.harness.run_tests(suite="invalid_suite_xyz")
        self.assertEqual(obs.status, "error")
        self.assertIn("Невідомий тестовий набір", obs.summary)
        self.assertIsNotNone(obs.safe_retry_instruction)


if __name__ == "__main__":
    unittest.main()
