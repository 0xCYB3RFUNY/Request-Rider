"""Tests for the parallel specialist swarm and its shared intent board."""

import json
import threading
from unittest.mock import patch

from django.db import connections
from django.test import TestCase, TransactionTestCase

from . import agent_swarm
from .models import AgentRunUsage, Project, WorkflowNodeExecution, WorkflowRun


# Swarm workers are real threads with their own DB connections. Django's
# TestCase wraps a test in an uncommitted transaction that those connections
# cannot see, so thread-using tests must be TransactionTestCase.
class SwarmBoardTests(TransactionTestCase):
    def setUp(self):
        self.project = Project.objects.create(name="swarm-board-tests")

    def test_board_creates_persisted_intents_and_claims_atomically(self):
        board = agent_swarm.SwarmBoard.create(
            project=self.project,
            goal="probe the API",
            intents=["enumerate endpoints", "test auth", "verify findings"],
        )
        self.assertEqual(board.summary()["total"], 3)
        first = board.claim("worker#1")
        second = board.claim("worker#2")
        third = board.claim("worker#3")
        self.assertEqual([first["node_id"], second["node_id"], third["node_id"]],
                         ["intent_0", "intent_1", "intent_2"])
        self.assertIsNone(board.claim("worker#4"))

        board.complete(first["node_id"], {"answer": "10 endpoints"}, {"worker": "worker#1"})
        summary = board.summary()
        self.assertEqual(summary["completed"], 1)
        self.assertEqual(summary["running"], 2)
        run = WorkflowRun.objects.get(id=board.run_id)
        self.assertEqual(run.status, "running")
        self.assertIn("intent::intent_0", run.shared_data)

        board.complete(second["node_id"], {"answer": "auth bypass"}, {})
        board.complete(third["node_id"], {"answer": "confirmed"}, {})
        self.assertEqual(board.summary()["completed"], 3)
        run.refresh_from_db()
        self.assertEqual(run.status, "completed")

    def test_concurrent_claims_never_duplicate_an_intent(self):
        board = agent_swarm.SwarmBoard.create(
            project=self.project, goal="parallel", intents=[f"intent {index}" for index in range(8)]
        )
        claimed = []
        lock = threading.Lock()

        def claim_once():
            # A lost atomic claim is a retry, not a reason for this thread to
            # exit — the production worker loops on the same signal.
            try:
                while True:
                    result = board.claim("thread")
                    if not result:
                        return
                    if result.get("retry"):
                        continue
                    with lock:
                        claimed.append(result["node_id"])
                    return
            finally:
                connections.close_all()

        threads = [threading.Thread(target=claim_once) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(claimed), 8)
        self.assertEqual(len(set(claimed)), 8)
        self.assertEqual(WorkflowNodeExecution.objects.filter(status="running").count(), 8)


class SwarmExecutionTests(TransactionTestCase):
    def setUp(self):
        self.project = Project.objects.create(name="swarm-run-tests")

    def test_all_intents_are_executed_and_errors_are_visible(self):
        answers = iter(["recon answer", "analysis answer", "verify answer"])

        def fake_loop(user_prompt, **kwargs):
            answer = next(answers)
            return {
                "final_answer": answer,
                "steps": [{"step": 1, "thought": answer, "tool_name": "none", "observation": "Completed"}],
                "total_steps": 1,
                "completed": True,
                "usage": {"total_tokens": 10, "estimated_cost_usd": "0.000100"},
                "session_id": "fake-session",
            }

        with patch.object(agent_swarm, "run_agent_loop", side_effect=fake_loop):
            result = agent_swarm.run_agent_swarm(
                "дослідити API",
                project=self.project,
                intents=["recon", "analysis", "verify"],
                workers=3,
            )

        self.assertTrue(result["ok"], result["errors"])
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["summary"]["completed"], 3)
        self.assertEqual(len(result["intents"]), 3)
        for expected in ("recon answer", "analysis answer", "verify answer"):
            self.assertIn(expected, result["final_answer"])
        self.assertEqual(AgentRunUsage.objects.count(), 1)
        self.assertEqual(result["usage"]["steps"], 3)

    def test_worker_failure_is_reported_not_hidden(self):
        def failing_loop(user_prompt, **kwargs):
            raise RuntimeError("provider exploded")

        with patch.object(agent_swarm, "run_agent_loop", side_effect=failing_loop):
            result = agent_swarm.run_agent_swarm(
                "дослідити", project=self.project, intents=["one"], workers=1
            )

        self.assertFalse(result["ok"])
        self.assertEqual(len(result["errors"]), 1)
        self.assertIn("RuntimeError", result["errors"][0]["error"])
        self.assertEqual(result["summary"]["completed"], 0)

    def test_cancelled_swarm_leaves_intents_pending_and_reports_it(self):
        event = threading.Event()
        event.set()
        with patch.object(agent_swarm, "run_agent_loop") as mock_loop:
            result = agent_swarm.run_agent_swarm(
                "дослідити", project=self.project, intents=["one", "two"],
                workers=2, cancel_event=event,
            )
        mock_loop.assert_not_called()
        self.assertEqual(result["summary"]["pending"], 2)
        self.assertFalse(result["usage"]["completed"])


class SwarmApiTests(TestCase):
    def test_swarm_endpoint_uses_project_and_returns_board_summary(self):
        captured = {}

        def fake_swarm(prompt, **kwargs):
            captured.update(kwargs)
            return {
                "ok": True,
                "plan_id": 77,
                "workers": kwargs.get("workers"),
                "roles": ["recon"],
                "summary": {"total": 1, "completed": 1, "pending": 0, "running": 0},
                "intents": [],
                "final_answer": "done",
                "errors": [],
                "usage": {"total_tokens": 1, "estimated_cost_usd": "0"},
            }

        # views.py imports run_agent_swarm inside the function, so the patch
        # must target the defining module, not the caller's namespace.
        with patch("lab.agent_swarm.run_agent_swarm", side_effect=fake_swarm):
            response = self.client.post(
                "/api/agent/swarm",
                data=json.dumps({
                    "prompt": "перевір",
                    "intents": ["one intent"],
                    "workers": 1,
                    "provider": "ollama",
                }),
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["final_answer"], "done")
        self.assertEqual(captured["workers"], 1)
        self.assertFalse(captured["context"]["allow_browser_tools"])
