"""Unit tests for the process-local outbound route barrier."""

from __future__ import annotations

import threading
import unittest

from .outbound_runtime import OutboundOperationCancelled, OutboundRuntime


class OutboundRuntimeTests(unittest.TestCase):
    def test_successful_switch_cancels_old_generation_and_reopens(self):
        runtime = OutboundRuntime()
        callback_called = threading.Event()
        with runtime.operation("repeater", project_id=7) as operation:
            operation.on_cancel(callback_called.set)
            with runtime.route_switch() as switch:
                switch.activate(workflow_runs=[4], browser_jobs=["browser-a"], agent_requests=2)
                self.assertEqual(operation.stale, True)
                self.assertEqual(switch.cancelled_operations, [operation.id])
            self.assertEqual(runtime.snapshot()["generation"], 1)
            self.assertEqual(runtime.snapshot()["switching"], False)
            self.assertEqual(switch.cancelled_workflow_runs, [4])
            self.assertEqual(switch.cancelled_browser_jobs, ["browser-a"])
            self.assertEqual(switch.cancelled_agent_requests, 2)
            with self.assertRaises(OutboundOperationCancelled):
                operation.raise_if_cancelled()
        self.assertTrue(callback_called.is_set())
        with runtime.operation("scanner") as current:
            self.assertEqual(current.generation, 1)
            self.assertFalse(current.stale)

    def test_failed_switch_keeps_generation_and_does_not_cancel(self):
        runtime = OutboundRuntime()
        with runtime.operation("osint") as operation:
            with runtime.route_switch():
                pass
            self.assertFalse(operation.stale)
            self.assertEqual(operation.generation, 0)
        self.assertEqual(runtime.snapshot(), {
            "generation": 0,
            "switching": False,
            "active_operations": 0,
        })

    def test_generation_sync_is_safe_while_idle(self):
        runtime = OutboundRuntime()
        self.assertTrue(runtime.sync_generation(4))
        self.assertEqual(runtime.snapshot()["generation"], 4)
        with runtime.operation("repeater"):
            self.assertFalse(runtime.sync_generation(9))
        self.assertEqual(runtime.snapshot()["generation"], 4)

    def test_new_operation_waits_until_switch_finishes(self):
        runtime = OutboundRuntime()
        entered = threading.Event()
        result = {}

        def worker():
            with runtime.operation("ai") as operation:
                result["generation"] = operation.generation
                entered.set()

        thread = threading.Thread(target=worker)
        with runtime.route_switch() as switch:
            switch.activate()
            thread.start()
            thread.join(timeout=0.2)
            self.assertFalse(entered.is_set())
        thread.join(timeout=1)
        self.assertTrue(entered.is_set())
        self.assertEqual(result["generation"], 1)


if __name__ == "__main__":
    unittest.main()
