"""Регресія: призупинений вузол не скасовує власну задачу.

`dispatch_workflow_engine_task` реєструє `cancel_if_active` і через
`control.add_cleanup`, і через `operation.on_cancel`. Cleanup виконується у
`finally` рану — **в тому числі** коли вузол щойно відклався (`waiting`).
Тому звичайний cleanup скасовував задачу, на якій рана чекала: `target.crawl`
закінчувався `cancelled`, споживач відновлював граф,
`_terminal_task_result` кидав `engine task was cancelled`, і рана падала з
`failed`.

Виміряно на живому стенді: два однакові workflow, один без проєкту
(`target.crawl` → `completed`) і один із проєктом (`target.crawl` →
`cancelled`, рана `failed: engine task was cancelled`). Різниця — час виконання:
з проєктом crawl іде через проксі і встигає ще триматися, коли cleanup
відпрацьовує. Тому дефект і виглядав як флейк, а не як поломка.

Тест відтворює саме цю умову: задача ще не завершена, коли cleanup біжить.
Другий тест стоїть на тому ж місці з протилежного боку — скасування, яке
оператор справді замовив, мусить працювати, іначе «захист» від паркування
просто вимкнув би керування.
"""

import threading
from contextlib import contextmanager
from unittest.mock import patch

from django.test import TestCase

from .engine_broker import EngineTaskDeferred
from .models import EngineTask, Workflow, WorkflowRun


class RecordingControl:
    """The part of `RunControl` that decides *when* a cleanup may run.

    Mirrors the real object on purpose: callbacks are collected and then run by
    `run_cleanup`, which is what the run loop's `finally` does.
    """

    def __init__(self):
        self.cancel = threading.Event()
        self._callbacks = []
        self._cleaned = False

    def add_cleanup(self, callback):
        if not self._cleaned:
            self._callbacks.append(callback)
            return
        callback()

    def run_cleanup(self):
        if self._cleaned:
            return
        self._cleaned = True
        for callback in self._callbacks:
            callback()


class ParkedRunKeepsItsExternalTaskTests(TestCase):
    @contextmanager
    def dispatched_target(self, run, control):
        """Dispatch a `target` node, yielding the `cancel_engine_task` mock.

        The patch has to span the whole scenario, not just the dispatch: the
        cleanup that decides whether to cancel runs *after* the node deferred,
        so a patch scoped to the dispatch would let the real canceller through
        and the mock would never see the call.
        """
        from . import views

        with patch("lab.engine_broker.WORKFLOW_ENGINE_BROKER_ENABLED", True), \
                patch("lab.engine_broker._enqueue_publish"), \
                patch("lab.engine_broker.cancel_engine_task") as cancel:
            with self.assertRaises(EngineTaskDeferred):
                views._workflow_tool_runner(
                    "target",
                    {"url": "http://127.0.0.1/fixture"},
                    {
                        "run": run,
                        "workflow": run.workflow,
                        "node": {"id": "target-1"},
                        "input": {},
                        "control": control,
                    },
                )
            yield cancel

    def test_parking_a_node_does_not_cancel_the_task_it_waits_for(self):
        workflow = Workflow.objects.create(name="Parked keeps task")
        run = WorkflowRun.objects.create(workflow=workflow, status="running")
        control = RecordingControl()

        with self.dispatched_target(run, control) as cancel:
            task = EngineTask.objects.get(workflow_run=run)
            # `_enqueue_publish` is stubbed, so the task stays in its initial
            # state; what matters here is that it is still open, not terminal.
            self.assertNotIn(task.status, {"completed", "failed", "cancelled"})

            # What the run loop does on the way out of a deferred node.
            WorkflowRun.objects.filter(pk=run.pk).update(status="waiting")
            control.run_cleanup()

            self.assertEqual(
                WorkflowRun.objects.get(pk=run.pk).status,
                "waiting",
                "the run must stay parked on the external action",
            )
            cancel.assert_not_called()
            task.refresh_from_db()
            self.assertNotEqual(
                task.status,
                "cancelled",
                "parking a node must not cancel the task the run is waiting for",
            )

    def test_a_cancelled_run_still_cancels_its_external_task(self):
        workflow = Workflow.objects.create(name="Cancel still cancels")
        run = WorkflowRun.objects.create(workflow=workflow, status="running")
        control = RecordingControl()

        with self.dispatched_target(run, control) as cancel:
            # An operator-initiated cancel arrives while the run is still
            # `running`.
            control.cancel.set()
            control.run_cleanup()

            # One publish, addressed at the task this run started - the guard
            # added for parking must not silence a cancellation the operator
            # asked for.
            cancel.assert_called_once()
            self.assertEqual(
                cancel.call_args.args[0].pk,
                EngineTask.objects.get(workflow_run=run).pk,
            )

    def test_parking_a_run_keeps_its_oast_listener(self):
        """A parked run still needs the listener it started.

        The `OAST Listener` node registers a cleanup that deletes the engine-side
        listener. The run loop's `finally` runs cleanups on the way out of a park
        too, so the listener was deleted while the run was waiting for it: on
        resume `OAST Collect` polled a listener the engine reported as cancelled,
        the node failed with an empty error and the run ended `cancelled`.

        Same rule as `test_parking_a_node_does_not_cancel_the_task_it_waits_for`,
        applied to the second kind of resource a parked run owns.
        """
        from . import views

        workflow = Workflow.objects.create(name="Parked keeps listener")
        run = WorkflowRun.objects.create(workflow=workflow, status="running")
        control = RecordingControl()

        with patch("lab.views.call_engine",
                   return_value=(200, {"listener_id": "L1", "payload_url": "http://127.0.0.1:1/hit"})) as call, \
                patch("lab.views.call_engine_delete") as drop:
            views._workflow_tool_runner(
                "oast_listener",
                {"server_url": "http://127.0.0.1:1"},
                {
                    "run": run,
                    "workflow": workflow,
                    "node": {"id": "oast-1"},
                    "input": {},
                    "control": control,
                },
            )
            self.assertEqual(call.call_count, 1)

            # What the run loop does on the way out of a deferred node.
            WorkflowRun.objects.filter(pk=run.pk).update(status="waiting")
            control.run_cleanup()

            drop.assert_not_called()
            self.assertEqual(
                WorkflowRun.objects.get(pk=run.pk).status,
                "waiting",
                "the run must stay parked on its own listener",
            )

    def test_abandoning_a_run_still_drops_its_oast_listener(self):
        from . import views

        workflow = Workflow.objects.create(name="Abandon drops listener")
        run = WorkflowRun.objects.create(workflow=workflow, status="running")
        control = RecordingControl()

        with patch("lab.views.call_engine",
                   return_value=(200, {"listener_id": "L1", "payload_url": "http://127.0.0.1:1/hit"})), \
                patch("lab.views.call_engine_delete") as drop:
            views._workflow_tool_runner(
                "oast_listener",
                {"server_url": "http://127.0.0.1:1"},
                {
                    "run": run,
                    "workflow": workflow,
                    "node": {"id": "oast-1"},
                    "input": {},
                    "control": control,
                },
            )
            # The run is abandoned, not parked: cleanup must still release the
            # listener, otherwise a cancelled run leaks one per attempt.
            control.cancel.set()
            control.run_cleanup()

            drop.assert_called_once_with("/proxy/oast/L1")
