import json
from datetime import datetime, timezone
from threading import Event
from unittest.mock import MagicMock, patch
from uuid import uuid4

from django.db import DatabaseError
from django.test import TestCase

from .engine_broker import (
    EngineTaskCancelled,
    EngineTaskDeferred,
    apply_engine_result_to_workflow,
    create_engine_task,
    dispatch_workflow_engine_task,
    persist_engine_result,
)
from .engine_task_contract import EngineTaskContractError
from .broker_auth import sign_envelope
from .broker_transport import BrokerTransportError
from .management.commands.consume_engine_results import Command as ConsumeEngineResults
from .models import (
    EngineTask,
    EngineTaskEvent,
    TargetJob,
    Workflow,
    WorkflowNodeExecution,
    WorkflowRun,
)
from .tasks import publish_engine_task


def result_event(task, state, *, event_id=None, **fields):
    """One result envelope, signed the way the engine signs it.

    The signature is not decoration here. `publish_engine_task` signs every task
    it hands to the broker (`create_engine_task` → `sign_envelope`), and
    `persist_engine_result` refuses an envelope that arrives without a valid one
    whenever an installation has a key — which `start.sh` generates for every
    stand and exports into `./start.sh --check`. A fixture that built an unsigned
    envelope therefore passed only in compatibility mode, and 17 of these tests
    went red the moment the key existed: the documented check was measuring a
    configuration no installation has.

    `sign_envelope` returns the envelope unchanged when no key is configured, so
    the same fixture is honest in both modes instead of being green in one and
    red in the other.
    """
    return sign_envelope(
        {
            "schema_version": 1,
            "task_id": str(task.task_id),
            "event_id": str(event_id or uuid4()),
            "state": state,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            **fields,
        }
    )


class EngineBrokerPersistenceTests(TestCase):
    def test_a_suspended_node_keeps_its_own_exception_type(self):
        """A deferred task must arrive as deferred, not as a validation error.

        `EngineTaskDeferred` is a subclass of `EngineTaskDispatchError`, so a
        broad `except EngineTaskDispatchError` around the dispatch also catches
        the suspension signal and re-raises it as `WorkflowValidationError`. The
        run loop cannot tell those apart - it parks a deferred node in
        `waiting` and rejects a validation error - so the run ended `failed`
        carrying the deferred message, which is what the E2E suite reported as
        "engine task ... is running outside the graph worker".

        The assertion is on the *type*, not the message: the message survives
        the conversion, so only the type distinguishes the two outcomes.
        """
        from . import views
        from .workflow_engine import WorkflowValidationError

        workflow = Workflow.objects.create(name="Broker Suspend")
        run = WorkflowRun.objects.create(workflow=workflow, status="running")
        context = {
            "run": run,
            "workflow": workflow,
            "node": {"id": "target-1"},
            "input": {},
        }
        deferred = EngineTaskDeferred(uuid4(), "target-1")

        with patch("lab.engine_broker.WORKFLOW_ENGINE_BROKER_ENABLED", True):
            with patch(
                "lab.engine_broker.dispatch_workflow_engine_task",
                side_effect=deferred,
            ):
                with self.assertRaises(EngineTaskDeferred):
                    views._workflow_tool_runner(
                        "target",
                        {"url": "http://127.0.0.1/fixture"},
                        context,
                    )
        # The conversion is what broke the run, so the complementary assertion
        # is named explicitly: if the narrow handler is ever dropped again, this
        # is the line that turns red.
        self.assertFalse(
            issubclass(EngineTaskDeferred, WorkflowValidationError),
            "a deferred task must not masquerade as a validation error",
        )

    def test_repeater_workflow_node_uses_broker_when_enabled(self):
        from . import views

        workflow = Workflow.objects.create(name="Broker Repeater")
        run = WorkflowRun.objects.create(workflow=workflow, status="running")
        context = {
            "run": run,
            "workflow": workflow,
            "node": {"id": "repeater-1"},
            "input": {},
        }
        result_payload = {
            "status": 200,
            "headers": {},
            "body": "fixture",
            "size": 7,
        }

        with patch("lab.engine_broker.WORKFLOW_ENGINE_BROKER_ENABLED", True):
            with patch(
                "lab.engine_broker.dispatch_workflow_engine_task",
                return_value=result_payload,
            ) as dispatch:
                result = views._workflow_tool_runner(
                    "repeater",
                    {"method": "GET", "url": "http://127.0.0.1/fixture"},
                    context,
                )

        self.assertEqual(result["response"], result_payload)
        dispatch.assert_called_once_with(
            "request.execute",
            {
                "method": "GET",
                "url": "http://127.0.0.1/fixture",
                "headers": {},
                "body": "",
            },
            context,
            task_id="",
        )

    def test_static_target_workflow_node_uses_broker_when_enabled(self):
        from . import views

        workflow = Workflow.objects.create(name="Broker Target")
        run = WorkflowRun.objects.create(workflow=workflow, status="running")
        context = {
            "run": run,
            "workflow": workflow,
            "node": {"id": "target-1"},
            "input": {},
        }
        result_payload = {
            "map_id": 91,
            "status": "completed",
            "pages": [{"url": "http://127.0.0.1/fixture"}],
        }

        with patch("lab.engine_broker.WORKFLOW_ENGINE_BROKER_ENABLED", True):
            with patch(
                "lab.engine_broker.dispatch_workflow_engine_task",
                return_value=result_payload,
            ) as dispatch:
                result = views._workflow_tool_runner(
                    "target",
                    {"url": "http://127.0.0.1/fixture"},
                    context,
                )

        self.assertEqual(result, result_payload)
        # retry_attempts travels even at its default of 0: the static crawler
        # now honours Retry-After, and a node that does not name the count must
        # still state it rather than leave the field to a default nobody wrote
        # down. accept_language is absent instead, because identity is never
        # invented — no key means no header.
        #
        # bypass_forms is the opposite case and travels even when empty. It is a
        # selection, and an absent key would be a fourth way of saying "off" —
        # absent, empty, unknown-name, and empty-name — for a field whose whole
        # purpose is to be read. An empty list says "off, deliberately"; the
        # engine reads it as no walk.
        dispatch.assert_called_once_with(
            "target.crawl",
            {
                "url": "http://127.0.0.1/fixture",
                "max_pages": 0,
                "max_depth": -1,
                "delay_ms": 0,
                "same_origin": False,
                "retry_attempts": 0,
                "bypass_forms": [],
            },
            context,
            task_id="",
        )
        self.assertEqual(TargetJob.objects.get(job_id="91").status, "completed")

    def test_a_repeater_node_resumes_at_the_request_that_was_in_flight(self):
        from . import views

        workflow = Workflow.objects.create(name="Resumable Repeater")
        run = WorkflowRun.objects.create(workflow=workflow, status="waiting")
        context = {
            "run": run,
            "workflow": workflow,
            "node": {"id": "repeater-1"},
            "node_progress": {
                "results": [{"request": {"url": "http://127.0.0.1/first"}, "response": {"status": 200}}],
                "task_id": "11111111-1111-4111-8111-111111111111",
            },
        }
        # The first request already has its answer and must not be sent again;
        # the second is the one that was in flight, identified by its task ID.
        dispatched = []

        def fake_dispatch(task_type, payload, dispatch_context, task_id=""):
            dispatched.append((payload["url"], task_id))
            return {"status": 200, "body": "second"}

        with patch("lab.engine_broker.WORKFLOW_ENGINE_BROKER_ENABLED", True):
            with patch(
                "lab.engine_broker.dispatch_workflow_engine_task",
                side_effect=fake_dispatch,
            ):
                result = views._workflow_tool_runner(
                    "repeater",
                    {
                        "requests": [
                            {"url": "http://127.0.0.1/first"},
                            {"url": "http://127.0.0.1/second"},
                        ],
                        "delay_ms": 0,
                    },
                    context,
                )

        self.assertEqual(
            dispatched,
            [("http://127.0.0.1/second", "11111111-1111-4111-8111-111111111111")],
        )
        self.assertEqual(result["count"], 2)
        self.assertEqual(
            [item["request"]["url"] for item in result["items"]],
            ["http://127.0.0.1/first", "http://127.0.0.1/second"],
        )

    def test_task_is_persisted_before_celery_publish_is_queued(self):
        with patch("lab.tasks.publish_engine_task.delay") as publish:
            with self.captureOnCommitCallbacks(execute=True):
                task, envelope = create_engine_task(
                    "target.crawl",
                    {"url": "http://127.0.0.1/fixture"},
                    route_generation=12,
                )

        self.assertEqual(task.status, "queued")
        self.assertEqual(envelope["task_id"], str(task.task_id))
        self.assertEqual(envelope["payload"], task.payload)
        self.assertEqual(envelope["route_generation"], 12)
        publish.assert_called_once_with(str(task.task_id))

    def test_workflow_dispatch_persists_correlation_before_the_result_exists(self):
        workflow = Workflow.objects.create(name="Broker workflow")
        run = WorkflowRun.objects.create(workflow=workflow, status="running")

        class Operation:
            generation = 17
            stale = False

            def on_cancel(self, callback):
                self.cancel_callback = callback

        context = {
            "run": run,
            "workflow": workflow,
            "node": {"id": "target-1"},
            "outbound_operation": Operation(),
        }

        with patch("lab.tasks.publish_engine_task.delay"):
            with self.captureOnCommitCallbacks(execute=True):
                with self.assertRaises(EngineTaskDeferred):
                    dispatch_workflow_engine_task(
                        "target.crawl",
                        {"url": "http://127.0.0.1/fixture"},
                        context,
                    )

        task = EngineTask.objects.get(workflow_run=run)
        self.assertEqual(task.workflow_node_id, "target-1")
        self.assertEqual(task.route_generation, 17)

    def test_workflow_dispatch_releases_the_worker_instead_of_blocking_it(self):
        workflow = Workflow.objects.create(name="Deferred broker workflow")
        run = WorkflowRun.objects.create(workflow=workflow, status="running")

        class Operation:
            generation = 17
            stale = False

            def on_cancel(self, callback):
                self.cancel_callback = callback

        context = {
            "run": run,
            "workflow": workflow,
            "node": {"id": "target-1"},
            "outbound_operation": Operation(),
        }

        with patch("lab.tasks.publish_engine_task.delay"):
            with self.captureOnCommitCallbacks(execute=True):
                with self.assertRaises(EngineTaskDeferred) as deferred:
                    dispatch_workflow_engine_task(
                        "target.crawl",
                        {"url": "http://127.0.0.1/fixture"},
                        context,
                    )

        task = EngineTask.objects.get(workflow_run=run)
        self.assertEqual(deferred.exception.task_id, str(task.task_id))
        self.assertEqual(deferred.exception.node_id, "target-1")
        # The correlation exists before any result does, which is the only thing
        # that lets a restart tell a live external action from a lost one.
        self.assertEqual(task.workflow_node_id, "target-1")
        self.assertEqual(task.workflow_run_id, run.pk)
        self.assertEqual(task.route_generation, 17)
        self.assertEqual(task.status, "queued")

    def test_re_entering_a_node_waits_for_its_own_task_instead_of_republishing(self):
        workflow = Workflow.objects.create(name="Resumed broker workflow")
        run = WorkflowRun.objects.create(workflow=workflow, status="waiting")
        task = EngineTask.objects.create(
            task_type="request.execute",
            payload={"url": "http://127.0.0.1/fixture"},
            workflow_run=run,
            workflow_node_id="repeater-1",
        )
        context = {
            "run": run,
            "workflow": workflow,
            "node": {"id": "repeater-1"},
        }

        with patch("lab.tasks.publish_engine_task.delay") as publish:
            with self.captureOnCommitCallbacks(execute=True):
                with self.assertRaises(EngineTaskDeferred) as deferred:
                    dispatch_workflow_engine_task(
                        "request.execute",
                        {"url": "http://127.0.0.1/fixture"},
                        context,
                        task_id=str(task.task_id),
                    )

        publish.assert_not_called()
        self.assertEqual(deferred.exception.task_id, str(task.task_id))
        # One external action in, one external action published: a resumed node
        # that started over would be the duplicate this whole path prevents.
        self.assertEqual(EngineTask.objects.filter(workflow_run=run).count(), 1)

    def test_re_entering_a_node_returns_the_answer_it_already_has(self):
        workflow = Workflow.objects.create(name="Answered broker workflow")
        run = WorkflowRun.objects.create(workflow=workflow, status="waiting")
        task = EngineTask.objects.create(
            task_type="request.execute",
            payload={"url": "http://127.0.0.1/fixture"},
            workflow_run=run,
            workflow_node_id="repeater-1",
            status="completed",
            result={"status": 200, "body": "ok"},
        )
        context = {
            "run": run,
            "workflow": workflow,
            "node": {"id": "repeater-1"},
        }

        with patch("lab.tasks.publish_engine_task.delay") as publish:
            with self.captureOnCommitCallbacks(execute=True):
                result = dispatch_workflow_engine_task(
                    "request.execute",
                    {"url": "http://127.0.0.1/fixture"},
                    context,
                    task_id=str(task.task_id),
                )

        self.assertEqual(result, {"status": 200, "body": "ok"})
        publish.assert_not_called()
        self.assertEqual(EngineTask.objects.filter(workflow_run=run).count(), 1)

    def test_workflow_dispatch_cancellation_publishes_cancel_command(self):
        workflow = Workflow.objects.create(name="Cancelled broker workflow")
        run = WorkflowRun.objects.create(workflow=workflow, status="running")
        cancel = Event()
        cancel.set()
        context = {
            "run": run,
            "workflow": workflow,
            "node": {"id": "repeater-1"},
            "control": type("Control", (), {"cancel": cancel, "add_cleanup": lambda *_: None})(),
        }

        with patch("lab.tasks.publish_engine_task.delay"):
            with self.captureOnCommitCallbacks(execute=True):
                with self.assertRaises(EngineTaskCancelled):
                    dispatch_workflow_engine_task(
                        "request.execute",
                        {"url": "http://127.0.0.1/fixture"},
                        context,
                    )

        self.assertEqual(EngineTask.objects.filter(workflow_run=run).count(), 0)

    def test_failed_celery_dispatch_is_reported_and_keeps_task_retryable(self):
        with patch(
            "lab.tasks.publish_engine_task.delay",
            side_effect=RuntimeError("broker unavailable"),
        ):
            with self.assertRaises(RuntimeError):
                with self.captureOnCommitCallbacks(execute=True):
                    create_engine_task("target.crawl", {"url": "http://127.0.0.1/fixture"})

        task = EngineTask.objects.get(task_type="target.crawl")
        self.assertEqual(task.status, "queued")
        self.assertEqual(task.error["code"], "CELERY_PUBLISH_FAILED")
        self.assertTrue(task.error["retryable"])

    def test_duplicate_result_event_is_persisted_once(self):
        task = EngineTask.objects.create(task_type="target.crawl", payload={})
        event = result_event(task, "accepted")

        saved_task, created = persist_engine_result(event)
        duplicate_task, duplicate_created = persist_engine_result(event)

        self.assertTrue(created)
        self.assertFalse(duplicate_created)
        self.assertEqual(saved_task.status, "accepted")
        self.assertEqual(duplicate_task.status, "accepted")
        self.assertEqual(EngineTaskEvent.objects.filter(task=task).count(), 1)

    def test_terminal_result_is_not_regressed_by_late_progress(self):
        task = EngineTask.objects.create(task_type="target.crawl", payload={})
        completed = result_event(task, "completed", result={"pages": []})
        late_progress = result_event(task, "progress", progress={"visited": 1})

        persist_engine_result(completed)
        updated, created = persist_engine_result(late_progress)
        updated.refresh_from_db()

        self.assertTrue(created)
        self.assertEqual(updated.status, "completed")
        self.assertEqual(updated.result, {"pages": []})
        self.assertEqual(updated.progress, {})
        self.assertIsNotNone(updated.finished_at)

    def test_conflicting_terminal_result_is_rejected(self):
        task = EngineTask.objects.create(task_type="target.crawl", payload={})
        persist_engine_result(
            result_event(task, "completed", result={"pages": []}),
        )

        with self.assertRaises(EngineTaskContractError):
            persist_engine_result(
                result_event(
                    task,
                    "failed",
                    error={
                        "code": "ENGINE_FAILURE",
                        "message": "conflicting terminal outcome",
                        "retryable": False,
                    },
                ),
            )

        task.refresh_from_db()
        self.assertEqual(task.status, "completed")
        self.assertEqual(EngineTaskEvent.objects.filter(task=task).count(), 1)

    def test_late_acceptance_does_not_regress_progress_state(self):
        task = EngineTask.objects.create(task_type="target.crawl", payload={})
        persist_engine_result(
            result_event(task, "progress", progress={"visited": 3}),
        )

        updated, _ = persist_engine_result(result_event(task, "accepted"))

        self.assertEqual(updated.status, "progress")
        self.assertEqual(updated.progress, {"visited": 3})

    def test_failed_result_is_stored_with_explicit_error(self):
        task = EngineTask.objects.create(task_type="target.crawl", payload={})
        event = result_event(
            task,
            "failed",
            error={
                "code": "ENGINE_UNAVAILABLE",
                "message": "The engine is unavailable",
                "retryable": True,
            },
        )

        updated, created = persist_engine_result(event)

        self.assertTrue(created)
        self.assertEqual(updated.status, "failed")
        self.assertEqual(updated.error["code"], "ENGINE_UNAVAILABLE")
        self.assertIsNotNone(updated.finished_at)

    def test_event_id_cannot_be_reused_for_another_task(self):
        first_task = EngineTask.objects.create(task_type="target.crawl", payload={})
        second_task = EngineTask.objects.create(task_type="target.crawl", payload={})
        event_id = uuid4()
        persist_engine_result(result_event(first_task, "accepted", event_id=event_id))

        with self.assertRaises(EngineTaskContractError):
            persist_engine_result(result_event(second_task, "accepted", event_id=event_id))

    @patch("lab.tasks.publish_task")
    def test_publisher_marks_a_persisted_task_published_after_the_broker_answers(
        self,
        publish,
    ):
        task = EngineTask.objects.create(
            task_type="target.crawl",
            payload={"url": "http://127.0.0.1/fixture"},
        )

        publish_engine_task.run(str(task.task_id))

        publish.assert_called_once()
        task.refresh_from_db()
        self.assertEqual(task.status, "published")

    def test_publisher_marks_invalid_task_as_terminal_failure(self):
        task = EngineTask.objects.create(task_type="Invalid Type", payload={})

        publish_engine_task.run(str(task.task_id))

        task.refresh_from_db()
        self.assertEqual(task.status, "failed")
        self.assertEqual(task.error["code"], "INVALID_TASK")
        self.assertFalse(task.error["retryable"])
        self.assertIsNotNone(task.finished_at)

    def test_result_consumer_acks_only_after_persistence(self):
        task = EngineTask.objects.create(task_type="target.crawl", payload={})
        message = MagicMock()

        ConsumeEngineResults._on_message(
            result_event(task, "completed", result={"pages": []}),
            message,
        )

        message.ack.assert_called_once_with()
        message.reject.assert_not_called()
        message.requeue.assert_not_called()

    def test_result_consumer_rejects_malformed_payload(self):
        message = MagicMock()

        ConsumeEngineResults._on_message([], message)

        message.reject.assert_called_once_with(requeue=False)
        message.ack.assert_not_called()

    def test_result_consumer_rejects_unknown_task_correlation(self):
        message = MagicMock()
        unknown_task = EngineTask(task_type="target.crawl", payload={})
        unknown_task.task_id = uuid4()

        ConsumeEngineResults._on_message(
            result_event(unknown_task, "accepted"),
            message,
        )

        message.reject.assert_called_once_with(requeue=False)
        message.ack.assert_not_called()

    @patch(
        "lab.management.commands.consume_engine_results.time.sleep",
        return_value=None,
    )
    @patch(
        "lab.management.commands.consume_engine_results.persist_engine_result",
        side_effect=DatabaseError("database unavailable"),
    )
    def test_result_consumer_requeues_when_database_persistence_fails(
        self,
        _persist,
        _sleep,
    ):
        message = MagicMock()

        ConsumeEngineResults._on_message(
            {"task_id": "task", "event_id": "event"},
            message,
        )

        # Called with the rewritten body, not with no arguments: a requeue now
        # carries the attempt counter so the ceiling survives a consumer restart
        # (A10-02). The disposition itself is unchanged — still requeue, still no ack.
        message.requeue.assert_called_once()
        message.ack.assert_not_called()

        rewritten = json.loads(message.requeue.call_args[0][0])
        self.assertEqual(rewritten["_rr_attempt"], 1)
        # The event's own fields must survive the rewrite untouched: a counter that
        # replaced or renamed them would corrupt the very result it is retrying.
        self.assertEqual(rewritten["task_id"], "task")
        self.assertEqual(rewritten["event_id"], "event")


class WorkflowResultResumeTests(TestCase):
    """A persisted engine result is what moves a parked run forward."""

    def build_waiting_run(self):
        workflow = Workflow.objects.create(name="Resumed workflow")
        run = WorkflowRun.objects.create(workflow=workflow, status="waiting")
        WorkflowNodeExecution.objects.create(
            workflow_run=run,
            node_id="target-1",
            status="waiting",
            output_data={"results": [{"status": 200}]},
        )
        task = EngineTask.objects.create(
            task_type="target.crawl",
            payload={},
            workflow_run=run,
            workflow_node_id="target-1",
        )
        return run, task

    def test_completed_result_requeues_the_run_for_the_node_to_collect_it(self):
        run, task = self.build_waiting_run()
        task.status = "completed"
        task.result = {"status": "completed", "pages": [{"url": "http://127.0.0.1/a"}]}

        with patch("lab.engine_broker.resume_waiting_workflow_run") as resume:
            applied = apply_engine_result_to_workflow(task)

        run.refresh_from_db()
        checkpoint = WorkflowNodeExecution.objects.get(workflow_run=run, node_id="target-1")
        self.assertEqual(applied["action"], "resumed")
        self.assertEqual(run.status, "queued")
        # The node stays waiting: only the node itself knows its own port shape
        # and whether it has more requests, so it re-enters and finishes.
        self.assertEqual(checkpoint.status, "waiting")
        self.assertEqual(checkpoint.output_data["task_id"], str(task.task_id))
        resume.assert_called_once_with(run.pk)

    def test_a_repeated_result_does_not_run_the_next_node_twice(self):
        run, task = self.build_waiting_run()
        task.status = "completed"
        task.result = {"status": "completed"}

        with patch("lab.engine_broker.resume_waiting_workflow_run"):
            apply_engine_result_to_workflow(task)
        run.status = "waiting"
        run.save(update_fields=["status"])
        WorkflowNodeExecution.objects.filter(workflow_run=run, node_id="target-1").update(
            status="completed",
        )

        with patch("lab.engine_broker.resume_waiting_workflow_run") as resume:
            applied = apply_engine_result_to_workflow(task)

        run.refresh_from_db()
        self.assertIsNone(applied)
        self.assertEqual(run.status, "waiting")
        resume.assert_not_called()

    def test_failed_result_fails_the_node_and_the_run_with_its_reason(self):
        run, task = self.build_waiting_run()
        task.status = "failed"
        task.error = {"code": "ENGINE_FAILURE", "message": "crawl refused the host"}

        with patch("lab.engine_broker.resume_waiting_workflow_run") as resume:
            applied = apply_engine_result_to_workflow(task)

        run.refresh_from_db()
        checkpoint = WorkflowNodeExecution.objects.get(workflow_run=run, node_id="target-1")
        self.assertEqual(applied["action"], "failed")
        self.assertEqual(run.status, "failed")
        self.assertEqual(run.error, "crawl refused the host")
        self.assertEqual(checkpoint.status, "failed")
        self.assertEqual(checkpoint.error, "crawl refused the host")
        resume.assert_not_called()

    def test_a_paused_run_keeps_its_result_and_continues_on_resume(self):
        run, task = self.build_waiting_run()
        run.status = "paused"
        run.save(update_fields=["status"])
        task.status = "completed"
        task.result = {"status": "completed"}

        with patch("lab.engine_broker.resume_waiting_workflow_run") as resume:
            applied = apply_engine_result_to_workflow(task)

        run.refresh_from_db()
        checkpoint = WorkflowNodeExecution.objects.get(workflow_run=run, node_id="target-1")
        self.assertEqual(applied["action"], "paused")
        self.assertEqual(run.status, "paused")
        # The answer is durable and the node will collect it on resume; the
        # operator's pause is not turned into a failure.
        self.assertEqual(checkpoint.status, "waiting")
        self.assertEqual(checkpoint.output_data["task_id"], str(task.task_id))
        resume.assert_not_called()

    def test_a_cancelled_run_never_resumes_on_a_late_result(self):
        run, task = self.build_waiting_run()
        run.status = "cancelled"
        run.save(update_fields=["status"])
        task.status = "completed"
        task.result = {"status": "completed"}

        with patch("lab.engine_broker.resume_waiting_workflow_run") as resume:
            applied = apply_engine_result_to_workflow(task)

        run.refresh_from_db()
        self.assertIsNone(applied)
        self.assertEqual(run.status, "cancelled")
        resume.assert_not_called()

    def test_an_uncorrelated_task_changes_nothing(self):
        task = EngineTask.objects.create(
            task_type="target.crawl",
            payload={},
            status="completed",
            result={"status": "completed"},
        )

        with patch("lab.engine_broker.resume_waiting_workflow_run") as resume:
            self.assertIsNone(apply_engine_result_to_workflow(task))

        resume.assert_not_called()

    def test_result_consumer_applies_a_correlated_result_before_acking(self):
        run, task = self.build_waiting_run()
        message = MagicMock()

        with patch("lab.engine_broker.resume_waiting_workflow_run") as resume:
            ConsumeEngineResults._on_message(
                result_event(task, "completed", result={"pages": []}),
                message,
            )

        run.refresh_from_db()
        checkpoint = WorkflowNodeExecution.objects.get(workflow_run=run, node_id="target-1")
        message.ack.assert_called_once_with()
        self.assertEqual(checkpoint.status, "waiting")
        self.assertEqual(run.status, "queued")
        resume.assert_called_once_with(run.pk)

    def test_result_consumer_keeps_the_acked_result_when_resume_cannot_start(self):
        run, task = self.build_waiting_run()
        message = MagicMock()

        with patch("lab.tasks.execute_workflow_run.delay", side_effect=RuntimeError("no worker")):
            ConsumeEngineResults._on_message(
                result_event(task, "completed", result={"pages": []}),
                message,
            )

        run.refresh_from_db()
        task.refresh_from_db()
        # The engine answer is durable and must not be re-delivered. What the
        # process can still do is say the run could not be picked up, because a
        # queued run with a completed checkpoint resumes from the safe boundary.
        message.ack.assert_called_once_with()
        self.assertEqual(task.status, "completed")
        self.assertEqual(run.status, "queued")
