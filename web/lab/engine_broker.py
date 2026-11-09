"""Durable Django-side submission and result handling for Go engine tasks."""

import logging
import os
import threading
from datetime import datetime
from typing import Any
from uuid import UUID

from django.db import transaction
from django.utils import timezone

from .broker_auth import sign_envelope, verify_envelope_signature
from .engine_task_contract import (
    EngineTaskContractError,
    validate_engine_result,
    validate_engine_task,
)
from .models import EngineTask, EngineTaskEvent, WorkflowNodeExecution, WorkflowRun

logger = logging.getLogger(__name__)
WORKFLOW_ENGINE_BROKER_ENABLED = os.environ.get(
    "WORKFLOW_ENGINE_BROKER_ENABLED", ""
).strip().lower() in {"1", "true", "yes", "on"}


class EngineTaskDispatchError(RuntimeError):
    """A broker-dispatched workflow node did not complete successfully."""


class EngineTaskCancelled(EngineTaskDispatchError):
    """A broker-dispatched workflow node was cancelled."""

_STATE_ORDER = {
    "queued": 0,
    "published": 0,
    "accepted": 1,
    "progress": 2,
}


def engine_task_envelope(task):
    envelope = {
        "schema_version": 1,
        "task_id": str(task.task_id),
        "task_type": task.task_type,
        "created_at": task.created_at.isoformat(),
        "payload": task.payload,
        "route_generation": task.route_generation,
    }
    if task.workflow_run_id is not None:
        envelope["workflow_run_id"] = task.workflow_run_id
    if task.workflow_node_id:
        envelope["workflow_node_id"] = task.workflow_node_id
    if task.project_id is not None:
        envelope["project_id"] = task.project_id
    # Signed here, once, for every publisher: `tasks.publish_engine_task` sends
    # exactly this dict, so there is no second place that must remember to sign.
    # Without a configured key this is a no-op copy (compatibility mode).
    return sign_envelope(validate_engine_task(envelope))


def create_engine_task(
    task_type,
    payload,
    *,
    workflow_run=None,
    workflow_node_id="",
    project=None,
    route_generation=0,
):
    """Persist a task envelope, then ask Celery to publish it after commit."""
    if not isinstance(task_type, str) or not isinstance(payload, dict):
        raise EngineTaskContractError("task_type and object payload are required")
    with transaction.atomic():
        task = EngineTask.objects.create(
            task_type=task_type,
            payload=payload,
            workflow_run=workflow_run,
            workflow_node_id=str(workflow_node_id or ""),
            project=project,
            route_generation=route_generation,
        )
        envelope = engine_task_envelope(task)
        transaction.on_commit(
            lambda: _enqueue_publish(task.task_id),
        )
    return task, envelope


TERMINAL_TASK_STATES = {"completed", "failed", "cancelled"}


class EngineTaskDeferred(EngineTaskDispatchError):
    """The node published a durable task and released its worker.

    Raised instead of blocking a Django thread until an external result
    arrives. The caller records the correlation on the node checkpoint, the run
    moves to ``waiting``, and the result consumer resumes the graph.
    """

    def __init__(self, task_id, node_id: str) -> None:
        super().__init__(f"engine task {task_id} is running outside the graph worker")
        self.task_id = str(task_id)
        self.node_id = str(node_id)


def cancel_engine_task(task, run=None, node_id: str = "", project=None, route_generation=0):
    """Publish a cancellation for one still-active engine task, exactly once."""
    current = EngineTask.objects.filter(pk=task.pk).values_list("status", flat=True).first()
    if current is None or current in TERMINAL_TASK_STATES:
        return False
    create_engine_task(
        "engine.task.cancel",
        {"task_id": str(task.task_id)},
        workflow_run=run,
        workflow_node_id=str(node_id or task.workflow_node_id or ""),
        project=project,
        route_generation=route_generation,
    )
    return True


def dispatch_workflow_engine_task(task_type, payload, context, task_id=""):
    """Submit one workflow node task without holding a worker until it finishes.

    A re-entering node passes the task ID it published last time. That task is
    then authoritative: a persisted terminal result is returned as the answer,
    and a still-running one makes the node wait again instead of publishing the
    same external action a second time. Only a node with no task ID publishes.
    """
    run = context.get("run")
    node = context.get("node")
    workflow = context.get("workflow")
    operation = context.get("outbound_operation")
    route_generation = getattr(operation, "generation", 0)
    node_id = str((node or {}).get("id", ""))
    project = getattr(run, "project", None) or getattr(workflow, "project", None)

    def is_cancelled() -> bool:
        if run is not None and WorkflowRun.objects.filter(pk=run.pk, status="cancelled").exists():
            return True
        control = context.get("control")
        if control is not None and control.cancel.is_set():
            return True
        return operation is not None and operation.stale

    if is_cancelled():
        raise EngineTaskCancelled("workflow engine task was cancelled")

    task = None
    if task_id:
        try:
            task = EngineTask.objects.get(task_id=UUID(str(task_id)))
        except (EngineTask.DoesNotExist, ValueError):
            task = None
    if task is not None and task.status in TERMINAL_TASK_STATES:
        return _terminal_task_result(task)
    if task is None:
        task, _envelope = create_engine_task(
            task_type,
            payload,
            workflow_run=run,
            workflow_node_id=node_id,
            project=project,
            route_generation=route_generation,
        )
        if task.status in TERMINAL_TASK_STATES:
            return _terminal_task_result(task)

    control = context.get("control")
    cancel_lock = threading.Lock()
    cancel_requested = False

    def cancel_if_active():
        nonlocal cancel_requested
        # A parked run owns no worker while an external action finishes, and the
        # run loop's `finally` block calls `control.run_cleanup()` on its way
        # out - including when the node deferred. Registering this as a plain
        # cleanup therefore cancelled the very task the run was parked on: the
        # task ended `cancelled`, the consumer resumed the graph, and
        # `_terminal_task_result` raised "engine task was cancelled", so the run
        # ended `failed` while its node was still legitimately running. It only
        # passed when the task happened to finish before the cleanup ran, which
        # is why it read as a flake and not as a defect.
        #
        # The cleanup means "this run is being abandoned", and a `waiting` run
        # is not abandoned - it is waiting. Cancellation for an operator-initiated
        # cancel still arrives while the run is `running`, and a parked run that
        # is cancelled from outside has no live control to clean up: that path
        # is `_cancel_waiting_engine_task`.
        if run is not None and WorkflowRun.objects.filter(
            pk=run.pk, status="waiting"
        ).exists():
            return
        with cancel_lock:
            if cancel_requested:
                return
            cancel_requested = True
        try:
            cancel_engine_task(task, run=run, node_id=node_id, project=project, route_generation=route_generation)
        except Exception:
            logger.exception("engine_task_cancel_dispatch_failed task_id=%s", task.task_id)

    if control is not None:
        control.add_cleanup(cancel_if_active)
    if operation is not None:
        operation.on_cancel(cancel_if_active)

    raise EngineTaskDeferred(task.task_id, node_id)


def _terminal_task_result(task):
    """Turn a persisted terminal engine state into a value or a typed error."""
    if task.status == "completed":
        return task.result
    if task.status == "cancelled":
        raise EngineTaskCancelled("engine task was cancelled")
    detail = task.error.get("message") or task.error.get("code") or "engine task failed"
    raise EngineTaskDispatchError(str(detail))


def _enqueue_publish(task_id):
    from .tasks import publish_engine_task

    try:
        publish_engine_task.delay(str(task_id))
    except Exception:
        EngineTask.objects.filter(task_id=task_id, status="queued").update(
            error={
                "code": "CELERY_PUBLISH_FAILED",
                "message": "Celery could not queue the engine task publisher.",
                "retryable": True,
            },
        )
        logger.error("celery_engine_task_dispatch_failed task_id=%s", task_id)
        raise


def persist_engine_result(message):
    """Persist one validated event idempotently before its acknowledgement."""
    # Signature first, shape second: a forged envelope has the right shape by
    # construction, so validating the shape first would answer the wrong question.
    # A bad signature raises EngineTaskContractError, which the consumer turns
    # into a dead-letter — the forgery survives as evidence instead of vanishing,
    # and the run it targeted never moves.
    verify_envelope_signature(message)
    validate_engine_result(message)
    occurred_at = datetime.fromisoformat(message["occurred_at"].replace("Z", "+00:00"))
    with transaction.atomic():
        task = EngineTask.objects.select_for_update().filter(
            task_id=UUID(message["task_id"]),
        ).first()
        if task is None:
            raise EngineTask.DoesNotExist(message["task_id"])
        existing_event = EngineTaskEvent.objects.filter(
            event_id=UUID(message["event_id"]),
        ).first()
        if existing_event:
            if existing_event.task_id != task.id:
                raise EngineTaskContractError(
                    "event_id is already associated with a different task"
                )
            return task, False
        terminal = {"completed", "failed", "cancelled"}
        if (
            task.status in terminal
            and message["state"] in terminal
            and task.status != message["state"]
        ):
            raise EngineTaskContractError(
                "task already has a different terminal state"
            )
        EngineTaskEvent.objects.create(
            task=task,
            event_id=UUID(message["event_id"]),
            state=message["state"],
            occurred_at=occurred_at,
            data=message,
        )
        fields = ["updated_at"]
        if task.status not in terminal:
            current_order = _STATE_ORDER.get(task.status, -1)
            incoming_order = _STATE_ORDER.get(message["state"], 3)
            if incoming_order >= current_order:
                task.status = message["state"]
                fields.append("status")
            if "progress" in message and incoming_order >= current_order:
                task.progress = message["progress"]
                fields.append("progress")
            if message["state"] == "completed":
                task.result = message["result"]
                fields.append("result")
            elif message["state"] == "failed":
                task.error = message["error"]
                fields.append("error")
            if message["state"] in terminal:
                task.finished_at = occurred_at
                fields.append("finished_at")
            task.save(update_fields=fields)
    return task, True


def apply_engine_result_to_workflow(task) -> dict[str, Any] | None:
    """Move a correlated workflow run forward from a persisted engine result.

    The Go side already answered, so the only safe thing left is to record that
    answer and let the graph continue from its durable checkpoints. A repeated
    result for a node that is no longer waiting changes nothing, which is what
    keeps a redelivered event from running the next node twice.
    """
    run_id = task.workflow_run_id
    node_id = str(task.workflow_node_id or "")
    if not run_id or not node_id or task.status not in TERMINAL_TASK_STATES:
        return None
    run = WorkflowRun.objects.filter(pk=run_id).first()
    if run is None:
        return None
    checkpoint = WorkflowNodeExecution.objects.filter(
        workflow_run_id=run_id,
        node_id=node_id,
    ).first()
    if checkpoint is None:
        return None

    now = timezone.now()
    if task.status == "completed":
        if checkpoint.status not in {"waiting", "running"}:
            return None
        # The node is NOT completed here. Only the node itself knows the port
        # shape of its own output and whether it has more requests to send, so
        # the DAG re-enters it with this answer and the node finishes. Marking
        # the checkpoint complete from outside would hand the next node a raw
        # engine payload that no edge can carry.
        progress = checkpoint.output_data if isinstance(checkpoint.output_data, dict) else {}
        progress = {**progress, "task_id": str(task.task_id)}
        WorkflowNodeExecution.objects.filter(pk=checkpoint.pk).update(
            status="waiting",
            output_data=progress,
            error="",
            updated_at=now,
        )
    else:
        if checkpoint.status != "waiting":
            return None
        reason = "engine task was cancelled"
        if task.status == "failed":
            reason = str(task.error.get("message") or task.error.get("code") or "engine task failed")
        WorkflowNodeExecution.objects.filter(pk=checkpoint.pk).update(
            status="failed",
            error=reason,
            finished_at=now,
            updated_at=now,
        )
        if run.status != "cancelled":
            _fail_waiting_run(run.pk, reason, now)
        return {"run_id": run.pk, "node_id": node_id, "action": "failed"}

    if run.status == "cancelled":
        return None
    if run.status not in {"waiting", "running", "paused"}:
        return None
    if run.status == "paused":
        # An operator pause outlives the result: the node output is durable, so
        # the graph continues when the run is resumed instead of being lost.
        return {"run_id": run.pk, "node_id": node_id, "action": "paused"}
    updated = WorkflowRun.objects.filter(pk=run.pk, status="waiting").update(
        status="queued",
        updated_at=now,
    )
    if not updated:
        return None
    resume_waiting_workflow_run(run.pk)
    return {"run_id": run.pk, "node_id": node_id, "action": "resumed"}


def _fail_waiting_run(run_id: int, reason: str, now) -> None:
    WorkflowRun.objects.filter(
        pk=run_id,
        status__in={"waiting", "queued", "running"},
    ).update(
        status="failed",
        current_node="",
        error=reason,
        finished_at=now,
        updated_at=now,
    )


def resume_waiting_workflow_run(run_id: int) -> None:
    """Hand a resumed run back to whichever worker mode this process runs."""
    from .workflow_engine import WORKFLOW_CELERY_ENABLED, get_runtime

    if WORKFLOW_CELERY_ENABLED:
        from .tasks import execute_workflow_run

        try:
            execute_workflow_run.delay(run_id)
        except Exception:
            logger.exception("workflow_run_resume_dispatch_failed run_id=%s", run_id)
            _fail_waiting_run(run_id, "workflow worker could not be dispatched", timezone.now())
        return
    get_runtime().start_recovered(run_id)
