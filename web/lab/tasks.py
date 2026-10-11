import logging

from celery import shared_task
from django.utils import timezone

from .broker_transport import require_redis_broker, publish_task
from .engine_broker import engine_task_envelope
from .engine_task_contract import EngineTaskContractError
from .models import EngineTask

logger = logging.getLogger(__name__)


@shared_task(
    bind=True,
    name="lab.execute_workflow_run",
    acks_late=True,
    reject_on_worker_lost=True,
)
def execute_workflow_run(self, run_id):
    """Execute one durable workflow run from its persisted graph snapshot."""
    from .workflow_engine import get_runtime

    get_runtime()._execute(int(run_id), None)


@shared_task(
    bind=True,
    name="lab.publish_engine_task",
    acks_late=True,
    max_retries=None,
)
def publish_engine_task(self, task_id):
    """Publish one already-persisted engine task to the durable Redis queue."""
    try:
        task = EngineTask.objects.get(task_id=task_id)
        envelope = engine_task_envelope(task)
    except EngineTask.DoesNotExist:
        logger.error("engine_task_publish_missing task_id=%s", task_id)
        return
    except EngineTaskContractError as error:
        EngineTask.objects.filter(task_id=task_id).update(
            status="failed",
            error={"code": "INVALID_TASK", "message": str(error), "retryable": False},
            finished_at=timezone.now(),
            updated_at=timezone.now(),
        )
        logger.error("engine_task_publish_invalid task_id=%s reason=%s", task_id, error)
        return

    try:
        # LPUSH is a single atomic command whose answer is the new queue length,
        # so the publish is confirmed by the broker's own reply. A broker URL
        # this deployment cannot serve is an error, not a silent no-op: a task
        # that never reaches the queue must never be marked published.
        publish_task(require_redis_broker(self.app.conf.broker_url or ""), envelope)
        EngineTask.objects.filter(task_id=task_id, status="queued").update(
            status="published",
            error={},
        )
    except Exception as error:
        logger.exception("engine_task_publish_failed task_id=%s", task_id)
        raise self.retry(exc=error, max_retries=None, countdown=5) from error
