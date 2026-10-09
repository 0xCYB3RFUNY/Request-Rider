import json
import logging
import os
import time

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import DatabaseError

from lab.broker_transport import (
    RESULT_QUEUE,
    BrokerTransportError,
    RedisResultConsumer,
    dead_list,
    require_redis_broker,
)
from lab.engine_broker import apply_engine_result_to_workflow, persist_engine_result
from lab.engine_task_contract import EngineTaskContractError
from lab.models import EngineTask

logger = logging.getLogger("lab.engine_broker")

# --- bounded retries for a transient database failure --------------------------
#
# `message.requeue()` used to run in a hot loop: LREM + LPUSH, no delay, no ceiling.
# Stopping PostgreSQL while one result was in flight therefore turned the consumer
# into a spin — measured during the audit, and the log filled with one identical line
# per iteration instead of one line saying what had happened. Two separate problems,
# two separate fixes: the delay and the ceiling here, the flooding in the log line
# that names the attempt.
#
# THE LIMITS ARE DEFAULTS WITH OVERRIDES, NEVER CONSTANTS, and both the delay and the
# exhaustion are named in the log. A silent cap is the thing this project forbids: an
# operator has to be able to see that a result went to the dead-letter list and why,
# and to raise the ceiling if a slow database deserves more attempts.
#
# The delay is exponential and capped. It blocks this consumer, and that is the point
# while the database is down: every message in this queue needs the same database, so
# a fast loop cannot make progress on anything — it can only spend CPU and fill the
# disk with identical lines.
RESULT_MAX_ATTEMPTS = int(os.environ.get("RR_ENGINE_RESULT_MAX_ATTEMPTS") or 5)
RESULT_RETRY_BASE_SECONDS = float(os.environ.get("RR_ENGINE_RESULT_RETRY_BASE_SECONDS") or 1.0)
RESULT_RETRY_MAX_SECONDS = 30.0

# Carried in the message so the count survives a consumer restart. It is **popped**
# before validation: the result envelope is a signed contract, and an extra key inside
# it would either fail the schema or, worse, be accepted into the persisted record.
ATTEMPT_KEY = "_rr_attempt"


def _retry_delay(attempt: int) -> float:
    """Exponential from the base, capped, and never negative for a nonsense input."""
    exponent = max(0, min(attempt, 30) - 1)
    return min(RESULT_RETRY_BASE_SECONDS * (2**exponent), RESULT_RETRY_MAX_SECONDS)


def _retry_or_dead_letter(payload, message, *, attempt: int, reason: str, error: BaseException) -> None:
    """Requeue a transient database failure with a delay, or dead-letter it.

    The exhaustion is deliberately a dead-letter and not a silent drop: the message
    keeps its place in `<queue>.dead`, which is where an operator looks, and the log
    line names the reason, the attempts and the ceiling. Losing a result quietly is
    the one outcome worse than a stopped consumer.

    The counter rides **in the message** rather than in this process, so a consumer
    restart does not reset the ceiling — otherwise every restart would hand a stuck
    result a fresh set of attempts and the spin would return with it.
    """
    next_attempt = attempt + 1
    if next_attempt > RESULT_MAX_ATTEMPTS:
        logger.error(
            "engine_result_retry_exhausted reason=%s attempts=%d max_attempts=%d "
            "error_type=%s dead_list=%s",
            reason,
            attempt,
            RESULT_MAX_ATTEMPTS,
            type(error).__name__,
            dead_list(RESULT_QUEUE),
        )
        message.reject(requeue=False)
        return

    delay = _retry_delay(next_attempt)
    logger.warning(
        "engine_result_retry_scheduled reason=%s attempt=%d max_attempts=%d "
        "delay_s=%.1f error_type=%s",
        reason,
        next_attempt,
        RESULT_MAX_ATTEMPTS,
        delay,
        type(error).__name__,
    )
    payload[ATTEMPT_KEY] = next_attempt
    message.requeue(json.dumps(payload).encode("utf-8"))
    # Sleep last, after the message is already back in the queue, so a crash during
    # the pause cannot lose it.
    time.sleep(delay)


class Command(BaseCommand):
    help = "Consume and persist durable result events from the Go engine queue."

    def add_arguments(self, parser):
        parser.add_argument(
            "--once",
            action="store_true",
            help="Consume currently available results and exit when the queue is idle.",
        )

    def handle(self, *args, **options):
        broker_url = settings.CELERY_BROKER_URL
        if not broker_url:
            raise CommandError(
                "CELERY_BROKER_URL must configure the Redis broker, for example "
                "redis://127.0.0.1:6379/0"
            )
        try:
            broker_url = require_redis_broker(broker_url)
        except BrokerTransportError as error:
            raise CommandError(str(error)) from None
        while True:
            try:
                self._consume(broker_url, once=options["once"])
                return
            except KeyboardInterrupt:
                self.stdout.write("Engine result consumer stopped.")
                return
            except (BrokerTransportError, OSError) as error:
                if options["once"]:
                    raise CommandError(
                        "Cannot connect to the engine result queue "
                        f"(error type: {type(error).__name__})"
                    ) from None
                logger.error(
                    "engine_result_consumer_disconnected error_type=%s",
                    type(error).__name__,
                )
                time.sleep(5)

    def _consume(self, broker_url, *, once):
        """Block for results, holding each one inflight until it is persisted.

        The handler and the dispositions are the ones a broker message has, so a
        result is validated, persisted and acknowledged the same way whether the
        failure was a contract error, a database error or a dead connection.
        """
        with RedisResultConsumer(broker_url, queue=RESULT_QUEUE) as consumer:
            while True:
                delivery = consumer.next_message()
                if delivery is None:
                    # An empty poll is the "queue is idle" signal, so --once
                    # returns instead of waiting for a message that may never
                    # come.
                    if once:
                        return
                    continue
                self._on_message(self._decode(delivery.body), delivery)
                if once:
                    return

    @staticmethod
    def _decode(body):
        """Parse one result body, and say so when it cannot be parsed.

        This used to return `None` with nothing written anywhere, so a corrupt message
        vanished: the delivery was then rejected without a trace, and the analyst had
        a silently missing result and no line to start from. The body itself is not
        logged — it is the engine's payload, and the project does not put payloads in
        diagnostics — only its size and the failure type.
        """
        try:
            return json.loads(body)
        except (TypeError, ValueError) as error:
            logger.error(
                "engine_result_undecodable error_type=%s bytes=%d",
                type(error).__name__,
                len(body or b""),
            )
            return None

    @staticmethod
    def _on_message(payload, message):
        if not isinstance(payload, dict):
            logger.error("engine_result_rejected reason=payload_not_object")
            message.reject(requeue=False)
            return
        # Read the retry counter and take it **out** of the envelope before anything
        # validates it. `persist_engine_result` checks an HMAC signature and then the
        # contract schema, so an extra key left inside would either fail validation or
        # be written into the persisted record — and this key is broker bookkeeping,
        # not part of the signed event.
        attempt = payload.pop(ATTEMPT_KEY, 0)
        if not isinstance(attempt, int) or attempt < 0:
            attempt = 0
        try:
            task, created = persist_engine_result(payload)
        except EngineTask.DoesNotExist:
            logger.error(
                "engine_result_rejected task_id=%s reason=unknown_task",
                payload.get("task_id"),
            )
            message.reject(requeue=False)
            return
        except EngineTaskContractError as error:
            logger.error(
                "engine_result_rejected task_id=%s reason=%s",
                payload.get("task_id"),
                error,
            )
            message.reject(requeue=False)
            return
        except DatabaseError as error:
            _retry_or_dead_letter(
                payload,
                message,
                attempt=attempt,
                reason="persistence_failed",
                error=error,
            )
            return
        if created:
            logger.info(
                "engine_result_persisted task_id=%s event_id=%s state=%s",
                task.task_id,
                payload["event_id"],
                payload["state"],
            )
        # The graph transition runs on **every** delivery, not only the first one.
        #
        # `ack()` used to happen before it, and a failure after that point left the
        # run in `waiting` with no retry, no timeout and no sweeper: the operator saw
        # a spinner forever, and the only recovery was a restart, which re-published
        # the engine task and executed the external node a second time.
        #
        # Attempting it on a redelivery is what makes the requeue below meaningful,
        # and it is safe because `apply_engine_result_to_workflow` is idempotent by
        # contract — it returns None once the node is no longer waiting, which is
        # exactly what stops a duplicated result from running the next node twice.
        if task.workflow_run_id and task.workflow_node_id:
            try:
                applied = apply_engine_result_to_workflow(task)
            except DatabaseError as resume_error:
                # Transient by nature: the answer is already durable in `task`, and
                # the edge is the only thing missing. Hand the message back rather
                # than acking a result the graph has not consumed yet.
                #
                # Same disposition as a persistence failure and for the same reason:
                # the result is durable, the edge is missing, and the database is the
                # thing that is down. It goes through the same bounded path rather
                # than getting its own — two retry policies for one database is how
                # one of them ends up without a ceiling.
                _retry_or_dead_letter(
                    payload,
                    message,
                    attempt=attempt,
                    reason="workflow_resume_failed",
                    error=resume_error,
                )
                return
            except Exception:  # noqa: BLE001 - deterministic failure, not a race
                # Requeuing a deterministic bug would spin the consumer: it would
                # fail identically every time. The result stays durable, the line
                # below is the evidence that the run needs a human, and the sweep in
                # the scheduler is what eventually fails a parked run.
                logger.exception(
                    "engine_result_workflow_resume_failed task_id=%s transient=False",
                    task.task_id,
                )
            else:
                if applied:
                    logger.info(
                        "engine_result_workflow_applied task_id=%s run_id=%s "
                        "node_id=%s action=%s",
                        task.task_id,
                        applied["run_id"],
                        applied["node_id"],
                        applied["action"],
                    )
        message.ack()
