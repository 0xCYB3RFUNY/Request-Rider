"""The broker ack must not precede the workflow transition.

`consume_engine_results` used to ack the message and only then call
`apply_engine_result_to_workflow`. A failure between the two left the run in
`waiting` with no retry, no timeout and no sweeper: the operator saw a spinner
forever, and the only recovery was a restart — which re-published the engine task
and executed the external node a second time.

The ordering is asserted on a fake message rather than on a real broker, because
what is being tested is *when* `ack()` is called relative to the graph transition,
and that is invisible once a real Redis is in the loop.
"""

import uuid
from unittest.mock import patch

from django.db.utils import OperationalError
from django.test import TestCase

from lab.broker_auth import sign_envelope
from lab.management.commands.consume_engine_results import Command
from lab.models import EngineTask, Workflow, WorkflowNodeExecution, WorkflowRun


class FakeMessage:
    """Records the delivery outcome instead of talking to Redis.

    `requeue` takes the optional rewritten body because the bounded-retry path now
    passes one: the retry counter rides in the message so it survives a consumer
    restart. Keeping the rewritten bytes here is what lets the tests assert the
    counter rather than just the disposition.
    """

    def __init__(self):
        self.events = []
        self.requeued_bodies = []

    def ack(self):
        self.events.append("ack")

    def requeue(self, body=None):
        self.events.append("requeue")
        if body is not None:
            self.requeued_bodies.append(body)

    def reject(self, requeue=False):
        self.events.append(f"reject(requeue={requeue})")

    @property
    def outcome(self):
        return self.events[-1] if self.events else None


def _payload(task_id, event_id, state="completed"):
    """One result envelope, signed the way the engine signs it.

    `persist_engine_result` verifies the HMAC before it validates anything else,
    and `start.sh` exports a key into every stand and into `./start.sh --check`.
    An unsigned fixture passed only while no key existed, so the documented check
    was green in a mode the product cannot run in. `sign_envelope` is a no-op
    without a key, which keeps one fixture honest in both.
    """
    return sign_envelope(
        {
            "schema_version": 1,
            "task_id": str(task_id),
            "event_id": str(event_id),
            "state": state,
            "occurred_at": "2026-10-01T00:00:00Z",
            "result": {"status": 200, "body": "ok"},
        }
    )


class AckOrderingTests(TestCase):
    def setUp(self):
        self.workflow = Workflow.objects.create(name="ack-order", nodes=[], connections=[])
        self.run = WorkflowRun.objects.create(workflow=self.workflow, status="waiting")
        self.task = EngineTask.objects.create(
            task_id=uuid.uuid4(),
            task_type="engine.target.request",
            status="pending",
            workflow_run=self.run,
            workflow_node_id="probe",
        )
        self.checkpoint = WorkflowNodeExecution.objects.create(
            workflow_run=self.run,
            node_id="probe",
            status="running",
        )
        from lab.models import EngineTaskEvent

        from django.utils import timezone

        self.event = EngineTaskEvent.objects.create(
            task=self.task,
            event_id=uuid.uuid4(),
            state="completed",
            occurred_at=timezone.now(),
            data={"status": 200},
        )
        self.payload = _payload(self.task.task_id, self.event.event_id)

    def test_ack_happens_after_the_workflow_transition(self):
        """Ordering, not just outcome: ack must be the last thing that happens."""
        calls = []
        message = FakeMessage()

        def apply(task):
            calls.append("apply")
            return {"run_id": self.run.id, "node_id": "probe", "action": "resume"}

        original_ack = message.ack

        def ack():
            calls.append("ack")
            original_ack()

        message.ack = ack

        with patch(
            "lab.management.commands.consume_engine_results."
            "apply_engine_result_to_workflow", side_effect=apply
        ):
            Command()._on_message(self.payload, message)

        self.assertEqual(calls, ["apply", "ack"],
                         f"apply must precede ack, got {calls}")
        self.assertEqual(message.outcome, "ack")

    def test_transient_failure_requeues_instead_of_acking(self):
        """A `DatabaseError` is transient: the answer is durable, the edge is not."""
        message = FakeMessage()
        with patch(
            "lab.management.commands.consume_engine_results."
            "apply_engine_result_to_workflow",
            side_effect=OperationalError("connection lost"),
        ):
            Command()._on_message(self.payload, message)

        self.assertEqual(message.outcome, "requeue")
        self.assertNotIn("ack", message.events,
                         "acking here is exactly the bug: the run would park")

    def test_deterministic_failure_still_acks_without_spinning(self):
        """A bug that fails identically must not requeue forever."""
        message = FakeMessage()
        with patch(
            "lab.management.commands.consume_engine_results."
            "apply_engine_result_to_workflow",
            side_effect=TypeError("a real bug"),
        ):
            Command()._on_message(self.payload, message)

        self.assertEqual(message.outcome, "ack")
        self.assertNotIn("requeue", message.events,
                         "requeuing a deterministic failure is a hot spin")

    def test_a_redelivery_still_attempts_the_transition(self):
        """The retry is only real if the transition runs when `created` is False.

        On redelivery the event already exists, so `created` is False. If the
        transition stayed behind `if created`, the requeue would return the message
        and the code would skip the very work it requeued for — which is the shape
        of the original defect, wearing a retry.
        """
        import uuid

        from lab.engine_broker import persist_engine_result

        Command()._on_message(self.payload, FakeMessage())
        self.task.refresh_from_db()
        self.checkpoint.refresh_from_db()

        # Second delivery, same event_id: `created` must be False.
        _task, created = persist_engine_result(self.payload)
        self.assertFalse(created)

        applied = []
        with patch(
            "lab.management.commands.consume_engine_results."
            "apply_engine_result_to_workflow",
            side_effect=lambda task: applied.append(task.task_id) or None,
        ):
            Command()._on_message(self.payload, FakeMessage())

        self.assertEqual(applied, [self.task.task_id],
                         "a redelivery must still attempt the graph transition")

    def test_unknown_task_is_still_dead_lettered(self):
        """The reject paths are unchanged by this fix."""
        import uuid

        message = FakeMessage()
        Command()._on_message(_payload(uuid.uuid4(), uuid.uuid4()), message)
        self.assertEqual(message.outcome, "reject(requeue=False)")

class BoundedRetryTests(TestCase):
    """A10-02 — `requeue()` used to be a hot loop with no ceiling.

    Stopping PostgreSQL while one result was in flight turned the consumer into a
    spin: LREM + LPUSH per iteration, no delay, no limit, and one identical log line
    per pass. These tests pin the three things that end that — a ceiling that
    dead-letters, a delay that grows, and a counter that survives the message.
    """

    def setUp(self):
        import uuid

        from django.utils import timezone

        from lab.models import EngineTask, EngineTaskEvent, Workflow, WorkflowRun

        self.workflow = Workflow.objects.create(name="bounded", nodes=[], connections=[])
        self.run = WorkflowRun.objects.create(workflow=self.workflow, status="waiting")
        self.task = EngineTask.objects.create(
            task_id=uuid.uuid4(),
            task_type="engine.target.request",
            status="pending",
            workflow_run=self.run,
            workflow_node_id="probe",
        )
        self.event = EngineTaskEvent.objects.create(
            task=self.task,
            event_id=uuid.uuid4(),
            state="completed",
            occurred_at=timezone.now(),
            data={"status": 200},
        )
        self.payload = _payload(self.task.task_id, self.event.event_id)

    def _run_with_database_failure(self, message, *, delay_patched=True):
        import lab.management.commands.consume_engine_results as consumer

        with patch(
            "lab.management.commands.consume_engine_results."
            "apply_engine_result_to_workflow",
            side_effect=OperationalError("connection lost"),
        ):
            if delay_patched:
                # The real delay is the behaviour under test, but a test must not spend
                # seconds asleep: the value itself is asserted separately.
                with patch.object(consumer.time, "sleep") as slept:
                    consumer.Command()._on_message(self.payload, message)
                    return slept
            consumer.Command()._on_message(self.payload, message)
        return None

    def test_a_transient_failure_is_delayed_not_retried_immediately(self):
        message = FakeMessage()
        slept = self._run_with_database_failure(message)

        self.assertEqual(message.outcome, "requeue")
        self.assertIsNotNone(slept, "no sleep: this is the hot loop A10-02 describes")
        self.assertGreater(slept.call_args[0][0], 0,
                           "the first retry must wait, not spin")

    def test_the_delay_grows_and_stays_capped(self):
        from lab.management.commands.consume_engine_results import (
            RESULT_RETRY_BASE_SECONDS,
            RESULT_RETRY_MAX_SECONDS,
            _retry_delay,
        )

        self.assertEqual(_retry_delay(1), RESULT_RETRY_BASE_SECONDS)
        self.assertEqual(_retry_delay(2), RESULT_RETRY_BASE_SECONDS * 2)
        self.assertEqual(_retry_delay(3), RESULT_RETRY_BASE_SECONDS * 4)

        # A ceiling on the delay matters as much as a growth: without it, attempt 30
        # would sleep for years and the message would never be redelivered.
        for attempt in range(1, 200):
            self.assertLessEqual(_retry_delay(attempt), RESULT_RETRY_MAX_SECONDS)

        # Nonsense input must not produce a negative sleep or a `TypeError`.
        self.assertGreaterEqual(_retry_delay(0), 0)
        self.assertGreaterEqual(_retry_delay(-5), 0)

    def test_the_attempt_counter_rides_in_the_message(self):
        """In the message, not in the process. A consumer restart that reset the
        counter would hand a stuck result a fresh set of attempts and the spin would
        return with it."""
        import json

        message = FakeMessage()
        self._run_with_database_failure(message)

        self.assertEqual(len(message.requeued_bodies), 1)
        carried = json.loads(message.requeued_bodies[0])
        self.assertEqual(carried["_rr_attempt"], 1)

    def test_the_counter_is_removed_before_the_envelope_is_validated(self):
        """`persist_engine_result` checks an HMAC signature and then the schema, so a
        broker bookkeeping key left inside the envelope would fail validation or be
        written into the persisted record."""
        from lab.management.commands.consume_engine_results import ATTEMPT_KEY

        self.payload[ATTEMPT_KEY] = 2   # as a redelivery would carry it
        Command()._on_message(self.payload, FakeMessage())
        self.assertNotIn(ATTEMPT_KEY, self.payload,
                         "the counter must be popped before the envelope is validated")

    def test_a_higher_counter_is_honoured_and_a_fresh_one_is_not_overwritten(self):
        """Starting at 4 with a ceiling of 5 must dead-letter, not retry once more —
        and starting at 0 must not be treated as already exhausted."""
        import json

        import lab.management.commands.consume_engine_results as consumer

        self.payload["_rr_attempt"] = consumer.RESULT_MAX_ATTEMPTS
        message = FakeMessage()
        self._run_with_database_failure(message)
        self.assertEqual(message.outcome, "reject(requeue=False)",
                         "past the ceiling the result must reach the dead-letter list")

        self.payload["_rr_attempt"] = 0
        message = FakeMessage()
        self._run_with_database_failure(message)
        self.assertEqual(message.outcome, "requeue",
                         "a counter of 0 is a first attempt, not an exhausted one")
        carried = json.loads(message.requeued_bodies[0])
        self.assertEqual(carried["_rr_attempt"], 1)

    def test_a_nonsense_counter_does_not_bypass_the_ceiling(self):
        """A message can carry any value at all; it arrives from the queue."""
        import lab.management.commands.consume_engine_results as consumer

        for bogus in ("not-a-number", -3, None, 1.5, [1]):
            self.payload["_rr_attempt"] = bogus
            message = FakeMessage()
            self._run_with_database_failure(message)
            self.assertEqual(message.outcome, "requeue",
                             f"{bogus!r} should be treated as a fresh attempt")
            del message.requeued_bodies[:]

    def test_the_ceiling_is_configurable_and_has_a_documented_default(self):
        """A constant nobody can raise is a cap the project forbids. The default has
        to exist so the tool works with no configuration at all."""
        import importlib

        import lab.management.commands.consume_engine_results as consumer

        self.assertGreater(consumer.RESULT_MAX_ATTEMPTS, 0)
        self.assertGreater(consumer.RESULT_RETRY_BASE_SECONDS, 0)

        for env, value, attribute in (
            ("RR_ENGINE_RESULT_MAX_ATTEMPTS", "9", "RESULT_MAX_ATTEMPTS"),
            ("RR_ENGINE_RESULT_RETRY_BASE_SECONDS", "0.25", "RESULT_RETRY_BASE_SECONDS"),
        ):
            with patch.dict("os.environ", {env: value}):
                reloaded = importlib.reload(consumer)
                self.assertEqual(getattr(reloaded, attribute), float(value)
                                 if "." in value else int(value))
        importlib.reload(consumer)

    def test_an_undecodable_body_is_reported_instead_of_vanishing(self):
        """A10-06: `_decode` returned `None` and wrote nothing anywhere, so a corrupt
        message disappeared — the delivery was then rejected without a trace."""
        import json

        message = FakeMessage()
        with self.assertLogs("lab.engine_broker", level="ERROR") as captured:
            self.assertIsNone(Command._decode(b"{not json"))
        joined = "\n".join(captured.output)
        self.assertIn("engine_result_undecodable", joined)
        self.assertIn("error_type=", joined)

        # And the body itself must not land in the log: it is the engine's payload.
        # The bytes must be *undecodable* for this to mean anything — a valid JSON
        # body logs nothing, so asserting on it proved nothing.
        with self.assertLogs("lab.engine_broker", level="ERROR") as captured:
            Command._decode(b'{"secret": "payload-bytes"')   # truncated -> invalid
        joined = "\n".join(captured.output)
        self.assertIn("engine_result_undecodable", joined)
        self.assertNotIn("payload-bytes", joined,
                         "the engine's payload must never reach the log")

    def test_the_bytes_of_the_body_are_counted_instead(self):
        with self.assertLogs("lab.engine_broker", level="ERROR") as captured:
            Command._decode(b"x" * 42)
        self.assertIn("bytes=42", "\n".join(captured.output))
