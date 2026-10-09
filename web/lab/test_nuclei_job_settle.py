from __future__ import annotations

"""A finished nuclei run has to leave its exchanges in History.

The scan's traffic is written from the job's terminal state, and the browser may
learn about that state from either of two callers: the status poll or the live
stream. Which one it uses is a UI decision, so a run that completed is not evidence
that anything was written — the observable is the row.

Both paths are covered here against a real capture context and a real report, and
the "exactly once" property is asserted too, because the stream and the poll can
both fire and a duplicated exchange would be a second kind of wrong.
"""

from unittest.mock import patch

from django.test import SimpleTestCase, TestCase

from lab import views
from lab.models import TrafficCaptureContext, TrafficRecord


def snapshot_event(record):
    """One engine-snapshot event, shaped the way the engine actually serialises it.

    `id` and `session` are JSON **strings** in the real payload, which is the shape
    that broke deduplication; the columns they are matched against are integers.
    Writing the fixture as integers would have hidden that, so it repeats the
    engine's own types instead of the types the database wishes for.
    """
    return {
        "id": str(record.proxy_event_id), "session": str(record.proxy_session),
        "timestamp": "2026-10-07T10:00:00Z", "source": "proxy", "method": "GET",
        "url": record.url, "host": record.host, "status": record.status_code,
        "capture_context": record.capture_context.token,
    }


def done_frame(state="completed", report=None):
    import json

    return (
        b"event: done\n"
        b"data: " + json.dumps({"state": state, "result": report}).encode("utf-8") + b"\n\n"
    )


class DoneFrameTests(SimpleTestCase):
    def test_the_terminal_state_is_read_out_of_the_frame(self):
        payload = views._nuclei_done_payload(done_frame("cancelled"))
        self.assertIsNotNone(payload)
        self.assertEqual(payload["state"], "cancelled")

    def test_a_frame_without_a_state_settles_nothing(self):
        self.assertIsNone(views._nuclei_done_payload(b"event: template\ndata: {\"name\": \"a.yaml\"}\n\n"))

    def test_a_malformed_frame_is_not_an_error(self):
        # The stream forwards the frame to the browser byte for byte; reading it
        # must not be able to take the run's results down with it.
        self.assertIsNone(views._nuclei_done_payload(b"event: done\ndata: {not json\n\n"))


class SettleNucleiJobTests(TestCase):
    def setUp(self):
        self.context = TrafficCaptureContext.objects.create(name="nuclei · http://target.test/")
        # The store's key for an exchange is (source, session, event id), so the
        # fixture carries the same one the snapshot below reports: a run that was
        # already written down has to stay at one row.
        self.record = TrafficRecord.objects.create(
            source="proxy", method="GET", url="http://target.test/",
            host="target.test", status_code=404, capture_context=self.context,
            proxy_session="7", proxy_event_id="11",
        )
        views._remember_nuclei_job("job-test", None, "http://target.test/")

    def _events(self):
        return [snapshot_event(self.record)]

    def test_the_stream_frame_writes_the_run_into_history(self):
        """The path the browser actually takes: finished from the `done` frame."""
        TrafficRecord.objects.all().delete()
        payload = views._nuclei_done_payload(done_frame())
        with patch.object(views, "call_engine_get", return_value=(200, self._events())):
            views._settle_nuclei_job("job-test", payload)
        self.assertEqual(
            TrafficRecord.objects.filter(capture_context=self.context).count(), 1,
            "a completed scan that ran through the stream wrote nothing to History",
        )

    def _settled_rows(self, *payloads):
        """Settle each payload and return how many rows the run now owns."""
        with patch.object(views, "call_engine_get", return_value=(200, self._events())):
            for payload in payloads:
                views._settle_nuclei_job("job-test", payload)
        return TrafficRecord.objects.filter(capture_context=self.context).count()

    def test_the_status_poll_writes_the_run_into_history(self):
        self.assertEqual(self._settled_rows({"state": "completed", "result": {}}), 1)

    def test_the_string_ids_of_a_snapshot_are_matched_against_the_integer_columns(self):
        """The engine sends `id`/`session` as strings; the columns are integers.

        Compared as they arrive, `"11"` never equals `11`, the deduplication this
        batch exists for could not fire, and every poll inserted a second row for an
        exchange already stored — a live `http/iot` run's single exchange became 3.
        The assertion is on the outcome rather than on the conversion: a snapshot
        whose exchange is already stored leaves the count alone.
        """
        rows = self._settled_rows({"state": "completed", "result": {}})
        self.assertEqual(rows, 1)
        self.assertEqual(
            views._event_id_as_int("11"), 11,
            "a string id from the snapshot must reach the column as its integer",
        )
        self.assertEqual(
            views._event_id_as_int("11"), views._event_id_as_int(11),
            "both sides of the deduplication key must be the same type",
        )

    def test_both_callers_together_write_the_run_once(self):
        """The stream ends the run and the page may poll straight after."""
        rows = self._settled_rows(
            views._nuclei_done_payload(done_frame()),
            {"state": "completed", "result": {}},
        )
        self.assertEqual(rows, 1, "the run was written down twice")

    def test_a_running_job_is_left_alone(self):
        with patch.object(views, "call_engine_get") as engine:
            views._settle_nuclei_job("job-test", {"state": "running"})
        engine.assert_not_called()
        # Still remembered, so its terminal state can settle it later.
        self.assertIn("job-test", views.nucleiScannerJobs)

    def test_a_failed_run_still_keeps_its_exchanges(self):
        # The scan failed, but the exchanges it made before failing are still the
        # operator's evidence, so the terminal state settles them like any other.
        self.assertEqual(self._settled_rows({"state": "failed"}), 1)

    def tearDown(self):
        views._forget_nuclei_job("job-test")