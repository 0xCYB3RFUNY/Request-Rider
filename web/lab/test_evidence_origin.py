"""A01-02 (HIGH) — an evidence row did not say where it came from.

`persist_proxy_history` was the single ingest path for both the engine's traffic poll and
`POST /api/traffic/save`, so a row planted by any local caller looked exactly like a
captured exchange: same shape, same `source`, and it rode the project export with nothing
to tell the two apart. The product of this tool is evidence, and evidence without
provenance is a claim.

The forgery itself is still possible — a local process is outside the single-operator
threat model, and the origin middleware already refuses the cross-site case — so what
these tests pin is that it is now **visible** rather than indistinguishable. That is what
an evidence product owes its reader.
"""

from django.test import TestCase

from lab.models import TrafficRecord
from lab.views import history_item, persist_proxy_history


def _event(url="https://shop.acme.test/a", event_id=1, session=7, source="proxy"):
    return {
        "id": event_id,
        "session": session,
        "url": url,
        "method": "GET",
        "status": 200,
        "source": source,
        "source_ip": "203.0.113.9",
        "request_headers": {"Host": "shop.acme.test"},
        "response_headers": {"Content-Type": "text/html"},
        "response_body": "hello",
    }


class EvidenceOriginTests(TestCase):
    def test_the_engine_poll_records_a_capture(self) -> None:
        persist_proxy_history([_event()], None, origin="engine_capture")
        self.assertEqual(TrafficRecord.objects.get().origin, "engine_capture")

    def test_a_client_supplied_row_says_so_by_default(self) -> None:
        """The conservative default, so a call site added later and left undeclared is
        marked as client-supplied rather than quietly acquiring a capture's authority."""
        persist_proxy_history([_event(event_id=2)])
        self.assertEqual(TrafficRecord.objects.get().origin, "client_supplied")

    def test_the_payload_cannot_declare_its_own_origin(self) -> None:
        """A forged row must not be able to claim it came from the engine."""
        event = _event(event_id=3)
        event["origin"] = "engine_capture"
        persist_proxy_history([event], None, origin="client_supplied")
        self.assertEqual(TrafficRecord.objects.get().origin, "client_supplied")

    def test_the_serializer_carries_the_field(self) -> None:
        """An evidence field nobody can read is not an evidence field."""
        persist_proxy_history([_event(event_id=4)], None, origin="engine_capture")
        record = TrafficRecord.objects.get()
        self.assertEqual(history_item(record)["origin"], "engine_capture")
        self.assertEqual(
            history_item(TrafficRecord(origin=None, url="x"))["origin"],
            "client_supplied",
            "a row written before the field existed must not read as blank",
        )

    def test_the_bulk_path_keeps_the_origin(self) -> None:
        """`persist_proxy_history` writes through `bulk_create`, which bypasses the
        model's default when a value is passed — so this is a separate path from the
        single-row one and has to be its own assertion."""
        persist_proxy_history(
            [_event(event_id=10, session=1), _event(event_id=11, session=1, url="https://shop.acme.test/b")],
            None,
            origin="engine_capture",
        )
        origins = set(TrafficRecord.objects.values_list("origin", flat=True))
        self.assertEqual(origins, {"engine_capture"})

    def test_origin_survives_a_redelivery_of_the_same_event(self) -> None:
        """The deduplication path must not restamp a row as if a second capture happened.
        `ignore_conflicts`/existing-key lookup means the first origin stands."""
        persist_proxy_history([_event(event_id=20)], None, origin="engine_capture")
        persist_proxy_history([_event(event_id=20)], None, origin="client_supplied")
        self.assertEqual(TrafficRecord.objects.count(), 1)
        self.assertEqual(TrafficRecord.objects.get().origin, "engine_capture")


class HistoryImportOriginTests(TestCase):
    def test_an_imported_row_is_client_supplied_and_cannot_say_otherwise(self) -> None:
        from django.test import Client

        payload = {
            "items": [{
                "url": "https://evil.example/x",
                "status": 200,
                "response_body": "planted",
                "origin": "engine_capture",
            }]
        }
        response = Client().post(
            "/api/history/import",
            data=__import__("json").dumps(payload),
            content_type="application/json",
        )
        self.assertIn(response.status_code, (200, 201))
        record = TrafficRecord.objects.get(url="https://evil.example/x")
        self.assertEqual(record.origin, "client_supplied",
                         "a history import is client-supplied by definition")


class ViewWiringOriginTests(TestCase):
    """The wiring, not the helper.

    Every test above calls `persist_proxy_history` directly, so they all pass with the
    real view call sites undeclared — and the mutation that deleted
    `origin="engine_capture"` from the traffic poll went through 7 green tests. A field
    nobody asserts at the boundary is a field the next refactor removes. These go
    through the actual endpoints with the engine replaced.
    """

    def _engine_event(self, event_id=1, session=7):
        return [_event(event_id=event_id, session=session)]

    def test_the_traffic_poll_records_a_capture(self) -> None:
        from unittest.mock import patch

        with patch("lab.views.call_engine_get", return_value=(200, self._engine_event())):
            response = self.client.get("/api/traffic")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(TrafficRecord.objects.get().origin, "engine_capture",
                         "the poll is the engine's own capture and must say so")

    def test_saving_a_row_from_the_ui_records_a_client_supplied_body(self) -> None:
        import json

        response = self.client.post(
            "/api/traffic/save",
            data=json.dumps({"items": [self._engine_event(event_id=2)[0]]}),
            content_type="application/json",
        )
        self.assertIn(response.status_code, (200, 201))
        self.assertEqual(TrafficRecord.objects.get().origin, "client_supplied")

    def test_both_paths_can_be_told_apart_in_one_database(self) -> None:
        """The whole point: two rows, identical shape, distinguishable provenance."""
        import json
        from unittest.mock import patch

        with patch("lab.views.call_engine_get",
                   return_value=(200, self._engine_event(event_id=30, session=1))):
            self.client.get("/api/traffic")
        self.client.post(
            "/api/traffic/save",
            data=json.dumps({"items": [self._engine_event(event_id=31, session=1)[0]]}),
            content_type="application/json",
        )

        origins = dict(
            TrafficRecord.objects.values_list("proxy_event_id", "origin")
        )
        self.assertEqual(origins, {30: "engine_capture", 31: "client_supplied"})

    def test_the_history_endpoint_exposes_the_field(self) -> None:
        """If the field never reaches the API, an analyst cannot see it at all.

        History lists proxy traffic only when it is linked to a capture context — that
        filter is existing product behaviour, not something this fix touches — so the
        row here is linked on purpose. Without the context the row is correctly absent
        and the test would pass for the wrong reason.
        """
        from unittest.mock import patch

        from lab.models import TrafficCaptureContext

        context = TrafficCaptureContext.objects.create(name="Linked evidence capture")

        with patch("lab.views.call_engine_get", return_value=(200, [])):
            response = self.client.get("/api/history")
        self.assertEqual(response.status_code, 200)

        persist_proxy_history(
            [_event(event_id=40, session=9) | {"capture_context": context.token}],
            None,
            origin="engine_capture",
        )
        with patch("lab.views.call_engine_get", return_value=(200, [])):
            response = self.client.get("/api/history")
        rows = response.json()["items"]
        self.assertTrue(rows, f"the linked row did not reach History: {response.content[:200]}")
        self.assertEqual(rows[0]["origin"], "engine_capture")
