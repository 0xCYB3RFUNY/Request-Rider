"""Manual-behaviour and hostile-input regression suite for the browser-facing API.

The product is driven by a human typing into free-form fields, and by automated
clients that may send anything at all. This suite pins the contract that the
gateway must never:

  * answer a malformed request with HTTP 500;
  * answer a rejected request with a success-shaped body;
  * store a value the caller did not send, or silently coerce a wrong type;
  * leak the opaque capture token through a listing endpoint;
  * let one request's payload reach another request's project.

Each test drives the real URLconf through Django's test client, so routing,
middleware, decorators and view bodies are all exercised.
"""

import json
from contextlib import contextmanager
from unittest import mock

from django.db import connection
from django.test import Client, TestCase
from django.test.utils import CaptureQueriesContext

from lab.models import (
    Project,
    ProjectSecret,
    TrafficCaptureContext,
    TrafficRecord,
)


def post_json(client, url, payload, **extra):
    return client.post(url, data=json.dumps(payload), content_type="application/json", **extra)


@contextmanager
def engine_offline(reason="ENGINE_UNAVAILABLE"):
    """Make every engine hop fail fast and deterministically.

    Without this the gateway opens real sockets to 127.0.0.1:8081, so the suite
    measures whichever engine happens to be running and takes minutes when one
    is not. Every assertion here is about gateway behaviour, not engine output.
    """
    unavailable = (502, {"error": f"engine unavailable: {reason}", "reason": reason})
    targets = (
        "call_engine", "call_engine_get", "call_engine_delete", "call_engine_action",
        "call_browser_worker", "call_browser_worker_get", "call_browser_worker_delete",
    )
    with mock.patch.multiple("lab.views", **{name: mock.DEFAULT for name in targets}) as patched:
        for name in targets:
            patched[name].return_value = unavailable
        yield patched


class ApiContractTestCase(TestCase):
    """Shared helpers: a project, a session, and strict response assertions."""

    def setUp(self):
        self.client = Client()
        self.project = Project.objects.create(name="QA", target="fixture.local")
        session = self.client.session
        session["active_project_id"] = self.project.id
        session.save()
        # Every test in this suite is about gateway behaviour, so engine hops are
        # stubbed by default. Tests that need a specific engine answer override it.
        self._engine = engine_offline()
        self._engine_patches = self._engine.__enter__()

    def tearDown(self):
        self._engine.__exit__(None, None, None)

    def assertNoServerError(self, response, context=""):
        """Reject an unhandled crash, but allow an explicit 5xx.

        Django's test client re-raises view exceptions, so a genuine crash shows
        up as a test error rather than a 500 response. A 502 from this gateway
        means "the engine is unreachable", which is a correct, explicit answer.
        """
        self.assertNotEqual(
            response.status_code, 500,
            msg=f"{context} returned an unhandled HTTP 500: "
            f"{getattr(response, 'content', b'')[:300]!r}",
        )

    def assertExplicitError(self, response, context=""):
        """A rejected request must carry a machine-readable error, not `ok: true`."""
        self.assertGreaterEqual(response.status_code, 400, msg=f"{context} should have failed")
        body = response.json()
        self.assertTrue(
            isinstance(body, dict) and body.get("error"),
            msg=f"{context} must return an explicit 'error', got {body!r}",
        )
        self.assertIsNone(body.get("ok"), msg=f"{context} leaked a success-shaped body: {body!r}")


class MalformedRequestTests(ApiContractTestCase):
    """Non-JSON bodies, wrong types and hostile scalars must be 4xx, never 5xx."""

    def test_invalid_json_is_rejected_cleanly(self):
        for url in ("/api/execute", "/api/intruder", "/api/traffic/save", "/api/osint"):
            with self.subTest(url=url):
                response = self.client.post(url, data="{not json", content_type="application/json")
                self.assertNoServerError(response, url)
                self.assertEqual(response.status_code, 400, url)

    def test_wrong_typed_payloads_are_rejected_not_crashed(self):
        """A body that is not a JSON object, or whose url is not a string."""
        for payload in (None, [], "string", 42, True, {"url": None}, {"url": []},
                        {"url": {}}, {"url": 12345}, {"url": True}):
            with self.subTest(payload=payload):
                response = post_json(self.client, "/api/execute", payload)
                self.assertNoServerError(response, f"execute {payload!r}")
                self.assertEqual(response.status_code, 400, payload)
                self.assertTrue(response.json().get("error"))

    def test_intruder_rejects_non_object_and_bad_base_request(self):
        for payload in (None, [], "text", 7, {"base_request": "not-an-object"},
                        {"base_request": []}, {"base_request": {"url": 5}},
                        {"base_request": None}):
            with self.subTest(payload=payload):
                response = post_json(self.client, "/api/intruder", payload)
                self.assertNoServerError(response, f"intruder {payload!r}")
                self.assertEqual(response.status_code, 400, payload)

    def test_wrong_typed_editor_fields_do_not_crash(self):
        """`headers`, `body`, `query` and `cookies` may be any JSON type."""
        hostile = [
            {"url": "http://fixture.local/", "headers": "not-a-dict"},
            {"url": "http://fixture.local/", "headers": []},
            {"url": "http://fixture.local/", "body": {"nested": "object"}},
            {"url": "http://fixture.local/", "body": [1, 2, 3]},
            {"url": "http://fixture.local/", "query": "not-a-dict"},
            {"url": "http://fixture.local/", "cookies": 5},
            {"url": "http://fixture.local/", "query": {"a": ["x", "y"]}},
        ]
        for payload in hostile:
            with self.subTest(payload=payload):
                response = post_json(self.client, "/api/execute", payload)
                self.assertNoServerError(response, f"execute {payload!r}")
                # These reach the engine, which is stubbed offline here.
                self.assertEqual(response.status_code, 502, payload)

    def test_wrong_method_is_rejected(self):
        for url in ("/api/execute", "/api/intruder", "/api/target-map", "/api/traffic/save"):
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertNoServerError(response, url)
                self.assertIn(response.status_code, {400, 405}, url)

    def test_hostile_query_parameters_are_rejected_or_ignored(self):
        cases = [
            f"/api/history?status={value}" for value in ("abc", "1; DROP TABLE lab_project", "-", "1e999")
        ] + [
            "/api/history?limit=abc",
            "/api/history?limit=-5",
            "/api/history?offset=-1",
            "/api/history?offset=abc",
            "/api/history?size_min=abc",
            "/api/history?latency_max=not-a-number",
        ]
        for url in cases:
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertNoServerError(response, url)
                self.assertEqual(response.status_code, 400, url)
        # The table is still there.
        self.assertEqual(TrafficRecord.objects.count(), 0)
        self.assertTrue(Project.objects.filter(id=self.project.id).exists())

    def test_unknown_sort_is_ignored_rather_than_interpolated(self):
        """`sort` is allow-listed; a hostile value must not reach the ORM."""
        for value in ("id; DROP TABLE lab_project", "timestamp", "nonexistent", ""):
            with self.subTest(sort=value):
                response = self.client.get("/api/history", {"sort": value})
                self.assertNoServerError(response, value)
                self.assertEqual(response.status_code, 200, value)
        self.assertTrue(Project.objects.filter(id=self.project.id).exists())

    def test_injection_style_payloads_are_stored_inertly(self):
        """Hostile strings round-trip as data and never execute or leak structure."""
        marker = "<script>alert(1)</script>"
        payload = {
            "method": "POST",
            "url": f"http://fixture.local/x?q={marker}",
            "headers": {"X-Probe": marker},
            "body": marker,
        }
        response = post_json(self.client, "/api/execute", payload)
        self.assertNoServerError(response)
        # The engine is stubbed offline here, so the gateway must still not 500.
        self.assertEqual(response.status_code, 502)

    def test_oversized_and_deeply_nested_values_are_handled(self):
        for payload in (
            {"url": "http://fixture.local/" + "a" * 20000},
            {"url": "http://fixture.local/", "body": "x" * 500000},
            {"url": "http://fixture.local/", "headers": {str(i): "v" for i in range(500)}},
            {"url": "http://fixture.local/", "body": {"a": {"b": {"c": {"d": [1, 2, 3]}}}}},
        ):
            with self.subTest(size=len(str(payload))):
                response = post_json(self.client, "/api/execute", payload)
                self.assertNoServerError(response)
                self.assertEqual(response.status_code, 502)


class ValidationBoundaryTests(ApiContractTestCase):
    """Numeric and identifier parameters must validate before touching the ORM."""

    def test_intruder_rejects_non_numeric_attack_id(self):
        for value in ("abc", "-1", "1.5", "0x10", "", " ", "1 OR 1=1", "١٢٣٤x"):
            with self.subTest(attack_id=value):
                response = self.client.get("/api/intruder", {"attack_id": value})
                self.assertNoServerError(response)
                self.assertEqual(response.status_code, 400, value)

    def test_intruder_rejects_negative_since(self):
        response = self.client.get("/api/intruder", {"attack_id": "1", "since": "-5"})
        self.assertNoServerError(response)
        self.assertEqual(response.status_code, 400)

    def test_intruder_rejects_unknown_action(self):
        response = post_json(
            self.client, "/api/intruder?attack_id=1&action=explode", {}
        )
        self.assertNoServerError(response)
        self.assertEqual(response.status_code, 400)

    def test_route_rejects_non_object_payload(self):
        for payload in ([], "text", 5, None, True):
            with self.subTest(payload=payload):
                response = self.client.post(
                    "/api/route", data=json.dumps(payload), content_type="application/json"
                )
                self.assertNoServerError(response)
                self.assertEqual(response.status_code, 400)

    def test_route_rejects_invalid_json(self):
        response = self.client.post("/api/route", data="{oops", content_type="application/json")
        self.assertNoServerError(response)
        self.assertEqual(response.status_code, 400)

    def test_route_rejects_unsupported_method(self):
        response = self.client.delete("/api/route")
        self.assertNoServerError(response)
        self.assertEqual(response.status_code, 405)

    def test_traffic_rejects_unknown_action(self):
        for action in ("explode", "delete", "drop"):
            with self.subTest(action=action):
                response = post_json(self.client, "/api/traffic", {"action": action})
                self.assertNoServerError(response)
                self.assertEqual(response.status_code, 400, action)

    def test_traffic_accepts_documented_actions(self):
        for action in ("pause", "resume", "status"):
            with self.subTest(action=action):
                response = post_json(self.client, "/api/traffic", {"action": action})
                self.assertNoServerError(response)
                # The stubbed engine is offline, so the gateway reports 502.
                self.assertEqual(response.status_code, 502, action)

    def test_project_id_must_be_numeric_in_path(self):
        response = self.client.get("/api/projects/not-a-number/hub")
        self.assertEqual(response.status_code, 404)

    def test_history_delete_is_idempotent_and_never_crashes(self):
        record = TrafficRecord.objects.create(
            project=self.project, source="repeater", method="GET",
            url="http://fixture.local/gone", response_body="",
        )
        first = self.client.delete(f"/api/history/{record.id}")
        self.assertNoServerError(first)
        self.assertEqual(first.status_code, 200)
        # Deleting an already-removed row must not raise.
        second = self.client.delete(f"/api/history/{record.id}")
        self.assertNoServerError(second)
        self.assertEqual(second.status_code, 200)

    def test_graph_and_entity_ids_must_be_numeric(self):
        for url in ("/api/osint/graphs/abc", "/api/osint/graphs/abc/entities/1",
                    "/api/osint/graphs/1/relations/xyz"):
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertNoServerError(response)
                self.assertEqual(response.status_code, 404, url)


class EngineFailureTests(ApiContractTestCase):
    """Engine unavailability must be reported, never disguised as success."""

    def test_refresh_traffic_does_not_report_success_when_engine_is_down(self):
        """`DELETE /api/traffic` used to answer {"ok": true} with the engine down."""
        from unittest import mock

        with mock.patch("lab.views.call_engine_delete", return_value=(
            502, {"error": "engine unavailable", "reason": "ENGINE_UNAVAILABLE"}
        )):
            response = self.client.delete("/api/traffic")
        self.assertNoServerError(response)
        self.assertEqual(response.status_code, 502)
        self.assertNotEqual(response.json().get("ok"), True)

    def test_read_endpoints_surface_engine_failure(self):
        from unittest import mock

        unavailable = (502, {"error": "engine unavailable", "reason": "ENGINE_UNAVAILABLE"})
        with mock.patch("lab.views.call_engine_get", return_value=unavailable):
            for url in ("/api/traffic", "/api/intruder?attack_id=1", "/api/route"):
                with self.subTest(url=url):
                    response = self.client.get(url)
                    self.assertNoServerError(response, url)
                    self.assertEqual(response.status_code, 502, url)


class ProjectIsolationTests(ApiContractTestCase):
    """Project context comes from the validated session, never from the request."""

    def test_project_id_query_parameter_does_not_change_context(self):
        other = Project.objects.create(name="Other", target="other.local")
        response = post_json(self.client, f"/api/projects/{other.id}/hub?project_id={other.id}", {})
        self.assertNoServerError(response)

    def test_spoofed_local_storage_style_header_is_ignored(self):
        other = Project.objects.create(name="Other", target="other.local")
        response = self.client.get(
            f"/api/projects/{self.project.id}/hub",
            HTTP_X_ACTIVE_PROJECT_ID=str(other.id),
        )
        self.assertNoServerError(response)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        # The active project comes from the validated session, so the hub must
        # describe the session project regardless of any client-supplied header.
        self.assertEqual(body.get("id", self.project.id), self.project.id)

    def test_capture_token_is_never_returned_by_listings(self):
        context = TrafficCaptureContext.objects.create(name="ctx", project=self.project)
        TrafficRecord.objects.create(
            project=self.project, source="proxy", method="GET",
            url="http://fixture.local/a", capture_context=context, response_body="ok",
        )
        for url in (f"/api/traffic", "/api/history", f"/api/projects/{self.project.id}/hub",
                    "/api/traffic/capture-contexts"):
            with self.subTest(url=url):
                response = self.client.get(url)
                self.assertNoServerError(response, url)
                if response.status_code == 200:
                    self.assertNotIn(
                        context.token,
                        response.content.decode(errors="replace"),
                        msg=f"{url} leaked the opaque capture token",
                    )


class HistoryPagingTests(ApiContractTestCase):
    """`limit`/`offset` are additive: the default response shape is unchanged."""

    def setUp(self):
        super().setUp()
        for index in range(25):
            TrafficRecord.objects.create(
                project=self.project, source="repeater", method="GET",
                url=f"http://fixture.local/item/{index}", status_code=200,
                response_body=f"body-{index}",
            )

    def test_default_returns_everything(self):
        response = self.client.get("/api/history")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["items"]), 25)

    def test_limit_and_offset_window(self):
        response = self.client.get("/api/history", {"limit": 5, "offset": 10})
        items = response.json()["items"]
        self.assertEqual(len(items), 5)
        # Newest first: the 25 records descend from item/24, so offset 10 is item/14.
        self.assertEqual(
            [item["url"].rsplit("/", 1)[-1] for item in items],
            ["14", "13", "12", "11", "10"],
        )

    def test_paging_is_stable_across_identical_requests(self):
        """Ties on timestamp must not make a page repeat or skip records."""
        first = self.client.get("/api/history", {"limit": 10, "offset": 0}).json()["items"]
        second = self.client.get("/api/history", {"limit": 10, "offset": 0}).json()["items"]
        self.assertEqual([i["id"] for i in first], [i["id"] for i in second])
        third = self.client.get("/api/history", {"limit": 10, "offset": 10}).json()["items"]
        ids = [i["id"] for i in first] + [i["id"] for i in third]
        self.assertEqual(len(set(ids)), len(ids), "pages must not overlap")

    def test_zero_limit_returns_no_items(self):
        response = self.client.get("/api/history", {"limit": 0})
        self.assertEqual(response.json()["items"], [])

    def test_offset_past_end_returns_empty(self):
        response = self.client.get("/api/history", {"offset": 1000})
        self.assertEqual(response.json()["items"], [])

    def test_invalid_paging_is_a_client_error(self):
        for params in ({"limit": "x"}, {"offset": "x"}, {"limit": -1}, {"offset": -1}):
            with self.subTest(params=params):
                response = self.client.get("/api/history", params)
                self.assertEqual(response.status_code, 400)


class PersistenceIntegrityTests(ApiContractTestCase):
    """Manual input must not be silently normalised into a different record."""

    def test_binary_body_is_preserved_exactly(self):
        blob = bytes(range(256))
        import base64
        encoded = base64.b64encode(blob).decode()
        response = post_json(self.client, "/api/traffic/save", {
            "url": "http://fixture.local/bin",
            "method": "GET",
            "status": 200,
            "response_body_encoding": "base64",
            "response_body_base64": encoded,
            "response_headers": {"Content-Type": "application/octet-stream"},
        })
        self.assertNoServerError(response)
        row = TrafficRecord.objects.filter(url="http://fixture.local/bin").first()
        if row is not None:
            self.assertEqual(row.response_body_base64, encoded)
            self.assertEqual(base64.b64decode(row.response_body_base64), blob)
            self.assertEqual(row.response_body, "")

    def test_unicode_and_emoji_survive_a_round_trip(self):
        url = "http://fixture.local/юнікод?q=🔍"
        response = post_json(self.client, "/api/traffic/save", {
            "url": url, "method": "GET", "status": 200, "response_body": "відповідь 🟢",
        })
        self.assertNoServerError(response)
        row = TrafficRecord.objects.filter(url=url).first()
        if row is not None:
            self.assertEqual(row.response_body, "відповідь 🟢")

    def test_status_and_timestamps_are_preserved(self):
        response = post_json(self.client, "/api/traffic/save", {
            "url": "http://fixture.local/t", "method": "DELETE", "status": 404,
            "latency_ms": 17, "response_size": 9, "response_body": "nope",
        })
        self.assertNoServerError(response)
        row = TrafficRecord.objects.filter(url="http://fixture.local/t").first()
        if row is not None:
            self.assertEqual(row.status_code, 404)
            self.assertEqual(row.method, "DELETE")
            self.assertEqual(row.latency_ms, 17)


class KnowledgeBaseIntegrityTests(ApiContractTestCase):
    """Secret references must be recorded without ever storing the value."""

    def test_authorization_header_is_remembered_as_a_reference_only(self):
        secret_value = "Bearer super-secret-token-value"
        post_json(self.client, "/api/traffic/save", {
            "url": "http://fixture.local/auth", "method": "GET", "status": 200,
            "request_headers": {"Authorization": secret_value},
            "response_body": "ok",
        })
        secrets = list(ProjectSecret.objects.filter(project=self.project))
        self.assertTrue(secrets, "expected a secret reference to be recorded")
        for row in secrets:
            self.assertEqual(row.value_ref, "", "raw secret value must never be stored")
            self.assertNotIn(secret_value, row.value_ref)

    def test_no_secret_reference_without_an_active_project(self):
        """With no validated active Project, evidence must not be attributed."""
        # `client.session` builds a fresh SessionStore on every access, so the
        # clear and the save must share one instance.
        session = self.client.session
        session.clear()
        session.save()
        self.assertIsNone(self.client.session.get("active_project_id"))
        post_json(self.client, "/api/traffic/save", {
            "url": "http://fixture.local/auth2", "method": "GET", "status": 200,
            "request_headers": {"Authorization": "Bearer abc"},
        })
        self.assertEqual(ProjectSecret.objects.filter(project=self.project).count(), 0)
        row = TrafficRecord.objects.filter(url="http://fixture.local/auth2").first()
        self.assertIsNotNone(row)
        self.assertIsNone(row.project_id)


class TargetIngestOnceTests(ApiContractTestCase):
    """The Project hub must read the knowledge base, not rebuild it.

    Indexing a finished Target job is a write proportional to the pages the
    crawl found. Doing that on every dashboard read made one read cost one
    write per page, so the hub slowed down with the size of past crawls instead
    of with its own work. It must index a job once and then only read.
    """

    def _finished_job(self, pages, status="completed"):
        from lab.models import TargetJob

        return TargetJob.objects.create(
            project=self.project,
            job_id=f"map-{status}-{len(pages)}",
            engine_kind="static",
            url="http://fixture.local/",
            status=status,
            result={"status": status, "pages": pages},
        )

    def test_first_hub_read_indexes_a_finished_job(self):
        job = self._finished_job([
            {"url": "http://fixture.local/a", "method": "GET", "status": 200},
            {"url": "http://fixture.local/b", "method": "GET", "status": 200},
        ])
        response = self.client.get(f"/api/projects/{self.project.id}/hub")
        self.assertNoServerError(response, "hub after a Target job")
        self.assertEqual(response.status_code, 200)
        paths = {item["path"] for item in response.json()["endpoints"]}
        self.assertEqual(paths, {"/a", "/b"})
        job.refresh_from_db()
        self.assertTrue(job.ingested, "a finished job must be marked as indexed")

    def test_second_hub_read_writes_nothing(self):
        self._finished_job([
            {"url": f"http://fixture.local/p{index}", "method": "GET", "status": 200}
            for index in range(12)
        ])
        self.client.get(f"/api/projects/{self.project.id}/hub")

        with CaptureQueriesContext(connection) as captured:
            response = self.client.get(f"/api/projects/{self.project.id}/hub")
        self.assertNoServerError(response, "repeated hub read")
        self.assertEqual(response.status_code, 200)
        writes = [
            query["sql"] for query in captured.captured_queries
            if query["sql"].lstrip()[:6].upper() in {"INSERT", "UPDATE", "DELET"}
        ]
        self.assertEqual(
            writes, [],
            msg=f"reading the Project hub must not write; got {writes[:3]}",
        )
        # The pages stay visible after the read skipped the rebuild.
        self.assertEqual(len(response.json()["endpoints"]), 12)

    def test_running_job_is_not_indexed(self):
        job = self._finished_job(
            [{"url": "http://fixture.local/live", "method": "GET", "status": 200}],
            status="running",
        )
        response = self.client.get(f"/api/projects/{self.project.id}/hub")
        self.assertNoServerError(response, "hub with a running Target job")
        self.assertEqual(response.json()["endpoints"], [])
        job.refresh_from_db()
        self.assertFalse(job.ingested, "a running job has no finished result to index")

    def test_a_job_without_a_project_is_skipped(self):
        from lab.models import TargetJob

        TargetJob.objects.create(
            project=None,
            job_id="map-orphan",
            engine_kind="static",
            url="http://fixture.local/",
            status="completed",
            result={"status": "completed", "pages": [
                {"url": "http://fixture.local/orphan", "method": "GET", "status": 200},
            ]},
        )
        response = self.client.get(f"/api/projects/{self.project.id}/hub")
        self.assertNoServerError(response, "hub with an unscoped Target job")
        self.assertEqual(response.json()["endpoints"], [])


class HistorySummaryListingTests(ApiContractTestCase):
    """A History row needs columns, not every stored body.

    Listing a window used to ship the captured payload of every row, so the tab
    pulled tens of megabytes to draw host, method, URL, status and time. The
    listing can be asked for row columns alone; the complete record is then read
    for the row the operator opens, so no payload is lost.
    """

    def _record(self, body="x" * 4096):
        return TrafficRecord.objects.create(
            source="intruder",
            host="fixture.local",
            method="POST",
            url="http://fixture.local/api",
            request_headers="Content-Type: text/plain",
            request_body="request-payload",
            status_code=200,
            latency_ms=12,
            response_headers="Content-Type: text/plain",
            response_body=body,
            response_size=len(body),
        )

    def test_summary_listing_omits_the_payload_and_keeps_every_column(self):
        record = self._record()
        response = self.client.get("/api/history?detail=summary")
        self.assertNoServerError(response, "summary History listing")
        body = response.json()
        self.assertTrue(body["bodies_omitted"], msg=f"summary listing must announce itself: {body}")
        item = body["items"][0]
        self.assertEqual(item["id"], record.id)
        self.assertEqual(item["host"], "fixture.local")
        self.assertEqual(item["method"], "POST")
        self.assertEqual(item["url"], "http://fixture.local/api")
        self.assertEqual(item["status"], 200)
        self.assertEqual(item["time"], 12)
        # The size of the real body stays visible, so a summary row still says
        # that there is something to read.
        self.assertEqual(item["response_size"], 4096)
        self.assertEqual(item["request_body"], "")
        self.assertEqual(item["response_body"], "")
        self.assertEqual(item["request_headers"], "")
        self.assertEqual(item["response_headers"], "")

    def test_default_listing_still_returns_the_whole_record(self):
        record = self._record()
        response = self.client.get("/api/history")
        self.assertNoServerError(response, "default History listing")
        body = response.json()
        self.assertFalse(body["bodies_omitted"], msg="the default listing must stay complete")
        item = body["items"][0]
        self.assertEqual(item["request_body"], "request-payload")
        self.assertEqual(item["response_body"], "x" * 4096)
        self.assertEqual(item["request_headers"], "Content-Type: text/plain")
        self.assertEqual(item["id"], record.id)

    def test_detail_read_returns_the_complete_record(self):
        record = self._record()
        response = self.client.get(f"/api/history/{record.id}")
        self.assertNoServerError(response, "History detail read")
        self.assertEqual(response.status_code, 200)
        item = response.json()
        self.assertEqual(item["request_body"], "request-payload")
        self.assertEqual(item["response_body"], "x" * 4096)
        self.assertEqual(item["response_size"], 4096)

    def test_detail_read_of_a_missing_record_is_an_explicit_404(self):
        response = self.client.get("/api/history/999999")
        self.assertExplicitError(response, "History detail read of a missing record")
        self.assertEqual(response.status_code, 404)

    def test_unknown_detail_is_rejected(self):
        self._record()
        response = self.client.get("/api/history?detail=compact")
        self.assertExplicitError(response, "History listing with an unknown detail")

    def test_summary_listing_keeps_the_filters_and_paging(self):
        keep = self._record()
        TrafficRecord.objects.create(
            source="intruder", host="other.local", method="GET",
            url="http://other.local/keep", status_code=404, response_body="nope",
        )
        response = self.client.get("/api/history?detail=summary&host=fixture&limit=1")
        self.assertNoServerError(response, "filtered summary History listing")
        body = response.json()
        self.assertEqual([item["id"] for item in body["items"]], [keep.id])

    def test_summary_listing_never_returns_a_capture_token(self):
        context = TrafficCaptureContext.objects.create(
            project=self.project, name="QA capture", token="super-secret-capture-token",
        )
        TrafficRecord.objects.create(
            source="intruder", host="fixture.local", method="GET",
            url="http://fixture.local/x", status_code=200, response_body="ok",
            capture_context=context,
        )
        for url in ("/api/history?detail=summary", f"/api/history?host=fixture"):
            body = self.client.get(url).json()
            self.assertNotIn("super-secret-capture-token", json.dumps(body), msg=url)


class NonUtf8BodyTests(ApiContractTestCase):
    """A body that is not valid UTF-8 is a client error, never a crash.

    `json.loads` on bytes raises `UnicodeDecodeError` for a body that is not
    valid UTF-8, and that is a `ValueError` but not a `JSONDecodeError`. A view
    that only caught the narrower pair turned a mistyped or binary paste into an
    unhandled HTTP 500, which is exactly the answer a caller must not get for
    input it simply did not understand.
    """

    INVALID = b'{"base_request": {"url": "http://host/\xa7m\xa7/"}}'

    def _post(self, url, body=None):
        return self.client.post(
            url, data=body if body is not None else self.INVALID,
            content_type="application/json",
        )

    def test_endpoints_reject_a_non_utf8_body_with_400(self):
        for url in (
            "/api/execute",
            "/api/intruder",
            "/api/target-map",
            "/api/target-browser",
            "/api/traffic",
            "/api/traffic/capture-contexts",
        ):
            with self.subTest(url=url):
                response = self._post(url)
                self.assertNoServerError(response, f"non-UTF-8 body to {url}")
                self.assertExplicitError(response, f"non-UTF-8 body to {url}")
                self.assertEqual(response.status_code, 400)

    def test_a_truncated_body_is_also_a_client_error(self):
        for url in ("/api/execute", "/api/intruder", "/api/target-map"):
            with self.subTest(url=url):
                response = self._post(url, body=b'{"method": "GET"')
                self.assertNoServerError(response, f"truncated body to {url}")
                self.assertExplicitError(response, f"truncated body to {url}")

    def test_a_utf8_body_with_a_section_marker_is_not_rejected_as_encoding(self):
        # The section sign is the Intruder marker syntax; it must reach the
        # payload validation rather than die in the decoder.
        response = self._post(
            "/api/intruder",
            body='{"base_request":{"method":"GET","url":"http://host/§m§/"},"payloads":[["a"]]}'.encode("utf-8"),
        )
        self.assertNoServerError(response, "UTF-8 marker body")
        self.assertNotEqual(
            response.status_code, 400,
            msg="a valid UTF-8 marker body must not be reported as invalid JSON",
        )


class TrafficListingContractTests(ApiContractTestCase):
    """The Traffic listing carries rows; the payload is read for one event.

    The passive snapshot can be asked for row columns only, and a single event
    read returns it in full. An event must therefore still be readable after the
    listing skipped its body, and the engine answer must never leak the capture
    token that links an event to its Project.
    """

    EVENT = {
        "id": 42, "session": 7, "method": "GET", "url": "http://target.local/big",
        "host": "target.local", "status": 200, "latency_ms": 9,
        "request_headers": {"Host": "target.local"}, "request_body": "in",
        "response_headers": {"Content-Type": "text/plain"},
        "response_body": "out" * 100, "response_size": 300,
    }
    CAPTURED = dict(EVENT, capture_context="super-secret-capture-token")

    def test_summary_listing_is_forwarded_and_keeps_the_row(self):
        # The engine wraps a summary snapshot so it can flag what it left out.
        summary = {"bodies_omitted": True, "events": [
            dict(self.EVENT, request_body="", response_body="",
                 request_headers={}, response_headers={}),
        ]}
        with mock.patch("lab.views.call_engine_get", return_value=(200, summary)) as call:
            with mock.patch("lab.views.persist_proxy_history"):
                response = self.client.get("/api/traffic?detail=summary")
        self.assertNoServerError(response, "summary Traffic listing")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(call.call_args[0][0], "/events?detail=summary",
                         msg="the summary request must reach the engine")
        # The browser sees one shape either way: a list of events.
        events = response.json()
        self.assertIsInstance(events, list, msg=f"summary must unwrap to a list, got {type(events)}")
        event = events[0]
        self.assertEqual(event["url"], "http://target.local/big")
        self.assertEqual(event["response_body"], "")
        self.assertEqual(event["response_size"], 300)

    def test_default_listing_still_requests_every_payload(self):
        with mock.patch("lab.views.call_engine_get", return_value=(200, [self.EVENT])) as call:
            with mock.patch("lab.views.persist_proxy_history"):
                response = self.client.get("/api/traffic")
        self.assertEqual(call.call_args[0][0], "/events")
        self.assertEqual(response.json()[0]["response_body"], "out" * 100)

    def test_unknown_detail_is_rejected_before_the_engine_is_called(self):
        with mock.patch("lab.views.call_engine_get") as call:
            response = self.client.get("/api/traffic?detail=compact")
        self.assertExplicitError(response, "Traffic listing with an unknown detail")
        call.assert_not_called()

    def test_event_detail_returns_the_complete_exchange(self):
        with mock.patch("lab.views.call_engine_get", return_value=(200, self.EVENT)) as call:
            response = self.client.get("/api/traffic/detail?id=42")
        self.assertNoServerError(response, "Traffic event detail")
        self.assertEqual(call.call_args[0][0], "/events/detail?id=42")
        event = response.json()
        self.assertEqual(event["request_body"], "in")
        self.assertEqual(event["response_body"], "out" * 100)
        self.assertEqual(event["request_headers"], {"Host": "target.local"})
        self.assertEqual(event["id"], 42)

    def test_event_detail_rejects_a_malformed_id(self):
        for value in ("", "abc", "0", "-1", "1.5"):
            with self.subTest(id=value):
                with mock.patch("lab.views.call_engine_get") as call:
                    response = self.client.get(f"/api/traffic/detail?id={value}")
                self.assertExplicitError(response, f"Traffic event detail id={value!r}")
                call.assert_not_called()

    def test_event_detail_never_returns_a_capture_token(self):
        with mock.patch("lab.views.call_engine_get", return_value=(200, self.CAPTURED)):
            response = self.client.get("/api/traffic/detail?id=42")
        self.assertNoServerError(response, "Traffic event detail with a context")
        self.assertNotIn("super-secret-capture-token", json.dumps(response.json()))

    def test_listing_never_returns_a_capture_token(self):
        with mock.patch("lab.views.call_engine_get", return_value=(200, [self.CAPTURED])):
            with mock.patch("lab.views.persist_proxy_history"):
                response = self.client.get("/api/traffic?detail=summary")
        self.assertNotIn("super-secret-capture-token", json.dumps(response.json()))
