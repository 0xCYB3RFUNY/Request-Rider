"""Tests for the Request-Rider MCP server.

What is covered, and why:

* the pure helpers, because the byte windowing and raw-HTTP reconstruction are
  where a silent corruption would live — a body that decodes to something the
  target never sent is worse than no body at all;
* the tool bodies against a stub client, because the mapping from tool arguments
  to gateway query parameters is exactly the part that drifts from the gateway
  silently. The stub records the request, so a renamed parameter fails the test
  rather than returning an empty page forever.

No test here touches the network. The gateway contract these tools depend on is
verified by the Django suite; what is verified here is that this server speaks it.
"""

import asyncio
import base64
import json
import importlib.util
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PATH = os.path.join(_HERE, "server.py")


def _load_module():
    """Import the server module by path; its directory name is not a package name."""
    spec = importlib.util.spec_from_file_location("rr_mcp_server", _PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["rr_mcp_server"] = module
    spec.loader.exec_module(module)
    return module


srv = _load_module()


class StubClient:
    """A recording stand-in for `RRClient`.

    Answers are a queue, so a test can make one tool call see a 200 and the next
    see a 409 without the stub knowing anything about the tool under test.
    """

    def __init__(self, responses=None):
        self.calls = []
        self.responses = list(responses or [])

    def _next(self):
        if self.responses:
            return self.responses.pop(0)
        return 200, {}

    async def gateway(self, method, path, **kwargs):
        self.calls.append({"service": "gateway", "method": method, "path": path, **kwargs})
        return self._next()

    async def engine(self, method, path, **kwargs):
        self.calls.append({"service": "engine", "method": method, "path": path, **kwargs})
        return self._next()

    async def worker(self, method, path, **kwargs):
        self.calls.append({"service": "worker", "method": method, "path": path, **kwargs})
        return self._next()

    async def aclose(self):
        return None


def run(coro):
    return asyncio.run(coro)


def with_client(responses, call):
    """Run `call(client)` against a stub, restoring the module global afterwards."""
    original = srv._client
    stub = StubClient(responses)
    srv._client = stub
    try:
        return run(call(stub)), stub
    finally:
        srv._client = original


# ---------------------------------------------------------------------------
# Raw HTTP parsing and reconstruction
# ---------------------------------------------------------------------------


class RawHttpTests(unittest.TestCase):
    def test_parses_crlf_request_with_host_header(self):
        result = srv.parse_raw_http(
            "GET /admin?x=1 HTTP/1.1\r\nHost: target.example\r\nAccept: */*\r\n\r\n"
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["url"], "http://target.example/admin?x=1")
        self.assertEqual(result["headers"]["Accept"], "*/*")

    def test_parses_escaped_newlines_a_model_actually_writes(self):
        result = srv.parse_raw_http(
            "POST /login HTTP/1.1\\r\\nHost: target.example\\r\\n"
            "Content-Type: application/json\\r\\n\\r\\n{\"user\":\"a\"}"
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["method"], "POST")
        self.assertEqual(result["body"], '{"user":"a"}')
        self.assertEqual(result["headers"]["Content-Type"], "application/json")

    def test_absolute_url_wins_over_host_header(self):
        result = srv.parse_raw_http("GET https://real.example/x HTTP/1.1\r\nHost: decoy\r\n\r\n")
        self.assertEqual(result["url"], "https://real.example/x")

    def test_missing_host_and_relative_target_is_an_error(self):
        result = srv.parse_raw_http("GET /x HTTP/1.1\r\nUser-Agent: t\r\n\r\n")
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "INVALID_ARGUMENT")

    def test_empty_input_is_rejected(self):
        self.assertFalse(srv.parse_raw_http("")["ok"])


class RawReconstructionTests(unittest.TestCase):
    def test_raw_request_carries_method_url_headers_and_body(self):
        raw = srv._raw_request(
            "POST", "https://t/x", {"Content-Type": "application/json"}, b'{"a":1}'
        )
        self.assertTrue(raw.startswith("POST https://t/x HTTP/1.1\r\n"))
        self.assertIn("Content-Type: application/json\r\n", raw)
        self.assertIn("Content-Length: 7\r\n", raw)
        self.assertTrue(raw.endswith('{"a":1}'))

    def test_content_length_is_not_duplicated_when_supplied(self):
        raw = srv._raw_request("GET", "https://t/", {"Content-Length": "99"}, b"")
        self.assertEqual(raw.count("Content-Length"), 1)
        self.assertIn("Content-Length: 99", raw)

    def test_raw_response_has_status_line_and_body(self):
        raw = srv._raw_response(404, {"Server": "nginx"}, b"nope")
        self.assertTrue(raw.startswith("HTTP/1.1 404 Not Found\r\n"))
        self.assertIn("Server: nginx\r\n", raw)
        self.assertTrue(raw.endswith("nope"))

    def test_unknown_status_code_does_not_raise(self):
        self.assertTrue(srv._raw_response(None, {}, b"").startswith("HTTP/1.1 0"))

    def test_repeated_header_is_emitted_once_per_value(self):
        raw = srv._raw_response(200, {"Set-Cookie": ["a=1", "b=2"]}, b"")
        self.assertEqual(raw.count("Set-Cookie:"), 2)


# ---------------------------------------------------------------------------
# Body byte-exactness and context-window protection
# ---------------------------------------------------------------------------


class BodyBytesTests(unittest.TestCase):
    def test_base64_column_wins_over_text_column(self):
        """A binary body must not be taken from the lossy text column."""
        payload = bytes(range(256))
        encoded = base64.b64encode(payload).decode()
        self.assertEqual(srv._body_bytes("corrupted", encoded, "utf8"), payload)

    def test_text_column_is_used_when_there_is_no_base64(self):
        self.assertEqual(srv._body_bytes("héllo", "", "utf8").decode("utf-8"), "héllo")

    def test_base64_marked_body_is_decoded_even_without_the_column(self):
        encoded = base64.b64encode(b"\xff\xfe binary").decode()
        self.assertEqual(srv._body_bytes(encoded, "", "base64"), b"\xff\xfe binary")

    def test_undecodable_base64_falls_back_to_text_rather_than_raising(self):
        self.assertEqual(srv._body_bytes("plain text", "!!!not base64!!!", "utf8"),
                         b"plain text")

    def test_missing_body_is_empty_not_none(self):
        self.assertEqual(srv._body_bytes(None, None, None), b"")


class WindowTests(unittest.TestCase):
    def test_default_window_reports_a_cursor_and_says_it_is_incomplete(self):
        window = srv._window(b"x" * 1000, limit=100)
        self.assertEqual(window["total_bytes"], 1000)
        self.assertEqual(window["returned_bytes"], 100)
        self.assertEqual(window["next_offset"], 100)
        self.assertFalse(window["complete"])
        self.assertIn("continues", window["hint"].lower())

    def test_offset_pages_through_a_body(self):
        first = srv._window(b"abcdefghij", offset=0, length=4, limit=4)
        second = srv._window(b"abcdefghij", offset=first["next_offset"], length=4, limit=4)
        third = srv._window(b"abcdefghij", offset=second["next_offset"], length=4, limit=4)
        self.assertEqual(first["data"] + second["data"] + third["data"], "abcdefghij")
        self.assertTrue(third["complete"])
        self.assertIsNone(third["next_offset"])

    def test_full_body_has_no_cursor(self):
        window = srv._window(b"short", limit=64)
        self.assertTrue(window["complete"])
        self.assertIsNone(window["next_offset"])

    def test_base64_window_is_byte_exact(self):
        payload = bytes(range(256))
        window = srv._window(payload, as_base64=True)
        self.assertEqual(base64.b64decode(window["data"]), payload)

    def test_offset_past_the_end_is_clamped_not_an_error(self):
        window = srv._window(b"abc", offset=99, limit=10)
        self.assertEqual(window["returned_bytes"], 0)
        self.assertTrue(window["complete"])

    def test_requested_length_is_capped_by_limit(self):
        window = srv._window(b"y" * 5000, length=5000, limit=100)
        self.assertEqual(window["returned_bytes"], 100)


# ---------------------------------------------------------------------------
# Intruder markers and "Send to..." placement
# ---------------------------------------------------------------------------


class MarkerTests(unittest.TestCase):
    def test_three_marker_styles_are_supported(self):
        self.assertEqual(srv.build_marker("{{name}}", "id"), "{{id}}")
        self.assertEqual(srv.build_marker("§name§", "id"), "§id§")
        self.assertEqual(srv.build_marker("%name%", "id"), "%id%")
        self.assertEqual(srv.build_marker("mustache", "id"), "{{id}}")
        self.assertEqual(srv.build_marker("sigil", "id"), "§id§")

    def test_marker_goes_on_the_first_query_parameter(self):
        marked, note = srv.insert_marker("https://t/s?a=1&b=2", "https://t/s?a=1&b=2", "",
                                        "{{a}}")
        self.assertIn("a=%7B%7Ba%7D%7D", marked)
        self.assertIn("b=2", marked)
        self.assertIn("'a'", note)

    def test_marker_goes_on_a_form_field_when_there_is_no_query(self):
        marked, note = srv.insert_marker("https://t/l", "https://t/l", "user=a&pass=b", "{{user}}")
        self.assertIn("user=%7B%7Buser%7D%7D", note + marked)
        self.assertIn("pass=b", marked)

    def test_no_parameters_appends_rather_than_failing(self):
        marked, note = srv.insert_marker("https://t/p", "https://t/p", "", "{{x}}")
        self.assertTrue(marked.endswith("{{x}}"))
        self.assertIn("appended", note)

    def test_marked_string_splits_back_into_url_and_body(self):
        marked = "https://t/l?u=%7B%7Bx%7D%7D&pass=1"
        url, body = srv.split_marked(marked, "https://t/l", "pass=1")
        self.assertEqual(body, "pass=1")
        # The marker is percent-encoded in the query, which is what the engine
        # parses back into the literal marker.
        self.assertIn("%7B%7Bx%7D%7D", url)
        self.assertNotIn("pass=1", url)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


class ClampTests(unittest.TestCase):
    def test_non_numeric_falls_back_to_default(self):
        self.assertEqual(srv._clamp("abc", 1, 10, 5), 5)

    def test_bounds_are_applied(self):
        self.assertEqual(srv._clamp(0, 1, 10, 5), 1)
        self.assertEqual(srv._clamp(99, 1, 10, 5), 10)
        self.assertEqual(srv._clamp(7, 1, 10, 5), 7)


class ErrorEnvelopeTests(unittest.TestCase):
    def test_reason_is_preserved_and_hint_added_for_known_codes(self):
        failure = srv._fail("ROUTE_CHANGED", "cancelled")
        self.assertFalse(failure["ok"])
        self.assertEqual(failure["reason"], "ROUTE_CHANGED")
        self.assertIn("re-issue", failure["hint"].lower())

    def test_unknown_reason_gets_no_invented_hint(self):
        failure = srv._fail("SOMETHING_NEW", "boom")
        self.assertNotIn("hint", failure)

    def test_missing_reason_falls_back_rather_than_being_blank(self):
        self.assertEqual(srv._fail("", "boom")["reason"], "UNKNOWN")

    def test_reason_extracted_from_a_gateway_error_body(self):
        reason, message = srv._reason_of(409, {"error": "cancelled", "reason": "ROUTE_CHANGED"})
        self.assertEqual(reason, "ROUTE_CHANGED")
        self.assertEqual(message, "cancelled")


# ---------------------------------------------------------------------------
# Tool bodies against a stub client
# ---------------------------------------------------------------------------


class HistoryToolTests(unittest.TestCase):
    def test_listing_returns_metadata_and_a_cursor(self):
        rows = [{"id": i, "method": "GET", "url": f"https://t/{i}", "status": 200,
                 "response_body": "x" * 5000, "source": "repeater"}
                for i in range(1, 6)]
        result, stub = with_client(
            [(200, {"items": rows, "total": 120})],
            lambda c: srv.history_get_records(limit=5),
        )
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["items"]), 5)
        self.assertEqual(result["next_offset"], 5)
        self.assertEqual(stub.calls[0]["path"], "/api/history")

    def test_source_filter_is_applied_by_this_server(self):
        rows = [{"id": 1, "source": "repeater"}, {"id": 2, "source": "proxy"}]
        result, _ = with_client(
            [(200, {"items": rows, "total": 2})],
            lambda c: srv.history_get_records(source="proxy"),
        )
        self.assertEqual([r["id"] for r in result["items"]], [2])

    def test_filters_reach_the_gateway_as_query_parameters(self):
        _, stub = with_client(
            [(200, {"items": [], "total": 0})],
            lambda c: srv.history_get_records(host="t.example", path="/admin", method="post",
                                             status=401, mime="json", query="token",
                                             latency_min_ms=10, latency_max_ms=900),
        )
        params = stub.calls[0]["params"]
        self.assertEqual(params["host"], "t.example")
        self.assertEqual(params["path"], "/admin")
        self.assertEqual(params["method"], "post")
        self.assertEqual(params["status"], 401)
        self.assertEqual(params["mime"], "json")
        self.assertEqual(params["q"], "token")
        self.assertEqual(params["latency_min"], 10)
        self.assertEqual(params["latency_max"], 900)

    def test_traffic_store_asks_for_the_summary_window(self):
        _, stub = with_client(
            [(200, {"items": [], "total": 0})],
            lambda c: srv.history_get_records(store="traffic"),
        )
        self.assertEqual(stub.calls[0]["path"], "/api/traffic/records")
        self.assertEqual(stub.calls[0]["params"]["detail"], "summary")

    def test_gateway_failure_is_reported_with_its_reason(self):
        result, _ = with_client(
            [(502, {"error": "engine unavailable", "reason": "ENGINE_UNAVAILABLE"})],
            lambda c: srv.history_get_records(),
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "ENGINE_UNAVAILABLE")


class RawTransactionToolTests(unittest.TestCase):
    def _record(self):
        return {
            "id": 42, "timestamp": "2026-10-15T10:00:00Z", "method": "POST",
            "url": "https://t/api?q=1", "host": "t", "status": 200, "time": 123,
            "response_size": 9, "response_content_type": "text/html",
            "request_headers": {"Content-Type": "application/json"},
            "response_headers": {"Server": "nginx"},
            "request_body": '{"a":1}', "request_body_encoding": "utf8",
            "request_body_base64": "", "response_body": "hello",
            "response_body_encoding": "utf8", "response_body_base64": "",
            "tags": [], "notes": "",
        }

    def test_complete_exchange_is_returned_in_wire_form(self):
        result, _ = with_client(
            [(200, self._record())],
            lambda c: srv.history_get_transaction_raw(record_id=42),
        )
        self.assertTrue(result["ok"])
        self.assertTrue(result["raw_request"].startswith("POST https://t/api?q=1 HTTP/1.1"))
        self.assertIn('{"a":1}', result["raw_request"])
        self.assertTrue(result["raw_response"].startswith("HTTP/1.1 200 OK"))
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["latency_ms"], 123)
        self.assertEqual(result["response_body"]["data"], "hello")
        self.assertTrue(result["response_body"]["complete"])

    def test_large_body_is_windowed_with_a_cursor(self):
        record = self._record()
        record["response_body"] = "z" * 5000
        result, _ = with_client(
            [(200, record)],
            lambda c: srv.history_get_transaction_raw(record_id=42, length=100),
        )
        window = result["response_body"]
        self.assertEqual(window["returned_bytes"], 100)
        self.assertEqual(window["next_offset"], 100)
        self.assertFalse(window["complete"])
        self.assertIsNotNone(result["next_call"])

    def test_binary_response_is_flagged_and_returned_as_base64(self):
        record = self._record()
        payload = bytes(range(256))
        record["response_body"] = ""
        record["response_body_base64"] = base64.b64encode(payload).decode()
        record["response_content_type"] = "image/png"
        result, _ = with_client(
            [(200, record)],
            lambda c: srv.history_get_transaction_raw(record_id=42, encoding="base64"),
        )
        self.assertTrue(result["binary_response"])
        self.assertEqual(base64.b64decode(result["response_body"]["data"]), payload)

    def test_missing_record_is_reported_not_silently_empty(self):
        result, _ = with_client(
            [(404, {"error": "history record not found"})],
            lambda c: srv.history_get_transaction_raw(record_id=999),
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "RECORD_NOT_FOUND")

    def test_neither_id_given_is_rejected_before_any_request(self):
        result, stub = with_client([], lambda c: srv.history_get_transaction_raw())
        self.assertFalse(result["ok"])
        self.assertEqual(stub.calls, [])


class ProjectToolTests(unittest.TestCase):
    def test_switching_active_project_posts_the_id(self):
        result, stub = with_client(
            [(200, {"active_project_id": 7, "active_project": {"id": 7, "name": "x"}})],
            lambda c: srv.project_switch_active(project_id=7),
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["active_project_id"], 7)
        self.assertEqual(stub.calls[0]["path"], "/api/project-context")
        self.assertEqual(stub.calls[0]["json_body"], {"project_id": 7})
        self.assertTrue(stub.calls[0]["csrf"])

    def test_clearing_the_binding_sends_null_not_zero(self):
        _, stub = with_client(
            [(200, {"active_project_id": None})],
            lambda c: srv.project_switch_active(project_id=0),
        )
        self.assertIsNone(stub.calls[0]["json_body"]["project_id"])

    def test_create_requires_a_name(self):
        result, stub = with_client([], lambda c: srv.project_create(name=""))
        self.assertFalse(result["ok"])
        self.assertEqual(stub.calls, [])

    def test_create_sends_the_optional_fields_only_when_given(self):
        _, stub = with_client(
            [(201, {"id": 3, "name": "acme"})],
            lambda c: srv.project_create(name="acme", target="https://a.example"),
        )
        body = stub.calls[0]["json_body"]
        self.assertEqual(body["name"], "acme")
        self.assertEqual(body["target"], "https://a.example")
        self.assertNotIn("environment", body)

    def test_hub_without_active_project_says_so(self):
        result, _ = with_client(
            [(200, {"items": [{"id": 1, "name": "a"}]})],
            lambda c: srv.project_get_knowledge_hub(),
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "PROJECT_CONTEXT_REQUIRED")

    def test_hub_reads_the_named_project_when_one_is_given(self):
        _, stub = with_client(
            [(200, {"counts": {}, "findings_by_severity": {}})],
            lambda c: srv.project_get_knowledge_hub(project_id=5),
        )
        self.assertEqual(stub.calls[0]["path"], "/api/projects/5/hub")


class KebabTests(unittest.TestCase):
    def _record(self):
        return {"id": 5, "method": "GET", "url": "https://t/s?a=1", "status": 200,
                "request_headers": {}, "response_headers": {}, "request_body": "",
                "response_body": "ok", "response_body_encoding": "utf8",
                "response_body_base64": "", "request_body_encoding": "utf8",
                "request_body_base64": ""}

    def test_intruder_target_saves_an_attack_with_a_marker(self):
        result, stub = with_client(
            [(200, self._record()), (201, {"id": 11, "name": "saved", "mode": "sniper"})],
            lambda c: srv.kebab_send_to_tool(
                target="intruder", record_id=5, marker_style="{{name}}",
                marker_name="id", payloads=[["1", "2"]],
            ),
        )
        # The tool reads the source record first, then saves.
        self.assertEqual(stub.calls[0]["path"], "/api/history/5")
        self.assertEqual(stub.calls[1]["path"], "/api/intruder/saved")
        base = stub.calls[1]["json_body"]["base_request"]
        self.assertEqual(base["method"], "GET")
        self.assertIn("%7B%7Bid%7D%7D", base["url"])
        self.assertEqual(result["marker"], "{{id}}")

    def test_automation_target_creates_an_inactive_workflow(self):
        result, stub = with_client(
            [(200, self._record()), (201, {"id": 9, "name": "wf", "active": False})],
            lambda c: srv.kebab_send_to_tool(target="automation", record_id=5),
        )
        self.assertTrue(result["ok"])
        body = stub.calls[1]["json_body"]
        self.assertFalse(body["active"])
        self.assertEqual([n["type"] for n in body["nodes"]], ["manual_trigger", "repeater"])

    def test_comparer_states_that_it_cannot_place_a_browser_panel(self):
        result, stub = with_client(
            [(200, self._record())],
            lambda c: srv.kebab_send_to_tool(target="comparer", record_id=5),
        )
        self.assertTrue(result["ok"])
        self.assertIn("browser state", result["note"])
        self.assertEqual(stub.calls[-1]["path"], "/api/history/5")

    def test_unknown_target_is_rejected_before_any_read(self):
        result, stub = with_client([], lambda c: srv.kebab_send_to_tool(target="nowhere"))
        self.assertFalse(result["ok"])
        self.assertEqual(stub.calls, [])

    def test_neither_record_nor_raw_http_is_rejected(self):
        result, _ = with_client([], lambda c: srv.kebab_send_to_tool(target="intruder"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "INVALID_ARGUMENT")


class ScannerToolTests(unittest.TestCase):
    def test_nuclei_not_supported(self):
        result, stub = with_client([], lambda c: srv.scanner_job_status(job_id="n1", kind="nuclei"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "NOT_SUPPORTED")

    def test_active_scan_passes_limits_and_words(self):
        _, stub = with_client(
            [(202, {"job_id": "a1", "state": "running"})],
            lambda c: srv.scanner_active_start(url="https://t", max_pages=50, max_depth=3,
                                               blind_delay_ms=2000, params="id\nuid"),
        )
        body = stub.calls[0]["json_body"]
        self.assertEqual(stub.calls[0]["path"], "/api/scanner/active/jobs")
        self.assertEqual(body["max_pages"], 50)
        self.assertEqual(body["max_depth"], 3)
        self.assertEqual(body["blind_delay_ms"], 2000)
        self.assertEqual(body["params"], "id\nuid")

    def test_active_scan_keeps_unbounded_limits_unbounded(self):
        _, stub = with_client(
            [(202, {"job_id": "a1", "state": "running"})],
            lambda c: srv.scanner_active_start(url="https://t"),
        )
        body = stub.calls[0]["json_body"]
        self.assertEqual(body["max_pages"], 0)
        self.assertEqual(body["max_depth"], -1)

    def test_forgotten_engine_job_says_it_can_no_longer_be_recovered(self):
        result, _ = with_client(
            [(404, {"error": "not found"})],
            lambda c: srv.scanner_job_status(job_id="gone", kind="active"),
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "JOB_NOT_FOUND")
        self.assertIn("re-run", result["hint"].lower())


class IntruderToolTests(unittest.TestCase):
    def test_raw_request_and_single_payload_list_are_normalised(self):
        _, stub = with_client(
            [(202, {"attack_id": 4, "status": "running"})],
            lambda c: srv.intruder_start_attack(
                base_request="GET /x HTTP/1.1\r\nHost: t\r\n\r\n", payloads=["a", "b"],
            ),
        )
        body = stub.calls[0]["json_body"]
        self.assertEqual(stub.calls[0]["path"], "/api/intruder")
        self.assertEqual(body["payloads"], [["a", "b"]])

    def test_empty_payloads_rejected(self):
        result, stub = with_client(
            [], lambda c: srv.intruder_start_attack(base_request="GET / HTTP/1.1\r\nHost: t\r\n\r\n",
                                                    payloads=[])
        )
        self.assertFalse(result["ok"])
        self.assertEqual(stub.calls, [])

    def test_results_are_polled_incrementally(self):
        result, stub = with_client(
            [(200, {"status": "running", "results": [{"payload": "a", "status": 200}],
                    "result_offset": 1})],
            lambda c: srv.intruder_get_attack_results(attack_id=4, since=7),
        )
        self.assertEqual(stub.calls[0]["params"]["since"], 7)
        self.assertEqual(result["result_offset"], 1)
        self.assertFalse(result["complete"])

    def test_completed_attack_is_marked_complete(self):
        result, _ = with_client(
            [(200, {"status": "completed", "results": [], "result_offset": 9})],
            lambda c: srv.intruder_get_attack_results(attack_id=4),
        )
        self.assertTrue(result["complete"])


class TransformToolTests(unittest.TestCase):
    def test_encoding_round_trips(self):
        result = run(srv.data_transform("base64Encode", "hunter2"))
        self.assertEqual(run(srv.data_transform("base64Decode", result["result"]))["result"],
                         "hunter2")

    def test_sha256_matches_the_known_digest(self):
        result = run(srv.data_transform("sha256", "abc"))
        self.assertEqual(result["result"],
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_json_pretty_and_minify_round_trip(self):
        pretty = run(srv.data_transform("jsonPretty", '{"b":2,"a":1}'))
        self.assertIn("\n", pretty["result"])
        minified = run(srv.data_transform("jsonMinify", pretty["result"]))
        self.assertNotIn("\n", minified["result"])

    def test_binary_decode_returns_bytes_in_base64_and_says_so(self):
        encoded = base64.b64encode(bytes([0xFF, 0xFE, 0x00, 0x01])).decode()
        result = run(srv.data_transform("base64Decode", encoded))
        self.assertTrue(result["binary_safe"])
        self.assertEqual(base64.b64decode(result["result_base64"]), bytes([0xFF, 0xFE, 0x00, 0x01]))

    def test_hex_round_trip(self):
        result = run(srv.data_transform("hexEncode", "hi"))
        self.assertEqual(run(srv.data_transform("hexDecode", result["result"]))["result"], "hi")

    def test_url_round_trip(self):
        result = run(srv.data_transform("urlEncode", "a b&c=d"))
        self.assertEqual(run(srv.data_transform("urlDecode", result["result"]))["result"],
                         "a b&c=d")

    def test_prepend_and_append_use_the_argument(self):
        self.assertEqual(run(srv.data_transform("prepend", "id=", argument="1"))["result"], "1id=")
        self.assertEqual(run(srv.data_transform("append", "id", argument="=1"))["result"], "id=1")

    def test_unknown_operation_lists_the_real_ones(self):
        result = run(srv.data_transform("rot13", "x"))
        self.assertFalse(result["ok"])
        self.assertIn("sha256", result["error"])

    def test_malformed_input_is_a_clear_failure_not_a_traceback(self):
        result = run(srv.data_transform("base64Decode", "!!!not base64!!!"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "TRANSFORM_FAILED")


class OsintToolTests(unittest.TestCase):
    def test_missing_graph_id_is_rejected_before_any_request(self):
        result, stub = with_client(
            [], lambda c: srv.osint_run_transform(graph_id=0, transform="subdomains", value="x")
        )
        self.assertFalse(result["ok"])
        self.assertEqual(stub.calls, [])

    def test_network_refusal_tells_the_caller_exactly_what_to_set(self):
        result, _ = with_client(
            [(400, {"error": "explicit network confirmation is required for this transform",
                    "reason": "NETWORK_CONFIRMATION_REQUIRED"})],
            lambda c: srv.osint_run_transform(graph_id=1, transform="subdomains", value="x"),
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "NETWORK_CONFIRMATION_REQUIRED")
        self.assertIn("confirm_network=True", result["error"])

    def test_confirmed_run_passes_the_flag_through(self):
        _, stub = with_client(
            [(200, {"status": "completed", "entities": [{"name": "a"}], "relations": []})],
            lambda c: srv.osint_run_transform(graph_id=1, transform="subdomains", value="x",
                                              confirm_network=True),
        )
        self.assertTrue(stub.calls[0]["json_body"]["confirm_network"])

    def test_partial_result_is_kept_rather_than_discarded(self):
        result, _ = with_client(
            [(200, {"status": "failed", "entities": [{"name": "a"}], "relations": [],
                    "warnings": ["index 4 timed out"]})],
            lambda c: srv.osint_run_transform(graph_id=1, transform="subdomains", value="x",
                                              confirm_network=True),
        )
        self.assertEqual(len(result["entities"]), 1)
        self.assertEqual(result["warnings"], ["index 4 timed out"])

    def test_transform_not_applicable_is_passed_through_with_its_reason(self):
        result, _ = with_client(
            [(400, {"error": "value must be an IP address", "reason": "TRANSFORM_NOT_APPLICABLE"})],
            lambda c: srv.osint_run_transform(graph_id=1, transform="reverse_dns", value="example.com"),
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "TRANSFORM_NOT_APPLICABLE")


class ReportParsingTests(unittest.TestCase):
    def test_crawler_json_is_structured_not_dumped(self):
        payload = '{"pages": [{"url": "https://t/a", "status": 200}], "target": "https://t"}'
        parsed = srv._parse_report(payload, "map.json")
        self.assertEqual(parsed["report_type"], "target_crawler_json")
        self.assertEqual(parsed["data"]["pages"][0]["url"], "https://t/a")

    def test_findings_json_keeps_evidence(self):
        payload = '{"findings": [{"title": "IDOR", "severity": "HIGH", "evidence": "x"}]}'
        parsed = srv._parse_report(payload, "findings.json")
        self.assertEqual(parsed["report_type"], "scanner_findings_json")
        self.assertEqual(parsed["data"]["findings"][0]["evidence"], "x")

    def test_html_report_extracts_links_forms_and_scripts(self):
        html = ('<a href="/a">a</a><form action="/login"></form>'
                '<script src="/app.js"></script>')
        parsed = srv._parse_report(html, "map.html")
        self.assertIn("/a", parsed["data"]["links"])
        self.assertIn("/login", parsed["data"]["forms"])
        self.assertIn("/app.js", parsed["data"]["scripts"])

    def test_broken_json_does_not_raise(self):
        parsed = srv._parse_report("{not json", "broken.json")
        self.assertEqual(parsed["report_type"], "json_unparsed")


class OobAndSkillsTests(unittest.TestCase):
    def test_generated_token_appears_in_every_payload(self):
        result = run(srv.oob_generate(tag="xxe"))
        self.assertTrue(result["token"].startswith("rroob_"))
        for template in result["payload_templates"].values():
            rendered = template if isinstance(template, str) else json.dumps(template)
            self.assertIn(result["token"], rendered)

    def test_skills_read_rejects_a_path_traversal(self):
        result = run(srv.skills_read(name="../../etc/passwd"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "INVALID_ARGUMENT")

    def test_skills_read_reports_a_missing_skill(self):
        result = run(srv.skills_read(name="definitely-not-a-skill-xyz"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "SKILL_NOT_FOUND")

    def test_skills_list_finds_the_shipped_library(self):
        directory = srv._skills_dir()
        if not directory:
            self.skipTest("no skills directory in this checkout")
        result = run(srv.skills_list(limit=5))
        self.assertTrue(result["ok"])
        self.assertTrue(result["total_found"] > 0)
        self.assertLessEqual(len(result["skills"]), 5)


class PlatformStatusTests(unittest.TestCase):
    def test_reports_each_service_separately(self):
        result, stub = with_client(
            [
                (200, {"services": {"engine": "up"}}),
                (200, {"ok": True}),
                (200, {"ok": True}),
                (200, {"address": "direct"}),
                (200, {"items": [{"id": 1, "name": "p"}]}),
            ],
            lambda c: srv.platform_status(),
        )
        self.assertTrue(result["gateway"]["reachable"])
        self.assertTrue(result["engine"]["reachable"])
        self.assertTrue(result["browser_worker"]["reachable"])
        self.assertEqual(result["route"], {"address": "direct"})

    def test_a_dead_engine_does_not_pretend_the_platform_is_down(self):
        class DeadEngine(StubClient):
            async def engine(self, method, path, **kwargs):
                raise srv.RRTransport("connection refused")

        original = srv._client
        stub = DeadEngine([(200, {"services": {}})])
        srv._client = stub
        try:
            result = run(srv.platform_status())
        finally:
            srv._client = original
        self.assertTrue(result["gateway"]["reachable"])
        self.assertFalse(result["engine"]["reachable"])
        self.assertIn("connection refused", result["engine"]["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)