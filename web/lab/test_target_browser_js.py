"""Tests for the browser-driven crawler's JavaScript analysis.

`target_browser_js.py` is deliberately free of models and database access, so
these tests need neither a database nor a live site: the engine caller is
injected, and the claim under test is what the gateway does with a network log
and an engine answer — not what the engine reads, which
`engine/target_js_endpoint_test.go` covers against a real HTTP server.
"""

import unittest

from lab import target_browser_js as browser_js


def finished_result(network=None, status="completed", page_url="https://shop.example/cart"):
    """A finished browser job with one page and the network log it recorded."""
    return {
        "status": status,
        "visited": 1,
        "pages": [
            {
                "url": page_url,
                "depth": 0,
                "status": 200,
                "kind": "browser-page",
                "content_type": "text/html",
                "network": list(network or []),
            }
        ],
    }


SCRIPT_ENTRY = {
    "url": "https://shop.example/static/app.js",
    "kind": "javascript",
    "status": 200,
    "content_type": "application/javascript",
    "bytes": 4096,
    "time": 12,
    "ms": 7,
    "js": {
        "endpoints": [{"url": "/api/v1/cart", "method": "GET", "query_params": ["id"]}],
        "findings": [{"kind": "dom-write", "line": 4, "snippet": "el.innerHTML = t"}],
        "secrets": [],
        "bytes": 4096,
        "ms": 7,
    },
}


def recording_call(answer=None, status=200, recorder=None):
    """An engine caller that records what it was asked and answers a fixed reply."""
    recorder = recorder if recorder is not None else []

    def call(path, payload):
        recorder.append((path, payload))
        return status, answer

    call.recorder = recorder
    return call


class ScriptCollectionTests(unittest.TestCase):
    """Which URLs a finished job hands to the analyser."""

    def test_collects_scripts_and_keeps_request_order(self):
        result = finished_result(
            network=[
                {"url": "https://shop.example/a.js", "resource_type": "script"},
                {"url": "https://shop.example/b.js", "resource_type": "script"},
            ]
        )
        self.assertEqual(
            browser_js.browser_script_urls(result),
            ["https://shop.example/a.js", "https://shop.example/b.js"],
        )

    def test_takes_a_suffixed_url_whose_type_was_not_recorded(self):
        # A log written by something that did not classify its entries still names
        # the program in the path, and a bundle is a bundle.
        result = finished_result(network=[{"url": "https://cdn.example/v/app.mjs"}])
        self.assertEqual(browser_js.browser_script_urls(result), ["https://cdn.example/v/app.mjs"])

    def test_takes_an_extensionless_url_the_browser_called_a_script(self):
        result = finished_result(network=[{"url": "https://cdn.example/bundle?h=9", "resource_type": "script"}])
        self.assertEqual(browser_js.browser_script_urls(result), ["https://cdn.example/bundle?h=9"])

    def test_ignores_the_rest_of_the_network_log(self):
        result = finished_result(
            network=[
                {"url": "https://shop.example/api/cart", "resource_type": "xhr"},
                {"url": "https://shop.example/logo.png", "resource_type": "image"},
                {"url": "https://shop.example/style.css", "resource_type": "stylesheet"},
                {"url": "data:image/png;base64,AAAA", "resource_type": "image"},
            ]
        )
        self.assertEqual(browser_js.browser_script_urls(result), [])

    def test_reports_each_url_once(self):
        # One page requests the same framework bundle from several of its own
        # modules; the analyst is shown the file, not the number of times it was
        # asked for.
        result = finished_result(
            network=[
                {"url": "https://shop.example/vendor.js", "resource_type": "script"},
                {"url": "https://shop.example/vendor.js", "resource_type": "script"},
                {"url": "https://shop.example/vendor.js", "resource_type": "fetch"},
            ]
        )
        self.assertEqual(browser_js.browser_script_urls(result), ["https://shop.example/vendor.js"])

    def test_ignores_a_result_without_pages(self):
        self.assertEqual(browser_js.browser_script_urls({"status": "completed"}), [])
        self.assertEqual(browser_js.browser_script_urls({"status": "completed", "pages": "nope"}), [])
        self.assertEqual(browser_js.browser_script_urls(None), [])


class TerminalStateTests(unittest.TestCase):
    """When the analysis is allowed to run."""

    def test_every_stopped_status_analyses(self):
        for status in sorted(browser_js.BROWSER_TERMINAL_STATUSES):
            with self.subTest(status=status):
                self.assertTrue(browser_js.is_terminal({"status": status}))

    def test_a_running_job_is_left_alone(self):
        # A running job re-reports its network list on every poll; analysing each
        # one would re-read every bundle once a second for the whole crawl.
        result = finished_result(status="running", network=[{"url": "https://shop.example/a.js", "resource_type": "script"}])
        call = recording_call(answer={"results": [SCRIPT_ENTRY]})
        self.assertEqual(browser_js.enrich_browser_target_result(result, call=call), result)
        self.assertEqual(call.recorder, [])

    def test_a_terminal_job_without_scripts_does_not_call_the_engine(self):
        call = recording_call(answer={"results": []})
        result = finished_result(network=[{"url": "https://shop.example/api", "resource_type": "xhr"}])
        browser_js.enrich_browser_target_result(result, call=call)
        self.assertEqual(call.recorder, [])


class EnrichmentTests(unittest.TestCase):
    """What the map gets once the answers are back."""

    def test_answers_become_page_rows_the_existing_renderer_can_draw(self):
        result = finished_result(network=[{"url": "https://shop.example/static/app.js", "resource_type": "script"}])
        call = recording_call(answer={"results": [SCRIPT_ENTRY]})
        browser_js.enrich_browser_target_result(result, call=call)

        derived = [page for page in result["pages"] if page.get("js_source") == browser_js.SCRIPT_PAGE_SOURCE]
        self.assertEqual(len(derived), 1)
        page = derived[0]
        # The static crawler's own field names, because this is its record.
        self.assertEqual(page["url"], SCRIPT_ENTRY["url"])
        self.assertEqual(page["kind"], "javascript")
        self.assertEqual(page["status"], 200)
        self.assertEqual(page["content_type"], "application/javascript")
        self.assertEqual(page["depth"], 0)
        self.assertEqual(page["js"]["endpoints"][0]["url"], "/api/v1/cart")
        self.assertEqual(page["js"]["findings"][0]["kind"], "dom-write")

    def test_the_page_keeps_its_own_network_log(self):
        network = [{"url": "https://shop.example/static/app.js", "resource_type": "script"}]
        result = finished_result(network=network)
        browser_js.enrich_browser_target_result(result, call=recording_call(answer={"results": [SCRIPT_ENTRY]}))
        self.assertEqual(result["pages"][0]["network"], network)
        self.assertEqual(len(result["pages"]), 2)

    def test_a_second_poll_does_not_double_the_rows(self):
        result = finished_result(network=[{"url": "https://shop.example/static/app.js", "resource_type": "script"}])
        call = recording_call(answer={"results": [SCRIPT_ENTRY]})
        browser_js.enrich_browser_target_result(result, call=call)
        # A finished job is polled until the UI stops asking, and the worker's own
        # answer never carries the derived rows, so they are rebuilt every time.
        worker_result = finished_result(network=[{"url": "https://shop.example/static/app.js", "resource_type": "script"}])
        browser_js.enrich_browser_target_result(worker_result, previous=result, call=call)
        self.assertEqual(len(worker_result["pages"]), 2)
        self.assertEqual(
            len([p for p in worker_result["pages"] if p.get("js_source") == browser_js.SCRIPT_PAGE_SOURCE]),
            1,
        )

    def test_a_finished_job_is_not_re_downloaded_on_every_poll(self):
        network = [{"url": "https://shop.example/static/app.js", "resource_type": "script"}]
        first = finished_result(network=network)
        call = recording_call(answer={"results": [SCRIPT_ENTRY]})
        browser_js.enrich_browser_target_result(first, call=call)
        self.assertEqual(len(call.recorder), 1)

        again = finished_result(network=network)
        browser_js.enrich_browser_target_result(again, previous=first, call=call)
        self.assertEqual(len(call.recorder), 1, "the cached answer was not used")
        self.assertEqual(again["js_analysis"]["records"], [SCRIPT_ENTRY])

    def test_attaching_twice_to_the_same_result_keeps_one_row(self):
        # The worker never echoes the derived rows back, so the removal pass is not
        # reached by the poll path — but it is the only thing standing between a
        # re-run and a map that lists every bundle twice, and it is exactly the
        # path a future caller of `attach_script_pages` would take.
        result = finished_result(network=[{"url": SCRIPT_ENTRY["url"], "resource_type": "script"}])
        call = recording_call(answer={"results": [SCRIPT_ENTRY]})
        browser_js.enrich_browser_target_result(result, call=call)
        browser_js.attach_script_pages(result, [SCRIPT_ENTRY], {"https://shop.example/static/app.js": 0})
        derived = [page for page in result["pages"] if page.get("js_source") == browser_js.SCRIPT_PAGE_SOURCE]
        self.assertEqual(len(derived), 1)
        self.assertEqual(len(result["pages"]), 2)

    def test_a_changed_url_list_is_analysed_again(self):
        first = finished_result(network=[{"url": "https://shop.example/a.js", "resource_type": "script"}])
        call = recording_call(answer={"results": [SCRIPT_ENTRY]})
        browser_js.enrich_browser_target_result(first, call=call)

        # A late script, or a redirect that resolved elsewhere, changes what the
        # job saw. Re-using the old answer here would report a stale map as a
        # fresh one.
        second = finished_result(
            network=[
                {"url": "https://shop.example/a.js", "resource_type": "script"},
                {"url": "https://shop.example/late.js", "resource_type": "script"},
            ]
        )
        browser_js.enrich_browser_target_result(second, previous=first, call=call)
        self.assertEqual(len(call.recorder), 2)
        self.assertEqual(
            [entry["url"] for entry in call.recorder[1][1]["urls"]],
            ["https://shop.example/a.js", "https://shop.example/late.js"],
        )

    def test_each_script_carries_the_page_that_loaded_it(self):
        result = finished_result(
            page_url="https://shop.example/cart",
            network=[{"url": "https://shop.example/static/app.js", "resource_type": "script"}],
        )
        call = recording_call(answer={"results": [SCRIPT_ENTRY]})
        browser_js.enrich_browser_target_result(result, call=call)
        payload = call.recorder[0][1]
        self.assertEqual(payload["urls"], [{"url": "https://shop.example/static/app.js", "referer": "https://shop.example/cart"}])
        self.assertEqual(payload["referer"], "https://shop.example/cart")

    def test_a_failed_analysis_says_why_instead_of_showing_nothing(self):
        # A silent failure is indistinguishable from a site with no JavaScript,
        # which is a claim about the site and not about our engine.
        result = finished_result(network=[{"url": "https://shop.example/a.js", "resource_type": "script"}])
        call = recording_call(status=502, answer={"error": "engine unreachable"})
        browser_js.enrich_browser_target_result(result, call=call)
        self.assertIn("engine unreachable", result["js_analysis"]["error"])
        self.assertEqual(result["js_analysis"]["records"], [])
        self.assertEqual([p for p in result["pages"] if p.get("js_source")], [])

    def test_a_refused_engine_call_is_reported_not_raised(self):
        def call(path, payload):
            raise OSError("connection reset")

        result = finished_result(network=[{"url": "https://shop.example/a.js", "resource_type": "script"}])
        browser_js.enrich_browser_target_result(result, call=call)
        self.assertIn("OSError", result["js_analysis"]["error"])

    def test_a_dropped_entry_is_surfaced(self):
        result = finished_result(network=[{"url": "https://shop.example/a.js", "resource_type": "script"}])
        call = recording_call(answer={"results": [SCRIPT_ENTRY], "warning": "an entry named no url"})
        browser_js.enrich_browser_target_result(result, call=call)
        self.assertIn("an entry named no url", result["js_analysis"]["error"])
        self.assertEqual(result["js_analysis"]["records"], [SCRIPT_ENTRY])

    def test_a_single_failed_bundle_still_lands_as_a_row(self):
        # One dead host must not blank the analyses of the ones that loaded, and
        # the failure has to be visible on the row rather than swallowed.
        record = {"url": "https://gone.example/a.js", "error": "connection refused", "status": 0}
        result = finished_result(
            network=[
                {"url": "https://gone.example/a.js", "resource_type": "script"},
                {"url": "https://shop.example/static/app.js", "resource_type": "script"},
            ]
        )
        browser_js.enrich_browser_target_result(result, call=recording_call(answer={"results": [record, SCRIPT_ENTRY]}))
        derived = [page for page in result["pages"] if page.get("js_source") == browser_js.SCRIPT_PAGE_SOURCE]
        self.assertEqual(len(derived), 2)
        self.assertEqual(derived[0]["error"], "connection refused")
        self.assertNotIn("js", derived[0])
        self.assertIn("js", derived[1])

    def test_a_script_takes_the_depth_of_the_page_that_loaded_it(self):
        # A bundle has no crawl level of its own; the row shows the depth of the
        # page that reached it rather than a made-up one.
        result = finished_result(network=[{"url": SCRIPT_ENTRY["url"], "resource_type": "script"}])
        result["pages"][0]["depth"] = 3
        browser_js.enrich_browser_target_result(result, call=recording_call(answer={"results": [SCRIPT_ENTRY]}))
        derived = [page for page in result["pages"] if page.get("js_source") == browser_js.SCRIPT_PAGE_SOURCE][0]
        self.assertEqual(derived["depth"], 3)

    def test_a_script_reached_from_two_pages_takes_the_shallowest(self):
        result = finished_result(network=[{"url": SCRIPT_ENTRY["url"], "resource_type": "script"}])
        result["pages"].append(
            {
                "url": "https://shop.example/checkout",
                "depth": 2,
                "status": 200,
                "kind": "browser-page",
                "content_type": "text/html",
                "network": [{"url": SCRIPT_ENTRY["url"], "resource_type": "script"}],
            }
        )
        browser_js.enrich_browser_target_result(result, call=recording_call(answer={"results": [SCRIPT_ENTRY]}))
        derived = [page for page in result["pages"] if page.get("js_source") == browser_js.SCRIPT_PAGE_SOURCE][0]
        self.assertEqual(derived["depth"], 0, "the first place the script was reached from is depth 0")


class ScriptBatchTests(unittest.TestCase):
    """Why the engine call is split into batches.

    Measured on a real browser job against ria.ru: the browser reported 85 script
    URLs, the engine needed **248 s** to analyse all of them, and Django's engine
    client cuts that socket at `DEFAULT_ENGINE_TIMEOUT = 120.0`. One call carrying
    every URL therefore always lost: the gateway answered `502 … timed out`,
    `records` came back empty, `attach_script_pages` attached nothing, and the map
    showed zero findings for a site that had 437 of them — with no reason on
    screen.

    These tests hold that shape: every URL reaches the engine, the records come
    back in one answer, and one dead batch costs only its own scripts.
    """

    def _many_scripts(self, count):
        return finished_result(
            network=[
                {"url": f"https://cdn.example/v/{index}.js", "resource_type": "script"}
                for index in range(count)
            ]
        )

    def test_every_script_reaches_the_engine_across_the_batches(self):
        count = browser_js.JS_ANALYSIS_CHUNK * 3 + 5
        result = self._many_scripts(count)
        call = recording_call(answer={"results": []})
        browser_js.enrich_browser_target_result(result, call=call)

        sent = [
            entry["url"]
            for _path, payload in call.recorder
            for entry in payload["urls"]
        ]
        self.assertEqual(
            sent,
            [f"https://cdn.example/v/{index}.js" for index in range(count)],
            "batching may split the list, never drop from it",
        )

    def test_no_single_call_carries_more_than_the_batch_size(self):
        result = self._many_scripts(browser_js.JS_ANALYSIS_CHUNK * 4)
        call = recording_call(answer={"results": []})
        browser_js.enrich_browser_target_result(result, call=call)
        for _path, payload in call.recorder:
            self.assertLessEqual(len(payload["urls"]), browser_js.JS_ANALYSIS_CHUNK)

    def test_records_from_every_batch_are_joined_in_order(self):
        def entry(index):
            return {**SCRIPT_ENTRY, "url": f"https://cdn.example/v/{index}.js"}

        def call(path, payload):
            return 200, {"results": [entry(i) for i, _u in enumerate(payload["urls"])]}

        result = self._many_scripts(browser_js.JS_ANALYSIS_CHUNK * 2)
        browser_js.enrich_browser_target_result(result, call=call)
        records = result["js_analysis"]["records"]
        self.assertEqual(len(records), browser_js.JS_ANALYSIS_CHUNK * 2)
        derived = [p for p in result["pages"] if p.get("js_source") == browser_js.SCRIPT_PAGE_SOURCE]
        self.assertEqual(len(derived), browser_js.JS_ANALYSIS_CHUNK * 2)

    def test_one_dead_batch_costs_only_its_own_scripts(self):
        # The failure that cost 80 bundles: a host that stopped answering ended the
        # whole analysis. Now it must end only its own round trip.
        state = {"n": 0}

        def call(path, payload):
            state["n"] += 1
            if state["n"] == 2:
                return 502, {"error": "engine unavailable: timed out"}
            return 200, {"results": [{**SCRIPT_ENTRY, "url": u} for u in payload["urls"]]}

        count = browser_js.JS_ANALYSIS_CHUNK * 3
        result = self._many_scripts(count)
        browser_js.enrich_browser_target_result(result, call=call)

        records = result["js_analysis"]["records"]
        self.assertEqual(len(records), count - browser_js.JS_ANALYSIS_CHUNK)
        self.assertIn("timed out", result["js_analysis"]["error"])
        derived = [p for p in result["pages"] if p.get("js_source") == browser_js.SCRIPT_PAGE_SOURCE]
        self.assertEqual(len(derived), count - browser_js.JS_ANALYSIS_CHUNK)

    def test_the_split_is_reported_so_a_missing_range_is_attributable(self):
        result = self._many_scripts(browser_js.JS_ANALYSIS_CHUNK * 2)
        browser_js.enrich_browser_target_result(result, call=recording_call(answer={"results": []}))
        analysis = result["js_analysis"]
        self.assertEqual(analysis["batch_size"], browser_js.JS_ANALYSIS_CHUNK)
        self.assertEqual(analysis["batches"], 2)

    def test_a_single_batch_still_reports_the_bare_reason(self):
        # The range only disambiguates when there is more than one batch, so the
        # answer for the common one-script job stays exactly what it always was.
        result = finished_result(network=[{"url": "https://shop.example/a.js", "resource_type": "script"}])
        call = recording_call(status=502, answer={"error": "engine unreachable"})
        browser_js.enrich_browser_target_result(result, call=call)
        self.assertEqual(result["js_analysis"]["error"], "engine answered 502: engine unreachable")


if __name__ == "__main__":
    unittest.main()
