"""Gateway contract for the nuclei *folder* source and the template-type list.

The engine side of this path was complete and measured: `ListTemplateDirs` and
`TemplateTypes` are covered in `engine/pkg/scanner/nuclei_dirsource_test.go`, and
the live engine answers the route with 905 folders and the 11 values `-pt`
accepts. The gateway view in front of it was the broken half, and it was broken
in a way that no engine test could see, because the failure was one argument
away from the engine:

    TypeError: call_engine() missing 1 required positional argument: 'payload'

That raised on every call, so `GET /api/scanner/nuclei/dirs` answered HTTP 500,
so `loadScannerTemplateSources()` put its failure text into the status line, so
both dropdowns stayed empty on a machine whose engine was answering 200. The
panel was therefore dead in the product and green in the engine's own tests —
which is the exact shape of defect the rule about a live target exists to catch.

The tests here hold the gateway to the engine's actual contract rather than to
the shape the view was written against: the engine handler for this path accepts
GET only (`main.go`, `scannerNucleiTemplateDirs`), so the gateway must reach it
with `call_engine_get`. The sibling `inspect` view is not evidence to the
contrary — that handler accepts GET *and* POST, which is why that one works.
"""

from unittest import mock

from django.test import TestCase


class TemplateDirListingTests(TestCase):
    """`/api/scanner/nuclei/dirs` must pass the engine's own answer through."""

    DIRS = {"dirs": [{"path": "/corpus/http/cves", "name": "http/cves", "files": 4320}],
            "types": [{"value": "http", "label": "http"}]}

    def test_the_listing_is_forwarded_and_answers(self):
        # The regression: this answered 500 because the view called `call_engine`
        # with no payload, and the panel therefore never filled a dropdown.
        with mock.patch("lab.views.call_engine_get", return_value=(200, self.DIRS)) as call:
            response = self.client.get("/api/scanner/nuclei/dirs")
        self.assertNotEqual(
            response.status_code, 500,
            msg=f"the folder listing returned an unhandled 500: {response.content[:300]!r}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(call.call_args[0][0], "/proxy/scanner/nuclei/dirs",
                         msg="the listing must reach the engine's own path")
        body = response.json()
        self.assertEqual(body["dirs"], self.DIRS["dirs"],
                         msg="the operator must see the folders the engine found")
        self.assertEqual(body["types"], self.DIRS["types"],
                         msg="the operator must see the values -pt accepts")

    def test_the_gateway_asks_the_engine_with_GET(self):
        # The engine handler for this path refuses anything but GET. Reaching it
        # through `call_engine` would POST and earn a 405 from the engine, so the
        # method is part of this view's contract, not an implementation detail.
        with mock.patch("lab.views.call_engine_get", return_value=(200, self.DIRS)):
            with mock.patch("lab.views.call_engine") as posting:
                self.client.get("/api/scanner/nuclei/dirs")
        posting.assert_not_called()

    def test_an_engine_refusal_is_passed_on_and_not_flattened_to_an_empty_list(self):
        # An engine that cannot answer must not be reported as "this host has no
        # template folders": that sentence reads as a fact about the corpus, and
        # it is what an operator would act on.
        with mock.patch("lab.views.call_engine_get",
                        return_value=(502, {"error": "engine unreachable",
                                            "reason": "SCANNER_NUCLEI_FAILED"})):
            response = self.client.get("/api/scanner/nuclei/dirs")
        self.assertEqual(response.status_code, 502)
        body = response.json()
        self.assertEqual(body.get("error"), "engine unreachable")
        self.assertNotIn("dirs", body,
                         msg="a refusal must not be dressed as an empty folder list")

    def test_a_post_to_the_browser_facing_route_is_refused_before_the_engine(self):
        with mock.patch("lab.views.call_engine_get") as call:
            response = self.client.post("/api/scanner/nuclei/dirs")
        self.assertEqual(response.status_code, 405)
        self.assertTrue(response.json().get("error"),
                        msg="a refused method must carry an explicit error")
        call.assert_not_called()