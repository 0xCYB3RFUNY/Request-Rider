"""Tests for the 403-bypass form registry the Target control offers its choice from.

The selection itself is validated by ``test_bypass_forms.py``. What is tested here
is the list: where it comes from, that it arrives unedited, and that an engine which
cannot be reached says so instead of answering with an empty one.

That last one is the reason this file exists at all. An empty list on this endpoint
means "the engine has no forms", which reads as "the button does nothing" — and if
it is returned because the engine was down rather than because the ladder is empty,
the operator is told a falsehood and given nothing to notice it by.
"""

import json
from unittest import TestCase
from unittest.mock import patch

from django.test import Client

from lab import views


class BypassFormsRegistryTests(TestCase):
    """The registry view is a proxy, and what it must not do is edit or invent the list."""

    def _get(self, method="GET", engine=(200, {"items": ["verb-post", "path-segment-1"]})):
        # `Client()`, not `RequestFactory`: `csrf_protect` wraps this view, and on a
        # bare `RequestFactory` request in this Django version the CSRF rejection
        # answers first — measured, not assumed. The existing
        # `osint_transform_registry` answers 403 the same way on the same request,
        # so the view matches the pattern and only the harness was wrong. The
        # client defaults to `enforce_csrf_checks=False`, so the method guard is
        # what answers.
        with patch.object(views, "call_engine_get") as call:
            call.return_value = engine
            response = Client().generic(method, "/api/bypass/forms")
        return response, call

    def _body(self, response):
        return json.loads(response.content)

    def test_the_engine_path_is_the_one_the_engine_serves(self):
        # A typo in this path would not fail any selection test: the list would
        # simply come back empty, and empty means the walk has nothing to walk, so
        # the button would quietly do nothing. The path is therefore asserted
        # directly rather than inferred from a working request.
        _, call = self._get()
        self.assertEqual(call.call_args[0][0], "/proxy/bypass/forms")

    def test_the_list_reaches_the_browser_unedited(self):
        response, _ = self._get()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self._body(response)["items"], ["verb-post", "path-segment-1"])

    def test_a_writing_method_is_refused_rather_than_read_as_a_list(self):
        response, call = self._get(method="POST")
        self.assertEqual(response.status_code, 405)
        call.assert_not_called()

    def test_an_engine_failure_is_passed_through_not_reported_as_an_empty_list(self):
        response, _ = self._get(engine=(502, {"error": "engine unreachable"}))
        self.assertEqual(response.status_code, 502)
        self.assertNotEqual(self._body(response).get("items"), [])
        self.assertIn("error", self._body(response))