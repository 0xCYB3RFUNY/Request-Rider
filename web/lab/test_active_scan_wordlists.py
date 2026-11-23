"""Tests for the two operator-supplied wordlists the active scanner now accepts.

They are the fields that make four capabilities reachable at all: `HiddenParams`
fires parameter names the application's own JavaScript binds, `HiddenPaths` fires a
dictionary, and neither has a default on purpose. A field that is accepted but not
carried is a field the operator filled in and the run ignored, and the two tests
that matter here are therefore the wiring ones, not the parsing ones.
"""

from django.test import SimpleTestCase

from lab.active_scanner_views import _active_scan_request, _active_scan_words


class ActiveScanWordlistTests(SimpleTestCase):
    """`_active_scan_words` reads what an operator pastes."""

    def test_an_absent_list_is_empty(self):
        self.assertEqual(_active_scan_words({}, "params"), [])

    def test_newline_separated_text_is_split_and_trimmed(self):
        words = _active_scan_words({"params": "  report_token \ndebug\n\n  "}, "params")
        self.assertEqual(words, ["report_token", "debug"])

    def test_comments_are_dropped(self):
        # A dictionary pasted out of a file keeps its comments, and a name that is
        # a comment is a request nobody asked for.
        words = _active_scan_words({"path_wordlist": "# admin surfaces\n/admin/\n"}, "path_wordlist")
        self.assertEqual(words, ["/admin/"])

    def test_a_list_is_accepted_as_well_as_text(self):
        # Both shapes have to work: the browser sends text, an API caller sends a
        # list, and neither may be a trap.
        self.assertEqual(_active_scan_words({"params": ["a", "b"]}, "params"), ["a", "b"])

    def test_windows_line_endings_do_not_become_part_of_a_name(self):
        self.assertEqual(_active_scan_words({"params": "alpha\r\nbeta"}, "params"), ["alpha", "beta"])

    def test_a_number_is_refused_outright(self):
        with self.assertRaises(ValueError):
            _active_scan_words({"params": 7}, "params")

    def test_a_pasted_megabyte_is_refused_with_the_limit_named(self):
        with self.assertRaises(ValueError) as caught:
            _active_scan_words({"params": "\n".join(f"name{i}" for i in range(200001))}, "params")
        self.assertIn("200000", str(caught.exception))


class ActiveScanRequestCarriesTheWordlistsTests(SimpleTestCase):
    """The browser's words reach the engine's request shape."""

    def _request(self, **extra):
        payload = {"url": "https://example.test/"}
        payload.update(extra)
        return _active_scan_request(payload)

    def test_the_wordlists_travel(self):
        request = self._request(params="report_token", path_wordlist="/admin/")
        self.assertEqual(request["params"], ["report_token"])
        self.assertEqual(request["path_wordlist"], ["/admin/"])

    def test_an_absent_wordlist_travels_as_empty(self):
        # Empty, not missing: the engine's documented behaviour for an empty list
        # is that those probes do not run, and a missing key would read there as
        # a field that never existed.
        request = self._request()
        self.assertEqual(request["params"], [])
        self.assertEqual(request["path_wordlist"], [])

    def test_the_existing_numbers_still_travel(self):
        # The change is additive and this is the guard for that claim: a run that
        # only fills the URL must still carry the bounds it always did.
        request = self._request(max_pages=10, max_depth=-1, blind_delay_ms=3000)
        self.assertEqual(request["max_pages"], 10)
        self.assertEqual(request["max_depth"], -1)
        self.assertEqual(request["blind_delay_ms"], 3000)
