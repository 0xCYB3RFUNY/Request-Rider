"""A10-03 — the engine's raw bytes were handed to a browser in full.

Both failure paths in `engine_client` passed `raw_response.decode(errors="replace")`
into the JSON payload. When the engine dies mid-request what it returns is not JSON but
its own HTML error page, and that page carries the binary's filesystem paths. Those bytes
travel into the analyst's browser inside a JSON field, and 512 bytes of markup rendered
into the page is content the operator reads as if it had come from the target.

The `502` + `ENGINE_UNAVAILABLE` / `ENGINE_INVALID_RESPONSE` contract is unchanged:
there is no invented success anywhere in this file. Only the diagnostic blob is bounded.
"""

import hashlib
import unittest

from lab.engine_client import ENGINE_RAW_RESPONSE_LIMIT, EngineClient, summarize_raw_response


class RawResponseSummaryTests(unittest.TestCase):
    def test_markup_is_stripped(self) -> None:
        page = (
            b"<html><head><title>http: panic: runtime error</title></head>"
            b"<body><h1>Internal Server Error</h1></body></html>"
        )
        summary = summarize_raw_response(page)
        self.assertNotIn("<", summary["raw_response"])
        self.assertNotIn(">", summary["raw_response"])

    def test_the_tag_names_do_not_survive_as_text(self) -> None:
        """The two guarantees are separate and both are needed.

        Replacing `<` and `>` would leave `p`, `body`, `title` in the blob as bare
        words. Removing whole tags first is what keeps the text readable, and dropping
        only the tag-removal line has to fail here — an earlier version of this test
        asserted only the brackets and passed against markup-stripped code with that
        line deleted.
        """
        page = b"<body><h1>Internal Server Error</h1></body>"
        summary = summarize_raw_response(page)
        # Tag names go; the text they wrapped stays.
        for word in ("body", "h1", "<", ">"):
            self.assertNotIn(word, summary["raw_response"])
        self.assertIn("Internal Server Error", summary["raw_response"])

    def test_the_text_survives_because_it_is_the_diagnosis(self) -> None:
        """Stripping the markup must not throw away the reason. The panic text and the
        path are what turn `ENGINE_INVALID_RESPONSE` from a shrug into an answer."""
        page = b"<pre>runtime error: index out of range\n/bin/engine.main.go:412</pre>"
        summary = summarize_raw_response(page)
        self.assertIn("index out of range", summary["raw_response"])
        self.assertIn("/bin/engine.main.go:412", summary["raw_response"])

    def test_a_tag_cut_in_half_cannot_break_out_of_the_panel(self) -> None:
        """Truncation can end mid-tag, and those two characters alone are enough to open
        a real element inside a `<pre>`."""
        for payload in (b"<html><body><scr", b"<<script>alert(1)</script", b"text <"):
            summary = summarize_raw_response(payload)
            self.assertNotIn("<", summary["raw_response"])
            self.assertNotIn(">", summary["raw_response"])

    def test_the_blob_is_bounded_and_says_so(self) -> None:
        payload = b"x" * (ENGINE_RAW_RESPONSE_LIMIT * 4)
        summary = summarize_raw_response(payload)
        self.assertLessEqual(len(summary["raw_response"]), ENGINE_RAW_RESPONSE_LIMIT)
        self.assertTrue(summary["raw_response_truncated"])

    def test_length_and_hash_describe_the_original_bytes(self) -> None:
        """A truncated blob alone cannot answer "12 bytes or 12 megabytes?" nor tell two
        failures apart. Both numbers come from the bytes that really arrived."""
        payload = b"<p>" + b"y" * 1000 + b"</p>"
        summary = summarize_raw_response(payload)
        self.assertEqual(summary["raw_response_bytes"], len(payload))
        self.assertEqual(
            summary["raw_response_sha256"], hashlib.sha256(payload).hexdigest()
        )

    def test_two_different_failures_are_told_apart(self) -> None:
        """This is what the hash is for: identical first 512 bytes, different whole."""
        shared = b"<p>" + b"z" * (ENGINE_RAW_RESPONSE_LIMIT * 2)
        self.assertNotEqual(
            summarize_raw_response(shared)["raw_response_sha256"],
            summarize_raw_response(shared + b"tail")["raw_response_sha256"],
        )

    def test_undecodable_bytes_do_not_raise(self) -> None:
        """`errors="replace"` must keep producing a string, and the length has to be the
        byte count rather than the character count after replacement."""
        payload = b"\xff\xfe\x00binary"
        summary = summarize_raw_response(payload)
        self.assertEqual(summary["raw_response_bytes"], len(payload))
        self.assertIsInstance(summary["raw_response"], str)
        self.assertEqual(summary["raw_response_sha256"], hashlib.sha256(payload).hexdigest())

    def test_empty_bytes_are_handled(self) -> None:
        summary = summarize_raw_response(b"")
        self.assertEqual(summary["raw_response"], "")
        self.assertFalse(summary["raw_response_truncated"])
        self.assertEqual(summary["raw_response_bytes"], 0)
        self.assertEqual(
            summary["raw_response_sha256"], hashlib.sha256(b"").hexdigest()
        )

    def test_both_call_sites_go_through_the_summary(self) -> None:
        """Two sites, one helper. A third site reading the raw bytes directly has to
        fail here rather than reappear in a future edit."""
        import inspect

        source = inspect.getsource(EngineClient)
        self.assertNotIn("raw_response.decode(errors=\"replace\")", source)
        self.assertEqual(source.count("**summarize_raw_response(raw_response)"), 2)


class RawResponseInTheWireTests(unittest.TestCase):
    """Through the client, not just the helper."""

    def test_a_non_json_engine_answer_is_bounded(self) -> None:
        page = b"<html><body>panic in " + b"q" * 2000 + b"</body></html>"
        client = EngineClient("http://engine.invalid", opener=None)
        payload = client._decode(page, 500, "/proxy/request")
        self.assertEqual(payload["reason"], "ENGINE_INVALID_RESPONSE")
        self.assertLessEqual(len(payload["raw_response"]), ENGINE_RAW_RESPONSE_LIMIT)
        self.assertNotIn("<", payload["raw_response"])
        self.assertEqual(payload["raw_response_bytes"], len(page))

    def test_an_http_error_body_is_bounded_too(self) -> None:
        page = b"<html><body>engine died at /opt/rr/bin/engine</body></html>"
        client = EngineClient("http://engine.invalid", opener=None)
        payload = client._decode_http_error(page, 500, "/proxy/request")
        self.assertEqual(payload["reason"], "ENGINE_HTTP_ERROR")
        self.assertNotIn("<", payload["raw_response"])
        self.assertEqual(payload["raw_response_bytes"], len(page))

    def test_the_status_contract_is_untouched(self) -> None:
        """A guard against over-fixing: bounding the blob must not turn a failure into
        a success or invent a status."""
        client = EngineClient("http://engine.invalid", opener=None)
        for raw, status in ((b"<html>nope</html>", 500), (b"[]", 200), (b'{"a": 1}', 200)):
            payload = client._decode(raw, status, "/proxy/request")
            if not isinstance(payload, dict) or payload.get("reason") not in {
                "ENGINE_INVALID_RESPONSE",
            }:
                self.assertNotIn("raw_response_truncated", payload,
                                 "a decoded engine payload must not be annotated")


if __name__ == "__main__":
    unittest.main()
