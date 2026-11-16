"""The target crawler must survive a page whose body is not text.

Measured 2026-10-16 against the live cluster. A crawl of a site whose JavaScript
bundle carried a NUL byte made every subsequent `GET /api/target-map` poll answer
HTTP 500:

    psycopg.errors.UntranslatableCharacter: unsupported Unicode escape sequence
    DETAIL:  \\u0000 cannot be converted to text
    CONTEXT:  JSON data, line 1: ...allActionsIncluded\\ufffd\\u0000...

The poll writes `TargetJob.result` on **every** request, so one byte in one page
took the whole endpoint down for the rest of that crawl — the map finished and the
operator could not read it. These tests pin the write path against that shape, and
they check the stored value rather than only the status code, because a 200 with
the finding silently dropped would be the same defect wearing a different hat.
"""

from unittest.mock import patch

from django.test import TestCase

from lab import views
from lab.models import Project, TargetJob


# The bytes as the engine actually published them: Go's JSON encoder writes an
# invalid byte as U+FFFD and a NUL as U+0000, and a minified bundle carries both.
#
# `NUL` is built with `chr(0)` rather than written as a literal: a source file
# that contains a NUL byte cannot be imported at all, which is what this module
# proved the moment the character was typed in directly.
NUL = chr(0)
NUL_SNAPSHOT = {
    "map_id": 4242,
    "status": "completed",
    "pages": [
        {
            "url": "https://target.test/static/app.js",
            "depth": 1,
            "status": 200,
            "content_type": "application/javascript",
            "js": {
                "bytes": 1048576,
                "variables": [{"name": f"allActionsIncluded�{NUL}tail", "line": 91}],
                "secrets": [{"rule": "generic_api_key", "value": f"AKIA{NUL}REAL", "line": 12}],
            },
            "enrich": {
                "patterns": [{"pattern": "email", "value": f"a@b.test�{NUL}"}],
                "secrets": {"findings": [{"rule": "jwt", "value": f"eyJhbG{NUL}ciOi.J9", "severity": "high"}]},
            },
        }
    ],
}


class TargetMapNulByteTests(TestCase):
    """A polled snapshot is written on every request, so it has to always write."""

    def setUp(self):
        self.project = Project.objects.create(name="nul-target")
        TargetJob.objects.create(
            project=self.project, job_id="4242", engine_kind="static",
            url="https://target.test/", status="running", result={},
        )

    @patch("lab.views.call_engine_get")
    @patch("lab.views._ingest_target_job")
    def test_polling_a_map_with_a_nul_byte_stores_it_and_answers_200(self, ingest, call_engine_get):
        call_engine_get.return_value = (200, dict(NUL_SNAPSHOT))
        response = self.client.get("/api/target-map", {"map_id": "4242"})
        self.assertEqual(response.status_code, 200)

        stored = TargetJob.objects.get(job_id="4242").result
        self.assertEqual(stored["status"], "completed")
        page = stored["pages"][0]
        # The finding survives as something the operator can read: the NUL is
        # rendered as its own escape text, not dropped and not truncated. The
        # U+FFFD that precedes it is the engine's own encoding of an invalid byte
        # and is left exactly as it arrived — PostgreSQL stores it without
        # complaint, so rewriting it would alter evidence for no reason.
        self.assertEqual(page["js"]["variables"][0]["name"], "allActionsIncluded�\\u0000tail")
        self.assertEqual(page["js"]["secrets"][0]["value"], "AKIA\\u0000REAL")
        self.assertEqual(page["enrich"]["patterns"][0]["value"], "a@b.test�\\u0000")
        self.assertEqual(page["enrich"]["secrets"]["findings"][0]["value"], "eyJhbG\\u0000ciOi.J9")
        # A finished job is ingested, which is the second reader of the same value.
        ingest.assert_called_once()

    @patch("lab.views.call_engine_get")
    @patch("lab.views._ingest_target_job")
    def test_the_response_still_carries_the_engines_own_bytes(self, ingest, call_engine_get):
        """The browser gets the engine's JSON unchanged.

        The adaptation is for the storage layer only. Rewriting the response would
        mean the operator reads a different value than the one the engine reported,
        for no gain: a NUL renders as nothing on screen either way.
        """
        call_engine_get.return_value = (200, dict(NUL_SNAPSHOT))
        response = self.client.get("/api/target-map", {"map_id": "4242"})
        page = response.json()["pages"][0]
        self.assertEqual(page["js"]["variables"][0]["name"], f"allActionsIncluded�{NUL}tail")

    @patch("lab.views.call_engine_get")
    @patch("lab.views._ingest_target_job")
    def test_repeated_polls_keep_answering_200(self, ingest, call_engine_get):
        """The regression that reached the operator: every later poll failed."""
        call_engine_get.return_value = (200, dict(NUL_SNAPSHOT))
        for _ in range(5):
            self.assertEqual(self.client.get("/api/target-map", {"map_id": "4242"}).status_code, 200)

    @patch("lab.views.call_browser_worker_get")
    @patch("lab.views._analyze_browser_job_scripts")
    @patch("lab.views._ingest_target_job")
    def test_the_browser_target_poll_writes_the_same_way(self, ingest, analyze, call_browser_worker_get):
        """Browser-driven Target analyses bundles after the crawl, so it reads the
        same bodies and carries the same bytes into the same column."""
        analyze.side_effect = lambda result, job: dict(NUL_SNAPSHOT, job_id="b7")
        call_browser_worker_get.return_value = (200, {"job_id": "b7", "status": "completed"})
        TargetJob.objects.create(
            project=self.project, job_id="b7", engine_kind="browser",
            url="https://target.test/", status="running", result={},
        )
        response = self.client.get("/api/target-browser", {"job_id": "b7"})
        self.assertEqual(response.status_code, 200)
        stored = TargetJob.objects.get(job_id="b7").result
        self.assertEqual(stored["pages"][0]["js"]["variables"][0]["name"], "allActionsIncluded�\\u0000tail")


class PgStorableTests(TestCase):
    """The adaptation itself, measured against the database rather than assumed."""

    def test_a_nul_byte_cannot_be_stored_and_the_escape_can(self):
        """Pins the premise: PostgreSQL refuses U+0000, so this is not our rule."""
        from django.db import DataError, transaction

        with self.assertRaises(DataError):
            with transaction.atomic():
                TargetJob.objects.filter(job_id="none").update(result={"v": f"a{NUL}b"})

    def test_structure_and_other_characters_are_left_alone(self):
        payload = {
            "n": 1, "f": 1.5, "t": True, "none": None,
            "keep": "tab\tnewline\nreturn\r bell\x07 replacement\ufffd",
            "list": [1, "a", {"deep": "b"}],
        }
        from lab.pg_json import pg_storable

        cleaned = pg_storable(payload)
        self.assertEqual(cleaned["n"], 1)
        self.assertEqual(cleaned["f"], 1.5)
        self.assertIs(cleaned["t"], True)
        self.assertIsNone(cleaned["none"])
        # Only U+0000 is unrepresentable in `text`. Changing anything else would
        # alter evidence for no reason, so the replacement character, the tab and
        # the control characters all survive untouched.
        self.assertEqual(cleaned["keep"], payload["keep"])
        self.assertEqual(cleaned["list"], [1, "a", {"deep": "b"}])

    def test_a_lone_surrogate_is_replaced_because_it_has_no_utf8_form(self):
        from lab.pg_json import pg_storable

        cleaned = pg_storable({"v": "before\ud800after"})
        self.assertEqual(cleaned["v"], "before\\u0000after")
        # The whole point: before the replacement this string has no UTF-8 form at
        # all, so psycopg cannot send it. Asserting the encode is the check that
        # would have failed for the right reason.
        cleaned["v"].encode("utf-8")

    def test_dict_keys_are_cleaned_because_jsonb_stores_them_as_text(self):
        from lab.pg_json import pg_storable

        cleaned = pg_storable({"key\x00with\x00nul": "v"})
        self.assertEqual(list(cleaned), ["key\\u0000with\\u0000nul"])
        TargetJob.objects.create(
            job_id="keys", engine_kind="static", url="https://target.test/", result=cleaned,
        )
        self.assertEqual(TargetJob.objects.get(job_id="keys").result, cleaned)

    def test_non_string_keys_are_not_coerced(self):
        from lab.pg_json import pg_storable

        self.assertEqual(pg_storable({1: "a"}), {1: "a"})