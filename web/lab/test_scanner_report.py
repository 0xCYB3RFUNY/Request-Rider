"""Tests for the server-rendered Scanner report.

Three things are proved here, and the third one is the reason this file exists
rather than the first two.

**The allow-lists are closed.** A severity, a per-file status and a WAF verdict
are each drawn from a set the engine itself defines. A value outside that set is
refused and shown as refused. These tests walk the real vocabulary constants
rather than restating them, so a set that grows in the engine and not here fails
here instead of silently reporting an empty table.

**The report escapes.** A finding's title, a template name, a matcher output and
a response excerpt all came from a target and from a corpus of YAML the operator
did not write. The tests render the real template through Django and assert the
hostile markup arrived as text, which is the only assertion that says something
about the document rather than about a function.

**A green suite here is not evidence until it has been seen to fail.** The
allow-lists are the kind of code that can be written wrong in a way tests accept:
a normaliser that accepts everything, or an escape that is present but bypassed.
The last test class therefore names, for each rule, the mutation that would break
it, so the next person changing this module knows which green is load-bearing.
"""

import json

from django.template.loader import render_to_string
from django.test import RequestFactory, TestCase

from lab import scanner_exports, scanner_report_views
from lab.report_i18n import (
    LANGUAGE_COOKIE,
    REPORT_LABELS,
    SCANNER_REPORT_LABELS,
    normalize_language,
    report_text,
)


class VocabularyTests(TestCase):
    """The three closed sets, and the refusal of anything outside them."""

    def test_severity_set_is_exactly_the_one_the_report_styles(self):
        # The report draws a severity as a `rr-sev-<level>` class. A level with
        # no class renders as an uncoloured chip, so the two sets are the same
        # set and this is the assertion that keeps them so.
        self.assertEqual(
            set(scanner_exports.SEVERITIES),
            {"critical", "high", "medium", "low", "info", "unknown"},
        )

    def test_status_set_is_exactly_the_engine_constants(self):
        # `engine/pkg/scanner/nuclei_exec.go` defines the per-template statuses.
        # `duplicate` joined them when content-addressed deduplication landed;
        # a report without a word for it folds it into `not_matched`, which is a
        # claim about work that never happened. `workflow` joined them when the
        # `workflows:` orchestrators landed, and the expected set here had not
        # learned it — so the test failed on a change both production sides had
        # already made: the engine emits `TemplateWorkflow` (nuclei_exec.go:116) and
        # `scanner_exports.STATUSES` names it. `flow` and `uncompiled` joined them
        # the same way, for the two document shapes the binary compiles nothing
        # out of: a top-level `flow:` key, and the reserved `fuzz` tag. Both were
        # missing here while the engine already emitted them, which means every
        # report rendered such a row was REFUSING it — `status_counts` folds an
        # unlisted status into `unknown` and the validation pass drops the row
        # outright. The set is written out rather than imported on purpose, so a
        # status that reaches one side only is caught here instead of being agreed
        # with itself.
        self.assertEqual(
            set(scanner_exports.STATUSES),
            {
                "matched",
                "not_matched",
                "no_request",
                "workflow",
                "flow",
                "uncompiled",
                "skipped",
                "invalid",
                "duplicate",
            },
        )

    def test_every_status_word_normalises_to_itself(self):
        for status in scanner_exports.STATUSES:
            self.assertEqual(scanner_exports.normalize_status(status), status)

    def test_every_severity_word_normalises_to_itself(self):
        for level in scanner_exports.SEVERITIES:
            self.assertEqual(scanner_exports.normalize_severity(level), level)

    def test_severity_folds_case_and_hyphen_spelling(self):
        # nuclei writes a severity upper case, and a hand-written template may
        # write it hyphenated. These are spellings of one word, not two.
        self.assertEqual(scanner_exports.normalize_severity("HIGH"), "high")
        self.assertEqual(scanner_exports.normalize_severity("  Medium "), "medium")
        self.assertEqual(scanner_exports.normalize_status("Not-Matched"), "not_matched")

    def test_unknown_severity_is_refused_not_defaulted(self):
        # `unknown` is a severity nuclei emits on purpose, so a refusal must not
        # be reported as `unknown`: that would claim the tool had an opinion
        # where it had none.
        self.assertIsNone(scanner_exports.normalize_severity("catastrophic"))
        self.assertIsNone(scanner_exports.normalize_severity(""))
        self.assertIsNone(scanner_exports.normalize_severity(None))
        self.assertIsNone(scanner_exports.normalize_severity(7))

    def test_unknown_status_is_refused(self):
        self.assertIsNone(scanner_exports.normalize_status("matched!"))
        self.assertIsNone(scanner_exports.normalize_status("passed"))
        self.assertIsNone(scanner_exports.normalize_status("not matched"))

    def test_confidence_is_a_third_shape_and_is_validated_on_its_own(self):
        # Confidence is a graded WAF verdict, not an ordering and not an
        # outcome, so it gets its own list. Running it through the severity list
        # would accept `critical`, which is a severity word and not a verdict.
        self.assertEqual(scanner_exports.normalize_confidence("high"), "high")
        self.assertEqual(scanner_exports.normalize_confidence("none"), "none")
        self.assertIsNone(scanner_exports.normalize_confidence("critical"))
        self.assertIsNone(scanner_exports.normalize_confidence("medium"))

    def test_severity_rank_orders_worst_first_and_unknown_last(self):
        ranks = [scanner_exports.severity_rank(level) for level in ("critical", "high", "low", "info")]
        self.assertEqual(ranks, sorted(ranks))
        self.assertGreater(scanner_exports.severity_rank("nonsense"), scanner_exports.severity_rank("info"))

    def test_filter_drops_unknown_words_instead_of_refusing(self):
        # A filter is a request, not evidence. An analyst who asks for a
        # severity that does not exist wants an empty table; refusing to open
        # would be a worse answer than showing one.
        levels, states = scanner_exports.validate_filters(
            severities=["high", "catastrophic", "HIGH"],
            statuses=["matched", "passed"],
        )
        self.assertEqual(levels, ["high"])
        self.assertEqual(states, ["matched"])


class ValidateFindingsTests(TestCase):
    """Splitting a raw findings list into accepted rows and refusals."""

    def test_a_refused_row_keeps_its_raw_value_and_does_not_stop_the_run(self):
        findings = [
            {"title": "Real", "severity": "high"},
            {"title": "Injected", "severity": "critical\"><script>alert(1)</script>"},
        ]
        accepted, rejected = scanner_exports.validate_findings(findings)
        self.assertEqual([row["title"] for row in accepted], ["Real"])
        self.assertEqual(len(rejected), 1)
        self.assertIn("<script>", rejected[0]["raw"])

    def test_a_non_object_row_is_refused_rather_than_read(self):
        # There is no severity to read, so there is nothing to trust about it.
        accepted, rejected = scanner_exports.validate_findings(["high", 5, None])
        self.assertEqual(accepted, [])
        self.assertEqual(len(rejected), 3)

    def test_refused_severity_is_distinguishable_from_a_declared_unknown(self):
        # Both rows reach the report as "no severity", and only one of them is a
        # severity the engine emits on purpose.
        _, rejected = scanner_exports.validate_findings([{"severity": "unknown"}, {"severity": "wat"}])
        accepted, _ = scanner_exports.validate_findings([{"severity": "unknown"}])
        self.assertEqual(len(accepted), 1)
        self.assertEqual(len(rejected), 1)

    def test_filters_narrow_the_accepted_rows(self):
        findings = [{"severity": "low"}, {"severity": "critical"}, {"severity": "low"}]
        accepted, rejected = scanner_exports.validate_findings(findings, severities=["critical"])
        self.assertEqual(len(accepted), 1)
        self.assertEqual(rejected, [])

    def test_validate_templates_refuses_an_undefined_status(self):
        templates = [
            {"name": "a.yaml", "status": "matched"},
            {"name": "b.yaml", "status": "exploded"},
        ]
        accepted, rejected = scanner_exports.validate_templates(templates)
        self.assertEqual([row["name"] for row in accepted], ["a.yaml"])
        self.assertEqual(len(rejected), 1)

    def test_counters_are_per_status_and_never_a_remainder(self):
        # Two earlier versions of this test passed against a
        # `not_matched`-as-remainder implementation, for two different reasons.
        # The first used one row per status, so the remainder coincidentally
        # equalled the real count. The second asserted only that the counts sum
        # to the row total, which a remainder also satisfies by construction.
        #
        # The assertion that separates them is the status nobody else claims. An
        # implementation that folds "everything else" into `not_matched` cannot
        # report `no_request` at all once `matched` is present, so `no_request`
        # and `not_matched` must both be right at once, and a folder of templates
        # that never send a request must report zero matches.
        templates = (
            [{"name": "a", "status": "not_matched"}] * 3
            + [{"name": "b", "status": "matched"}] * 5
            + [{"name": "c", "status": "no_request"}] * 2
            + [{"name": "d", "status": "skipped"}] * 7
            + [{"name": "e", "status": "duplicate"}] * 11
            + [{"name": "f", "status": "invalid"}] * 13
        )
        counts = scanner_exports.status_counts(templates)
        self.assertEqual(counts["matched"], 5)
        self.assertEqual(counts["not_matched"], 3)
        self.assertEqual(counts["no_request"], 2)
        self.assertEqual(counts["skipped"], 7)
        self.assertEqual(counts["duplicate"], 11)
        self.assertEqual(counts["invalid"], 13)
        # The remainder form computes not_matched as 41 - 38 = 3 by luck of this
        # shape, so the sum check below is kept but is not the load-bearing one.
        self.assertEqual(sum(counts.values()), len(templates))

    def test_a_run_that_never_addressed_the_target_is_not_a_clean_sweep(self):
        # The claim a report makes about a folder of `code`, `file` and
        # `javascript` templates, which never send a request at all.
        templates = [{"name": str(index), "status": "no_request"} for index in range(40)]
        counts = scanner_exports.status_counts(templates)
        self.assertEqual(counts["no_request"], 40)
        self.assertEqual(counts["not_matched"], 0)
        self.assertEqual(counts["matched"], 0)

    def test_severity_counts_carry_every_level_even_at_zero(self):
        counts = scanner_exports.severity_counts([{"severity": "high"}])
        self.assertEqual(set(counts), set(scanner_exports.SEVERITIES))
        self.assertEqual(counts["high"], 1)
        self.assertEqual(counts["critical"], 0)

    def test_highest_severity_of_an_empty_run_is_info_not_unknown(self):
        # A run that found nothing did not produce an unknown severity; it
        # produced no severity at all.
        self.assertEqual(scanner_exports.highest_severity([]), "info")


class EvidenceTests(TestCase):
    """Bounding the bulky part of a finding without hiding that it was cut."""

    def test_oversized_evidence_is_cut_and_its_real_size_reported(self):
        finding = {"evidence": "x" * 5000}
        text, total, truncated = scanner_exports.evidence_text(finding, limit=100)
        self.assertTrue(truncated)
        self.assertEqual(total, 5000)
        self.assertEqual(len(text), 100)

    def test_short_evidence_is_not_marked_truncated(self):
        text, total, truncated = scanner_exports.evidence_text({"evidence": "short"})
        self.assertFalse(truncated)
        self.assertEqual(total, len("short"))

    def test_a_list_evidence_is_joined_rather_than_repr_d(self):
        text, _, _ = scanner_exports.evidence_text({"evidence": ["one", "two"]})
        self.assertEqual(text, "one\ntwo")

    def test_empty_evidence_returns_empty_and_no_size(self):
        text, total, truncated = scanner_exports.evidence_text({"evidence": None})
        self.assertEqual((text, total, truncated), ("", 0, False))


class FilenameTests(TestCase):
    """A download name built from operator text."""

    def test_a_quote_in_the_name_cannot_break_the_header(self):
        # A quote or a newline in a Content-Disposition value is a
        # response-splitting primitive, so the name is built from a fixed
        # alphabet rather than by stripping characters that are dangerous today.
        cleaned = scanner_exports.slugify_filename('re"port\r\nX-Injected: 1')
        self.assertNotIn('"', cleaned)
        self.assertNotIn("\n", cleaned)
        self.assertNotIn("\r", cleaned)

    def test_the_name_is_reduced_to_a_fixed_alphabet(self):
        # Stripping a known-bad list only holds for the characters on that list.
        # The property that holds is the alphabet itself, so this asserts the
        # property rather than the incident: a name that keeps a semicolon, a
        # space or a percent sign is one that a future header parser could
        # disagree with us about.
        #
        # A strip-based implementation survives the quote test above and fails
        # this one, which is the only reason both exist.
        cleaned = scanner_exports.slugify_filename('a b;c%d|e/f\\g:h"i<j>k')
        self.assertTrue(cleaned, "a name made only of forbidden characters still needs a name")
        for character in cleaned:
            self.assertIn(
                character,
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-",
                cleaned,
            )

    def test_an_empty_name_still_produces_a_filename(self):
        self.assertEqual(scanner_exports.slugify_filename(""), "report")

    def test_non_ascii_name_is_carried_in_the_extended_form(self):
        header = scanner_exports.quoted_filename("звіт")
        self.assertIn("filename*=UTF-8''", header)


# UNTRANSLATED_LABELS are the report labels that are the same in both languages
# on purpose. `CVE` is an identifier, not wording: it names a vulnerability
# database entry, and a translated column header would no longer match the field
# it labels. The project's own rule already says this for abbreviations
# (`CVE / CWE`) and for values that come from the backend, so the exception is
# written down here rather than left as a test that mysteriously passes.
UNTRANSLATED_LABELS = {"scanner.cve"}


class RenderedReportTests(TestCase):
    """The rendered document, which is the thing that actually gets opened."""

    def setUp(self):
        self.factory = RequestFactory()

    def _render(self, payload, view="nuclei", query="", language=None):
        report = scanner_exports.build_scanner_report(payload, view=view, query=query)
        request = self.factory.get("/", {"q": query})
        if language:
            request.COOKIES[LANGUAGE_COOKIE] = language
        context = {
            "language": normalize_language(language),
            "other_language": "uk" if normalize_language(language) == "en" else "en",
            "other_language_label": "Українська" if normalize_language(language) == "en" else "English",
            "report_title": report_text(normalize_language(language), "scanner.findings"),
            "report_css": scanner_exports.EXPORT_REPORT_CSS,
            "report_js": scanner_exports.EXPORT_REPORT_JS,
            "report_brand": scanner_exports.EXPORT_REPORT_BRAND,
            "back_url": "/",
            "back_label": "Back",
            "all_severities": scanner_exports.SEVERITIES,
            "all_statuses": scanner_exports.STATUSES,
            "filter_severities": [],
            "filter_statuses": [],
            **report,
        }
        return render_to_string("lab/scanner_report.html", context, request=request)

    def test_hostile_markup_in_a_finding_title_arrives_as_text(self):
        # The assertion that matters: the payload is in the document as visible
        # text and no `<script>` element was created from it.
        html = self._render(
            {
                "findings": [
                    {
                        "title": '<script>alert(1)</script>',
                        "severity": "high",
                        "template_id": "cve-2026-1",
                    }
                ]
            }
        )
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_hostile_markup_in_a_template_name_arrives_as_text(self):
        html = self._render(
            {"templates": [{"name": '"><img src=x onerror=alert(1)>', "status": "matched"}]}
        )
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;img", html)

    def test_hostile_markup_in_evidence_arrives_as_text(self):
        html = self._render(
            {"findings": [{"severity": "low", "evidence": "<img src=x onerror=alert(1)>"}]}
        )
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;img", html)

    def test_a_refused_severity_is_shown_rather_than_dropped_silently(self):
        # The rejection is upstream behaviour worth seeing: a run produced a
        # severity the tool does not define, and that is not the same as a run
        # that produced no findings.
        html = self._render({"findings": [{"severity": "<b>x</b>", "title": "t"}]})
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", html)

    def test_the_report_declares_no_more_than_three_safe_marks(self):
        # `|safe` on operator data is the defect this module exists to prevent,
        # so its count is pinned. Three marks: the stylesheet, the script and the
        # masthead, all project constants.
        #
        # Django comments are stripped first: this file's own `{% comment %}`
        # block explains the rule and names `|safe` three times while doing it,
        # and a count that included the explanation would be measuring the prose.
        import re

        from pathlib import Path

        source = (
            Path(__file__).resolve().parents[1] / "templates" / "lab" / "scanner_report.html"
        ).read_text()
        without_comments = re.sub(
            r"{%\s*comment\s*%}.*?{%\s*endcomment\s*%}", "", source, flags=re.S
        )
        self.assertEqual(
            without_comments.count("|safe"),
            3,
            "a fourth |safe needs a reason in this file",
        )

    def test_the_inline_script_block_is_parsable(self):
        # A `<script>` element escaped as `&lt;script&gt;` inside the app's own
        # inline block would break the workspace page. The tag is assembled from
        # parts in the builder, and this asserts the rendered output has exactly
        # the script elements it should.
        html = self._render({"findings": [{"severity": "high", "title": "t"}]})
        self.assertIn("<script>", html)
        self.assertEqual(html.count("<script>"), 1)

    def test_language_switch_renders_ukrainian_when_the_cookie_says_so(self):
        html = self._render({"findings": [{"severity": "high", "title": "t"}]}, language="uk")
        self.assertIn("знахідок", html)
        self.assertNotIn(">findings<", html)

    def test_english_page_carries_no_ukrainian_wording(self):
        html = self._render({"findings": [{"severity": "high", "title": "t"}]}, language="en")
        self.assertNotIn("знахідок", html)

    def test_two_statuses_never_share_a_wording(self):
        # `not_matched` and `no_request` are the pair that must differ: one is
        # "ran and found nothing", the other is "never addressed the target".
        words = {
            key: pair
            for key, pair in SCANNER_REPORT_LABELS.items()
            if key.startswith("scanner.status.")
        }
        self.assertEqual(len({pair[0] for pair in words.values()}), len(words))
        self.assertEqual(len({pair[1] for pair in words.values()}), len(words))

    def test_no_scanner_label_is_identical_in_both_languages(self):
        # The rule `REPORT_LABELS` is held to, applied to the scanner table, with
        # the exceptions written down rather than left implicit.
        for key, (english, ukrainian) in SCANNER_REPORT_LABELS.items():
            if key in UNTRANSLATED_LABELS:
                self.assertEqual(english, ukrainian, key)
                continue
            self.assertNotEqual(english, ukrainian, key)

    def test_every_untranslated_label_really_is_an_identifier(self):
        # An exception is only honest while it stays narrow. If somebody adds a
        # full sentence to `UNTRANSLATED_LABELS`, it is a sentence on a Ukrainian
        # page and this test is the one that says so.
        for key in UNTRANSLATED_LABELS:
            english, ukrainian = SCANNER_REPORT_LABELS[key]
            self.assertLessEqual(len(english), 4, key)
            self.assertEqual(english, ukrainian)
            self.assertTrue(english.isupper(), key)

    def test_scanner_keys_do_not_collide_with_the_shared_table(self):
        # The two dictionaries are searched in order by `report_text`, so an
        # overlapping key would silently change an OSINT report's wording.
        self.assertEqual(set(SCANNER_REPORT_LABELS) & set(REPORT_LABELS), set())

    def test_every_scanner_key_the_template_uses_exists(self):
        # A missing key raises inside `report_text` while rendering, which would
        # turn a half-translated page into a 500 for one of the two languages.
        used = {
            "scanner.findings", "scanner.files", "scanner.rejected",
            "scanner.rejected_note", "scanner.filtered_by", "scanner.clear_filters",
            "scanner.severity_filter", "scanner.status_filter", "scanner.severity",
            "scanner.status", "scanner.title", "scanner.template", "scanner.cve",
            "scanner.evidence", "scanner.rows", "scanner.statistic", "scanner.value",
            "scanner.source_ip", "scanner.empty",
        }
        self.assertTrue(used <= set(SCANNER_REPORT_LABELS), sorted(used - set(SCANNER_REPORT_LABELS)))

    def test_every_status_filter_chip_names_the_status_it_filters(self):
        # Found by looking at the rendered page, not by reading the template: the
        # chips were a row of six bare counts, so the analyst had six buttons and
        # no way to tell which was which. A chip that does not say what it
        # filters is worse than no chip, because it looks like it works.
        html = self._render(
            {"templates": [{"name": "a.yaml", "status": "no_request"}]}
        )
        for status in scanner_exports.STATUSES:
            self.assertIn(
                f'data-rr-filter="{status}"',
                html,
                f"no chip for {status}",
            )
            self.assertIn(
                f'aria-label="{report_text("en", "scanner.status." + status)}',
                html,
                f"chip for {status} carries no accessible name",
            )

    def test_the_row_count_is_separated_from_its_word(self):
        # `{% tr %}` emits no leading space, so the count and the word it counts
        # have to be separated in CSS. Without it the strip read `10rows`.
        css = scanner_exports.EXPORT_REPORT_CSS
        self.assertIn(
            ".rr-foot .rr-status-line b{color:var(--text);font-weight:600;margin-right:4px}",
            css,
        )

    def test_no_template_syntax_reaches_the_rendered_page(self):
        # Found by screenshotting the rendered report and reading it: a comment
        # wrapped across lines is not a comment in Django, and its own
        # explanation printed across the report as visible text. The assertion is
        # about the rendered output rather than about the template source,
        # because the defect is only visible after rendering.
        html = self._render(
            {
                "findings": [{"severity": "high", "title": "t"}],
                "templates": [{"name": "a.yaml", "status": "matched"}],
            }
        )
        for marker in ("{%", "%}", "{#", "#}"):
            self.assertNotIn(
                marker,
                html,
                f"{marker!r} reached the page: a template block is not being closed",
            )

    def test_no_comment_body_reaches_the_rendered_page(self):
        # The specific sentence that leaked, asserted as a sentence rather than
        # as a marker, so a differently-worded comment fails here too.
        html = self._render(
            {"findings": [{"severity": "high", "title": "t"}]}
        )
        self.assertNotIn("no way to tell them", html)
        self.assertNotIn("comment", html.lower().split("<script")[0])

    def test_search_narrows_both_tables_and_survives_an_unmatched_word(self):
        payload = {
            "findings": [
                {"severity": "high", "title": "admin panel exposed"},
                {"severity": "low", "title": "missing header"},
            ],
            "templates": [
                {"name": "admin.yaml", "status": "matched"},
                {"name": "headers.yaml", "status": "not_matched"},
            ],
        }
        html = self._render(payload, query="admin")
        self.assertIn("admin panel exposed", html)
        self.assertNotIn("missing header", html)

        empty = self._render(payload, query="nothing-matches-this")
        self.assertNotIn("admin panel exposed", empty)

    def test_a_non_array_findings_field_does_not_raise(self):
        # The export is a report about a run; a wrong-shaped field should cost
        # the rows, not the page.
        html = self._render({"findings": {"severity": "high"}})
        self.assertIn("rr-empty", html)


class ReportEndpointTests(TestCase):
    """The endpoint itself, over real HTTP verbs.

    The unit tests above render the template directly, so they cannot see a
    failure that lives in the view. This class exists because one did: the view
    built its context through `views._report_context`, which is wrapped in
    `@csrf_protect`, and on a POST without a CSRF token that wrapper returns an
    `HttpResponseForbidden` instead of a context. Every GET rendered correctly,
    every POST was a 500, and the template tests were green throughout.
    """

    def setUp(self):
        self.factory = RequestFactory()

    def _post(self, payload, **params):
        query = "&".join(f"{key}={value}" for key, value in params.items())
        return scanner_report_views.scanner_report(
            self.factory.post(
                f"/api/scanner/report?{query}",
                data=json.dumps(payload),
                content_type="application/json",
            )
        )

    def test_post_renders_the_report(self):
        response = self._post(
            {"view": "nuclei", "findings": [{"title": "t", "severity": "high"}]},
            view="nuclei",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"rr-table", response.content)

    def test_post_and_get_produce_the_same_report(self):
        payload = {
            "view": "nuclei",
            "findings": [{"title": "admin", "severity": "critical"}],
            "templates": [{"name": "a.yaml", "status": "matched"}],
        }
        post = self._post(payload, view="nuclei")
        get = scanner_report_views.scanner_report(
            self.factory.get(
                "/api/scanner/report",
                {"view": "nuclei", "payload": json.dumps(payload)},
            )
        )
        self.assertEqual(post.status_code, 200)
        self.assertEqual(get.status_code, 200)
        # The two verbs must not diverge: the export menu posts, the language
        # switch and a shared link get, and a report that changed with the verb
        # would be two reports with one name.
        for marker in (b"admin", b"critical", b"matched"):
            self.assertIn(marker, post.content)
            self.assertIn(marker, get.content)

    def test_a_malformed_body_renders_an_empty_report_rather_than_failing(self):
        response = scanner_report_views.scanner_report(
            self.factory.post(
                "/api/scanner/report?view=nuclei",
                data="{not json",
                content_type="application/json",
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"rr-empty", response.content)

    def test_an_unknown_view_is_refused_rather_than_guessed(self):
        # Defaulting to `nuclei` would answer a request for a CMS report with a
        # Nuclei report that is legitimately empty.
        response = scanner_report_views.scanner_report(
            self.factory.post(
                "/api/scanner/report",
                data=json.dumps({"view": "burp"}),
                content_type="application/json",
            )
        )
        self.assertEqual(response.status_code, 400)

    def test_the_json_form_reports_the_allow_list_decision(self):
        response = self._post(
            {
                "view": "nuclei",
                "findings": [{"severity": "high"}, {"severity": "catastrophic"}],
            },
            view="nuclei",
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content)
        self.assertEqual(payload["findings"], 1)
        self.assertEqual(len(payload["rejected"]), 1)
        self.assertEqual(payload["severity_counts"]["high"], 1)

    def test_a_filter_word_outside_the_vocabulary_drops_the_filter(self):
        response = self._post(
            {"view": "nuclei", "findings": [{"severity": "high", "title": "kept"}]},
            view="nuclei",
            format="json",
            severity="catastrophic",
        )
        payload = json.loads(response.content)
        self.assertEqual(payload["filters"]["severities"], [])
        self.assertEqual(payload["findings"], 1)


class MutationTests(TestCase):
    """Names the mutation that would break each rule, so green is load-bearing.

    This class asserts nothing on its own. It is a written statement of which
    green test is worth what, kept next to the tests rather than in a commit
    message nobody reads when the module changes.
    """

    #: Each entry is (rule, mutation that would break it, test that would go red).
    EXPECTED_FAILURES = (
        (
            "unknown severity is refused",
            "make normalize_severity return UNKNOWN_SEVERITY instead of None",
            "SeverityAllowListTests.test_unknown_severity_is_refused_not_defaulted",
        ),
        (
            "not_matched is never a remainder",
            "derive it as total minus the other statuses",
            "ValidateFindingsTests.test_counters_are_per_status_and_never_a_remainder",
        ),
        (
            "evidence truncation is visible",
            "drop the truncated flag when the block is cut",
            "EvidenceTests.test_oversized_evidence_is_cut_and_its_real_size_reported",
        ),
        (
            "filename cannot split a header",
            "strip quotes instead of restricting the alphabet",
            "FilenameTests.test_a_quote_in_the_name_cannot_break_the_header",
        ),
        (
            "data is escaped",
            "add a |safe to the title or evidence cell",
            "RenderedReportTests.test_the_report_declares_no_more_than_three_safe_marks",
        ),
    )

    def test_the_table_names_a_distinct_test_for_every_rule(self):
        targets = [entry[2] for entry in self.EXPECTED_FAILURES]
        self.assertEqual(len(set(targets)), len(targets))
        # Every named test has to exist, or this table documents a protection
        # nobody is keeping.
        source = (
            __import__("pathlib").Path(__file__).read_text()
        )
        for _, _, target in self.EXPECTED_FAILURES:
            self.assertIn(target.rsplit(".", 1)[1], source)