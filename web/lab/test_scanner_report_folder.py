"""Атрибутація теки у серверному звіті сканера.

HTML-звіт, який віддає `GET /api/scanner/report`, рендериться на сервері шаблоном
`lab/scanner_report.html`. Для обходу теки це єдине місце, де аналітик бачить, з якої
папки прийшов файл: `path` був у рядку і в `data-rr-search` (фільтр пошуку
розгортає всі значення рядка), тобто шлях був у документі — і невидимий.

Ці перевірки живуть окремо від `test_scanner_report.py`, бо стосуються одного
аспекту — шляху, а не словника статусів, і не повинні зникати разом з чужим
переписуванням того файлу.
"""

from django.test import TestCase

from lab.scanner_exports import build_scanner_report
from lab.templatetags.scanner_report import row_search


class ScannerReportFolderAttributionTests(TestCase):
    """A folder run must say which folder each file came from, in every format."""

    def _report(self, templates):
        return build_scanner_report(
            {
                "engine": "nuclei",
                "url": "https://target.example.test/",
                "findings": [],
                "templates": templates,
                "stats": {},
            },
            view="nuclei",
        )

    def _html(self, report):
        from django.template.loader import render_to_string

        return render_to_string(
            "lab/scanner_report.html",
            {
                "language": "en",
                "other_language": "uk",
                "other_language_label": "Українська",
                "report_title": "Scanner",
                "back_url": "/",
                "back_label": "Back",
                "all_severities": ("critical", "high", "medium", "low", "info", "unknown"),
                "all_statuses": ("matched", "not_matched", "no_request", "workflow", "skipped", "invalid", "duplicate"),
                "filter_severities": [],
                "filter_statuses": [],
                **report,
            },
        )

    def test_row_carries_the_path_as_a_machine_readable_attribute(self):
        report = self._report(
            [
                {"name": "check-00.yaml", "path": "templates/http/cves/2024/check-00.yaml", "status": "matched"},
                {"name": "check-01.yaml", "path": "templates/http/misconfig/check-01.yaml", "status": "invalid",
                 "reason": "missing info.author"},
            ]
        )
        html = self._html(report)
        self.assertIn('data-rr-path="templates/http/cves/2024/check-00.yaml"', html)
        self.assertIn('data-rr-path="templates/http/misconfig/check-01.yaml"', html)

    def test_the_path_is_printed_not_only_stored(self):
        # The attribute is for a machine; the report is for a person. A path that
        # is only in an attribute is invisible to the reader of the exported file,
        # which is the whole point of saying where a file came from.
        report = self._report(
            [{"name": "check-00.yaml", "path": "templates/http/cves/2024/check-00.yaml", "status": "matched"}]
        )
        html = self._html(report)
        self.assertIn("templates/http/cves/2024/check-00.yaml</span>", html)

    def test_a_flat_upload_does_not_repeat_its_own_name_as_a_path(self):
        # `name` and `path` are the same string when a single file was uploaded,
        # and printing both would put the filename on screen twice.
        report = self._report([{"name": "solo.yaml", "path": "solo.yaml", "status": "matched"}])
        html = self._html(report)
        self.assertIn('data-rr-path="solo.yaml"', html)
        # The name is printed once, in its own cell, and the path line is not
        # repeated underneath it — the two fields are the same string here.
        self.assertIn(">solo.yaml</td>", html)
        self.assertNotIn('<span class="rr-muted" title="solo.yaml">', html)

    def test_search_still_finds_a_row_by_its_folder(self):
        row = {"name": "check-00.yaml", "path": "templates/http/cves/2024/check-00.yaml", "status": "matched"}
        haystack = row_search(row).lower()
        self.assertIn("cves", haystack)
        self.assertIn("check-00.yaml", haystack)
