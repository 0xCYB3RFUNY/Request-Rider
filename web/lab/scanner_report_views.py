"""The HTTP entry point for the server-rendered Scanner report.

This view lives in its own module rather than in `views.py` because another
session holds `views.py` for the JavaScript-analysis work, and two sessions
writing one file is how a change disappears. The only wiring it needs from
`urls.py` is one `path(...)`, and every rule it follows comes from somewhere
that already exists:

- the language comes from `report_language` and the `?lang=` setter behaviour
  comes from `_report_page`, exactly as the OSINT reports do it, so a Scanner
  report and an OSINT report cannot disagree about which language the workspace
  is speaking;
- the escaping comes from the Django template layer, because nothing in the
  template marks a value safe except the three project constants;
- the vocabulary comes from `lab.scanner_exports`, so the allow-lists and the
  counters that appear on the page come from one source.

The payload arrives from the browser because a live scan result lives in browser
state, not in a database row: `ScannerRun.findings` is the durable record of a
*completed* run, and the report an analyst exports mid-run is over a result the
server has never been told about. So the view accepts the run document the same
way the export menu does, and every field in it is treated as untrusted — which
is the whole reason the allow-lists are on this side of the boundary.
"""

import json

from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from lab import scanner_exports
from lab.report_i18n import report_language, report_text
from lab.views import _report_page


@csrf_exempt
@require_http_methods(["GET", "POST"])
def scanner_report(request):
    """Render one Scanner report on the server.

    `GET` is the readable URL and the one a language switch returns to, so it
    accepts the document in a query parameter as well. `POST` is what the export
    menu uses, because a scan over a large corpus produces a result larger
    than a URL is for. Both read the same body and take the same path, so the two
    verbs cannot produce two different reports from the same input.
    """
    if request.method == "POST":
        payload = _read_json(request) or {}
    else:
        payload = _read_embedded(request) or {}

    view = str(payload.get("view") or request.GET.get("view") or "active").strip().lower()
    if view not in {"active", "corpus", "cms", "nuclei"}:
        # An unknown view is a naming mistake, and defaulting to `active` would
        # answer a request for a CMS report with an Active report that is
        # legitimately empty. A 400 says what was wrong.
        return JsonResponse(
            {"error": "view must be one of: active, corpus, cms, nuclei", "received": view[:64]},
            status=400,
        )

    filters = _filters(request)
    report = scanner_exports.build_scanner_report(payload, view=view, **filters)

    # `format=html` renders the page; `format=json` returns the same validated
    # document the page was built from. The second form exists so that the
    # allow-list decision is inspectable without parsing a rendered table — a
    # rejection is a claim about upstream behaviour, and it has to be checkable.
    if str(request.GET.get("format") or payload.get("format") or "").lower() == "json":
        return JsonResponse(
            {
                "findings": report["findings_total"],
                "templates": report["templates_total"],
                "rejected": report["rejected"],
                "severity_counts": report["severity_counts"],
                "status_counts": report["status_counts"],
                "highest_severity": report["highest_severity"],
                "filters": report["filters"],
            }
        )

    return _report_page(
        request,
        "lab/scanner_report.html",
        _scanner_context(request, view, report),
    )


def _scanner_context(request, view, report):
    """Build the context the scanner report template renders from.

    This mirrors the shape `views._report_context` builds, and it reads the
    language from the same `report_language`, so the two report families cannot
    drift apart in wording. It is not a second implementation of that helper:
    the helper is wrapped in `@csrf_protect`, and a wrapped helper returns an
    `HttpResponseForbidden` instead of a context when it is called on a POST that
    carries no CSRF token. This endpoint is CSRF-exempt because it accepts a
    document rather than changing server state, so calling the wrapped helper
    here made every POST a 500. The keys below are the ones this template uses;
    `t_result_files` is carried too so the shared template conventions still
    resolve if it is ever included from this page.
    """
    language = report_language(request)
    other = "uk" if language == "en" else "en"
    return {
        "language": language,
        "other_language": other,
        "other_language_label": "Українська" if other == "uk" else "English",
        "t_result_files": report_text(language, "result_files"),
        "report_title": report_text(language, "scanner.view_active" if view == "active" else ("scanner.view_corpus" if view == "corpus" else ("scanner.view_nuclei" if view == "nuclei" else "scanner.view_cms"))),
        "report_css": scanner_exports.EXPORT_REPORT_CSS,
        "report_js": scanner_exports.EXPORT_REPORT_JS,
        "report_brand": scanner_exports.EXPORT_REPORT_BRAND,
        "back_url": "/",
        "back_label": report_text(language, "scanner.back_to_workspace"),
        "all_severities": scanner_exports.SEVERITIES,
        "all_statuses": scanner_exports.STATUSES,
        "filter_severities": report["filters"]["severities"],
        "filter_statuses": report["filters"]["statuses"],
        **report,
    }


def _read_json(request):
    """Return a parsed JSON body, or None when there is nothing to parse.

    A malformed body is a None rather than a 400: the browser sends this
    document, and a truncated body means the page should say "no rows" rather
    than refuse to open. `format=json` on the request still reports the empty
    result, so the caller can see what happened.
    """
    if not request.body:
        return None
    try:
        parsed = json.loads(request.body)
    except (ValueError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _read_embedded(request):
    """Return the document carried in a query parameter, if any."""
    raw = request.GET.get("payload")
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _filters(request):
    """Read the requested severity and status filters out of the query string.

    Only the query string is read, for GET and POST alike, so the two verbs cannot
    filter differently. The values themselves are cleaned by
    `scanner_exports.validate_filters`; a word outside the vocabulary is dropped
    rather than refused, because a filter that named nothing the tool knows
    should show an empty table, not fail to open.
    """
    return {
        "severities": request.GET.getlist("severity"),
        "statuses": request.GET.getlist("status"),
        "query": request.GET.get("q", ""),
    }


# `_title` and `_back_label` used to live here and were folded into
# `_scanner_context`, which is their only caller. Two helpers that resolve a
# label are the shape that lets the title and the body come from different
# sources, so there is now one place that reads the language.