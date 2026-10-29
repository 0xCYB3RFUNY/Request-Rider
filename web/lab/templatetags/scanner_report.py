"""Template tags for the server-rendered Scanner report.

The three filters here exist so that the report template never has to implement a
rule. `finding_status` turns a vocabulary word into its wording, `row_search`
flattens a row into the string the report's own search reads, and
`evidence_block` renders the bulky part of a finding.

`evidence_block` returns `mark_safe` output, and that is the one mark_safe in
this file. It is safe because it escapes the evidence itself and then wraps it in
markup of this project's own: the `<pre>` and the surrounding `<span>` are literal
strings written here, and the only interpolated value is passed through
`django.utils.html.escape` on the way in. A template filter that escapes its own
interpolations and adds fixed tags around them is the correct shape; a `|safe` in
the template around a raw field is the shape that is not.
"""
from django import template
from django.utils.html import escape
from django.utils.safestring import mark_safe

from lab.scanner_exports import STATUSES, evidence_text

register = template.Library()


@register.simple_tag(takes_context=True)
def finding_status(context, status):
    """Render one per-file status in the language the page was rendered in.

    A status the vocabulary does not define gets its own wording rather than the
    wording of the nearest known one. Falling back to `not_matched` would put a
    claim on the page that the run never made: "the file was never executed" and
    "the file ran and matched nothing" are opposite statements about the same
    file.
    """
    from lab.report_i18n import report_text

    language = context.get("language")
    word = str(status or "").strip()
    key = f"scanner.status.{word}" if word in STATUSES else "scanner.status.unknown"
    return report_text(language, key)


@register.filter
def row_search(row):
    """Flatten one report row into the text the search box reads.

    The value lands in a `data-` attribute, so Django escapes it and the browser
    reads it back as the original text. Lower-casing happens in JavaScript, once,
    rather than here, so the attribute holds what the row actually said.
    """
    if not isinstance(row, dict):
        return ""
    parts = []
    for value in row.values():
        if isinstance(value, list):
            parts.extend(str(entry) for entry in value)
            continue
        if isinstance(value, dict):
            parts.extend(str(entry) for entry in value.values())
            continue
        parts.append(str(value))
    return " ".join(part for part in parts if part)


@register.simple_tag(takes_context=True)
def evidence_block(context, row):
    """Render one finding's evidence as a bounded, escaped block.

    Three things happen here and none of them belong in the template. The evidence
    is bounded, so a matcher output of a hundred thousand characters cannot make
    the document unusable. The block states the real size it wrote when it cut
    something, because a report that silently truncated its evidence and printed
    itself identically to one that did not misstates its own evidence. And the
    text is escaped before the markup around it is added.

    An empty finding gets a dash rather than an empty `<pre>`: a bordered empty
    box next to every finding without evidence reads as a rendering failure.
    """
    from lab.report_i18n import report_text

    text, total, truncated = evidence_text(row)
    if not text:
        return mark_safe('<span class="rr-dash">—</span>')
    body = escape(text)
    if truncated:
        note = report_text(context.get("language"), "scanner.evidence_truncated").format(count=total)
        return mark_safe(
            f'<p class="rr-note">{escape(note)}</p><pre class="rr-evidence">{body}</pre>'
        )
    return mark_safe(f'<pre class="rr-evidence">{body}</pre>')