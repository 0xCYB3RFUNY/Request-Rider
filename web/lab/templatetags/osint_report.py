"""Template filters for the server-rendered OSINT result reports.

The viewer has to show a six-figure row count and a cell that holds a JSON
object without either becoming unreadable, so the formatting lives here rather
than in the template: a template that formats numbers by hand is how two pages
end up disagreeing about what 19171 looks like.
"""
from django import template
from django.utils.safestring import mark_safe

register = template.Library()

# _GROUP_SEPARATOR is a narrow no-break space. It is the separator both English
# and Ukrainian typography use for a thousands group, and it does not wrap in
# the middle of a number the way an ordinary space would.
_GROUP_SEPARATOR = " "



@register.filter
def intcomma(value):
    """Render an integer with grouped thousands, for row and byte counts."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return ""
    sign = "-" if number < 0 else ""
    digits = str(abs(number))
    parts = []
    while len(digits) > 3:
        parts.insert(0, digits[-3:])
        digits = digits[:-3]
    parts.insert(0, digits)
    return sign + _GROUP_SEPARATOR.join(parts)


@register.filter
def provenance_parts(value):
    """Turn a provenance cell into the short labels the viewer shows as chips."""
    from lab.osint_exports import provenance_parts as split

    return split(value)


@register.simple_tag(takes_context=True)
def tr(context, key):
    """Render one report label in the language the page was rendered in.

    The tag takes the language from the page context rather than from a
    dictionary the template indexes by hand, so a missing key fails loudly
    instead of printing nothing into an otherwise translated page.
    """
    from lab.report_i18n import report_text

    return report_text(context.get("language"), key)


@register.simple_tag(takes_context=True)
def kind_label(context, kind):
    """Render a row-kind label, translating only the kind the report invented.

    The kind is also the filter value in the query string, and that value stays
    the canonical key in both languages, so a saved `?type=` link keeps working
    after the language changes. Only the visible word follows the page.
    """
    from lab.report_i18n import report_text

    label = str(kind or "").strip()
    if label.lower() == "link":
        return report_text(context.get("language"), "link")
    # Every other kind is an entity type the transform produced. It is data, and
    # a translated type would no longer match the file it came from.
    return label





@register.filter
def get_item(mapping, key):
    """Read one key of a row dict, so a column renders whatever it is named."""
    if not isinstance(mapping, dict):
        return ""
    return mapping.get(key, "")


@register.filter
def row_cell(row, column):
    """Render one table cell for a column name, with a dash for an empty value.

    The dash keeps a column readable when a transform filled it for only some
    rows, and every value is escaped on the way out because a row came from a
    third-party certificate index and is never markup.
    """
    from django.utils.html import escape

    if not isinstance(row, dict):
        return ""
    text = str(row.get(column) or "")
    if not text:
        return mark_safe('<span class="rr-dash">—</span>')
    return escape(text)
