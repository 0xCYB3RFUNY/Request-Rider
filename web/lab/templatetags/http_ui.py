from django import template
from django.utils.html import format_html

register = template.Library()


@register.filter
def status_badge(status):
    value = str(status or "").strip()
    try:
        code = int(value)
    except (TypeError, ValueError):
        code = 0
    if 100 <= code < 200:
        tone = "status-1xx"
    elif 200 <= code < 300:
        tone = "status-2xx"
    elif 300 <= code < 400:
        tone = "status-3xx"
    elif 400 <= code < 500:
        tone = "status-4xx"
    elif 500 <= code < 600:
        tone = "status-5xx"
    else:
        tone = "status-error"
    return format_html('<span class="status-badge {}">{}</span>', tone, value or "—")
