"""Fill in the secret values that were never collected.

The ingest wrote an empty string into `ProjectSecret.value_ref` for every secret
it detected, so the Project hub, the AI snapshot and every exported report could
only say "a JWT was seen at this URL". The header that carried the credential was
on the exchange the whole time — `ProjectExchange` keeps the complete request and
response, headers included — so the value is recoverable from evidence the
Project already stores, without re-capturing anything.

One statement per project, not per row: the exchanges are folded into a lookup
keyed by the URL first, and only then read against the project's secrets. The
newest exchange for a URL wins, because the newest observation of a credential is
the one currently in use.
"""

import re

from django.db import migrations

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")

# The header each `key_name` came from. `Authorization` is stored capitalised by
# the ingest while the rest keep the wire name, so the lookup normalises both.
HEADER_FOR_KEY = {
    "Authorization": "authorization",
    "authorization": "authorization",
    "x-api-key": "x-api-key",
    "x-api-token": "x-api-token",
    "cookie": "cookie",
    "set-cookie": "set-cookie",
}


def _merged_headers(exchange):
    """Request and response headers of one exchange, lower-cased keys."""
    headers = {}
    for source in (exchange.get("request_headers") or {}, exchange.get("response_headers") or {}):
        if isinstance(source, dict):
            for key, value in source.items():
                headers.setdefault(str(key).lower(), "" if value is None else str(value))
    return headers


def _index_project_exchanges(exchanges):
    """URL -> the newest exchange carrying it, for one project.

    The queryset is ordered by `(timestamp, id)` and this comparison keeps that
    order on the same tie-break, so the winner does not depend on which row the
    database happened to return first.
    """
    newest = {}
    for exchange in exchanges:
        url = exchange["url"]
        current = newest.get(url)
        if current is None or (exchange["timestamp"], exchange["id"]) > (
            current["timestamp"], current["id"]
        ):
            newest[url] = exchange
    return newest


def _value_for(secret, exchange):
    """The credential a secret row refers to, or `""` when it is not recoverable."""
    if exchange is None:
        return ""
    headers = _merged_headers(exchange)

    header_name = HEADER_FOR_KEY.get(secret["key_name"])
    if header_name and headers.get(header_name):
        return headers[header_name]

    key_name = secret["key_name"]
    if key_name == "JWT token":
        for text in headers.values():
            match = JWT_RE.search(text)
            if match:
                return match.group(0)
    elif key_name.startswith("JWT token "):
        # `JWT token 2`, `JWT token 3`, … — the ingest suffixes every distinct
        # token after the first so that two credentials on one exchange are two
        # rows rather than one overwriting the other.
        position = key_name.rsplit(" ", 1)[-1]
        if position.isdigit():
            found = []
            for text in headers.values():
                for match in JWT_RE.finditer(text):
                    if match.group(0) not in found:
                        found.append(match.group(0))
            index = int(position) - 1
            if index < len(found):
                return found[index]
    return ""


def backfill_secret_values(apps, schema_editor):
    ProjectSecret = apps.get_model("lab", "ProjectSecret")
    ProjectExchange = apps.get_model("lab", "ProjectExchange")

    pending = ProjectSecret.objects.filter(value_ref="").exclude(source_url="")
    project_ids = list(
        pending.values_list("project_id", flat=True).distinct().order_by("project_id")
    )

    for project_id in project_ids:
        secrets = list(
            ProjectSecret.objects.filter(project_id=project_id, value_ref="")
            .exclude(source_url="")
            .values("id", "key_name", "source_url")
        )
        if not secrets:
            continue
        urls = {secret["source_url"] for secret in secrets}
        exchanges = list(
            ProjectExchange.objects.filter(project_id=project_id)
            .filter(url__in=urls)
            .values("id", "url", "timestamp", "request_headers", "response_headers")
            .order_by("timestamp", "id")
        )
        if not exchanges:
            continue
        newest = _index_project_exchanges(exchanges)

        updates = []
        for secret in secrets:
            value = _value_for(secret, newest.get(secret["source_url"]))
            if value:
                updates.append(ProjectSecret(id=secret["id"], value_ref=value))
        if updates:
            ProjectSecret.objects.bulk_update(updates, ["value_ref"], batch_size=200)


class Migration(migrations.Migration):

    dependencies = [
        ("lab", "0058_projectsecret_dedup_and_unique"),
    ]

    operations = [
        migrations.RunPython(backfill_secret_values, migrations.RunPython.noop),
    ]