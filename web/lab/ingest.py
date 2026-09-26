"""Batched Project knowledge-base ingestion for durable HTTP evidence.

`signals.ingest_traffic_record` registers endpoints, merges technology hints and
remembers secret header references for every stored `TrafficRecord`. That logic
is correct but inherently per-row: one passive capture burst of a few hundred
exchanges performs hundreds of `ProjectEndpoint` lookups and unconditional
`save()` calls against the same handful of rows, plus a `tech_stack` write per
exchange.

The work is idempotent, so a batch can be folded first and written once. The
resulting database state is identical to applying the per-row path N times, while
the number of statements drops from O(rows) to O(distinct endpoints/headers).

This is a write-amplification fix, not an execution budget: nothing here limits
how much traffic is ingested.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from django.utils import timezone

from .models import Project, ProjectEndpoint, ProjectSecret, TrafficCaptureContext


TECH_HEADERS = {
    "server": "server",
    "x-powered-by": "powered_by",
    "via": "via",
}
SECRET_HEADER_NAMES = {
    "authorization": "api_key",
    "x-api-key": "api_key",
    "x-api-token": "api_key",
    "cookie": "cookie",
    "set-cookie": "cookie",
}
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


def header_value(headers, name):
    """Case-insensitive header lookup shared by the batch and single paths."""
    for key, value in (headers or {}).items():
        if str(key).lower() == name:
            return str(value or "")
    return ""


def _merged_headers(record):
    headers = {str(key).lower(): value for key, value in (record.request_headers or {}).items()}
    headers.update({str(key).lower(): value for key, value in (record.response_headers or {}).items()})
    return headers


class KnowledgeBaseIngestor:
    """Fold a batch of records into the fewest possible statements.

    Usage: build the list, call :meth:`run`. The ingestor is single-use so the
    accumulators never leak between batches.
    """

    def __init__(self) -> None:
        # (project_id, method, path) -> folded endpoint state.
        self._endpoints: dict[tuple[int, str, str], dict] = {}
        # project_id -> merged tech stack additions.
        self._tech: dict[int, dict[str, list[str]]] = {}
        # Deduplicated (project_id, secret_type, key_name, source_url) tuples.
        self._secrets: set[tuple[int, str, str, str]] = set()
        self._projects: set[int] = set()

    # -- accumulation ----------------------------------------------------
    def add(self, record) -> None:
        project_id = getattr(record, "project_id", None)
        if not project_id:
            return
        self._projects.add(project_id)

        url = record.url or ""
        parsed = urlsplit(url)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            key = (project_id, (record.method or "GET").upper(), parsed.path or "/")
            entry = self._endpoints.get(key)
            if entry is None:
                entry = {"sample_url": url, "statuses": [], "parameters": set()}
                self._endpoints[key] = entry
            if not entry["sample_url"]:
                entry["sample_url"] = url
            status = record.status_code
            if status is not None:
                try:
                    value = int(status)
                except (TypeError, ValueError):
                    value = None
                if value is not None and value not in entry["statuses"]:
                    entry["statuses"].append(value)
            entry["parameters"].update(
                key_name for key_name, _ in parse_qsl(parsed.query, keep_blank_values=True)
            )

        headers = _merged_headers(record)
        for header_name, tech_key in TECH_HEADERS.items():
            value = header_value(record.response_headers, header_name)
            if not value:
                continue
            bucket = self._tech.setdefault(project_id, {})
            values = bucket.setdefault(tech_key, [])
            if value not in values:
                values.append(value)

        for header_name, secret_type in SECRET_HEADER_NAMES.items():
            if headers.get(header_name):
                key_name = "Authorization" if header_name == "authorization" else header_name
                self._secrets.add((project_id, secret_type, key_name, url))
        if JWT_RE.search(" ".join(str(value) for value in headers.values())):
            self._secrets.add((project_id, "jwt", "JWT token", url))

    def add_many(self, records) -> None:
        for record in records:
            self.add(record)

    # -- flush -----------------------------------------------------------
    def run(self) -> dict[str, int]:
        """Write the folded batch. Returns counters for diagnostics and tests."""
        counters = {
            "endpoints": 0,
            "endpoints_updated": 0,
            "tech_updates": 0,
            "secrets": 0,
            "projects": 0,
        }
        if not self._projects:
            return counters

        # One read of the endpoints already registered for these projects, so
        # the merge happens in Python instead of one get_or_create per row.
        existing = {}
        for row in ProjectEndpoint.objects.filter(
            project_id__in=self._projects
        ).values("id", "project_id", "method", "path", "sample_url", "statuses", "parameters"):
            existing[(row["project_id"], row["method"], row["path"])] = row

        now = timezone.now()
        to_create = []
        to_update = []
        for key, entry in self._endpoints.items():
            found = existing.get(key)
            if found is None:
                to_create.append(ProjectEndpoint(
                    project_id=key[0],
                    method=key[1],
                    path=key[2],
                    sample_url=entry["sample_url"],
                    statuses=list(entry["statuses"]),
                    parameters=sorted(entry["parameters"]),
                    last_seen=now,
                ))
                counters["endpoints"] += 1
                continue

            statuses = list(found["statuses"] or [])
            changed_statuses = False
            for value in entry["statuses"]:
                if value not in statuses:
                    statuses.append(value)
                    changed_statuses = True
            known_parameters = set(found["parameters"] or [])
            merged_parameters = sorted(known_parameters | entry["parameters"])
            changed_parameters = merged_parameters != sorted(known_parameters)

            # last_seen always advances, matching the per-row register_endpoint.
            endpoint = ProjectEndpoint(id=found["id"], last_seen=now)
            fields = ["last_seen"]
            if changed_statuses:
                endpoint.statuses = statuses
                fields.append("statuses")
            if changed_parameters:
                endpoint.parameters = merged_parameters
                fields.append("parameters")
            to_update.append((endpoint, fields))
            counters["endpoints_updated"] += 1

        if to_create:
            ProjectEndpoint.objects.bulk_create(to_create, batch_size=200)
        if to_update:
            # bulk_update emits one CASE statement per batch, so the statement
            # count does not grow with the number of endpoints the batch touched.
            by_field: dict[str, list[ProjectEndpoint]] = {}
            for endpoint, fields in to_update:
                for field in fields:
                    by_field.setdefault(field, []).append(endpoint)
            for field, endpoints in by_field.items():
                ProjectEndpoint.objects.bulk_update(endpoints, [field], batch_size=200)

        stacks = {
            project.id: (project.tech_stack or {})
            for project in Project.objects.filter(id__in=self._projects)
        }
        counters["projects"] = len(stacks)

        # One technology-stack write per project that actually changed.
        for project_id, additions in self._tech.items():
            if project_id not in stacks:
                continue
            merged = dict(stacks.get(project_id) or {})
            for tech_key, values in additions.items():
                current = merged.get(tech_key)
                current = list(current) if isinstance(current, list) else ([current] if current else [])
                for value in values:
                    if value not in current:
                        current.append(value)
                merged[tech_key] = current
            if merged != stacks.get(project_id):
                Project.objects.filter(id=project_id).update(tech_stack=merged)
                counters["tech_updates"] += 1

        # One get_or_create per distinct secret reference.
        for project_id, secret_type, key_name, source_url in self._secrets:
            if not source_url:
                continue
            ProjectSecret.objects.get_or_create(
                project_id=project_id,
                secret_type=secret_type,
                key_name=key_name,
                source_url=source_url,
                defaults={"value_ref": ""},
            )
            counters["secrets"] += 1

        return counters


def ingest_traffic_batch(records) -> dict[str, int]:
    """Fold `records` into the Project knowledge base with batched statements."""
    ingestor = KnowledgeBaseIngestor()
    ingestor.add_many(records)
    return ingestor.run()


def ingest_traffic_record(record) -> dict[str, int]:
    """Single-record entry point used by the post_save receiver."""
    return ingest_traffic_batch([record])


def capture_contexts_by_token(tokens) -> dict[str, object]:
    """Resolve many opaque capture tokens in one query.

    `public_traffic_event` runs once per event; without this cache a snapshot of
    a few hundred exchanges issues a few hundred identical token lookups.
    """
    wanted = {str(token).strip() for token in tokens if str(token or "").strip()}
    if not wanted:
        return {}
    rows = TrafficCaptureContext.objects.select_related("project").filter(token__in=wanted)
    return {row.token: row for row in rows}
