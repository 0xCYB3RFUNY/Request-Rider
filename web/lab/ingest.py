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

import base64
import json
import re
from urllib.parse import parse_qsl, urlsplit

from django.utils import timezone

from .models import (
    Project,
    ProjectEndpoint,
    ProjectExchange,
    ProjectSecret,
    TrafficCaptureContext,
)


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
HASH_HEX_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")
IDENTIFIER_RE = re.compile(r"^[a-zA-Z0-9_\-\.\[\]]{1,64}$")
PASSWORD_KEYS = {"password", "passwd", "pass", "pwd", "user_password", "new_password", "old_password"}
API_KEY_KEYS = {"api_key", "apikey", "access_token", "auth_token", "client_secret", "secret_key"}
STATIC_EXTENSIONS = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map")
MAX_BODY_SCAN_BYTES = 2 * 1024 * 1024


def _decode_jwt_payload(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        raw = base64.urlsafe_b64decode(payload)
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def header_value(headers, name):
    """Case-insensitive header lookup shared by the batch and single paths."""
    if not isinstance(headers, dict):
        return ""
    for key, value in headers.items():
        if str(key).lower() == name:
            return str(value or "")
    return ""


def _merged_headers(record):
    headers = {}
    if isinstance(record.request_headers, dict):
        headers.update({str(key).lower(): value for key, value in record.request_headers.items()})
    if isinstance(record.response_headers, dict):
        headers.update({str(key).lower(): value for key, value in record.response_headers.items()})
    return headers


def project_exchange_key(record) -> tuple[int, str] | None:
    """The identity of one exchange inside a Project, or `None` if it has none.

    The capture row's own `(session, event)` pair is the identity, because that
    is what the capture archive already deduplicates on. A record without one —
    a Repeater row, or a project import that restored a bundle from another
    installation — is given a key derived from what it carries, so it is still
    copied exactly once instead of once per poll.
    """
    project_id = getattr(record, "project_id", None)
    if not project_id:
        return None
    session = getattr(record, "proxy_session", None)
    event = getattr(record, "proxy_event_id", None)
    if session is not None and event is not None:
        return (project_id, f"{session}:{event}")
    # The fallback has to be stable across polls of the same snapshot and
    # different across two exchanges that really are different, so it mixes the
    # request identity with the moment and the outcome.
    stamp = getattr(record, "timestamp", None)
    return (
        project_id,
        "derived:{method} {url} {status} {latency} {stamp}".format(
            method=(getattr(record, "method", "") or "").upper(),
            url=getattr(record, "url", "") or "",
            status=getattr(record, "status_code", None),
            latency=getattr(record, "latency_ms", None),
            stamp=stamp.isoformat() if stamp else "",
        ),
    )


def _project_exchange_from(record) -> dict:
    """The Project's own copy of one capture row, field for field.

    `event_key` is not here: it is the copy's identity, so the caller passes it
    next to the project id rather than it travelling with the payload.
    """
    return {
        "timestamp": record.timestamp,
        "source": record.source,
        "method": record.method,
        "url": record.url,
        "host": record.host or "",
        "source_ip": record.source_ip,
        "status_code": record.status_code,
        "latency_ms": record.latency_ms,
        "response_size": record.response_size,
        "response_content_type": record.response_content_type or "",
        "scope_status": record.scope_status,
        "request_headers": record.request_headers or {},
        "request_body": record.request_body,
        "request_body_encoding": record.request_body_encoding or "utf8",
        "request_body_base64": record.request_body_base64 or "",
        "response_headers": record.response_headers or {},
        "response_body": record.response_body,
        "response_body_encoding": record.response_body_encoding or "utf8",
        "response_body_base64": record.response_body_base64 or "",
        "capture_context_id": record.capture_context_id,
    }


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
        # Deduplicated (project_id, secret_type, key_name, source_url) -> the
        # complete secret value as it travelled on the wire. The value is the
        # point: a row that says only "a JWT was seen here" costs the analyst a
        # manual re-capture to learn the one thing the row exists to record.
        self._secrets: dict[tuple[int, str, str, str], str] = {}
        # (project_id, event_key) -> the Project's own copy of one exchange.
        self._exchanges: dict[tuple[int, str], dict] = {}
        self._projects: set[int] = set()

    # -- accumulation ----------------------------------------------------
    def add(self, record) -> None:
        project_id = getattr(record, "project_id", None)
        if not project_id:
            return
        self._projects.add(project_id)
        # The Project keeps its own copy of the exchange, so the evidence it
        # exports does not depend on the capture archive surviving a `Clear` in
        # the Traffic tab. The copy is accumulated here and written in the same
        # run as the folded endpoints, which is what keeps the two in step: there
        # is no second place to forget.
        key = project_exchange_key(record)
        if key and key not in self._exchanges:
            self._exchanges[key] = _project_exchange_from(record)

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
            header_value_text = headers.get(header_name)
            if header_value_text:
                key_name = "Authorization" if header_name == "authorization" else header_name
                self._secrets[(project_id, secret_type, key_name, url)] = str(header_value_text)
        # Every distinct JWT on the exchange, not just the first match: a request
        # that carries a token in `Authorization` and a second one in `Cookie` is
        # one exchange with two credentials, and the Project's unique key is
        # `(project, secret_type, key_name, source_url)`, so the second one needs
        # its own row to exist at all. The suffix is what keeps the two apart.
        seen_jwts: set[str] = set()
        for header_text in (str(value) for value in headers.values()):
            for match in JWT_RE.finditer(header_text):
                token = match.group(0)
                if token in seen_jwts:
                    continue
                seen_jwts.add(token)
                key_name = "JWT token" if len(seen_jwts) == 1 else f"JWT token {len(seen_jwts)}"
                self._secrets[(project_id, "jwt", key_name, url)] = token

        request_body_text = str(record.request_body or "") if getattr(record, "request_body", None) else ""
        response_body_text = str(record.response_body or "") if getattr(record, "response_body", None) else ""

        for body_text in (request_body_text, response_body_text):
            if body_text and len(body_text) <= MAX_BODY_SCAN_BYTES:
                for match in JWT_RE.finditer(body_text):
                    token = match.group(0)
                    if token in seen_jwts:
                        continue
                    seen_jwts.add(token)
                    key_name = "JWT token" if len(seen_jwts) == 1 else f"JWT token {len(seen_jwts)}"
                    self._secrets[(project_id, "jwt", key_name, url)] = token

        # Extract credentials and password hashes from discovered JWT payloads:
        seen_jwt_hashes: set[str] = set()
        for token in list(seen_jwts):
            jwt_payload = _decode_jwt_payload(token)
            if jwt_payload:
                self._collect_nested_secrets(project_id, url, jwt_payload, seen_jwt_hashes, source_label="JWT payload")

        # Parse request body (JSON and form-urlencoded) for passwords and api keys:
        parsed_path = (parsed.path or "").lower()
        is_static_asset = any(parsed_path.endswith(ext) for ext in STATIC_EXTENSIONS)

        if request_body_text and not is_static_asset and len(request_body_text) <= MAX_BODY_SCAN_BYTES:
            status = getattr(record, "status_code", None)
            is_valid_attempt = status is None or (isinstance(status, int) and status < 400)
            if is_valid_attempt:
                self._scan_body_for_secrets(project_id, url, request_body_text, allow_form=True)

        # Parse response body (JSON only) for passwords, hashes, and tokens:
        if response_body_text and len(response_body_text) <= MAX_BODY_SCAN_BYTES:
            self._scan_body_for_secrets(project_id, url, response_body_text, allow_form=False)

        # Parse URL query parameters for secrets / tokens:
        if parsed.query:
            self._scan_params_for_secrets(project_id, url, parse_qsl(parsed.query, keep_blank_values=False))

    def _record_secret(self, project_id: int, secret_type: str, base_name: str, url: str, value: str) -> None:
        """Register a secret under (project_id, secret_type, key_name, url), disambiguating duplicate keys."""
        if not url or not value:
            return
        tuple_key = (project_id, secret_type, base_name, url)
        if tuple_key in self._secrets and self._secrets[tuple_key] == value:
            return
        key_name = base_name
        idx = 2
        while (project_id, secret_type, key_name, url) in self._secrets:
            if self._secrets[(project_id, secret_type, key_name, url)] == value:
                return
            key_name = f"{base_name} #{idx}"
            idx += 1
        self._secrets[(project_id, secret_type, key_name, url)] = value

    def _collect_nested_secrets(self, project_id: int, url: str, obj: object, seen_hashes: set[str], source_label: str = "") -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                k_lower = str(k).lower()
                if isinstance(v, str) and v.strip():
                    val = v.strip()
                    if any(pk in k_lower for pk in PASSWORD_KEYS):
                        if HASH_HEX_RE.match(val):
                            if val not in seen_hashes:
                                seen_hashes.add(val)
                                label = f"Password Hash ({k})" if not source_label else f"Password Hash ({source_label} {k})"
                                self._record_secret(project_id, "password", label, url, val)
                        else:
                            label = f"Password ({k})" if not source_label else f"Password ({source_label} {k})"
                            self._record_secret(project_id, "password", label, url, val)
                    elif any(ak in k_lower for ak in API_KEY_KEYS) and not JWT_RE.match(val):
                        label = f"API Key ({k})"
                        self._record_secret(project_id, "api_key", label, url, val)
                self._collect_nested_secrets(project_id, url, v, seen_hashes, source_label)
        elif isinstance(obj, list):
            for item in obj:
                self._collect_nested_secrets(project_id, url, item, seen_hashes, source_label)

    def _scan_body_for_secrets(self, project_id: int, url: str, body_text: str, allow_form: bool = True) -> None:
        trimmed = body_text.strip()
        if (trimmed.startswith("{") and trimmed.endswith("}")) or (trimmed.startswith("[") and trimmed.endswith("]")):
            try:
                data = json.loads(trimmed)
                self._collect_nested_secrets(project_id, url, data, set())
                return
            except Exception:
                pass
        if allow_form and "=" in body_text and not trimmed.startswith("<"):
            try:
                params = parse_qsl(body_text, keep_blank_values=False)
                self._scan_params_for_secrets(project_id, url, params)
            except Exception:
                pass

    def _scan_params_for_secrets(self, project_id: int, url: str, params: list[tuple[str, str]]) -> None:
        for k, v in params:
            k_str = str(k).strip()
            if not IDENTIFIER_RE.match(k_str):
                continue
            k_lower = k_str.lower()
            val = str(v).strip()
            if not val or len(val) > 1024:
                continue
            if any(pk in k_lower for pk in PASSWORD_KEYS):
                if HASH_HEX_RE.match(val):
                    self._record_secret(project_id, "password", f"Password Hash ({k_str})", url, val)
                else:
                    self._record_secret(project_id, "password", f"Password ({k_str})", url, val)
            elif any(ak in k_lower for ak in API_KEY_KEYS) and not JWT_RE.match(val):
                self._record_secret(project_id, "api_key", f"API Key ({k_str})", url, val)

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
            "secrets_updated": 0,
            "projects": 0,
            "exchanges": 0,
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

        # Collect the secrets for these projects. The lookup key is the row's unique
        # constraint, so a key that is already present updates its value instead
        # of creating a second row, and a value that did not move is not written.
        existing_secrets = {
            (row["project_id"], row["secret_type"], row["key_name"], row["source_url"]): row
            for row in ProjectSecret.objects.filter(project_id__in=self._projects).values(
                "id", "project_id", "secret_type", "key_name", "source_url", "value_ref"
            )
        }
        to_create_secrets = []
        to_update_secrets = []
        for (project_id, secret_type, key_name, source_url), value in self._secrets.items():
            if not source_url or not value:
                continue
            secret_tuple = (project_id, secret_type, key_name, source_url)
            existing = existing_secrets.get(secret_tuple)
            if existing is None:
                to_create_secrets.append(
                    ProjectSecret(
                        project_id=project_id,
                        secret_type=secret_type,
                        key_name=key_name,
                        source_url=source_url,
                        value_ref=value,
                    )
                )
                counters["secrets"] += 1
            elif existing["value_ref"] != value:
                # The row exists and its value moved: a repeated poll of the same
                # snapshot finds every value already equal and writes nothing,
                # which is what keeps a live capture from rewriting the whole
                # secret table on every poll.
                to_update_secrets.append(ProjectSecret(id=existing["id"], value_ref=value))
                counters["secrets_updated"] += 1
        if to_create_secrets:
            ProjectSecret.objects.bulk_create(to_create_secrets, ignore_conflicts=True)
        if to_update_secrets:
            # One statement for the whole batch: `bulk_update` on partially
            # loaded rows would write every column, and only `value_ref` is the
            # ingest's to write.
            ProjectSecret.objects.bulk_update(to_update_secrets, ["value_ref"], batch_size=200)

        counters["exchanges"] = self._write_exchanges()
        return counters

    def _write_exchanges(self) -> int:
        """Write the Project's own copies, one statement for the whole batch.

        `ignore_conflicts` is what makes a repeated poll free: the second poll
        of the same snapshot finds the `(project, event_key)` rows already there
        and writes nothing. Failing loudly instead would make every second poll
        of a live capture an error, which is the opposite of what a poll is.
        """
        if not self._exchanges:
            return 0
        rows = []
        for (project_id, event_key), values in self._exchanges.items():
            rows.append(ProjectExchange(project_id=project_id, event_key=event_key, **values))
        ProjectExchange.objects.bulk_create(rows, batch_size=200, ignore_conflicts=True)
        return len(rows)


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
