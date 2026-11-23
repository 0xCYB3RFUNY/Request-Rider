"""Database models for durable HTTP history and future Intruder metadata."""

import hashlib
import secrets
import uuid
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from django.db import models
from django.utils import timezone


def generate_capture_context_token():
    """Return an opaque local correlation token for one Traffic capture."""
    return secrets.token_urlsafe(24)


class Project(models.Model):
    """Workspace metadata shared by all durable RequestRider records."""

    name = models.TextField(unique=True)
    target = models.TextField(blank=True, default="")
    environment = models.TextField(blank=True, default="")
    route_profile = models.TextField(blank=True, default="")
    # Legacy columns retained for migration/data compatibility only. They are
    # not read or enforced; Project is an organizational workspace.
    scope_in = models.JSONField(default=list)
    scope_out = models.JSONField(default=list)
    tech_stack = models.JSONField(default=dict)
    notes = models.TextField(blank=True, default="")
    metadata = models.JSONField(default=dict)
    schema_version = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def register_endpoint(self, url, method="GET", status=None, params=None):
        """Register endpoint metadata without storing request or secret values."""
        parsed = urlsplit(str(url or "").strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return None
        path = parsed.path or "/"
        endpoint, _ = ProjectEndpoint.objects.get_or_create(
            project=self,
            method=str(method or "GET").upper(),
            path=path,
            defaults={"sample_url": str(url)},
        )
        changed = []
        if status is not None:
            statuses = list(endpoint.statuses or [])
            try:
                value = int(status)
            except (TypeError, ValueError):
                value = None
            if value is not None and value not in statuses:
                endpoint.statuses = statuses + [value]
                changed.append("statuses")
        query_params = sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)})
        if params:
            query_params.extend(str(item) for item in params if item)
        merged = sorted(set((endpoint.parameters or []) + query_params))
        if merged != (endpoint.parameters or []):
            endpoint.parameters = merged
            changed.append("parameters")
        endpoint.last_seen = timezone.now()
        changed.extend(["last_seen", "updated_at"])
        endpoint.save(update_fields=list(dict.fromkeys(changed)))
        return endpoint


class ProjectEndpoint(models.Model):
    """Observed endpoint metadata for the Project knowledge base."""

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="endpoints")
    method = models.TextField()
    path = models.TextField()
    sample_url = models.TextField(blank=True, default="")
    statuses = models.JSONField(default=list)
    parameters = models.JSONField(default=list)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["path", "method"]
        constraints = [
            models.UniqueConstraint(fields=["project", "method", "path"], name="project_endpoint_method_path_unique"),
        ]
        indexes = [
            models.Index(fields=["project", "path"]),
        ]


class ProjectHost(models.Model):
    """Network host and service inventory (Nmap DB, Metasploit, GVM scans)."""

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="hosts")
    ip_address = models.CharField(max_length=128, db_index=True)
    hostname = models.CharField(max_length=255, blank=True, default="")
    status = models.CharField(max_length=32, default="up")
    os_name = models.CharField(max_length=255, blank=True, default="")
    os_accuracy = models.CharField(max_length=32, blank=True, default="")
    mac_address = models.CharField(max_length=64, blank=True, default="")
    services = models.JSONField(default=list, blank=True)
    vulns = models.JSONField(default=list, blank=True)
    extra_data = models.JSONField(default=dict, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["ip_address", "hostname"]
        constraints = [
            models.UniqueConstraint(fields=["project", "ip_address"], name="project_host_ip_unique"),
        ]
        indexes = [
            models.Index(fields=["project", "ip_address"]),
            models.Index(fields=["project", "hostname"]),
        ]

    @property
    def open_ports_count(self) -> int:
        count = 0
        for s in (self.services or []):
            if isinstance(s, dict) and s.get("state") in ("open", "open|filtered", ""):
                count += 1
        return count

    @property
    def vulns_count(self) -> int:
        c = len(self.vulns or [])
        for s in (self.services or []):
            if isinstance(s, dict):
                c += len(s.get("vulns") or [])
        return c

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "project_id": self.project_id,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "status": self.status,
            "os_name": self.os_name,
            "os_accuracy": self.os_accuracy,
            "mac_address": self.mac_address,
            "services": self.services or [],
            "vulns": self.vulns or [],
            "extra_data": self.extra_data or {},
            "open_ports_count": self.open_ports_count,
            "vulns_count": self.vulns_count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else "",
            "last_seen": self.last_seen.isoformat() if self.last_seen else "",
            "updated_at": self.updated_at.isoformat() if self.updated_at else "",
        }



class TrafficCaptureContext(models.Model):
    """Explicit local correlation context for passive browser traffic."""

    name = models.TextField()
    token = models.TextField(unique=True, default=generate_capture_context_token, editable=False)
    project = models.ForeignKey(
        Project,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="traffic_capture_contexts",
    )
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class OsintGraph(models.Model):
    """Versioned container for passive OSINT observations.

    A Project is an optional workspace label here, not an entry requirement.
    The analyst may collect a graph without ever creating a Project, so
    ``project`` is nullable, and versioning is scoped per Project with the
    project-less scope counting as a scope of its own.
    """

    STATUS_CHOICES = [
        ("current", "Current"),
        ("archived", "Archived"),
    ]

    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="osint_graphs",
        null=True,
        blank=True,
    )
    version = models.PositiveIntegerField(default=1)
    schema_version = models.PositiveSmallIntegerField(default=1)
    status = models.TextField(choices=STATUS_CHOICES, default="current")
    source = models.TextField(default="manual")
    name = models.TextField(default="OSINT graph")
    metadata = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-version", "-created_at"]
        constraints = [
            models.UniqueConstraint(fields=["project", "version"], name="osint_graph_project_version_unique"),
            # PostgreSQL treats NULLs in a unique index as distinct, so the
            # constraint above cannot hold the project-less scope together. This
            # one does, which keeps "one version per scope" true for a graph the
            # analyst never attached to a Project.
            models.UniqueConstraint(
                fields=["version"],
                condition=models.Q(project__isnull=True),
                name="osint_graph_orphan_version_unique",
            ),
        ]


class OsintEntity(models.Model):
    """One normalized passive identity observed inside an OSINT graph."""

    ENTITY_TYPE_CHOICES = [
        ("domain", "Domain"),
        ("subdomain", "Subdomain"),
        ("ip", "IP"),
        ("cidr", "CIDR"),
        ("url", "URL"),
        ("email", "Email"),
        ("username", "Username"),
        ("asn", "ASN"),
        ("technology", "Technology"),
        ("cloud_asset", "Cloud asset"),
        # `profile` is what a social-platform account found for an address or a
        # handle is, as distinct from the handle itself. The engine emitted it
        # from `email_recon` and the gateway refused it — `unsupported OSINT entity
        # type: profile` — so the probe's entire answer was discarded on the way in
        # and the transform reported itself as having found nothing. The type was
        # missing for the same reason `certificate` and `port` were removed on
        # 2026-09-29, except that here the producer exists: the code is in
        # `osint_transforms.go` and was reachable only once the registry entry was
        # marked as a network transform.
        ("profile", "Profile"),
        # `certificate` and `port` were removed on 2026-09-29. Neither type had a
        # producer anywhere: the engine emits no certificate and no port entity, and
        # the Django ingest path writes domain, url, ip and technology only. A type
        # nothing can create is a value a hand-typed node can carry and nothing can
        # read — and `port` also had a hub metric summed over those nodes, which
        # could therefore only ever read zero. Rows written before the removal are
        # left alone on purpose: they are evidence, and deleting evidence is a
        # decision of the owner's, not a side effect of removing a type.
    ]

    graph = models.ForeignKey(OsintGraph, on_delete=models.CASCADE, related_name="entities")
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="osint_entities",
        null=True,
        blank=True,
    )
    entity_type = models.TextField(choices=ENTITY_TYPE_CHOICES)
    identity = models.TextField()
    display_value = models.TextField(blank=True, default="")
    risk_score = models.IntegerField(default=0)
    properties = models.JSONField(default=dict)
    provenance = models.JSONField(default=dict)
    observed_at = models.DateTimeField(default=timezone.now)
    first_observed_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["entity_type", "identity"]
        constraints = [
            models.UniqueConstraint(
                fields=["graph", "entity_type", "identity"],
                name="osint_entity_graph_type_identity_unique",
            ),
        ]
        indexes = [
            models.Index(fields=["project", "entity_type"]),
            models.Index(fields=["graph", "observed_at"]),
        ]


class OsintRelation(models.Model):
    """A typed edge between two normalized OSINT entities.

    ``project`` mirrors the owning graph and is therefore nullable for the same
    reason: a graph need not belong to a Project.
    """

    graph = models.ForeignKey(OsintGraph, on_delete=models.CASCADE, related_name="relations")
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="osint_relations",
        null=True,
        blank=True,
    )
    relation_type = models.TextField()
    source_entity = models.ForeignKey(OsintEntity, on_delete=models.CASCADE, related_name="outgoing_relations")
    target_entity = models.ForeignKey(OsintEntity, on_delete=models.CASCADE, related_name="incoming_relations")
    properties = models.JSONField(default=dict)
    provenance = models.JSONField(default=dict)
    observed_at = models.DateTimeField(default=timezone.now)
    first_observed_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["relation_type", "source_entity", "target_entity"]
        constraints = [
            models.UniqueConstraint(
                fields=["graph", "relation_type", "source_entity", "target_entity"],
                name="osint_relation_graph_type_endpoints_unique",
            ),
        ]
        indexes = [
            models.Index(fields=["project", "relation_type"]),
            models.Index(fields=["graph", "observed_at"]),
        ]


class ProjectSecret(models.Model):
    """One secret the operator's own traffic or crawl produced, stored in full.

    `value_ref` holds the credential as it travelled — the whole JWT, the whole
    cookie header, the whole leaked key. The field name is historical: it began
    as a pointer to somewhere else, and the ingest wrote an empty string into it
    because the value was not collected at all, so every surface that listed a
    secret could only say "a secret was seen here". A row that costs a manual
    re-capture to learn the one thing it exists to record is not a record.
    """

    SECRET_TYPE_CHOICES = [
        ("jwt", "JWT"),
        ("api_key", "API key"),
        ("password", "Password"),
        ("leak", "Leak reference"),
    ]
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="secret_references")
    secret_type = models.TextField(choices=SECRET_TYPE_CHOICES, default="api_key")
    key_name = models.TextField()
    # The credential itself. See the class docstring: this is the value, not a
    # pointer, and it is rendered whole in the report and in the Project hub.
    value_ref = models.TextField(blank=True, default="")
    source_url = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["secret_type", "key_name", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["project", "secret_type", "key_name", "source_url"],
                name="project_secret_project_type_key_url_unique",
            ),
        ]


def _extract_evidence_anchor(evidence: str) -> str:
    """Extract the primary invariant subject from evidence.

    Examples:
    - 'Strict-Transport-Security missing' -> 'strict-transport-security'
    - 'Server: Apache/2.4' -> 'server'
    - '/.env returned 200 OK' -> '/.env'
    - 'Header: cf-ray' -> 'header:cf-ray'
    """
    text = str(evidence or "").strip()
    if not text:
        return ""
    first_line = text.split("\n")[0].strip()
    if ":" in first_line:
        parts = first_line.split(":", 1)
        prefix = parts[0].strip().lower()
        sub = parts[1].strip().split()[0].lower() if parts[1].strip() else ""
        if prefix in {"header", "cookie", "meta", "asset", "marker"}:
            return f"{prefix}:{sub}"
        return prefix
    token = first_line.split()[0].strip().lower()
    return token


def compute_finding_identity(item: dict, target_url: str = "") -> str:
    """Stable, evidence-aware identity hash for a finding.

    Combines:
    - vulnerability type/title (title, vulnerability, name, check_id, template_id)
    - target URL, endpoint, or matched path
    - HTTP method
    - parameter name
    - invariant evidence anchor

    Produces a deterministic SHA256 hex string ensuring collisions are avoided
    while identical findings across repeated runs resolve to the exact same identity,
    even when evidence details are enriched over time.
    """
    if not isinstance(item, dict):
        return hashlib.sha256(b"").hexdigest()

    vuln_type = str(
        item.get("title")
        or item.get("vulnerability")
        or item.get("name")
        or item.get("check_id")
        or item.get("template_id")
        or ""
    ).strip().lower()

    target = str(
        item.get("matched_at")
        or item.get("target")
        or item.get("endpoint")
        or item.get("url")
        or item.get("path")
        or target_url
        or ""
    ).strip().lower()

    method = str(item.get("method") or "").strip().upper()
    param = str(item.get("param") or item.get("parameter") or "").strip().lower()
    evidence_anchor = _extract_evidence_anchor(item.get("evidence"))

    seed = f"{vuln_type}|{target}|{method}|{param}|{evidence_anchor}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def _notify_finding_webhook(scanner_run, newly_added: list[dict]) -> bool:
    """Send an outbound JSON webhook notification when new scanner findings are recorded (Phase 5.1)."""
    import json
    import os
    import urllib.request

    webhook_url = ""
    if getattr(scanner_run, "project_id", None) and getattr(scanner_run, "project", None):
        meta = scanner_run.project.metadata if isinstance(scanner_run.project.metadata, dict) else {}
        webhook_url = str(meta.get("finding_webhook_url") or "").strip()
    if not webhook_url:
        webhook_url = os.environ.get("RR_FINDING_WEBHOOK_URL", "").strip()
    if not webhook_url or not webhook_url.startswith(("http://", "https://")):
        return False

    payload = json.dumps({
        "event": "scanner.finding.discovered",
        "run_id": scanner_run.id,
        "project_id": scanner_run.project_id,
        "url": scanner_run.url,
        "engine": scanner_run.engine,
        "new_count": len(newly_added),
        "findings": newly_added,
    }).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "RequestRider-Webhook/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


class ScannerRun(models.Model):
    """Durable log of one scanner run bound to a project (evidence only)."""

    ENGINE_CHOICES = [
        ("builtin", "Builtin"),
        ("templates", "Templates"),
        ("corpus", "Corpus"),
        # The active scanner is its own engine rather than another `builtin`
        # value: its findings carry a surface, a payload and a proven/unproven
        # tier instead of a template and a CVE, and writing them under the same
        # label would make the journal's two evidence shapes indistinguishable.
        ("active", "Active"),
        ("openvas", "OpenVAS"),
    ]
    project = models.ForeignKey(Project, null=True, blank=True, on_delete=models.CASCADE, related_name="scanner_runs")
    engine = models.TextField(choices=ENGINE_CHOICES, default="builtin")
    url = models.TextField(blank=True, default="")
    summary = models.JSONField(default=dict)
    findings = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)

    def upsert_findings(self, new_findings, stats=None, templates=None):
        """Idempotently merge new findings into this run's findings list.

        Updates matching findings by identity_hash, or appends new ones.
        Recalculates findings_count and highest_severity.
        """
        severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        existing_map = {}
        order = []
        newly_added = []
        for row in self.findings or []:
            if not isinstance(row, dict):
                continue
            key = row.get("identity_hash") or row.get("id") or compute_finding_identity(row, self.url)
            row["identity_hash"] = key
            if not row.get("id"):
                row["id"] = key
            existing_map[key] = row
            order.append(key)

        for incoming in new_findings or []:
            if not isinstance(incoming, dict):
                continue
            key = incoming.get("identity_hash") or incoming.get("id") or compute_finding_identity(incoming, self.url)
            incoming["identity_hash"] = key
            if not incoming.get("id"):
                incoming["id"] = key
            if key in existing_map:
                current = existing_map[key]
                curr_sev = str(current.get("severity") or "INFO").upper()
                new_sev = str(incoming.get("severity") or "INFO").upper()
                if severity_rank.get(new_sev, 9) < severity_rank.get(curr_sev, 9):
                    current["severity"] = new_sev
                curr_ev = str(current.get("evidence") or "")
                new_ev = str(incoming.get("evidence") or "")
                if len(new_ev) > len(curr_ev):
                    current["evidence"] = new_ev
                if incoming.get("recommendation"):
                    current["recommendation"] = str(incoming["recommendation"])
                if incoming.get("cve"):
                    current["cve"] = sorted(list(set((current.get("cve") or []) + incoming["cve"])))
            else:
                existing_map[key] = incoming
                order.append(key)
                newly_added.append(incoming)

        updated_findings = [existing_map[k] for k in order]
        self.findings = updated_findings

        severities = sorted(
            {str(item.get("severity") or "INFO").upper() for item in updated_findings},
            key=lambda level: severity_rank.get(level, 9),
        )
        summary = dict(self.summary or {})
        summary["findings_count"] = len(updated_findings)
        summary["highest_severity"] = severities[0] if severities else "INFO"
        if stats and isinstance(stats, dict):
            curr_stats = dict(summary.get("stats") or {})
            curr_stats.update(stats)
            summary["stats"] = curr_stats
        if templates:
            summary["templates"] = templates

        self.summary = summary
        self.save(update_fields=["findings", "summary"])
        if newly_added:
            _notify_finding_webhook(self, newly_added)
        return self


class TargetJob(models.Model):
    """Durable association between a Target run and its workspace."""

    project = models.ForeignKey(Project, null=True, blank=True, on_delete=models.CASCADE, related_name="target_jobs")
    capture_context = models.ForeignKey(
        TrafficCaptureContext,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="target_jobs",
    )
    job_id = models.TextField(unique=True)
    engine_kind = models.TextField()
    url = models.TextField()
    status = models.TextField(default="running")
    result = models.JSONField(default=dict)
    # The run's own frontier: where it stopped, why, how many probes were dropped
    # by a pause, and the requests that never produced a response.
    #
    # It lives here rather than only in the engine because the engine forgets a
    # job when it restarts, and the moment an operator most needs "where did it
    # break" is after the thing that broke it. A crawl that walked into a host
    # which stopped answering left this row with nothing but its last error, and
    # the only way back to the failure was to re-read the export.
    checkpoint = models.JSONField(default=dict, blank=True)
    # Whether this job's pages are already indexed into the Project knowledge
    # base. The index is derived data, so the flag is what keeps a settled job
    # from re-writing every page it found on each Project dashboard read.
    ingested = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class ActiveScanJob(models.Model):
    """Durable association between an active-scanner run and its workspace.

    This is the same shape as `TargetJob` and for the same reason: the engine keeps
    the run, but the engine does not know what a Project is, so the link between
    the two has to live somewhere the gateway restart cannot erase. A scan is
    measured in hours — the run that motivated this row spent 65 minutes on one
    target before its gateway was restarted, and a link kept in a process-local
    dict meant the finished report had nowhere to go afterwards.

    `settled` is the guard that makes the record safe to re-read. It is not a
    second copy of `ingested`: `ingested` says "the findings were written to
    `ScannerRun`", and a cancelled run has nothing to write yet still has to stop
    being re-examined. So `settled` is what the sweep reads, and it is set whether
    the outcome was a report or a stop.
    """

    project = models.ForeignKey(Project, null=True, blank=True, on_delete=models.CASCADE, related_name="active_scan_jobs")
    job_id = models.TextField(unique=True)
    url = models.TextField(blank=True, default="")
    status = models.TextField(default="running")
    # Whether this run's findings were written to `ScannerRun`. The report is
    # derived from the run, so the flag is what keeps a poll that a browser
    # repeats every second from writing the same evidence over and over.
    ingested = models.BooleanField(default=False)
    # The run's frontier, exactly as `TargetJob.checkpoint`: the pause state, the
    # first failure, the classes of failure and the requests that never answered.
    # It is what makes "return to where it broke" possible after a reload or a
    # gateway restart, because the engine's own copy of the run does not survive
    # one.
    checkpoint = models.JSONField(default=dict, blank=True)
    # Whether this run has reached an outcome that needs no further reading —
    # completed and written, cancelled, failed, or abandoned by the engine. A
    # sweep reads this column, not the state it gets from the engine, because the
    # sweep must not depend on the engine still remembering the run.
    settled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


# Durable History combines completed Repeater requests and explicitly saved
# passive proxy events in one table so both workflows can be replayed together.
class TrafficRecord(models.Model):
    """One request/response exchange shown in the History tab."""

    # See the `origin` field below: which ingest path wrote this row.
    ORIGIN_CHOICES = [
        ("engine_capture", "Engine capture"),
        ("client_supplied", "Client-supplied"),
    ]

    SCOPE_STATUS_CHOICES = [
        ("unscoped", "Unassigned"),
        ("project_linked", "Project-linked"),
        ("in_scope", "Legacy project-linked"),
        ("out_of_scope", "Legacy scope metadata"),
        ("invalid_context", "Invalid capture context"),
    ]

    # The source distinguishes active Repeater traffic from saved proxy traffic.
    SOURCE_CHOICES = [
        ("repeater", "Repeater"),
        ("intruder", "Intruder"),
        ("last-byte", "Last-Byte Sync"),
        ("proxy", "Proxy"),
        ("route-check", "Route check"),
        ("tool", "Tool"),
    ]
    # History sorting order, and the moment the exchange was actually observed.
    # A plain default rather than `auto_now_add` because a Project import has to
    # restore the moment the source installation recorded; `auto_now_add` would
    # overwrite it and restamp the whole imported workspace with the import time.
    # Every live capture path still gets the same value it always did: it passes
    # no timestamp, so the default stamps it.
    timestamp = models.DateTimeField(default=timezone.now)
    project = models.ForeignKey(Project, null=True, blank=True, on_delete=models.CASCADE, related_name="traffic_records")
    # Origin of the record in the UI workflow.
    source = models.TextField(choices=SOURCE_CHOICES, default="repeater")
    # Original HTTP request metadata.
    method = models.TextField()
    url = models.TextField()
    # Passive proxy metadata, empty for ordinary Repeater records.
    host = models.TextField(blank=True, default="")
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    proxy_event_id = models.PositiveBigIntegerField(null=True, blank=True)
    proxy_session = models.BigIntegerField(null=True, blank=True)
    capture_context = models.ForeignKey(
        TrafficCaptureContext,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="traffic_records",
    )
    scope_status = models.TextField(choices=SCOPE_STATUS_CHOICES, default="unscoped")
    # Where the row came from, which is the one thing an analyst cannot infer from its
    # contents. `engine_capture` is the engine's own passive capture arriving through the
    # traffic poll; `client_supplied` is a body the gateway was handed by a caller and
    # stored verbatim.
    #
    # The product of this tool is evidence, and evidence without provenance is a claim.
    # Before this field, `persist_proxy_history` was the single ingest path for both the
    # poll and `POST /api/traffic/save`, so a row planted by any local caller looked
    # exactly like a captured exchange: same shape, same `source`, and it rode the
    # project export with nothing to tell the two apart. The forgery is still possible —
    # a local process is outside the single-operator threat model — but it is now
    # *visible* rather than indistinguishable, which is what an evidence product owes.
    origin = models.TextField(choices=ORIGIN_CHOICES, default="client_supplied")
    # Request data is stored as JSON headers plus text body.
    request_headers = models.JSONField(default=dict)
    request_body = models.TextField(null=True, blank=True)
    request_body_encoding = models.TextField(default="utf8")
    request_body_base64 = models.TextField(blank=True, default="")
    # Response data mirrors the request representation.
    response_headers = models.JSONField(default=dict)
    response_body = models.TextField(null=True, blank=True)
    response_body_encoding = models.TextField(default="utf8")
    response_body_base64 = models.TextField(blank=True, default="")
    response_content_type = models.TextField(blank=True, default="")
    # Measurement fields are nullable because pending proxy events may lack
    # a response when they are first observed.
    status_code = models.IntegerField(null=True, blank=True)
    latency_ms = models.IntegerField(null=True, blank=True)
    response_size = models.IntegerField(null=True, blank=True)
    tags = models.JSONField(default=list)
    notes = models.TextField(blank=True, default="")

    class Meta:
        # Every passive/Intruder sync deduplicates on
        # (source, proxy_session, proxy_event_id), and History always filters on
        # source before ordering by time. Without these indexes every sync did a
        # full table scan per exchange, which turned a passive capture burst into
        # quadratic read volume against a table that also holds full bodies.
        indexes = [
            models.Index(
                fields=["source", "proxy_session", "proxy_event_id"],
                name="lab_traffic_dedup_idx",
            ),
            models.Index(
                fields=["source", "timestamp"],
                name="lab_traffic_source_time_idx",
            ),
            models.Index(
                fields=["project", "timestamp"],
                name="lab_traffic_project_time_idx",
            ),
            # History's default order is newest first. Without an index that
            # already provides `timestamp DESC, id DESC`, the query planner can
            # walk the ordering backwards and stop at the requested page boundary.
            models.Index(
                fields=["-timestamp", "-id"],
                name="lab_traffic_recent_idx",
            ),
        ]


class ProjectExchange(models.Model):
    """One exchange as the Project received it, kept in the Project's own table.

    `TrafficRecord` is the capture archive: it is what the Traffic tab lists, it
    is windowed, and clearing it is a normal thing an operator does. A Project
    is the opposite of that — it is the workspace that carries the evidence, and
    the bundle it exports is meant to survive on its own. Reading the bundle out
    of the capture archive therefore made the Project's evidence depend on rows
    that a `Clear` in another tab is allowed to delete, which is backwards: the
    evidence is the part that must not be wiped by a view being cleared.

    So the ingestor writes the exchange here as well, in the same batch that
    writes the capture row, and everything a Project reads about traffic reads
    this table instead. The link back to `TrafficRecord` is a convenience for
    the UI, not a dependency: it is nullable and set to `NULL` when the capture
    row goes, and the copy stands on its own fields.
    """

    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name="exchanges"
    )
    # The moment the exchange was observed, copied from the capture row. A plain
    # default rather than `auto_now_add`, for the same reason TrafficRecord has
    # one: an import has to restore the recorded moment, not stamp the import.
    timestamp = models.DateTimeField(default=timezone.now)
    # Stable identity of the exchange, used to write the copy exactly once.
    # It is the capture's own `(session, event)` pair, so a repeated poll of the
    # same snapshot cannot produce a second copy of the same request.
    event_key = models.TextField()
    source = models.TextField(default="proxy")
    method = models.TextField()
    url = models.TextField()
    host = models.TextField(blank=True, default="")
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    status_code = models.IntegerField(null=True, blank=True)
    latency_ms = models.IntegerField(null=True, blank=True)
    response_size = models.IntegerField(null=True, blank=True)
    response_content_type = models.TextField(blank=True, default="")
    scope_status = models.TextField(default="project_linked")
    # The complete exchange, exactly as the capture held it. A Project bundle is
    # only worth exporting if it carries the raw request and response.
    request_headers = models.JSONField(default=dict)
    request_body = models.TextField(null=True, blank=True)
    request_body_encoding = models.TextField(default="utf8")
    request_body_base64 = models.TextField(blank=True, default="")
    response_headers = models.JSONField(default=dict)
    response_body = models.TextField(null=True, blank=True)
    response_body_encoding = models.TextField(default="utf8")
    response_body_base64 = models.TextField(blank=True, default="")

    # A convenience link for the UI, never a dependency: clearing the capture
    # archive nulls it and leaves this row and its payload untouched.
    capture_context = models.ForeignKey(
        TrafficCaptureContext,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="project_exchanges",
    )

    class Meta:
        ordering = ["timestamp", "id"]
        constraints = [
            # The copy is written once per observed exchange. Without this a
            # second poll of the same snapshot would duplicate the evidence, and
            # a duplicated exchange in a bundle is a claim the workspace did not
            # make.
            models.UniqueConstraint(
                fields=["project", "event_key"], name="lab_project_exchange_event_uniq"
            ),
        ]
        indexes = [
            # Bundle order and hub aggregation both read one project newest
            # first, so the index carries the sort instead of the planner.
            models.Index(
                fields=["project", "-timestamp"], name="lab_project_exch_proj_time_idx"
            ),
        ]


class IntruderAttack(models.Model):
    """Saved Intruder configuration that can be run again."""

    # These values match the Go generator and UI mode names.
    TYPE_CHOICES = [
        ('sniper', 'Sniper'),
        ('batteringRam', 'Battering Ram'),
        ('pitchfork', 'Pitchfork'),
        ('clusterBomb', 'Cluster Bomb'),
    ]
    # Human-readable label shown in the saved attack list.
    name = models.TextField(default="Intruder attack")
    project = models.ForeignKey(Project, null=True, blank=True, on_delete=models.CASCADE, related_name="intruder_attacks")
    engine_attack_id = models.TextField(blank=True, default="", db_index=True)
    # Selected generation algorithm for the attack.
    attack_type = models.TextField(choices=TYPE_CHOICES)
    # Base request before marker replacement.
    base_request = models.JSONField()
    # Original dictionaries/payload lists submitted by the user.
    payloads = models.JSONField()
    # Ordered transformation chain applied by the engine.
    transformations = models.JSONField(default=list)
    # Delay between sequential Intruder requests in milliseconds.
    delay_ms = models.PositiveIntegerField(default=150)
    # Number of concurrent Intruder workers.
    concurrency = models.PositiveIntegerField(default=1)
    # Lifecycle state reserved for future persisted attack jobs.
    status = models.TextField(default='pending')
    # Creation time used for future attack history sorting.
    created_at = models.DateTimeField(auto_now_add=True)


class Workflow(models.Model):
    """Durable visual automation graph belonging to an optional Project."""

    name = models.TextField(default="Workflow")
    description = models.TextField(blank=True, default="")
    project = models.ForeignKey(
        Project,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="workflows",
    )
    # Nodes and connections mirror the editor's portable JSON representation.
    nodes = models.JSONField(default=list)
    connections = models.JSONField(default=list)
    graph_schema_version = models.PositiveSmallIntegerField(default=1)
    settings = models.JSONField(default=dict)
    metadata = models.JSONField(default=dict)
    version = models.PositiveIntegerField(default=1)
    active = models.BooleanField(default=False)
    # A five-field cron expression is the default; six fields include seconds.
    schedule = models.TextField(blank=True, default="")
    # Stable public path segment for an active webhook trigger.
    webhook_slug = models.TextField(
        unique=True,
        null=True,
        blank=True,
    )
    last_run_at = models.DateTimeField(null=True, blank=True)
    next_run_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class WorkflowRun(models.Model):
    """Persisted execution state and node-level event log for one workflow."""

    STATUS_CHOICES = [
        ("queued", "Queued"),
        ("running", "Running"),
        # Durable wait for an external engine result. The run holds no worker
        # thread while it is in this state: the correlated EngineTask keeps the
        # action alive in Go, and the result consumer resumes the graph.
        ("waiting", "Waiting"),
        ("paused", "Paused"),
        ("completed", "Completed"),
        ("failed", "Failed"),
        ("cancelled", "Cancelled"),
        ("interrupted", "Interrupted"),
    ]
    MODE_CHOICES = [
        ("manual", "Manual"),
        ("schedule", "Schedule"),
        ("webhook", "Webhook"),
    ]
    workflow = models.ForeignKey(
        Workflow,
        on_delete=models.CASCADE,
        related_name="runs",
    )
    project = models.ForeignKey(
        Project,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="workflow_runs",
    )
    status = models.TextField(choices=STATUS_CHOICES, default="queued")
    mode = models.TextField(choices=MODE_CHOICES, default="manual")
    trigger_type = models.TextField(default="manual")
    trigger_node_id = models.TextField(blank=True, default="")
    graph_schema_version = models.PositiveSmallIntegerField(default=1)
    graph_nodes = models.JSONField(null=True, blank=True, default=None)
    graph_connections = models.JSONField(null=True, blank=True, default=None)
    input_data = models.JSONField(default=dict)
    output_data = models.JSONField(default=dict)
    current_node = models.TextField(blank=True, default="")
    # Run-scoped scratch space that nodes publish into (`context["shared"]`),
    # for example an OAST `listener_id` that a later `OAST Collect` node reads.
    # It has to be durable: a run that parked on an external action is resumed
    # from its checkpoints by a later execution, and an in-memory dict would
    # come back empty. Measured - the OAST chain failed with "OAST listener_id
    # is unavailable" on every resume, because the state never left the process
    # that happened to park.
    shared_data = models.JSONField(default=dict)
    logs = models.JSONField(default=list)
    error = models.TextField(blank=True, default="")
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class WorkflowNodeExecution(models.Model):
    """Durable checkpoint for one node within a WorkflowRun."""

    STATUS_CHOICES = [
        ("running", "Running"),
        # `waiting` means the node published a durable engine task and released
        # its worker; only a terminal engine result may move it forward. It is
        # distinct from `running` so a restart can tell a safe resume from a
        # node whose external action may already have happened.
        ("waiting", "Waiting"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]
    workflow_run = models.ForeignKey(
        WorkflowRun,
        on_delete=models.CASCADE,
        related_name="node_executions",
    )
    node_id = models.TextField()
    status = models.TextField(choices=STATUS_CHOICES)
    input_data = models.JSONField(default=dict)
    output_data = models.JSONField(default=dict)
    error = models.TextField(blank=True, default="")
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["workflow_run", "node_id"],
                name="unique_workflow_run_node_execution",
            ),
        ]


class EngineTask(models.Model):
    """Durable correlation state for one task dispatched to the Go engine."""

    STATUS_CHOICES = [
        ("queued", "Queued"),
        ("published", "Published"),
        ("accepted", "Accepted"),
        ("progress", "Progress"),
        ("completed", "Completed"),
        ("failed", "Failed"),
        ("cancelled", "Cancelled"),
    ]
    task_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    task_type = models.TextField()
    status = models.TextField(choices=STATUS_CHOICES, default="queued")
    workflow_run = models.ForeignKey(
        WorkflowRun,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="engine_tasks",
    )
    workflow_node_id = models.TextField(blank=True, default="")
    route_generation = models.PositiveBigIntegerField(default=0)
    project = models.ForeignKey(
        Project,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="engine_tasks",
    )
    payload = models.JSONField(default=dict)
    progress = models.JSONField(default=dict)
    result = models.JSONField(default=dict)
    error = models.JSONField(default=dict)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class EngineTaskEvent(models.Model):
    """Deduplication ledger for at-least-once engine result deliveries."""

    task = models.ForeignKey(
        EngineTask,
        on_delete=models.CASCADE,
        related_name="events",
    )
    event_id = models.UUIDField(unique=True)
    state = models.TextField(choices=EngineTask.STATUS_CHOICES)
    occurred_at = models.DateTimeField()
    data = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)


class ProjectAuthProfile(models.Model):
    """Named authorization actor profile (role) for multi-actor BOLA/IDOR matrix testing."""

    ROLE_TYPE_CHOICES = [
        ("admin", "Admin"),
        ("manager", "Manager"),
        ("user", "User"),
        ("anon", "Anonymous"),
        ("custom", "Custom"),
    ]
    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="auth_profiles",
    )
    name = models.TextField()
    role_type = models.TextField(choices=ROLE_TYPE_CHOICES, default="user")
    headers = models.JSONField(default=dict)
    strip_auth = models.BooleanField(default=False)
    secret_ref = models.ForeignKey(
        ProjectSecret,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="auth_profiles",
    )
    is_baseline = models.BooleanField(default=False)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-is_baseline", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["project", "name"],
                name="project_auth_profile_unique_name",
            ),
        ]

    def resolve_headers(self) -> dict[str, str]:
        """Return effective headers for this role, substituting live ProjectSecret if attached."""
        resolved: dict[str, str] = {}
        raw_headers = self.headers if isinstance(self.headers, dict) else {}
        secret_val = ""
        if self.secret_ref_id and self.secret_ref:
            secret_val = str(self.secret_ref.value_ref or "").strip()

        for k, v in raw_headers.items():
            key = str(k).strip()
            if not key:
                continue
            val = str(v or "")
            if secret_val and ("${secret}" in val or "{{secret}}" in val):
                val = val.replace("${secret}", secret_val).replace("{{secret}}", secret_val)
            resolved[key] = val

        if secret_val and not any(
            h.lower() in {"authorization", "cookie", "x-api-key", "x-auth-token"}
            for h in resolved
        ):
            if self.secret_ref.secret_type == "jwt":
                resolved["Authorization"] = (
                    secret_val if secret_val.lower().startswith("bearer ") else f"Bearer {secret_val}"
                )
            elif self.secret_ref.secret_type == "api_key":
                resolved["X-API-Key"] = secret_val
            else:
                resolved["Authorization"] = secret_val
        return resolved


class ProjectSurfaceSnapshot(models.Model):
    """Immutable point-in-time snapshot of a Project's attack surface for Drift & Shadow API detection."""

    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="surface_snapshots",
    )
    label = models.TextField(blank=True, default="")
    endpoints_data = models.JSONField(default=list)
    js_bundles = models.JSONField(default=dict)
    security_headers = models.JSONField(default=dict)
    finding_identities = models.JSONField(default=list)
    osint_summary = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]

    def to_summary_dict(self) -> dict:
        return {
            "id": self.id,
            "project_id": self.project_id,
            "label": self.label or f"Snapshot #{self.id}",
            "endpoints_count": len(self.endpoints_data or []),
            "js_bundles_count": len(self.js_bundles or {}),
            "findings_count": len(self.finding_identities or []),
            "osint_summary": self.osint_summary or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class WorkflowTemplate(models.Model):
    """Server-backed workflow template with schema signing and community manifest metadata."""

    project = models.ForeignKey(
        Project,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="workflow_templates",
    )
    slug = models.SlugField(max_length=120, unique=True)
    name = models.TextField()
    description = models.TextField(blank=True, default="")
    category = models.TextField(blank=True, default="security")
    author = models.TextField(blank=True, default="local")
    version = models.TextField(blank=True, default="1.0.0")
    nodes = models.JSONField(default=list)
    connections = models.JSONField(default=list)
    manifest = models.JSONField(default=dict)
    schema_signature = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at", "-id"]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "project_id": self.project_id,
            "slug": self.slug,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "author": self.author,
            "version": self.version,
            "nodes": self.nodes or [],
            "connections": self.connections or [],
            "manifest": self.manifest or {},
            "schema_signature": self.schema_signature or "",
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class AttackChain(models.Model):
    """Semantic security attack graph separate from technical Workflow execution DAG."""

    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name="attack_chains",
    )
    title = models.TextField()
    objective = models.TextField(blank=True, default="")
    severity = models.TextField(default="high")
    status = models.TextField(default="verified")
    mitre_techniques = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at", "-id"]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "project_id": self.project_id,
            "title": self.title,
            "objective": self.objective,
            "severity": self.severity,
            "status": self.status,
            "mitre_techniques": self.mitre_techniques or [],
            "steps": [step.to_dict() for step in self.steps.all().order_by("step_order", "id")],
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AttackStep(models.Model):
    """Individual step in a semantic AttackChain linked by stable finding/exchange provenance."""

    chain = models.ForeignKey(
        AttackChain,
        on_delete=models.CASCADE,
        related_name="steps",
    )
    step_order = models.IntegerField(default=1)
    phase = models.TextField(default="exploitation")
    description = models.TextField()
    finding_identity = models.TextField(blank=True, default="")
    exchange_id = models.IntegerField(null=True, blank=True)
    evidence_provenance = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["step_order", "id"]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "chain_id": self.chain_id,
            "step_order": self.step_order,
            "phase": self.phase,
            "description": self.description,
            "finding_identity": self.finding_identity,
            "exchange_id": self.exchange_id,
            "evidence_provenance": self.evidence_provenance or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AgentMemoryAtom(models.Model):
    """One durable, project-scoped fact learned by the AI agent.

    The tier is an injection policy, not a storage detail: L1 atoms are recalled
    only on relevance, L2 is this project's context (every run), L3 is a stable
    cross-project fact (every run). Promotion is *proposed*, never applied
    automatically — an operator confirms the final step. Every atom carries a
    back-pointer to the step that produced it; a citation is mandatory.
    """

    TIER_CHOICES = [
        ("L1", "Candidate"),
        ("L2", "Project context"),
        ("L3", "Stable / cross-project"),
    ]

    # "project:<id>" or "global". A string (rather than a nullable FK) makes the
    # uniqueness constraint work for global atoms too — PostgreSQL treats NULLs
    # as distinct, so a nullable project_id would allow unlimited duplicates.
    scope = models.TextField()
    scope_key = models.TextField()
    value = models.TextField()
    kind = models.TextField(default="fact")
    source_citation = models.TextField(blank=True, default="")
    source_session = models.TextField(blank=True, default="")
    occurrences = models.PositiveIntegerField(default=1)
    distinct_sessions = models.PositiveIntegerField(default=1)
    distinct_days = models.PositiveIntegerField(default=1)
    first_seen_on = models.DateField(default=timezone.localdate)
    # A redacted atom never promotes on evidence alone: the filter firing is
    # evidence the source was sensitive, not proof that every secret was found.
    redacted = models.BooleanField(default=False)
    # A contested atom stays injected but is tagged; one claim never silently
    # overwrites its incumbent.
    contested = models.BooleanField(default=False)
    contested_note = models.TextField(blank=True, default="")
    verified = models.BooleanField(default=False)
    tier = models.TextField(choices=TIER_CHOICES, default="L1")
    proposed_tier = models.TextField(blank=True, default="")
    proposed_reason = models.TextField(blank=True, default="")
    promoted_at = models.DateTimeField(null=True, blank=True)
    last_seen_at = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-last_seen_at", "-id"]
        constraints = [
            models.UniqueConstraint(
                fields=["scope", "scope_key"],
                name="uniq_agent_memory_scope_key",
            )
        ]
        indexes = [
            models.Index(fields=["scope", "tier"], name="idx_agent_memory_scope_tier"),
        ]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scope": self.scope,
            "scope_key": self.scope_key,
            "value": self.value,
            "kind": self.kind,
            "source_citation": self.source_citation,
            "source_session": self.source_session,
            "occurrences": self.occurrences,
            "distinct_sessions": self.distinct_sessions,
            "distinct_days": self.distinct_days,
            "redacted": self.redacted,
            "contested": self.contested,
            "contested_note": self.contested_note,
            "verified": self.verified,
            "tier": self.tier,
            "proposed_tier": self.proposed_tier,
            "proposed_reason": self.proposed_reason,
            "promoted_at": self.promoted_at.isoformat() if self.promoted_at else None,
        }


class AgentRunUsage(models.Model):
    """Visible per-run token and cost ledger — accounting, never a cap."""

    project = models.ForeignKey(
        Project,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="agent_usage",
    )
    run_id = models.TextField(unique=True)
    provider = models.TextField(default="")
    model = models.TextField(default="")
    prompt_tokens = models.PositiveIntegerField(default=0)
    completion_tokens = models.PositiveIntegerField(default=0)
    total_tokens = models.PositiveIntegerField(default=0)
    input_rate_per_million = models.DecimalField(max_digits=16, decimal_places=6, default=0)
    output_rate_per_million = models.DecimalField(max_digits=16, decimal_places=6, default=0)
    estimated_cost_usd = models.DecimalField(max_digits=16, decimal_places=6, default=0)
    steps = models.PositiveIntegerField(default=0)
    completed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "provider": self.provider,
            "model": self.model,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "input_rate_per_million": str(self.input_rate_per_million),
            "output_rate_per_million": str(self.output_rate_per_million),
            "estimated_cost_usd": str(self.estimated_cost_usd),
            "steps": self.steps,
            "completed": self.completed,
        }


class FindingVerification(models.Model):
    """Three-gate finding check: baseline -> attack -> response difference.

    A result is not 'confirmed' because a tool returned a string. The three
    observations must be recorded and the difference must be named, otherwise
    the status stays 'suspected' — the same honesty rule the scanner uses for
    matcher-status false.
    """

    STATUS_CHOICES = [
        ("suspected", "Suspected"),
        ("baseline", "Baseline recorded"),
        ("attack", "Attack recorded"),
        ("confirmed", "Confirmed"),
        ("refuted", "Refuted"),
    ]

    scope = models.TextField(default="global")
    finding_key = models.TextField()
    title = models.TextField(blank=True, default="")
    status = models.TextField(choices=STATUS_CHOICES, default="suspected")
    baseline = models.JSONField(default=dict, blank=True)
    attack = models.JSONField(default=dict, blank=True)
    diff = models.JSONField(default=dict, blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    note = models.TextField(blank=True, default="")
    verified_by = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at", "-id"]
        constraints = [
            models.UniqueConstraint(
                fields=["scope", "finding_key"],
                name="uniq_finding_verification_scope_key",
            )
        ]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "finding_key": self.finding_key,
            "title": self.title,
            "status": self.status,
            "baseline": self.baseline or {},
            "attack": self.attack or {},
            "diff": self.diff or {},
            "evidence": self.evidence or {},
            "note": self.note,
            "verified_by": self.verified_by,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

