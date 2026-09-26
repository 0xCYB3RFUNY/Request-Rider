"""Database models for durable HTTP history and future Intruder metadata."""

import secrets
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
    """Versioned project-scoped container for passive OSINT observations."""

    STATUS_CHOICES = [
        ("current", "Current"),
        ("archived", "Archived"),
    ]

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="osint_graphs")
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
        ("certificate", "Certificate"),
        ("technology", "Technology"),
        ("port", "Port"),
        ("cloud_asset", "Cloud asset"),
    ]

    graph = models.ForeignKey(OsintGraph, on_delete=models.CASCADE, related_name="entities")
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="osint_entities")
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
    """A typed, project-scoped edge between two normalized OSINT entities."""

    graph = models.ForeignKey(OsintGraph, on_delete=models.CASCADE, related_name="relations")
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="osint_relations")
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
    """Non-secret metadata and environment reference for one Project secret."""

    SECRET_TYPE_CHOICES = [
        ("jwt", "JWT"),
        ("api_key", "API key"),
        ("password", "Password"),
        ("leak", "Leak reference"),
    ]
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="secret_references")
    secret_type = models.TextField(choices=SECRET_TYPE_CHOICES, default="api_key")
    key_name = models.TextField()
    value_ref = models.TextField(blank=True, default="")
    source_url = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["secret_type", "key_name", "id"]


class ScannerRun(models.Model):
    """Durable log of one scanner run bound to a project (evidence only)."""

    ENGINE_CHOICES = [
        ("builtin", "Builtin"),
        ("templates", "Templates"),
        ("nuclei", "Nuclei"),
    ]
    project = models.ForeignKey(Project, null=True, blank=True, on_delete=models.CASCADE, related_name="scanner_runs")
    engine = models.TextField(choices=ENGINE_CHOICES, default="builtin")
    url = models.TextField(blank=True, default="")
    summary = models.JSONField(default=dict)
    findings = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)


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
    # Whether this job's pages are already indexed into the Project knowledge
    # base. The index is derived data, so the flag is what keeps a settled job
    # from re-writing every page it found on each Project dashboard read.
    ingested = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


# Durable History combines completed Repeater requests and explicitly saved
# passive proxy events in one table so both workflows can be replayed together.
class TrafficRecord(models.Model):
    """One request/response exchange shown in the History tab."""

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
            # already provides `timestamp DESC, id DESC`, SQLite satisfies the
            # three-value `source IN (...)` filter from lab_traffic_source_time_idx
            # and then sorts every matching row in a TEMP B-TREE just to return
            # the first page - a fixed multi-second cost that grew with the table
            # and was independent of the requested page size. This index lets the
            # planner walk the ordering backwards and stop at the page boundary.
            models.Index(
                fields=["-timestamp", "-id"],
                name="lab_traffic_recent_idx",
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
    input_data = models.JSONField(default=dict)
    output_data = models.JSONField(default=dict)
    current_node = models.TextField(blank=True, default="")
    logs = models.JSONField(default=list)
    error = models.TextField(blank=True, default="")
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
