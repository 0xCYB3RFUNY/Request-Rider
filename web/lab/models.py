"""Database models for durable HTTP history and future Intruder metadata."""

import secrets
import uuid
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
        # The active scanner is its own engine rather than another `builtin`
        # value: its findings carry a surface, a payload and a proven/unproven
        # tier instead of a template and a CVE, and writing them under the same
        # label would make the journal's two evidence shapes indistinguishable.
        ("active", "Active"),
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
