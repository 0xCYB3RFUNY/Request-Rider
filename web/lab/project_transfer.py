"""Project bundle export and import for the browser-facing API.

A Project is an organizational workspace rather than a policy container, so its
export is the workspace itself: the metadata, the derived knowledge base
(endpoints, secrets, scanner runs, Target jobs, workflows, OSINT graphs) and the
durable exchange evidence. Nothing is masked or truncated on the way out:
`ProjectSecret` holds the credential, OSINT entities hold the identity that was
found, and the raw request and response of every exchange travel with them.

Import recreates a bundle as a **new** Project rather than merging into an
existing one. A merge would have to decide, per record type, whether an incoming
row updates an existing row or creates a second one, and a wrong answer would
silently rewrite the evidence of the workspace that was already there. Creating
a sibling Project keeps the source installation untouched and makes the import
verifiable: two workspaces that should match can be compared directly.

Identifiers that are unique across the whole database are regenerated instead of
copied (`Project.name`, `TargetJob.job_id`, `Workflow.webhook_slug`,
`TrafficCaptureContext.token`), so importing the same bundle twice cannot fail on
a collision and cannot let one installation's webhook path or capture token
answer on another. Foreign keys are carried as positional references into the
same bundle, so the relationships survive without depending on the exporting
installation's row numbers.
"""

import ipaddress
import json
from datetime import datetime

from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .models import (
    IntruderAttack,
    OsintEntity,
    OsintGraph,
    OsintRelation,
    Project,
    ProjectEndpoint,
    ProjectExchange,
    ProjectSecret,
    ScannerRun,
    TargetJob,
    TrafficCaptureContext,
    TrafficRecord,
    Workflow,
    WorkflowNodeExecution,
    WorkflowRun,
)
from .project_context import ProjectContextError, normalize_project_notes, normalize_tech_stack
from .workflow_engine import (
    WorkflowValidationError,
    validate_graph_schema_version,
    validate_workflow,
)

#: Wire format written by :func:`export_bundle` and accepted by
#: :func:`import_bundle`. The trailing version is the bundle shape, not the
#: database schema, so a future field addition bumps it instead of guessing.
PROJECT_BUNDLE_SCHEMA = "requestrider.project/v1"

#: Rows are written in batches so a workspace with a large History imports in a
#: bounded number of statements. This is a write batching detail, not a limit on
#: how much a bundle may contain.
IMPORT_BATCH_SIZE = 500


class ProjectTransferError(ValueError):
    """Raised when a bundle cannot be read as a Project transfer document."""


def _iso(value):
    """Serialize a datetime, or report the absence of one as JSON null."""
    if not value:
        return None
    if isinstance(value, str):
        return value
    return value.isoformat()


def _moment(value):
    """Read an exported timestamp back, tolerating the shapes JSON can carry.

    A bundle is a document that can be hand-edited, so a missing or unreadable
    timestamp must not turn an import into a 500. `None` lets the column keep
    its own default instead of inventing a moment the source never recorded.
    """
    if not value:
        return None
    if isinstance(value, datetime):
        return value if timezone.is_aware(value) else timezone.make_aware(value)
    if not isinstance(value, str):
        return None
    parsed = parse_datetime(value)
    if parsed is None:
        return None
    return parsed if timezone.is_aware(parsed) else timezone.make_aware(parsed)


def _address(value):
    """Keep only a value the address column can actually store."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return None
    return text


def _mapping(value):
    """Return a JSON object, or an empty one for anything else."""
    return dict(value) if isinstance(value, dict) else {}


def _sequence(value):
    """Return a JSON array, or an empty one for anything else."""
    return list(value) if isinstance(value, list) else []


# --- imported-workflow provenance ----------------------------------------------
#
# A bundle is a plain JSON file the analyst can be handed. It was written as
# `metadata={**mapping(item["metadata"]), "imported": True}`, so the file chose every
# key in `metadata` and `imported` sat right beside them. A reader could not tell
# "the exporter asserted this" from "the importer recorded this", which is exactly the
# question provenance exists to answer.
#
# So provenance is now written **by this installation**, with values it computed, and
# whatever arrived is kept under one key where it cannot pose as a fact about this
# workspace. Nothing from the file can now look like a local observation.
IMPORTED_METADATA_KEY = "bundle_metadata"


def _imported_workflow_metadata(raw_metadata, *, imported_at, graph_error=None):
    """Build workflow metadata whose provenance keys are server-owned.

    `graph_error` is the validation verdict from import time. It is recorded rather
    than raised, because this module's stated design is that a partly readable bundle
    produces a Project holding exactly the sections it did contain — one malformed
    graph must not throw away a workspace's traffic. The graph is already inert: an
    imported workflow always lands `active=False`, and `validate_workflow` runs again
    before it can execute. What was missing is the operator seeing it, and this is it.
    """
    metadata = {
        "imported": True,
        "imported_at": imported_at,
        "imported_source": "project_bundle",
        "imported_graph_valid": graph_error is None,
    }
    if graph_error is not None:
        metadata["imported_graph_error"] = str(graph_error)[:200]
    incoming = _mapping(raw_metadata)
    if incoming:
        # Namespaced, and never merged: a key from the file cannot overwrite `imported`
        # or invent `imported_at`.
        metadata[IMPORTED_METADATA_KEY] = incoming
    return metadata


def _json_value(value):
    """Keep JSON-compatible checkpoint values intact and discard other types."""
    if value is None or isinstance(value, (dict, list, str, int, float, bool)):
        return value
    return {}


def _imported_workflow_run_status(value):
    """Keep terminal history terminal; imported active runs require review."""
    status = _text(value).strip()
    if status in {"completed", "failed", "cancelled", "interrupted"}:
        return status, ""
    if status in {"queued", "running", "paused"}:
        return "interrupted", (
            "imported active run requires manual review before it can be resumed"
        )
    return "interrupted", "imported run had an unsupported status"


def _integer(value):
    """Return a whole number, or `None` so the column keeps its own default."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _text(value):
    """Return a scalar as text; nested containers are not project text."""
    if value is None or isinstance(value, (dict, list)):
        return ""
    return str(value)


def _split_event_key(event_key: str) -> tuple[int | None, int | None]:
    """Read an exchange's `(session, event)` pair back out of its `event_key`.

    The Project's copy stores the pair as one string, because that is what makes
    the copy unique per project without a second column. A bundle still carries
    the pair in the two fields an importer has always read, so the string is
    taken apart here rather than changing the shape of the document.
    """
    text = _text(event_key)
    session, separator, event = text.partition(":")
    if not separator or session.startswith("derived"):
        return None, None
    return _integer(session), _integer(event)


def _exchange_session(event_key: str) -> int | None:
    return _split_event_key(event_key)[0]


def _exchange_event_id(event_key: str) -> int | None:
    return _split_event_key(event_key)[1]


def export_bundle(project, include_bodies=True):
    """Serialize one Project and every record scoped to it.

    The document is complete rather than sampled: an export that quietly left
    out exchanges or endpoints would read as "this is the workspace" while
    missing the evidence that matters, so a large History produces a large
    response instead of a truncated one. When include_bodies is False, raw request/
    response bodies are omitted to produce a lightweight summary bundle for reports.
    """
    endpoints = ProjectEndpoint.objects.filter(project=project).order_by("path", "method")
    secret_refs = ProjectSecret.objects.filter(project=project)
    scanner_runs = ScannerRun.objects.filter(project=project).order_by("created_at")
    target_jobs = TargetJob.objects.filter(project=project).order_by("created_at")
    workflows = list(Workflow.objects.filter(project=project).order_by("created_at"))
    workflow_index = {workflow.id: index for index, workflow in enumerate(workflows)}
    workflow_runs = list(
        WorkflowRun.objects.filter(workflow__in=workflows)
        .prefetch_related("node_executions")
        .order_by("created_at")
    )
    workflow_runs.sort(
        key=lambda run: (workflow_index[run.workflow_id], run.created_at)
    )
    graphs = list(OsintGraph.objects.filter(project=project).order_by("version", "id"))
    entities = list(OsintEntity.objects.filter(project=project).order_by("id"))
    relations = list(
        OsintRelation.objects.filter(project=project).select_related("source_entity", "target_entity").order_by("id")
    )
    traffic = ProjectExchange.objects.filter(project=project).order_by("timestamp", "id")
    attacks = IntruderAttack.objects.filter(project=project).order_by("created_at")
    contexts = list(TrafficCaptureContext.objects.filter(project=project).order_by("created_at"))

    graph_index = {graph.id: index for index, graph in enumerate(graphs)}
    entity_index = {entity.id: index for index, entity in enumerate(entities)}
    context_index = {context.id: index for index, context in enumerate(contexts)}

    bundle = {
        "schema": PROJECT_BUNDLE_SCHEMA,
        "exported_at": timezone.now().isoformat(),
        "source": {"name": project.name, "created_at": _iso(project.created_at)},
        "project": {
            "name": project.name,
            "target": project.target,
            "environment": project.environment,
            "route_profile": project.route_profile,
            "tech_stack": project.tech_stack or {},
            "notes": project.notes or "",
            "metadata": project.metadata or {},
            "schema_version": project.schema_version,
            "created_at": _iso(project.created_at),
            "updated_at": _iso(project.updated_at),
        },
        "endpoints": [
            {
                "method": endpoint.method,
                "path": endpoint.path,
                "sample_url": endpoint.sample_url,
                "statuses": endpoint.statuses or [],
                "parameters": endpoint.parameters or [],
                "first_seen": _iso(endpoint.first_seen),
                "last_seen": _iso(endpoint.last_seen),
            }
            for endpoint in endpoints
        ],
        # Full disclosure: `value_ref` holds the credential itself, so a bundle carries
        # the value. The Project already stores it and already exports the raw
        # request and response of every exchange, so a bundle that withheld this
        # one field would be less complete than the evidence sitting next to it.
        "secret_references": [
            {
                "secret_type": secret.secret_type,
                "key_name": secret.key_name,
                "value_ref": secret.value_ref,
                "source_url": secret.source_url,
                "created_at": _iso(secret.created_at),
                "updated_at": _iso(secret.updated_at),
            }
            for secret in secret_refs
        ],
        "scanner_runs": [
            {
                "engine": run.engine,
                "url": run.url,
                "summary": run.summary or {},
                "findings": run.findings or [],
                "created_at": _iso(run.created_at),
            }
            for run in scanner_runs
        ],
        "target_jobs": [
            {
                "job_id": job.job_id,
                "engine_kind": job.engine_kind,
                "url": job.url,
                "status": job.status,
                "result": job.result or {},
                "ingested": job.ingested,
                "created_at": _iso(job.created_at),
                "updated_at": _iso(job.updated_at),
            }
            for job in target_jobs
        ],
        "workflows": [
            {
                "name": workflow.name,
                "description": workflow.description,
                "nodes": workflow.nodes or [],
                "connections": workflow.connections or [],
                "graph_schema_version": workflow.graph_schema_version,
                "settings": workflow.settings or {},
                "metadata": workflow.metadata or {},
                "version": workflow.version,
                "active": workflow.active,
                "schedule": workflow.schedule,
                "created_at": _iso(workflow.created_at),
                "updated_at": _iso(workflow.updated_at),
            }
            for workflow in workflows
        ],
        "workflow_runs": [
            {
                "workflow": workflow_index[run.workflow_id],
                "status": run.status,
                "mode": run.mode,
                "trigger_type": run.trigger_type,
                "trigger_node_id": run.trigger_node_id,
                "graph_schema_version": run.graph_schema_version,
                "graph_nodes": run.graph_nodes,
                "graph_connections": run.graph_connections,
                "input_data": run.input_data or {},
                "output_data": run.output_data or {},
                "current_node": run.current_node,
                "logs": run.logs or [],
                "error": run.error,
                "started_at": _iso(run.started_at),
                "finished_at": _iso(run.finished_at),
                "created_at": _iso(run.created_at),
                "updated_at": _iso(run.updated_at),
                "node_executions": [
                    {
                        "node_id": checkpoint.node_id,
                        "status": checkpoint.status,
                        "input_data": checkpoint.input_data,
                        "output_data": checkpoint.output_data,
                        "error": checkpoint.error,
                        "started_at": _iso(checkpoint.started_at),
                        "finished_at": _iso(checkpoint.finished_at),
                    }
                    for checkpoint in sorted(
                        run.node_executions.all(),
                        key=lambda checkpoint: checkpoint.created_at,
                    )
                ],
            }
            for run in workflow_runs
        ],
        "osint": {
            "graphs": [
                {
                    "version": graph.version,
                    "schema_version": graph.schema_version,
                    "status": graph.status,
                    "source": graph.source,
                    "name": graph.name,
                    "metadata": graph.metadata or {},
                    "created_at": _iso(graph.created_at),
                    "updated_at": _iso(graph.updated_at),
                }
                for graph in graphs
            ],
            "entities": [
                {
                    "graph": graph_index.get(entity.graph_id),
                    "type": entity.entity_type,
                    "identity": entity.identity,
                    "display_value": entity.display_value,
                    "risk_score": entity.risk_score,
                    "properties": entity.properties or {},
                    "provenance": entity.provenance or {},
                    "observed_at": _iso(entity.observed_at),
                    "first_observed_at": _iso(entity.first_observed_at),
                }
                for entity in entities
            ],
            "relations": [
                {
                    "graph": graph_index.get(relation.graph_id),
                    "type": relation.relation_type,
                    "source": entity_index.get(relation.source_entity_id),
                    "target": entity_index.get(relation.target_entity_id),
                    "properties": relation.properties or {},
                    "provenance": relation.provenance or {},
                    "observed_at": _iso(relation.observed_at),
                    "first_observed_at": _iso(relation.first_observed_at),
                }
                for relation in relations
            ],
        },
        # Full exchanges: headers and bodies travel with the row, so an exported
        # History stays replayable in Repeater and Intruder after the import.
        #
        # These come from the Project's own copies rather than from the capture
        # archive, so a bundle still holds the evidence after the operator clears
        # the Traffic tab. The row shape is unchanged, which is what keeps a
        # bundle written before this split importable: `proxy_event_id` and
        # `proxy_session` are read back out of the copy's `event_key`, and the
        # two keys that were only ever capture-UI metadata carry their empty
        # defaults.
        "traffic": [
            {
                "timestamp": _iso(record.timestamp),
                "source": record.source,
                "host": record.host,
                "source_ip": record.source_ip or "",
                "proxy_event_id": _exchange_event_id(record.event_key),
                "proxy_session": _exchange_session(record.event_key),
                "capture_context": context_index.get(record.capture_context_id),
                "scope_status": record.scope_status,
                "method": record.method,
                "url": record.url,
                "request_headers": record.request_headers or {} if include_bodies else {},
                "request_body": record.request_body if include_bodies else "",
                "request_body_encoding": record.request_body_encoding if include_bodies else "plain",
                "request_body_base64": record.request_body_base64 if include_bodies else "",
                "response_headers": record.response_headers or {} if include_bodies else {},
                "response_body": record.response_body if include_bodies else "",
                "response_body_encoding": record.response_body_encoding if include_bodies else "plain",
                "response_body_base64": record.response_body_base64 if include_bodies else "",
                "response_content_type": record.response_content_type,
                "status_code": record.status_code,
                "latency_ms": record.latency_ms,
                "response_size": record.response_size,
                "tags": [],
                "notes": "",
            }
            for record in traffic
        ],
        "intruder_attacks": [
            {
                "name": attack.name,
                "engine_attack_id": attack.engine_attack_id,
                "attack_type": attack.attack_type,
                "base_request": attack.base_request or {},
                "payloads": attack.payloads or [],
                "transformations": attack.transformations or [],
                "delay_ms": attack.delay_ms,
                "concurrency": attack.concurrency,
                "status": attack.status,
                "created_at": _iso(attack.created_at),
            }
            for attack in attacks
        ],
        # Tokens are correlation secrets for one installation's live capture, so
        # the bundle names the contexts and the import issues fresh ones.
        "capture_contexts": [
            {"name": context.name, "active": context.active, "created_at": _iso(context.created_at)}
            for context in contexts
        ],
    }
    bundle["counts"] = {
        key: len(bundle[key]) for key in (
            "endpoints", "secret_references", "scanner_runs", "target_jobs",
            "workflows", "workflow_runs", "traffic", "intruder_attacks", "capture_contexts",
        )
    }
    bundle["counts"]["osint_graphs"] = len(bundle["osint"]["graphs"])
    bundle["counts"]["osint_entities"] = len(bundle["osint"]["entities"])
    bundle["counts"]["osint_relations"] = len(bundle["osint"]["relations"])
    return bundle


def _read_bundle(payload):
    """Pull the transfer document out of a request body.

    Both the wrapper written by :func:`export_bundle` and a bare project object
    are accepted, so a bundle someone extracted by hand still imports.
    """
    if not isinstance(payload, dict):
        raise ProjectTransferError("project bundle must be a JSON object")
    schema = str(payload.get("schema") or "").strip()
    if schema and not schema.startswith("requestrider.project/"):
        raise ProjectTransferError(f"unsupported bundle schema: {schema}")
    source = payload.get("project") if isinstance(payload.get("project"), dict) else payload
    if not isinstance(source, dict):
        raise ProjectTransferError("project bundle has no project object")
    return source


def _unique_project_name(preferred):
    """Return a name no Project holds yet.

    Importing a bundle into an installation that already has the workspace is
    the normal case, so the name is suffixed instead of rejected: the operator
    ends up with a second, clearly labelled workspace rather than an error and
    no way forward.
    """
    base = (preferred or "Imported project").strip() or "Imported project"
    candidate = base
    suffix = 2
    while Project.objects.filter(name=candidate).exists():
        candidate = f"{base} ({suffix})"
        suffix += 1
    return candidate


def _slug(value, fallback):
    """Build a fresh unique slug for an imported webhook path.

    The exported slug belongs to the installation that produced the bundle, and
    webhook paths are routed globally here, so reusing it would either collide
    or point this installation's triggers at the other one's runs.
    """
    raw = "".join(character if character.isalnum() else "-" for character in str(value or "").lower())
    base = "-".join(part for part in raw.split("-") if part) or fallback
    candidate = base
    suffix = 2
    while Workflow.objects.filter(webhook_slug=candidate).exists():
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate


def _job_id(seed, index):
    """Return a Target job id that cannot collide with an existing run."""
    candidate = f"imported-{seed}-{index}"
    while TargetJob.objects.filter(job_id=candidate).exists():
        candidate = f"{candidate}-x"
    return candidate


def import_bundle(payload):
    """Recreate a bundle as a new Project and return it with a record report.

    Rows are written in dependency order - Project, then the records that point
    at it, then the records that point at those - so a partially readable
    bundle produces a Project with exactly the sections it did contain instead
    of a failed transaction. The report says which sections were written, so the
    UI can state the result rather than implying a perfect copy.
    """
    source = _read_bundle(payload)
    name = _text(source.get("name")).strip()
    if not name:
        raise ProjectTransferError("project bundle has no name")
    workflow_rows = [
        item for item in _sequence(payload.get("workflows")) if isinstance(item, dict)
    ]
    workflow_run_rows = [
        item
        for item in _sequence(payload.get("workflow_runs"))
        if isinstance(item, dict)
        and (position := _integer(item.get("workflow"))) is not None
        and 0 <= position < len(workflow_rows)
    ]
    try:
        workflow_schema_versions = [
            validate_graph_schema_version(item.get("graph_schema_version"))
            for item in workflow_rows
        ]
        workflow_run_schema_versions = [
            validate_graph_schema_version(item.get("graph_schema_version"))
            for item in workflow_run_rows
        ]
    except WorkflowValidationError as error:
        raise ProjectTransferError(str(error)) from error
    try:
        tech_stack = normalize_tech_stack(source.get("tech_stack"))
        notes = normalize_project_notes(source.get("notes"))
    except ProjectContextError as error:
        raise ProjectTransferError(str(error)) from error
    project = Project(
        name=_unique_project_name(name),
        target=_text(source.get("target")).strip(),
        environment=_text(source.get("environment")).strip(),
        route_profile=_text(source.get("route_profile")).strip(),
        tech_stack=tech_stack,
        notes=notes,
        metadata=_mapping(source.get("metadata")),
        schema_version=max(1, _integer(source.get("schema_version")) or 1),
    )
    project.save()

    report = {"project_id": project.id, "project_name": project.name}

    endpoints = []
    for item in _sequence(payload.get("endpoints")):
        if not isinstance(item, dict):
            continue
        path = _text(item.get("path")).strip()
        if not path:
            continue
        endpoints.append(ProjectEndpoint(
            project=project,
            method=_text(item.get("method")).strip().upper() or "GET",
            path=path,
            sample_url=_text(item.get("sample_url")),
            statuses=_sequence(item.get("statuses")),
            parameters=_sequence(item.get("parameters")),
            first_seen=_moment(item.get("first_seen")) or timezone.now(),
            last_seen=_moment(item.get("last_seen")) or timezone.now(),
        ))
    # One endpoint per (method, path) is a database constraint, so a bundle that
    # repeats a pair is collapsed instead of failing the whole import.
    unique_endpoints = {}
    for endpoint in endpoints:
        unique_endpoints[(endpoint.method, endpoint.path)] = endpoint
    if unique_endpoints:
        ProjectEndpoint.objects.bulk_create(list(unique_endpoints.values()), batch_size=IMPORT_BATCH_SIZE)
    report["endpoints"] = len(unique_endpoints)

    secrets = []
    for item in _sequence(payload.get("secret_references")):
        if not isinstance(item, dict) or not _text(item.get("key_name")).strip():
            continue
        secrets.append(ProjectSecret(
            project=project,
            secret_type=_text(item.get("secret_type")).strip() or "api_key",
            key_name=_text(item.get("key_name")).strip(),
            value_ref=_text(item.get("value_ref")),
            source_url=_text(item.get("source_url")),
        ))
    if secrets:
        ProjectSecret.objects.bulk_create(secrets, batch_size=IMPORT_BATCH_SIZE)
    report["secret_references"] = len(secrets)

    runs = [
        ScannerRun(
            project=project,
            engine=_text(item.get("engine")).strip() or "builtin",
            url=_text(item.get("url")),
            summary=_mapping(item.get("summary")),
            findings=_sequence(item.get("findings")),
        )
        for item in _sequence(payload.get("scanner_runs"))
        if isinstance(item, dict)
    ]
    if runs:
        ScannerRun.objects.bulk_create(runs, batch_size=IMPORT_BATCH_SIZE)
    report["scanner_runs"] = len(runs)

    contexts = []
    for item in _sequence(payload.get("capture_contexts")):
        if not isinstance(item, dict):
            continue
        context = TrafficCaptureContext(
            project=project,
            name=_text(item.get("name")).strip() or "Capture context",
            # A fresh token is generated by the model default, so an imported
            # context can never be spoken for by a token from another install.
            active=bool(item.get("active", True)),
        )
        context.save()
        contexts.append(context)
    report["capture_contexts"] = len(contexts)

    jobs = []
    for index, item in enumerate(_sequence(payload.get("target_jobs"))):
        if not isinstance(item, dict):
            continue
        url = _text(item.get("url")).strip()
        if not url:
            continue
        jobs.append(TargetJob(
            project=project,
            job_id=_job_id(project.id, index),
            engine_kind=_text(item.get("engine_kind")).strip() or "static",
            url=url,
            status=_text(item.get("status")).strip() or "imported",
            result=_mapping(item.get("result")),
            # The pages were indexed into the bundle, so the knowledge base they
            # produced is already present and must not be written a second time.
            ingested=True,
        ))
    if jobs:
        TargetJob.objects.bulk_create(jobs, batch_size=IMPORT_BATCH_SIZE)
    report["target_jobs"] = len(jobs)

    imported_at = timezone.now().isoformat()
    workflows = []
    for index, (item, graph_schema_version) in enumerate(
        zip(workflow_rows, workflow_schema_versions, strict=True)
    ):
        # Validate the graph at import so the verdict is on the record. Only the schema
        # version was checked before, so a graph that cannot run was stored with nothing
        # saying so, and the operator found out by activating it.
        graph_error = None
        try:
            validate_workflow(
                _sequence(item.get("nodes")),
                _sequence(item.get("connections")),
            )
        except WorkflowValidationError as error:
            graph_error = error

        workflow = Workflow(
            project=project,
            name=_text(item.get("name")).strip() or f"Workflow {index + 1}",
            description=_text(item.get("description")),
            nodes=_sequence(item.get("nodes")),
            connections=_sequence(item.get("connections")),
            graph_schema_version=graph_schema_version,
            settings=_mapping(item.get("settings")),
            metadata=_imported_workflow_metadata(
                item.get("metadata"), imported_at=imported_at, graph_error=graph_error
            ),
            version=max(1, _integer(item.get("version")) or 1),
            # A schedule would start firing on this installation the moment it
            # were activated, so an imported workflow always lands inactive and
            # is activated deliberately by the operator.
            active=False,
            schedule=_text(item.get("schedule")),
            webhook_slug=_slug(item.get("webhook_slug"), f"imported-{project.id}-{index + 1}"),
        )
        workflow.save()
        workflows.append(workflow)
    report["workflows"] = len(workflows)

    workflow_runs = []
    for item, run_graph_schema_version in zip(
        workflow_run_rows,
        workflow_run_schema_versions,
        strict=True,
    ):
        position = _integer(item.get("workflow"))
        run_status, imported_status_error = _imported_workflow_run_status(
            item.get("status")
        )
        workflow_runs.append(WorkflowRun(
            workflow=workflows[position],
            project=project,
            status=run_status,
            mode=_text(item.get("mode")).strip() or "manual",
            trigger_type=_text(item.get("trigger_type")) or "imported",
            trigger_node_id=_text(item.get("trigger_node_id")),
            graph_schema_version=run_graph_schema_version,
            graph_nodes=(
                _sequence(item.get("graph_nodes"))
                if isinstance(item.get("graph_nodes"), list)
                else None
            ),
            graph_connections=(
                _sequence(item.get("graph_connections"))
                if isinstance(item.get("graph_connections"), list)
                else None
            ),
            input_data=_mapping(item.get("input_data")),
            output_data=_mapping(item.get("output_data")),
            current_node=_text(item.get("current_node")),
            logs=_sequence(item.get("logs")),
            error=_text(item.get("error")) or imported_status_error,
            started_at=_moment(item.get("started_at")),
            finished_at=_moment(item.get("finished_at")),
        ))
        workflow_runs[-1]._imported_node_executions = [
            checkpoint
            for checkpoint in _sequence(item.get("node_executions"))
            if isinstance(checkpoint, dict)
            and _text(checkpoint.get("node_id")).strip()
            and _text(checkpoint.get("status")).strip() in {
                "running", "completed", "failed"
            }
        ]
    if workflow_runs:
        WorkflowRun.objects.bulk_create(workflow_runs, batch_size=IMPORT_BATCH_SIZE)
        checkpoint_rows = []
        for run in workflow_runs:
            for checkpoint in run._imported_node_executions:
                checkpoint_rows.append(WorkflowNodeExecution(
                    workflow_run=run,
                    node_id=_text(checkpoint.get("node_id")).strip(),
                    status=_text(checkpoint.get("status")).strip(),
                    input_data=_json_value(checkpoint.get("input_data")),
                    output_data=_mapping(checkpoint.get("output_data")),
                    error=_text(checkpoint.get("error")),
                    started_at=_moment(checkpoint.get("started_at")),
                    finished_at=_moment(checkpoint.get("finished_at")),
                ))
        if checkpoint_rows:
            WorkflowNodeExecution.objects.bulk_create(
                checkpoint_rows,
                batch_size=IMPORT_BATCH_SIZE,
            )
    report["workflow_runs"] = len(workflow_runs)

    osint = payload.get("osint") if isinstance(payload.get("osint"), dict) else {}
    graphs = []
    for index, item in enumerate(_sequence(osint.get("graphs"))):
        if not isinstance(item, dict):
            continue
        graph = OsintGraph(
            project=project,
            version=max(1, _integer(item.get("version")) or index + 1),
            schema_version=max(1, _integer(item.get("schema_version")) or 1),
            status=_text(item.get("status")).strip() or "current",
            source=_text(item.get("source")) or "imported",
            name=_text(item.get("name")).strip() or "OSINT graph",
            metadata=_mapping(item.get("metadata")),
        )
        graph.save()
        graphs.append(graph)
    report["osint_graphs"] = len(graphs)

    entity_rows = []
    for item in _sequence(osint.get("entities")):
        if not isinstance(item, dict):
            continue
        position = _integer(item.get("graph"))
        identity = _text(item.get("identity")).strip()
        if position is None or not 0 <= position < len(graphs) or not identity:
            continue
        entity_rows.append(OsintEntity(
            graph=graphs[position],
            project=project,
            entity_type=_text(item.get("type")).strip() or "domain",
            identity=identity,
            display_value=_text(item.get("display_value")),
            risk_score=_integer(item.get("risk_score")) or 0,
            properties=_mapping(item.get("properties")),
            provenance=_mapping(item.get("provenance")),
            observed_at=_moment(item.get("observed_at")) or timezone.now(),
            first_observed_at=_moment(item.get("first_observed_at")) or timezone.now(),
        ))
    if entity_rows:
        OsintEntity.objects.bulk_create(entity_rows, batch_size=IMPORT_BATCH_SIZE)
    report["osint_entities"] = len(entity_rows)

    relation_rows = []
    for item in _sequence(osint.get("relations")):
        if not isinstance(item, dict):
            continue
        source_index = _integer(item.get("source"))
        target_index = _integer(item.get("target"))
        if (
            source_index is None or target_index is None
            or not 0 <= source_index < len(entity_rows)
            or not 0 <= target_index < len(entity_rows)
        ):
            continue
        relation_rows.append(OsintRelation(
            graph=entity_rows[source_index].graph,
            project=project,
            relation_type=_text(item.get("type")).strip() or "related_to",
            source_entity=entity_rows[source_index],
            target_entity=entity_rows[target_index],
            properties=_mapping(item.get("properties")),
            provenance=_mapping(item.get("provenance")),
            observed_at=_moment(item.get("observed_at")) or timezone.now(),
            first_observed_at=_moment(item.get("first_observed_at")) or timezone.now(),
        ))
    if relation_rows:
        OsintRelation.objects.bulk_create(relation_rows, batch_size=IMPORT_BATCH_SIZE)
    report["osint_relations"] = len(relation_rows)

    attacks = []
    for item in _sequence(payload.get("intruder_attacks")):
        if not isinstance(item, dict):
            continue
        base_request = _mapping(item.get("base_request"))
        if not base_request.get("url"):
            continue
        attacks.append(IntruderAttack(
            project=project,
            name=_text(item.get("name")).strip() or "Intruder attack",
            # The engine's own attack id names a run inside the exporting
            # installation; the import gets its own so a rerun cannot append to
            # a job this database has never seen.
            engine_attack_id="",
            attack_type=_text(item.get("attack_type")).strip() or "sniper",
            base_request=base_request,
            payloads=_sequence(item.get("payloads")),
            transformations=_sequence(item.get("transformations")),
            delay_ms=max(0, _integer(item.get("delay_ms")) or 0),
            concurrency=max(1, _integer(item.get("concurrency")) or 1),
            status="imported",
        ))
    if attacks:
        IntruderAttack.objects.bulk_create(attacks, batch_size=IMPORT_BATCH_SIZE)
    report["intruder_attacks"] = len(attacks)

    traffic = []
    traffic_times = []
    for item in _sequence(payload.get("traffic")):
        if not isinstance(item, dict):
            continue
        url = _text(item.get("url")).strip()
        if not url:
            continue
        # An unreadable observation time keeps the column default rather than
        # inventing a moment, so a hand-edited bundle still imports.
        traffic_times.append(_moment(item.get("timestamp")) or timezone.now())
        context_position = _integer(item.get("capture_context"))
        context = (
            contexts[context_position]
            if context_position is not None and 0 <= context_position < len(contexts)
            else None
        )
        traffic.append(TrafficRecord(
            project=project,
            source=_text(item.get("source")).strip() or "repeater",
            host=_text(item.get("host")),
            source_ip=_address(item.get("source_ip")),
            proxy_event_id=_integer(item.get("proxy_event_id")),
            proxy_session=_integer(item.get("proxy_session")),
            capture_context=context,
            scope_status=_text(item.get("scope_status")).strip() or ("project_linked" if context else "unscoped"),
            method=_text(item.get("method")).strip().upper() or "GET",
            url=url,
            request_headers=_mapping(item.get("request_headers")),
            request_body=item.get("request_body"),
            request_body_encoding=_text(item.get("request_body_encoding")) or "utf8",
            request_body_base64=_text(item.get("request_body_base64")),
            response_headers=_mapping(item.get("response_headers")),
            response_body=item.get("response_body"),
            response_body_encoding=_text(item.get("response_body_encoding")) or "utf8",
            response_body_base64=_text(item.get("response_body_base64")),
            response_content_type=_text(item.get("response_content_type")),
            status_code=_integer(item.get("status_code")),
            latency_ms=_integer(item.get("latency_ms")),
            response_size=_integer(item.get("response_size")),
            tags=_sequence(item.get("tags")),
            notes=_text(item.get("notes")),
        ))
    if traffic:
        # The exported observation time is restored, so an imported workspace
        # keeps its chronology in History instead of appearing as one burst that
        # happened at the moment of the import.
        for record, observed in zip(traffic, traffic_times):
            record.timestamp = observed
        TrafficRecord.objects.bulk_create(traffic, batch_size=IMPORT_BATCH_SIZE)
        # bulk_create skips post_save, so the derived knowledge base is written
        # for the imported rows in one pass instead of never at all.
        try:
            from .ingest import ingest_traffic_batch

            ingest_traffic_batch(traffic)
        except Exception as error:  # noqa: BLE001 - a derived index must not lose the evidence
            project.metadata = {**project.metadata, "import_traffic_index_error": error.__class__.__name__}
            project.save(update_fields=["metadata", "updated_at"])
    report["traffic"] = len(traffic)
    return project, report


def parse_bundle_body(body):
    """Read a request body as a transfer document.

    A body that is not JSON, or is valid JSON of the wrong shape, is a client
    error naming the reason - never a silent empty import that reports success.
    """
    if isinstance(body, (bytes, bytearray)):
        try:
            body = body.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ProjectTransferError("project bundle must be UTF-8 encoded JSON") from error
    if isinstance(body, str):
        if not body.strip():
            raise ProjectTransferError("project bundle is empty")
        try:
            body = json.loads(body)
        except json.JSONDecodeError as error:
            raise ProjectTransferError(f"project bundle is not valid JSON: {error.msg}") from error
    return body
