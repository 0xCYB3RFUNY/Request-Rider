"""Project-scoped OSINT graph persistence and idempotent upserts."""

from __future__ import annotations

import ipaddress
import re
from datetime import timezone as datetime_timezone
from urllib.parse import urlsplit, urlunsplit

from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .models import OsintEntity, OsintGraph, OsintRelation, Project

ENTITY_TYPES = {choice for choice, _ in OsintEntity.ENTITY_TYPE_CHOICES}
RELATION_TYPES = {
    "contains",
    "resolves_to",
    "subdomain_of",
    "dns_record",
    "same_as",
    "hosted_on",
    "uses",
    "exposes",
    "certificate_for",
    "linked_to",
    "observed_at",
}

_SENSITIVE_RE = re.compile(
    r"(?i)\b(authorization|cookie|set-cookie|x-api-key|x-csrftoken|api[_-]?key|password|passwd|pwd|secret|token)\b\s*[:=]\s*(?:bearer\s+)?[^\s,;]+"
)
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[^\s,;]+")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


class OsintGraphError(ValueError):
    """Raised when graph input is invalid."""


def _redact_text(value):
    text = " ".join(str(value or "").split())
    text = _SENSITIVE_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    return _JWT_RE.sub("[REDACTED_JWT]", text)


def _safe_value(value):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, list):
        return [_safe_value(item) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            clean_key = _redact_text(key)
            if not clean_key:
                raise OsintGraphError("OSINT metadata contains an empty key")
            result[clean_key] = _safe_value(item)
        return result
    raise OsintGraphError("OSINT metadata must contain JSON-compatible values")


def normalize_metadata(value, field_name="metadata"):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise OsintGraphError(f"{field_name} must be an object")
    return _safe_value(value)


def parse_observed_at(value, field_name="observed_at"):
    if value in (None, ""):
        return timezone.now()
    if not isinstance(value, str):
        raise OsintGraphError(f"{field_name} must be an ISO-8601 timestamp")
    parsed = parse_datetime(value)
    if not parsed:
        raise OsintGraphError(f"{field_name} must be an ISO-8601 timestamp")
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone=datetime_timezone.utc)
    return parsed


def _normalize_hostname(value):
    raw = str(value or "").strip().lower().rstrip(".")
    if not raw or any(ord(character) < 33 for character in raw):
        raise OsintGraphError("domain identity is invalid")
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        address = None
    if address is not None:
        return str(address)
    if any(character in raw for character in "\\/:@?#"):
        raise OsintGraphError("domain identity is invalid")
    try:
        ascii_host = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise OsintGraphError("domain identity is invalid") from error
    labels = ascii_host.split(".")
    if any(
        not label
        or not label[0].isalnum()
        or not label[-1].isalnum()
        or any(not (character.isalnum() or character == "-") for character in label)
        for label in labels
    ):
        raise OsintGraphError("domain identity is invalid")
    return ascii_host


def normalize_entity_identity(entity_type, value):
    if entity_type not in ENTITY_TYPES:
        raise OsintGraphError(f"unsupported OSINT entity type: {entity_type}")
    raw = str(value or "").strip()
    if not raw or any(ord(character) < 32 for character in raw):
        raise OsintGraphError("OSINT entity identity is invalid")
    if entity_type in {"domain", "subdomain"}:
        return _normalize_hostname(raw), raw
    if entity_type == "ip":
        try:
            return str(ipaddress.ip_address(raw)), raw
        except ValueError as error:
            raise OsintGraphError("IP identity is invalid") from error
    if entity_type == "cidr":
        try:
            return str(ipaddress.ip_network(raw, strict=False)), raw
        except ValueError as error:
            raise OsintGraphError("CIDR identity is invalid") from error
    if entity_type == "url":
        try:
            parsed = urlsplit(raw)
            port = parsed.port
        except ValueError as error:
            raise OsintGraphError("URL identity is invalid") from error
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise OsintGraphError("URL identity must be absolute HTTP(S)")
        if parsed.username or parsed.password or parsed.fragment:
            raise OsintGraphError("URL identity must not contain credentials or fragments")
        host = _normalize_hostname(parsed.hostname)
        display_host = f"[{host}]" if ":" in host else host
        default_port = 443 if parsed.scheme.lower() == "https" else 80
        netloc = display_host if port in {None, default_port} else f"{display_host}:{port}"
        canonical = urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", "", ""))
        return canonical, canonical
    if entity_type == "email":
        if "@" not in raw or any(character.isspace() for character in raw):
            raise OsintGraphError("email identity is invalid")
        return raw.lower(), raw
    if entity_type == "username":
        return raw, raw
    if entity_type == "asn":
        asn_value = raw[2:] if raw.lower().startswith("as") else raw
        if not asn_value.isdigit() or int(asn_value) < 1:
            raise OsintGraphError("ASN identity is invalid")
        return f"AS{int(asn_value)}", raw
    if entity_type == "port":
        if not raw.isdigit() or not 1 <= int(raw) <= 65535:
            raise OsintGraphError("port identity is invalid")
        return str(int(raw)), raw
    return _redact_text(raw), _redact_text(raw)


def _merge_metadata(existing, incoming):
    merged = dict(existing or {})
    merged.update(incoming or {})
    return normalize_metadata(merged, "metadata")


def _upsert_entity(graph, item, default_observed_at):
    if not isinstance(item, dict):
        raise OsintGraphError("each OSINT entity must be an object")
    entity_type = str(item.get("type") or item.get("entity_type") or "").strip().lower()
    identity_input = item.get("identity")
    identity, display_value = normalize_entity_identity(entity_type, identity_input)
    observed_at = parse_observed_at(item.get("observed_at"), "entity.observed_at") if item.get("observed_at") else default_observed_at
    properties = normalize_metadata(item.get("properties"), "entity.properties")
    provenance = normalize_metadata(item.get("provenance"), "entity.provenance")
    risk_score = item.get("risk_score", 0)
    if isinstance(risk_score, bool) or not isinstance(risk_score, int):
        raise OsintGraphError("entity risk_score must be an integer")
    if risk_score < 0 or risk_score > 100:
        raise OsintGraphError("entity risk_score must be between 0 and 100")
    entity, _created = OsintEntity.objects.get_or_create(
        graph=graph,
        project=graph.project,
        entity_type=entity_type,
        identity=identity,
        defaults={
            "display_value": display_value,
            "risk_score": risk_score,
            "properties": properties,
            "provenance": provenance,
            "observed_at": observed_at,
            "first_observed_at": observed_at,
        },
    )
    if observed_at >= entity.first_observed_at:
        entity.first_observed_at = min(entity.first_observed_at, observed_at)
    if observed_at >= entity.observed_at:
        entity.display_value = display_value or entity.display_value
        if "risk_score" in item:
            entity.risk_score = risk_score
        entity.properties = _merge_metadata(entity.properties, properties)
        entity.provenance = _merge_metadata(entity.provenance, provenance)
        entity.observed_at = observed_at
        entity.save(update_fields=["display_value", "risk_score", "properties", "provenance", "observed_at", "first_observed_at", "updated_at"])
    return entity


def _find_entity(graph, entity_type, identity_input):
    entity_type = str(entity_type or "").strip().lower()
    identity, _display = normalize_entity_identity(entity_type, identity_input)
    return OsintEntity.objects.filter(graph=graph, entity_type=entity_type, identity=identity).first()


def _upsert_relation(graph, item, default_observed_at, entity_cache):
    if not isinstance(item, dict):
        raise OsintGraphError("each OSINT relation must be an object")
    relation_type = str(item.get("type") or item.get("relation_type") or "").strip().lower()
    if relation_type not in RELATION_TYPES:
        raise OsintGraphError(f"unsupported OSINT relation type: {relation_type}")
    source = item.get("source") or item.get("source_identity")
    target = item.get("target") or item.get("target_identity")
    source_entity = entity_cache.get((str(item.get("source_type") or "domain").lower(), str(source))) if source else None
    target_entity = entity_cache.get((str(item.get("target_type") or "domain").lower(), str(target))) if target else None
    if source_entity is None and source:
        source_entity = _find_entity(graph, item.get("source_type") or "domain", source)
    if target_entity is None and target:
        target_entity = _find_entity(graph, item.get("target_type") or "domain", target)
    if source_entity is None:
        raise OsintGraphError(f"OSINT relation source is not an entity in this graph: {source}")
    if target_entity is None:
        raise OsintGraphError(f"OSINT relation target is not an entity in this graph: {target}")
    observed_at = parse_observed_at(item.get("observed_at"), "relation.observed_at") if item.get("observed_at") else default_observed_at
    properties = normalize_metadata(item.get("properties"), "relation.properties")
    provenance = normalize_metadata(item.get("provenance"), "relation.provenance")
    relation, _created = OsintRelation.objects.get_or_create(
        graph=graph,
        project=graph.project,
        relation_type=relation_type,
        source_entity=source_entity,
        target_entity=target_entity,
        defaults={
            "properties": properties,
            "provenance": provenance,
            "observed_at": observed_at,
            "first_observed_at": observed_at,
        },
    )
    if observed_at >= relation.observed_at:
        relation.properties = _merge_metadata(relation.properties, properties)
        relation.provenance = _merge_metadata(relation.provenance, provenance)
        relation.observed_at = observed_at
        relation.save(update_fields=["properties", "provenance", "observed_at", "updated_at"])
    return relation


@transaction.atomic
def create_graph(project, version=None, source="manual", name="OSINT graph", metadata=None):
    if project is None:
        raise OsintGraphError("project is required")
    if version is None:
        latest = OsintGraph.objects.filter(project=project).order_by("-version").first()
        version = (latest.version + 1) if latest else 1
    try:
        version = int(version)
    except (TypeError, ValueError) as error:
        raise OsintGraphError("graph version must be a positive integer") from error
    if version < 1:
        raise OsintGraphError("graph version must be a positive integer")
    if OsintGraph.objects.filter(project=project, version=version).exists():
        raise OsintGraphError("graph version already exists")
    OsintGraph.objects.filter(project=project, status="current").update(status="archived")
    return OsintGraph.objects.create(
        project=project,
        version=version,
        source=_redact_text(source or "manual"),
        name=_redact_text(name or "OSINT graph"),
        metadata=normalize_metadata(metadata, "graph.metadata"),
        status="current",
    )


@transaction.atomic
def upsert_graph(graph, payload, skip_invalid=False):
    """Merge entities and relations into one graph.

    Third-party OSINT adapters legitimately return identities the graph cannot
    store, for example a wildcard certificate name such as ``*.*.example.com``
    or an underscore label. With ``skip_invalid`` those single rows are dropped
    and reported in the returned ``rejected`` list instead of aborting the whole
    batch, so one unusable name cannot discard thousands of valid findings.
    Without it the batch stays atomic and the first invalid row is an error.
    """
    if graph.project_id is None:
        raise OsintGraphError("graph project is required")
    if not isinstance(payload, dict):
        raise OsintGraphError("graph upsert payload must be an object")
    entities = payload.get("entities", [])
    relations = payload.get("relations", [])
    if not isinstance(entities, list):
        raise OsintGraphError("entities must be a list")
    if not isinstance(relations, list):
        raise OsintGraphError("relations must be a list")
    default_observed_at = parse_observed_at(payload.get("observed_at"))
    rejected = []
    entity_cache = {}
    for item in entities:
        try:
            entity = _upsert_entity(graph, item, default_observed_at)
        except OsintGraphError as error:
            if not skip_invalid:
                raise
            rejected.append(_rejected_item("entity", item, error))
            continue
        entity_cache[(entity.entity_type, entity.identity)] = entity
    for item in relations:
        try:
            _upsert_relation(graph, item, default_observed_at, entity_cache)
        except OsintGraphError as error:
            if not skip_invalid:
                raise
            rejected.append(_rejected_item("relation", item, error))
    graph.metadata = _merge_metadata(graph.metadata, normalize_metadata(payload.get("metadata"), "graph.metadata"))
    graph.save(update_fields=["metadata", "updated_at"])
    return {
        "entities": OsintEntity.objects.filter(graph=graph).count(),
        "relations": OsintRelation.objects.filter(graph=graph).count(),
        "rejected": rejected,
    }


def _rejected_item(kind, item, error):
    """Describe one dropped row without echoing a whole third-party payload."""
    if not isinstance(item, dict):
        return {"kind": kind, "identity": None, "error": str(error)}
    identity = item.get("identity")
    if identity is None and kind == "relation":
        source = item.get("source") or item.get("source_identity")
        target = item.get("target") or item.get("target_identity")
        return {
            "kind": kind,
            "type": str(item.get("type") or item.get("relation_type") or ""),
            "identity": f"{source} -> {target}",
            "error": str(error),
        }
    return {
        "kind": kind,
        "type": str(item.get("type") or item.get("entity_type") or item.get("relation_type") or ""),
        "identity": str(identity)[:200] if identity is not None else None,
        "error": str(error),
    }


@transaction.atomic
def update_entity(graph, entity_id, payload):
    """Edit one stored entity in place; identity and type stay immutable."""
    if not isinstance(payload, dict):
        raise OsintGraphError("entity update payload must be an object")
    entity = OsintEntity.objects.filter(graph=graph, id=entity_id).first()
    if entity is None:
        raise OsintGraphError("OSINT entity not found in this graph")
    update_fields = []
    if "risk_score" in payload:
        risk_score = payload.get("risk_score")
        if isinstance(risk_score, bool) or not isinstance(risk_score, int):
            raise OsintGraphError("entity risk_score must be an integer")
        if risk_score < 0 or risk_score > 100:
            raise OsintGraphError("entity risk_score must be between 0 and 100")
        entity.risk_score = risk_score
        update_fields.append("risk_score")
    if "display_value" in payload:
        display_value = str(payload.get("display_value") or "")
        if any(ord(character) < 32 for character in display_value):
            raise OsintGraphError("entity display_value is invalid")
        entity.display_value = _redact_text(display_value)
        update_fields.append("display_value")
    if "properties" in payload:
        entity.properties = _merge_metadata(entity.properties, normalize_metadata(payload.get("properties"), "entity.properties"))
        update_fields.append("properties")
    if "provenance" in payload:
        entity.provenance = _merge_metadata(entity.provenance, normalize_metadata(payload.get("provenance"), "entity.provenance"))
        update_fields.append("provenance")
    if not update_fields:
        raise OsintGraphError("entity update requires at least one editable field")
    entity.save(update_fields=[*update_fields, "updated_at"])
    return entity


@transaction.atomic
def delete_entity(graph, entity_id):
    """Remove one entity together with every relation that referenced it."""
    entity = OsintEntity.objects.filter(graph=graph, id=entity_id).first()
    if entity is None:
        raise OsintGraphError("OSINT entity not found in this graph")
    relations = entity.outgoing_relations.count() + entity.incoming_relations.count()
    identity = entity.identity
    entity.delete()
    return {"entity": identity, "relations": relations}


@transaction.atomic
def delete_relation(graph, relation_id):
    """Remove one relation while keeping both of its endpoint entities."""
    relation = OsintRelation.objects.filter(graph=graph, id=relation_id).first()
    if relation is None:
        raise OsintGraphError("OSINT relation not found in this graph")
    detail = {
        "relation": relation.relation_type,
        "source_identity": relation.source_entity.identity,
        "target_identity": relation.target_entity.identity,
    }
    relation.delete()
    return detail


@transaction.atomic
def clear_graph(graph):
    """Empty one graph so a fresh entity set can be collected into it."""
    relations = OsintRelation.objects.filter(graph=graph).delete()[0]
    entities = OsintEntity.objects.filter(graph=graph).delete()[0]
    graph.metadata = {}
    graph.save(update_fields=["metadata", "updated_at"])
    return {"entities": entities, "relations": relations}


def entity_item(entity):
    return {
        "id": entity.id,
        "graph_id": entity.graph_id,
        "project_id": entity.project_id,
        "type": entity.entity_type,
        "identity": entity.identity,
        "display_value": entity.display_value,
        "risk_score": entity.risk_score,
        "properties": entity.properties or {},
        "provenance": entity.provenance or {},
        "observed_at": entity.observed_at.isoformat(),
        "first_observed_at": entity.first_observed_at.isoformat(),
    }


def relation_item(relation):
    return {
        "id": relation.id,
        "graph_id": relation.graph_id,
        "project_id": relation.project_id,
        "type": relation.relation_type,
        "source_entity_id": relation.source_entity_id,
        "target_entity_id": relation.target_entity_id,
        "source_identity": relation.source_entity.identity,
        "target_identity": relation.target_entity.identity,
        "properties": relation.properties or {},
        "provenance": relation.provenance or {},
        "observed_at": relation.observed_at.isoformat(),
        "first_observed_at": relation.first_observed_at.isoformat(),
    }


def graph_item(graph, include_contents=False):
    data = {
        "id": graph.id,
        "project_id": graph.project_id,
        "version": graph.version,
        "schema_version": graph.schema_version,
        "status": graph.status,
        "source": graph.source,
        "name": graph.name,
        "metadata": graph.metadata or {},
        "entity_count": graph.entities.count(),
        "relation_count": graph.relations.count(),
        "created_at": graph.created_at.isoformat(),
        "updated_at": graph.updated_at.isoformat(),
    }
    if include_contents:
        data["entities"] = [entity_item(entity) for entity in graph.entities.all()]
        data["relations"] = [relation_item(relation) for relation in graph.relations.select_related("source_entity", "target_entity")]
    return data
