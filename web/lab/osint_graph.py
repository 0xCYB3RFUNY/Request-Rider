"""Bounded, project-scoped OSINT graph persistence and idempotent upserts."""

from __future__ import annotations

import ipaddress
import re
from datetime import timezone as datetime_timezone
from urllib.parse import urlsplit, urlunsplit

from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from .models import OsintEntity, OsintGraph, OsintRelation, Project
from .runtime_limits import (
    OSINT_GRAPH_MAX_ENTITIES,
    OSINT_GRAPH_MAX_ENTITY_PROPERTY_KEYS,
    OSINT_GRAPH_MAX_IDENTITY_LENGTH,
    OSINT_GRAPH_MAX_METADATA_KEYS,
    OSINT_GRAPH_MAX_NESTED_LIST,
    OSINT_GRAPH_MAX_OBJECT_KEYS,
    OSINT_GRAPH_MAX_PROVENANCE_DEPTH,
    OSINT_GRAPH_MAX_RELATIONS,
    OSINT_GRAPH_MAX_TEXT_LENGTH,
)


MAX_GRAPH_METADATA_KEYS = OSINT_GRAPH_MAX_METADATA_KEYS
MAX_ENTITY_PROPERTIES_KEYS = OSINT_GRAPH_MAX_ENTITY_PROPERTY_KEYS
MAX_ENTITY_IDENTITY_LENGTH = OSINT_GRAPH_MAX_IDENTITY_LENGTH
MAX_ENTITY_LIST = OSINT_GRAPH_MAX_ENTITIES
MAX_RELATION_LIST = OSINT_GRAPH_MAX_RELATIONS
MAX_PROVENANCE_DEPTH = OSINT_GRAPH_MAX_PROVENANCE_DEPTH
MAX_TEXT_LENGTH = OSINT_GRAPH_MAX_TEXT_LENGTH

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
    """Raised when graph input violates the bounded OSINT contract."""


def _redact_text(value, limit=MAX_TEXT_LENGTH):
    text = " ".join(str(value or "").split())[:limit]
    text = _SENSITIVE_RE.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
    text = _BEARER_RE.sub("Bearer [REDACTED]", text)
    text = _JWT_RE.sub("[REDACTED_JWT]", text)
    return text[:limit]


def _safe_value(value, depth=0):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _redact_text(value)
    if depth >= MAX_PROVENANCE_DEPTH:
        raise OsintGraphError("OSINT metadata exceeds the supported nesting depth")
    if isinstance(value, list):
        if len(value) > OSINT_GRAPH_MAX_NESTED_LIST:
            raise OsintGraphError(f"OSINT metadata list exceeds {OSINT_GRAPH_MAX_NESTED_LIST} items")
        return [_safe_value(item, depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > OSINT_GRAPH_MAX_OBJECT_KEYS:
            raise OsintGraphError(f"OSINT metadata object exceeds {OSINT_GRAPH_MAX_OBJECT_KEYS} keys")
        result = {}
        for key, item in value.items():
            clean_key = _redact_text(key, 80)
            if not clean_key:
                raise OsintGraphError("OSINT metadata contains an empty key")
            result[clean_key] = _safe_value(item, depth + 1)
        return result
    raise OsintGraphError("OSINT metadata must contain JSON-compatible values")


def normalize_metadata(value, field_name="metadata", max_keys=MAX_GRAPH_METADATA_KEYS):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise OsintGraphError(f"{field_name} must be an object")
    if len(value) > max_keys:
        raise OsintGraphError(f"{field_name} exceeds the {max_keys}-key limit")
    return _safe_value(value)


def parse_observed_at(value, field_name="observed_at"):
    if value in (None, ""):
        return timezone.now()
    if not isinstance(value, str) or len(value) > 80:
        raise OsintGraphError(f"{field_name} must be an ISO-8601 timestamp")
    parsed = parse_datetime(value)
    if not parsed:
        raise OsintGraphError(f"{field_name} must be an ISO-8601 timestamp")
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone=datetime_timezone.utc)
    return parsed


def _normalize_hostname(value):
    raw = str(value or "").strip().lower().rstrip(".")
    if not raw or len(raw) > 253 or any(ord(character) < 33 for character in raw):
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
        or len(label) > 63
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
    if not raw or len(raw) > MAX_ENTITY_IDENTITY_LENGTH or any(ord(character) < 32 for character in raw):
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
    return normalize_metadata(merged, "metadata", max_keys=MAX_ENTITY_PROPERTIES_KEYS)


def _upsert_entity(graph, item, default_observed_at):
    if not isinstance(item, dict):
        raise OsintGraphError("each OSINT entity must be an object")
    entity_type = str(item.get("type") or item.get("entity_type") or "").strip().lower()
    identity_input = item.get("identity")
    identity, display_value = normalize_entity_identity(entity_type, identity_input)
    observed_at = parse_observed_at(item.get("observed_at"), "entity.observed_at") if item.get("observed_at") else default_observed_at
    properties = normalize_metadata(item.get("properties"), "entity.properties", MAX_ENTITY_PROPERTIES_KEYS)
    provenance = normalize_metadata(item.get("provenance"), "entity.provenance", MAX_ENTITY_PROPERTIES_KEYS)
    risk_score = item.get("risk_score", 0)
    if isinstance(risk_score, bool) or not isinstance(risk_score, int) or not 0 <= risk_score <= 100:
        raise OsintGraphError("entity risk_score must be an integer from 0 to 100")
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
    if not source_entity or not target_entity:
        raise OsintGraphError("OSINT relation endpoints must reference entities in the graph")
    observed_at = parse_observed_at(item.get("observed_at"), "relation.observed_at") if item.get("observed_at") else default_observed_at
    properties = normalize_metadata(item.get("properties"), "relation.properties", MAX_ENTITY_PROPERTIES_KEYS)
    provenance = normalize_metadata(item.get("provenance"), "relation.provenance", MAX_ENTITY_PROPERTIES_KEYS)
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
        source=_redact_text(source or "manual", 80),
        name=_redact_text(name or "OSINT graph", 160),
        metadata=normalize_metadata(metadata, "graph.metadata", MAX_GRAPH_METADATA_KEYS),
        status="current",
    )


@transaction.atomic
def upsert_graph(graph, payload):
    if graph.project_id is None:
        raise OsintGraphError("graph project is required")
    if not isinstance(payload, dict):
        raise OsintGraphError("graph upsert payload must be an object")
    entities = payload.get("entities", [])
    relations = payload.get("relations", [])
    if not isinstance(entities, list) or len(entities) > MAX_ENTITY_LIST:
        raise OsintGraphError(f"entities must be a list of at most {MAX_ENTITY_LIST} items")
    if not isinstance(relations, list) or len(relations) > MAX_RELATION_LIST:
        raise OsintGraphError(f"relations must be a list of at most {MAX_RELATION_LIST} items")
    default_observed_at = parse_observed_at(payload.get("observed_at"))
    entity_cache = {}
    for item in entities:
        entity = _upsert_entity(graph, item, default_observed_at)
        entity_cache[(entity.entity_type, entity.identity)] = entity
    for item in relations:
        _upsert_relation(graph, item, default_observed_at, entity_cache)
    graph.metadata = _merge_metadata(graph.metadata, normalize_metadata(payload.get("metadata"), "graph.metadata", MAX_GRAPH_METADATA_KEYS))
    graph.save(update_fields=["metadata", "updated_at"])
    return {
        "entities": OsintEntity.objects.filter(graph=graph).count(),
        "relations": OsintRelation.objects.filter(graph=graph).count(),
    }


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
