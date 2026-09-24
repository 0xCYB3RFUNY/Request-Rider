"""Automatic Project knowledge-base ingestion for durable HTTP evidence."""

import re
from urllib.parse import parse_qsl, urlsplit

from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import Project, ProjectSecret, TrafficRecord


_TECH_HEADERS = {
    "server": "server",
    "x-powered-by": "powered_by",
    "via": "via",
}
_SECRET_HEADER_NAMES = {
    "authorization": "api_key",
    "x-api-key": "api_key",
    "x-api-token": "api_key",
    "cookie": "cookie",
    "set-cookie": "cookie",
}
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


def _header_value(headers, name):
    for key, value in (headers or {}).items():
        if str(key).lower() == name:
            return str(value or "")
    return ""


def _remember_secret_reference(project, secret_type, key_name, source_url):
    if not source_url:
        return
    ProjectSecret.objects.get_or_create(
        project=project,
        secret_type=secret_type,
        key_name=key_name[:120],
        source_url=source_url[:2048],
        defaults={"value_ref": ""},
    )


@receiver(post_save, sender=TrafficRecord)
def ingest_traffic_record(sender, instance, created, **kwargs):
    if not created or not instance.project_id:
        return
    project = instance.project
    query = urlsplit(instance.url).query
    params = [key for key, _ in parse_qsl(query, keep_blank_values=True)]
    project.register_endpoint(instance.url, instance.method, instance.status_code, params)
    tech_stack = dict(project.tech_stack or {})
    for header_name, tech_key in _TECH_HEADERS.items():
        value = _header_value(instance.response_headers, header_name)
        if value:
            tech_stack.setdefault(tech_key, [])
            values = tech_stack[tech_key] if isinstance(tech_stack[tech_key], list) else [tech_stack[tech_key]]
            if value not in values:
                values.append(value)
            tech_stack[tech_key] = values[-32:]
    if tech_stack != (project.tech_stack or {}):
        Project.objects.filter(id=project.id).update(tech_stack=tech_stack)
    headers = {str(key).lower(): value for key, value in (instance.request_headers or {}).items()}
    headers.update({str(key).lower(): value for key, value in (instance.response_headers or {}).items()})
    for header_name, secret_type in _SECRET_HEADER_NAMES.items():
        value = str(headers.get(header_name) or "")
        if value:
            key_name = "Authorization" if header_name == "authorization" else header_name
            _remember_secret_reference(project, secret_type, key_name, instance.url)
    if _JWT_RE.search(" ".join(str(value) for value in headers.values())):
        _remember_secret_reference(project, "jwt", "JWT token", instance.url)
