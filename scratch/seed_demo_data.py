#!/usr/bin/env python3
"""Idempotent demo-data seeder for the live Request-Rider stand.

Fills the dimensions that were empty in the 2026-11-20 snapshot:
  * Workflow / WorkflowRun / WorkflowNodeExecution (Automation workspace)
  * OsintRelation edges for the existing "Passive OSINT observations" graph

Run from the repository root:

    POSTGRES_HOST=127.0.0.1 POSTGRES_PORT=55433 POSTGRES_USER=kali \
      POSTGRES_DB=requestrider web/.venv/bin/python scratch/seed_demo_data.py

The script never deletes evidence and never creates a scope/allowlist/limit.
Re-running it only tops up missing demo rows (get_or_create / explicit markers).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "web"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
os.environ.setdefault("POSTGRES_HOST", "127.0.0.1")
os.environ.setdefault("POSTGRES_PORT", "55433")
os.environ.setdefault("POSTGRES_USER", "kali")
os.environ.setdefault("POSTGRES_DB", "requestrider")

import django  # noqa: E402

django.setup()

from django.utils import timezone  # noqa: E402
from lab.models import (  # noqa: E402
    OsintEntity,
    OsintGraph,
    OsintRelation,
    Project,
    ProjectAuthProfile,
    ProjectHost,
    Workflow,
    WorkflowNodeExecution,
    WorkflowRun,
)


def _node(node_id: str, node_type: str, x: int, y: int, **params):
    return {"id": node_id, "type": node_type, "params": params, "position": {"x": x, "y": y}}


def _edge(source: str, target: str, *, source_handle: str = "main", target_handle: str = "main"):
    return {"source": source, "target": target, "source_handle": source_handle, "target_handle": target_handle}


WORKFLOWS = [
    {
        "name": "Демо · Перевірка HTTP-поверхні",
        "description": "Ручний запуск: Repeater → умова статусу → результат. Демонстрація вузлів, гілок та інспектора.",
        "nodes": [
            _node("trigger", "manual_trigger", 80, 120),
            _node("probe", "repeater", 320, 120, method="GET", url="http://192.168.56.6/", headers={"User-Agent": "RequestRider demo"}),
            _node("gate", "condition", 580, 120, field="status_code", operator="eq", value=200),
            _node("ok", "output", 860, 40, label="Відповідь отримано"),
            _node("note", "set", 860, 220, values={"verdict": "needs-review"}),
        ],
        "connections": [
            _edge("trigger", "probe"),
            _edge("probe", "gate"),
            _edge("gate", "ok", source_handle="true"),
            _edge("gate", "note", source_handle="false"),
        ],
    },
    {
        "name": "Демо · Безперервна OSINT-розвідка",
        "description": "Розклад: Target → OSINT → збереження сутностей у граф проєкту.",
        "nodes": [
            _node("cron", "schedule_trigger", 80, 140, cron="0 6 * * *"),
            _node("map", "target", 320, 140, url="http://192.168.56.6/", max_pages=25, max_depth=2),
            _node("recon", "osint", 580, 140, transform="subdomains"),
            _node("save", "output", 850, 140, label="Граф оновлено"),
        ],
        "connections": [_edge("cron", "map"), _edge("map", "recon"), _edge("recon", "save")],
        "settings": {"timezone": "UTC"},
    },
    {
        "name": "Демо · OAST ланцюжок підтвердження",
        "description": "Ручний запуск: слухач → збір подій → підсумковий звіт.",
        "nodes": [
            _node("start", "manual_trigger", 80, 130),
            _node("listener", "oast_listener", 320, 130, protocol="http"),
            _node("collect", "oast_collect", 570, 130, wait_seconds=20),
            _node("report", "output", 840, 130, label="Proof-of-concept"),
        ],
        "connections": [_edge("start", "listener"), _edge("listener", "collect"), _edge("collect", "report")],
    },
]

RUNS = [
    ("completed", "manual", 0, {"status_code": 200, "bytes": 1421}, "Усі вузли виконано"),
    ("failed", "manual", 1, {"error": "engine timeout"}, "Час очікування движка вичерпано"),
    ("completed", "schedule", 2, {"entities": 21, "relations": 18}, "Граф поповнено"),
    ("paused", "webhook", 2, {"listener_id": "oast-demo-01"}, "Очікує події OAST"),
]


def seed_workflows(project: Project):
    created = []
    for spec in WORKFLOWS:
        wf, was_created = Workflow.objects.get_or_create(
            name=spec["name"],
            defaults={
                "description": spec["description"],
                "project": project,
                "nodes": spec["nodes"],
                "connections": spec["connections"],
                "settings": spec.get("settings", {}),
                "metadata": {"demo_seed": "2026-11-20", "source": "scratch/seed_demo_data.py"},
                "active": False,
            },
        )
        if was_created:
            created.append(f"workflow:{wf.id}")

    workflows = list(Workflow.objects.filter(name__startswith="Демо ·").order_by("id"))
    for idx, (status, mode, wf_idx, output, note) in enumerate(RUNS):
        if wf_idx >= len(workflows):
            continue
        marker = f"demo-run-{idx}"
        run = WorkflowRun.objects.filter(input_data__demo_marker=marker).first()
        if run:
            continue
        now = timezone.now()
        run = WorkflowRun.objects.create(
            workflow=workflows[wf_idx],
            project=project,
            status=status,
            mode=mode,
            trigger_type=mode,
            graph_schema_version=1,
            graph_nodes=workflows[wf_idx].nodes,
            graph_connections=workflows[wf_idx].connections,
            input_data={"demo_marker": marker, "target": "http://192.168.56.6/"},
            output_data=output,
            logs=[
                {"ts": now.isoformat(), "level": "info", "node": "trigger", "message": "Запуск демо-графа"},
                {"ts": now.isoformat(), "level": "info", "node": "probe", "message": note},
                {"ts": now.isoformat(), "level": "info" if status == "completed" else "warn", "node": "output", "message": note},
            ],
            error="" if status == "completed" else note,
            started_at=now,
            finished_at=now if status in ("completed", "failed") else None,
        )
        created.append(f"run:{run.id}")
        for node in workflows[wf_idx].nodes[:3]:
            WorkflowNodeExecution.objects.get_or_create(
                workflow_run=run,
                node_id=node["id"],
                defaults={
                    "status": "completed" if status == "completed" else ("failed" if status == "failed" else "waiting"),
                    "input_data": {},
                    "output_data": {"demo": True},
                },
            )
    return created


RELATION_SPECS = [
    ("resolves_to", "domain", "192.168.56.6", "ip", "192.168.56.6"),
    ("hosted_on", "url", "http://192.168.56.6/", "domain", "192.168.56.6"),
    ("hosted_on", "url", "https://192.168.56.6/", "domain", "192.168.56.6"),
    ("hosted_on", "url", "https://192.168.56.6/robots.txt", "domain", "192.168.56.6"),
    ("hosted_on", "url", "https://192.168.56.6/sitemap.xml", "domain", "192.168.56.6"),
    ("uses_technology", "domain", "192.168.56.6", "technology", "PHP:5.3.2"),
    ("uses_technology", "domain", "192.168.56.6", "technology", "Apache HTTP Server:2.2.14"),
    ("uses_technology", "domain", "192.168.56.6", "technology", "jQuery"),
    ("uses_technology", "domain", "192.168.56.6", "technology", "Ruby on Rails"),
    ("uses_technology", "domain", "192.168.56.6", "technology", "Python:2.6.5"),
    ("uses_technology", "domain", "192.168.56.6", "technology", "Joomla"),
    ("uses_technology", "domain", "192.168.56.6", "technology", "Ubuntu"),
    ("uses_technology", "domain", "192.168.56.6", "technology", "OpenSSL:0.9.8k"),
    ("uses_technology", "domain", "192.168.56.6", "technology", "Perl:5.10.1"),
    ("uses_technology", "domain", "192.168.56.6", "technology", "Web server"),
    ("link", "url", "https://192.168.56.6/robots.txt", "url", "https://192.168.56.6/sitemap.xml"),
    ("link", "url", "http://192.168.56.6/", "url", "https://192.168.56.6/"),
    ("service", "domain", "192.168.56.6", "ip", "192.168.56.6"),
]


def _find_entity(graph, entity_type, prefix):
    return OsintEntity.objects.filter(graph=graph, entity_type=entity_type, identity__startswith=prefix).first()


def seed_relations(project: Project):
    graph = OsintGraph.objects.filter(project=project, name="Passive OSINT observations").first()
    if not graph:
        return []
    created = []
    for rel_type, st, si, tt, ti in RELATION_SPECS:
        src = _find_entity(graph, st, si)
        dst = _find_entity(graph, tt, ti)
        if not src or not dst or src.id == dst.id:
            continue
        _, was_created = OsintRelation.objects.get_or_create(
            graph=graph,
            relation_type=rel_type,
            source_entity=src,
            target_entity=dst,
            defaults={
                "project": project,
                "properties": {"demo_seed": "2026-11-20"},
                "provenance": {"transform": "demo-seed", "confidence": "observed"},
            },
        )
        if was_created:
            created.append(f"relation:{rel_type}:{src.id}->{dst.id}")
    return created


AUTH_PROFILES = [
    ("Анонім (baseline)", "anonymous", {"User-Agent": "RequestRider/anonymous"}, True, True),
    ("Користувач", "user", {"Authorization": "Bearer demo_user_token", "Cookie": "session=demo_user"}, False, True),
    ("Адміністратор", "admin", {"Authorization": "Bearer demo_admin_token", "Cookie": "session=demo_admin"}, False, True),
    ("API-ключ партнера", "api_key", {"X-API-Key": "demo-partner-key-2026"}, False, True),
]


def seed_aux(project: Project):
    created = []
    for name, role, headers, baseline, enabled in AUTH_PROFILES:
        _, was_created = ProjectAuthProfile.objects.get_or_create(
            project=project,
            name=name,
            defaults={
                "role_type": role,
                "headers": headers,
                "is_baseline": baseline,
                "enabled": enabled,
            },
        )
        if was_created:
            created.append(f"auth:{name}")
    hosts = [
        ("mail.ru", "mail.ru", "up", "Linux", "95%", "aa:bb:cc:dd:ee:01", [{"port": 443, "service": "https", "state": "open"}], []),
        ("192.168.56.6", "target.local", "up", "Ubuntu Linux", "98%", "aa:bb:cc:dd:ee:02", [{"port": 80, "service": "http", "state": "open"}, {"port": 443, "service": "https", "state": "open"}], [{"name": "outdated-apache", "severity": "high"}]),
    ]
    for hostname, display, status, os_name, accuracy, mac, services, vulns in hosts:
        ip = hostname if hostname[0].isdigit() else "185.5.136.14"
        _, was_created = ProjectHost.objects.get_or_create(
            project=project,
            ip_address=ip,
            defaults={
                "hostname": display,
                "status": status,
                "os_name": os_name,
                "os_accuracy": accuracy,
                "mac_address": mac,
                "services": services,
                "vulns": vulns,
                "extra_data": {"demo_seed": "2026-11-21"},
            },
        )
        if was_created:
            created.append(f"host:{display}")
    return created


def main():
    project = Project.objects.order_by("id").first()
    if not project:
        raise SystemExit("No Project found — run the application once and create a workspace first.")
    created = seed_workflows(project) + seed_relations(project) + seed_aux(project)
    print(f"project={project.id} name={project.name}")
    print(f"workflows={Workflow.objects.count()} runs={WorkflowRun.objects.count()} relations={OsintRelation.objects.count()}")
    print("created:", ", ".join(created) if created else "nothing (already seeded)")


if __name__ == "__main__":
    main()
