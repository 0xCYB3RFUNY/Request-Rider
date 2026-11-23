"""Tool schemas and handlers for agent continuity: memory and verification.

Registered into the existing tool registry from `agent_tools.py`; no parallel
registry is created. All values pass through the existing `execute_agent_tool`
error boundary, and every write names its source step.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from . import agent_memory as memory
from . import agent_verification as verification

logger = logging.getLogger(__name__)

SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "memory_remember",
            "description": "Зберегти факт/урок поточного проєкту в постійну пам'ять агента між запусками.",
            "parameters": {
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "Короткий стабільний ключ факту."},
                    "value": {"type": "string", "description": "Повне значення факту без маскування."},
                    "kind": {"type": "string", "description": "fact | correction | preference | lesson | failure"},
                    "verified": {"type": "boolean", "description": "Чи підтверджено факт доказом у цьому запуску."},
                    "global_scope": {"type": "boolean", "description": "Зберегти як глобальний факт, а не факт проєкту."},
                },
                "required": ["key", "value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "memory_recall",
            "description": "ОтриматиRelevant факти з пам'яті проєкту для поточного запиту.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Що шукати у збережених фактах."},
                    "limit": {"type": "integer", "description": "Максимальна кількість фактів."},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "memory_propose_promotions",
            "description": "Запропонувати підвищення рівня фактів за повторюваністю. Не змінює рівні — лише пропонує.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "memory_adopt_promotion",
            "description": "Явно підтвердити підвищення рівня факту від імені оператора.",
            "parameters": {
                "type": "object",
                "properties": {
                    "atom_id": {"type": "integer"},
                    "operator": {"type": "string", "description": "Ім'я оператора, який підтверджує."},
                },
                "required": ["atom_id", "operator"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "memory_forget",
            "description": "Видалити один факт з пам'яті поточного проєкту за ключем.",
            "parameters": {
                "type": "object",
                "properties": {"key": {"type": "string"}},
                "required": ["key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_verify_start",
            "description": "Гейт 1: записати базову (незмінену) відповідь для знахідки.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_key": {"type": "string"},
                    "title": {"type": "string"},
                    "baseline": {"type": "object", "description": "Спостереження базової відповіді."},
                },
                "required": ["finding_key", "baseline"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_verify_attack",
            "description": "Гейт 2: записати відповідь на атаку після baseline.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_key": {"type": "string"},
                    "attack": {"type": "object", "description": "Спостереження відповіді на атаку."},
                },
                "required": ["finding_key", "attack"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_verify_conclude",
            "description": "Гейт 3: назвати різницю і підтвердити/спростувати знахідку.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_key": {"type": "string"},
                    "diff": {"type": "object", "description": "changed: true та what: опис різниці."},
                    "decision": {"type": "string", "description": "confirmed | refuted | порожньо (автовирішення за diff)."},
                    "evidence": {"type": "object"},
                    "verified_by": {"type": "string"},
                    "note": {"type": "string"},
                },
                "required": ["finding_key", "diff"],
            },
        },
    },
]


def _project(context):
    if not isinstance(context, dict):
        return None
    return context.get("active_project")


def _session(context) -> str:
    if not isinstance(context, dict):
        return "in-app-agent"
    swarm = context.get("swarm") or {}
    return str(
        swarm.get("worker_id")
        or context.get("agent_session_id")
        or "in-app-agent"
    )


def _citation(context, tool_name: str) -> str:
    return f"{_session(context)}:{tool_name}"


def tool_memory_remember(arguments, context=None):
    try:
        atom = memory.remember(
            project=_project(context),
            key=str(arguments.get("key") or ""),
            value=str(arguments.get("value") or ""),
            citation=_citation(context, "memory_remember"),
            source_session=_session(context),
            kind=str(arguments.get("kind") or "fact"),
            verified=arguments.get("verified") is True,
            global_scope=arguments.get("global_scope") is True,
        )
        return {"status": "success", "atom": atom}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def tool_memory_recall(arguments, context=None):
    try:
        atoms = memory.recall(
            project=_project(context),
            query=str(arguments.get("query") or ""),
            limit=int(arguments.get("limit") or 12),
        )
        return {"status": "success", "count": len(atoms), "atoms": atoms}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def tool_memory_propose_promotions(arguments, context=None):
    try:
        proposals = memory.propose_promotions(project=_project(context))
        return {"status": "success", "count": len(proposals), "proposals": proposals}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def tool_memory_adopt_promotion(arguments, context=None):
    try:
        atom = memory.adopt_promotion(
            atom_id=int(arguments.get("atom_id") or 0),
            operator=str(arguments.get("operator") or ""),
        )
        return {"status": "success", "atom": atom}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def tool_memory_forget(arguments, context=None):
    try:
        removed = memory.forget(
            project=_project(context), key=str(arguments.get("key") or "")
        )
        return {"status": "success", "removed": removed}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def tool_find_verify_start(arguments, context=None):
    try:
        row = verification.start_verification(
            project=_project(context),
            finding_key=str(arguments.get("finding_key") or ""),
            title=str(arguments.get("title") or ""),
            baseline=arguments.get("baseline") if isinstance(arguments.get("baseline"), dict) else None,
        )
        return {"status": "success", "verification": row}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def tool_find_verify_attack(arguments, context=None):
    try:
        row = verification.record_attack(
            project=_project(context),
            finding_key=str(arguments.get("finding_key") or ""),
            attack=arguments.get("attack") if isinstance(arguments.get("attack"), dict) else None,
        )
        return {"status": "success", "verification": row}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


def tool_find_verify_conclude(arguments, context=None):
    try:
        row = verification.conclude_verification(
            project=_project(context),
            finding_key=str(arguments.get("finding_key") or ""),
            diff=arguments.get("diff") if isinstance(arguments.get("diff"), dict) else None,
            decision=str(arguments.get("decision") or ""),
            evidence=arguments.get("evidence") if isinstance(arguments.get("evidence"), dict) else None,
            verified_by=str(arguments.get("verified_by") or ""),
            note=str(arguments.get("note") or ""),
        )
        return {"status": "success", "verification": row}
    except Exception as exc:
        return {"status": "error", "message": str(exc)}


HANDLERS = {
    "memory_remember": tool_memory_remember,
    "memory_recall": tool_memory_recall,
    "memory_propose_promotions": tool_memory_propose_promotions,
    "memory_adopt_promotion": tool_memory_adopt_promotion,
    "memory_forget": tool_memory_forget,
    "find_verify_start": tool_find_verify_start,
    "find_verify_attack": tool_find_verify_attack,
    "find_verify_conclude": tool_find_verify_conclude,
}


def register_into(module) -> None:
    """Register tools into the single existing registry."""
    definitions = getattr(module, "TOOL_DEFINITIONS", None)
    handlers = getattr(module, "TOOL_HANDLERS", None)
    if definitions is None or handlers is None:
        raise RuntimeError("agent_tools registry is not available")
    existing = {item.get("function", {}).get("name") for item in definitions}
    for schema in SCHEMAS:
        name = schema["function"]["name"]
        if name not in existing:
            definitions.append(schema)
    handlers.update(HANDLERS)
