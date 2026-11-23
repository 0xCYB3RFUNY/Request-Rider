"""Persistent, project-scoped memory for the in-app AI agent.

Design follows the four-tier agent-memory discipline (AGENTS.md §3: skills
concretise but never override the repository contract):

* L1 — candidate atom, recalled only on relevance;
* L2 — project context, injected on every run of that project;
* L3 — stable cross-project fact, injected on every run.

Promotion is earned by recurrence across distinct sessions and days and is
**proposed, never applied**. Only an explicit operator action (`adopt_promotion`)
writes the final tier. Every atom keeps a back-pointer to the step that produced
it, and a contested claim is injected with its conflict tag rather than silently
overwriting the incumbent.

AGENTS.md §5.6 requires secret values to appear whole in the application.
Therefore the sensitivity filter *detects and flags* (`redacted=True`) without
altering the stored value; a flagged atom is quarantined from promotion. No
value is masked, truncated or replaced by a fingerprint.
"""

from __future__ import annotations

import hashlib
import os
import re
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Iterable, List, Optional

from django.db import transaction
from django.utils import timezone

from .models import AgentMemoryAtom, AgentRunUsage


SENSITIVE_PATTERNS = (
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),  # JWT
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),  # AWS access key id
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"),  # GitHub token
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),  # OpenAI-style key
    re.compile(r"(?i)\bauthorization\s*[:=]\s*bearer\s+[^\s,'\"}]{8,}"),
    re.compile(r"(?i)\b(?:api[_-]?key|password|secret)\s*[:=]\s*[^\s,'\"}]{8,}"),
)

_TOKEN_RE = re.compile(r"[A-Za-z0-9_А-Яа-яІіЇїЄєҐґ]{3,}")


def scope_for_project(project: Any) -> str:
    """Return the injection scope string for a project (or global)."""
    if project is None:
        return "global"
    project_id = getattr(project, "id", None)
    if project_id is None:
        return "global"
    return f"project:{project_id}"


def normalize_key(text: str) -> str:
    """Stable, bounded key for an atom; long text is hashed, never truncated lossy."""
    normalized = " ".join(str(text or "").split()).lower()
    if not normalized:
        raise ValueError("memory key is required")
    if len(normalized) > 180:
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
        return f"{normalized[:140]}#{digest}"
    return normalized


def detect_sensitive(value: str) -> bool:
    """Flag sensitive-looking content without changing it (AGENTS.md §5.6)."""
    text = str(value or "")
    return any(pattern.search(text) for pattern in SENSITIVE_PATTERNS)


def _today() -> Any:
    return timezone.localdate()


def remember(
    *,
    project: Any = None,
    key: str,
    value: str,
    citation: str,
    source_session: str = "",
    kind: str = "fact",
    verified: bool = False,
    global_scope: bool = False,
) -> Dict[str, Any]:
    """Record (or reinforce) one atom. Repeated claims earn promotion; new
    contradictory claims are recorded as contested and never overwrite the
    incumbent silently.

    `citation` is mandatory: a memory line without a source is a guess.
    """
    key = normalize_key(key)
    value = str(value or "").strip()
    citation = str(citation or "").strip()
    if not value:
        raise ValueError("memory value is required")
    if not citation:
        raise ValueError("memory citation is required")

    scope = "global" if global_scope else scope_for_project(project)
    session = str(source_session or "").strip() or "unattributed"
    today = _today()
    sensitive = detect_sensitive(value)

    with transaction.atomic():
        atom = (
            AgentMemoryAtom.objects.select_for_update()
            .filter(scope=scope, scope_key=key)
            .first()
        )
        if atom is None:
            atom = AgentMemoryAtom.objects.create(
                scope=scope,
                scope_key=key,
                value=value,
                kind=str(kind or "fact"),
                source_citation=citation,
                source_session=session,
                first_seen_on=today,
                redacted=sensitive,
                verified=bool(verified),
            )
            return atom.to_dict()

        if atom.value.strip() != value and not atom.contested:
            # Both directions are preserved: the incumbent stays authoritative,
            # the new claim is visible as a conflict for a human to resolve.
            atom.contested = True
            atom.contested_note = (
                (atom.contested_note + "\n" if atom.contested_note else "")
                + f"[{session}] {value[:500]}"
            ).strip()
        elif atom.value.strip() != value:
            atom.contested_note = (
                (atom.contested_note + "\n" if atom.contested_note else "")
                + f"[{session}] {value[:500]}"
            ).strip()

        atom.occurrences += 1
        if session not in (atom.source_session or "").split("|"):
            atom.distinct_sessions += 1
            atom.source_session = "|".join(
                part for part in (atom.source_session or "").split("|") if part
            ) + (f"|{session}" if atom.source_session else session)
        previous_day = atom.updated_at.date() if atom.updated_at else atom.first_seen_on
        if today != previous_day and today != atom.first_seen_on:
            atom.distinct_days += 1
        atom.redacted = atom.redacted or sensitive
        atom.verified = atom.verified or bool(verified)
        atom.last_seen_at = timezone.now()
        atom.save(
            update_fields=[
                "occurrences",
                "distinct_sessions",
                "distinct_days",
                "source_session",
                "contested",
                "contested_note",
                "redacted",
                "verified",
                "last_seen_at",
                "updated_at",
            ]
        )
        return atom.to_dict()


def _score(atom: AgentMemoryAtom, query_tokens: set, now: Any) -> float:
    text_tokens = set(_TOKEN_RE.findall(f"{atom.scope_key} {atom.value}"))
    overlap = len(query_tokens & text_tokens)
    score = float(overlap) * 2.0
    score += {"L3": 3.0, "L2": 2.0, "L1": 0.0}.get(atom.tier, 0.0)
    age_days = max(0, (now - atom.last_seen_at).days)
    score += max(0.0, 2.0 - age_days / 30.0)
    if atom.verified:
        score += 0.5
    return score


def recall(
    *,
    project: Any = None,
    query: str = "",
    limit: int = 12,
    include_global: bool = True,
) -> List[Dict[str, Any]]:
    """Return injected memory atoms.

    L2/L3 are always injected (that is what makes them a different tier); L1 is
    injected only when relevant to the query. Contested atoms are returned with
    their conflict tag — hiding the disagreement is worse than showing it.
    """
    scope = scope_for_project(project)
    scopes = [scope]
    if include_global and scope != "global":
        scopes.append("global")

    atoms = list(
        AgentMemoryAtom.objects.filter(scope__in=scopes).order_by("-last_seen_at", "-id")
    )
    query_tokens = set(_TOKEN_RE.findall(str(query or "").lower()))
    now = timezone.now()
    ranked = sorted(atoms, key=lambda atom: _score(atom, query_tokens, now), reverse=True)

    selected: List[AgentMemoryAtom] = []
    # Always-injected tiers first.
    for atom in ranked:
        if atom.tier in {"L2", "L3"}:
            selected.append(atom)
    # Relevant candidates fill the remaining budget.
    for atom in ranked:
        if atom.tier == "L1" and query_tokens and (set(_TOKEN_RE.findall(atom.scope_key)) & query_tokens):
            if atom not in selected:
                selected.append(atom)
        if len(selected) >= max(0, limit):
            break

    return [atom.to_dict() for atom in selected[: max(0, limit)]]


def format_memory_context(atoms: Iterable[Dict[str, Any]], language: str = "uk") -> str:
    """Render recalled atoms as a compact section for the agent prompt."""
    items = list(atoms)
    if not items:
        return ""
    header = (
        "ПАМ'ЯТЬ ПРОЄКТУ (перевірені факти попередніх запусків):"
        if language == "uk"
        else "PROJECT MEMORY (facts recorded in previous runs):"
    )
    lines = [header]
    for atom in items:
        flags = []
        if atom.get("contested"):
            flags.append("Є ПРОТИРІЧЧЯ / CONTESTED" if language == "uk" else "CONTESTED")
        if atom.get("redacted"):
            flags.append("МІСТИТЬ СЕНСИТИВНІ ДАНІ / SENSITIVE" if language == "uk" else "SENSITIVE")
        flag_text = f" [{' | '.join(flags)}]" if flags else ""
        lines.append(
            f"- [{atom.get('tier')}] {atom.get('scope_key')}: {atom.get('value')}"
            f" (джерело: {atom.get('source_citation')}){flag_text}"
        )
    return "\n".join(lines)


def propose_promotions(*, project: Any = None) -> List[Dict[str, Any]]:
    """Compute promotion candidates and record proposals. Never changes tier."""
    scope = scope_for_project(project)
    scopes = [scope]
    if scope != "global":
        scopes.append("global")
    now = timezone.now()
    proposed: List[Dict[str, Any]] = []

    for atom in AgentMemoryAtom.objects.filter(scope__in=scopes):
        if atom.contested or atom.redacted or atom.proposed_tier:
            continue
        target = ""
        reason = ""
        if atom.tier == "L1":
            if atom.verified:
                target, reason = "L2", "verified claim: day/session rule exempt"
            elif atom.distinct_sessions >= 3 and atom.distinct_days >= 2:
                target, reason = (
                    "L2",
                    f"recurred in {atom.distinct_sessions} sessions across {atom.distinct_days} days",
                )
        elif atom.tier == "L2" and atom.scope == "global":
            age = now - atom.created_at
            if age >= timedelta(days=30) and atom.occurrences >= 2:
                target, reason = (
                    "L3",
                    f"global atom aged {age.days} days with {atom.occurrences} observations",
                )
        if not target:
            continue
        atom.proposed_tier = target
        atom.proposed_reason = reason
        atom.save(update_fields=["proposed_tier", "proposed_reason", "updated_at"])
        proposed.append(
            {
                "id": atom.id,
                "scope_key": atom.scope_key,
                "from": atom.tier,
                "to": target,
                "reason": reason,
            }
        )
    return proposed


def adopt_promotion(*, atom_id: int, operator: str) -> Dict[str, Any]:
    """Operator-confirmed promotion. The only write path to a higher tier."""
    operator = str(operator or "").strip()
    if not operator:
        raise ValueError("operator name is required to adopt a promotion")
    atom = AgentMemoryAtom.objects.filter(id=atom_id).first()
    if atom is None:
        raise ValueError("memory atom not found")
    if not atom.proposed_tier:
        raise ValueError("no promotion proposed for this atom")
    if atom.contested:
        raise ValueError("contested atom cannot be promoted before the conflict is resolved")
    atom.tier = atom.proposed_tier
    atom.promoted_at = timezone.now()
    atom.proposed_tier = ""
    atom.proposed_reason = ""
    atom.source_citation = f"{atom.source_citation} | adopted-by:{operator}"
    atom.save(
        update_fields=[
            "tier",
            "promoted_at",
            "proposed_tier",
            "proposed_reason",
            "source_citation",
            "updated_at",
        ]
    )
    return atom.to_dict()


def forget(*, project: Any = None, key: str) -> bool:
    """Explicit operator removal of one atom from the active scope."""
    key = normalize_key(key)
    deleted, _ = AgentMemoryAtom.objects.filter(
        scope=scope_for_project(project), scope_key=key
    ).delete()
    return deleted > 0


def _decimal_env(name: str, default: str = "0") -> Decimal:
    raw = os.environ.get(name, default) or default
    try:
        return Decimal(str(raw))
    except (InvalidOperation, ValueError):
        return Decimal("0")


def record_usage(
    *,
    run_id: str,
    project: Any = None,
    provider: str = "",
    model: str = "",
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    steps: int = 0,
    completed: bool = False,
    input_rate_per_million: Optional[Decimal] = None,
    output_rate_per_million: Optional[Decimal] = None,
) -> Dict[str, Any]:
    """Persist a visible token/cost ledger row. No cap is applied anywhere."""
    in_rate = (
        input_rate_per_million
        if input_rate_per_million is not None
        else _decimal_env("AGENT_LLM_INPUT_RATE_PER_MILLION")
    )
    out_rate = (
        output_rate_per_million
        if output_rate_per_million is not None
        else _decimal_env("AGENT_LLM_OUTPUT_RATE_PER_MILLION")
    )
    prompt_tokens = max(0, int(prompt_tokens or 0))
    completion_tokens = max(0, int(completion_tokens or 0))
    cost = (Decimal(prompt_tokens) * in_rate + Decimal(completion_tokens) * out_rate) / Decimal(1_000_000)
    row, _ = AgentRunUsage.objects.update_or_create(
        run_id=str(run_id),
        defaults={
            "project": project if getattr(project, "id", None) else None,
            "provider": str(provider or ""),
            "model": str(model or ""),
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
            "input_rate_per_million": in_rate,
            "output_rate_per_million": out_rate,
            "estimated_cost_usd": cost,
            "steps": max(0, int(steps or 0)),
            "completed": bool(completed),
        },
    )
    return row.to_dict()
