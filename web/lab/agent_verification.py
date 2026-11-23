"""Three-gate finding verification for the in-app AI agent.

A finding is not confirmed because a tool returned a string. The three
observations are recorded explicitly:

    suspected -> baseline -> attack -> confirmed | refuted

`confirmed` requires a named response difference AND both observations in the
evidence. A missing field is a reason to stay `suspected`, never a reason to
guess a positive verdict. This mirrors the scanner contract where
`matcher-status: false` is discarded instead of reported as a vulnerability.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from django.utils import timezone

from .models import FindingVerification


ALLOWED_TRANSITIONS = {
    "suspected": {"baseline"},
    "baseline": {"attack"},
    "attack": {"confirmed", "refuted"},
    "confirmed": {"baseline"},
    "refuted": {"baseline"},
}


def _scope(project: Any = None) -> str:
    if project is None or getattr(project, "id", None) is None:
        return "global"
    return f"project:{project.id}"


def get_verification(*, project: Any = None, finding_key: str) -> Optional[Dict[str, Any]]:
    row = FindingVerification.objects.filter(
        scope=_scope(project), finding_key=str(finding_key)
    ).first()
    return row.to_dict() if row else None


def list_verifications(
    *, project: Any = None, status: str = "", limit: int = 200
) -> List[Dict[str, Any]]:
    qs = FindingVerification.objects.filter(scope=_scope(project))
    if status:
        qs = qs.filter(status=status)
    return [row.to_dict() for row in qs[: max(0, min(int(limit or 200), 1000))]]


def start_verification(
    *,
    project: Any = None,
    finding_key: str,
    title: str = "",
    baseline: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Gate 1: record the unchanged baseline response."""
    finding_key = str(finding_key or "").strip()
    if not finding_key:
        raise ValueError("finding_key is required")
    baseline = dict(baseline or {})
    if not baseline:
        raise ValueError("baseline observation is required for gate 1")

    row, _ = FindingVerification.objects.update_or_create(
        scope=_scope(project),
        finding_key=finding_key,
        defaults={
            "title": str(title or ""),
            "status": "baseline",
            "baseline": baseline,
            "attack": {},
            "diff": {},
            "evidence": {"baseline_at": timezone.now().isoformat()},
            "note": "",
            "verified_by": "",
        },
    )
    return row.to_dict()


def record_attack(
    *,
    project: Any = None,
    finding_key: str,
    attack: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Gate 2: record the attack response. Requires a baseline first."""
    attack = dict(attack or {})
    if not attack:
        raise ValueError("attack observation is required for gate 2")
    row = FindingVerification.objects.filter(
        scope=_scope(project), finding_key=str(finding_key)
    ).first()
    if row is None:
        raise ValueError("verification not started for this finding")
    if row.status not in ALLOWED_TRANSITIONS or "attack" not in ALLOWED_TRANSITIONS[row.status]:
        raise ValueError(
            f"cannot record attack from status '{row.status}': expected 'baseline'"
        )
    row.attack = attack
    row.status = "attack"
    evidence = dict(row.evidence or {})
    evidence["attack_at"] = timezone.now().isoformat()
    row.evidence = evidence
    row.save(update_fields=["attack", "status", "evidence", "updated_at"])
    return row.to_dict()


def conclude_verification(
    *,
    project: Any = None,
    finding_key: str,
    diff: Optional[Dict[str, Any]] = None,
    decision: str = "",
    evidence: Optional[Dict[str, Any]] = None,
    verified_by: str = "",
    note: str = "",
) -> Dict[str, Any]:
    """Gate 3: name the difference, then confirm or refute.

    `decision` may be 'confirmed' or 'refuted'. When omitted, a diff that
    explicitly says `changed: true` confirms; anything else refutes. A
    'confirmed' verdict without both observations or without a named change is
    rejected rather than silently accepted.
    """
    diff = dict(diff or {})
    row = FindingVerification.objects.filter(
        scope=_scope(project), finding_key=str(finding_key)
    ).first()
    if row is None:
        raise ValueError("verification not started for this finding")
    if row.status != "attack":
        raise ValueError(
            f"cannot conclude from status '{row.status}': expected 'attack'"
        )
    if not row.baseline or not row.attack:
        raise ValueError("both baseline and attack observations are required")

    decision = str(decision or "").strip().lower()
    if decision and decision not in {"confirmed", "refuted"}:
        raise ValueError("decision must be 'confirmed', 'refuted' or empty")
    if not decision:
        decision = "confirmed" if diff.get("changed") is True else "refuted"

    if decision == "confirmed":
        if diff.get("changed") is not True:
            raise ValueError("confirmed verdict requires diff.changed === true")
        if not str(diff.get("what") or "").strip():
            raise ValueError("confirmed verdict requires a named difference (diff.what)")

    merged_evidence = dict(row.evidence or {})
    merged_evidence.update(dict(evidence or {}))
    merged_evidence["concluded_at"] = timezone.now().isoformat()
    row.diff = diff
    row.evidence = merged_evidence
    row.status = decision
    row.verified_by = str(verified_by or "")
    row.note = str(note or "")
    row.save(
        update_fields=["diff", "evidence", "status", "verified_by", "note", "updated_at"]
    )
    return row.to_dict()


def reset_verification(*, project: Any = None, finding_key: str) -> Dict[str, Any]:
    """Re-open a finished verification for a fresh three-gate run."""
    row = FindingVerification.objects.filter(
        scope=_scope(project), finding_key=str(finding_key)
    ).first()
    if row is None:
        raise ValueError("verification not started for this finding")
    row.status = "suspected"
    row.baseline = {}
    row.attack = {}
    row.diff = {}
    row.evidence = {}
    row.verified_by = ""
    row.save(
        update_fields=["status", "baseline", "attack", "diff", "evidence", "verified_by", "updated_at"]
    )
    return row.to_dict()
