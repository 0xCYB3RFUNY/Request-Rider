#!/usr/bin/env python3
"""
Request-Rider Agent Harness (rr_agent_harness.py)
Імплементація специфікації agent-harness-construction:
- Чіткий Action Space для автономних агентів.
- Детерміновані структуровані Observations (status, summary, next_actions, artifacts).
- Error Recovery контракт (root_cause_hint, safe_retry_instruction, explicit_stop_condition).
- Scope Compliance (перевірка git diff проти дозволених файлів).
- Guard-перевірки цілісності проєкту.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, List, Optional


@dataclass
class Observation:
    status: str  # "success" | "warning" | "error"
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    root_cause_hint: Optional[str] = None
    safe_retry_instruction: Optional[str] = None
    explicit_stop_condition: Optional[str] = None
    next_actions: List[str] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


CANONICAL_VERDICTS = {"супадає", "улучшено", "не перенесено"}
FORBIDDEN_VERDICT_TYPOS = {"улушшено", "совпадает", "не_перенесено", "покращено"}


class AgentHarness:
    def __init__(self, repo_root: Optional[Path] = None):
        self.repo_root = (repo_root or Path(__file__).resolve().parent.parent).resolve()

    def check_scope(self, allowed_files: List[str]) -> Observation:
        """Перевіряє, чи не змінені файли поза зафіксованим планом."""
        norm_allowed = {
            str(Path(f).resolve().relative_to(self.repo_root))
            if Path(f).is_absolute()
            else str(Path(f))
            for f in allowed_files
        }

        try:
            res = subprocess.run(
                ["git", "-c", "core.quotePath=false", "status", "--porcelain"],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except Exception as e:
            return Observation(
                status="error",
                summary=f"Не вдалося виконати git status: {e}",
                root_cause_hint="git не доступний або помилка виконання команди",
                safe_retry_instruction="Перевірте наявність git репозиторію",
                explicit_stop_condition="Зупиніться, якщо .git каталог пошкоджений",
            )

        changed_files: list[str] = []
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                changed_files.append(parts[1].strip('"'))

        disallowed = [f for f in changed_files if f not in norm_allowed]

        if disallowed:
            return Observation(
                status="error",
                summary=f"Виявлено {len(disallowed)} несанкціонованих змін поза планом",
                details={
                    "allowed": sorted(list(norm_allowed)),
                    "changed": changed_files,
                    "disallowed": disallowed,
                },
                root_cause_hint=f"Файли {disallowed} змінено без відповідного пункту в плані",
                safe_retry_instruction="Оновіть план із дозволом або скасуйте зміни у незатверджених файлах",
                explicit_stop_condition="AGENTS.md забороняє завершувати задачу з несанкціонованими змінами",
                next_actions=[
                    f"git checkout -- {f}" for f in disallowed[:3]
                ],
                artifacts=["file://" + str(self.repo_root / "AGENTS.md")],
            )

        return Observation(
            status="success",
            summary=f"Усі змінені файли ({len(changed_files)}) відповідають дозволеному списку",
            details={
                "allowed": sorted(list(norm_allowed)),
                "changed": changed_files,
            },
            next_actions=["Продовжити перевірки тестів або зафіксувати результат"],
        )

    def check_verdict_guards(self) -> Observation:
        """Перевіряє коректність написання вердиктів у файлах звірення (reconciliation)."""
        reconciliation_dirs = [
            self.repo_root / "engine" / "reconciliation",
            self.repo_root / "Прочее",
        ]

        typo_findings: list[dict[str, Any]] = []

        for r_dir in reconciliation_dirs:
            if not r_dir.exists():
                continue
            for md_file in r_dir.glob("**/*.md"):
                try:
                    content = md_file.read_text(encoding="utf-8")
                except Exception:
                    continue

                for line_no, line in enumerate(content.splitlines(), start=1):
                    for typo in FORBIDDEN_VERDICT_TYPOS:
                        if typo in line:
                            typo_findings.append({
                                "file": str(md_file.relative_to(self.repo_root)),
                                "line": line_no,
                                "typo": typo,
                                "line_content": line.strip(),
                            })

        if typo_findings:
            return Observation(
                status="error",
                summary=f"Виявлено {len(typo_findings)} некоректних написань вердиктів",
                details={"findings": typo_findings},
                root_cause_hint="Використано помилковий варіант замість канону (наприклад 'улушшено' замість 'улучшено')",
                safe_retry_instruction="Замініть помилкові вердикти на канонічні: 'улучшено', 'супадає', 'не перенесено'",
                explicit_stop_condition="Тести TestNoRegistryMisspellsAVerdict впадуть при наявності таких слів",
                next_actions=[
                    f"Виправити вердикт у {f['file']}:{f['line']}"
                    for f in typo_findings[:3]
                ],
            )

        return Observation(
            status="success",
            summary="Усі реєстри звірення містять виключно канонічні вердикти",
            details={"checked_dirs": [str(d) for d in reconciliation_dirs if d.exists()]},
            next_actions=["Запустити наступний етап тестів"],
        )

    def run_tests(self, suite: str = "guards", timeout_sec: int = 60) -> Observation:
        """Запускає ізольовані тести з тайм-аутом та structured observation."""
        cmd: list[str] = []
        cwd = self.repo_root

        if suite == "guards":
            cmd = ["python3", "-m", "unittest", "discover", "-s", "tools", "-p", "test_*.py"]
        elif suite == "tools":
            cmd = ["python3", "-m", "unittest", "discover", "-s", "tools", "-p", "test_*.py"]
        elif suite == "engine_reconciliation":
            cmd = ["go", "test", "-v", "./engine/reconciliation_summary_test.go"]
        elif suite == "go_vet":
            cmd = ["go", "vet", "./engine/..."]
        else:
            return Observation(
                status="error",
                summary=f"Невідомий тестовий набір: {suite}",
                root_cause_hint=f"suite '{suite}' не підтримується harness",
                safe_retry_instruction="Оберіть один із: guards, tools, engine_reconciliation, go_vet",
            )

        try:
            proc = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
        except subprocess.TimeoutExpired:
            return Observation(
                status="error",
                summary=f"Тестовий набір '{suite}' перевищив ліміт часу ({timeout_sec}s)",
                root_cause_hint="Тест завис або очікує мережеву взаємодію без таймауту",
                safe_retry_instruction="Перевірте блокуючі сокети чи відсутність моків у тестах",
                explicit_stop_condition="Зупиніться для усунення блокування у коді тесту",
            )
        except Exception as e:
            return Observation(
                status="error",
                summary=f"Помилка запуску команди {' '.join(cmd)}: {e}",
                root_cause_hint=str(e),
            )

        if proc.returncode != 0:
            lines = (proc.stdout + "\n" + proc.stderr).splitlines()
            error_tail = "\n".join(lines[-15:])
            return Observation(
                status="error",
                summary=f"Тестовий набір '{suite}' завершився з кодом помилки {proc.returncode}",
                details={"cmd": cmd, "stdout_tail": error_tail},
                root_cause_hint=lines[-1] if lines else "Невідома помилка виконання",
                safe_retry_instruction=f"Запустіть локально '{' '.join(cmd)}' для аналізу",
                explicit_stop_condition="Виправте помилки перед повідомленням про успіх",
                next_actions=["Проаналізувати стек помилки та виправити відповідний файл"],
            )

        return Observation(
            status="success",
            summary=f"Тестовий набір '{suite}' виконано успішно (returncode 0)",
            details={"cmd": cmd},
            next_actions=["Продовжувати за планом"],
        )


def main():
    parser = argparse.ArgumentParser(description="Request-Rider Agent Harness CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # check-scope
    p_scope = subparsers.add_parser("check-scope")
    p_scope.add_argument("--allowed", nargs="+", default=[], help="Список дозволених файлів")
    p_scope.add_argument("--json", action="store_true", help="Вивести у форматі JSON")

    # check-guards
    p_guards = subparsers.add_parser("check-guards")
    p_guards.add_argument("--json", action="store_true", help="Вивести у форматі JSON")

    # run-tests
    p_test = subparsers.add_parser("run-tests")
    p_test.add_argument("--suite", default="guards", help="Набір тестів: guards, tools, go_vet")
    p_test.add_argument("--timeout", type=int, default=60, help="Таймаут у секундах")
    p_test.add_argument("--json", action="store_true", help="Вивести у форматі JSON")

    args = parser.parse_args()
    harness = AgentHarness()

    obs: Observation
    if args.command == "check-scope":
        obs = harness.check_scope(args.allowed)
    elif args.command == "check-guards":
        obs = harness.check_verdict_guards()
    elif args.command == "run-tests":
        obs = harness.run_tests(suite=args.suite, timeout_sec=args.timeout)
    else:
        sys.exit(1)

    if getattr(args, "json", False):
        print(json.dumps(obs.to_dict(), indent=2, ensure_ascii=False))
    else:
        prefix = "✓" if obs.status == "success" else "✗"
        print(f"[{prefix}] [{obs.status.upper()}] {obs.summary}")
        if obs.root_cause_hint:
            print(f"  Root cause: {obs.root_cause_hint}")
        if obs.safe_retry_instruction:
            print(f"  Retry instruction: {obs.safe_retry_instruction}")
        if obs.next_actions:
            print("  Next actions:")
            for act in obs.next_actions:
                print(f"    - {act}")

    if obs.status == "error":
        sys.exit(1)


if __name__ == "__main__":
    main()
