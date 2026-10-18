#!/usr/bin/env python3
"""Request-Rider Agent Harness Runner (CLI Core).

Implements the deterministic Action Space and Observation Contract specified in
Документація/agent-harness-specification.md for autonomous security models.
"""

import argparse
import json
import os
import subprocess
import sys
import urllib.request
import urllib.error

RR_GATEWAY_URL = os.environ.get("RR_GATEWAY_URL", "http://127.0.0.1:8000")


def format_observation(status: str, summary: str, details: dict = None,
                       root_cause_hint: str = None, safe_retry_instruction: str = None,
                       explicit_stop_condition: str = None, next_actions: list = None) -> str:
    """Format structured observation conforming to the agent-harness contract."""
    payload = {
        "status": status,
        "summary": summary,
        "details": details or {},
        "root_cause_hint": root_cause_hint,
        "safe_retry_instruction": safe_retry_instruction,
        "explicit_stop_condition": explicit_stop_condition,
        "next_actions": next_actions or [],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def cmd_probe(args):
    """Send an HTTP probe request through Request-Rider engine/proxy."""
    headers = {}
    if args.headers:
        try:
            headers = json.loads(args.headers)
        except Exception as exc:
            print(format_observation(
                status="error",
                summary=f"Некоректний JSON заголовків: {exc}",
                root_cause_hint="Заголовки мають передаватися як валідний JSON об'єкт",
                safe_retry_instruction="Перевірте лапки та синтаксис аргументу --headers"
            ))
            return 1

    payload_data = {
        "method": args.method.upper(),
        "url": args.url,
        "headers": headers,
        "body": args.body or "",
    }

    try:
        req = urllib.request.Request(
            f"{RR_GATEWAY_URL}/api/execute",
            data=json.dumps(payload_data).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            http_status = data.get("status", 200)
            status = "success" if http_status < 400 else "warning"
            print(format_observation(
                status=status,
                summary=f"HTTP probe completed: {args.method} {args.url} -> {http_status}",
                details={
                    "http_status": http_status,
                    "latency_ms": data.get("time", 0),
                    "size": data.get("size", 0),
                    "headers": data.get("headers", {}),
                    "body_snippet": str(data.get("body", ""))[:1500]
                },
                next_actions=[
                    "Проаналізувати статус код та тіло відповіді",
                    "У разі виявлення аномалії зареєструвати знахідку через record-finding"
                ]
            ))
            return 0
    except Exception as exc:
        print(format_observation(
            status="error",
            summary=f"Помилка надсилання зонду: {exc}",
            root_cause_hint="Цільовий сервіс недоступний або шлюз Request-Rider (:8000) зупинено",
            safe_retry_instruction="Перевірте статус: curl -I http://127.0.0.1:8000/ або статус цілі",
            explicit_stop_condition="Зупинитися, якщо цільовий хост офлайн",
            next_actions=["Перевірити мережеву доступність", "Повторити запит"]
        ))
        return 1


def cmd_search_history(args):
    """Search project traffic history for recorded exchanges."""
    try:
        req = urllib.request.Request(
            f"{RR_GATEWAY_URL}/api/agent/run",
            data=json.dumps({
                "prompt": f"Search history for {args.query}",
                "max_steps": 1,
                "include_project_context": True
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(format_observation(
                status="success",
                summary=f"Пошук історії завершено для запиту '{args.query}'",
                details=data
            ))
            return 0
    except Exception as exc:
        print(format_observation(
            status="error",
            summary=f"Помилка пошуку в історії: {exc}",
            root_cause_hint="API /api/agent/run недоступне",
            safe_retry_instruction="Перевірте роботу Django сервера на :8000"
        ))
        return 1


def cmd_record_finding(args):
    """Record a verified finding into Request-Rider ScannerRun."""
    try:
        req = urllib.request.Request(
            f"{RR_GATEWAY_URL}/api/agent/run",
            data=json.dumps({
                "prompt": f"Record finding: Title={args.title}, Severity={args.severity}, URL={args.evidence_url}, Description={args.description or ''}, Remediation={args.remediation or ''}",
                "max_steps": 2
            }).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(format_observation(
                status="success",
                summary=f"Знахідка '{args.title}' [{args.severity}] успішно зафіксована",
                details=data,
                next_actions=["Перевірити інші пов'язані ендпоінти"]
            ))
            return 0
    except Exception as exc:
        print(format_observation(
            status="error",
            summary=f"Не вдалося зафіксувати знахідку: {exc}",
            safe_retry_instruction="Перевірте валідність аргументів та доступність шлюзу"
        ))
        return 1


def cmd_check_scope(args):
    """Check git diff against allowed files list (AGENTS.md compliance)."""
    allowed = [os.path.normpath(f.strip()) for f in args.allowed.split(",") if f.strip()]
    res = subprocess.run(["git", "diff", "--name-only"], capture_output=True, text=True)
    if res.returncode != 0:
        print(format_observation(status="error", summary="Не вдалося виконати git diff"))
        return 1

    changed = [os.path.normpath(f.strip()) for f in res.stdout.strip().split("\n") if f.strip()]
    violations = [f for f in changed if f not in allowed]

    if violations:
        print(format_observation(
            status="error",
            summary=f"Виявлено {len(violations)} файлів, змінених поза планом!",
            details={"violations": violations, "allowed": allowed, "all_changed": changed},
            root_cause_hint="Порушення розділу 5 та 10 AGENTS.md (SCOPE VIOLATION)",
            safe_retry_instruction="Скасуйте зміни в нерозрешених файлах або оновіть зафіксований план",
            explicit_stop_condition="ЗУПИНИТИСЯ і повернути CONFLICT_DETECTED при несанкціонованих змінах"
        ))
        return 1
    else:
        print(format_observation(
            status="success",
            summary="Scope Check: PASS. Усі змінені файли відповідають затвердженому плану.",
            details={"changed_count": len(changed), "files": changed}
        ))
        return 0


def cmd_run_tests(args):
    """Run isolated unit tests through the harness."""
    env = dict(os.environ)
    env.update({
        "POSTGRES_HOST": "127.0.0.1",
        "POSTGRES_PORT": "55433",
        "POSTGRES_USER": "kali",
        "POSTGRES_DB": "requestrider"
    })
    cmd = ["python3", "web/manage.py", "test", "lab.test_agent_tools", "lab.test_agent_loop"]
    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if res.returncode == 0:
        print(format_observation(
            status="success",
            summary="Tests: PASS. Всі тести агента та інструментів виконані успішно.",
            details={"output": res.stderr.strip() or res.stdout.strip()}
        ))
        return 0
    else:
        print(format_observation(
            status="error",
            summary="Tests: FAILED.",
            details={"output": res.stderr.strip() or res.stdout.strip()},
            root_cause_hint="Падіння асертів або помилка конфігурації оточення",
            safe_retry_instruction="Перевірте traceback вище та виправте регресію"
        ))
        return 1


def main():
    parser = argparse.ArgumentParser(description="Request-Rider Agent Harness CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # probe
    p_probe = subparsers.add_parser("probe", help="Send HTTP probe to target")
    p_probe.add_argument("--url", required=True, help="Target URL")
    p_probe.add_argument("--method", default="GET", help="HTTP Method")
    p_probe.add_argument("--headers", help="JSON string of headers")
    p_probe.add_argument("--body", help="Request body")
    p_probe.add_argument("--timeout", type=int, default=10, help="Timeout in seconds")
    p_probe.set_defaults(func=cmd_probe)

    # search-history
    p_sh = subparsers.add_parser("search-history", help="Search project traffic history")
    p_sh.add_argument("--query", required=True, help="Search query")
    p_sh.set_defaults(func=cmd_search_history)

    # record-finding
    p_rf = subparsers.add_parser("record-finding", help="Record finding into ScannerRun")
    p_rf.add_argument("--title", required=True, help="Finding title")
    p_rf.add_argument("--severity", default="MEDIUM", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    p_rf.add_argument("--evidence-url", required=True, help="Vulnerable URL")
    p_rf.add_argument("--description", help="Finding description")
    p_rf.add_argument("--remediation", help="Remediation advice")
    p_rf.set_defaults(func=cmd_record_finding)

    # check-scope
    p_cs = subparsers.add_parser("check-scope", help="Verify git diff against allowed files")
    p_cs.add_argument("--allowed", required=True, help="Comma-separated allowed files")
    p_cs.set_defaults(func=cmd_check_scope)

    # run-tests
    p_rt = subparsers.add_parser("run-tests", help="Run test suite")
    p_rt.set_defaults(func=cmd_run_tests)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
