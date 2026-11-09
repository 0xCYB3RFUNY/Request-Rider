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
    import urllib.parse
    try:
        url = f"{RR_GATEWAY_URL}/api/history?path={urllib.parse.quote(args.query)}&detail=summary&limit=10"
        req = urllib.request.Request(
            url,
            headers={"Content-Type": "application/json"},
            method="GET"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            items = data.get("items", [])
            print(format_observation(
                status="success",
                summary=f"Пошук історії завершено: знайдено {len(items)} записів за запитом '{args.query}'",
                details={"count": len(items), "items": items[:5]}
            ))
            return 0
    except Exception as exc:
        print(format_observation(
            status="error",
            summary=f"Помилка пошуку в історії: {exc}",
            root_cause_hint="API /api/history недоступне або шлюз не відповідає",
            safe_retry_instruction="Перевірте роботу Django сервера на :8000"
        ))
        return 1


def cmd_record_finding(args):
    """Record a verified finding into Request-Rider ScannerRun."""
    env = dict(os.environ)
    env.update({
        "POSTGRES_HOST": "127.0.0.1",
        "POSTGRES_PORT": "55433",
        "POSTGRES_USER": "kali",
        "POSTGRES_DB": "requestrider"
    })
    py_code = (
        "import os, sys, django, json;"
        "sys.path.insert(0, 'web');"
        "os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings');"
        "django.setup();"
        "from lab.agent_tools import execute_agent_tool;"
        f"res = execute_agent_tool('finding_record', {{"
        f"    'title': {repr(args.title)},"
        f"    'severity': {repr(args.severity)},"
        f"    'description': {repr(args.description or '')},"
        f"    'evidence_url': {repr(args.evidence_url or '')},"
        f"    'remediation': {repr(args.remediation or '')}"
        f"}});"
        "print(json.dumps(res))"
    )
    try:
        res = subprocess.run([sys.executable, "-c", py_code], capture_output=True, text=True, env=env)
        if res.returncode == 0:
            data = json.loads(res.stdout.strip())
            print(format_observation(
                status="success",
                summary=f"Знахідка '{args.title}' [{args.severity}] успішно зафіксована",
                details=data,
                next_actions=["Перевірити інші пов'язані ендпоінти"]
            ))
            return 0
        else:
            raise RuntimeError(res.stderr.strip() or res.stdout.strip())
    except Exception as exc:
        print(format_observation(
            status="error",
            summary=f"Не вдалося зафіксувати знахідку: {exc}",
            safe_retry_instruction="Перевірте валідність аргументів та доступність бази даних"
        ))
        return 1


def cmd_check_scope(args):
    """Check git diff against allowed files list (AGENTS.md compliance)."""
    allowed = [os.path.normpath(f.strip()) for f in args.allowed.split(",") if f.strip()]
    git_check = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
    )
    if git_check.returncode != 0:
        missing_allowed = [
            f for f in allowed
            if not f.endswith("/*") and not f.endswith("/") and not os.path.exists(f)
        ]
        print(format_observation(
            status="warning",
            summary="Scope Check: SKIPPED (робочий каталог є резервною копією без .git).",
            details={
                "git_worktree": False,
                "allowed_count": len(allowed),
                "allowed": allowed,
                "missing_allowed_files": missing_allowed,
            },
            root_cause_hint="Директорія не є git-репозиторієм (.git відсутній), тому git diff недоступний",
            safe_retry_instruction="Ініціалізуйте git-репозиторій або використовуйте явний список дозволених файлів у сесії",
        ))
        return 0

    res = subprocess.run(["git", "-c", "core.quotepath=off", "diff", "--name-only"], capture_output=True, text=True)
    if res.returncode != 0:
        print(format_observation(
            status="error",
            summary="Не вдалося виконати git diff",
            root_cause_hint=res.stderr.strip() or "Помилка виклику git diff",
            safe_retry_instruction="Перевірте цілісність .git у робочому каталозі",
        ))
        return 1
    changed = [os.path.normpath(f.strip()) for f in res.stdout.strip().split("\n") if f.strip()]

    def is_allowed(f):
        for a in allowed:
            if f == a:
                return True
            if a.endswith("/*") and f.startswith(a[:-2]):
                return True
            if a.endswith("/") and f.startswith(a):
                return True
        return False

    violations = [f for f in changed if not is_allowed(f)]

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
    cmd = ["python3", "web/manage.py", "test", "--noinput", "lab.test_agent_tools", "lab.test_agent_loop"]
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


def cmd_verify(args):
    """Verify full agent environment readiness (MCP, Harnesses, Skills)."""
    bootstrap_script = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "scripts", "bootstrap_agents_env.py")
    bootstrap_script = os.path.normpath(bootstrap_script)
    if not os.path.isfile(bootstrap_script):
        print(format_observation(
            status="error",
            summary="bootstrap_agents_env.py script not found",
            root_cause_hint=f"Expected script at {bootstrap_script}",
            safe_retry_instruction="Ensure scripts/bootstrap_agents_env.py exists in project root"
        ))
        return 1
    cmd = [sys.executable, bootstrap_script, "--verify-only", "--json"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    print(res.stdout.strip() if res.stdout else res.stderr.strip())
    return res.returncode


def cmd_bootstrap(args):
    """Bootstrap and auto-install complete agent environment (MCP, Harnesses, Skills)."""
    bootstrap_script = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "scripts", "bootstrap_agents_env.py")
    bootstrap_script = os.path.normpath(bootstrap_script)
    if not os.path.isfile(bootstrap_script):
        print(format_observation(
            status="error",
            summary="bootstrap_agents_env.py script not found",
            root_cause_hint=f"Expected script at {bootstrap_script}",
            safe_retry_instruction="Ensure scripts/bootstrap_agents_env.py exists in project root"
        ))
        return 1
    cmd = [sys.executable, bootstrap_script, "--json"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    print(res.stdout.strip() if res.stdout else res.stderr.strip())
    return res.returncode


def main():
    parser = argparse.ArgumentParser(description="Request-Rider Agent Harness CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # verify / preflight
    p_ver = subparsers.add_parser("verify", help="Verify full agent environment readiness")
    p_ver.set_defaults(func=cmd_verify)
    p_pre = subparsers.add_parser("preflight", help="Preflight check agent environment")
    p_pre.set_defaults(func=cmd_verify)

    # init / bootstrap
    p_init = subparsers.add_parser("init", help="Bootstrap & auto-install full agent environment")
    p_init.set_defaults(func=cmd_bootstrap)
    p_boot = subparsers.add_parser("bootstrap", help="Bootstrap & auto-install full agent environment")
    p_boot.set_defaults(func=cmd_bootstrap)

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
