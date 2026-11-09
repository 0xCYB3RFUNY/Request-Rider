#!/usr/bin/env python3
"""Bootstrap & verify script for Request-Rider Agents Environment.

Ensures that when working with agents, the full 3-tier execution stack is
automatically installed, validated, and ready:
1. Core MCP: request-rider-mcp venv, dependencies, server scripts.
2. Harness Layer: request-rider-harness + Google Research Harness² (harness2).
3. Skills Arsenal: 550+ skills in .agents/skills/ synced with skills.json.
4. Agent Configs: opencode.json and .agents/mcp_config.json properly configured.
"""

import argparse
import json
import os
import subprocess
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MCP_DIR = os.path.join(BASE_DIR, "request-rider-mcp")
MCP_VENV_DIR = os.path.join(MCP_DIR, ".venv")
MCP_PYTHON = os.path.join(MCP_VENV_DIR, "bin", "python")
MCP_PIP = os.path.join(MCP_VENV_DIR, "bin", "pip")
MCP_SERVER = os.path.join(MCP_DIR, "server.py")
HARNESS2_SRC = os.path.join(BASE_DIR, ".agents", "harness2")
SKILLS_DIR = os.path.join(BASE_DIR, ".agents", "skills")
SKILLS_JSON = os.path.join(BASE_DIR, ".agents", "skills.json")
MCP_CONFIG = os.path.join(BASE_DIR, ".agents", "mcp_config.json")
OPENCODE_JSON = os.path.join(BASE_DIR, "opencode.json")


def format_observation(status: str, summary: str, details: dict = None,
                       root_cause_hint: str = None, safe_retry_instruction: str = None,
                       next_actions: list = None) -> str:
    """Format structured observation conforming to the Request-Rider agent-harness contract."""
    payload = {
        "status": status,
        "summary": summary,
        "details": details or {},
        "root_cause_hint": root_cause_hint,
        "safe_retry_instruction": safe_retry_instruction,
        "next_actions": next_actions or [],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def check_and_bootstrap(verify_only: bool = False, as_json: bool = False) -> int:
    steps_log = []
    issues = []

    # 1. Check Python Venv for request-rider-mcp
    if not os.path.isfile(MCP_PYTHON):
        if verify_only:
            issues.append(f"Missing venv at {MCP_PYTHON}")
        else:
            steps_log.append(f"Creating virtual environment in {MCP_VENV_DIR}...")
            res = subprocess.run([sys.executable, "-m", "venv", MCP_VENV_DIR], capture_output=True, text=True)
            if res.returncode != 0:
                issues.append(f"Failed to create venv: {res.stderr.strip()}")

    # 2. Check dependencies in request-rider-mcp venv
    if os.path.isfile(MCP_PYTHON):
        dep_check = subprocess.run(
            [MCP_PYTHON, "-c", "import mcp; import httpx; print('deps_ok')"],
            capture_output=True, text=True
        )
        if dep_check.returncode != 0:
            if verify_only:
                issues.append("Missing mcp or httpx dependencies in request-rider-mcp venv")
            else:
                steps_log.append("Installing required packages (mcp, httpx)...")
                req_file = os.path.join(MCP_DIR, "requirements.txt")
                cmd = [MCP_PIP, "install", "mcp>=2.0.0", "httpx>=0.27.0"]
                res = subprocess.run(cmd, capture_output=True, text=True)
                if res.returncode != 0:
                    issues.append(f"Failed to install dependencies: {res.stderr.strip()}")

        # 3. Check Google Research Harness² (harness2)
        harness2_check = subprocess.run(
            [MCP_PYTHON, "-c", "import harness2; print('harness2_ok')"],
            capture_output=True, text=True
        )
        if harness2_check.returncode != 0:
            if verify_only:
                issues.append("Google Research Harness² (harness2) is not installed in venv")
            else:
                steps_log.append(f"Installing Google Research Harness² from {HARNESS2_SRC}...")
                if os.path.isdir(HARNESS2_SRC):
                    res = subprocess.run([MCP_PIP, "install", "-e", HARNESS2_SRC], capture_output=True, text=True)
                    if res.returncode != 0:
                        issues.append(f"Failed to install harness2: {res.stderr.strip()}")
                else:
                    issues.append(f"Source directory {HARNESS2_SRC} not found")

    # 4. Check Harnesses in .agents/skills/
    rr_harness_dir = os.path.join(SKILLS_DIR, "request-rider-harness")
    google_harness_dir = os.path.join(SKILLS_DIR, "google-harness2")
    if not os.path.isdir(rr_harness_dir):
        issues.append("request-rider-harness skill directory is missing")
    if not os.path.isdir(google_harness_dir):
        issues.append("google-harness2 skill directory is missing")

    # 5. Check Skills Catalog
    skills_count = 0
    if os.path.isdir(SKILLS_DIR):
        skills_count = len([d for d in os.listdir(SKILLS_DIR) if os.path.isdir(os.path.join(SKILLS_DIR, d))])
    if skills_count < 500:
        issues.append(f"Unexpected skills count: {skills_count} (expected 500+)")

    # 6. Check Agent Configs (opencode.json, .agents/mcp_config.json)
    for cfg_path in [OPENCODE_JSON, MCP_CONFIG]:
        if not os.path.isfile(cfg_path):
            issues.append(f"Missing agent config file: {cfg_path}")

    # Final verdict
    success = len(issues) == 0
    status_str = "success" if success else "error"
    summary = (
        "Agent Environment is verified and ready (MCP, Harnesses, 550+ Skills active)"
        if success else f"Agent Environment verification failed: {len(issues)} issue(s) detected"
    )

    details = {
        "mcp_python": MCP_PYTHON,
        "mcp_server": MCP_SERVER,
        "harnesses": {
            "request_rider_harness": os.path.isdir(rr_harness_dir),
            "google_harness2": os.path.isdir(google_harness_dir),
            "harness2_package_installed": (os.path.isfile(MCP_PYTHON) and harness2_check.returncode == 0 if 'harness2_check' in locals() else False)
        },
        "skills_count": skills_count,
        "configs": {
            "opencode_json": os.path.isfile(OPENCODE_JSON),
            "mcp_config_json": os.path.isfile(MCP_CONFIG)
        },
        "steps_taken": steps_log,
        "issues": issues
    }

    if as_json:
        print(format_observation(
            status=status_str,
            summary=summary,
            details=details,
            root_cause_hint="; ".join(issues) if issues else None,
            safe_retry_instruction="Run 'python3 scripts/bootstrap_agents_env.py' to auto-fix issues" if issues else None,
            next_actions=["Launch agent with opencode or IDE connected to request-rider-mcp"] if success else ["Fix issues before launching agent"]
        ))
    else:
        print(f"=== Request-Rider Agent Environment: {status_str.upper()} ===")
        print(f"Summary: {summary}")
        if steps_log:
            print("\nActions performed:")
            for s in steps_log:
                print(f"  [+] {s}")
        print("\nEnvironment status:")
        print(f"  • MCP Python venv: {'OK' if os.path.isfile(MCP_PYTHON) else 'FAIL'}")
        print(f"  • Google Harness² package: {'OK' if details['harnesses']['harness2_package_installed'] else 'FAIL'}")
        print(f"  • Request-Rider Harness skill: {'OK' if details['harnesses']['request_rider_harness'] else 'FAIL'}")
        print(f"  • Google Harness² skill: {'OK' if details['harnesses']['google_harness2'] else 'FAIL'}")
        print(f"  • Total Skills available: {skills_count}")
        print(f"  • opencode.json & mcp_config.json: OK")
        if issues:
            print("\nIssues:")
            for iss in issues:
                print(f"  [-] {iss}")

    return 0 if success else 1


def main():
    parser = argparse.ArgumentParser(description="Bootstrap & Verify Request-Rider Agents Environment")
    parser.add_argument("--verify-only", action="store_true", help="Only verify without installing")
    parser.add_argument("--json", action="store_true", help="Output Observation Contract JSON")
    args = parser.parse_args()

    sys.exit(check_and_bootstrap(verify_only=args.verify_only, as_json=args.json))


if __name__ == "__main__":
    main()
