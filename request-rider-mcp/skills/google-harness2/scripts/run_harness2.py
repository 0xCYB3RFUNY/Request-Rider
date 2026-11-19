#!/usr/bin/env python3
"""Runner script for Google Research Harness² integration in Request-Rider.

Connects the Request-Rider agent runtime with the Google Harness² package
located in .agents/harness2 and installed into request-rider-mcp/.venv.
"""

import argparse
import json
import os
import subprocess
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
MCP_VENV_BIN = os.path.join(BASE_DIR, "request-rider-mcp", ".venv", "bin")
PYTHON_BIN = os.path.join(MCP_VENV_BIN, "python")
HARNESS2_CLI = os.path.join(MCP_VENV_BIN, "harness2")
HARNESS2_DEMO = os.path.join(MCP_VENV_BIN, "harness2-demo")
HARNESS2_CHECK = os.path.join(MCP_VENV_BIN, "harness2-check")


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


def cmd_status(args):
    """Check Harness2 environment status in request-rider-mcp venv."""
    if not os.path.isfile(PYTHON_BIN):
        print(format_observation(
            status="error",
            summary="request-rider-mcp .venv Python binary not found",
            root_cause_hint=f"Expected venv at {PYTHON_BIN}",
            safe_retry_instruction="Run uv venv or python3 -m venv in request-rider-mcp"
        ))
        return 1

    proc = subprocess.run(
        [PYTHON_BIN, "-c", "import harness2; print(harness2.__version__ if hasattr(harness2, '__version__') else '0.1.0')"],
        capture_output=True,
        text=True
    )
    if proc.returncode != 0:
        print(format_observation(
            status="error",
            summary="harness2 module is not importable in request-rider-mcp .venv",
            details={"stderr": proc.stderr.strip()},
            root_cause_hint="harness2 package may not be installed in the virtual environment",
            safe_retry_instruction=f"{PYTHON_BIN} -m pip install -e .agents/harness2"
        ))
        return 1

    version = proc.stdout.strip()
    components = [
        "system_prompt", "guardrails", "memory", "tool_guidance",
        "subagents", "skills", "scripts", "plugins"
    ]
    print(format_observation(
        status="success",
        summary=f"Google Research Harness² v{version} is operational in request-rider-mcp venv",
        details={
            "version": version,
            "venv_python": PYTHON_BIN,
            "harness2_cli": HARNESS2_CLI,
            "components": components,
            "architecture": "3-tier: Request-Rider MCP -> Harnesses (RR + Google Harness²) -> Skills"
        },
        next_actions=[
            "Execute run_harness2.py demo --k 2 for local recursive hardening verification",
            "Use harness2 MCP tools in request-rider-mcp"
        ]
    ))
    return 0


def cmd_demo(args):
    """Run local deterministic Harness2 demo."""
    if not os.path.isfile(HARNESS2_DEMO):
        print(format_observation(
            status="error",
            summary="harness2-demo executable not found",
            root_cause_hint=f"Expected {HARNESS2_DEMO}",
            safe_retry_instruction=f"{PYTHON_BIN} -m pip install -e .agents/harness2"
        ))
        return 1

    out_dir = args.output or "/tmp/harness2_demo_run"
    cmd = [HARNESS2_DEMO, "--output", out_dir, "--k", str(args.k)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        print(format_observation(
            status="error",
            summary=f"harness2-demo failed with exit code {proc.returncode}",
            details={"stdout": proc.stdout[-1000:], "stderr": proc.stderr[-1000:]},
            safe_retry_instruction="Check dependencies or run with --k 1"
        ))
        return 1

    print(format_observation(
        status="success",
        summary=f"harness2-demo completed successfully (k={args.k})",
        details={
            "output_dir": out_dir,
            "output_snippet": proc.stdout[-1500:].strip()
        },
        next_actions=["Examine generated deliverables and improvement ledger in output directory"]
    ))
    return 0


def main():
    parser = argparse.ArgumentParser(description="Google Research Harness² Runner")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("status", help="Check Harness2 installation status")
    demo_p = subparsers.add_parser("demo", help="Run deterministic Harness2 demo")
    demo_p.add_argument("--k", type=int, default=2, help="Recursion steps (default: 2)")
    demo_p.add_argument("--output", type=str, default="/tmp/harness2_demo_run", help="Output directory")

    args = parser.parse_args()
    if args.command == "status":
        return cmd_status(args)
    elif args.command == "demo":
        return cmd_demo(args)
    else:
        return cmd_status(args)


if __name__ == "__main__":
    sys.exit(main())
