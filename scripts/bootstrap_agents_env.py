#!/usr/bin/env python3
"""Bootstrap & verify script for Request-Rider Agents Environment.

Ensures that when working with agents, the full 3-tier execution stack is
automatically installed, validated, and ready:
1. Core MCP: request-rider-mcp venv, dependencies, server scripts.
2. Harness Layer: request-rider-harness + Google Research Harness² (harness2).
3. Skills Arsenal: 500+ skills in request-rider-mcp/skills/.

Note: the whole agent environment (server, venv, skills, harness2) lives in
request-rider-mcp/. The .agents/ folder and opencode.json are working files
and are NOT used or checked here.
"""

import argparse
import glob
import json
import os
import subprocess
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MCP_DIR = os.path.join(BASE_DIR, "request-rider-mcp")
MCP_VENV_DIR = os.path.join(MCP_DIR, ".venv")
MCP_PYTHON = os.path.join(MCP_VENV_DIR, "bin", "python")
MCP_SERVER = os.path.join(MCP_DIR, "server.py")
HARNESS2_SRC = os.path.join(MCP_DIR, "harness2")
SKILLS_DIR = os.path.join(MCP_DIR, "skills")


def _venv_python_healthy() -> bool:
    """Return True if MCP_PYTHON exists, runs, and has the pip module available."""
    if not os.path.isfile(MCP_PYTHON):
        return False
    try:
        res = subprocess.run(
            [MCP_PYTHON, "-m", "pip", "--version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return res.returncode == 0
    except OSError:
        return False


def _get_venv_site_packages() -> str | None:
    """Resolve the site-packages directory inside MCP_VENV_DIR."""
    try:
        res = subprocess.run(
            [MCP_PYTHON, "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if res.returncode == 0:
            path = res.stdout.strip()
            if path and os.path.isdir(path):
                return path
    except OSError:
        pass
    return None


def _install_harness2_pth_fallback() -> tuple[bool, str]:
    """Fallback editable link when pip build isolation cannot reach PyPI.

    harness2 has zero runtime dependencies (`dependencies = []` in pyproject.toml),
    so cleaning stale editable finders from a relocated repo and registering a
    `.pth` entry pointing at the current HARNESS2_SRC restores `import harness2`
    even in offline environments.
    """
    pkg_dir = os.path.join(HARNESS2_SRC, "harness2")
    if not os.path.isdir(pkg_dir):
        return False, f"Package directory {pkg_dir} not found"

    site_packages = _get_venv_site_packages()
    if not site_packages:
        return False, "Could not resolve venv site-packages directory"

    for pattern in ("__editable__.harness2*.pth", "__editable___harness2*_finder.py"):
        for stale in glob.glob(os.path.join(site_packages, pattern)):
            try:
                os.remove(stale)
            except OSError:
                pass

    pth_path = os.path.join(site_packages, "harness2_editable.pth")
    try:
        with open(pth_path, "w", encoding="utf-8") as fh:
            fh.write(HARNESS2_SRC + "\n")
    except OSError as exc:
        return False, f"Failed to write {pth_path}: {exc}"

    return True, pth_path


def _check_python_imports(code: str) -> subprocess.CompletedProcess[str]:
    """Run an import check using MCP_PYTHON."""
    return subprocess.run(
        [MCP_PYTHON, "-c", code],
        capture_output=True,
        text=True,
        timeout=30,
    )


def _desired_script_header() -> str:
    """Return a POSIX-safe shebang header pointing at MCP_PYTHON (handles spaces in paths)."""
    if " " in MCP_PYTHON or "\t" in MCP_PYTHON:
        escaped = MCP_PYTHON.replace("'", "'\"'\"'")
        return f"#!/bin/sh\n'''exec' '{escaped}' \"$0\" \"$@\"\n' '''\n"
    return f"#!{MCP_PYTHON}\n"


def _inspect_venv_script(path: str) -> tuple[bool, int]:
    """Check whether a Python console script in .venv/bin has a stale or broken shebang.

    Returns `(needs_repair, header_line_count)`. Non-script / binary / activate files
    return `(False, 0)`.
    """
    if os.path.islink(path) or not os.path.isfile(path) or not os.access(path, os.X_OK):
        return False, 0
    try:
        with open(path, "rb") as fh:
            head = fh.read(512)
    except OSError:
        return False, 0
    if b"\x00" in head or not head.startswith(b"#!"):
        return False, 0
    try:
        lines = head.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError:
        return False, 0
    if not lines:
        return False, 0

    first = lines[0].strip()
    if first == "#!/bin/sh" and len(lines) >= 3 and lines[1].startswith("'''exec' ") and lines[2].strip() == "' '''":
        if f"'{MCP_PYTHON}'" in lines[1]:
            return False, 0
        return True, 3

    if "python" in first.lower():
        interp = first[2:].strip()
        if interp == MCP_PYTHON and " " not in interp and "\t" not in interp:
            return False, 0
        if "python" in os.path.basename(interp).lower() or ".venv/bin/python" in interp:
            return True, 1

    return False, 0


def _repair_venv_script_shebangs(verify_only: bool = False) -> list[str]:
    """Find (and unless verify_only, rewrite) stale console script shebangs in MCP_VENV_DIR/bin."""
    bin_dir = os.path.join(MCP_VENV_DIR, "bin")
    if not os.path.isdir(bin_dir):
        return []
    header = _desired_script_header()
    affected: list[str] = []
    for entry in sorted(os.listdir(bin_dir)):
        script_path = os.path.join(bin_dir, entry)
        needs_repair, header_lines = _inspect_venv_script(script_path)
        if not needs_repair:
            continue
        affected.append(entry)
        if verify_only:
            continue
        try:
            with open(script_path, "r", encoding="utf-8") as fh:
                content_lines = fh.readlines()
            with open(script_path, "w", encoding="utf-8") as fh:
                fh.write(header)
                fh.writelines(content_lines[header_lines:])
        except OSError:
            pass
    return affected


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
    venv_ok = _venv_python_healthy()
    if not venv_ok:
        if verify_only:
            issues.append(f"Missing or broken venv at {MCP_PYTHON}")
        else:
            steps_log.append(f"Creating virtual environment in {MCP_VENV_DIR}...")
            res = subprocess.run(
                [sys.executable, "-m", "venv", "--clear", MCP_VENV_DIR],
                capture_output=True,
                text=True,
            )
            if res.returncode != 0:
                issues.append(f"Failed to create venv: {res.stderr.strip()}")
            else:
                venv_ok = _venv_python_healthy()
                if not venv_ok:
                    issues.append(f"Created venv at {MCP_PYTHON} is not runnable")

    # 2. Check dependencies in request-rider-mcp venv
    harness2_ok = False
    if venv_ok:
        dep_check = _check_python_imports("import mcp; import httpx; print('deps_ok')")
        if dep_check.returncode != 0:
            if verify_only:
                issues.append("Missing mcp or httpx dependencies in request-rider-mcp venv")
            else:
                steps_log.append("Installing required packages (mcp, httpx)...")
                cmd = [MCP_PYTHON, "-m", "pip", "install", "mcp>=2.0.0", "httpx>=0.27.0"]
                res = subprocess.run(cmd, capture_output=True, text=True)
                if res.returncode != 0:
                    issues.append(f"Failed to install dependencies: {res.stderr.strip()}")
                else:
                    dep_check = _check_python_imports("import mcp; import httpx; print('deps_ok')")
                    if dep_check.returncode != 0:
                        issues.append("Dependencies still fail to import after installation")

        # 3. Check Google Research Harness² (harness2)
        harness2_check = _check_python_imports("import harness2; print('harness2_ok')")
        harness2_ok = harness2_check.returncode == 0
        if not harness2_ok:
            if verify_only:
                issues.append("Google Research Harness² (harness2) is not installed in venv")
            else:
                steps_log.append(f"Installing Google Research Harness² from {HARNESS2_SRC}...")
                if os.path.isdir(HARNESS2_SRC):
                    res = subprocess.run(
                        [MCP_PYTHON, "-m", "pip", "install", "--no-deps", "-e", HARNESS2_SRC],
                        capture_output=True,
                        text=True,
                    )
                    if res.returncode != 0:
                        pth_ok, pth_info = _install_harness2_pth_fallback()
                        if pth_ok:
                            steps_log.append(f"Registered offline editable link: {pth_info}")
                        else:
                            issues.append(
                                f"Failed to install harness2: {res.stderr.strip()} "
                                f"(fallback failed: {pth_info})"
                            )
                    harness2_check = _check_python_imports("import harness2; print('harness2_ok')")
                    harness2_ok = harness2_check.returncode == 0
                    if not harness2_ok and not any("harness2" in iss for iss in issues):
                        issues.append("Google Research Harness² (harness2) failed import after install")
                else:
                    issues.append(f"Source directory {HARNESS2_SRC} not found")

        # 3b. Ensure venv console-script shebangs match the current MCP_PYTHON path
        stale_scripts = _repair_venv_script_shebangs(verify_only=verify_only)
        if stale_scripts:
            if verify_only:
                issues.append(
                    f"Stale shebangs in request-rider-mcp/.venv/bin ({len(stale_scripts)} script(s))"
                )
            else:
                steps_log.append(
                    f"Repaired {len(stale_scripts)} console script shebang(s) in {os.path.join(MCP_VENV_DIR, 'bin')}"
                )

    # 4. Check Harness skill in request-rider-mcp/skills/
    rr_harness_dir = os.path.join(SKILLS_DIR, "request-rider-harness")
    if not os.path.isdir(rr_harness_dir):
        issues.append("request-rider-harness skill directory is missing in request-rider-mcp/skills")

    # 5. Check Skills Catalog
    skills_count = 0
    if os.path.isdir(SKILLS_DIR):
        skills_count = len([d for d in os.listdir(SKILLS_DIR) if os.path.isdir(os.path.join(SKILLS_DIR, d))])
    if skills_count < 500:
        issues.append(f"Unexpected skills count: {skills_count} (expected 500+)")

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
            "harness2_package_installed": harness2_ok,
        },
        "skills_count": skills_count,
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
        print(f"  • MCP Python venv: {'OK' if venv_ok else 'FAIL'}")
        print(f"  • Google Harness² package: {'OK' if details['harnesses']['harness2_package_installed'] else 'FAIL'}")
        print(f"  • Request-Rider Harness skill: {'OK' if details['harnesses']['request_rider_harness'] else 'FAIL'}")
        print(f"  • Total Skills available: {skills_count}")
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
