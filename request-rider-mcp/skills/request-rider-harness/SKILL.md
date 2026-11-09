---
name: request-rider-harness
description: "Standardized security evaluation harness for autonomous AI models working with Request-Rider. Implements structured Action Space (probes, history search, finding recording), deterministic Observation Contract (JSON status, root-cause hints, safe retries), and scope/compliance enforcement. Use when evaluating, benchmarking, or executing bounded security tasks with LLMs."
license: MIT
compatibility: opencode
metadata:
    source: "Request-Rider v1.2"
---

# Request-Rider Agent Harness

A deterministic execution and evaluation harness for autonomous AI models conducting security testing, web reconnaissance, and vulnerability verification within Request-Rider.

## The Contract

Autonomous models must never operate via unbounded ad-hoc shell commands. The harness enforces:

```
MODEL → Action Space (CLI Harness / MCP) → Observation Contract (Structured JSON) → Bounded Loop
```

1. **Structured Action Space**: Fixed endpoints for probing HTTP targets, querying traffic history, recording verified findings, and verifying change scope.
2. **Deterministic Observation**: Structured JSON responses providing status, response metadata, `root_cause_hint`, `safe_retry_instruction`, and explicit stop conditions.
3. **Scope & Budget Protection**: Hard constraints against modifying unapproved files or exceeding context limits.

## Quick Start

```bash
# 1. Probe a target endpoint via the Request-Rider proxy engine
python3 .agents/skills/request-rider-harness/scripts/harness_runner.py probe \
  --url "http://127.0.0.1:42000/rest/products/search?q=test" \
  --method GET

# 2. Search intercepted project traffic
python3 .agents/skills/request-rider-harness/scripts/harness_runner.py search-history \
  --query "login"

# 3. Record a verified security finding into the project ScannerRun
python3 .agents/skills/request-rider-harness/scripts/harness_runner.py record-finding \
  --title "SQL Injection in Search Query" \
  --severity HIGH \
  --evidence-url "http://127.0.0.1:42000/rest/products/search?q=1'" \
  --description "Boolean-based blind SQL injection detected."

# 4. Check scope compliance against approved files (AGENTS.md contract)
python3 .agents/skills/request-rider-harness/scripts/harness_runner.py check-scope \
  --allowed "web/lab/agent_tools.py,web/lab/views.py"

# 5. Run isolated unit tests
python3 .agents/skills/request-rider-harness/scripts/harness_runner.py run-tests
```

## Observation Contract Specification

Every action executed through the harness outputs a strictly formatted JSON object:

```json
{
  "status": "success | warning | error",
  "summary": "One sentence summary of the execution result",
  "details": {
    "http_status": 200,
    "latency_ms": 15,
    "size": 128
  },
  "root_cause_hint": "Null or explanation of failure",
  "safe_retry_instruction": "Exact command or action for recovery",
  "explicit_stop_condition": "Criteria where the model must immediately halt",
  "next_actions": [
    "Suggested logical next step"
  ]
}
```

## Workflows

### 1. Target Vulnerability Audit Workflow
1. Run `probe` to inspect target response headers, status code, and reflected parameters.
2. In case of unexpected behavior, run `search-history` to locate previous transactions or credentials.
3. Once an exploit or anomaly is confirmed, invoke `record-finding` with structured evidence.

### 2. Code Change & TDD Verification Workflow
1. Before modifying code, check scope with `check-scope`.
2. Apply changes strictly within authorized files.
3. Execute `run-tests` to ensure zero regressions in the test suite.
