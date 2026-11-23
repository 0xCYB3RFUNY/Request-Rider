"""Тести контракту локальних ланцюгів MCP-інструментів.

Тести перевіряють вже реалізоване поведінкове API модуля ``chain_contract``:
валiдацію локальних меж, References, топологічного порядку, retry, fallback
та локальної шини подій. Тести навмисно не змінюють канонічний MCP runtime.
"""

from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

from chain_contract import (
    ChainContractError,
    execute_chain_locally,
    load_chain_contract,
    validate_chain,
)


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONTRACT_PATH = ROOT / "contracts" / "mcp-chain-v1.json"


def _baseline_chain() -> dict:
    return {
        "contract_version": "mcp-chain-v1",
        "chain_id": "example-chain",
        "created_at": "2026-11-20T00:00:00Z",
        "mode": "local_only",
        "limits": {
            "max_steps": 3,
            "max_depth": 2,
            "shared_platform_access": False,
            "remote_access": False,
            "multi_user": False,
            "external_handlers": False,
            "streaming": {
                "enabled": True,
                "transport": "local_event_bus",
                "events": ["step.started", "step.finished"],
            },
        },
        "events": [
            {"name": "finding.confirmed", "produced_by": ["record_finding"]}
        ],
        "steps": [
            {
                "id": "recon",
                "tool": "osint_recon",
                "timeout_ms": 5000,
                "args": {"domain": "ria.ru"},
            },
            {
                "id": "record_finding",
                "tool": "finding_record",
                "depends_on": ["recon"],
                "timeout_ms": 5000,
                "args": {"target": "$step.recon"},
                "emit": ["finding.confirmed"],
            },
        ],
    }


class ChainContractValidationTests(unittest.TestCase):
    def test_default_contract_is_valid(self) -> None:
        plan = validate_chain(_baseline_chain())

        self.assertEqual(plan["contract_version"], "mcp-chain-v1")
        self.assertEqual(plan["chain_id"], "example-chain")
        self.assertEqual(plan["execution_order"], ["recon", "record_finding"])
        self.assertEqual(set(plan["steps_by_id"]), {"recon", "record_finding"})
        self.assertEqual(
            [event["name"] for event in plan["events"]],
            ["finding.confirmed"],
        )

    def test_loading_from_disk_validates_contract(self) -> None:
        chain = _baseline_chain()
        handle, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as fh:
                json.dump(chain, fh)
            loaded = load_chain_contract(path)
            self.assertEqual(loaded["mode"], "local_only")
            self.assertEqual(loaded["limits"]["streaming"]["transport"], "local_event_bus")
        finally:
            os.unlink(path)

    def test_chain_id_and_step_ids_are_checked(self) -> None:
        chain = _baseline_chain()
        chain["chain_id"] = "bad id"

        with self.assertRaisesRegex(ChainContractError, "chain_id"):
            validate_chain(chain)

    def test_duplicate_step_id_is_rejected(self) -> None:
        chain = _baseline_chain()
        duplicated = copy.deepcopy(chain["steps"][0])
        duplicated["id"] = "record_finding"
        chain["steps"].append(duplicated)

        with self.assertRaisesRegex(ChainContractError, "дублікат кроку"):
            validate_chain(chain)

    def test_unknown_dependency_is_rejected(self) -> None:
        chain = _baseline_chain()
        chain["steps"][1]["depends_on"] = ["missing"]

        with self.assertRaisesRegex(ChainContractError, "невідомий крок"):
            validate_chain(chain)

    def test_dependency_cycle_is_rejected(self) -> None:
        chain = _baseline_chain()
        chain["steps"][0]["depends_on"] = ["record_finding"]

        with self.assertRaisesRegex(ChainContractError, "цикл залежностей"):
            validate_chain(chain)

    def test_remote_mode_is_rejected(self) -> None:
        chain = _baseline_chain()
        chain["mode"] = "remote"

        with self.assertRaisesRegex(ChainContractError, "local_only"):
            validate_chain(chain)

    def test_remote_transport_is_rejected(self) -> None:
        chain = _baseline_chain()
        chain["limits"]["streaming"]["transport"] = "webhook"

        with self.assertRaisesRegex(ChainContractError, "local_event_bus"):
            validate_chain(chain)

    def test_shared_platform_access_flag_must_be_false(self) -> None:
        chain = _baseline_chain()
        chain["limits"]["shared_platform_access"] = True

        with self.assertRaisesRegex(ChainContractError, "shared_platform_access"):
            validate_chain(chain)

    def test_step_tool_reference_must_point_to_known_step(self) -> None:
        chain = _baseline_chain()
        chain["steps"][1]["tool"] = "$step.unknown"

        with self.assertRaisesRegex(ChainContractError, "невідомий крок"):
            validate_chain(chain)

    def test_argument_reference_must_be_well_formed(self) -> None:
        chain = _baseline_chain()
        chain["steps"][1]["args"]["target"] = "$bad reference"

        with self.assertRaisesRegex(ChainContractError, "некоректне посилання"):
            validate_chain(chain)

    def test_event_producer_must_be_known_step(self) -> None:
        chain = _baseline_chain()
        chain["events"][0]["produced_by"] = ["missing"]

        with self.assertRaisesRegex(ChainContractError, "невідомий крок"):
            validate_chain(chain)

    def test_event_name_must_use_dot_namespace(self) -> None:
        chain = _baseline_chain()
        chain["steps"][1]["emit"] = ["finding_confirmed"]

        with self.assertRaisesRegex(ChainContractError, "finding_confirmed"):
            validate_chain(chain)

    def test_retry_contract_is_checked(self) -> None:
        chain = _baseline_chain()
        chain["steps"][0]["retry"] = {
            "max_attempts": 0,
            "backoff": "fixed",
            "backoff_ms": 10,
        }

        with self.assertRaisesRegex(ChainContractError, "max_attempts"):
            validate_chain(chain)

    def test_fallback_reason_is_required(self) -> None:
        chain = _baseline_chain()
        chain["steps"][0]["fallback"] = {"target": "local_fallback", "reason": "   "}

        with self.assertRaisesRegex(ChainContractError, "причина не може бути порожньою"):
            validate_chain(chain)

    def test_external_handler_is_rejected(self) -> None:
        chain = _baseline_chain()
        chain["steps"][0]["handler"] = {"type": "http", "value": "https://example.test"}

        with self.assertRaisesRegex(ChainContractError, "дозволено"):
            validate_chain(chain)

    def test_local_file_handler_rejects_traversal(self) -> None:
        chain = _baseline_chain()
        chain["steps"][0]["handler"] = {"type": "local_file", "value": "../secret.py"}

        with self.assertRaisesRegex(ChainContractError, "traversal"):
            validate_chain(chain)

    def test_created_at_must_be_rfc3339(self) -> None:
        invalid_values = (
            "not-a-date",
            "2026-11-21",
            "2026-11-21T10:00:00",
            "2026-02-30T10:00:00Z",
            "2026-11-21T10:00:00+25:00",
        )
        for bad_value in invalid_values:
            with self.subTest(created_at=bad_value):
                chain = _baseline_chain()
                chain["created_at"] = bad_value
                with self.assertRaisesRegex(ChainContractError, "date-time"):
                    validate_chain(chain)

        valid_values = (
            "2026-11-21T10:00:00Z",
            "2026-11-21T10:00:00.123456Z",
            "2026-11-21T10:00:00+02:00",
            "2026-11-21t10:00:00-05:00",
        )
        for good_value in valid_values:
            with self.subTest(valid_created_at=good_value):
                chain = _baseline_chain()
                chain["created_at"] = good_value
                validate_chain(chain)


class LocalChainExecutionTests(unittest.TestCase):
    def test_execution_resolves_references_and_emits_events(self) -> None:
        chain = _baseline_chain()
        chain["steps"][1]["args"]["target"] = "$step.recon"
        calls: list[tuple[str, dict]] = []
        events: list[str] = []

        def executor(tool: str, args: dict) -> dict:
            calls.append((tool, copy.deepcopy(args)))
            if tool == "osint_recon":
                return {"domain": "ria.ru", "entities": 12}
            return {"recorded": True, "detail": args["target"]}

        result = execute_chain_locally(
            chain,
            executor,
            event_handler=lambda name, payload: events.append(name),
        )

        self.assertEqual(result["statuses"], {"recon": "succeeded", "record_finding": "succeeded"})
        self.assertEqual(
            calls,
            [
                ("osint_recon", {"domain": "ria.ru"}),
                ("finding_record", {"target": {"domain": "ria.ru", "entities": 12}}),
            ],
        )
        self.assertIn("step.started", events)
        self.assertIn("step.succeeded", events)
        self.assertIn("finding.confirmed", events)
        self.assertEqual(
            [event["name"] for event in result["events"] if event["name"] == "finding.confirmed"],
            ["finding.confirmed"],
        )

    def test_execution_honours_dependency_order(self) -> None:
        chain = _baseline_chain()
        executed: list[str] = []

        def executor(tool: str, args: dict) -> dict:
            executed.append(tool)
            return {"ok": True}

        execute_chain_locally(chain, executor)

        self.assertEqual(executed, ["osint_recon", "finding_record"])

    def test_retry_runs_before_success(self) -> None:
        chain = _baseline_chain()
        chain["steps"][0]["retry"] = {
            "max_attempts": 3,
            "backoff": "fixed",
            "backoff_ms": 0,
        }
        attempts = {"count": 0}

        def executor(tool: str, args: dict) -> dict:
            if tool == "osint_recon":
                attempts["count"] += 1
                if attempts["count"] < 3:
                    raise RuntimeError("temporary")
            return {"ok": True}

        result = execute_chain_locally(chain, executor)

        self.assertEqual(attempts["count"], 3)
        self.assertEqual(result["statuses"]["recon"], "succeeded")
        self.assertEqual(
            len([event for event in result["events"] if event["name"] == "step.retry"]),
            2,
        )

    def test_fallback_marks_step_failed_without_aborting_chain(self) -> None:
        chain = _baseline_chain()
        chain["steps"][0]["fallback"] = {
            "target": "local_fallback",
            "reason": "локальний резервний інструмент",
        }
        seen: list[str] = []

        def executor(tool: str, args: dict) -> dict:
            seen.append(tool)
            if tool == "osint_recon":
                raise RuntimeError("primary failed")
            return {"ok": True}

        result = execute_chain_locally(chain, executor)

        self.assertEqual(result["statuses"]["recon"], "failed")
        self.assertEqual(result["statuses"]["record_finding"], "succeeded")
        self.assertEqual(seen, ["osint_recon", "finding_record"])
        self.assertTrue(any(event["name"] == "step.fallback" for event in result["events"]))

    def test_failure_without_fallback_raises(self) -> None:
        chain = _baseline_chain()

        def executor(tool: str, args: dict) -> dict:
            if tool == "osint_recon":
                raise RuntimeError("primary failed")
            return {"ok": True}

        with self.assertRaisesRegex(ChainContractError, "execution|виконання|помилкою"):
            execute_chain_locally(chain, executor)

    def test_execution_does_not_mutate_input_contract(self) -> None:
        chain = _baseline_chain()
        original = copy.deepcopy(chain)

        def executor(tool: str, args: dict) -> dict:
            return {"ok": True}

        execute_chain_locally(chain, executor)

        self.assertEqual(chain, original)

    def test_null_external_handlers_are_enforced_before_execution(self) -> None:
        chain = _baseline_chain()
        chain["limits"]["external_handlers"] = True

        with self.assertRaisesRegex(ChainContractError, "external_handlers"):
            validate_chain(chain)


if __name__ == "__main__":
    unittest.main()
