import json
from pathlib import Path

from django.test import SimpleTestCase

from .engine_task_contract import (
    EngineTaskContractError,
    validate_engine_result,
    validate_engine_task,
)


CONTRACT_FIXTURES = Path(__file__).resolve().parents[2] / "contracts"


class EngineTaskContractTests(SimpleTestCase):
    def setUp(self):
        self.task = json.loads((CONTRACT_FIXTURES / "engine-task-v1.json").read_text())
        self.result = json.loads((CONTRACT_FIXTURES / "engine-result-v1.json").read_text())

    def test_shared_task_fixture_is_valid(self):
        self.assertIs(validate_engine_task(self.task), self.task)

    def test_shared_result_fixture_is_valid(self):
        self.assertIs(validate_engine_result(self.result), self.result)

    def test_task_rejects_unknown_schema_and_invalid_correlation(self):
        self.task["schema_version"] = 2
        with self.assertRaises(EngineTaskContractError):
            validate_engine_task(self.task)

        self.task["schema_version"] = 1
        self.task["workflow_run_id"] = True
        with self.assertRaises(EngineTaskContractError):
            validate_engine_task(self.task)

    def test_result_requires_terminal_error_shape(self):
        self.result["state"] = "failed"
        with self.assertRaises(EngineTaskContractError):
            validate_engine_result(self.result)

        self.result["error"] = {
            "code": "ENGINE_FAILURE",
            "message": "request failed",
            "retryable": True,
        }
        self.result.pop("result")
        self.assertIs(validate_engine_result(self.result), self.result)

    def test_task_route_generation_must_be_non_negative_integer(self):
        self.task["route_generation"] = 0
        self.assertIs(validate_engine_task(self.task), self.task)

        self.task["route_generation"] = -1
        with self.assertRaises(EngineTaskContractError):
            validate_engine_task(self.task)

        self.task["route_generation"] = True
        with self.assertRaises(EngineTaskContractError):
            validate_engine_task(self.task)
