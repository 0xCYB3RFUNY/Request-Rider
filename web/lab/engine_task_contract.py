"""Validation for the versioned Django-to-engine broker JSON contract."""

import re
from datetime import datetime
from uuid import UUID


class EngineTaskContractError(ValueError):
    """A broker message does not conform to its versioned contract."""


_TASK_TYPE = re.compile(r"^[a-z][a-z0-9_.-]*$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_RESULT_STATES = {"accepted", "progress", "completed", "failed", "cancelled"}


def _require_object(value, field):
    if not isinstance(value, dict):
        raise EngineTaskContractError(f"{field} must be an object")


def _require_uuid(value, field):
    if not isinstance(value, str) or not _UUID.fullmatch(value):
        raise EngineTaskContractError(f"{field} must be a UUID string")
    try:
        UUID(value)
    except (ValueError, AttributeError) as error:
        raise EngineTaskContractError(f"{field} must be a UUID string") from error


def _require_timestamp(value, field):
    if not isinstance(value, str) or not _RFC3339.fullmatch(value):
        raise EngineTaskContractError(f"{field} must be an RFC 3339 timestamp")
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EngineTaskContractError(f"{field} must be an RFC 3339 timestamp") from error
    if timestamp.tzinfo is None:
        raise EngineTaskContractError(f"{field} must include a timezone")


def validate_engine_task(message):
    """Validate a task envelope without mutating or narrowing its payload."""
    _require_object(message, "message")
    if type(message.get("schema_version")) is not int or message["schema_version"] != 1:
        raise EngineTaskContractError("schema_version must be 1")
    _require_uuid(message.get("task_id"), "task_id")
    task_type = message.get("task_type")
    if not isinstance(task_type, str) or not _TASK_TYPE.fullmatch(task_type):
        raise EngineTaskContractError("task_type must be a lowercase identifier")
    if "workflow_run_id" in message and (
        isinstance(message["workflow_run_id"], bool)
        or not isinstance(message["workflow_run_id"], int)
        or message["workflow_run_id"] < 1
    ):
        raise EngineTaskContractError("workflow_run_id must be a positive integer")
    if "workflow_node_id" in message and not isinstance(message["workflow_node_id"], str):
        raise EngineTaskContractError("workflow_node_id must be a string")
    if "project_id" in message and (
        isinstance(message["project_id"], bool)
        or not isinstance(message["project_id"], int)
        or message["project_id"] < 1
    ):
        raise EngineTaskContractError("project_id must be a positive integer")
    if "route_generation" in message and (
        isinstance(message["route_generation"], bool)
        or not isinstance(message["route_generation"], int)
        or message["route_generation"] < 0
    ):
        raise EngineTaskContractError("route_generation must be a non-negative integer")
    _require_timestamp(message.get("created_at"), "created_at")
    _require_object(message.get("payload"), "payload")
    return message


def validate_engine_result(message):
    """Validate a result event and its terminal-state-specific fields."""
    _require_object(message, "message")
    if type(message.get("schema_version")) is not int or message["schema_version"] != 1:
        raise EngineTaskContractError("schema_version must be 1")
    _require_uuid(message.get("task_id"), "task_id")
    _require_uuid(message.get("event_id"), "event_id")
    state = message.get("state")
    if not isinstance(state, str) or state not in _RESULT_STATES:
        raise EngineTaskContractError("state is not supported")
    _require_timestamp(message.get("occurred_at"), "occurred_at")
    if "progress" in message:
        _require_object(message["progress"], "progress")
    if state == "completed":
        _require_object(message.get("result"), "result")
        if "error" in message:
            raise EngineTaskContractError("completed results cannot include error")
    elif state == "failed":
        _require_object(message.get("error"), "error")
        error = message["error"]
        if not isinstance(error.get("code"), str) or not error["code"]:
            raise EngineTaskContractError("error.code must be a non-empty string")
        if not isinstance(error.get("message"), str) or not error["message"]:
            raise EngineTaskContractError("error.message must be a non-empty string")
        if not isinstance(error.get("retryable"), bool):
            raise EngineTaskContractError("error.retryable must be a boolean")
        if "result" in message:
            raise EngineTaskContractError("failed results cannot include result")
    elif "result" in message or "error" in message:
        raise EngineTaskContractError("non-terminal results cannot include result or error")
    return message
