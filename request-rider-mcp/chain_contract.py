"""Локальная валидация контракта ланцюгів MCP-інструментів Request-Rider.

Модуль навмисно не імпортує ``server.py`` або ``core/server_core.py``: він є
окремою перевіркою контракту й не змінює канонічний MCP runtime. ``jsonschema``
використовується для перевірки форми JSON, а додаткові детерміновані перевірки
гарантують локальні межі, коректність посилань, retry/fallback і подій.
"""

from __future__ import annotations

import copy
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError as exc:  # pragma: no cover - залежність є у системному Python
    raise RuntimeError(
        "Для валідації MCP Chain Contract потрібен пакет jsonschema"
    ) from exc


_CHAIN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_REFERENCE_RE = re.compile(r"^\$([A-Za-z0-9_-]+)(\.[A-Za-z0-9_-]+|\[\d+\])*$")
_EVENT_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_.]*$")
_RFC3339_DATETIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)
_EVENT_NAME_MAX_LENGTH = 128
_TOOL_NAME_MAX_LENGTH = 128
_ALLOWED_MODES = frozenset({"local_only"})
_ALLOWED_TRANSPORTS = frozenset({"local_event_bus"})
_ALLOWED_HANDLER_TYPES = frozenset({"python_callable", "local_file"})
_ALLOWED_STATUSES = frozenset({"pending", "running", "succeeded", "failed", "skipped"})

_HERE = Path(__file__).resolve().parent
_DEFAULT_SCHEMA_PATH = _HERE.parent / "contracts" / "mcp-chain-v1.json"


def _is_rfc3339_datetime(value: str) -> bool:
    if not _RFC3339_DATETIME_RE.fullmatch(value):
        return False
    raw = value[:-1] + "+00:00" if value[-1] in ("Z", "z") else value
    try:
        datetime.fromisoformat(raw)
    except ValueError:
        return False
    return True


_FORMAT_CHECKER = FormatChecker()


@_FORMAT_CHECKER.checks("date-time")
def _check_rfc3339_datetime(value: Any) -> bool:
    if not isinstance(value, str):
        return True
    return _is_rfc3339_datetime(value)


_VALIDATOR = Draft202012Validator(
    json.loads(_DEFAULT_SCHEMA_PATH.read_text(encoding="utf-8")),
    format_checker=_FORMAT_CHECKER,
)


class ChainContractError(ValueError):
    """Контракт ланцюга порушено; повідомлення містить точний шлях до дефекту."""


def _require_mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ChainContractError(f"{path}: очікується об'єкт")
    return value


def _require_sequence(value: Any, path: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ChainContractError(f"{path}: очікується масив")
    return value


def _require_string(value: Any, path: str, *, max_length: Optional[int] = None) -> str:
    if not isinstance(value, str) or not value:
        raise ChainContractError(f"{path}: очікується непорожній рядок")
    if max_length is not None and len(value) > max_length:
        raise ChainContractError(f"{path}: рядок довший за {max_length} символів")
    return value


def _validate_schema(chain: Any) -> None:
    errors = sorted(_VALIDATOR.iter_errors(chain), key=lambda error: list(error.absolute_path))
    if errors:
        messages = []
        for error in errors[:20]:
            path = ".".join(str(part) for part in error.absolute_path) or "<root>"
            messages.append(f"{path}: {error.message}")
        suffix = "" if len(errors) <= 20 else f"; ще {len(errors) - 20} помилок"
        raise ChainContractError("Невідповідність JSON Schema: " + "; ".join(messages) + suffix)


def _validate_created_at(value: str) -> None:
    if not _is_rfc3339_datetime(value):
        raise ChainContractError("created_at: некоректний RFC 3339 date-time timestamp")


def _validate_local_limits(limits: Mapping[str, Any]) -> None:
    for field in ("shared_platform_access", "remote_access", "multi_user", "external_handlers"):
        if limits.get(field) is not False:
            raise ChainContractError(f"limits.{field}: має бути false у локальному контракті")


def _validate_events(events: Any, step_ids: set[str]) -> None:
    for index, raw_event in enumerate(events):
        path = f"events[{index}]"
        event = _require_mapping(raw_event, path)
        name = _require_string(event.get("name"), f"{path}.name", max_length=_EVENT_NAME_MAX_LENGTH)
        if not _EVENT_NAME_RE.fullmatch(name):
            raise ChainContractError(f"{path}.name: некоректна назва події '{name}'")
        for producer_index, raw_producer in enumerate(_require_sequence(event.get("produced_by", []), f"{path}.produced_by")):
            producer_path = f"{path}.produced_by[{producer_index}]"
            producer = _require_string(raw_producer, producer_path)
            if producer not in step_ids:
                raise ChainContractError(f"{producer_path}: невідомий крок '{producer}'")


def _validate_retry(raw_retry: Any, path: str) -> None:
    retry = _require_mapping(raw_retry, path)
    attempts = retry.get("max_attempts")
    if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 1 or attempts > 10:
        raise ChainContractError(f"{path}.max_attempts: ціле число від 1 до 10")
    delay_ms = retry.get("backoff_ms")
    if not isinstance(delay_ms, int) or isinstance(delay_ms, bool) or delay_ms < 0:
        raise ChainContractError(f"{path}.backoff_ms: невід'ємне ціле число")
    strategy = retry.get("backoff")
    if strategy not in ("fixed", "exponential"):
        raise ChainContractError(f"{path}.backoff: дозволено 'fixed' або 'exponential'")


def _validate_target(raw_target: Any, path: str, step_ids: set[str]) -> str:
    target = _require_string(raw_target, path, max_length=_TOOL_NAME_MAX_LENGTH)
    if target.startswith("$"):
        match = _REFERENCE_RE.fullmatch(target)
        if match is None:
            raise ChainContractError(f"{path}: некоректне посилання '{target}'")
        referenced = match.group(1)
        if referenced.startswith("step."):
            step_id = referenced.split(".", 1)[1]
            if step_id not in step_ids:
                raise ChainContractError(f"{path}: посилання на невідомий крок '{step_id}'")
        return "reference"
    return "tool"


def _validate_fallback(raw_fallback: Any, path: str, step_ids: set[str]) -> None:
    fallback = _require_mapping(raw_fallback, path)
    _validate_target(fallback.get("target"), f"{path}.target", step_ids)
    reason = _require_string(fallback.get("reason"), f"{path}.reason", max_length=4096)
    if not reason.strip():
        raise ChainContractError(f"{path}.reason: причина не може бути порожньою")


def _validate_handler(raw_handler: Any, path: str) -> None:
    handler = _require_mapping(raw_handler, path)
    handler_type = _require_string(handler.get("type"), f"{path}.type")
    if handler_type not in _ALLOWED_HANDLER_TYPES:
        allowed = ", ".join(sorted(_ALLOWED_HANDLER_TYPES))
        raise ChainContractError(f"{path}.type: дозволено {allowed}")
    if handler_type == "python_callable":
        value = handler.get("value")
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", value):
            raise ChainContractError(f"{path}.value: очікується ім'я локальної Python-функції")
    else:
        value = handler.get("value")
        if not isinstance(value, str) or value.startswith("/") or ".." in value or "\\" in value:
            raise ChainContractError(f"{path}.value: очікується відносний локальний шлях без traversal")


def _validate_steps(steps: Sequence[Any], step_ids: set[str]) -> Dict[str, Mapping[str, Any]]:
    by_id: Dict[str, Mapping[str, Any]] = {}
    for index, raw_step in enumerate(steps):
        path = f"steps[{index}]"
        step = _require_mapping(raw_step, path)
        step_id = _require_string(step.get("id"), f"{path}.id", max_length=_TOOL_NAME_MAX_LENGTH)
        if not _CHAIN_ID_RE.fullmatch(step_id):
            raise ChainContractError(f"{path}.id: некоректний ідентифікатор '{step_id}'")
        if step_id in by_id:
            raise ChainContractError(f"{path}.id: дублікат кроку '{step_id}'")
        by_id[step_id] = step

        tool = _require_string(step.get("tool"), f"{path}.tool", max_length=_TOOL_NAME_MAX_LENGTH)
        if not _CHAIN_ID_RE.fullmatch(tool) and not tool.startswith("$"):
            raise ChainContractError(f"{path}.tool: некоректна назва інструмента '{tool}'")
        if tool.startswith("$"):
            match = _REFERENCE_RE.fullmatch(tool)
            if match is None:
                raise ChainContractError(f"{path}.tool: некоректне посилання '{tool}'")
            if tool.startswith("$step."):
                ref_step_id = tool[len("$step."):]
                if ref_step_id not in step_ids:
                    raise ChainContractError(f"{path}.tool: посилання на невідомий крок '{ref_step_id}'")

        for dep_index, raw_dep in enumerate(_require_sequence(step.get("depends_on", []), f"{path}.depends_on")):
            dep_path = f"{path}.depends_on[{dep_index}]"
            dependency = _require_string(raw_dep, dep_path)
            if dependency not in step_ids:
                raise ChainContractError(f"{dep_path}: невідомий крок '{dependency}'")
            if dependency == step_id:
                raise ChainContractError(f"{dep_path}: крок не може залежати від самого себе")

        timeout_ms = step.get("timeout_ms")
        if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool) or timeout_ms <= 0:
            raise ChainContractError(f"{path}.timeout_ms: додатне ціле число")

        if "retry" in step:
            _validate_retry(step["retry"], f"{path}.retry")
        if "fallback" in step:
            _validate_fallback(step["fallback"], f"{path}.fallback", step_ids)
        if "handler" in step:
            _validate_handler(step["handler"], f"{path}.handler")

        for emit_index, raw_emit in enumerate(_require_sequence(step.get("emit", []), f"{path}.emit")):
            emit_path = f"{path}.emit[{emit_index}]"
            emit = _require_string(raw_emit, emit_path, max_length=_EVENT_NAME_MAX_LENGTH)
            if not _EVENT_NAME_RE.fullmatch(emit):
                raise ChainContractError(f"{emit_path}: некоректна назва події '{emit}'")

        args = step.get("args", {})
        _require_mapping(args, f"{path}.args")
        for arg_name, arg_value in args.items():
            if isinstance(arg_value, str) and arg_value.startswith("$"):
                match = _REFERENCE_RE.fullmatch(arg_value)
                if match is None:
                    raise ChainContractError(f"{path}.args.{arg_name}: некоректне посилання '{arg_value}'")
                referenced = match.group(1)
                if referenced.startswith("step."):
                    referenced_step = referenced.split(".", 1)[1]
                    if referenced_step not in step_ids:
                        raise ChainContractError(
                            f"{path}.args.{arg_name}: посилання на невідомий крок '{referenced_step}'"
                        )
    return by_id


def _validate_execution_order(steps: Sequence[Mapping[str, Any]], by_id: Mapping[str, Mapping[str, Any]]) -> List[str]:
    """Топологічне сортування; цикл або невизначеність є помилкою контракту."""
    indegree = {step_id: 0 for step_id in by_id}
    children: Dict[str, List[str]] = {step_id: [] for step_id in by_id}
    for step in steps:
        step_id = step["id"]
        for dependency in step.get("depends_on", []):
            indegree[step_id] += 1
            children[dependency].append(step_id)

    ready = [step_id for step_id, degree in indegree.items() if degree == 0]
    ready.sort()
    order: List[str] = []
    while ready:
        current = ready.pop(0)
        order.append(current)
        for child in children[current]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
                ready.sort()
    if len(order) != len(by_id):
        unresolved = sorted(step_id for step_id, degree in indegree.items() if degree > 0)
        raise ChainContractError(f"steps: виявлено цикл залежностей: {', '.join(unresolved)}")
    return order


def _resolve_references(value: Any, outputs: Mapping[str, Any]) -> Any:
    if isinstance(value, str) and _REFERENCE_RE.fullmatch(value):
        parts: List[str | int] = []
        for token in re.findall(r"[A-Za-z0-9_-]+|\[\d+\]", value[1:]):
            if token.startswith("["):
                parts.append(int(token[1:-1]))
            else:
                parts.append(token)
        if parts and parts[0] == "step":
            if len(parts) < 2 or not isinstance(outputs, Mapping) or parts[1] not in outputs:
                return value
            current: Any = outputs[parts[1]]
            remaining: List[str | int] = parts[2:]
        elif parts and parts[0] == "chain":
            current = {"chain": outputs.get("__chain__", {})}
            remaining = parts[1:]
        else:
            return value
        for part in remaining:
            if isinstance(part, str) and isinstance(current, Mapping):
                if part not in current:
                    return value
                current = current[part]
            elif isinstance(part, int) and isinstance(current, Sequence) and not isinstance(current, str):
                if part >= len(current):
                    return value
                current = current[part]
            else:
                return value
        return current
    if isinstance(value, list):
        return [_resolve_references(item, outputs) for item in value]
    if isinstance(value, dict):
        return {key: _resolve_references(item, outputs) for key, item in value.items()}
    return value


def validate_chain(chain: Any) -> Dict[str, Any]:
    """Валідує контракт і повертає нормалізований план виконання.

    Повернені дані: ``steps_by_id``, ``execution_order`` та ``events``. Функція
    детермінована: не звертається до мережі, файлівruntime або стануprocess.
    """
    _validate_schema(chain)
    chain_object = _require_mapping(chain, "<root>")

    _validate_created_at(_require_string(chain_object.get("created_at"), "created_at"))
    _validate_local_limits(_require_mapping(chain_object.get("limits"), "limits"))

    steps = _require_sequence(chain_object.get("steps"), "steps")
    step_ids = {
        step["id"]
        for step in steps
        if isinstance(step, Mapping) and isinstance(step.get("id"), str)
    }
    events = _require_sequence(chain_object.get("events", []), "events")
    _validate_events(events, step_ids)
    by_id = _validate_steps(steps, step_ids)
    order = _validate_execution_order(steps, by_id)

    return {
        "contract_version": chain_object["contract_version"],
        "chain_id": chain_object["chain_id"],
        "steps_by_id": copy.deepcopy(dict(by_id)),
        "execution_order": order,
        "events": copy.deepcopy(list(events)),
    }


def _status_is_terminal(status: str) -> bool:
    return status in ("succeeded", "failed", "skipped")


def execute_chain_locally(
    chain: Any,
    tool_executor: Callable[[str, Mapping[str, Any]], Any],
    *,
    event_handler: Optional[Callable[[str, Mapping[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """Виконує локальний ланцюг без мережі та без зовнішніх обробників.

    ``tool_executor`` — локальна функція, яка отримує назву інструмента й аргументи.
    ``event_handler`` — локальний спостерігач подій; контракт забороняє writable
    external handler. Результат містить статуси, виходи та фактично випущені події.
    """
    plan = validate_chain(chain)
    by_id: Mapping[str, Mapping[str, Any]] = plan["steps_by_id"]
    outputs: Dict[str, Any] = {"__chain__": {"chain_id": plan["chain_id"]}}
    statuses: Dict[str, str] = {step_id: "pending" for step_id in by_id}
    emitted: List[Dict[str, Any]] = []

    def emit(name: str, payload: Mapping[str, Any]) -> None:
        event = {"name": name, "payload": copy.deepcopy(dict(payload))}
        emitted.append(event)
        if event_handler is not None:
            event_handler(name, event["payload"])

    for step_id in plan["execution_order"]:
        step = by_id[step_id]
        statuses[step_id] = "running"
        emit("step.started", {"step_id": step_id, "tool": step["tool"]})

        args = _resolve_references(step.get("args", {}), outputs)
        attempts = step.get("retry", {}).get("max_attempts", 1)
        last_error: Optional[Exception] = None
        result: Any = None
        for attempt in range(1, attempts + 1):
            try:
                result = tool_executor(step["tool"], args)
                last_error = None
                break
            except Exception as exc:  # retry — частина контракту, помилка не приховується
                last_error = exc
                if attempt < attempts:
                    emit(
                        "step.retry",
                        {"step_id": step_id, "attempt": attempt, "error": str(exc)},
                    )

        if last_error is not None:
            fallback = step.get("fallback")
            if fallback is not None:
                emit(
                    "step.fallback",
                    {
                        "step_id": step_id,
                        "reason": fallback["reason"],
                        "target": fallback["target"],
                        "error": str(last_error),
                    },
                )
                statuses[step_id] = "failed"
                emit("step.failed", {"step_id": step_id, "error": str(last_error)})
                continue

            statuses[step_id] = "failed"
            emit("step.failed", {"step_id": step_id, "error": str(last_error)})
            raise ChainContractError(f"steps '{step_id}': виконання завершилося помилкою: {last_error}") from last_error

        outputs[step_id] = result
        outputs[f"step.{step_id}"] = result
        statuses[step_id] = "succeeded"
        emit("step.succeeded", {"step_id": step_id})

        for event_name in step.get("emit", []):
            emit(event_name, {"step_id": step_id, "result": result})

    return {
        "chain_id": plan["chain_id"],
        "statuses": statuses,
        "outputs": outputs,
        "events": emitted,
    }


def load_chain_contract(path: str | Path) -> Dict[str, Any]:
    """Завантажує контракт з локального JSON-файлу та одразу його валідує."""
    contract_path = Path(path)
    with contract_path.open(encoding="utf-8") as handle:
        chain = json.load(handle)
    validate_chain(chain)
    return chain


__all__ = [
    "ChainContractError",
    "load_chain_contract",
    "validate_chain",
    "execute_chain_locally",
]
