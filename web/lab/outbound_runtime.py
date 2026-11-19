"""Process-local admission and cancellation for route-bound outbound work."""

from __future__ import annotations

import itertools
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Callable, Iterator


class OutboundOperationCancelled(RuntimeError):
    """Raised when a route switch invalidates an outbound operation."""


_CURRENT_OPERATION: ContextVar["OutboundOperation | None"] = ContextVar(
    "requestrider_outbound_operation",
    default=None,
)


def current_outbound_operation() -> "OutboundOperation | None":
    return _CURRENT_OPERATION.get()


@dataclass
class OutboundOperation:
    """One admitted operation bound to the current route generation."""

    id: int
    kind: str
    project_id: int | None
    generation: int
    cancelled: threading.Event = field(default_factory=threading.Event)
    _callbacks: list[Callable[[], None]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def stale(self) -> bool:
        return self.cancelled.is_set()

    def on_cancel(self, callback: Callable[[], None]) -> None:
        """Attach a transport cleanup callback and invoke it immediately if stale."""
        with self._lock:
            if not self.cancelled.is_set():
                self._callbacks.append(callback)
                return
        self._invoke(callback)

    def cancel(self) -> None:
        with self._lock:
            if self.cancelled.is_set():
                return
            self.cancelled.set()
            callbacks = list(self._callbacks)
            self._callbacks.clear()
        for callback in callbacks:
            self._invoke(callback)

    def raise_if_cancelled(self) -> None:
        if self.cancelled.is_set():
            raise OutboundOperationCancelled(f"{self.kind} cancelled by route switch")

    @staticmethod
    def _invoke(callback: Callable[[], None]) -> None:
        try:
            callback()
        except Exception:  # noqa: BLE001 - cancellation must not block the route switch
            import logging

            logging.getLogger(__name__).warning(
                "outbound cancellation callback failed",
                exc_info=True,
            )


class OutboundRouteSwitch:
    """Mutable result of a successfully prepared route switch."""

    def __init__(self, runtime: "OutboundRuntime") -> None:
        self._runtime = runtime
        self._activated = False
        self.cancelled_operations: list[int] = []
        self.cancelled_workflow_runs: list[int] = []
        self.cancelled_browser_jobs: list[str] = []
        self.cancelled_agent_requests = 0
        self.cleanup_errors: list[str] = []

    def activate(
        self,
        *,
        workflow_runs: list[int] | None = None,
        browser_jobs: list[str] | None = None,
        agent_requests: int = 0,
    ) -> None:
        """Invalidate admitted web operations and publish the new generation."""
        if self._activated:
            return
        self._activated = True
        self.cancelled_operations = self._runtime._activate_generation()
        self.cancelled_workflow_runs = list(workflow_runs or [])
        self.cancelled_browser_jobs = list(browser_jobs or [])
        self.cancelled_agent_requests = max(0, int(agent_requests))

    def record_cleanup(
        self,
        *,
        workflow_runs: list[int] | None = None,
        browser_jobs: list[str] | None = None,
        agent_requests: int | None = None,
        errors: list[str] | None = None,
    ) -> None:
        if workflow_runs is not None:
            self.cancelled_workflow_runs = list(workflow_runs)
        if browser_jobs is not None:
            self.cancelled_browser_jobs = list(browser_jobs)
        if agent_requests is not None:
            self.cancelled_agent_requests = max(0, int(agent_requests))
        if errors is not None:
            self.cleanup_errors = [str(error) for error in errors if str(error)]

    def result_metadata(self) -> dict[str, object]:
        return {
            "route_switched": self._activated,
            "cancelled_operations": len(self.cancelled_operations),
            "cancelled_workflow_runs": self.cancelled_workflow_runs,
            "cancelled_browser_jobs": self.cancelled_browser_jobs,
            "cancelled_agent_requests": self.cancelled_agent_requests,
            "incomplete": bool(self.cleanup_errors),
            "cleanup_errors": list(self.cleanup_errors),
        }


class OutboundRuntime:
    """Temporarily close admission while the process-wide route is replaced.

    Read and status operations are deliberately not admitted here. The barrier is
    momentary: it cancels the old generation and immediately reopens for new work.
    """

    def __init__(self) -> None:
        self.condition = threading.Condition(threading.RLock())
        self.generation = 0
        self.switching = False
        self._operations: dict[int, OutboundOperation] = {}
        self._ids = itertools.count(1)

    @contextmanager
    def operation(
        self,
        kind: str,
        project_id: int | None = None,
    ) -> Iterator[OutboundOperation]:
        with self.condition:
            while self.switching:
                self.condition.wait()
            operation = OutboundOperation(
                id=next(self._ids),
                kind=str(kind or "outbound"),
                project_id=project_id,
                generation=self.generation,
            )
            self._operations[operation.id] = operation
        token = _CURRENT_OPERATION.set(operation)
        try:
            yield operation
        finally:
            _CURRENT_OPERATION.reset(token)
            with self.condition:
                self._operations.pop(operation.id, None)
                self.condition.notify_all()

    @contextmanager
    def route_switch(self) -> Iterator[OutboundRouteSwitch]:
        """Close admission and cancel the old generation only on success."""
        with self.condition:
            while self.switching:
                self.condition.wait()
            self.switching = True
        switch = OutboundRouteSwitch(self)
        try:
            yield switch
        finally:
            with self.condition:
                self.switching = False
                self.condition.notify_all()

    def _activate_generation(self) -> list[int]:
        with self.condition:
            operations = list(self._operations.values())
            self.generation += 1
        for operation in operations:
            operation.cancel()
        return [operation.id for operation in operations]

    def sync_generation(self, generation: int) -> bool:
        """Reconcile after an engine restart when no local work is active."""
        with self.condition:
            if self.switching or self._operations:
                return False
            self.generation = max(0, int(generation))
            return True

    def snapshot(self) -> dict[str, object]:
        with self.condition:
            return {
                "generation": self.generation,
                "switching": self.switching,
                "active_operations": len(self._operations),
            }


_OUTBOUND_RUNTIME = OutboundRuntime()


def get_outbound_runtime() -> OutboundRuntime:
    return _OUTBOUND_RUNTIME
