"""Run correlation: tie every governance decision to the agent run it
belongs to.

    from marshal_ai.runs import agent_run, run_timeline

    with agent_run(sink, task="refund-request") as run:
        retrieval.retrieve(...)          # every audit entry written in here —
        tools.call(...)                  # retrieval, tool, model, flow, egress,
        client.chat.completions.create(...)  # sensitive-data — carries run.run_id

    for entry in run_timeline(sink, run.run_id):
        print(entry)

An audit trail without run ids can say *what* happened but not *which
task it was part of*: a denied tool call, the retrieval that tainted the
session before it, and the model call that asked for it are three
unrelated rows. Every built-in audit entry type has `run_id` and
`parent_run_id` fields that default to the current run (a context
variable), so nothing at any call site changes — including inside
frameworks you didn't write, since context variables follow asyncio
tasks and `contextvars.copy_context()`.

Runs nest: an `agent_run` started inside another records the outer run
as its parent, so a sub-agent's activity is attributable to the task that
spawned it. `run_timeline(sink, run_id)` returns the run and all of its
descendants in time order.

Run ids are random and carry no meaning; pass `run_id=` to reuse your
own (a request id, an OpenTelemetry trace id) so Marshal's trail joins
up with the rest of your telemetry.
"""

from __future__ import annotations

import time
import uuid
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from marshal_ai._runctx import _PARENT_RUN_ID, _RUN_ID, current_parent_run_id, current_run_id
from marshal_ai.audit import AuditableEvent, AuditSink, is_denied, register_entry_type

__all__ = ["AgentRun", "RunEntry", "agent_run", "current_run_id", "run_summary", "run_timeline"]


@dataclass(frozen=True)
class RunEntry:
    """The start or end of an agent run. `status` on the end marker is
    `"completed"`, `"failed"` (an exception escaped the run) or
    `"cancelled"` (asyncio cancellation / KeyboardInterrupt); `error` is
    the exception type name, never its message."""

    timestamp: float
    principal_id: str
    run_id: Optional[str]
    phase: str  # "start" | "end"
    parent_run_id: Optional[str] = None
    task: Optional[str] = None
    status: Optional[str] = None
    duration_ms: Optional[float] = None
    error: Optional[str] = None
    on_behalf_of: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "agent_run", **asdict(self)}


register_entry_type("agent_run", RunEntry)


class AgentRun:
    """Context manager for one agent run; use via `agent_run(...)`."""

    def __init__(
        self,
        sink: Optional[AuditSink],
        task: Optional[str],
        run_id: Optional[str],
        principal_id: str,
        on_behalf_of: Optional[list[str]],
    ) -> None:
        self.run_id = run_id or f"run-{uuid.uuid4().hex[:16]}"
        self.task = task
        self.parent_run_id: Optional[str] = None
        self.status: Optional[str] = None
        self._sink = sink
        self._principal_id = principal_id
        self._on_behalf_of = list(on_behalf_of or [])
        self._tokens: list[Any] = []
        self._start = 0.0

    def _enter(self) -> "AgentRun":
        self.parent_run_id = current_run_id()
        self._tokens = [_RUN_ID.set(self.run_id), _PARENT_RUN_ID.set(self.parent_run_id)]
        self._start = time.monotonic()
        self._write("start")
        return self

    def _exit(self, exc_type: Any) -> None:
        if exc_type is None:
            self.status = "completed"
        elif issubclass(exc_type, (KeyboardInterrupt,)) or exc_type.__name__ == "CancelledError":
            self.status = "cancelled"
        else:
            self.status = "failed"
        try:
            self._write(
                "end", status=self.status, duration_ms=(time.monotonic() - self._start) * 1000,
                error=exc_type.__name__ if exc_type is not None else None,
            )
        finally:
            _PARENT_RUN_ID.reset(self._tokens[1])
            _RUN_ID.reset(self._tokens[0])

    def _write(self, phase: str, **extra: Any) -> None:
        if self._sink is None:
            return
        self._sink.write(
            RunEntry(
                timestamp=time.time(), principal_id=self._principal_id, run_id=self.run_id, phase=phase,
                parent_run_id=self.parent_run_id, task=self.task, on_behalf_of=self._on_behalf_of, **extra,
            )
        )

    def __enter__(self) -> "AgentRun":
        return self._enter()

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self._exit(exc_type)

    async def __aenter__(self) -> "AgentRun":
        return self._enter()

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self._exit(exc_type)


def agent_run(
    sink: Optional[AuditSink] = None,
    task: Optional[str] = None,
    run_id: Optional[str] = None,
    principal_id: str = "-",
    on_behalf_of: Optional[list[str]] = None,
) -> AgentRun:
    """Start a run (`with` or `async with`). With `sink`, start/end
    markers (`RunEntry`) are written — the end marker records completed /
    failed / cancelled and the duration. `task` is a short task-type label
    (e.g. "refund-request") used to group runs in reports — keep it free of
    personal data."""
    return AgentRun(sink, task, run_id, principal_id, on_behalf_of)


def _descendants(entries: list[AuditableEvent], run_id: str) -> set[str]:
    children: dict[str, set[str]] = {}
    for entry in entries:
        rid, parent = getattr(entry, "run_id", None), getattr(entry, "parent_run_id", None)
        if rid and parent:
            children.setdefault(parent, set()).add(rid)
    found, frontier = {run_id}, [run_id]
    while frontier:
        for child in children.get(frontier.pop(), ()):
            if child not in found:
                found.add(child)
                frontier.append(child)
    return found


def run_timeline(sink: AuditSink, run_id: str, include_children: bool = True) -> list[AuditableEvent]:
    """Every audit entry belonging to `run_id` (and, by default, its
    sub-runs), oldest first."""
    entries = sink.all_entries()
    wanted = _descendants(entries, run_id) if include_children else {run_id}
    return sorted((e for e in entries if getattr(e, "run_id", None) in wanted), key=lambda e: e.timestamp)


@dataclass(frozen=True)
class RunSummary:
    run_id: str
    task: Optional[str]
    status: Optional[str]
    duration_ms: Optional[float]
    sub_runs: int
    entries_by_kind: dict[str, int]
    denials: int
    tool_failures: int
    prompt_tokens: int
    completion_tokens: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_summary(sink: AuditSink, run_id: str) -> RunSummary:
    """Counts for one run and its sub-runs: what kinds of activity, how
    many denials, how many tool failures, and tokens used."""
    timeline = run_timeline(sink, run_id)
    end = next(
        (e for e in timeline if isinstance(e, RunEntry) and e.run_id == run_id and e.phase == "end"), None
    )
    start = next(
        (e for e in timeline if isinstance(e, RunEntry) and e.run_id == run_id and e.phase == "start"), None
    )
    kinds = Counter(e.to_dict()["kind"] for e in timeline if not isinstance(e, RunEntry))
    sub_runs = {e.run_id for e in timeline if isinstance(e, RunEntry) and e.run_id != run_id}
    return RunSummary(
        run_id=run_id,
        task=(start or end).task if (start or end) else None,
        status=end.status if end else None,
        duration_ms=end.duration_ms if end else None,
        sub_runs=len(sub_runs),
        entries_by_kind=dict(kinds),
        denials=sum(1 for e in timeline if not isinstance(e, RunEntry) and is_denied(e)),
        tool_failures=sum(1 for e in timeline if e.to_dict()["kind"] == "tool_outcome" and not e.success),
        prompt_tokens=sum(getattr(e, "prompt_tokens", 0) for e in timeline if e.to_dict()["kind"] == "model_usage"),
        completion_tokens=sum(getattr(e, "completion_tokens", 0) for e in timeline if e.to_dict()["kind"] == "model_usage"),
    )
