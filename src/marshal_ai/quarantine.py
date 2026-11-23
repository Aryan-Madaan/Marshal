"""Quarantine: an authorized, audited kill switch for tools, models and
agents.

    from marshal_ai.quarantine import Quarantine, QuarantineToolPolicy, QuarantineModelPolicy

    q = Quarantine("quarantine.db", audit_sink=sink)
    tools = QuarantineToolPolicy(base_tool_policy, q)
    models = QuarantineModelPolicy(base_model_policy, q)

    # an operator, mid-incident, from any process (or the CLI):
    q.quarantine("tool", "wire_transfer", reason="INC-42: suspected misuse", by="oncall@company")
    q.quarantine("agent", "billing-agent", reason="INC-42", by="oncall@company")
    ...
    q.release("tool", "wire_transfer", by="oncall@company", reason="fix deployed")

Detection without a way to act is half a control. Every other policy
decides from rules written ahead of time; this one lets a human change
the answer *right now*, during an incident, without a deploy: stop one
tool for everyone, stop one agent from doing anything, or stop a model
deployment from being routed to. Three properties:

- **Durable and shared.** State lives in SQLite (stdlib), so a quarantine
  set from an operator's terminal applies to every process using the same
  file, immediately, and survives restarts.
- **Accountable.** Every quarantine and release requires `by` and
  `reason`, is audited as a `QuarantineEntry`, and is kept as history.
- **Fail closed.** If the quarantine store can't be read, the wrapped
  policies deny rather than assume nothing is quarantined.

Subjects: `"tool"` (by tool name; MCP tools by bare name), `"agent"` (by
principal id — the actor, or anyone in its delegation chain), and
`"model"` (a logical name or a resolved deployment).
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal, Optional

from marshal_ai._runctx import current_parent_run_id, current_run_id
from marshal_ai.audit import AuditSink, register_entry_type
from marshal_ai.models import ModelCallRequest, ModelDecision, ModelPolicy
from marshal_ai.policy import Principal
from marshal_ai.tools import ToolCallRequest, ToolDecision, ToolPolicy

Kind = Literal["tool", "agent", "model"]
_KINDS = ("tool", "agent", "model")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS quarantine (
    kind TEXT NOT NULL, name TEXT NOT NULL, reason TEXT NOT NULL, by TEXT NOT NULL, since REAL NOT NULL,
    PRIMARY KEY (kind, name)
);
CREATE TABLE IF NOT EXISTS quarantine_history (
    at REAL NOT NULL, action TEXT NOT NULL, kind TEXT NOT NULL, name TEXT NOT NULL, reason TEXT NOT NULL, by TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class QuarantineEntry:
    timestamp: float
    principal_id: str  # the operator who acted
    action: str  # "quarantine" | "release"
    subject_kind: str
    subject: str
    reason: str
    on_behalf_of: list[str] = field(default_factory=list)
    run_id: Optional[str] = field(default_factory=current_run_id)
    parent_run_id: Optional[str] = field(default_factory=current_parent_run_id)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "quarantine", **asdict(self)}


register_entry_type("quarantine", QuarantineEntry)


@dataclass(frozen=True)
class QuarantineRecord:
    kind: str
    name: str
    reason: str
    by: str
    since: float


class QuarantineUnavailable(RuntimeError):
    """The quarantine store couldn't be read; wrapped policies deny."""


class Quarantine:
    def __init__(self, path: "str | Path", audit_sink: Optional[AuditSink] = None) -> None:
        self._path = Path(path)
        self._audit_sink = audit_sink
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None, timeout=10)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)

    def _act(self, action: str, kind: str, name: str, reason: str, by: str) -> None:
        if kind not in _KINDS:
            raise ValueError(f"kind must be one of {_KINDS}")
        if not name or not by or not reason:
            raise ValueError("name, by and reason are all required — the audit trail records who acted and why")
        now = time.time()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if action == "quarantine":
                    self._conn.execute(
                        "INSERT OR REPLACE INTO quarantine (kind, name, reason, by, since) VALUES (?, ?, ?, ?, ?)",
                        (kind, name, reason, by, now),
                    )
                else:
                    cursor = self._conn.execute("DELETE FROM quarantine WHERE kind = ? AND name = ?", (kind, name))
                    if cursor.rowcount == 0:
                        raise KeyError(f"{kind} {name!r} is not quarantined")
                self._conn.execute(
                    "INSERT INTO quarantine_history (at, action, kind, name, reason, by) VALUES (?, ?, ?, ?, ?, ?)",
                    (now, action, kind, name, reason, by),
                )
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
        if self._audit_sink is not None:
            self._audit_sink.write(QuarantineEntry(now, by, action, kind, name, reason))

    def quarantine(self, kind: Kind, name: str, reason: str, by: str) -> None:
        self._act("quarantine", kind, name, reason, by)

    def release(self, kind: Kind, name: str, by: str, reason: str) -> None:
        self._act("release", kind, name, reason, by)

    def lookup(self, kind: str, names: "list[str]") -> Optional[QuarantineRecord]:
        """The quarantine record for the first of `names` that is
        quarantined, or None. Raises `QuarantineUnavailable` if the store
        can't be read."""
        if not names:
            return None
        try:
            with self._lock:
                row = self._conn.execute(
                    f"SELECT kind, name, reason, by, since FROM quarantine WHERE kind = ? AND name IN "
                    f"({', '.join('?' for _ in names)}) LIMIT 1",
                    (kind, *names),
                ).fetchone()
        except sqlite3.Error as exc:
            raise QuarantineUnavailable(type(exc).__name__) from exc
        return QuarantineRecord(*row) if row else None

    def active(self) -> list[QuarantineRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT kind, name, reason, by, since FROM quarantine ORDER BY since"
            ).fetchall()
        return [QuarantineRecord(*row) for row in rows]

    def history(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT at, action, kind, name, reason, by FROM quarantine_history ORDER BY at"
            ).fetchall()
        return [dict(zip(("at", "action", "kind", "name", "reason", "by"), row)) for row in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _agents(principal: Principal) -> list[str]:
    return [principal.id, *principal.delegation_chain]


def _blocked(record: QuarantineRecord) -> str:
    return f"{record.kind} {record.name!r} is quarantined by {record.by}: {record.reason}"


class QuarantineToolPolicy(ToolPolicy):
    """Wraps a `ToolPolicy`; denies calls to a quarantined tool, or by a
    quarantined agent (actor or anyone it acts for). Monotonic; fails
    closed if the store can't be read."""

    def __init__(self, base: ToolPolicy, quarantine: Quarantine) -> None:
        self._base = base
        self._quarantine = quarantine

    def evaluate(self, request: ToolCallRequest) -> ToolDecision:
        try:
            record = (
                self._quarantine.lookup("tool", [request.tool_name])
                or self._quarantine.lookup("agent", _agents(request.principal))
            )
        except QuarantineUnavailable as exc:
            return ToolDecision("deny", f"quarantine store unavailable ({exc}) — failing closed")
        if record is not None:
            return ToolDecision("deny", _blocked(record))
        return self._base.evaluate(request)

    def redact_arguments(self, request: ToolCallRequest) -> dict[str, Any]:
        return self._base.redact_arguments(request)


class QuarantineModelPolicy(ModelPolicy):
    """Wraps a `ModelPolicy`; denies a quarantined agent outright, and
    never resolves to a quarantined model (logical name or deployment) —
    the base's next qualifying candidate is used instead when there is one."""

    def __init__(self, base: ModelPolicy, quarantine: Quarantine) -> None:
        self._base = base
        self._quarantine = quarantine

    def _clear(self, model: Optional[str]) -> bool:
        return model is not None and self._quarantine.lookup("model", [model]) is None

    def resolve(self, request: ModelCallRequest) -> ModelDecision:
        try:
            record = self._quarantine.lookup("agent", _agents(request.principal)) or self._quarantine.lookup(
                "model", [request.logical_name]
            )
            if record is not None:
                return ModelDecision("deny", None, _blocked(record))
            decision = self._base.resolve(request)
            if decision.outcome != "allow" or self._clear(decision.resolved_model):
                return decision
            for candidate in self._base.fallback_chain(request):
                if self._clear(candidate):
                    return ModelDecision(
                        "allow", candidate,
                        f"resolved {request.logical_name!r} -> {candidate!r}: "
                        f"{decision.resolved_model!r} is quarantined",
                    )
            blocked = self._quarantine.lookup("model", [decision.resolved_model or ""])
            return ModelDecision("deny", None, _blocked(blocked) if blocked else "every candidate is quarantined")
        except QuarantineUnavailable as exc:
            return ModelDecision("deny", None, f"quarantine store unavailable ({exc}) — failing closed")

    def fallback_chain(self, request: ModelCallRequest) -> list[str]:
        try:
            return [m for m in self._base.fallback_chain(request) if self._clear(m)]
        except QuarantineUnavailable:
            return []

    def record_usage(self, principal: Principal, model: str, prompt_tokens: int, completion_tokens: int) -> None:
        self._base.record_usage(principal, model, prompt_tokens, completion_tokens)

    def record_outcome(self, principal: Principal, model: str, success: bool,
                       latency_ms: Optional[float] = None, error: Optional[str] = None) -> None:
        self._base.record_outcome(principal, model, success, latency_ms, error)
