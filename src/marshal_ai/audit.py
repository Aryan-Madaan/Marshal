from __future__ import annotations

import json
import threading
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional, Protocol


class AuditableEvent(Protocol):
    """Structural shape any audit record needs: a timestamp, a principal,
    and a way to serialize itself. `AuditEntry` (retrieval) and
    `marshal_ai.tools.ToolCallEntry` both satisfy this without either module
    importing the other — this is what lets one AuditSink hold both kinds
    of record and give you one unified trail instead of two separate logs.
    """

    timestamp: float
    principal_id: str

    def to_dict(self) -> dict[str, Any]: ...


# Registry mapping a "kind" discriminator to the dataclass that can
# reconstruct it from JSON. Each event type registers itself at import
# time (see the bottom of this file, and marshal_ai/tools.py) — audit.py
# itself never needs to know what event types exist.
_ENTRY_TYPES: dict[str, type] = {}


def register_entry_type(kind: str, cls: type) -> None:
    _ENTRY_TYPES[kind] = cls


def _decode_entry(data: dict[str, Any]) -> AuditableEvent:
    data = dict(data)
    kind = data.pop("kind")
    cls = _ENTRY_TYPES[kind]
    return cls(**data)


def decode_entry(data: dict[str, Any]) -> AuditableEvent:
    """Public counterpart to `_decode_entry`: turn a decoded JSON dict
    (one that still carries its `"kind"` discriminator, exactly what
    `entry.to_dict()` produces) back into the right dataclass via the
    `register_entry_type` registry.

    This is the reconstruction half of the self-registering-discriminator
    mechanism `register_entry_type` already documents as OCP's extension
    point — `JSONLAuditSink.all_entries` (in this module) and
    `marshal_ai.sinks.SQLiteAuditSink` (a different module) both need it
    to round-trip mixed entry types, so it's public: a sink outside
    `audit.py` should never have to reach into a private helper to do
    what `audit.py`'s own sink already does internally.
    """
    return _decode_entry(data)


@dataclass(frozen=True)
class AuditEntry:
    """A record of one retrieval call — enough to answer "who saw what,
    and what got filtered out, and why" after the fact.

    `shadow` — True when this entry was written by a `RetrievalGuard`
    running in shadow mode (`marshal_ai.policy.GuardMode`): the policy
    decision below (`allowed_ids`/`denied_ids`/`denied_reasons`) was
    computed and audited exactly as in enforce mode, but never acted on
    — every candidate document was returned to the caller unfiltered and
    unredacted regardless of what the decision says.

    `would_redact_fields` — for documents the policy would allow, maps
    document id -> which fields (``"content"`` or a metadata key) its
    `redact()` would have changed. Field *names* only, matching the
    existing discipline (`SensitiveDataEntry.findings`,
    `ToolCallEntry.arguments`) that the audit trail never stores the
    value a redaction was meant to hide, only what was hidden.

    Both fields default to their enforce-mode-equivalent values (`False`,
    `{}`) so older JSONL/SQLite logs written before shadow mode existed —
    and simply lack these two keys — still decode correctly.
    """

    timestamp: float
    principal_id: str
    query: str
    candidates_seen: int
    allowed_ids: list[str]
    denied_ids: list[str]
    denied_reasons: dict[str, str]
    shadow: bool = False
    would_redact_fields: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "retrieval", **asdict(self)}


register_entry_type("retrieval", AuditEntry)


def is_denied(entry: AuditableEvent) -> bool:
    """Duck-typed denial check shared by `AuditSink.query(denied_only=True)`
    and `marshal_ai.cli` — one definition of "was this a denial" so the two
    can't silently drift apart. Retrieval entries expose `denied_ids`,
    tool-call/model-call entries expose an `outcome` string, and
    `marshal_ai.sensitive.SensitiveDataEntry` exposes `action == "blocked"`
    instead (it has no `outcome` at all). Any future event type just needs
    to expose one of these three to participate — this module never needs
    to import the type to recognize it.
    """
    return (
        bool(getattr(entry, "denied_ids", None))
        or getattr(entry, "outcome", None) in ("deny", "declined")
        or getattr(entry, "action", None) == "blocked"
    )


class AuditSink(ABC):
    """Where audit entries go. Implement `write` and `all_entries` to plug
    in your own backend (Postgres, a SIEM, Kafka); `tail` and `query` are
    provided for free on top of `all_entries`.
    """

    @abstractmethod
    def write(self, entry: AuditableEvent) -> None: ...

    def all_entries(self) -> list[AuditableEvent]:
        """Every entry this sink holds, oldest first. Sinks that can't
        cheaply support reads (e.g. write-only log shippers) may leave
        this raising NotImplementedError — `tail`/`query` will then also
        raise, since both are built on top of this.
        """
        raise NotImplementedError

    def tail(self, n: int = 10) -> list[AuditableEvent]:
        """The most recent n entries."""
        return self.all_entries()[-n:]

    def query(
        self,
        *,
        principal_id: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        denied_only: bool = False,
    ) -> list[AuditableEvent]:
        """Filter the audit trail — e.g. "everything Bob was denied last
        week," across *every* surface writing to this sink, not just
        retrieval. `since`/`until` are Unix timestamps (see `time.time()`),
        inclusive on both ends.
        """
        entries = self.all_entries()
        if principal_id is not None:
            entries = [e for e in entries if e.principal_id == principal_id]
        if since is not None:
            entries = [e for e in entries if e.timestamp >= since]
        if until is not None:
            entries = [e for e in entries if e.timestamp <= until]
        if denied_only:
            entries = [e for e in entries if is_denied(e)]
        return entries


class InMemoryAuditSink(AuditSink):
    """Zero-config default. Good for tests, local scripts, and a solo dev
    who wants to see what's being filtered without standing up infra."""

    def __init__(self, max_entries: int = 10_000) -> None:
        self._entries: list[AuditableEvent] = []
        self._max_entries = max_entries
        self._lock = threading.Lock()

    def write(self, entry: AuditableEvent) -> None:
        with self._lock:
            self._entries.append(entry)
            if len(self._entries) > self._max_entries:
                self._entries.pop(0)

    def all_entries(self) -> list[AuditableEvent]:
        with self._lock:
            return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)


class JSONLAuditSink(AuditSink):
    """Appends one JSON object per line to a local file — the format most
    compliance and log-shipping pipelines already know how to ingest.
    Thread-safe within one process; not coordinated across processes.

    Mixed event types (retrieval + tool-call, all written by different
    guards sharing this sink) round-trip correctly: each line carries a
    "kind" discriminator so `all_entries` reconstructs the right dataclass.

    `all_entries`/`tail`/`query` all read and parse the whole file — fine
    for local/dev-scale logs, not meant for querying a large production
    audit history. Ship the file to something queryable (or implement a
    custom AuditSink backed by one) past that point.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, entry: AuditableEvent) -> None:
        line = json.dumps(entry.to_dict(), sort_keys=True)
        with self._lock:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

    def all_entries(self) -> list[AuditableEvent]:
        if not self._path.exists():
            return []
        with self._path.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        return [_decode_entry(json.loads(line)) for line in lines if line.strip()]
