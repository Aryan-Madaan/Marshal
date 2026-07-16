"""Durable, tamper-evident audit storage — the piece the EU AI Act's
Article 12 (automatic record-keeping) and Article 26 (deployers must
retain those logs for >=6 months) obligations actually need once "audit
sink" has to mean more than "a file on the box that's about to redeploy."

`InMemoryAuditSink` (marshal_ai.audit) doesn't survive a restart at all.
`JSONLAuditSink` does, but an append-only text file gives you no defense
against someone editing or truncating it after the fact, and answering
"show me everything for principal X since June 1" means reading and
re-parsing the entire file every time. `SQLiteAuditSink` closes both
gaps using nothing but the standard library (`sqlite3`, already in every
CPython install — no new dependency, no infra to stand up):

  - durable storage that survives a process restart (a real file, real
    transactions, not a process-lifetime list);
  - indexed queries on `principal_id` and `timestamp`, the two axes
    `AuditSink.query()` already filters on;
  - a hash chain over every stored record, so an edit, deletion, or
    reorder of past entries is detectable after the fact via `verify()`
    — see that method's docstring for exactly what it proves and what it
    doesn't.

Built entirely on top of the existing `AuditSink` interface
(`marshal_ai/audit.py`) — this module subclasses it and reuses the same
`kind` discriminator + `register_entry_type` registry `JSONLAuditSink`
uses to round-trip mixed entry types, rather than inventing a second
serialization scheme.

What this deliberately does *not* claim to solve: this is *your own
process's* record of its *own* governance decisions, made tamper-evident
after the fact. It proves the log of "what Marshal decided" hasn't been
silently altered since it was written. It says nothing about, and has no
way to check, whether a model vendor Marshal routed a call to actually
honors its retention/deletion promises downstream — that's the same
scope limit `ResidencyPolicy`/`RetentionPolicy` (`marshal_ai/models.py`)
already state explicitly for the routing decision itself; this module
just makes sure the *record* of that decision can't be quietly rewritten
later.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from marshal_ai.audit import AuditableEvent, AuditSink, decode_entry, is_denied

# `decode_entry` (audit.py) turns a decoded JSON dict back into the right
# dataclass via the `kind` discriminator + `register_entry_type` registry
# — exactly the reconstruction `JSONLAuditSink.all_entries` does. Reusing
# the public function here (instead of reimplementing the same three
# lines against the private `_ENTRY_TYPES` dict, or reaching into
# audit.py's own private `_decode_entry`) keeps there being exactly one
# place, publicly reachable, that knows how to turn a `kind` string back
# into a class.

# The hash that would precede the very first record in a chain: a fixed,
# known constant, not derived from any content, so `verify()` always has
# a deterministic anchor to start hashing forward from regardless of what
# the first real record turns out to contain.
GENESIS_HASH = "0" * 64


def _canonical_json(data: dict[str, Any]) -> str:
    """The exact bytes that get hashed for a record — same
    `json.dumps(..., sort_keys=True)` convention `JSONLAuditSink` already
    uses for its on-disk lines, so a `SQLiteAuditSink` and a
    `JSONLAuditSink` fed the same entries would hash identically. Key
    order must be deterministic for the hash to be reproducible at all;
    `sort_keys=True` is what guarantees that regardless of a dataclass's
    field-declaration order.
    """
    return json.dumps(data, sort_keys=True)


def _hash_link(prev_hash: str, canonical_data: str) -> str:
    """SHA-256 over the previous record's hash plus this record's own
    canonical content — the standard hash-chain construction (the same
    idea a Merkle log or a blockchain's block-hash uses): every hash
    commits to everything written before it, so changing, deleting, or
    reordering any earlier record changes this hash and every hash after
    it. `:` is an arbitrary but fixed separator between the two
    components — its only job is making the concatenation unambiguous;
    `prev_hash` is always a fixed-length hex digest so collision risk
    from the separator choice itself is not a real concern.
    """
    return hashlib.sha256(f"{prev_hash}:{canonical_data}".encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ChainVerificationResult:
    """Result of `SQLiteAuditSink.verify()`.

    `ok=True` means every stored record's hash matches a hash recomputed
    from (that record's own canonical content, the previous record's
    *stored* hash) — the chain is intact end to end, and `checked` is the
    total number of records that were walked.

    `ok=False` pinpoints the *first* record where that stops being true.
    A hash chain only proves integrity forward from a break, not backward
    past it — once one link is broken, records after it can't be trusted
    to be unaltered either (that's the entire point of chaining them),
    so `verify()` stops at the first break rather than continuing to
    report on records whose own guarantee has already been undermined.
    `broken_at_seq`/`broken_kind`/`broken_principal_id` identify the
    offending record without repeating its content — same discipline the
    audit trail itself follows: enough to locate the record and go
    inspect it directly, never a copy of what might be sensitive in it.
    """

    ok: bool
    checked: int
    broken_at_seq: Optional[int] = None
    broken_kind: Optional[str] = None
    broken_principal_id: Optional[str] = None
    reason: Optional[str] = None


class SQLiteAuditSink(AuditSink):
    """Persists every audit entry to a local SQLite database file —
    stdlib `sqlite3`, no new dependency. Survives process restart: a new
    `SQLiteAuditSink` opened over the same path picks up exactly where
    the last one left off, hash chain included.

    Mixed entry types (retrieval + tool-call + model-call + ...,
    written by different guards sharing this sink) round-trip correctly,
    the same way `JSONLAuditSink` handles them: each row stores its
    entry's `kind` discriminator alongside the canonical JSON body, and
    reads reconstruct the right dataclass via `register_entry_type`.

    Indexed on `principal_id` and `timestamp` — the two axes
    `AuditSink.query()` filters on — so `query()` pushes those filters
    down into SQL instead of loading and reconstructing the entire table
    for every call the way `JSONLAuditSink.query()` (inherited from the
    `AuditSink` base) necessarily does.

    Thread-safe within one process via an internal lock, the same
    guarantee `InMemoryAuditSink`/`JSONLAuditSink` make. Not coordinated
    across processes: two processes writing to the same file concurrently
    would each cache their own "last hash" and could each append a
    locally-consistent chain that diverges from the other's view, and
    SQLite's own file locking prevents corruption but not that logical
    race. Route all writes through a single process (e.g. one writer
    behind a queue) if you need multi-process durability; a single local
    script or service instance — the common case this sink targets — has
    exactly one writer already.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # check_same_thread=False: safe because every access (read or
        # write) below is serialized through self._lock — the same
        # single-connection-plus-lock shape sqlite3's own docs recommend
        # for sharing one connection across threads.
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_entries (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                timestamp REAL NOT NULL,
                principal_id TEXT NOT NULL,
                data TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_entries_principal_id "
            "ON audit_entries(principal_id)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_entries_timestamp "
            "ON audit_entries(timestamp)"
        )
        self._conn.commit()
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        row = self._conn.execute(
            "SELECT hash FROM audit_entries ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row[0] if row is not None else GENESIS_HASH

    def write(self, entry: AuditableEvent) -> None:
        data = entry.to_dict()
        canonical = _canonical_json(data)
        with self._lock:
            record_hash = _hash_link(self._last_hash, canonical)
            self._conn.execute(
                "INSERT INTO audit_entries "
                "(kind, timestamp, principal_id, data, prev_hash, hash) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    data["kind"],
                    entry.timestamp,
                    entry.principal_id,
                    canonical,
                    self._last_hash,
                    record_hash,
                ),
            )
            self._conn.commit()
            self._last_hash = record_hash

    def all_entries(self) -> list[AuditableEvent]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT data FROM audit_entries ORDER BY seq ASC"
            ).fetchall()
        return [decode_entry(json.loads(row[0])) for row in rows]

    def query(
        self,
        *,
        principal_id: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        denied_only: bool = False,
    ) -> list[AuditableEvent]:
        """Same filter semantics as `AuditSink.query` (inclusive
        `since`/`until`), overridden here to push `principal_id`/
        `since`/`until` down into indexed SQL predicates instead of
        reconstructing every row in the table and filtering in Python —
        the payoff of having durable, indexed storage in the first
        place. `denied_only` stays a Python-side pass using the shared
        `is_denied()` from `marshal_ai.audit`, the same duck-typed check
        every other sink uses, since "was this a denial" depends on
        which entry type a row decodes to, not on anything indexed.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if principal_id is not None:
            clauses.append("principal_id = ?")
            params.append(principal_id)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)
        if until is not None:
            clauses.append("timestamp <= ?")
            params.append(until)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._lock:
            rows = self._conn.execute(
                f"SELECT data FROM audit_entries {where} ORDER BY seq ASC",
                params,
            ).fetchall()
        entries = [decode_entry(json.loads(row[0])) for row in rows]
        if denied_only:
            entries = [e for e in entries if is_denied(e)]
        return entries

    def verify(self) -> ChainVerificationResult:
        """Walk the stored chain in insertion order and identify the
        first record where the recorded chain and a freshly recomputed
        chain diverge.

        For each record in turn: its stored `prev_hash` must equal the
        *previous* record's stored `hash` (catches a deleted or
        reordered record — the gap or swap breaks this link even though
        neither the missing nor the moved record is itself being
        inspected), and a hash recomputed from `_hash_link(prev_hash,
        data)` must equal the record's own stored `hash` (catches that
        record's `data` or `hash` having been edited directly). The walk
        starts from `GENESIS_HASH` so the very first record is checked
        against a known constant, not an unverified assumption.

        Deterministic: same stored rows always produce the same result,
        no wall-clock or environment dependence. Returns a structured
        result rather than raising, so a caller (e.g. a report generator
        that wants to state chain integrity as a fact in a compliance
        document) can inspect `ok` without wrapping every call in
        `try/except`.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, kind, principal_id, data, prev_hash, hash "
                "FROM audit_entries ORDER BY seq ASC"
            ).fetchall()

        expected_prev = GENESIS_HASH
        for checked, (seq, kind, principal_id, data, stored_prev, stored_hash) in enumerate(
            rows, start=1
        ):
            if stored_prev != expected_prev:
                return ChainVerificationResult(
                    ok=False,
                    checked=checked,
                    broken_at_seq=seq,
                    broken_kind=kind,
                    broken_principal_id=principal_id,
                    reason=(
                        "stored prev_hash does not match the previous record's hash "
                        "— a record before this one was edited, deleted, or reordered"
                    ),
                )
            recomputed_hash = _hash_link(stored_prev, data)
            if recomputed_hash != stored_hash:
                return ChainVerificationResult(
                    ok=False,
                    checked=checked,
                    broken_at_seq=seq,
                    broken_kind=kind,
                    broken_principal_id=principal_id,
                    reason=(
                        "stored hash does not match a hash recomputed from this "
                        "record's own content — this record's data or hash was "
                        "edited directly"
                    ),
                )
            expected_prev = stored_hash

        return ChainVerificationResult(ok=True, checked=len(rows))

    def close(self) -> None:
        """Close the underlying SQLite connection. Not part of the
        `AuditSink` interface (no other sink holds a resource that needs
        releasing) — call it when you're done writing, e.g. before
        another process or another `SQLiteAuditSink` instance opens the
        same file, to make sure everything is flushed and the file isn't
        held open longer than necessary."""
        with self._lock:
            self._conn.close()

    def __len__(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) FROM audit_entries").fetchone()
        return row[0]
