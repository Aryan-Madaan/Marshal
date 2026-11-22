"""A durable approval queue: human-in-the-loop that doesn't block a terminal.

`CLIApprovalHandler` asks on stdin, which only works for a person sitting
at the process. Real deployments need the request to wait somewhere a
reviewer can see it — a Slack button, a ticket, an admin page — and the
agent to pick the decision up later, possibly in another process.
`ApprovalQueue` is that somewhere: stdlib `sqlite3`, no new dependency,
safe across threads and processes.

    queue = ApprovalQueue("approvals.db")
    guard = ToolGuard(tool=issue_refund, policy=policy,
                      approval_handler=QueuedApprovalHandler(queue, wait_seconds=0))

    try:
        guard.call(agent, {"order_id": "42", "amount": 500}, risk_tier="medium")
    except ApprovalPending as pending:
        notify_reviewers(pending.approval_id)   # your Slack/ticket integration

    # elsewhere, a reviewer (or `python -m marshal_ai.cli approvals approve ...`):
    queue.approve(approval_id, approver="maria@company")

    # the agent retries the *identical* call; now it runs, exactly once:
    guard.call(agent, {"order_id": "42", "amount": 500}, risk_tier="medium")

Three properties matter, and each is enforced in SQL rather than trusted:

- **An approval releases exactly the call that was reviewed.** Each
  request is keyed by an HMAC over (tool, raw arguments, principal and
  delegation chain, risk tier). Change one argument and it's a different
  request that needs its own approval — an approval for a $5 refund can't
  be spent on a $5,000 one. The HMAC key is random per queue, so the
  stored digest can't be used to guess low-entropy argument values (a
  salary, a yes/no) offline; raw arguments are never stored, only the
  redacted view a reviewer is allowed to see.
- **Single use.** Consuming an approval is one conditional `UPDATE ...
  WHERE status = 'approved'`; two processes retrying the same call can't
  both spend it.
- **Expiry.** A request nobody decides within `ttl_seconds` (default 15
  minutes) expires, and an approval not used within the same window
  expires too — a stale "yes" from yesterday doesn't release today's call.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from marshal_ai.tools import ApprovalHandler, ApprovalPending, ToolCallRequest

_SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    call_digest TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    on_behalf_of TEXT NOT NULL,
    risk_tier TEXT NOT NULL,
    redacted_arguments TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    decided_at REAL,
    decided_by TEXT,
    note TEXT
);
CREATE INDEX IF NOT EXISTS approvals_digest ON approvals (call_digest, status);
CREATE INDEX IF NOT EXISTS approvals_status ON approvals (status, created_at);
CREATE TABLE IF NOT EXISTS approval_meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
"""


@dataclass(frozen=True)
class ApprovalRequest:
    id: str
    tool_name: str
    principal_id: str
    on_behalf_of: list[str]
    risk_tier: str
    redacted_arguments: dict[str, Any]
    status: str  # "pending" | "approved" | "declined" | "expired" | "used"
    created_at: float
    expires_at: float
    decided_at: Optional[float] = None
    decided_by: Optional[str] = None
    note: Optional[str] = None


class ApprovalQueue:
    def __init__(self, path: "str | Path", ttl_seconds: float = 900.0) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._path = Path(path)
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None, timeout=30)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._key = self._load_key()

    def _load_key(self) -> bytes:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute("SELECT value FROM approval_meta WHERE key = 'hmac_key'").fetchone()
                if row is None:
                    key = os.urandom(32)
                    self._conn.execute("INSERT INTO approval_meta (key, value) VALUES ('hmac_key', ?)", (key,))
                else:
                    key = bytes(row[0])
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
        return key

    def digest(self, request: ToolCallRequest) -> str:
        """The HMAC identifying exactly this call."""
        payload = json.dumps(
            {
                "tool": request.tool_name,
                "arguments": request.arguments,
                "principal": [request.principal.id, *request.principal.delegation_chain],
                "risk_tier": request.risk_tier,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=repr,
        )
        return hmac.new(self._key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def _expire_locked(self, now: float) -> None:
        self._conn.execute(
            "UPDATE approvals SET status = 'expired' WHERE status IN ('pending', 'approved') AND expires_at <= ?",
            (now,),
        )

    def submit(self, request: ToolCallRequest, redacted_arguments: dict[str, Any]) -> ApprovalRequest:
        """Queue `request` for review, or return the live (pending or
        approved, unexpired) request for the identical call if one exists."""
        call_digest = self.digest(request)
        now = time.time()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._expire_locked(now)
                row = self._conn.execute(
                    "SELECT id FROM approvals WHERE call_digest = ? AND status IN ('pending', 'approved') "
                    "ORDER BY created_at DESC LIMIT 1",
                    (call_digest,),
                ).fetchone()
                if row is None:
                    approval_id = f"apr-{uuid.uuid4().hex[:16]}"
                    self._conn.execute(
                        "INSERT INTO approvals (id, call_digest, tool_name, principal_id, on_behalf_of, risk_tier, "
                        "redacted_arguments, status, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
                        (
                            approval_id, call_digest, request.tool_name, request.principal.id,
                            json.dumps(request.principal.delegation_chain), request.risk_tier,
                            json.dumps(redacted_arguments, sort_keys=True, default=repr),
                            now, now + self._ttl,
                        ),
                    )
                else:
                    approval_id = row[0]
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
        return self.get(approval_id)

    def _decide(self, approval_id: str, status: str, decided_by: str, note: Optional[str]) -> ApprovalRequest:
        if not decided_by:
            raise ValueError("decided_by is required — the audit trail records who decided")
        now = time.time()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._expire_locked(now)
                # An approval gets a fresh window to be used in.
                cursor = self._conn.execute(
                    "UPDATE approvals SET status = ?, decided_at = ?, decided_by = ?, note = ?, "
                    "expires_at = CASE WHEN ? = 'approved' THEN ? ELSE expires_at END "
                    "WHERE id = ? AND status = 'pending'",
                    (status, now, decided_by, note, status, now + self._ttl, approval_id),
                )
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
        if cursor.rowcount != 1:
            current = self.get(approval_id)
            raise ValueError(f"approval {approval_id!r} is {current.status}, not pending")
        return self.get(approval_id)

    def approve(self, approval_id: str, approver: str, note: Optional[str] = None) -> ApprovalRequest:
        return self._decide(approval_id, "approved", approver, note)

    def decline(self, approval_id: str, approver: str, note: Optional[str] = None) -> ApprovalRequest:
        return self._decide(approval_id, "declined", approver, note)

    def consume(self, request: ToolCallRequest) -> Optional[ApprovalRequest]:
        """Atomically spend an approval for exactly this call. Returns the
        approval it used, or None if there is no unexpired, approved,
        unused one."""
        call_digest = self.digest(request)
        now = time.time()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._expire_locked(now)
                row = self._conn.execute(
                    "SELECT id FROM approvals WHERE call_digest = ? AND status = 'approved' "
                    "ORDER BY decided_at ASC LIMIT 1",
                    (call_digest,),
                ).fetchone()
                used = None
                if row is not None:
                    cursor = self._conn.execute(
                        "UPDATE approvals SET status = 'used' WHERE id = ? AND status = 'approved'", (row[0],)
                    )
                    used = row[0] if cursor.rowcount == 1 else None
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
        return self.get(used) if used else None

    def recently_declined(self, request: ToolCallRequest) -> Optional[ApprovalRequest]:
        """A decline of exactly this call within the last `ttl_seconds`.
        Retrying a declined call inside that window is declined again
        without asking anyone (no reviewer spam from a looping agent);
        after it, an identical call may be reviewed afresh."""
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM approvals WHERE call_digest = ? AND status = 'declined' AND decided_at > ? "
                "ORDER BY decided_at DESC LIMIT 1",
                (self.digest(request), time.time() - self._ttl),
            ).fetchone()
        return self.get(row[0]) if row else None

    def get(self, approval_id: str) -> ApprovalRequest:
        with self._lock:
            self._expire_locked(time.time())
            row = self._conn.execute(
                "SELECT id, tool_name, principal_id, on_behalf_of, risk_tier, redacted_arguments, status, "
                "created_at, expires_at, decided_at, decided_by, note FROM approvals WHERE id = ?",
                (approval_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"no approval {approval_id!r}")
        return ApprovalRequest(
            id=row[0], tool_name=row[1], principal_id=row[2], on_behalf_of=json.loads(row[3]),
            risk_tier=row[4], redacted_arguments=json.loads(row[5]), status=row[6], created_at=row[7],
            expires_at=row[8], decided_at=row[9], decided_by=row[10], note=row[11],
        )

    def pending(self) -> list[ApprovalRequest]:
        with self._lock:
            self._expire_locked(time.time())
            ids = [r[0] for r in self._conn.execute(
                "SELECT id FROM approvals WHERE status = 'pending' ORDER BY created_at ASC"
            ).fetchall()]
        return [self.get(i) for i in ids]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class QueuedApprovalHandler(ApprovalHandler):
    """`ApprovalHandler` backed by an `ApprovalQueue`.

    `wait_seconds=0` (non-blocking): if the identical call has an unused
    approval, spend it and proceed; otherwise queue it (once) and raise
    `ApprovalPending` — retry the same call after it's decided. With
    `wait_seconds > 0`, poll for a decision up to that long before raising
    `ApprovalPending`. A declined or expired request is a decline.
    """

    identity = "approval-queue"

    def __init__(self, queue: ApprovalQueue, wait_seconds: float = 0.0, poll_seconds: float = 1.0) -> None:
        self._queue = queue
        self._wait = wait_seconds
        self._poll = poll_seconds
        self._approvers: dict[str, str] = {}
        self._approvers_lock = threading.Lock()

    def request_approval(self, request: ToolCallRequest, redacted_arguments: dict[str, Any]) -> bool:
        deadline = time.monotonic() + self._wait
        submitted: Optional[ApprovalRequest] = None
        while True:
            used = self._queue.consume(request)
            if used is not None:
                with self._approvers_lock:
                    self._approvers[self._queue.digest(request)] = used.decided_by or self.identity
                return True
            if submitted is None:
                if self._queue.recently_declined(request) is not None:
                    return False
                submitted = self._queue.submit(request, redacted_arguments)
            else:
                current = self._queue.get(submitted.id)
                if current.status in ("declined", "expired"):
                    return False
            if time.monotonic() >= deadline:
                raise ApprovalPending(request.tool_name, submitted.id)
            time.sleep(self._poll)

    def approved_by(self, request: ToolCallRequest) -> str:
        with self._approvers_lock:
            return self._approvers.pop(self._queue.digest(request), self.identity)


async def wait_for_decision(queue: ApprovalQueue, approval_id: str, timeout: float, poll_seconds: float = 1.0) -> str:
    """Async helper: wait until `approval_id` leaves "pending" (or
    `timeout` passes) without blocking the event loop. Returns the final
    status — then retry the call to spend an approval."""
    deadline = time.monotonic() + timeout
    while True:
        status = queue.get(approval_id).status
        if status != "pending" or time.monotonic() >= deadline:
            return status
        await asyncio.sleep(poll_seconds)
