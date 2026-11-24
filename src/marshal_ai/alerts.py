"""Alert delivery: from "assess() says it's failing" to a person knowing.

    from marshal_ai.alerts import AlertManager, WebhookNotifier, alerts_from

    manager = AlertManager(
        "alerts.db",
        notifiers=[WebhookNotifier("https://hooks.ourcompany.example/marshal", secret=WEBHOOK_SECRET)],
        audit_sink=sink,
    )
    # from a scheduler, every minute or so (any number of processes may do this):
    manager.process(alerts_from(sink))

    # an operator, from the CLI:
    #   python -m marshal_ai.cli alerts ack alerts.db health:tool:track_shipment --as oncall@company --reason "on it"

`health.assess` and `incidents.incident_candidates` compute what's wrong;
this module makes sure someone hears about it exactly as often as they
should. The design is about delivery guarantees, not the HTTP call:

- **Deduplicated by key.** An alert has a stable key (e.g.
  `health:tool:track_shipment`). While it stays open it notifies once,
  then at most every `renotify_seconds` as a reminder — never once per
  `process()` call. When it disappears from the computed set it's
  resolved, and that is notified too.
- **Acknowledged.** `acknowledge(key, by, reason)` silences reminders for
  an open alert and is audited. If the alert gets *worse* (warning to
  critical) the acknowledgement is cleared and it notifies again: an ack
  covers what the person saw, not whatever it turns into.
- **At-least-once, through an outbox.** Every notification is a row in
  SQLite before anything is sent, per notifier. A worker leases rows,
  sends, then marks them delivered; a crash mid-send means the lease
  expires and the row is sent again. Failures retry with exponential
  backoff; after `max_attempts` a row is dead-lettered and audited, never
  dropped silently. Each notice carries a stable `delivery_id` so a
  receiver can discard the duplicates at-least-once implies.
- **Nothing sensitive in transit.** Notices carry subject names, counts
  and the health reasons — never principal ids from incident signals,
  arguments or content. Failure records keep the exception type, not its
  message (which can contain a URL with a token in it).

`WebhookNotifier` refuses redirects (a redirect would let the receiving
host point Marshal at any other host), refuses credentials embedded in
the URL, requires https unless told otherwise, can be checked against an
`EgressAllowlist`, and signs each body with HMAC-SHA256 over the
timestamp and body; `verify_webhook_signature` is the receiving side.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Protocol, Sequence

from marshal_ai._runctx import current_parent_run_id, current_run_id
from marshal_ai.audit import AuditSink, register_entry_type
from marshal_ai.egress import EgressAllowlist
from marshal_ai.health import HealthThresholds, assess
from marshal_ai.incidents import incident_candidates

__all__ = [
    "Alert", "AlertEntry", "AlertManager", "AlertNotice", "AlertRecord", "CallableNotifier", "Notifier",
    "ProcessResult", "WebhookNotifier", "alerts_from", "slack_payload", "verify_webhook_signature",
]

_SEVERITY_RANK = {"warning": 1, "critical": 2}


@dataclass(frozen=True)
class Alert:
    key: str  # stable identity used for deduplication
    severity: str  # "warning" | "critical"
    title: str
    detail: str
    source: str  # "health" | "signal" | anything you raise yourself

    def __post_init__(self) -> None:
        if self.severity not in _SEVERITY_RANK:
            raise ValueError("severity must be 'warning' or 'critical'")
        if not self.key:
            raise ValueError("an alert needs a key")


_HEALTH_SEVERITY = {"failing": "critical", "unknown": "critical", "degraded": "warning"}
_CRITICAL_SIGNALS = {"mcp_tool_changed", "mcp_tool_shadowed", "lethal_trifecta", "policy_error"}


def alerts_from(
    sink: AuditSink,
    window_seconds: float = 900.0,
    now: Optional[float] = None,
    thresholds: HealthThresholds = HealthThresholds(),
    signals: bool = True,
) -> list[Alert]:
    """The alerts the trail supports right now: every tool, model, agent
    or task that `assess` rates failing / unknown (critical) or degraded
    (warning), plus — with `signals` — incident-triage signals seen in the
    window. Idle and not-instrumented subjects don't alert."""
    now = time.time() if now is None else now
    out = []
    for report in assess(sink, window_seconds=window_seconds, now=now, thresholds=thresholds):
        severity = _HEALTH_SEVERITY.get(report.status)
        if severity:
            out.append(Alert(
                key=f"health:{report.subject_kind}:{report.subject}", severity=severity,
                title=f"{report.subject_kind} {report.subject} is {report.status}",
                detail="; ".join(report.reasons), source="health",
            ))
    if signals:
        for sig in incident_candidates(sink, since=now - window_seconds):
            out.append(Alert(
                key=f"signal:{sig.signal}",
                severity="critical" if sig.signal in _CRITICAL_SIGNALS else "warning",
                title=f"{sig.signal.replace('_', ' ')} ({sig.count} in the last {int(window_seconds)}s)",
                detail=f"{sig.count} event(s) from {len(sig.principals)} principal(s); triage with incident_candidates()",
                source="signal",
            ))
    return out


@dataclass(frozen=True)
class AlertNotice:
    """What a notifier receives. `delivery_id` is stable across retries."""

    delivery_id: str
    event: str  # "opened" | "reminder" | "escalated" | "resolved"
    key: str
    severity: str
    title: str
    detail: str
    source: str
    first_seen: float
    at: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Notifier(Protocol):
    name: str

    def send(self, notice: AlertNotice) -> None:
        """Deliver or raise. Returning normally means delivered."""


class CallableNotifier:
    """Adapts any `fn(notice)` — a pager client, an email sender, a test
    list — into a notifier."""

    def __init__(self, fn: Callable[[AlertNotice], Any], name: str = "callable") -> None:
        self.name = name
        self._fn = fn

    def send(self, notice: AlertNotice) -> None:
        self._fn(notice)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: Any, msg: Any, headers: Any, newurl: Any) -> None:
        return None  # urllib then raises HTTPError for the 3xx


def _sign(secret: bytes, timestamp: str, body: bytes) -> str:
    return hmac.new(secret, timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()


def verify_webhook_signature(
    secret: bytes, body: bytes, header: str, tolerance_seconds: float = 300.0, now: Optional[float] = None
) -> bool:
    """Receiver side: check a `Marshal-Signature: t=<unix>,v1=<hex>`
    header against the raw request body. Rejects stale timestamps (replay)."""
    try:
        parts = dict(item.split("=", 1) for item in header.split(","))
        timestamp, signature = parts["t"].strip(), parts["v1"].strip()
        age = abs((time.time() if now is None else now) - int(timestamp))
    except (KeyError, ValueError):
        return False
    if age > tolerance_seconds:
        return False
    return hmac.compare_digest(_sign(secret, timestamp, body), signature)


def slack_payload(notice: AlertNotice) -> dict[str, Any]:
    """A `formatter` for Slack-compatible incoming webhooks."""
    mark = {"resolved": "resolved", "escalated": "ESCALATED"}.get(notice.event, notice.severity.upper())
    return {"text": f"[{mark}] {notice.title}\n{notice.detail}\n`{notice.key}`"}


class WebhookNotifier:
    def __init__(
        self,
        url: str,
        secret: Optional[bytes] = None,
        name: str = "webhook",
        allowlist: Optional[EgressAllowlist] = None,
        timeout_seconds: float = 5.0,
        allow_http: bool = False,
        formatter: Optional[Callable[[AlertNotice], dict[str, Any]]] = None,
    ) -> None:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in (("https", "http") if allow_http else ("https",)):
            raise ValueError("webhook URL must be https (pass allow_http=True for a local receiver)")
        if not parsed.hostname:
            raise ValueError("webhook URL has no host")
        if parsed.username or parsed.password:
            raise ValueError("credentials in the webhook URL are refused; use `secret` to sign requests")
        if allowlist is not None and not allowlist.is_allowed(parsed.hostname):
            raise ValueError("webhook host is not in the egress allowlist")
        if secret is not None and len(secret) < 16:
            raise ValueError("secret must be at least 16 bytes")
        self.name = name
        self._url = url
        self._secret = secret
        self._timeout = timeout_seconds
        self._formatter = formatter
        self._opener = urllib.request.build_opener(_NoRedirect())

    def send(self, notice: AlertNotice) -> None:
        payload = self._formatter(notice) if self._formatter else notice.to_dict()
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "marshal-ai-alerts",
            "Marshal-Delivery-Id": notice.delivery_id,
        }
        if self._secret is not None:
            timestamp = str(int(time.time()))
            headers["Marshal-Signature"] = f"t={timestamp},v1={_sign(self._secret, timestamp, body)}"
        request = urllib.request.Request(self._url, data=body, headers=headers, method="POST")
        with self._opener.open(request, timeout=self._timeout) as response:  # raises on 3xx/4xx/5xx
            response.read(65536)
            if not 200 <= response.status < 300:
                raise urllib.error.HTTPError(self._url, response.status, "non-2xx", response.headers, None)


@dataclass(frozen=True)
class AlertEntry:
    timestamp: float
    principal_id: str  # "marshal", or the operator who acknowledged
    action: str  # "opened" | "escalated" | "resolved" | "acknowledged" | "dead_letter"
    alert_key: str
    severity: str
    notifier: Optional[str] = None
    detail: Optional[str] = None  # ack reason, or the dead-lettered error type
    on_behalf_of: list[str] = field(default_factory=list)
    run_id: Optional[str] = field(default_factory=current_run_id)
    parent_run_id: Optional[str] = field(default_factory=current_parent_run_id)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "alert", **asdict(self)}


register_entry_type("alert", AlertEntry)


@dataclass(frozen=True)
class AlertRecord:
    key: str
    state: str  # "open" | "acknowledged" | "resolved"
    severity: str
    title: str
    detail: str
    source: str
    first_seen: float
    last_seen: float
    acknowledged_by: Optional[str]
    acknowledged_reason: Optional[str]


@dataclass(frozen=True)
class ProcessResult:
    opened: list[str] = field(default_factory=list)
    escalated: list[str] = field(default_factory=list)
    reminded: list[str] = field(default_factory=list)
    resolved: list[str] = field(default_factory=list)
    delivered: int = 0
    retrying: int = 0
    dead_lettered: int = 0


_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    key TEXT PRIMARY KEY, state TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL,
    detail TEXT NOT NULL, source TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
    last_notified REAL NOT NULL, acked_by TEXT, acked_reason TEXT
);
CREATE TABLE IF NOT EXISTS outbox (
    delivery_id TEXT PRIMARY KEY, notifier TEXT NOT NULL, key TEXT NOT NULL, payload TEXT NOT NULL,
    state TEXT NOT NULL, attempts INTEGER NOT NULL, next_attempt REAL NOT NULL, lease_until REAL NOT NULL,
    last_error TEXT, created REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox (state, next_attempt);
"""
_COLUMNS = "key, state, severity, title, detail, source, first_seen, last_seen, acked_by, acked_reason"


class AlertManager:
    def __init__(
        self,
        path: "str | Path",
        notifiers: Sequence[Notifier] = (),
        audit_sink: Optional[AuditSink] = None,
        renotify_seconds: float = 3600.0,
        max_attempts: int = 8,
        backoff_seconds: float = 30.0,
        max_backoff_seconds: float = 3600.0,
        lease_seconds: float = 60.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        names = [n.name for n in notifiers]
        if len(set(names)) != len(names):
            raise ValueError("notifier names must be unique — they key the outbox")
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        self._notifiers = {n.name: n for n in notifiers}
        self._audit_sink = audit_sink
        self._renotify = renotify_seconds
        self._max_attempts = max_attempts
        self._backoff = backoff_seconds
        self._max_backoff = max_backoff_seconds
        self._lease = lease_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(Path(path), check_same_thread=False, isolation_level=None, timeout=10)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)

    # --- state ----------------------------------------------------------------

    def _tx(self) -> "_Tx":
        return _Tx(self._conn, self._lock)

    def _enqueue(self, event: str, alert: Alert, first_seen: float, now: float) -> None:
        for name in self._notifiers:
            notice = AlertNotice(
                delivery_id=uuid.uuid4().hex, event=event, key=alert.key, severity=alert.severity,
                title=alert.title, detail=alert.detail, source=alert.source, first_seen=first_seen, at=now,
            )
            self._conn.execute(
                "INSERT INTO outbox VALUES (?, ?, ?, ?, 'pending', 0, ?, 0, NULL, ?)",
                (notice.delivery_id, name, alert.key, json.dumps(notice.to_dict()), now, now),
            )

    def _audit(self, action: str, key: str, severity: str, by: str = "marshal",
               notifier: Optional[str] = None, detail: Optional[str] = None) -> None:
        if self._audit_sink is not None:
            self._audit_sink.write(AlertEntry(self._clock(), by, action, key, severity, notifier, detail))

    def process(self, alerts: Iterable[Alert], deliver: bool = True) -> ProcessResult:
        """Reconcile the currently-true alerts with stored state, enqueue
        what needs notifying, then (by default) deliver what's due. Safe to
        call from several processes at once."""
        current = {}
        for alert in alerts:  # duplicates in one batch: keep the most severe
            if alert.key not in current or _SEVERITY_RANK[alert.severity] > _SEVERITY_RANK[current[alert.key].severity]:
                current[alert.key] = alert
        now = self._clock()
        result = ProcessResult()
        events: list[tuple[str, str, str]] = []
        with self._tx():
            stored = {row[0]: row for row in self._conn.execute(
                "SELECT key, state, severity, first_seen, last_notified FROM alerts WHERE state != 'resolved'")}
            for key, alert in current.items():
                row = stored.get(key)
                if row is None:
                    self._conn.execute(
                        "INSERT OR REPLACE INTO alerts VALUES (?, 'open', ?, ?, ?, ?, ?, ?, ?, NULL, NULL)",
                        (key, alert.severity, alert.title, alert.detail, alert.source, now, now, now),
                    )
                    self._enqueue("opened", alert, now, now)
                    result.opened.append(key)
                    events.append(("opened", key, alert.severity))
                    continue
                _, state, severity, first_seen, last_notified = row
                worse = _SEVERITY_RANK[alert.severity] > _SEVERITY_RANK[severity]
                due = state == "open" and now - last_notified >= self._renotify
                self._conn.execute(
                    "UPDATE alerts SET severity = ?, title = ?, detail = ?, last_seen = ? WHERE key = ?",
                    (alert.severity, alert.title, alert.detail, now, key),
                )
                if worse:
                    self._conn.execute(
                        "UPDATE alerts SET state = 'open', acked_by = NULL, acked_reason = NULL, last_notified = ? "
                        "WHERE key = ?", (now, key))
                    self._enqueue("escalated", alert, first_seen, now)
                    result.escalated.append(key)
                    events.append(("escalated", key, alert.severity))
                elif due:
                    self._conn.execute("UPDATE alerts SET last_notified = ? WHERE key = ?", (now, key))
                    self._enqueue("reminder", alert, first_seen, now)
                    result.reminded.append(key)
            for key, row in stored.items():
                if key in current:
                    continue
                full = self._conn.execute(
                    "SELECT severity, title, detail, source, first_seen FROM alerts WHERE key = ?", (key,)).fetchone()
                self._conn.execute("UPDATE alerts SET state = 'resolved', last_seen = ? WHERE key = ?", (now, key))
                self._enqueue("resolved", Alert(key, full[0], full[1], full[2], full[3]), full[4], now)
                result.resolved.append(key)
                events.append(("resolved", key, full[0]))
        for action, key, severity in events:
            self._audit(action, key, severity)
        if deliver:
            delivered, retrying, dead = self.deliver()
            return ProcessResult(result.opened, result.escalated, result.reminded, result.resolved,
                                 delivered, retrying, dead)
        return result

    def acknowledge(self, key: str, by: str, reason: str) -> None:
        if not by or not reason:
            raise ValueError("by and reason are required — acknowledgements are audited")
        with self._tx():
            row = self._conn.execute("SELECT state, severity FROM alerts WHERE key = ?", (key,)).fetchone()
            if row is None or row[0] == "resolved":
                raise KeyError(f"no open alert {key!r}")
            self._conn.execute(
                "UPDATE alerts SET state = 'acknowledged', acked_by = ?, acked_reason = ? WHERE key = ?",
                (by, reason, key))
        self._audit("acknowledged", key, row[1], by=by, detail=reason)

    # --- delivery -------------------------------------------------------------

    def deliver(self) -> tuple[int, int, int]:
        """Send every due outbox row once. Returns (delivered, retrying,
        dead-lettered). Rows for a notifier this manager doesn't have stay
        queued for a process that does."""
        if not self._notifiers:
            return 0, 0, 0
        now = self._clock()
        placeholders = ", ".join("?" for _ in self._notifiers)
        with self._tx():
            rows = self._conn.execute(
                f"SELECT delivery_id, notifier, key, payload, attempts FROM outbox WHERE state = 'pending' "
                f"AND next_attempt <= ? AND lease_until <= ? AND notifier IN ({placeholders}) ORDER BY created",
                (now, now, *self._notifiers),
            ).fetchall()
            for row in rows:  # lease them so a concurrent worker skips them
                self._conn.execute("UPDATE outbox SET lease_until = ? WHERE delivery_id = ?", (now + self._lease, row[0]))
        delivered = retrying = dead = 0
        for delivery_id, notifier, key, payload, attempts in rows:
            notice = AlertNotice(**json.loads(payload))
            try:
                self._notifiers[notifier].send(notice)
            except Exception as exc:
                attempts += 1
                error = type(exc).__name__
                if attempts >= self._max_attempts:
                    with self._tx():
                        self._conn.execute(
                            "UPDATE outbox SET state = 'dead', attempts = ?, last_error = ?, lease_until = 0 "
                            "WHERE delivery_id = ?", (attempts, error, delivery_id))
                    self._audit("dead_letter", key, notice.severity, notifier=notifier, detail=error)
                    dead += 1
                else:
                    wait = min(self._backoff * 2 ** (attempts - 1), self._max_backoff)
                    with self._tx():
                        self._conn.execute(
                            "UPDATE outbox SET attempts = ?, last_error = ?, next_attempt = ?, lease_until = 0 "
                            "WHERE delivery_id = ?", (attempts, error, self._clock() + wait, delivery_id))
                    retrying += 1
                continue
            with self._tx():
                self._conn.execute(
                    "UPDATE outbox SET state = 'delivered', attempts = ?, lease_until = 0 WHERE delivery_id = ?",
                    (attempts + 1, delivery_id))
            delivered += 1
        return delivered, retrying, dead

    # --- inspection -----------------------------------------------------------

    def alerts(self, include_resolved: bool = False) -> list[AlertRecord]:
        where = "" if include_resolved else "WHERE state != 'resolved'"
        with self._lock:
            rows = self._conn.execute(f"SELECT {_COLUMNS} FROM alerts {where} ORDER BY first_seen").fetchall()
        return [AlertRecord(*row) for row in rows]

    def dead_letters(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT delivery_id, notifier, key, attempts, last_error, created FROM outbox "
                "WHERE state = 'dead' ORDER BY created").fetchall()
        return [dict(zip(("delivery_id", "notifier", "key", "attempts", "last_error", "created"), r)) for r in rows]

    def pending(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM outbox WHERE state = 'pending'").fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class _Tx:
    def __init__(self, conn: sqlite3.Connection, lock: threading.Lock) -> None:
        self._conn = conn
        self._lock = lock

    def __enter__(self) -> None:
        self._lock.acquire()
        try:
            self._conn.execute("BEGIN IMMEDIATE")
        except BaseException:
            self._lock.release()
            raise

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        try:
            self._conn.execute("ROLLBACK" if exc_type is not None else "COMMIT")
        finally:
            self._lock.release()
