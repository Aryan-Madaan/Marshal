"""Operational health, computed from evidence — not declared.

    from marshal_ai.health import assess, record_heartbeat, render_health_markdown

    record_heartbeat(sink, "billing-agent")            # from the agent's own loop / a probe
    print(render_health_markdown(assess(sink, window_seconds=900)))

A registry can say an agent is "active"; only runtime evidence can say
whether it's *working*. `assess` derives a status for every tool, model
deployment and agent that appears in the audit trail, from what actually
happened in the trailing window:

| Status | Meaning |
|---|---|
| `healthy` | enough recent calls, error rate and latency within thresholds |
| `degraded` | error rate, p95 latency or (for agents) the denial rate is past the warning threshold |
| `failing` | error rate past the critical threshold, or a circuit breaker / runaway trip in the window |
| `idle` | alive (fresh heartbeat or recent decisions) but no calls in the window — *not* the same as stopped |
| `unknown` | heartbeats were expected and stopped arriving — telemetry loss, or the agent died |
| `not_instrumented` | decisions are recorded but no outcomes ever are, so health can't be judged |

Outcomes come from `ToolOutcomeEntry` (`ToolGuard(..., audit_outcomes=True)`,
the MCP session, framework hooks) and `ModelOutcomeEntry`
(`marshal_ai.integrations`). Denials are counted separately from
failures: a denial is governance working, but an agent whose calls are
mostly denied is behaving badly and is flagged `degraded`.

Every threshold is a parameter (`HealthThresholds`). The defaults are a
starting point for a busy service and will be wrong for some of yours —
set them per deployment.
"""

from __future__ import annotations

import math
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from marshal_ai._runctx import current_parent_run_id, current_run_id
from marshal_ai.audit import AuditSink, is_denied, register_entry_type

__all__ = ["HealthReport", "HealthThresholds", "HeartbeatEntry", "assess", "record_heartbeat", "render_health_markdown"]


@dataclass(frozen=True)
class HeartbeatEntry:
    """A liveness signal from an agent (or a synthetic probe), independent
    of user traffic. `ok=False` records a probe that ran and failed."""

    timestamp: float
    principal_id: str
    ok: bool = True
    on_behalf_of: list[str] = field(default_factory=list)
    run_id: Optional[str] = field(default_factory=current_run_id)
    parent_run_id: Optional[str] = field(default_factory=current_parent_run_id)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "heartbeat", **asdict(self)}


register_entry_type("heartbeat", HeartbeatEntry)


def record_heartbeat(sink: AuditSink, agent_id: str, ok: bool = True) -> None:
    sink.write(HeartbeatEntry(timestamp=time.time(), principal_id=agent_id, ok=ok))


@dataclass(frozen=True)
class HealthThresholds:
    min_samples: int = 5
    warn_error_rate: float = 0.10
    fail_error_rate: float = 0.25
    warn_p95_latency_ms: Optional[float] = None
    warn_denial_rate: float = 0.50  # agents only
    heartbeat_stale_seconds: float = 900.0


@dataclass(frozen=True)
class HealthReport:
    subject_kind: str  # "tool" | "model" | "agent"
    subject: str
    status: str
    reasons: list[str]
    calls: int
    failures: int
    error_rate: Optional[float]
    p95_latency_ms: Optional[float]
    denials: int
    last_seen: Optional[float]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class _Acc:
    outcomes: list[tuple[bool, Optional[float]]] = field(default_factory=list)
    decisions: int = 0
    denials: int = 0
    trips: int = 0
    last_seen: Optional[float] = None
    ever_had_outcomes: bool = False
    heartbeats: list[tuple[float, bool]] = field(default_factory=list)

    def seen(self, ts: float) -> None:
        self.last_seen = ts if self.last_seen is None else max(self.last_seen, ts)


def _p95(values: list[float]) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


_TRIP_MARKERS = ("circuit breaker open", "runaway-agent breaker tripped", "model runaway breaker tripped")


def assess(
    sink: AuditSink,
    window_seconds: float = 900.0,
    now: Optional[float] = None,
    thresholds: HealthThresholds = HealthThresholds(),
) -> list[HealthReport]:
    """Health of every tool, model deployment and agent in the trail,
    worst first."""
    now = now if now is not None else time.time()
    since = now - window_seconds
    subjects: dict[tuple[str, str], _Acc] = {}

    def acc(kind: str, name: str) -> _Acc:
        return subjects.setdefault((kind, name), _Acc())

    for entry in sink.all_entries():
        data = entry.to_dict()
        kind, ts, agent = data["kind"], entry.timestamp, entry.principal_id
        in_window = ts >= since
        if kind == "heartbeat":
            acc("agent", agent).heartbeats.append((ts, data.get("ok", True)))
            acc("agent", agent).seen(ts)
            continue
        if kind in ("tool_outcome", "model_outcome"):
            subject = ("tool", data["tool_name"]) if kind == "tool_outcome" else ("model", data["model"])
            for target in (acc(*subject), acc("agent", agent)):
                target.ever_had_outcomes = True
                target.seen(ts)
                if in_window:
                    target.outcomes.append((data["success"], data.get("latency_ms")))
            continue
        if kind in ("tool_call", "model_call"):
            subject = ("tool", data["tool_name"]) if kind == "tool_call" else ("model", data["logical_name"])
            denied = is_denied(entry)
            for target in (acc(*subject), acc("agent", agent)):
                target.seen(ts)
                if in_window:
                    target.decisions += 1
                    target.denials += int(denied)
                    target.trips += int(any(m in data.get("reason", "") for m in _TRIP_MARKERS))

    reports = [_judge(kind, name, a, now, thresholds) for (kind, name), a in subjects.items()]
    severity = {"failing": 0, "unknown": 1, "degraded": 2, "not_instrumented": 3, "idle": 4, "healthy": 5}
    return sorted(reports, key=lambda r: (severity[r.status], r.subject_kind, r.subject))


def _judge(kind: str, name: str, a: _Acc, now: float, t: HealthThresholds) -> HealthReport:
    calls = len(a.outcomes)
    failures = sum(1 for ok, _ in a.outcomes if not ok)
    rate = failures / calls if calls else None
    p95 = _p95([lat for _, lat in a.outcomes if lat is not None])
    reasons: list[str] = []
    status = "healthy"

    last_beat = max((ts for ts, _ in a.heartbeats), default=None)
    beats_failing = a.heartbeats and not sorted(a.heartbeats)[-1][1]

    if kind == "agent" and a.heartbeats and last_beat is not None and now - last_beat > t.heartbeat_stale_seconds:
        status = "unknown"
        reasons.append(f"no heartbeat for {int(now - last_beat)}s (stale after {int(t.heartbeat_stale_seconds)}s)")
    elif kind == "agent" and beats_failing:
        status = "failing"
        reasons.append("latest heartbeat probe failed")
    elif a.trips:
        status = "failing"
        reasons.append(f"{a.trips} call(s) refused by a tripped breaker in the window")
    elif calls == 0:
        if a.decisions and not a.ever_had_outcomes:
            status = "not_instrumented"
            reasons.append("decisions recorded but no outcomes — enable audit_outcomes / outcome reporting")
        else:
            status = "idle"
            reasons.append("no calls in the window")
    else:
        if calls < t.min_samples:
            reasons.append(f"only {calls} call(s) in the window — low confidence")
        if rate is not None and rate >= t.fail_error_rate and calls >= t.min_samples:
            status = "failing"
            reasons.append(f"error rate {rate:.0%} ≥ {t.fail_error_rate:.0%}")
        elif rate is not None and rate >= t.warn_error_rate and calls >= t.min_samples:
            status = "degraded"
            reasons.append(f"error rate {rate:.0%} ≥ {t.warn_error_rate:.0%}")
        if t.warn_p95_latency_ms is not None and p95 is not None and p95 > t.warn_p95_latency_ms and status == "healthy":
            status = "degraded"
            reasons.append(f"p95 latency {p95:.0f} ms > {t.warn_p95_latency_ms:.0f} ms")

    if kind == "agent" and status in ("healthy", "idle") and a.decisions >= t.min_samples:
        denial_rate = a.denials / a.decisions
        if denial_rate >= t.warn_denial_rate:
            status = "degraded"
            reasons.append(f"{denial_rate:.0%} of its calls were denied — misbehaving or misconfigured")

    return HealthReport(
        subject_kind=kind, subject=name, status=status, reasons=reasons, calls=calls, failures=failures,
        error_rate=rate, p95_latency_ms=p95, denials=a.denials, last_seen=a.last_seen,
    )


def render_health_markdown(reports: list[HealthReport]) -> str:
    lines = ["| Status | Kind | Subject | Calls | Errors | p95 ms | Denials | Why |", "|---|---|---|---|---|---|---|---|"]
    for r in reports:
        rate = f"{r.error_rate:.0%}" if r.error_rate is not None else "-"
        p95 = f"{r.p95_latency_ms:.0f}" if r.p95_latency_ms is not None else "-"
        why = "; ".join(r.reasons) or "-"
        lines.append(f"| {r.status} | {r.subject_kind} | {r.subject} | {r.calls} | {rate} | {p95} | {r.denials} | {why} |")
    return "\n".join(lines) + "\n"
