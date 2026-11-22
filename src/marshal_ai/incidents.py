"""Serious-incident support shaped by EU AI Act Article 73.

Article 73 requires a high-risk AI system's provider to report a
"serious incident" (Article 3(49): death or serious harm to health,
serious and irreversible disruption of critical infrastructure,
infringement of fundamental-rights obligations, or serious harm to
property or the environment) to the market surveillance authority:

- no later than 15 days after becoming aware of it (Art. 73(2));
- no later than 2 days for a widespread infringement, or for a serious
  incident under Art. 3(49)(b) — critical infrastructure (Art. 73(3));
- no later than 10 days in the event of a death (Art. 73(4)).

A deployer that identifies a serious incident must inform the provider
"immediately" (Art. 26(5)); this module uses 24 hours for that, a common
reading of the Commission's September 2025 draft guidance, configurable
via `deployer_notice_hours`. Not legal advice — check the final guidance
and your counsel's reading before relying on any deadline here.

What this module does and deliberately doesn't do. Deciding that
something *is* a serious incident is a legal and factual judgment no
library can make, so nothing here ever declares one automatically:

1. `incident_candidates(sink)` surfaces deterministic *signals* from the
   audit trail worth a human look — blocked exfiltration, lethal-trifecta
   escalations, changed MCP tool definitions, tripped runaway breakers,
   blocked credentials — grouped, with counts and time ranges.
2. `record_incident(sink, ...)` is the human declaration, written into
   the same audit trail as an `IncidentEntry` (so in a `SQLiteAuditSink`
   it's hash-chained like everything else, and the awareness time — which
   starts the clock — can't be quietly moved later).
3. `serious_incident_report(sink, incident_id)` computes the applicable
   deadlines and assembles the evidence: the related audit activity in
   the incident's window (counts and outcomes only, never content) and,
   for a sink that supports it, hash-chain verification.
"""

from __future__ import annotations

import time
import uuid
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from marshal_ai.audit import AuditSink, is_denied, register_entry_type
from marshal_ai.policy import Principal

IncidentCategory = Literal[
    "death_or_serious_harm",  # Art. 3(49)(a)
    "critical_infrastructure",  # Art. 3(49)(b)
    "fundamental_rights",  # Art. 3(49)(c)
    "property_or_environment",  # Art. 3(49)(d)
]
_CATEGORIES = ("death_or_serious_harm", "critical_infrastructure", "fundamental_rights", "property_or_environment")
_DAY = 86_400.0


@dataclass(frozen=True)
class IncidentEntry:
    """A human's declaration that a serious incident occurred. `aware_at`
    (Unix time) is when the organization became aware — what Article 73's
    deadlines count from. `window_start`/`window_end` bound the audit
    activity the report treats as related."""

    timestamp: float
    principal_id: str  # who declared it
    incident_id: str
    title: str
    category: str
    description: str
    aware_at: float
    role: str  # "provider" | "deployer"
    death: bool = False
    widespread: bool = False
    affected_principals: list[str] = field(default_factory=list)
    window_start: Optional[float] = None
    window_end: Optional[float] = None
    on_behalf_of: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "incident", **asdict(self)}


register_entry_type("incident", IncidentEntry)


def record_incident(
    sink: AuditSink,
    declared_by: Principal,
    *,
    title: str,
    category: IncidentCategory,
    description: str,
    role: Literal["provider", "deployer"] = "deployer",
    aware_at: Optional[float] = None,
    death: bool = False,
    widespread: bool = False,
    affected_principals: tuple[str, ...] = (),
    window_start: Optional[float] = None,
    window_end: Optional[float] = None,
) -> IncidentEntry:
    """Write a serious-incident declaration into the audit trail and
    return it. `aware_at` defaults to now. Keep `description` factual and
    free of personal data — it's stored in the audit trail verbatim."""
    if category not in _CATEGORIES:
        raise ValueError(f"category must be one of {list(_CATEGORIES)}")
    if role not in ("provider", "deployer"):
        raise ValueError("role must be 'provider' or 'deployer'")
    now = time.time()
    entry = IncidentEntry(
        timestamp=now,
        principal_id=declared_by.id,
        incident_id=f"inc-{uuid.uuid4().hex[:12]}",
        title=title,
        category=category,
        description=description,
        aware_at=aware_at if aware_at is not None else now,
        role=role,
        death=death,
        widespread=widespread,
        affected_principals=list(affected_principals),
        window_start=window_start,
        window_end=window_end,
        on_behalf_of=declared_by.delegation_chain,
    )
    sink.write(entry)
    return entry


# --- triage signals ------------------------------------------------------------


@dataclass(frozen=True)
class IncidentSignal:
    signal: str
    count: int
    first_seen: float
    last_seen: float
    principals: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _signal_of(data: dict[str, Any]) -> Optional[str]:
    kind = data.get("kind")
    shadow = data.get("shadow", False)
    if kind == "egress" and data.get("action") == "blocked":
        return "exfiltration_blocked"
    if kind == "sensitive_data" and data.get("action") == "blocked":
        return "credential_blocked"
    if kind == "mcp_tool_definition" and data.get("status") in ("changed", "shadowed"):
        return f"mcp_tool_{data['status']}"
    if kind == "tool_call":
        reason = data.get("reason", "")
        if "lethal trifecta" in reason:
            return "lethal_trifecta" + ("_shadow" if shadow else "")
        if "runaway-agent breaker tripped" in reason:
            return "runaway_agent"
        if "failing closed" in reason:
            return "policy_error"
    return None


def incident_candidates(
    sink: AuditSink, since: Optional[float] = None, until: Optional[float] = None
) -> list[IncidentSignal]:
    """Deterministic signals in the audit trail that may warrant incident
    triage, most frequent first. These are prompts for a human, never a
    finding: a blocked exfiltration attempt is governance *working*, but a
    burst of them can be the visible edge of a real compromise."""
    buckets: dict[str, list[tuple[float, str]]] = {}
    for entry in sink.query(since=since, until=until):
        signal = _signal_of(entry.to_dict())
        if signal is not None:
            buckets.setdefault(signal, []).append((entry.timestamp, entry.principal_id))
    signals = [
        IncidentSignal(
            signal=name,
            count=len(items),
            first_seen=min(t for t, _ in items),
            last_seen=max(t for t, _ in items),
            principals=sorted({p for _, p in items}),
        )
        for name, items in buckets.items()
    ]
    return sorted(signals, key=lambda s: (-s.count, s.signal))


# --- report ---------------------------------------------------------------------


@dataclass(frozen=True)
class IncidentReport:
    incident: dict[str, Any]
    legal_basis: str
    authority_deadline: float  # provider -> market surveillance authority
    authority_days: int
    deployer_notice_deadline: Optional[float]  # deployer -> provider
    generated_at: float
    overdue: bool
    seconds_remaining: float
    related_activity: dict[str, dict[str, int]]  # kind -> outcome -> count
    related_entries: int
    signals: list[dict[str, Any]]
    chain_ok: Optional[bool]
    chain_checked: Optional[int]
    chain_reason: Optional[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _deadline_days(entry: IncidentEntry) -> tuple[int, str]:
    if entry.widespread or entry.category == "critical_infrastructure":
        return 2, "Art. 73(3) — widespread infringement or Art. 3(49)(b) critical infrastructure"
    if entry.death:
        return 10, "Art. 73(4) — death of a person"
    return 15, "Art. 73(2) — serious incident"


def _outcome_of(data: dict[str, Any]) -> str:
    for key in ("outcome", "action", "status"):
        if data.get(key) is not None:
            return str(data[key])
    if data.get("kind") == "retrieval":
        return "denied" if data.get("denied_ids") else "allowed"
    return "recorded"


def serious_incident_report(
    sink: AuditSink,
    incident_id: str,
    now: Optional[float] = None,
    deployer_notice_hours: float = 24.0,
    default_window_days: float = 7.0,
) -> IncidentReport:
    """Assemble the report for a recorded incident: deadlines (and whether
    they've passed), the related audit activity, triage signals in the
    window, and chain integrity when `sink` supports `verify()`.

    Related activity is everything in [window_start, window_end] — by
    default the `default_window_days` before `aware_at` up to `aware_at`
    — narrowed to `affected_principals` (as actor or as subject) when
    any were given. Counts only: no queries, arguments or content."""
    incidents = [
        e for e in sink.all_entries() if isinstance(e, IncidentEntry) and e.incident_id == incident_id
    ]
    if not incidents:
        raise KeyError(f"no incident {incident_id!r} in this audit trail")
    entry = incidents[-1]
    now = now if now is not None else time.time()

    days, basis = _deadline_days(entry)
    authority_deadline = entry.aware_at + days * _DAY
    deployer_deadline = entry.aware_at + deployer_notice_hours * 3600 if entry.role == "deployer" else None
    governing = deployer_deadline if deployer_deadline is not None else authority_deadline

    start = entry.window_start if entry.window_start is not None else entry.aware_at - default_window_days * _DAY
    end = entry.window_end if entry.window_end is not None else entry.aware_at
    affected = set(entry.affected_principals)
    related = [
        e for e in sink.query(since=start, until=end)
        if not isinstance(e, IncidentEntry)
        and (not affected or e.principal_id in affected or affected & set(getattr(e, "on_behalf_of", []) or []))
    ]
    activity: dict[str, Counter] = {}
    for e in related:
        data = e.to_dict()
        activity.setdefault(data.get("kind", "unknown"), Counter())[_outcome_of(data)] += 1

    chain_ok = chain_checked = chain_reason = None
    verify = getattr(sink, "verify", None)
    if callable(verify):
        result = verify()
        chain_ok, chain_checked, chain_reason = result.ok, result.checked, result.reason

    return IncidentReport(
        incident=entry.to_dict(),
        legal_basis=basis,
        authority_deadline=authority_deadline,
        authority_days=days,
        deployer_notice_deadline=deployer_deadline,
        generated_at=now,
        overdue=now > governing,
        seconds_remaining=governing - now,
        related_activity={kind: dict(counts) for kind, counts in sorted(activity.items())},
        related_entries=len(related),
        signals=[s.to_dict() for s in incident_candidates(sink, since=start, until=end)],
        chain_ok=chain_ok,
        chain_checked=chain_checked,
        chain_reason=chain_reason,
    )


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def render_incident_markdown(report: IncidentReport) -> str:
    inc = report.incident
    lines = [
        f"# Serious incident report — {inc['incident_id']}",
        "",
        f"**{inc['title']}**",
        "",
        f"- Category: {inc['category']} (Art. 3(49))",
        f"- Reporting role: {inc['role']}",
        f"- Aware since: {_iso(inc['aware_at'])}",
        f"- Declared by: {inc['principal_id']} at {_iso(inc['timestamp'])}",
        "",
        "## Deadlines",
        "",
        f"- Basis: {report.legal_basis}",
        f"- Report to market surveillance authority by: {_iso(report.authority_deadline)} "
        f"({report.authority_days} days from awareness)",
    ]
    if report.deployer_notice_deadline is not None:
        lines.append(f"- Deployer notice to provider by: {_iso(report.deployer_notice_deadline)} (Art. 26(5), 'immediately')")
    status = "OVERDUE" if report.overdue else f"{report.seconds_remaining / 3600:.1f} hours remaining"
    lines += [f"- Status at {_iso(report.generated_at)}: **{status}**", "", "## Description", "", inc["description"], ""]
    lines += ["## Related audit activity", "", f"{report.related_entries} entries in the incident window.", ""]
    if report.related_activity:
        lines += ["| Kind | Outcome | Count |", "|---|---|---|"]
        for kind, outcomes in report.related_activity.items():
            for outcome, count in sorted(outcomes.items()):
                lines.append(f"| {kind} | {outcome} | {count} |")
        lines.append("")
    if report.signals:
        lines += ["## Triage signals in window", "", "| Signal | Count | Principals |", "|---|---|---|"]
        for s in report.signals:
            lines.append(f"| {s['signal']} | {s['count']} | {', '.join(s['principals'])} |")
        lines.append("")
    lines += ["## Audit trail integrity", ""]
    if report.chain_ok is None:
        lines.append("This sink does not support hash-chain verification (use SQLiteAuditSink).")
    elif report.chain_ok:
        lines.append(f"Hash chain verified: {report.chain_checked} records, no tampering detected.")
    else:
        lines.append(f"**Hash chain verification FAILED** after {report.chain_checked} records: {report.chain_reason}")
    lines += ["", "_Generated by marshal_ai.incidents. Not legal advice._", ""]
    return "\n".join(lines)
