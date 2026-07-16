"""Compliance artifacts derived *purely* from an `AuditSink`'s contents —
no new state, no raw secrets, nothing that isn't already sitting in the
audit trail every guard already writes to.

Two reports, tied to two specific obligations that become binding for
high-risk AI systems under the EU AI Act on 2026-08-02:

  - `cross_border_data_flow_report` — the tangible artifact behind
    Marshal's "the model call *is* the transfer" thesis (see
    `marshal_ai.models.ResidencyPolicy` and the cross-border post it
    shipped alongside). Aggregates which jurisdictions data actually
    flowed to, under which legal transfer mechanism, under which
    controller, and how many calls — the shape a DPO needs to fill in a
    Records of Processing Activities (ROPA) entry or answer a transfer
    audit, without hand-grepping the audit trail.

  - `article12_activity_record` — a per-period count of allowed / denied
    / approval-required decisions across all three governed surfaces
    (retrieval, tool calls, model calls). Article 12 requires high-risk
    systems to *automatically* log their own operation; Article 26
    requires deployers to *retain* those logs for at least six months.
    Marshal's audit trail is structurally that log already — this is
    the rollup that turns "every individual decision, one row each"
    into the periodic activity summary an actual record-keeping
    obligation asks for.

Both work against any `AuditSink` — `InMemoryAuditSink`, `JSONLAuditSink`,
`marshal_ai.sinks.SQLiteAuditSink`, or your own — via `query()`/
`all_entries()` alone. Neither writes anything back to the sink, and
neither ever stores or prints raw secrets: the underlying entries are
already redacted by the guards that wrote them (see `ToolCallEntry.
arguments`, `ModelOutcomeEntry.error`), and these reports only ever
aggregate counts, jurisdiction/mechanism/controller labels, and model
names that were already safe to have in the trail.

Honest scope limit, stated once here rather than repeated on every
function: these reports summarize what Marshal itself decided and
recorded. They are not, and cannot be, proof that a model vendor
actually processed data only in the jurisdiction it was routed to, or
actually deleted it on schedule — Marshal has no API into a vendor's
infrastructure to verify that. What they *do* give a regulator or
auditor: a durable, aggregatable record of what your own systems were
instructed to do and did, decision by decision. Pair with `marshal_ai.
sinks.SQLiteAuditSink.verify()` to additionally state that the
underlying record hasn't been altered since it was written.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Optional, Protocol

from marshal_ai.audit import AuditSink

# Deliberately no import of `ModelCallEntry`/`ToolCallEntry`/`AuditEntry`
# (marshal_ai.models / marshal_ai.tools / marshal_ai.audit) here. This
# module reads every entry structurally, via `entry.to_dict()` and its
# `kind` discriminator, the same generic way `marshal_ai/cli.py`'s
# `_summarize` consumes a mixed audit trail — a report generator depends
# on the `AuditSink`/`AuditableEvent` contract only, not on the concrete
# dataclass behind any particular `kind`. Adding a fourth governed
# surface later would still need a new branch here either way (the
# categories this report counts are a deliberate, named list, not
# open-ended); what this buys instead is that reading one already-known
# surface's fields never requires importing that surface's module.

# ---------------------------------------------------------------------------
# Cross-border data-flow report
# ---------------------------------------------------------------------------

# `ModelCallEntry` (marshal_ai/models.py) has no structured jurisdiction/
# mechanism/controller fields of its own — those only ever land in its
# free-text `reason`, and only when the resolving policy is (or wraps)
# `ResidencyPolicy`. This is a narrow, documented parse of that one
# policy's exact reason-string shape (see `ResidencyPolicy.resolve`):
#
#   "resolved 'logical' -> 'deployment' for jurisdiction 'EU' via "
#   "'adequacy_decision', controller 'acme-eu-entity'"
#
# — not a general reason-string parser. A `ModelCallEntry` produced by
# `AllowlistModelPolicy`/`RetentionPolicy`/`CircuitBreakerPolicy` alone
# (no `ResidencyPolicy` in the stack) won't match, and is counted
# separately below (`unparsed_allowed_calls`) rather than silently
# dropped, so the report is honest about what it could and couldn't
# attribute to a jurisdiction.
_RESIDENCY_REASON_RE = re.compile(
    r"for jurisdiction '(?P<jurisdiction>[^']*)' via '(?P<mechanism>[^']*)'"
    r"(?:, controller '(?P<controller>[^']*)')?"
)


def _parse_residency_reason(reason: str) -> Optional[dict[str, Optional[str]]]:
    match = _RESIDENCY_REASON_RE.search(reason)
    if match is None:
        return None
    return {
        "jurisdiction": match.group("jurisdiction"),
        "mechanism": match.group("mechanism"),
        "controller": match.group("controller"),
    }


@dataclass(frozen=True)
class DataFlowRoute:
    """One (jurisdiction, mechanism, controller) route data actually
    flowed through — an aggregate over every allowed, residency-governed
    model call that resolved to it. `controller` is `None` when the
    calls on this route never carried `context["controller"]` — a
    distinct, visible bucket rather than being merged into whichever
    route happens to sort first, since "no controller was recorded" is
    itself a fact worth a DPO seeing, not hiding.
    """

    jurisdiction: str
    mechanism: str
    controller: Optional[str]
    resolved_models: tuple[str, ...]
    call_count: int
    principal_count: int


@dataclass(frozen=True)
class CrossBorderDataFlowReport:
    """Structured result of `cross_border_data_flow_report`. `routes` is
    sorted by (jurisdiction, mechanism, controller) for a stable,
    diffable rendering across repeated runs against a growing log.

    `total_allowed_calls`/`denied_transfer_attempts`/`routes` describe
    only *enforced* decisions (`shadow == False` on the underlying
    `ModelCallEntry`) — what actually happened. `shadow_observed_calls`/
    `shadow_would_have_denied_transfers` count `ModelGuard(mode="shadow")`
    entries separately: see `cross_border_data_flow_report`'s docstring
    for why folding those into the figures above would misstate what was
    actually blocked.
    """

    generated_at: float
    period_since: Optional[float]
    period_until: Optional[float]
    routes: tuple[DataFlowRoute, ...]
    total_allowed_calls: int
    denied_transfer_attempts: int
    unparsed_allowed_calls: int
    shadow_observed_calls: int
    shadow_would_have_denied_transfers: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def cross_border_data_flow_report(
    sink: AuditSink,
    *,
    since: Optional[float] = None,
    until: Optional[float] = None,
) -> CrossBorderDataFlowReport:
    """Aggregate every `ModelCallEntry` in `sink` (optionally restricted
    to `[since, until]`, inclusive — same convention as `AuditSink.
    query`) into cross-border data-flow routes.

    Only `outcome == "allow"` entries with a parseable `ResidencyPolicy`
    reason become a `DataFlowRoute` — a denied call never actually
    transferred anything, so it isn't a "flow" (its count still shows up
    in `denied_transfer_attempts`, since a blocked transfer attempt is
    itself worth recording for an activity log, just not as a route data
    flowed through). Allowed calls whose reason doesn't match the
    `ResidencyPolicy` shape at all (no residency governance configured
    for that call) are counted in `unparsed_allowed_calls` rather than
    silently omitted.

    Entries written by a `ModelGuard` running in shadow mode
    (`entry.shadow == True`, see `marshal_ai.policy.GuardMode`) are
    excluded from *all* of the above and counted separately in
    `shadow_observed_calls`/`shadow_would_have_denied_transfers`. This
    isn't an aesthetic choice: shadow mode never blocks a call — even a
    shadow `outcome == "deny"` entry means `ModelGuard.resolve()` still
    returned a real (fallback) model and the caller's real call went
    through (see `ModelGuard._shadow_fallback_model`). Counting that
    entry in `denied_transfer_attempts` would state, in a document meant
    for a regulator, that a transfer was blocked when it in fact
    happened — the exact miscount this function exists to avoid. A
    shadow `outcome == "allow"` entry, by contrast, resolves identically
    to enforce mode (no fallback substitution happens on the allow path
    at all — see `ModelGuard.resolve`), but is still kept out of the real
    figures here so "what shadow mode observed" and "what was actually
    enforced" never blur into one number; a caller who wants to know
    *what would have happened once enforcement is turned on* should read
    the shadow-mode audit trail directly (e.g. `sink.query(denied_only=
    True)` on a shadow-only sink), the same pattern `marshal_ai.policy.
    GuardMode`'s own docs already point callers at.
    """
    entries = sink.query(since=since, until=until)

    routes: dict[tuple[str, str, Optional[str]], dict[str, Any]] = {}
    total_allowed = 0
    denied_attempts = 0
    unparsed_allowed = 0
    shadow_observed = 0
    shadow_would_have_denied = 0

    for entry in entries:
        data = entry.to_dict()
        if data.get("kind") != "model_call":
            continue
        outcome = data["outcome"]
        reason = data["reason"]

        if data.get("shadow"):
            shadow_observed += 1
            if outcome == "deny":
                shadow_would_have_denied += 1
            continue

        if outcome == "allow":
            total_allowed += 1
            parsed = _parse_residency_reason(reason)
            if parsed is None:
                unparsed_allowed += 1
                continue
            key = (parsed["jurisdiction"], parsed["mechanism"], parsed["controller"])
            bucket = routes.setdefault(
                key, {"call_count": 0, "principal_ids": set(), "resolved_models": set()}
            )
            bucket["call_count"] += 1
            bucket["principal_ids"].add(data["principal_id"])
            resolved_model = data.get("resolved_model")
            if resolved_model:
                bucket["resolved_models"].add(resolved_model)
        elif outcome == "deny":
            # Only count denials that were actually a residency decision
            # (jurisdiction missing, or no compliant deployment) — a
            # denial from an unrelated policy (budget exhausted, circuit
            # breaker tripped) isn't a blocked *transfer* attempt.
            if "jurisdiction" in reason:
                denied_attempts += 1

    sorted_routes = tuple(
        DataFlowRoute(
            jurisdiction=jurisdiction,
            mechanism=mechanism,
            controller=controller,
            resolved_models=tuple(sorted(bucket["resolved_models"])),
            call_count=bucket["call_count"],
            principal_count=len(bucket["principal_ids"]),
        )
        for (jurisdiction, mechanism, controller), bucket in sorted(
            routes.items(), key=lambda item: (item[0][0], item[0][1], item[0][2] or "")
        )
    )

    return CrossBorderDataFlowReport(
        generated_at=time.time(),
        period_since=since,
        period_until=until,
        routes=sorted_routes,
        total_allowed_calls=total_allowed,
        denied_transfer_attempts=denied_attempts,
        unparsed_allowed_calls=unparsed_allowed,
        shadow_observed_calls=shadow_observed,
        shadow_would_have_denied_transfers=shadow_would_have_denied,
    )


def render_cross_border_markdown(report: CrossBorderDataFlowReport) -> str:
    """A clean, pasteable Markdown rendering of `report` — the "hand it
    to a DPO" form of the structured data above."""
    lines = ["# Cross-Border Data Flow Report", ""]
    lines.append(f"Generated: {_iso(report.generated_at)}")
    lines.append(f"Period: {_period_label(report.period_since, report.period_until)}")
    lines.append("")

    if report.routes:
        lines.append("| Jurisdiction | Mechanism | Controller | Deployment(s) | Calls | Principals |")
        lines.append("|---|---|---|---|---|---|")
        for route in report.routes:
            deployments = ", ".join(route.resolved_models) if route.resolved_models else "-"
            controller = route.controller or "-"
            lines.append(
                f"| {route.jurisdiction} | {route.mechanism} | {controller} | "
                f"{deployments} | {route.call_count} | {route.principal_count} |"
            )
    else:
        lines.append("_No residency-governed model calls in this period._")

    lines.append("")
    lines.append(f"- Total allowed model calls: {report.total_allowed_calls}")
    lines.append(f"- Denied cross-border transfer attempts: {report.denied_transfer_attempts}")
    lines.append(
        f"- Allowed calls with no parseable jurisdiction/mechanism "
        f"(not governed by ResidencyPolicy): {report.unparsed_allowed_calls}"
    )

    if report.shadow_observed_calls:
        lines.append("")
        lines.append("## Observed in shadow mode (not enforced)")
        lines.append("")
        lines.append(
            "The following calls were resolved by a `ModelGuard` running in "
            "`mode=\"shadow\"` — nothing above was actually blocked by them; "
            "every one of these calls proceeded regardless of the policy's "
            "decision. Kept separate from the enforcement figures above so "
            "this report never states a transfer was blocked when it in "
            "fact happened."
        )
        lines.append("")
        lines.append(f"- Shadow-mode model calls observed: {report.shadow_observed_calls}")
        lines.append(
            "- Of those, the policy would have denied (but the call still "
            f"went through): {report.shadow_would_have_denied_transfers}"
        )
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Article 12 activity record
# ---------------------------------------------------------------------------

_GRANULARITY_FORMATS = {
    "day": "%Y-%m-%d",
    "month": "%Y-%m",
}

# Every raw `outcome`/decision this report has ever seen, normalized to
# the three-way bucket Article 12-style activity logs actually count in:
# was the action carried out unconditionally, blocked outright, or routed
# through mandatory human oversight first. Retrieval has no "outcome"
# field at all (see the `kind == "retrieval"` branch in
# `article12_activity_record` below, which derives allow/deny counts
# from `allowed_ids`/`denied_ids` instead) so it isn't listed here.
#
# "require_approval" is included here even though enforce mode never
# persists it (a `ToolCallEntry` always resolves it to "approved"/
# "declined" first) — a `ToolGuard(mode="shadow")` entry audits the raw,
# untranslated decision verbatim (see `ToolCallEntry.outcome`'s
# docstring), so it only ever shows up in the shadow-mode counts
# `article12_activity_record` tracks separately, below. Without it here,
# a shadow "require_approval" entry would land in `outcome_breakdown` but
# in none of the three normalized buckets — silently uncounted.
_ALLOWED_OUTCOMES = {"allow", "approved"}
_DENIED_OUTCOMES = {"deny", "declined"}
_APPROVAL_OUTCOMES = {"approved", "declined", "require_approval"}


@dataclass(frozen=True)
class PeriodActivityCounts:
    """Counts for one (period, surface) cell. `allowed`/`denied`/
    `approval_required` are the normalized three-way bucket;
    `outcome_breakdown` keeps every entry's *raw* outcome string (e.g.
    `tool_call`'s `"approved"` vs `"declined"`, both folded into
    `approval_required` above) so nothing is lost in the rollup —
    the normalized view is a summary of `outcome_breakdown`, never a
    replacement for it.
    """

    period: str
    surface: str
    allowed: int
    denied: int
    approval_required: int
    outcome_breakdown: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ActivityRecord:
    """Structured result of `article12_activity_record`. `counts` is
    sorted by (period, surface) for a stable rendering; `totals` sums
    every cell in `counts` into a single (period="TOTAL", surface="all")
    row for a quick top-line number.

    `counts`/`totals` describe only *enforced* decisions (entries with
    `shadow == False`) — real allow/deny/approval-required outcomes that
    actually happened. `shadow_counts`/`shadow_totals` are the identical
    shape, computed only from `shadow == True` entries (written by a
    guard running in `mode="shadow"`, see `marshal_ai.policy.GuardMode`)
    — kept in a fully separate pair of fields rather than merged into
    `counts`/`totals`, because a shadow "deny"/"require_approval" entry
    means the action still proceeded (nothing was actually enforced);
    folding it into the real counts would misstate what this system
    actually did in a document whose entire purpose is that accuracy.
    """

    generated_at: float
    granularity: str
    period_since: Optional[float]
    period_until: Optional[float]
    counts: tuple[PeriodActivityCounts, ...]
    totals: PeriodActivityCounts
    shadow_counts: tuple[PeriodActivityCounts, ...]
    shadow_totals: PeriodActivityCounts

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _period_key(timestamp: float, granularity: str) -> str:
    fmt = _GRANULARITY_FORMATS.get(granularity)
    if fmt is None:
        raise ValueError(
            f"unknown granularity {granularity!r}; must be one of {sorted(_GRANULARITY_FORMATS)}"
        )
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime(fmt)


def _new_bucket() -> dict[str, Any]:
    return {"allowed": 0, "denied": 0, "approval_required": 0, "outcome_breakdown": {}}


def _record_outcome(bucket: dict[str, Any], outcome: str, count: int = 1) -> None:
    bucket["outcome_breakdown"][outcome] = bucket["outcome_breakdown"].get(outcome, 0) + count
    if outcome in _APPROVAL_OUTCOMES:
        bucket["approval_required"] += count
    elif outcome in _ALLOWED_OUTCOMES:
        bucket["allowed"] += count
    elif outcome in _DENIED_OUTCOMES:
        bucket["denied"] += count


def _finalize_buckets(
    buckets: dict[tuple[str, str], dict[str, Any]]
) -> tuple[PeriodActivityCounts, ...]:
    """Turn the raw (period, surface) -> counter-dict buckets built while
    walking the audit trail into the sorted, immutable `PeriodActivityCounts`
    tuple both the real and shadow halves of `article12_activity_record`
    return — one shared implementation so the two never drift apart."""
    return tuple(
        PeriodActivityCounts(
            period=period,
            surface=surface,
            allowed=bucket["allowed"],
            denied=bucket["denied"],
            approval_required=bucket["approval_required"],
            outcome_breakdown=dict(bucket["outcome_breakdown"]),
        )
        for (period, surface), bucket in sorted(buckets.items())
    )


def _sum_counts(counts: tuple[PeriodActivityCounts, ...]) -> PeriodActivityCounts:
    """Roll `counts` up into one `(period="TOTAL", surface="all")` cell —
    shared by the real and shadow totals for the same reason as
    `_finalize_buckets` above."""
    totals_bucket = _new_bucket()
    for cell in counts:
        totals_bucket["allowed"] += cell.allowed
        totals_bucket["denied"] += cell.denied
        totals_bucket["approval_required"] += cell.approval_required
        for outcome, count in cell.outcome_breakdown.items():
            totals_bucket["outcome_breakdown"][outcome] = (
                totals_bucket["outcome_breakdown"].get(outcome, 0) + count
            )
    return PeriodActivityCounts(
        period="TOTAL",
        surface="all",
        allowed=totals_bucket["allowed"],
        denied=totals_bucket["denied"],
        approval_required=totals_bucket["approval_required"],
        outcome_breakdown=dict(totals_bucket["outcome_breakdown"]),
    )


def article12_activity_record(
    sink: AuditSink,
    *,
    since: Optional[float] = None,
    until: Optional[float] = None,
    granularity: str = "day",
) -> ActivityRecord:
    """Per-period counts of allowed / denied / approval-required
    decisions across all three governed surfaces — retrieval (per
    candidate document), tool calls, and model-routing calls.

    `granularity` buckets each entry's UTC timestamp into `"day"`
    (`YYYY-MM-DD`) or `"month"` (`YYYY-MM`) periods — always UTC, so the
    same log produces the same periods regardless of where this report
    is generated.

    Retrieval entries (`kind == "retrieval"`, `marshal_ai.audit.AuditEntry`)
    carry no single `outcome` — one retrieval call evaluates a whole
    batch of candidate documents, each independently allowed or denied —
    so each entry contributes
    `len(allowed_ids)` to `allowed` and `len(denied_ids)` to `denied`
    for its period, the same per-decision granularity Article 12 asks
    for ("automatic recording of events", not "recording of batches").
    Tool-call and model-call entries contribute 1 to their period per
    entry, keyed off that entry's own `outcome` field.

    Every entry kind that carries a `shadow` field (retrieval, tool-call,
    model-call — see `marshal_ai.policy.GuardMode`) routes into
    `counts`/`totals` when `shadow == False` and into `shadow_counts`/
    `shadow_totals` when `shadow == True`, never both. A shadow entry
    records what a guard's policy *would* have decided while the real
    action proceeded regardless — Article 12 is a record of what a
    system *did*, so a would-have-denied/would-have-required-approval
    entry counted as `denied`/`approval_required` above would state, in
    a document meant for a regulator, that this system enforced
    something it never actually enforced. See `ActivityRecord`'s
    docstring for the full reasoning; the tables stay structurally
    identical so a caller comparing "what shadow mode would have done"
    against "what's actually enforced today" doesn't need two different
    shapes to do it.
    """
    entries = sink.query(since=since, until=until)
    buckets: dict[tuple[str, str], dict[str, Any]] = {}
    shadow_buckets: dict[tuple[str, str], dict[str, Any]] = {}

    for entry in entries:
        period = _period_key(entry.timestamp, granularity)
        data = entry.to_dict()
        kind = data.get("kind")
        target = shadow_buckets if data.get("shadow") else buckets

        if kind == "retrieval":
            bucket = target.setdefault((period, "retrieval"), _new_bucket())
            allowed_ids = data["allowed_ids"]
            denied_ids = data["denied_ids"]
            if allowed_ids:
                _record_outcome(bucket, "allow", count=len(allowed_ids))
            if denied_ids:
                _record_outcome(bucket, "deny", count=len(denied_ids))
        elif kind == "tool_call":
            bucket = target.setdefault((period, "tool_call"), _new_bucket())
            _record_outcome(bucket, data["outcome"])
        elif kind == "model_call":
            bucket = target.setdefault((period, "model_call"), _new_bucket())
            _record_outcome(bucket, data["outcome"])
        # Other entry kinds (model_usage, model_outcome, sensitive_data)
        # aren't governance decisions on one of the three guarded
        # surfaces themselves — model_usage/model_outcome are follow-up
        # telemetry for a call already counted via its ModelCallEntry,
        # and sensitive_data findings are cross-cutting (see
        # marshal_ai.sensitive) rather than a fourth surface — so they're
        # deliberately not double-counted here.

    counts = _finalize_buckets(buckets)
    shadow_counts = _finalize_buckets(shadow_buckets)

    return ActivityRecord(
        generated_at=time.time(),
        granularity=granularity,
        period_since=since,
        period_until=until,
        counts=counts,
        totals=_sum_counts(counts),
        shadow_counts=shadow_counts,
        shadow_totals=_sum_counts(shadow_counts),
    )


def render_activity_record_markdown(report: ActivityRecord) -> str:
    """A clean, pasteable Markdown rendering of `report`."""
    lines = ["# AI Act Article 12 Activity Record", ""]
    lines.append(f"Generated: {_iso(report.generated_at)}")
    lines.append(f"Granularity: {report.granularity}")
    lines.append(f"Period: {_period_label(report.period_since, report.period_until)}")
    lines.append("")
    lines.append("| Period | Surface | Allowed | Denied | Approval Required |")
    lines.append("|---|---|---|---|---|")
    for cell in report.counts:
        lines.append(
            f"| {cell.period} | {cell.surface} | {cell.allowed} | {cell.denied} | "
            f"{cell.approval_required} |"
        )
    t = report.totals
    lines.append(f"| **TOTAL** | **all** | **{t.allowed}** | **{t.denied}** | **{t.approval_required}** |")

    if report.shadow_totals.outcome_breakdown:
        lines.append("")
        lines.append("## Observed in shadow mode (not enforced)")
        lines.append("")
        lines.append(
            "The rows below are from guards running in `mode=\"shadow\"` — every "
            "action they cover actually proceeded regardless of the policy's "
            "decision; nothing here was actually denied or held for approval. "
            "Kept separate from the table above so this record never states "
            "this system enforced something it didn't."
        )
        lines.append("")
        lines.append("| Period | Surface | Would-Allow | Would-Deny | Would-Require-Approval |")
        lines.append("|---|---|---|---|---|")
        for cell in report.shadow_counts:
            lines.append(
                f"| {cell.period} | {cell.surface} | {cell.allowed} | {cell.denied} | "
                f"{cell.approval_required} |"
            )
        st = report.shadow_totals
        lines.append(
            f"| **TOTAL** | **all** | **{st.allowed}** | **{st.denied}** | "
            f"**{st.approval_required}** |"
        )
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Shared rendering helpers
# ---------------------------------------------------------------------------


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _period_label(since: Optional[float], until: Optional[float]) -> str:
    if since is None and until is None:
        return "entire audit trail"
    since_label = _iso(since) if since is not None else "-inf"
    until_label = _iso(until) if until is not None else "now"
    return f"{since_label} to {until_label}"


class _Reportable(Protocol):
    """Structural shape `render_json` needs: anything exposing
    `to_dict()` — the same duck-typed convention `marshal_ai.audit.
    AuditableEvent` already uses for "anything that can serialize
    itself." Both report dataclasses above satisfy this without
    `render_json` needing to import either one specifically, and a
    future third report would too, automatically."""

    def to_dict(self) -> dict[str, Any]: ...


def render_json(report: _Reportable) -> str:
    """`json.dumps` of any report's `to_dict()`, sorted and indented —
    the machine-readable pairing to the Markdown renderers above, for
    piping into whatever compliance tooling ingests structured records.
    """
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)
