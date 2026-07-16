import time

from marshal_ai.audit import AuditEntry, InMemoryAuditSink
from marshal_ai.models import ModelCallEntry
from marshal_ai.reports import (
    ActivityRecord,
    CrossBorderDataFlowReport,
    article12_activity_record,
    cross_border_data_flow_report,
    render_activity_record_markdown,
    render_cross_border_markdown,
    render_json,
)
from marshal_ai.tools import ToolCallEntry

# 2026-07-01T00:00:00Z and 2026-07-02T00:00:00Z, as Unix timestamps —
# fixed, known instants (not time.time()) so period-bucketing assertions
# are deterministic regardless of when the test runs.
DAY_1 = 1782288000.0
DAY_2 = DAY_1 + 86400


def model_entry(
    ts: float,
    principal_id: str,
    outcome: str,
    jurisdiction: str | None = None,
    mechanism: str | None = None,
    controller: str | None = None,
    resolved_model: str | None = None,
    shadow: bool = False,
) -> ModelCallEntry:
    if outcome == "allow" and jurisdiction is not None:
        controller_note = f", controller {controller!r}" if controller else ""
        reason = (
            f"resolved 'default-chat-model' -> {resolved_model!r} for jurisdiction "
            f"{jurisdiction!r} via {mechanism!r}{controller_note}"
        )
    elif outcome == "deny" and jurisdiction is not None:
        reason = f"no jurisdiction-compliant deployment for {jurisdiction!r} among candidates for 'default-chat-model'"
    elif outcome == "deny":
        reason = "jurisdiction not provided in context — refusing to resolve without it"
    else:
        reason = "AllowAllModels policy"
    return ModelCallEntry(
        timestamp=ts,
        principal_id=principal_id,
        logical_name="default-chat-model",
        # A shadow "deny" still carries a resolved_model — ModelGuard's
        # shadow fallback returns a real model even on a would-be denial
        # (see ModelGuard._shadow_fallback_model) — so the real call
        # actually proceeds. A real (enforced) "deny" never resolves one.
        resolved_model=resolved_model if (outcome == "allow" or shadow) else None,
        outcome=outcome,
        reason=reason,
        shadow=shadow,
    )


def tool_entry(ts: float, principal_id: str, outcome: str, shadow: bool = False) -> ToolCallEntry:
    return ToolCallEntry(
        timestamp=ts,
        principal_id=principal_id,
        tool_name="send_email",
        arguments={},
        risk_tier="medium",
        outcome=outcome,
        reason="test",
        approved_by="cli-approver" if outcome in ("approved", "declined") else None,
        shadow=shadow,
    )


def retrieval_entry(
    ts: float, principal_id: str, allowed: int, denied: int, shadow: bool = False
) -> AuditEntry:
    return AuditEntry(
        timestamp=ts,
        principal_id=principal_id,
        query="q",
        candidates_seen=allowed + denied,
        allowed_ids=[f"a{i}" for i in range(allowed)],
        denied_ids=[f"d{i}" for i in range(denied)],
        denied_reasons={f"d{i}": "no acl match" for i in range(denied)},
        shadow=shadow,
    )


# --- cross-border data-flow report ------------------------------------------


def test_cross_border_report_aggregates_routes_by_jurisdiction_mechanism_controller():
    sink = InMemoryAuditSink()
    sink.write(
        model_entry(
            DAY_1, "alice", "allow", jurisdiction="EU", mechanism="adequacy_decision",
            controller="acme-eu", resolved_model="eu-deployment",
        )
    )
    sink.write(
        model_entry(
            DAY_1 + 1, "bob", "allow", jurisdiction="EU", mechanism="adequacy_decision",
            controller="acme-eu", resolved_model="eu-deployment",
        )
    )
    sink.write(
        model_entry(
            DAY_1 + 2, "alice", "allow", jurisdiction="IN", mechanism="dpdp_section_16",
            controller=None, resolved_model="in-deployment",
        )
    )

    report = cross_border_data_flow_report(sink)
    assert isinstance(report, CrossBorderDataFlowReport)
    assert len(report.routes) == 2

    eu_route = next(r for r in report.routes if r.jurisdiction == "EU")
    assert eu_route.mechanism == "adequacy_decision"
    assert eu_route.controller == "acme-eu"
    assert eu_route.call_count == 2
    assert eu_route.principal_count == 2
    assert eu_route.resolved_models == ("eu-deployment",)

    in_route = next(r for r in report.routes if r.jurisdiction == "IN")
    assert in_route.controller is None
    assert in_route.call_count == 1
    assert in_route.principal_count == 1

    assert report.total_allowed_calls == 3
    assert report.denied_transfer_attempts == 0
    assert report.unparsed_allowed_calls == 0


def test_cross_border_report_separates_controller_less_calls_into_their_own_route():
    sink = InMemoryAuditSink()
    sink.write(
        model_entry(
            DAY_1, "alice", "allow", jurisdiction="EU", mechanism="adequacy_decision",
            controller="acme-eu", resolved_model="eu-deployment",
        )
    )
    sink.write(
        model_entry(
            DAY_1, "bob", "allow", jurisdiction="EU", mechanism="adequacy_decision",
            controller=None, resolved_model="eu-deployment",
        )
    )
    report = cross_border_data_flow_report(sink)
    assert len(report.routes) == 2
    controllers = {r.controller for r in report.routes}
    assert controllers == {"acme-eu", None}


def test_cross_border_report_counts_denied_transfer_attempts_separately():
    sink = InMemoryAuditSink()
    sink.write(model_entry(DAY_1, "alice", "deny", jurisdiction="TH"))
    sink.write(model_entry(DAY_1, "alice", "deny"))  # jurisdiction missing entirely
    report = cross_border_data_flow_report(sink)
    assert report.routes == ()
    assert report.denied_transfer_attempts == 2
    assert report.total_allowed_calls == 0


def test_cross_border_report_excludes_shadow_denies_from_denied_transfer_attempts():
    # The headline cross-cutting bug this test guards against: a shadow
    # ModelGuard's would-be "deny" doesn't block anything — ModelGuard
    # still returns a real fallback model and the caller's real call goes
    # through (see ModelGuard._shadow_fallback_model). Counting that
    # entry in denied_transfer_attempts would state, in a document meant
    # for a regulator, that a transfer was blocked when it actually
    # happened.
    sink = InMemoryAuditSink()
    sink.write(model_entry(DAY_1, "alice", "deny", jurisdiction="TH", shadow=True))
    # A real, enforced denial in the same sink must still be counted —
    # shadow exclusion must not swallow genuine denials either.
    sink.write(model_entry(DAY_1, "bob", "deny", jurisdiction="TH"))

    report = cross_border_data_flow_report(sink)
    assert report.denied_transfer_attempts == 1  # only bob's real denial
    assert report.total_allowed_calls == 0
    assert report.shadow_observed_calls == 1
    assert report.shadow_would_have_denied_transfers == 1


def test_cross_border_report_excludes_shadow_allows_from_real_totals():
    sink = InMemoryAuditSink()
    sink.write(
        model_entry(
            DAY_1, "alice", "allow", jurisdiction="EU", mechanism="adequacy_decision",
            resolved_model="eu-deployment", shadow=True,
        )
    )
    report = cross_border_data_flow_report(sink)
    assert report.total_allowed_calls == 0
    assert report.routes == ()
    assert report.shadow_observed_calls == 1
    assert report.shadow_would_have_denied_transfers == 0


def test_cross_border_markdown_surfaces_shadow_section_when_present():
    sink = InMemoryAuditSink()
    sink.write(model_entry(DAY_1, "alice", "deny", jurisdiction="TH", shadow=True))
    report = cross_border_data_flow_report(sink)
    md = render_cross_border_markdown(report)
    assert "Observed in shadow mode" in md
    assert "not enforced" in md


def test_cross_border_report_flags_allowed_calls_with_no_residency_governance():
    sink = InMemoryAuditSink()
    sink.write(model_entry(DAY_1, "alice", "allow"))  # AllowAllModels, no jurisdiction at all
    report = cross_border_data_flow_report(sink)
    assert report.routes == ()
    assert report.total_allowed_calls == 1
    assert report.unparsed_allowed_calls == 1


def test_cross_border_report_ignores_non_model_call_entries():
    sink = InMemoryAuditSink()
    sink.write(tool_entry(DAY_1, "alice", "allow"))
    sink.write(retrieval_entry(DAY_1, "alice", allowed=1, denied=0))
    report = cross_border_data_flow_report(sink)
    assert report.routes == ()
    assert report.total_allowed_calls == 0


def test_cross_border_report_respects_since_until():
    sink = InMemoryAuditSink()
    sink.write(
        model_entry(
            DAY_1, "alice", "allow", jurisdiction="EU", mechanism="adequacy_decision",
            resolved_model="eu-deployment",
        )
    )
    sink.write(
        model_entry(
            DAY_2, "alice", "allow", jurisdiction="EU", mechanism="adequacy_decision",
            resolved_model="eu-deployment",
        )
    )
    report = cross_border_data_flow_report(sink, since=DAY_2)
    assert report.total_allowed_calls == 1


def test_cross_border_markdown_and_json_render_without_error():
    sink = InMemoryAuditSink()
    sink.write(
        model_entry(
            DAY_1, "alice", "allow", jurisdiction="EU", mechanism="adequacy_decision",
            controller="acme-eu", resolved_model="eu-deployment",
        )
    )
    report = cross_border_data_flow_report(sink)
    md = render_cross_border_markdown(report)
    assert "Cross-Border Data Flow Report" in md
    assert "EU" in md
    assert "adequacy_decision" in md
    assert "acme-eu" in md

    js = render_json(report)
    assert '"jurisdiction": "EU"' in js
    assert '"mechanism": "adequacy_decision"' in js


def test_cross_border_report_never_contains_raw_reason_text():
    # The report's own dataclasses must expose only labels/counts, never
    # the original free-text `reason` string that was parsed to get them.
    sink = InMemoryAuditSink()
    sink.write(
        model_entry(
            DAY_1, "alice", "allow", jurisdiction="EU", mechanism="adequacy_decision",
            controller="acme-eu", resolved_model="eu-deployment",
        )
    )
    report = cross_border_data_flow_report(sink)
    assert "reason" not in report.to_dict()["routes"][0]


# --- article 12 activity record ---------------------------------------------


def test_activity_record_counts_across_all_three_surfaces():
    sink = InMemoryAuditSink()
    sink.write(retrieval_entry(DAY_1, "alice", allowed=2, denied=1))
    sink.write(tool_entry(DAY_1, "bob", "allow"))
    sink.write(tool_entry(DAY_1, "bob", "deny"))
    sink.write(tool_entry(DAY_1, "bob", "approved"))
    sink.write(tool_entry(DAY_1, "bob", "declined"))
    sink.write(model_entry(DAY_1, "carol", "allow", resolved_model="m1"))
    sink.write(model_entry(DAY_1, "carol", "deny"))

    report = article12_activity_record(sink)
    assert isinstance(report, ActivityRecord)
    assert len(report.counts) == 3  # retrieval, tool_call, model_call — all same day

    retrieval_cell = next(c for c in report.counts if c.surface == "retrieval")
    assert retrieval_cell.allowed == 2
    assert retrieval_cell.denied == 1
    assert retrieval_cell.approval_required == 0

    tool_cell = next(c for c in report.counts if c.surface == "tool_call")
    assert tool_cell.allowed == 1  # "allow"
    assert tool_cell.denied == 1  # "deny"
    assert tool_cell.approval_required == 2  # "approved" + "declined"
    assert tool_cell.outcome_breakdown == {"allow": 1, "deny": 1, "approved": 1, "declined": 1}

    model_cell = next(c for c in report.counts if c.surface == "model_call")
    assert model_cell.allowed == 1
    assert model_cell.denied == 1
    assert model_cell.approval_required == 0

    assert report.totals.allowed == 2 + 1 + 1
    assert report.totals.denied == 1 + 1 + 1
    assert report.totals.approval_required == 2


def test_activity_record_excludes_shadow_entries_from_real_counts():
    # Same cross-cutting bug as the cross-border test above, for the
    # Article 12 activity record: a shadow ToolGuard's "deny"/
    # "require_approval" entry means the tool call actually proceeded
    # (see ToolCallEntry.outcome's docstring) — it must not be counted
    # as a real denial/approval-requirement, only surfaced separately.
    sink = InMemoryAuditSink()
    sink.write(tool_entry(DAY_1, "bob", "deny", shadow=True))
    sink.write(tool_entry(DAY_1, "bob", "require_approval", shadow=True))
    sink.write(retrieval_entry(DAY_1, "alice", allowed=0, denied=3, shadow=True))
    sink.write(model_entry(DAY_1, "carol", "deny", jurisdiction="TH", shadow=True))
    # One real, enforced denial in the same sink — must still show up in
    # the real totals; shadow exclusion must not swallow it too.
    sink.write(tool_entry(DAY_1, "dave", "deny"))

    report = article12_activity_record(sink)

    # Real figures: only dave's genuine denial.
    assert report.totals.denied == 1
    assert report.totals.allowed == 0
    assert report.totals.approval_required == 0

    # Shadow figures: everything else, correctly bucketed — including
    # the "require_approval" outcome landing in approval_required
    # (the secondary defect: previously fell into no normalized bucket).
    # 5 = bob's tool "deny" (1) + carol's model "deny" (1) + alice's
    # retrieval entry's 3 would-be-denied documents.
    assert report.shadow_totals.denied == 5
    assert report.shadow_totals.approval_required == 1  # bob's require_approval
    assert report.shadow_totals.outcome_breakdown.get("require_approval") == 1


def test_activity_record_shadow_retrieval_entries_counted_in_shadow_bucket_only():
    sink = InMemoryAuditSink()
    sink.write(retrieval_entry(DAY_1, "alice", allowed=2, denied=1, shadow=True))
    report = article12_activity_record(sink)
    assert report.totals.allowed == 0
    assert report.totals.denied == 0
    assert report.shadow_totals.allowed == 2
    assert report.shadow_totals.denied == 1


def test_activity_record_markdown_surfaces_shadow_section_when_present():
    sink = InMemoryAuditSink()
    sink.write(tool_entry(DAY_1, "bob", "deny", shadow=True))
    report = article12_activity_record(sink)
    md = render_activity_record_markdown(report)
    assert "Observed in shadow mode" in md
    assert "Would-Deny" in md


def test_activity_record_buckets_by_day():
    sink = InMemoryAuditSink()
    sink.write(tool_entry(DAY_1, "bob", "allow"))
    sink.write(tool_entry(DAY_2, "bob", "allow"))

    report = article12_activity_record(sink, granularity="day")
    periods = sorted({c.period for c in report.counts})
    assert len(periods) == 2
    assert periods[0] != periods[1]


def test_activity_record_buckets_by_month():
    sink = InMemoryAuditSink()
    sink.write(tool_entry(DAY_1, "bob", "allow"))
    sink.write(tool_entry(DAY_2, "bob", "allow"))

    report = article12_activity_record(sink, granularity="month")
    periods = {c.period for c in report.counts}
    # DAY_1 and DAY_2 are 1 day apart in the same month -> one period.
    assert len(periods) == 1


def test_activity_record_ignores_model_usage_and_outcome_entries():
    from marshal_ai.models import ModelOutcomeEntry, ModelUsageEntry

    sink = InMemoryAuditSink()
    sink.write(model_entry(DAY_1, "carol", "allow", resolved_model="m1"))
    sink.write(
        ModelUsageEntry(timestamp=DAY_1, principal_id="carol", model="m1", prompt_tokens=1, completion_tokens=1)
    )
    sink.write(ModelOutcomeEntry(timestamp=DAY_1, principal_id="carol", model="m1", success=True))

    report = article12_activity_record(sink)
    assert report.totals.allowed == 1  # only the ModelCallEntry counted


def test_activity_record_respects_since_until():
    sink = InMemoryAuditSink()
    sink.write(tool_entry(DAY_1, "bob", "allow"))
    sink.write(tool_entry(DAY_2, "bob", "allow"))

    report = article12_activity_record(sink, since=DAY_2)
    assert report.totals.allowed == 1


def test_activity_record_markdown_and_json_render_without_error():
    sink = InMemoryAuditSink()
    sink.write(tool_entry(DAY_1, "bob", "allow"))
    sink.write(tool_entry(DAY_1, "bob", "deny"))
    report = article12_activity_record(sink)

    md = render_activity_record_markdown(report)
    assert "Article 12 Activity Record" in md
    assert "tool_call" in md
    assert "TOTAL" in md

    js = render_json(report)
    assert '"surface": "tool_call"' in js


def test_empty_sink_produces_empty_reports():
    sink = InMemoryAuditSink()
    cross_border = cross_border_data_flow_report(sink)
    activity = article12_activity_record(sink)
    assert cross_border.routes == ()
    assert activity.counts == ()
    assert activity.totals.allowed == 0
    assert activity.totals.denied == 0
    assert activity.totals.approval_required == 0
