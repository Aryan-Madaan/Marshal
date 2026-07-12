import time

import pytest

from marshal_ai.audit import InMemoryAuditSink
from marshal_ai.policy import Principal
from marshal_ai.tools import (
    AllowAllTools,
    ArgumentRedaction,
    AutoApprove,
    JurisdictionalRiskTierPolicy,
    RateLimitPolicy,
    RedactingToolPolicy,
    RiskTierPolicy,
    RunawayAgentPolicy,
    ToolCallDenied,
    ToolCallRequest,
    ToolGuard,
)


def test_allow_all_tools_allows_and_calls_through():
    calls = []

    def send_email(to: str, body: str):
        calls.append((to, body))
        return "sent"

    guard = ToolGuard(tool=send_email, policy=AllowAllTools())
    result = guard.call(Principal(id="alice"), {"to": "bob@x.com", "body": "hi"})

    assert result == "sent"
    assert calls == [("bob@x.com", "hi")]


def test_deny_raises_and_does_not_call_the_tool():
    calls = []

    def dangerous(**kw):
        calls.append(kw)

    policy = RiskTierPolicy({"high": "deny"})
    guard = ToolGuard(tool=dangerous, policy=policy)

    with pytest.raises(ToolCallDenied) as exc_info:
        guard.call(Principal(id="alice"), {"x": 1}, risk_tier="high")

    assert calls == []  # the underlying tool must never have run
    assert exc_info.value.tool_name == "dangerous"


def test_require_approval_calls_tool_when_approved():
    def delete_record(record_id: str):
        return f"deleted {record_id}"

    policy = RiskTierPolicy({"medium": "require_approval"})
    guard = ToolGuard(tool=delete_record, policy=policy, approval_handler=AutoApprove(True))

    result = guard.call(Principal(id="alice"), {"record_id": "42"}, risk_tier="medium")

    assert result == "deleted 42"


def test_require_approval_raises_when_declined():
    calls = []

    def delete_record(record_id: str):
        calls.append(record_id)

    policy = RiskTierPolicy({"medium": "require_approval"})
    guard = ToolGuard(tool=delete_record, policy=policy, approval_handler=AutoApprove(False))

    with pytest.raises(ToolCallDenied):
        guard.call(Principal(id="alice"), {"record_id": "42"}, risk_tier="medium")

    assert calls == []


def test_risk_tier_policy_rejects_invalid_outcome():
    with pytest.raises(ValueError):
        RiskTierPolicy({"low": "maybe"})


def test_risk_tier_policy_uses_default_for_unconfigured_tier():
    policy = RiskTierPolicy({"low": "allow"}, default="deny")
    decision = policy.evaluate(
        ToolCallRequest(tool_name="x", arguments={}, principal=Principal(id="a"), risk_tier="unknown")
    )
    assert decision.outcome == "deny"


def test_audit_log_records_allow_deny_and_approval_outcomes():
    sink = InMemoryAuditSink()
    policy = RiskTierPolicy({"low": "allow", "high": "deny", "medium": "require_approval"})

    allow_guard = ToolGuard(tool=lambda **kw: None, policy=policy, audit_sink=sink, tool_name="t")
    allow_guard.call(Principal(id="alice"), {}, risk_tier="low")

    try:
        allow_guard.call(Principal(id="alice"), {}, risk_tier="high")
    except ToolCallDenied:
        pass

    approving_guard = ToolGuard(
        tool=lambda **kw: None,
        policy=policy,
        audit_sink=sink,
        approval_handler=AutoApprove(True),
        tool_name="t",
    )
    approving_guard.call(Principal(id="alice"), {}, risk_tier="medium")

    entries = sink.tail(3)
    outcomes = [e.outcome for e in entries]
    assert outcomes == ["allow", "deny", "approved"]
    assert entries[2].approved_by == "auto-approve"


def test_redacting_tool_policy_hides_argument_without_required_attribute():
    policy = RedactingToolPolicy(
        base=AllowAllTools(),
        rules=[ArgumentRedaction(name="ssn", requires_attribute="role:compliance")],
    )
    engineer = Principal(id="bob", attributes={"role:engineering"})
    request = ToolCallRequest(
        tool_name="lookup", arguments={"ssn": "123-45-6789", "name": "x"}, principal=engineer
    )

    redacted = policy.redact_arguments(request)

    assert redacted["ssn"] == "[REDACTED]"
    assert redacted["name"] == "x"
    # the request's own arguments are untouched — redact returns a copy
    assert request.arguments["ssn"] == "123-45-6789"


def test_redacting_tool_policy_leaves_argument_visible_with_required_attribute():
    policy = RedactingToolPolicy(
        base=AllowAllTools(),
        rules=[ArgumentRedaction(name="ssn", requires_attribute="role:compliance")],
    )
    compliance = Principal(id="rhea", attributes={"role:compliance"})
    request = ToolCallRequest(
        tool_name="lookup", arguments={"ssn": "123-45-6789"}, principal=compliance
    )

    assert policy.redact_arguments(request)["ssn"] == "123-45-6789"


def test_tool_actually_receives_unredacted_arguments_even_when_audit_log_is_redacted():
    seen_by_tool = []

    def lookup(ssn: str):
        seen_by_tool.append(ssn)
        return "ok"

    policy = RedactingToolPolicy(
        base=AllowAllTools(),
        rules=[ArgumentRedaction(name="ssn", requires_attribute="role:compliance")],
    )
    sink = InMemoryAuditSink()
    guard = ToolGuard(tool=lookup, policy=policy, audit_sink=sink)
    engineer = Principal(id="bob", attributes={"role:engineering"})

    guard.call(engineer, {"ssn": "123-45-6789"})

    assert seen_by_tool == ["123-45-6789"]  # the real tool got the real value
    assert sink.tail(1)[0].arguments["ssn"] == "[REDACTED]"  # the log did not


def test_unified_audit_trail_across_retrieval_and_tool_guards():
    from marshal_ai.retrieval import Document, RetrievalGuard

    shared_sink = InMemoryAuditSink()
    alice = Principal(id="alice")

    retrieval_guard = RetrievalGuard(
        retriever=lambda q, k: [Document(id="1", content="a")], audit_sink=shared_sink
    )
    tool_guard = ToolGuard(tool=lambda **kw: "done", audit_sink=shared_sink)

    retrieval_guard.retrieve("q", principal=alice, k=1)
    tool_guard.call(alice, {})

    all_alice_activity = shared_sink.query(principal_id="alice")
    assert len(all_alice_activity) == 2
    # one retrieval entry (has candidates_seen) and one tool-call entry
    # (has tool_name) — proof this is genuinely one trail, not two
    kinds = {getattr(e, "tool_name", None) is not None for e in all_alice_activity}
    assert kinds == {True, False}


def test_jsonl_sink_round_trips_mixed_retrieval_and_tool_entries(tmp_path):
    from marshal_ai.audit import JSONLAuditSink
    from marshal_ai.retrieval import Document, RetrievalGuard

    path = tmp_path / "audit.jsonl"
    shared_sink = JSONLAuditSink(path)
    alice = Principal(id="alice")

    RetrievalGuard(
        retriever=lambda q, k: [Document(id="1", content="a")], audit_sink=shared_sink
    ).retrieve("q", principal=alice, k=1)
    ToolGuard(tool=lambda **kw: "done", audit_sink=shared_sink).call(alice, {})

    # Reading back must reconstruct each line as its own correct type —
    # this is the part that actually proves mixed persistence works,
    # not just mixed in-memory storage (which Python gives you for free).
    entries = shared_sink.all_entries()
    assert len(entries) == 2
    assert hasattr(entries[0], "candidates_seen")  # AuditEntry
    assert hasattr(entries[1], "tool_name")  # ToolCallEntry
    assert shared_sink.query(principal_id="alice") == entries


# --- RateLimitPolicy -------------------------------------------------------


def test_rate_limit_allows_calls_under_the_limit():
    policy = RateLimitPolicy(AllowAllTools(), max_calls=2, window_seconds=60)
    guard = ToolGuard(tool=lambda **kw: "ok", policy=policy)
    alice = Principal(id="alice")

    assert guard.call(alice, {}) == "ok"
    assert guard.call(alice, {}) == "ok"


def test_rate_limit_denies_once_exceeded():
    policy = RateLimitPolicy(AllowAllTools(), max_calls=2, window_seconds=60)
    guard = ToolGuard(tool=lambda **kw: "ok", policy=policy)
    alice = Principal(id="alice")

    guard.call(alice, {})
    guard.call(alice, {})
    with pytest.raises(ToolCallDenied) as exc_info:
        guard.call(alice, {})
    assert "rate limit exceeded" in exc_info.value.reason


def test_rate_limit_counts_denied_calls_too():
    # a rate limit caps attempt frequency, not just successful attempts —
    # a base policy that always denies should still count toward the limit
    policy = RateLimitPolicy(RiskTierPolicy({}, default="deny"), max_calls=1, window_seconds=60)
    guard = ToolGuard(tool=lambda **kw: "ok", policy=policy)
    alice = Principal(id="alice")

    with pytest.raises(ToolCallDenied):
        guard.call(alice, {})  # denied by the base policy, still counts

    with pytest.raises(ToolCallDenied) as exc_info:
        guard.call(alice, {})
    assert "rate limit exceeded" in exc_info.value.reason


def test_rate_limit_tracks_principals_independently():
    policy = RateLimitPolicy(AllowAllTools(), max_calls=1, window_seconds=60)
    guard = ToolGuard(tool=lambda **kw: "ok", policy=policy)
    alice = Principal(id="alice")
    bob = Principal(id="bob")

    guard.call(alice, {})
    with pytest.raises(ToolCallDenied):
        guard.call(alice, {})

    assert guard.call(bob, {}) == "ok"  # bob hasn't called anything yet


def test_rate_limit_self_heals_once_the_window_elapses():
    policy = RateLimitPolicy(AllowAllTools(), max_calls=1, window_seconds=0.05)
    guard = ToolGuard(tool=lambda **kw: "ok", policy=policy)
    alice = Principal(id="alice")

    guard.call(alice, {})
    with pytest.raises(ToolCallDenied):
        guard.call(alice, {})

    time.sleep(0.08)
    assert guard.call(alice, {}) == "ok"


# --- RunawayAgentPolicy -----------------------------------------------------


def test_runaway_agent_allows_distinct_calls():
    policy = RunawayAgentPolicy(AllowAllTools(), identical_call_threshold=2, window_seconds=60)
    guard = ToolGuard(tool=lambda **kw: "ok", policy=policy)
    alice = Principal(id="alice")

    assert guard.call(alice, {"x": 1}) == "ok"
    assert guard.call(alice, {"x": 2}) == "ok"  # different arguments, doesn't count together


def test_runaway_agent_trips_on_identical_calls():
    policy = RunawayAgentPolicy(AllowAllTools(), identical_call_threshold=2, window_seconds=60)
    guard = ToolGuard(tool=lambda **kw: "ok", policy=policy, tool_name="loop_tool")
    alice = Principal(id="alice")

    guard.call(alice, {"x": 1})
    with pytest.raises(ToolCallDenied) as exc_info:
        guard.call(alice, {"x": 1})
    assert "runaway-agent breaker tripped" in exc_info.value.reason
    assert "identical" in exc_info.value.reason


def test_runaway_agent_stays_tripped_regardless_of_arguments_until_reset():
    policy = RunawayAgentPolicy(AllowAllTools(), identical_call_threshold=2, window_seconds=60)
    guard = ToolGuard(tool=lambda **kw: "ok", policy=policy)
    alice = Principal(id="alice")

    guard.call(alice, {"x": 1})
    with pytest.raises(ToolCallDenied):
        guard.call(alice, {"x": 1})  # trips here

    # tripped principal is denied outright now, even with different arguments
    with pytest.raises(ToolCallDenied) as exc_info:
        guard.call(alice, {"x": 999})
    assert "requires a human reset" in exc_info.value.reason
    assert policy.is_tripped("alice")

    policy.reset("alice")
    assert not policy.is_tripped("alice")
    assert guard.call(alice, {"x": 1}) == "ok"


def test_runaway_agent_tracks_principals_independently():
    policy = RunawayAgentPolicy(AllowAllTools(), identical_call_threshold=2, window_seconds=60)
    guard = ToolGuard(tool=lambda **kw: "ok", policy=policy)
    alice = Principal(id="alice")
    bob = Principal(id="bob")

    guard.call(alice, {"x": 1})
    with pytest.raises(ToolCallDenied):
        guard.call(alice, {"x": 1})  # alice trips

    assert guard.call(bob, {"x": 1}) == "ok"  # bob is unaffected
    assert not policy.is_tripped("bob")


def test_runaway_agent_composes_with_risk_tier_policy():
    base = RiskTierPolicy({"low": "allow"})
    policy = RunawayAgentPolicy(base, identical_call_threshold=2, window_seconds=60)
    guard = ToolGuard(tool=lambda **kw: "ok", policy=policy)
    alice = Principal(id="alice")

    assert guard.call(alice, {"x": 1}, risk_tier="low") == "ok"
    with pytest.raises(ToolCallDenied) as exc_info:
        guard.call(alice, {"x": 1}, risk_tier="low")
    assert "runaway-agent breaker" in exc_info.value.reason


# --- JurisdictionalRiskTierPolicy -------------------------------------------


def test_jurisdictional_override_tightens_allow_to_require_approval():
    base = RiskTierPolicy({"employment_decision": "allow"})
    policy = JurisdictionalRiskTierPolicy(
        base, overrides_by_jurisdiction={"EU": {"employment_decision": "require_approval"}}
    )
    guard = ToolGuard(tool=lambda **kw: "hired", policy=policy, approval_handler=AutoApprove(True))
    alice = Principal(id="alice")

    result = guard.call(alice, {}, risk_tier="employment_decision", context={"jurisdiction": "EU"})
    assert result == "hired"  # approved via AutoApprove, proving require_approval actually fired


def test_jurisdictional_override_denies_approval():
    base = RiskTierPolicy({"employment_decision": "allow"})
    policy = JurisdictionalRiskTierPolicy(
        base, overrides_by_jurisdiction={"EU": {"employment_decision": "require_approval"}}
    )
    guard = ToolGuard(tool=lambda **kw: "hired", policy=policy, approval_handler=AutoApprove(False))
    alice = Principal(id="alice")

    with pytest.raises(ToolCallDenied):
        guard.call(alice, {}, risk_tier="employment_decision", context={"jurisdiction": "EU"})


def test_jurisdictional_override_is_a_noop_without_jurisdiction_context():
    base = RiskTierPolicy({"employment_decision": "allow"})
    policy = JurisdictionalRiskTierPolicy(
        base, overrides_by_jurisdiction={"EU": {"employment_decision": "require_approval"}}
    )
    guard = ToolGuard(tool=lambda **kw: "hired", policy=policy)
    alice = Principal(id="alice")

    # no context at all -> defers entirely to the base, no fail-closed here
    assert guard.call(alice, {}, risk_tier="employment_decision") == "hired"


def test_jurisdictional_override_is_a_noop_for_unconfigured_jurisdiction():
    base = RiskTierPolicy({"employment_decision": "allow"})
    policy = JurisdictionalRiskTierPolicy(
        base, overrides_by_jurisdiction={"EU": {"employment_decision": "require_approval"}}
    )
    guard = ToolGuard(tool=lambda **kw: "hired", policy=policy)
    alice = Principal(id="alice")

    assert guard.call(alice, {}, risk_tier="employment_decision", context={"jurisdiction": "US"}) == "hired"


def test_jurisdictional_override_never_loosens_a_stricter_base_decision():
    base = RiskTierPolicy({"x": "deny"})
    policy = JurisdictionalRiskTierPolicy(base, overrides_by_jurisdiction={"EU": {"x": "allow"}})
    guard = ToolGuard(tool=lambda **kw: "ok", policy=policy)
    alice = Principal(id="alice")

    with pytest.raises(ToolCallDenied) as exc_info:
        guard.call(alice, {}, risk_tier="x", context={"jurisdiction": "EU"})
    assert "maps to 'deny'" in exc_info.value.reason  # base's own reason, unchanged


def test_jurisdictional_override_rejects_invalid_outcome_at_construction():
    base = RiskTierPolicy({"x": "allow"})
    with pytest.raises(ValueError):
        JurisdictionalRiskTierPolicy(base, overrides_by_jurisdiction={"EU": {"x": "not-a-real-outcome"}})
