import time

import pytest

from marshal_ai.audit import InMemoryAuditSink
from marshal_ai.models import (
    AllowAllModels,
    AllowlistModelPolicy,
    BudgetPolicy,
    CircuitBreakerPolicy,
    ModelCallDenied,
    ModelCandidate,
    ModelGuard,
    ResidencyPolicy,
    RetentionPolicy,
)
from marshal_ai.policy import Principal


def test_allow_all_models_passes_logical_name_through_unchanged():
    guard = ModelGuard(policy=AllowAllModels())
    resolved = guard.resolve(Principal(id="alice"), "default-chat-model")
    assert resolved == "default-chat-model"


def test_allowlist_resolves_to_first_qualifying_candidate():
    policy = AllowlistModelPolicy(
        {
            "default-chat-model": [
                ModelCandidate("gpt-fast"),
                ModelCandidate("gpt-backup"),
            ]
        }
    )
    guard = ModelGuard(policy=policy)
    resolved = guard.resolve(Principal(id="alice"), "default-chat-model")
    assert resolved == "gpt-fast"


def test_allowlist_skips_candidates_principal_does_not_qualify_for():
    policy = AllowlistModelPolicy(
        {
            "pii-safe-model": [
                ModelCandidate("consumer-model"),
                ModelCandidate("zero-retention-model", requires_attribute="clearance:pii"),
            ]
        }
    )
    guard = ModelGuard(policy=policy)

    unqualified = Principal(id="bob")
    resolved = guard.resolve(unqualified, "pii-safe-model")
    assert resolved == "consumer-model"


def test_allowlist_denies_when_no_candidate_qualifies():
    policy = AllowlistModelPolicy(
        {
            "restricted-model": [
                ModelCandidate("secure-model", requires_attribute="clearance:top"),
            ]
        }
    )
    guard = ModelGuard(policy=policy)

    with pytest.raises(ModelCallDenied):
        guard.resolve(Principal(id="bob"), "restricted-model")


def test_allowlist_denies_for_unknown_logical_name():
    policy = AllowlistModelPolicy({"known-model": [ModelCandidate("x")]})
    guard = ModelGuard(policy=policy)

    with pytest.raises(ModelCallDenied):
        guard.resolve(Principal(id="bob"), "unknown-model")


def test_fallback_chain_only_contains_qualifying_candidates_in_order():
    policy = AllowlistModelPolicy(
        {
            "default-chat-model": [
                ModelCandidate("primary"),
                ModelCandidate("eu-only-backup", requires_attribute="region:eu"),
                ModelCandidate("general-backup"),
            ]
        }
    )
    guard = ModelGuard(policy=policy)

    us_principal = Principal(id="alice", attributes={"region:us"})
    chain = guard.fallback_chain(us_principal, "default-chat-model")

    # primary is resolve()'s pick, not part of the fallback chain; the
    # eu-only backup is skipped since this principal doesn't qualify
    assert chain == ["general-backup"]


def test_model_resolution_is_audited():
    sink = InMemoryAuditSink()
    policy = AllowlistModelPolicy({"m": [ModelCandidate("real-model")]})
    guard = ModelGuard(policy=policy, audit_sink=sink)

    guard.resolve(Principal(id="alice"), "m")

    entry = sink.tail(1)[0]
    assert entry.logical_name == "m"
    assert entry.resolved_model == "real-model"
    assert entry.outcome == "allow"


def test_denied_resolution_is_also_audited():
    sink = InMemoryAuditSink()
    policy = AllowlistModelPolicy({})
    guard = ModelGuard(policy=policy, audit_sink=sink)

    with pytest.raises(ModelCallDenied):
        guard.resolve(Principal(id="alice"), "nope")

    entry = sink.tail(1)[0]
    assert entry.outcome == "deny"
    assert entry.resolved_model is None


def test_budget_policy_allows_under_limit_and_denies_once_exceeded():
    base = AllowlistModelPolicy({"m": [ModelCandidate("gpt-x")]})
    pricing = {"gpt-x": (1.0, 2.0)}  # $1/1K prompt tokens, $2/1K completion tokens
    policy = BudgetPolicy(base, pricing=pricing, limit_usd=1.0)
    guard = ModelGuard(policy=policy)
    alice = Principal(id="alice")

    # first call: still under budget (nothing spent yet)
    resolved = guard.resolve(alice, "m")
    assert resolved == "gpt-x"

    # report usage that exceeds the $1.00 limit: 1000 prompt tokens = $1.00
    guard.record_usage(alice, "gpt-x", prompt_tokens=1000, completion_tokens=0)
    assert policy.spent_by("alice") == pytest.approx(1.0)

    with pytest.raises(ModelCallDenied):
        guard.resolve(alice, "m")


def test_budget_is_tracked_per_principal_independently():
    base = AllowlistModelPolicy({"m": [ModelCandidate("gpt-x")]})
    policy = BudgetPolicy(base, pricing={"gpt-x": (1.0, 0.0)}, limit_usd=1.0)
    guard = ModelGuard(policy=policy)

    alice = Principal(id="alice")
    bob = Principal(id="bob")

    guard.record_usage(alice, "gpt-x", prompt_tokens=1000, completion_tokens=0)

    with pytest.raises(ModelCallDenied):
        guard.resolve(alice, "m")

    # bob hasn't spent anything — still fine
    assert guard.resolve(bob, "m") == "gpt-x"


def test_budget_policy_ignores_usage_for_unpriced_models_without_raising():
    base = AllowlistModelPolicy({"m": [ModelCandidate("unpriced-model")]})
    policy = BudgetPolicy(base, pricing={}, limit_usd=0.01)
    guard = ModelGuard(policy=policy)
    alice = Principal(id="alice")

    guard.record_usage(alice, "unpriced-model", prompt_tokens=1_000_000, completion_tokens=0)

    # no exception, and spend stayed at zero since the model has no pricing entry
    assert policy.spent_by("alice") == 0.0
    assert guard.resolve(alice, "m") == "unpriced-model"


def test_budget_policy_preserves_base_denial_reason_when_already_denied():
    base = AllowlistModelPolicy({})  # nothing configured -> always denies
    policy = BudgetPolicy(base, pricing={}, limit_usd=1000.0)
    guard = ModelGuard(policy=policy)

    with pytest.raises(ModelCallDenied) as exc_info:
        guard.resolve(Principal(id="alice"), "unconfigured")

    assert "no candidate" in exc_info.value.reason


def test_residency_policy_allows_when_resolved_model_covers_the_jurisdiction():
    base = AllowlistModelPolicy({"m": [ModelCandidate("eu-deployment")]})
    policy = ResidencyPolicy(base, allowed_by_jurisdiction={"EU": {"eu-deployment": "adequacy_decision"}})
    guard = ModelGuard(policy=policy)

    resolved = guard.resolve(Principal(id="alice"), "m", context={"jurisdiction": "EU"})
    assert resolved == "eu-deployment"


def test_residency_policy_records_mechanism_and_controller_in_audit_reason():
    sink = InMemoryAuditSink()
    base = AllowlistModelPolicy({"m": [ModelCandidate("eu-deployment")]})
    policy = ResidencyPolicy(base, allowed_by_jurisdiction={"EU": {"eu-deployment": "adequacy_decision"}})
    guard = ModelGuard(policy=policy, audit_sink=sink)

    guard.resolve(
        Principal(id="alice"),
        "m",
        context={"jurisdiction": "EU", "controller": "acme-eu-entity"},
    )

    entry = sink.tail(1)[0]
    assert "adequacy_decision" in entry.reason
    assert "acme-eu-entity" in entry.reason


def test_residency_policy_denies_when_jurisdiction_missing_from_context():
    base = AllowlistModelPolicy({"m": [ModelCandidate("eu-deployment")]})
    policy = ResidencyPolicy(base, allowed_by_jurisdiction={"EU": {"eu-deployment": "adequacy_decision"}})
    guard = ModelGuard(policy=policy)

    with pytest.raises(ModelCallDenied) as exc_info:
        guard.resolve(Principal(id="alice"), "m")

    assert "jurisdiction not provided" in exc_info.value.reason


def test_residency_policy_denies_when_no_deployment_covers_the_jurisdiction():
    base = AllowlistModelPolicy({"m": [ModelCandidate("us-deployment")]})
    policy = ResidencyPolicy(base, allowed_by_jurisdiction={"EU": {"eu-deployment": "adequacy_decision"}})
    guard = ModelGuard(policy=policy)

    with pytest.raises(ModelCallDenied) as exc_info:
        guard.resolve(Principal(id="alice"), "m", context={"jurisdiction": "EU"})

    assert "no jurisdiction-compliant deployment" in exc_info.value.reason


def test_residency_policy_preserves_base_denial_reason_when_already_denied():
    base = AllowlistModelPolicy({})  # nothing configured -> always denies
    policy = ResidencyPolicy(base, allowed_by_jurisdiction={"EU": {"eu-deployment": "adequacy_decision"}})
    guard = ModelGuard(policy=policy)

    with pytest.raises(ModelCallDenied) as exc_info:
        guard.resolve(Principal(id="alice"), "unconfigured", context={"jurisdiction": "EU"})

    assert "no candidate" in exc_info.value.reason


def test_residency_policy_fallback_chain_only_contains_jurisdiction_compliant_candidates():
    base = AllowlistModelPolicy(
        {
            "m": [
                ModelCandidate("primary-eu"),
                ModelCandidate("backup-eu"),
                ModelCandidate("backup-us"),
            ]
        }
    )
    policy = ResidencyPolicy(
        base,
        allowed_by_jurisdiction={
            "EU": {"primary-eu": "adequacy_decision", "backup-eu": "scc_2024_module2"}
        },
    )
    guard = ModelGuard(policy=policy)

    chain = guard.fallback_chain(Principal(id="alice"), "m", context={"jurisdiction": "EU"})
    assert chain == ["backup-eu"]


def test_residency_policy_promotes_a_compliant_fallback_when_top_pick_is_not_compliant():
    base = AllowlistModelPolicy({"m": [ModelCandidate("eu-deployment"), ModelCandidate("in-deployment")]})
    policy = ResidencyPolicy(
        base,
        allowed_by_jurisdiction={
            "EU": {"eu-deployment": "adequacy_decision"},
            "IN": {"in-deployment": "dpdp_section_16"},
        },
    )
    guard = ModelGuard(policy=policy)

    # base always prefers eu-deployment first; a call carrying India-governed
    # data should still resolve to in-deployment, not deny outright
    resolved = guard.resolve(Principal(id="alice"), "m", context={"jurisdiction": "IN"})
    assert resolved == "in-deployment"


def test_residency_policy_fallback_chain_empty_when_jurisdiction_missing():
    base = AllowlistModelPolicy({"m": [ModelCandidate("primary"), ModelCandidate("backup")]})
    policy = ResidencyPolicy(base, allowed_by_jurisdiction={"EU": {"backup": "adequacy_decision"}})
    guard = ModelGuard(policy=policy)

    assert guard.fallback_chain(Principal(id="alice"), "m") == []


def test_residency_policy_composes_with_budget_policy():
    base = AllowlistModelPolicy({"m": [ModelCandidate("eu-deployment")]})
    residency = ResidencyPolicy(base, allowed_by_jurisdiction={"EU": {"eu-deployment": "adequacy_decision"}})
    policy = BudgetPolicy(residency, pricing={"eu-deployment": (1.0, 0.0)}, limit_usd=1.0)
    guard = ModelGuard(policy=policy)
    alice = Principal(id="alice")

    resolved = guard.resolve(alice, "m", context={"jurisdiction": "EU"})
    assert resolved == "eu-deployment"

    guard.record_usage(alice, "eu-deployment", prompt_tokens=1000, completion_tokens=0)

    with pytest.raises(ModelCallDenied):
        guard.resolve(alice, "m", context={"jurisdiction": "EU"})


def test_retention_policy_allows_when_deployment_meets_ceiling():
    base = AllowlistModelPolicy({"m": [ModelCandidate("zdr-deployment")]})
    policy = RetentionPolicy(base, deployment_retention_days={"zdr-deployment": 0})
    guard = ModelGuard(policy=policy)

    resolved = guard.resolve(Principal(id="alice"), "m", context={"max_retention_days": 0})
    assert resolved == "zdr-deployment"


def test_retention_policy_denies_when_max_retention_days_missing_from_context():
    base = AllowlistModelPolicy({"m": [ModelCandidate("zdr-deployment")]})
    policy = RetentionPolicy(base, deployment_retention_days={"zdr-deployment": 0})
    guard = ModelGuard(policy=policy)

    with pytest.raises(ModelCallDenied) as exc_info:
        guard.resolve(Principal(id="alice"), "m")

    assert "max_retention_days not provided" in exc_info.value.reason


def test_retention_policy_denies_when_deployment_retains_longer_than_ceiling():
    base = AllowlistModelPolicy({"m": [ModelCandidate("thirty-day-deployment")]})
    policy = RetentionPolicy(base, deployment_retention_days={"thirty-day-deployment": 30})
    guard = ModelGuard(policy=policy)

    with pytest.raises(ModelCallDenied) as exc_info:
        guard.resolve(Principal(id="alice"), "m", context={"max_retention_days": 0})

    assert "retention ceiling" in exc_info.value.reason


def test_retention_policy_denies_for_unconfigured_deployment():
    base = AllowlistModelPolicy({"m": [ModelCandidate("unknown-to-retention-config")]})
    policy = RetentionPolicy(base, deployment_retention_days={})
    guard = ModelGuard(policy=policy)

    with pytest.raises(ModelCallDenied):
        guard.resolve(Principal(id="alice"), "m", context={"max_retention_days": 30})


def test_retention_policy_promotes_a_compliant_fallback_when_top_pick_retains_too_long():
    base = AllowlistModelPolicy(
        {"m": [ModelCandidate("thirty-day-deployment"), ModelCandidate("zdr-deployment")]}
    )
    policy = RetentionPolicy(
        base, deployment_retention_days={"thirty-day-deployment": 30, "zdr-deployment": 0}
    )
    guard = ModelGuard(policy=policy)

    resolved = guard.resolve(Principal(id="alice"), "m", context={"max_retention_days": 0})
    assert resolved == "zdr-deployment"


def test_residency_and_retention_policies_compose_together():
    base = AllowlistModelPolicy({"m": [ModelCandidate("eu-zdr-deployment")]})
    residency = ResidencyPolicy(base, allowed_by_jurisdiction={"EU": {"eu-zdr-deployment": "adequacy_decision"}})
    policy = RetentionPolicy(residency, deployment_retention_days={"eu-zdr-deployment": 0})
    guard = ModelGuard(policy=policy)

    resolved = guard.resolve(
        Principal(id="alice"), "m", context={"jurisdiction": "EU", "max_retention_days": 0}
    )
    assert resolved == "eu-zdr-deployment"

    # geography passes but retention doesn't: same deployment, stricter ceiling
    with pytest.raises(ModelCallDenied) as exc_info:
        guard.resolve(
            Principal(id="alice"),
            "m",
            context={"jurisdiction": "EU", "max_retention_days": -1},
        )
    assert "retention ceiling" in exc_info.value.reason


def test_record_outcome_writes_model_outcome_entry():
    sink = InMemoryAuditSink()
    guard = ModelGuard(policy=AllowAllModels(), audit_sink=sink)

    guard.record_outcome(Principal(id="alice"), "gpt-fast", success=True, latency_ms=123.4)

    entry = sink.tail(1)[0]
    assert entry.to_dict()["kind"] == "model_outcome"
    assert entry.success is True
    assert entry.model == "gpt-fast"
    assert entry.latency_ms == 123.4
    assert entry.error is None


def test_record_outcome_with_failure_and_error_category():
    sink = InMemoryAuditSink()
    guard = ModelGuard(policy=AllowAllModels(), audit_sink=sink)

    guard.record_outcome(Principal(id="alice"), "gpt-fast", success=False, error="timeout")

    entry = sink.tail(1)[0]
    assert entry.success is False
    assert entry.error == "timeout"


def test_circuit_breaker_allows_healthy_deployment():
    base = AllowlistModelPolicy({"m": [ModelCandidate("a")]})
    policy = CircuitBreakerPolicy(base, failure_threshold=3, window_seconds=60)
    guard = ModelGuard(policy=policy)

    assert guard.resolve(Principal(id="alice"), "m") == "a"


def test_circuit_breaker_trips_after_threshold_failures_and_promotes_fallback():
    base = AllowlistModelPolicy({"m": [ModelCandidate("a"), ModelCandidate("b")]})
    policy = CircuitBreakerPolicy(base, failure_threshold=2, window_seconds=60)
    guard = ModelGuard(policy=policy)
    alice = Principal(id="alice")

    assert guard.resolve(alice, "m") == "a"

    guard.record_outcome(alice, "a", success=False)
    guard.record_outcome(alice, "a", success=False)

    assert guard.resolve(alice, "m") == "b"


def test_circuit_breaker_fails_closed_when_every_candidate_is_tripped():
    base = AllowlistModelPolicy({"m": [ModelCandidate("a"), ModelCandidate("b")]})
    policy = CircuitBreakerPolicy(base, failure_threshold=1, window_seconds=60)
    guard = ModelGuard(policy=policy)
    alice = Principal(id="alice")

    guard.record_outcome(alice, "a", success=False)
    guard.record_outcome(alice, "b", success=False)

    with pytest.raises(ModelCallDenied) as exc_info:
        guard.resolve(alice, "m")
    assert "tripped its circuit breaker" in exc_info.value.reason


def test_circuit_breaker_self_heals_once_the_window_elapses():
    base = AllowlistModelPolicy({"m": [ModelCandidate("a")]})
    policy = CircuitBreakerPolicy(base, failure_threshold=1, window_seconds=0.05)
    guard = ModelGuard(policy=policy)
    alice = Principal(id="alice")

    guard.record_outcome(alice, "a", success=False)
    with pytest.raises(ModelCallDenied):
        guard.resolve(alice, "m")

    time.sleep(0.08)  # past the window — the failure ages out on its own

    assert guard.resolve(alice, "m") == "a"


def test_circuit_breaker_does_not_trip_on_governance_denials():
    # a policy that always denies for compliance reasons, not because the
    # deployment is broken — record_outcome is never called for this, so
    # the circuit breaker has nothing to trip on. Confirms the two are
    # correctly independent: policy denials aren't deployment failures.
    base = AllowlistModelPolicy({})  # always denies: no candidates configured
    policy = CircuitBreakerPolicy(base, failure_threshold=1, window_seconds=60)
    guard = ModelGuard(policy=policy)
    alice = Principal(id="alice")

    for _ in range(5):
        with pytest.raises(ModelCallDenied):
            guard.resolve(alice, "m")

    assert policy.recent_failure_count("m") == 0


def test_circuit_breaker_composes_with_residency_policy():
    base = AllowlistModelPolicy({"m": [ModelCandidate("eu-deployment")]})
    residency = ResidencyPolicy(base, allowed_by_jurisdiction={"EU": {"eu-deployment": "adequacy_decision"}})
    policy = CircuitBreakerPolicy(residency, failure_threshold=1, window_seconds=60)
    guard = ModelGuard(policy=policy)
    alice = Principal(id="alice")

    assert guard.resolve(alice, "m", context={"jurisdiction": "EU"}) == "eu-deployment"

    guard.record_outcome(alice, "eu-deployment", success=False)

    # tripped and no other jurisdiction-compliant candidate exists -> deny
    with pytest.raises(ModelCallDenied):
        guard.resolve(alice, "m", context={"jurisdiction": "EU"})


def test_unified_audit_trail_across_all_three_guards():
    from marshal_ai.retrieval import Document, RetrievalGuard
    from marshal_ai.tools import ToolGuard

    shared_sink = InMemoryAuditSink()
    alice = Principal(id="alice")

    RetrievalGuard(
        retriever=lambda q, k: [Document(id="1", content="a")], audit_sink=shared_sink
    ).retrieve("q", principal=alice, k=1)
    ToolGuard(tool=lambda **kw: "done", audit_sink=shared_sink).call(alice, {})
    ModelGuard(policy=AllowAllModels(), audit_sink=shared_sink).resolve(alice, "m")

    all_activity = shared_sink.query(principal_id="alice")
    assert len(all_activity) == 3
    kinds = {e.to_dict()["kind"] for e in all_activity}
    assert kinds == {"retrieval", "tool_call", "model_call"}


def test_record_usage_writes_to_the_audit_trail():
    sink = InMemoryAuditSink()
    policy = BudgetPolicy(
        AllowlistModelPolicy({"m": [ModelCandidate("gpt-x")]}),
        pricing={"gpt-x": (1.0, 2.0)},
        limit_usd=10.0,
    )
    guard = ModelGuard(policy=policy, audit_sink=sink)
    alice = Principal(id="alice")

    guard.resolve(alice, "m")
    guard.record_usage(alice, "gpt-x", prompt_tokens=100, completion_tokens=50)

    entries = sink.tail(2)
    assert entries[0].to_dict()["kind"] == "model_call"
    usage_entry = entries[1]
    assert usage_entry.to_dict()["kind"] == "model_usage"
    assert usage_entry.model == "gpt-x"
    assert usage_entry.prompt_tokens == 100
    assert usage_entry.completion_tokens == 50
