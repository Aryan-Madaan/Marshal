import pytest

from marshal_ai.audit import InMemoryAuditSink
from marshal_ai.models import (
    AllowAllModels,
    AllowlistModelPolicy,
    BudgetPolicy,
    ModelCallDenied,
    ModelCandidate,
    ModelGuard,
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
