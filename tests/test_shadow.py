import json

import pytest

from marshal_ai.audit import InMemoryAuditSink, JSONLAuditSink
from marshal_ai.models import (
    AllowlistModelPolicy,
    BudgetPolicy,
    ModelCallDenied,
    ModelCandidate,
    ModelGuard,
)
from marshal_ai.policy import AttributePolicy, FieldRedaction, Principal, RedactingPolicy
from marshal_ai.retrieval import Document, RetrievalGuard
from marshal_ai.tools import (
    ApprovalHandler,
    ArgumentRedaction,
    AutoApprove,
    RedactingToolPolicy,
    RiskTierPolicy,
    ToolCallDenied,
    ToolGuard,
)


# --- RetrievalGuard ----------------------------------------------------------


def test_retrieval_shadow_returns_unfiltered_results_and_audits_would_be_denials():
    docs = [
        Document(id="1", content="public", metadata={}),
        Document(id="2", content="hr-only", metadata={"acl": ["role:hr"]}),
    ]
    sink = InMemoryAuditSink()
    guard = RetrievalGuard(
        retriever=lambda q, k: docs,
        policy=AttributePolicy(default="allow"),
        audit_sink=sink,
        mode="shadow",
    )
    engineer = Principal(id="bob", attributes={"role:engineering"})

    results = guard.retrieve("query", principal=engineer, k=2)

    # nothing is actually filtered out in shadow mode
    assert [d.id for d in results] == ["1", "2"]

    entry = sink.tail(1)[0]
    assert entry.shadow is True
    assert entry.allowed_ids == ["1"]
    assert entry.denied_ids == ["2"]  # what WOULD have been denied under enforce
    assert "role:hr" in entry.denied_reasons["2"]


def test_retrieval_enforce_mode_is_unchanged_by_default():
    docs = [
        Document(id="1", content="public", metadata={}),
        Document(id="2", content="hr-only", metadata={"acl": ["role:hr"]}),
    ]
    sink = InMemoryAuditSink()
    guard = RetrievalGuard(
        retriever=lambda q, k: docs, policy=AttributePolicy(default="allow"), audit_sink=sink
    )
    engineer = Principal(id="bob", attributes={"role:engineering"})

    results = guard.retrieve("query", principal=engineer, k=2)

    assert [d.id for d in results] == ["1"]  # doc 2 is actually filtered out
    entry = sink.tail(1)[0]
    assert entry.shadow is False
    assert entry.denied_ids == ["2"]


def test_retrieval_shadow_audits_which_fields_would_have_been_redacted():
    docs = [Document(id="1", content="secret salary details", metadata={"team": "hr"})]
    policy = RedactingPolicy(
        base=AttributePolicy(default="allow"),
        rules=[FieldRedaction(field="content", requires_attribute="role:hr")],
    )
    sink = InMemoryAuditSink()
    guard = RetrievalGuard(retriever=lambda q, k: docs, policy=policy, audit_sink=sink, mode="shadow")
    engineer = Principal(id="bob", attributes={"role:engineering"})

    results = guard.retrieve("q", principal=engineer, k=1)

    # shadow returns the real, un-redacted content — nothing is hidden
    assert results[0].content == "secret salary details"

    entry = sink.tail(1)[0]
    assert entry.would_redact_fields == {"1": ["content"]}
    # only the field name is recorded, never the value it would have hidden
    assert "secret salary details" not in json.dumps(entry.to_dict())


def test_retrieval_enforce_mode_still_redacts_content():
    docs = [Document(id="1", content="secret salary details", metadata={"team": "hr"})]
    policy = RedactingPolicy(
        base=AttributePolicy(default="allow"),
        rules=[FieldRedaction(field="content", requires_attribute="role:hr")],
    )
    guard = RetrievalGuard(retriever=lambda q, k: docs, policy=policy)
    engineer = Principal(id="bob", attributes={"role:engineering"})

    results = guard.retrieve("q", principal=engineer, k=1)
    assert results[0].content == "[REDACTED]"


# --- ToolGuard -----------------------------------------------------------


def test_tool_shadow_lets_a_denied_call_through_and_audits_the_would_be_denial():
    calls = []

    def dangerous(**kw):
        calls.append(kw)
        return "ran"

    sink = InMemoryAuditSink()
    policy = RiskTierPolicy({"high": "deny"})
    guard = ToolGuard(tool=dangerous, policy=policy, audit_sink=sink, mode="shadow")

    result = guard.call(Principal(id="alice"), {"x": 1}, risk_tier="high")

    assert result == "ran"
    assert calls == [{"x": 1}]  # the tool actually ran — nothing was blocked

    entry = sink.tail(1)[0]
    assert entry.shadow is True
    assert entry.outcome == "deny"  # what governance WOULD have done

    # shadow denials still show up where a real denial would — no changes
    # needed to AuditSink.query or the CLI to make this true
    assert sink.query(denied_only=True) == [entry]


def test_tool_enforce_mode_still_denies():
    policy = RiskTierPolicy({"high": "deny"})
    guard = ToolGuard(tool=lambda **kw: "ran", policy=policy)

    with pytest.raises(ToolCallDenied):
        guard.call(Principal(id="alice"), {"x": 1}, risk_tier="high")


def test_tool_shadow_never_prompts_for_approval_and_lets_the_call_through():
    class ExplodingApprovalHandler(ApprovalHandler):
        identity = "should-never-run"

        def request_approval(self, request, redacted_arguments):
            raise AssertionError("approval handler must not be invoked in shadow mode")

    sink = InMemoryAuditSink()
    policy = RiskTierPolicy({"medium": "require_approval"})
    guard = ToolGuard(
        tool=lambda **kw: "done",
        policy=policy,
        audit_sink=sink,
        approval_handler=ExplodingApprovalHandler(),
        mode="shadow",
    )

    result = guard.call(Principal(id="alice"), {}, risk_tier="medium")

    assert result == "done"
    entry = sink.tail(1)[0]
    assert entry.shadow is True
    assert entry.outcome == "require_approval"  # never resolved to approved/declined
    assert entry.approved_by is None


def test_tool_enforce_mode_still_calls_approval_handler():
    calls = []

    class CountingApprovalHandler(ApprovalHandler):
        identity = "counter"

        def request_approval(self, request, redacted_arguments):
            calls.append(1)
            return True

    policy = RiskTierPolicy({"medium": "require_approval"})
    guard = ToolGuard(
        tool=lambda **kw: "done", policy=policy, approval_handler=CountingApprovalHandler()
    )

    assert guard.call(Principal(id="alice"), {}, risk_tier="medium") == "done"
    assert calls == [1]


def test_tool_shadow_audits_would_be_redacted_field_names_without_raw_values():
    seen_by_tool = []

    def lookup(ssn: str):
        seen_by_tool.append(ssn)
        return "ok"

    policy = RedactingToolPolicy(
        base=RiskTierPolicy({"low": "allow"}),
        rules=[ArgumentRedaction(name="ssn", requires_attribute="role:compliance")],
    )
    sink = InMemoryAuditSink()
    guard = ToolGuard(tool=lookup, policy=policy, audit_sink=sink, mode="shadow")
    engineer = Principal(id="bob", attributes={"role:engineering"})

    guard.call(engineer, {"ssn": "123-45-6789"}, risk_tier="low")

    assert seen_by_tool == ["123-45-6789"]  # the real tool still gets the real value

    entry = sink.tail(1)[0]
    assert entry.would_redact_fields == ["ssn"]
    assert entry.arguments["ssn"] == "[REDACTED]"  # the log itself never shows the raw value
    assert "123-45-6789" not in json.dumps(entry.to_dict())


def test_tool_enforce_mode_unchanged_with_approval():
    policy = RiskTierPolicy({"medium": "require_approval"})
    guard = ToolGuard(tool=lambda **kw: "done", policy=policy, approval_handler=AutoApprove(True))

    assert guard.call(Principal(id="alice"), {}, risk_tier="medium") == "done"


# --- ModelGuard ------------------------------------------------------------


def test_model_shadow_returns_a_sensible_fallback_when_budget_is_exceeded():
    sink = InMemoryAuditSink()
    base = AllowlistModelPolicy({"m": [ModelCandidate("primary"), ModelCandidate("secondary")]})
    policy = BudgetPolicy(base, pricing={"primary": (1.0, 0.0)}, limit_usd=1.0)
    guard = ModelGuard(policy=policy, audit_sink=sink, mode="shadow")
    alice = Principal(id="alice")

    resolved = guard.resolve(alice, "m")
    assert resolved == "primary"  # under budget — the real resolution

    guard.record_usage(alice, "primary", prompt_tokens=1000, completion_tokens=0)

    resolved_again = guard.resolve(alice, "m")
    # would have denied (budget exceeded); shadow falls back to the base
    # policy's own next qualifying candidate instead of raising
    assert resolved_again == "secondary"

    entry = sink.tail(1)[0]
    assert entry.shadow is True
    assert entry.outcome == "deny"
    assert "budget exceeded" in entry.reason
    assert entry.resolved_model == "secondary"


def test_model_shadow_falls_back_to_logical_name_when_nothing_else_is_available():
    sink = InMemoryAuditSink()
    policy = AllowlistModelPolicy({})  # nothing routed at all
    guard = ModelGuard(policy=policy, audit_sink=sink, mode="shadow")
    alice = Principal(id="alice")

    resolved = guard.resolve(alice, "unconfigured-model")

    assert resolved == "unconfigured-model"  # last-resort passthrough, never raises
    entry = sink.tail(1)[0]
    assert entry.shadow is True
    assert entry.outcome == "deny"
    assert entry.resolved_model == "unconfigured-model"


def test_model_enforce_mode_still_raises_on_denial():
    policy = AllowlistModelPolicy({})
    guard = ModelGuard(policy=policy)

    with pytest.raises(ModelCallDenied):
        guard.resolve(Principal(id="alice"), "unconfigured-model")


def test_model_shadow_allow_path_is_unaffected():
    policy = AllowlistModelPolicy({"m": [ModelCandidate("gpt-fast")]})
    sink = InMemoryAuditSink()
    guard = ModelGuard(policy=policy, audit_sink=sink, mode="shadow")

    assert guard.resolve(Principal(id="alice"), "m") == "gpt-fast"
    entry = sink.tail(1)[0]
    assert entry.shadow is True
    assert entry.outcome == "allow"


# --- JSONL round-trip for the new shadow fields -------------------------------


def test_shadow_entries_round_trip_through_jsonl(tmp_path):
    path = tmp_path / "audit.jsonl"
    sink = JSONLAuditSink(path)
    alice = Principal(id="alice")

    RetrievalGuard(
        retriever=lambda q, k: [Document(id="1", content="x", metadata={"acl": ["role:hr"]})],
        policy=AttributePolicy(default="allow"),
        audit_sink=sink,
        mode="shadow",
    ).retrieve("q", principal=alice, k=1)

    ToolGuard(
        tool=lambda **kw: "ok",
        policy=RiskTierPolicy({"high": "deny"}),
        audit_sink=sink,
        mode="shadow",
    ).call(alice, {}, risk_tier="high")

    ModelGuard(policy=AllowlistModelPolicy({}), audit_sink=sink, mode="shadow").resolve(alice, "m")

    entries = sink.all_entries()
    assert len(entries) == 3
    assert all(e.shadow is True for e in entries)

    retrieval_entry, tool_entry, model_entry = entries
    assert retrieval_entry.denied_ids == ["1"]
    assert tool_entry.outcome == "deny"
    assert model_entry.outcome == "deny"
    assert model_entry.resolved_model == "m"  # last-resort passthrough

    # reading the file back from scratch (a fresh sink over the same path)
    # reconstructs the same shadow-flagged entries — proves persistence,
    # not just in-memory storage
    reloaded = JSONLAuditSink(path).all_entries()
    assert [e.shadow for e in reloaded] == [True, True, True]
    assert reloaded[0].denied_ids == ["1"]


def test_jsonl_sink_still_reads_older_logs_missing_the_new_shadow_fields(tmp_path):
    path = tmp_path / "audit.jsonl"
    old_retrieval_line = {
        "kind": "retrieval",
        "timestamp": 1.0,
        "principal_id": "alice",
        "query": "q",
        "candidates_seen": 1,
        "allowed_ids": ["1"],
        "denied_ids": [],
        "denied_reasons": {},
    }
    old_tool_line = {
        "kind": "tool_call",
        "timestamp": 2.0,
        "principal_id": "alice",
        "tool_name": "t",
        "arguments": {},
        "risk_tier": "low",
        "outcome": "allow",
        "reason": "AllowAllTools policy",
        "approved_by": None,
    }
    old_model_line = {
        "kind": "model_call",
        "timestamp": 3.0,
        "principal_id": "alice",
        "logical_name": "m",
        "resolved_model": "m",
        "outcome": "allow",
        "reason": "AllowAllModels policy",
    }
    path.write_text(
        "\n".join(json.dumps(line) for line in [old_retrieval_line, old_tool_line, old_model_line])
        + "\n",
        encoding="utf-8",
    )

    sink = JSONLAuditSink(path)
    entries = sink.all_entries()

    assert len(entries) == 3
    assert all(e.shadow is False for e in entries)
    assert entries[0].would_redact_fields == {}
    assert entries[1].would_redact_fields == []
