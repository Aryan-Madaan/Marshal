import json

import pytest

from marshal_ai import (
    AttributePolicy,
    DelegatedPolicy,
    Document,
    FieldRedaction,
    InMemoryAuditSink,
    JSONLAuditSink,
    Principal,
    RedactingPolicy,
    RetrievalGuard,
    SQLiteAuditSink,
    ToolGuard,
)
from marshal_ai.audit import decode_entry

DOCS = [
    Document("public", "hello", {"acl": ["role:customer", "role:support"]}),
    Document("internal", "runbook", {"acl": ["role:support"]}),
]
SUPPORT_BOT = Principal("support-bot", {"role:support"})
ALICE = Principal("alice", {"role:customer"})


def test_principal_chain_helpers():
    nested = Principal("sub-agent", on_behalf_of=Principal("bot", on_behalf_of=ALICE))
    assert nested.delegation_chain == ["bot", "alice"]
    assert nested.subject.id == "alice"
    assert [h.id for h in nested.hops()] == ["sub-agent", "bot", "alice"]
    assert all(h.on_behalf_of is None for h in nested.hops())
    assert SUPPORT_BOT.acting_for(ALICE).on_behalf_of == ALICE
    assert SUPPORT_BOT.delegation_chain == [] and SUPPORT_BOT.subject is SUPPORT_BOT


def test_confused_deputy_agent_cannot_see_more_than_the_user_it_acts_for():
    guard = RetrievalGuard(lambda q, k: DOCS, policy=DelegatedPolicy(AttributePolicy()))
    assert {d.id for d in guard.retrieve("q", SUPPORT_BOT)} == {"public", "internal"}
    assert {d.id for d in guard.retrieve("q", SUPPORT_BOT.acting_for(ALICE))} == {"public"}


def test_user_cannot_borrow_the_agents_broader_access_either():
    narrow_bot = Principal("faq-bot", {"role:customer"})
    staff = Principal("staff", {"role:support"})
    guard = RetrievalGuard(lambda q, k: DOCS, policy=DelegatedPolicy(AttributePolicy()))
    assert {d.id for d in guard.retrieve("q", narrow_bot.acting_for(staff))} == {"public"}


def test_denial_reason_names_the_hop_that_failed():
    sink = InMemoryAuditSink()
    guard = RetrievalGuard(lambda q, k: DOCS, policy=DelegatedPolicy(AttributePolicy()), audit_sink=sink)
    guard.retrieve("q", SUPPORT_BOT.acting_for(ALICE))
    entry = sink.tail(1)[0]
    assert "'alice'" in entry.denied_reasons["internal"]
    assert entry.on_behalf_of == ["alice"]


def test_redaction_applies_for_the_most_restricted_hop():
    policy = DelegatedPolicy(
        RedactingPolicy(AttributePolicy(), [FieldRedaction("content", requires_attribute="role:support")])
    )
    guard = RetrievalGuard(lambda q, k: DOCS[:1], policy=policy)
    assert guard.retrieve("q", SUPPORT_BOT)[0].content == "hello"
    assert guard.retrieve("q", SUPPORT_BOT.acting_for(ALICE))[0].content == "[REDACTED]"


def test_delegated_principal_disables_pushdown_filters():
    from marshal_ai import GroupPolicy

    policy = DelegatedPolicy(GroupPolicy())
    assert policy.to_filter(Principal("x", {"team:a"})) is not None
    assert policy.to_filter(Principal("x", {"team:a"}, on_behalf_of=ALICE)) is None


@pytest.mark.parametrize("sink_factory", ["memory", "jsonl", "sqlite"])
def test_query_on_behalf_of_works_on_every_sink(tmp_path, sink_factory):
    sink = {
        "memory": lambda: InMemoryAuditSink(),
        "jsonl": lambda: JSONLAuditSink(tmp_path / "a.jsonl"),
        "sqlite": lambda: SQLiteAuditSink(tmp_path / "a.db"),
    }[sink_factory]()
    ToolGuard(tool=lambda **kw: 1, audit_sink=sink, tool_name="t").call(SUPPORT_BOT.acting_for(ALICE), {})
    ToolGuard(tool=lambda **kw: 1, audit_sink=sink, tool_name="t").call(SUPPORT_BOT, {})
    for_alice = sink.query(on_behalf_of="alice")
    assert len(for_alice) == 1 and for_alice[0].principal_id == "support-bot"


def test_pre_v013_log_lines_without_on_behalf_of_still_decode():
    old_line = {"kind": "tool_call", "timestamp": 1.0, "principal_id": "a", "tool_name": "t",
                "arguments": {}, "risk_tier": "low", "outcome": "allow", "reason": "r"}
    entry = decode_entry(json.loads(json.dumps(old_line)))
    assert entry.on_behalf_of == [] and entry.mcp_server is None
