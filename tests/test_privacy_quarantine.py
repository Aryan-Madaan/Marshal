import os
import subprocess
import sys

import pytest

from marshal_ai import (
    AllowlistModelPolicy,
    InMemoryAuditSink,
    JSONLAuditSink,
    ModelCallDenied,
    ModelCandidate,
    ModelGuard,
    Principal,
    RiskTierPolicy,
    ToolCallDenied,
    ToolGuard,
)
from marshal_ai.privacy import PseudonymizingAuditSink
from marshal_ai.quarantine import Quarantine, QuarantineModelPolicy, QuarantineToolPolicy

KEY = os.urandom(32)


# --- pseudonymization ------------------------------------------------------------


def test_raw_identities_never_reach_the_stored_trail(tmp_path):
    from marshal_ai.incidents import record_incident

    path = tmp_path / "audit.jsonl"
    sink = PseudonymizingAuditSink(JSONLAuditSink(path), key=KEY)
    agent = Principal("support-bot", on_behalf_of=Principal("alice@company.com"))
    ToolGuard(tool=lambda **kw: 1, audit_sink=sink, tool_name="lookup").call(agent, {"order": "1"})
    record_incident(sink, Principal("dpo@company.com"), title="t", category="fundamental_rights",
                    description="d", affected_principals=("alice@company.com",))

    stored = path.read_text()
    for raw in ("alice@company.com", "dpo@company.com", "support-bot"):
        assert raw not in stored

    assert len(sink.query_on_behalf_of("alice@company.com")) == 1
    assert len(sink.query_principal("support-bot")) == 1
    assert sink.pseudonym_for("alice@company.com") == PseudonymizingAuditSink(InMemoryAuditSink(), KEY).pseudonym_for("alice@company.com")
    assert sink.pseudonym_for("x") != PseudonymizingAuditSink(InMemoryAuditSink(), os.urandom(32)).pseudonym_for("x")


def test_weak_keys_are_rejected():
    with pytest.raises(ValueError):
        PseudonymizingAuditSink(InMemoryAuditSink(), key=b"short")


def test_hash_chain_still_verifies_through_the_wrapper(tmp_path):
    from marshal_ai import SQLiteAuditSink

    sink = PseudonymizingAuditSink(SQLiteAuditSink(tmp_path / "a.db"), key=KEY)
    ToolGuard(tool=lambda: 1, audit_sink=sink, tool_name="t").call(Principal("p"), {})
    assert sink.verify().ok and sink.anchor().count == 1


# --- quarantine ----------------------------------------------------------------------


def _tool_guard(q, sink, name="wire_transfer"):
    return ToolGuard(tool=lambda **kw: "sent", policy=QuarantineToolPolicy(RiskTierPolicy({"low": "allow"}), q),
                     audit_sink=sink, tool_name=name)


def test_quarantined_tool_and_agent_are_refused_and_release_restores(tmp_path):
    sink = InMemoryAuditSink()
    q = Quarantine(tmp_path / "q.db", audit_sink=sink)
    guard = _tool_guard(q, sink)
    assert guard.call(Principal("a"), {}) == "sent"

    q.quarantine("tool", "wire_transfer", reason="INC-42 suspected misuse", by="oncall@co")
    with pytest.raises(ToolCallDenied, match="quarantined by oncall@co: INC-42"):
        guard.call(Principal("a"), {})
    q.release("tool", "wire_transfer", by="oncall@co", reason="fixed")
    assert guard.call(Principal("a"), {}) == "sent"

    q.quarantine("agent", "alice", reason="compromised account", by="secops@co")
    with pytest.raises(ToolCallDenied):  # an agent acting *for* a quarantined user is stopped too
        guard.call(Principal("support-bot", on_behalf_of=Principal("alice")), {})
    assert guard.call(Principal("support-bot", on_behalf_of=Principal("bob")), {}) == "sent"

    actions = [(e.action, e.subject_kind, e.principal_id) for e in sink.all_entries() if e.to_dict()["kind"] == "quarantine"]
    assert actions == [("quarantine", "tool", "oncall@co"), ("release", "tool", "oncall@co"), ("quarantine", "agent", "secops@co")]
    assert [h["action"] for h in q.history()] == ["quarantine", "release", "quarantine"]


def test_quarantine_set_in_another_process_applies_immediately(tmp_path):
    db = tmp_path / "q.db"
    guard = _tool_guard(Quarantine(db), InMemoryAuditSink())
    assert guard.call(Principal("a"), {}) == "sent"
    subprocess.run([sys.executable, "-c",
                    "import sys; from marshal_ai.quarantine import Quarantine; "
                    "Quarantine(sys.argv[1]).quarantine('tool', 'wire_transfer', reason='r', by='ops')", str(db)], check=True)
    with pytest.raises(ToolCallDenied):
        guard.call(Principal("a"), {})


def test_quarantined_model_is_routed_around_or_denied(tmp_path):
    q = Quarantine(tmp_path / "q.db")
    routes = AllowlistModelPolicy({"chat": [ModelCandidate("gpt-primary"), ModelCandidate("gpt-backup")]})
    guard = ModelGuard(policy=QuarantineModelPolicy(routes, q))
    q.quarantine("model", "gpt-primary", reason="bad release", by="ops")
    assert guard.resolve(Principal("a"), "chat") == "gpt-backup"
    q.quarantine("model", "gpt-backup", reason="also bad", by="ops")
    with pytest.raises(ModelCallDenied, match="quarantined"):
        guard.resolve(Principal("a"), "chat")
    q.quarantine("agent", "rogue", reason="r", by="ops")
    with pytest.raises(ModelCallDenied):
        guard.resolve(Principal("rogue"), "chat")


def test_unreadable_store_fails_closed(tmp_path):
    q = Quarantine(tmp_path / "q.db")
    guard = _tool_guard(q, InMemoryAuditSink())
    q.close()
    with pytest.raises(ToolCallDenied, match="failing closed"):
        guard.call(Principal("a"), {})


def test_every_action_needs_who_and_why(tmp_path):
    q = Quarantine(tmp_path / "q.db")
    with pytest.raises(ValueError):
        q.quarantine("tool", "x", reason="", by="ops")
    with pytest.raises(ValueError):
        q.quarantine("planet", "x", reason="r", by="ops")
    with pytest.raises(KeyError):
        q.release("tool", "never-quarantined", by="ops", reason="r")
