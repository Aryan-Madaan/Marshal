import json
import sqlite3
from pathlib import Path

import pytest

from marshal_ai.audit import AuditEntry
from marshal_ai.models import ModelCallEntry
from marshal_ai.sinks import GENESIS_HASH, ChainVerificationResult, SQLiteAuditSink
from marshal_ai.tools import ToolCallEntry


def make_retrieval_entry(i: int, principal_id: str = "alice", denied: bool = False) -> AuditEntry:
    return AuditEntry(
        timestamp=float(i),
        principal_id=principal_id,
        query=f"q{i}",
        candidates_seen=2,
        allowed_ids=[] if denied else ["doc-a"],
        denied_ids=["doc-b"] if denied else [],
        denied_reasons={"doc-b": "no match"} if denied else {},
    )


def make_tool_entry(i: int, principal_id: str = "bob", outcome: str = "allow") -> ToolCallEntry:
    return ToolCallEntry(
        timestamp=float(i),
        principal_id=principal_id,
        tool_name="send_email",
        arguments={"to": "someone"},
        risk_tier="low",
        outcome=outcome,
        reason="test reason",
        approved_by="cli-approver" if outcome in ("approved", "declined") else None,
    )


def make_model_entry(
    i: int, principal_id: str = "carol", outcome: str = "allow", resolved_model: str = "eu-deployment"
) -> ModelCallEntry:
    return ModelCallEntry(
        timestamp=float(i),
        principal_id=principal_id,
        logical_name="default-chat-model",
        resolved_model=resolved_model if outcome == "allow" else None,
        outcome=outcome,
        reason="resolved 'default-chat-model' -> 'eu-deployment' for jurisdiction 'EU' via 'adequacy_decision'",
    )


def test_round_trips_mixed_entry_types(tmp_path: Path):
    path = tmp_path / "audit.db"
    sink = SQLiteAuditSink(path)

    retrieval = make_retrieval_entry(1)
    tool_call = make_tool_entry(2)
    model_call = make_model_entry(3)

    sink.write(retrieval)
    sink.write(tool_call)
    sink.write(model_call)

    entries = sink.all_entries()
    assert len(entries) == 3
    assert isinstance(entries[0], AuditEntry)
    assert entries[0].query == "q1"
    assert isinstance(entries[1], ToolCallEntry)
    assert entries[1].tool_name == "send_email"
    assert isinstance(entries[2], ModelCallEntry)
    assert entries[2].resolved_model == "eu-deployment"
    sink.close()


def test_round_trips_model_usage_and_outcome_entries(tmp_path: Path):
    from marshal_ai.models import ModelOutcomeEntry, ModelUsageEntry

    sink = SQLiteAuditSink(tmp_path / "audit.db")
    sink.write(
        ModelUsageEntry(
            timestamp=1.0, principal_id="carol", model="eu-deployment", prompt_tokens=10, completion_tokens=5
        )
    )
    sink.write(
        ModelOutcomeEntry(
            timestamp=2.0, principal_id="carol", model="eu-deployment", success=False, error="timeout"
        )
    )
    entries = sink.all_entries()
    assert isinstance(entries[0], ModelUsageEntry)
    assert entries[0].prompt_tokens == 10
    assert isinstance(entries[1], ModelOutcomeEntry)
    assert entries[1].error == "timeout"
    sink.close()


def test_survives_close_and_reopen(tmp_path: Path):
    path = tmp_path / "audit.db"
    sink = SQLiteAuditSink(path)
    sink.write(make_retrieval_entry(1))
    sink.write(make_tool_entry(2))
    sink.close()

    reopened = SQLiteAuditSink(path)
    entries = reopened.all_entries()
    assert len(entries) == 2
    assert entries[0].timestamp == 1.0
    assert entries[1].timestamp == 2.0
    reopened.close()


def test_reopen_continues_the_hash_chain(tmp_path: Path):
    path = tmp_path / "audit.db"
    sink = SQLiteAuditSink(path)
    sink.write(make_retrieval_entry(1))
    sink.close()

    reopened = SQLiteAuditSink(path)
    reopened.write(make_retrieval_entry(2))
    result = reopened.verify()
    assert result.ok
    assert result.checked == 2
    reopened.close()


def test_query_filters_by_principal_id(tmp_path: Path):
    sink = SQLiteAuditSink(tmp_path / "audit.db")
    sink.write(make_retrieval_entry(1, principal_id="alice"))
    sink.write(make_tool_entry(2, principal_id="bob"))
    sink.write(make_model_entry(3, principal_id="alice"))

    results = sink.query(principal_id="alice")
    assert [e.timestamp for e in results] == [1.0, 3.0]
    sink.close()


def test_query_filters_by_time_range(tmp_path: Path):
    sink = SQLiteAuditSink(tmp_path / "audit.db")
    for i in range(1, 6):
        sink.write(make_retrieval_entry(i))
    results = sink.query(since=2.0, until=4.0)
    assert [e.timestamp for e in results] == [2.0, 3.0, 4.0]
    sink.close()


def test_query_denied_only(tmp_path: Path):
    sink = SQLiteAuditSink(tmp_path / "audit.db")
    sink.write(make_retrieval_entry(1, denied=False))
    sink.write(make_retrieval_entry(2, denied=True))
    sink.write(make_tool_entry(3, outcome="deny"))
    sink.write(make_model_entry(4, outcome="allow"))

    results = sink.query(denied_only=True)
    assert [e.timestamp for e in results] == [2.0, 3.0]
    sink.close()


def test_query_combines_filters(tmp_path: Path):
    sink = SQLiteAuditSink(tmp_path / "audit.db")
    sink.write(make_tool_entry(1, principal_id="bob", outcome="allow"))
    sink.write(make_tool_entry(2, principal_id="bob", outcome="deny"))
    sink.write(make_tool_entry(3, principal_id="carol", outcome="deny"))

    results = sink.query(principal_id="bob", denied_only=True)
    assert [e.timestamp for e in results] == [2.0]
    sink.close()


def test_tail_uses_default_all_entries_implementation(tmp_path: Path):
    sink = SQLiteAuditSink(tmp_path / "audit.db")
    for i in range(1, 6):
        sink.write(make_retrieval_entry(i))
    tailed = sink.tail(2)
    assert [e.timestamp for e in tailed] == [4.0, 5.0]
    sink.close()


def test_len_reports_entry_count(tmp_path: Path):
    sink = SQLiteAuditSink(tmp_path / "audit.db")
    assert len(sink) == 0
    sink.write(make_retrieval_entry(1))
    sink.write(make_retrieval_entry(2))
    assert len(sink) == 2
    sink.close()


# --- hash chain / tamper evidence ------------------------------------------


def test_verify_passes_on_intact_log(tmp_path: Path):
    sink = SQLiteAuditSink(tmp_path / "audit.db")
    sink.write(make_retrieval_entry(1))
    sink.write(make_tool_entry(2))
    sink.write(make_model_entry(3))
    result = sink.verify()
    assert result == ChainVerificationResult(ok=True, checked=3)
    sink.close()


def test_verify_passes_on_empty_log(tmp_path: Path):
    sink = SQLiteAuditSink(tmp_path / "audit.db")
    result = sink.verify()
    assert result.ok
    assert result.checked == 0
    sink.close()


def test_first_record_chains_from_genesis_hash(tmp_path: Path):
    path = tmp_path / "audit.db"
    sink = SQLiteAuditSink(path)
    sink.write(make_retrieval_entry(1))
    sink.close()

    conn = sqlite3.connect(str(path))
    row = conn.execute("SELECT prev_hash FROM audit_entries WHERE seq = 1").fetchone()
    conn.close()
    assert row[0] == GENESIS_HASH


def test_verify_pinpoints_tampered_record_data(tmp_path: Path):
    path = tmp_path / "audit.db"
    sink = SQLiteAuditSink(path)
    sink.write(make_retrieval_entry(1))
    sink.write(make_tool_entry(2))
    sink.write(make_model_entry(3))
    sink.close()

    # Mutate the second record's stored data directly, bypassing the sink
    # entirely — simulating someone editing the underlying DB file by hand
    # after the fact (exactly the scenario the hash chain exists to catch).
    conn = sqlite3.connect(str(path))
    row = conn.execute("SELECT data FROM audit_entries WHERE seq = 2").fetchone()
    tampered = json.loads(row[0])
    tampered["tool_name"] = "delete_everything"
    conn.execute(
        "UPDATE audit_entries SET data = ? WHERE seq = 2", (json.dumps(tampered, sort_keys=True),)
    )
    conn.commit()
    conn.close()

    reopened = SQLiteAuditSink(path)
    result = reopened.verify()
    assert result.ok is False
    assert result.broken_at_seq == 2
    assert result.broken_kind == "tool_call"
    assert result.broken_principal_id == "bob"
    reopened.close()


def test_verify_pinpoints_deleted_record(tmp_path: Path):
    path = tmp_path / "audit.db"
    sink = SQLiteAuditSink(path)
    sink.write(make_retrieval_entry(1))
    sink.write(make_tool_entry(2))
    sink.write(make_model_entry(3))
    sink.close()

    conn = sqlite3.connect(str(path))
    conn.execute("DELETE FROM audit_entries WHERE seq = 2")
    conn.commit()
    conn.close()

    reopened = SQLiteAuditSink(path)
    result = reopened.verify()
    assert result.ok is False
    # Record 2 is gone; record 3's stored prev_hash no longer matches the
    # hash actually produced by record 1 — the break surfaces at seq 3,
    # the first row that's still present and inconsistent.
    assert result.broken_at_seq == 3
    assert result.broken_kind == "model_call"
    reopened.close()


def test_verify_pinpoints_reordered_records(tmp_path: Path):
    path = tmp_path / "audit.db"
    sink = SQLiteAuditSink(path)
    sink.write(make_retrieval_entry(1))
    sink.write(make_tool_entry(2))
    sink.write(make_model_entry(3))
    sink.close()

    conn = sqlite3.connect(str(path))
    row2 = conn.execute("SELECT data FROM audit_entries WHERE seq = 2").fetchone()[0]
    row3 = conn.execute("SELECT data FROM audit_entries WHERE seq = 3").fetchone()[0]
    conn.execute("UPDATE audit_entries SET data = ? WHERE seq = 2", (row3,))
    conn.execute("UPDATE audit_entries SET data = ? WHERE seq = 3", (row2,))
    conn.commit()
    conn.close()

    reopened = SQLiteAuditSink(path)
    result = reopened.verify()
    assert result.ok is False
    assert result.broken_at_seq == 2
    reopened.close()


def test_verify_pinpoints_tampered_hash_field_itself(tmp_path: Path):
    path = tmp_path / "audit.db"
    sink = SQLiteAuditSink(path)
    sink.write(make_retrieval_entry(1))
    sink.write(make_tool_entry(2))
    sink.close()

    conn = sqlite3.connect(str(path))
    conn.execute("UPDATE audit_entries SET hash = ? WHERE seq = 1", ("f" * 64,))
    conn.commit()
    conn.close()

    reopened = SQLiteAuditSink(path)
    result = reopened.verify()
    assert result.ok is False
    # seq 1's own hash was tampered directly -> caught while checking seq 1.
    assert result.broken_at_seq == 1
    reopened.close()


def test_indexes_exist_on_principal_id_and_timestamp(tmp_path: Path):
    path = tmp_path / "audit.db"
    sink = SQLiteAuditSink(path)
    sink.write(make_retrieval_entry(1))
    sink.close()

    conn = sqlite3.connect(str(path))
    names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    conn.close()
    assert any("principal_id" in n for n in names)
    assert any("timestamp" in n for n in names)


def test_creates_parent_directories(tmp_path: Path):
    path = tmp_path / "nested" / "dir" / "audit.db"
    sink = SQLiteAuditSink(path)
    sink.write(make_retrieval_entry(1))
    assert path.exists()
    sink.close()
