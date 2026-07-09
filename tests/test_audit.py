import json
from pathlib import Path

from marshal_ai.audit import AuditEntry, InMemoryAuditSink, JSONLAuditSink


def make_entry(
    i: int, principal_id: str | None = None, denied: bool = False
) -> AuditEntry:
    return AuditEntry(
        timestamp=float(i),
        principal_id=principal_id or f"user-{i}",
        query="q",
        candidates_seen=1,
        allowed_ids=[] if denied else ["a"],
        denied_ids=["a"] if denied else [],
        denied_reasons={"a": "no match"} if denied else {},
    )


def test_in_memory_sink_records_and_tails():
    sink = InMemoryAuditSink()
    for i in range(5):
        sink.write(make_entry(i))
    assert len(sink) == 5
    assert [e.principal_id for e in sink.tail(2)] == ["user-3", "user-4"]


def test_in_memory_sink_evicts_oldest_past_max():
    sink = InMemoryAuditSink(max_entries=3)
    for i in range(5):
        sink.write(make_entry(i))
    assert len(sink) == 3
    assert [e.principal_id for e in sink.tail(3)] == ["user-2", "user-3", "user-4"]


def test_jsonl_sink_round_trips(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    sink = JSONLAuditSink(path)
    sink.write(make_entry(1))
    sink.write(make_entry(2))

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["principal_id"] == "user-1"

    tailed = sink.tail(1)
    assert len(tailed) == 1
    assert tailed[0].principal_id == "user-2"


def test_jsonl_sink_tail_on_missing_file(tmp_path: Path):
    path = tmp_path / "does-not-exist.jsonl"
    sink = JSONLAuditSink(path)
    assert sink.tail(5) == []


def test_jsonl_sink_creates_parent_directories(tmp_path: Path):
    path = tmp_path / "nested" / "dir" / "audit.jsonl"
    sink = JSONLAuditSink(path)
    sink.write(make_entry(1))
    assert path.exists()


def _populate(sink) -> None:
    sink.write(make_entry(1, principal_id="alice", denied=False))
    sink.write(make_entry(2, principal_id="alice", denied=True))
    sink.write(make_entry(3, principal_id="bob", denied=False))
    sink.write(make_entry(4, principal_id="bob", denied=True))


def test_query_filters_by_principal_id():
    sink = InMemoryAuditSink()
    _populate(sink)
    results = sink.query(principal_id="alice")
    assert [e.timestamp for e in results] == [1.0, 2.0]


def test_query_filters_by_denied_only():
    sink = InMemoryAuditSink()
    _populate(sink)
    results = sink.query(denied_only=True)
    assert [e.principal_id for e in results] == ["alice", "bob"]
    assert all(e.denied_ids for e in results)


def test_query_filters_by_time_range():
    sink = InMemoryAuditSink()
    _populate(sink)
    results = sink.query(since=2.0, until=3.0)
    assert [e.timestamp for e in results] == [2.0, 3.0]


def test_query_combines_filters():
    sink = InMemoryAuditSink()
    _populate(sink)
    results = sink.query(principal_id="bob", denied_only=True)
    assert [e.timestamp for e in results] == [4.0]


def test_query_works_on_jsonl_sink_too(tmp_path: Path):
    sink = JSONLAuditSink(tmp_path / "audit.jsonl")
    _populate(sink)
    results = sink.query(principal_id="alice", denied_only=True)
    assert [e.timestamp for e in results] == [2.0]
