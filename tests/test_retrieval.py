from typing import Callable

from marshal_ai.audit import InMemoryAuditSink
from marshal_ai.retrieval import Document, RetrievalGuard
from marshal_ai.policy import AttributePolicy, Principal


def fake_retriever(all_docs: list[Document]) -> Callable[[str, int], list[Document]]:
    def _retriever(query: str, k: int) -> list[Document]:
        return all_docs[:k]

    return _retriever


def test_guard_zero_config_allows_everything_and_audits():
    docs = [Document(id="1", content="hello"), Document(id="2", content="world")]
    guard = RetrievalGuard(retriever=fake_retriever(docs))
    alice = Principal(id="alice")

    results = guard.retrieve("hi", principal=alice, k=2)

    assert [d.id for d in results] == ["1", "2"]
    entry = guard.audit_log.tail(1)[0]
    assert entry.principal_id == "alice"
    assert entry.allowed_ids == ["1", "2"]
    assert entry.denied_ids == []
    assert entry.candidates_seen == 2


def test_guard_filters_by_policy_and_audits_denials():
    docs = [
        Document(id="1", content="public", metadata={}),
        Document(id="2", content="hr-only", metadata={"acl": ["role:hr"]}),
    ]
    guard = RetrievalGuard(
        retriever=fake_retriever(docs),
        policy=AttributePolicy(default="allow"),
    )
    engineer = Principal(id="bob", attributes={"role:engineering"})

    results = guard.retrieve("query", principal=engineer, k=2)

    assert [d.id for d in results] == ["1"]
    entry = guard.audit_log.tail(1)[0]
    assert entry.allowed_ids == ["1"]
    assert entry.denied_ids == ["2"]
    assert "role:hr" in entry.denied_reasons["2"]


def test_guard_default_deny_filters_unlabeled_documents_too():
    docs = [Document(id="1", content="unlabeled", metadata={})]
    guard = RetrievalGuard(
        retriever=fake_retriever(docs),
        policy=AttributePolicy(default="deny"),
    )
    someone = Principal(id="x")

    results = guard.retrieve("query", principal=someone, k=1)

    assert results == []
    assert guard.audit_log.tail(1)[0].denied_ids == ["1"]


def test_guard_passes_query_and_k_through_to_retriever():
    calls = []

    def retriever(query: str, k: int) -> list[Document]:
        calls.append((query, k))
        return []

    guard = RetrievalGuard(retriever=retriever)
    guard.retrieve("what is the leave policy", principal=Principal(id="x"), k=3)

    assert calls == [("what is the leave policy", 3)]


def test_guard_uses_custom_audit_sink():
    sink = InMemoryAuditSink()
    guard = RetrievalGuard(retriever=fake_retriever([]), audit_sink=sink)

    guard.retrieve("q", principal=Principal(id="x"), k=1)

    assert len(sink) == 1


def test_guard_preserves_retriever_order_among_allowed_docs():
    docs = [
        Document(id="3", content="c"),
        Document(id="1", content="a"),
        Document(id="2", content="b"),
    ]
    guard = RetrievalGuard(retriever=fake_retriever(docs))

    results = guard.retrieve("q", principal=Principal(id="x"), k=3)

    assert [d.id for d in results] == ["3", "1", "2"]
