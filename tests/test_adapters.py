"""Proves RetrievalGuard against two real backends instead of the fake
in-memory retriever every other retrieval test uses — a real `chromadb`
`EphemeralClient` collection, and a real `langchain_core`
`InMemoryVectorStore` retriever. No network, no API keys: both use a tiny
deterministic embedding function defined below instead of chromadb's
network-downloaded default ONNX model or a real embeddings API.
"""

from typing import Any

import pytest

chromadb = pytest.importorskip("chromadb")
from chromadb.api.types import Documents, Embeddings, EmbeddingFunction  # noqa: E402

pytest.importorskip("langchain_core")
from langchain_core.documents import Document as LCDocument  # noqa: E402
from langchain_core.embeddings import Embeddings as LCEmbeddings  # noqa: E402
from langchain_core.retrievers import BaseRetriever  # noqa: E402
from langchain_core.vectorstores import InMemoryVectorStore  # noqa: E402

from marshal_ai.adapters import from_chroma_collection, from_langchain_retriever
from marshal_ai.policy import AttributePolicy, GroupPolicy, Principal
from marshal_ai.retrieval import RetrievalGuard


class _DeterministicChromaEmbedding(EmbeddingFunction):
    """A trivial, fully offline stand-in for a real embedding model — no
    network call, no downloaded ONNX model (chromadb's default embedding
    function downloads one on first use). Deterministic per-string so
    query results are stable across runs. Subclasses the real
    `chromadb.api.types.EmbeddingFunction` (rather than just duck-typing
    `__call__`) so `embed_query`/`is_legacy`/etc., which chromadb's
    collection internals call directly, come from the real base class.
    """

    def __init__(self) -> None:
        pass

    def __call__(self, input: Documents) -> Embeddings:
        return [[float(len(text) % 17), float(sum(map(ord, text)) % 97), 1.0] for text in input]

    @staticmethod
    def name() -> str:
        return "marshal-test-deterministic-embedding"

    def get_config(self) -> dict[str, Any]:
        return {}

    @staticmethod
    def build_from_config(config: dict[str, Any]) -> "_DeterministicChromaEmbedding":
        return _DeterministicChromaEmbedding()


class _DeterministicLCEmbedding(LCEmbeddings):
    """Same idea as `_DeterministicChromaEmbedding`, shaped for LangChain's
    `Embeddings` ABC (`embed_documents`/`embed_query`) instead of
    chromadb's `EmbeddingFunction` protocol."""

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [[float(len(t) % 17), float(sum(map(ord, t)) % 97), 1.0] for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return self.embed_documents([text])[0]


def _make_chroma_collection(name: str):
    client = chromadb.EphemeralClient()
    return client.create_collection(name, embedding_function=_DeterministicChromaEmbedding())


# ---------------------------------------------------------------------------
# Chroma adapter
# ---------------------------------------------------------------------------


def test_chroma_adapter_maps_real_query_results_into_documents():
    collection = _make_chroma_collection("mapping-test")
    collection.add(
        ids=["policy-1", "salary-1"],
        documents=["General leave policy for all staff", "Q3 compensation review notes"],
        metadatas=[{"note": "public"}, {"acl": ["role:hr"]}],
    )

    retriever = from_chroma_collection(collection)
    results = retriever("compensation review", 2)

    assert {doc.id for doc in results} == {"policy-1", "salary-1"}
    by_id = {doc.id: doc for doc in results}
    assert by_id["salary-1"].content == "Q3 compensation review notes"
    assert by_id["salary-1"].metadata == {"acl": ["role:hr"]}
    assert by_id["policy-1"].metadata == {"note": "public"}
    # Chroma's raw distance, not a fabricated placeholder.
    assert isinstance(by_id["salary-1"].score, float)


def test_chroma_adapter_k_zero_short_circuits_without_calling_chroma():
    # n_results=0 raises TypeError in the installed chromadb — verified
    # directly against the real client — so the adapter must guard it
    # rather than let a k=0 caller crash.
    collection = _make_chroma_collection("k-zero-test")
    collection.add(ids=["a"], documents=["hello"], metadatas=[{"note": "x"}])

    retriever = from_chroma_collection(collection)

    assert retriever("hello", 0) == []


def test_chroma_adapter_through_retrieval_guard_enforces_attribute_acl_end_to_end():
    collection = _make_chroma_collection("acl-test")
    collection.add(
        ids=["policy-1", "salary-1", "incident-1"],
        documents=[
            "General leave policy for all staff",
            "Q3 compensation review notes",
            "Plant safety incident report",
        ],
        metadatas=[
            {"note": "public"},
            {"acl": ["role:hr"]},
            {"acl": ["role:safety", "role:hr"]},
        ],
    )

    guard = RetrievalGuard(
        retriever=from_chroma_collection(collection),
        policy=AttributePolicy(default="allow"),
    )

    engineer = Principal(id="deepa", attributes={"role:engineering"})
    hr_lead = Principal(id="rhea", attributes={"role:hr"})

    engineer_results = {doc.id for doc in guard.retrieve("compensation and safety", engineer, k=3)}
    hr_results = {doc.id for doc in guard.retrieve("compensation and safety", hr_lead, k=3)}

    # The engineer only clears the unlabeled document; real Chroma content
    # for the other two was fetched (it's in the audit trail's
    # candidates_seen) but denied before being returned.
    assert engineer_results == {"policy-1"}
    assert hr_results == {"policy-1", "salary-1", "incident-1"}

    entry = guard.audit_log.tail(1)[0]
    assert entry.principal_id == "rhea"
    assert set(entry.allowed_ids) == {"policy-1", "salary-1", "incident-1"}

    denied_entry = guard.audit_log.tail(2)[0]
    assert denied_entry.principal_id == "deepa"
    assert set(denied_entry.denied_ids) == {"salary-1", "incident-1"}


def test_chroma_adapter_group_policy_pushdown_actually_filters_at_chroma():
    collection = _make_chroma_collection("group-pushdown-test")
    collection.add(
        ids=["eng-1", "hr-1", "eng-2"],
        documents=["engineering doc one", "hr doc one", "engineering doc two"],
        metadatas=[{"group": "eng"}, {"group": "hr"}, {"group": "eng"}],
    )

    guard = RetrievalGuard(retriever=from_chroma_collection(collection), policy=GroupPolicy())
    engineer = Principal(id="deepa", attributes={"eng"})

    results = guard.retrieve("doc", engineer, k=3)

    assert {doc.id for doc in results} == {"eng-1", "eng-2"}
    # Proves the `where` filter reached the real Chroma query, not just
    # RetrievalGuard's post-filter: only the 2 matching-group documents
    # were ever fetched from the store, out of 3 total in the collection.
    entry = guard.audit_log.tail(1)[0]
    assert entry.candidates_seen == 2
    assert entry.denied_ids == []


def test_chroma_adapter_denies_wrong_group_end_to_end():
    collection = _make_chroma_collection("group-deny-test")
    collection.add(
        ids=["eng-1", "hr-1"],
        documents=["engineering doc one", "hr doc one"],
        metadatas=[{"group": "eng"}, {"group": "hr"}],
    )

    guard = RetrievalGuard(retriever=from_chroma_collection(collection), policy=GroupPolicy())
    hr_principal = Principal(id="rhea", attributes={"hr"})

    results = guard.retrieve("doc", hr_principal, k=2)

    assert [doc.id for doc in results] == ["hr-1"]


# ---------------------------------------------------------------------------
# LangChain adapter
# ---------------------------------------------------------------------------


def _make_langchain_retriever(k: int = 5):
    store = InMemoryVectorStore(embedding=_DeterministicLCEmbedding())
    store.add_texts(
        texts=[
            "General leave policy for all staff",
            "Q3 compensation review notes",
            "Plant safety incident report",
        ],
        metadatas=[
            {"note": "public"},
            {"acl": ["role:hr"]},
            {"acl": ["role:safety", "role:hr"]},
        ],
        ids=["policy-1", "salary-1", "incident-1"],
    )
    return store.as_retriever(search_kwargs={"k": k})


def test_langchain_adapter_maps_real_retriever_results_into_documents():
    lc_retriever = _make_langchain_retriever()
    retriever = from_langchain_retriever(lc_retriever)

    results = retriever("compensation", 3)

    assert {doc.id for doc in results} == {"policy-1", "salary-1", "incident-1"}
    by_id = {doc.id: doc for doc in results}
    assert by_id["salary-1"].content == "Q3 compensation review notes"
    assert by_id["salary-1"].metadata == {"acl": ["role:hr"]}


def test_langchain_adapter_respects_k_against_the_real_vectorstore():
    lc_retriever = _make_langchain_retriever(k=5)
    retriever = from_langchain_retriever(lc_retriever)

    results = retriever("policy", 1)

    assert len(results) == 1


class _NoIdRetriever(BaseRetriever):
    """A minimal, real `BaseRetriever` subclass whose documents never carry
    an `id` — the case `from_langchain_retriever`'s id-synthesis exists
    for. Deliberately doesn't accept `**kwargs`, so it also exercises the
    "custom retriever ignores k" path documented on the adapter."""

    def _get_relevant_documents(self, query: str, *, run_manager: Any) -> list[Any]:
        return [LCDocument(page_content="no id here", metadata={"note": "x"})]


def test_langchain_adapter_synthesizes_id_when_langchain_document_lacks_one():
    retriever = from_langchain_retriever(_NoIdRetriever())
    results = retriever("query", 5)

    assert len(results) == 1
    assert results[0].id == "lc-0"
    assert results[0].content == "no id here"


def test_langchain_adapter_through_retrieval_guard_enforces_attribute_acl_end_to_end():
    lc_retriever = _make_langchain_retriever()
    guard = RetrievalGuard(
        retriever=from_langchain_retriever(lc_retriever),
        policy=AttributePolicy(default="allow"),
    )

    engineer = Principal(id="deepa", attributes={"role:engineering"})
    safety = Principal(id="omar", attributes={"role:safety"})

    engineer_results = {doc.id for doc in guard.retrieve("policy compensation safety", engineer, k=3)}
    safety_results = {doc.id for doc in guard.retrieve("policy compensation safety", safety, k=3)}

    assert engineer_results == {"policy-1"}
    assert safety_results == {"policy-1", "incident-1"}

    entry = guard.audit_log.tail(1)[0]
    assert entry.principal_id == "omar"
    assert "salary-1" in entry.denied_ids
