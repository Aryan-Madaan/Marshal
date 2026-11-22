"""Proves RetrievalGuard against a real `langchain_core`
`InMemoryVectorStore` retriever. No network, no API keys: a tiny
deterministic embedding function stands in for a real embeddings API.
"""

from typing import Any

import pytest

pytest.importorskip("langchain_core")
from langchain_core.documents import Document as LCDocument  # noqa: E402
from langchain_core.embeddings import Embeddings as LCEmbeddings  # noqa: E402
from langchain_core.retrievers import BaseRetriever  # noqa: E402
from langchain_core.vectorstores import InMemoryVectorStore  # noqa: E402

from marshal_ai.adapters import from_langchain_retriever  # noqa: E402
from marshal_ai.policy import AttributePolicy, GroupPolicy, Principal
from marshal_ai.retrieval import RetrievalGuard  # noqa: E402


class _DeterministicLCEmbedding(LCEmbeddings):
    """Same idea as `_DeterministicChromaEmbedding`, shaped for LangChain's
    `Embeddings` ABC (`embed_documents`/`embed_query`) instead of
    chromadb's `EmbeddingFunction` protocol."""

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [[float(len(t) % 17), float(sum(map(ord, t)) % 97), 1.0] for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return self.embed_documents([text])[0]


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
