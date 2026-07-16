"""Real vector-store adapters for `RetrievalGuard`.

`RetrievalGuard` only ever asks a retriever for one shape: `(query, k) ->
list[Document]`, optionally accepting a `filter` keyword for native pushdown
(see `marshal_ai.retrieval.Retriever`). Up to this module, that contract has
only ever been proven against a fake in-memory retriever built for tests.
These two factory functions close that gap by wrapping two real, widely-used
backends into that exact shape:

- `from_chroma_collection` — wraps a real `chromadb` `Collection`.
- `from_langchain_retriever` — wraps a real LangChain `BaseRetriever`
  (including a `VectorStore.as_retriever()` result).

Both `chromadb` and `langchain-core` are optional dependencies of Marshal,
not required ones. This module is not imported by `marshal_ai/__init__.py`,
and neither factory function below imports its backend package at all —
each one only calls methods (`.query(...)`, `.invoke(...)`) on whatever
object the caller already constructed and passed in, so there is nothing
for this module to import lazily in the first place. `import
marshal_ai.adapters` therefore never requires either package, and having
one installed never requires the other. Install `chromadb` (or `pip
install "marshal-ai[chroma]"`) for the first, `langchain-core` for the
second — use whichever adapter you need.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from marshal_ai.retrieval import Document, Retriever

if TYPE_CHECKING:  # pragma: no cover - type-checking only, never imported at runtime
    from chromadb.api.models.Collection import Collection as ChromaCollection
    from langchain_core.retrievers import BaseRetriever as LangChainBaseRetriever


def _document_from_chroma_row(
    doc_id: str,
    content: Optional[str],
    metadata: Optional[dict[str, Any]],
    distance: Optional[float],
) -> Document:
    return Document(
        id=doc_id,
        content=content or "",
        metadata=dict(metadata) if metadata else {},
        score=distance,
    )


def from_chroma_collection(collection: "ChromaCollection") -> Retriever:
    """Wrap a real `chromadb` `Collection` as a Marshal `Retriever`.

    Verified against the installed `chromadb` 1.5.9 (inspected the real
    `Collection.query`/`Collection.add` signatures and an actual
    `QueryResult`, not assumed):

    - `Collection.query(query_texts=[...], n_results=k, where=filter,
      include=[...])` is the real call. Its return value is a plain
      `dict` of *parallel lists, nested one extra level per query text* —
      `ids`, `documents`, `metadatas`, `distances`. This adapter only ever
      sends a single query text per call, so every field is read at
      `[0]`. Confirmed empty results still come back as `[[]]` per field
      (not `None`), so no defensive fallback is needed there.
    - `n_results=0` raises `TypeError` in the installed version ("cannot
      be negative, or zero") — confirmed by calling it — so `k <= 0`
      short-circuits to `[]` before ever calling `query`.
    - `where=` is Chroma's native metadata filter and accepts exactly the
      `{field: {"$in": [...]}}` shape `GroupPolicy.to_filter` already
      produces (see `marshal_ai.policy.GroupPolicy`) — confirmed against
      `Collection.query`'s real `where` type. No translation layer is
      needed for `RetrievalGuard`'s pushdown path (see
      `retrieval.py::_call_retriever`) to reach Chroma directly; `filter`
      is accepted here by that literal name so `RetrievalGuard`'s
      `_accepts_filter` check recognizes this retriever as pushdown-capable.
    - `score` on the returned `Document` is Chroma's raw `distance`
      (lower means closer under whatever space the collection was
      configured with) — deliberately not renormalized into a 0-1
      "similarity" here, since that mapping depends on the space and
      Marshal doesn't know it.
    - Metadata comes back exactly as stored — including list-valued
      fields like `acl`, which Chroma accepts natively — so
      `AttributePolicy`/`GroupPolicy` see the same shape whether the
      retriever behind them is Chroma or the in-memory fake used in
      `tests/test_retrieval.py`.

    `collection.add(ids=..., documents=..., metadatas=...)` is what you
    use to populate the collection in the first place — plain `chromadb`
    API, nothing Marshal-specific about it (see `examples/chroma_example.py`).
    """

    def _retriever(query: str, k: int, filter: Optional[dict[str, Any]] = None) -> list[Document]:
        if k <= 0:
            return []
        results = collection.query(
            query_texts=[query],
            n_results=k,
            where=filter,
            include=["documents", "metadatas", "distances"],
        )
        ids = results["ids"][0]
        documents = results["documents"][0]
        metadatas = results["metadatas"][0]
        distances = results["distances"][0]
        return [
            _document_from_chroma_row(doc_id, content, metadata, distance)
            for doc_id, content, metadata, distance in zip(ids, documents, metadatas, distances)
        ]

    return _retriever


def _document_from_langchain(lc_document: Any, index: int) -> Document:
    doc_id = getattr(lc_document, "id", None)
    if doc_id is None:
        # LangChain's `Document.id` is optional (confirmed against the
        # installed `langchain-core` 1.4.9 model fields) and is frequently
        # left unset by a retriever. Marshal's `Document.id` is required
        # and is the audit trail's key for allowed/denied ids, so a
        # missing one gets a deterministic, call-local synthesized id
        # instead of `None` or a random `uuid4()` — reproducible if the
        # same query is retried, unlike a random id would be.
        doc_id = f"lc-{index}"
    return Document(
        id=str(doc_id),
        content=lc_document.page_content,
        metadata=dict(lc_document.metadata),
    )


def from_langchain_retriever(retriever: "LangChainBaseRetriever") -> Retriever:
    """Wrap a real LangChain `BaseRetriever` (including the
    `VectorStoreRetriever` returned by `VectorStore.as_retriever()`) as a
    Marshal `Retriever`.

    Verified against the installed `langchain-core` 1.4.9 (inspected the
    real `BaseRetriever.invoke`/`VectorStoreRetriever._get_relevant_documents`
    source and a real `Document`'s Pydantic fields, not assumed):

    - `BaseRetriever.invoke(query, **kwargs) -> list[Document]` is the
      current synchronous entry point (`get_relevant_documents` is
      deprecated) and returns the document list directly — nothing to
      unwrap.
    - Passing `k=k` through `**kwargs` reaches a `VectorStoreRetriever`'s
      real search call: its `_get_relevant_documents` merges
      `self.search_kwargs | kwargs` before calling
      `vectorstore.similarity_search(query, **kwargs_)`, so `k` here
      genuinely bounds the underlying search rather than being truncated
      client-side afterward — confirmed by invoking a real
      `InMemoryVectorStore` retriever with `k=2` against a larger corpus.
      A custom `BaseRetriever` subclass whose `_get_relevant_documents`
      doesn't accept extra keyword arguments simply ignores `k` (that's
      LangChain's own dispatch behavior, not this adapter's); either way,
      `RetrievalGuard` only ever returns what the policy allows.
    - LangChain's `Document` has `page_content: str`, `metadata: dict`,
      and an optional `id: str | None` field (confirmed via its Pydantic
      `model_fields`) — mapped to Marshal's `content`/`metadata`/`id`
      respectively; see `_document_from_langchain` for the `id` fallback.
    """

    def _retriever(query: str, k: int) -> list[Document]:
        lc_documents = retriever.invoke(query, k=k)
        return [_document_from_langchain(doc, index) for index, doc in enumerate(lc_documents)]

    return _retriever
