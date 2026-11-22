"""Pinecone connector.

    from pinecone import Pinecone
    from marshal_ai.connectors.pinecone import from_pinecone

    index = Pinecone(api_key=...).Index("kb")
    retriever = from_pinecone(index, embed=my_embedder, namespace="tenant-a")

Calls `index.query(vector=..., top_k=k, include_metadata=True,
filter=..., namespace=...)`. Pinecone's metadata filter is Mongo-style
(`$eq`/`$in`/`$and`), so Marshal's pushdown maps one to one and is
applied inside Pinecone. Pinecone has no document text field: the text is
read from `metadata[text_key]` and the rest of the metadata is passed to
the policy. Namespaces are a good fit for hard tenant isolation; use one
retriever per namespace. Requires the `[pinecone]` extra.
"""

from __future__ import annotations

from typing import Any, Optional

from marshal_ai.connectors._common import Embed, make_document, vector_of
from marshal_ai.connectors._filters import try_parse
from marshal_ai.retrieval import Document, Retriever


def _get(obj: Any, name: str) -> Any:
    return obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)


def from_pinecone(index: Any, embed: Embed, namespace: Optional[str] = None, text_key: str = "text") -> Retriever:
    def _retriever(query: str, k: int, filter: Optional[dict[str, Any]] = None) -> list[Document]:
        if k <= 0:
            return []
        kwargs: dict[str, Any] = {"vector": vector_of(embed, query), "top_k": k, "include_metadata": True}
        if namespace is not None:
            kwargs["namespace"] = namespace
        clauses = try_parse(filter)
        if clauses:
            parts = [{c.field: {"$eq": c.values[0]} if c.op == "eq" else {"$in": list(c.values)}} for c in clauses]
            kwargs["filter"] = parts[0] if len(parts) == 1 else {"$and": parts}
        response = index.query(**kwargs)
        return [
            make_document(_get(m, "id"), _get(m, "metadata") or {}, text_key, None, score=_get(m, "score"))
            for m in (_get(response, "matches") or [])
        ]

    return _retriever
