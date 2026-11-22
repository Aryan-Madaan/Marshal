"""Qdrant connector.

    from qdrant_client import QdrantClient
    from marshal_ai.connectors.qdrant import from_qdrant

    retriever = from_qdrant(QdrantClient(url=...), "kb", embed=my_embedder)

Calls `client.query_points(collection_name, query=vector, limit=k,
query_filter=..., with_payload=True)`. Marshal's pushdown becomes a
`Filter(must=[FieldCondition(..., match=MatchValue | MatchAny)])`, applied
inside Qdrant's HNSW search (create payload indexes on filtered keys for
speed). `MatchAny` also matches list-valued payload fields, so an `acl`
list works the way `GroupPolicy` expects. Verified against qdrant-client
1.20, including its in-process `QdrantClient(":memory:")` mode the tests
use. Requires the `[qdrant]` extra.
"""

from __future__ import annotations

from typing import Any, Optional

from marshal_ai.connectors._common import Embed, make_document, vector_of
from marshal_ai.connectors._filters import prefixed, try_parse
from marshal_ai.retrieval import Document, Retriever


def from_qdrant(
    client: Any,
    collection_name: str,
    embed: Embed,
    text_key: str = "text",
    metadata_key: Optional[str] = "metadata",
    using: Optional[str] = None,
) -> Retriever:
    """`using` — the named vector to search, for multi-vector collections."""
    from qdrant_client import models

    def _retriever(query: str, k: int, filter: Optional[dict[str, Any]] = None) -> list[Document]:
        if k <= 0:
            return []
        query_filter = None
        clauses = try_parse(filter)
        if clauses:
            query_filter = models.Filter(must=[
                models.FieldCondition(
                    key=prefixed(c.field, metadata_key),
                    match=models.MatchValue(value=c.values[0]) if c.op == "eq" else models.MatchAny(any=list(c.values)),
                )
                for c in clauses
            ])
        response = client.query_points(
            collection_name=collection_name,
            query=vector_of(embed, query),
            using=using,
            query_filter=query_filter,
            limit=k,
            with_payload=True,
        )
        return [
            make_document(point.id, point.payload or {}, text_key, metadata_key, score=point.score)
            for point in response.points
        ]

    return _retriever
