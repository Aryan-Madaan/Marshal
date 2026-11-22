"""Weaviate (v4 client) connector.

    import weaviate
    from marshal_ai.connectors.weaviate import from_weaviate

    collection = weaviate.connect_to_local().collections.get("KbChunk")
    retriever = from_weaviate(collection, embed=my_embedder)

Calls `collection.query.near_vector(near_vector, limit=k, filters=...,
return_metadata=MetadataQuery(distance=True))`, with Marshal's pushdown
compiled to `Filter.by_property(...).equal(...)` / `.contains_any(...)`
combined with `Filter.all_of`. Weaviate filters on top-level object
properties, so metadata is read from the object's properties (everything
except `text_property`). Pass `embed=None` to use the collection's own
vectorizer via `near_text` instead. Verified against weaviate-client 4.24.
Requires the `[weaviate]` extra.
"""

from __future__ import annotations

from typing import Any, Optional

from marshal_ai.connectors._common import Embed, make_document, vector_of
from marshal_ai.connectors._filters import try_parse
from marshal_ai.retrieval import Document, Retriever


def from_weaviate(collection: Any, embed: Optional[Embed], text_property: str = "text") -> Retriever:
    from weaviate.classes.query import Filter, MetadataQuery

    def _retriever(query: str, k: int, filter: Optional[dict[str, Any]] = None) -> list[Document]:
        if k <= 0:
            return []
        filters = None
        clauses = try_parse(filter)
        # Weaviate properties are flat; a dotted Marshal field can't map.
        if clauses and all("." not in c.field for c in clauses):
            parts = [
                Filter.by_property(c.field).equal(c.values[0]) if c.op == "eq"
                else Filter.by_property(c.field).contains_any(list(c.values))
                for c in clauses
            ]
            filters = parts[0] if len(parts) == 1 else Filter.all_of(parts)
        metadata = MetadataQuery(distance=True)
        if embed is None:
            response = collection.query.near_text(query=query, limit=k, filters=filters, return_metadata=metadata)
        else:
            response = collection.query.near_vector(
                near_vector=vector_of(embed, query), limit=k, filters=filters, return_metadata=metadata
            )
        return [
            make_document(
                obj.uuid, obj.properties or {}, text_property, None,
                score=getattr(obj.metadata, "distance", None),
            )
            for obj in response.objects
        ]

    return _retriever
