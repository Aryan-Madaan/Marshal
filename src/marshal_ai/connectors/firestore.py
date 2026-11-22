"""Google Cloud Firestore vector search connector.

    from google.cloud import firestore
    from marshal_ai.connectors.firestore import from_firestore

    collection = firestore.Client().collection("kb_chunks")
    retriever = from_firestore(collection, embed=my_embedder)

Builds `collection.where(...).find_nearest(vector_field, query_vector,
limit=k, distance_measure=..., distance_result_field=...)` and runs it.
Marshal's pushdown filter becomes `FieldFilter` `==`/`in` clauses, which
Firestore applies as a pre-filter on the nearest-neighbour search (it
needs a composite vector index covering those fields; Firestore's error
message names the index to create). Firestore caps an `in` filter at 30
values; a principal with more attributes than that falls back to
post-filtering in `RetrievalGuard` instead of failing.

Also works with a collection-group query or any `Query` you've already
narrowed. Verified against google-cloud-firestore 2.34. Requires the
`[firestore]` extra.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from marshal_ai.connectors._common import Embed, make_document, vector_of
from marshal_ai.connectors._filters import prefixed, try_parse
from marshal_ai.retrieval import Document, Retriever

FIRESTORE_IN_LIMIT = 30
_DISTANCE_FIELD = "_marshal_distance"


def from_firestore(
    query: Any,
    embed: Embed,
    vector_field: str = "embedding",
    text_field: str = "text",
    metadata_field: Optional[str] = "metadata",
    distance_measure: Literal["COSINE", "EUCLIDEAN", "DOT_PRODUCT"] = "COSINE",
) -> Retriever:
    from google.cloud.firestore_v1.base_query import FieldFilter
    from google.cloud.firestore_v1.base_vector_query import DistanceMeasure
    from google.cloud.firestore_v1.vector import Vector

    measure = DistanceMeasure[distance_measure]

    def _retriever(text: str, k: int, filter: Optional[dict[str, Any]] = None) -> list[Document]:
        if k <= 0:
            return []
        narrowed = query
        clauses = try_parse(filter)
        if clauses and all(len(c.values) <= FIRESTORE_IN_LIMIT for c in clauses):
            for c in clauses:
                field = prefixed(c.field, metadata_field)
                if c.op == "eq":
                    narrowed = narrowed.where(filter=FieldFilter(field, "==", c.values[0]))
                else:
                    narrowed = narrowed.where(filter=FieldFilter(field, "in", list(c.values)))
        vector_query = narrowed.find_nearest(
            vector_field=vector_field,
            query_vector=Vector(vector_of(embed, text)),
            limit=k,
            distance_measure=measure,
            distance_result_field=_DISTANCE_FIELD,
        )
        documents = []
        for snapshot in vector_query.get():
            record = snapshot.to_dict() or {}
            distance = record.pop(_DISTANCE_FIELD, None)
            record.pop(vector_field, None)
            documents.append(make_document(snapshot.id, record, text_field, metadata_field, score=distance))
        return documents

    return _retriever
