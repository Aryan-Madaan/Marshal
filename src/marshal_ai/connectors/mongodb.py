"""MongoDB Atlas Vector Search (`$vectorSearch`) connector.

    from pymongo import MongoClient
    from marshal_ai.connectors.mongodb import from_mongodb_atlas

    collection = MongoClient(uri)["kb"]["chunks"]
    retriever = from_mongodb_atlas(collection, embed=my_embedder, index="vector_index")
    guard = RetrievalGuard(retriever, policy=GroupPolicy(), audit_sink=sink)

Runs an aggregation with a `$vectorSearch` stage, then `$project`s the
score (`{"$meta": "vectorSearchScore"}`) and drops the embedding. Marshal's
pushdown filter becomes the stage's `filter` (MQL `$eq`/`$in`/`$and` —
the operators `$vectorSearch` pre-filtering supports), so documents a
principal may not see are excluded *inside* Atlas. Every field you filter
on must be declared as a `filter` field in the vector index definition;
Atlas rejects the query otherwise.

Works with any pymongo `Collection` (including `AsyncCollection.aggregate`
results awaited by you) and with the `mongodb-atlas-local` image, which
supports `$vectorSearch` for development. Requires the `[mongodb]` extra.
"""

from __future__ import annotations

from typing import Any, Optional

from marshal_ai.connectors._common import Embed, make_document, vector_of
from marshal_ai.connectors._filters import Clause, prefixed, try_parse
from marshal_ai.retrieval import Document, Retriever


def _mql(clauses: list[Clause], prefix: Optional[str]) -> dict[str, Any]:
    parts = [
        {prefixed(c.field, prefix): ({"$eq": c.values[0]} if c.op == "eq" else {"$in": list(c.values)})}
        for c in clauses
    ]
    return parts[0] if len(parts) == 1 else {"$and": parts}


def from_mongodb_atlas(
    collection: Any,
    embed: Embed,
    index: str,
    path: str = "embedding",
    text_field: str = "text",
    metadata_field: Optional[str] = "metadata",
    num_candidates_factor: int = 10,
) -> Retriever:
    """`metadata_field` — where each document's metadata lives (and the
    prefix filters are applied under), or None for top-level fields.
    `num_candidates_factor` — `numCandidates = k * factor`, Atlas's ANN
    breadth; 10-20x `limit` is MongoDB's guidance."""

    def _retriever(query: str, k: int, filter: Optional[dict[str, Any]] = None) -> list[Document]:
        if k <= 0:
            return []
        stage: dict[str, Any] = {
            "index": index,
            "path": path,
            "queryVector": vector_of(embed, query),
            "numCandidates": max(k * num_candidates_factor, k),
            "limit": k,
        }
        clauses = try_parse(filter)
        if clauses:
            stage["filter"] = _mql(clauses, metadata_field)
        pipeline = [
            {"$vectorSearch": stage},
            {"$set": {"_marshal_score": {"$meta": "vectorSearchScore"}}},
            {"$project": {path: 0}},
        ]
        documents = []
        for record in collection.aggregate(pipeline):
            record = dict(record)
            score = record.pop("_marshal_score", None)
            doc_id = record.pop("_id", None)
            documents.append(make_document(doc_id, record, text_field, metadata_field, score=score))
        return documents

    return _retriever
