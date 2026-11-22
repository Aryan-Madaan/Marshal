"""Elasticsearch / OpenSearch-compatible kNN connector.

    from elasticsearch import Elasticsearch
    from marshal_ai.connectors.elasticsearch import from_elasticsearch

    retriever = from_elasticsearch(Elasticsearch(url, api_key=...), index="kb", embed=my_embedder)

Runs `client.search(index=..., knn={...}, size=k)` with Marshal's pushdown
compiled into the kNN `filter` (`term`/`terms` queries), which
Elasticsearch applies *during* the approximate search, so k results are
still returned when many documents are filtered out. Filter fields must
be `keyword` (or numeric/boolean) fields; set `keyword_suffix=".keyword"`
if your metadata uses dynamic text+keyword mappings. Requires the
`[elasticsearch]` extra.
"""

from __future__ import annotations

from typing import Any, Optional

from marshal_ai.connectors._common import Embed, make_document, vector_of
from marshal_ai.connectors._filters import prefixed, try_parse
from marshal_ai.retrieval import Document, Retriever


def from_elasticsearch(
    client: Any,
    index: str,
    embed: Embed,
    vector_field: str = "embedding",
    text_field: str = "text",
    metadata_field: Optional[str] = "metadata",
    num_candidates_factor: int = 10,
    keyword_suffix: str = "",
) -> Retriever:
    def _retriever(query: str, k: int, filter: Optional[dict[str, Any]] = None) -> list[Document]:
        if k <= 0:
            return []
        knn: dict[str, Any] = {
            "field": vector_field,
            "query_vector": vector_of(embed, query),
            "k": k,
            "num_candidates": max(k * num_candidates_factor, k),
        }
        clauses = try_parse(filter)
        if clauses:
            knn["filter"] = [
                {"term": {prefixed(c.field, metadata_field) + keyword_suffix: c.values[0]}}
                if c.op == "eq"
                else {"terms": {prefixed(c.field, metadata_field) + keyword_suffix: list(c.values)}}
                for c in clauses
            ]
        response = client.search(index=index, knn=knn, size=k, source_excludes=[vector_field])
        hits = response["hits"]["hits"]
        return [
            make_document(hit["_id"], hit.get("_source") or {}, text_field, metadata_field, score=hit.get("_score"))
            for hit in hits
        ]

    return _retriever
