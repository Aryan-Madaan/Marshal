"""Retrieval connectors: governed retrieval over real vector stores.

Each factory wraps a client you've already built into the
`(query, k, filter=None) -> list[Document]` retriever `RetrievalGuard`
expects, with Marshal's pushdown filter (`Policy.to_filter`, e.g.
`GroupPolicy`) compiled into the store's own native filter:

| Store | Factory | Pushdown becomes |
|---|---|---|
| MongoDB Atlas Vector Search | `mongodb.from_mongodb_atlas` | `$vectorSearch.filter` (MQL) |
| Google Cloud Firestore | `firestore.from_firestore` | `FieldFilter` `==`/`in` on `find_nearest` |
| PostgreSQL + pgvector | `pgvector.from_pgvector` | bound `jsonb` predicates (+ your RLS) |
| Qdrant | `qdrant.from_qdrant` | `Filter(must=[FieldCondition])` |
| Pinecone | `pinecone.from_pinecone` | metadata filter `$eq`/`$in` |
| Elasticsearch | `elasticsearch.from_elasticsearch` | kNN `filter` `term`/`terms` |
| Weaviate | `weaviate.from_weaviate` | `Filter.by_property` |
| LanceDB | `lancedb.from_lancedb` | escaped SQL `where`, prefiltered |

(Chroma and LangChain retrievers are in `marshal_ai.adapters`.)

Pushdown is an optimization, never the enforcement: `RetrievalGuard`
re-checks every returned document against the policy, and a filter a
connector can't translate safely is simply not pushed down (see
`marshal_ai.connectors._filters`). Each connector imports its client
library only when you call the factory, and none of them is imported by
`marshal_ai` itself — install just the extras you use.

`embed` is your embedding function, `(text) -> list[float]`, using
whatever model your index was built with.
"""
