"""One access policy, enforced inside real vector stores.

`marshal_ai.connectors` wraps your existing store client so
`RetrievalGuard` can govern it — and compiles the policy's pushdown
filter into the store's own query, so documents a principal can't see
are never even returned by the database. `RetrievalGuard` still re-checks
every result (pushdown is an optimization, never the enforcement).

This runs offline against two real embedded stores — Qdrant's in-process
mode and LanceDB. The same three lines work for MongoDB Atlas Vector
Search, Firestore, pgvector, Pinecone, Elasticsearch and Weaviate (see the
end of this file).

Needs: pip install -e ".[qdrant,lancedb]"
Run:   python examples/connectors_example.py
"""

import tempfile

import lancedb
from qdrant_client import QdrantClient, models

from marshal_ai import GroupPolicy, InMemoryAuditSink, Principal, RetrievalGuard
from marshal_ai.connectors.lancedb import from_lancedb
from marshal_ai.connectors.qdrant import from_qdrant

CHUNKS = [
    ("hr-1", "Salary bands for L4-L6", "hr", [1.0, 0.0, 0.0]),
    ("hr-2", "2027 hiring plan", "hr", [0.9, 0.1, 0.0]),
    ("eng-1", "Production deploy runbook", "eng", [0.8, 0.2, 0.0]),
    ("all-1", "Holiday calendar", "everyone", [0.7, 0.3, 0.0]),
]


def embed(text: str) -> list[float]:
    """Stand-in for your real embedding model."""
    return [1.0, 0.0, 0.0]


# --- Qdrant (in-process) ---
qdrant = QdrantClient(":memory:")
qdrant.create_collection("kb", vectors_config=models.VectorParams(size=3, distance=models.Distance.COSINE))
qdrant.upsert("kb", points=[
    models.PointStruct(id=i, vector=vec, payload={"text": text, "metadata": {"group": group, "doc": doc_id}})
    for i, (doc_id, text, group, vec) in enumerate(CHUNKS)
])

# --- LanceDB (embedded) ---
lance = lancedb.connect(tempfile.mkdtemp()).create_table("kb", data=[
    {"id": doc_id, "text": text, "vector": vec, "metadata": {"group": group}} for doc_id, text, group, vec in CHUNKS
])

sink = InMemoryAuditSink()
stores = {
    "qdrant": from_qdrant(qdrant, "kb", embed),
    "lancedb": from_lancedb(lance, embed),
}
alice = Principal("alice", {"hr", "everyone"})
bob = Principal("bob", {"eng", "everyone"})

for name, retriever in stores.items():
    guard = RetrievalGuard(retriever, policy=GroupPolicy(), audit_sink=sink)
    for who in (alice, bob):
        docs = guard.retrieve("compensation", who, k=4)
        print(f"{name:8} {who.id:6} -> {[d.content for d in docs]}")

print("\nthe store itself only ever returned what each principal may see:")
for entry in sink.all_entries():
    print(f"  {entry.principal_id}: {entry.candidates_seen} candidates from the store, {len(entry.denied_ids)} denied after")

print('''
The same pattern for the other connectors:

    from marshal_ai.connectors.mongodb import from_mongodb_atlas        # $vectorSearch filter
    from marshal_ai.connectors.firestore import from_firestore          # find_nearest + FieldFilter
    from marshal_ai.connectors.pgvector import from_pgvector            # bound jsonb predicates (+ RLS)
    from marshal_ai.connectors.pinecone import from_pinecone
    from marshal_ai.connectors.elasticsearch import from_elasticsearch
    from marshal_ai.connectors.weaviate import from_weaviate

    RetrievalGuard(from_mongodb_atlas(collection, embed, index="vector_index"), policy=GroupPolicy())
''')
