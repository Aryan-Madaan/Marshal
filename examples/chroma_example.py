"""Real-Chroma end-to-end example: same access-control story as
basic_example.py, but the retriever is a genuine `chromadb` collection
instead of a toy in-memory list — proving RetrievalGuard against a real
vector store, not just a fake.

Uses `chromadb.EphemeralClient()` (in-process, nothing persisted, no
server) and a tiny deterministic embedding function so this runs with no
network call — chromadb's *default* embedding function downloads an ONNX
model on first use, which this example deliberately avoids. Swap in a real
embedding model/API in production; nothing else in this example changes.

Run: python examples/chroma_example.py
Requires: pip install "marshal-ai[chroma]"  (or: pip install chromadb)
"""

import chromadb
from chromadb.api.types import Documents, EmbeddingFunction, Embeddings

from marshal_ai import AttributePolicy, Principal, RetrievalGuard
from marshal_ai.adapters import from_chroma_collection


class DeterministicEmbedding(EmbeddingFunction):
    """Stand-in for a real embedding model: deterministic, offline, and
    good enough to make semantically-similar toy documents sort near each
    other for this example. Not something to ship to production."""

    def __init__(self) -> None:
        pass

    def __call__(self, input: Documents) -> Embeddings:
        return [[float(len(text) % 17), float(sum(map(ord, text)) % 97), 1.0] for text in input]

    @staticmethod
    def name() -> str:
        return "marshal-example-deterministic-embedding"


DOCS = [
    ("policy-1", "General leave policy for all staff", {"note": "public"}),
    ("salary-1", "Q3 compensation review notes", {"acl": ["role:hr"]}),
    ("incident-1", "Plant safety incident report", {"acl": ["role:safety", "role:hr"]}),
]


def build_collection():
    client = chromadb.EphemeralClient()
    collection = client.create_collection("marshal-example", embedding_function=DeterministicEmbedding())
    collection.add(
        ids=[doc_id for doc_id, _, _ in DOCS],
        documents=[content for _, content, _ in DOCS],
        metadatas=[metadata for _, _, metadata in DOCS],
    )
    return collection


def main() -> None:
    collection = build_collection()

    guard = RetrievalGuard(
        retriever=from_chroma_collection(collection),
        policy=AttributePolicy(default="allow"),
    )

    engineer = Principal(id="deepa", attributes={"role:engineering"})
    hr_lead = Principal(id="rhea", attributes={"role:hr"})

    for principal in (engineer, hr_lead):
        results = guard.retrieve("compensation and safety", principal=principal, k=3)
        seen = [doc.id for doc in results]
        print(f"{principal.id} ({sorted(principal.attributes)}) sees: {seen}")

    print("\naudit trail:")
    for entry in guard.audit_log.tail(2):
        print(
            f"  {entry.principal_id}: allowed={entry.allowed_ids} "
            f"denied={entry.denied_ids}"
        )


if __name__ == "__main__":
    main()
