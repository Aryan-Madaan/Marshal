"""Minimal end-to-end example: wrap a toy retriever with RetrievalGuard, enforce
per-document access control, and inspect the audit trail.

Run: python examples/basic_example.py
"""

from marshal_ai import AttributePolicy, Document, Principal, RetrievalGuard

DOCS = [
    Document(id="policy-1", content="General leave policy...", metadata={}),
    Document(
        id="salary-1",
        content="Q3 compensation review notes...",
        metadata={"acl": ["role:hr"]},
    ),
    Document(
        id="incident-1",
        content="Plant safety incident report...",
        metadata={"acl": ["role:safety", "role:hr"]},
    ),
]


def toy_retriever(query: str, k: int) -> list[Document]:
    # A real retriever would do semantic search here. This just returns
    # everything so the example stays focused on the access-control layer,
    # not retrieval quality.
    return DOCS[:k]


def main() -> None:
    guard = RetrievalGuard(retriever=toy_retriever, policy=AttributePolicy(default="allow"))

    engineer = Principal(id="deepa", attributes={"role:engineering"})
    hr_lead = Principal(id="rhea", attributes={"role:hr"})

    for principal in (engineer, hr_lead):
        results = guard.retrieve("compensation", principal=principal, k=3)
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
