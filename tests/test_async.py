import asyncio

from marshal_ai.retrieval import Document, RetrievalGuard
from marshal_ai.policy import AttributePolicy, Principal


def test_aretrieve_with_async_retriever():
    docs = [Document(id="1", content="a"), Document(id="2", content="b")]

    async def async_retriever(query: str, k: int) -> list[Document]:
        await asyncio.sleep(0)  # actually exercise the await path
        return docs[:k]

    guard = RetrievalGuard(retriever=async_retriever)

    results = asyncio.run(guard.aretrieve("q", principal=Principal(id="x"), k=2))

    assert [d.id for d in results] == ["1", "2"]
    assert guard.audit_log.tail(1)[0].allowed_ids == ["1", "2"]


def test_aretrieve_with_sync_retriever_still_works():
    docs = [Document(id="1", content="a")]

    def sync_retriever(query: str, k: int) -> list[Document]:
        return docs[:k]

    guard = RetrievalGuard(retriever=sync_retriever)

    results = asyncio.run(guard.aretrieve("q", principal=Principal(id="x"), k=1))

    assert [d.id for d in results] == ["1"]


def test_aretrieve_applies_policy_like_retrieve_does():
    docs = [
        Document(id="1", content="public", metadata={}),
        Document(id="2", content="hr-only", metadata={"acl": ["role:hr"]}),
    ]

    async def async_retriever(query: str, k: int) -> list[Document]:
        return docs[:k]

    guard = RetrievalGuard(retriever=async_retriever, policy=AttributePolicy(default="allow"))
    engineer = Principal(id="bob", attributes={"role:engineering"})

    results = asyncio.run(guard.aretrieve("q", principal=engineer, k=2))

    assert [d.id for d in results] == ["1"]


def test_retrieve_still_works_synchronously_after_adding_async():
    # Sanity check that adding aretrieve didn't regress the sync path.
    docs = [Document(id="1", content="a")]
    guard = RetrievalGuard(retriever=lambda query, k: docs[:k])
    results = guard.retrieve("q", principal=Principal(id="x"), k=1)
    assert [d.id for d in results] == ["1"]
