from marshal_ai.retrieval import Document, RetrievalGuard
from marshal_ai.policy import AttributePolicy, GroupPolicy, Principal


def test_group_policy_to_filter_with_attributes():
    policy = GroupPolicy()
    principal = Principal(id="alice", attributes={"hr", "finance"})
    assert policy.to_filter(principal) == {"group": {"$in": ["finance", "hr"]}}


def test_group_policy_to_filter_with_no_attributes_returns_none():
    policy = GroupPolicy()
    principal = Principal(id="anyone")
    assert policy.to_filter(principal) is None


def test_group_policy_custom_field_name():
    policy = GroupPolicy(group_field="team")
    principal = Principal(id="alice", attributes={"hr"})
    assert policy.to_filter(principal) == {"team": {"$in": ["hr"]}}


def test_attribute_policy_has_no_native_filter_by_default():
    # AttributePolicy's ACL is list-valued, which most vector stores can't
    # filter on natively — to_filter should honestly report "can't do it"
    # rather than return something wrong or misleading.
    policy = AttributePolicy()
    principal = Principal(id="alice", attributes={"role:hr"})
    assert policy.to_filter(principal) is None


def test_group_policy_evaluate_matches_scalar_group():
    policy = GroupPolicy()
    hr = Principal(id="rhea", attributes={"hr"})
    assert policy.evaluate(hr, {"group": "hr"}).allowed
    assert not policy.evaluate(hr, {"group": "finance"}).allowed


def test_guard_passes_pushdown_filter_to_retriever_that_accepts_it():
    seen_filters = []

    def retriever(query: str, k: int, filter=None):
        seen_filters.append(filter)
        return []

    guard = RetrievalGuard(retriever=retriever, policy=GroupPolicy())
    principal = Principal(id="alice", attributes={"hr"})

    guard.retrieve("q", principal=principal, k=5)

    assert seen_filters == [{"group": {"$in": ["hr"]}}]


def test_guard_does_not_pass_filter_to_retriever_that_lacks_the_param():
    calls = []

    def retriever(query: str, k: int):
        calls.append((query, k))
        return []

    # This must not raise TypeError even though the policy *could* produce
    # a filter — RetrievalGuard should only push down to retrievers that opt in.
    guard = RetrievalGuard(retriever=retriever, policy=GroupPolicy())
    principal = Principal(id="alice", attributes={"hr"})

    guard.retrieve("q", principal=principal, k=5)

    assert calls == [("q", 5)]


def test_guard_still_post_filters_even_when_pushdown_filter_was_sent():
    # Defense in depth: pushdown is an optimization, not a substitute for
    # enforcement. Even if the retriever "supports" filter=, a retriever
    # that ignores it (or a buggy backend) must still get post-filtered.
    docs = [
        Document(id="1", content="a", metadata={"group": "hr"}),
        Document(id="2", content="b", metadata={"group": "finance"}),
    ]

    def retriever(query: str, k: int, filter=None):
        return docs[:k]  # deliberately ignores the filter

    guard = RetrievalGuard(retriever=retriever, policy=GroupPolicy())
    hr_principal = Principal(id="rhea", attributes={"hr"})

    results = guard.retrieve("q", principal=hr_principal, k=2)

    assert [d.id for d in results] == ["1"]
