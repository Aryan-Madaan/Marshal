from marshal_ai.retrieval import Document, RetrievalGuard
from marshal_ai.policy import AllowAll, FieldRedaction, Principal, RedactingPolicy


def make_policy():
    return RedactingPolicy(
        base=AllowAll(),
        rules=[
            FieldRedaction(field="content", requires_attribute="role:hr"),
            FieldRedaction(field="salary_band", requires_attribute="role:hr"),
        ],
    )


def test_redacting_policy_hides_content_without_required_attribute():
    policy = make_policy()
    doc = Document(id="1", content="secret comp details", metadata={"salary_band": "L5"})
    engineer = Principal(id="bob", attributes={"role:engineering"})

    redacted = policy.redact(engineer, doc)

    assert redacted.content == "[REDACTED]"
    assert redacted.metadata["salary_band"] == "[REDACTED]"
    # original document is untouched — redact returns a copy
    assert doc.content == "secret comp details"
    assert doc.metadata["salary_band"] == "L5"


def test_redacting_policy_leaves_fields_visible_with_required_attribute():
    policy = make_policy()
    doc = Document(id="1", content="secret comp details", metadata={"salary_band": "L5"})
    hr = Principal(id="rhea", attributes={"role:hr"})

    redacted = policy.redact(hr, doc)

    assert redacted.content == "secret comp details"
    assert redacted.metadata["salary_band"] == "L5"


def test_redacting_policy_preserves_evaluate_from_base():
    policy = make_policy()
    someone = Principal(id="x")
    # base is AllowAll, so evaluate should still allow regardless of redaction rules
    assert policy.evaluate(someone, {}).allowed


def test_guard_applies_redaction_to_retrieved_documents():
    docs = [Document(id="1", content="secret", metadata={"salary_band": "L5"})]
    guard = RetrievalGuard(retriever=lambda q, k: docs[:k], policy=make_policy())
    engineer = Principal(id="bob", attributes={"role:engineering"})

    results = guard.retrieve("q", principal=engineer, k=1)

    assert len(results) == 1
    assert results[0].content == "[REDACTED]"
    assert results[0].metadata["salary_band"] == "[REDACTED]"


def test_missing_metadata_field_in_redaction_rule_is_a_no_op():
    policy = make_policy()
    doc = Document(id="1", content="hi", metadata={})  # no salary_band key at all
    engineer = Principal(id="bob", attributes={"role:engineering"})

    redacted = policy.redact(engineer, doc)

    assert redacted.content == "[REDACTED]"
    assert "salary_band" not in redacted.metadata
