import pytest

from marshal_ai.policy import AllowAll, AttributePolicy, Principal


def test_attribute_policy_allows_on_overlap():
    policy = AttributePolicy()
    alice = Principal(id="alice", attributes={"role:hr"})
    decision = policy.evaluate(alice, {"acl": ["role:hr", "role:finance"]})
    assert decision.allowed


def test_attribute_policy_denies_on_no_overlap():
    policy = AttributePolicy()
    bob = Principal(id="bob", attributes={"role:engineering"})
    decision = policy.evaluate(bob, {"acl": ["role:hr", "role:finance"]})
    assert not decision.allowed
    assert "role:hr" in decision.reason


def test_attribute_policy_default_allow_when_no_acl():
    policy = AttributePolicy(default="allow")
    anyone = Principal(id="anyone")
    assert policy.evaluate(anyone, {}).allowed


def test_attribute_policy_default_deny_when_no_acl():
    policy = AttributePolicy(default="deny")
    anyone = Principal(id="anyone")
    assert not policy.evaluate(anyone, {}).allowed


def test_attribute_policy_rejects_invalid_default():
    with pytest.raises(ValueError):
        AttributePolicy(default="maybe")


def test_attribute_policy_guards_against_bare_string_acl():
    # metadata={"acl": "role:hr"} is a common typo for {"acl": ["role:hr"]}.
    # A bare string is still Iterable, so without a guard this would be
    # treated as the set of individual characters {"r", "o", "l", "e", ...}.
    policy = AttributePolicy()
    alice = Principal(id="alice", attributes={"role:hr"})
    assert policy.evaluate(alice, {"acl": "role:hr"}).allowed

    mallory = Principal(id="mallory", attributes={"r"})
    assert not policy.evaluate(mallory, {"acl": "role:hr"}).allowed


def test_allow_all_always_allows():
    policy = AllowAll()
    principal = Principal(id="x")
    assert policy.evaluate(principal, {"acl": ["role:nobody-has-this"]}).allowed


def test_principal_normalizes_attributes_to_frozenset():
    principal = Principal(id="alice", attributes=["role:hr", "role:hr"])
    assert principal.attributes == frozenset({"role:hr"})
