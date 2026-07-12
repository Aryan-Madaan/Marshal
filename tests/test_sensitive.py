import pytest

from marshal_ai.audit import InMemoryAuditSink
from marshal_ai.policy import AllowAll, AttributePolicy, Principal
from marshal_ai.retrieval import Document
from marshal_ai.sensitive import (
    DEFAULT_BLOCK_DETECTORS,
    Finding,
    SensitiveDataPolicy,
    SensitiveDataScanner,
    SensitiveDataToolPolicy,
)
from marshal_ai.tools import AllowAllTools, RiskTierPolicy, ToolCallDenied, ToolCallRequest


# --- SensitiveDataScanner --------------------------------------------------


def test_scan_detects_email():
    findings = SensitiveDataScanner().scan("contact me at bob@example.com please")
    assert Finding("EMAIL", 1) in findings


def test_scan_detects_private_key_block():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIExyz\n-----END RSA PRIVATE KEY-----"
    findings = SensitiveDataScanner().scan(text)
    assert any(f.detector == "PRIVATE_KEY_BLOCK" for f in findings)


def test_scan_detects_aws_access_key():
    findings = SensitiveDataScanner().scan("key: AKIAABCDEFGHIJKLMNOP")
    assert Finding("AWS_ACCESS_KEY_ID", 1) in findings


def test_scan_detects_generic_api_key():
    findings = SensitiveDataScanner().scan("token sk-abcdefghijklmnopqrstuvwx123456")
    assert any(f.detector == "GENERIC_API_KEY" for f in findings)


def test_scan_returns_empty_for_clean_text():
    assert SensitiveDataScanner().scan("just a normal sentence about widgets") == []


def test_scan_never_returns_matched_text_only_counts():
    findings = SensitiveDataScanner().scan("bob@example.com and alice@example.com")
    email_finding = next(f for f in findings if f.detector == "EMAIL")
    assert email_finding == Finding("EMAIL", 2)
    assert not hasattr(email_finding, "value")
    assert not hasattr(email_finding, "text")


def test_redact_replaces_matches_and_reports_findings():
    redacted, findings = SensitiveDataScanner().redact("email bob@example.com now")
    assert "bob@example.com" not in redacted
    assert "[REDACTED:EMAIL]" in redacted
    assert findings == [Finding("EMAIL", 1)]


def test_redact_handles_empty_text():
    redacted, findings = SensitiveDataScanner().redact("")
    assert redacted == ""
    assert findings == []


def test_custom_detector_list_is_used_instead_of_defaults():
    from marshal_ai.sensitive import Detector
    import re

    only_ssn = [Detector("SSN_US", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"))]
    scanner = SensitiveDataScanner(detectors=only_ssn)
    # An email present, but EMAIL isn't in this scanner's detector list.
    assert scanner.scan("bob@example.com 123-45-6789") == [Finding("SSN_US", 1)]


# --- SensitiveDataPolicy (retrieval) ---------------------------------------


def test_sensitive_data_policy_redacts_content_leaves_acl_decision_to_base():
    sink = InMemoryAuditSink()
    policy = SensitiveDataPolicy(base=AttributePolicy(default="allow"), audit_sink=sink)
    alice = Principal(id="alice")

    decision = policy.evaluate(alice, {})
    assert decision.allowed is True  # unchanged from AttributePolicy(default="allow")

    doc = Document(id="d1", content="reach me at bob@example.com", metadata={})
    redacted_doc = policy.redact(alice, doc)
    assert "bob@example.com" not in redacted_doc.content
    assert "[REDACTED:EMAIL]" in redacted_doc.content

    entries = sink.tail(5)
    assert len(entries) == 1
    assert entries[0].to_dict()["kind"] == "sensitive_data"
    assert entries[0].surface == "retrieval"
    assert entries[0].action == "redacted"


def test_sensitive_data_policy_no_findings_writes_nothing():
    sink = InMemoryAuditSink()
    policy = SensitiveDataPolicy(base=AllowAll(), audit_sink=sink)
    doc = Document(id="d1", content="nothing sensitive here", metadata={})
    policy.redact(Principal(id="alice"), doc)
    assert sink.tail(5) == []


def test_sensitive_data_policy_delegates_to_filter():
    from marshal_ai.policy import GroupPolicy

    base = GroupPolicy()
    policy = SensitiveDataPolicy(base=base)
    alice = Principal(id="alice", attributes={"eng"})
    assert policy.to_filter(alice) == base.to_filter(alice)


# --- SensitiveDataToolPolicy ------------------------------------------------


def test_tool_policy_blocks_on_private_key_regardless_of_risk_tier():
    sink = InMemoryAuditSink()
    base = RiskTierPolicy({"low": "allow"})
    policy = SensitiveDataToolPolicy(base=base, audit_sink=sink)
    request = ToolCallRequest(
        tool_name="save_note",
        arguments={"note": "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"},
        principal=Principal(id="alice"),
        risk_tier="low",
    )

    decision = policy.evaluate(request)
    assert decision.outcome == "deny"
    assert "PRIVATE_KEY_BLOCK" in decision.reason

    entries = sink.tail(5)
    assert len(entries) == 1
    assert entries[0].action == "blocked"
    assert entries[0].surface == "tool_call"


def test_tool_policy_does_not_override_base_deny():
    base = RiskTierPolicy({"high": "deny"})
    policy = SensitiveDataToolPolicy(base=base)
    request = ToolCallRequest(
        tool_name="delete_all", arguments={}, principal=Principal(id="alice"), risk_tier="high"
    )
    decision = policy.evaluate(request)
    assert decision.outcome == "deny"
    assert "risk tier" in decision.reason  # base's reason, not a sensitive-data one


def test_tool_policy_redacts_non_blocking_findings_but_allows():
    sink = InMemoryAuditSink()
    policy = SensitiveDataToolPolicy(base=AllowAllTools(), audit_sink=sink)
    request = ToolCallRequest(
        tool_name="send_email",
        arguments={"body": "reach bob@example.com for details"},
        principal=Principal(id="alice"),
    )
    decision = policy.evaluate(request)
    assert decision.outcome == "allow"

    redacted = policy.redact_arguments(request)
    assert "bob@example.com" not in redacted["body"]
    assert "[REDACTED:EMAIL]" in redacted["body"]

    entries = sink.tail(5)
    assert len(entries) == 1
    assert entries[0].action == "redacted"


def test_tool_policy_does_not_double_audit_blocked_findings_in_redact_arguments():
    sink = InMemoryAuditSink()
    policy = SensitiveDataToolPolicy(base=AllowAllTools(), audit_sink=sink)
    request = ToolCallRequest(
        tool_name="save_note",
        arguments={"note": "AKIAABCDEFGHIJKLMNOP"},
        principal=Principal(id="alice"),
    )
    policy.evaluate(request)  # writes one "blocked" entry
    policy.redact_arguments(request)  # must not write a second "redacted" entry for the same finding

    entries = sink.tail(5)
    assert len(entries) == 1
    assert entries[0].action == "blocked"


def test_tool_policy_via_toolguard_raises_tool_call_denied():
    from marshal_ai.tools import ToolGuard

    def save_note(note: str) -> str:
        return "saved"

    policy = SensitiveDataToolPolicy(base=AllowAllTools())
    guard = ToolGuard(tool=save_note, policy=policy)
    with pytest.raises(ToolCallDenied):
        guard.call(Principal(id="alice"), {"note": "AKIAABCDEFGHIJKLMNOP"})


def test_tool_policy_ignores_non_string_argument_values():
    policy = SensitiveDataToolPolicy(base=AllowAllTools())
    request = ToolCallRequest(
        tool_name="update", arguments={"count": 42, "active": True}, principal=Principal(id="alice")
    )
    decision = policy.evaluate(request)
    assert decision.outcome == "allow"
    assert policy.redact_arguments(request) == {"count": 42, "active": True}


def test_default_block_detectors_are_credentials_not_pii():
    assert "EMAIL" not in DEFAULT_BLOCK_DETECTORS
    assert "PRIVATE_KEY_BLOCK" in DEFAULT_BLOCK_DETECTORS
