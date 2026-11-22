import json
import time

import pytest

from marshal_ai import AutoApprove, InMemoryAuditSink, Principal, RiskTierPolicy, ToolCallDenied, ToolGuard
from marshal_ai.egress import UNPARSEABLE, EgressAllowlist, EgressPolicy, host_of

ALLOW = EgressAllowlist(["api.github.com", "*.example.com"])


@pytest.mark.parametrize(
    "text,expected",
    [
        ("https://api.github.com/repos/x", []),
        ("https://API.GITHUB.COM./x", []),  # case + trailing dot normalize
        ("https://docs.example.com/page", []),
        ("https://example.com/page", ["example.com"]),  # *.x matches subdomains only
        ("https://api.github.com.evil.com/", ["api.github.com.evil.com"]),
        ("https://evil.com/?q=https://api.github.com", ["evil.com"]),
        # parser-confusion tricks are never treated as the allowed host
        ("https://api.github.com@evil.com/x", [UNPARSEABLE]),
        ("https://evil.com\\@api.github.com/", [UNPARSEABLE]),
        ("https://api.github.com:99999/", [UNPARSEABLE]),
        # a Cyrillic look-alike encodes to a different punycode name
        ("https://аpi.github.com/", ["xn--pi-6kc.github.com"]),
        ("http://2130706433/", ["2130706433"]),  # decimal IP is just an unlisted host
        ("exfil to evil.com/collect?d=secret", ["evil.com"]),  # scheme-less
        ("![chart](https://evil.example/p.png?d=SECRET)", ["evil.example"]),
        ("contact a@b.com/x for help", []),  # an email address is not a URL
    ],
)
def test_allowlist_classification(text, expected):
    assert [f.host for f in ALLOW.check(text)] == expected


def test_sanitize_replaces_only_disallowed_urls():
    text = "See https://docs.example.com/a and ![x](https://evil.example/p.png?d=1)."
    cleaned, findings = ALLOW.sanitize(text)
    assert "https://docs.example.com/a" in cleaned and "evil.example" not in cleaned
    assert [f.host for f in findings] == ["evil.example"]


def test_invalid_allowlist_entry_rejected():
    with pytest.raises(ValueError):
        EgressAllowlist(["*."])


def test_host_of_rejects_control_characters():
    assert host_of("https://api.github.com\r\n.evil.com/") == UNPARSEABLE


def test_egress_policy_blocks_nested_arguments_and_audits_hosts_only():
    sink = InMemoryAuditSink()
    policy = EgressPolicy(RiskTierPolicy({"low": "allow"}), ALLOW, audit_sink=sink)
    guard = ToolGuard(tool=lambda **kw: "sent", policy=policy, audit_sink=sink, tool_name="http_post")

    assert guard.call(Principal("a"), {"url": "https://api.github.com/issues"}) == "sent"
    with pytest.raises(ToolCallDenied, match="evil.example"):
        guard.call(Principal("a"), {"request": {"headers": {}, "targets": ["https://evil.example/?d=TOPSECRET"]}})

    egress = [e for e in sink.all_entries() if e.to_dict()["kind"] == "egress"][0]
    assert egress.hosts == ["evil.example:1"] and egress.action == "blocked"
    assert "TOPSECRET" not in json.dumps(egress.to_dict())


def test_egress_policy_can_escalate_to_approval_instead():
    policy = EgressPolicy(RiskTierPolicy({"low": "allow"}), ALLOW, on_violation="require_approval")
    guard = ToolGuard(tool=lambda **kw: "sent", policy=policy, approval_handler=AutoApprove(True), tool_name="t")
    assert guard.call(Principal("a"), {"url": "https://other.example.org/"}) == "sent"


def test_egress_policy_never_loosens_a_base_deny():
    policy = EgressPolicy(RiskTierPolicy({}, default="deny"), ALLOW)
    with pytest.raises(ToolCallDenied, match="maps to|default"):
        ToolGuard(tool=lambda **kw: 1, policy=policy, tool_name="t").call(Principal("a"), {"url": "https://api.github.com"})


def test_deeply_nested_arguments_do_not_blow_the_stack():
    nested = "https://evil.example/"
    for _ in range(5000):
        nested = [nested]
    policy = EgressPolicy(RiskTierPolicy({"low": "allow"}), ALLOW)
    with pytest.raises(ToolCallDenied):
        ToolGuard(tool=lambda **kw: 1, policy=policy, tool_name="t").call(Principal("a"), {"x": nested})


@pytest.mark.parametrize("text", ["a." * 50000, "https://" + "a" * 100000, ("x-" * 30000) + ".com/", "a/" * 50000])
def test_url_extraction_is_linear_time_on_adversarial_input(text):
    start = time.perf_counter()
    ALLOW.check(text)
    assert time.perf_counter() - start < 1.0
