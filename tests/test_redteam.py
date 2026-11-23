from marshal_ai import (
    AllowAllTools,
    AttributePolicy,
    DelegatedPolicy,
    EgressAllowlist,
    EgressPolicy,
    FlowTracker,
    LethalTrifectaPolicy,
    RateLimitPolicy,
    RiskTierPolicy,
    RunawayAgentPolicy,
    SensitiveDataToolPolicy,
)
from marshal_ai.flow import EXTERNAL_COMMUNICATION, PRIVATE_DATA, UNTRUSTED_CONTENT
from marshal_ai.redteam import RedTeamTargets, render_redteam_markdown, run_redteam

TARGETS = RedTeamTargets(send_external="send_email", read_untrusted="fetch_url", read_private="query_crm",
                         destructive="delete_account", destructive_tier="high", flood_calls=300)


def hardened():
    tracker = FlowTracker()
    policy = RiskTierPolicy({"low": "allow", "high": "require_approval"})
    policy = LethalTrifectaPolicy(policy, tracker, tool_capabilities={
        "send_email": {EXTERNAL_COMMUNICATION}, "fetch_url": {UNTRUSTED_CONTENT}, "query_crm": {PRIVATE_DATA}})
    policy = RunawayAgentPolicy(policy, identical_call_threshold=5, window_seconds=60)
    policy = RateLimitPolicy(policy, max_calls=200, window_seconds=60)
    policy = EgressPolicy(policy, EgressAllowlist(["*.ourcompany.example"]))
    return SensitiveDataToolPolicy(policy)


def test_a_permissive_configuration_fails_and_says_where():
    report = run_redteam(tool_policy=AllowAllTools, retrieval_policy=AttributePolicy, targets=TARGETS)
    assert not report.passed
    failed = {r.id for r in report.results if r.passed is False}
    assert failed == {"credential-exfiltration", "unicode-smuggling", "url-exfiltration", "lethal-trifecta",
                      "destructive-unapproved", "retry-loop", "request-flood", "confused-deputy"}
    assert "FAIL" in render_redteam_markdown(report)


def test_a_hardened_configuration_passes_every_scenario():
    report = run_redteam(tool_policy=hardened, retrieval_policy=lambda: DelegatedPolicy(AttributePolicy()), targets=TARGETS)
    assert report.passed, render_redteam_markdown(report)
    outcomes = {r.id: r.outcome for r in report.results}
    assert outcomes["destructive-unapproved"] == "escalated"  # a human would have to approve
    assert outcomes["lethal-trifecta"] == "escalated"
    assert outcomes["credential-exfiltration"] == "blocked"


def test_missing_targets_are_not_applicable_never_silently_passed():
    report = run_redteam(tool_policy=AllowAllTools, targets=RedTeamTargets())
    assert {r.outcome for r in report.results} == {"not_applicable"}
    assert all(r.passed is None for r in report.results) and report.passed


def test_a_crashing_policy_is_a_finding():
    def broken():
        raise RuntimeError("bad config")

    report = run_redteam(tool_policy=broken, targets=TARGETS)
    assert not report.passed and report.results[0].outcome == "error"


def test_runs_against_a_policy_file(tmp_path):
    from marshal_ai import load_policies

    path = tmp_path / "policies.json"
    path.write_text('{"tool_policy": {"base": {"type": "risk_tier", "tiers": {"low": "allow", "high": "deny"}},'
                    '"wrappers": [{"type": "sensitive_data"}, {"type": "egress", "allowed_hosts": ["ourcompany.example"]},'
                    '{"type": "runaway_agent", "identical_call_threshold": 5, "window_seconds": 60},'
                    '{"type": "rate_limit", "max_calls": 100, "window_seconds": 60}]}}')
    report = run_redteam(tool_policy=lambda: load_policies(path).tool_policy, targets=TARGETS)
    by_id = {r.id: r for r in report.results}
    # without a lethal_trifecta wrapper the trifecta path is open — reported, not hidden
    assert by_id["lethal-trifecta"].passed is False
    assert all(r.passed for r in report.results if r.id != "lethal-trifecta")

    import json

    config = json.loads(path.read_text())
    config["tool_policy"]["wrappers"].insert(0, {"type": "lethal_trifecta", "tool_capabilities": {
        "send_email": ["external_communication"], "fetch_url": ["untrusted_content"], "query_crm": ["private_data"]}})
    path.write_text(json.dumps(config))
    assert run_redteam(tool_policy=lambda: load_policies(path).tool_policy, targets=TARGETS).passed
