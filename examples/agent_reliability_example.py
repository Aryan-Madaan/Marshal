"""Three ToolGuard-side governance questions, independent of each other:

  1. Is this principal calling things too often, period? (RateLimitPolicy)
  2. Is this principal stuck in a broken loop, calling the *same* thing
     over and over? (RunawayAgentPolicy — requires a human reset, doesn't
     self-heal on a timer the way CircuitBreakerPolicy does)
  3. Does this specific action need more oversight in this jurisdiction
     than the base policy already gives it? (JurisdictionalRiskTierPolicy)

Run: python examples/agent_reliability_example.py
"""

from marshal_ai import (
    AutoApprove,
    InMemoryAuditSink,
    JurisdictionalRiskTierPolicy,
    Principal,
    RateLimitPolicy,
    RiskTierPolicy,
    RunawayAgentPolicy,
    ToolCallDenied,
    ToolGuard,
)


def main() -> None:
    shared_audit = InMemoryAuditSink()

    # --- Scene 1: rate limiting — caps call frequency, period ---
    print("=== 1. Rate limiting: caps how often, regardless of outcome ===")
    rate_limited = RateLimitPolicy(RiskTierPolicy({"low": "allow"}), max_calls=2, window_seconds=60)
    guard = ToolGuard(tool=lambda **kw: "sent", policy=rate_limited, audit_sink=shared_audit)
    alice = Principal(id="alice")

    guard.call(alice, {}, risk_tier="low")
    guard.call(alice, {}, risk_tier="low")
    try:
        guard.call(alice, {}, risk_tier="low")
    except ToolCallDenied as e:
        print(f"3rd call in the window blocked: {e}")

    # --- Scene 2: runaway-agent — a broken loop calling the same thing ---
    print("\n=== 2. Runaway-agent breaker: same tool, same arguments, over and over ===")
    loop_guard_policy = RunawayAgentPolicy(
        RiskTierPolicy({"low": "allow"}), identical_call_threshold=3, window_seconds=60
    )
    loop_guard = ToolGuard(
        tool=lambda **kw: "retrying...",
        policy=loop_guard_policy,
        audit_sink=shared_audit,
        tool_name="flaky_tool",
    )
    bob = Principal(id="bob")

    for i in range(2):
        loop_guard.call(bob, {"retry": True}, risk_tier="low")
    try:
        loop_guard.call(bob, {"retry": True}, risk_tier="low")
    except ToolCallDenied as e:
        print(f"tripped on the 3rd identical call: {e}")
    print("tripped for every call now, even a different one:")
    try:
        loop_guard.call(bob, {"retry": False}, risk_tier="low")
    except ToolCallDenied as e:
        print(f" -> {e}")
    print("a human decides it's fixed, resets, and bob can call things again:")
    loop_guard_policy.reset("bob")
    print(" ->", loop_guard.call(bob, {"retry": True}, risk_tier="low"))

    # --- Scene 3: jurisdiction can only ADD oversight, never remove it ---
    print("\n=== 3. Jurisdictional risk tiering: EU tightens, never loosens ===")
    hr_policy = JurisdictionalRiskTierPolicy(
        RiskTierPolicy({"employment_decision": "allow"}),
        overrides_by_jurisdiction={"EU": {"employment_decision": "require_approval"}},
    )
    hr_guard = ToolGuard(
        tool=lambda **kw: "candidate advanced",
        policy=hr_policy,
        audit_sink=shared_audit,
        approval_handler=AutoApprove(True),
        tool_name="advance_candidate",
    )
    carol = Principal(id="carol")

    print("US-governed call: base policy's 'allow' applies untouched:")
    print(" ->", hr_guard.call(carol, {}, risk_tier="employment_decision", context={"jurisdiction": "US"}))
    print("EU-governed call: same action, same base policy, forced through approval:")
    print(" ->", hr_guard.call(carol, {}, risk_tier="employment_decision", context={"jurisdiction": "EU"}))

    print("\naudit trail — every guard, one shared trail:")
    for entry in shared_audit.tail(10):
        d = entry.to_dict()
        print(f"  [{d['kind']}] {d['principal_id']}: {d['outcome']} — {d['reason']}")


if __name__ == "__main__":
    main()
