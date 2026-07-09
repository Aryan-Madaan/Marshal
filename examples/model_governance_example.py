"""Model routing with governed fallbacks and per-principal budgets — and
the same shared audit trail used by the other two examples.

Run: python examples/model_governance_example.py
"""

from marshal_ai import (
    AllowlistModelPolicy,
    BudgetPolicy,
    InMemoryAuditSink,
    ModelCallDenied,
    ModelCandidate,
    ModelGuard,
    Principal,
)

ROUTES = {
    "default-chat-model": [
        ModelCandidate("fast-model"),
        ModelCandidate("eu-hosted-model", requires_attribute="region:eu"),
        ModelCandidate("general-backup"),
    ]
}

# $ per 1K prompt / completion tokens — illustrative, not real pricing.
PRICING = {"fast-model": (0.50, 1.50), "general-backup": (0.10, 0.30)}


def main() -> None:
    shared_audit = InMemoryAuditSink()
    policy = BudgetPolicy(AllowlistModelPolicy(ROUTES), pricing=PRICING, limit_usd=1.00)
    guard = ModelGuard(policy=policy, audit_sink=shared_audit)

    alice = Principal(id="alice", attributes={"region:us"})
    eu_bob = Principal(id="bob", attributes={"region:eu"})

    model = guard.resolve(alice, "default-chat-model")
    print("alice resolved to:", model)
    print("alice's governed fallbacks (eu-hosted-model already excluded):",
          guard.fallback_chain(alice, "default-chat-model"))
    print("bob's governed fallbacks (he qualifies for the eu one):",
          guard.fallback_chain(eu_bob, "default-chat-model"))

    # Simulate a real call's usage coming back, then burn through alice's budget.
    guard.record_usage(alice, model, prompt_tokens=1000, completion_tokens=500)
    print(f"\nalice has spent ${policy.spent_by('alice'):.2f} of her $1.00 budget")

    try:
        guard.resolve(alice, "default-chat-model")
    except ModelCallDenied as e:
        print(f"next call blocked: {e}")

    print("\naudit trail:")
    for entry in shared_audit.tail(3):
        print(f"  {entry.principal_id}: {entry.outcome} -> {entry.resolved_model} ({entry.reason})")


if __name__ == "__main__":
    main()
