"""Shadow mode: run the exact same policies with `mode="shadow"` instead
of the default `mode="enforce"` and see what governance WOULD have
denied/redacted/required approval for — with nothing actually blocked.

This is the low-friction path to adopting Marshal in a system that's
already in production: turn shadow mode on first, watch the audit trail
for a while, and only flip to `mode="enforce"` once you trust what it's
about to start blocking. Same policies, same audit trail shape, one
constructor argument different.

Run: python examples/shadow_mode_example.py
"""

from marshal_ai import (
    AllowlistModelPolicy,
    ArgumentRedaction,
    AttributePolicy,
    AutoApprove,
    Document,
    InMemoryAuditSink,
    ModelCallDenied,
    ModelCandidate,
    ModelGuard,
    Principal,
    RedactingToolPolicy,
    RetrievalGuard,
    RiskTierPolicy,
    ToolCallDenied,
    ToolGuard,
)

DOCS = [
    Document(id="policy-1", content="general leave policy", metadata={}),
    Document(id="salary-1", content="Q3 comp review numbers", metadata={"acl": ["role:hr"]}),
]

TOOL_POLICY = RedactingToolPolicy(
    base=RiskTierPolicy({"low": "allow", "medium": "require_approval", "high": "deny"}),
    rules=[ArgumentRedaction(name="salary_band", requires_attribute="role:hr")],
)

# Deliberately empty: every resolution below is denied by design, so the
# same call demonstrates the "would have been denied" model-guard case in
# both modes without needing a real routing table.
MODEL_POLICY = AllowlistModelPolicy({})


def update_salary_band(employee_id: str, salary_band: str) -> str:
    return f"updated {employee_id} to band {salary_band}"


def run(mode: str) -> None:
    print(f"\n=== mode={mode!r} ===")
    audit = InMemoryAuditSink()
    engineer = Principal(id="deepa", attributes={"role:engineering"})

    retrieval_guard = RetrievalGuard(
        retriever=lambda q, k: DOCS,
        policy=AttributePolicy(default="allow"),
        audit_sink=audit,
        mode=mode,
    )
    results = retrieval_guard.retrieve("compensation", principal=engineer, k=5)
    print("retrieval — documents returned to the caller:", [d.id for d in results])

    # AutoApprove(True) so the *enforce* run doesn't block on stdin below;
    # shadow mode never calls the approval handler at all either way.
    tool_guard = ToolGuard(
        tool=update_salary_band,
        policy=TOOL_POLICY,
        audit_sink=audit,
        tool_name="update_salary_band",
        approval_handler=AutoApprove(True),
        mode=mode,
    )

    try:
        result = tool_guard.call(
            engineer, {"employee_id": "E1", "salary_band": "L9"}, risk_tier="high"
        )
        print("tool call (high risk) result:", result)
    except ToolCallDenied as e:
        print("tool call (high risk) blocked:", e)

    result = tool_guard.call(
        engineer, {"employee_id": "E2", "salary_band": "L7"}, risk_tier="medium"
    )
    print("tool call (medium risk, requires approval) result:", result)

    model_guard = ModelGuard(policy=MODEL_POLICY, audit_sink=audit, mode=mode)
    try:
        model = model_guard.resolve(engineer, "default-chat-model")
        print("model resolved to:", model)
    except ModelCallDenied as e:
        print("model resolution blocked:", e)

    print("audit trail:")
    for entry in audit.tail(10):
        kind = entry.to_dict()["kind"]
        tag = "[shadow] " if getattr(entry, "shadow", False) else "[enforce]"
        if kind == "retrieval":
            print(
                f"  {tag} retrieval: allowed={entry.allowed_ids} "
                f"would_deny={entry.denied_ids} would_redact={entry.would_redact_fields}"
            )
        elif kind == "tool_call":
            print(
                f"  {tag} tool_call({entry.tool_name}): outcome={entry.outcome} "
                f"would_redact={entry.would_redact_fields} approved_by={entry.approved_by}"
            )
        elif kind == "model_call":
            print(
                f"  {tag} model_call: outcome={entry.outcome} "
                f"resolved={entry.resolved_model} reason={entry.reason}"
            )


def main() -> None:
    run("enforce")
    run("shadow")
    print(
        "\nSame policies, same audit trail shape, one constructor argument "
        "different — 'shadow' shows exactly what 'enforce' would have "
        "blocked without blocking anything for real."
    )


if __name__ == "__main__":
    main()
