"""Tool-call governance: risk-tiered allow/deny/approve, argument
redaction, and an audit trail shared with retrieval governance.

Run: python examples/tool_governance_example.py
(The medium-risk call below will prompt you for approval on stdin.)
"""

from marshal_ai import (
    ArgumentRedaction,
    AutoApprove,
    InMemoryAuditSink,
    Principal,
    RedactingToolPolicy,
    RiskTierPolicy,
    ToolCallDenied,
    ToolGuard,
)


def update_employee_record(employee_id: str, salary_band: str) -> str:
    return f"updated {employee_id} to band {salary_band}"


def main() -> None:
    shared_audit = InMemoryAuditSink()

    policy = RedactingToolPolicy(
        base=RiskTierPolicy({"low": "allow", "medium": "require_approval", "high": "deny"}),
        rules=[ArgumentRedaction(name="salary_band", requires_attribute="role:hr")],
    )

    guard = ToolGuard(
        tool=update_employee_record,
        policy=policy,
        audit_sink=shared_audit,
        # AutoApprove(True) here so this example runs unattended; swap in
        # CLIApprovalHandler() (the default) for a real interactive prompt.
        approval_handler=AutoApprove(True),
        tool_name="update_employee_record",
    )

    hr = Principal(id="rhea", attributes={"role:hr"})
    engineer = Principal(id="deepa", attributes={"role:engineering"})

    result = guard.call(hr, {"employee_id": "E123", "salary_band": "L6"}, risk_tier="medium")
    print("hr call result:", result)

    try:
        guard.call(engineer, {"employee_id": "E123", "salary_band": "L9"}, risk_tier="high")
    except ToolCallDenied as e:
        print(f"engineer call blocked: {e}")

    print("\naudit trail (note: salary_band is redacted for the non-HR entry only):")
    for entry in shared_audit.tail(3):
        print(f"  {entry.principal_id}: {entry.outcome} — {entry.arguments}")


if __name__ == "__main__":
    main()
