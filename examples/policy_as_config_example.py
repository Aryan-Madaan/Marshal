"""Policy-as-config: load `examples/policies.yaml` — a reviewable,
diffable, version-controlled file a compliance reviewer who isn't a
Python engineer can read and propose a change to — and wire the exact
same `AttributePolicy`/`RiskTierPolicy`/`AllowlistModelPolicy`-shaped
objects `load_policies` builds from it into real guards, exactly as if
they'd been constructed by hand in Python.

Run: python examples/policy_as_config_example.py
(Needs PyYAML: pip install "marshal-ai[config]" — already a dev dependency
in this repo's own venv.)
"""

from pathlib import Path

from marshal_ai import (
    AutoApprove,
    Document,
    InMemoryAuditSink,
    ModelCallDenied,
    ModelGuard,
    Principal,
    RetrievalGuard,
    ToolCallDenied,
    ToolGuard,
    load_policies,
)

CONFIG_PATH = Path(__file__).parent / "policies.yaml"


def documents(query: str, k: int):
    return [
        Document(id="handbook-1", content="General leave policy...", metadata={}),
        Document(
            id="support-1",
            content="escalate to bob@example.com if this recurs",
            metadata={},
        ),
    ]


def update_employee_record(employee_id: str, salary_band: str) -> str:
    return f"updated {employee_id} to band {salary_band}"


def main() -> None:
    loaded = load_policies(CONFIG_PATH)
    print(f"loaded from {CONFIG_PATH.name}: retrieval={loaded.retrieval_policy is not None}, "
          f"tool={loaded.tool_policy is not None}, model={loaded.model_policy is not None}")

    shared_audit = InMemoryAuditSink()
    alice = Principal(id="alice")
    eu_alice = Principal(id="alice", attributes={"region:eu"})

    # --- retrieval: sensitive_data wrapper redacts regardless of ACL -----
    retrieval_guard = RetrievalGuard(retriever=documents, policy=loaded.retrieval_policy, audit_sink=shared_audit)
    results = retrieval_guard.retrieve("support tickets", principal=alice, k=5)
    for doc in results:
        print(f"retrieved {doc.id}: {doc.content!r}")

    # --- tool calls: risk_tier + rate_limit + jurisdictional tightening ---
    tool_guard = ToolGuard(
        tool=update_employee_record,
        policy=loaded.tool_policy,
        audit_sink=shared_audit,
        approval_handler=AutoApprove(True),  # auto-approve so this runs unattended
        tool_name="update_employee_record",
    )
    print("\nlow-risk call:", tool_guard.call(alice, {"employee_id": "E1", "salary_band": "L4"}, risk_tier="low"))
    try:
        tool_guard.call(alice, {"employee_id": "E1", "salary_band": "L9"}, risk_tier="high")
    except ToolCallDenied as e:
        print(f"high-risk call blocked outright: {e}")

    # employment_decision alone is "allow" under the base risk_tier table,
    # but the config's jurisdictional_risk_tier wrapper forces approval in
    # the EU specifically — proven here by declining that approval.
    declining_guard = ToolGuard(
        tool=update_employee_record,
        policy=loaded.tool_policy,
        audit_sink=shared_audit,
        approval_handler=AutoApprove(False),
        tool_name="update_employee_record",
    )
    try:
        declining_guard.call(
            alice, {"employee_id": "E1", "salary_band": "L4"},
            risk_tier="employment_decision", context={"jurisdiction": "EU"},
        )
    except ToolCallDenied as e:
        print(f"EU employment_decision forced through (declined) approval: {e}")

    # --- model calls: allowlist + budget + residency, stacked -------------
    # ResidencyPolicy fails closed on any call missing a jurisdiction, so
    # every resolve() below states one explicitly — same discipline the
    # config itself enforces on every real caller.
    model_guard = ModelGuard(policy=loaded.model_policy, audit_sink=shared_audit)
    us_model = model_guard.resolve(alice, "default-chat-model", context={"jurisdiction": "US"})
    print(f"\nalice, US-governed call, resolves to: {us_model}")

    eu_model = model_guard.resolve(eu_alice, "default-chat-model", context={"jurisdiction": "EU"})
    print(f"eu_alice, EU-governed call, resolves to: {eu_model}")

    try:
        model_guard.resolve(eu_alice, "default-chat-model", context={"jurisdiction": "TH"})
    except ModelCallDenied as e:
        print(f"Thailand-governed call blocked (no compliant deployment configured): {e}")

    model_guard.record_usage(alice, us_model, prompt_tokens=6000, completion_tokens=2000)  # $6.00, over the $5 limit
    try:
        model_guard.resolve(alice, "default-chat-model", context={"jurisdiction": "US"})
    except ModelCallDenied as e:
        print(f"alice's next call blocked over budget: {e}")

    print("\naudit trail — every decision above, retrieval + tool + model, in one shared sink:")
    for entry in shared_audit.tail(8):
        kind = entry.to_dict()["kind"]
        print(f"  [{kind}] {entry.principal_id}: {getattr(entry, 'reason', '')}")


if __name__ == "__main__":
    main()
