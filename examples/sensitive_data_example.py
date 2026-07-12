"""Content-based sensitive-data detection, layered on top of the three
governance surfaces plus the SDK-patch integration layer — a different
question from all of them ("is this allowed") because it asks "does the
literal content contain a secret, regardless of who's allowed to see it."

Three scenes, one shared audit trail:
  1. Retrieval — an ACL-allowed document still gets an email redacted.
  2. Tool calls — a hardcoded AWS key in the arguments blocks the call
     outright, regardless of the tool's configured risk tier.
  3. The SDK-patch layer — a credential in an outbound prompt is blocked
     *before* any network call (deny-path only, so this runs with no API
     key — see examples/framework_integration_example.py for the pattern).

Run: python examples/sensitive_data_example.py
"""

import marshal_ai.integrations as marshal_integrations
from marshal_ai import (
    AllowAllTools,
    AllowlistModelPolicy,
    AttributePolicy,
    Document,
    InMemoryAuditSink,
    ModelCandidate,
    ModelGuard,
    Principal,
    RetrievalGuard,
    RiskTierPolicy,
    SensitiveDataPolicy,
    SensitiveDataScanner,
    SensitiveDataToolPolicy,
    ToolCallDenied,
    ToolGuard,
)
from marshal_ai.models import ModelCallDenied

shared_audit = InMemoryAuditSink()
alice = Principal(id="alice", attributes={"role:engineering"})


def scene_retrieval() -> None:
    print("=== 1. Retrieval: ACL-allowed, but content still gets scrubbed ===")

    def fake_retriever(query: str, k: int):
        return [
            Document(
                id="ticket-42",
                content="Customer reported a login issue, contact them at bob@example.com for repro steps.",
                metadata={},  # no ACL -> AttributePolicy(default="allow") lets everyone see it
            )
        ]

    policy = SensitiveDataPolicy(base=AttributePolicy(default="allow"), audit_sink=shared_audit)
    guard = RetrievalGuard(retriever=fake_retriever, policy=policy, audit_sink=shared_audit)

    results = guard.retrieve("login issue", principal=alice, k=5)
    print("returned content:", results[0].content)
    print()


def scene_tool_call() -> None:
    print("=== 2. Tool calls: a hardcoded credential blocks outright ===")

    def deploy_service(config: str) -> str:
        return "deployed"  # never actually reached below

    policy = SensitiveDataToolPolicy(
        base=RiskTierPolicy({"low": "allow"}),  # base policy alone would allow this
        audit_sink=shared_audit,
    )
    guard = ToolGuard(tool=deploy_service, policy=policy, audit_sink=shared_audit, tool_name="deploy_service")

    try:
        guard.call(alice, {"config": "aws_key=AKIAABCDEFGHIJKLMNOP"}, risk_tier="low")
    except ToolCallDenied as e:
        print(f"blocked despite risk_tier='low': {e}")
    print()


def scene_sdk_layer() -> None:
    print("=== 3. SDK-patch layer: blocked before any network call ===")

    guard = ModelGuard(policy=AllowlistModelPolicy({"gpt-4o": [ModelCandidate("gpt-4o-mini")]}), audit_sink=shared_audit)
    marshal_integrations.enable_openai(guard, alice, scanner=SensitiveDataScanner())

    import openai

    client = openai.OpenAI(api_key="not-a-real-key")
    try:
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "use this key sk-abcdefghijklmnopqrstuvwx123456 to call the API"}],
        )
    except ModelCallDenied as e:
        print(f"blocked before any network call: {e}")

    marshal_integrations.disable_all()
    print()


def main() -> None:
    scene_retrieval()
    scene_tool_call()
    scene_sdk_layer()

    print("=== shared audit trail: every sensitive-data finding, one place ===")
    for entry in shared_audit.tail(10):
        if entry.to_dict()["kind"] != "sensitive_data":
            continue
        print(f"  [{entry.surface}] {entry.location}: {entry.findings} -> {entry.action}")


if __name__ == "__main__":
    main()
