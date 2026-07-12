"""Reliability tracking and circuit-breaking for model calls — the piece
neither ResidencyPolicy/RetentionPolicy nor BudgetPolicy can answer: is a
resolved deployment actually working right now, based on what really
happened to recent calls, not static config.

Run: python examples/circuit_breaker_example.py
"""

from marshal_ai import (
    AllowlistModelPolicy,
    CircuitBreakerPolicy,
    InMemoryAuditSink,
    ModelCallDenied,
    ModelCandidate,
    ModelGuard,
    Principal,
)

ROUTES = {
    "default-chat-model": [
        ModelCandidate("primary-deployment"),
        ModelCandidate("backup-deployment"),
    ]
}


def main() -> None:
    shared_audit = InMemoryAuditSink()
    policy = CircuitBreakerPolicy(
        AllowlistModelPolicy(ROUTES), failure_threshold=3, window_seconds=60
    )
    guard = ModelGuard(policy=policy, audit_sink=shared_audit)
    service_account = Principal(id="agent-service")

    print("healthy: resolves to the preferred deployment")
    print(" ->", guard.resolve(service_account, "default-chat-model"))

    print("\nsimulating 3 real call failures against primary-deployment...")
    for _ in range(3):
        # this is exactly what marshal_ai.integrations does automatically
        # on a real SDK call that raises — reported here by hand since
        # this example has no real API key to call.
        guard.record_outcome(service_account, "primary-deployment", success=False, error="timeout")

    print("tripped: circuit breaker routes around it automatically")
    print(" ->", guard.resolve(service_account, "default-chat-model"))

    print("\nnow trip the backup too...")
    for _ in range(3):
        guard.record_outcome(service_account, "backup-deployment", success=False, error="server_error")

    print("everything tripped: fails closed, doesn't silently retry a broken deployment")
    try:
        guard.resolve(service_account, "default-chat-model")
    except ModelCallDenied as e:
        print(" ->", e)

    print("\naudit trail — every resolution and every outcome, in one place:")
    for entry in shared_audit.tail(6):
        kind = entry.to_dict()["kind"]
        if kind == "model_call":
            print(f"  [resolve] {entry.outcome} -> {entry.resolved_model} ({entry.reason})")
        elif kind == "model_outcome":
            print(f"  [outcome] {entry.model}: success={entry.success} error={entry.error}")


if __name__ == "__main__":
    main()
