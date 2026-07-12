"""Cross-border data governance for model calls — three independent
questions, one shared audit trail:

  1. WHERE is this data allowed to be processed (ResidencyPolicy)
  2. HOW LONG is whoever processes it allowed to keep it (RetentionPolicy)
  3. WHAT'S actually in the payload that needs to be caught regardless of
     where it goes (marshal_ai.sensitive — see sensitive_data_example.py)

None of the three ever writes raw prompt content to the audit trail —
ResidencyPolicy/RetentionPolicy only ever see jurisdiction codes, day
counts, and deployment/mechanism names; the sensitive-data scanner
records "DETECTOR:count", never the matched text.

Run: python examples/residency_example.py
"""

from marshal_ai import (
    AllowlistModelPolicy,
    InMemoryAuditSink,
    ModelCallDenied,
    ModelCandidate,
    ModelGuard,
    Principal,
    ResidencyPolicy,
    RetentionPolicy,
)

ROUTES = {
    "default-chat-model": [
        ModelCandidate("eu-deployment"),
        ModelCandidate("in-deployment"),
    ]
}

# Only your data controller/fiduciary can decide this mapping — Marshal
# enforces it deterministically at every call, it doesn't make the legal
# call for you. Deliberately narrow: no candidate covers Thailand yet.
# jurisdiction -> {deployment: transfer mechanism}
ALLOWED_BY_JURISDICTION = {
    "EU": {"eu-deployment": "adequacy_decision"},
    "IN": {"in-deployment": "dpdp_section_16"},
}

# deployment -> days of retention its vendor agreement actually specifies.
# 0 means a signed zero-data-retention (ZDR) agreement.
DEPLOYMENT_RETENTION_DAYS = {
    "eu-deployment": 0,
    "in-deployment": 30,
}


def main() -> None:
    shared_audit = InMemoryAuditSink()

    # Scene 1: residency alone — where is this allowed to go.
    residency_only = ResidencyPolicy(AllowlistModelPolicy(ROUTES), ALLOWED_BY_JURISDICTION)
    guard = ModelGuard(policy=residency_only, audit_sink=shared_audit)
    service_account = Principal(id="agent-service")

    eu_model = guard.resolve(
        service_account,
        "default-chat-model",
        context={"jurisdiction": "EU", "controller": "acme-eu-entity"},
    )
    print("EU-governed call resolved to:", eu_model, "(mechanism + controller land in the audit reason)")

    in_model = guard.resolve(service_account, "default-chat-model", context={"jurisdiction": "IN"})
    print("India-governed call resolved to:", in_model)

    try:
        guard.resolve(service_account, "default-chat-model", context={"jurisdiction": "TH"})
    except ModelCallDenied as e:
        print(f"\nThailand-governed call blocked (no compliant deployment configured yet): {e}")

    # Scene 2: stack RetentionPolicy on top — same jurisdiction, but this
    # call also requires a zero-data-retention deployment specifically.
    print("\n--- stacking RetentionPolicy on top of ResidencyPolicy ---")
    residency_and_retention = RetentionPolicy(
        ResidencyPolicy(AllowlistModelPolicy(ROUTES), ALLOWED_BY_JURISDICTION),
        DEPLOYMENT_RETENTION_DAYS,
    )
    strict_guard = ModelGuard(policy=residency_and_retention, audit_sink=shared_audit)

    resolved = strict_guard.resolve(
        service_account, "default-chat-model", context={"jurisdiction": "EU", "max_retention_days": 0}
    )
    print("EU call requiring zero-data-retention resolved to:", resolved, "(eu-deployment is a ZDR deployment)")

    try:
        # in-deployment is jurisdiction-compliant for India, but retains
        # for 30 days — geography passes, retention doesn't.
        strict_guard.resolve(
            service_account, "default-chat-model", context={"jurisdiction": "IN", "max_retention_days": 0}
        )
    except ModelCallDenied as e:
        print(f"India call requiring zero-data-retention blocked (in-deployment retains 30 days): {e}")

    print("\naudit trail — every routing decision, allowed or denied, in one place:")
    for entry in shared_audit.tail(5):
        print(f"  resolve {entry.outcome} -> {entry.resolved_model} ({entry.reason})")


if __name__ == "__main__":
    main()
