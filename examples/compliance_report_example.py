"""Turning an audit trail into compliance artifacts: durable, tamper-
evident storage (`SQLiteAuditSink`) plus two reports derived purely from
its contents (`marshal_ai.reports`) — the pieces the EU AI Act's Article
12 (automatic record-keeping) and Article 26 (>=6 month log retention)
obligations for high-risk systems actually need, on top of the audit
trail every guard already writes to.

Scenario: a service makes a few residency-governed model calls across
jurisdictions (some allowed, one blocked), and an agent attempts a few
tool calls at different risk tiers (some allowed, one denied outright).
Everything lands in one `SQLiteAuditSink` on disk. We then:

  1. verify the hash chain is intact (nothing's been tampered with since
     it was written);
  2. render a cross-border data-flow report — which jurisdictions data
     flowed to, via which legal mechanism, under which controller;
  3. render an Article-12-style activity record — allowed/denied/
     approval-required counts per day, across all three guarded
     surfaces.

Run: python examples/compliance_report_example.py
"""

import tempfile
from pathlib import Path

from marshal_ai import (
    AllowlistModelPolicy,
    AutoApprove,
    ModelCallDenied,
    ModelCandidate,
    Principal,
    ResidencyPolicy,
    RiskTierPolicy,
    ToolCallDenied,
    ToolGuard,
)
from marshal_ai.models import ModelGuard
from marshal_ai.reports import (
    article12_activity_record,
    cross_border_data_flow_report,
    render_activity_record_markdown,
    render_cross_border_markdown,
)
from marshal_ai.sinks import SQLiteAuditSink

ROUTES = {
    "default-chat-model": [
        ModelCandidate("eu-deployment"),
        ModelCandidate("in-deployment"),
    ]
}

# Only your data controller/fiduciary decides this mapping — Marshal
# enforces it deterministically at every call; see ResidencyPolicy's
# docstring (marshal_ai/models.py) for why that split matters.
ALLOWED_BY_JURISDICTION = {
    "EU": {"eu-deployment": "adequacy_decision"},
    "IN": {"in-deployment": "dpdp_section_16"},
}


def delete_customer_record(record_id: str) -> str:
    return f"deleted {record_id}"


def send_notification(user_id: str, message: str) -> str:
    return f"notified {user_id}: {message}"


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "compliance_demo.db"
        sink = SQLiteAuditSink(db_path)

        # --- a handful of residency-governed model calls -------------------
        model_policy = ResidencyPolicy(AllowlistModelPolicy(ROUTES), ALLOWED_BY_JURISDICTION)
        model_guard = ModelGuard(policy=model_policy, audit_sink=sink)
        service_account = Principal(id="agent-service")

        model_guard.resolve(
            service_account,
            "default-chat-model",
            context={"jurisdiction": "EU", "controller": "acme-eu-entity"},
        )
        model_guard.resolve(
            service_account,
            "default-chat-model",
            context={"jurisdiction": "EU", "controller": "acme-eu-entity"},
        )
        model_guard.resolve(
            service_account,
            "default-chat-model",
            context={"jurisdiction": "IN"},
        )
        try:
            model_guard.resolve(service_account, "default-chat-model", context={"jurisdiction": "TH"})
        except ModelCallDenied:
            pass  # no compliant deployment configured for Thailand yet — expected

        # --- a handful of tool calls, one denied outright -------------------
        tool_policy = RiskTierPolicy({"low": "allow", "medium": "require_approval", "high": "deny"})
        notify_guard = ToolGuard(
            tool=send_notification,
            policy=tool_policy,
            audit_sink=sink,
            tool_name="send_notification",
        )
        delete_guard = ToolGuard(
            tool=delete_customer_record,
            policy=tool_policy,
            audit_sink=sink,
            approval_handler=AutoApprove(True),
            tool_name="delete_customer_record",
        )
        agent = Principal(id="support-agent-7")

        notify_guard.call(agent, {"user_id": "u-1", "message": "your ticket was updated"}, risk_tier="low")
        try:
            delete_guard.call(agent, {"record_id": "cust-42"}, risk_tier="high")
        except ToolCallDenied:
            pass  # high-risk destructive action denied outright — expected
        delete_guard.call(agent, {"record_id": "cust-43"}, risk_tier="medium")  # goes through approval

        # --- 1. tamper-evidence check ---------------------------------------
        result = sink.verify()
        print(f"hash chain verify(): ok={result.ok}, checked={result.checked} records\n")

        # --- 2. cross-border data-flow report -------------------------------
        flow_report = cross_border_data_flow_report(sink)
        print(render_cross_border_markdown(flow_report))

        # --- 3. Article-12-style activity record ----------------------------
        activity_report = article12_activity_record(sink)
        print(render_activity_record_markdown(activity_report))

        sink.close()


if __name__ == "__main__":
    main()
