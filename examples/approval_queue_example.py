"""Human approval that doesn't block a terminal: a durable approval queue.

An agent wants to issue a large refund. Policy says that needs a human.
Instead of blocking on stdin, the request goes into a SQLite-backed
queue; the agent gets `ApprovalPending` and moves on. A reviewer approves
it from another process (here: the CLI, the same way a Slack bot or an
admin page would). The agent retries the identical call and it runs —
exactly once. Trying to reuse that approval for a different amount, or a
second time, doesn't work.

Run: python examples/approval_queue_example.py
"""

import subprocess
import sys
import tempfile
from pathlib import Path

from marshal_ai import InMemoryAuditSink, Principal, RiskTierPolicy, ToolCallDenied, ToolGuard
from marshal_ai.approvals import ApprovalQueue, QueuedApprovalHandler
from marshal_ai.tools import ApprovalPending

db = Path(tempfile.mkdtemp()) / "approvals.db"
queue = ApprovalQueue(db, ttl_seconds=900)
sink = InMemoryAuditSink()
refunds: list[str] = []

guard = ToolGuard(
    tool=lambda order_id, amount: refunds.append(f"{order_id}:${amount}") or "refunded",
    policy=RiskTierPolicy({"low": "allow", "medium": "require_approval"}),
    audit_sink=sink,
    approval_handler=QueuedApprovalHandler(queue, wait_seconds=0),  # never block
    tool_name="issue_refund",
)
agent = Principal("billing-agent", on_behalf_of=Principal("customer-881"))
request = {"order_id": "881", "amount": 450}

print("=== 1. the agent asks; the call is queued, not run ===")
try:
    guard.call(agent, request, risk_tier="medium")
except ApprovalPending as pending:
    approval_id = pending.approval_id
    print("pending:", approval_id, "| refunds so far:", refunds)

print("\n=== 2. a reviewer looks at the queue (from another process) ===")
cli = [sys.executable, "-m", "marshal_ai.cli", "approvals"]
print(subprocess.run([*cli, "list", str(db)], capture_output=True, text=True).stdout.strip())
print(subprocess.run([*cli, "approve", str(db), approval_id, "--as", "maria@ourcompany.example"],
                     capture_output=True, text=True).stdout.strip())

print("\n=== 3. the agent retries the identical call: it runs ===")
print(guard.call(agent, request, risk_tier="medium"), "| refunds:", refunds)

print("\n=== 4. the approval can't be stretched ===")
for label, args in [("bigger amount", {"order_id": "881", "amount": 4500}), ("same call again", request)]:
    try:
        guard.call(agent, args, risk_tier="medium")
    except ToolCallDenied as e:
        print(f"{label}: not released ({type(e).__name__})")
print("refunds:", refunds)

print("\n=== audit trail ===")
for entry in sink.all_entries():
    by = f" by {entry.approved_by}" if entry.approved_by else ""
    print(f"  {entry.tool_name} {entry.arguments}: {entry.outcome}{by}")
queue.close()
