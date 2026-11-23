"""Operating agents, not just governing them: one shift, end to end.

  1. Agents work inside `agent_run`s — every decision, tool outcome and
     model usage is tied to the run (and task) it belongs to. The audit
     trail is pseudonymized: no raw user or agent ids are ever stored.
  2. A downstream tool starts failing. `assess()` reports it — computed
     from real outcomes, not from a status someone typed into a registry.
  3. An on-call engineer quarantines the tool from the CLI. It takes
     effect immediately, in every process, and is audited with who and why.
  4. The inventory, built from the same trail, shows which agents depend
     on that tool (the blast radius), and what each task type costs per
     *successful* run.
  5. Before redeploying, the red-team battery replays known attack
     patterns against the policy configuration — and gates the deploy.

Run: python examples/operations_example.py
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from marshal_ai import (
    AllowlistModelPolicy,
    EgressAllowlist,
    EgressPolicy,
    ModelCandidate,
    ModelGuard,
    Principal,
    PseudonymizingAuditSink,
    Quarantine,
    QuarantineToolPolicy,
    RateLimitPolicy,
    RedTeamTargets,
    RiskTierPolicy,
    RunawayAgentPolicy,
    SensitiveDataToolPolicy,
    SQLiteAuditSink,
    ToolCallDenied,
    ToolGuard,
    agent_run,
    assess,
    build_inventory,
    render_health_markdown,
    render_redteam_markdown,
    run_costs,
    run_redteam,
)

workdir = Path(tempfile.mkdtemp())
sink = PseudonymizingAuditSink(SQLiteAuditSink(workdir / "audit.db"), key=os.urandom(32))
quarantine = Quarantine(workdir / "quarantine.db", audit_sink=sink)


def tool_policy(rate_limited: bool = False):
    policy = RiskTierPolicy({"low": "allow", "high": "require_approval"})
    if rate_limited:
        policy = RateLimitPolicy(policy, max_calls=30, window_seconds=60)
    policy = RunawayAgentPolicy(policy, identical_call_threshold=5, window_seconds=60)
    policy = EgressPolicy(policy, EgressAllowlist(["*.ourcompany.example"]))
    return QuarantineToolPolicy(SensitiveDataToolPolicy(policy), quarantine)


shared_policy = tool_policy()
carrier_up = {"value": True}


def track_shipment(order_id: str) -> str:
    if not carrier_up["value"]:
        raise TimeoutError("carrier API timeout")
    return f"order {order_id}: in transit"


track = ToolGuard(tool=track_shipment, policy=shared_policy, audit_sink=sink, tool_name="track_shipment", audit_outcomes=True)
models = ModelGuard(policy=AllowlistModelPolicy({"chat": [ModelCandidate("gpt-fast")]}), audit_sink=sink)
pricing = {"gpt-fast": (0.5, 1.5)}


def handle_ticket(agent: Principal, customer: str, order_id: str) -> None:
    with agent_run(sink, task="where-is-my-order", principal_id=agent.id, on_behalf_of=[customer]):
        actor = agent.acting_for(Principal(customer))
        models.resolve(actor, "chat")
        models.record_usage(actor, "gpt-fast", prompt_tokens=1200, completion_tokens=300)
        track.call(actor, {"order_id": order_id})


print("=== 1. a normal morning ===")
for i in range(6):
    handle_ticket(Principal("support-agent-1"), f"customer-{i}@mail.example", f"A{i}")
print("6 tickets handled")

print("\n=== 2. the carrier API starts timing out ===")
carrier_up["value"] = False
for i in range(6, 12):
    try:
        handle_ticket(Principal("support-agent-2"), f"customer-{i}@mail.example", f"A{i}")
    except TimeoutError:
        pass
for report in assess(sink):
    if report.subject_kind == "tool":
        print(f"track_shipment: {report.status} — {'; '.join(report.reasons)}")

print("\n=== 3. on-call quarantines it from the CLI (another process) ===")
cli = subprocess.run([sys.executable, "-m", "marshal_ai.cli", "quarantine", "add", str(workdir / "quarantine.db"),
                      "tool", "track_shipment", "--as", "oncall@ourcompany.example", "--reason", "carrier outage"],
                     check=True, capture_output=True, text=True)
print("$ marshal_ai.cli quarantine add ... ->", cli.stdout.strip())
try:
    handle_ticket(Principal("support-agent-1"), "customer-99@mail.example", "A99")
except ToolCallDenied as e:
    print("next call refused:", e.reason)

print("\n=== 4. blast radius and unit cost, from the same trail ===")
inventory = build_inventory(sink)
print(f"inventory: {len(inventory.agents)} agents, {len(inventory.tools)} tool(s), {len(inventory.models)} model(s), "
      f"acting for {len(inventory.subjects)} customers")
print("agents depending on track_shipment:", len(inventory.dependents_of("tool:track_shipment")), "(pseudonymous ids)")
for task in run_costs(sink, pricing).by_task:
    print(f"{task.task}: {task.runs} runs, {task.success_rate:.0%} succeeded, "
          f"${task.cost_per_successful_run_usd:.4f} per successful run")
print("raw customer emails in the stored trail:", "mail.example" in (workdir / "audit.db").read_bytes().decode("latin-1"))

print("\n=== 5. red-team gate before redeploying the policy ===")
targets = RedTeamTargets(send_external="send_reply", destructive="refund", destructive_tier="high", flood_calls=50)
report = run_redteam(tool_policy=tool_policy, targets=targets)
print(render_redteam_markdown(report))
print("-> a burst of calls gets through: add a rate limit and re-check")
report = run_redteam(tool_policy=lambda: tool_policy(rate_limited=True), targets=targets)
print("red-team result:", "PASS" if report.passed else "FAIL")

print("\n=== tool health at the end of the shift ===")
print(render_health_markdown([r for r in assess(sink) if r.subject_kind == "tool"]))
print("(render_mermaid(inventory) draws the full dependency graph)")
