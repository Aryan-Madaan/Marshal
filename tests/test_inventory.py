import pytest

from marshal_ai import AllowlistModelPolicy, InMemoryAuditSink, ModelCandidate, ModelGuard, Principal, RiskTierPolicy, ToolCallDenied, ToolGuard
from marshal_ai.inventory import build_inventory, render_mermaid, run_costs
from marshal_ai.runs import agent_run


def _activity(sink):
    tools = ToolGuard(tool=lambda **kw: 1, policy=RiskTierPolicy({"low": "allow", "high": "deny"}), audit_sink=sink,
                      tool_name="lookup", mcp_server="crm")
    models = ModelGuard(policy=AllowlistModelPolicy({"chat": [ModelCandidate("gpt-real")]}), audit_sink=sink)
    bot = Principal("support-bot", on_behalf_of=Principal("alice"))
    tools.call(bot, {})
    with pytest.raises(ToolCallDenied):
        tools.call(bot, {}, risk_tier="high")
    models.resolve(Principal("planner"), "chat")
    return models


def test_inventory_and_blast_radius_come_from_the_trail():
    sink = InMemoryAuditSink()
    _activity(sink)
    inv = build_inventory(sink)
    assert inv.agents == ["planner", "support-bot"] and inv.tools == ["lookup"]
    assert inv.mcp_servers == ["crm"] and inv.models == ["gpt-real"] and inv.subjects == ["alice"]
    calls = next(e for e in inv.edges if e.target == "tool:lookup")
    assert (calls.count, calls.denied) == (2, 1)
    assert inv.dependents_of("tool:lookup") == ["support-bot"]
    assert inv.dependents_of("model:gpt-real") == ["planner"]


def test_mermaid_output_escapes_hostile_names():
    sink = InMemoryAuditSink()
    ToolGuard(tool=lambda: 1, audit_sink=sink, tool_name='x"]; click A "javascript:alert(1)').call(Principal("a"), {})
    out = render_mermaid(build_inventory(sink))
    node_lines = [line for line in out.splitlines() if "tool" in line and "-->" not in line]
    assert out.startswith("graph LR") and node_lines
    # the label stays inside its one pair of quotes: no way to close it and add a directive
    assert all(line.count('"') == 2 for line in node_lines)


def test_cost_per_successful_run_by_task():
    sink = InMemoryAuditSink()
    models = _activity(sink)
    pricing = {"gpt-real": (1.0, 2.0)}
    for status_ok in (True, True, False):
        try:
            with agent_run(sink, task="refund"):
                models.record_usage(Principal("a"), "gpt-real", 1000, 500)  # $2.00 per run
                if not status_ok:
                    raise RuntimeError
        except RuntimeError:
            pass
    with agent_run(sink, task="refund"):
        models.record_usage(Principal("a"), "mystery-model", 10, 10)
    models.record_usage(Principal("a"), "gpt-real", 1000, 0)  # outside any run: $1.00

    report = run_costs(sink, pricing)
    refund = next(t for t in report.by_task if t.task == "refund")
    assert refund.runs == 4 and refund.successful_runs == 3 and refund.total_cost_usd == 6.0
    assert refund.cost_per_successful_run_usd == 2.0 and refund.success_rate == 0.75
    assert report.unattributed_cost_usd == 1.0
    assert any(r.unpriced_models == ["mystery-model"] for r in report.runs)
