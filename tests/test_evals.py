import pytest

from marshal_ai import InMemoryAuditSink, Principal, ToolGuard
from marshal_ai.evals import Score, evaluate, record_evaluation
from marshal_ai.health import assess
from marshal_ai.inventory import build_inventory, run_costs
from marshal_ai.runs import agent_run


def test_scorers_land_in_the_run_and_content_does_not():
    sink = InMemoryAuditSink()
    secret_answer = "the merger closes on 3 March"
    with agent_run(sink, task="qa") as run:
        entries = evaluate(sink, {
            "nonempty": lambda out, ctx: bool(out),
            "similarity": lambda out, ctx: 0.4,
            "explicit": lambda out, ctx: Score(True, 0.9),
            "crashes": lambda out, ctx: 1 / 0,
            "bad_type": lambda out, ctx: "yes",
        }, secret_answer, context={"documents": ["x"]})
    assert [e.passed for e in entries] == [True, False, True, False, False]
    assert entries[1].score == 0.4 and entries[3].error == "ZeroDivisionError" and entries[4].error == "TypeError"
    assert all(e.run_id == run.run_id for e in entries)
    assert secret_answer not in repr(sink.all_entries())


def test_record_evaluation_validates():
    sink = InMemoryAuditSink()
    with pytest.raises(ValueError):
        record_evaluation(sink, "", True)
    with pytest.raises(ValueError):
        record_evaluation(sink, "s", True, score=float("nan"))
    e = record_evaluation(sink, "human_review", False, run_id="run-external")
    assert e.run_id == "run-external" and e.parent_run_id is None


def test_task_health_from_evaluation_pass_rate():
    sink = InMemoryAuditSink()
    for i in range(10):
        with agent_run(sink, task="summarize"):
            evaluate(sink, {"grounded": lambda out, ctx, ok=(i < 6): ok}, "out")
    task = next(r for r in assess(sink) if r.subject_kind == "task")
    assert (task.subject, task.status, task.calls, task.failures) == ("summarize", "failing", 10, 4)
    assert "failed-evaluation rate" in task.reasons[0]


def test_cost_per_passing_run():
    sink = InMemoryAuditSink()
    from marshal_ai import AllowlistModelPolicy, ModelCandidate, ModelGuard

    models = ModelGuard(policy=AllowlistModelPolicy({"chat": [ModelCandidate("m")]}), audit_sink=sink)
    for passed in (True, False, True, None):
        with agent_run(sink, task="t"):
            models.record_usage(Principal("a"), "m", 1000, 0)  # $1 each
            if passed is not None:
                record_evaluation(sink, "check", passed)
    t = run_costs(sink, {"m": (1.0, 0.0)}).by_task[0]
    assert (t.runs, t.successful_runs, t.evaluated_runs, t.passing_runs) == (4, 4, 3, 2)
    assert t.cost_per_successful_run_usd == 1.0 and t.cost_per_passing_run_usd == 2.0


def test_blast_radius_of_an_mcp_server_is_agents_not_tools():
    sink = InMemoryAuditSink()
    for agent, tool in (("a1", "search"), ("a2", "search"), ("a3", "create_ticket"), ("a4", "local")):
        server = None if tool == "local" else "jira"
        ToolGuard(tool=lambda **kw: 1, audit_sink=sink, tool_name=tool, mcp_server=server).call(
            Principal(agent, on_behalf_of=Principal("bob")), {})
    inv = build_inventory(sink)
    assert inv.dependents_of("mcp:jira") == ["a1", "a2", "a3"]
    assert inv.dependents_of("tool:search") == ["a1", "a2"]


def test_mermaid_ids_do_not_collide():
    from marshal_ai.inventory import render_mermaid

    sink = InMemoryAuditSink()
    for name in ("a-b", "a_b"):
        ToolGuard(tool=lambda: 1, audit_sink=sink, tool_name=name).call(Principal("x"), {})
    out = render_mermaid(build_inventory(sink))
    node_ids = {line.split("[")[0].strip() for line in out.splitlines()[1:] if "-->" not in line and "tool" in line}
    assert len(node_ids) == 2
