import asyncio
import json

import pytest

from marshal_ai import (
    AttributePolicy,
    Document,
    InMemoryAuditSink,
    JSONLAuditSink,
    Principal,
    RetrievalGuard,
    RiskTierPolicy,
    ToolCallDenied,
    ToolGuard,
)
from marshal_ai.runs import RunEntry, agent_run, current_run_id, run_summary, run_timeline


def _guards(sink):
    retrieval = RetrievalGuard(lambda q, k: [Document("d1", "x", {"acl": ["a"]})], policy=AttributePolicy(), audit_sink=sink)
    tools = ToolGuard(tool=lambda **kw: "ok", policy=RiskTierPolicy({"low": "allow", "high": "deny"}),
                      audit_sink=sink, tool_name="t")
    return retrieval, tools


def test_every_entry_written_inside_a_run_is_stamped():
    sink = InMemoryAuditSink()
    retrieval, tools = _guards(sink)
    tools.call(Principal("p"), {})  # outside any run
    with agent_run(sink, task="lookup") as run:
        retrieval.retrieve("q", Principal("p", {"a"}))
        tools.call(Principal("p"), {})
        with pytest.raises(ToolCallDenied):
            tools.call(Principal("p"), {}, risk_tier="high")
    assert current_run_id() is None
    stamped = [e for e in sink.all_entries() if e.run_id == run.run_id]
    assert [e.to_dict()["kind"] for e in stamped] == ["agent_run", "retrieval", "tool_call", "tool_call", "agent_run"]
    assert sink.all_entries()[0].run_id is None
    summary = run_summary(sink, run.run_id)
    assert summary.status == "completed" and summary.denials == 1 and summary.task == "lookup"


def test_runs_nest_and_the_timeline_includes_sub_runs():
    sink = InMemoryAuditSink()
    _, tools = _guards(sink)
    with agent_run(sink, task="orchestrate") as outer:
        tools.call(Principal("planner"), {})
        with agent_run(sink, task="research") as inner:
            tools.call(Principal("researcher"), {})
    assert inner.parent_run_id == outer.run_id
    assert {e.run_id for e in run_timeline(sink, outer.run_id)} == {outer.run_id, inner.run_id}
    assert {e.run_id for e in run_timeline(sink, inner.run_id)} == {inner.run_id}
    assert run_summary(sink, outer.run_id).sub_runs == 1


def test_failed_and_cancelled_runs_record_status_and_error_type_only():
    sink = InMemoryAuditSink()
    with pytest.raises(ValueError):
        with agent_run(sink) as failed:
            raise ValueError("customer 881 secret")
    end = [e for e in sink.all_entries() if isinstance(e, RunEntry) and e.phase == "end"][0]
    assert end.status == "failed" and end.error == "ValueError" and "881" not in json.dumps(end.to_dict())
    assert failed.status == "failed"

    async def cancelled():
        async with agent_run(sink):
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(cancelled())
    assert sink.tail(1)[0].status == "cancelled"


def test_concurrent_async_runs_do_not_bleed_into_each_other():
    sink = InMemoryAuditSink()
    _, tools = _guards(sink)

    async def one(name):
        async with agent_run(sink, task=name) as run:
            for _ in range(5):
                await asyncio.sleep(0)
                tools.call(Principal(name), {})
            return run.run_id

    async def main():
        return await asyncio.gather(one("a"), one("b"), one("c"))

    run_ids = asyncio.run(main())
    for name, run_id in zip("abc", run_ids):
        calls = [e for e in run_timeline(sink, run_id) if e.to_dict()["kind"] == "tool_call"]
        assert len(calls) == 5 and {e.principal_id for e in calls} == {name}


def test_decoding_old_entries_never_picks_up_the_current_run(tmp_path):
    path = tmp_path / "a.jsonl"
    path.write_text(json.dumps({"kind": "tool_call", "timestamp": 1.0, "principal_id": "p", "tool_name": "t",
                                "arguments": {}, "risk_tier": "low", "outcome": "allow", "reason": "r"}) + "\n")
    with agent_run():
        entry = JSONLAuditSink(path).all_entries()[0]
    assert entry.run_id is None and entry.parent_run_id is None


def test_run_ids_round_trip_through_jsonl_and_sqlite(tmp_path):
    from marshal_ai import SQLiteAuditSink

    for sink in (JSONLAuditSink(tmp_path / "a.jsonl"), SQLiteAuditSink(tmp_path / "a.db")):
        _, tools = _guards(sink)
        with agent_run(sink, run_id="req-123"):
            tools.call(Principal("p"), {})
        assert [e.run_id for e in sink.all_entries()] == ["req-123"] * 3


def test_run_id_is_exported_to_opentelemetry():
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from marshal_ai.otel import OpenTelemetryAuditSink

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    sink = OpenTelemetryAuditSink(tracer=provider.get_tracer("t"))
    _, tools = _guards(sink)
    with agent_run(run_id="req-9"):
        tools.call(Principal("p"), {})
    assert exporter.get_finished_spans()[0].attributes["marshal.run_id"] == "req-9"
