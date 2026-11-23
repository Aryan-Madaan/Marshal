import time

import pytest

from marshal_ai import InMemoryAuditSink, Principal, RiskTierPolicy, ToolCallDenied, ToolCircuitBreakerPolicy, ToolGuard
from marshal_ai.health import HealthThresholds, assess, record_heartbeat, render_health_markdown


def _run(sink, name, results, principal="agent-1", policy=None):
    it = iter(results)

    def tool(**kw):
        if not next(it):
            raise ConnectionError("down")
        return "ok"

    guard = ToolGuard(tool=tool, policy=policy, audit_sink=sink, tool_name=name, audit_outcomes=True)
    for _ in results:
        try:
            guard.call(Principal(principal), {})
        except (ConnectionError, ToolCallDenied):
            pass


def _status(reports, kind, name):
    return next(r for r in reports if r.subject_kind == kind and r.subject == name)


def test_statuses_follow_error_rates():
    sink = InMemoryAuditSink()
    _run(sink, "fine", [True] * 20)
    _run(sink, "wobbly", [True] * 8 + [False] * 2)
    _run(sink, "broken", [False] * 6 + [True] * 4)
    reports = assess(sink)
    assert _status(reports, "tool", "fine").status == "healthy"
    assert _status(reports, "tool", "wobbly").status == "degraded"
    assert _status(reports, "tool", "broken").status == "failing"
    assert reports[0].status == "failing"  # worst first
    assert "| failing | tool | broken |" in render_health_markdown(reports)


def test_breaker_trips_mark_a_tool_failing():
    sink = InMemoryAuditSink()
    breaker = ToolCircuitBreakerPolicy(RiskTierPolicy({"low": "allow"}), failure_threshold=2, window_seconds=60)
    _run(sink, "flaky", [False, False, True, True], policy=breaker)
    assert _status(assess(sink), "tool", "flaky").status == "failing"


def test_idle_unknown_and_not_instrumented_are_distinct():
    sink = InMemoryAuditSink()
    now = time.time()
    record_heartbeat(sink, "quiet-agent")  # alive, no traffic
    record_heartbeat(sink, "dead-agent")
    ToolGuard(tool=lambda: 1, audit_sink=sink, tool_name="uninstrumented").call(Principal("x"), {})
    reports = assess(sink, now=now + 1000, thresholds=HealthThresholds(heartbeat_stale_seconds=900))
    assert _status(reports, "agent", "dead-agent").status == "unknown"
    reports = assess(sink, now=now + 10)
    assert _status(reports, "agent", "quiet-agent").status == "idle"
    assert _status(reports, "tool", "uninstrumented").status == "not_instrumented"


def test_failed_heartbeat_probe_is_failing():
    sink = InMemoryAuditSink()
    record_heartbeat(sink, "probe-target", ok=False)
    assert _status(assess(sink), "agent", "probe-target").status == "failing"


def test_agent_with_mostly_denied_calls_is_degraded():
    sink = InMemoryAuditSink()
    guard = ToolGuard(tool=lambda: 1, policy=RiskTierPolicy({"high": "deny", "low": "allow"}), audit_sink=sink,
                      tool_name="t", audit_outcomes=True)
    for i in range(10):
        try:
            guard.call(Principal("pushy-agent"), {}, risk_tier="high" if i < 8 else "low")
        except ToolCallDenied:
            pass
    report = _status(assess(sink), "agent", "pushy-agent")
    assert report.status == "degraded" and any("denied" in r for r in report.reasons)


def test_latency_threshold_and_low_confidence():
    sink = InMemoryAuditSink()
    from marshal_ai.tools import ToolOutcomeEntry

    for latency in [50, 60, 70, 80, 900]:
        sink.write(ToolOutcomeEntry(time.time(), "a", "slow", True, latency_ms=latency))
    sink.write(ToolOutcomeEntry(time.time(), "a", "rare", False))
    reports = assess(sink, thresholds=HealthThresholds(warn_p95_latency_ms=500))
    assert _status(reports, "tool", "slow").status == "degraded"
    rare = _status(reports, "tool", "rare")
    assert rare.status == "healthy" and "low confidence" in rare.reasons[0]  # 1 failure isn't a verdict
