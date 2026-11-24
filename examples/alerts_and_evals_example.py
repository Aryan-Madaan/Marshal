"""From "something is wrong" to "the right person knows" — and from
"the agent finished" to "the agent's answer was any good".

  1. A reply-drafting agent runs; every draft is checked by two quality
     scorers. Verdicts land in the audit trail — the drafts never do.
  2. A prompt change ships and drafts start inventing facts. `assess()`
     rates the *task* degraded, cost per *passing* run goes up, and
     `AlertManager` sends one signed webhook — not one per check.
  3. On-call acknowledges from the CLI (audited); reminders stop.
  4. It gets worse. Escalation clears the acknowledgement and pages again:
     an ack covers what the person saw, not what it turned into.
  5. The rollback lands, the alert resolves, and the receiver hears that too.

Run: python examples/alerts_and_evals_example.py
"""

import json
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from marshal_ai import (
    AlertManager,
    AllowlistModelPolicy,
    ModelCandidate,
    ModelGuard,
    Principal,
    SQLiteAuditSink,
    WebhookNotifier,
    agent_run,
    alerts_from,
    assess,
    evaluate,
    run_costs,
    verify_webhook_signature,
)

SECRET = b"demo-secret-from-your-vault-0123"
workdir = Path(tempfile.mkdtemp())
sink = SQLiteAuditSink(workdir / "audit.db")
received = []


class Receiver(BaseHTTPRequestHandler):  # stands in for your incident tool
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        valid = verify_webhook_signature(SECRET, body, self.headers["Marshal-Signature"])
        received.append((json.loads(body), valid))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


server = HTTPServer(("127.0.0.1", 0), Receiver)
threading.Thread(target=server.serve_forever, daemon=True).start()
webhook = WebhookNotifier(f"http://127.0.0.1:{server.server_address[1]}/marshal", secret=SECRET, allow_http=True)
manager = AlertManager(workdir / "alerts.db", notifiers=[webhook], audit_sink=sink, renotify_seconds=1800)
models = ModelGuard(policy=AllowlistModelPolicy({"draft": [ModelCandidate("gpt-fast")]}), audit_sink=sink)
SOURCES = {"refund approved", "ships Monday"}


def grounded(draft: str, ctx) -> bool:  # stand-in for your real scorer: rules, or a model-based judge
    return all(claim in ctx["sources"] for claim in draft.split("; "))


def polite(draft: str, ctx) -> float:
    return 0.0 if draft.isupper() else 1.0


def draft_reply(invents_facts: bool) -> None:
    draft = "refund approved; ships tomorrow" if invents_facts else "refund approved; ships Monday"
    with agent_run(sink, task="draft-reply", principal_id="drafter"):
        models.resolve(Principal("drafter"), "draft")
        models.record_usage(Principal("drafter"), "gpt-fast", 2000, 400)
        evaluate(sink, {"grounded": grounded, "polite": polite}, draft, context={"sources": SOURCES})


def check(label: str, since: float) -> None:
    window = time.time() - since + 0.001
    task = next(r for r in assess(sink, window_seconds=window) if r.subject_kind == "task")
    result = manager.process(alerts_from(sink, window_seconds=window, signals=False))
    events = [f"{e} {k}" for e in ("opened", "escalated", "reminded", "resolved") for k in getattr(result, e)]
    print(f"{label}: task is {task.status} ({task.failures}/{task.calls} checks failed)"
          f" -> {', '.join(events) or 'no notification'}")


start = time.time()
print("=== 1. a normal hour ===")
for _ in range(10):
    draft_reply(invents_facts=False)
check("baseline", start)

print("\n=== 2. a prompt change ships ===")
for i in range(10):
    draft_reply(invents_facts=i % 2 == 0)
check("first check", start)
check("a minute later", start)  # still true, inside renotify_seconds: deduplicated
cost = run_costs(sink, {"gpt-fast": (0.5, 1.5)}).by_task[0]
print(f"{cost.passing_runs}/{cost.evaluated_runs} runs passed; ${cost.cost_per_passing_run_usd:.4f} per passing run "
      f"vs ${cost.cost_per_successful_run_usd:.4f} per merely *completed* one")
print(f"webhooks: {len(received)}, signatures valid: {all(v for _, v in received)}, "
      f"last: {received[-1][0]['event']} / {received[-1][0]['severity']}")

print("\n=== 3. on-call acknowledges from the CLI ===")
out = subprocess.run([sys.executable, "-m", "marshal_ai.cli", "alerts", "ack", str(workdir / "alerts.db"),
                      "health:task:draft-reply", "--as", "oncall@ourcompany.example",
                      "--reason", "rolling back prompt v42", "--audit", str(workdir / "audit.db")],
                     check=True, capture_output=True, text=True)
print("$ marshal_ai.cli alerts ack ... ->", out.stdout.strip())

print("\n=== 4. before the rollback lands, it gets worse ===")
for _ in range(20):
    draft_reply(invents_facts=True)
check("worse", start)
print(f"webhooks: {len(received)}, last: {received[-1][0]['event']} / {received[-1][0]['severity']}")

print("\n=== 5. the rollback lands ===")
fixed = time.time()
for _ in range(10):
    draft_reply(invents_facts=False)
check("after rollback", fixed)
print(f"webhooks: {len(received)}, last: {received[-1][0]['event']}")
print("alert trail:", [(e.action, e.principal_id) for e in sink.all_entries() if e.to_dict()["kind"] == "alert"])
server.shutdown()
