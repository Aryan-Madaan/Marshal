"""When tools break: outcome tracking, a tool circuit breaker, and the
failed-call runaway trigger.

`ToolGuard` reports what happened to every call it lets through — success
or failure, latency, and the exception *type* (never its message, which
can echo argument values). Two policies use that:

  - `ToolCircuitBreakerPolicy` — a *tool* that keeps failing (a downstream
    outage) stops being called by anyone until the failures age out.
  - `RunawayAgentPolicy(failed_call_threshold=...)` — a *principal* whose
    calls keep failing (an agent retrying malformed arguments in a loop)
    is stopped until a human calls `reset()`.

A governance denial never counts as a failure: a call that never ran
didn't fail.

Run: python examples/tool_reliability_example.py
"""

import time

from marshal_ai import (
    InMemoryAuditSink,
    Principal,
    RiskTierPolicy,
    RunawayAgentPolicy,
    ToolCallDenied,
    ToolCircuitBreakerPolicy,
    ToolGuard,
)

sink = InMemoryAuditSink()
# Protects callers from a broken *tool*.
breaker = ToolCircuitBreakerPolicy(RiskTierPolicy({"low": "allow"}), failure_threshold=3, window_seconds=2)
# Protects the system from a broken *agent*.
runaway = RunawayAgentPolicy(
    RiskTierPolicy({"low": "allow"}), identical_call_threshold=50, window_seconds=60, failed_call_threshold=3
)

backend = {"up": False, "calls": 0}


def search_orders(query: str) -> str:
    backend["calls"] += 1
    if not backend["up"]:
        raise ConnectionError(f"orders-api unreachable (query={query!r})")
    return f"3 orders match {query!r}"


def parse_invoice(blob: str) -> str:
    raise ValueError("malformed invoice")


search = ToolGuard(tool=search_orders, policy=breaker, audit_sink=sink, tool_name="search_orders", audit_outcomes=True)
parse = ToolGuard(tool=parse_invoice, policy=runaway, audit_sink=sink, tool_name="parse_invoice", audit_outcomes=True)
alice, bob, buggy = Principal("agent-alice"), Principal("agent-bob"), Principal("agent-buggy")

print("=== 1. the orders API goes down: three failures open the breaker ===")
for who in (alice, bob, alice):
    try:
        search.call(who, {"query": "late shipments"})
    except ConnectionError as e:
        print(f"{who.id}: failed ({type(e).__name__})")
try:
    search.call(bob, {"query": "late shipments"})
except ToolCallDenied as e:
    print(f"{bob.id}: refused — {e.reason}")
print("calls that actually reached the API:", backend["calls"])

print("\n=== 2. it recovers; once failures age out, calls flow again ===")
backend["up"] = True
time.sleep(2.1)
print(f"{alice.id}:", search.call(alice, {"query": "late shipments"}))

print("\n=== 3. a buggy agent keeps failing with different arguments ===")
for i in range(5):
    try:
        parse.call(buggy, {"blob": f"invoice-{i}"})
    except ValueError:
        print(f"attempt {i}: failed")
    except ToolCallDenied as e:
        print(f"attempt {i}: stopped — {e.reason[:60]}…")
print("tripped:", runaway.is_tripped("agent-buggy"), "| another agent is unaffected:", not runaway.is_tripped("agent-alice"))
runaway.reset("agent-buggy")  # the explicit human decision
print("after a human reset, tripped:", runaway.is_tripped("agent-buggy"))

print("\n=== outcomes in the audit trail (type only, never the message) ===")
for entry in sink.all_entries():
    if entry.to_dict()["kind"] == "tool_outcome":
        status = "ok" if entry.success else f"failed: {entry.error}"
        print(f"  {entry.principal_id} {entry.tool_name}: {status} in {entry.latency_ms:.1f} ms")
