# Marshal

Governance for AI systems: permission-aware retrieval, tool-call approval,
model routing with budgets, and one audit trail across all three.

`pip install`/`import` name is `marshal_ai` (not `marshal` — that name is a
reserved Python standard-library module, see below).

## Why

Most AI-system tooling treats governance as an exercise left to the reader.
"Who's allowed to see this document," "should this agent be allowed to call
this tool," "which model is it even allowed to run on, and what's it
costing" — all of that gets bolted on ad hoc, differently in every project,
usually without a real audit trail. That's exactly the part that matters
once more than one person or agent is using the same system.

Marshal is deliberately narrow. It does not do retrieval, embeddings, agent
orchestration, or make LLM calls itself. It sits between your system and its
most consequential actions and answers one question consistently for each:
*is this allowed, and who gets to know either way.*

Three governance surfaces, one shared audit trail:

- **`RetrievalGuard`** — wraps any retriever with document/field-level
  access control.
- **`ToolGuard`** — wraps any callable tool with risk-tiered
  allow/deny/require-approval and argument redaction.
- **`ModelGuard`** — resolves a logical model name to a real one per
  principal, with governed fallback chains and per-principal budget
  enforcement. Doesn't make the call for you — resolve, call it yourself,
  report usage back.

See [`ideas.md`](./ideas.md) for what's next: one-line framework-agnostic
integration (intercepting at the litellm/SDK layer instead of a
per-framework adapter), and real vector-store adapters.

## Install

```bash
pip install -e .
```

(Not yet published to PyPI — clone and install locally for now.)

## Quickstart: retrieval governance

```python
from marshal_ai import AttributePolicy, Document, Principal, RetrievalGuard

def my_retriever(query: str, k: int) -> list[Document]:
    # Call your real vector store / search API here, and wrap each result
    # into a Document. Marshal doesn't care what's underneath.
    return [
        Document(id="policy-1", content="General leave policy...", metadata={}),
        Document(id="salary-1", content="Q3 comp review...", metadata={"acl": ["role:hr"]}),
    ]

guard = RetrievalGuard(retriever=my_retriever, policy=AttributePolicy(default="allow"))

engineer = Principal(id="deepa", attributes={"role:engineering"})
results = guard.retrieve("compensation", principal=engineer, k=5)
# results excludes salary-1 — deepa doesn't have role:hr

for entry in guard.audit_log.tail(5):
    print(entry.principal_id, entry.allowed_ids, entry.denied_ids)
```

Run `python examples/basic_example.py` for a fuller walkthrough.

## Quickstart: tool-call governance

```python
from marshal_ai import ArgumentRedaction, Principal, RedactingToolPolicy, RiskTierPolicy, ToolGuard

def update_employee_record(employee_id: str, salary_band: str) -> str: ...

policy = RedactingToolPolicy(
    base=RiskTierPolicy({"low": "allow", "medium": "require_approval", "high": "deny"}),
    rules=[ArgumentRedaction(name="salary_band", requires_attribute="role:hr")],
)
guard = ToolGuard(tool=update_employee_record, policy=policy, tool_name="update_employee_record")

hr = Principal(id="rhea", attributes={"role:hr"})
guard.call(hr, {"employee_id": "E123", "salary_band": "L6"}, risk_tier="medium")
# prompts for approval on stdin (default CLIApprovalHandler); audit log shows
# the real salary_band for rhea (role:hr), [REDACTED] for anyone else
```

Run `python examples/tool_governance_example.py` for a fuller walkthrough.

## Quickstart: model governance

```python
from marshal_ai import AllowlistModelPolicy, BudgetPolicy, ModelCandidate, ModelGuard, Principal

routes = {
    "default-chat-model": [
        ModelCandidate("gpt-fast"),
        ModelCandidate("eu-hosted-model", requires_attribute="region:eu"),
    ]
}
policy = BudgetPolicy(AllowlistModelPolicy(routes), pricing={"gpt-fast": (0.5, 1.5)}, limit_usd=5.0)
guard = ModelGuard(policy=policy)

alice = Principal(id="alice")
model = guard.resolve(alice, "default-chat-model")  # "gpt-fast"
# ... call `model` with whatever LLM client you already use, get real usage back ...
guard.record_usage(alice, model, prompt_tokens=800, completion_tokens=200)

# if the call fails/times out, governed fallbacks — already filtered to
# what alice qualifies for — are right here, no re-checking needed:
for candidate in guard.fallback_chain(alice, "default-chat-model"):
    ...  # retry with candidate
```

Run `python examples/model_governance_example.py` for a fuller walkthrough.

## How it works

### Retrieval (`RetrievalGuard`)

- **`Document`** — the minimal shape Marshal needs: `id`, `content`,
  `metadata`. Zero framework dependencies.
- **`Principal`** — whoever is asking. Carries a flat set of `attributes`
  (roles, departments, clearance levels — shared across all three surfaces).
- **`Policy`** — `AttributePolicy` (list-valued `acl` metadata, post-filter
  only), `GroupPolicy` (scalar `group` metadata, can express itself as a
  native pushdown filter for retrievers that accept a `filter` keyword),
  `AllowAll` (audit only, the default), `RedactingPolicy` (strips
  content/metadata fields per principal).
- Async: `aretrieve()` alongside `retrieve()`.

### Tool calls (`ToolGuard`)

- **`ToolPolicy`** — `RiskTierPolicy` (tier → outcome lookup table, the
  default real policy), `AllowAllTools` (audit only, the default),
  `RedactingToolPolicy` (redacts argument values in the audit trail/
  approval prompt — the wrapped tool always gets the real values).
- **`ApprovalHandler`** — `CLIApprovalHandler` (blocks on a stdin prompt —
  the v0.1 "actually runnable today" path) and `AutoApprove` (tests/dev
  only). Implement your own for a Slack button or a web queue.
- A denied or declined call raises `ToolCallDenied` — never a silent no-op.

### Model calls (`ModelGuard`)

- **`ModelPolicy`** — `AllowlistModelPolicy` (each logical name maps to an
  ordered candidate list; `resolve` picks the first the principal qualifies
  for, `fallback_chain` returns the rest — already filtered, so a fallback
  is never a backdoor around governance), `AllowAllModels` (passes the
  logical name through unchanged, the default), `BudgetPolicy` (wraps
  another policy, denies once a principal's tracked spend hits a limit —
  spend comes from `record_usage`, reported after your real call
  completes; Marshal never estimates cost ahead of time).
- A denied resolution raises `ModelCallDenied`.

### One audit trail (`AuditSink`)

All three guards write to the same kind of `AuditSink` — share one
instance and `sink.query(...)` covers every surface at once:

```python
shared = InMemoryAuditSink()  # or JSONLAuditSink("audit.jsonl")
RetrievalGuard(retriever=my_retriever, audit_sink=shared)
ToolGuard(tool=my_tool, audit_sink=shared)
ModelGuard(policy=my_model_policy, audit_sink=shared)
# shared.query(principal_id="alice") now returns her retrievals, tool
# calls, and model resolutions, in one list, ordered by time.
```

`JSONLAuditSink` persists mixed event types correctly — each line carries
a `kind` discriminator so reading the log back reconstructs the right
dataclass. `query()` filters by `principal_id`, `since`/`until` (Unix
timestamps), and `denied_only`. Implement `AuditSink` yourself to plug in
Postgres, a SIEM, Kafka.

This is meant to scale down as much as up: a solo dev gets a working audit
trail with zero configuration on any surface, and can add real enforcement
incrementally whenever ready. Enterprise use swaps in custom
`Policy`/`ToolPolicy`/`ModelPolicy`/`AuditSink` implementations backed by
whatever's already running.

## Status

v0.3 — all three governance surfaces (retrieval, tool calls, model
routing/budgets), one shared audit trail. Real Chroma integration for
`RetrievalGuard` is in progress. See [`ideas.md`](./ideas.md) for what's
next, especially the one-line, framework-agnostic integration story
(litellm/SDK-level interception instead of per-framework adapters).

## License

MIT
