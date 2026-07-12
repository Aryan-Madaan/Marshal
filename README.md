# Marshal

Governance for AI systems: permission-aware retrieval, tool-call approval,
model routing with budgets, and one audit trail across all three.

`pip install`/`import` name is `marshal_ai` (not `marshal` — that name is a
reserved Python standard-library module, see below).

See [`DESIGN_DECISIONS.md`](./DESIGN_DECISIONS.md) for the architecture,
the SOLID reasoning behind it, and every real tradeoff considered along
the way.

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

Plus **one-line, framework-agnostic model governance** (`marshal_ai.integrations`)
— patches the OpenAI/Anthropic SDK clients directly, so LangChain, LangGraph,
CrewAI, AutoGen, Google ADK, or a raw script all get governed without
touching that framework's own code. See below.

Plus **deterministic sensitive-data detection** (`marshal_ai.sensitive`) —
a different question from the three guards above: not "is this allowed"
but "does the literal content contain a secret or PII, regardless of who's
allowed to see it." Plugs into all three surfaces, and into the SDK-patch
layer to scan real outbound prompts and inbound completions. See below.

See [`ideas.md`](./ideas.md) for what's next: real vector-store adapters,
and a litellm proxy hook for deployments already running the LiteLLM proxy.

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

## Quickstart: one-line governance for a framework you didn't write

```python
import marshal_ai.integrations as marshal_integrations
from marshal_ai import AllowlistModelPolicy, ModelCandidate, ModelGuard, Principal

guard = ModelGuard(policy=AllowlistModelPolicy({"gpt-4o": [ModelCandidate("gpt-4o-mini")]}))
marshal_integrations.enable(guard, Principal(id="service-account"))

# anything below this line — including code inside LangChain, LangGraph,
# CrewAI, AutoGen, or ADK — is now governed, with zero changes to that code:
import openai
openai.OpenAI().chat.completions.create(model="gpt-4o", messages=[...])
# ^ actually calls "gpt-4o-mini"; usage auto-reported to `guard` from the
# real response; a request for an unrouted model raises ModelCallDenied
# *before* any network call happens.
```

Run `python examples/framework_integration_example.py` for a fuller
walkthrough (denial path only, so it runs with no API key).

Patches the OpenAI and Anthropic SDK client classes (sync + async) by
exact method reference, resolved when `enable()` runs — not the
framework's code, which is what makes this work underneath any framework
built on either SDK without per-framework adapters. `disable_all()`
restores the originals. The known cost, stated plainly: this breaks
silently on a breaking SDK change to those exact classes/methods (it'll
raise clearly at `enable()` time, not patch nothing silently — but it will
need updating when that happens). This surface only covers *model*
routing/budget, deliberately — tool-call execution happens inside each
framework's own dispatch code at a different layer with no equivalent
single choke point; use `ToolGuard` directly around your tool functions
for that surface. See `ideas.md` for the reasoning.

## Quickstart: sensitive-data detection

```python
from marshal_ai import AttributePolicy, Document, Principal, RetrievalGuard, SensitiveDataPolicy

# Wraps your real policy — the ACL decision (who's allowed to see this
# document) is unchanged; content that looks like a secret/PII gets
# redacted regardless of who's allowed to see it.
policy = SensitiveDataPolicy(base=AttributePolicy(default="allow"))
guard = RetrievalGuard(retriever=my_retriever, policy=policy)

results = guard.retrieve("support tickets", principal=Principal(id="alice"), k=5)
# a doc's content containing "contact bob@example.com" comes back as
# "contact [REDACTED:EMAIL]" — the redaction, and a finding count (never
# the matched text), both land in the audit trail
```

The same scanner also wraps tool calls (`SensitiveDataToolPolicy` — a
hardcoded credential in the arguments *blocks the call outright*,
regardless of risk tier) and the SDK-patch layer (`marshal_integrations.
enable(guard, principal, scanner=...)` — a credential in an outbound
prompt is blocked *before any network call*; a completion that leaks one
is flagged in the audit trail, since by then the call already happened).
Run `python examples/sensitive_data_example.py` for all three in one
shared audit trail.

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

### Sensitive-data detection (`marshal_ai.sensitive`)

- **`SensitiveDataScanner`** — runs a list of `Detector`s (regex, no LLM
  call — see the module docstring for why) over text. `scan()` reports
  what fired; `redact()` also replaces matches in place. Both report
  findings as `Finding(detector, count)` — never the matched text, so the
  audit trail can't become a second copy of the secret it's meant to
  catch. Defaults cover common credentials (AWS keys, `sk-`/`ghp_`-style
  API keys, JWTs, PEM private key blocks) and common PII (email, US
  phone/SSN, card numbers) — tune `detectors=` per deployment; regexes are
  heuristics, not ground truth.
- **`SensitiveDataPolicy`** — wraps a `Policy`, redacts document content
  after the ACL decision (content-scanning can't block at `evaluate()`
  time; it only ever sees metadata, not content).
- **`SensitiveDataToolPolicy`** — wraps a `ToolPolicy`; a *blocking*
  detector (default: credentials, not PII — see `DEFAULT_BLOCK_DETECTORS`)
  overrides the base decision to deny outright, since tool arguments are
  available at decision time. Non-blocking findings are redacted, same as
  `RedactingToolPolicy`.
- Both take an `audit_sink=` — pass the *same* sink you give the guard so
  findings land in the shared trail (there's no automatic wiring between
  a policy and the guard wrapping it, the same way `RedactingPolicy`
  doesn't audit anything itself either).
- The SDK-patch layer (`marshal_ai.integrations.enable(..., scanner=...)`)
  is the only place that sees real prompt/completion *text* — see its
  Quickstart above.

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

## Seeing what happened: the dashboard question

Marshal doesn't ship a web dashboard, deliberately. Two answers instead,
for two different needs:

**Right now, zero infra** — a terminal viewer over a `JSONLAuditSink` file:

```bash
python -m marshal_ai.cli tail audit.jsonl              # last 20 entries
python -m marshal_ai.cli tail audit.jsonl --denied-only
python -m marshal_ai.cli tail audit.jsonl --follow      # live-tail
```

**In production, plug into what you already run** — `OpenTelemetryAuditSink`
exports every audit entry as an OTel span, so it shows up in Grafana,
Honeycomb, Datadog, or a local Jaeger instead of a second, worse dashboard
Marshal would otherwise have to build and maintain forever:

```python
from opentelemetry import trace
from marshal_ai.otel import OpenTelemetryAuditSink  # needs: pip install "marshal-ai[opentelemetry]"

otel_sink = OpenTelemetryAuditSink()
RetrievalGuard(retriever=my_retriever, audit_sink=otel_sink)
```

Model-call spans use the official OpenTelemetry GenAI semantic conventions
(`gen_ai.request.model`, `gen_ai.usage.input_tokens`/`output_tokens`) where
they're stable enough to rely on; tool-call and retrieval spans use a
`marshal.*` namespace, since the GenAI semconv's tool/agent conventions are
still in Development status as of 2026 — see `marshal_ai/otel.py`'s
docstring for the reasoning. `OpenTelemetryAuditSink` is write-only
(`all_entries`/`tail`/`query` raise `NotImplementedError` — spans live in
your tracing backend, not in this process).

## Status

v0.6 — all three governance surfaces (retrieval, tool calls, model
routing/budgets), one shared audit trail, OpenTelemetry export, a local
CLI viewer, one-line model governance for any OpenAI/Anthropic-based
framework via SDK patching, and deterministic sensitive-data detection
across every surface. Real Chroma integration for `RetrievalGuard` is
still in progress — see [`ideas.md`](./ideas.md) for that and what's next
beyond it (a litellm proxy hook for deployments already running the
LiteLLM proxy; framework-specific tool-call adapters).

## License

MIT
