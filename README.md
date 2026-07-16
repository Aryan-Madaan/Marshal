# Marshal

Governance for AI systems: permission-aware retrieval, tool-call approval
with rate limiting and jurisdiction-aware risk tiering, model routing with
budgets, cross-border data-residency/retention control, and
reliability-aware circuit breaking, with one audit trail across all three.

**[See the landing page →](https://aryan-madaan.github.io/Marshal/)** — the
pitch, a live checkpoint demo, and the code, in two minutes.

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
  allow/deny/require-approval, argument redaction, per-principal rate
  limiting, runaway-loop detection, and jurisdiction-aware oversight.
- **`ModelGuard`** — resolves a logical model name to a real one per
  principal, with governed fallback chains and per-principal budget
  enforcement. Doesn't make the call for you — resolve, call it yourself,
  report usage back.

Plus **one-line, framework-agnostic model governance** (`marshal_ai.integrations`)
— patches the OpenAI, Anthropic, and Google GenAI SDK clients directly, so
LangChain, LangGraph, CrewAI, AutoGen, Google ADK, or a raw script all get
governed without touching that framework's own code. The Google GenAI
patch specifically is what governs ADK's default `LlmAgent` path — ADK
calls Gemini through `google-genai` directly, not through LiteLLM or the
openai/anthropic clients, verified against ADK's own source rather than
assumed. See below.

Plus **deterministic sensitive-data detection** (`marshal_ai.sensitive`) —
a different question from the three guards above: not "is this allowed"
but "does the literal content contain a secret or PII, regardless of who's
allowed to see it." Plugs into all three surfaces, and into the SDK-patch
layer to scan real outbound prompts and inbound completions. See below.

Plus **cross-border data governance** (`ResidencyPolicy`, `RetentionPolicy`)
— a model call to a foreign-hosted deployment is a cross-border transfer
of whatever data is in that prompt, and GDPR, India's DPDP Act, Thailand's
PDPA, and Singapore's PDPA each apply a genuinely different legal test to
that same act. `ResidencyPolicy` wraps any `ModelPolicy` and denies,
fail-closed, if the resolved deployment isn't a compliant destination
(and legal mechanism — adequacy, SCC, BCR) for the jurisdiction governing
that specific request; `RetentionPolicy` separately denies unless the
resolved deployment's actual retention terms meet a required ceiling
(zero-data-retention included) — two independent questions, "where" and
"how long," both read from request context rather than the calling
principal's identity, since whose law and whose contract terms apply are
properties of the data, not of who's asking. Note what this deliberately
doesn't cover: AI-specific regulatory classification (the EU AI Act's
risk-tiering and mandatory human oversight, distinct from data-transfer
law) — Marshal's existing `RiskTierPolicy`/`ToolGuard` and shared audit
trail already provide the underlying mechanism for that; making the risk
*tier itself* jurisdiction-aware is a real next step, tracked in
`ideas.md` rather than folded into this release. See below.

Plus **reliability tracking and circuit breaking** (`CircuitBreakerPolicy`,
`ModelGuard.record_outcome`) — every policy above decides from static
config plus the current request; nothing tracked whether a resolved
deployment's calls were actually *succeeding*. `record_outcome` (auto-
reported by `marshal_ai.integrations` from real SDK call attempts, success
or failure, with latency) closes that gap, and `CircuitBreakerPolicy`
acts on it — routing around a deployment that's recently been failing,
fail-closed if every candidate has tripped. See below.

Plus **shadow mode** (`mode="shadow"` on any guard) — computes and audits
the identical policy decision `mode="enforce"` would, but never acts on
it: nothing is filtered, redacted, denied, or held for approval, the real
call always goes through. The low-friction adoption path — wire Marshal
into a production system with zero risk of breaking anything, watch the
audit trail build up real signal about what your policies would actually
do, then flip to `mode="enforce"` once you trust it. See below.

Plus **real vector-store adapters** (`marshal_ai.adapters`) — `from_chroma_
collection`/`from_langchain_retriever` turn a real Chroma collection or
any LangChain `BaseRetriever` into exactly the `(query, k) -> list[Document]`
shape `RetrievalGuard` already expects, so governance, audit, and pushdown
filtering all run over genuine backend results, not a hand-rolled list.
See below.

Plus **MCP tool-call governance** (`marshal_ai.mcp.GovernedMCPSession`) —
MCP (Model Context Protocol) is now the shared tool-integration standard
most agent frameworks speak, and its own Enterprise-Managed Authorization
spec explicitly governs the *connection* only, not individual tool
actions at runtime. `GovernedMCPSession` wraps a real `mcp.ClientSession`
so every `call_tool()` goes through the same `ToolGuard`/`ToolPolicy`
machinery above before the request reaches the real MCP server — one
governed session covers an agent's tool use across every framework that
talks to that server over MCP. See below.

Plus **durable, tamper-evident audit storage and compliance reports**
(`marshal_ai.sinks.SQLiteAuditSink`, `marshal_ai.reports`) — `JSONLAuditSink`
survives a restart but an append-only text file can be edited or
truncated after the fact with no way to detect it. `SQLiteAuditSink`
closes that gap on stdlib `sqlite3` alone: indexed queries, and a hash
chain over every record so `verify()` can name the first record an edit,
deletion, or reorder broke. `marshal_ai.reports` derives an EU AI Act
Article 12-shaped activity record and a cross-border data-flow report
straight from that same audit trail. See below.

See [`ideas.md`](./ideas.md) for what's next: a litellm proxy hook for
deployments already running the LiteLLM proxy, and adapters for
Pinecone/pgvector/Weaviate.

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

## Quickstart: real vector stores (Chroma, LangChain)

`RetrievalGuard` wraps *any* `(query, k) -> list[Document]` callable. Two
adapters turn real vector stores into exactly that shape — governance,
audit, and pushdown all work over genuine backend results, not a toy list:

```python
import chromadb
from marshal_ai import AttributePolicy, Principal, RetrievalGuard
from marshal_ai.adapters import from_chroma_collection

collection = chromadb.EphemeralClient().create_collection("docs")
collection.add(
    ids=["policy-1", "salary-1"],
    documents=["General leave policy...", "Q3 comp review..."],
    metadatas=[{"note": "public"}, {"acl": ["role:hr"]}],
)

guard = RetrievalGuard(
    retriever=from_chroma_collection(collection),
    policy=AttributePolicy(default="allow"),
)
engineer = Principal(id="deepa", attributes={"role:engineering"})
results = guard.retrieve("compensation", principal=engineer, k=5)
# excludes salary-1 — real Chroma results, filtered by the same ACL policy
```

A `GroupPolicy` pushes its filter down into Chroma's native `where` clause
automatically (the adapter accepts `filter=`), so the store never even
returns documents the principal can't see — and `RetrievalGuard` still
re-checks every candidate afterward (defense in depth).

For LangChain, wrap any `BaseRetriever` (including
`VectorStore.as_retriever()`):

```python
from marshal_ai.adapters import from_langchain_retriever

guard = RetrievalGuard(
    retriever=from_langchain_retriever(my_vectorstore.as_retriever()),
    policy=AttributePolicy(default="allow"),
)
```

Needs the `chroma` / `langchain` extra respectively. Run
`python examples/chroma_example.py` for the full Chroma walkthrough
(offline, `EphemeralClient`, no API key).

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

## Quickstart: MCP tool-call governance

MCP (Model Context Protocol) is now the shared tool-integration standard
most agent frameworks speak. Its Enterprise-Managed Authorization spec
governs whether a client may *connect* to a server — it explicitly does
not govern individual tool actions at runtime, per call, per argument.
`GovernedMCPSession` is that missing per-action check, wrapping a real
`mcp.ClientSession` so every `call_tool()` goes through the same
`ToolGuard`/`ToolPolicy` machinery above *before* the request reaches the
real MCP server — one governed session covers an agent's tool use across
every framework that talks to that server over MCP, no per-framework
adapter needed.

```python
import asyncio
from marshal_ai import Principal, RiskTierPolicy
from marshal_ai.mcp import GovernedMCPSession

async def main():
    # `session` is a real, already-connected mcp.ClientSession.
    governed = GovernedMCPSession(
        session=session,
        principal=Principal(id="agent-1"),
        policy=RiskTierPolicy({"low": "allow", "high": "deny"}),
        risk_tiers={"delete_database": "high", "read_file": "low"},
    )
    result = await governed.call_tool("read_file", {"path": "README.md"})
    # a call to "delete_database" raises ToolCallDenied instead —
    # the real server never sees that request; audited either way.

asyncio.run(main())
```

Run `python examples/mcp_governance_example.py` for a fuller walkthrough
(allow, require-approval, deny, and a hardcoded-credential block, all
against a real in-process MCP server). Needs `pip install "marshal-ai[mcp]"`.

## Quickstart: agent reliability (rate limits, runaway loops, jurisdiction)

```python
from marshal_ai import (
    JurisdictionalRiskTierPolicy, Principal, RateLimitPolicy,
    RiskTierPolicy, RunawayAgentPolicy, ToolGuard,
)

# caps call frequency, period — regardless of what any individual call resolves to
rate_limited = RateLimitPolicy(RiskTierPolicy({"low": "allow"}), max_calls=100, window_seconds=60)

# catches a broken retry loop: same tool, same arguments, over and over —
# requires a human reset(), doesn't self-heal like CircuitBreakerPolicy does
loop_guard = RunawayAgentPolicy(rate_limited, identical_call_threshold=5, window_seconds=10)

# same action, more oversight in a specific jurisdiction — never less
policy = JurisdictionalRiskTierPolicy(
    loop_guard, overrides_by_jurisdiction={"EU": {"employment_decision": "require_approval"}}
)
guard = ToolGuard(tool=my_tool, policy=policy)

alice = Principal(id="alice")
guard.call(alice, {...}, risk_tier="employment_decision", context={"jurisdiction": "EU"})
# forced through approval in the EU even if the base policy would allow it outright;
# an identical call repeated 5+ times in 10s trips loop_guard until a human calls
# loop_guard.reset(alice.id); everything above still counts toward rate_limited's cap
```

Three independent questions, stacked: *how often* (rate limit), *is this a
loop* (runaway-agent — a repetition problem, not a frequency one: a busy
but healthy agent can be just as fast), and *does this jurisdiction demand
more oversight* (jurisdictional risk tiering — monotonic, can only add
approval requirements, never remove one the base policy already set).
Run `python examples/agent_reliability_example.py` for all three together.

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

## Quickstart: shadow mode

Every guard — `RetrievalGuard`, `ToolGuard`, `ModelGuard` — takes an
optional `mode: Literal["enforce", "shadow"] = "enforce"`. `"enforce"` is
today's behavior, unchanged. `"shadow"` computes and audits the exact
same policy decision but never acts on it: `RetrievalGuard` returns every
document unfiltered and unredacted; `ToolGuard` never raises
`ToolCallDenied` and never prompts for approval, always calling the
wrapped tool; `ModelGuard.resolve()` never raises, returning a sensible
model (the policy's own governed fallback, or the logical name itself)
even when the real policy would have denied. Every entry a shadow-mode
guard writes sets `shadow=True` and still records what *would* have
happened — which document IDs would have been denied, which argument
fields would have been redacted, whether a call would have required
approval — so `sink.query(denied_only=True)` and `python -m
marshal_ai.cli tail --denied-only` show you exactly what enforcement
would start blocking, before you turn it on.

```python
guard = ToolGuard(tool=my_tool, policy=my_policy, mode="shadow")
guard.call(alice, {...}, risk_tier="high")  # never raises, tool actually runs
for entry in guard.audit_log.tail(5):
    print(entry.shadow, entry.outcome)  # True, "deny" — what WOULD have happened
```

This is the adoption on-ramp: wire Marshal into a production system in
shadow mode with zero risk of breaking anything, watch the audit trail
build up real signal about what your policies would actually do, then
flip `mode="enforce"` once you trust it. Note the one place shadow status
matters downstream: `marshal_ai.reports` (below) reads the same `shadow`
flag to keep would-have-denied decisions out of a compliance document's
real enforcement figures — a shadow "deny" never actually blocked
anything, so it must never be counted as though it did.

Run `python examples/shadow_mode_example.py` for all three guards, side
by side, in both modes.

## Quickstart: cross-border data residency

```python
from marshal_ai import AllowlistModelPolicy, ModelCandidate, ModelGuard, Principal, ResidencyPolicy

routes = {
    "default-chat-model": [
        ModelCandidate("eu-deployment"),
        ModelCandidate("in-deployment"),
    ]
}
policy = ResidencyPolicy(
    AllowlistModelPolicy(routes),
    allowed_by_jurisdiction={
        "EU": {"eu-deployment": "adequacy_decision"},
        "IN": {"in-deployment": "dpdp_section_16"},
    },
)
guard = ModelGuard(policy=policy)

alice = Principal(id="alice")
# jurisdiction describes whose data this call carries, not who alice is —
# the same principal can make calls covering different jurisdictions
model = guard.resolve(alice, "default-chat-model", context={"jurisdiction": "EU"})
# "eu-deployment" — the one candidate actually permitted for EU-governed data,
# and the audit trail records *why*: "...via 'adequacy_decision'"

guard.resolve(alice, "default-chat-model", context={"jurisdiction": "TH"})
# raises ModelCallDenied — no candidate covers Thailand yet. Fails closed,
# not a silent fall-through to whatever deployment is first in the list.
```

`allowed_by_jurisdiction` maps jurisdiction → `{deployment: mechanism}` — the
mechanism string (an adequacy decision, a signed SCC, a BCR, a
certification) is what makes that pairing lawful, and it's what lands in
the audit trail's reason alongside the jurisdiction and the resolved
deployment, not just the allow/deny outcome. That mapping is a decision
only your data controller/fiduciary can make (GDPR calls the role
controller, India's DPDP Act calls it data fiduciary, Singapore's PDPA
calls the processor side a data intermediary — different labels, same
functional split) — Marshal enforces that decision deterministically at
every call, it doesn't make it for you, and it doesn't verify the
mechanism is still real; keep it in sync with your actual DPA. Pass an
optional `context={"controller": "..."}` too, purely for audit
traceability back to whichever entity's instructions this config encodes.
Run `python examples/residency_example.py` for a fuller walkthrough.

## Quickstart: data-retention control

```python
from marshal_ai import AllowlistModelPolicy, ModelCandidate, ModelGuard, Principal, RetentionPolicy

policy = RetentionPolicy(
    AllowlistModelPolicy({"m": [ModelCandidate("thirty-day-vendor"), ModelCandidate("zdr-vendor")]}),
    deployment_retention_days={"thirty-day-vendor": 30, "zdr-vendor": 0},
)
guard = ModelGuard(policy=policy)

alice = Principal(id="alice")
guard.resolve(alice, "m", context={"max_retention_days": 0})
# "zdr-vendor" — the only deployment with a zero-data-retention agreement;
# thirty-day-vendor is skipped even though it's the base policy's top pick
```

A different question from residency, and an independent one: a deployment
can sit in the right country and still retain prompts for weeks under a
vendor's default abuse-monitoring window — exactly what a
zero-data-retention (ZDR) requirement exists to rule out. Stack both when
both matter: `RetentionPolicy(ResidencyPolicy(base, ...), ...)`. Same
fail-closed discipline: `max_retention_days` missing from context denies
outright, same as a missing jurisdiction does for `ResidencyPolicy`.

**What neither policy attempts**, because Marshal has no way to verify it
at call time: confirming a vendor's downstream retention/deletion actually
matches what a mechanism promises, or enforcing sub-processor
authorization chains beyond how you name your deployments (name them by
their actual processing chain — e.g. `"claude-bedrock-eu-west-1"` vs.
`"claude-foundry-global"` — since two deployments of "the same model" can
differ exactly in the guarantee that matters here). See `ideas.md` for
what's explicitly out of scope and why.

## Quickstart: reliability tracking & circuit breaking

```python
from marshal_ai import AllowlistModelPolicy, CircuitBreakerPolicy, ModelCandidate, ModelGuard, Principal

routes = {"default-chat-model": [ModelCandidate("primary"), ModelCandidate("backup")]}
policy = CircuitBreakerPolicy(AllowlistModelPolicy(routes), failure_threshold=3, window_seconds=60)
guard = ModelGuard(policy=policy)

alice = Principal(id="alice")
model = guard.resolve(alice, "default-chat-model")  # "primary"

# ... make your real call with `model`. If it raises, marshal_ai.integrations
# reports this automatically; calling it by hand looks like:
guard.record_outcome(alice, model, success=False, latency_ms=4200.0, error="timeout")
# after 3 such failures within 60s, "primary" is skipped automatically:
guard.resolve(alice, "default-chat-model")  # -> "backup", audited as to why
```

None of Marshal's other policies know whether a resolved deployment is
*actually working* — `ResidencyPolicy`/`RetentionPolicy` are static legal
config, `AllowlistModelPolicy`'s ordering is fixed. `CircuitBreakerPolicy`
is the first policy besides `BudgetPolicy` whose decision depends on
accumulated runtime history, not just the current request: it trips a
specific deployment once it has `failure_threshold`+ recorded failures in
the trailing `window_seconds`, promotes the next already-qualifying
candidate the same way a jurisdiction or retention mismatch does, and
fails closed if every candidate is currently tripped. It's deliberately
not a textbook open/half-open/closed state machine — a trailing time
window self-heals on its own once the window passes the last failure, no
separate recovery/probe logic needed.

`marshal_integrations.enable(guard, principal)` (below) calls
`record_outcome` for you automatically — timing every real call and
classifying a real failure into a short category (`"timeout"`,
`"rate_limited"`, `"server_error"`, `"connection_error"`) from the actual
SDK exception, then **re-raising it unchanged**. Time-to-first-token
isn't covered yet — that needs wrapping a streaming response's own
iterator, tracked in `ideas.md` as a separate follow-up, not folded in
here. Run `python examples/circuit_breaker_example.py` for a fuller
walkthrough.

## Quickstart: one-line governance for a framework you didn't write

```python
import marshal_ai.integrations as marshal_integrations
from marshal_ai import AllowlistModelPolicy, ModelCandidate, ModelGuard, Principal

guard = ModelGuard(policy=AllowlistModelPolicy({"gpt-4o": [ModelCandidate("gpt-4o-mini")]}))
marshal_integrations.enable(guard, Principal(id="service-account"))

# anything below this line — including code inside LangChain, LangGraph,
# CrewAI, AutoGen, or an ADK LlmAgent — is now governed, with zero changes
# to that code:
import openai
openai.OpenAI().chat.completions.create(model="gpt-4o", messages=[...])
# ^ actually calls "gpt-4o-mini"; usage/latency/success auto-reported to
# `guard` from the real response; a request for an unrouted model raises
# ModelCallDenied *before* any network call happens.
```

Run `python examples/framework_integration_example.py` for the OpenAI/
Anthropic case, or `python examples/adk_gemini_example.py` specifically
for Google ADK's default model path (both denial-path-only, so they run
with no API key).

Patches the OpenAI, Anthropic, and Google GenAI SDK client classes
(sync + async) by exact method reference, resolved when `enable()` runs
— not the framework's code, which is what makes this work underneath any
framework built on any of the three without per-framework adapters. For
ADK specifically: `LlmAgent` calls Gemini through `google-genai`'s
`Models.generate_content` by default (not LiteLLM, not the openai/
anthropic clients — checked against ADK's own source, not assumed), and
`LiteLlm(model="openai/...")`/`LiteLlm(model="anthropic/...")` genuinely
does call through to the real `openai`/`anthropic` client classes
underneath (also checked, not assumed) — so `enable()` covers both of
ADK's model paths with the same one call. `disable_all()` restores the
originals. The known cost, stated plainly: this breaks silently on a
breaking SDK change to those exact classes/methods (it'll raise clearly
at `enable()` time, not patch nothing silently — but it will need
updating when that happens). This surface only covers *model*
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

## Quickstart: durable audit storage & compliance reports

Durable, tamper-evident SQLite audit storage and Article 12/26-shaped
compliance reports, generated from the same audit trail every guard
already writes to. `InMemoryAuditSink` doesn't survive a restart;
`JSONLAuditSink` does, but an append-only text file can be edited or
truncated after the fact with no way to detect it. `SQLiteAuditSink`
closes both gaps on stdlib `sqlite3` alone — no new dependency:

```python
from marshal_ai import SQLiteAuditSink, ToolGuard

sink = SQLiteAuditSink("audit.db")  # survives process restart: same file, new process, same trail
guard = ToolGuard(tool=my_tool, audit_sink=sink)
...
result = sink.verify()  # ChainVerificationResult(ok=True, checked=142) if nothing's been tampered with
```

`marshal_ai.reports` derives two compliance artifacts *purely* from
whatever `AuditSink` you hand it — `InMemoryAuditSink`, `JSONLAuditSink`,
`SQLiteAuditSink`, or your own:

```python
from marshal_ai import (
    article12_activity_record, cross_border_data_flow_report,
    render_activity_record_markdown, render_cross_border_markdown,
)

print(render_cross_border_markdown(cross_border_data_flow_report(sink)))
print(render_activity_record_markdown(article12_activity_record(sink, granularity="day")))
```

Both reports read every entry's `shadow` flag and keep shadow-mode
would-have-happened decisions in a clearly separate section — a shadow
"deny" never actually blocked anything, so it's never folded into the
real allowed/denied/approval-required or cross-border transfer figures
these reports exist to get right. Run `python
examples/compliance_report_example.py` for a full end-to-end walkthrough.

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
- **`RateLimitPolicy`** — wraps another `ToolPolicy`; denies once a
  principal exceeds `max_calls` within a trailing `window_seconds`. Every
  attempt counts, including ones the base policy would deny anyway.
- **`RunawayAgentPolicy`** — wraps another `ToolPolicy`; trips a
  *principal* (not a tool, not a deployment) once they've made
  `identical_call_threshold` calls to the same tool with the same
  arguments in `window_seconds` — the "stuck in a broken retry loop"
  failure mode a rate limit alone can't distinguish from a busy, healthy
  agent. Deliberately does **not** self-heal on a timer: stays tripped
  until `reset(principal_id)` is called explicitly.
- **`JurisdictionalRiskTierPolicy`** — wraps another `ToolPolicy`; reads
  jurisdiction from `request.context["jurisdiction"]` and can force a
  *stricter* outcome (e.g. `require_approval`) for a specific risk tier
  in that jurisdiction — monotonic, it can only tighten a base policy's
  decision, never loosen one.
- `ToolCallRequest.context` mirrors `ModelCallRequest.context` — free-form,
  policy-interpreted, and how jurisdiction reaches `ToolGuard.call(...,
  context={"jurisdiction": "EU"})` the same way it already reaches
  `ModelGuard.resolve(..., context=...)`.

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

### Data residency (`ResidencyPolicy`)

- Wraps any `ModelPolicy` the same way `BudgetPolicy` does — the base
  policy's routing decision passes through unchanged unless the resolved
  deployment isn't a jurisdiction-compliant one.
- Reads jurisdiction from `request.context["jurisdiction"]`, not from the
  principal's attributes — which country's law governs a piece of data is
  a property of that data, not of who's making the call.
- `allowed_by_jurisdiction` maps jurisdiction → `{deployment: mechanism}` —
  the mechanism (adequacy decision, SCC, BCR, certification) lands in the
  audit reason alongside the jurisdiction and resolved deployment, so the
  trail records *why* a transfer was lawful, not just that it was allowed.
  An optional `context["controller"]` rides along too, purely for
  traceability back to the accountable entity.
- Doesn't just check the base's top pick: if a *later*, already-qualifying
  candidate from the base's own fallback chain is jurisdiction-compliant,
  that one is promoted instead of denying outright.
- Fails closed on two distinct conditions: jurisdiction missing from
  context, or a jurisdiction present but uncovered by any candidate. Both
  deny outright — no silent fallback to whatever deployment happens to be
  first in the list.
- `fallback_chain` is filtered the same way `resolve` is: a fallback can
  never route jurisdiction-governed data to a non-compliant deployment
  just because the preferred one is down.

### Data retention (`RetentionPolicy`)

- Same wrapping shape as `ResidencyPolicy`, checking a different,
  independent fact: not *where* a deployment sits but *how long* it's
  allowed to keep what it's sent, per `deployment_retention_days`.
- Reads the required ceiling from `request.context["max_retention_days"]`
  — `0` means "this call requires a zero-data-retention deployment."
- Same fail-closed discipline, same fallback-promotion behavior as
  `ResidencyPolicy` — both share a private `_first_compliant` helper
  rather than duplicating that candidate-search logic twice.
- Compose the two when both matter:
  `RetentionPolicy(ResidencyPolicy(base, ...), deployment_retention_days=...)`
  — geography and retention are independent checks; a call can fail
  either one without failing the other.

### Reliability tracking (`CircuitBreakerPolicy`, `ModelOutcomeEntry`)

- **`ModelGuard.record_outcome(principal, model, success, latency_ms=,
  error=)`** — the sibling to `record_usage` that reports whether a real
  call *attempt* actually worked, not just what it cost. Writes a
  `ModelOutcomeEntry` to the audit trail either way. `error` is a short
  category (`"timeout"`, `"rate_limited"`, `"server_error"`,
  `"connection_error"`), never a raw exception message.
- **`CircuitBreakerPolicy`** — wraps any `ModelPolicy`; trips a specific
  deployment once it has `failure_threshold`+ recorded failures within
  the trailing `window_seconds`, and searches the base policy's full
  qualifying candidate list (same `_first_compliant` helper
  `ResidencyPolicy`/`RetentionPolicy` share) to promote a healthy one
  instead of denying outright. Fails closed if every candidate is
  currently tripped.
- Deliberately a trailing time window, not an open/half-open/closed state
  machine — self-heals once the window passes the last failure, no
  separate recovery/probe logic needed.
- A governance denial is never a recorded failure — `record_outcome` only
  fires after a call was allowed and actually attempted, same separation
  `record_usage` already has from the routing decision itself.
- `marshal_ai.integrations` calls this automatically from real SDK call
  attempts (see below) — timed, classified, and the original exception is
  always re-raised unchanged.

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

v0.11 — all three governance surfaces (retrieval; tool calls with rate
limiting, runaway-loop detection, and jurisdiction-aware risk tiering;
model routing/budgets/cross-border data residency/data retention/
reliability-aware circuit breaking), one shared audit trail, OpenTelemetry
export, a local CLI viewer, one-line model governance for any
OpenAI/Anthropic/Google-GenAI-based framework via SDK patching (with
automatic outcome/latency reporting) — including Google ADK's default
Gemini path specifically, verified against ADK's own source rather than
assumed — and deterministic sensitive-data detection across every
surface. New this release: an observe-first `mode="shadow"` on every
guard; real Chroma and LangChain adapters for `RetrievalGuard` (Chroma
integration is shipped, no longer in progress); MCP tool-call governance
(`marshal_ai.mcp.GovernedMCPSession`) — the shared choke point every
MCP-speaking framework now has, reframing the old "tool-call interception
needs a framework-specific adapter" problem; and durable, tamper-evident
`SQLiteAuditSink` plus `marshal_ai.reports`' EU AI Act Article 12/26-shaped
compliance reports, both shadow-mode-aware so a would-have-denied decision
is never counted as a real one. See [`ideas.md`](./ideas.md) for what's
next (time-to-first-token tracking for streaming calls; an N-failed-calls
trigger for `RunawayAgentPolicy` once `ToolGuard` reports call outcomes
the way `ModelGuard` does; a litellm proxy hook for deployments already
running the LiteLLM proxy; adapters for Pinecone/pgvector/Weaviate;
policy-as-config).

## License

MIT
