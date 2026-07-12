# Marshal — idea backlog

Marshal is governance for AI systems, one library, three surfaces, one shared audit
trail: `RetrievalGuard` (document/field-level access control on any retriever),
`ToolGuard` (risk-tiered allow/deny/require-approval on tool calls, with argument
redaction), `ModelGuard` (logical-name model routing with governed fallback chains
and per-principal budget enforcement). All three generalize real-world
access-control, governance, and cross-jurisdiction compliance problems
seen in production enterprise AI systems — not generic tutorial clones.
`marshal_ai.sensitive` layers
deterministic, content-based secret/PII detection across all three, plus the
SDK-patch integration layer — a different question ("does this content contain
a secret") from what the three surfaces answer ("is this allowed").

Import name is `marshal_ai` — `marshal` collides with a Python stdlib module, so
that name was never usable; see the README for the full explanation.

## Shipped

- **v0.1 — `RetrievalGuard`.** Wraps any retriever, enforces document/field-level
  access control, logs every call. `AttributePolicy` (list ACL, post-filter),
  `GroupPolicy` (scalar group, native pushdown filter for retrievers that accept
  one), `RedactingPolicy`, async (`aretrieve`).
- **v0.3 — `ToolGuard`.** Wraps any callable tool. `RiskTierPolicy` maps a
  caller-assigned risk tier to allow/deny/require-approval. `CLIApprovalHandler`
  blocks on a stdin prompt (v0.1 of the approval path — no queue infra yet).
  `RedactingToolPolicy` hides specific argument values in the audit trail/approval
  prompt while the wrapped tool still gets the real arguments. A denied or
  declined call raises `ToolCallDenied` — never a silent no-op.
- **v0.3 — `ModelGuard`.** Resolves a *logical* model name to a real one per
  principal via `AllowlistModelPolicy` (ordered candidates, each optionally
  gated on a required principal attribute). `fallback_chain()` returns the rest
  of the *already-qualifying* candidates — a fallback can never be used to
  bypass governance just because the preferred model is down. `BudgetPolicy`
  wraps any model policy and denies once a principal's tracked spend (from
  `record_usage`, reported after your real call completes) hits a limit.
  Deliberately does *not* make the LLM call itself — resolve, call it with
  whatever client you already use, report usage back.
- **One shared `AuditSink`** across all three surfaces, proven not just claimed:
  `sink.query(principal_id=...)` returns retrieval + tool-call + model-call
  entries together, and `JSONLAuditSink` round-trips mixed event types correctly
  via a `kind` discriminator (each event type self-registers a reconstructor —
  `audit.py` never needs to import `tools.py`/`models.py`).
- **v0.4 — `ModelUsageEntry`.** `record_usage()` previously updated `BudgetPolicy`'s
  internal spend tracker silently — real usage now also lands in the audit trail
  as its own entry, not just invisible policy state.
- **v0.4 — `OpenTelemetryAuditSink`** (`marshal_ai.otel`, optional `opentelemetry`
  extra). The informed decision on "where's the dashboard": don't build one —
  export spans into whatever OTel-compatible backend already exists (Grafana,
  Honeycomb, Datadog, a local Jaeger). Model-call spans use the real, current
  OpenTelemetry GenAI semantic conventions (`gen_ai.request.model`,
  `gen_ai.usage.input_tokens`/`output_tokens` — verified against the spec, which
  exited experimental for client spans in early 2026); tool-call/retrieval spans
  use a `marshal.*` namespace since the tool/agent semconv is still Development
  status as of 2026 — didn't guess at a convention that doesn't stably exist yet.
  Write-only by design (spans live in the backend); tested against the real OTel
  SDK's `InMemorySpanExporter`, not mocked.
- **v0.4 — `marshal_ai.cli tail`.** The zero-infra half of the dashboard answer —
  a stdlib-only terminal viewer over a `JSONLAuditSink` file (`-n`, `--principal`,
  `--denied-only`, `--follow`). Covers "let me see it right now" without a
  collector running anywhere; OTel export is the answer once there's a real
  backend to point at.

- **v0.5 — `marshal_ai.integrations`: one-line model governance for any
  framework.** Patches the OpenAI and Anthropic SDK client classes directly
  (sync + async — `Completions.create`, `AsyncCompletions.create`,
  `Messages.create`, `AsyncMessages.create`, verified against the real classes,
  not guessed) — `enable(guard, principal)` and every outbound call from
  *any* framework built on either SDK (LangChain, LangGraph, CrewAI, AutoGen,
  ADK) is governed with zero changes to that framework's code. Substitutes the
  resolved model into the call, auto-reports usage from the real response
  (`response.usage.prompt_tokens`/`completion_tokens` for OpenAI,
  `.input_tokens`/`.output_tokens` for Anthropic — the field names genuinely
  differ between providers). Went with direct SDK patching over a litellm
  proxy hook after checking litellm's current docs: `async_pre_call_hook` is a
  *proxy-server* feature (has documented 2026 bugs where it's bypassed for
  some endpoints/tool calls) — most people calling `openai`/`anthropic`
  directly aren't running that proxy, so patching the SDK clients themselves
  reaches more of "anywhere" than a proxy-only hook would. `disable_all()`
  restores originals; the fragility-on-SDK-changes cost is documented in the
  module docstring, not hidden. Deliberately model-governance only — see
  below for why this doesn't (and structurally can't, the same way) cover
  tool-call interception.

- **v0.6 — `marshal_ai.sensitive`: deterministic sensitive-data detection.**
  A different question from every surface above: not "is this allowed" but
  "does the literal content contain a secret or PII, regardless of who's
  allowed to see it." A principal can be fully entitled to a document and
  it can still contain a credential that should never have been embedded;
  a model can leak one in its own completion without any ACL being
  violated at all. Deliberately regex-based, not another LLM call — same
  "who governs the governor" reasoning below: an LLM judge costs money and
  trust on every document/prompt/completion, and a document engineered to
  smuggle a prompt injection could plausibly talk an LLM judge out of
  flagging itself the same way it could talk one into rubber-stamping a
  malicious tool call. A regex either matches or it doesn't — no added
  attack surface. `SensitiveDataPolicy` wraps a `Policy` and redacts
  document content post-ACL-decision (content scanning structurally can't
  block at `evaluate()` time — that method only ever sees metadata, never
  content, so there's no clean point to deny an already-fetched, allowed
  document). `SensitiveDataToolPolicy` wraps a `ToolPolicy` and *can*
  block, since tool arguments are available at decision time — a
  hardcoded AWS key or private key in the arguments denies the call
  outright regardless of risk tier, while non-blocking findings (an email
  address) get redacted the same way `RedactingToolPolicy` already
  handles named fields. The SDK-patch layer (`marshal_ai.integrations`)
  got a `scanner=` param on `enable()` too — it's the only place in
  Marshal that ever sees actual prompt/completion *text* (the three
  guards govern metadata, arguments, and model names, never message
  content), so it's uniquely positioned to block a credential in an
  outbound prompt *before any network call happens*, and to flag one
  leaked in a completion afterward (audit-only there — the call already
  happened, there's nothing left to block). Findings are recorded as
  `"DETECTOR:count"` only, never the matched text — the same discipline
  `ToolCallEntry` already applies to redacted arguments, so the audit
  trail meant to catch a leaked secret can't become a second copy of it.
  Default block list is narrow on purpose (credentials, not PII) —
  blocking a document because it contains an email address would make the
  feature useless on day one; widen `block_detectors=` per deployment.

The "fold into one library or keep tool/model governance as a separate sibling
project" question from the original writeup below is resolved: one library.
Shared audit infrastructure across surfaces turned out to matter more than
keeping each surface's scope maximally narrow.

## Backlog — not started yet

- **Real vector-store integration for `RetrievalGuard`.** Everything's only ever
  been proven against a fake in-memory retriever. A real Chroma adapter (via
  `chromadb`, optional dependency, EphemeralClient for tests — no network needed)
  is in progress; a real integration test against it is the actual proof this
  isn't a toy.

- **Framework-specific tool-call interception.** `marshal_ai.integrations`
  covers *model* calls because there's one choke point (the SDK client) nearly
  every framework shares. Tool-call *execution* has no equivalent: it happens
  inside each framework's own dispatch code (LangChain's `Tool.run`, ADK's
  callback hooks, a hand-rolled loop) after the model's response is parsed —
  different shape per framework, not one shared choke point. This means
  one-line tool governance genuinely needs N framework-specific adapters, not
  one patch. Today, wrapping your tool functions in `ToolGuard` directly is
  the real (explicit, not automatic) answer. Worth revisiting per-framework
  once one specific framework's adoption justifies the adapter.

- **A litellm proxy hook**, for teams already running the LiteLLM proxy rather
  than calling `openai`/`anthropic` directly — `async_pre_call_hook` on a
  `CustomLogger` subclass, registered via `litellm_settings.callbacks`. Skipped
  for now in favor of direct SDK patching (see "Shipped" above) since it only
  reaches proxy deployments, and has documented 2026 bugs around certain
  endpoints/tool calls bypassing it entirely — worth re-checking litellm's
  docs before picking this up, this area moves.

- **Estimate-before-call budget checks.** `BudgetPolicy` today only enforces on
  the *next* call once prior usage has been reported — it can't yet block a call
  that would blow the budget before that call happens, since it has no way to
  estimate cost ahead of time without a maintained per-model pricing table (a
  real, ongoing maintenance burden — a stale table silently misreports cost,
  worse than not tracking it at all). Worth doing once the SDK-interception
  layer above exists, since that's the point where a pre-call estimate would
  actually get checked.

- **Messy-enterprise-data connector.** Docling handles clean PDFs/DOCX well
  already. This targets what it doesn't: call-recording transcripts, ad-hoc
  spreadsheets, normalized into retrieval-ready chunks with real provenance
  metadata — the kind of long-tail, mixed-format source mix a real
  enterprise retrieval system ends up needing to ingest.

- **Async approval queue for `ToolGuard`.** `CLIApprovalHandler` blocks the
  calling thread — fine for a script, not for a real agent that should keep
  working on other things while a human reviews one risky call. Needs a real
  queue (not necessarily infra — could start as a local SQLite-backed one) and
  an `ApprovalHandler` that returns a future/pending state instead of blocking.

- **Runaway-agent circuit breaker.** `BudgetPolicy` catches an agent that's
  burned through its dollar limit — it does nothing about an agent stuck in a
  loop calling the *same* tool or model hundreds of times in a few seconds
  before enough usage has even been reported to trip the budget. This is a
  real, expensive, well-documented failure mode (a broken termination
  condition, a tool that "fails" in a way the agent keeps retrying) — a
  `CircuitBreakerPolicy` wrapping any `ToolPolicy`/`ModelPolicy` could trip
  after N identical or N failed calls from one principal within a time
  window and require a human reset, independent of and faster-tripping than
  dollar-based budgets. Natural pairing with rate limiting (below) —
  probably one policy wrapper, two trigger conditions.

- **Rate limiting per principal.** Neither `ToolGuard` nor `ModelGuard` cap
  *how often* a principal can call something, only whether a given call is
  allowed. A token-bucket `RateLimitPolicy` (thread-safe, same shape as
  `BudgetPolicy`'s `_spent` tracking) wrapping a base policy would deny once
  a principal exceeds N calls per window — a cheap, deterministic backstop
  against both malicious abuse and an agent's own bugs, complementary to
  (not a replacement for) the circuit breaker above.

- **Policy-as-config (YAML/JSON).** Every policy today is a Python object,
  which means a compliance reviewer who isn't a Python engineer can't audit
  or propose a policy change without going through a PR review of code, and
  a policy change can't be versioned/approved separately from a code
  deploy. A loader that builds `AttributePolicy`/`RiskTierPolicy`/
  `AllowlistModelPolicy`/`SensitiveDataPolicy` (and the wrapping
  `Redacting*`/`SensitiveData*` layers) from a declarative file would let
  governance rules live in a reviewable, diffable artifact separate from
  application code — the OPA/Rego precedent, scoped to what Marshal's
  existing policy shapes can already express rather than a new DSL.

Add more here as they come up — pain points from real work beat cold-cloned ideas.

## The genuinely hard parts (worth remembering, not re-litigating)

- **Latency vs. safety.** Human-in-the-loop on every risky call kills the point
  of an agent being autonomous — needs async approval eventually (see backlog),
  plus a tiered auto-approve-below-threshold mode for genuinely low-risk tiers.
- **Who governs the governor.** Never let an LLM judge auto-approve a
  high-risk tool call — the same failure mode that lets a prompt-injected agent
  misuse a tool in the first place can talk an LLM-judge approver into
  rubber-stamping it. High-risk needs a human or a deterministic rule, full
  stop, never another LLM call.
- **Composability, not a competing framework.** A thin layer around whatever
  people already use, not a new framework to migrate onto. The moment it
  demands a rewrite, adoption goes to zero — this is *why* the SDK-interception
  integration path above matters more than it might look.
