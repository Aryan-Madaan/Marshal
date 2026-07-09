# Marshal — idea backlog

Marshal is governance for AI systems, one library, three surfaces, one shared audit
trail: `RetrievalGuard` (document/field-level access control on any retriever),
`ToolGuard` (risk-tiered allow/deny/require-approval on tool calls, with argument
redaction), `ModelGuard` (logical-name model routing with governed fallback chains
and per-principal budget enforcement). All three generalize the access-control,
governance, and cross-jurisdiction compliance work behind TDA and the agent fleet
at Tata Steel — not generic tutorial clones.

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
  metadata. Maps to integrating 150+ mixed-format sources into TDA.

- **Async approval queue for `ToolGuard`.** `CLIApprovalHandler` blocks the
  calling thread — fine for a script, not for a real agent that should keep
  working on other things while a human reviews one risky call. Needs a real
  queue (not necessarily infra — could start as a local SQLite-backed one) and
  an `ApprovalHandler` that returns a future/pending state instead of blocking.

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
