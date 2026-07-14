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

- **v0.7 — `ResidencyPolicy` + `RetentionPolicy`: cross-border data
  governance for `ModelGuard`.** A model call to a foreign-hosted
  deployment is a cross-border transfer of whatever data is in that
  prompt — GDPR, India's DPDP Act, Thailand's PDPA, and Singapore's PDPA
  each apply a genuinely different legal test to that same act (a
  whitelist with enumerated exceptions, a blacklist that's currently
  empty, an unpublished adequacy list that makes contracts mandatory by
  default, and a per-transfer "comparable protection" standard,
  respectively — four different mechanisms, not four strictness levels
  of one mechanism). Both policies wrap any `ModelPolicy` the same way
  `BudgetPolicy` does, and both read their deciding fact from
  `request.context`, not from the calling principal's attributes —
  jurisdiction and required retention ceiling are properties of the
  data in the call, not of who's making it, so the same principal can
  make one call carrying EU-governed data and the next carrying
  India-governed data without either fact leaking onto their identity.
  `ResidencyPolicy` additionally records the *transfer mechanism*
  (adequacy decision, SCC, BCR, certification) in the audit reason, not
  just the allow/deny outcome — recording *why* a transfer was lawful is
  a distinct requirement from recording *that* it was allowed, and the
  first version of this shipped without that distinction until a
  review pass caught the gap between what the cross-border blog post
  this shipped alongside actually argued for and what the code recorded.
  `RetentionPolicy` answers an independent question — not where a
  deployment sits but how long it's allowed to keep what it's sent
  (`max_retention_days=0` for a zero-data-retention requirement) — a
  deployment can be geographically compliant and still violate a ZDR
  agreement, or vice versa, so the two checks are separate, composable
  wrappers rather than one combined policy. Both fail closed on missing
  context, not just on an explicit non-match — an unstamped call is
  treated the same as a non-compliant one, since a silent default
  deployment is exactly the failure mode both policies exist to close
  off. Both search the base policy's full qualifying candidate list
  (top pick plus fallback chain), not just its top pick, promoting a
  compliant candidate further down that same already-qualified list
  instead of denying outright — sharing one private `_first_compliant`
  helper rather than duplicating that search twice. An optional
  `context["controller"]` rides along in `ResidencyPolicy`'s audit
  reason purely for traceability back to whichever entity's actual DPA
  the `allowed_by_jurisdiction`/`deployment_retention_days` config is
  supposed to encode — Marshal enforces that config deterministically,
  it doesn't validate that it's still accurate; keeping it in sync with
  a renegotiated contract is on whoever owns the config, the same way
  `BudgetPolicy`'s pricing table needs updating when a vendor's prices
  change. **Explicitly out of scope, and why**: confirming a vendor's
  downstream retention/deletion actually matches what it promises (no
  API exists for Marshal to verify that from the outside); enforcing
  sub-processor authorization chains beyond deployment-naming
  convention (name deployments by their actual processing chain, e.g.
  `"claude-bedrock-eu-west-1"` vs. `"claude-foundry-global"`, since two
  deployments of "the same model" can differ exactly in the guarantee
  that matters here); data-subject erasure requests once data has left
  Marshal's own boundary (a downstream vendor-system problem, not a
  routing-time one); and AI-specific regulatory classification like the
  EU AI Act's risk tiers, which is a different category of law from
  data-transfer law entirely — see the jurisdiction-aware risk-tiering
  backlog item below for where that actually belongs.

- **v0.8 — `CircuitBreakerPolicy` + `ModelGuard.record_outcome()`:
  reliability tracking.** Asked directly whether Marshal tracks each LLM
  call's failures and latency — checked, and the honest answer was no:
  every policy through v0.7 except `BudgetPolicy` decides from static
  config plus the current request alone; nothing tracked whether a
  resolved deployment's calls actually *succeeded*, or fed that back into
  routing. `ModelGuard.record_outcome(principal, model, success,
  latency_ms=, error=)` is the missing sibling to `record_usage` — called
  on every real call *attempt*, success or failure, writing a new
  `ModelOutcomeEntry` to the audit trail (`error` is a short category,
  never a raw exception message — same discipline
  `SensitiveDataEntry.findings` already applies). `CircuitBreakerPolicy`
  wraps any `ModelPolicy` and trips a specific deployment once it has
  `failure_threshold`+ recorded failures within a trailing
  `window_seconds`, reusing the same `_first_compliant` helper
  `ResidencyPolicy`/`RetentionPolicy` already share to promote a healthy
  candidate instead of denying outright, and failing closed only if every
  candidate is currently tripped. Deliberately a plain trailing time
  window, not a textbook open/half-open/closed state machine — it
  self-heals once the window passes the last failure, with no separate
  recovery/probe logic needed, which is simpler and sufficient. A
  governance denial (Residency/Retention/RiskTier) is never counted as a
  failure — `record_outcome` only fires after a call was allowed and
  actually attempted, the same separation `record_usage` already has from
  the routing decision, so a heavily-governed deployment that correctly
  denies most calls doesn't look identical to a genuinely broken one.
  `marshal_ai.integrations` now calls `record_outcome` automatically —
  timing every real call, classifying a real failure via the actual
  SDK exception class (`openai`/`anthropic` both expose identical names:
  `APITimeoutError`, `RateLimitError`, `APIConnectionError`,
  `InternalServerError` — verified directly in the installed packages,
  not guessed), and always re-raising the original exception unchanged —
  this layer only ever observes a failure, it never gatekeeps on it.
  **Explicitly out of scope, and why**: time-to-first-token, since that
  only means anything for a streaming call, and the SDK-patch layer
  doesn't wrap streaming responses at all yet — see the follow-up entry
  below rather than rushing a bigger, riskier change to the wrapper's
  return-value contract into the same pass.

- **v0.9 — `RateLimitPolicy` + `RunawayAgentPolicy` + `JurisdictionalRiskTierPolicy`:
  three `ToolGuard`-side governance questions v0.8 didn't cover.**
  `RateLimitPolicy` caps *how often* a principal can call anything, period
  — every attempt counts toward the limit, including ones a base policy
  would deny anyway, since a rate limit is about attempt frequency, not
  success rate. `RunawayAgentPolicy` catches a different failure mode
  entirely: a principal stuck in a broken loop calling the *same* tool
  with the *same* arguments over and over — high frequency isn't the
  tell (a busy, healthy agent can be just as fast), *repetition* is.
  Deliberately named apart from `CircuitBreakerPolicy` (`marshal_ai.
  models`) despite both being "circuit breaker"-shaped: that one trips a
  *deployment* on *failure rate*; this one trips a *principal* on
  *identical-call count*, and can trip on a loop that's "succeeding"
  every time. It also deliberately does **not** self-heal on a timer —
  once tripped, a principal stays denied until `reset(principal_id)` is
  called explicitly, because a runaway loop doesn't stop being a bug
  once a window elapses; that requires an actual human decision that
  it's fixed. Shipped with only the identical-call trigger — a parallel
  N-failed-calls trigger was considered and deliberately deferred (see
  backlog) since it needs outcome-reporting plumbing `ToolGuard` doesn't
  have yet. `JurisdictionalRiskTierPolicy` answers a third, unrelated
  question: whether a specific action needs *more* human oversight in a
  given jurisdiction than the base policy already requires (the EU AI
  Act's Annex III high-risk categories being the sharpest example) —
  reads jurisdiction from a new `ToolCallRequest.context` field (added
  this release, mirroring `ModelCallRequest.context`) and is strictly
  monotonic: it can only tighten a base decision (`allow` →
  `require_approval` or `deny`), never loosen one, so it can never be
  used to bypass a base policy's stricter judgment. All three reuse the
  existing per-principal sliding-window tracking shape `BudgetPolicy`
  established, applied to three different trigger conditions rather than
  three unrelated mechanisms.

This is also the first concrete step toward the "is Marshal becoming a
platform" question raised alongside this work: a platform (vs. a library)
is a system that learns from what actually happened and feeds it back into
future decisions, not just a wider set of static policy shapes. Every
policy before this one — including `ResidencyPolicy`/`RetentionPolicy` —
is static config plus the current request. `CircuitBreakerPolicy` is the
second policy (after `BudgetPolicy`) whose decision depends on accumulated
runtime history. Genuinely more platform-shaped than what came before it,
but still a library: no central config store, no cross-process
aggregation, no dashboard. Policy-as-config (below) is the other missing
piece of that story, not this one.

- **v0.10 — native Google GenAI (Gemini) support in `marshal_ai.integrations`,
  and a corrected claim about Google ADK.** Asked directly to make Marshal
  easy to wrap over existing providers/frameworks, specifically naming
  ADK — checked rather than assumed, and the README's existing claim that
  ADK "gets model governance transparently" via the openai/anthropic SDK
  patch was **wrong** for ADK's default, most common path: `LlmAgent`
  calls Gemini through `google-genai`'s `Models.generate_content`
  directly, not through the `openai`/`anthropic` client classes Marshal
  patched through v0.9 — confirmed against ADK's own source and docs,
  not guessed. (ADK's `LiteLlm(model="openai/...")`/`LiteLlm(model=
  "anthropic/...")` path was fine — LiteLLM genuinely does call through
  to the real `openai`/`anthropic` SDK client classes, also verified
  directly in LiteLLM's source rather than assumed, so that path was
  already covered.) Fixed by adding `enable_google()`, patching
  `Models`/`AsyncModels.generate_content` the same way `enable_openai`/
  `enable_anthropic` already patch `Completions`/`Messages.create`.
  `_PROVIDER_ADAPTERS` grew a third leg per provider — prompt-text
  extraction is now itself per-provider (`messages=` for openai/
  anthropic, `contents=` for google-genai, which has a structurally
  different shape: `Content`/`Part` objects rather than role/content
  dicts), alongside the completion-text and usage extractors that
  already existed — so `_scan_prompt_or_raise` reads prompts through an
  injected extractor instead of a hardcoded `messages` lookup. Error
  classification also branches per provider now: `google-genai` has a
  genuinely different exception shape from openai/anthropic (`APIError`/
  `ClientError`/`ServerError` with a `.code` HTTP status, no
  `RateLimitError`/`APITimeoutError` class names at all — checked
  directly against the installed SDK, not assumed) — network-level
  failures are classified from the underlying transport's own exceptions
  instead (`google-genai` uses `httpx` for its async client and
  `requests` for its sync client, both hard dependencies, not optional —
  verified in `_api_client.py`). Every real API shape used here —
  `GenerateContentResponse.text`, `.usage_metadata.prompt_token_count`/
  `.candidates_token_count`, `Content.parts`/`Part.text`,
  `Models.generate_content`'s keyword-only signature — was checked
  against the actually-installed `google-genai` package before writing
  the adapter, the same discipline already applied to the openai/
  anthropic exception hierarchy in v0.8.

The "fold into one library or keep tool/model governance as a separate sibling
project" question from the original writeup below is resolved: one library.
Shared audit infrastructure across surfaces turned out to matter more than
keeping each surface's scope maximally narrow.

## Backlog — not started yet

- **Time-to-first-token tracking for streaming calls.** v0.8's reliability
  tracking (`record_outcome`, `CircuitBreakerPolicy`) covers total latency
  and success/failure for ordinary `.create()` calls, but TTFT only means
  anything for a *streaming* response (`stream=True`), and
  `marshal_ai.integrations` doesn't wrap streaming responses at all today —
  verified directly against the file before shipping v0.8, not assumed. A
  streaming call returns an iterator of chunks, not a single response
  object with `.usage`; adding TTFT means transparently proxying that
  iterator (time the first `next()`, keep yielding chunks unchanged, time
  the last one for total latency, and usage often only arrives in the
  final chunk) — a materially bigger change to the wrapper's return-value
  contract than timing a normal call, and one with real risk of breaking a
  caller that iterates the stream itself. Deserves its own dedicated pass
  and review, not folding into the same release that shipped non-streaming
  reliability tracking.

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

- **`RunawayAgentPolicy`'s N-failed-calls trigger.** v0.9 shipped the
  identical-call trigger only (see Shipped below) — a parallel "N *failed*
  calls from one principal" trigger was considered too, but it needs
  `ToolGuard` to report call outcomes the way `ModelGuard.record_outcome`
  does for model calls, and that plumbing doesn't exist for tool calls
  yet (today, if the wrapped tool itself raises inside `ToolGuard.call()`,
  the exception just propagates — nothing observes or audits it, the same
  shape of gap `ModelGuard` had before v0.8). Worth its own pass: adding
  `ToolPolicy.record_outcome` and wiring `ToolGuard.call()` to report
  success/failure around the actual `self._tool(**arguments)` invocation
  is a real, separate piece of work, not a one-line addition to
  `RunawayAgentPolicy`.

- **Rate limiting / runaway-loop detection for `ModelGuard`, not just
  `ToolGuard`.** v0.9's `RateLimitPolicy`/`RunawayAgentPolicy` wrap
  `ToolPolicy` specifically — tool calls being the more expensive/
  consequential axis (actions, not just routing). An agent can just as
  easily loop on *model* calls (retrying the same prompt against the same
  model hundreds of times), and the same sliding-window mechanism applies
  cleanly to `ModelPolicy` too. Not built alongside v0.9 because Python's
  `ToolPolicy`/`ModelPolicy` are separate ABCs with separate request/
  decision shapes — a literal shared class isn't possible without
  awkward multiple inheritance, so this would be a second, `ModelPolicy`-
  side class (distinctly named, e.g. `ModelRateLimitPolicy`), not a
  one-line reuse of the `ToolGuard` version.

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
