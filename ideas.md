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

- **One-line, framework-agnostic integration for `ToolGuard`/`ModelGuard`.** The
  requirement that made the tool/model surfaces sharper: work with LangChain,
  LangGraph, CrewAI, AutoGen, Google ADK, or a raw script, with a single line of
  setup, not a per-framework adapter. The real unlock: nearly every framework's
  actual LLM call funnels through one of a small number of choke points — the
  OpenAI SDK, the Anthropic SDK, or increasingly a unifying layer like
  **litellm**. Two integration paths, in order of leverage:
  1. A litellm callback/proxy hook — litellm already has a callback/guardrails
     system built for pre-call inspection-and-block, not just after-the-fact
     logging (verify the exact API against litellm's current docs before
     building; APIs like this move). One hook, and every framework routed
     through litellm gets governed.
  2. A direct SDK monkeypatch (wrap `openai`'s / `anthropic`'s client
     `.create()`/`.messages.create()`) for frameworks calling those SDKs
     directly — the same technique Helicone/Langfuse/OpenLLMetry use for their
     own "add one line" story. Real, but fragile: breaks silently on SDK
     version bumps, worth calling out rather than hiding.

  Target shape: `import marshal_ai; marshal_ai.enable(tool_policy=..., model_policy=...)`
  at process startup, patching whichever client(s) are importable so the agent
  framework on top never has to know Marshal exists.

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
