# Design decisions

This is a record of *why* Marshal is built the way it is — the tradeoffs
considered at each decision point, not just what the code does (the code
already says that). Written after a SOLID / system-design audit of the
whole codebase; the "Audit findings" section documents the real bugs that
audit caught and fixed, and "Deliberate tradeoffs" documents the places
that looked like violations but were kept as-is, with the reasoning for why.

## Architecture in one picture

```
                     ┌─────────────────────────┐
                     │   marshal_ai.sensitive   │  content-based detection
                     │  (SensitiveDataPolicy,   │  ("does this contain a
                     │  SensitiveDataToolPolicy)│   secret", not "is this
                     └───────────┬─────────────┘   allowed")
                                 │ wraps
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
      ┌───────────────┐  ┌──────────────┐  ┌─────────────────┐
      │ policy.py      │  │ tools.py     │  │ models.py        │
      │ Policy          │  │ ToolPolicy   │  │ ModelPolicy      │
      │ (ACL, redact,   │  │ (allow/deny/ │  │ (route, budget)  │
      │  pushdown)      │  │  approve)    │  │                  │
      └───────┬────────┘  └──────┬───────┘  └────────┬─────────┘
              │ used by           │ used by            │ used by
              ▼                   ▼                    ▼
      RetrievalGuard         ToolGuard             ModelGuard
      (retrieval.py)         (tools.py)            (models.py)
              │                   │                    │
              └───────────────────┼────────────────────┘
                                  ▼
                          AuditSink (audit.py)
                    InMemoryAuditSink / JSONLAuditSink /
                    OpenTelemetryAuditSink (otel.py)
                                  │
                                  ▼
                   marshal_ai.cli tail  (local viewer)

      marshal_ai.integrations  ── patches openai/anthropic SDK classes
      directly, wrapping ModelGuard.resolve()/record_usage() underneath
      any framework built on those SDKs, plus optional sensitive-data
      scanning on real prompt/completion text (the only layer that sees it).
```

Three ACL-driven governance surfaces (`RetrievalGuard`/`ToolGuard`/
`ModelGuard`), one shared audit trail, one cross-cutting content-scanning
layer (`marshal_ai.sensitive`) that asks a different question than the
three surfaces, and one integration layer that reaches code Marshal never
had to wrap by hand (`marshal_ai.integrations`).

## SOLID, principle by principle

### Single Responsibility

Each surface's *guard* (the thing you construct and call — `RetrievalGuard`/
`ToolGuard`/`ModelGuard`) has exactly one job: evaluate a policy, log the
outcome, and — only if allowed — do the real thing (call the retriever /
tool / nothing, in `ModelGuard`'s case, since it never makes the LLM call
itself). Policy *decision logic* is factored out into separate `Policy`/
`ToolPolicy`/`ModelPolicy` hierarchies so a guard never has to know *how*
a decision gets made, only that it can ask for one.

**Decision point — why `policy.py` is its own file but `tools.py`/
`models.py` bundle guard + policy together.** `Principal` (the "who is
asking" type) is shared across all three surfaces, so it has to live
somewhere all three can import without any of them depending on each
other. `policy.py` is that shared home — and since the retrieval `Policy`
ABC was the first surface built, it rode along in the same file.
`ToolPolicy`/`ModelPolicy`, by contrast, are only ever used by
`tools.py`/`models.py` respectively, so splitting them into their own
files would add file-count without adding reuse. Not a violation — SRP is
about reasons to change, and `ToolPolicy` and `ToolGuard` change for
exactly the same reasons (tool-governance semantics), so keeping them
together is the more honest boundary, not less.

### Open/Closed

The clearest OCP mechanism in the codebase is the audit "kind" registry
(`register_entry_type` / `_ENTRY_TYPES` in `audit.py`): a brand new event
type — `ToolCallEntry`, `ModelCallEntry`, `ModelUsageEntry`, and now
`SensitiveDataEntry` — can join the shared audit trail by registering
itself at import time. `audit.py` was never modified to learn about any
of them; it was written once, closed for modification, open for exactly
this kind of extension. Same story for `Policy`/`ToolPolicy`/`ModelPolicy`:
a user backs access control with Postgres, OPA, or a hand-rolled rule
table by subclassing, never by editing Marshal's code.

**Audit finding (fixed): the registry's OCP promise had a gap.**
`AuditSink.query(denied_only=True)` and `marshal_ai.cli`'s row-flagging
both used a hand-written duck-typed check for "was this a denial" that
only recognized two shapes (`denied_ids`, or `outcome in
("deny","declined")`). `SensitiveDataEntry` uses neither — it has
`action == "blocked"` instead, since "blocked" isn't quite the same
concept as "denied" for every consumer (a redacted finding is neither
allowed nor denied). Before the fix, a model prompt blocked by
`marshal_ai.integrations`' scanner (which writes *only* a
`SensitiveDataEntry` — `ModelGuard.resolve()` is never reached, so there's
no `ModelCallEntry` either) would silently disappear from
`denied_only=True` and from the CLI's `!` flag column — a real denial,
invisible in the one place built to answer "what got blocked." Fixed by
extending the duck-type check to a third shape (see "Audit findings"
below for the full writeup, including the DRY fix that came with it).

### Liskov Substitution

Every `Policy`/`ToolPolicy`/`ModelPolicy` subclass returns the same
decision shape its base class promises (`PolicyDecision`/`ToolDecision`/
`ModelDecision`), and every guard only ever calls the abstract interface
— never `isinstance`-checks for a specific subclass to special-case
behavior. `SensitiveDataPolicy`/`SensitiveDataToolPolicy` (the wrappers
added for content scanning) both hold this precisely: `evaluate()` still
returns a `PolicyDecision`/`ToolDecision`, `redact()`/`redact_arguments()`
still return the same shapes their base classes return. Any of them can
replace their base class or one another with zero caller-side changes —
that's the entire mechanism `RedactingPolicy`, `BudgetPolicy`, and
`SensitiveDataPolicy` all lean on: wrap a base, preserve its contract
exactly, add one behavior.

### Interface Segregation

`Policy`/`ToolPolicy`/`ModelPolicy` each expose one abstract method
(`evaluate`/`evaluate`/`resolve`) and give every other method a working
default — a policy author who only cares about allow/deny never has to
implement `redact()`, `to_filter()`, `fallback_chain()`, or
`record_usage()` just to satisfy the ABC. This is the main reason adding
a new policy (including the `SensitiveData*` ones) is a small diff instead
of a large one.

**Deliberate tradeoff, not fixed:** `AuditSink` has one interface with
`write()` abstract and `all_entries()`/`tail()`/`query()` given permissive
defaults (`NotImplementedError`) rather than being split into a minimal
write-only ABC and a separate queryable-sink ABC. `OpenTelemetryAuditSink`
is forced to "inherit" three methods it structurally can't support (spans
live in the tracing backend, not in this process). A stricter ISP reading
would split these into two ABCs so a type checker could tell you
up front whether a given sink supports reads. Kept as one ABC on purpose:
the split would ripple through every guard's type hints for a benefit
that's already covered by tests (`test_reads_are_not_supported_since_...`)
and a clear docstring/README callout. Revisit if a second write-only sink
shows up and the asymmetry starts costing more than one paragraph of
documentation.

### Dependency Inversion

Every guard depends on an abstraction (`Policy`/`ToolPolicy`/`ModelPolicy`/
`AuditSink`), never a concrete implementation — concrete policies and
sinks are constructor-injected, which is what makes "swap in your own
Postgres-backed policy" a documented, tested capability rather than a
hypothetical one. `marshal_ai.integrations` depends on the `ModelGuard`
*façade*, not on `ModelPolicy` directly — which is correct, not a
violation, because `ModelGuard` is itself the abstraction boundary the
SDK-patch layer is meant to sit behind; reaching past it to a raw
`ModelPolicy` would mean re-implementing audit-writing and
`ModelCallDenied`-raising in the integration layer too.

## Where `marshal_ai.sensitive` sits, and why

**Decision point — a fourth top-level module, not folded into
`policy.py`/`tools.py`.** `SensitiveDataPolicy` wraps a `Policy` and
`SensitiveDataToolPolicy` wraps a `ToolPolicy`, so the obvious first
instinct is to put them next to `RedactingPolicy`/`RedactingToolPolicy` in
`policy.py`/`tools.py` respectively. That's not possible without a
circular import: `sensitive.py` needs `SensitiveDataScanner` in both
wrappers, and the scanner has nothing to do with retrieval or tools
specifically, so it can't live inside either of those files without one
of them importing the other's wrapper. Putting the scanner *and* both
wrappers in one new module that sits one layer above `policy.py`/
`tools.py`/`audit.py` (imports from them, is never imported by them)
resolves it cleanly — the same layering relationship
`marshal_ai.integrations` already has with `models.py`.

**Decision point — redact-only at the retrieval layer, block-or-redact at
the tool layer.** This isn't an inconsistency, it's a structural fact
about what each `evaluate()` can see. `Policy.evaluate(principal,
metadata)` only ever receives document *metadata* — by the time
`SensitiveDataPolicy.redact()` sees actual content, the ACL decision to
allow the document has already been made, and there's no interface point
left to retroactively deny it. `ToolPolicy.evaluate(request)` receives the
full `ToolCallRequest`, arguments included, *before* the decision is
final — so a hardcoded credential there can still flip the decision to
deny. Same asymmetry shows up a third time in
`marshal_ai.integrations`: the SDK-patch wrapper can block a prompt before
the network call (nothing has happened yet), but a completion is
scanned audit-only (the call already succeeded — there's nothing left to
prevent, only to flag).

**Decision point — `audit_sink=None` really means "don't audit," not
"audit somewhere invisible."** Every guard (`RetrievalGuard`/`ToolGuard`/
`ModelGuard`) defaults a missing `audit_sink` to a fresh
`InMemoryAuditSink()`, so "you get an audit trail for free" holds even
with zero configuration. `SensitiveDataPolicy`/`SensitiveDataToolPolicy`
deliberately do *not* follow that default. If they silently created their
own private `InMemoryAuditSink()` when none was passed, findings would
be recorded somewhere the caller has no handle to and can never read back
— strictly worse than not recording them, since it looks like there's an
audit trail when there functionally isn't one. Both classes' docstrings
say explicitly: pass the *same* sink you gave the guard.

**Decision point — findings store `"DETECTOR:count"`, never the matched
text.** This mirrors a rule already in the codebase before this feature
existed: `ToolCallEntry.arguments` are always the *redacted* view (see
its docstring in `tools.py`), specifically so the audit log itself can't
leak what a redaction rule was meant to hide. `SensitiveDataEntry.findings`
follows the same discipline for the same reason — the audit trail that
exists to catch a leaked secret must not become a second copy of it.

**Decision point — regex detectors, not an LLM judge.** Covered in depth
in `sensitive.py`'s module docstring and `ideas.md`; restated briefly
here since it's a real SOLID-adjacent point too: an LLM-based detector
would make `SensitiveDataScanner` depend on network I/O, an API key, and
non-determinism, none of which the rest of Marshal's policy layer
depends on — every existing `Policy`/`ToolPolicy`/`ModelPolicy` is a
pure, synchronous, local decision. Keeping detection regex-based keeps
`marshal_ai.sensitive` consistent with that shape (and closes off the
"a prompt-injected document argues its own scan result" attack the
`ideas.md` "who governs the governor" section already worries about for
tool approval).

## Where `ResidencyPolicy`/`RetentionPolicy` sit, and why

**Decision point — same file as `BudgetPolicy`, not a new module.**
`marshal_ai.sensitive` above got its own module specifically to avoid a
circular import (the scanner is needed by wrappers of two different base
types, `Policy` and `ToolPolicy`, in two different files). Neither new
class here has that problem: both wrap `ModelPolicy` only, need nothing
`models.py` doesn't already define, and sit next to their nearest sibling
in shape — `BudgetPolicy` — for the same reason `RedactingPolicy` lives
next to `AttributePolicy` rather than off in its own file. Different
inputs led to the opposite, and equally deliberate, placement decision
from `sensitive.py`'s.

**Decision point — context, not principal attributes.**
`ModelCandidate.requires_attribute` already gates candidates on the
*principal's* identity (role, clearance, region). Jurisdiction and
required retention ceiling are deliberately read from
`request.context` instead, because they're facts about the *data in this
specific call*, not the caller — the same service-account principal
legitimately makes one call carrying EU-governed data and the next
carrying India-governed data, and encoding "alice can touch EU data" as a
static attribute would be both wrong (it isn't about alice) and stale the
moment her employer's data footprint changes.

**Decision point — search the base's full qualifying list, not just its
top pick.** The first version of `ResidencyPolicy` only checked whether
`base.resolve()`'s single preferred candidate was jurisdiction-compliant,
and denied outright if not — even when a candidate further down the
base's own `fallback_chain` (already qualified for this principal) would
have passed. Caught by actually running the example script end-to-end,
not by a test in isolation: with two unconditional candidates
(`eu-deployment`, `in-deployment`), a jurisdiction-`"IN"` call always
failed, because `AllowlistModelPolicy` always prefers `eu-deployment`
first regardless of jurisdiction. Fixed with a shared `_first_compliant`
helper: gather `[base's top pick, *base's fallback_chain]`, filter to
compliant candidates, promote the first survivor. `RetentionPolicy` was
written after this fix and shares the same helper from the start, rather
than risking the same bug a second time.

**Decision point — two composable policies, not one combined
"compliance" policy.** Geography and retention are independent facts
about the same deployment (a deployment can be in the right country and
still retain data too long, or vice versa), so they're two single-purpose
wrappers — `RetentionPolicy(ResidencyPolicy(base, ...), ...)` — matching
the existing SRP discipline (`RiskTierPolicy` doesn't also redact;
`BudgetPolicy` doesn't also risk-tier) rather than one class with two
constructor dicts and an implicit AND between them.

**Decision point — the mechanism is part of the audit record, not just
the outcome.** The first version of `ResidencyPolicy` recorded jurisdiction
and resolved deployment but not *why* that pairing was lawful — a gap
between what this same release's cross-border blog post explicitly
argues the audit trail needs ("the jurisdiction, the mechanism, and the
endpoint — not just the outcome") and what the code actually recorded,
caught on a second pass rather than at first review. Fixed by changing
`allowed_by_jurisdiction`'s value type from a bare set of deployment names
to `dict[deployment, mechanism]`, so `resolve()`'s reason string always
states which adequacy decision/SCC/BCR made a specific transfer lawful,
not just that one was found.

**Decision point — what's deliberately not enforced.** Confirming a
vendor's downstream retention/deletion actually matches what a mechanism
or a `deployment_retention_days` entry promises; sub-processor
authorization chains beyond deployment-naming discipline; data-subject
erasure once data has left Marshal's own call boundary; AI-specific
regulatory classification (EU AI Act-style risk tiers) rather than
data-transfer law. None of these have a call-time signal Marshal could
check even in principle — see `ideas.md`'s v0.7 entry and the
jurisdiction-aware risk-tiering backlog item for the reasoning on each,
rather than silently pretending the feature covers more ground than it
does.

## Where `CircuitBreakerPolicy` sits, and why

**Decision point — library vs. platform, made concrete.** Asked directly
whether Marshal is becoming a "governance platform" and whether it tracks
LLM call failures/latency. The honest answer, checked against the code
rather than asserted: every policy through v0.7 — `ResidencyPolicy`,
`RetentionPolicy`, `RiskTierPolicy`, `AllowlistModelPolicy` — decides from
static config plus the current request only. `BudgetPolicy` was the one
exception (spend tracked over time). `CircuitBreakerPolicy` is the second:
its decision depends on accumulated runtime history (recent failures), not
just what's in the request. That's the actual dividing line between
"library" and "platform" — a feedback loop, not a wider set of static
policy shapes — and it's still a library by that definition: no central
config store, no cross-process state, no dashboard. Policy-as-config
(shipped in v0.12, see below) is the other missing piece, not this one.

**Decision point — `record_outcome` as a new, separate reporting path,
not folded into `record_usage`.** `record_usage` is called only on
success and answers "what did this cost." `record_outcome` is called on
every attempt and answers "did this work, and how fast." Conflating them
would force every existing caller of `record_usage` to also start
reporting reliability data it doesn't have, or force `record_usage` to be
called on failure too (with token counts that don't exist for a call that
never returned). Two questions, two methods, matching the existing
`ModelCallEntry`/`ModelUsageEntry` split (routing decision vs. reported
cost) rather than growing either into a catch-all.

**Decision point — a trailing time window, not an open/half-open/closed
state machine.** The textbook circuit-breaker pattern has three states
and an explicit recovery probe. A plain trailing window (count recent
failures, prune anything older than `window_seconds`) gets the same
practical property — automatic recovery once the underlying problem
stops recurring — for a fraction of the code and no separate probe logic
to get wrong. Simpler and sufficient, not a shortcut: documented here so
a future reader doesn't mistake the missing state machine for an
oversight.

**Decision point — reused `_first_compliant`, didn't build a fourth
copy of the same search.** `ResidencyPolicy` and `RetentionPolicy` already
share this helper for "search the base's top pick plus its fallback
chain for the first candidate satisfying one more constraint."
`CircuitBreakerPolicy` needed the exact same shape (find a non-tripped
candidate) — reusing it instead of writing a third near-identical
loop is the same DRY call this project already made once in this file's
own SOLID audit (the `integrations` wrapper consolidation).

**Decision point — governance denials never count as failures.**
`record_outcome` is only ever called after `ModelGuard.resolve()` already
returned "allow" and a real call was attempted — never on a
`ResidencyPolicy`/`RetentionPolicy`/base-policy denial. Getting this
wrong would mean a deployment correctly, heavily governed (denying most
calls for compliance reasons) looks identical in the circuit breaker's
eyes to one that's actually broken — exactly the kind of conflation this
project's existing tradeoffs section already warns against elsewhere
(sensitive-data findings vs. matched text, budget vs. risk tier).

**Decision point — real exception classes, verified, not guessed.**
`_classify_error` in `marshal_ai.integrations` checks `isinstance` against
`openai`/`anthropic`'s actual exception hierarchy (both installed in the
dev environment and inspected directly — `APITimeoutError` subclasses
`APIConnectionError`; `RateLimitError`/`InternalServerError` subclass
`APIStatusError` — checked via `__mro__`, not assumed from naming
convention), checking more specific subclasses before their parents.
Matches the same discipline the `claude-api`-style "never guess SDK
usage" rule already applies elsewhere in this project's own tooling.

## Where `RateLimitPolicy`/`RunawayAgentPolicy`/`JurisdictionalRiskTierPolicy` sit, and why

**Decision point — three separate classes, not one combined "protect the
agent" policy.** Rate limiting (call frequency), runaway-loop detection
(call repetition), and jurisdictional oversight (risk classification) are
three independent facts about a call, the same way residency and
retention are two independent facts about a model deployment. Collapsing
them into one class with three constructor arguments would repeat the
exact anti-pattern this project has already rejected twice (Residency vs.
Retention as `ModelGuard.py`'s `ResidencyPolicy`/`RetentionPolicy`, kept
separate on purpose; `RiskTierPolicy` not also redacting). Composability
over a combined config surface, consistently.

**Decision point — `RunawayAgentPolicy`, not a second `CircuitBreakerPolicy`.**
Both are "circuit breaker"-shaped in the loose sense (something trips,
something gets denied), which is exactly the trap: `CircuitBreakerPolicy`
trips a *model deployment* on *failure rate*; `RunawayAgentPolicy` trips
a *principal* on *identical-call count*, and can trip on a loop that
succeeds every single time — the two trigger conditions aren't
substitutable, and reusing the name would suggest they were. Naming them
apart was a deliberate choice made explicit in `ideas.md` before writing
either the class or its tests, not discovered as a bug afterward.

**Decision point — no self-healing timer for `RunawayAgentPolicy`,
unlike `CircuitBreakerPolicy`.** A model deployment recovering from a
transient failure and a runaway agent loop are different kinds of
problem: the deployment's failure rate genuinely can drop on its own
(the outage ends), but a broken termination condition doesn't fix itself
just because a clock ran out — the bug is still there. Requiring an
explicit `reset(principal_id)` reflects that the two failure modes need
different recovery models, not that one class is more "finished" than
the other.

**Decision point — `RateLimitPolicy` counts every attempt, including
ones the base policy denies.** A rate limit is answering "how often is
this principal trying," not "how often are they succeeding" — counting
only allowed calls would let a principal being denied for an unrelated
reason retry indefinitely without ever tripping the rate limit, which
defeats the backstop's actual purpose (protecting against both malicious
abuse and an agent's own bugs, neither of which politely stops retrying
just because the reason for denial is different from rate limiting).

**Decision point — `JurisdictionalRiskTierPolicy` is monotonic, and has
no fail-closed default.** Two asymmetric choices, both deliberate.
Monotonic (can only tighten a base decision, never loosen it) for the
same non-bypassable-fallback reason `AllowlistModelPolicy.fallback_chain`
already establishes: a jurisdiction overlay must never be usable to
argue a stricter base policy down to something more permissive. No
fail-closed default when jurisdiction is absent — unlike `ResidencyPolicy`,
where a missing jurisdiction always denies, because a cross-border
transfer is *always* either lawful or not, but AI-Act-style
classification may genuinely not apply at all outside a jurisdiction
that regulates it; treating "no jurisdiction context" as automatically
high-risk would manufacture oversight requirements the law never
actually imposed.

**Decision point — added `context` to `ToolCallRequest`, not a
`ToolCallRequest`-specific mechanism.** `ModelCallRequest.context`
already existed for exactly this purpose (jurisdiction, in
`ResidencyPolicy`/`RetentionPolicy`). Rather than inventing a
tool-call-specific way to pass "extra facts about this call that aren't
part of the principal's identity," `ToolCallRequest` grew the identical
field, and `ToolGuard.call()` grew the identical `context=` parameter
`ModelGuard.resolve()` already has. One concept, one shape, two guards.

## Adding Google GenAI support, and correcting a wrong claim

**Decision point — verify a framework-compatibility claim before trusting
it, not after.** Asked to make Marshal easy to wrap over frameworks like
ADK, the honest first step was checking whether the existing README claim
("ADK... gets model governance transparently") was actually true, not
assuming a fix was needed or that the claim already held. It wasn't true
for ADK's default path: `LlmAgent` calls Gemini through `google-genai`
directly, confirmed by reading ADK's own source and docs rather than
inferring from its README prose. The same verify-don't-assume discipline
already applied to the openai/anthropic exception hierarchy in v0.8
applies here to a bigger claim: which SDK a framework actually calls
under the hood isn't something to guess from a framework's marketing
description of itself.

**Decision point — prompt-text extraction became per-provider, not just
completion-text and usage.** Through v0.9, only completion-text
extraction and usage-field-names differed per provider; prompt scanning
was hardcoded to read `kwargs["messages"]`. `google-genai`'s `contents=`
kwarg has a structurally different shape (`Content`/`Part` objects, not
role/content dicts) that a `messages`-shaped extractor can't parse at
all — so `_PROVIDER_ADAPTERS` grew a third leg, and `_scan_prompt_or_raise`
now takes an injected extractor instead of a hardcoded one. This is the
same "add one entry to the table, not a new copy-pasted wrapper" shape
the original `_make_wrapper`/`_PROVIDER_ADAPTERS` refactor from the v0.6
SOLID audit already established — extended for a third differing
concern, not re-invented.

**Decision point — error classification branches by provider, not one
shared check.** openai and anthropic happen to expose identically-named
exception classes, which is what let v0.8's `_classify_error` use one
code path for both. `google-genai` doesn't share that shape at all — no
`RateLimitError`/`APITimeoutError` classes, just `APIError`/`ClientError`/
`ServerError` with a `.code` HTTP status, plus raw transport exceptions
(`httpx`/`requests`) for network-level failures that never reach the
GenAI-specific error classes at all. Forcing one shared classifier across
all three would have meant either silently misclassifying Google failures
as "other" or writing speculative `isinstance` checks against class names
that don't exist. Two classifier functions, correctly scoped to what each
SDK actually raises, beats one classifier pretending three SDKs share a
hierarchy they don't.

## Where shadow mode (`GuardMode`) sits, and why

**Decision point — `GuardMode` lives in `policy.py`, next to `Principal`.**
Shadow mode is a cross-cutting concern (`RetrievalGuard`/`ToolGuard`/
`ModelGuard` all take `mode: GuardMode`), so it needs a home none of the
three surfaces has to import another surface's file to reach — the same
reasoning that already put `Principal` in `policy.py` rather than in
whichever surface happened to be built first (see "why `policy.py` is its
own file," above). `GuardMode` is a bare `Literal["enforce", "shadow"]`
type alias, not a class hierarchy — no new ABC, nothing to subclass.

**Decision point — `outcome`/`allowed_ids`/`denied_ids` keep their
enforce-mode meaning in shadow entries; `shadow: bool` is the only new
enforcement-status flag.** The alternative (a parallel `would_deny: bool`,
`would_be_outcome: str`, etc., leaving `outcome` always reflecting "what
actually happened") was considered and rejected: it would silently break
`AuditSink.query(denied_only=True)` and the CLI's `!`/otel `ERROR`-status
logic for shadow-mode denials, which is exactly the audience shadow mode
exists to serve — someone trying to answer "what would enforcement have
blocked" needs that to fall out of the *existing* denial-flagging
machinery, not a second, unwired-up flag they have to know to check
separately. Reusing the vocabulary means "would deny" and "did deny" are
literally the same signal, disambiguated only by the new `shadow` flag —
and every existing consumer (`is_denied()`, the CLI, `otel.py`'s
`_write_tool_call`/`_write_model_call`) already handles it correctly with
*zero* changes to any of those three files.

**Decision point — `ModelGuard.resolve()` returns a model, not `None` or
a sentinel, when shadow + denied.** Considered three options: raise
anyway (rejected — spec requires never raising in shadow), return `None`
(rejected — every caller's very next line is "call this model with a real
client"; `None` just moves the crash one line downstream and loses the
"zero risk to prod" property that's shadow mode's entire point), or
compute a real fallback (chosen). `ModelGuard._shadow_fallback_model`
prefers the wrapped policy's own `fallback_chain()` — which can be
non-empty even under a denial (e.g. `BudgetPolicy.fallback_chain`
forwards to its base regardless of tracked spend) — and only falls back
to the bare `logical_name` itself when the policy has genuinely nothing
configured, mirroring `AllowAllModels`'s own last-resort behavior. This
means a shadow `ModelCallEntry` can have `outcome == "deny"` *and* a
non-`None` `resolved_model` at the same time — a new state that never
occurs in enforce mode, documented directly in `ModelCallEntry`'s
docstring so it doesn't read as an inconsistency later, and exactly the
fact `marshal_ai.reports` has to account for (see below): a shadow
"deny" is not a blocked transfer, it's a transfer to a fallback.

**Decision point — `ToolGuard`'s audited `arguments` field stays redacted
in shadow mode; only field *names* (`would_redact_fields`) are added, not
raw values.** Unlike `RetrievalGuard` (which hands the *caller* fully
unredacted content in shadow — there was never any other audience for
that data), the `ToolCallEntry.arguments` field is audit-trail-facing
content whose redaction exists to protect whoever reads the log/approval
prompt, not to enforce anything against the caller. Toggling that off in
shadow mode would mean a policy author who wrote `ArgumentRedaction(
name="ssn", ...)` to keep SSNs out of the audit trail would suddenly get
them in the audit trail the moment they tried shadow mode first — the
opposite of "zero risk." Kept identical to enforce; `would_redact_fields`
(names only) is the new, additive signal for "here's what a stricter/
attribute-gated approver would not have seen."

**Decision point — the two new `AuditEntry` fields (`shadow`,
`would_redact_fields`) live directly on the base dataclass in `audit.py`,
not on a subclass.** The first implementation grew these on
`RetrievalGuard`'s side of a branch boundary that (deliberately, for that
branch) kept `audit.py` off-limits: `retrieval.py` defined a
`RetrievalAuditEntry(AuditEntry)` subclass — same fields, same order,
two new ones with defaults — and called `register_entry_type("retrieval",
RetrievalAuditEntry)` at its own import time, overriding the base
registration `audit.py` performs for plain `AuditEntry`. This was a
legitimate, LSP-safe use of the self-registering-discriminator mechanism
(`RetrievalAuditEntry` is-a `AuditEntry`, same field order, `to_dict()`
inherited unchanged) and the full test suite passed unmodified against
it. A pre-merge review caught the real cost anyway: a plain
`AuditEntry(**shadow_dict)` raises `TypeError` on the two new keys, so
decoding a shadow "retrieval" JSONL/SQLite line only worked because
`marshal_ai/__init__.py` happens to import `retrieval.py` (which
overrides the registry) before any decode runs — correctness riding on
import ordering that a future refactor of `__init__.py` could silently
break, for no remaining reason once `audit.py` was back on the table at
integration time (the parallel-branch constraint that motivated the
subclass no longer applied once every branch merged into one tree).
Fixed by moving `shadow`/`would_redact_fields` directly onto `AuditEntry`
in `audit.py` and deleting `RetrievalAuditEntry` and its re-registration
entirely — `RetrievalGuard` now writes a plain `AuditEntry`, strictly
simpler, with no registry-override, no import-order dependency.
`RetrievalAuditEntry` was never exported, so nothing external depended on
the name. The re-registration *pattern* itself (overriding an
already-registered kind with a strict superset schema) remains a
legitimate, documented escape hatch for a future case where a field
genuinely can't be added to the base file — just not the right call here
once that constraint was lifted.

## Where the vector-store adapters (`marshal_ai.adapters`) sit, and why

**Decision point — the adapters live in the library, not as separate
`marshal-chroma` / `marshal-langchain` packages.** Each adapter is a
single small factory function with *zero import-time dependency* on its
backend — `from_chroma_collection` / `from_langchain_retriever` only ever
call methods (`.query(...)`, `.invoke(...)`) on an object the caller
already constructed and passed in, so `import marshal_ai.adapters`
succeeds with neither `chromadb` nor `langchain_core` installed, and
having one installed never drags in the other. That removes the usual
reason to split an integration into its own distributable (avoiding a
hard dependency), so a separate package would be pure release/versioning
overhead for two functions. They stay guarded behind optional extras
(`[chroma]`, `[langchain]`) and reached via the `marshal_ai.adapters`
submodule rather than re-exported from the top-level namespace — the same
pattern already used for `marshal_ai.otel` and `marshal_ai.integrations`,
keeping the core `import marshal_ai` free of any optional-backend import.

**Decision point — Chroma's raw `distance` maps straight onto
`Document.score`, never renormalized to a 0–1 "similarity."** That
mapping depends on the collection's configured distance space (l2/
cosine/ip), which Marshal has no way to know from the outside — inventing
a normalization would be a confident-looking number with no actual basis,
exactly the kind of lie-dressed-as-convenience this project's other
tradeoffs sections already reject (see `ResidencyPolicy`'s mechanism
field, `SensitiveDataEntry.findings`'s no-raw-secrets rule). `score`
isn't load-bearing for any governance decision, so leaving it as the raw,
honestly-labeled distance is strictly better than a plausible-looking
guess.

**Decision point — the Chroma adapter accepts `filter=` by that exact
name, reusing `RetrievalGuard`'s existing pushdown extension point
(`_accepts_filter`) rather than adding a new one.** `GroupPolicy.
to_filter` already knows how to produce a native filter dict for any
retriever whose signature accepts `filter=`; the Chroma adapter just
needs to accept that keyword and translate it into a `where` clause —
OCP in the sense the codebase already established (extended behavior via
the existing extension point, zero changes to `RetrievalGuard`, `Policy`,
or `Document`).

## Where `marshal_ai.mcp` sits, and why

**Decision point — client-side proxy, not server-side middleware.** MCP
tool governance could live on either side of the connection: a
`GovernedMCPSession` wrapping the client's `ClientSession` (what got
built), or middleware inside an MCP server that checks policy before
dispatching to a registered tool handler. Client-proxy was chosen first
because it matches every other Marshal guard's shape exactly — `ToolGuard`
wraps the *caller's* access to a callable, `RetrievalGuard` wraps the
caller's access to a retriever, `ModelGuard` resolves before the caller's
own SDK call — Marshal governs from the consumer's side of a boundary
throughout, never by modifying the thing being called. It also composes
with zero coordination: any MCP server, first-party or third-party,
already-deployed or not, gets governed the moment a client wraps its
session, with no server-side deploy required. The real limitation, stated
plainly: a client that doesn't route through `GovernedMCPSession` bypasses
governance entirely — this only works when the governance owner also
controls the client. A server operator who can't trust every client to
opt in needs server-side middleware instead, enforcing policy regardless
of which client connects; that's real, different work (a different
extension point in `mcp.server`, not just a different constructor
argument) and is intentionally not this pass's scope.

**Decision point — reuses `ToolGuard` itself, not just its types.**
`ToolGuard.call()` is synchronous; `mcp.ClientSession.call_tool` is a
coroutine function — a real mismatch, not a cosmetic one. Rather than
duplicating `ToolGuard.call()`'s evaluate -> redact -> (approve) -> audit
sequence in `mcp.py` (which would create exactly the kind of sync/async
copy this codebase's own DRY discipline elsewhere warns against),
`GovernedMCPSession.call_tool` builds a `ToolGuard` per call with
`tool=lambda **kw: self._session.call_tool(name, kw, ...)`. Calling a
Python `async def` function never runs its body — it only constructs a
coroutine object — so `ToolGuard.call()` runs its entire existing,
unmodified code path synchronously, and on the allow/approved branch its
final line (`return self._tool(**arguments)`) merely constructs the real
`call_tool` coroutine, which `GovernedMCPSession` then awaits itself. On
the deny/declined branch, `ToolGuard.call()` raises before ever reaching
`self._tool(...)`, so that coroutine — and the real request it
represents — is never constructed at all, not just uncalled. Verified
under `-W error::RuntimeWarning` (no "coroutine was never awaited" leak
on the deny path) before wiring it into `mcp.py`.

**Decision point — deny raises `ToolCallDenied`, not an `isError=True`
`CallToolResult`.** MCP's own `CallToolResult.isError` shape already means
something specific: the tool *ran* and failed. Reusing it for "governance
blocked this before the server ever saw it" would collapse two different
facts into one shape — exactly the conflation `CircuitBreakerPolicy`'s own
docs already reject elsewhere ("a governance denial is never a recorded
failure"). Raising `ToolCallDenied` — the same exception type `ToolGuard`
and `ModelGuard` already raise on their own denials — keeps one exception
type meaning "Marshal said no" across every surface. A framework loop that
specifically wants `isError` results instead of exceptions can translate
`ToolCallDenied` at its own boundary in one line; not baked into Marshal.

**Decision point — principal bound at session construction, not per
call.** `ToolGuard.call(principal, ...)` takes a principal per call
because it wraps a bare Python callable with no session concept at all.
An MCP `ClientSession` already *is* a session scoped to one connected
identity, so `GovernedMCPSession(session, principal, ...)` binds it once,
matching what the thing being wrapped actually is instead of re-deriving
an already-fixed fact on every call.

**Decision point — `risk_tiers: dict[tool_name, tier]` at the session
level, not inside `ToolPolicy`.** `RiskTierPolicy` maps *tier -> outcome*;
it has no notion of tool names, by design (a `ToolGuard` is already
scoped to one named tool, so this mapping never needed to exist before).
An MCP session exposes many tools, named only at call time, so
`GovernedMCPSession` owns the *tool name -> tier* half of the lookup
itself (with a `default_risk_tier` fallback and a per-call override), and
hands the resolved tier to whatever `ToolPolicy` the caller supplied —
composable with `RiskTierPolicy`, `JurisdictionalRiskTierPolicy`,
`RateLimitPolicy`, `RunawayAgentPolicy`, `SensitiveDataToolPolicy`,
`RedactingToolPolicy`, or any stack of them, unchanged.

**Note on `marshal_ai.mcp`'s own dependency posture:** `ClientSession`/
`CallToolResult`/`ListToolsResult`/`ProgressFnT` are imported only under
`TYPE_CHECKING` — `GovernedMCPSession` duck-types whatever `session`
object it's given (`.call_tool(...)`, `.list_tools(...)`, forwarded via
`__getattr__`), the same way `ToolGuard` never imports whatever library a
wrapped callable came from. `import marshal_ai.mcp` succeeds with no `mcp`
package installed; the `mcp` extra exists purely for whoever wants to
actually *construct* a real `mcp.ClientSession` to hand it.

## Where `SQLiteAuditSink`/`marshal_ai.reports` sit, and why

**Why SQLite (stdlib) over a DB dependency.** The brief was durable +
queryable + indexed + survives-restart, without adding a dependency to a
library whose whole pitch is "governance without infra." `sqlite3` is
bundled with every CPython install, gives real transactions and real
indexes, and is a file you can hand to `sqlite3 audit.db` or ship to S3 —
versus adding `psycopg2`/an ORM/a message-queue client for a feature
whose target user is often a solo dev or a mid-size team that doesn't
want to stand up Postgres just to get a compliant audit log. The
`AuditSink` ABC already makes this a non-decision for anyone who *does*
want Postgres/a SIEM: implement `AuditSink` yourself against it.
`SQLiteAuditSink` is the "zero-infra but actually durable" rung between
`JSONLAuditSink` and "bring your own production DB," not a claim that
SQLite is the right choice at every scale.

**Hash-chain design.** Each row stores `(kind, timestamp, principal_id,
data, prev_hash, hash)` where `data` is the entry's own canonical JSON
(`json.dumps(entry.to_dict(), sort_keys=True)` — the same convention
`JSONLAuditSink` already uses for its on-disk lines) and `hash =
sha256(f"{prev_hash}:{data}")`. Chosen over a Merkle tree or a
signed-log scheme because the threat model here is specifically "did
someone edit the SQLite file after the fact," which a linear chain
answers exactly as well as a tree would while being trivial to verify
sequentially and trivial to reason about — no batching, no
tree-balancing edge cases. `GENESIS_HASH = "0" * 64` gives `verify()` a
fixed anchor for record #1 instead of trusting it unconditionally.
`verify()` returns a structured `ChainVerificationResult` (not an
exception) so a report generator can state chain integrity as a fact
without a `try/except` — and stops at the *first* break, since everything
chained after a broken link inherits its own unprovable-ness. Known,
stated limitation: this proves tamper-evidence for a single
`SQLiteAuditSink` file; it does not protect against an attacker with
full read/write access replaying an *entire* forged chain from
`GENESIS_HASH` — that needs an external anchor (e.g. periodically
publishing the latest hash somewhere append-only), out of scope here.

**Report shape.** `reports.py` reads every entry via `entry.to_dict()` +
its `kind` string, not via `isinstance` against concrete entry classes
from `models.py`/`tools.py`/`audit.py` — mirrors `marshal_ai/cli.py`'s
`_summarize`, and keeps a report generator depending on the `AuditSink`/
`AuditableEvent` contract only. Two report functions instead of one
combined "compliance report" — different aggregation dimensions
(jurisdiction/mechanism/controller vs. period/surface/outcome), different
consumers (DPO doing transfer accounting vs. whoever owns the Article 12
record), and forcing them into one shape would mean one query parameter
set doing two unrelated jobs. Both are pure functions of `AuditSink.
query()`'s output — no writes back to the sink, no hidden state — so they
compose with any sink, including ones that don't exist yet.

**Why the reports exclude shadow-mode entries from every real
enforcement figure — see "Audit findings," M2 below for the full failure
scenario this closes.** In short: `cross_border_data_flow_report` and
`article12_activity_record` were originally written and tested against
`marshal_ai/models.py`/`marshal_ai/tools.py` alone, before shadow mode
existed in the same tree. Once both landed together, a shadow-mode
"deny"/"require_approval" entry — which never actually blocks anything;
shadow mode's entire contract is that the real action always proceeds —
would have been silently counted as a real denial/approval-requirement.
Neither this module's own tests nor shadow mode's own tests could catch
this alone; it only appears once both features are exercised against the
same audit trail, which is exactly the scenario both features' own docs
recommend (share one sink across every guard). Fixed by reading each
entry's `shadow` flag and routing shadow entries into a fully separate
accounting that never touches the real figures — see `ActivityRecord`/
`CrossBorderDataFlowReport`'s docstrings for the field-level shape.

## Where `marshal_ai.config` (policy-as-config) sits, and why

**Decision point — a translation layer, not a rules engine.** The obvious
precedent is OPA/Rego: policies in their own language, evaluated by their
own engine. Rejected for Marshal because a second evaluator is a second
place governance logic lives, and the two can drift. A Rego-style rule
that the Python classes can't express would mean either a silent gap
(config says deny, nothing enforces it) or a parallel implementation that
has to be kept identical to the real one forever. `load_policies` instead
deserializes into the exact `AttributePolicy`/`RiskTierPolicy`/etc.
objects code would construct, and lets each constructor's own validation
(`AttributePolicy`'s `default` check, `RiskTierPolicy`'s outcome check)
do the rejecting. Constructor `ValueError`/`TypeError`s are re-raised as
`PolicyConfigError` with the config path prefixed, still the
constructor's check doing the work. The cost is stated plainly: config
can only express what the classes already can. That is the point, not a
limitation to grow out of.

**Decision point — `base` + ordered `wrappers`, not arbitrary nesting.**
Every non-base policy in Marshal is a decorator taking `base` as its
first argument, so a chain is the only shape there is. A flat list reads
top-to-bottom in a diff (what a compliance reviewer actually looks at)
where a nested `{type: residency, base: {type: budget, base: ...}}` tree
gets deeper with every rule. Order is first-wraps-base, matching hand
nesting. Each registry entry records its role, so a wrapper in the base
slot, or a base in `wrappers`, fails with a message saying which slot it
belongs in rather than a `TypeError` about a missing argument.

**Decision point — what stays Python-only.** Anything that's an object or
callable rather than data: custom `SensitiveDataScanner` detector regexes,
`audit_sink` instances, `ApprovalHandler`s, custom policy subclasses.
Detector regexes were the closest call. A list of strings is easy to put
in YAML, but it's arbitrary pattern logic authored outside code review,
i.e. a DSL by another name. Narrowing *which* built-in detectors block a
tool call (`block_detectors`) is supported, since that's a subset of
known names validated against `DEFAULT_DETECTORS`. Custom policy types
are reachable through `register_builder` (the same self-registering idiom
as `register_entry_type`), so the escape hatch is code, reviewed as code.

**Decision point — fail closed on every malformed input, and one
exception type.** A governance config that half-loads is worse than one
that doesn't load: the operator believes rules are in force that aren't.
So every problem raises before anything is returned. Unknown keys are
rejected rather than ignored, because a typo'd `wrapers:` that's silently
skipped drops every wrapper. Everything surfaces as `PolicyConfigError`
so a deployment can catch one type at startup and refuse to boot. An
absent surface key is the one non-error: it returns `None`, not an
allow-all stand-in, so the caller decides what absence means.

**Decision point — YAML optional, `safe_load` only.** JSON is stdlib and
always available. PyYAML is a `[config]` extra imported only when a
`.yaml`/`.yml` file is loaded, keeping the core install dependency-free.
A missing PyYAML raises `PolicyConfigError` with the install command.
`yaml.safe_load` is used unconditionally: a policy file is exactly the
kind of input that passes through many hands, and `yaml.load` can
construct arbitrary Python objects. An optional `version: 1` key is
reserved so a future incompatible schema change is rejected loudly
rather than misparsed.

**Audit findings (pre-commit pass).** Two contract violations, both
fixed with regression tests: (1) a missing or non-UTF-8 config file
escaped as a raw `FileNotFoundError`/`UnicodeDecodeError`, breaking the
"catch one type" promise above; file reads now go through one helper that
wraps `OSError`/`UnicodeDecodeError`. (2) `version: true` and
`version: 1.0` passed `version != 1` because `True == 1 == 1.0` in
Python; the check now requires an actual `int`. Also corrected a comment
in `examples/policies.yaml` that claimed the base tool policy already
denies `employment_decision` (it allows it; the EU wrapper is what adds
approval).

## Where `marshal_ai.flow` (the lethal-trifecta gate) sits, and why

**Decision point — session state, not per-call rules.** Every existing
policy judges one call. The attacks that actually leaked data from agents
in 2025-2026 are made of individually normal calls; what's wrong is the
combination one session accumulated (private data + untrusted content +
an outbound channel). So the gate needs state across calls *and* across
surfaces. That's the first Marshal feature where one surface's policy
(`FlowLabelingPolicy`, retrieval) feeds another's (`LethalTrifectaPolicy`,
tools) through a shared object (`FlowTracker`). The tracker is explicit
and injected, not a global, so two agents never share taint by accident.

**Decision point — declared labels, not detection.** A document is
untrusted because of where it came from (a ticket, a web page), not
because its text looks like an injection; classifiers that try the latter
are reliably beaten by adaptive attacks. Labels come from metadata
(`flow_labels`), defaults per retriever, and declared tool capabilities.
The cost, stated in SECURITY.md: an unlabeled untrusted source doesn't
taint anything, so labeling at ingestion is the operator's job.

**Decision point — escalate, monotonically, only the completing call.**
A tool that adds none of the forbidden labels is never gated however
tainted the session is (a calculator keeps working). The completing call
goes to `require_approval` by default, not `deny`, because "this session
read a customer ticket and now wants to send email" is often legitimate
and a human can tell. Like `JurisdictionalRiskTierPolicy`, it can only
tighten. Capabilities are recorded *before* approval is answered: a
declined call over-taints, never under-taints.

**Decision point — MCP annotations only add.** `openWorldHint: true` adds
untrusted/external capabilities; an absent hint adds nothing (the spec's
default for an absent `openWorldHint` is true, but treating every
unannotated tool as open-world would gate nearly everything). A server
can never use annotations to *remove* a declared capability, since
annotations are the server's claim.

## Where `marshal_ai.egress` sits, and why

**Decision point — allowlist, conservative parser.** A blocklist of bad
hosts can't keep up; an allowlist of the few hosts an agent should reach
can. The risk of an allowlist is a parser that sees an allowed host where
the HTTP client sees another (`https://allowed@evil/`, backslashes,
look-alike Unicode). Rather than emulate WHATWG parsing, anything
ambiguous is disallowed outright, and hosts compare after IDNA encoding.
Scheme-less `host.tld/path` is matched too, since many tools prepend the
scheme themselves.

**Decision point — model output is audited and sanitized, not blocked.**
By the time output exists the call happened; `integrations.enable(...,
egress_allowlist=)` audits links to other hosts, and `sanitize()` is
offered for the renderer — the component that would actually fetch a
markdown image.

## Tool-definition pinning (`MCPToolPins`)

**Decision point — hash what the model reads.** The fingerprint covers
name, title, description, input/output schema and annotations — every
field that reaches the model's context — and excludes transport and UI
metadata. A changed definition is *hidden from `list_tools()`*, not just
refused at call time, because the attack happens when the model reads
the description.

**Decision point — trust on first use by default, `on_new="deny"` for
reviewed deployments.** TOFU keeps adoption frictionless and still catches
the rug pull (the definition changing after you started relying on it).
It can't catch a definition that was malicious from the start; that needs
a review step, which `on_new="deny"` plus a committed pins file provides.
Pins persist as plain JSON, written atomically, so they can be reviewed in
a PR like `policies.yaml`.

**Decision point — shadowing is checked only for tools a server hasn't
had explicitly approved.** Otherwise a human who deliberately approved the
same tool name on two servers could never use it.

## Delegation (`Principal.on_behalf_of`, `DelegatedPolicy`)

**Decision point — one `Principal` type with a chain, not separate
user/agent types.** Every guard, policy and sink already takes a
`Principal`; adding an optional `on_behalf_of` keeps every existing call
site valid and nests naturally for multi-hop delegation (the gap the IETF
agent-authorization drafts flag). `principal_id` stays the *actor*, so
existing queries and reports keep meaning what they meant.

**Decision point — enforcement is opt-in (`DelegatedPolicy`), recording
is always on.** Intersecting permissions changes what existing
deployments return, so it's a wrapper you choose. Recording the chain on
every audit entry changes nothing for anyone and is what an
accountability trail needs.

## `ToolGuard.authorize()` and the native framework hooks

**Decision point — native hooks over more monkeypatching.** Every major
framework now has an official "may this tool run" hook. Using them is
stable across releases in a way patching internals never is.
`ToolGuard.authorize()` (the old `call()` minus the invocation) is the one
decision path; `ToolGovernor` adapts its result to each framework's
refusal shape. An allowed call through the Claude Agent SDK returns *no*
decision rather than "allow", so the SDK's own permission prompts still
apply: Marshal can only make a call less permitted.

**Decision point — refusals go back to the model where the framework
allows it.** LangChain, ADK and the OpenAI Agents SDK all get an error
result the agent can reason about ("blocked by policy: ...") rather than
an exception that kills the run. `on_deny="raise"` is there for callers
who want the old behavior.

## Full SDK coverage, and the re-entrancy guard

**Decision point — patch every entry point, and fail loudly if one
disappears.** `parse()`/`stream()` don't route through `create()`, so a
create-only patch silently governed a fraction of real calls. The patch
table lists all 28 entry points; if an installed SDK is missing one,
`enable()` raises instead of patching the rest.

**Decision point — a context variable, not per-call markers, to stop
double governance.** SDKs call their own methods internally
(`responses.stream()` ends up in `responses.create()` when the stream is
entered), and governing the inner call again would re-resolve an
already-resolved model name. A context variable set for the duration of a
governed call, and across the stream manager's `__enter__`, lets the
SDK's own inner call through while any new user call is still governed.

**Decision point — hosted tools are governed at the request.** Tools the
provider executes never pass through any client-side wrapper. The only
honest control is refusing requests that enable them, by tool type,
before they're sent.

## `marshal_ai.incidents`

**Decision point — signals, declaration and report are three separate
steps.** Whether something is a serious incident under Article 3(49) is a
legal judgment, so nothing is ever declared automatically.
`incident_candidates()` is deterministic triage. `record_incident()` puts
the human declaration, and the awareness time that starts the clock,
into the same hash-chained trail as the evidence, so the clock can't be
quietly moved later. The report contains counts and outcomes only, the
same no-content discipline as every other report.

## Audit findings (v0.13 pass) — what was actually broken, and the fix

- **ReDoS in the shipped `EMAIL` detector.** `[A-Za-z0-9._%+-]+@...` with
  no start boundary is quadratic on long text without an `@`: about 20
  seconds on 100 KB, on the request path, over attacker-controlled text.
  Fixed with a boundary lookbehind and possessive, dot-delimited domain
  labels (now ~30 ms). Every detector and URL pattern is now timed against
  adversarial inputs in the test suite.
- **Governance bypass through `parse()`/`stream()`/Responses API/beta
  messages** — see above. 22 of 28 entry points were ungoverned.
- **Approval TOCTOU.** `call()` evaluated and executed the caller's own
  dict; anything mutating it (including nested values) between approval
  and execution changed what ran. Fixed by snapshotting once.
- **Fail-open edges in `ToolGuard`.** An approval handler returning a
  truthy non-bool counted as approval, and an unknown outcome string fell
  through to the allow path. Both now deny; policy exceptions become an
  audited deny with the exception type only.
- **Claude Agent SDK MCP naming.** Tools arrived as `mcp__server__tool`
  and were evaluated under that name, so a tier configured for the bare
  name never applied. Now audited under the bare name with `mcp_server`
  set; tiers may use either form.
- **Test isolation.** The integrations test fixture's `disable_all()` ran
  after `monkeypatch` undo, "restoring" a test's fake SDK method and
  leaking it into later tests. The fixture now depends on `monkeypatch`.
- **CI never ran on pushes.** The workflow triggered on `main`; the
  branch is `master`.

## Where `marshal_ai.connectors` sits, and why

**Decision point — one neutral filter dialect, compiled per store.**
Policies already speak one pushdown dialect (`GroupPolicy.to_filter`'s
Mongo-style `{field: {"$in": [...]}}`). Rather than teach every policy
every store, each connector compiles that dialect into the store's own
filter (MQL, `FieldFilter`, Qdrant `Filter`, bound SQL, a LanceDB
`where`). The dialect is deliberately tiny (equality, membership,
conjunction), because every operator added is another thing eight
compilers must get exactly right.

**Decision point — refuse to translate rather than translate loosely.**
A filter outside the dialect, a non-scalar value, a field name that isn't
a plain identifier, or Firestore's 30-value `in` limit all mean *no
pushdown*, never a best-effort guess. That is always safe, because
`RetrievalGuard` re-checks every document: the worst case is fewer than
k results, never a leak. Rejecting non-scalar values is also what makes
MongoDB operator injection impossible. A value can never *be* an
operator.

**Decision point — test against real backends wherever one can run.** A
connector tested only against a fake proves it matches the fake. MongoDB
(`mongodb-atlas-local` supports `$vectorSearch`) and pgvector run as CI
service containers, pinned by digest. Qdrant and LanceDB run for real
in-process. Firestore's emulator needs a JVM plus gcloud, so the real SDK
builds and serializes the query and only the network round trip is
replaced. Pinecone, Elasticsearch and Weaviate (managed or heavyweight)
use recording fakes that pin the exact request.

## Where `marshal_ai.approvals` sits, and why

**Decision point — bind the approval to the call, not to an id.** An
approval id alone would let an agent get "$5 refund" approved and then
spend that approval on a $5,000 one. The queue keys every request by an
HMAC of (tool, raw arguments, principal chain, risk tier), and only that
exact call can consume it. Re-submitting the identical call finds the
existing request, which is also what makes the non-blocking flow
("pending, retry later") work without callers passing an id back. The
HMAC key is per queue, so the digest can't be brute-forced into
low-entropy argument values. Reviewers only ever see the redacted view.

**Decision point — SQLite again.** Same reasoning as `SQLiteAuditSink`:
durable, transactional, zero new dependencies, safe across processes. The
single-use guarantee is a conditional `UPDATE ... WHERE status =
'approved'` inside `BEGIN IMMEDIATE`, which the concurrency test hammers
with eight racing retries.

**Decision point — `ApprovalPending` subclasses `ToolCallDenied`.** Code
written before the queue existed catches `ToolCallDenied` and stops,
which is the right default for a call that didn't run. Code that knows
about the queue catches `ApprovalPending` first.

## `ModelRunawayPolicy`: why a prompt fingerprint

A model-call loop is the same prompt resent, and a real conversation
never resends one (each turn includes the history). So "identical" is a
SHA-256 of the extracted prompt text, computed in the SDK layer, which is
the only layer that sees text. The policy only ever receives the digest.
Calls with no fingerprint are never counted as identical, so the policy
fails *open* on missing data. That's deliberate: tripping a principal
needs evidence, and `ModelRateLimitPolicy` is the blunt backstop.

## CrewAI: an adapter without an extra

Every CrewAI release pins `mcp<2` and `openai<3`. Adding a `[crewai]`
extra would make `marshal-ai[all]` unsolvable, or push users onto mcp
versions with client-side advisories. Installing it into the dev
environment silently downgraded mcp to 1.23. So the adapter is
dependency-free (a plain hook function), imports CrewAI only inside
`enable_crewai`, and is tested in its own CI job.

## Tool outcomes: always reported to policies, audited only on request

**Decision point — two separate switches.** Reliability policies need
every outcome to work at all, so `ToolGuard` always feeds
`ToolPolicy.record_outcome`. Writing a `ToolOutcomeEntry` per call is a
different decision: it doubles audit volume and changes the trail's shape
for existing consumers (16 existing tests read "the last entry is the
tool call"). So it's `audit_outcomes=True`, off by default.

**Decision point — forward by default through `_base`.** Every tool
wrapper already keeps its wrapped policy in `_base`. The base-class
`record_outcome` forwards there, so outcomes reach a breaker at the
bottom of any stack, including wrappers written before outcomes existed,
without each one opting in.

**Decision point — record the exception type, never the message.**
Exception messages routinely echo arguments (URLs with tokens, account
ids). The type is enough to tell a timeout from a validation error.

**Decision point — "deferred to host" is not "approved".** When the
Claude Agent SDK's own prompt takes the approval, Marshal never sees the
answer. Recording "approved" would claim something Marshal didn't
observe, so the outcome is `deferred_to_host`, and whether the tool then
ran shows up as an outcome entry.

## Operating agents (v0.16)

**Run ids from a context variable, as a field default.** Every entry type
gets `run_id: Optional[str] = field(default_factory=current_run_id)`. An
explicit parameter would have meant touching every guard, every adapter,
and every framework's call path Marshal doesn't control. A context
variable follows asyncio tasks and `copy_context()`, so it reaches inside
frameworks too. The one trap is decoding: an entry rebuilt from an old
log line would call the factory and inherit whatever run is active
*while reading*. `_decode_entry` sets both run fields explicitly before
constructing.

**Health is computed, and "no data" is three different states.** A
system that says "healthy" whenever nothing is wrong *in the data it has*
hides outages. `idle` (alive, no traffic), `unknown` (heartbeats
stopped) and `not_instrumented` (decisions but never any outcomes) are
separate statuses on purpose, because each needs a different response.
Small samples are reported as low confidence rather than judged.

**Quarantine fails closed and is accountable.** It's the one control a
human flips during an incident. If its store is unreadable, the safe
assumption is "everything might be quarantined", so calls are denied.
Every action requires who and why, and is both audited and kept in its
own history table.

**Pseudonyms by keyed HMAC, not a lookup table.** A table mapping
pseudonyms to people is exactly the thing to steal. A keyed HMAC gives
deterministic pseudonyms (every analysis still works) that only the key
holder can recompute, and there's nothing else to leak.

**Red-team checks take factories.** Policies are stateful (rate limits,
flow tracking, breakers), so scenarios must not share an instance, or
one scenario's flood would decide another's outcome. A zero-argument
factory per scenario keeps them independent and deterministic. Anything
not configured is `not_applicable`, never a pass.

**Policy versions hash the parsed config.** Hashing the file would change
on a comment or a reformat. Hashing the canonical JSON of what was parsed
changes exactly when the meaning does.

## Design patterns already in use (kept, not re-invented)

- **Self-registering discriminator** (`register_entry_type`) for the
  shared audit trail — new event kinds opt in without touching `audit.py`.
  v0.13 adds `flow_label`, `egress`, `mcp_tool_definition` and `incident`
  the same way.
  `marshal_ai.config.register_builder` reuses the same shape for loadable
  policy types.
- **Strategy via constructor injection** — every `*Policy` base class is
  the strategy interface; `RedactingPolicy`/`BudgetPolicy`/
  `SensitiveDataPolicy` are all "wrap a strategy, add one behavior,
  delegate the rest" decorators over it.
- **Duck typing over inheritance for cross-cutting queries** —
  `AuditSink.query(denied_only=True)` and `marshal_ai.cli`'s row flag both
  ask "does this object look like a denial" via `getattr(...)`, not via
  an `isinstance` chain — a new entry type participates by shape, not by
  registration.

## Audit findings (this pass) — what was actually broken, and the fix

1. **`marshal_ai.integrations` had four near-duplicate wrapper closures**
   (`_make_openai_wrapper` sync + async, `_make_anthropic_wrapper` sync +
   async) differing only in which provider-specific completion-text
   extractor and usage-reporter they called. Refactored to one generic
   `_make_wrapper` plus a `_PROVIDER_ADAPTERS` table of
   `(extract_completion_text, report_usage)` pairs — a real DRY fix, and
   it also means adding a third provider later is one table entry, not a
   fourth copy-pasted closure (an OCP improvement as a side effect).
   Covered by the existing 13 `test_integrations.py` tests, all of which
   passed unchanged after the refactor (behavior-preserving).

2. **`AuditSink.query(denied_only=True)` didn't recognize
   `SensitiveDataEntry`'s "blocked" action** — see "Open/Closed" above for
   the full failure scenario. Fixed by extracting a module-level
   `is_denied(entry)` function in `audit.py` that checks all three known
   shapes, and using it both in `query()` and in `marshal_ai.cli`
   (see #3). New regression test:
   `test_query_denied_only_includes_sensitive_data_blocked_entries` in
   `tests/test_audit.py`.

3. **`marshal_ai.cli`'s `_is_denied()` independently duplicated the exact
   same duck-typed logic `AuditSink.query()` used** — before this pass
   they happened to agree; after adding `SensitiveDataEntry` they would
   have silently diverged (the CLI's `!` flag would miss blocked
   sensitive-data rows even after the `audit.py` fix, since `cli.py` had
   its own copy). Fixed by deleting `cli.py`'s local `_is_denied()`
   entirely and importing `is_denied` from `audit.py` — one definition,
   used in both places, can't drift again. New test:
   `test_tail_shows_sensitive_data_entries_flagged_when_blocked` in
   `tests/test_cli.py`.

4. **`OpenTelemetryAuditSink` had no handler for the new entry kind.**
   `write()` already degrades gracefully for unknown kinds (exports
   generic attributes rather than crashing — this part was already
   correctly OCP-respecting), but the generic fallback doesn't set span
   status to `ERROR`, so a blocked sensitive-data finding would export as
   a normal-looking span instead of the error-flagged one every other
   denial-shaped event gets. Added `_write_sensitive_data`, registered in
   `_HANDLERS`, following the exact pattern `_write_tool_call`/
   `_write_model_call` already use (`ERROR` status when the outcome is
   the denial-equivalent one). New tests:
   `test_sensitive_data_span_error_status_on_block` and
   `test_sensitive_data_span_ok_status_on_redact` in `tests/test_otel.py`.

5. **Minor import-style inconsistency**: `sensitive.py` imported
   `dataclasses.replace` locally inside a method instead of at module
   top, where every other file that uses it (`policy.py`) imports it.
   Fixed for consistency; no behavior change.

All five were caught by re-reading the new code against the rest of the
codebase's own established conventions, not by a generic linter pass —
each one only shows up once you ask "does this new entry kind actually
flow correctly through every *existing* consumer of the audit trail," which
is exactly the kind of gap SOLID's Open/Closed principle is meant to
catch: extension should not require the extension author to also go audit
every existing call site by hand, but it's still worth doing once, here,
explicitly.

## Audit findings (v0.11 integration pass) — what four parallel branches missed by not seeing each other

v0.11 shipped four features (shadow mode, real vector-store adapters, MCP
tool-call governance, durable SQLite audit storage + compliance reports)
built in parallel, each on code that couldn't see the others' changes
yet. An independent pre-merge review of the assembled tree caught two
real bugs — both, tellingly, at the *intersection* of two features that
were each individually correct in isolation.

1. **`sinks.py` imported the private `marshal_ai.audit._decode_entry`.**
   `SQLiteAuditSink.all_entries`/`query` needed the same "turn a decoded
   JSON dict back into the right dataclass via its `kind` discriminator"
   reconstruction `JSONLAuditSink.all_entries` already does in-module —
   but `audit.py` exposed no public equivalent, and the task that built
   `sinks.py` had `audit.py` off-limits (parallel work elsewhere touched
   it). Importing the private helper was the least-bad option available
   at the time, self-flagged by its own author as the one corner cut.
   Real violation of the DIP rule this project holds elsewhere: depend on
   Marshal's *public* abstractions, not another module's private members.
   Fixed at integration, once `audit.py` was back on the table: added a
   public `decode_entry(data: dict) -> AuditableEvent` in `audit.py`
   (thin wrapper delegating to the existing `_decode_entry`), and
   `sinks.py` now imports the public name. One source of truth for "kind
   string -> dataclass," publicly reachable from outside `audit.py` for
   the first time.
2. **Shadow-mode entries were counted as real enforcement in the
   compliance reports.** See "Where `SQLiteAuditSink`/`marshal_ai.reports`
   sit, and why," above, for the full writeup — the short version: a
   shadow "deny"/"require_approval" entry never actually blocks anything
   (shadow mode's entire contract is that the real action proceeds
   regardless), but `reports.py` was written and tested before shadow
   mode existed in the same tree, so it folded a shadow "deny" straight
   into `denied`/`denied_transfer_attempts` — numbers a regulator-facing
   document would read as "this system blocked this," when the system in
   fact let it through. A secondary defect shared the same root: a shadow
   `ToolCallEntry`'s raw `outcome == "require_approval"` wasn't in any of
   the three normalized outcome buckets, so it silently vanished from
   `outcome_breakdown`'s rollup entirely. Fixed by reading each entry's
   `shadow` flag and routing shadow entries into `ActivityRecord.
   shadow_counts`/`shadow_totals` and `CrossBorderDataFlowReport.
   shadow_observed_calls`/`shadow_would_have_denied_transfers` — fully
   separate fields, never merged into the real figures, surfaced in their
   own clearly labeled section in both Markdown renderers — plus adding
   `"require_approval"` to the approval-outcome bucket set. Regression
   tests: `test_cross_border_report_excludes_shadow_denies_from_denied_
   transfer_attempts` and `test_activity_record_excludes_shadow_entries_
   from_real_counts` in `tests/test_reports.py`.

Neither bug was visible from inside the branch that "caused" it: shadow
mode's own 16 tests never touch `reports.py`, and `reports.py`'s own
tests were written and passing before shadow mode's `shadow` field
existed. Both only appear once the audit trail both features write to is
actually shared and read back — exactly the integration scenario every
one of Marshal's own docs recommends (one sink, every guard) and exactly
why a real merge-time review pass, not just four independently-green
branches, is the point of the step this file records.

A third item — `RetrievalAuditEntry`, an import-order-fragile way of
adding shadow's two new fields to the retrieval entry type without
editing `audit.py` — was flagged SHOULD-FIX rather than MUST-FIX (it
never actually broke anything the review could reproduce) and is written
up under "Where shadow mode (`GuardMode`) sits, and why," above, since
it's a design-simplification rather than a bug with an observable failure
scenario.

## Deliberate tradeoffs (considered, not changed)

- **Frozen dataclasses with mutable list/dict fields** (`AuditEntry.
  denied_ids`, `SensitiveDataEntry.findings`, etc.) — `frozen=True`
  prevents reassigning a field after construction but doesn't deep-freeze
  its contents; a caller could still mutate the list in place. Pre-existing
  in every entry type, not introduced by this pass. A fully immutable
  version would use tuples, at the cost of ergonomics for ordinary list
  operations and for `dataclasses.asdict()`-based JSON serialization.
  Not worth changing four existing types for a theoretical mutation no
  code in the project actually performs.
- **`AuditSink` as one ABC instead of a read/write split** — see
  "Interface Segregation" above.
- **`tools.py`/`models.py` bundle policy + guard + entry type in one
  file each** — see "Single Responsibility" above.

## Alerts and evaluations (v0.17)

- **Outbox before send.** A notification is a database row before it is
  a network call. Sending first and recording after loses alerts on a
  crash; recording first and leasing gives at-least-once with a stable
  `delivery_id` for receivers to dedupe. Exactly-once isn't offered
  because no webhook receiver can make it true.
- **Acknowledgement is scoped to severity.** Escalation clears an ack.
  An ack on a warning silencing the critical that follows is the failure
  that makes on-call stop trusting alerts.
- **Error types, not messages, are stored** for failed deliveries: an
  exception message from an HTTP client often contains the URL, and
  webhook URLs often contain tokens.
- **Redirects are refused** by the webhook notifier: following one lets
  the receiving host point Marshal anywhere, including cloud metadata
  endpoints.
- **Marshal ships no scorers.** Quality checks are domain-specific and,
  when model-based, steerable by the content they judge. Evaluations are
  for people deciding whether an agent works — never an input to an
  authorization decision. A crashing scorer is recorded as a failure,
  because a missing quality signal reads as "fine".

