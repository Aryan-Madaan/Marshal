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

## Design patterns already in use (kept, not re-invented)

- **Self-registering discriminator** (`register_entry_type`) for the
  shared audit trail — new event kinds opt in without touching `audit.py`.
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
