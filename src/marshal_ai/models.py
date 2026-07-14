from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Optional

from marshal_ai.audit import AuditSink, InMemoryAuditSink, register_entry_type
from marshal_ai.policy import GuardMode, Principal


@dataclass(frozen=True)
class ModelCallRequest:
    """A request to resolve a *logical* model name (e.g.
    "default-chat-model") to a real one. `context` carries whatever your
    policy needs to decide — e.g. {"contains_pii": True} — Marshal doesn't
    interpret it, your policy does."""

    logical_name: str
    principal: Principal
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ModelDecision:
    outcome: str  # "allow" | "deny"
    resolved_model: Optional[str]
    reason: str


class ModelCallDenied(Exception):
    def __init__(self, logical_name: str, reason: str) -> None:
        self.logical_name = logical_name
        self.reason = reason
        super().__init__(f"Model call for {logical_name!r} denied: {reason}")


class ModelPolicy(ABC):
    """Decides which real model a logical name resolves to for this
    principal/context — and, separately, what to try next if that model
    turns out to be unavailable.

    Note what this deliberately does *not* do: make the actual LLM call.
    Marshal doesn't depend on any specific SDK or provider. You resolve a
    model here, call it yourself however you already do, then report back
    usage via `record_usage` for budget tracking.
    """

    @abstractmethod
    def resolve(self, request: ModelCallRequest) -> ModelDecision: ...

    def fallback_chain(self, request: ModelCallRequest) -> list[str]:
        """Ordered candidates to try if the resolved model errors, rate
        limits, or times out. Every name returned here has *already*
        cleared this policy for this principal/context — a fallback is
        not a backdoor around governance just because the preferred model
        is down. Default: no fallbacks configured.
        """
        return []

    def record_usage(
        self, principal: Principal, model: str, prompt_tokens: int, completion_tokens: int
    ) -> None:
        """Called after a real call completes, so budget-tracking policies
        can update spend. Default: no-op (most policies don't track cost)."""
        return None

    def record_outcome(
        self,
        principal: Principal,
        model: str,
        success: bool,
        latency_ms: Optional[float] = None,
        error: Optional[str] = None,
    ) -> None:
        """Called after a real call *attempt* completes — success or
        failure — so reliability-tracking policies (e.g.
        `CircuitBreakerPolicy`) can update their view of a deployment's
        health. A different question from `record_usage`: usage is
        reported only on success and answers "what did this cost,"
        `record_outcome` is reported on every attempt and answers "did
        this deployment actually work, and how fast." Default: no-op
        (most policies don't track reliability)."""
        return None


class AllowAllModels(ModelPolicy):
    """No routing/governance configured — the logical name is used as the
    literal model name, unchanged. The default if you don't pass a
    policy: get the audit trail for free, add real routing when ready."""

    def resolve(self, request: ModelCallRequest) -> ModelDecision:
        return ModelDecision("allow", request.logical_name, "AllowAllModels policy")


@dataclass(frozen=True)
class ModelCandidate:
    """One entry in an AllowlistModelPolicy route. `requires_attribute`,
    if set, means the principal needs that attribute for this candidate to
    qualify — e.g. a candidate hosted outside the EU might require
    `requires_attribute="region:non-eu-ok"`."""

    name: str
    requires_attribute: Optional[str] = None


class AllowlistModelPolicy(ModelPolicy):
    """The default real policy: each logical name maps to an *ordered*
    list of candidates. `resolve` picks the first one the principal
    qualifies for; `fallback_chain` returns the rest of the qualifying
    ones, in order — so a caller retrying on failure never has to
    re-implement the governance check itself.

    Example: route "default-chat-model" to a fast/cheap model for anyone,
    but only fall back to an on-prem model for principals with
    "region:restricted" if the primary is down — and never fall back to
    an even-cheaper model that wasn't approved for that principal at all.
    """

    def __init__(self, routes: dict[str, list[ModelCandidate]]) -> None:
        self._routes = routes

    def _qualifying(self, request: ModelCallRequest) -> list[ModelCandidate]:
        candidates = self._routes.get(request.logical_name, [])
        return [
            c
            for c in candidates
            if c.requires_attribute is None or c.requires_attribute in request.principal.attributes
        ]

    def resolve(self, request: ModelCallRequest) -> ModelDecision:
        qualifying = self._qualifying(request)
        if not qualifying:
            return ModelDecision(
                "deny",
                None,
                f"no candidate for {request.logical_name!r} that principal "
                f"{request.principal.id!r} qualifies for",
            )
        chosen = qualifying[0]
        return ModelDecision(
            "allow", chosen.name, f"resolved {request.logical_name!r} -> {chosen.name!r}"
        )

    def fallback_chain(self, request: ModelCallRequest) -> list[str]:
        return [c.name for c in self._qualifying(request)[1:]]


class BudgetPolicy(ModelPolicy):
    """Wraps another policy, keeping its routing decision unchanged, and
    additionally denies once a principal's tracked spend hits `limit_usd`.

    Spend is tracked per-principal, in-process, from `record_usage` calls
    — nothing here estimates cost *before* a call executes; it enforces
    the limit on the *next* call once prior usage has been reported. A
    stale or missing `pricing` entry for a model is treated as
    unbudgeted/unpriced (that model's usage silently doesn't count toward
    spend) rather than raising — call out unpriced models in your own
    monitoring if that matters for your setup.
    """

    def __init__(
        self,
        base: ModelPolicy,
        pricing: dict[str, tuple[float, float]],
        limit_usd: float,
    ) -> None:
        # pricing: model name -> (usd per 1K prompt tokens, usd per 1K completion tokens)
        self._base = base
        self._pricing = pricing
        self._limit_usd = limit_usd
        self._spent: dict[str, float] = {}
        self._lock = threading.Lock()

    def resolve(self, request: ModelCallRequest) -> ModelDecision:
        decision = self._base.resolve(request)
        if decision.outcome != "allow":
            return decision
        spent = self._spent.get(request.principal.id, 0.0)
        if spent >= self._limit_usd:
            return ModelDecision(
                "deny",
                None,
                f"budget exceeded for {request.principal.id!r}: "
                f"${spent:.4f} >= ${self._limit_usd:.4f}",
            )
        return decision

    def fallback_chain(self, request: ModelCallRequest) -> list[str]:
        return self._base.fallback_chain(request)

    def record_usage(
        self, principal: Principal, model: str, prompt_tokens: int, completion_tokens: int
    ) -> None:
        self._base.record_usage(principal, model, prompt_tokens, completion_tokens)
        if model not in self._pricing:
            return
        prompt_rate, completion_rate = self._pricing[model]
        cost = (prompt_tokens / 1000) * prompt_rate + (completion_tokens / 1000) * completion_rate
        with self._lock:
            self._spent[principal.id] = self._spent.get(principal.id, 0.0) + cost

    def record_outcome(
        self,
        principal: Principal,
        model: str,
        success: bool,
        latency_ms: Optional[float] = None,
        error: Optional[str] = None,
    ) -> None:
        self._base.record_outcome(principal, model, success, latency_ms, error)

    def spent_by(self, principal_id: str) -> float:
        return self._spent.get(principal_id, 0.0)


def _first_compliant(
    base: ModelPolicy, request: ModelCallRequest, is_compliant: "Callable[[str], bool]"
) -> list[str]:
    """Every candidate `base` already qualified this principal for — its
    top pick plus its own fallback chain, in order — filtered down to
    ones satisfying `is_compliant`. Empty if the base denies, or nothing
    qualifies.

    Shared by every wrapping `ModelPolicy` below that layers one more
    compliance constraint on top of a base's routing (`ResidencyPolicy`,
    `RetentionPolicy`): each needs the same behavior when its own
    constraint rules out the base's top pick — promote the next
    candidate the base *already* qualified this principal for, rather
    than denying outright just because the first one didn't also clear
    the new constraint. That's the same governed-substitution reasoning
    `AllowlistModelPolicy.fallback_chain` establishes for its own
    attribute gate, applied consistently to every later constraint
    stacked on top of it.
    """
    decision = base.resolve(request)
    if decision.outcome != "allow":
        return []
    candidates = [decision.resolved_model, *base.fallback_chain(request)]
    return [c for c in candidates if is_compliant(c)]


class ResidencyPolicy(ModelPolicy):
    """Wraps another `ModelPolicy`, keeping its routing decision unchanged
    unless the resolved model isn't a compliant deployment for the
    request's jurisdiction — answers *where* this data is allowed to be
    processed.

    Reads jurisdiction from `request.context["jurisdiction"]`,
    deliberately *not* from a principal attribute the way
    `ModelCandidate.requires_attribute` gates on identity/role. Which
    country's law governs a piece of data is a property of that data (or
    of the person it's about), not of who's asking to process it — the
    same request, on behalf of the same principal, can carry EU-governed
    data one call and India-governed data the next. That's decided once,
    at ingestion, and passed through as context; it isn't something the
    principal's own attributes should encode.

    `allowed_by_jurisdiction` maps jurisdiction -> {deployment name ->
    transfer mechanism}, e.g. `{"EU": {"eu-deployment": "adequacy_decision"},
    "TH": {"th-deployment": "scc_2024_module2"}}`. The mechanism string
    isn't decoration: "is this transfer allowed" and "under what
    documented legal basis is it allowed" are different questions with
    different audit requirements (GDPR Article 46 and Thailand's PDPA
    Section 29 both require an actual documented safeguard, not just a
    country that happens to be permissible), and the mechanism is what
    lands in the audit trail's `reason` field alongside the jurisdiction
    and the resolved deployment — recording *why* a transfer was lawful,
    not just that it was allowed.

    Fails closed on two distinct conditions, not just one: jurisdiction
    missing from context entirely, or a jurisdiction that's present but
    has no compliant deployment among the base policy's candidates. Both
    deny outright. There is deliberately no silent default deployment to
    fall back to — that silent fallback is exactly the failure mode this
    class exists to close off; see `ideas.md` and the cross-border data
    transfer post this shipped alongside for the full argument.

    Optionally reads `request.context["controller"]` — an identifier for
    whichever entity is legally accountable for this data (a group
    company, a customer, a business unit) — and folds it into the audit
    reason purely for traceability. Marshal doesn't validate it against
    anything; it exists so a later audit query can be reconciled against
    the entity whose instructions `allowed_by_jurisdiction` is supposed
    to encode, per the controller/processor note below.

    One more thing this class is deliberately *not*: a substitute for the
    controller/processor legal analysis. GDPR calls the two roles
    controller and processor; India's DPDP Act calls them data fiduciary
    and data processor; Singapore's PDPA calls the processor role a data
    intermediary — different labels, same functional split in every
    regime this policy is meant to help with. Only the controller (the
    entity that decides *why* the data is being processed) has the legal
    standing to decide which destinations a transfer of that data may
    lawfully go to, and under what mechanism. `allowed_by_jurisdiction` is
    that controller's decision, expressed as config — Marshal enforces it
    deterministically at every call, it doesn't make it, and it doesn't
    verify that the mechanism string is still valid or was ever real. If
    the application calling this policy is itself a processor/data
    intermediary acting on someone else's instructions, this config
    should be populated from that controller's actual instructions
    (typically the same ones already captured in the processing
    agreement/DPA), kept in sync as those instructions change — not
    decided ad hoc, and not left stale, by whoever wires up `ModelGuard`.

    What this class deliberately does *not* attempt, because Marshal has
    no way to verify it at call time: confirming a vendor's downstream
    retention or deletion actually matches what a mechanism promises
    (see `RetentionPolicy` for the retention axis specifically), or
    enforcing sub-processor authorization chains beyond how you name
    your deployments. Name deployments by their actual processing chain
    (e.g. `"claude-bedrock-eu-west-1"` vs. `"claude-foundry-global"`) if
    that distinction matters for your compliance posture — two
    deployments of "the same model" can differ exactly in the residency
    and sub-processor guarantee that matters here.
    """

    def __init__(
        self, base: ModelPolicy, allowed_by_jurisdiction: dict[str, dict[str, str]]
    ) -> None:
        self._base = base
        self._allowed_by_jurisdiction = allowed_by_jurisdiction

    def resolve(self, request: ModelCallRequest) -> ModelDecision:
        decision = self._base.resolve(request)
        if decision.outcome != "allow":
            return decision
        jurisdiction = request.context.get("jurisdiction")
        if jurisdiction is None:
            return ModelDecision(
                "deny",
                None,
                "jurisdiction not provided in context — refusing to resolve without it",
            )
        mechanisms = self._allowed_by_jurisdiction.get(jurisdiction, {})
        compliant = _first_compliant(self._base, request, lambda c: c in mechanisms)
        if not compliant:
            return ModelDecision(
                "deny",
                None,
                f"no jurisdiction-compliant deployment for {jurisdiction!r} among "
                f"candidates for {request.logical_name!r}",
            )
        chosen = compliant[0]
        controller = request.context.get("controller")
        controller_note = f", controller {controller!r}" if controller else ""
        return ModelDecision(
            "allow",
            chosen,
            f"resolved {request.logical_name!r} -> {chosen!r} for jurisdiction "
            f"{jurisdiction!r} via {mechanisms[chosen]!r}{controller_note}",
        )

    def fallback_chain(self, request: ModelCallRequest) -> list[str]:
        jurisdiction = request.context.get("jurisdiction")
        if jurisdiction is None:
            return []
        mechanisms = self._allowed_by_jurisdiction.get(jurisdiction, {})
        return _first_compliant(self._base, request, lambda c: c in mechanisms)[1:]

    def record_usage(
        self, principal: Principal, model: str, prompt_tokens: int, completion_tokens: int
    ) -> None:
        self._base.record_usage(principal, model, prompt_tokens, completion_tokens)

    def record_outcome(
        self,
        principal: Principal,
        model: str,
        success: bool,
        latency_ms: Optional[float] = None,
        error: Optional[str] = None,
    ) -> None:
        self._base.record_outcome(principal, model, success, latency_ms, error)


class RetentionPolicy(ModelPolicy):
    """Wraps another `ModelPolicy`, keeping its routing decision unchanged
    unless the resolved deployment's configured retention terms exceed
    the ceiling this specific request requires — answers *how long*
    (and, implicitly, under what terms) whoever processes this data is
    allowed to keep it. A different question from `ResidencyPolicy`, and
    an independent one: a deployment can be geographically compliant and
    still retain prompts for weeks under a vendor's default
    abuse-monitoring window, which is exactly what a zero-data-retention
    (ZDR) agreement exists to rule out. A call can fail either check
    without failing the other, so stack both when both matter:
    `RetentionPolicy(ResidencyPolicy(base, ...), ...)`.

    Reads the required ceiling from
    `request.context["max_retention_days"]` — `0` means this call
    requires a zero-data-retention deployment. Same reasoning as
    `ResidencyPolicy`: what retention ceiling a piece of data requires is
    a property of the data (a trade secret, a health record, anything
    under a strict DPA), not of who's asking, so it travels in context,
    not on the principal.

    Fails closed the same way `ResidencyPolicy` does: `max_retention_days`
    missing from context, or present but met by no candidate, both deny
    outright. No silent fallback to a deployment whose retention terms
    were never actually checked.

    `deployment_retention_days` should reflect the *current*, actual
    terms of your agreement with each deployment's vendor, not an
    estimate — and needs updating when a contract is renegotiated, the
    same discipline `ResidencyPolicy.allowed_by_jurisdiction` requires
    for transfer mechanisms. Marshal enforces whatever this config says;
    it has no way to confirm a vendor is actually honoring it downstream.
    """

    def __init__(self, base: ModelPolicy, deployment_retention_days: dict[str, int]) -> None:
        self._base = base
        self._deployment_retention_days = deployment_retention_days

    def _meets_ceiling(self, name: str, max_days: int) -> bool:
        days = self._deployment_retention_days.get(name)
        return days is not None and days <= max_days

    def resolve(self, request: ModelCallRequest) -> ModelDecision:
        decision = self._base.resolve(request)
        if decision.outcome != "allow":
            return decision
        max_days = request.context.get("max_retention_days")
        if max_days is None:
            return ModelDecision(
                "deny",
                None,
                "max_retention_days not provided in context — refusing to resolve without it",
            )
        compliant = _first_compliant(self._base, request, lambda c: self._meets_ceiling(c, max_days))
        if not compliant:
            return ModelDecision(
                "deny",
                None,
                f"no deployment for {request.logical_name!r} meets a {max_days}-day "
                f"retention ceiling",
            )
        chosen = compliant[0]
        return ModelDecision(
            "allow",
            chosen,
            f"resolved {request.logical_name!r} -> {chosen!r}: retains for "
            f"{self._deployment_retention_days[chosen]} day(s), within the {max_days}-day ceiling",
        )

    def fallback_chain(self, request: ModelCallRequest) -> list[str]:
        max_days = request.context.get("max_retention_days")
        if max_days is None:
            return []
        return _first_compliant(self._base, request, lambda c: self._meets_ceiling(c, max_days))[1:]

    def record_usage(
        self, principal: Principal, model: str, prompt_tokens: int, completion_tokens: int
    ) -> None:
        self._base.record_usage(principal, model, prompt_tokens, completion_tokens)

    def record_outcome(
        self,
        principal: Principal,
        model: str,
        success: bool,
        latency_ms: Optional[float] = None,
        error: Optional[str] = None,
    ) -> None:
        self._base.record_outcome(principal, model, success, latency_ms, error)


class CircuitBreakerPolicy(ModelPolicy):
    """Wraps another `ModelPolicy`, keeping its routing decision unchanged
    unless the resolved deployment has been failing — answers a question
    none of `ResidencyPolicy`/`RetentionPolicy`/`BudgetPolicy` can:
    *is this deployment actually working right now*, based on what
    recently happened to real calls, not static config. The first policy
    in Marshal besides `BudgetPolicy` whose decision depends on
    accumulated runtime history rather than the current request alone.

    A deployment trips once it has `failure_threshold` or more recorded
    failures within the trailing `window_seconds` — fed by
    `record_outcome(success=False, ...)`, typically called automatically
    by `marshal_ai.integrations` when a real downstream call raises. A
    tripped deployment is skipped the same way a jurisdiction or
    retention mismatch is: `resolve`/`fallback_chain` search the base
    policy's full qualifying candidate list (top pick plus its own
    fallback chain) via the same `_first_compliant` helper
    `ResidencyPolicy`/`RetentionPolicy` already share, promoting the next
    non-tripped candidate instead of denying outright — and denying
    outright, fail-closed, only if every candidate is currently tripped.

    Deliberately *not* a textbook open/half-open/closed circuit-breaker
    state machine. A trailing time window is self-healing by
    construction: once `window_seconds` passes the last recorded failure,
    that failure ages out and the count drops back below threshold with
    no separate recovery/probe logic needed. Simpler, and sufficient —
    see `DESIGN_DECISIONS.md` for the tradeoff stated explicitly.

    What does *not* count as a failure here: a governance denial from
    this policy's own base (or any wrapped policy) — `record_outcome` is
    only ever called after a call was allowed and actually attempted,
    the same separation `record_usage` already has from routing
    decisions. A heavily-governed deployment that correctly denies most
    calls for compliance reasons must not look identical to a genuinely
    broken one.
    """

    def __init__(self, base: ModelPolicy, failure_threshold: int, window_seconds: float) -> None:
        self._base = base
        self._failure_threshold = failure_threshold
        self._window_seconds = window_seconds
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, model: str, now: float) -> list[float]:
        cutoff = now - self._window_seconds
        return [t for t in self._failures.get(model, []) if t >= cutoff]

    def _is_healthy(self, model: str) -> bool:
        with self._lock:
            recent = self._prune(model, time.monotonic())
            self._failures[model] = recent
        return len(recent) < self._failure_threshold

    def resolve(self, request: ModelCallRequest) -> ModelDecision:
        decision = self._base.resolve(request)
        if decision.outcome != "allow":
            return decision
        compliant = _first_compliant(self._base, request, self._is_healthy)
        if not compliant:
            return ModelDecision(
                "deny",
                None,
                f"every candidate for {request.logical_name!r} has tripped its circuit "
                f"breaker ({self._failure_threshold}+ failures in the last "
                f"{self._window_seconds:.0f}s)",
            )
        chosen = compliant[0]
        if chosen == decision.resolved_model:
            return decision
        return ModelDecision(
            "allow",
            chosen,
            f"resolved {request.logical_name!r} -> {chosen!r}: base preferred "
            f"{decision.resolved_model!r}, which has tripped its circuit breaker",
        )

    def fallback_chain(self, request: ModelCallRequest) -> list[str]:
        return _first_compliant(self._base, request, self._is_healthy)[1:]

    def record_usage(
        self, principal: Principal, model: str, prompt_tokens: int, completion_tokens: int
    ) -> None:
        self._base.record_usage(principal, model, prompt_tokens, completion_tokens)

    def record_outcome(
        self,
        principal: Principal,
        model: str,
        success: bool,
        latency_ms: Optional[float] = None,
        error: Optional[str] = None,
    ) -> None:
        self._base.record_outcome(principal, model, success, latency_ms, error)
        if not success:
            with self._lock:
                recent = self._prune(model, time.monotonic())
                recent.append(time.monotonic())
                self._failures[model] = recent

    def recent_failure_count(self, model: str) -> int:
        return len(self._prune(model, time.monotonic()))


@dataclass(frozen=True)
class ModelCallEntry:
    """`resolved_model` is `None` only for a real (enforced) denial —
    `outcome == "deny"` and `shadow == False`. A shadow-mode denial keeps
    `outcome == "deny"` (the real policy's decision, audited verbatim,
    the same reuse-the-vocabulary approach `ToolCallEntry.outcome` uses)
    but `resolved_model` is still populated with whatever `ModelGuard`
    handed back to the caller instead of raising — see
    `ModelGuard._shadow_fallback_model`. Because `outcome` keeps its
    enforce-mode meaning, a shadow "deny" entry still shows up under
    `AuditSink.query(denied_only=True)` for free.
    """

    timestamp: float
    principal_id: str
    logical_name: str
    resolved_model: Optional[str]
    outcome: str  # "allow" | "deny"
    reason: str
    shadow: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "model_call", **asdict(self)}


register_entry_type("model_call", ModelCallEntry)


@dataclass(frozen=True)
class ModelUsageEntry:
    """A record of actual usage reported after a real call completed —
    separate from `ModelCallEntry` (the routing decision) since usage is
    only known after the fact, often well after resolution happened."""

    timestamp: float
    principal_id: str
    model: str
    prompt_tokens: int
    completion_tokens: int

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "model_usage", **asdict(self)}


register_entry_type("model_usage", ModelUsageEntry)


@dataclass(frozen=True)
class ModelOutcomeEntry:
    """A record of whether a real call *attempt* to a resolved deployment
    actually succeeded — separate from both `ModelCallEntry` (the routing
    decision) and `ModelUsageEntry` (cost, success-only): this is the
    piece that answers "is this deployment actually working, and how
    fast," which nothing else in the audit trail captures. `error` is a
    short category (`"timeout"`, `"rate_limited"`, `"server_error"`,
    `"connection_error"`, `"other"`) — never a raw exception message,
    same discipline `SensitiveDataEntry.findings` already applies to
    what's safe to persist in an audit trail."""

    timestamp: float
    principal_id: str
    model: str
    success: bool
    latency_ms: Optional[float] = None
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "model_outcome", **asdict(self)}


register_entry_type("model_outcome", ModelOutcomeEntry)


class ModelGuard:
    """Resolves logical model names through a policy, audits every
    resolution, and forwards usage reports for budget tracking — sharing
    the same `AuditSink` as `RetrievalGuard`/`ToolGuard` if you pass one
    in, for one trail across every surface.

    `mode="enforce"` (the default) is today's behavior unchanged: a
    denied resolution raises `ModelCallDenied`. `mode="shadow"` still
    resolves and audits the real decision, but never raises — see
    `resolve` below for what it returns instead of raising.
    """

    def __init__(
        self,
        policy: Optional[ModelPolicy] = None,
        audit_sink: Optional[AuditSink] = None,
        mode: GuardMode = "enforce",
    ) -> None:
        self._policy = policy if policy is not None else AllowAllModels()
        self._audit_sink = audit_sink if audit_sink is not None else InMemoryAuditSink()
        self._mode = mode

    @property
    def audit_log(self) -> AuditSink:
        return self._audit_sink

    def _shadow_fallback_model(self, request: ModelCallRequest) -> str:
        """What shadow mode hands back when the real policy would have
        denied `request` — `resolve()` must always return a usable model
        name in shadow mode, never `None`, the same way a caller expects
        a real answer in enforce mode.

        Prefers the policy's own `fallback_chain()`, which can be
        non-empty even under a denial — e.g. `BudgetPolicy.fallback_chain`
        forwards to its base regardless of spend (see `BudgetPolicy`
        above), so an over-budget principal still gets back a real,
        already-qualifying candidate rather than nothing. Falls back to
        the bare logical name itself only when the policy has genuinely
        nothing configured for it — the same last-resort behavior
        `AllowAllModels` already uses when there's no routing at all.
        """
        chain = self._policy.fallback_chain(request)
        if chain:
            return chain[0]
        return request.logical_name

    def resolve(
        self, principal: Principal, logical_name: str, context: Optional[dict[str, Any]] = None
    ) -> str:
        """Resolve `logical_name` to a real model name for `principal`.
        Raises `ModelCallDenied` if no candidate qualifies. Make your real
        LLM call with the returned name, using whatever client you
        already have — Marshal doesn't wrap the call itself.

        In shadow mode, never raises: a denial is still computed and
        audited (see `ModelCallEntry`), but this returns a sensible model
        anyway (the policy's own governed fallback if one exists,
        otherwise `logical_name` itself) so the caller's code keeps
        working exactly as if governance weren't wired in yet.
        """
        request = ModelCallRequest(logical_name, principal, context or {})
        decision = self._policy.resolve(request)
        shadow = self._mode == "shadow"

        resolved_model = decision.resolved_model
        if shadow and decision.outcome != "allow":
            resolved_model = self._shadow_fallback_model(request)

        self._audit_sink.write(
            ModelCallEntry(
                timestamp=time.time(),
                principal_id=principal.id,
                logical_name=logical_name,
                resolved_model=resolved_model,
                outcome=decision.outcome,
                reason=decision.reason,
                shadow=shadow,
            )
        )
        if decision.outcome == "deny" and not shadow:
            raise ModelCallDenied(logical_name, decision.reason)
        return resolved_model  # type: ignore[return-value]

    def fallback_chain(
        self, principal: Principal, logical_name: str, context: Optional[dict[str, Any]] = None
    ) -> list[str]:
        """Governed fallback candidates, in order, if the model from
        `resolve` turns out to be unavailable — every name here has
        already cleared the same policy check."""
        request = ModelCallRequest(logical_name, principal, context or {})
        return self._policy.fallback_chain(request)

    def record_usage(
        self, principal: Principal, model: str, prompt_tokens: int, completion_tokens: int
    ) -> None:
        """Report actual token usage after a real call completes, so
        budget-tracking policies (e.g. `BudgetPolicy`) can update spend —
        and so the usage itself shows up in the audit trail, not just as
        invisible internal policy state."""
        self._policy.record_usage(principal, model, prompt_tokens, completion_tokens)
        self._audit_sink.write(
            ModelUsageEntry(
                timestamp=time.time(),
                principal_id=principal.id,
                model=model,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
            )
        )

    def record_outcome(
        self,
        principal: Principal,
        model: str,
        success: bool,
        latency_ms: Optional[float] = None,
        error: Optional[str] = None,
    ) -> None:
        """Report whether a real call attempt to `model` succeeded, so
        reliability-tracking policies (e.g. `CircuitBreakerPolicy`) can
        update their view of that deployment's health — and so the
        outcome itself lands in the audit trail. Call this for *every*
        attempt, success or failure; `record_usage` above only fires on
        success and only carries cost, not reliability."""
        self._policy.record_outcome(principal, model, success, latency_ms, error)
        self._audit_sink.write(
            ModelOutcomeEntry(
                timestamp=time.time(),
                principal_id=principal.id,
                model=model,
                success=success,
                latency_ms=latency_ms,
                error=error,
            )
        )
