from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from marshal_ai.audit import AuditSink, InMemoryAuditSink, register_entry_type
from marshal_ai.policy import Principal


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

    def spent_by(self, principal_id: str) -> float:
        return self._spent.get(principal_id, 0.0)


@dataclass(frozen=True)
class ModelCallEntry:
    timestamp: float
    principal_id: str
    logical_name: str
    resolved_model: Optional[str]
    outcome: str  # "allow" | "deny"
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "model_call", **asdict(self)}


register_entry_type("model_call", ModelCallEntry)


class ModelGuard:
    """Resolves logical model names through a policy, audits every
    resolution, and forwards usage reports for budget tracking — sharing
    the same `AuditSink` as `RetrievalGuard`/`ToolGuard` if you pass one
    in, for one trail across every surface."""

    def __init__(
        self,
        policy: Optional[ModelPolicy] = None,
        audit_sink: Optional[AuditSink] = None,
    ) -> None:
        self._policy = policy if policy is not None else AllowAllModels()
        self._audit_sink = audit_sink if audit_sink is not None else InMemoryAuditSink()

    @property
    def audit_log(self) -> AuditSink:
        return self._audit_sink

    def resolve(
        self, principal: Principal, logical_name: str, context: Optional[dict[str, Any]] = None
    ) -> str:
        """Resolve `logical_name` to a real model name for `principal`.
        Raises `ModelCallDenied` if no candidate qualifies. Make your real
        LLM call with the returned name, using whatever client you
        already have — Marshal doesn't wrap the call itself."""
        request = ModelCallRequest(logical_name, principal, context or {})
        decision = self._policy.resolve(request)
        self._audit_sink.write(
            ModelCallEntry(
                timestamp=time.time(),
                principal_id=principal.id,
                logical_name=logical_name,
                resolved_model=decision.resolved_model,
                outcome=decision.outcome,
                reason=decision.reason,
            )
        )
        if decision.outcome == "deny":
            raise ModelCallDenied(logical_name, decision.reason)
        return decision.resolved_model  # type: ignore[return-value]

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
        budget-tracking policies (e.g. `BudgetPolicy`) can update spend."""
        self._policy.record_usage(principal, model, prompt_tokens, completion_tokens)
