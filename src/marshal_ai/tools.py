from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Iterable, Optional

from marshal_ai.audit import AuditSink, InMemoryAuditSink, register_entry_type
from marshal_ai.policy import GuardMode, Principal


@dataclass(frozen=True)
class ToolCallRequest:
    """One agent's attempt to call one tool. `risk_tier` is assigned by the
    caller (you decide what "high risk" means for your tools) — policies
    decide what to *do* with that tier. `context` mirrors
    `ModelCallRequest.context` — free-form, policy-interpreted extra
    facts about this specific call (e.g. jurisdiction) that don't belong
    on the principal's own identity."""

    tool_name: str
    arguments: dict[str, Any]
    principal: Principal
    risk_tier: str = "low"
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolDecision:
    outcome: str  # "allow" | "deny" | "require_approval"
    reason: str


class ToolCallDenied(Exception):
    """Raised when a call is blocked outright, or a required approval is
    declined. Deliberately loud — a blocked tool call should never look
    like a silent no-op to the caller's code."""

    def __init__(self, tool_name: str, reason: str) -> None:
        self.tool_name = tool_name
        self.reason = reason
        super().__init__(f"Tool call to {tool_name!r} denied: {reason}")


class ToolPolicy(ABC):
    """Decides what happens when a principal tries to call a tool.
    Implement this to back it with your own risk model (a DB lookup, an
    OPA call, a simple risk-tier table)."""

    @abstractmethod
    def evaluate(self, request: ToolCallRequest) -> ToolDecision: ...

    def redact_arguments(self, request: ToolCallRequest) -> dict[str, Any]:
        """Called before arguments are written to the audit trail or shown
        to an approver. Default: no redaction. Override, or wrap with
        `RedactingToolPolicy`, to strip specific argument values — the
        underlying tool still receives the real arguments; only what gets
        logged/displayed is affected.
        """
        return dict(request.arguments)


class AllowAllTools(ToolPolicy):
    """No enforcement — audit trail only. The default if you don't pass a
    policy, same philosophy as `marshal_ai.policy.AllowAll`: adopt Marshal
    for visibility first, turn on real enforcement once you know what your
    actual risk tiers should block."""

    def evaluate(self, request: ToolCallRequest) -> ToolDecision:
        return ToolDecision("allow", "AllowAllTools policy")


class RiskTierPolicy(ToolPolicy):
    """The default real policy: maps each `risk_tier` to an outcome via a
    lookup table. Any tier not in the table falls back to `default`.

    Example: `RiskTierPolicy({"low": "allow", "medium": "require_approval",
    "high": "deny"})` — the shape most tool-governance setups actually
    want to start from.
    """

    _VALID_OUTCOMES = {"allow", "deny", "require_approval"}

    def __init__(self, tiers: dict[str, str], default: str = "require_approval") -> None:
        for tier, outcome in {**tiers, "__default__": default}.items():
            if outcome not in self._VALID_OUTCOMES:
                raise ValueError(
                    f"invalid outcome {outcome!r} for tier {tier!r}; "
                    f"must be one of {sorted(self._VALID_OUTCOMES)}"
                )
        self._tiers = dict(tiers)
        self._default = default

    def evaluate(self, request: ToolCallRequest) -> ToolDecision:
        outcome = self._tiers.get(request.risk_tier, self._default)
        if request.risk_tier in self._tiers:
            reason = f"risk tier {request.risk_tier!r} maps to {outcome!r}"
        else:
            reason = f"risk tier {request.risk_tier!r} not configured, default {outcome!r}"
        return ToolDecision(outcome, reason)


_OUTCOME_SEVERITY = {"allow": 0, "require_approval": 1, "deny": 2}


class JurisdictionalRiskTierPolicy(ToolPolicy):
    """Wraps another `ToolPolicy`, keeping its decision unchanged unless
    the request's jurisdiction requires *more* oversight than the base
    policy already gives it — answers a different question from
    `ResidencyPolicy`/`RetentionPolicy` (`marshal_ai.models`): not "where
    can this data go" or "how long can it be kept," but "does this
    specific *action* require mandatory human oversight before it
    happens, given a risk classification that can itself vary by
    jurisdiction" — the EU AI Act's Annex III high-risk categories
    (employment, creditworthiness, and others) being the sharpest
    example: the same tool call can be Annex-III high-risk specifically
    in the EU and carry no equivalent classification elsewhere.

    Reads jurisdiction from `request.context["jurisdiction"]` — same
    context-not-principal-attribute reasoning as `ResidencyPolicy`: which
    regulatory regime applies is a property of whose data/decision this
    call concerns, not of who's making it. If jurisdiction is absent,
    this policy is a no-op and defers entirely to the base — unlike
    `ResidencyPolicy`, there's no fail-closed default here, since AI-Act-
    style classification (unlike a cross-border transfer) genuinely may
    not apply at all outside a jurisdiction that regulates it.

    `overrides_by_jurisdiction` maps jurisdiction -> {risk_tier: outcome}.
    The override is **monotonic — it can only tighten, never loosen**: if
    the base policy already resolved to something at least as strict
    (`deny` > `require_approval` > `allow`), the override is ignored and
    the base's own decision (and reason) passes through unchanged. This
    can never be used to bypass a base policy's stricter judgment, only
    to add oversight a jurisdiction-blind base policy wouldn't have
    known to require — the same non-bypassable-fallback principle
    `AllowlistModelPolicy.fallback_chain` already establishes elsewhere.
    """

    def __init__(self, base: ToolPolicy, overrides_by_jurisdiction: dict[str, dict[str, str]]) -> None:
        for jurisdiction, tiers in overrides_by_jurisdiction.items():
            for tier, outcome in tiers.items():
                if outcome not in _OUTCOME_SEVERITY:
                    raise ValueError(
                        f"invalid outcome {outcome!r} for jurisdiction {jurisdiction!r}, "
                        f"tier {tier!r}; must be one of {sorted(_OUTCOME_SEVERITY)}"
                    )
        self._base = base
        self._overrides = overrides_by_jurisdiction

    def evaluate(self, request: ToolCallRequest) -> ToolDecision:
        base_decision = self._base.evaluate(request)
        jurisdiction = request.context.get("jurisdiction")
        if jurisdiction is None:
            return base_decision
        override_outcome = self._overrides.get(jurisdiction, {}).get(request.risk_tier)
        if override_outcome is None:
            return base_decision
        if _OUTCOME_SEVERITY[override_outcome] <= _OUTCOME_SEVERITY[base_decision.outcome]:
            return base_decision
        return ToolDecision(
            override_outcome,
            f"jurisdiction {jurisdiction!r} requires {override_outcome!r} for risk tier "
            f"{request.risk_tier!r} (base policy would have allowed {base_decision.outcome!r})",
        )

    def redact_arguments(self, request: ToolCallRequest) -> dict[str, Any]:
        return self._base.redact_arguments(request)


@dataclass(frozen=True)
class ArgumentRedaction:
    """A rule for RedactingToolPolicy: hide argument `name` in the audit
    log / approval prompt unless the principal has `requires_attribute`.
    The wrapped tool itself always receives the real, unredacted value."""

    name: str
    requires_attribute: str
    replacement: str = "[REDACTED]"


class RedactingToolPolicy(ToolPolicy):
    """Wraps another policy, keeping its allow/deny/approve decision
    unchanged, and additionally redacts specific argument values from what
    gets audited or shown to an approver — e.g. everyone can be seen
    calling `update_employee_record`, but the actual salary value in the
    arguments only shows up in the log for principals with `role:hr`.
    """

    def __init__(self, base: ToolPolicy, rules: Iterable[ArgumentRedaction]) -> None:
        self._base = base
        self._rules = list(rules)

    def evaluate(self, request: ToolCallRequest) -> ToolDecision:
        return self._base.evaluate(request)

    def redact_arguments(self, request: ToolCallRequest) -> dict[str, Any]:
        arguments = self._base.redact_arguments(request)
        for rule in self._rules:
            if rule.requires_attribute in request.principal.attributes:
                continue
            if rule.name in arguments:
                arguments[rule.name] = rule.replacement
        return arguments


class RateLimitPolicy(ToolPolicy):
    """Wraps another `ToolPolicy`, keeping its decision unchanged unless a
    principal has made more than `max_calls` calls (of any kind, to any
    tool, allowed or not) within the trailing `window_seconds` — a cheap,
    deterministic backstop against both abuse and an agent's own bugs,
    independent of whether any individual call would otherwise be allowed.

    Every call to `evaluate()` counts toward the limit, including ones the
    base policy would deny anyway — a rate limit caps *how often* a
    principal is attempting something, not just how often they succeed.
    Denies outright once the limit is exceeded; does not touch
    `redact_arguments`, which always defers to the base policy.
    """

    def __init__(self, base: ToolPolicy, max_calls: int, window_seconds: float) -> None:
        self._base = base
        self._max_calls = max_calls
        self._window_seconds = window_seconds
        self._calls: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _record_and_count(self, principal_id: str) -> int:
        now = time.monotonic()
        cutoff = now - self._window_seconds
        with self._lock:
            recent = [t for t in self._calls.get(principal_id, []) if t >= cutoff]
            recent.append(now)
            self._calls[principal_id] = recent
            return len(recent)

    def evaluate(self, request: ToolCallRequest) -> ToolDecision:
        count = self._record_and_count(request.principal.id)
        if count > self._max_calls:
            return ToolDecision(
                "deny",
                f"rate limit exceeded for {request.principal.id!r}: {count} calls "
                f"within the last {self._window_seconds:.0f}s (limit {self._max_calls})",
            )
        return self._base.evaluate(request)

    def redact_arguments(self, request: ToolCallRequest) -> dict[str, Any]:
        return self._base.redact_arguments(request)


class RunawayAgentPolicy(ToolPolicy):
    """Wraps another `ToolPolicy`; trips a specific *principal* — not a
    tool, not a deployment — once they've made `identical_call_threshold`
    calls to the *same* tool with the *same* arguments within
    `window_seconds`. Catches the failure mode `RateLimitPolicy` and
    `BudgetPolicy` both miss: an agent stuck in a broken retry loop,
    calling one tool with one fixed set of arguments hundreds of times in
    a few seconds — high frequency isn't the tell (a legitimately busy
    agent can be just as fast), *repetition* is.

    Deliberately named differently from `CircuitBreakerPolicy`
    (`marshal_ai.models`), which trips a *model deployment* based on
    *failure rate* — a different axis entirely (a runaway loop can be
    "succeeding" on every identical call and still be exactly the bug this
    class exists to catch).

    Deliberately does **not** self-heal on a timer the way
    `CircuitBreakerPolicy` does. A loop that's already run away doesn't
    stop being a bug once a time window elapses — once tripped, a
    principal stays denied until `reset(principal_id)` is called
    explicitly, matching the backlog's own framing: this requires a human
    decision that the loop is actually fixed, not a timeout guessing that
    it might be.

    Scope, stated plainly: only the identical-call trigger is implemented
    here. A parallel "N *failed* calls" trigger was also considered, but
    it needs `ToolGuard` to report call outcomes the way `ModelGuard.
    record_outcome` does — that plumbing doesn't exist yet for tool calls,
    so it's tracked as a named follow-up in `ideas.md` rather than
    bundled into this class before the mechanism it would depend on
    exists.
    """

    def __init__(
        self, base: ToolPolicy, identical_call_threshold: int, window_seconds: float
    ) -> None:
        self._base = base
        self._identical_call_threshold = identical_call_threshold
        self._window_seconds = window_seconds
        self._recent_calls: dict[str, list[tuple[float, str, dict[str, Any]]]] = {}
        self._tripped: set[str] = set()
        self._lock = threading.Lock()

    def _identical_count(self, request: ToolCallRequest) -> int:
        now = time.monotonic()
        cutoff = now - self._window_seconds
        with self._lock:
            recent = [
                (t, name, args)
                for t, name, args in self._recent_calls.get(request.principal.id, [])
                if t >= cutoff
            ]
            recent.append((now, request.tool_name, request.arguments))
            self._recent_calls[request.principal.id] = recent
            return sum(
                1
                for _, name, args in recent
                if name == request.tool_name and args == request.arguments
            )

    def evaluate(self, request: ToolCallRequest) -> ToolDecision:
        principal_id = request.principal.id
        with self._lock:
            already_tripped = principal_id in self._tripped
        if already_tripped:
            return ToolDecision(
                "deny",
                f"runaway-agent breaker tripped for {principal_id!r} — "
                f"requires a human reset() before this principal can call anything again",
            )

        count = self._identical_count(request)
        if count >= self._identical_call_threshold:
            with self._lock:
                self._tripped.add(principal_id)
            return ToolDecision(
                "deny",
                f"runaway-agent breaker tripped for {principal_id!r}: {count} identical "
                f"calls to {request.tool_name!r} within {self._window_seconds:.0f}s "
                f"(threshold {self._identical_call_threshold}) — requires a human reset()",
            )
        return self._base.evaluate(request)

    def redact_arguments(self, request: ToolCallRequest) -> dict[str, Any]:
        return self._base.redact_arguments(request)

    def reset(self, principal_id: str) -> None:
        """Clear a tripped principal so they can call tools again — the
        explicit human decision this class requires instead of a timeout.
        A no-op if that principal was never tripped."""
        with self._lock:
            self._tripped.discard(principal_id)
            self._recent_calls.pop(principal_id, None)

    def is_tripped(self, principal_id: str) -> bool:
        with self._lock:
            return principal_id in self._tripped


class ApprovalHandler(ABC):
    """Decides whether a REQUIRE_APPROVAL call actually proceeds. Gets the
    already-redacted arguments — never the raw ones — so an approver never
    sees more than the policy says they should."""

    @abstractmethod
    def request_approval(
        self, request: ToolCallRequest, redacted_arguments: dict[str, Any]
    ) -> bool: ...

    identity: str = "approver"


class CLIApprovalHandler(ApprovalHandler):
    """Blocks the calling thread and prompts on stdin/stdout. No queue, no
    async — this is the "actually runnable today" v0.1 approval path for a
    single local script or a human sitting at the terminal. A real
    deployment (a Slack approval button, a web queue) means implementing
    `ApprovalHandler` yourself; the interface is intentionally this thin.
    """

    identity = "cli-approver"

    def request_approval(
        self, request: ToolCallRequest, redacted_arguments: dict[str, Any]
    ) -> bool:
        print(
            f"[marshal] approval requested: {request.principal.id} wants to call "
            f"{request.tool_name}({redacted_arguments}) (risk tier: {request.risk_tier})"
        )
        answer = input("Approve? [y/N] ").strip().lower()
        return answer == "y"


class AutoApprove(ApprovalHandler):
    """Testing/scripting convenience — approves or denies every request
    without prompting. Not for production use (that's exactly the "let an
    automated system rubber-stamp risky actions" trap); use it for tests
    and local dev only."""

    identity = "auto-approve"

    def __init__(self, approve: bool = True) -> None:
        self._approve = approve

    def request_approval(
        self, request: ToolCallRequest, redacted_arguments: dict[str, Any]
    ) -> bool:
        return self._approve


def _redacted_argument_names(raw: dict[str, Any], redacted: dict[str, Any]) -> list[str]:
    """Which argument keys `ToolPolicy.redact_arguments()` actually
    changed relative to the real, raw arguments — names only, never the
    raw or redacted values, so this is safe to audit even in shadow mode
    without leaking what a redaction rule would have hidden.
    """
    return sorted(key for key, value in raw.items() if redacted.get(key, value) != value)


@dataclass(frozen=True)
class ToolCallEntry:
    """A record of one tool-call attempt. `arguments` here are always the
    *redacted* view — see `ToolPolicy.redact_arguments` — never the raw
    ones, so the audit log itself can't leak what a redaction rule was
    meant to hide.

    `shadow` — True when this entry was written by a `ToolGuard` running
    in shadow mode: `outcome`/`reason` below are still the real policy's
    decision, computed and audited exactly as in enforce mode, but never
    acted on — the wrapped tool was called regardless of what `outcome`
    says, and no approval was ever requested even when `outcome` is
    `"require_approval"` (a value only ever seen on shadow entries;
    enforce mode always resolves it to `"approved"`/`"declined"` first).
    Because `outcome` keeps its enforce-mode vocabulary, a shadow "deny"
    entry still shows up under `AuditSink.query(denied_only=True)` and
    the CLI's `!` flag for free — exactly what shadow mode exists to
    surface, with no changes needed to either consumer.

    `would_redact_fields` — argument key names `redact_arguments()`
    would change relative to the real arguments, regardless of mode —
    names only, never values, so a reader can see *what* a redaction
    rule targets without the audit trail itself becoming a second copy
    of what it's meant to hide.
    """

    timestamp: float
    principal_id: str
    tool_name: str
    arguments: dict[str, Any]
    risk_tier: str
    outcome: str  # "allow" | "deny" | "approved" | "declined" | "require_approval" (shadow only)
    reason: str
    approved_by: Optional[str] = None
    shadow: bool = False
    would_redact_fields: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "tool_call", **asdict(self)}


register_entry_type("tool_call", ToolCallEntry)


Tool = Callable[..., Any]


class ToolGuard:
    """Wraps a callable tool with governance: policy-based allow / deny /
    require-approval, argument redaction in the audit trail, and an audit
    entry written to the same kind of `AuditSink` `RetrievalGuard` uses —
    share one sink between guards and `sink.query(...)` covers both
    surfaces in one place.

    `mode="enforce"` (the default) is today's behavior unchanged: a deny
    raises, a require-approval decision blocks on the approval handler.
    `mode="shadow"` still evaluates the policy and writes the identical
    audit entry, but never raises and never requests approval — the
    wrapped tool is always called with the real arguments, letting a team
    see what governance *would* have blocked before turning enforcement on.
    """

    def __init__(
        self,
        tool: Tool,
        policy: Optional[ToolPolicy] = None,
        audit_sink: Optional[AuditSink] = None,
        approval_handler: Optional[ApprovalHandler] = None,
        tool_name: Optional[str] = None,
        mode: GuardMode = "enforce",
    ) -> None:
        self._tool = tool
        self._policy = policy if policy is not None else AllowAllTools()
        self._audit_sink = audit_sink if audit_sink is not None else InMemoryAuditSink()
        self._approval_handler = (
            approval_handler if approval_handler is not None else CLIApprovalHandler()
        )
        self._tool_name = tool_name or getattr(tool, "__name__", "tool")
        self._mode = mode

    @property
    def audit_log(self) -> AuditSink:
        return self._audit_sink

    def _audit(
        self,
        request: ToolCallRequest,
        redacted_arguments: dict[str, Any],
        outcome: str,
        reason: str,
        approved_by: Optional[str],
        shadow: bool = False,
        would_redact_fields: Optional[list[str]] = None,
    ) -> None:
        self._audit_sink.write(
            ToolCallEntry(
                timestamp=time.time(),
                principal_id=request.principal.id,
                tool_name=request.tool_name,
                arguments=redacted_arguments,
                risk_tier=request.risk_tier,
                outcome=outcome,
                reason=reason,
                approved_by=approved_by,
                shadow=shadow,
                would_redact_fields=would_redact_fields or [],
            )
        )

    def call(
        self,
        principal: Principal,
        arguments: dict[str, Any],
        risk_tier: str = "low",
        context: Optional[dict[str, Any]] = None,
    ) -> Any:
        """Evaluate policy, redact for the audit trail, get approval if
        required, log the outcome, and — only if allowed — actually call
        the wrapped tool with the real (unredacted) arguments.

        Raises `ToolCallDenied` if the policy denies outright, or if a
        required approval is declined — unless this guard is in shadow
        mode (see the class docstring), in which case the decision is
        still computed and audited but never enforced: this never raises,
        never requests approval, and always calls the wrapped tool.
        """
        request = ToolCallRequest(
            tool_name=self._tool_name,
            arguments=arguments,
            principal=principal,
            risk_tier=risk_tier,
            context=context or {},
        )
        decision = self._policy.evaluate(request)
        redacted = self._policy.redact_arguments(request)
        would_redact_fields = _redacted_argument_names(request.arguments, redacted)

        if self._mode == "shadow":
            # decision.outcome is audited verbatim ("allow"/"deny"/
            # "require_approval") — the real policy's raw answer, not
            # translated into "approved"/"declined" the way enforce mode
            # does, since no approval flow ever runs here.
            self._audit(
                request,
                redacted,
                decision.outcome,
                decision.reason,
                approved_by=None,
                shadow=True,
                would_redact_fields=would_redact_fields,
            )
            return self._tool(**arguments)

        if decision.outcome == "deny":
            self._audit(
                request, redacted, "deny", decision.reason, approved_by=None,
                would_redact_fields=would_redact_fields,
            )
            raise ToolCallDenied(request.tool_name, decision.reason)

        approved_by: Optional[str] = None
        if decision.outcome == "require_approval":
            approved = self._approval_handler.request_approval(request, redacted)
            if not approved:
                self._audit(
                    request, redacted, "declined", decision.reason, approved_by=None,
                    would_redact_fields=would_redact_fields,
                )
                raise ToolCallDenied(request.tool_name, "approval declined")
            approved_by = self._approval_handler.identity
            self._audit(
                request, redacted, "approved", decision.reason, approved_by=approved_by,
                would_redact_fields=would_redact_fields,
            )
        else:
            self._audit(
                request, redacted, "allow", decision.reason, approved_by=None,
                would_redact_fields=would_redact_fields,
            )

        return self._tool(**arguments)
