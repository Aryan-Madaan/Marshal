from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Any, Callable, Iterable, Optional

from marshal_ai.audit import AuditSink, InMemoryAuditSink, register_entry_type
from marshal_ai.policy import Principal


@dataclass(frozen=True)
class ToolCallRequest:
    """One agent's attempt to call one tool. `risk_tier` is assigned by the
    caller (you decide what "high risk" means for your tools) — policies
    decide what to *do* with that tier."""

    tool_name: str
    arguments: dict[str, Any]
    principal: Principal
    risk_tier: str = "low"


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


@dataclass(frozen=True)
class ToolCallEntry:
    """A record of one tool-call attempt. `arguments` here are always the
    *redacted* view — see `ToolPolicy.redact_arguments` — never the raw
    ones, so the audit log itself can't leak what a redaction rule was
    meant to hide."""

    timestamp: float
    principal_id: str
    tool_name: str
    arguments: dict[str, Any]
    risk_tier: str
    outcome: str  # "allow" | "deny" | "approved" | "declined"
    reason: str
    approved_by: Optional[str] = None

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
    """

    def __init__(
        self,
        tool: Tool,
        policy: Optional[ToolPolicy] = None,
        audit_sink: Optional[AuditSink] = None,
        approval_handler: Optional[ApprovalHandler] = None,
        tool_name: Optional[str] = None,
    ) -> None:
        self._tool = tool
        self._policy = policy if policy is not None else AllowAllTools()
        self._audit_sink = audit_sink if audit_sink is not None else InMemoryAuditSink()
        self._approval_handler = (
            approval_handler if approval_handler is not None else CLIApprovalHandler()
        )
        self._tool_name = tool_name or getattr(tool, "__name__", "tool")

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
            )
        )

    def call(
        self,
        principal: Principal,
        arguments: dict[str, Any],
        risk_tier: str = "low",
    ) -> Any:
        """Evaluate policy, redact for the audit trail, get approval if
        required, log the outcome, and — only if allowed — actually call
        the wrapped tool with the real (unredacted) arguments.

        Raises `ToolCallDenied` if the policy denies outright, or if a
        required approval is declined.
        """
        request = ToolCallRequest(
            tool_name=self._tool_name,
            arguments=arguments,
            principal=principal,
            risk_tier=risk_tier,
        )
        decision = self._policy.evaluate(request)
        redacted = self._policy.redact_arguments(request)

        if decision.outcome == "deny":
            self._audit(request, redacted, "deny", decision.reason, approved_by=None)
            raise ToolCallDenied(request.tool_name, decision.reason)

        approved_by: Optional[str] = None
        if decision.outcome == "require_approval":
            approved = self._approval_handler.request_approval(request, redacted)
            if not approved:
                self._audit(request, redacted, "declined", decision.reason, approved_by=None)
                raise ToolCallDenied(request.tool_name, "approval declined")
            approved_by = self._approval_handler.identity
            self._audit(request, redacted, "approved", decision.reason, approved_by=approved_by)
        else:
            self._audit(request, redacted, "allow", decision.reason, approved_by=None)

        return self._tool(**arguments)
