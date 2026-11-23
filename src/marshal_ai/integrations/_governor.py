"""The one tool-governance check every native framework adapter shares.

Each framework has its own way to say "don't run this tool" — LangChain
middleware returns an error `ToolMessage`, a Claude Agent SDK hook returns
`permissionDecision: "deny"`, an ADK plugin returns a short-circuit
result, an OpenAI Agents guardrail returns `reject_content`, a LiteLLM
guardrail raises. What's identical is the decision itself, so it lives
here once: `ToolGovernor.check()` runs `ToolGuard.authorize()` (policy,
redaction, approval, audit — the same path `ToolGuard.call()` takes) and
reports the outcome without raising, leaving the framework-specific
translation to each adapter.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Callable, Optional, Union

from marshal_ai.audit import AuditSink, InMemoryAuditSink
from marshal_ai.policy import GuardMode, Principal
from marshal_ai.tools import (
    ApprovalDeferredToHost,
    ApprovalHandler,
    CLIApprovalHandler,
    ToolCallDenied,
    ToolDecision,
    ToolGuard,
    ToolPolicy,
)

PrincipalSource = Union[Principal, Callable[[], Principal]]


@dataclass(frozen=True)
class GovernorResult:
    allowed: bool
    reason: str
    # True when the decision was handed to the host's own prompt
    # (`DeferToHostApprovalHandler`), rather than denied.
    deferred: bool = False


class _ForcedDeny(ToolPolicy):
    def __init__(self, reason: str) -> None:
        self._reason = reason

    def evaluate(self, request: Any) -> ToolDecision:
        return ToolDecision("deny", self._reason)


class ToolGovernor:
    """Configuration shared by every adapter: the `ToolPolicy`, the audit
    sink, the approval handler, how tool names map to risk tiers, and the
    guard mode. `principal` is a `Principal` or a zero-argument callable
    returning one (e.g. reading a contextvar your request handler sets);
    adapters whose framework carries identity per call can override it."""

    def __init__(
        self,
        policy: Optional[ToolPolicy] = None,
        principal: Optional[PrincipalSource] = None,
        risk_tiers: Optional[dict[str, str]] = None,
        default_risk_tier: str = "low",
        audit_sink: Optional[AuditSink] = None,
        approval_handler: Optional[ApprovalHandler] = None,
        mode: GuardMode = "enforce",
        audit_outcomes: bool = False,
        policy_version: Optional[str] = None,
    ) -> None:
        self.policy = policy
        self._principal = principal
        self.risk_tiers = dict(risk_tiers) if risk_tiers else {}
        self.default_risk_tier = default_risk_tier
        self.audit_sink = audit_sink if audit_sink is not None else InMemoryAuditSink()
        self.approval_handler = approval_handler if approval_handler is not None else CLIApprovalHandler()
        self.mode = mode
        self.audit_outcomes = audit_outcomes
        self.policy_version = policy_version

    def _guard(
        self, tool_name: str, mcp_server: Optional[str], policy: Any = None,
        approval_handler: Optional[ApprovalHandler] = None,
    ) -> ToolGuard:
        return ToolGuard(
            policy=policy if policy is not None else self.policy,
            audit_sink=self.audit_sink,
            approval_handler=approval_handler if approval_handler is not None else self.approval_handler,
            tool_name=tool_name,
            mode=self.mode,
            mcp_server=mcp_server,
            audit_outcomes=self.audit_outcomes,
            policy_version=self.policy_version,
        )

    def _tier(self, tool_name: str, tier_aliases: tuple[str, ...]) -> str:
        # `tier_aliases` (e.g. the full "mcp__crm__delete_account" form)
        # are looked up first, then the bare name, then the default.
        return next(
            (self.risk_tiers[key] for key in (*tier_aliases, tool_name) if key in self.risk_tiers),
            self.default_risk_tier,
        )

    def record_outcome(
        self,
        tool_name: str,
        arguments: Any,
        success: bool,
        latency_ms: Optional[float] = None,
        error: Optional[str] = None,
        principal: Optional[Principal] = None,
        mcp_server: Optional[str] = None,
        tier_aliases: tuple[str, ...] = (),
    ) -> None:
        """Report what happened to a call `check()` allowed, so
        reliability policies (`ToolCircuitBreakerPolicy`,
        `RunawayAgentPolicy(failed_call_threshold=...)`) see it. Never
        raises: a reporting problem must not turn a successful tool call
        into a failed one."""
        try:
            resolved = self.resolve_principal(principal)
            args = arguments if isinstance(arguments, dict) else {}
            self._guard(tool_name, mcp_server).record_outcome(
                resolved, args, success, latency_ms, error, self._tier(tool_name, tier_aliases)
            )
        except Exception:
            pass

    def resolve_principal(self, override: Optional[Principal] = None) -> Principal:
        if override is not None:
            return override
        if self._principal is None:
            raise ValueError("no principal configured for this ToolGovernor and none supplied for the call")
        if isinstance(self._principal, Principal):
            return self._principal
        return self._principal()

    def check(
        self,
        tool_name: str,
        arguments: Any,
        principal: Optional[Principal] = None,
        context: Optional[dict[str, Any]] = None,
        mcp_server: Optional[str] = None,
        tier_aliases: tuple[str, ...] = (),
        approval_handler: Optional[ApprovalHandler] = None,
        policy_override_reason: Optional[str] = None,
    ) -> GovernorResult:
        """Authorize one tool call. Never raises for a governance
        decision: returns `allowed=False` with the reason instead. A
        non-dict `arguments` (malformed tool-call JSON from a model) is a
        denial, never a pass-through. Arguments are deep-copied before
        evaluation, so nothing the framework does to its own dict
        afterwards can change what was evaluated. `tier_aliases` are other
        names the tool may be configured under in `risk_tiers`."""
        if not isinstance(arguments, dict):
            reason = f"tool arguments must be a JSON object, got {type(arguments).__name__} — failing closed"
            arguments = {"_raw": repr(arguments)[:200]}
            forced_deny = reason
        else:
            forced_deny = policy_override_reason
        try:
            resolved = self.resolve_principal(principal)
        except Exception as exc:
            return GovernorResult(False, f"could not resolve principal ({type(exc).__name__}) — failing closed")

        policy = self.policy
        if forced_deny is not None:
            # Audited through the ordinary deny path, with the real reason.
            policy = _ForcedDeny(forced_deny)
        guard = self._guard(tool_name, mcp_server, policy, approval_handler)
        tier = self._tier(tool_name, tier_aliases)
        try:
            evaluated = copy.deepcopy(arguments)
        except Exception:
            evaluated = dict(arguments)
        try:
            decision = guard.authorize(resolved, evaluated, risk_tier=tier, context=context)
        except ApprovalDeferredToHost as exc:
            return GovernorResult(False, exc.reason, deferred=True)
        except ToolCallDenied as exc:
            return GovernorResult(False, forced_deny or exc.reason)
        return GovernorResult(True, decision.reason)
