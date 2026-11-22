"""LangChain v1 / LangGraph: govern tool calls with agent middleware.

    from langchain.agents import create_agent
    from marshal_ai.integrations._governor import ToolGovernor
    from marshal_ai.integrations.langchain import MarshalToolMiddleware

    governor = ToolGovernor(policy=RiskTierPolicy({...}), principal=agent_principal,
                            risk_tiers={"delete_user": "high"})
    agent = create_agent(model, tools=[...], middleware=[MarshalToolMiddleware(governor)])

Uses LangChain's own `wrap_tool_call`/`awrap_tool_call` hook (verified
against langchain 1.5), which every tool call an agent built with
`create_agent` makes passes through — sync and async. A refused call
never reaches the tool: by default the model gets an error `ToolMessage`
explaining the refusal (so the agent can recover or tell the user);
`on_deny="raise"` raises `ToolCallDenied` out of the agent run instead.

Requires `langchain>=1.0` (the `[langchain]` extra).
"""

from __future__ import annotations

from typing import Any, Callable, Literal, Optional

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import ToolMessage

from marshal_ai.integrations._governor import GovernorResult, ToolGovernor
from marshal_ai.policy import Principal
from marshal_ai.tools import ToolCallDenied


class MarshalToolMiddleware(AgentMiddleware):
    """`principal_from_request` — optional `(request) -> Principal` for
    agents whose identity is in the run's state/runtime context; otherwise
    the governor's own `principal` is used."""

    def __init__(
        self,
        governor: ToolGovernor,
        on_deny: Literal["message", "raise"] = "message",
        principal_from_request: Optional[Callable[[Any], Principal]] = None,
    ) -> None:
        super().__init__()
        if on_deny not in ("message", "raise"):
            raise ValueError("on_deny must be 'message' or 'raise'")
        self._governor = governor
        self._on_deny = on_deny
        self._principal_from_request = principal_from_request

    def _check(self, request: Any) -> tuple[GovernorResult, dict]:
        call = request.tool_call
        principal = self._principal_from_request(request) if self._principal_from_request else None
        result = self._governor.check(call["name"], call.get("args", {}), principal=principal)
        return result, call

    def _refusal(self, result: GovernorResult, call: dict) -> ToolMessage:
        if self._on_deny == "raise":
            raise ToolCallDenied(call["name"], result.reason)
        return ToolMessage(
            content=f"Tool call blocked by policy: {result.reason}",
            tool_call_id=call.get("id") or "",
            name=call["name"],
            status="error",
        )

    def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        result, call = self._check(request)
        if not result.allowed:
            return self._refusal(result, call)
        return handler(request)

    async def awrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
        result, call = self._check(request)
        if not result.allowed:
            return self._refusal(result, call)
        return await handler(request)
