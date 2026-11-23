"""Microsoft Agent Framework: govern tool (function) calls with function
middleware.

    from agent_framework import ChatAgent
    from marshal_ai.integrations.agent_framework import MarshalFunctionMiddleware

    agent = ChatAgent(chat_client=client, tools=[...], middleware=[MarshalFunctionMiddleware(governor)])

Agent Framework (the AutoGen + Semantic Kernel successor) runs every
function call through `FunctionMiddleware.process(context, call_next)`.
A refused call never calls `call_next()`: by default `context.result` is
set to Marshal's reason, which the framework returns to the model as the
tool result; `on_deny="raise"` raises the framework's own
`MiddlewareFailure`, which aborts the run fail-closed. Outcomes (success,
failure, latency) are reported for reliability policies.

Register it after any argument-repair middleware: Agent Framework's own
guidance is that policy middleware must inspect the effective arguments,
and it fails closed if they change after security middleware ran.
Verified against agent-framework-core 1.26. Requires the
`[agent-framework]` extra.
"""

from __future__ import annotations

import time
from typing import Any, Awaitable, Callable, Literal

from agent_framework import FunctionMiddleware, MiddlewareFailure

from marshal_ai.integrations._governor import ToolGovernor


def _arguments(context: Any) -> Any:
    args = context.arguments
    if hasattr(args, "model_dump"):
        return args.model_dump()
    return dict(args) if hasattr(args, "items") else args


class MarshalFunctionMiddleware(FunctionMiddleware):
    def __init__(self, governor: ToolGovernor, on_deny: Literal["message", "raise"] = "message") -> None:
        if on_deny not in ("message", "raise"):
            raise ValueError("on_deny must be 'message' or 'raise'")
        self._governor = governor
        self._on_deny = on_deny

    async def process(self, context: Any, call_next: Callable[[], Awaitable[None]]) -> None:
        name = getattr(context.function, "name", "function")
        arguments = _arguments(context)
        result = self._governor.check(name, arguments)
        if not result.allowed:
            if self._on_deny == "raise":
                raise MiddlewareFailure(f"Tool call to {name!r} blocked by policy: {result.reason}")
            context.result = f"Tool call blocked by policy: {result.reason}"
            return
        start = time.monotonic()
        try:
            await call_next()
        except Exception as exc:
            self._governor.record_outcome(name, arguments, False, (time.monotonic() - start) * 1000, type(exc).__name__)
            raise
        self._governor.record_outcome(name, arguments, True, (time.monotonic() - start) * 1000)
