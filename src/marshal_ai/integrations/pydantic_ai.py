"""Pydantic AI: govern tool calls by wrapping an agent's toolsets.

    from pydantic_ai import Agent
    from marshal_ai.integrations.pydantic_ai import MarshalToolset

    agent = Agent("openai:gpt-5", toolsets=[MarshalToolset(my_toolset, governor)])

`MarshalToolset` is a Pydantic AI `WrapperToolset`: every `call_tool`
goes through the governor before the wrapped toolset runs it. Wrap any
toolset — a `FunctionToolset`, an MCP server toolset, a combined one. By
default a refused call returns its reason as the tool result, so the
model can recover; `on_deny="raise"` raises `ToolCallDenied` out of the
run instead. Verified against pydantic-ai-slim 1.60
(`WrapperToolset.call_tool(name, tool_args, ctx, tool)`). Requires the
`[pydantic-ai]` extra.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic_ai.toolsets import WrapperToolset

from marshal_ai.integrations._governor import ToolGovernor
from marshal_ai.tools import ToolCallDenied


@dataclass
class MarshalToolset(WrapperToolset):
    governor: ToolGovernor = field(kw_only=True)
    on_deny: Literal["message", "raise"] = field(default="message", kw_only=True)

    def __init__(self, wrapped: Any, governor: ToolGovernor, on_deny: Literal["message", "raise"] = "message") -> None:
        super().__init__(wrapped)
        if on_deny not in ("message", "raise"):
            raise ValueError("on_deny must be 'message' or 'raise'")
        self.governor = governor
        self.on_deny = on_deny

    async def call_tool(self, name: str, tool_args: dict[str, Any], ctx: Any, tool: Any) -> Any:
        result = self.governor.check(name, tool_args, context={"pydantic_ai_run_step": getattr(ctx, "run_step", None)})
        if not result.allowed:
            if self.on_deny == "raise":
                raise ToolCallDenied(name, result.reason)
            return f"Tool call blocked by policy: {result.reason}"
        start = time.monotonic()
        try:
            output = await super().call_tool(name, tool_args, ctx, tool)
        except Exception as exc:
            self.governor.record_outcome(name, tool_args, False, (time.monotonic() - start) * 1000, type(exc).__name__)
            raise
        self.governor.record_outcome(name, tool_args, True, (time.monotonic() - start) * 1000)
        return output
