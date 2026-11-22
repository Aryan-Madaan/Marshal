"""OpenAI Agents SDK: govern function-tool calls with a tool input
guardrail.

    from agents import Agent, function_tool
    from marshal_ai.integrations.openai_agents import govern_tools, marshal_tool_guardrail

    guardrail = marshal_tool_guardrail(governor)

    @function_tool(tool_input_guardrails=[guardrail])
    def refund(order_id: str, amount: float) -> str: ...

    # or attach to every function tool an agent already has:
    govern_tools(agent, guardrail)

A refused call returns `ToolGuardrailFunctionOutput.reject_content(...)`:
the tool doesn't run and the model receives Marshal's reason as the tool
result, so the run continues. Arguments arrive as the model's raw JSON
string; JSON that doesn't parse to an object is refused (fail closed).
Verified against openai-agents 0.25 (`ToolInputGuardrail`,
`ToolInputGuardrailData.context.tool_name/tool_arguments`).

Scope, stated plainly: tool guardrails apply to *function tools*. Hosted
tools (web search, file search, hosted MCP, code interpreter) execute on
OpenAI's side and never pass through them — govern those at the request
with `marshal_ai.integrations.enable(..., hosted_tools=...)`. Requires
the `[openai-agents]` extra.
"""

from __future__ import annotations

import json
from typing import Any

from agents import ToolGuardrailFunctionOutput, ToolInputGuardrail

from marshal_ai.integrations._governor import ToolGovernor


def marshal_tool_guardrail(governor: ToolGovernor, name: str = "marshal") -> ToolInputGuardrail:
    def check(data: Any) -> ToolGuardrailFunctionOutput:
        ctx = data.context
        raw = getattr(ctx, "tool_arguments", None) or "{}"
        try:
            arguments = json.loads(raw) if isinstance(raw, str) else raw
        except (TypeError, ValueError):
            arguments = raw  # not a dict -> the governor refuses it
        result = governor.check(getattr(ctx, "tool_name", "tool"), arguments)
        if result.allowed:
            return ToolGuardrailFunctionOutput.allow(output_info={"marshal": result.reason})
        return ToolGuardrailFunctionOutput.reject_content(
            f"Tool call blocked by policy: {result.reason}", output_info={"marshal": result.reason}
        )

    return ToolInputGuardrail(guardrail_function=check, name=name)


def govern_tools(agent_or_tools: Any, guardrail: ToolInputGuardrail) -> int:
    """Append `guardrail` to every function tool on an `Agent` (or in a
    list of tools) that doesn't already have it. Returns how many tools
    were updated. Tools without `tool_input_guardrails` (hosted tools)
    are skipped — see the module docstring."""
    tools = getattr(agent_or_tools, "tools", agent_or_tools)
    updated = 0
    for tool in tools:
        if not hasattr(tool, "tool_input_guardrails"):
            continue
        existing = list(tool.tool_input_guardrails or [])
        if guardrail not in existing:
            tool.tool_input_guardrails = [*existing, guardrail]
            updated += 1
    return updated
