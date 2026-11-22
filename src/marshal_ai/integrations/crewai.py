"""CrewAI: govern tool calls with a `before_tool_call` hook.

    from marshal_ai.integrations.crewai import enable_crewai

    enable_crewai(governor)          # every tool call in every crew

or, scoped to one crew, register the hook yourself:

    from crewai.hooks import register_before_tool_call_hook
    from marshal_ai.integrations.crewai import marshal_tool_hook
    register_before_tool_call_hook(marshal_tool_hook(governor))

CrewAI's before-tool hooks receive a `ToolCallHookContext` (`tool_name`,
`tool_input`, `agent`, `task`, `crew`) and block the call by returning
`False` (verified against crewai 1.9 and 1.15). The agent's `role` is
passed in the call's context as `crewai_agent_role`.

Why there's no `[crewai]` extra: every current CrewAI release pins
`mcp<2` and `openai<3`, below the versions Marshal requires (mcp<2.3 has
client-side security advisories). This module therefore imports nothing
from CrewAI except inside `enable_crewai`, and works against whatever
CrewAI you've installed — just not in the same environment as
`marshal-ai[mcp]` or `[openai]`.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from marshal_ai.integrations._governor import ToolGovernor


def marshal_tool_hook(governor: ToolGovernor) -> Callable[[Any], Optional[bool]]:
    def hook(context: Any) -> Optional[bool]:
        agent = getattr(context, "agent", None)
        result = governor.check(
            str(getattr(context, "tool_name", "tool")),
            getattr(context, "tool_input", None) or {},
            context={"crewai_agent_role": getattr(agent, "role", None)},
        )
        return None if result.allowed else False

    return hook


def enable_crewai(governor: ToolGovernor) -> Callable[[Any], Optional[bool]]:
    """Register `marshal_tool_hook(governor)` globally; returns the hook
    (pass it to `crewai.hooks.unregister_before_tool_call_hook` to undo)."""
    from crewai.hooks import register_before_tool_call_hook

    hook = marshal_tool_hook(governor)
    register_before_tool_call_hook(hook)
    return hook
