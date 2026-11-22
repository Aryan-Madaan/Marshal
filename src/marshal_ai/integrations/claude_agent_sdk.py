"""Claude Agent SDK: govern every tool call — built-in tools (Bash, Write,
WebFetch, ...) and MCP tools alike — with a `PreToolUse` hook.

    from claude_agent_sdk import ClaudeAgentOptions
    from marshal_ai.integrations.claude_agent_sdk import marshal_hooks

    options = ClaudeAgentOptions(hooks=marshal_hooks(governor))

A refused call gets `permissionDecision: "deny"` with Marshal's reason,
which the SDK reports back to the model instead of running the tool. An
allowed call returns no decision at all, so the SDK's own permission
mode and prompts still apply on top — Marshal can only ever make a call
*less* permitted, never skip a prompt the SDK would otherwise show.
The matcher is registered with `on_failure="block"`, so a hook that
errors or times out blocks the tool rather than letting it run.

MCP tools arrive named `mcp__<server>__<tool>`: they're audited under
the bare tool name with `mcp_server` set (matching `GovernedMCPSession`),
and `risk_tiers` may key them either way — the full name wins. Verified against
claude-agent-sdk 0.2.187 (`HookMatcher`, `PreToolUseHookInput`,
`PreToolUseHookSpecificOutput`). Requires the `[claude-agent-sdk]` extra.
"""

from __future__ import annotations

from typing import Any, Optional

from claude_agent_sdk import HookMatcher

from marshal_ai.integrations._governor import ToolGovernor


def _split_mcp_name(tool_name: str) -> tuple[Optional[str], str]:
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__", 2)
        if len(parts) == 3 and parts[1] and parts[2]:
            return parts[1], parts[2]
    return None, tool_name


def pre_tool_use_hook(governor: ToolGovernor):
    """The raw hook callback, for composing into your own `HookMatcher`."""

    async def hook(input_data: Any, tool_use_id: Optional[str], context: Any) -> dict[str, Any]:
        tool_name = input_data.get("tool_name", "")
        mcp_server, name = _split_mcp_name(tool_name)
        result = governor.check(
            name,
            input_data.get("tool_input", {}),
            context={"claude_session_id": input_data.get("session_id")},
            mcp_server=mcp_server,
            tier_aliases=(tool_name,) if mcp_server else (),
        )
        if result.allowed:
            return {}
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f"Blocked by Marshal policy: {result.reason}",
            }
        }

    return hook


def marshal_hooks(governor: ToolGovernor, matcher: Optional[str] = None) -> dict[str, list[HookMatcher]]:
    """A ready-made `hooks=` value for `ClaudeAgentOptions`. `matcher`
    narrows which tools are governed (the SDK's own matcher syntax);
    the default, None, governs every tool."""
    return {"PreToolUse": [HookMatcher(matcher=matcher, hooks=[pre_tool_use_hook(governor)], on_failure="block")]}
