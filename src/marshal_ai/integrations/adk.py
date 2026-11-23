"""Google ADK: govern every tool call across every agent in a runner with
one plugin.

    from google.adk.runners import Runner
    from marshal_ai.integrations.adk import MarshalPlugin

    runner = Runner(agent=root_agent, app_name="app", session_service=...,
                    plugins=[MarshalPlugin(governor)])

ADK's safety guidance recommends plugins over per-agent callbacks for
policy enforcement because a plugin applies to every agent, tool and
sub-agent the runner executes. `before_tool_callback` returning a dict
short-circuits the tool: the dict becomes the tool's result, so the model
sees `{"error": "..."}` with Marshal's reason and the tool never runs.
Returning None lets the call proceed. Verified against google-adk 2.15
(`BasePlugin.before_tool_callback(*, tool, tool_args, tool_context)`).

ADK's own session id is passed in the call's `context` as
`adk_session_id`, so session-scoped policies (`marshal_ai.flow`) can key
on it. Requires the `[adk]` extra.
"""

from __future__ import annotations

from typing import Any, Optional

from google.adk.plugins.base_plugin import BasePlugin

from marshal_ai.integrations._governor import ToolGovernor


class MarshalPlugin(BasePlugin):
    def __init__(self, governor: ToolGovernor, name: str = "marshal") -> None:
        super().__init__(name=name)
        self._governor = governor

    async def before_tool_callback(self, *, tool: Any, tool_args: dict[str, Any], tool_context: Any) -> Optional[dict]:
        session = getattr(tool_context, "session", None)
        result = self._governor.check(
            getattr(tool, "name", type(tool).__name__),
            tool_args,
            context={"adk_session_id": getattr(session, "id", None)},
        )
        if result.allowed:
            return None
        return {"error": f"Tool call blocked by policy: {result.reason}"}

    async def after_tool_callback(
        self, *, tool: Any, tool_args: dict[str, Any], tool_context: Any, result: dict[str, Any]
    ) -> Optional[dict]:
        self._governor.record_outcome(getattr(tool, "name", type(tool).__name__), tool_args, True)
        return None

    async def on_tool_error_callback(
        self, *, tool: Any, tool_args: dict[str, Any], tool_context: Any, error: Exception
    ) -> Optional[dict]:
        self._governor.record_outcome(
            getattr(tool, "name", type(tool).__name__), tool_args, False, error=type(error).__name__
        )
        return None  # let ADK's own error handling proceed
