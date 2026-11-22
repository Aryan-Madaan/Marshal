"""A2A (Agent2Agent): govern what your agent sends to *other* agents.

    from a2a.client import ClientFactory
    from marshal_ai.integrations.a2a import MarshalA2AInterceptor

    client = await ClientFactory.connect(agent_card_url)
    client.add_interceptor(MarshalA2AInterceptor(governor))

A2A is the second inter-agent call path next to MCP: instead of calling a
tool, an agent delegates work to another agent. Every outbound
`send_message` / `send_message_streaming` goes through the governor as a
call named `a2a:<remote agent name>`, with the message's text parts as
its arguments — so risk tiers apply per remote agent, and wrappers like
`SensitiveDataToolPolicy`, `EgressPolicy` and `LethalTrifectaPolicy` see
what's being sent (delegating to an external agent *is* external
communication). A refused message raises `ToolCallDenied` before
anything is sent. The remote agent's name, interface URL and the A2A
method are passed in the call's `context` (`a2a_agent`, `a2a_url`,
`a2a_method`).

Uses A2A 1.x's own `ClientCallInterceptor` hook (verified against
a2a-sdk 1.3: `before(BeforeArgs(input, method, agent_card, ...))`).
Read-only methods (`get_task`, `list_tasks`, ...) pass through. Requires
the `[a2a]` extra.
"""

from __future__ import annotations

from typing import Any, Iterable

from a2a.client import ClientCallInterceptor

from marshal_ai.integrations._governor import ToolGovernor
from marshal_ai.tools import ToolCallDenied

GOVERNED_METHODS = frozenset({"send_message", "send_message_streaming"})


def _message_text(request: Any) -> str:
    message = getattr(request, "message", None)
    parts = getattr(message, "parts", None) or []
    texts = [getattr(part, "text", "") for part in parts]
    return "\n".join(t for t in texts if t)


def _card_url(card: Any) -> str:
    interfaces = list(getattr(card, "supported_interfaces", None) or [])
    return getattr(interfaces[0], "url", "") if interfaces else ""


class MarshalA2AInterceptor(ClientCallInterceptor):
    def __init__(self, governor: ToolGovernor, methods: Iterable[str] = GOVERNED_METHODS) -> None:
        self._governor = governor
        self._methods = frozenset(methods)

    async def before(self, args: Any) -> None:
        if args.method not in self._methods:
            return
        card = args.agent_card
        name = getattr(card, "name", "") or "unknown-agent"
        url = _card_url(card)
        result = self._governor.check(
            f"a2a:{name}",
            {"text": _message_text(args.input), "agent_url": url},
            context={"a2a_agent": name, "a2a_url": url, "a2a_method": args.method},
        )
        if not result.allowed:
            raise ToolCallDenied(f"a2a:{name}", result.reason)

    async def after(self, args: Any) -> None:
        return None
