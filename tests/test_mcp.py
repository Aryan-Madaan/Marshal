"""Exercises GovernedMCPSession against a *real* mcp.ClientSession talking
to a real mcp.server.fastmcp.FastMCP server, connected by the SDK's own
in-memory transport (mcp.shared.memory.create_connected_server_and_client_
session) — no subprocess, no socket, no mocked SDK types. Every assertion
below is about what the real MCP request/response round trip actually did,
not about what marshal_ai.mcp *says* it does.
"""

import asyncio

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session

from marshal_ai import (
    ArgumentRedaction,
    InMemoryAuditSink,
    Principal,
    RedactingToolPolicy,
    RiskTierPolicy,
    SensitiveDataToolPolicy,
    ToolCallDenied,
)
from marshal_ai.mcp import GovernedMCPSession


def _build_server(calls: dict) -> FastMCP:
    """A tiny real MCP server exposing a couple of tools. `calls` is a
    plain dict the test closes over so it can prove, after the fact,
    whether the *server-side* tool function actually ran — the only way
    to prove a denial was truly fail-closed rather than just raising an
    exception the caller happens to swallow."""
    server = FastMCP("test-server")

    @server.tool()
    def echo(text: str) -> str:
        return f"echo: {text}"

    @server.tool()
    def record_call(value: str) -> str:
        calls.setdefault("record_call", []).append(value)
        return "recorded"

    @server.tool()
    def delete_all(confirm: bool) -> str:
        calls["delete_all"] = calls.get("delete_all", 0) + 1
        return "deleted everything"

    return server


def test_list_tools_passes_through_to_the_real_server():
    server = _build_server({})

    async def run():
        async with create_connected_server_and_client_session(server) as session:
            governed = GovernedMCPSession(session=session, principal=Principal(id="agent-1"))
            return await governed.list_tools()

    result = asyncio.run(run())
    assert {t.name for t in result.tools} == {"echo", "record_call", "delete_all"}


def test_allowed_tool_call_passes_through_and_returns_the_real_server_result():
    calls: dict = {}
    server = _build_server(calls)

    async def run():
        async with create_connected_server_and_client_session(server) as session:
            governed = GovernedMCPSession(
                session=session,
                principal=Principal(id="agent-1"),
                policy=RiskTierPolicy({"low": "allow"}),
                risk_tiers={"echo": "low"},
            )
            return await governed.call_tool("echo", {"text": "hi"})

    result = asyncio.run(run())
    assert result.isError is False
    assert result.content[0].text == "echo: hi"  # the real server's own response


def test_denied_call_is_blocked_before_reaching_the_server_and_is_audited():
    calls: dict = {}
    server = _build_server(calls)
    sink = InMemoryAuditSink()

    async def run():
        async with create_connected_server_and_client_session(server) as session:
            governed = GovernedMCPSession(
                session=session,
                principal=Principal(id="agent-1"),
                policy=RiskTierPolicy({"high": "deny"}),
                risk_tiers={"delete_all": "high"},
                audit_sink=sink,
            )
            with pytest.raises(ToolCallDenied) as exc_info:
                await governed.call_tool("delete_all", {"confirm": True})
            return exc_info.value

    denied = asyncio.run(run())
    assert denied.tool_name == "delete_all"
    assert "delete_all" not in calls  # server-side tool function never ran — fail closed

    entries = sink.tail(1)
    assert entries[0].outcome == "deny"
    assert entries[0].tool_name == "delete_all"
    assert entries[0].principal_id == "agent-1"


def test_declined_approval_is_also_blocked_before_reaching_the_server():
    from marshal_ai import AutoApprove

    calls: dict = {}
    server = _build_server(calls)

    async def run():
        async with create_connected_server_and_client_session(server) as session:
            governed = GovernedMCPSession(
                session=session,
                principal=Principal(id="agent-1"),
                policy=RiskTierPolicy({"medium": "require_approval"}),
                risk_tiers={"delete_all": "medium"},
                approval_handler=AutoApprove(False),
            )
            with pytest.raises(ToolCallDenied):
                await governed.call_tool("delete_all", {"confirm": True})

    asyncio.run(run())
    assert "delete_all" not in calls


def test_argument_redaction_hides_the_value_in_the_audit_trail_but_the_real_server_gets_it():
    calls: dict = {}
    server = _build_server(calls)
    sink = InMemoryAuditSink()

    policy = RedactingToolPolicy(
        base=RiskTierPolicy({"low": "allow"}),
        rules=[ArgumentRedaction(name="value", requires_attribute="role:admin")],
    )

    async def run():
        async with create_connected_server_and_client_session(server) as session:
            # agent-1 has no attributes at all, so it does not carry role:admin
            governed = GovernedMCPSession(
                session=session,
                principal=Principal(id="agent-1"),
                policy=policy,
                risk_tiers={"record_call": "low"},
                audit_sink=sink,
            )
            return await governed.call_tool("record_call", {"value": "topsecret"})

    result = asyncio.run(run())
    assert result.isError is False
    assert calls["record_call"] == ["topsecret"]  # the real server got the real value
    assert sink.tail(1)[0].arguments["value"] == "[REDACTED]"  # the audit trail did not


def test_sensitive_data_in_arguments_blocks_the_call_before_it_reaches_the_server():
    calls: dict = {}
    server = _build_server(calls)
    sink = InMemoryAuditSink()

    # SensitiveDataToolPolicy composes over any ToolPolicy exactly the way
    # it composes over ToolGuard — nothing MCP-specific needed in mcp.py.
    policy = SensitiveDataToolPolicy(base=RiskTierPolicy({"low": "allow"}), audit_sink=sink)

    async def run():
        async with create_connected_server_and_client_session(server) as session:
            governed = GovernedMCPSession(
                session=session,
                principal=Principal(id="agent-1"),
                policy=policy,
                risk_tiers={"record_call": "low"},
                audit_sink=sink,
            )
            with pytest.raises(ToolCallDenied) as exc_info:
                # a real-looking AWS access key ID — a DEFAULT_BLOCK_DETECTORS hit
                await governed.call_tool("record_call", {"value": "AKIAABCDEFGHIJKLMNOP"})
            return exc_info.value

    denied = asyncio.run(run())
    assert "sensitive data detected" in denied.reason
    assert "record_call" not in calls  # fail closed — the credential never left this process

    blocked = [e for e in sink.all_entries() if getattr(e, "action", None) == "blocked"]
    assert len(blocked) == 1
    assert blocked[0].findings == ["AWS_ACCESS_KEY_ID:1"]  # detector name + count, never the key itself


def test_risk_tier_defaults_when_tool_name_is_not_in_the_map():
    calls: dict = {}
    server = _build_server(calls)

    async def run():
        async with create_connected_server_and_client_session(server) as session:
            governed = GovernedMCPSession(
                session=session,
                principal=Principal(id="agent-1"),
                policy=RiskTierPolicy({"high": "deny"}, default="deny"),
                # "echo" deliberately absent from risk_tiers -> default_risk_tier
                default_risk_tier="high",
            )
            with pytest.raises(ToolCallDenied):
                await governed.call_tool("echo", {"text": "hi"})

    asyncio.run(run())


def test_default_policy_is_allow_all_when_none_is_passed():
    # No policy= at all -> GovernedMCPSession leaves it None and the
    # per-call ToolGuard resolves its own AllowAllTools() default,
    # same audit-only-by-default philosophy every other guard has.
    calls: dict = {}
    server = _build_server(calls)

    async def run():
        async with create_connected_server_and_client_session(server) as session:
            governed = GovernedMCPSession(session=session, principal=Principal(id="agent-1"))
            return await governed.call_tool("echo", {"text": "hi"})

    result = asyncio.run(run())
    assert result.isError is False
    assert result.content[0].text == "echo: hi"


def test_per_call_risk_tier_override():
    calls: dict = {}
    server = _build_server(calls)

    async def run():
        async with create_connected_server_and_client_session(server) as session:
            governed = GovernedMCPSession(
                session=session,
                principal=Principal(id="agent-1"),
                policy=RiskTierPolicy({"low": "allow", "high": "deny"}),
                risk_tiers={"echo": "low"},
            )
            # override the configured "low" tier for this one call
            with pytest.raises(ToolCallDenied):
                await governed.call_tool("echo", {"text": "hi"}, risk_tier="high")

    asyncio.run(run())
