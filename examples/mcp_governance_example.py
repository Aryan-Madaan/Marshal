"""MCP tool-call governance: a real mcp.ClientSession, talking to a real
mcp.server.fastmcp.FastMCP server over the SDK's own in-memory transport,
with a GovernedMCPSession in front of every tools/call request.

MCP's own Enterprise-Managed Authorization governs whether a client may
*connect* to a server — it deliberately says nothing about whether one
specific tool call, with these specific arguments, should go through.
That's the gap GovernedMCPSession closes, reusing the exact same
ToolGuard/ToolPolicy machinery marshal_ai.tools already ships, so one
governed session covers an agent's tool use no matter which framework
is driving it, as long as that framework speaks MCP.

Four scenes, one shared audit trail:
  1. A low-risk call passes straight through to the real server.
  2. A medium-risk call requires approval (AutoApprove here, so this runs
     unattended — swap in CLIApprovalHandler() for a real interactive
     prompt, same as examples/tool_governance_example.py).
  3. A high-risk call is denied outright — the server-side tool function
     never runs (proven below by a call counter the "server" itself
     increments).
  4. A hardcoded credential in the arguments blocks the call even though
     its configured risk tier would otherwise just require approval —
     SensitiveDataToolPolicy composes over any ToolPolicy, MCP included.

Run: python examples/mcp_governance_example.py
"""

import asyncio

from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session

from marshal_ai import (
    InMemoryAuditSink,
    Principal,
    RiskTierPolicy,
    SensitiveDataToolPolicy,
    ToolCallDenied,
)
from marshal_ai.tools import AutoApprove
from marshal_ai.mcp import GovernedMCPSession

shared_audit = InMemoryAuditSink()
agent = Principal(id="support-agent-1")

# What the *real* server actually did — proof that a denied call never
# reached it, not just that GovernedMCPSession claims it didn't.
server_side_calls: list[str] = []


def build_server() -> FastMCP:
    server = FastMCP("support-tools")

    @server.tool()
    def read_file(path: str) -> str:
        server_side_calls.append(f"read_file({path})")
        return f"contents of {path}: ..."

    @server.tool()
    def send_email(to: str, body: str) -> str:
        server_side_calls.append(f"send_email(to={to})")
        return f"sent to {to}"

    @server.tool()
    def delete_database(confirm: bool) -> str:
        server_side_calls.append("delete_database")  # should never appear in output
        return "deleted"

    return server


async def main() -> None:
    server = build_server()

    base_policy = RiskTierPolicy({"low": "allow", "medium": "require_approval", "high": "deny"})
    risk_tiers = {"read_file": "low", "send_email": "medium", "delete_database": "high"}

    async with create_connected_server_and_client_session(server) as session:
        governed = GovernedMCPSession(
            session=session,
            principal=agent,
            policy=base_policy,
            risk_tiers=risk_tiers,
            audit_sink=shared_audit,
            approval_handler=AutoApprove(True),
        )

        print("=== 1. low risk: passes straight through to the real server ===")
        result = await governed.call_tool("read_file", {"path": "README.md"})
        print("result:", result.content[0].text)
        print()

        print("=== 2. medium risk: requires approval, then reaches the real server ===")
        result = await governed.call_tool("send_email", {"to": "customer@example.com", "body": "hi"})
        print("result:", result.content[0].text)
        print()

        print("=== 3. high risk: denied outright, real server never runs the tool ===")
        try:
            await governed.call_tool("delete_database", {"confirm": True})
        except ToolCallDenied as e:
            print(f"blocked: {e}")
        print("server_side_calls so far (delete_database must be absent):", server_side_calls)
        print()

        print("=== 4. sensitive data in arguments blocks even a require_approval call ===")
        blocking_policy = SensitiveDataToolPolicy(base=base_policy, audit_sink=shared_audit)
        governed_with_scanning = GovernedMCPSession(
            session=session,
            principal=agent,
            policy=blocking_policy,
            risk_tiers=risk_tiers,
            audit_sink=shared_audit,
            approval_handler=AutoApprove(True),
        )
        try:
            await governed_with_scanning.call_tool(
                "send_email",
                {"to": "customer@example.com", "body": "here is our prod key AKIAABCDEFGHIJKLMNOP"},
            )
        except ToolCallDenied as e:
            print(f"blocked despite medium risk tier + approval configured: {e}")
        print()

    print("=== shared audit trail: every allow/require_approval/deny, one place ===")
    for entry in shared_audit.tail(10):
        kind = entry.to_dict()["kind"]
        if kind == "tool_call":
            print(f"  [tool_call] {entry.principal_id}: {entry.tool_name} -> {entry.outcome} ({entry.reason})")
        elif kind == "sensitive_data":
            print(f"  [sensitive_data] {entry.principal_id}: {entry.location} {entry.findings} -> {entry.action}")


if __name__ == "__main__":
    asyncio.run(main())
