"""One tool policy, enforced natively in four agent frameworks.

Each framework has its own hook for "may this tool run?". Marshal plugs
into each one through its official extension point (not monkeypatching),
with one shared `ToolGovernor` (policy, risk tiers, approvals) and one
audit trail:

  - LangChain v1 / LangGraph: `MarshalToolMiddleware` (wrap_tool_call)
  - Claude Agent SDK:         `marshal_hooks(...)` (PreToolUse hook)
  - Google ADK:               `MarshalPlugin` (before_tool_callback)
  - OpenAI Agents SDK:        `marshal_tool_guardrail(...)` (tool input guardrail)

(The LiteLLM proxy has one too, `marshal_ai.integrations.litellm.
MarshalGuardrail`, which also covers the proxy's MCP gateway.)

The LangChain scene is a real `create_agent` run with a scripted chat
model, so it runs offline; the others call each framework's real hook
with the inputs that framework passes. Needs the extras:
pip install -e ".[langchain,claude-agent-sdk,adk,openai-agents]"

Run: python examples/framework_hooks_example.py
"""

import asyncio
import json

from marshal_ai import AutoApprove, InMemoryAuditSink, Principal, RiskTierPolicy
from marshal_ai.integrations import ToolGovernor

sink = InMemoryAuditSink()
governor = ToolGovernor(
    policy=RiskTierPolicy({"low": "allow", "high": "deny", "medium": "require_approval"}),
    principal=Principal("support-agent", on_behalf_of=Principal("alice")),
    risk_tiers={"lookup_order": "low", "issue_refund": "medium", "delete_account": "high"},
    audit_sink=sink,
    approval_handler=AutoApprove(True),  # swap in your Slack/ticket approval handler
)

# --- LangChain: a real agent run ------------------------------------------
from langchain.agents import create_agent  # noqa: E402
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel  # noqa: E402
from langchain_core.messages import AIMessage  # noqa: E402
from langchain_core.tools import tool  # noqa: E402

from marshal_ai.integrations.langchain import MarshalToolMiddleware  # noqa: E402


@tool
def delete_account(user_id: str) -> str:
    """Permanently delete a user account."""
    return "deleted"


class ScriptedModel(GenericFakeChatModel):
    """Stands in for a real model: asks to delete an account, then replies."""

    def bind_tools(self, tools, **kwargs):
        return self


model = ScriptedModel(messages=iter([
    AIMessage("", tool_calls=[{"name": "delete_account", "args": {"user_id": "alice"}, "id": "call_1"}]),
    AIMessage("I can't delete accounts, but I've flagged this for a human."),
]))
agent = create_agent(model, tools=[delete_account], middleware=[MarshalToolMiddleware(governor)])
result = agent.invoke({"messages": [{"role": "user", "content": "delete my account"}]})
tool_reply = next(m for m in result["messages"] if m.type == "tool")
print("LangChain   delete_account ->", tool_reply.content)
print("            agent's final answer:", result["messages"][-1].content)

# --- Claude Agent SDK: PreToolUse hook ------------------------------------
from marshal_ai.integrations.claude_agent_sdk import marshal_hooks  # noqa: E402

hooks = marshal_hooks(governor)  # ClaudeAgentOptions(hooks=hooks)
hook = hooks["PreToolUse"][0].hooks[0]
decision = asyncio.run(hook(
    {"hook_event_name": "PreToolUse", "tool_name": "mcp__crm__delete_account", "tool_input": {"user_id": "alice"}},
    "toolu_1", None,
))
print("Claude SDK  mcp__crm__delete_account ->", decision["hookSpecificOutput"]["permissionDecision"])

# --- Google ADK: plugin ----------------------------------------------------
from google.adk.tools import FunctionTool  # noqa: E402

from marshal_ai.integrations.adk import MarshalPlugin  # noqa: E402


def issue_refund(order_id: str, amount: float) -> str:
    """Refund an order."""
    return "refunded"


plugin = MarshalPlugin(governor)  # Runner(..., plugins=[plugin])
outcome = asyncio.run(plugin.before_tool_callback(
    tool=FunctionTool(issue_refund), tool_args={"order_id": "42", "amount": 20.0}, tool_context=None
))
print("Google ADK  issue_refund ->", "runs (approved)" if outcome is None else outcome)

# --- OpenAI Agents SDK: tool input guardrail -------------------------------
from agents import Agent, ToolInputGuardrailData, function_tool  # noqa: E402
from agents.tool_context import ToolContext  # noqa: E402

from marshal_ai.integrations.openai_agents import govern_tools, marshal_tool_guardrail  # noqa: E402


@function_tool
def lookup_order(order_id: str) -> str:
    """Look up an order's status."""
    return "shipped"


openai_agent = Agent(name="support", tools=[lookup_order])
govern_tools(openai_agent, marshal_tool_guardrail(governor))
guardrail = lookup_order.tool_input_guardrails[0]
ctx = ToolContext(context=None, tool_name="lookup_order", tool_call_id="c1", tool_arguments=json.dumps({"order_id": "42"}))
verdict = asyncio.run(guardrail.run(ToolInputGuardrailData(context=ctx, agent=openai_agent)))
print("OpenAI      lookup_order ->", verdict.behavior["type"])

print("\n=== one audit trail, four frameworks ===")
for entry in sink.all_entries():
    server = f" (mcp server {entry.mcp_server})" if entry.mcp_server else ""
    print(f"  {entry.tool_name}{server}: {entry.outcome} — actor {entry.principal_id} for {entry.on_behalf_of}")
