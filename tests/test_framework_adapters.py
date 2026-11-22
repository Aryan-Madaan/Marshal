"""Native framework adapters, exercised against the real installed
frameworks: a full LangChain `create_agent` run (with a scripted fake chat
model — no network), and each other framework's real hook types."""

import asyncio
import json

import pytest

from marshal_ai import AutoApprove, InMemoryAuditSink, Principal, RiskTierPolicy, ToolCallDenied
from marshal_ai.integrations import ToolGovernor

POLICY = RiskTierPolicy({"low": "allow", "high": "deny", "medium": "require_approval"})


def _governor(sink=None, **kwargs):
    return ToolGovernor(
        policy=POLICY,
        principal=Principal(id="agent-1", on_behalf_of=Principal(id="alice")),
        risk_tiers={"lookup_order": "low", "delete_account": "high", "issue_refund": "medium"},
        audit_sink=sink if sink is not None else InMemoryAuditSink(),
        approval_handler=AutoApprove(False),
        **kwargs,
    )


def test_governor_refuses_non_object_arguments():
    result = _governor().check("lookup_order", "not-json-object")
    assert not result.allowed and "JSON object" in result.reason


def test_governor_deep_copies_arguments_so_later_mutation_cannot_change_what_was_evaluated():
    seen = {}

    from marshal_ai import ToolDecision, ToolPolicy

    class Capture(ToolPolicy):
        def evaluate(self, request):
            seen["args"] = request.arguments
            return ToolDecision("allow", "ok")

    args = {"nested": {"to": "ops@example.com"}}
    ToolGovernor(policy=Capture(), principal=Principal(id="a")).check("send", args)
    args["nested"]["to"] = "attacker@evil.example"
    assert seen["args"]["nested"]["to"] == "ops@example.com"


# --- LangChain v1 middleware: a real create_agent run ----------------------


def _scripted_agent(tool_name, tool_args, middleware):
    from langchain.agents import create_agent
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool

    executed = []

    @tool
    def lookup_order(order_id: str) -> str:
        """Look up an order."""
        executed.append(("lookup_order", order_id))
        return "shipped"

    @tool
    def delete_account(user_id: str) -> str:
        """Delete a user account."""
        executed.append(("delete_account", user_id))
        return "deleted"

    class ScriptedModel(GenericFakeChatModel):
        def bind_tools(self, tools, **kwargs):
            return self

    model = ScriptedModel(messages=iter([
        AIMessage(content="", tool_calls=[{"name": tool_name, "args": tool_args, "id": "call_1"}]),
        AIMessage(content="done"),
    ]))
    agent = create_agent(model, tools=[lookup_order, delete_account], middleware=middleware)
    return agent, executed


def test_langchain_middleware_allows_and_blocks_inside_a_real_agent_run():
    from marshal_ai.integrations.langchain import MarshalToolMiddleware

    sink = InMemoryAuditSink()
    middleware = [MarshalToolMiddleware(_governor(sink))]

    agent, executed = _scripted_agent("lookup_order", {"order_id": "42"}, middleware)
    agent.invoke({"messages": [{"role": "user", "content": "where is 42"}]})
    assert executed == [("lookup_order", "42")]

    agent, executed = _scripted_agent("delete_account", {"user_id": "alice"}, middleware)
    result = agent.invoke({"messages": [{"role": "user", "content": "delete me"}]})
    assert executed == []  # the tool never ran
    refusal = [m for m in result["messages"] if getattr(m, "type", "") == "tool"][0]
    assert refusal.status == "error" and "blocked by policy" in refusal.content

    entries = sink.all_entries()
    assert [e.outcome for e in entries] == ["allow", "deny"]
    assert entries[1].on_behalf_of == ["alice"]


def test_langchain_middleware_can_raise_instead():
    from marshal_ai.integrations.langchain import MarshalToolMiddleware

    agent, executed = _scripted_agent(
        "delete_account", {"user_id": "alice"}, [MarshalToolMiddleware(_governor(), on_deny="raise")]
    )
    with pytest.raises(ToolCallDenied):
        agent.invoke({"messages": [{"role": "user", "content": "delete me"}]})
    assert executed == []


# --- Claude Agent SDK PreToolUse hook ---------------------------------------


def test_claude_agent_sdk_hook_denies_and_records_mcp_server():
    from claude_agent_sdk import HookMatcher
    from marshal_ai.integrations.claude_agent_sdk import marshal_hooks

    sink = InMemoryAuditSink()
    hooks = marshal_hooks(_governor(sink))
    matcher = hooks["PreToolUse"][0]
    assert isinstance(matcher, HookMatcher) and matcher.on_failure == "block"
    hook = matcher.hooks[0]

    denied = asyncio.run(hook(
        {"hook_event_name": "PreToolUse", "tool_name": "mcp__crm__delete_account",
         "tool_input": {"user_id": "alice"}, "session_id": "s1"}, "tu_1", None,
    ))
    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"

    allowed = asyncio.run(hook(
        {"hook_event_name": "PreToolUse", "tool_name": "lookup_order", "tool_input": {"order_id": "1"}}, "tu_2", None,
    ))
    assert allowed == {}  # no decision: the SDK's own permission flow still applies

    first = sink.all_entries()[0]
    assert first.mcp_server == "crm" and first.tool_name == "delete_account"


# --- Google ADK plugin ------------------------------------------------------


def test_adk_plugin_short_circuits_a_refused_tool():
    from google.adk.tools import FunctionTool
    from marshal_ai.integrations.adk import MarshalPlugin

    def delete_account(user_id: str) -> str:
        """Delete a user account."""
        return "deleted"

    def lookup_order(order_id: str) -> str:
        """Look up an order."""
        return "shipped"

    plugin = MarshalPlugin(_governor())

    class Ctx:
        session = type("S", (), {"id": "adk-session-1"})()

    blocked = asyncio.run(plugin.before_tool_callback(
        tool=FunctionTool(delete_account), tool_args={"user_id": "alice"}, tool_context=Ctx()
    ))
    assert "blocked by policy" in blocked["error"]
    assert asyncio.run(plugin.before_tool_callback(
        tool=FunctionTool(lookup_order), tool_args={"order_id": "1"}, tool_context=Ctx()
    )) is None


# --- OpenAI Agents SDK tool input guardrail ---------------------------------


def test_openai_agents_guardrail_rejects_content_and_attaches_to_tools():
    from agents import Agent, ToolInputGuardrailData, function_tool
    from agents.tool_context import ToolContext
    from marshal_ai.integrations.openai_agents import govern_tools, marshal_tool_guardrail

    guardrail = marshal_tool_guardrail(_governor())

    @function_tool
    def delete_account(user_id: str) -> str:
        """Delete a user account."""
        return "deleted"

    agent = Agent(name="support", tools=[delete_account])
    assert govern_tools(agent, guardrail) == 1
    assert govern_tools(agent, guardrail) == 0  # idempotent
    assert guardrail in delete_account.tool_input_guardrails

    def run(name, args):
        ctx = ToolContext(context=None, tool_name=name, tool_call_id="c1", tool_arguments=args)
        return asyncio.run(guardrail.run(ToolInputGuardrailData(context=ctx, agent=agent)))

    rejected = run("delete_account", json.dumps({"user_id": "alice"}))
    assert rejected.behavior["type"] == "reject_content"
    allowed = run("lookup_order", json.dumps({"order_id": "1"}))
    assert allowed.behavior["type"] == "allow"
    malformed = run("lookup_order", "{not json")
    assert malformed.behavior["type"] == "reject_content"


# --- LiteLLM proxy guardrail ------------------------------------------------


def test_litellm_guardrail_routes_models_and_governs_mcp_tool_calls():
    from marshal_ai import AllowlistModelPolicy, ModelCallDenied, ModelCandidate, ModelGuard
    from marshal_ai.integrations.litellm import MarshalGuardrail

    sink = InMemoryAuditSink()
    model_guard = ModelGuard(
        policy=AllowlistModelPolicy({"chat": [ModelCandidate("gpt-real")]}), audit_sink=sink
    )
    guardrail = MarshalGuardrail(
        model_guard=model_guard,
        tool_governor=MarshalGuardrail.tool_governor(
            policy=POLICY, risk_tiers={"issue_refund": "medium"}, audit_sink=sink
        ),
        hosted_tools=set(),
    )
    key = {"user_id": "svc-support", "team_id": "cx", "end_user_id": "alice"}

    data = asyncio.run(guardrail.async_pre_call_hook(key, None, {"model": "chat", "messages": []}, "acompletion"))
    assert data["model"] == "gpt-real"
    routed = sink.all_entries()[-1]
    assert routed.principal_id == "svc-support" and routed.on_behalf_of == ["alice"]

    with pytest.raises(ModelCallDenied):
        asyncio.run(guardrail.async_pre_call_hook(
            key, None, {"model": "chat", "messages": [], "tools": [{"type": "web_search"}]}, "acompletion"
        ))

    # require_approval through a non-interactive proxy is declined, not hung
    with pytest.raises(ToolCallDenied, match="approval declined"):
        asyncio.run(guardrail.async_pre_call_hook(
            key, None,
            {"mcp_tool_name": "issue_refund", "mcp_arguments": {"amount": 50}, "mcp_server_name": "billing"},
            "call_mcp_tool",
        ))
    assert sink.all_entries()[-1].mcp_server == "billing"


# --- Pydantic AI: a real Agent run with TestModel -----------------------------


def test_pydantic_ai_toolset_blocks_inside_a_real_agent_run():
    pytest.importorskip("pydantic_ai")
    from pydantic_ai import Agent
    from pydantic_ai.models.test import TestModel
    from pydantic_ai.toolsets import FunctionToolset

    from marshal_ai.integrations.pydantic_ai import MarshalToolset

    executed = []
    toolset = FunctionToolset()

    @toolset.tool_plain
    def lookup_order(order_id: str) -> str:
        """Look up an order."""
        executed.append("lookup_order")
        return "shipped"

    @toolset.tool_plain
    def delete_account(user_id: str) -> str:
        """Delete an account."""
        executed.append("delete_account")
        return "deleted"

    sink = InMemoryAuditSink()
    agent = Agent(TestModel(), toolsets=[MarshalToolset(toolset, _governor(sink))])
    agent.run_sync("help")  # TestModel calls every tool once
    assert executed == ["lookup_order"]
    outcomes = {e.tool_name: e.outcome for e in sink.all_entries()}
    assert outcomes == {"lookup_order": "allow", "delete_account": "deny"}


# --- A2A interceptor ------------------------------------------------------------


def _a2a_args(method, text, agent_name="billing-agent"):
    from a2a.client.interceptors import BeforeArgs
    from a2a.types import a2a_pb2

    card = a2a_pb2.AgentCard(name=agent_name, supported_interfaces=[a2a_pb2.AgentInterface(url="https://billing.partner.example/a2a")])
    message = a2a_pb2.Message(role=a2a_pb2.ROLE_USER, message_id="m1", parts=[a2a_pb2.Part(text=text)])
    return BeforeArgs(input=a2a_pb2.SendMessageRequest(message=message), method=method, agent_card=card)


def test_a2a_interceptor_governs_outbound_messages_per_remote_agent():
    pytest.importorskip("a2a")
    from marshal_ai import SensitiveDataToolPolicy
    from marshal_ai.integrations.a2a import MarshalA2AInterceptor

    sink = InMemoryAuditSink()
    governor = ToolGovernor(
        policy=SensitiveDataToolPolicy(RiskTierPolicy({"low": "allow", "high": "deny"})),
        principal=Principal("orchestrator"),
        risk_tiers={"a2a:billing-agent": "low", "a2a:unknown-vendor": "high"},
        audit_sink=sink,
    )
    interceptor = MarshalA2AInterceptor(governor)

    asyncio.run(interceptor.before(_a2a_args("send_message", "refund order 42")))
    with pytest.raises(ToolCallDenied):
        asyncio.run(interceptor.before(_a2a_args("send_message_streaming", "hi", agent_name="unknown-vendor")))
    with pytest.raises(ToolCallDenied, match="sensitive data"):
        asyncio.run(interceptor.before(_a2a_args("send_message", "our key AKIAABCDEFGHIJKLMNOP")))
    asyncio.run(interceptor.before(_a2a_args("get_task", "")))  # read-only: not governed

    assert [e.tool_name for e in sink.all_entries() if e.to_dict()["kind"] == "tool_call"] == [
        "a2a:billing-agent", "a2a:unknown-vendor", "a2a:billing-agent",
    ]


# --- CrewAI hook (the logic; tests/test_crewai_real.py runs it in real CrewAI) ---


def test_crewai_hook_returns_false_to_block():
    from marshal_ai.integrations.crewai import marshal_tool_hook

    hook = marshal_tool_hook(_governor())
    context = type("Ctx", (), {"tool_name": "delete_account", "tool_input": {"user_id": "a"},
                               "agent": type("A", (), {"role": "support"})()})()
    assert hook(context) is False
    context.tool_name = "lookup_order"
    assert hook(context) is None
