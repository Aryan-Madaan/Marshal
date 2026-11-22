"""The CrewAI hook inside real CrewAI. CrewAI pins mcp<2 and openai<3, so
it can't be installed alongside Marshal's other extras; CI runs this file
in its own job (crewai + pytest only). Skipped everywhere else."""

import pytest

crewai = pytest.importorskip("crewai")

from marshal_ai import AutoApprove, InMemoryAuditSink, Principal, RiskTierPolicy  # noqa: E402
from marshal_ai.integrations import ToolGovernor  # noqa: E402
from marshal_ai.integrations.crewai import enable_crewai  # noqa: E402


def test_registered_hook_blocks_a_real_crewai_tool_call():
    from crewai.hooks import ToolCallHookContext, get_before_tool_call_hooks, unregister_before_tool_call_hook
    from crewai.tools import tool

    @tool("delete_account")
    def delete_account(user_id: str) -> str:
        """Delete an account."""
        return "deleted"

    sink = InMemoryAuditSink()
    governor = ToolGovernor(
        policy=RiskTierPolicy({"high": "deny"}), principal=Principal("crew"),
        risk_tiers={"delete_account": "high"}, audit_sink=sink, approval_handler=AutoApprove(False),
    )
    hook = enable_crewai(governor)
    try:
        assert hook in get_before_tool_call_hooks()
        structured = delete_account.to_structured_tool()
        context = ToolCallHookContext(tool_name="delete_account", tool_input={"user_id": "a"}, tool=structured)
        assert [h(context) for h in get_before_tool_call_hooks()] == [False]
        assert sink.tail(1)[0].outcome == "deny"
    finally:
        unregister_before_tool_call_hook(hook)
