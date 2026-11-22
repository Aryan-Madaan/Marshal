"""LiteLLM proxy: one guardrail governing model routing *and* MCP tool
calls for every client of the gateway.

    # proxy config.yaml
    guardrails:
      - guardrail_name: marshal
        litellm_params:
          guardrail: my_module.marshal_guardrail   # a MarshalGuardrail instance
          mode: pre_call
          default_on: true

For chat/completion/responses calls, `async_pre_call_hook` resolves the
requested model through a `ModelGuard` (rewriting `data["model"]`), scans
the prompt with an optional `SensitiveDataScanner`, and refuses
provider-hosted tools outside `hosted_tools`. For the proxy's MCP gateway
(`call_type="call_mcp_tool"`), it governs the tool call through the
`ToolGovernor`. Raising from the hook is how LiteLLM refuses a request
(for MCP it becomes `should_proceed=False`) — verified against litellm
1.110 (`CustomGuardrail.async_pre_call_hook`, and the MCP pre-call
conversion in `litellm/proxy/utils.py`, which passes `mcp_tool_name`,
`mcp_arguments` and `mcp_server_name`).

Identity comes from the proxy's own key auth: `principal_from_key`
receives LiteLLM's `UserAPIKeyAuth` and the request data. The default
uses the key's user id (or key alias), adds `team:<id>` as an attribute,
and records an `end_user` as `on_behalf_of`.

No interactive approvals in a proxy: build the governor with
`MarshalGuardrail.tool_governor(...)`, whose default approval handler
declines every `require_approval` decision, unless you supply your own
(a Slack or ticketing handler).

Supply chain note: litellm 1.82.7 and 1.82.8 on PyPI were malicious
(credential-stealing, March 2026, MAL-2026-2144). The `[litellm]` extra
excludes them and requires a release with the 2025-2026 proxy security
fixes.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Optional

from litellm.integrations.custom_guardrail import CustomGuardrail

from marshal_ai.integrations import _openai_hosted_tools, _scan_prompt_or_raise, _extract_text_from_messages
from marshal_ai.integrations._governor import ToolGovernor
from marshal_ai.models import ModelCallDenied, ModelGuard
from marshal_ai.policy import Principal
from marshal_ai.sensitive import DEFAULT_BLOCK_DETECTORS, SensitiveDataScanner
from marshal_ai.tools import AutoApprove, ToolCallDenied

_MCP_CALL_TYPES = ("call_mcp_tool", "mcp_call")


def default_principal_from_key(user_api_key_dict: Any, data: dict) -> Principal:
    def get(name: str) -> Any:
        if isinstance(user_api_key_dict, dict):
            return user_api_key_dict.get(name)
        return getattr(user_api_key_dict, name, None)

    actor = get("user_id") or get("key_alias") or data.get("user_api_key_user_id") or "litellm-key"
    attributes = {f"team:{get('team_id')}"} if get("team_id") else set()
    end_user = get("end_user_id") or data.get("user_api_key_end_user_id") or data.get("user")
    subject = Principal(id=str(end_user)) if end_user and str(end_user) != str(actor) else None
    return Principal(id=str(actor), attributes=attributes, on_behalf_of=subject)


class _Declined(AutoApprove):
    identity = "litellm-no-interactive-approval"

    def __init__(self) -> None:
        super().__init__(approve=False)


class MarshalGuardrail(CustomGuardrail):
    def __init__(
        self,
        model_guard: Optional[ModelGuard] = None,
        tool_governor: Optional[ToolGovernor] = None,
        scanner: Optional[SensitiveDataScanner] = None,
        block_detectors: frozenset[str] = DEFAULT_BLOCK_DETECTORS,
        hosted_tools: Optional[Iterable[str]] = None,
        principal_from_key: Callable[[Any, dict], Principal] = default_principal_from_key,
        **kwargs: Any,
    ) -> None:
        """Build `tool_governor` with `approval_handler=` set if you want
        approvals; `MarshalGuardrail.tool_governor(...)` builds one that
        declines them, the safe default for a non-interactive proxy."""
        kwargs.setdefault("guardrail_name", "marshal")
        super().__init__(**kwargs)
        self._model_guard = model_guard
        self._tool_governor = tool_governor
        self._scanner = scanner
        self._block_detectors = block_detectors
        self._hosted_tools = frozenset(hosted_tools) if hosted_tools is not None else None
        self._principal_from_key = principal_from_key

    @staticmethod
    def tool_governor(**kwargs: Any) -> ToolGovernor:
        """A `ToolGovernor` whose default approval handler declines —
        a proxy has no terminal to prompt on."""
        kwargs.setdefault("approval_handler", _Declined())
        kwargs.setdefault("principal", Principal(id="litellm-proxy"))
        return ToolGovernor(**kwargs)

    async def async_pre_call_hook(self, user_api_key_dict: Any, cache: Any, data: dict, call_type: str) -> Any:
        principal = self._principal_from_key(user_api_key_dict, data)

        if call_type in _MCP_CALL_TYPES:
            if self._tool_governor is None:
                return data
            result = self._tool_governor.check(
                str(data.get("mcp_tool_name") or "mcp-tool"),
                data.get("mcp_arguments") or {},
                principal=principal,
                mcp_server=data.get("mcp_server_name"),
            )
            if not result.allowed:
                raise ToolCallDenied(str(data.get("mcp_tool_name")), result.reason)
            return data

        if self._model_guard is None:
            return data
        requested = data.get("model")
        _scan_prompt_or_raise(
            self._scanner, self._block_detectors, self._model_guard, principal, requested, data,
            lambda kw: "\n".join(filter(None, [_extract_text_from_messages(kw.get("messages")),
                                               kw.get("input") if isinstance(kw.get("input"), str) else None])),
        )
        if self._hosted_tools is not None:
            names, _ = _openai_hosted_tools(data)
            refused = sorted(names - self._hosted_tools)
            if refused:
                raise ModelCallDenied(requested or "?", f"provider-hosted tool(s) not allowed: {', '.join(refused)}")
        if requested is not None:
            data["model"] = self._model_guard.resolve(principal, requested)
        return data
