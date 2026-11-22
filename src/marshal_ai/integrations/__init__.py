"""One-line, framework-agnostic model governance.

`marshal_ai.integrations.enable(guard, principal)` patches whichever of the
OpenAI, Anthropic, and Google GenAI (Gemini) Python SDK clients are
installed, so *any* framework built on top of them — LangChain, LangGraph,
CrewAI, AutoGen, or a raw script — gets model governance transparently,
without touching the framework's own code. This includes Google's Agent
Development Kit (ADK) specifically: ADK's default path for `LlmAgent`
calls Gemini through `google-genai` directly, not through LiteLLM or the
`openai`/`anthropic` clients — verified against ADK's own source and
docs, not assumed — so the Google GenAI patch below is what actually
governs a native Gemini-backed ADK agent. (ADK configured with `LiteLlm`
to reach OpenAI/Anthropic models goes through those SDKs' real client
classes too — also verified — so that path was already covered.)

    import marshal_ai.integrations as marshal_integrations
    from marshal_ai import AllowlistModelPolicy, ModelCandidate, ModelGuard, Principal

    guard = ModelGuard(policy=AllowlistModelPolicy({
        "gpt-4o": [ModelCandidate("gpt-4o-mini")],  # e.g. route down to a cheaper model
    }))
    marshal_integrations.enable(guard, Principal(id="service-account"))

    # anything below this line — including code inside a framework you
    # didn't write — is now governed:
    import openai
    openai.OpenAI().chat.completions.create(model="gpt-4o", messages=[...])
    # actually calls "gpt-4o-mini" — resolved and audited by `guard`

What this patches: every model-call entry point each SDK exposes — not
just `create()`, since `parse()`/`stream()` don't route through it
(verified against the installed SDKs: openai 3.x, anthropic 2.x,
google-genai 3.x):

- openai: `chat.completions.create/parse/stream` and the Responses API,
  `responses.create/parse/stream` (sync + async) — the Responses API is
  what OpenAI now recommends for new code, so a chat-completions-only
  patch would leave most new code ungoverned.
- anthropic: `messages.create/parse/stream` and `beta.messages.*`.
- google-genai: `models.generate_content` and `generate_content_stream`.

`stream()`-style methods are governed *before* the call (model routing,
prompt scanning, hosted-tool and egress checks); usage and outcome aren't
auto-reported for them, since the real request happens inside the
returned stream. `patched_methods()` lists exactly what's patched, so a
deployment can assert coverage at startup instead of assuming it.

What gets governed on each call: the requested `model` on every
outbound call, substituted for whatever the guard resolves it to, with
usage from the real response auto-reported via `guard.record_usage`, and
the call's actual outcome — success or failure, and latency — auto-
reported via `guard.record_outcome` so reliability-tracking policies
like `CircuitBreakerPolicy` see real deployment health, not just static
routing config. A failure is classified into a short category (timeout,
rate-limited, connection error, server error) from the real SDK exception
raised, then **re-raised unchanged** — this layer only ever observes a
failure, it never swallows or alters one. Time-to-first-token isn't
covered yet: that requires wrapping a streaming response's own iterator,
which this layer doesn't handle yet — see `ideas.md`. It deliberately
does *not* attempt to intercept tool-call execution here — that happens
inside each framework's own dispatch code, which SDK patching can't
honestly reach. Tool calls are governed through each framework's native
hook instead (`marshal_ai.integrations.langchain`, `.claude_agent_sdk`,
`.adk`, `.openai_agents`, `.litellm`), all built on `ToolGovernor`, or
with `ToolGuard` around your own tool functions.

Known cost of this approach (documented, not hidden): monkeypatching an
SDK's client class breaks silently on breaking changes to that SDK's
internals. `enable()` patches by exact class/method reference, resolved at
call time — if a future SDK major version renames or restructures these,
`enable()` will raise ImportError/AttributeError immediately rather than
patching nothing silently, but it will need updating.

Provider-hosted tools (`hosted_tools=`): tools the *provider* executes —
OpenAI's `web_search`/`file_search`/hosted `mcp`/`code_interpreter`,
Anthropic's server tools and MCP connector, Gemini's `google_search`/
`code_execution`/`url_context` — run on the provider's infrastructure, so
no client-side wrapper (`ToolGuard`, `GovernedMCPSession`) ever sees
them execute. The one place they can be governed is the request that
enables them. Pass `hosted_tools={"web_search"}` and any request enabling
a hosted tool outside that set raises `ModelCallDenied` before it's sent;
`hosted_tools=set()` forbids them all. `None` (the default) leaves them
unchecked, for backward compatibility.

Egress (`egress_allowlist=`): a `marshal_ai.egress.EgressAllowlist`. Any
hosted MCP server URL in a request must be on it (else `ModelCallDenied`),
and completions are scanned for links/images to other hosts — audited as
`EgressEntry` records (the response already exists, so there's nothing
left to block; sanitize before rendering with `allowlist.sanitize()`).

Optional sensitive-data scanning (`scanner=`): this SDK-patch layer is the
only place in Marshal that ever sees actual prompt/completion *text*
(`RetrievalGuard`/`ToolGuard`/`ModelGuard` govern document metadata, tool
arguments, and model names — never message content). Passing a
`marshal_ai.sensitive.SensitiveDataScanner` here scans outbound prompts
*before* the network call — a blocking detector (default: hardcoded
credentials, not PII) raises `ModelCallDenied` before any request is sent,
the same exception an unrouted model would raise — and scans inbound
completions afterward, audit-only (the call already happened; there's
nothing left to block, only to flag). See `marshal_ai.sensitive` for why
detection is regex-based rather than another LLM call.
"""

from __future__ import annotations

import contextvars
import inspect
import re
import time
from typing import Any, Callable, Iterable, Optional, Union

from marshal_ai.egress import EgressAllowlist, host_of, write_egress_finding
from marshal_ai.integrations._governor import GovernorResult, ToolGovernor
from marshal_ai.models import ModelCallDenied, ModelCallEntry, ModelGuard
from marshal_ai.policy import Principal
from marshal_ai.sensitive import DEFAULT_BLOCK_DETECTORS, SensitiveDataScanner, write_finding

PrincipalSource = Union[Principal, Callable[[], Principal]]

_patched: list[tuple[object, str, Callable]] = []  # (cls, attr_name, original) for disable()

# True while a governed call is in progress in this context. SDK methods
# call each other internally — openai's `responses.stream()` ends up in
# `responses.create()` once its stream manager is entered — and that inner
# call must pass straight through: the request was already governed, and
# governing it again would re-resolve an already-resolved model name.
_IN_GOVERNED_CALL: contextvars.ContextVar[bool] = contextvars.ContextVar("marshal_in_governed_call", default=False)


class _GovernedStream:
    """Wraps a stream/stream-manager returned by a governed `stream()`
    call so the SDK's own deferred request (made when the manager is
    entered) runs inside the governed context. Everything else is
    forwarded to the real object."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def __getattr__(self, item: str) -> Any:
        return getattr(self._inner, item)

    def __enter__(self):
        token = _IN_GOVERNED_CALL.set(True)
        try:
            return self._inner.__enter__()
        finally:
            _IN_GOVERNED_CALL.reset(token)

    def __exit__(self, *exc):
        return self._inner.__exit__(*exc)

    async def __aenter__(self):
        token = _IN_GOVERNED_CALL.set(True)
        try:
            return await self._inner.__aenter__()
        finally:
            _IN_GOVERNED_CALL.reset(token)

    async def __aexit__(self, *exc):
        return await self._inner.__aexit__(*exc)

    def __iter__(self):
        return iter(self._inner)

    def __aiter__(self):
        return self._inner.__aiter__()


def _wrap_stream(result: Any) -> Any:
    if hasattr(result, "__enter__") or hasattr(result, "__aenter__"):
        return _GovernedStream(result)
    return result


def _resolve_principal(source: PrincipalSource) -> Principal:
    if isinstance(source, Principal):
        return source
    return source()


def _extract_text_from_messages(messages) -> str:
    """Best-effort text extraction covering both providers' message shapes:
    OpenAI's `content` is a string or a list of `{"type": "text", "text":
    ...}` blocks; Anthropic's is the same list-of-blocks shape. Non-text
    blocks (images, tool calls) are skipped, not guessed at."""
    if not messages:
        return ""
    parts = []
    for message in messages:
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    text = block.get("text")
                    if isinstance(text, str):
                        parts.append(text)
    return "\n".join(parts)


def _extract_text_from_google_contents(contents) -> str:
    """`google-genai`'s `contents=` kwarg has a different shape from
    `messages=`: a plain string, a `Content`/`ContentDict` (`{"parts":
    [...], "role": ...}`), a `Part`/`PartDict`, or a list of any of
    those — verified against `google.genai.types.Content`/`Part`'s real
    fields (`Content.parts: list[Part]`, `Part.text: Optional[str]`), not
    guessed. Non-text parts (images, function calls) are skipped."""
    if contents is None:
        return ""
    if isinstance(contents, str):
        return contents
    if isinstance(contents, list):
        return "\n".join(_extract_text_from_google_contents(c) for c in contents)
    if isinstance(contents, dict):
        parts = contents.get("parts")
    else:
        parts = getattr(contents, "parts", None)
    if not parts:
        return ""
    texts = []
    for part in parts:
        if isinstance(part, str):
            texts.append(part)
        elif isinstance(part, dict):
            text = part.get("text")
            if isinstance(text, str):
                texts.append(text)
        else:
            text = getattr(part, "text", None)
            if isinstance(text, str):
                texts.append(text)
    return "\n".join(texts)


def _extract_openai_prompt_text(kwargs: dict) -> str:
    return _extract_text_from_messages(kwargs.get("messages"))


def _extract_anthropic_prompt_text(kwargs: dict) -> str:
    return _extract_text_from_messages(kwargs.get("messages"))


def _extract_openai_responses_prompt_text(kwargs: dict) -> str:
    """Responses API `input=` is a string or a list of items: messages
    (`{"role", "content": str | [{"type": "input_text", "text": ...}]}`)
    and tool results fed back in (`{"type": "function_call_output",
    "output": ...}`) — the latter are exactly where untrusted content
    re-enters a conversation, so they're scanned too. `instructions=` is
    the system prompt."""
    parts = []
    instructions = kwargs.get("instructions")
    if isinstance(instructions, str):
        parts.append(instructions)
    value = kwargs.get("input")
    if isinstance(value, str):
        parts.append(value)
    elif isinstance(value, list):
        parts.append(_extract_text_from_messages(value))
        for item in value:
            output = item.get("output") if isinstance(item, dict) else getattr(item, "output", None)
            if isinstance(output, str):
                parts.append(output)
    return "\n".join(p for p in parts if p)


def _extract_google_prompt_text(kwargs: dict) -> str:
    return _extract_text_from_google_contents(kwargs.get("contents"))


def _extract_openai_completion_text(response) -> str:
    choices = getattr(response, "choices", None) or []
    parts = []
    for choice in choices:
        message = getattr(choice, "message", None)
        text = getattr(message, "content", None) if message is not None else None
        if isinstance(text, str):
            parts.append(text)
    return "\n".join(parts)


def _extract_openai_responses_completion_text(response) -> str:
    # `Response.output_text` is the SDK's own property concatenating every
    # output_text part — verified, not reimplemented.
    text = getattr(response, "output_text", None)
    return text if isinstance(text, str) else ""


def _extract_anthropic_completion_text(response) -> str:
    blocks = getattr(response, "content", None) or []
    parts = []
    for block in blocks:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(text)
    return "\n".join(parts)


def _extract_google_completion_text(response) -> str:
    # `GenerateContentResponse.text` is a real, documented property —
    # "the concatenation of all text parts in the response" — verified
    # directly, not reimplemented by guessing at `.candidates` ourselves.
    text = getattr(response, "text", None)
    return text if isinstance(text, str) else ""


def _scan_prompt_or_raise(
    scanner: Optional[SensitiveDataScanner],
    block_detectors: frozenset[str],
    guard: ModelGuard,
    principal: Principal,
    requested_model: Optional[str],
    kwargs: dict,
    extract_prompt_text: Callable[[dict], str],
) -> None:
    if scanner is None:
        return
    text = extract_prompt_text(kwargs)
    findings = scanner.scan(text)
    blocking = [f for f in findings if f.detector in block_detectors]
    location = requested_model or "?"
    if blocking:
        write_finding(guard.audit_log, principal, "model_prompt", location, blocking, "blocked")
        names = ", ".join(sorted({f.detector for f in blocking}))
        raise ModelCallDenied(location, f"blocked: sensitive data detected in prompt ({names})")
    non_blocking = [f for f in findings if f.detector not in block_detectors]
    if non_blocking:
        write_finding(guard.audit_log, principal, "model_prompt", location, non_blocking, "audited_only")


def _scan_completion(
    scanner: Optional[SensitiveDataScanner],
    guard: ModelGuard,
    principal: Principal,
    model: Optional[str],
    text: str,
) -> None:
    if scanner is None or not text:
        return
    findings = scanner.scan(text)
    if findings:
        write_finding(guard.audit_log, principal, "model_completion", model or "?", findings, "audited_only")


def _classify_openai_or_anthropic_error(exc: BaseException, provider: str) -> str:
    """openai and anthropic expose identical exception class names
    (verified directly, not assumed) — one branch covers both. Order
    matters: their own hierarchy has APITimeoutError as a subclass of
    APIConnectionError, and RateLimitError/InternalServerError as
    subclasses of APIStatusError, so the more specific checks run first."""
    try:
        sdk = __import__(provider)
    except ImportError:
        return "other"
    if isinstance(exc, sdk.APITimeoutError):
        return "timeout"
    if isinstance(exc, sdk.RateLimitError):
        return "rate_limited"
    if isinstance(exc, sdk.APIConnectionError):
        return "connection_error"
    if isinstance(exc, sdk.APIStatusError):
        status = getattr(exc, "status_code", None) or 0
        return "server_error" if status >= 500 else "other"
    return "other"


def _classify_google_error(exc: BaseException) -> str:
    """`google-genai` has a genuinely different exception shape from
    openai/anthropic (verified directly, not assumed): no
    APITimeoutError/RateLimitError/APIConnectionError class names at
    all — `APIError`/`ClientError`/`ServerError` carry a `.code` (the
    HTTP status), and network-level failures surface as the underlying
    transport's own exceptions (`google-genai` uses `httpx` for its
    async client and `requests` for its sync client — verified in
    `_api_client.py` — both are hard dependencies of `google-genai`
    itself, not optional)."""
    import httpx
    import requests
    from google.genai import errors as google_errors

    if isinstance(exc, (httpx.TimeoutException, requests.exceptions.Timeout)):
        return "timeout"
    if isinstance(exc, (httpx.ConnectError, requests.exceptions.ConnectionError)):
        return "connection_error"
    if isinstance(exc, google_errors.APIError):
        code = getattr(exc, "code", None) or 0
        if code == 429:
            return "rate_limited"
        if code >= 500:
            return "server_error"
    return "other"


def _classify_error(exc: BaseException, provider: str) -> str:
    """Best-effort classification of a real downstream call failure into a
    short, audit-safe category — never guessed from the exception's
    message text, which could embed request details that shouldn't land
    in an audit trail."""
    if provider == "google":
        try:
            return _classify_google_error(exc)
        except ImportError:
            return "other"
    return _classify_openai_or_anthropic_error(exc, provider)


ExtractPromptText = Callable[[dict], str]
ExtractText = Callable[[object], str]
ReportUsage = Callable[[ModelGuard, Principal, object], None]


def _report_openai_usage(guard: ModelGuard, principal: Principal, response) -> None:
    usage = getattr(response, "usage", None)
    model = getattr(response, "model", None)
    if usage is not None and model is not None:
        guard.record_usage(
            principal,
            model,
            prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
        )


def _report_openai_responses_usage(guard: ModelGuard, principal: Principal, response) -> None:
    usage = getattr(response, "usage", None)
    model = getattr(response, "model", None)
    if usage is not None and model is not None:
        guard.record_usage(
            principal,
            model,
            prompt_tokens=getattr(usage, "input_tokens", 0) or 0,
            completion_tokens=getattr(usage, "output_tokens", 0) or 0,
        )


def _report_anthropic_usage(guard: ModelGuard, principal: Principal, response) -> None:
    usage = getattr(response, "usage", None)
    model = getattr(response, "model", None)
    if usage is not None and model is not None:
        guard.record_usage(
            principal,
            model,
            prompt_tokens=getattr(usage, "input_tokens", 0) or 0,
            completion_tokens=getattr(usage, "output_tokens", 0) or 0,
        )


def _report_google_usage(guard: ModelGuard, principal: Principal, response) -> None:
    # `GenerateContentResponseUsageMetadata` field names verified directly
    # against the installed SDK, not guessed — no `.usage`/`.model` at the
    # top level the way openai/anthropic have; it's `.usage_metadata` and
    # `.model_version`.
    usage = getattr(response, "usage_metadata", None)
    model = getattr(response, "model_version", None)
    if usage is not None and model is not None:
        guard.record_usage(
            principal,
            model,
            prompt_tokens=getattr(usage, "prompt_token_count", 0) or 0,
            completion_tokens=getattr(usage, "candidates_token_count", 0) or 0,
        )


def _field(obj: Any, name: str) -> Any:
    return obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)


# Tool types the *client* executes; everything else in a request's tool
# list is run by the provider.
_CLIENT_TOOL_TYPES = {None, "function", "custom"}


def _openai_hosted_tools(kwargs: dict) -> tuple[set[str], list[str]]:
    names: set[str] = set()
    urls: list[str] = []
    for tool in kwargs.get("tools") or []:
        tool_type = _field(tool, "type")
        if tool_type in _CLIENT_TOOL_TYPES:
            continue
        names.add(str(tool_type))
        if tool_type == "mcp":
            url = _field(tool, "server_url")
            if isinstance(url, str):
                urls.append(url)
    return names, urls


_DATED_SUFFIX = re.compile(r"_\d{8}$")


def _anthropic_hosted_tools(kwargs: dict) -> tuple[set[str], list[str]]:
    names: set[str] = set()
    urls: list[str] = []
    for tool in kwargs.get("tools") or []:
        tool_type = _field(tool, "type")
        if tool_type in _CLIENT_TOOL_TYPES:
            continue
        # "web_search_20250305" -> "web_search": allowlists name the tool,
        # not the dated revision.
        names.add(_DATED_SUFFIX.sub("", str(tool_type)))
    for server in kwargs.get("mcp_servers") or []:
        names.add("mcp")
        url = _field(server, "url")
        if isinstance(url, str):
            urls.append(url)
    return names, urls


_GOOGLE_HOSTED_FIELDS = (
    "google_search", "google_search_retrieval", "code_execution", "url_context",
    "enterprise_web_search", "google_maps", "computer_use", "file_search",
)


def _google_hosted_tools(kwargs: dict) -> tuple[set[str], list[str]]:
    config = kwargs.get("config")
    tools = _field(config, "tools") if config is not None else None
    names: set[str] = set()
    for tool in tools or []:
        for name in _GOOGLE_HOSTED_FIELDS:
            if _field(tool, name) is not None:
                names.add(name)
    return names, []


ExtractHostedTools = Callable[[dict], tuple[set[str], list[str]]]


# What actually differs between providers at this layer: how to pull
# prompt text out of the request kwargs (`messages=` vs. `contents=`),
# how to pull completion text out of the (differently-shaped) response
# object, and which usage field names each one uses. Everything else —
# principal resolution, prompt scanning, model substitution, calling
# `original` sync or async, completion scanning — is identical, so it
# lives once in `_make_wrapper` below instead of once per provider.
# Adding a fourth provider means adding one entry here, not copy-pasting
# a wrapper.
_PROVIDER_ADAPTERS: dict[str, tuple[ExtractPromptText, ExtractText, ReportUsage, ExtractHostedTools]] = {
    "openai": (
        _extract_openai_prompt_text, _extract_openai_completion_text, _report_openai_usage,
        _openai_hosted_tools,
    ),
    "openai_responses": (
        _extract_openai_responses_prompt_text, _extract_openai_responses_completion_text,
        _report_openai_responses_usage, _openai_hosted_tools,
    ),
    "anthropic": (
        _extract_anthropic_prompt_text, _extract_anthropic_completion_text, _report_anthropic_usage,
        _anthropic_hosted_tools,
    ),
    "google": (
        _extract_google_prompt_text, _extract_google_completion_text, _report_google_usage,
        _google_hosted_tools,
    ),
}

# (module, class, method, adapter, mode) for every entry point patched.
# "full" = pre-call governance + usage/outcome/completion reporting;
# "pre_call" = governance before the call only (stream managers, whose
# real request happens later, inside the returned object).
_PATCH_TABLE: dict[str, list[tuple[str, str, str, str, str]]] = {
    "openai": [
        (mod, cls, method, adapter, mode)
        for mod, adapter, classes in (
            ("openai.resources.chat.completions.completions", "openai", ("Completions", "AsyncCompletions")),
            ("openai.resources.responses.responses", "openai_responses", ("Responses", "AsyncResponses")),
        )
        for cls in classes
        for method, mode in (("create", "full"), ("parse", "full"), ("stream", "pre_call"))
    ],
    "anthropic": [
        (mod, cls, method, "anthropic", mode)
        for mod in ("anthropic.resources.messages.messages", "anthropic.resources.beta.messages.messages")
        for cls in ("Messages", "AsyncMessages")
        for method, mode in (("create", "full"), ("parse", "full"), ("stream", "pre_call"))
    ],
    "google": [
        ("google.genai.models", cls, method, "google", mode)
        for cls in ("Models", "AsyncModels")
        for method, mode in (("generate_content", "full"), ("generate_content_stream", "pre_call"))
    ],
}


def _deny_hosted(guard: ModelGuard, principal: Principal, requested: Optional[str], reason: str) -> None:
    location = requested or "?"
    guard.audit_log.write(
        ModelCallEntry(
            timestamp=time.time(),
            principal_id=principal.id,
            logical_name=location,
            resolved_model=None,
            outcome="deny",
            reason=reason,
            on_behalf_of=principal.delegation_chain,
        )
    )
    raise ModelCallDenied(location, reason)


def _check_hosted_tools(
    guard: ModelGuard,
    principal: Principal,
    requested: Optional[str],
    kwargs: dict,
    extract_hosted: ExtractHostedTools,
    hosted_tools: Optional[frozenset[str]],
    egress: Optional[EgressAllowlist],
) -> None:
    if hosted_tools is None and egress is None:
        return
    names, urls = extract_hosted(kwargs)
    if hosted_tools is not None:
        refused = sorted(names - hosted_tools)
        if refused:
            _deny_hosted(guard, principal, requested, f"provider-hosted tool(s) not allowed: {', '.join(refused)}")
    if egress is not None:
        refused_hosts = sorted({host for host in map(host_of, urls) if not egress.is_allowed(host)})
        if refused_hosts:
            _deny_hosted(
                guard, principal, requested,
                f"hosted MCP server host(s) not on the egress allowlist: {', '.join(refused_hosts)}",
            )


def _make_wrapper(
    guard: ModelGuard,
    principal_source: PrincipalSource,
    original,
    scanner: Optional[SensitiveDataScanner],
    block_detectors: frozenset[str],
    adapter: str,
    mode: str,
    hosted_tools: Optional[frozenset[str]],
    egress: Optional[EgressAllowlist],
):
    extract_prompt_text, extract_completion_text, report_usage, extract_hosted = _PROVIDER_ADAPTERS[adapter]
    provider = "openai" if adapter.startswith("openai") else adapter

    def _before(kwargs: dict) -> Principal:
        principal = _resolve_principal(principal_source)
        requested = kwargs.get("model")
        _scan_prompt_or_raise(
            scanner, block_detectors, guard, principal, requested, kwargs, extract_prompt_text
        )
        _check_hosted_tools(guard, principal, requested, kwargs, extract_hosted, hosted_tools, egress)
        if requested is not None:
            kwargs["model"] = guard.resolve(principal, requested)
        return principal

    def _after(principal: Principal, response, kwargs: dict) -> None:
        report_usage(guard, principal, response)
        text = extract_completion_text(response)
        _scan_completion(scanner, guard, principal, kwargs.get("model"), text)
        if egress is not None and text:
            findings = egress.check(text)
            write_egress_finding(
                guard.audit_log, principal, "model_completion", kwargs.get("model") or "?", findings, "audited_only"
            )

    def _record(principal: Principal, resolved_model, start: float, exc: Optional[BaseException]) -> None:
        if resolved_model is None:
            return
        latency_ms = (time.monotonic() - start) * 1000
        if exc is None:
            guard.record_outcome(principal, resolved_model, success=True, latency_ms=latency_ms)
        else:
            guard.record_outcome(
                principal, resolved_model, success=False,
                latency_ms=latency_ms, error=_classify_error(exc, provider),
            )

    # Decided from the real method, not from which class it's on: e.g.
    # openai's AsyncCompletions.stream is a plain function returning an
    # async stream manager, not a coroutine function.
    is_async = inspect.iscoroutinefunction(original)

    # Reports every real call *attempt* (success or failure) on "full"
    # methods — what lets CircuitBreakerPolicy see actual deployment
    # health. A call denied during `_before` reports nothing: a
    # governance denial isn't a deployment failure.
    if mode == "pre_call":
        if is_async:
            async def pre_call_wrapper(self, *args, **kwargs):
                if _IN_GOVERNED_CALL.get():
                    return await original(self, *args, **kwargs)
                _before(kwargs)
                token = _IN_GOVERNED_CALL.set(True)
                try:
                    return _wrap_stream(await original(self, *args, **kwargs))
                finally:
                    _IN_GOVERNED_CALL.reset(token)

            return pre_call_wrapper

        def pre_call_sync_wrapper(self, *args, **kwargs):
            if _IN_GOVERNED_CALL.get():
                return original(self, *args, **kwargs)
            _before(kwargs)
            token = _IN_GOVERNED_CALL.set(True)
            try:
                return _wrap_stream(original(self, *args, **kwargs))
            finally:
                _IN_GOVERNED_CALL.reset(token)

        return pre_call_sync_wrapper

    if is_async:
        async def wrapper(self, *args, **kwargs):
            if _IN_GOVERNED_CALL.get():
                return await original(self, *args, **kwargs)
            principal = _before(kwargs)
            resolved_model = kwargs.get("model")
            start = time.monotonic()
            token = _IN_GOVERNED_CALL.set(True)
            try:
                response = await original(self, *args, **kwargs)
            except Exception as exc:
                _record(principal, resolved_model, start, exc)
                raise
            finally:
                _IN_GOVERNED_CALL.reset(token)
            _record(principal, resolved_model, start, None)
            _after(principal, response, kwargs)
            return response

        return wrapper

    def sync_wrapper(self, *args, **kwargs):
        if _IN_GOVERNED_CALL.get():
            return original(self, *args, **kwargs)
        principal = _before(kwargs)
        resolved_model = kwargs.get("model")
        start = time.monotonic()
        token = _IN_GOVERNED_CALL.set(True)
        try:
            response = original(self, *args, **kwargs)
        except Exception as exc:
            _record(principal, resolved_model, start, exc)
            raise
        finally:
            _IN_GOVERNED_CALL.reset(token)
        _record(principal, resolved_model, start, None)
        _after(principal, response, kwargs)
        return response

    return sync_wrapper


def _enable_provider(
    provider: str,
    guard: ModelGuard,
    principal: PrincipalSource,
    scanner: Optional[SensitiveDataScanner],
    block_detectors: frozenset[str],
    hosted_tools: Optional[Iterable[str]],
    egress_allowlist: Optional[EgressAllowlist],
) -> bool:
    """Patch every entry point in `_PATCH_TABLE[provider]`. Returns False
    if the provider's SDK isn't installed. If the SDK *is* installed but
    an expected class or method is missing (a breaking SDK change), this
    raises rather than silently patching only part of the surface."""
    entries = _PATCH_TABLE[provider]
    try:
        # __import__ (not importlib.import_module) so an import hook that
        # hides the SDK is honored.
        __import__(entries[0][0], fromlist=["_"])
    except ImportError:
        return False
    hosted = frozenset(hosted_tools) if hosted_tools is not None else None
    targets = []
    for module_name, class_name, method, adapter, mode in entries:
        module = __import__(module_name, fromlist=["_"])
        cls = getattr(module, class_name)
        if not hasattr(cls, method):
            raise AttributeError(f"{module_name}.{class_name}.{method} not found — unsupported {provider} SDK version")
        targets.append((cls, method, adapter, mode))
    for cls, method, adapter, mode in targets:
        _patch_method(cls, method, guard, principal, scanner, block_detectors, adapter, mode, hosted, egress_allowlist)
    return True


def enable_openai(
    guard: ModelGuard,
    principal: PrincipalSource,
    scanner: Optional[SensitiveDataScanner] = None,
    block_detectors: frozenset[str] = DEFAULT_BLOCK_DETECTORS,
    hosted_tools: Optional[Iterable[str]] = None,
    egress_allowlist: Optional[EgressAllowlist] = None,
) -> bool:
    """Patch the OpenAI SDK's chat completions *and* Responses API clients
    (create/parse/stream, sync + async), if installed. Returns True if
    patching happened, False if `openai` isn't importable — never raises
    just because it's absent."""
    return _enable_provider("openai", guard, principal, scanner, block_detectors, hosted_tools, egress_allowlist)


def enable_anthropic(
    guard: ModelGuard,
    principal: PrincipalSource,
    scanner: Optional[SensitiveDataScanner] = None,
    block_detectors: frozenset[str] = DEFAULT_BLOCK_DETECTORS,
    hosted_tools: Optional[Iterable[str]] = None,
    egress_allowlist: Optional[EgressAllowlist] = None,
) -> bool:
    """Patch the Anthropic SDK's messages clients, including `beta.messages`
    (create/parse/stream, sync + async), if installed. Returns True if
    patching happened, False if `anthropic` isn't importable."""
    return _enable_provider("anthropic", guard, principal, scanner, block_detectors, hosted_tools, egress_allowlist)


def enable_google(
    guard: ModelGuard,
    principal: PrincipalSource,
    scanner: Optional[SensitiveDataScanner] = None,
    block_detectors: frozenset[str] = DEFAULT_BLOCK_DETECTORS,
    hosted_tools: Optional[Iterable[str]] = None,
    egress_allowlist: Optional[EgressAllowlist] = None,
) -> bool:
    """Patch the Google GenAI SDK's `Models.generate_content` and
    `generate_content_stream` (sync + async), if installed — the calls
    ADK's `LlmAgent` makes for a native Gemini model (verified against
    ADK's own source). Returns True if patching happened, False if
    `google-genai` isn't importable."""
    return _enable_provider("google", guard, principal, scanner, block_detectors, hosted_tools, egress_allowlist)


def _patch_method(
    cls,
    attr_name: str,
    guard,
    principal,
    scanner: Optional[SensitiveDataScanner],
    block_detectors: frozenset[str],
    adapter: str,
    mode: str,
    hosted_tools: Optional[frozenset[str]],
    egress: Optional[EgressAllowlist],
) -> None:
    original = cls.__dict__.get(attr_name, getattr(cls, attr_name))
    # Never wrap a wrapper: a second enable() would otherwise govern each
    # call twice (two audit entries, two budget charges).
    while hasattr(original, "__marshal_original__"):
        original = original.__marshal_original__
    wrapped = _make_wrapper(guard, principal, original, scanner, block_detectors, adapter, mode, hosted_tools, egress)
    wrapped.__marshal_original__ = original  # type: ignore[attr-defined]
    wrapped.__name__ = getattr(original, "__name__", attr_name)
    wrapped.__qualname__ = getattr(original, "__qualname__", attr_name)
    wrapped.__doc__ = getattr(original, "__doc__", None)
    _patched.append((cls, attr_name, cls.__dict__.get(attr_name, original)))
    setattr(cls, attr_name, wrapped)


def enable(
    guard: ModelGuard,
    principal: PrincipalSource,
    scanner: Optional[SensitiveDataScanner] = None,
    block_detectors: frozenset[str] = DEFAULT_BLOCK_DETECTORS,
    hosted_tools: Optional[Iterable[str]] = None,
    egress_allowlist: Optional[EgressAllowlist] = None,
) -> list[str]:
    """Patch every installed, supported SDK. Returns the names of what
    actually got patched (e.g. ["openai", "anthropic", "google"]) so you
    can confirm what's actually governed rather than assuming — see
    `patched_methods()` for the method-level list."""
    patched = []
    for provider, fn in (("openai", enable_openai), ("anthropic", enable_anthropic), ("google", enable_google)):
        if fn(guard, principal, scanner, block_detectors, hosted_tools, egress_allowlist):
            patched.append(provider)
    return patched


def patched_methods() -> list[str]:
    """Every SDK method currently governed, as "module.Class.method" —
    for asserting coverage at startup."""
    seen = []
    for cls, attr_name, _ in _patched:
        name = f"{cls.__module__}.{cls.__qualname__}.{attr_name}"
        if name not in seen and hasattr(getattr(cls, attr_name, None), "__marshal_original__"):
            seen.append(name)
    return seen


def disable_all() -> None:
    """Restore every method `enable()`/`enable_openai()`/`enable_anthropic()`/
    `enable_google()` patched, in reverse order. Mainly for tests — most
    processes that call `enable()` want it on for the process lifetime."""
    while _patched:
        cls, attr_name, original = _patched.pop()
        setattr(cls, attr_name, original)


__all__ = [
    "ModelCallDenied",
    "enable",
    "enable_openai",
    "enable_anthropic",
    "enable_google",
    "disable_all",
    "patched_methods",
    "ToolGovernor",
    "GovernorResult",
]
