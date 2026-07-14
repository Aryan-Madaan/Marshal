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

What this patches, and why only this: the requested `model` on every
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
does *not* attempt to intercept tool-call execution here —
that happens inside each framework's own dispatch code, at a different
layer with no single choke point the way model calls have one. Use
`ToolGuard` directly around your tool functions for that surface; see
`ideas.md` for why framework-specific tool-call adapters are a separate,
later piece of work, not something SDK patching can honestly cover.

Known cost of this approach (documented, not hidden): monkeypatching an
SDK's client class breaks silently on breaking changes to that SDK's
internals. `enable()` patches by exact class/method reference, resolved at
call time — if a future SDK major version renames or restructures these,
`enable()` will raise ImportError/AttributeError immediately rather than
patching nothing silently, but it will need updating.

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

import time
from typing import Callable, Optional, Union

from marshal_ai.models import ModelCallDenied, ModelGuard
from marshal_ai.policy import Principal
from marshal_ai.sensitive import DEFAULT_BLOCK_DETECTORS, SensitiveDataScanner, write_finding

PrincipalSource = Union[Principal, Callable[[], Principal]]

_patched: list[tuple[object, str, Callable]] = []  # (cls, attr_name, original) for disable()


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


# What actually differs between providers at this layer: how to pull
# prompt text out of the request kwargs (`messages=` vs. `contents=`),
# how to pull completion text out of the (differently-shaped) response
# object, and which usage field names each one uses. Everything else —
# principal resolution, prompt scanning, model substitution, calling
# `original` sync or async, completion scanning — is identical, so it
# lives once in `_make_wrapper` below instead of once per provider.
# Adding a fourth provider means adding one entry here, not copy-pasting
# a wrapper.
_PROVIDER_ADAPTERS: dict[str, tuple[ExtractPromptText, ExtractText, ReportUsage]] = {
    "openai": (_extract_openai_prompt_text, _extract_openai_completion_text, _report_openai_usage),
    "anthropic": (_extract_anthropic_prompt_text, _extract_anthropic_completion_text, _report_anthropic_usage),
    "google": (_extract_google_prompt_text, _extract_google_completion_text, _report_google_usage),
}


def _make_wrapper(
    guard: ModelGuard,
    principal_source: PrincipalSource,
    original,
    is_async: bool,
    scanner: Optional[SensitiveDataScanner],
    block_detectors: frozenset[str],
    extract_prompt_text: ExtractPromptText,
    extract_completion_text: ExtractText,
    report_usage: ReportUsage,
    provider: str,
):
    def _before(kwargs: dict) -> Principal:
        principal = _resolve_principal(principal_source)
        requested = kwargs.get("model")
        _scan_prompt_or_raise(
            scanner, block_detectors, guard, principal, requested, kwargs, extract_prompt_text
        )
        if requested is not None:
            kwargs["model"] = guard.resolve(principal, requested)
        return principal

    def _after(principal: Principal, response, kwargs: dict) -> None:
        report_usage(guard, principal, response)
        _scan_completion(scanner, guard, principal, kwargs.get("model"), extract_completion_text(response))

    # Reports every real call *attempt* (success or failure), not just the
    # success path `_after` above already covers — this is what lets
    # CircuitBreakerPolicy see actual deployment health, not just static
    # routing config. A call that never actually happens (denied during
    # `_before`, before `start` is ever taken) correctly reports nothing:
    # a governance denial isn't a deployment failure. TTFT specifically
    # isn't covered here — that requires wrapping a streaming response's
    # iterator, which this layer doesn't handle yet; see ideas.md.
    if is_async:
        async def wrapper(self, *args, **kwargs):
            principal = _before(kwargs)
            resolved_model = kwargs.get("model")
            start = time.monotonic()
            try:
                response = await original(self, *args, **kwargs)
            except Exception as exc:
                if resolved_model is not None:
                    latency_ms = (time.monotonic() - start) * 1000
                    guard.record_outcome(
                        principal, resolved_model, success=False,
                        latency_ms=latency_ms, error=_classify_error(exc, provider),
                    )
                raise
            if resolved_model is not None:
                latency_ms = (time.monotonic() - start) * 1000
                guard.record_outcome(principal, resolved_model, success=True, latency_ms=latency_ms)
            _after(principal, response, kwargs)
            return response

        return wrapper

    def wrapper(self, *args, **kwargs):
        principal = _before(kwargs)
        resolved_model = kwargs.get("model")
        start = time.monotonic()
        try:
            response = original(self, *args, **kwargs)
        except Exception as exc:
            if resolved_model is not None:
                latency_ms = (time.monotonic() - start) * 1000
                guard.record_outcome(
                    principal, resolved_model, success=False,
                    latency_ms=latency_ms, error=_classify_error(exc, provider),
                )
            raise
        if resolved_model is not None:
            latency_ms = (time.monotonic() - start) * 1000
            guard.record_outcome(principal, resolved_model, success=True, latency_ms=latency_ms)
        _after(principal, response, kwargs)
        return response

    return wrapper


def enable_openai(
    guard: ModelGuard,
    principal: PrincipalSource,
    scanner: Optional[SensitiveDataScanner] = None,
    block_detectors: frozenset[str] = DEFAULT_BLOCK_DETECTORS,
) -> bool:
    """Patch the OpenAI SDK's chat completions client (sync + async), if
    installed. Returns True if patching happened, False if the `openai`
    package isn't importable — never raises just because it's absent."""
    try:
        from openai.resources.chat.completions.completions import (
            AsyncCompletions,
            Completions,
        )
    except ImportError:
        return False

    _patch_method(Completions, "create", guard, principal, False, scanner, block_detectors, "openai")
    _patch_method(AsyncCompletions, "create", guard, principal, True, scanner, block_detectors, "openai")
    return True


def enable_anthropic(
    guard: ModelGuard,
    principal: PrincipalSource,
    scanner: Optional[SensitiveDataScanner] = None,
    block_detectors: frozenset[str] = DEFAULT_BLOCK_DETECTORS,
) -> bool:
    """Patch the Anthropic SDK's messages client (sync + async), if
    installed. Returns True if patching happened, False if the
    `anthropic` package isn't importable — never raises just because it's
    absent."""
    try:
        from anthropic.resources.messages.messages import AsyncMessages, Messages
    except ImportError:
        return False

    _patch_method(Messages, "create", guard, principal, False, scanner, block_detectors, "anthropic")
    _patch_method(AsyncMessages, "create", guard, principal, True, scanner, block_detectors, "anthropic")
    return True


def enable_google(
    guard: ModelGuard,
    principal: PrincipalSource,
    scanner: Optional[SensitiveDataScanner] = None,
    block_detectors: frozenset[str] = DEFAULT_BLOCK_DETECTORS,
) -> bool:
    """Patch the Google GenAI SDK's `Models.generate_content` (sync +
    async), if installed — this is the call ADK's `LlmAgent` actually
    makes for a native Gemini model (verified against ADK's own source:
    it uses `google-genai` directly, not LiteLLM or the openai/anthropic
    clients, for its default, non-`LiteLlm` model path). Returns True if
    patching happened, False if the `google-genai` package isn't
    importable — never raises just because it's absent."""
    try:
        from google.genai.models import AsyncModels, Models
    except ImportError:
        return False

    _patch_method(Models, "generate_content", guard, principal, False, scanner, block_detectors, "google")
    _patch_method(AsyncModels, "generate_content", guard, principal, True, scanner, block_detectors, "google")
    return True


def _patch_method(
    cls,
    attr_name: str,
    guard,
    principal,
    is_async: bool,
    scanner: Optional[SensitiveDataScanner],
    block_detectors: frozenset[str],
    provider: str,
) -> None:
    extract_prompt_text, extract_completion_text, report_usage = _PROVIDER_ADAPTERS[provider]
    original = getattr(cls, attr_name)
    wrapped = _make_wrapper(
        guard, principal, original, is_async, scanner, block_detectors,
        extract_prompt_text, extract_completion_text, report_usage, provider,
    )
    wrapped.__marshal_original__ = original  # type: ignore[attr-defined]
    setattr(cls, attr_name, wrapped)
    _patched.append((cls, attr_name, original))


def enable(
    guard: ModelGuard,
    principal: PrincipalSource,
    scanner: Optional[SensitiveDataScanner] = None,
    block_detectors: frozenset[str] = DEFAULT_BLOCK_DETECTORS,
) -> list[str]:
    """Patch every installed, supported SDK. Returns the names of what
    actually got patched (e.g. ["openai", "anthropic", "google"]) so you
    can confirm what's actually governed rather than assuming."""
    patched = []
    if enable_openai(guard, principal, scanner, block_detectors):
        patched.append("openai")
    if enable_anthropic(guard, principal, scanner, block_detectors):
        patched.append("anthropic")
    if enable_google(guard, principal, scanner, block_detectors):
        patched.append("google")
    return patched


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
]
