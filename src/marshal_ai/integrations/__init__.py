"""One-line, framework-agnostic model governance.

`marshal_ai.integrations.enable(guard, principal)` patches whichever of the
OpenAI and Anthropic Python SDK clients are installed, so *any* framework
built on top of them — LangChain, LangGraph, CrewAI, AutoGen, Google ADK
(when configured with either provider), or a raw script — gets model
governance transparently, without touching the framework's own code:

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


def _scan_prompt_or_raise(
    scanner: Optional[SensitiveDataScanner],
    block_detectors: frozenset[str],
    guard: ModelGuard,
    principal: Principal,
    requested_model: Optional[str],
    kwargs: dict,
    extract_text: Callable[[list], str],
) -> None:
    if scanner is None:
        return
    text = extract_text(kwargs.get("messages"))
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


def _classify_error(exc: BaseException, provider: str) -> str:
    """Best-effort classification of a real downstream call failure into a
    short, audit-safe category — checked against each SDK's actual
    exception classes (openai and anthropic expose identical names for
    these, verified directly rather than assumed), not guessed from the
    exception's message text, which could embed request details that
    shouldn't land in an audit trail. Order matters: openai/anthropic's
    own hierarchy has APITimeoutError as a subclass of APIConnectionError,
    and RateLimitError/InternalServerError as subclasses of
    APIStatusError, so the more specific checks have to run first."""
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


# What actually differs between OpenAI and Anthropic at this layer: how to
# pull completion text out of their (differently-shaped) response objects,
# and which usage field names their `usage` object uses. Everything else —
# principal resolution, prompt scanning, model substitution, calling
# `original` sync or async, completion scanning — is identical, so it lives
# once in `_make_wrapper` below instead of twice per provider. Adding a
# third provider means adding one entry here, not copy-pasting a wrapper.
_PROVIDER_ADAPTERS: dict[str, tuple[ExtractText, ReportUsage]] = {
    "openai": (_extract_openai_completion_text, _report_openai_usage),
    "anthropic": (_extract_anthropic_completion_text, _report_anthropic_usage),
}


def _make_wrapper(
    guard: ModelGuard,
    principal_source: PrincipalSource,
    original,
    is_async: bool,
    scanner: Optional[SensitiveDataScanner],
    block_detectors: frozenset[str],
    extract_completion_text: ExtractText,
    report_usage: ReportUsage,
    provider: str,
):
    def _before(kwargs: dict) -> Principal:
        principal = _resolve_principal(principal_source)
        requested = kwargs.get("model")
        _scan_prompt_or_raise(
            scanner, block_detectors, guard, principal, requested, kwargs, _extract_text_from_messages
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
    extract_completion_text, report_usage = _PROVIDER_ADAPTERS[provider]
    original = getattr(cls, attr_name)
    wrapped = _make_wrapper(
        guard, principal, original, is_async, scanner, block_detectors,
        extract_completion_text, report_usage, provider,
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
    actually got patched (e.g. ["openai", "anthropic"]) so you can confirm
    what's actually governed rather than assuming."""
    patched = []
    if enable_openai(guard, principal, scanner, block_detectors):
        patched.append("openai")
    if enable_anthropic(guard, principal, scanner, block_detectors):
        patched.append("anthropic")
    return patched


def disable_all() -> None:
    """Restore every method `enable()`/`enable_openai()`/`enable_anthropic()`
    patched, in reverse order. Mainly for tests — most processes that call
    `enable()` want it on for the process lifetime."""
    while _patched:
        cls, attr_name, original = _patched.pop()
        setattr(cls, attr_name, original)


__all__ = [
    "ModelCallDenied",
    "enable",
    "enable_openai",
    "enable_anthropic",
    "disable_all",
]
