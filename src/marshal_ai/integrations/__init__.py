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
usage from the real response auto-reported via `guard.record_usage`. It
deliberately does *not* attempt to intercept tool-call execution here —
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
"""

from __future__ import annotations

from typing import Callable, Optional, Union

from marshal_ai.models import ModelCallDenied, ModelGuard
from marshal_ai.policy import Principal

PrincipalSource = Union[Principal, Callable[[], Principal]]

_patched: list[tuple[object, str, Callable]] = []  # (cls, attr_name, original) for disable()


def _resolve_principal(source: PrincipalSource) -> Principal:
    if isinstance(source, Principal):
        return source
    return source()


def _make_openai_wrapper(guard: ModelGuard, principal_source: PrincipalSource, original, is_async: bool):
    if is_async:
        async def wrapper(self, *args, **kwargs):
            principal = _resolve_principal(principal_source)
            requested = kwargs.get("model")
            if requested is not None:
                kwargs["model"] = guard.resolve(principal, requested)
            response = await original(self, *args, **kwargs)
            _report_openai_usage(guard, principal, response)
            return response

        return wrapper

    def wrapper(self, *args, **kwargs):
        principal = _resolve_principal(principal_source)
        requested = kwargs.get("model")
        if requested is not None:
            kwargs["model"] = guard.resolve(principal, requested)
        response = original(self, *args, **kwargs)
        _report_openai_usage(guard, principal, response)
        return response

    return wrapper


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


def _make_anthropic_wrapper(guard: ModelGuard, principal_source: PrincipalSource, original, is_async: bool):
    if is_async:
        async def wrapper(self, *args, **kwargs):
            principal = _resolve_principal(principal_source)
            requested = kwargs.get("model")
            if requested is not None:
                kwargs["model"] = guard.resolve(principal, requested)
            response = await original(self, *args, **kwargs)
            _report_anthropic_usage(guard, principal, response)
            return response

        return wrapper

    def wrapper(self, *args, **kwargs):
        principal = _resolve_principal(principal_source)
        requested = kwargs.get("model")
        if requested is not None:
            kwargs["model"] = guard.resolve(principal, requested)
        response = original(self, *args, **kwargs)
        _report_anthropic_usage(guard, principal, response)
        return response

    return wrapper


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


def enable_openai(guard: ModelGuard, principal: PrincipalSource) -> bool:
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

    _patch_method(Completions, "create", _make_openai_wrapper, guard, principal, is_async=False)
    _patch_method(AsyncCompletions, "create", _make_openai_wrapper, guard, principal, is_async=True)
    return True


def enable_anthropic(guard: ModelGuard, principal: PrincipalSource) -> bool:
    """Patch the Anthropic SDK's messages client (sync + async), if
    installed. Returns True if patching happened, False if the
    `anthropic` package isn't importable — never raises just because it's
    absent."""
    try:
        from anthropic.resources.messages.messages import AsyncMessages, Messages
    except ImportError:
        return False

    _patch_method(Messages, "create", _make_anthropic_wrapper, guard, principal, is_async=False)
    _patch_method(AsyncMessages, "create", _make_anthropic_wrapper, guard, principal, is_async=True)
    return True


def _patch_method(cls, attr_name: str, wrapper_factory, guard, principal, is_async: bool) -> None:
    original = getattr(cls, attr_name)
    wrapped = wrapper_factory(guard, principal, original, is_async)
    wrapped.__marshal_original__ = original  # type: ignore[attr-defined]
    setattr(cls, attr_name, wrapped)
    _patched.append((cls, attr_name, original))


def enable(guard: ModelGuard, principal: PrincipalSource) -> list[str]:
    """Patch every installed, supported SDK. Returns the names of what
    actually got patched (e.g. ["openai", "anthropic"]) so you can confirm
    what's actually governed rather than assuming."""
    patched = []
    if enable_openai(guard, principal):
        patched.append("openai")
    if enable_anthropic(guard, principal):
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
