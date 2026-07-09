from dataclasses import dataclass

import pytest

import marshal_ai.integrations as marshal_integrations
from marshal_ai.audit import InMemoryAuditSink
from marshal_ai.models import (
    AllowlistModelPolicy,
    ModelCallDenied,
    ModelCandidate,
    ModelGuard,
)
from marshal_ai.policy import Principal


@pytest.fixture(autouse=True)
def cleanup_patches():
    yield
    marshal_integrations.disable_all()


# --- fake response shapes matching the real SDKs' field names -------------


@dataclass
class FakeOpenAIUsage:
    prompt_tokens: int
    completion_tokens: int


@dataclass
class FakeOpenAIResponse:
    model: str
    usage: FakeOpenAIUsage


@dataclass
class FakeAnthropicUsage:
    input_tokens: int
    output_tokens: int


@dataclass
class FakeAnthropicResponse:
    model: str
    usage: FakeAnthropicUsage


# --- OpenAI ------------------------------------------------------------


def test_enable_openai_substitutes_resolved_model_and_calls_original(monkeypatch):
    from openai.resources.chat.completions.completions import Completions

    calls = []

    def fake_create(self, *args, **kwargs):
        calls.append(kwargs.get("model"))
        return FakeOpenAIResponse(model=kwargs.get("model"), usage=FakeOpenAIUsage(10, 5))

    monkeypatch.setattr(Completions, "create", fake_create, raising=True)

    policy = AllowlistModelPolicy({"gpt-4o": [ModelCandidate("gpt-4o-mini")]})
    guard = ModelGuard(policy=policy)
    alice = Principal(id="alice")

    patched = marshal_integrations.enable_openai(guard, alice)
    assert patched is True

    client = Completions.__new__(Completions)  # bypass real __init__, we only call .create
    response = client.create(model="gpt-4o", messages=[])

    assert calls == ["gpt-4o-mini"]  # the real call got the *resolved* model
    assert response.model == "gpt-4o-mini"


def test_enable_openai_denies_and_never_calls_original(monkeypatch):
    from openai.resources.chat.completions.completions import Completions

    calls = []
    monkeypatch.setattr(
        Completions, "create", lambda self, **kw: calls.append(kw) or None, raising=True
    )

    policy = AllowlistModelPolicy({})  # nothing routed -> always denies
    guard = ModelGuard(policy=policy)
    marshal_integrations.enable_openai(guard, Principal(id="alice"))

    client = Completions.__new__(Completions)
    with pytest.raises(ModelCallDenied):
        client.create(model="gpt-4o", messages=[])

    assert calls == []


def test_enable_openai_reports_usage_from_the_real_response(monkeypatch):
    from openai.resources.chat.completions.completions import Completions

    monkeypatch.setattr(
        Completions,
        "create",
        lambda self, **kw: FakeOpenAIResponse(
            model=kw["model"], usage=FakeOpenAIUsage(prompt_tokens=100, completion_tokens=42)
        ),
        raising=True,
    )

    sink = InMemoryAuditSink()
    guard = ModelGuard(policy=AllowlistModelPolicy({"m": [ModelCandidate("real-model")]}), audit_sink=sink)
    marshal_integrations.enable_openai(guard, Principal(id="alice"))

    Completions.__new__(Completions).create(model="m", messages=[])

    usage_entries = [e for e in sink.tail(5) if e.to_dict()["kind"] == "model_usage"]
    assert len(usage_entries) == 1
    assert usage_entries[0].prompt_tokens == 100
    assert usage_entries[0].completion_tokens == 42


# --- Anthropic -----------------------------------------------------------


def test_enable_anthropic_substitutes_resolved_model_and_reports_usage(monkeypatch):
    from anthropic.resources.messages.messages import Messages

    monkeypatch.setattr(
        Messages,
        "create",
        lambda self, **kw: FakeAnthropicResponse(
            model=kw["model"], usage=FakeAnthropicUsage(input_tokens=7, output_tokens=3)
        ),
        raising=True,
    )

    sink = InMemoryAuditSink()
    policy = AllowlistModelPolicy({"claude-opus-4-8": [ModelCandidate("claude-sonnet-5")]})
    guard = ModelGuard(policy=policy, audit_sink=sink)
    marshal_integrations.enable_anthropic(guard, Principal(id="bob"))

    response = Messages.__new__(Messages).create(model="claude-opus-4-8", max_tokens=100, messages=[])

    assert response.model == "claude-sonnet-5"
    usage_entries = [e for e in sink.tail(5) if e.to_dict()["kind"] == "model_usage"]
    assert usage_entries[0].prompt_tokens == 7
    assert usage_entries[0].completion_tokens == 3


# --- principal resolution, enable()/disable_all() -------------------------


def test_principal_can_be_a_callable_for_per_request_resolution(monkeypatch):
    from openai.resources.chat.completions.completions import Completions

    monkeypatch.setattr(
        Completions,
        "create",
        lambda self, **kw: FakeOpenAIResponse(model=kw["model"], usage=FakeOpenAIUsage(1, 1)),
        raising=True,
    )

    seen_principals = []
    policy = AllowlistModelPolicy({"m": [ModelCandidate("m")]})

    class TrackingGuard(ModelGuard):
        def resolve(self, principal, logical_name, context=None):
            seen_principals.append(principal.id)
            return super().resolve(principal, logical_name, context)

    guard = TrackingGuard(policy=policy)
    current_user = {"id": "alice"}
    marshal_integrations.enable_openai(guard, lambda: Principal(id=current_user["id"]))

    Completions.__new__(Completions).create(model="m", messages=[])
    current_user["id"] = "bob"
    Completions.__new__(Completions).create(model="m", messages=[])

    assert seen_principals == ["alice", "bob"]


def test_enable_returns_names_of_what_actually_got_patched():
    guard = ModelGuard()
    patched = marshal_integrations.enable(guard, Principal(id="alice"))
    assert set(patched) == {"openai", "anthropic"}  # both are installed in this test env


def test_disable_all_restores_original_behavior(monkeypatch):
    from openai.resources.chat.completions.completions import Completions

    def original(self, **kw):
        return "untouched"

    monkeypatch.setattr(Completions, "create", original, raising=True)

    guard = ModelGuard(policy=AllowlistModelPolicy({}))  # would deny if it ran
    marshal_integrations.enable_openai(guard, Principal(id="alice"))
    marshal_integrations.disable_all()

    # after disabling, the original (unpatched, un-governed) method runs again
    result = Completions.__new__(Completions).create(model="anything")
    assert result == "untouched"


def test_missing_sdk_does_not_raise(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def blocking_import(name, *args, **kwargs):
        if name.startswith("openai"):
            raise ImportError("simulated: openai not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocking_import)

    guard = ModelGuard()
    result = marshal_integrations.enable_openai(guard, Principal(id="alice"))
    assert result is False


# --- async path (separate code from sync — verify it too) ----------------


def test_enable_openai_async_path_substitutes_model_and_reports_usage(monkeypatch):
    import asyncio

    from openai.resources.chat.completions.completions import AsyncCompletions

    async def fake_create(self, *args, **kwargs):
        return FakeOpenAIResponse(model=kwargs["model"], usage=FakeOpenAIUsage(4, 2))

    monkeypatch.setattr(AsyncCompletions, "create", fake_create, raising=True)

    sink = InMemoryAuditSink()
    policy = AllowlistModelPolicy({"gpt-4o": [ModelCandidate("gpt-4o-mini")]})
    guard = ModelGuard(policy=policy, audit_sink=sink)
    marshal_integrations.enable_openai(guard, Principal(id="alice"))

    client = AsyncCompletions.__new__(AsyncCompletions)
    response = asyncio.run(client.create(model="gpt-4o", messages=[]))

    assert response.model == "gpt-4o-mini"
    usage_entries = [e for e in sink.tail(5) if e.to_dict()["kind"] == "model_usage"]
    assert usage_entries[0].prompt_tokens == 4


def test_enable_anthropic_async_path_denies_without_calling_original(monkeypatch):
    import asyncio

    from anthropic.resources.messages.messages import AsyncMessages

    calls = []

    async def fake_create(self, **kw):
        calls.append(kw)
        return None

    monkeypatch.setattr(AsyncMessages, "create", fake_create, raising=True)

    guard = ModelGuard(policy=AllowlistModelPolicy({}))
    marshal_integrations.enable_anthropic(guard, Principal(id="alice"))

    client = AsyncMessages.__new__(AsyncMessages)
    with pytest.raises(ModelCallDenied):
        asyncio.run(client.create(model="claude-opus-4-8", max_tokens=10, messages=[]))

    assert calls == []
