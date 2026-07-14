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


@dataclass
class FakeGoogleUsage:
    prompt_token_count: int
    candidates_token_count: int


@dataclass
class FakeGoogleResponse:
    model_version: str
    usage_metadata: FakeGoogleUsage
    text: str = "ok"


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


def test_enable_openai_reports_successful_outcome_with_latency(monkeypatch):
    from openai.resources.chat.completions.completions import Completions

    monkeypatch.setattr(
        Completions,
        "create",
        lambda self, **kw: FakeOpenAIResponse(model=kw["model"], usage=FakeOpenAIUsage(1, 1)),
        raising=True,
    )

    sink = InMemoryAuditSink()
    guard = ModelGuard(policy=AllowlistModelPolicy({"m": [ModelCandidate("real-model")]}), audit_sink=sink)
    marshal_integrations.enable_openai(guard, Principal(id="alice"))

    Completions.__new__(Completions).create(model="m", messages=[])

    outcomes = [e for e in sink.tail(5) if e.to_dict()["kind"] == "model_outcome"]
    assert len(outcomes) == 1
    assert outcomes[0].success is True
    assert outcomes[0].model == "real-model"
    assert outcomes[0].latency_ms is not None and outcomes[0].latency_ms >= 0
    assert outcomes[0].error is None


def test_enable_openai_reports_failure_outcome_and_still_reraises(monkeypatch):
    import httpx
    import openai
    from openai.resources.chat.completions.completions import Completions

    req = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    real_error = openai.RateLimitError("rate limited", response=httpx.Response(429, request=req), body=None)

    def fake_create(self, **kw):
        raise real_error

    monkeypatch.setattr(Completions, "create", fake_create, raising=True)

    sink = InMemoryAuditSink()
    guard = ModelGuard(policy=AllowlistModelPolicy({"m": [ModelCandidate("real-model")]}), audit_sink=sink)
    marshal_integrations.enable_openai(guard, Principal(id="alice"))

    # the critical regression: Marshal must never swallow the real error —
    # it only ever observes a failure here, never gatekeeps on it.
    with pytest.raises(openai.RateLimitError) as exc_info:
        Completions.__new__(Completions).create(model="m", messages=[])
    assert exc_info.value is real_error

    outcomes = [e for e in sink.tail(5) if e.to_dict()["kind"] == "model_outcome"]
    assert len(outcomes) == 1
    assert outcomes[0].success is False
    assert outcomes[0].model == "real-model"
    assert outcomes[0].error == "rate_limited"
    assert outcomes[0].latency_ms is not None


def test_enable_openai_classifies_timeout_correctly(monkeypatch):
    import httpx
    import openai
    from openai.resources.chat.completions.completions import Completions

    req = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")

    def fake_create(self, **kw):
        raise openai.APITimeoutError(req)

    monkeypatch.setattr(Completions, "create", fake_create, raising=True)

    sink = InMemoryAuditSink()
    guard = ModelGuard(policy=AllowlistModelPolicy({"m": [ModelCandidate("real-model")]}), audit_sink=sink)
    marshal_integrations.enable_openai(guard, Principal(id="alice"))

    with pytest.raises(openai.APITimeoutError):
        Completions.__new__(Completions).create(model="m", messages=[])

    outcomes = [e for e in sink.tail(5) if e.to_dict()["kind"] == "model_outcome"]
    assert outcomes[0].error == "timeout"


def test_denied_call_never_reports_an_outcome(monkeypatch):
    from openai.resources.chat.completions.completions import Completions

    calls = []
    monkeypatch.setattr(
        Completions, "create", lambda self, **kw: calls.append(kw) or None, raising=True
    )

    sink = InMemoryAuditSink()
    guard = ModelGuard(policy=AllowlistModelPolicy({}), audit_sink=sink)  # always denies
    marshal_integrations.enable_openai(guard, Principal(id="alice"))

    with pytest.raises(ModelCallDenied):
        Completions.__new__(Completions).create(model="gpt-4o", messages=[])

    # a governance denial isn't a deployment failure — nothing was attempted
    assert calls == []
    outcomes = [e for e in sink.tail(5) if e.to_dict()["kind"] == "model_outcome"]
    assert outcomes == []


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


# --- Google GenAI (Gemini / ADK's default model path) ----------------------


def test_enable_google_substitutes_resolved_model_and_reports_usage(monkeypatch):
    from google.genai.models import Models

    monkeypatch.setattr(
        Models,
        "generate_content",
        lambda self, **kw: FakeGoogleResponse(
            model_version=kw["model"], usage_metadata=FakeGoogleUsage(prompt_token_count=12, candidates_token_count=7)
        ),
        raising=True,
    )

    sink = InMemoryAuditSink()
    policy = AllowlistModelPolicy({"gemini-pro": [ModelCandidate("gemini-flash")]})
    guard = ModelGuard(policy=policy, audit_sink=sink)
    marshal_integrations.enable_google(guard, Principal(id="alice"))

    response = Models.__new__(Models).generate_content(model="gemini-pro", contents="hi")

    assert response.model_version == "gemini-flash"
    usage_entries = [e for e in sink.tail(5) if e.to_dict()["kind"] == "model_usage"]
    assert usage_entries[0].prompt_tokens == 12
    assert usage_entries[0].completion_tokens == 7


def test_enable_google_denies_and_never_calls_original(monkeypatch):
    from google.genai.models import Models

    calls = []
    monkeypatch.setattr(
        Models, "generate_content", lambda self, **kw: calls.append(kw) or None, raising=True
    )

    policy = AllowlistModelPolicy({})  # nothing routed -> always denies
    guard = ModelGuard(policy=policy)
    marshal_integrations.enable_google(guard, Principal(id="alice"))

    client = Models.__new__(Models)
    with pytest.raises(ModelCallDenied):
        client.generate_content(model="gemini-pro", contents="hi")

    assert calls == []


def test_enable_google_reports_successful_outcome_with_latency(monkeypatch):
    from google.genai.models import Models

    monkeypatch.setattr(
        Models,
        "generate_content",
        lambda self, **kw: FakeGoogleResponse(
            model_version=kw["model"], usage_metadata=FakeGoogleUsage(1, 1)
        ),
        raising=True,
    )

    sink = InMemoryAuditSink()
    guard = ModelGuard(policy=AllowlistModelPolicy({"m": [ModelCandidate("gemini-flash")]}), audit_sink=sink)
    marshal_integrations.enable_google(guard, Principal(id="alice"))

    Models.__new__(Models).generate_content(model="m", contents="hi")

    outcomes = [e for e in sink.tail(5) if e.to_dict()["kind"] == "model_outcome"]
    assert outcomes[0].success is True
    assert outcomes[0].model == "gemini-flash"
    assert outcomes[0].latency_ms is not None


def test_enable_google_classifies_rate_limit_and_still_reraises(monkeypatch):
    from google.genai import errors as google_errors
    from google.genai.models import Models

    real_error = google_errors.ClientError(
        code=429, response_json={"error": {"message": "quota exceeded", "status": "RESOURCE_EXHAUSTED"}}
    )

    def fake_generate_content(self, **kw):
        raise real_error

    monkeypatch.setattr(Models, "generate_content", fake_generate_content, raising=True)

    sink = InMemoryAuditSink()
    guard = ModelGuard(policy=AllowlistModelPolicy({"m": [ModelCandidate("gemini-flash")]}), audit_sink=sink)
    marshal_integrations.enable_google(guard, Principal(id="alice"))

    with pytest.raises(google_errors.ClientError) as exc_info:
        Models.__new__(Models).generate_content(model="m", contents="hi")
    assert exc_info.value is real_error

    outcomes = [e for e in sink.tail(5) if e.to_dict()["kind"] == "model_outcome"]
    assert outcomes[0].success is False
    assert outcomes[0].error == "rate_limited"


def test_enable_google_with_scanner_blocks_prompt_before_any_network_call(monkeypatch):
    from google.genai.models import Models

    from marshal_ai.sensitive import SensitiveDataScanner

    calls = []
    monkeypatch.setattr(
        Models, "generate_content", lambda self, **kw: calls.append(kw) or None, raising=True
    )

    sink = InMemoryAuditSink()
    guard = ModelGuard(policy=AllowlistModelPolicy({"m": [ModelCandidate("gemini-flash")]}), audit_sink=sink)
    marshal_integrations.enable_google(guard, Principal(id="alice"), scanner=SensitiveDataScanner())

    with pytest.raises(ModelCallDenied):
        Models.__new__(Models).generate_content(
            model="m", contents="here's my key: sk-ant-abcdefghijklmnopqrstuvwx012345"
        )

    assert calls == []  # blocked before the real call ever happened


def test_enable_google_async_path_substitutes_model_and_reports_usage(monkeypatch):
    import asyncio

    from google.genai.models import AsyncModels

    async def fake_generate_content(self, **kw):
        return FakeGoogleResponse(model_version=kw["model"], usage_metadata=FakeGoogleUsage(4, 2))

    monkeypatch.setattr(AsyncModels, "generate_content", fake_generate_content, raising=True)

    sink = InMemoryAuditSink()
    policy = AllowlistModelPolicy({"gemini-pro": [ModelCandidate("gemini-flash")]})
    guard = ModelGuard(policy=policy, audit_sink=sink)
    marshal_integrations.enable_google(guard, Principal(id="alice"))

    client = AsyncModels.__new__(AsyncModels)
    response = asyncio.run(client.generate_content(model="gemini-pro", contents="hi"))

    assert response.model_version == "gemini-flash"
    usage_entries = [e for e in sink.tail(5) if e.to_dict()["kind"] == "model_usage"]
    assert usage_entries[0].prompt_tokens == 4


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
    assert set(patched) == {"openai", "anthropic", "google"}  # all three installed in this test env


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


def test_enable_openai_async_path_reports_failure_outcome_and_still_reraises(monkeypatch):
    import asyncio

    import httpx
    import openai
    from openai.resources.chat.completions.completions import AsyncCompletions

    req = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    real_error = openai.APITimeoutError(req)

    async def fake_create(self, *args, **kwargs):
        raise real_error

    monkeypatch.setattr(AsyncCompletions, "create", fake_create, raising=True)

    sink = InMemoryAuditSink()
    guard = ModelGuard(policy=AllowlistModelPolicy({"m": [ModelCandidate("real-model")]}), audit_sink=sink)
    marshal_integrations.enable_openai(guard, Principal(id="alice"))

    client = AsyncCompletions.__new__(AsyncCompletions)
    with pytest.raises(openai.APITimeoutError) as exc_info:
        asyncio.run(client.create(model="m", messages=[]))
    assert exc_info.value is real_error

    outcomes = [e for e in sink.tail(5) if e.to_dict()["kind"] == "model_outcome"]
    assert outcomes[0].success is False
    assert outcomes[0].error == "timeout"


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


# --- sensitive-data scanning at the SDK-patch layer -----------------------


def test_enable_openai_with_scanner_blocks_prompt_before_any_network_call(monkeypatch):
    from openai.resources.chat.completions.completions import Completions
    from marshal_ai.sensitive import SensitiveDataScanner

    calls = []
    monkeypatch.setattr(
        Completions, "create", lambda self, **kw: calls.append(kw) or None, raising=True
    )

    sink = InMemoryAuditSink()
    guard = ModelGuard(policy=AllowlistModelPolicy({"m": [ModelCandidate("m")]}), audit_sink=sink)
    marshal_integrations.enable_openai(guard, Principal(id="alice"), scanner=SensitiveDataScanner())

    messages = [{"role": "user", "content": "here is my key AKIAABCDEFGHIJKLMNOP, use it"}]
    with pytest.raises(ModelCallDenied) as exc_info:
        Completions.__new__(Completions).create(model="m", messages=messages)

    assert "sensitive data" in str(exc_info.value).lower()
    assert calls == []  # the real SDK method never ran

    findings_entries = [e for e in sink.tail(5) if e.to_dict()["kind"] == "sensitive_data"]
    assert len(findings_entries) == 1
    assert findings_entries[0].action == "blocked"
    assert findings_entries[0].surface == "model_prompt"


def test_enable_openai_with_scanner_allows_clean_prompt_and_scans_completion(monkeypatch):
    from openai.resources.chat.completions.completions import Completions
    from marshal_ai.sensitive import SensitiveDataScanner

    def fake_create(self, **kw):
        return FakeOpenAIResponse(
            model=kw["model"],
            usage=FakeOpenAIUsage(prompt_tokens=5, completion_tokens=5),
        )

    monkeypatch.setattr(Completions, "create", fake_create, raising=True)

    sink = InMemoryAuditSink()
    guard = ModelGuard(policy=AllowlistModelPolicy({"m": [ModelCandidate("m")]}), audit_sink=sink)
    marshal_integrations.enable_openai(guard, Principal(id="alice"), scanner=SensitiveDataScanner())

    response = Completions.__new__(Completions).create(
        model="m", messages=[{"role": "user", "content": "hello, how are you?"}]
    )
    assert response.model == "m"  # call proceeded normally

    findings_entries = [e for e in sink.tail(5) if e.to_dict()["kind"] == "sensitive_data"]
    assert findings_entries == []  # nothing sensitive anywhere, nothing written


def test_enable_without_scanner_never_scans(monkeypatch):
    from openai.resources.chat.completions.completions import Completions

    monkeypatch.setattr(
        Completions,
        "create",
        lambda self, **kw: FakeOpenAIResponse(model=kw["model"], usage=FakeOpenAIUsage(1, 1)),
        raising=True,
    )

    sink = InMemoryAuditSink()
    guard = ModelGuard(policy=AllowlistModelPolicy({"m": [ModelCandidate("m")]}), audit_sink=sink)
    marshal_integrations.enable_openai(guard, Principal(id="alice"))  # no scanner passed

    # A prompt that would otherwise block, but scanning was never opted into.
    Completions.__new__(Completions).create(
        model="m", messages=[{"role": "user", "content": "key AKIAABCDEFGHIJKLMNOP"}]
    )
    assert [e for e in sink.tail(5) if e.to_dict()["kind"] == "sensitive_data"] == []
