import json

import httpx
import pytest

import marshal_ai.integrations as marshal_integrations
from marshal_ai import (
    AllowlistModelPolicy,
    BudgetPolicy,
    InMemoryAuditSink,
    ModelCallDenied,
    ModelCandidate,
    ModelGuard,
    ModelRateLimitPolicy,
    ModelRunawayPolicy,
    Principal,
)

ROUTES = AllowlistModelPolicy({"chat": [ModelCandidate("gpt-real")]})
ALICE = Principal("alice")


@pytest.fixture(autouse=True)
def cleanup_patches():
    yield
    marshal_integrations.disable_all()


def test_model_rate_limit_denies_past_the_limit_per_principal():
    guard = ModelGuard(policy=ModelRateLimitPolicy(ROUTES, max_calls=2, window_seconds=60))
    guard.resolve(ALICE, "chat")
    guard.resolve(ALICE, "chat")
    with pytest.raises(ModelCallDenied, match="rate limit"):
        guard.resolve(ALICE, "chat")
    assert guard.resolve(Principal("bob"), "chat") == "gpt-real"


def test_model_runaway_trips_on_identical_prompts_only_and_needs_a_reset():
    policy = ModelRunawayPolicy(ROUTES, identical_call_threshold=3, window_seconds=60)
    guard = ModelGuard(policy=policy)
    for turn in range(5):  # a growing conversation: every prompt differs
        guard.resolve(ALICE, "chat", {"prompt_fingerprint": f"turn-{turn}"})
    for _ in range(2):
        guard.resolve(ALICE, "chat", {"prompt_fingerprint": "stuck"})
    with pytest.raises(ModelCallDenied, match="runaway"):
        guard.resolve(ALICE, "chat", {"prompt_fingerprint": "stuck"})
    with pytest.raises(ModelCallDenied, match="reset"):
        guard.resolve(ALICE, "chat", {"prompt_fingerprint": "something new"})
    policy.reset("alice")
    assert guard.resolve(ALICE, "chat", {"prompt_fingerprint": "something new"}) == "gpt-real"


def test_calls_without_a_fingerprint_are_never_identical():
    guard = ModelGuard(policy=ModelRunawayPolicy(ROUTES, identical_call_threshold=2, window_seconds=60))
    for _ in range(10):
        guard.resolve(ALICE, "chat")


def test_budget_estimates_refuse_a_call_that_would_overshoot():
    policy = BudgetPolicy(ROUTES, pricing={"gpt-real": (1.0, 2.0)}, limit_usd=1.0, enforce_estimates=True)
    guard = ModelGuard(policy=policy)
    # 100 prompt tokens + 200 output tokens = $0.10 + $0.40 — fits
    guard.resolve(ALICE, "chat", {"estimated_prompt_tokens": 100, "max_output_tokens": 200})
    policy.record_usage(ALICE, "gpt-real", prompt_tokens=100, completion_tokens=300)  # $0.70 spent
    with pytest.raises(ModelCallDenied, match="estimated cost"):
        guard.resolve(ALICE, "chat", {"estimated_prompt_tokens": 100, "max_output_tokens": 200})
    # without an estimate, only the after-the-fact check applies
    assert guard.resolve(ALICE, "chat") == "gpt-real"


def test_budget_estimates_are_opt_in():
    policy = BudgetPolicy(ROUTES, pricing={"gpt-real": (1.0, 2.0)}, limit_usd=0.01)
    assert ModelGuard(policy=policy).resolve(ALICE, "chat", {"max_output_tokens": 100_000}) == "gpt-real"


def _openai_client():
    import openai

    body = {
        "id": "c1", "object": "chat.completion", "created": 0, "model": "gpt-real",
        "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
    }
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=body))
    return openai.OpenAI(api_key="sk-test", http_client=httpx.Client(transport=transport))


def test_integrations_fill_in_fingerprint_and_estimates_for_real_sdk_calls():
    seen = {}

    from marshal_ai import ModelDecision, ModelPolicy

    class Capture(ModelPolicy):
        def resolve(self, request):
            seen.update(request.context)
            return ModelDecision("allow", "gpt-real", "ok")

    marshal_integrations.enable_openai(ModelGuard(policy=Capture()), ALICE)
    _openai_client().chat.completions.create(
        model="chat", max_tokens=256, messages=[{"role": "user", "content": "x" * 400}]
    )
    assert seen["estimated_prompt_tokens"] == 100 and seen["max_output_tokens"] == 256
    assert len(seen["prompt_fingerprint"]) == 64
    assert "x" * 400 not in json.dumps(seen)  # never the prompt itself


def test_a_real_sdk_retry_loop_trips_the_runaway_breaker():
    sink = InMemoryAuditSink()
    guard = ModelGuard(policy=ModelRunawayPolicy(ROUTES, identical_call_threshold=3, window_seconds=60), audit_sink=sink)
    marshal_integrations.enable_openai(guard, ALICE)
    client = _openai_client()
    messages = [{"role": "user", "content": "summarize the report"}]
    client.chat.completions.create(model="chat", messages=messages)
    client.chat.completions.create(model="chat", messages=messages)
    with pytest.raises(ModelCallDenied, match="runaway"):
        client.chat.completions.create(model="chat", messages=messages)
