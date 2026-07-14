"""One-line model governance for *any* framework built on the OpenAI,
Anthropic, or Google GenAI SDKs — LangChain, LangGraph, CrewAI, AutoGen,
or a raw script. `enable()` patches the SDK client classes directly, so
code you didn't write (inside a framework) gets governed transparently.
See `examples/adk_gemini_example.py` for the Google ADK case specifically
— ADK's default `LlmAgent` path calls Gemini through `google-genai`
directly, which is exactly what this patches.

This example only exercises the DENY path, deliberately, so it runs with
no API key and no network call — a real ALLOW path looks identical from
the framework's point of view, it just also makes the real request with
whatever model `guard.resolve()` returned.

Run: python examples/framework_integration_example.py
"""

import marshal_ai.integrations as marshal_integrations
from marshal_ai import AllowlistModelPolicy, InMemoryAuditSink, ModelCandidate, ModelGuard, Principal
from marshal_ai.models import ModelCallDenied

# Only "gpt-4o-mini" is an approved route for "gpt-4o" requests — anything
# asking for a model with no configured route (like "gpt-4-turbo" below)
# gets denied before any network call happens.
policy = AllowlistModelPolicy({"gpt-4o": [ModelCandidate("gpt-4o-mini")]})
audit = InMemoryAuditSink()
guard = ModelGuard(policy=policy, audit_sink=audit)

patched = marshal_integrations.enable(guard, Principal(id="ci-service-account"))
print(f"patched SDKs: {patched}")

# From here on, ANY code — including inside a framework — that calls
# openai.OpenAI().chat.completions.create(model=..., ...) is governed.
import openai  # noqa: E402  (import after enable() is intentional, matches real usage)

client = openai.OpenAI(api_key="not-a-real-key")

try:
    client.chat.completions.create(model="gpt-4-turbo", messages=[{"role": "user", "content": "hi"}])
except ModelCallDenied as e:
    print(f"blocked before any network call: {e}")

print("\naudit trail (no network call happened, but the attempt is logged):")
for entry in audit.tail(1):
    print(f"  {entry.principal_id}: {entry.outcome} — {entry.reason}")

marshal_integrations.disable_all()
