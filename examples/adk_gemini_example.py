"""Governing Google ADK's default model path specifically.

ADK's `LlmAgent` calls Gemini through `google-genai`'s `Models.
generate_content` directly when you pass a plain model string (e.g.
`Agent(model="gemini-flash-latest")`) — verified against ADK's own
source, not assumed. It does *not* go through LiteLLM or the
openai/anthropic clients unless you explicitly wrap the model in
`google.adk.models.lite_llm.LiteLlm(...)`. That means the same
`enable()` call already governs both ADK's native Gemini path and its
LiteLLM-routed path (LiteLLM itself calls the real openai/anthropic SDK
client classes under the hood — also verified, not assumed) — one call,
whichever path an ADK agent actually takes.

This example calls `google.genai` directly rather than going through ADK
itself, to keep the dependency footprint to just `google-genai` — an ADK
agent configured with `model="gemini-flash-latest"` makes the exact same
underlying call this example makes.

Only exercises the DENY path, deliberately, so it runs with no API key
and no network call — a real ALLOW path looks identical, it just also
makes the real request with whatever model `guard.resolve()` returned.

Run: python examples/adk_gemini_example.py
"""

import marshal_ai.integrations as marshal_integrations
from marshal_ai import AllowlistModelPolicy, InMemoryAuditSink, ModelCandidate, ModelGuard, Principal
from marshal_ai.models import ModelCallDenied

# Only "gemini-flash-latest" is an approved route for "gemini-pro-latest"
# requests — anything asking for a model with no configured route gets
# denied before any network call happens.
policy = AllowlistModelPolicy({"gemini-pro-latest": [ModelCandidate("gemini-flash-latest")]})
audit = InMemoryAuditSink()
guard = ModelGuard(policy=policy, audit_sink=audit)

patched = marshal_integrations.enable(guard, Principal(id="adk-agent-service-account"))
print(f"patched SDKs: {patched}")

# From here on, ANY code that calls google.genai.Client().models.generate_content(...)
# is governed — including an ADK LlmAgent's internal call, since it's the
# exact same client class and method.
from google import genai  # noqa: E402  (import after enable() is intentional, matches real usage)

client = genai.Client(api_key="not-a-real-key")

try:
    client.models.generate_content(model="gemini-2.5-pro", contents="hi")
except ModelCallDenied as e:
    print(f"blocked before any network call: {e}")

print("\naudit trail (no network call happened, but the attempt is logged):")
for entry in audit.tail(1):
    print(f"  {entry.principal_id}: {entry.outcome} — {entry.reason}")

marshal_integrations.disable_all()
