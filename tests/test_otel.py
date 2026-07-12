import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from marshal_ai.models import AllowAllModels, AllowlistModelPolicy, ModelCandidate, ModelGuard
from marshal_ai.otel import OpenTelemetryAuditSink
from marshal_ai.policy import AttributePolicy, Principal
from marshal_ai.retrieval import Document, RetrievalGuard
from marshal_ai.tools import AutoApprove, RiskTierPolicy, ToolCallDenied, ToolGuard


@pytest.fixture
def otel_sink():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("marshal_ai.tests")
    return OpenTelemetryAuditSink(tracer=tracer), exporter


def test_retrieval_span_has_expected_attributes(otel_sink):
    sink, exporter = otel_sink
    docs = [
        Document(id="1", content="public", metadata={}),
        Document(id="2", content="hr-only", metadata={"acl": ["role:hr"]}),
    ]
    guard = RetrievalGuard(
        retriever=lambda q, k: docs[:k],
        policy=AttributePolicy(default="allow"),
        audit_sink=sink,
    )
    engineer = Principal(id="bob", attributes={"role:engineering"})

    guard.retrieve("q", principal=engineer, k=2)

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.name == "marshal.retrieval"
    attrs = dict(span.attributes)
    assert attrs["marshal.principal_id"] == "bob"
    assert attrs["marshal.retrieval.query"] == "q"
    assert attrs["marshal.retrieval.candidates_seen"] == 2
    assert attrs["marshal.retrieval.allowed_count"] == 1
    assert attrs["marshal.retrieval.denied_count"] == 1
    assert span.status.status_code == StatusCode.ERROR


def test_retrieval_span_ok_status_when_nothing_denied(otel_sink):
    sink, exporter = otel_sink
    guard = RetrievalGuard(retriever=lambda q, k: [Document(id="1", content="a")], audit_sink=sink)

    guard.retrieve("q", principal=Principal(id="alice"), k=1)

    span = exporter.get_finished_spans()[0]
    assert span.status.status_code != StatusCode.ERROR


def test_tool_call_span_records_approval(otel_sink):
    sink, exporter = otel_sink
    policy = RiskTierPolicy({"medium": "require_approval"})
    guard = ToolGuard(
        tool=lambda **kw: "ok",
        policy=policy,
        audit_sink=sink,
        approval_handler=AutoApprove(True),
        tool_name="delete_record",
    )

    guard.call(Principal(id="alice"), {}, risk_tier="medium")

    span = exporter.get_finished_spans()[0]
    assert span.name == "marshal.tool_call"
    attrs = dict(span.attributes)
    assert attrs["marshal.tool.name"] == "delete_record"
    assert attrs["marshal.tool.outcome"] == "approved"
    assert attrs["marshal.tool.approved_by"] == "auto-approve"
    assert span.status.status_code != StatusCode.ERROR


def test_tool_call_span_error_status_on_deny(otel_sink):
    sink, exporter = otel_sink
    guard = ToolGuard(
        tool=lambda **kw: "ok",
        policy=RiskTierPolicy({"high": "deny"}),
        audit_sink=sink,
    )

    with pytest.raises(ToolCallDenied):
        guard.call(Principal(id="alice"), {}, risk_tier="high")

    span = exporter.get_finished_spans()[0]
    assert span.status.status_code == StatusCode.ERROR


def test_model_call_span_uses_gen_ai_semantic_convention(otel_sink):
    sink, exporter = otel_sink
    policy = AllowlistModelPolicy({"default-chat-model": [ModelCandidate("gpt-fast")]})
    guard = ModelGuard(policy=policy, audit_sink=sink)

    guard.resolve(Principal(id="alice"), "default-chat-model")

    span = exporter.get_finished_spans()[0]
    assert span.name == "marshal.model_call"
    attrs = dict(span.attributes)
    assert attrs["gen_ai.request.model"] == "default-chat-model"
    assert attrs["marshal.model.resolved"] == "gpt-fast"


def test_model_usage_span_uses_gen_ai_usage_attributes(otel_sink):
    sink, exporter = otel_sink
    guard = ModelGuard(policy=AllowAllModels(), audit_sink=sink)

    guard.record_usage(Principal(id="alice"), "gpt-fast", prompt_tokens=100, completion_tokens=50)

    span = exporter.get_finished_spans()[0]
    assert span.name == "marshal.model_usage"
    attrs = dict(span.attributes)
    assert attrs["gen_ai.request.model"] == "gpt-fast"
    assert attrs["gen_ai.usage.input_tokens"] == 100
    assert attrs["gen_ai.usage.output_tokens"] == 50


def test_reads_are_not_supported_since_spans_live_in_the_backend(otel_sink):
    sink, _ = otel_sink
    with pytest.raises(NotImplementedError):
        sink.all_entries()
    with pytest.raises(NotImplementedError):
        sink.tail()
    with pytest.raises(NotImplementedError):
        sink.query()


def test_sensitive_data_span_error_status_on_block(otel_sink):
    sink, exporter = otel_sink
    from marshal_ai.sensitive import SensitiveDataToolPolicy
    from marshal_ai.tools import AllowAllTools

    policy = SensitiveDataToolPolicy(base=AllowAllTools(), audit_sink=sink)
    guard = ToolGuard(tool=lambda **kw: "ok", policy=policy, audit_sink=sink, tool_name="save_note")

    with pytest.raises(ToolCallDenied):
        guard.call(Principal(id="alice"), {"note": "AKIAABCDEFGHIJKLMNOP"})

    spans = exporter.get_finished_spans()
    sensitive_span = next(s for s in spans if s.name == "marshal.sensitive_data")
    attrs = dict(sensitive_span.attributes)
    assert attrs["marshal.sensitive.action"] == "blocked"
    assert sensitive_span.status.status_code == StatusCode.ERROR


def test_sensitive_data_span_ok_status_on_redact(otel_sink):
    sink, exporter = otel_sink
    from marshal_ai.sensitive import SensitiveDataPolicy

    policy = SensitiveDataPolicy(base=AttributePolicy(default="allow"), audit_sink=sink)
    guard = RetrievalGuard(
        retriever=lambda q, k: [Document(id="1", content="reach bob@example.com")],
        policy=policy,
        audit_sink=sink,
    )

    guard.retrieve("q", principal=Principal(id="alice"), k=1)

    spans = exporter.get_finished_spans()
    sensitive_span = next(s for s in spans if s.name == "marshal.sensitive_data")
    assert sensitive_span.status.status_code != StatusCode.ERROR


def test_unified_trail_across_all_three_guards_produces_three_spans(otel_sink):
    sink, exporter = otel_sink
    alice = Principal(id="alice")

    RetrievalGuard(retriever=lambda q, k: [], audit_sink=sink).retrieve("q", principal=alice, k=1)
    ToolGuard(tool=lambda **kw: None, audit_sink=sink).call(alice, {})
    ModelGuard(policy=AllowAllModels(), audit_sink=sink).resolve(alice, "m")

    names = {s.name for s in exporter.get_finished_spans()}
    assert names == {"marshal.retrieval", "marshal.tool_call", "marshal.model_call"}
