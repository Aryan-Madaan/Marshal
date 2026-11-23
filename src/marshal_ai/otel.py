"""OpenTelemetry export for the Marshal audit trail.

Requires the `opentelemetry` extra (`pip install "marshal-ai[opentelemetry]"`)
— this module is not imported by `marshal_ai/__init__.py`, so the base
library never forces the OTel SDK on anyone who doesn't want it.

Informed decision on "where's the dashboard": Marshal doesn't ship one, and
deliberately won't build a bespoke web UI. Piping audit entries into
OpenTelemetry means they show up in whatever your org already runs —
Grafana, Honeycomb, Datadog, a local Jaeger — for the cost of a couple of
attribute-mapping functions, instead of maintaining a second, worse
dashboard forever. See `marshal_ai.cli` for the zero-infra local answer
(a terminal viewer) that covers the "just let me see it right now" case
without needing a collector running anywhere.
"""

from __future__ import annotations

from typing import Any, Optional

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from marshal_ai.audit import AuditableEvent, AuditSink

_DEFAULT_TRACER = trace.get_tracer("marshal_ai")


class OpenTelemetryAuditSink(AuditSink):
    """Emits every audit entry as an OpenTelemetry span instead of storing
    it locally. Write-only: `all_entries`/`tail`/`query` raise
    NotImplementedError, since spans live in your tracing backend, not in
    this process. Combine with a second `AuditSink` (write to both) if you
    also want local queryability — Marshal doesn't provide a fan-out sink
    itself; it's a five-line `AuditSink` subclass if you need one.

    Attribute naming follows the OpenTelemetry GenAI semantic conventions
    (verified against `opentelemetry-semantic-conventions` 0.66b2) wherever
    one exists, with Marshal's own `marshal.*` attributes alongside:

    - Tool calls are `execute_tool {tool}` spans carrying
      `gen_ai.operation.name="execute_tool"` and `gen_ai.tool.name`; calls
      made through `GovernedMCPSession` add `mcp.method.name="tools/call"`
      (the MCP semconv names tools with `gen_ai.tool.name`, not an
      `mcp.*` attribute).
    - Model routing/usage spans use `gen_ai.request.model` and
      `gen_ai.usage.*`.
    - Delegation: when the actor acts `on_behalf_of` someone, `user.id` is
      the subject and `gen_ai.agent.id` the acting principal.

    The GenAI and MCP conventions are still in Development status, so the
    `marshal.*` attributes (the pre-v0.13 names) are kept, unchanged, for
    anything already built on them. Retrieval, flow-label, egress and
    MCP tool-definition spans have no semconv equivalent and stay
    `marshal.{kind}`.
    """

    def __init__(self, tracer: Optional[trace.Tracer] = None) -> None:
        self._tracer = tracer if tracer is not None else _DEFAULT_TRACER

    def write(self, entry: AuditableEvent) -> None:
        data = entry.to_dict()
        kind = data.get("kind", "unknown")
        if kind == "tool_call":
            span_name = f"execute_tool {data.get('tool_name', '')}".strip()
        else:
            span_name = f"marshal.{kind}"
        with self._tracer.start_as_current_span(span_name) as span:
            span.set_attribute("marshal.principal_id", entry.principal_id)
            if data.get("run_id"):
                span.set_attribute("marshal.run_id", data["run_id"])
            if data.get("parent_run_id"):
                span.set_attribute("marshal.parent_run_id", data["parent_run_id"])
            chain = data.get("on_behalf_of") or []
            if chain:
                span.set_attribute("marshal.on_behalf_of", list(chain))
                span.set_attribute("user.id", chain[-1])
                span.set_attribute("gen_ai.agent.id", entry.principal_id)
            handler = self._HANDLERS.get(kind)
            if handler is not None:
                handler(self, span, data)
            else:
                # Unknown/future event kind (e.g. a custom AuditableEvent a
                # user registered) — still export something rather than
                # silently dropping it.
                for key, value in data.items():
                    if key not in ("kind", "principal_id", "on_behalf_of", "run_id", "parent_run_id") and _is_span_attr_safe(value):
                        span.set_attribute(f"marshal.{key}", value)

    def _write_retrieval(self, span: trace.Span, data: dict[str, Any]) -> None:
        span.set_attribute("marshal.retrieval.query", data["query"])
        span.set_attribute("marshal.retrieval.candidates_seen", data["candidates_seen"])
        span.set_attribute("marshal.retrieval.allowed_count", len(data["allowed_ids"]))
        span.set_attribute("marshal.retrieval.denied_count", len(data["denied_ids"]))
        if data["denied_ids"]:
            span.set_status(Status(StatusCode.ERROR, "one or more documents denied"))

    def _write_tool_call(self, span: trace.Span, data: dict[str, Any]) -> None:
        span.set_attribute("gen_ai.operation.name", "execute_tool")
        span.set_attribute("gen_ai.tool.name", data["tool_name"])
        if data.get("mcp_server"):
            span.set_attribute("mcp.method.name", "tools/call")
            span.set_attribute("marshal.mcp.server", data["mcp_server"])
        if data.get("shadow"):
            span.set_attribute("marshal.shadow", True)
        span.set_attribute("marshal.tool.name", data["tool_name"])
        span.set_attribute("marshal.tool.risk_tier", data["risk_tier"])
        span.set_attribute("marshal.tool.outcome", data["outcome"])
        span.set_attribute("marshal.tool.reason", data["reason"])
        if data.get("approved_by"):
            span.set_attribute("marshal.tool.approved_by", data["approved_by"])
        if data["outcome"] in ("deny", "declined"):
            span.set_status(Status(StatusCode.ERROR, data["reason"]))

    def _write_model_call(self, span: trace.Span, data: dict[str, Any]) -> None:
        span.set_attribute("gen_ai.request.model", data["logical_name"])
        if data.get("resolved_model"):
            span.set_attribute("marshal.model.resolved", data["resolved_model"])
        span.set_attribute("marshal.model.outcome", data["outcome"])
        span.set_attribute("marshal.model.reason", data["reason"])
        if data["outcome"] == "deny":
            span.set_status(Status(StatusCode.ERROR, data["reason"]))

    def _write_model_usage(self, span: trace.Span, data: dict[str, Any]) -> None:
        span.set_attribute("gen_ai.request.model", data["model"])
        span.set_attribute("gen_ai.usage.input_tokens", data["prompt_tokens"])
        span.set_attribute("gen_ai.usage.output_tokens", data["completion_tokens"])

    def _write_sensitive_data(self, span: trace.Span, data: dict[str, Any]) -> None:
        span.set_attribute("marshal.sensitive.surface", data["surface"])
        span.set_attribute("marshal.sensitive.location", data["location"])
        span.set_attribute("marshal.sensitive.findings", data["findings"])
        span.set_attribute("marshal.sensitive.action", data["action"])
        if data["action"] == "blocked":
            span.set_status(Status(StatusCode.ERROR, "sensitive data detected"))

    def _write_egress(self, span: trace.Span, data: dict[str, Any]) -> None:
        span.set_attribute("marshal.egress.surface", data["surface"])
        span.set_attribute("marshal.egress.location", data["location"])
        span.set_attribute("marshal.egress.hosts", data["hosts"])
        span.set_attribute("marshal.egress.action", data["action"])
        if data["action"] == "blocked":
            span.set_status(Status(StatusCode.ERROR, "egress to non-allowlisted host"))

    def _write_mcp_tool_definition(self, span: trace.Span, data: dict[str, Any]) -> None:
        span.set_attribute("gen_ai.tool.name", data["tool_name"])
        span.set_attribute("marshal.mcp.server", data["server_id"])
        span.set_attribute("marshal.mcp.pin_status", data["status"])
        span.set_attribute("marshal.mcp.action", data["action"])
        if data["action"] == "hidden":
            span.set_status(Status(StatusCode.ERROR, f"MCP tool definition {data['status']}"))

    _HANDLERS = {
        "retrieval": _write_retrieval,
        "tool_call": _write_tool_call,
        "model_call": _write_model_call,
        "model_usage": _write_model_usage,
        "sensitive_data": _write_sensitive_data,
        "egress": _write_egress,
        "mcp_tool_definition": _write_mcp_tool_definition,
    }


def _is_span_attr_safe(value: Any) -> bool:
    if isinstance(value, (str, bool, int, float)):
        return True
    if isinstance(value, (list, tuple)):
        return all(isinstance(v, (str, bool, int, float)) for v in value)
    return False
