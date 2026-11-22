"""Cross-surface information-flow control: the "lethal trifecta" gate.

The attack this closes is the one behind most real agent data leaks of
2025-2026 (EchoLeak, the GitHub MCP "toxic flow", the Supabase MCP leak):
an agent that, within one session, (1) has access to private data, (2)
reads untrusted content an attacker can write, and (3) can communicate
externally, can be steered by instructions hidden in (2) into sending (1)
out through (3). Simon Willison named the combination the lethal
trifecta; Meta's "Agents Rule of Two" states the same rule as policy —
never let one session hold all three.

No individual call in such an attack looks wrong. The tool call that
leaks data is often a perfectly ordinary `send_email` or `fetch_url` —
what makes it dangerous is what the session already touched. That's why
this has to be tracked *across* calls and *across* surfaces, and why it
fits Marshal specifically: Marshal already sits on both the retrieval
side (where private data and untrusted documents enter) and the tool side
(where data leaves).

Deterministic by design. There is no classifier here deciding whether
content "looks like" a prompt injection — adaptive attacks reliably beat
those ("The Attacker Moves Second", USENIX Security 2026). Instead, each
source declares what it is (a document's `flow_labels` metadata, a tool's
declared capabilities) and the gate refuses or escalates the one call
that would complete the forbidden combination, whatever the content says.

    from marshal_ai import FlowTracker, FlowLabelingPolicy, LethalTrifectaPolicy

    tracker = FlowTracker(audit_sink=sink)
    retrieval = RetrievalGuard(
        retriever,
        policy=FlowLabelingPolicy(AttributePolicy(), tracker, default_labels={"private_data"}),
        audit_sink=sink,
    )
    tools = LethalTrifectaPolicy(
        RiskTierPolicy({"low": "allow"}),
        tracker,
        tool_capabilities={
            "fetch_url": {"untrusted_content"},
            "send_email": {"external_communication"},
        },
    )

Sessions are keyed by the principal's id plus its delegation chain by
default, so give each agent session its own principal id (e.g.
`"agent-7/session-42"`), or pass `session_key=` to choose the key
yourself. Call `tracker.reset(principal)` when a session genuinely ends.
"""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Iterable, Literal, Optional

from marshal_ai.audit import AuditSink, register_entry_type
from marshal_ai.policy import Policy, PolicyDecision, Principal
from marshal_ai.tools import ToolCallRequest, ToolDecision, ToolPolicy

if TYPE_CHECKING:
    from marshal_ai.retrieval import Document

PRIVATE_DATA = "private_data"
UNTRUSTED_CONTENT = "untrusted_content"
EXTERNAL_COMMUNICATION = "external_communication"
LETHAL_TRIFECTA: frozenset[str] = frozenset({PRIVATE_DATA, UNTRUSTED_CONTENT, EXTERNAL_COMMUNICATION})


def default_session_key(principal: Principal) -> str:
    return "/".join([principal.id, *principal.delegation_chain])


@dataclass(frozen=True)
class FlowLabelEntry:
    """A session gained one or more flow labels. `labels_added` is what's
    new; `labels_now` is everything the session holds after this event.
    `source` names where it came from — `"retrieval:<doc id>"` or
    `"tool:<tool name>"` — never content."""

    timestamp: float
    principal_id: str
    session: str
    source: str
    labels_added: list[str]
    labels_now: list[str]
    on_behalf_of: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "flow_label", **asdict(self)}


register_entry_type("flow_label", FlowLabelEntry)


class FlowTracker:
    """Which flow labels each session has accumulated. Thread-safe and
    in-process; labels only ever accumulate until `reset()`, so a session
    can never "forget" it read untrusted content."""

    def __init__(
        self,
        audit_sink: Optional[AuditSink] = None,
        session_key: Callable[[Principal], str] = default_session_key,
    ) -> None:
        self._audit_sink = audit_sink
        self._session_key = session_key
        self._labels: dict[str, frozenset[str]] = {}
        self._lock = threading.Lock()

    def session_of(self, principal: Principal) -> str:
        return self._session_key(principal)

    def labels(self, principal: Principal) -> frozenset[str]:
        with self._lock:
            return self._labels.get(self._session_key(principal), frozenset())

    def add(self, principal: Principal, labels: Iterable[str], source: str) -> frozenset[str]:
        """Record `labels` for this principal's session; returns the labels
        that were new. Audits a `FlowLabelEntry` only when something new
        was added, so repeated reads of the same kind of source stay quiet."""
        key = self._session_key(principal)
        with self._lock:
            before = self._labels.get(key, frozenset())
            after = before | frozenset(labels)
            self._labels[key] = after
        added = after - before
        if added and self._audit_sink is not None:
            self._audit_sink.write(
                FlowLabelEntry(
                    timestamp=time.time(),
                    principal_id=principal.id,
                    session=key,
                    source=source,
                    labels_added=sorted(added),
                    labels_now=sorted(after),
                    on_behalf_of=principal.delegation_chain,
                )
            )
        return added

    def reset(self, principal: Principal) -> None:
        with self._lock:
            self._labels.pop(self._session_key(principal), None)


def _as_labels(value: Any) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        return frozenset({value})
    if isinstance(value, Iterable):
        return frozenset(v for v in value if isinstance(v, str))
    return frozenset()


class FlowLabelingPolicy(Policy):
    """Wraps a retrieval `Policy`, keeping its decisions unchanged, and
    records the flow labels of every document actually returned to the
    principal: whatever is in `metadata[labels_field]` (a string or list,
    e.g. `["untrusted_content"]` for a scraped web page or a customer-
    submitted ticket) plus `default_labels` (e.g. `{"private_data"}` for
    an internal knowledge base). Denied documents never label the session
    — the principal never saw them."""

    def __init__(
        self,
        base: Policy,
        tracker: FlowTracker,
        labels_field: str = "flow_labels",
        default_labels: Iterable[str] = (),
    ) -> None:
        self._base = base
        self._tracker = tracker
        self._labels_field = labels_field
        self._default_labels = frozenset(default_labels)

    def evaluate(self, principal: Principal, metadata: dict[str, Any]) -> PolicyDecision:
        return self._base.evaluate(principal, metadata)

    def to_filter(self, principal: Principal) -> Optional[dict[str, Any]]:
        return self._base.to_filter(principal)

    def redact(self, principal: Principal, document: "Document") -> "Document":
        # Labels come from the original metadata, before the base policy's
        # redaction could replace the label field with "[REDACTED]".
        labels = _as_labels(document.metadata.get(self._labels_field)) | self._default_labels
        if labels:
            self._tracker.add(principal, labels, f"retrieval:{document.id}")
        return self._base.redact(principal, document)


_SEVERITY = {"allow": 0, "require_approval": 1, "deny": 2}


class LethalTrifectaPolicy(ToolPolicy):
    """Wraps a `ToolPolicy`. Before a tool call, takes the labels the
    session already holds plus the capabilities this tool would add; if
    together they complete `forbidden` (default: the lethal trifecta), the
    call is escalated to `on_violation` — `"require_approval"` (the
    default) or `"deny"`. Strictly monotonic, like
    `JurisdictionalRiskTierPolicy`: it can only tighten the base decision,
    never loosen it. A tool that adds none of the forbidden capabilities
    is never gated, however tainted the session is.

    `tool_capabilities` maps tool name -> the labels calling it adds (what
    it reads or where it sends). Tools not listed get
    `default_capabilities` — set that to e.g. `{"external_communication"}`
    to fail closed on tools nobody has classified yet.

    `use_mcp_annotations` — for calls through `GovernedMCPSession`, a tool
    whose MCP annotations explicitly set `openWorldHint: true` also gets
    `untrusted_content` and `external_communication`. Annotations come
    from the server, so they are only ever used to *add* capabilities,
    never to remove declared ones; an absent hint adds nothing.

    A call that isn't denied records its capabilities into the session
    immediately — before an approval is answered. That's the conservative
    direction: a declined call can only over-taint a session, never
    under-taint it.
    """

    def __init__(
        self,
        base: ToolPolicy,
        tracker: FlowTracker,
        tool_capabilities: Optional[dict[str, Iterable[str]]] = None,
        default_capabilities: Iterable[str] = (),
        forbidden: Iterable[str] = LETHAL_TRIFECTA,
        on_violation: Literal["require_approval", "deny"] = "require_approval",
        use_mcp_annotations: bool = True,
    ) -> None:
        if on_violation not in ("require_approval", "deny"):
            raise ValueError("on_violation must be 'require_approval' or 'deny'")
        self._base = base
        self._tracker = tracker
        self._capabilities = {name: frozenset(caps) for name, caps in (tool_capabilities or {}).items()}
        self._default = frozenset(default_capabilities)
        self._forbidden = frozenset(forbidden)
        if not self._forbidden:
            raise ValueError("forbidden must name at least one label")
        self._on_violation = on_violation
        self._use_mcp_annotations = use_mcp_annotations

    def capabilities_of(self, request: ToolCallRequest) -> frozenset[str]:
        caps = self._capabilities.get(request.tool_name, self._default)
        if self._use_mcp_annotations:
            annotations = request.context.get("mcp_annotations") or {}
            if annotations.get("open_world_hint") is True or annotations.get("openWorldHint") is True:
                caps = caps | {UNTRUSTED_CONTENT, EXTERNAL_COMMUNICATION}
        return caps

    def evaluate(self, request: ToolCallRequest) -> ToolDecision:
        decision = self._base.evaluate(request)
        if decision.outcome == "deny":
            return decision

        caps = self.capabilities_of(request)
        held = self._tracker.labels(request.principal)
        if caps & self._forbidden and self._forbidden <= (held | caps):
            if _SEVERITY[self._on_violation] > _SEVERITY.get(decision.outcome, 2):
                decision = ToolDecision(
                    self._on_violation,
                    f"lethal trifecta: session already holds {sorted(held & self._forbidden)}; "
                    f"{request.tool_name!r} would add {sorted(caps & self._forbidden - held)}",
                )
        if decision.outcome != "deny" and caps:
            self._tracker.add(request.principal, caps, f"tool:{request.tool_name}")
        return decision

    def redact_arguments(self, request: ToolCallRequest) -> dict[str, Any]:
        return self._base.redact_arguments(request)
