"""Governs a real MCP `ClientSession`'s tool calls the same way `ToolGuard`
governs a raw Python callable — risk-tiered allow/deny/require-approval,
argument redaction, rate limiting, runaway-loop detection, and
jurisdiction-aware oversight (`marshal_ai.tools.ToolPolicy` and everything
that composes with it), evaluated *before* a `tools/call` request ever
reaches the real MCP server.

Why this module exists, stated plainly: MCP (Model Context Protocol) is
now the shared tool-integration standard most agent frameworks speak.
Its Enterprise-Managed Authorization spec governs whether a client may
*connect* to a server at all — it explicitly does not govern individual
tool actions at runtime (per-call, per-argument decisions). That gap is
exactly what `ToolGuard` already does for a bare Python callable; this
module is the same governance applied at MCP's own choke point, so one
`GovernedMCPSession` covers an agent's tool use across every framework
that talks to that server over MCP, the same way
`marshal_ai.integrations.enable()` is one choke point for model calls
across every framework built on the openai/anthropic/google-genai SDKs.

    import asyncio
    from marshal_ai import Principal, RiskTierPolicy
    from marshal_ai.mcp import GovernedMCPSession

    async def main():
        # `session` is a real, already-connected mcp.ClientSession —
        # however your client normally obtains one (stdio, SSE,
        # streamable HTTP, or the SDK's in-memory transport for tests).
        governed = GovernedMCPSession(
            session=session,
            principal=Principal(id="agent-1"),
            policy=RiskTierPolicy({"low": "allow", "high": "deny"}),
            risk_tiers={"delete_database": "high", "read_file": "low"},
        )
        result = await governed.call_tool("read_file", {"path": "README.md"})
        # a call to "delete_database" raises ToolCallDenied instead —
        # the real server never sees that request.

Verified against the installed `mcp` SDK (2.3.0, protocol revision
2026-07-28) before writing a line of this module, not assumed from memory:

- mcp 2 has two client shapes, and `GovernedMCPSession` wraps either:
  the high-level `mcp.Client` (which negotiates the protocol, retries
  multi-round-trip `input_required` results itself, and connects
  in-process to an `MCPServer` for tests) and the lower-level
  `mcp.ClientSession` (`client.session`). Both expose `call_tool(name,
  arguments=None, read_timeout_seconds=None, progress_callback=None, *,
  ...)` and `list_tools(...)` as coroutines; the keyword-only tail
  differs between them and between SDK releases (`input_responses`,
  `request_state`, `meta`, `allow_input_required`, ...), so every
  argument after `arguments` is forwarded verbatim rather than mirrored.
- `CallToolResult` carries `content`, `structured_content`, and
  `is_error` (mcp 2 renamed the 1.x camelCase fields). `Tool` carries
  `name`, `title`, `description`, `input_schema`, `output_schema`, and
  `annotations` — what `tool_fingerprint` hashes.
- The 2026-07-28 revision removed the `initialize` handshake and
  sessions; nothing here depended on either. Multi round-trip requests
  re-send `tools/call` with `input_responses`: through `mcp.Client` that
  retry loop happens inside one governed `call_tool`; driving it yourself
  on a raw `ClientSession` governs each round as its own call (fail
  closed — a policy is never skipped because a request claims to be a
  continuation).

Deliberately imports nothing from `mcp` at module scope (only inside a
`TYPE_CHECKING` block, for annotations). `GovernedMCPSession` never
constructs or type-checks a `ClientSession` itself — it only ever awaits
`.call_tool(...)`/`.list_tools(...)` on whatever object it's given and
forwards everything else via `__getattr__` — so `import marshal_ai.mcp`
succeeds with zero dependency on the `mcp` package actually being
installed, matching the rest of `marshal_ai`'s zero required
dependencies (`pyproject.toml`'s `dependencies = []`; `mcp` is an
optional extra, same as `openai`/`anthropic`/`google-genai`)
and the same lazy-import discipline `marshal_ai.integrations` already
uses (it imports `openai`/`anthropic`/`google.genai` inside each
`enable_*` function, never at that module's top). Constructing a *real*
governed session obviously still needs a real `ClientSession` to wrap —
that's on the caller, exactly like `ToolGuard(tool=...)` never imports
whatever library the wrapped callable happens to come from.

Deny-surface decision — `GovernedMCPSession.call_tool` raises
`ToolCallDenied` on a governance denial or a declined approval; it does
not return an `isError=True` CallToolResult. This mirrors every other
Marshal guard (`ToolGuard.call`, `ModelGuard.resolve` both raise their
own `*Denied` type rather than returning a sentinel) instead of reusing
MCP's own `isError` shape, which already means something different in
the spec: the tool *ran* and failed. Collapsing "governance blocked this
before the server ever saw it" into the same shape as "the tool executed
and errored" would erase a distinction Marshal already insists on
elsewhere for the identical reason — see `CircuitBreakerPolicy`'s own
rule that a governance denial is never recorded as a call failure
(`DESIGN_DECISIONS.md`). A framework loop that specifically wants
`isError` results instead of exceptions can catch `ToolCallDenied` at its
own boundary and translate it in one line; that's a one-directional,
caller-side choice, not something worth baking into Marshal's own
denial semantics. `ToolCallDenied` is re-exported from `marshal_ai.tools`
(and top-level `marshal_ai`) already — nothing new to import here.

Tool-definition pinning (`MCPToolPins`) — the defense against MCP "rug
pulls" (a server changing a tool's description or schema after it was
reviewed, so the model reads new, attacker-written instructions) and
tool shadowing (a second server registering a tool name that another
server already provides). `tool_fingerprint` is a SHA-256 over the
canonical JSON of everything a model reads about a tool. Pass a shared
`MCPToolPins` to every `GovernedMCPSession` and give each one a stable
`server_id`: the first time a tool is seen it's pinned (trust on first
use, or `on_new="deny"` to require pre-approved pins); afterwards a
changed definition is hidden from `list_tools()` and refused by
`call_tool()` until someone calls `pins.approve(...)`, and a name already
pinned under a different server is treated the same way. Stated limit:
pinning catches a definition that *changes*; it cannot tell you a
definition was malicious the first time you saw it — review new tools
before pinning them, which is what `on_new="deny"` is for.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Literal, Optional

from marshal_ai.audit import AuditSink, InMemoryAuditSink, register_entry_type
from marshal_ai.policy import GuardMode, Principal
from marshal_ai.tools import (
    _snapshot,
    ApprovalHandler,
    CLIApprovalHandler,
    ToolCallRequest,
    ToolDecision,
    ToolGuard,
    ToolPolicy,
)

if TYPE_CHECKING:
    from mcp.types import CallToolResult, ListToolsResult

    from marshal_ai.flow import FlowTracker


# The fields a model actually reads about a tool. `meta`/`icons`/
# `execution` are transport/UI details, not instructions to the model.
_FINGERPRINT_FIELDS = ("name", "title", "description", "input_schema", "output_schema", "annotations")


def _tool_field(tool: Any, name: str) -> Any:
    if isinstance(tool, dict):
        return tool.get(name)
    value = getattr(tool, name, None)
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", exclude_none=True)
    return value


def tool_fingerprint(tool: Any) -> str:
    """SHA-256 (hex) over the canonical JSON of a tool's model-visible
    definition: name, title, description, input/output schema, and
    annotations. Works on an `mcp.types.Tool` or a plain dict."""
    payload = {name: _tool_field(tool, name) for name in _FINGERPRINT_FIELDS}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


PinStatus = Literal["verified", "pinned_new", "changed", "unpinned", "shadowed"]


@dataclass(frozen=True)
class PinCheck:
    status: PinStatus
    expected: Optional[str]  # the pinned fingerprint, if any
    actual: str
    shadowed_server: Optional[str] = None

    @property
    def blocked(self) -> bool:
        return self.status in ("changed", "unpinned", "shadowed")


class MCPToolPins:
    """Pinned tool fingerprints, keyed by server id then tool name.
    Thread-safe; persisted to `path` (JSON, written atomically) when one
    is given, so pins survive restarts and can be committed and reviewed
    like any other policy file.

    `on_new` — what happens the first time a tool is seen: `"pin"` (trust
    on first use; the default) or `"deny"` (only pre-approved pins pass).
    `on_shadowed` — a tool name already pinned under a *different* server:
    `"deny"` (the default) or `"allow"`.
    """

    def __init__(
        self,
        path: "str | Path | None" = None,
        on_new: Literal["pin", "deny"] = "pin",
        on_shadowed: Literal["deny", "allow"] = "deny",
    ) -> None:
        if on_new not in ("pin", "deny"):
            raise ValueError("on_new must be 'pin' or 'deny'")
        if on_shadowed not in ("deny", "allow"):
            raise ValueError("on_shadowed must be 'deny' or 'allow'")
        self._path = Path(path) if path is not None else None
        self._on_new = on_new
        self._on_shadowed = on_shadowed
        self._lock = threading.Lock()
        self._pins: dict[str, dict[str, str]] = {}
        if self._path is not None and self._path.exists():
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or not all(
                isinstance(tools, dict) and all(isinstance(v, str) for v in tools.values())
                for tools in raw.values()
            ):
                raise ValueError(f"{self._path}: expected {{server_id: {{tool_name: fingerprint}}}}")
            self._pins = {server: dict(tools) for server, tools in raw.items()}

    def pins(self) -> dict[str, dict[str, str]]:
        with self._lock:
            return {server: dict(tools) for server, tools in self._pins.items()}

    def _save_locked(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._path.parent, prefix=".pins-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._pins, f, indent=2, sort_keys=True)
            os.replace(tmp, self._path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def approve(self, server_id: str, tool_name: str, fingerprint: str) -> None:
        """Pin (or re-pin, after reviewing a changed definition) a tool —
        the explicit human step a changed definition requires."""
        with self._lock:
            self._pins.setdefault(server_id, {})[tool_name] = fingerprint
            self._save_locked()

    def revoke(self, server_id: str, tool_name: str) -> None:
        with self._lock:
            self._pins.get(server_id, {}).pop(tool_name, None)
            self._save_locked()

    def check(self, server_id: str, tool: Any) -> PinCheck:
        return self.check_fingerprint(server_id, _tool_field(tool, "name"), tool_fingerprint(tool))

    def check_fingerprint(self, server_id: str, name: str, actual: str) -> PinCheck:
        """Pin check for any reviewed definition, not just MCP tools — e.g.
        an A2A agent card (`marshal_ai.integrations.a2a`). Same rules as
        `check`. Use a separate `MCPToolPins` (its own file) per kind of
        definition, so names from one can't look like shadowing in another."""
        with self._lock:
            expected = self._pins.get(server_id, {}).get(name)
            if expected is None:
                # Shadow check only for a tool this server has no pin for:
                # a name a human explicitly approved on two servers via
                # approve() is a reviewed decision, not shadowing.
                if self._on_shadowed == "deny":
                    for other, tools in self._pins.items():
                        if other != server_id and name in tools:
                            return PinCheck("shadowed", None, actual, shadowed_server=other)
                if self._on_new == "deny":
                    return PinCheck("unpinned", None, actual)
                self._pins.setdefault(server_id, {})[name] = actual
                self._save_locked()
                return PinCheck("pinned_new", None, actual)
            if expected != actual:
                return PinCheck("changed", expected, actual)
            return PinCheck("verified", expected, actual)


@dataclass(frozen=True)
class MCPToolDefinitionEntry:
    """A tool definition that was newly pinned, or refused because it
    changed, was never approved, or shadows another server's tool.
    Fingerprints are truncated to 16 hex characters — enough to tell
    definitions apart in a review, without the log becoming a lookup
    table. Verified (unchanged) tools aren't logged on every listing."""

    timestamp: float
    principal_id: str
    server_id: str
    tool_name: str
    status: str  # PinStatus
    action: str  # "pinned" | "hidden" | "audited_only"
    expected_fingerprint: Optional[str] = None
    actual_fingerprint: Optional[str] = None
    shadowed_server: Optional[str] = None
    shadow: bool = False
    on_behalf_of: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "mcp_tool_definition", **asdict(self)}


register_entry_type("mcp_tool_definition", MCPToolDefinitionEntry)


class _DefinitionGate(ToolPolicy):
    """Puts a definition-check verdict in front of the real policy, so a
    refused tool goes through `ToolGuard`'s ordinary deny path (one audit
    shape, shadow mode honored) rather than a separate code path."""

    def __init__(self, base: Optional[ToolPolicy], blocked_reason: Optional[str]) -> None:
        from marshal_ai.tools import AllowAllTools

        self._base = base if base is not None else AllowAllTools()
        self._blocked_reason = blocked_reason

    def evaluate(self, request: ToolCallRequest) -> ToolDecision:
        if self._blocked_reason is not None:
            return ToolDecision("deny", self._blocked_reason)
        return self._base.evaluate(request)

    def redact_arguments(self, request: ToolCallRequest) -> dict[str, Any]:
        return self._base.redact_arguments(request)


def _blocked_reason(check: PinCheck) -> str:
    if check.status == "changed":
        return (
            f"tool definition changed since it was pinned ({check.expected[:16]} -> "
            f"{check.actual[:16]}) — re-approve it with MCPToolPins.approve() after review"
        )
    if check.status == "shadowed":
        return f"tool name is already provided by MCP server {check.shadowed_server!r} (tool shadowing)"
    return "tool definition is not pinned and this session only allows pre-approved tools"


def _annotations_dict(tool: Any) -> dict[str, Any]:
    value = _tool_field(tool, "annotations")
    return dict(value) if isinstance(value, dict) else {}


class GovernedMCPSession:
    """Wraps a real, already-connected `mcp.Client` or `mcp.ClientSession`
    so every `call_tool(name, arguments)` is evaluated by a Marshal
    `ToolPolicy` *before* the underlying `tools/call` request is forwarded
    to the MCP server. A denied or declined call never reaches the server
    (fail closed) and is still audited either way — same discipline
    `ToolGuard` already applies to a bare Python callable.

    One `GovernedMCPSession` is bound to one `principal` at construction
    (use `Principal(..., on_behalf_of=...)` for an agent acting for a
    user), because a real MCP connection is already scoped to one
    identity. `risk_tiers` maps MCP tool name -> risk tier (the same
    vocabulary `RiskTierPolicy` keys on); a tool absent from it falls back
    to `default_risk_tier`, and either can be overridden per call via
    `call_tool(..., risk_tier=...)`.

    `server_id` names this server in the audit trail and in `tool_pins`.
    Every call's `context` also carries `mcp_server` and the tool's
    `mcp_annotations` (when the tool has been listed), so policies such as
    `marshal_ai.flow.LethalTrifectaPolicy` can use them.

    Outcomes: every call that runs is reported to the policy's
    `record_outcome` — a raised exception, or a result with `is_error`
    set, is a failure — so `ToolCircuitBreakerPolicy` and
    `RunawayAgentPolicy(failed_call_threshold=...)` see a broken server.
    `audit_outcomes=True` also writes a `ToolOutcomeEntry` per call.

    Resources: with a `flow_tracker`, `read_resource(uri)` labels the
    session — `default_resource_labels` (`{"untrusted_content"}`: text an
    MCP server hands back is attacker-writable unless you know otherwise),
    or the labels of the longest matching prefix in `resource_labels`
    (e.g. `{"crm://": {"private_data"}}`). The flow-label entry names the
    server, never the URI, which can itself carry sensitive identifiers.

    `list_tools()` is governed only when `tool_pins` is given (see the
    module docstring): tools whose definitions fail the pin check are
    removed from the listing, so the model never reads a changed
    description. Every other method (`list_resources`, `read_resource`,
    `get_prompt`, …) passes straight through via `__getattr__`.
    `mode="shadow"` audits every decision — policy and pin checks alike —
    without hiding or refusing anything.

    Reuses `ToolGuard.authorize()` for the evaluate -> redact -> (approve)
    -> audit sequence, then awaits the real request only once that
    returns; on deny/declined it raises `ToolCallDenied` before the
    request coroutine is ever created.
    """

    def __init__(
        self,
        session: Any,
        principal: Principal,
        policy: Optional[ToolPolicy] = None,
        risk_tiers: Optional[dict[str, str]] = None,
        default_risk_tier: str = "low",
        audit_sink: Optional[AuditSink] = None,
        approval_handler: Optional[ApprovalHandler] = None,
        server_id: str = "mcp",
        tool_pins: Optional[MCPToolPins] = None,
        mode: GuardMode = "enforce",
        audit_outcomes: bool = False,
        flow_tracker: Optional["FlowTracker"] = None,
        resource_labels: Optional[dict[str, Iterable[str]]] = None,
        default_resource_labels: Iterable[str] = ("untrusted_content",),
    ) -> None:
        self._session = session
        self._principal = principal
        # Left as None, not defaulted to AllowAllTools() here — the
        # per-call ToolGuard applies that default itself.
        self._policy = policy
        self._risk_tiers = dict(risk_tiers) if risk_tiers else {}
        self._default_risk_tier = default_risk_tier
        self._audit_sink = audit_sink if audit_sink is not None else InMemoryAuditSink()
        self._approval_handler = (
            approval_handler if approval_handler is not None else CLIApprovalHandler()
        )
        self._server_id = server_id
        self._tool_pins = tool_pins
        self._mode = mode
        self._audit_outcomes = audit_outcomes
        self._flow_tracker = flow_tracker
        # Longest prefix wins, so "file:///public/" can override "file:///".
        self._resource_labels = sorted(
            ((prefix, frozenset(labels)) for prefix, labels in (resource_labels or {}).items()),
            key=lambda item: len(item[0]),
            reverse=True,
        )
        self._default_resource_labels = frozenset(default_resource_labels)
        # tool name -> PinCheck from the most recent listing, and
        # annotations for context. Only meaningful when tool_pins is set.
        self._checks: dict[str, PinCheck] = {}
        self._annotations: dict[str, dict[str, Any]] = {}

    @property
    def audit_log(self) -> AuditSink:
        return self._audit_sink

    @property
    def principal(self) -> Principal:
        return self._principal

    @property
    def server_id(self) -> str:
        return self._server_id

    def __getattr__(self, item: str) -> Any:
        # Transparent passthrough for every client method except the two
        # governed below. Only reached when normal lookup misses.
        return getattr(self._session, item)

    def _audit_definition(self, tool_name: str, check: PinCheck, action: str) -> None:
        self._audit_sink.write(
            MCPToolDefinitionEntry(
                timestamp=time.time(),
                principal_id=self._principal.id,
                server_id=self._server_id,
                tool_name=tool_name,
                status=check.status,
                action=action,
                expected_fingerprint=check.expected[:16] if check.expected else None,
                actual_fingerprint=check.actual[:16],
                shadowed_server=check.shadowed_server,
                shadow=self._mode == "shadow",
                on_behalf_of=self._principal.delegation_chain,
            )
        )

    async def list_tools(self, *args: Any, **kwargs: Any) -> "ListToolsResult":
        """Forward to the client's `list_tools`. With `tool_pins`, check
        every returned definition against its pin and drop any that fail
        (enforce mode), auditing each newly pinned or refused tool."""
        result = await self._session.list_tools(*args, **kwargs)
        tools = list(getattr(result, "tools", None) or [])
        for tool in tools:
            name = _tool_field(tool, "name")
            self._annotations[name] = _annotations_dict(tool)
        if self._tool_pins is None:
            return result

        kept = []
        for tool in tools:
            name = _tool_field(tool, "name")
            check = self._tool_pins.check(self._server_id, tool)
            self._checks[name] = check
            if check.status == "pinned_new":
                self._audit_definition(name, check, "pinned")
            elif check.blocked:
                self._audit_definition(name, check, "audited_only" if self._mode == "shadow" else "hidden")
            if not check.blocked or self._mode == "shadow":
                kept.append(tool)
        if len(kept) == len(tools):
            return result
        if hasattr(result, "model_copy"):
            return result.model_copy(update={"tools": kept})
        result.tools = kept
        return result

    async def _list_all_tools(self) -> None:
        cursor: Optional[str] = None
        seen: set[Optional[str]] = set()
        while True:
            result = await self.list_tools(cursor=cursor) if cursor else await self.list_tools()
            cursor = getattr(result, "next_cursor", None)
            if not cursor or cursor in seen:
                return
            seen.add(cursor)

    async def call_tool(
        self,
        name: str,
        arguments: Optional[dict[str, Any]] = None,
        *args: Any,
        risk_tier: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
        **kwargs: Any,
    ) -> "CallToolResult":
        """Evaluate policy, redact for the audit trail, get approval if
        required, log the outcome, and — only if allowed — forward the
        real `tools/call` request to the connected MCP server.

        Everything after `arguments` (timeouts, progress callbacks,
        `meta`, `input_responses`, ...) is forwarded verbatim to the
        wrapped client's own `call_tool`, so swapping a raw client for a
        `GovernedMCPSession` needs no call-site changes. Only `risk_tier`
        and `context` are new, both keyword-only.

        Raises `ToolCallDenied` if the policy denies outright, a required
        approval is declined, or (with `tool_pins`) the tool's definition
        failed its pin check. With `tool_pins`, a tool not yet seen in this
        session is listed first, so a tool can't be called around the
        check by never listing it.
        """
        # Snapshot once: the dict evaluated and approved is the one sent.
        arguments = _snapshot(arguments) if arguments else {}
        tier = risk_tier if risk_tier is not None else self._risk_tiers.get(name, self._default_risk_tier)

        blocked_reason: Optional[str] = None
        if self._tool_pins is not None:
            if name not in self._checks:
                await self._list_all_tools()
            check = self._checks.get(name)
            if check is None:
                blocked_reason = "tool is not offered by this MCP server's tool listing"
            elif check.blocked:
                blocked_reason = _blocked_reason(check)

        call_context = {
            **(context or {}),
            "mcp_server": self._server_id,
            "mcp_annotations": self._annotations.get(name, {}),
        }
        guard = ToolGuard(
            policy=_DefinitionGate(self._policy, blocked_reason),
            audit_sink=self._audit_sink,
            approval_handler=self._approval_handler,
            tool_name=name,
            mode=self._mode,
            mcp_server=self._server_id,
            audit_outcomes=self._audit_outcomes,
        )
        guard.authorize(self._principal, arguments, risk_tier=tier, context=call_context)
        start = time.monotonic()
        try:
            result = await self._session.call_tool(name, arguments, *args, **kwargs)
        except Exception as exc:
            guard.record_outcome(
                self._principal, arguments, False, (time.monotonic() - start) * 1000,
                type(exc).__name__, tier, call_context,
            )
            raise
        failed = bool(getattr(result, "is_error", False))
        guard.record_outcome(
            self._principal, arguments, not failed, (time.monotonic() - start) * 1000,
            "tool_error" if failed else None, tier, call_context,
        )
        return result

    async def read_resource(self, uri: Any, *args: Any, **kwargs: Any) -> Any:
        """Forward to the client's `read_resource`, first labeling the
        session in `flow_tracker` (if one was given) — see the class
        docstring."""
        if self._flow_tracker is not None:
            text = str(uri)
            labels = next(
                (labels for prefix, labels in self._resource_labels if text.startswith(prefix)),
                self._default_resource_labels,
            )
            if labels:
                self._flow_tracker.add(self._principal, labels, f"mcp_resource:{self._server_id}")
        return await self._session.read_resource(uri, *args, **kwargs)
