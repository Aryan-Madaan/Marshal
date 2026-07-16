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

Verified against the installed `mcp` SDK (1.28.1) before writing a line
of this module, not assumed from memory:

- `mcp.ClientSession.call_tool(name, arguments=None, read_timeout_seconds=
  None, progress_callback=None, *, meta=None) -> mcp.types.CallToolResult`
  is a coroutine (`mcp/client/session.py`). `CallToolResult` carries
  `content: list[ContentBlock]`, `structuredContent: dict | None`, and
  `isError: bool = False` — the SDK's own shape for "the tool ran and
  failed" (`mcp/types.py`).
- `mcp.ClientSession.list_tools(...) -> mcp.types.ListToolsResult` is
  also a coroutine; listing isn't a call (no arguments, no side effect),
  so it isn't governed here — see `GovernedMCPSession` below.
- `mcp.shared.memory.create_connected_server_and_client_session(server)`
  is the SDK's own in-process client<->server transport — an
  `@asynccontextmanager` that spins up a real `mcp.server.lowlevel.Server`
  (or `mcp.server.fastmcp.FastMCP`) on one end and a real `ClientSession`
  on the other, connected by `anyio` memory object streams, no socket or
  subprocess involved. This is what `tests/test_mcp.py` and
  `examples/mcp_governance_example.py` stand a real server up on, and
  what makes those tests exercise the real SDK's request/response
  machinery rather than a hand-rolled stand-in for it.

Deliberately imports nothing from `mcp` at module scope (only inside a
`TYPE_CHECKING` block, for annotations). `GovernedMCPSession` never
constructs or type-checks a `ClientSession` itself — it only ever awaits
`.call_tool(...)`/`.list_tools(...)` on whatever object it's given and
forwards everything else via `__getattr__` — so `import marshal_ai.mcp`
succeeds with zero dependency on the `mcp` package actually being
installed, matching the rest of `marshal_ai`'s zero required
dependencies (`pyproject.toml`'s `dependencies = []`; `mcp` should be an
optional extra, same as `openai`/`anthropic`/`google-genai` already are)
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
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any, Optional

from marshal_ai.audit import AuditSink, InMemoryAuditSink
from marshal_ai.policy import Principal
from marshal_ai.tools import ApprovalHandler, CLIApprovalHandler, ToolGuard, ToolPolicy

if TYPE_CHECKING:
    from mcp import ClientSession
    from mcp.shared.session import ProgressFnT
    from mcp.types import CallToolResult, ListToolsResult


class GovernedMCPSession:
    """Wraps a real, already-connected `mcp.ClientSession` so every
    `call_tool(name, arguments)` is evaluated by a Marshal `ToolPolicy`
    *before* the underlying `tools/call` request is forwarded to the MCP
    server. A denied or declined call never reaches the server (fail
    closed) and is still audited either way — same discipline `ToolGuard`
    already applies to a bare Python callable.

    One `GovernedMCPSession` is bound to one `principal` at construction,
    unlike `ToolGuard.call(principal, ...)`, which takes a principal per
    call. That's a deliberate difference, not an inconsistency: a real
    MCP client session is already scoped to one connected identity (one
    connection, one set of credentials) the way a bare Python callable
    wrapped by `ToolGuard` structurally is not — so binding the principal
    once, at the point where the session itself was already established,
    matches what a session *is* instead of re-deriving it on every call.

    `risk_tiers` maps MCP tool name -> risk tier (the same tier
    vocabulary `RiskTierPolicy`/`JurisdictionalRiskTierPolicy` already key
    on) — the "tool name -> risk tier comes from policy config" lookup
    that `ToolGuard` itself never had to provide, since it's constructed
    around exactly one already-named tool. A tool absent from `risk_tiers`
    falls back to `default_risk_tier`; either can be overridden per call
    via `call_tool(..., risk_tier=...)` for a one-off exception without
    reconstructing the whole session.

    Only `call_tool` is governed. Every other `ClientSession` method
    (`list_resources`, `read_resource`, `get_prompt`, `initialize`, …)
    passes straight through via `__getattr__` — listing/reading
    capabilities carries no arguments and no side effect on the server,
    so there is nothing here for a `ToolPolicy` to evaluate; `tools/call`
    is MCP's only action surface. This is also why `GovernedMCPSession`
    doesn't reimplement `async with` — wrap an already-`__aenter__`'d
    session (see the module docstring's example, and `tests/test_mcp.py`),
    don't hand it an unopened one.

    Reuses `ToolGuard` itself for the evaluate -> redact -> (approve) ->
    audit -> dispatch sequence — not just its constituent types — despite
    `ToolGuard.call()` being synchronous and `ClientSession.call_tool`
    being a coroutine function. The mechanism: calling a Python
    `async def` function does not run its body, it only ever returns a
    coroutine object — so `ToolGuard(tool=lambda **kw:
    self._session.call_tool(name, kw, ...), ...).call(principal,
    arguments, risk_tier=..., context=...)` runs `ToolGuard.call()`'s
    entire existing code path synchronously and unmodified (evaluate,
    redact, approval, audit), and on the allow/approved path its final
    line, `return self._tool(**arguments)`, merely *constructs* — without
    running — the real `call_tool` coroutine, which `GovernedMCPSession.
    call_tool` then awaits itself. On the deny/declined path,
    `ToolGuard.call()` raises `ToolCallDenied` before ever reaching
    `self._tool(...)` — so the coroutine representing the real request is
    never constructed, let alone sent; nothing to cancel, nothing that
    could accidentally fire. A fresh `ToolGuard` is built per call because
    `tool_name` — and the closure capturing which tool to invoke — varies
    per call, unlike a single long-lived `ToolGuard` wrapping one fixed
    callable; `ToolGuard.__init__` only stores references (no I/O), so
    this adds one cheap object per call, not a second copy of any
    governance logic.
    """

    def __init__(
        self,
        session: "ClientSession",
        principal: Principal,
        policy: Optional[ToolPolicy] = None,
        risk_tiers: Optional[dict[str, str]] = None,
        default_risk_tier: str = "low",
        audit_sink: Optional[AuditSink] = None,
        approval_handler: Optional[ApprovalHandler] = None,
    ) -> None:
        self._session = session
        self._principal = principal
        # Left as None, not defaulted to AllowAllTools() here — the
        # per-call ToolGuard built in call_tool already applies that
        # exact default itself; resolving it twice would just be two
        # copies of the same one-line fallback.
        self._policy = policy
        self._risk_tiers = dict(risk_tiers) if risk_tiers else {}
        self._default_risk_tier = default_risk_tier
        # Same "None -> the library's own default type" resolution every
        # other guard already does (ToolGuard/ModelGuard/RetrievalGuard) —
        # resolved once here, then handed unchanged to every per-call
        # ToolGuard built in call_tool, so all of them (and this session)
        # share one audit_sink/approval_handler instance.
        self._audit_sink = audit_sink if audit_sink is not None else InMemoryAuditSink()
        self._approval_handler = (
            approval_handler if approval_handler is not None else CLIApprovalHandler()
        )

    @property
    def audit_log(self) -> AuditSink:
        return self._audit_sink

    @property
    def principal(self) -> Principal:
        return self._principal

    def __getattr__(self, item: str) -> Any:
        # Transparent passthrough for every ClientSession method except
        # call_tool (governed explicitly below) — see the class docstring.
        # Only reached when normal attribute lookup on this object misses.
        return getattr(self._session, item)

    async def list_tools(self, *args: Any, **kwargs: Any) -> "ListToolsResult":
        """Ungoverned passthrough to `ClientSession.list_tools` — spelled
        out explicitly (rather than left to `__getattr__`) only so it
        shows up in this class's own public surface next to `call_tool`;
        behavior is identical to letting `__getattr__` forward it."""
        return await self._session.list_tools(*args, **kwargs)

    async def call_tool(
        self,
        name: str,
        arguments: Optional[dict[str, Any]] = None,
        read_timeout_seconds: "timedelta | None" = None,
        progress_callback: "ProgressFnT | None" = None,
        *,
        meta: Optional[dict[str, Any]] = None,
        risk_tier: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> "CallToolResult":
        """Evaluate policy, redact for the audit trail, get approval if
        required, log the outcome, and — only if allowed — forward the
        real `tools/call` request to the connected MCP server.

        `name`, `arguments`, `read_timeout_seconds`, `progress_callback`,
        and `meta` mirror `ClientSession.call_tool`'s own signature
        exactly (verified against the installed SDK), so a caller
        migrating from a raw `ClientSession` to a `GovernedMCPSession`
        doesn't need to change how it calls `call_tool` at all — only
        `risk_tier` and `context` are new, both keyword-only so they
        can't collide with a positional call written against the real
        SDK's signature. `risk_tier` overrides this call's entry in the
        `risk_tiers` map passed at construction (and `default_risk_tier`)
        for this one call. `context` reaches jurisdiction-aware policies
        exactly the way `ToolGuard.call(..., context=...)`'s does.

        Raises `ToolCallDenied` if the policy denies outright, or a
        required approval is declined — the real server is never reached
        in either case. See the module docstring for why this raises
        instead of returning an `isError=True` CallToolResult.
        """
        arguments = dict(arguments) if arguments else {}
        tier = risk_tier if risk_tier is not None else self._risk_tiers.get(name, self._default_risk_tier)

        guard = ToolGuard(
            tool=lambda **kw: self._session.call_tool(
                name, kw, read_timeout_seconds, progress_callback, meta=meta
            ),
            policy=self._policy,
            audit_sink=self._audit_sink,
            approval_handler=self._approval_handler,
            tool_name=name,
        )
        # Synchronous all the way through (evaluate/redact/approve/audit);
        # on allow/approved this *constructs* (doesn't run) the real
        # call_tool coroutine via the lambda above — see the class
        # docstring. On deny/declined, ToolGuard.call raises ToolCallDenied
        # before the lambda is ever invoked, so no coroutine exists to await.
        pending_call = guard.call(self._principal, arguments, risk_tier=tier, context=context)
        return await pending_call
