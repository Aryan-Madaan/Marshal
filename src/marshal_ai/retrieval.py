from __future__ import annotations

import inspect
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from marshal_ai.audit import AuditEntry, AuditSink, InMemoryAuditSink
from marshal_ai.policy import AllowAll, GuardMode, Policy, Principal


@dataclass
class Document:
    """The minimal shape RetrievalGuard needs from a retrieved chunk. Wrap
    whatever your vector store returns into this — it doesn't depend on
    LangChain, LlamaIndex, or any specific backend."""

    id: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    score: Optional[float] = None


# A retriever is `(query, k) -> Iterable[Document]`. It may optionally also
# accept a `filter` keyword — see `_accepts_filter` — to receive a native
# pushdown filter from the policy (e.g. a Chroma `where` clause) instead of
# RetrievalGuard always fetching everything and filtering after the fact.
Retriever = Callable[..., Iterable[Document]]
AsyncRetriever = Callable[..., Any]  # returns an awaitable[Iterable[Document]]


def _accepts_filter(retriever: Callable[..., Any]) -> bool:
    try:
        params = inspect.signature(retriever).parameters
    except (TypeError, ValueError):
        return False
    if "filter" in params:
        return True
    return any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())


def _redacted_document_fields(original: Document, redacted: Document) -> list[str]:
    """Which fields differ between `original` and its `Policy.redact()`ed
    counterpart — field names only, never the values. Used by shadow mode
    to audit *what a redaction rule would have hidden* without actually
    hiding it; diffing the two documents works against any `Policy`
    subclass's `redact()` output without that policy needing to
    self-report what it changed.
    """
    changed: list[str] = []
    if redacted.content != original.content:
        changed.append("content")
    for key, value in original.metadata.items():
        if redacted.metadata.get(key) != value:
            changed.append(key)
    return changed


class RetrievalGuard:
    """Wraps a retriever with access control and an audit trail — the
    retrieval-governance surface of Marshal.

    Works with zero configuration: you get an audit log for free even if
    you never touch the policy. Access control only starts actually
    filtering once documents carry metadata your policy understands — see
    `marshal_ai.policy.AttributePolicy` / `GroupPolicy`.

    `mode="enforce"` (the default) is today's behavior unchanged: denied
    documents are filtered out, allowed ones are redacted per the policy.
    `mode="shadow"` computes and audits the identical policy decision for
    every candidate but returns them all, unfiltered and unredacted —
    the low-friction adoption path: run Marshal against real traffic and
    see what it *would* have filtered/redacted before ever risking it
    actually filtering something a caller needed.
    """

    def __init__(
        self,
        retriever: Retriever,
        policy: Optional[Policy] = None,
        audit_sink: Optional[AuditSink] = None,
        mode: GuardMode = "enforce",
    ) -> None:
        self._retriever = retriever
        # Deliberately `is None`, not `or` — an empty InMemoryAuditSink()
        # defines __len__ and is falsy when empty, so `audit_sink or
        # InMemoryAuditSink()` would silently discard a caller-provided
        # sink the moment it had zero entries.
        self._policy = policy if policy is not None else AllowAll()
        self._audit_sink = audit_sink if audit_sink is not None else InMemoryAuditSink()
        self._retriever_accepts_filter = _accepts_filter(retriever)
        self._mode = mode

    @property
    def audit_log(self) -> AuditSink:
        return self._audit_sink

    def _call_retriever(self, query: str, k: int, pushdown_filter: Optional[dict[str, Any]]):
        if self._retriever_accepts_filter:
            return self._retriever(query, k, filter=pushdown_filter)
        return self._retriever(query, k)

    def _process(
        self, query: str, principal: Principal, candidates: Iterable[Document]
    ) -> list[Document]:
        candidates = list(candidates)
        shadow = self._mode == "shadow"
        allowed_ids: list[str] = []
        denied_ids: list[str] = []
        denied_reasons: dict[str, str] = {}
        would_redact_fields: dict[str, list[str]] = {}
        enforced_results: list[Document] = []

        for doc in candidates:
            decision = self._policy.evaluate(principal, doc.metadata)
            if decision.allowed:
                allowed_ids.append(doc.id)
                redacted_doc = self._policy.redact(principal, doc)
                if shadow:
                    changed = _redacted_document_fields(doc, redacted_doc)
                    if changed:
                        would_redact_fields[doc.id] = changed
                else:
                    enforced_results.append(redacted_doc)
            else:
                denied_ids.append(doc.id)
                denied_reasons[doc.id] = decision.reason

        self._audit_sink.write(
            AuditEntry(
                timestamp=time.time(),
                principal_id=principal.id,
                query=query,
                candidates_seen=len(candidates),
                allowed_ids=allowed_ids,
                denied_ids=denied_ids,
                denied_reasons=denied_reasons,
                shadow=shadow,
                would_redact_fields=would_redact_fields,
            )
        )

        # Shadow mode never filters or redacts what the caller gets back —
        # every candidate passes through exactly as the retriever returned
        # it, in the same order. `allowed_ids`/`denied_ids` above still
        # record the real decision, just never acted on.
        return candidates if shadow else enforced_results

    def retrieve(self, query: str, principal: Principal, k: int = 5) -> list[Document]:
        """Fetch candidates from the wrapped retriever, filter and redact
        them per-principal, and log the outcome.

        If the policy can express itself as a native filter (see
        `Policy.to_filter`) and the retriever accepts a `filter` keyword,
        that filter is pushed down into the retrieval call itself —
        RetrievalGuard still re-checks every candidate afterward (defense
        in depth: a pushdown filter is an optimization, not a substitute
        for enforcement, in case the backend's filtering has gaps).
        """
        pushdown_filter = self._policy.to_filter(principal)
        candidates = self._call_retriever(query, k, pushdown_filter)
        return self._process(query, principal, candidates)

    async def aretrieve(self, query: str, principal: Principal, k: int = 5) -> list[Document]:
        """Async counterpart to `retrieve`. Works with either an async
        retriever (awaited directly) or a plain sync one (called inline —
        fine for local/in-memory retrievers; wrap a blocking sync client
        yourself with `asyncio.to_thread` if it does real I/O)."""
        pushdown_filter = self._policy.to_filter(principal)
        result = self._call_retriever(query, k, pushdown_filter)
        if inspect.isawaitable(result):
            candidates = await result
        else:
            candidates = result
        return self._process(query, principal, candidates)
