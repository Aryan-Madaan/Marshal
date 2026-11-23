"""Pseudonymous audit trails: identities out of the log, accountability in.

    from marshal_ai.privacy import PseudonymizingAuditSink

    sink = PseudonymizingAuditSink(SQLiteAuditSink("audit.db"), key=load_key_from_vault())
    guard = ToolGuard(tool=..., audit_sink=sink)
    ...
    sink.query_principal("alice@company.com")   # the key holder can still ask

Principal ids are often personal data (an email, an employee number), and
an audit trail is long-lived, widely read and exported. This sink
replaces every identity field — `principal_id`, the `on_behalf_of`
delegation chain, and an incident's `affected_principals` — with a keyed
pseudonym (`"p-" + HMAC-SHA256(key, id)[:16 bytes]`) *before* the entry
reaches the wrapped sink, so the stored trail (and any copy of it) never
contains the raw id.

The mapping is deterministic, so every analysis still works — per-agent
counts, delegation queries, runaway detection over the log — and the key
holder can recompute a pseudonym to look someone up (`pseudonym_for`,
`query_principal`). It is one-way for everyone else: unlike a lookup
table, there is nothing to steal that maps pseudonyms back. Keep the key
in a secrets manager; rotating it starts a new pseudonym space.

Stated limit: this protects identifiers, not content. Free-text fields a
policy writes (a reason that quotes a value, a retrieval query) are
stored as-is; Marshal's own reasons avoid identities, but a custom
policy's may not.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import fields, is_dataclass, replace
from typing import Any, Optional

from marshal_ai.audit import AuditableEvent, AuditSink

_IDENTITY_FIELDS = ("principal_id",)
_IDENTITY_LIST_FIELDS = ("on_behalf_of", "affected_principals")


class PseudonymizingAuditSink(AuditSink):
    def __init__(self, inner: AuditSink, key: bytes, prefix: str = "p-") -> None:
        if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
            raise ValueError("key must be at least 16 random bytes (e.g. os.urandom(32))")
        self._inner = inner
        self._key = bytes(key)
        self._prefix = prefix

    @property
    def inner(self) -> AuditSink:
        return self._inner

    def pseudonym_for(self, identity: str) -> str:
        digest = hmac.new(self._key, identity.encode("utf-8"), hashlib.sha256).hexdigest()
        return self._prefix + digest[:32]

    def _pseudonymize(self, entry: AuditableEvent) -> AuditableEvent:
        if not is_dataclass(entry):
            raise TypeError(
                f"{type(entry).__name__} is not a dataclass; PseudonymizingAuditSink can only rewrite "
                "dataclass entries — refusing to store it with raw identities"
            )
        names = {f.name for f in fields(entry)}
        changes: dict[str, Any] = {}
        for name in _IDENTITY_FIELDS:
            value = getattr(entry, name, None) if name in names else None
            if isinstance(value, str) and value and not value.startswith(self._prefix):
                changes[name] = self.pseudonym_for(value)
        for name in _IDENTITY_LIST_FIELDS:
            value = getattr(entry, name, None) if name in names else None
            if value:
                changes[name] = [self.pseudonym_for(v) if isinstance(v, str) else v for v in value]
        return replace(entry, **changes) if changes else entry

    def write(self, entry: AuditableEvent) -> None:
        self._inner.write(self._pseudonymize(entry))

    def all_entries(self) -> list[AuditableEvent]:
        return self._inner.all_entries()

    def query(
        self,
        *,
        principal_id: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        denied_only: bool = False,
        on_behalf_of: Optional[str] = None,
    ) -> list[AuditableEvent]:
        """Same as the wrapped sink's `query`; pass pseudonyms (or use
        `query_principal`) — stored entries only contain pseudonyms."""
        return self._inner.query(
            principal_id=principal_id, since=since, until=until, denied_only=denied_only, on_behalf_of=on_behalf_of
        )

    def query_principal(self, identity: str, **kwargs: Any) -> list[AuditableEvent]:
        """Everything a real identity did — as actor — for the key holder."""
        return self.query(principal_id=self.pseudonym_for(identity), **kwargs)

    def query_on_behalf_of(self, identity: str, **kwargs: Any) -> list[AuditableEvent]:
        """Everything done for a real identity via delegation."""
        return self.query(on_behalf_of=self.pseudonym_for(identity), **kwargs)

    def verify(self, *args: Any, **kwargs: Any) -> Any:
        """Forward hash-chain verification to the wrapped sink (if it has one)."""
        return self._inner.verify(*args, **kwargs)  # type: ignore[attr-defined]

    def anchor(self) -> Any:
        return self._inner.anchor()  # type: ignore[attr-defined]
