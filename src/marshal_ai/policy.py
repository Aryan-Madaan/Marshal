from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Iterable, Optional

if TYPE_CHECKING:
    from marshal_ai.retrieval import Document


@dataclass(frozen=True)
class Principal:
    """Whoever is making the retrieval call. `attributes` is a flat set of
    strings — roles, departments, clearance levels, whatever your policy
    matches against (e.g. {"role:hr", "dept:finance"})."""

    id: str
    attributes: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        # Accept a plain list/set/tuple and normalize it, since callers
        # shouldn't have to know frozenset is the internal representation.
        object.__setattr__(self, "attributes", frozenset(self.attributes))


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


class Policy(ABC):
    """Decides whether a principal may see a given document. Implement
    this to back access control with your own system (an IAM lookup, a DB
    query, an OPA call) instead of the metadata-matching default."""

    @abstractmethod
    def evaluate(self, principal: Principal, metadata: dict[str, Any]) -> PolicyDecision: ...

    def redact(self, principal: Principal, document: "Document") -> "Document":
        """Called on every document the principal is *allowed* to see,
        before it's returned. Default: return it unchanged. Override (or
        wrap with `RedactingPolicy`) to strip specific fields — e.g. a
        principal can see that a document exists without seeing every
        field in it.
        """
        return document

    def to_filter(self, principal: Principal) -> Optional[dict[str, Any]]:
        """Optionally express this policy's access rule as a native
        filter the underlying store can push down into the query itself
        (e.g. a Chroma/Pinecone/pgvector `where` clause), instead of
        RetrievalGuard fetching everything and filtering after the fact.

        Return None (the default) if this policy has no native
        representation — RetrievalGuard falls back to post-filtering, which
        always works but fetches candidates the principal may not end up
        being allowed to see.
        """
        return None


class AttributePolicy(Policy):
    """Default policy: allow or deny based on an ACL list in document
    metadata.

    Convention: ``metadata["acl"]`` is a list of attribute strings. A
    document is visible to a principal if the two sets overlap. Documents
    with no ACL key fall back to `default`:

    - "allow" (the default) — wrapping an existing, unannotated retriever
      doesn't silently break it. Access control only starts biting once you
      annotate documents with an ACL.
    - "deny" — fail closed. Use once your index is actually annotated and
      you want anything unlabeled treated as sensitive by default.
    """

    def __init__(self, default: str = "allow", acl_field: str = "acl") -> None:
        if default not in ("allow", "deny"):
            raise ValueError('default must be "allow" or "deny"')
        self._default_allow = default == "allow"
        self._acl_field = acl_field

    def evaluate(self, principal: Principal, metadata: dict[str, Any]) -> PolicyDecision:
        acl = metadata.get(self._acl_field)
        if acl is None:
            if self._default_allow:
                return PolicyDecision(True, "no ACL on document, default allow")
            return PolicyDecision(False, "no ACL on document, default deny")

        # Guard against the common mistake of passing a bare string (e.g.
        # metadata={"acl": "role:hr"}) — str is Iterable too, and without
        # this check we'd silently treat it as a set of characters.
        if isinstance(acl, (str, bytes)):
            acl_set = frozenset({acl})
        elif isinstance(acl, Iterable):
            acl_set = frozenset(acl)
        else:
            acl_set = frozenset()
        if acl_set & principal.attributes:
            return PolicyDecision(True, "principal attribute matched document ACL")
        return PolicyDecision(
            False,
            f"no overlap between principal attributes and document ACL {sorted(acl_set)}",
        )


class AllowAll(Policy):
    """No enforcement — useful when you only want the audit trail for now
    and plan to turn on real access control once documents are annotated."""

    def evaluate(self, principal: Principal, metadata: dict[str, Any]) -> PolicyDecision:
        return PolicyDecision(True, "AllowAll policy")


class GroupPolicy(Policy):
    """Like AttributePolicy, but backed by a single scalar metadata field
    (e.g. ``metadata["team"] = "hr"``) instead of a list.

    The tradeoff for the narrower model: most vector stores (Chroma,
    pgvector, Pinecone) only support filtering on scalar metadata fields,
    not "does this list field contain any of N values" — so GroupPolicy
    can express itself as a real pushdown filter via `to_filter`, while
    the more flexible list-based AttributePolicy can only ever
    post-filter. Use GroupPolicy when you want the vector store itself to
    do the filtering (fewer wasted fetches, no data leaving the store for
    documents nobody's allowed to see).
    """

    def __init__(self, default: str = "allow", group_field: str = "group") -> None:
        if default not in ("allow", "deny"):
            raise ValueError('default must be "allow" or "deny"')
        self._default_allow = default == "allow"
        self._group_field = group_field

    def evaluate(self, principal: Principal, metadata: dict[str, Any]) -> PolicyDecision:
        group = metadata.get(self._group_field)
        if group is None:
            if self._default_allow:
                return PolicyDecision(True, "no group on document, default allow")
            return PolicyDecision(False, "no group on document, default deny")

        if group in principal.attributes:
            return PolicyDecision(True, f"principal has matching group {group!r}")
        return PolicyDecision(False, f"principal lacks group {group!r}")

    def to_filter(self, principal: Principal) -> Optional[dict[str, Any]]:
        if not principal.attributes:
            # No groups at all: only documents with no group field (which
            # fall back to `default`) could ever match for this principal.
            # There's no clean scalar-filter way to express "field is
            # absent" portably, so let RetrievalGuard fall back to post-filtering.
            return None
        return {self._group_field: {"$in": sorted(principal.attributes)}}


@dataclass(frozen=True)
class FieldRedaction:
    """A rule for RedactingPolicy: hide `field` unless the principal has
    `requires_attribute`. `field` is either "content" or a metadata key."""

    field: str
    requires_attribute: str
    replacement: str = "[REDACTED]"


class RedactingPolicy(Policy):
    """Wraps another policy, keeping its allow/deny decision unchanged,
    and additionally strips specific fields from documents the principal
    doesn't fully clear — e.g. everyone with `role:employee` can see a
    document exists, but only `role:hr` sees its content.
    """

    def __init__(self, base: Policy, rules: Iterable[FieldRedaction]) -> None:
        self._base = base
        self._rules = list(rules)

    def evaluate(self, principal: Principal, metadata: dict[str, Any]) -> PolicyDecision:
        return self._base.evaluate(principal, metadata)

    def to_filter(self, principal: Principal) -> Optional[dict[str, Any]]:
        return self._base.to_filter(principal)

    def redact(self, principal: Principal, document: "Document") -> "Document":
        document = self._base.redact(principal, document)
        content = document.content
        metadata = dict(document.metadata)

        for rule in self._rules:
            if rule.requires_attribute in principal.attributes:
                continue
            if rule.field == "content":
                content = rule.replacement
            elif rule.field in metadata:
                metadata[rule.field] = rule.replacement

        return replace(document, content=content, metadata=metadata)
