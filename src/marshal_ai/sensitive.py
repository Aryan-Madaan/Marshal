"""Deterministic, content-based sensitive-data detection.

This is a different question from the one the other three surfaces answer.
`RetrievalGuard`/`ToolGuard`/`ModelGuard` all decide "is this allowed" —
access control, ACL-driven. None of them ask "does the literal content
contain a secret, regardless of who's allowed to see it." A principal can
be fully entitled to a document and it can still contain a credential that
should never have been embedded in the first place; a model can leak one
in its own completion without any ACL being violated at all. That gap is
what this module closes — it plugs into all three existing surfaces plus
`marshal_ai.integrations`, rather than being a fourth competing guard.

Detection is regex-based, on purpose — see "who governs the governor" in
ideas.md. Using an LLM to judge whether content is sensitive would mean
paying for and trusting another model call on every document, tool
argument, prompt, and completion — and a document engineered to smuggle a
prompt injection could plausibly talk an LLM judge out of flagging itself,
the same way it could talk an LLM judge into approving a malicious tool
call. A regex either matches or it doesn't; no call, no cost, no attack
surface of its own. The tradeoff, stated plainly: regexes are heuristics,
not ground truth — PHONE_US and CREDIT_CARD in particular will both miss
real instances and flag look-alikes. Tune `detectors=` per deployment
rather than trusting the defaults blindly for anything compliance-critical.

Findings are recorded as *detector name and count only* — never the
matched text itself, the same discipline `ToolCallEntry` already applies
to redacted arguments. The audit trail that exists to catch a leaked
secret must never become a second copy of it.
"""

from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass, field, replace
from typing import TYPE_CHECKING, Any, Iterable, Optional

from marshal_ai.audit import AuditSink, register_entry_type
from marshal_ai.policy import Policy, PolicyDecision, Principal
from marshal_ai.tools import ToolCallRequest, ToolDecision, ToolPolicy

if TYPE_CHECKING:
    from marshal_ai.retrieval import Document


@dataclass(frozen=True)
class Detector:
    """One named pattern. `pattern` must not use capturing groups —
    `findall`/`subn` are used directly against it, and a capturing group
    would change what they return."""

    name: str
    pattern: "re.Pattern[str]"


def _detector(name: str, pattern: str, flags: int = 0) -> Detector:
    return Detector(name=name, pattern=re.compile(pattern, flags))


DEFAULT_DETECTORS: list[Detector] = [
    _detector("EMAIL", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    _detector("PHONE_US", r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    _detector("SSN_US", r"\b\d{3}-\d{2}-\d{4}\b"),
    _detector(
        "CREDIT_CARD",
        r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,4}\b",
    ),
    _detector("AWS_ACCESS_KEY_ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    _detector(
        "GENERIC_API_KEY",
        r"\b(?:sk-ant-[A-Za-z0-9\-_]{20,}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36}|"
        r"gho_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,})\b",
    ),
    _detector("JWT", r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    _detector("PRIVATE_KEY_BLOCK", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
]

# Detectors severe enough that finding one is grounds to refuse the call
# outright (tool call, or model prompt before any network call happens),
# not just redact-and-continue. Deliberately narrow: credentials, not PII —
# blocking a document because it contains an email address would make the
# feature useless day one. Widen per deployment via `block_detectors=`.
DEFAULT_BLOCK_DETECTORS: frozenset[str] = frozenset(
    {"PRIVATE_KEY_BLOCK", "AWS_ACCESS_KEY_ID", "GENERIC_API_KEY"}
)


@dataclass(frozen=True)
class Finding:
    detector: str
    count: int


class SensitiveDataScanner:
    """Runs a set of detectors over text. `scan` reports what fired without
    touching the text; `redact` replaces every match in place and reports
    the same. Neither ever returns the matched substring itself."""

    def __init__(self, detectors: Optional[Iterable[Detector]] = None) -> None:
        self._detectors = list(detectors) if detectors is not None else list(DEFAULT_DETECTORS)

    def scan(self, text: str) -> list[Finding]:
        if not text:
            return []
        findings = []
        for detector in self._detectors:
            matches = detector.pattern.findall(text)
            if matches:
                findings.append(Finding(detector.name, len(matches)))
        return findings

    def redact(self, text: str) -> tuple[str, list[Finding]]:
        if not text:
            return text, []
        findings = []
        for detector in self._detectors:
            text, count = detector.pattern.subn(f"[REDACTED:{detector.name}]", text)
            if count:
                findings.append(Finding(detector.name, count))
        return text, findings


@dataclass(frozen=True)
class SensitiveDataEntry:
    """A record that content scanning found something — deliberately its
    own entry kind, independent of which surface triggered it, so
    `sink.query(...)` can show every place a credential or PII pattern
    showed up (a retrieved document, a tool argument, a model prompt or
    completion) in one place. `findings` is `["DETECTOR:count", ...]` —
    names and counts only, never matched text."""

    timestamp: float
    principal_id: str
    surface: str  # "retrieval" | "tool_call" | "model_prompt" | "model_completion"
    location: str  # document id / argument name / resolved model name
    findings: list[str] = field(default_factory=list)
    action: str = "audited_only"  # "redacted" | "blocked" | "audited_only"

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "sensitive_data", **asdict(self)}


register_entry_type("sensitive_data", SensitiveDataEntry)


def write_finding(
    audit_sink: Optional[AuditSink],
    principal: Principal,
    surface: str,
    location: str,
    findings: list[Finding],
    action: str,
) -> None:
    """Shared by every surface's wrapper below, and reusable by
    `marshal_ai.integrations` for the SDK-patch layer, which sees prompt
    and completion text no other surface has access to."""
    if audit_sink is None or not findings:
        return
    audit_sink.write(
        SensitiveDataEntry(
            timestamp=time.time(),
            principal_id=principal.id,
            surface=surface,
            location=location,
            findings=[f"{f.detector}:{f.count}" for f in findings],
            action=action,
        )
    )


class SensitiveDataPolicy(Policy):
    """Wraps another `Policy`, keeping its allow/deny decision unchanged,
    and additionally scans + redacts document *content* for regex-
    detectable secrets/PII before it's returned — regardless of ACL, since
    "is this principal allowed to see this document" and "should this
    document's literal content have contained this credential" are
    different questions.

    Redact-only, deliberately not block: `Policy.evaluate()` only ever
    sees document metadata, not content (see `Policy` in `policy.py`) —
    there's no clean point in the interface to deny an already-fetched,
    ACL-allowed document just because a substring inside it looks like a
    secret. Use `SensitiveDataToolPolicy` where blocking is meaningful
    (tool arguments are available at decision time, not just metadata).

    Pass the *same* `audit_sink` you give the `RetrievalGuard` so findings
    land in the shared trail rather than nowhere.
    """

    def __init__(
        self,
        base: Policy,
        scanner: Optional[SensitiveDataScanner] = None,
        audit_sink: Optional[AuditSink] = None,
    ) -> None:
        self._base = base
        self._scanner = scanner if scanner is not None else SensitiveDataScanner()
        self._audit_sink = audit_sink

    def evaluate(self, principal: Principal, metadata: dict[str, Any]) -> PolicyDecision:
        return self._base.evaluate(principal, metadata)

    def to_filter(self, principal: Principal) -> Optional[dict[str, Any]]:
        return self._base.to_filter(principal)

    def redact(self, principal: Principal, document: "Document") -> "Document":
        document = self._base.redact(principal, document)
        redacted_content, findings = self._scanner.redact(document.content)
        if findings:
            write_finding(self._audit_sink, principal, "retrieval", document.id, findings, "redacted")
            document = replace(document, content=redacted_content)
        return document


class SensitiveDataToolPolicy(ToolPolicy):
    """Wraps another `ToolPolicy`, keeping its allow/deny/require-approval
    decision unchanged *unless* a blocking detector (default:
    `DEFAULT_BLOCK_DETECTORS`) fires in the arguments — that overrides the
    base decision to deny outright, since a raw credential in a tool
    call's arguments is worth stopping for regardless of the tool's
    assigned risk tier. Non-blocking findings (e.g. an email address) are
    redacted from what gets audited/shown to an approver, the same way
    `RedactingToolPolicy` handles named fields — the wrapped tool itself
    always still receives the real, unredacted arguments.

    Pass the *same* `audit_sink` you give the `ToolGuard` so findings land
    in the shared trail rather than nowhere.
    """

    def __init__(
        self,
        base: ToolPolicy,
        scanner: Optional[SensitiveDataScanner] = None,
        block_detectors: Iterable[str] = DEFAULT_BLOCK_DETECTORS,
        audit_sink: Optional[AuditSink] = None,
    ) -> None:
        self._base = base
        self._scanner = scanner if scanner is not None else SensitiveDataScanner()
        self._block_detectors = frozenset(block_detectors)
        self._audit_sink = audit_sink

    def evaluate(self, request: ToolCallRequest) -> ToolDecision:
        decision = self._base.evaluate(request)
        if decision.outcome == "deny":
            return decision

        blocking: list[Finding] = []
        for value in request.arguments.values():
            if isinstance(value, str):
                blocking.extend(
                    f for f in self._scanner.scan(value) if f.detector in self._block_detectors
                )
        if blocking:
            write_finding(
                self._audit_sink, request.principal, "tool_call", request.tool_name, blocking, "blocked"
            )
            names = ", ".join(sorted({f.detector for f in blocking}))
            return ToolDecision("deny", f"blocked: sensitive data detected ({names})")
        return decision

    def redact_arguments(self, request: ToolCallRequest) -> dict[str, Any]:
        arguments = self._base.redact_arguments(request)
        # Findings from block_detectors already got their own "blocked"
        # entry from evaluate() above (which always runs first — see
        # ToolGuard.call) — excluding them here avoids auditing the same
        # secret twice under two different actions.
        auditable: list[Finding] = []
        for key, value in list(arguments.items()):
            if isinstance(value, str):
                redacted_value, findings = self._scanner.redact(value)
                if findings:
                    arguments[key] = redacted_value
                    auditable.extend(f for f in findings if f.detector not in self._block_detectors)
        if auditable:
            write_finding(
                self._audit_sink, request.principal, "tool_call", request.tool_name, auditable, "redacted"
            )
        return arguments
