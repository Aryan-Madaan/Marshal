# Security policy

## Reporting a vulnerability

Please report security issues privately, through GitHub's
[private vulnerability reporting](https://github.com/Aryan-Madaan/marshal/security/advisories/new),
not in a public issue. Include what you found, how to reproduce it, and what
an attacker could do with it. You'll get an acknowledgement within a few days.
Marshal is a governance library: a bypass of any policy, guard, or audit
guarantee is a vulnerability, even when nothing crashes.

Only the latest release receives fixes.

## What Marshal defends against, and how

Marshal sits on the request path and processes attacker-influenced text:
prompts, tool arguments, retrieved documents, model output, MCP tool
definitions. These are the guarantees it is built and tested to keep.

| Threat | Defense | Tested in |
|---|---|---|
| Policy bug or crash turning into an allow | Every guard fails closed: a policy that raises, an unknown outcome, or an approval channel that errors is a denial | `tests/test_tools.py` |
| Approval time-of-check/time-of-use | Arguments are deep-copied once; the copy that was evaluated and approved is the one executed | `tests/test_tools.py` |
| Regex denial of service (ReDoS) | Every detector uses possessive quantifiers and boundary lookbehinds; all are timed against adversarial input in CI | `tests/test_sensitive.py`, `tests/test_egress.py` |
| Secrets hidden from detectors with Unicode | Detection also runs on an NFKC-normalized copy with zero-width and bidi controls removed | `tests/test_sensitive.py` |
| ASCII smuggling (invisible Unicode tag characters) | `UNICODE_TAG_SMUGGLING` detector, blocking by default | `tests/test_sensitive.py` |
| URL-parser confusion bypassing allowlists | Userinfo, backslashes, control characters and malformed ports are treated as disallowed; hosts compare after IDNA encoding | `tests/test_egress.py` |
| MCP rug pulls and tool shadowing | `MCPToolPins` hashes each tool's model-visible definition; changed or shadowing tools are hidden and refused | `tests/test_mcp.py` |
| Data exfiltration through an agent (the "lethal trifecta") | `LethalTrifectaPolicy` tracks flow labels across retrieval and tool calls; `EgressPolicy` allowlists destinations | `tests/test_flow.py`, `tests/test_egress.py` |
| Confused deputy (agent acting for a user) | `DelegatedPolicy` requires every hop of the delegation chain to be allowed | `tests/test_delegation.py` |
| Calls that bypass SDK patching | Every model-call entry point is patched (create, parse, stream, Responses API, beta), verified against the real SDKs | `tests/test_integrations_coverage.py` |
| Audit-log tampering | `SQLiteAuditSink` hash chain; `anchor()` plus `verify(anchor=...)` also detects truncation and rollback | `tests/test_sinks.py` |
| Secrets leaking into the audit trail | Entries store detector names, host names and counts, never matched text, URLs or exception messages | throughout |
| Terminal escape injection via the CLI | Control, bidi and tag characters are escaped before printing | `tests/test_cli.py` |
| Malicious policy files | YAML aliases rejected (expansion bombs), no Python object tags, 1 MB size cap, recursion limits | `tests/test_config.py` |

Stated limits, so nobody relies on something that isn't there:

- Marshal governs what passes through it. Provider-hosted tools (OpenAI web
  search, Anthropic server tools, hosted MCP) execute on the provider's side;
  Marshal can only refuse requests that enable them
  (`enable(..., hosted_tools=...)`).
- The trifecta gate trusts the labels it's given. An untrusted document that
  isn't labeled `untrusted_content` (and has no default label) won't taint a
  session. Label at ingestion.
- Pinning catches a tool definition that *changes*. It can't tell you a
  definition was malicious the first time you saw it. Use `on_new="deny"` and
  review tools before approving them.
- Regex detectors are heuristics. They miss things and flag look-alikes.
- The hash chain proves a log wasn't edited in place. Without an anchor stored
  outside the database, it can't prove the newest records weren't deleted.

## Supply chain

- The core library has **no runtime dependencies**. Every integration is an
  optional extra.
- Extras have floors at or above every known security fix for the code paths
  Marshal uses. Examples: `mcp>=2.3` (CVE-2026-116685, CVE-2026-116686), and
  `litellm>=1.110,!=1.82.7,!=1.82.8`, which excludes the malicious March 2026
  uploads (MAL-2026-2144).
- **Known open advisories, not affecting Marshal:** chromadb ≤1.5.9 has four
  2026 advisories (CVE-2026-45829, -45830, -45831, -45833) with no fixed
  release yet. All four are in chromadb's HTTP server: authentication,
  multi-tenant RBAC, and server-side embedding-function configuration.
  Marshal's adapter wraps an in-process collection object and never runs or
  exposes a Chroma server. If you run one yourself, keep it off untrusted
  networks until upstream ships a fix.
- CI installs only from the hash-locked `uv.lock`, audits it with
  `pip-audit`, pins every GitHub Action to a full upstream commit SHA, runs
  with a read-only token, and lints workflows with zizmor. Releases publish
  through PyPI Trusted Publishing (no stored token) with PEP 740 and GitHub
  build-provenance attestations. Dependabot updates wait seven days before
  adopting a new release.
