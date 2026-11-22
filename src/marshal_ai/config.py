"""Policy-as-config: build Marshal's existing composable policies from a
declarative YAML/JSON file instead of Python code.

Why this exists — the backlog entry this ships (see `ideas.md`): every
policy through v0.11 is a Python object, which means a compliance reviewer
who isn't a Python engineer can't audit or propose a governance change
without going through a PR review of application code, and a policy change
can't be versioned/approved separately from a code deploy. This module is
the OPA/Rego precedent, deliberately scoped down: it does not add a new
expression language, a rules engine, or any way to express logic Marshal's
existing policy classes can't already express. It is a THIN TRANSLATION
LAYER — `load_policies` deserializes a dict into the exact same
`AttributePolicy`/`RiskTierPolicy`/`AllowlistModelPolicy`/etc. objects you'd
otherwise construct by hand, and leans on *their own* constructors to
enforce their own invariants (e.g. `AttributePolicy` still rejects a bad
`default` value, `RiskTierPolicy` still rejects a bad outcome string).
Because this module never re-implements a policy's own logic, it can never
become a second, weaker copy of it — a backdoor around governance would
require a bug in this module *and* in the policy class it built, not just
one or the other.

Schema
------
Top-level keys select which governance surface(s) this file configures —
any subset of `retrieval_policy` / `tool_policy` / `model_policy` may be
present; an absent key means `LoadedPolicies` leaves that surface `None`
and the caller's own guard keeps its own default (`AllowAll`/`AllowAllTools`/
`AllowAllModels`). An optional `version` key, if present, must be `1` —
reserved so a future incompatible schema change can be rejected loudly
instead of silently misparsed.

    version: 1
    retrieval_policy:
      base: {type: attribute, default: allow}
      wrappers:
        - {type: sensitive_data}
    tool_policy:
      base: {type: risk_tier, tiers: {low: allow, medium: require_approval, high: deny}}
      wrappers:
        - {type: rate_limit, max_calls: 100, window_seconds: 60}
    model_policy:
      base:
        type: allowlist
        routes:
          default-chat-model:
            - {model: gpt-fast}
            - {model: eu-hosted, requires_attribute: "region:eu"}
      wrappers:
        - {type: budget, pricing: {gpt-fast: [0.5, 1.5]}, limit_usd: 5.0}
        - {type: residency, allowed_by_jurisdiction: {EU: {eu-hosted: adequacy_decision}}}

Each surface is a `base` policy (required) plus an ordered `wrappers` list
(optional, default `[]`). Wrappers apply OUTERMOST-LAST: the first entry
wraps `base` directly, the second wraps the result of the first, and so on
— in the example above, the built policy is
`residency(budget(allowlist(...)))`, matching how you'd nest the
constructors by hand.

Supported types, by surface — the builder registry below
----------------------------------------------------------
Each `{type: ..., ...params}` block is resolved via a registry keyed by
`(surface, type name)`, mirroring `marshal_ai.audit.register_entry_type`'s
self-registration idiom: adding a new type means calling `register_builder`
once, never editing this module's own control flow (open for extension,
closed for modification). Every entry also records whether it's usable as
a `base` (no `base` argument — starts a chain) or a `wrapper` (takes the
accumulated policy as its first argument) — using one in the other's slot,
or a type registered for a different surface, both raise `PolicyConfigError`
naming exactly where the mismatch is.

retrieval_policy (`marshal_ai.policy`, `marshal_ai.sensitive`):
  - `attribute` (base) -> `AttributePolicy`: `default` ("allow"|"deny",
    default "allow"), `acl_field` (str, default "acl").
  - `group` (base) -> `GroupPolicy`: `default`, `group_field` (default "group").
  - `allow_all` (base) -> `AllowAll`: no params.
  - `redacting` (wrapper) -> `RedactingPolicy`: `rules` (list of
    `{field, requires_attribute, replacement?}`).
  - `sensitive_data` (wrapper) -> `SensitiveDataPolicy`: no params (see
    "Left Python-only" below).

tool_policy (`marshal_ai.tools`):
  - `risk_tier` (base) -> `RiskTierPolicy`: `tiers` (dict[str, str]),
    `default` (default "require_approval").
  - `allow_all` (base) -> `AllowAllTools`: no params.
  - `redacting` (wrapper) -> `RedactingToolPolicy`: `rules` (list of
    `{name, requires_attribute, replacement?}`).
  - `rate_limit` (wrapper) -> `RateLimitPolicy`: `max_calls` (int),
    `window_seconds` (number).
  - `runaway_agent` (wrapper) -> `RunawayAgentPolicy`:
    `identical_call_threshold` (int), `window_seconds` (number).
  - `jurisdictional_risk_tier` (wrapper) -> `JurisdictionalRiskTierPolicy`:
    `overrides_by_jurisdiction` (dict[str, dict[str, str]]).
  - `sensitive_data` (wrapper) -> `SensitiveDataToolPolicy`:
    `block_detectors` (optional list of detector names — must be a subset
    of `marshal_ai.DEFAULT_DETECTORS`' names; omit for the built-in default).

model_policy (`marshal_ai.models`):
  - `allowlist` (base) -> `AllowlistModelPolicy`: `routes` (dict[str,
    list of `{model, requires_attribute?}`]).
  - `allow_all` (base) -> `AllowAllModels`: no params.
  - `budget` (wrapper) -> `BudgetPolicy`: `pricing` (dict[str, [prompt_rate,
    completion_rate]]), `limit_usd` (number).
  - `residency` (wrapper) -> `ResidencyPolicy`: `allowed_by_jurisdiction`
    (dict[str, dict[str, str]]).
  - `retention` (wrapper) -> `RetentionPolicy`: `deployment_retention_days`
    (dict[str, int]).
  - `circuit_breaker` (wrapper) -> `CircuitBreakerPolicy`:
    `failure_threshold` (int), `window_seconds` (number).

Left Python-only, deliberately
-------------------------------
Anything that needs a real Python callable/object rather than data is NOT
faked into this schema — it stays Python-only, composed by hand after
`load_policies` returns (every built policy is a normal object; wrap it
further exactly as you would if you'd constructed it yourself):

  - `SensitiveDataPolicy.scanner` / `SensitiveDataToolPolicy.scanner` —
    a custom `SensitiveDataScanner` with hand-picked `Detector` regexes.
    Config only ever gets the built-in `DEFAULT_DETECTORS` bank; narrowing
    which of *those* block a tool call (`block_detectors`) is supported
    since it's just a list of known names, but authoring new regexes
    through config would be exactly the "new DSL" this module refuses to
    become.
  - `SensitiveDataPolicy.audit_sink` / `SensitiveDataToolPolicy.audit_sink`
    — an `AuditSink` instance. There is no sink object in a declarative
    config, so findings from a config-built `sensitive_data` wrapper are
    still redacted/blocked correctly but are NOT separately logged as
    `SensitiveDataEntry` records unless you construct that one policy by
    hand with the same sink your guard uses.
  - `ApprovalHandler` (`CLIApprovalHandler`/`AutoApprove`/your own) — passed
    to `ToolGuard` directly, not part of any `ToolPolicy` this module builds.
  - Any custom `Policy`/`ToolPolicy`/`ModelPolicy` subclass you've written
    yourself — this module only knows the types registered via
    `register_builder`; register your own to make it loadable, or compose
    it around a config-built policy in Python.

Fail-closed, always
--------------------
Every validation failure raises `PolicyConfigError` naming the offending
path (e.g. `model_policy.wrappers[1]: unknown type 'residencyy'`) —
unknown surface key, unknown `type`, a missing/mistyped required param, a
type used in the wrong slot (base vs. wrapper) or registered for a
different surface, an unsupported file extension, or content that isn't
even valid JSON/YAML. There is no code path in this module that responds
to a malformed config by falling back to an allow-all policy, skipping a
rule, or returning a partially built `LoadedPolicies` — validation happens
before anything is returned to the caller.

Formats
-------
JSON is loaded via the stdlib `json` module always. YAML support needs
PyYAML, imported LAZILY (only when a `.yaml`/`.yml` file is actually
loaded) via `yaml.safe_load` — never `yaml.load`, which can execute
arbitrary Python objects from untrusted input. PyYAML is an optional
extra (`pip install "marshal-ai[config]"`), never a hard dependency of
this library; loading a YAML file without it installed raises
`PolicyConfigError` naming that exact install command, not an opaque
`ModuleNotFoundError`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from marshal_ai.models import (
    AllowAllModels,
    AllowlistModelPolicy,
    BudgetPolicy,
    CircuitBreakerPolicy,
    ModelCandidate,
    ModelPolicy,
    ResidencyPolicy,
    RetentionPolicy,
)
from marshal_ai.policy import (
    AllowAll,
    AttributePolicy,
    FieldRedaction,
    GroupPolicy,
    Policy,
    RedactingPolicy,
)
from marshal_ai.sensitive import (
    DEFAULT_DETECTORS,
    SensitiveDataPolicy,
    SensitiveDataToolPolicy,
)
from marshal_ai.tools import (
    AllowAllTools,
    ArgumentRedaction,
    JurisdictionalRiskTierPolicy,
    RateLimitPolicy,
    RedactingToolPolicy,
    RiskTierPolicy,
    RunawayAgentPolicy,
    ToolPolicy,
)


class PolicyConfigError(Exception):
    """Raised for every way a declarative policy config can be malformed —
    unknown surface/type, a missing or mistyped param, a type used in the
    wrong slot or on the wrong surface, an unsupported file extension, a
    file that can't be read, or content that isn't valid JSON/YAML. The
    only exception this module
    raises for bad input, so a caller only ever needs to catch one type.

    Fails closed: raised immediately on the first problem found, before
    `load_policies` returns anything — never a silent degrade to an
    allow-all policy or a skipped rule.
    """


@dataclass(frozen=True)
class LoadedPolicies:
    """The result of `load_policies` — one optional built policy per
    governance surface. `None` means that surface's key was simply absent
    from the config (not present as some weaker "allow all" stand-in) —
    it's on the caller to decide whether an absent surface means "use this
    guard's own default" or is itself an error for their deployment."""

    retrieval_policy: Optional[Policy] = None
    tool_policy: Optional[ToolPolicy] = None
    model_policy: Optional[ModelPolicy] = None


@dataclass(frozen=True)
class _Builder:
    fn: Callable[..., Any]
    role: str  # "base" | "wrapper"


# (surface, type name) -> _Builder. Populated by `register_builder` calls
# at the bottom of this module — a plain module-level dict, the same
# self-registering-discriminator shape `marshal_ai.audit.register_entry_type`
# already establishes, so adding a new loadable type never means touching
# `load_policies`/`_build_step` themselves.
_REGISTRY: dict[tuple[str, str], _Builder] = {}


def register_builder(surface: str, type_name: str, role: str, fn: Callable[..., Any]) -> None:
    """Register a builder for `type_name` on `surface`
    ("retrieval"/"tool"/"model") as either a "base" builder
    (`fn(params: dict) -> policy`, starts a chain) or a "wrapper" builder
    (`fn(params: dict, base: policy) -> policy`, wraps the accumulated
    policy). Public extension point (OCP): register a builder to make a
    new type loadable from config without modifying this module at all.
    """
    if role not in ("base", "wrapper"):
        raise ValueError(f"role must be 'base' or 'wrapper', got {role!r}")
    _REGISTRY[(surface, type_name)] = _Builder(fn, role)


_SURFACE_KEYS: dict[str, str] = {
    "retrieval_policy": "retrieval",
    "tool_policy": "tool",
    "model_policy": "model",
}


# --------------------------------------------------------------------------
# Small, explicit validation helpers. Every one raises a bare (path-free)
# PolicyConfigError — `_build_step` below is the single place that prefixes
# the full config path onto whatever message bubbles up, so a nested
# helper never needs to know where in the document it's being called from.
# --------------------------------------------------------------------------


def _require(params: dict[str, Any], key: str) -> Any:
    if key not in params:
        raise PolicyConfigError(f"missing required param {key!r}")
    return params.pop(key)


def _reject_unknown(params: dict[str, Any]) -> None:
    if params:
        raise PolicyConfigError(f"unknown param(s) {sorted(params)}")


def _as_str(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise PolicyConfigError(f"{name} must be a string, got {type(value).__name__}")
    return value


def _as_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PolicyConfigError(f"{name} must be a number, got {type(value).__name__}")
    return value


def _as_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyConfigError(f"{name} must be an integer, got {type(value).__name__}")
    return value


def _as_dict(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyConfigError(f"{name} must be a mapping, got {type(value).__name__}")
    return value


def _as_list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise PolicyConfigError(f"{name} must be a list, got {type(value).__name__}")
    return value


# --------------------------------------------------------------------------
# retrieval_policy builders (marshal_ai.policy, marshal_ai.sensitive)
# --------------------------------------------------------------------------


def _build_attribute_policy(params: dict[str, Any]) -> Policy:
    default = _as_str(params.pop("default", "allow"), "'default'")
    acl_field = _as_str(params.pop("acl_field", "acl"), "'acl_field'")
    _reject_unknown(params)
    return AttributePolicy(default=default, acl_field=acl_field)


def _build_group_policy(params: dict[str, Any]) -> Policy:
    default = _as_str(params.pop("default", "allow"), "'default'")
    group_field = _as_str(params.pop("group_field", "group"), "'group_field'")
    _reject_unknown(params)
    return GroupPolicy(default=default, group_field=group_field)


def _build_allow_all_policy(params: dict[str, Any]) -> Policy:
    _reject_unknown(params)
    return AllowAll()


def _build_field_redaction(raw: Any, index: int) -> FieldRedaction:
    rule = dict(_as_dict(raw, f"rules[{index}]"))
    field_name = _as_str(_require(rule, "field"), f"rules[{index}].field")
    requires_attribute = _as_str(_require(rule, "requires_attribute"), f"rules[{index}].requires_attribute")
    replacement = _as_str(rule.pop("replacement", "[REDACTED]"), f"rules[{index}].replacement")
    if rule:
        raise PolicyConfigError(f"rules[{index}]: unknown param(s) {sorted(rule)}")
    return FieldRedaction(field=field_name, requires_attribute=requires_attribute, replacement=replacement)


def _build_redacting_policy(params: dict[str, Any], base: Policy) -> Policy:
    raw_rules = _as_list(_require(params, "rules"), "'rules'")
    _reject_unknown(params)
    rules = [_build_field_redaction(r, i) for i, r in enumerate(raw_rules)]
    return RedactingPolicy(base=base, rules=rules)


def _build_sensitive_data_policy(params: dict[str, Any], base: Policy) -> Policy:
    _reject_unknown(params)
    return SensitiveDataPolicy(base=base)


# --------------------------------------------------------------------------
# tool_policy builders (marshal_ai.tools)
# --------------------------------------------------------------------------


def _build_risk_tier_policy(params: dict[str, Any]) -> ToolPolicy:
    tiers_raw = _as_dict(_require(params, "tiers"), "'tiers'")
    default = _as_str(params.pop("default", "require_approval"), "'default'")
    _reject_unknown(params)
    tiers = {
        _as_str(tier, "a key in 'tiers'"): _as_str(outcome, f"tiers[{tier!r}]")
        for tier, outcome in tiers_raw.items()
    }
    return RiskTierPolicy(tiers=tiers, default=default)


def _build_allow_all_tools(params: dict[str, Any]) -> ToolPolicy:
    _reject_unknown(params)
    return AllowAllTools()


def _build_argument_redaction(raw: Any, index: int) -> ArgumentRedaction:
    rule = dict(_as_dict(raw, f"rules[{index}]"))
    name = _as_str(_require(rule, "name"), f"rules[{index}].name")
    requires_attribute = _as_str(_require(rule, "requires_attribute"), f"rules[{index}].requires_attribute")
    replacement = _as_str(rule.pop("replacement", "[REDACTED]"), f"rules[{index}].replacement")
    if rule:
        raise PolicyConfigError(f"rules[{index}]: unknown param(s) {sorted(rule)}")
    return ArgumentRedaction(name=name, requires_attribute=requires_attribute, replacement=replacement)


def _build_redacting_tool_policy(params: dict[str, Any], base: ToolPolicy) -> ToolPolicy:
    raw_rules = _as_list(_require(params, "rules"), "'rules'")
    _reject_unknown(params)
    rules = [_build_argument_redaction(r, i) for i, r in enumerate(raw_rules)]
    return RedactingToolPolicy(base=base, rules=rules)


def _build_rate_limit_policy(params: dict[str, Any], base: ToolPolicy) -> ToolPolicy:
    max_calls = _as_int(_require(params, "max_calls"), "'max_calls'")
    window_seconds = _as_number(_require(params, "window_seconds"), "'window_seconds'")
    _reject_unknown(params)
    return RateLimitPolicy(base=base, max_calls=max_calls, window_seconds=window_seconds)


def _build_runaway_agent_policy(params: dict[str, Any], base: ToolPolicy) -> ToolPolicy:
    threshold = _as_int(_require(params, "identical_call_threshold"), "'identical_call_threshold'")
    window_seconds = _as_number(_require(params, "window_seconds"), "'window_seconds'")
    _reject_unknown(params)
    return RunawayAgentPolicy(base=base, identical_call_threshold=threshold, window_seconds=window_seconds)


def _build_jurisdictional_risk_tier_policy(params: dict[str, Any], base: ToolPolicy) -> ToolPolicy:
    raw = _as_dict(_require(params, "overrides_by_jurisdiction"), "'overrides_by_jurisdiction'")
    _reject_unknown(params)
    overrides: dict[str, dict[str, str]] = {}
    for jurisdiction, tiers in raw.items():
        tiers_dict = _as_dict(tiers, f"overrides_by_jurisdiction[{jurisdiction!r}]")
        overrides[jurisdiction] = {
            tier: _as_str(outcome, f"overrides_by_jurisdiction[{jurisdiction!r}][{tier!r}]")
            for tier, outcome in tiers_dict.items()
        }
    return JurisdictionalRiskTierPolicy(base=base, overrides_by_jurisdiction=overrides)


_KNOWN_DETECTOR_NAMES: frozenset[str] = frozenset(d.name for d in DEFAULT_DETECTORS)


def _build_sensitive_data_tool_policy(params: dict[str, Any], base: ToolPolicy) -> ToolPolicy:
    raw_block = params.pop("block_detectors", None)
    _reject_unknown(params)
    if raw_block is None:
        return SensitiveDataToolPolicy(base=base)
    block_list = _as_list(raw_block, "'block_detectors'")
    names = [_as_str(n, f"block_detectors[{i}]") for i, n in enumerate(block_list)]
    unknown_names = sorted(set(names) - _KNOWN_DETECTOR_NAMES)
    if unknown_names:
        raise PolicyConfigError(
            f"block_detectors contains unknown detector name(s) {unknown_names}; "
            f"known detectors: {sorted(_KNOWN_DETECTOR_NAMES)}"
        )
    return SensitiveDataToolPolicy(base=base, block_detectors=frozenset(names))


# --------------------------------------------------------------------------
# model_policy builders (marshal_ai.models)
# --------------------------------------------------------------------------


def _build_model_candidate(raw: Any, logical_name: str, index: int) -> ModelCandidate:
    entry = dict(_as_dict(raw, f"routes[{logical_name!r}][{index}]"))
    model = _as_str(_require(entry, "model"), f"routes[{logical_name!r}][{index}].model")
    requires_attribute = entry.pop("requires_attribute", None)
    if requires_attribute is not None:
        requires_attribute = _as_str(
            requires_attribute, f"routes[{logical_name!r}][{index}].requires_attribute"
        )
    if entry:
        raise PolicyConfigError(f"routes[{logical_name!r}][{index}]: unknown param(s) {sorted(entry)}")
    return ModelCandidate(name=model, requires_attribute=requires_attribute)


def _build_allowlist_model_policy(params: dict[str, Any]) -> ModelPolicy:
    raw_routes = _as_dict(_require(params, "routes"), "'routes'")
    _reject_unknown(params)
    routes: dict[str, list[ModelCandidate]] = {}
    for logical_name, candidates_raw in raw_routes.items():
        candidates_list = _as_list(candidates_raw, f"routes[{logical_name!r}]")
        routes[logical_name] = [
            _build_model_candidate(c, logical_name, i) for i, c in enumerate(candidates_list)
        ]
    return AllowlistModelPolicy(routes=routes)


def _build_allow_all_models(params: dict[str, Any]) -> ModelPolicy:
    _reject_unknown(params)
    return AllowAllModels()


def _build_budget_policy(params: dict[str, Any], base: ModelPolicy) -> ModelPolicy:
    raw_pricing = _as_dict(_require(params, "pricing"), "'pricing'")
    limit_usd = _as_number(_require(params, "limit_usd"), "'limit_usd'")
    _reject_unknown(params)
    pricing: dict[str, tuple[float, float]] = {}
    for model, rate in raw_pricing.items():
        rate_list = _as_list(rate, f"pricing[{model!r}]")
        if len(rate_list) != 2:
            raise PolicyConfigError(
                f"pricing[{model!r}] must be a 2-item [prompt_rate, completion_rate] list, "
                f"got {len(rate_list)} item(s)"
            )
        prompt_rate = _as_number(rate_list[0], f"pricing[{model!r}][0]")
        completion_rate = _as_number(rate_list[1], f"pricing[{model!r}][1]")
        pricing[model] = (prompt_rate, completion_rate)
    return BudgetPolicy(base=base, pricing=pricing, limit_usd=limit_usd)


def _build_residency_policy(params: dict[str, Any], base: ModelPolicy) -> ModelPolicy:
    raw = _as_dict(_require(params, "allowed_by_jurisdiction"), "'allowed_by_jurisdiction'")
    _reject_unknown(params)
    allowed: dict[str, dict[str, str]] = {}
    for jurisdiction, deployments in raw.items():
        deployments_dict = _as_dict(deployments, f"allowed_by_jurisdiction[{jurisdiction!r}]")
        allowed[jurisdiction] = {
            deployment: _as_str(mechanism, f"allowed_by_jurisdiction[{jurisdiction!r}][{deployment!r}]")
            for deployment, mechanism in deployments_dict.items()
        }
    return ResidencyPolicy(base=base, allowed_by_jurisdiction=allowed)


def _build_retention_policy(params: dict[str, Any], base: ModelPolicy) -> ModelPolicy:
    raw = _as_dict(_require(params, "deployment_retention_days"), "'deployment_retention_days'")
    _reject_unknown(params)
    retention = {
        deployment: _as_int(days, f"deployment_retention_days[{deployment!r}]")
        for deployment, days in raw.items()
    }
    return RetentionPolicy(base=base, deployment_retention_days=retention)


def _build_circuit_breaker_policy(params: dict[str, Any], base: ModelPolicy) -> ModelPolicy:
    failure_threshold = _as_int(_require(params, "failure_threshold"), "'failure_threshold'")
    window_seconds = _as_number(_require(params, "window_seconds"), "'window_seconds'")
    _reject_unknown(params)
    return CircuitBreakerPolicy(base=base, failure_threshold=failure_threshold, window_seconds=window_seconds)


register_builder("retrieval", "attribute", "base", _build_attribute_policy)
register_builder("retrieval", "group", "base", _build_group_policy)
register_builder("retrieval", "allow_all", "base", _build_allow_all_policy)
register_builder("retrieval", "redacting", "wrapper", _build_redacting_policy)
register_builder("retrieval", "sensitive_data", "wrapper", _build_sensitive_data_policy)

register_builder("tool", "risk_tier", "base", _build_risk_tier_policy)
register_builder("tool", "allow_all", "base", _build_allow_all_tools)
register_builder("tool", "redacting", "wrapper", _build_redacting_tool_policy)
register_builder("tool", "rate_limit", "wrapper", _build_rate_limit_policy)
register_builder("tool", "runaway_agent", "wrapper", _build_runaway_agent_policy)
register_builder("tool", "jurisdictional_risk_tier", "wrapper", _build_jurisdictional_risk_tier_policy)
register_builder("tool", "sensitive_data", "wrapper", _build_sensitive_data_tool_policy)

register_builder("model", "allowlist", "base", _build_allowlist_model_policy)
register_builder("model", "allow_all", "base", _build_allow_all_models)
register_builder("model", "budget", "wrapper", _build_budget_policy)
register_builder("model", "residency", "wrapper", _build_residency_policy)
register_builder("model", "retention", "wrapper", _build_retention_policy)
register_builder("model", "circuit_breaker", "wrapper", _build_circuit_breaker_policy)


def _build_step(
    config_key: str,
    surface: str,
    step_path: str,
    spec: Any,
    base: Optional[Any],
    expected_role: str,
) -> Any:
    """Build one `{type: ..., ...params}` block — either the `base` slot
    (`expected_role="base"`, `base=None`) or one entry of `wrappers`
    (`expected_role="wrapper"`, `base=`the policy accumulated so far).
    Every error raised here (or bubbled up from the builder it calls) is
    re-raised with `config_key.step_path` prefixed, so a caller always
    sees exactly where in the document the problem is — e.g.
    `model_policy.wrappers[1]: unknown type 'residencyy'`.
    """
    if not isinstance(spec, dict):
        raise PolicyConfigError(f"{config_key}.{step_path}: expected a mapping, got {type(spec).__name__}")
    spec = dict(spec)
    type_name = spec.pop("type", None)
    if type_name is None:
        raise PolicyConfigError(f"{config_key}.{step_path}: missing required key 'type'")
    if not isinstance(type_name, str):
        raise PolicyConfigError(
            f"{config_key}.{step_path}: 'type' must be a string, got {type(type_name).__name__}"
        )

    entry = _REGISTRY.get((surface, type_name))
    if entry is None:
        raise PolicyConfigError(f"{config_key}.{step_path}: unknown type {type_name!r}")
    if entry.role != expected_role:
        if expected_role == "base":
            raise PolicyConfigError(
                f"{config_key}.{step_path}: type {type_name!r} wraps another policy and cannot "
                f"be used as a base — put it in 'wrappers' instead"
            )
        raise PolicyConfigError(
            f"{config_key}.{step_path}: type {type_name!r} is a base policy and cannot be used "
            f"as a wrapper"
        )

    try:
        if expected_role == "base":
            return entry.fn(spec)
        return entry.fn(spec, base)
    except PolicyConfigError as exc:
        raise PolicyConfigError(f"{config_key}.{step_path}: {exc}") from exc
    except (TypeError, ValueError, KeyError) as exc:
        # A real policy constructor's own invariant check (e.g.
        # RiskTierPolicy rejecting a bad outcome string) — still the
        # constructor's own validation doing the work, per this module's
        # thin-translation-layer contract; wrapped only so it names the
        # same config path every other failure here does.
        raise PolicyConfigError(f"{config_key}.{step_path} (type {type_name!r}): {exc}") from exc


def _build_surface(config_key: str, surface: str, spec: Any) -> Any:
    if not isinstance(spec, dict):
        raise PolicyConfigError(f"{config_key}: expected a mapping, got {type(spec).__name__}")
    spec = dict(spec)
    if "base" not in spec:
        raise PolicyConfigError(f"{config_key}: missing required key 'base'")
    base_spec = spec.pop("base")
    wrappers_spec = spec.pop("wrappers", [])
    if spec:
        raise PolicyConfigError(f"{config_key}: unknown key(s) {sorted(spec)}")
    if not isinstance(wrappers_spec, list):
        raise PolicyConfigError(f"{config_key}.wrappers: expected a list, got {type(wrappers_spec).__name__}")

    policy = _build_step(config_key, surface, "base", base_spec, None, "base")
    for i, wrapper_spec in enumerate(wrappers_spec):
        policy = _build_step(config_key, surface, f"wrappers[{i}]", wrapper_spec, policy, "wrapper")
    return policy


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise PolicyConfigError(f"{path}: could not read config file — {exc}") from exc


def _load_source(source: "str | Path | dict[str, Any]") -> Any:
    if isinstance(source, dict):
        return source
    if not isinstance(source, (str, Path)):
        raise PolicyConfigError(
            f"source must be a path (str/Path) to a .json/.yaml/.yml file, or a dict — "
            f"got {type(source).__name__}"
        )

    path = Path(source)
    suffix = path.suffix.lower()

    if suffix == ".json":
        text = _read_text(path)
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyConfigError(f"{path}: invalid JSON — {exc}") from exc

    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # PyYAML — optional, lazy: only imported when a YAML file is actually loaded.
        except ImportError as exc:
            raise PolicyConfigError(
                f"loading {path} requires PyYAML, which isn't installed — "
                f'run: pip install "marshal-ai[config]"'
            ) from exc
        text = _read_text(path)
        try:
            # safe_load, never yaml.load — this may be untrusted, reviewed
            # config content, not a place to allow arbitrary Python object
            # construction from the file.
            return yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise PolicyConfigError(f"{path}: invalid YAML — {exc}") from exc

    raise PolicyConfigError(
        f"unsupported config file extension {suffix!r} for {path} — expected .json, .yaml, or .yml"
    )


def load_policies(source: "str | Path | dict[str, Any]") -> LoadedPolicies:
    """Build a `LoadedPolicies` from `source` — a path (`str`/`Path`) to a
    `.json`/`.yaml`/`.yml` file, or an already-parsed `dict` (e.g. if your
    application loads config itself and wants to hand over just the
    resulting mapping). See the module docstring for the full schema.

    Raises `PolicyConfigError` — and only ever that, wrapping anything
    more specific (`json.JSONDecodeError`, `yaml.YAMLError`, a real policy
    constructor's own `ValueError`) — for anything wrong with `source`,
    naming the offending path in the config. Never returns a partially
    built result: the first problem found raises before anything is
    handed back to the caller.
    """
    raw = _load_source(source)
    if not isinstance(raw, dict):
        raise PolicyConfigError(f"top-level config must be a mapping, got {type(raw).__name__}")
    data = dict(raw)

    version = data.pop("version", 1)
    # Type check first: `True == 1` and `1.0 == 1` in Python, and neither
    # is a schema version anyone meant to write.
    if type(version) is not int or version != 1:
        raise PolicyConfigError(f"unsupported config 'version' {version!r} — only version 1 is supported")

    unknown_top = set(data) - set(_SURFACE_KEYS)
    if unknown_top:
        raise PolicyConfigError(f"unknown top-level key(s) {sorted(unknown_top)}")

    built: dict[str, Any] = {}
    for config_key, surface in _SURFACE_KEYS.items():
        if config_key in data:
            built[surface] = _build_surface(config_key, surface, data[config_key])

    return LoadedPolicies(
        retrieval_policy=built.get("retrieval"),
        tool_policy=built.get("tool"),
        model_policy=built.get("model"),
    )
