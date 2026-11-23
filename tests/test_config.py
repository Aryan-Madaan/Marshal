import json

import pytest
import yaml

from marshal_ai.audit import InMemoryAuditSink
from marshal_ai.config import LoadedPolicies, PolicyConfigError, load_policies, register_builder
from marshal_ai.policy import Principal
from marshal_ai.retrieval import Document, RetrievalGuard
from marshal_ai.tools import ToolCallDenied, ToolGuard
from marshal_ai.models import ModelCallDenied, ModelGuard


# --- retrieval_policy: build from dict, real behavior ----------------------


def test_attribute_policy_from_dict_enforces_acl():
    config = {"retrieval_policy": {"base": {"type": "attribute", "default": "allow"}}}
    loaded = load_policies(config)
    assert loaded.tool_policy is None
    assert loaded.model_policy is None

    guard = RetrievalGuard(
        retriever=lambda query, k: [
            Document(id="public", content="ok", metadata={}),
            Document(id="hr-only", content="salary stuff", metadata={"acl": ["role:hr"]}),
        ],
        policy=loaded.retrieval_policy,
    )
    engineer = Principal(id="deepa", attributes={"role:engineering"})
    results = guard.retrieve("q", principal=engineer, k=5)
    assert {d.id for d in results} == {"public"}


def test_sensitive_data_wrapper_from_dict_redacts_content():
    config = {
        "retrieval_policy": {
            "base": {"type": "attribute", "default": "allow"},
            "wrappers": [{"type": "sensitive_data"}],
        }
    }
    loaded = load_policies(config)
    guard = RetrievalGuard(
        retriever=lambda query, k: [
            Document(id="ticket-1", content="contact bob@example.com for help", metadata={}),
        ],
        policy=loaded.retrieval_policy,
    )
    results = guard.retrieve("q", principal=Principal(id="alice"), k=5)
    assert results[0].content == "contact [REDACTED:EMAIL] for help"


def test_group_policy_and_redacting_wrapper_from_dict():
    config = {
        "retrieval_policy": {
            "base": {"type": "group", "default": "allow", "group_field": "team"},
            "wrappers": [
                {"type": "redacting", "rules": [{"field": "content", "requires_attribute": "role:hr"}]}
            ],
        }
    }
    loaded = load_policies(config)
    guard = RetrievalGuard(
        retriever=lambda query, k: [Document(id="d1", content="secret salary info", metadata={"team": "hr"})],
        policy=loaded.retrieval_policy,
    )
    hr = Principal(id="rhea", attributes={"hr"})
    engineer = Principal(id="deepa", attributes={"role:engineering"})

    hr_results = guard.retrieve("q", principal=hr, k=5)
    assert hr_results[0].content == "[REDACTED]"  # not role:hr, so content redacted anyway

    nobody_results = guard.retrieve("q", principal=engineer, k=5)
    assert nobody_results == []  # engineer isn't in the "hr" group at all, denied outright


# --- tool_policy: build from dict, real behavior ----------------------------


def test_risk_tier_config_denies_high_allows_low():
    config = {
        "tool_policy": {
            "base": {"type": "risk_tier", "tiers": {"low": "allow", "high": "deny"}},
        }
    }
    loaded = load_policies(config)
    guard = ToolGuard(tool=lambda: "ok", policy=loaded.tool_policy, tool_name="noop")

    assert guard.call(Principal(id="a"), {}, risk_tier="low") == "ok"
    with pytest.raises(ToolCallDenied):
        guard.call(Principal(id="a"), {}, risk_tier="high")


def test_rate_limit_wrapper_from_dict_denies_after_max_calls():
    config = {
        "tool_policy": {
            "base": {"type": "risk_tier", "tiers": {"low": "allow"}},
            "wrappers": [{"type": "rate_limit", "max_calls": 2, "window_seconds": 60}],
        }
    }
    loaded = load_policies(config)
    guard = ToolGuard(tool=lambda: "ok", policy=loaded.tool_policy, tool_name="noop")
    principal = Principal(id="alice")

    assert guard.call(principal, {}, risk_tier="low") == "ok"
    assert guard.call(principal, {}, risk_tier="low") == "ok"
    with pytest.raises(ToolCallDenied):
        guard.call(principal, {}, risk_tier="low")


def test_jurisdictional_risk_tier_wrapper_tightens_in_eu():
    from marshal_ai.tools import AutoApprove

    config = {
        "tool_policy": {
            "base": {"type": "risk_tier", "tiers": {"employment_decision": "allow"}},
            "wrappers": [
                {
                    "type": "jurisdictional_risk_tier",
                    "overrides_by_jurisdiction": {"EU": {"employment_decision": "require_approval"}},
                }
            ],
        }
    }
    loaded = load_policies(config)
    principal = Principal(id="alice")

    # No jurisdiction in context: base policy's plain "allow" passes through.
    plain_guard = ToolGuard(tool=lambda: "ok", policy=loaded.tool_policy, tool_name="noop")
    assert plain_guard.call(principal, {}, risk_tier="employment_decision") == "ok"

    # In the EU, the same base "allow" is forced through approval instead —
    # monotonic tightening, never a loosening.
    declining_guard = ToolGuard(
        tool=lambda: "ok",
        policy=loaded.tool_policy,
        tool_name="noop",
        approval_handler=AutoApprove(False),
    )
    with pytest.raises(ToolCallDenied):
        declining_guard.call(
            principal, {}, risk_tier="employment_decision", context={"jurisdiction": "EU"}
        )


# --- model_policy: build from dict, real behavior ---------------------------


def test_budget_wrapper_from_dict_denies_once_over_limit():
    config = {
        "model_policy": {
            "base": {"type": "allowlist", "routes": {"m": [{"model": "gpt-fast"}]}},
            "wrappers": [{"type": "budget", "pricing": {"gpt-fast": [1.0, 1.0]}, "limit_usd": 1.0}],
        }
    }
    loaded = load_policies(config)
    guard = ModelGuard(policy=loaded.model_policy)
    alice = Principal(id="alice")

    assert guard.resolve(alice, "m") == "gpt-fast"
    guard.record_usage(alice, "gpt-fast", prompt_tokens=1000, completion_tokens=0)  # $1.00 spent
    with pytest.raises(ModelCallDenied):
        guard.resolve(alice, "m")


def test_residency_wrapper_from_dict_denies_non_compliant_jurisdiction():
    config = {
        "model_policy": {
            "base": {
                "type": "allowlist",
                "routes": {
                    "default-chat-model": [
                        {"model": "gpt-fast"},
                        {"model": "eu-hosted", "requires_attribute": "region:eu"},
                    ]
                },
            },
            "wrappers": [
                {
                    "type": "residency",
                    "allowed_by_jurisdiction": {"EU": {"eu-hosted": "adequacy_decision"}},
                }
            ],
        }
    }
    loaded = load_policies(config)
    eu_user = Principal(id="bob", attributes={"region:eu"})
    guard = ModelGuard(policy=loaded.model_policy)

    resolved = guard.resolve(eu_user, "default-chat-model", context={"jurisdiction": "EU"})
    assert resolved == "eu-hosted"

    with pytest.raises(ModelCallDenied):
        guard.resolve(eu_user, "default-chat-model", context={"jurisdiction": "TH"})


def test_allowlist_requires_attribute_round_trips_through_config():
    config = {
        "model_policy": {
            "base": {
                "type": "allowlist",
                "routes": {"m": [{"model": "restricted", "requires_attribute": "region:eu"}]},
            }
        }
    }
    loaded = load_policies(config)
    guard = ModelGuard(policy=loaded.model_policy)
    with pytest.raises(ModelCallDenied):
        guard.resolve(Principal(id="alice"), "m")
    assert guard.resolve(Principal(id="bob", attributes={"region:eu"}), "m") == "restricted"


# --- from real files ---------------------------------------------------------


MULTI_SURFACE_CONFIG = {
    "version": 1,
    "retrieval_policy": {
        "base": {"type": "attribute", "default": "allow"},
        "wrappers": [{"type": "sensitive_data"}],
    },
    "tool_policy": {
        "base": {"type": "risk_tier", "tiers": {"low": "allow", "medium": "require_approval", "high": "deny"}},
        "wrappers": [{"type": "rate_limit", "max_calls": 100, "window_seconds": 60}],
    },
    "model_policy": {
        "base": {
            "type": "allowlist",
            "routes": {
                "default-chat-model": [
                    {"model": "gpt-fast"},
                    {"model": "eu-hosted", "requires_attribute": "region:eu"},
                ]
            },
        },
        "wrappers": [
            {"type": "budget", "pricing": {"gpt-fast": [0.5, 1.5]}, "limit_usd": 5.0},
            {"type": "residency", "allowed_by_jurisdiction": {"EU": {"eu-hosted": "adequacy_decision"}}},
        ],
    },
}


def _assert_multi_surface_behaves(loaded: LoadedPolicies) -> None:
    assert loaded.retrieval_policy is not None
    assert loaded.tool_policy is not None
    assert loaded.model_policy is not None

    tool_guard = ToolGuard(tool=lambda: "ok", policy=loaded.tool_policy, tool_name="noop")
    with pytest.raises(ToolCallDenied):
        tool_guard.call(Principal(id="alice"), {}, risk_tier="high")

    model_guard = ModelGuard(policy=loaded.model_policy)
    eu_user = Principal(id="bob", attributes={"region:eu"})
    assert (
        model_guard.resolve(eu_user, "default-chat-model", context={"jurisdiction": "EU"}) == "eu-hosted"
    )


def test_load_from_json_file_path_str_and_path(tmp_path):
    path = tmp_path / "policies.json"
    path.write_text(json.dumps(MULTI_SURFACE_CONFIG), encoding="utf-8")

    loaded_from_str = load_policies(str(path))
    _assert_multi_surface_behaves(loaded_from_str)

    loaded_from_path = load_policies(path)
    _assert_multi_surface_behaves(loaded_from_path)


def test_load_from_yaml_file_uses_real_pyyaml(tmp_path):
    path = tmp_path / "policies.yaml"
    path.write_text(yaml.safe_dump(MULTI_SURFACE_CONFIG), encoding="utf-8")

    loaded = load_policies(path)
    _assert_multi_surface_behaves(loaded)


def test_yaml_extension_without_pyyaml_raises_clear_install_hint(tmp_path, monkeypatch):
    import sys

    path = tmp_path / "policies.yaml"
    path.write_text(yaml.safe_dump({"tool_policy": {"base": {"type": "allow_all"}}}), encoding="utf-8")

    # sys.modules[name] = None is the standard idiom for forcing `import
    # name` to raise ImportError — simulating "PyYAML isn't installed"
    # without actually uninstalling it from this environment.
    monkeypatch.setitem(sys.modules, "yaml", None)

    with pytest.raises(PolicyConfigError, match=r'pip install "marshal-ai\[config\]"'):
        load_policies(path)


# --- LoadedPolicies defaults --------------------------------------------------


def test_absent_surfaces_are_none():
    loaded = load_policies({"tool_policy": {"base": {"type": "allow_all"}}})
    assert loaded.retrieval_policy is None
    assert loaded.model_policy is None
    assert loaded.tool_policy is not None


def test_empty_config_yields_all_none():
    loaded = load_policies({})
    assert (loaded.retrieval_policy, loaded.tool_policy, loaded.model_policy) == (None, None, None)


# --- fail-closed: malformed configs always raise PolicyConfigError ----------


MALFORMED_CASES = [
    pytest.param({"embedding_policy": {}}, "unknown top-level key", id="unknown-top-level-key"),
    pytest.param({"version": 2}, "version", id="unsupported-version"),
    # `True == 1` and `1.0 == 1` in Python — neither is a real version 1.
    pytest.param({"version": True}, "version", id="bool-version"),
    pytest.param({"version": 1.0}, "version", id="float-version"),
    pytest.param(
        {"retrieval_policy": {"wrappers": []}}, "missing required key 'base'", id="missing-base"
    ),
    pytest.param(
        {"model_policy": {"base": {"type": "residencyy"}}},
        "unknown type 'residencyy'",
        id="unknown-type-typo",
    ),
    pytest.param(
        {"retrieval_policy": {"base": {"type": "budget", "pricing": {}, "limit_usd": 1}}},
        "unknown type 'budget'",
        id="model-type-on-retrieval-surface",
    ),
    pytest.param(
        {
            "tool_policy": {
                "base": {"type": "risk_tier", "tiers": {"low": "allow"}},
                "wrappers": [
                    {"type": "residency", "allowed_by_jurisdiction": {"EU": {"x": "adequacy_decision"}}}
                ],
            }
        },
        "unknown type 'residency'",
        id="wrapper-used-on-wrong-surface",
    ),
    pytest.param(
        {"tool_policy": {"base": {"type": "rate_limit", "max_calls": 1, "window_seconds": 1}}},
        "cannot be used as a base",
        id="wrapper-used-as-base",
    ),
    pytest.param(
        {
            "model_policy": {
                "base": {"type": "allowlist", "routes": {"m": [{"model": "x"}]}},
                "wrappers": [{"type": "allow_all"}],
            }
        },
        "cannot be used as a wrapper",
        id="base-type-used-as-wrapper",
    ),
    pytest.param(
        {"tool_policy": {"base": {"type": "risk_tier"}}},
        "missing required param 'tiers'",
        id="missing-required-param",
    ),
    pytest.param(
        {
            "model_policy": {
                "base": {"type": "allowlist", "routes": {"m": [{"model": "gpt-fast"}]}},
                "wrappers": [{"type": "budget", "pricing": {}, "limit_usd": "five"}],
            }
        },
        "must be a number",
        id="wrong-param-type",
    ),
    pytest.param(
        {"tool_policy": {"base": {"type": "risk_tier", "tiers": {"low": "maybe"}}}},
        "must be one of",  # RiskTierPolicy's own ValueError, surfaced verbatim
        id="bad-outcome-value-from-real-constructor",
    ),
    pytest.param(
        {
            "tool_policy": {
                "base": {"type": "risk_tier", "tiers": {"low": "allow"}},
                "wrappers": [{"type": "sensitive_data", "block_detectors": ["NOT_A_REAL_DETECTOR"]}],
            }
        },
        "unknown detector name",
        id="unknown-block-detector-name",
    ),
    pytest.param(
        {
            "model_policy": {
                "base": {"type": "allowlist", "routes": {"m": [{"model": "gpt-fast"}]}},
                "wrappers": [{"type": "budget", "pricing": {"gpt-fast": [1.0]}, "limit_usd": 5.0}],
            }
        },
        "2-item",
        id="pricing-wrong-arity",
    ),
    pytest.param(
        {"retrieval_policy": {"base": {"type": "attribute", "acl_field": "acl", "typo_field": 1}}},
        "unknown param",
        id="unknown-param-key",
    ),
]


@pytest.mark.parametrize("config, expected_substring", MALFORMED_CASES)
def test_malformed_config_raises_policy_config_error(config, expected_substring):
    with pytest.raises(PolicyConfigError, match=expected_substring):
        load_policies(config)


def test_invalid_source_type_raises():
    with pytest.raises(PolicyConfigError, match="source must be a path"):
        load_policies([1, 2, 3])  # not a str/Path/dict at all


def test_json_file_with_non_dict_top_level_raises(tmp_path):
    path = tmp_path / "policies.json"
    path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    with pytest.raises(PolicyConfigError, match="must be a mapping"):
        load_policies(path)


def test_bad_file_extension_raises(tmp_path):
    path = tmp_path / "policies.txt"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(PolicyConfigError, match="unsupported config file extension"):
        load_policies(path)


def test_missing_file_raises_policy_config_error_not_oserror(tmp_path):
    with pytest.raises(PolicyConfigError, match="could not read config file"):
        load_policies(tmp_path / "does-not-exist.yaml")


def test_non_utf8_file_raises_policy_config_error(tmp_path):
    path = tmp_path / "policies.json"
    path.write_bytes(b"\xff\xfe{}")
    with pytest.raises(PolicyConfigError, match="could not read config file"):
        load_policies(path)


def test_invalid_json_content_raises(tmp_path):
    path = tmp_path / "policies.json"
    path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(PolicyConfigError, match="invalid JSON"):
        load_policies(path)


def test_invalid_yaml_content_raises(tmp_path):
    path = tmp_path / "policies.yaml"
    path.write_text("key: [unclosed", encoding="utf-8")
    with pytest.raises(PolicyConfigError, match="invalid YAML"):
        load_policies(path)


def test_second_malformed_surface_raises_nothing_partial_returned():
    # retrieval_policy alone would build cleanly — proving a later,
    # malformed surface still raises before load_policies returns anything
    # at all, rather than handing back a half-built LoadedPolicies.
    config = {
        "retrieval_policy": {"base": {"type": "attribute", "default": "allow"}},
        "tool_policy": {"base": {"type": "totally_unknown_type"}},
    }
    with pytest.raises(PolicyConfigError, match="unknown type"):
        load_policies(config)


# --- builder registry is a real extension point -----------------------------


def test_register_builder_adds_a_new_loadable_type():
    from marshal_ai.policy import AllowAll

    def _build_custom(params):
        assert params == {}
        return AllowAll()

    register_builder("retrieval", "custom_allow_all_for_test", "base", _build_custom)
    try:
        loaded = load_policies(
            {"retrieval_policy": {"base": {"type": "custom_allow_all_for_test"}}}
        )
        assert loaded.retrieval_policy is not None
        guard = RetrievalGuard(
            retriever=lambda query, k: [Document(id="d", content="x", metadata={"acl": ["nobody"]})],
            policy=loaded.retrieval_policy,
        )
        results = guard.retrieve("q", principal=Principal(id="alice"), k=5)
        assert {d.id for d in results} == {"d"}  # AllowAll: not gated by the ACL at all
    finally:
        from marshal_ai.config import _REGISTRY

        _REGISTRY.pop(("retrieval", "custom_allow_all_for_test"), None)


def test_register_builder_rejects_bad_role():
    with pytest.raises(ValueError):
        register_builder("retrieval", "whatever", "not-a-real-role", lambda params: None)


# --- audit_sink findings note (documented Python-only limitation) ----------


def test_sensitive_data_from_config_still_redacts_without_a_config_supplied_sink():
    # SensitiveDataPolicy.audit_sink can't be expressed in the config
    # schema (no AuditSink object exists in a YAML/JSON file) — this is
    # documented as Python-only in config.py's module docstring. Prove the
    # redaction itself still works even though findings won't additionally
    # land in a SensitiveDataEntry unless the caller wires up the same
    # policy by hand with a real sink.
    config = {
        "retrieval_policy": {
            "base": {"type": "allow_all"},
            "wrappers": [{"type": "sensitive_data"}],
        }
    }
    loaded = load_policies(config)
    sink = InMemoryAuditSink()
    guard = RetrievalGuard(
        retriever=lambda query, k: [Document(id="d1", content="email me at a@b.com", metadata={})],
        policy=loaded.retrieval_policy,
        audit_sink=sink,
    )
    results = guard.retrieve("q", principal=Principal(id="alice"), k=5)
    assert "[REDACTED:EMAIL]" in results[0].content
    # No SensitiveDataEntry shows up in the shared sink (only the guard's
    # own AuditEntry does) — because the config-built SensitiveDataPolicy
    # has no audit_sink wired in, exactly as documented.
    kinds = {entry.to_dict()["kind"] for entry in sink.all_entries()}
    assert kinds == {"retrieval"}


def test_yaml_alias_bomb_is_rejected(tmp_path):
    bomb = "a: &a [x, x, x, x, x, x, x, x, x]\n" + "".join(
        f"{chr(98 + i)}: &{chr(98 + i)} [*{chr(97 + i)}, *{chr(97 + i)}, *{chr(97 + i)}, *{chr(97 + i)}]\n"
        for i in range(8)
    )
    path = tmp_path / "policies.yaml"
    path.write_text(bomb, encoding="utf-8")
    with pytest.raises(PolicyConfigError, match="aliases are not allowed"):
        load_policies(path)


def test_oversized_config_file_is_refused_before_parsing(tmp_path):
    from marshal_ai.config import MAX_CONFIG_BYTES

    path = tmp_path / "policies.json"
    path.write_text(" " * (MAX_CONFIG_BYTES + 1) + "{}", encoding="utf-8")
    with pytest.raises(PolicyConfigError, match="limit"):
        load_policies(path)


def test_pathologically_nested_json_raises_policy_config_error(tmp_path):
    path = tmp_path / "policies.json"
    path.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    with pytest.raises(PolicyConfigError):
        load_policies(path)


def test_yaml_python_object_tags_are_still_refused(tmp_path):
    path = tmp_path / "policies.yaml"
    path.write_text("tool_policy: !!python/object/apply:os.system ['echo pwned']\n", encoding="utf-8")
    with pytest.raises(PolicyConfigError, match="invalid YAML"):
        load_policies(path)


def test_delegated_and_egress_policies_load_from_config():
    from marshal_ai import DelegatedPolicy, EgressPolicy

    loaded = load_policies({
        "retrieval_policy": {"base": {"type": "attribute"}, "wrappers": [{"type": "delegated"}]},
        "tool_policy": {
            "base": {"type": "allow_all"},
            "wrappers": [{"type": "egress", "allowed_hosts": ["api.github.com", "*.example.com"]}],
        },
    })
    assert isinstance(loaded.retrieval_policy, DelegatedPolicy)
    assert isinstance(loaded.tool_policy, EgressPolicy)
    with pytest.raises(PolicyConfigError, match="on_violation"):
        load_policies({"tool_policy": {"base": {"type": "allow_all"}, "wrappers": [
            {"type": "egress", "allowed_hosts": [], "on_violation": "allow"}]}})
    with pytest.raises(PolicyConfigError, match="allowed_hosts"):
        load_policies({"tool_policy": {"base": {"type": "allow_all"}, "wrappers": [{"type": "egress"}]}})


def test_model_rate_limit_runaway_and_budget_estimates_load_from_config():
    from marshal_ai import BudgetPolicy, ModelRunawayPolicy

    loaded = load_policies({"model_policy": {
        "base": {"type": "allow_all"},
        "wrappers": [
            {"type": "rate_limit", "max_calls": 100, "window_seconds": 60},
            {"type": "runaway", "identical_call_threshold": 5, "window_seconds": 30},
            {"type": "budget", "pricing": {"m": [1, 2]}, "limit_usd": 5, "enforce_estimates": True},
        ],
    }})
    assert isinstance(loaded.model_policy, BudgetPolicy)
    assert isinstance(loaded.model_policy._base, ModelRunawayPolicy)
    with pytest.raises(PolicyConfigError, match="enforce_estimates"):
        load_policies({"model_policy": {"base": {"type": "allow_all"}, "wrappers": [
            {"type": "budget", "pricing": {}, "limit_usd": 1, "enforce_estimates": "yes"}]}})


def test_tool_circuit_breaker_and_failed_call_threshold_load_from_config():
    from marshal_ai import RunawayAgentPolicy, ToolCircuitBreakerPolicy

    loaded = load_policies({"tool_policy": {"base": {"type": "allow_all"}, "wrappers": [
        {"type": "circuit_breaker", "failure_threshold": 5, "window_seconds": 60},
        {"type": "runaway_agent", "identical_call_threshold": 10, "window_seconds": 60, "failed_call_threshold": 5},
    ]}})
    assert isinstance(loaded.tool_policy, RunawayAgentPolicy)
    assert isinstance(loaded.tool_policy._base, ToolCircuitBreakerPolicy)


def test_policy_version_is_stable_across_formatting_and_changes_with_semantics(tmp_path):
    from marshal_ai import InMemoryAuditSink, Principal, ToolGuard

    a = tmp_path / "a.yaml"
    a.write_text("tool_policy:\n  base: {type: risk_tier, tiers: {low: allow}}\n", encoding="utf-8")
    b = tmp_path / "b.json"
    b.write_text('{"tool_policy": {"base": {"tiers": {"low": "allow"}, "type": "risk_tier"}}}', encoding="utf-8")
    c = tmp_path / "c.yaml"
    c.write_text("tool_policy:\n  base: {type: risk_tier, tiers: {low: deny}}\n", encoding="utf-8")
    va, vb, vc = (load_policies(p).version for p in (a, b, c))
    assert va == vb and va != vc and len(va) == 16

    loaded = load_policies(a)
    sink = InMemoryAuditSink()
    ToolGuard(tool=lambda: 1, policy=loaded.tool_policy, audit_sink=sink, tool_name="t",
              policy_version=loaded.version).call(Principal("p"), {})
    assert sink.tail(1)[0].policy_version == va


def test_flow_wrappers_share_one_tracker_across_surfaces():
    from marshal_ai import Document, Principal, RetrievalGuard, ToolCallDenied, ToolGuard

    loaded = load_policies({
        "retrieval_policy": {"base": {"type": "allow_all"},
                             "wrappers": [{"type": "flow_labels", "default_labels": ["private_data"]}]},
        "tool_policy": {"base": {"type": "allow_all"}, "wrappers": [{"type": "lethal_trifecta", "on_violation": "deny",
                        "tool_capabilities": {"fetch_url": ["untrusted_content"], "send_email": ["external_communication"]}}]},
    })
    assert loaded.flow_tracker is not None
    agent = Principal("agent/s1")
    RetrievalGuard(lambda q, k: [Document("d", "x")], policy=loaded.retrieval_policy).retrieve("q", agent)
    ToolGuard(tool=lambda **kw: 1, policy=loaded.tool_policy, tool_name="fetch_url").call(agent, {})
    with pytest.raises(ToolCallDenied, match="lethal trifecta"):
        ToolGuard(tool=lambda **kw: 1, policy=loaded.tool_policy, tool_name="send_email").call(agent, {})
    # a separate load gets a separate tracker
    assert load_policies({"tool_policy": {"base": {"type": "allow_all"},
                          "wrappers": [{"type": "lethal_trifecta"}]}}).flow_tracker is not loaded.flow_tracker
