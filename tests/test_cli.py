from marshal_ai.audit import JSONLAuditSink
from marshal_ai.cli import build_parser, main
from marshal_ai.models import AllowlistModelPolicy, ModelCandidate, ModelGuard
from marshal_ai.policy import AttributePolicy, Principal
from marshal_ai.retrieval import Document, RetrievalGuard
from marshal_ai.sensitive import SensitiveDataPolicy
from marshal_ai.tools import RiskTierPolicy, ToolCallDenied, ToolGuard


def _populate(path):
    sink = JSONLAuditSink(path)
    alice = Principal(id="alice")
    bob = Principal(id="bob")

    RetrievalGuard(retriever=lambda q, k: [Document(id="1", content="a")], audit_sink=sink).retrieve(
        "q", principal=alice, k=1
    )

    guard = ToolGuard(
        tool=lambda **kw: None,
        policy=RiskTierPolicy({"high": "deny"}),
        audit_sink=sink,
        tool_name="delete_record",
    )
    try:
        guard.call(bob, {}, risk_tier="high")
    except ToolCallDenied:
        pass

    ModelGuard(
        policy=AllowlistModelPolicy({"m": [ModelCandidate("gpt-fast")]}), audit_sink=sink
    ).resolve(alice, "m")


def test_tail_prints_all_entries_by_default(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    _populate(path)

    main(["tail", str(path)])

    out = capsys.readouterr().out
    assert "retrieval" in out
    assert "tool_call" in out
    assert "model_call" in out
    assert "alice" in out
    assert "bob" in out


def test_tail_filters_by_principal(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    _populate(path)

    main(["tail", str(path), "--principal", "bob"])

    out = capsys.readouterr().out
    assert "bob" in out
    assert "alice" not in out


def test_tail_denied_only_excludes_the_allowed_model_call(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    _populate(path)

    main(["tail", str(path), "--denied-only"])

    out = capsys.readouterr().out
    assert "tool_call" in out
    assert "model_call" not in out


def test_tail_respects_n_limit(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    _populate(path)  # writes 3 entries

    main(["tail", str(path), "-n", "1"])

    lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
    assert len(lines) == 1


def test_denied_rows_are_flagged_and_allowed_rows_are_not(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    _populate(path)

    main(["tail", str(path)])

    lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
    flagged = {l[0] for l in lines}
    assert "!" in flagged  # the denied tool call
    assert " " in flagged  # the allowed retrieval / model call


def test_tail_shows_sensitive_data_entries_flagged_when_blocked(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    sink = JSONLAuditSink(path)
    policy = SensitiveDataPolicy(base=AttributePolicy(default="allow"), audit_sink=sink)
    RetrievalGuard(
        retriever=lambda q, k: [Document(id="1", content="reach bob@example.com")],
        policy=policy,
        audit_sink=sink,
    ).retrieve("q", principal=Principal(id="alice"), k=1)

    main(["tail", str(path)])

    out = capsys.readouterr().out
    assert "sensitive_data" in out
    assert "EMAIL:1" in out
    assert "redacted" in out


def test_parser_requires_a_subcommand():
    parser = build_parser()
    args = parser.parse_args(["tail", "somefile.jsonl"])
    assert args.command == "tail"
    assert args.path == "somefile.jsonl"
    assert args.n == 20
    assert args.follow is False


def test_untrusted_text_cannot_inject_terminal_escapes(tmp_path, capsys):
    from marshal_ai import JSONLAuditSink, Principal, ToolGuard
    from marshal_ai.cli import main

    path = tmp_path / "audit.jsonl"
    sink = JSONLAuditSink(path)
    hostile = "lookup\x1b[2J\x1b]8;;https://evil.example\x07click\x1b]8;;\x07\nFORGED ROW‮"
    ToolGuard(tool=lambda **kw: 1, audit_sink=sink, tool_name=hostile).call(Principal(id="a"), {})

    main(["tail", str(path)])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out and "‮" not in out
    assert out.count("\n") == 1  # the embedded newline did not forge a second row
    assert "\\x{1b}" in out


def test_approvals_cli_lists_and_decides(tmp_path, capsys):
    import pytest

    from marshal_ai import Principal, RiskTierPolicy, ToolGuard
    from marshal_ai.approvals import ApprovalQueue, QueuedApprovalHandler
    from marshal_ai.cli import main
    from marshal_ai.tools import ApprovalPending

    db = tmp_path / "approvals.db"
    guard = ToolGuard(
        tool=lambda **kw: "done", policy=RiskTierPolicy({"medium": "require_approval"}),
        approval_handler=QueuedApprovalHandler(ApprovalQueue(db)), tool_name="wire\x1b[31m_transfer",
    )
    with pytest.raises(ApprovalPending) as pending:
        guard.call(Principal("agent"), {"amount": 10}, risk_tier="medium")

    main(["approvals", "list", str(db)])
    listed = capsys.readouterr().out
    assert pending.value.approval_id in listed and "\x1b" not in listed

    main(["approvals", "approve", str(db), pending.value.approval_id, "--as", "maria"])
    assert "approved by maria" in capsys.readouterr().out
    assert guard.call(Principal("agent"), {"amount": 10}, risk_tier="medium") == "done"

    with pytest.raises(SystemExit):
        main(["approvals", "approve", str(db), pending.value.approval_id, "--as", "maria"])  # already used


def test_quarantine_health_inventory_and_redteam_commands(tmp_path, capsys):
    import json

    import pytest

    from marshal_ai import JSONLAuditSink, Principal, ToolGuard
    from marshal_ai.cli import main

    q = str(tmp_path / "q.db")
    main(["quarantine", "add", q, "tool", "wire_transfer", "--as", "oncall", "--reason", "INC-42"])
    main(["quarantine", "list", q])
    assert "wire_transfer" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main(["quarantine", "add", q, "tool", "x"])  # no --as / --reason
    main(["quarantine", "release", q, "tool", "wire_transfer", "--as", "oncall", "--reason", "fixed"])
    capsys.readouterr()

    audit = tmp_path / "audit.jsonl"
    guard = ToolGuard(tool=lambda **kw: 1, audit_sink=JSONLAuditSink(audit), tool_name="lookup\x1b[2J", audit_outcomes=True)
    for _ in range(6):
        guard.call(Principal("agent-1"), {})
    main(["health", str(audit)])
    out = capsys.readouterr().out
    assert "| healthy | tool |" in out and "\x1b" not in out
    main(["inventory", str(audit)])
    assert capsys.readouterr().out.startswith("graph LR")

    weak = tmp_path / "weak.json"
    weak.write_text(json.dumps({"tool_policy": {"base": {"type": "allow_all"}}}))
    with pytest.raises(SystemExit) as failed:
        main(["redteam", str(weak), "--send-external", "send_email"])
    assert failed.value.code == 1 and "FAIL" in capsys.readouterr().out
