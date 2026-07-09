from marshal_ai.audit import JSONLAuditSink
from marshal_ai.cli import build_parser, main
from marshal_ai.models import AllowlistModelPolicy, ModelCandidate, ModelGuard
from marshal_ai.policy import Principal
from marshal_ai.retrieval import Document, RetrievalGuard
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


def test_parser_requires_a_subcommand():
    parser = build_parser()
    args = parser.parse_args(["tail", "somefile.jsonl"])
    assert args.command == "tail"
    assert args.path == "somefile.jsonl"
    assert args.n == 20
    assert args.follow is False
