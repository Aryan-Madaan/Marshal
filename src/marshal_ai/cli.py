"""A minimal terminal viewer for a JSONL audit log.

This is the "I just want to see what happened, right now, with nothing to
stand up" answer. It is deliberately not a web dashboard — see
`marshal_ai/otel.py` for the "plug into a real dashboard you already run"
answer, which is where production visibility should actually live.

Usage:
    python -m marshal_ai.cli tail audit.jsonl
    python -m marshal_ai.cli tail audit.jsonl -n 20 --principal alice
    python -m marshal_ai.cli tail audit.jsonl --denied-only
    python -m marshal_ai.cli tail audit.jsonl --follow
    python -m marshal_ai.cli approvals list approvals.db
    python -m marshal_ai.cli approvals approve approvals.db apr-1234 --as maria@company
    python -m marshal_ai.cli approvals decline approvals.db apr-1234 --as maria@company --note "not eligible"
    python -m marshal_ai.cli quarantine add quarantine.db tool wire_transfer --as oncall@company --reason "INC-42"
    python -m marshal_ai.cli quarantine list quarantine.db
    python -m marshal_ai.cli health audit.db --window 900
    python -m marshal_ai.cli inventory audit.jsonl            # Mermaid graph
    python -m marshal_ai.cli redteam policies.yaml --send-external send_email --destructive delete_account

`health` and `inventory` read a JSONLAuditSink file or a SQLiteAuditSink
database (`.db`/`.sqlite`). `redteam` exits non-zero when any scenario
fails, so it can gate CI.
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any

from marshal_ai.audit import AuditableEvent, JSONLAuditSink, is_denied


# Audit entries carry attacker-influenced text (queries, tool names,
# reasons echoing model output). Printed raw, an ESC sequence could
# rewrite the terminal, forge earlier lines, or plant an OSC 8 hyperlink;
# bidi and tag characters can make a line read differently than it is.
_UNSAFE_FOR_TERMINAL = re.compile("[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f]")


def _terminal_safe(text: str) -> str:
    return _UNSAFE_FOR_TERMINAL.sub(lambda m: f"\\x{{{ord(m.group()):x}}}", text)


def _summarize(entry: AuditableEvent) -> str:
    data = entry.to_dict()
    kind = data.get("kind", "unknown")
    if kind == "retrieval":
        return (
            f'query={data["query"]!r} allowed={len(data["allowed_ids"])} '
            f'denied={len(data["denied_ids"])}'
        )
    if kind == "tool_call":
        approver = f' by={data["approved_by"]}' if data.get("approved_by") else ""
        return f'tool={data["tool_name"]} outcome={data["outcome"]}{approver} — {data["reason"]}'
    if kind == "model_call":
        return (
            f'{data["logical_name"]} -> {data.get("resolved_model") or "-"} '
            f'({data["outcome"]}) — {data["reason"]}'
        )
    if kind == "model_usage":
        return f'model={data["model"]} prompt={data["prompt_tokens"]} completion={data["completion_tokens"]}'
    if kind == "sensitive_data":
        return f'[{data["surface"]}] {data["location"]}: {data["findings"]} -> {data["action"]}'
    if kind == "egress":
        return f'[{data["surface"]}] {data["location"]}: {data["hosts"]} -> {data["action"]}'
    if kind == "flow_label":
        return f'{data["source"]} added {data["labels_added"]} (now {data["labels_now"]})'
    if kind == "mcp_tool_definition":
        return f'{data["server_id"]}/{data["tool_name"]}: {data["status"]} -> {data["action"]}'
    if kind == "incident":
        return f'{data["incident_id"]} [{data["category"]}] {data["title"]}'
    return str(data)


def _format_row(entry: AuditableEvent) -> str:
    data = entry.to_dict()
    ts = datetime.fromtimestamp(entry.timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    kind = data.get("kind", "unknown")
    flag = "!" if is_denied(entry) else " "
    return _terminal_safe(f"{flag} {ts}  {kind:<12} {entry.principal_id:<12} {_summarize(entry)}")


def _print_entries(entries: list[AuditableEvent]) -> None:
    for entry in entries:
        print(_format_row(entry))


def cmd_tail(args: argparse.Namespace) -> None:
    sink = JSONLAuditSink(args.path)
    entries = sink.query(
        principal_id=args.principal,
        denied_only=args.denied_only,
    )
    _print_entries(entries[-args.n :])

    if not args.follow:
        return

    seen = len(entries)
    print("-- following (Ctrl+C to stop) --", file=sys.stderr)
    try:
        while True:
            time.sleep(args.interval)
            current = sink.query(principal_id=args.principal, denied_only=args.denied_only)
            if len(current) > seen:
                _print_entries(current[seen:])
                seen = len(current)
    except KeyboardInterrupt:
        pass


def cmd_approvals(args: argparse.Namespace) -> None:
    from marshal_ai.approvals import ApprovalQueue

    queue = ApprovalQueue(args.path)
    try:
        if args.action == "list":
            pending = queue.pending()
            if not pending:
                print("no pending approvals")
            for item in pending:
                chain = f" for {'/'.join(item.on_behalf_of)}" if item.on_behalf_of else ""
                left = max(0, int(item.expires_at - time.time()))
                print(_terminal_safe(
                    f"{item.id}  {item.tool_name}  by {item.principal_id}{chain}  tier={item.risk_tier}  "
                    f"expires in {left}s  args={item.redacted_arguments}"
                ))
            return
        if not args.id or not getattr(args, "approver", None):
            raise SystemExit("approve/decline need an approval id and --as <your name>")
        decide = queue.approve if args.action == "approve" else queue.decline
        try:
            result = decide(args.id, approver=args.approver, note=args.note)
        except (KeyError, ValueError) as exc:
            raise SystemExit(_terminal_safe(str(exc)))
        print(_terminal_safe(f"{result.id} {result.status} by {result.decided_by}"))
    finally:
        queue.close()


def _print_safe_lines(text: str) -> None:
    for line in text.splitlines():
        print(_terminal_safe(line))


def _open_sink(path: str):
    if path.endswith((".db", ".sqlite", ".sqlite3")):
        from marshal_ai.sinks import SQLiteAuditSink

        return SQLiteAuditSink(path)
    return JSONLAuditSink(path)


def cmd_quarantine(args: argparse.Namespace) -> None:
    from marshal_ai.quarantine import Quarantine

    q = Quarantine(args.path)
    try:
        if args.action == "list":
            records = q.active()
            if not records:
                print("nothing quarantined")
            for r in records:
                print(_terminal_safe(f"{r.kind:<6} {r.name}  by {r.by}  since "
                                     f"{datetime.fromtimestamp(r.since, tz=timezone.utc):%Y-%m-%d %H:%M} UTC  — {r.reason}"))
            return
        if not (args.kind and args.name and args.by and args.reason):
            raise SystemExit("add/release need: <kind> <name> --as <you> --reason <why>")
        try:
            if args.action == "add":
                q.quarantine(args.kind, args.name, reason=args.reason, by=args.by)
            else:
                q.release(args.kind, args.name, by=args.by, reason=args.reason)
        except (KeyError, ValueError) as exc:
            raise SystemExit(_terminal_safe(str(exc)))
        print(_terminal_safe(f"{args.action}: {args.kind} {args.name}"))
    finally:
        q.close()


def cmd_health(args: argparse.Namespace) -> None:
    from marshal_ai.health import assess, render_health_markdown

    _print_safe_lines(render_health_markdown(assess(_open_sink(args.path), window_seconds=args.window)))


def cmd_inventory(args: argparse.Namespace) -> None:
    from marshal_ai.inventory import build_inventory, render_mermaid

    _print_safe_lines(render_mermaid(build_inventory(_open_sink(args.path))))


def cmd_redteam(args: argparse.Namespace) -> None:
    from marshal_ai.config import load_policies
    from marshal_ai.redteam import RedTeamTargets, render_redteam_markdown, run_redteam

    loaded = load_policies(args.path)  # fail fast on a broken file
    targets = RedTeamTargets(
        send_external=args.send_external, read_untrusted=args.read_untrusted, read_private=args.read_private,
        destructive=args.destructive, destructive_tier=args.destructive_tier, default_tier=args.default_tier,
    )
    report = run_redteam(
        tool_policy=(lambda: load_policies(args.path).tool_policy) if loaded.tool_policy is not None else None,
        retrieval_policy=(lambda: load_policies(args.path).retrieval_policy) if loaded.retrieval_policy is not None else None,
        targets=targets,
    )
    print(render_redteam_markdown(report), end="")
    if not report.passed:
        raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="marshal_ai", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    tail_parser = subparsers.add_parser("tail", help="Print entries from a JSONL audit log")
    tail_parser.add_argument("path", help="Path to the JSONLAuditSink file")
    tail_parser.add_argument("-n", type=int, default=20, help="Show the last N entries (default 20)")
    tail_parser.add_argument("--principal", default=None, help="Filter to one principal id")
    tail_parser.add_argument(
        "--denied-only", action="store_true", help="Show only denied/declined entries"
    )
    tail_parser.add_argument(
        "--follow", action="store_true", help="Keep watching the file for new entries"
    )
    tail_parser.add_argument(
        "--interval", type=float, default=1.0, help="Poll interval in seconds for --follow"
    )
    tail_parser.set_defaults(func=cmd_tail)

    approvals_parser = subparsers.add_parser("approvals", help="Review a marshal_ai.approvals queue")
    approvals_parser.add_argument("action", choices=["list", "approve", "decline"])
    approvals_parser.add_argument("path", help="Path to the ApprovalQueue database")
    approvals_parser.add_argument("id", nargs="?", help="Approval id (approve/decline)")
    approvals_parser.add_argument("--as", dest="approver", help="Who is deciding (recorded in the audit trail)")
    approvals_parser.add_argument("--note", default=None, help="Optional note recorded with the decision")
    approvals_parser.set_defaults(func=cmd_approvals)

    q_parser = subparsers.add_parser("quarantine", help="Quarantine or release a tool, agent or model")
    q_parser.add_argument("action", choices=["add", "release", "list"])
    q_parser.add_argument("path", help="Path to the Quarantine database")
    q_parser.add_argument("kind", nargs="?", choices=["tool", "agent", "model"])
    q_parser.add_argument("name", nargs="?")
    q_parser.add_argument("--as", dest="by", help="Who is acting (recorded)")
    q_parser.add_argument("--reason", help="Why (recorded)")
    q_parser.set_defaults(func=cmd_quarantine)

    h_parser = subparsers.add_parser("health", help="Operational health from an audit trail")
    h_parser.add_argument("path")
    h_parser.add_argument("--window", type=float, default=900.0, help="Trailing window in seconds (default 900)")
    h_parser.set_defaults(func=cmd_health)

    i_parser = subparsers.add_parser("inventory", help="Agents, tools, MCP servers and models as a Mermaid graph")
    i_parser.add_argument("path")
    i_parser.set_defaults(func=cmd_inventory)

    r_parser = subparsers.add_parser("redteam", help="Run the deterministic attack battery against a policy file")
    r_parser.add_argument("path", help="policies.yaml / .json")
    r_parser.add_argument("--send-external")
    r_parser.add_argument("--read-untrusted")
    r_parser.add_argument("--read-private")
    r_parser.add_argument("--destructive")
    r_parser.add_argument("--destructive-tier", default="high")
    r_parser.add_argument("--default-tier", default="low")
    r_parser.set_defaults(func=cmd_redteam)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
