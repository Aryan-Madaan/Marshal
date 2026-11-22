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

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
