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
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone
from typing import Any

from marshal_ai.audit import AuditableEvent, JSONLAuditSink, is_denied


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
    return str(data)


def _format_row(entry: AuditableEvent) -> str:
    data = entry.to_dict()
    ts = datetime.fromtimestamp(entry.timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    kind = data.get("kind", "unknown")
    flag = "!" if is_denied(entry) else " "
    return f"{flag} {ts}  {kind:<12} {entry.principal_id:<12} {_summarize(entry)}"


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

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
