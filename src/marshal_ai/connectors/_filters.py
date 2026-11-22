"""Translate Marshal's neutral pushdown filter into each store's dialect.

Policies express pushdown (`Policy.to_filter`) in one small, Mongo-style
dialect — the shape `GroupPolicy` produces:

    {"group": "hr"}                          # equality
    {"group": {"$eq": "hr"}}                 # equality
    {"group": {"$in": ["hr", "finance"]}}    # membership
    {"$and": [{...}, {...}]}                 # conjunction (also: several keys)

`parse_filter` turns that into a flat list of `Clause`s each connector
compiles into its native filter. Two rules keep this safe:

- Only scalar values (str, int, float, bool) are accepted. A value that is
  itself a dict or list-of-dicts is rejected, so nothing a principal or
  document controls can ever be smuggled through as a store operator
  (e.g. a MongoDB `{"$ne": ...}`).
- Anything outside the dialect raises `UnsupportedFilter`; connectors
  then skip pushdown rather than guess. That is always safe:
  `RetrievalGuard` re-evaluates every returned document against the
  policy regardless (pushdown is an optimization, never the enforcement).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal, Optional

Scalar = "str | int | float | bool"
_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*)*$")


class UnsupportedFilter(ValueError):
    """The filter uses something outside Marshal's pushdown dialect."""


@dataclass(frozen=True)
class Clause:
    field: str
    op: Literal["eq", "in"]
    values: tuple[Any, ...]  # one value for "eq"


def _scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) and value is not None


def _field(name: Any) -> str:
    if not isinstance(name, str) or not _FIELD.match(name):
        raise UnsupportedFilter(f"field name {name!r} is not a plain (optionally dotted) identifier")
    return name


def parse_filter(filter: Optional[dict[str, Any]]) -> list[Clause]:
    if not filter:
        return []
    if not isinstance(filter, dict):
        raise UnsupportedFilter(f"filter must be a dict, got {type(filter).__name__}")
    clauses: list[Clause] = []
    for key, value in filter.items():
        if key == "$and":
            if not isinstance(value, list) or not value:
                raise UnsupportedFilter("$and needs a non-empty list")
            for part in value:
                clauses.extend(parse_filter(part))
            continue
        name = _field(key)
        if _scalar(value):
            clauses.append(Clause(name, "eq", (value,)))
        elif isinstance(value, dict) and len(value) == 1:
            ((op, operand),) = value.items()
            if op == "$eq" and _scalar(operand):
                clauses.append(Clause(name, "eq", (operand,)))
            elif op == "$in" and isinstance(operand, (list, tuple)) and operand and all(map(_scalar, operand)):
                clauses.append(Clause(name, "in", tuple(operand)))
            else:
                raise UnsupportedFilter(f"unsupported condition {op!r} on {name!r}")
        else:
            raise UnsupportedFilter(f"unsupported condition on {name!r}")
    return clauses


def try_parse(filter: Optional[dict[str, Any]]) -> Optional[list[Clause]]:
    """`parse_filter`, or None when the filter can't be pushed down."""
    try:
        return parse_filter(filter)
    except UnsupportedFilter:
        return None


def prefixed(field: str, prefix: Optional[str]) -> str:
    return f"{prefix}.{field}" if prefix else field
