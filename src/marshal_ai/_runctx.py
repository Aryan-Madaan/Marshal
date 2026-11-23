"""The current agent run, as context variables — the one piece of state
every audit entry type reads (see `marshal_ai.runs`). Kept in its own
dependency-free module so `audit.py` and every entry module can import it
without import cycles."""

from __future__ import annotations

import contextvars
from typing import Optional

_RUN_ID: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("marshal_run_id", default=None)
_PARENT_RUN_ID: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("marshal_parent_run_id", default=None)


def current_run_id() -> Optional[str]:
    return _RUN_ID.get()


def current_parent_run_id() -> Optional[str]:
    return _PARENT_RUN_ID.get()
