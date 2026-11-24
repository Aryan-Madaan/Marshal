"""Output-quality evaluation: a plug-in point, not a judge.

    from marshal_ai.evals import evaluate, record_evaluation

    def cites_a_source(output, context):            # any callable scorer
        return "[source:" in output

    with agent_run(sink, task="answer-policy-question"):
        answer = agent.run(question)
        evaluate(sink, {"cites_source": cites_a_source, "grounded": my_llm_judge}, answer,
                 context={"documents": docs})

Governance answers "was the agent *allowed* to do that"; it can't answer
"was the answer any good". Quality scorers can — groundedness checks,
task-completion checks, format validators, a model-based judge — but
they are domain-specific and, when model-based, non-deterministic, so
Marshal ships none of them by default. What it provides is the place
their results land:

- **One trail.** Each result is an `EvaluationEntry` in the same audit
  sink, tied to the current `agent_run` (and so to its task type), so a
  failing answer sits next to the retrievals and tool calls that produced
  it.
- **It feeds the rest.** `assess()` reports a `task` subject whose
  status comes from the evaluation pass rate; `run_costs()` reports cost
  per *passing* run, not just per completed one; alerts fire on both.
- **Content stays out.** The output and context are handed to the
  scorer and never written to the trail — only the scorer name, the
  pass/fail, an optional numeric score and, if the scorer crashed, the
  exception type.
- **A broken scorer fails, visibly.** A scorer that raises is recorded as
  `passed=False` with its error type, not skipped: a silently missing
  quality signal reads as "everything's fine".

A scorer returns a `bool`, a number in [0, 1] (passed when
>= `pass_threshold`), or a `Score(passed, score)`. Never use an
evaluation result to authorize anything: a model-based judge can be
steered by the same content it's judging. Evaluations are for people
deciding whether an agent is working, not for the agent's own gates.
"""

from __future__ import annotations

import math
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Mapping, Optional, Union

from marshal_ai._runctx import current_parent_run_id, current_run_id
from marshal_ai.audit import AuditSink, register_entry_type

__all__ = ["EvaluationEntry", "Score", "evaluate", "record_evaluation"]


@dataclass(frozen=True)
class Score:
    passed: bool
    score: Optional[float] = None


ScorerResult = Union[bool, float, int, Score]
Scorer = Callable[[Any, Mapping[str, Any]], ScorerResult]


@dataclass(frozen=True)
class EvaluationEntry:
    """One scorer's verdict on one output. `task` is optional: when it's
    left empty, reports take the task from the enclosing `agent_run`."""

    timestamp: float
    principal_id: str
    scorer: str
    passed: bool
    score: Optional[float] = None
    task: Optional[str] = None
    error: Optional[str] = None  # exception type name if the scorer crashed
    on_behalf_of: list[str] = field(default_factory=list)
    run_id: Optional[str] = field(default_factory=current_run_id)
    parent_run_id: Optional[str] = field(default_factory=current_parent_run_id)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "evaluation", **asdict(self)}


register_entry_type("evaluation", EvaluationEntry)


def record_evaluation(
    sink: AuditSink,
    scorer: str,
    passed: bool,
    score: Optional[float] = None,
    principal_id: str = "-",
    task: Optional[str] = None,
    run_id: Optional[str] = None,
) -> EvaluationEntry:
    """Record a verdict produced elsewhere (an offline eval job, a human
    review, a user's thumbs-down). `run_id` defaults to the current run."""
    if not scorer:
        raise ValueError("scorer name is required")
    if score is not None and not (isinstance(score, (int, float)) and math.isfinite(score)):
        raise ValueError("score must be a finite number")
    kwargs: dict[str, Any] = {} if run_id is None else {"run_id": run_id, "parent_run_id": None}
    entry = EvaluationEntry(
        timestamp=time.time(), principal_id=principal_id, scorer=scorer, passed=bool(passed),
        score=None if score is None else float(score), task=task, **kwargs,
    )
    sink.write(entry)
    return entry


def _verdict(result: Any, pass_threshold: float) -> tuple[bool, Optional[float]]:
    if isinstance(result, Score):
        return bool(result.passed), result.score
    if isinstance(result, bool):
        return result, None
    if isinstance(result, (int, float)) and math.isfinite(result):
        return result >= pass_threshold, float(result)
    raise TypeError(f"scorer returned {type(result).__name__}; expected bool, a number or Score")


def evaluate(
    sink: AuditSink,
    scorers: Mapping[str, Scorer],
    output: Any,
    context: Optional[Mapping[str, Any]] = None,
    principal_id: str = "-",
    task: Optional[str] = None,
    pass_threshold: float = 0.5,
) -> list[EvaluationEntry]:
    """Run each scorer on `output` and record its verdict. Returns the
    entries written; `all(e.passed for e in ...)` is the overall verdict."""
    ctx: Mapping[str, Any] = context or {}
    written = []
    for name, scorer in scorers.items():
        try:
            passed, score = _verdict(scorer(output, ctx), pass_threshold)
            error = None
        except Exception as exc:  # a crashing scorer is a failed check, never a skipped one
            passed, score, error = False, None, type(exc).__name__
        entry = EvaluationEntry(
            timestamp=time.time(), principal_id=principal_id, scorer=name, passed=passed,
            score=score, task=task, error=error,
        )
        sink.write(entry)
        written.append(entry)
    return written
