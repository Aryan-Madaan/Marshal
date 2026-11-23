"""What is actually running, what it depends on, and what it costs —
derived from the audit trail, not from a registry someone has to keep
up to date.

    from marshal_ai.inventory import build_inventory, render_mermaid, run_costs

    inv = build_inventory(sink)
    print(render_mermaid(inv))                      # agents -> tools / MCP servers / models / subjects
    for task in run_costs(sink, pricing).by_task:   # cost per *successful* run, per task type
        print(task)

`build_inventory` answers "which agents exist, which tools and models
does each one actually use, through which MCP servers, and on whose
behalf" from what the guards recorded — so it can't drift from reality,
and a tool nobody registered still shows up the first time it's called.
The graph is also a blast-radius map: quarantine a tool or an MCP server
and the agents that depend on it are one hop away.

`run_costs` joins `ModelUsageEntry` token counts to `agent_run` markers
(`marshal_ai.runs`), so spend is attributed per run and per task type,
and cost per *successful* run — the number that says whether an agent is
worth what it costs — falls out directly.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from marshal_ai.audit import AuditSink, is_denied

__all__ = ["Inventory", "RunCost", "RunCostReport", "TaskCost", "build_inventory", "render_mermaid", "run_costs"]


@dataclass(frozen=True)
class Edge:
    source: str  # "agent:<id>"
    target: str  # "tool:<name>" | "mcp:<server>" | "model:<name>" | "subject:<id>"
    relation: str  # "calls" | "via" | "resolves" | "acts_for"
    count: int
    denied: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Inventory:
    agents: list[str]
    tools: list[str]
    mcp_servers: list[str]
    models: list[str]
    subjects: list[str]
    edges: list[Edge] = field(default_factory=list)

    def dependents_of(self, node: str) -> list[str]:
        """Agents that depend on `node` (e.g. "tool:wire_transfer",
        "mcp:billing", "model:gpt-5") — the blast radius of quarantining it."""
        return sorted({e.source.split(":", 1)[1] for e in self.edges if e.target == node})

    def to_dict(self) -> dict[str, Any]:
        return {**{k: v for k, v in asdict(self).items() if k != "edges"}, "edges": [e.to_dict() for e in self.edges]}


def build_inventory(sink: AuditSink, since: Optional[float] = None) -> Inventory:
    counts: dict[tuple[str, str, str], list[int]] = defaultdict(lambda: [0, 0])

    def add(source: str, target: str, relation: str, denied: bool) -> None:
        bucket = counts[(source, target, relation)]
        bucket[0] += 1
        bucket[1] += int(denied)

    for entry in sink.query(since=since):
        data = entry.to_dict()
        kind = data["kind"]
        agent = f"agent:{entry.principal_id}"
        denied = is_denied(entry)
        if kind == "tool_call":
            add(agent, f"tool:{data['tool_name']}", "calls", denied)
            if data.get("mcp_server"):
                add(f"tool:{data['tool_name']}", f"mcp:{data['mcp_server']}", "via", denied)
        elif kind == "model_call":
            add(agent, f"model:{data.get('resolved_model') or data['logical_name']}", "resolves", denied)
        else:
            continue
        for subject in data.get("on_behalf_of") or []:
            add(agent, f"subject:{subject}", "acts_for", False)

    edges = [Edge(s, t, r, c, d) for (s, t, r), (c, d) in sorted(counts.items())]
    nodes = {n for e in edges for n in (e.source, e.target)}

    def of(prefix: str) -> list[str]:
        return sorted(n.split(":", 1)[1] for n in nodes if n.startswith(prefix + ":"))

    return Inventory(of("agent"), of("tool"), of("mcp"), of("model"), of("subject"), edges)


def _node_id(node: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", node)


def render_mermaid(inventory: Inventory) -> str:
    """A Mermaid `graph LR` of the inventory. Node labels are escaped, so
    an agent or tool name can't inject Mermaid syntax."""
    shape = {"agent": ("([", "])"), "tool": ("[", "]"), "mcp": ("[(", ")]"), "model": ("{{", "}}"), "subject": ("((", "))")}
    lines = ["graph LR"]
    nodes = sorted({n for e in inventory.edges for n in (e.source, e.target)})
    for node in nodes:
        kind, name = node.split(":", 1)
        left, right = shape.get(kind, ("[", "]"))
        label = re.sub(r'["<>`\[\](){}|]', "_", f"{kind}: {name}")
        lines.append(f'    {_node_id(node)}{left}"{label}"{right}')
    for e in inventory.edges:
        note = f"{e.relation} x{e.count}" + (f", {e.denied} denied" if e.denied else "")
        lines.append(f"    {_node_id(e.source)} -->|{note}| {_node_id(e.target)}")
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class RunCost:
    run_id: str
    task: Optional[str]
    status: Optional[str]
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float
    unpriced_models: list[str]


@dataclass(frozen=True)
class TaskCost:
    task: str
    runs: int
    successful_runs: int
    success_rate: Optional[float]
    total_cost_usd: float
    cost_per_successful_run_usd: Optional[float]


@dataclass(frozen=True)
class RunCostReport:
    runs: list[RunCost]
    by_task: list[TaskCost]
    unattributed_cost_usd: float  # usage recorded outside any run

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_costs(sink: AuditSink, pricing: dict[str, tuple[float, float]]) -> RunCostReport:
    """`pricing` uses the same shape as `BudgetPolicy`: model -> (USD per
    1K prompt tokens, USD per 1K completion tokens). Usage on a model with
    no price counts toward tokens but not cost, and is listed per run.
    A sub-run's spend is attributed to its own run, and its parent's task
    via `parent_run_id` isn't double-counted."""
    meta: dict[str, dict[str, Any]] = {}
    usage: dict[Optional[str], list[Any]] = defaultdict(list)
    for entry in sink.all_entries():
        data = entry.to_dict()
        if data["kind"] == "agent_run":
            m = meta.setdefault(data["run_id"], {"task": None, "status": None})
            m["task"] = m["task"] or data.get("task")
            if data["phase"] == "end":
                m["status"] = data.get("status")
        elif data["kind"] == "model_usage":
            usage[data.get("run_id")].append(data)

    def price(rows: list[dict[str, Any]]) -> tuple[int, int, float, list[str]]:
        p = c = 0
        cost = 0.0
        unpriced: set[str] = set()
        for row in rows:
            p += row["prompt_tokens"]
            c += row["completion_tokens"]
            if row["model"] in pricing:
                rp, rc = pricing[row["model"]]
                cost += row["prompt_tokens"] / 1000 * rp + row["completion_tokens"] / 1000 * rc
            else:
                unpriced.add(row["model"])
        return p, c, cost, sorted(unpriced)

    runs = []
    for run_id, m in meta.items():
        p, c, cost, unpriced = price(usage.get(run_id, []))
        runs.append(RunCost(run_id, m["task"], m["status"], p, c, round(cost, 6), unpriced))

    tasks: dict[str, list[RunCost]] = defaultdict(list)
    for run in runs:
        tasks[run.task or "(untasked)"].append(run)
    by_task = []
    for task, items in sorted(tasks.items()):
        total = sum(r.cost_usd for r in items)
        ok = sum(1 for r in items if r.status == "completed")
        finished = sum(1 for r in items if r.status is not None)
        by_task.append(TaskCost(
            task=task, runs=len(items), successful_runs=ok,
            success_rate=ok / finished if finished else None,
            total_cost_usd=round(total, 6),
            cost_per_successful_run_usd=round(total / ok, 6) if ok else None,
        ))
    _, _, loose, _ = price(usage.get(None, []))
    return RunCostReport(sorted(runs, key=lambda r: r.run_id), by_task, round(loose, 6))
