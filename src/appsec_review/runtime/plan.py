from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, TYPE_CHECKING

from appsec_review.runtime.job import Job

if TYPE_CHECKING:
    from appsec_review.config import AppConfig


@dataclass(frozen=True, slots=True)
class PlanNode:
    """One application-owned execution unit exposed to an orchestrator."""

    node_id: str
    job_id: str
    unit_id: str
    step_id: str
    task_id: str
    dependencies: tuple[str, ...]
    workers: int
    pool: str


@dataclass(frozen=True, slots=True)
class ExecutionPlan:
    """A deterministic typed DAG; handlers and validators remain on ``Job``/``Unit``."""

    jobs: tuple[str, ...]
    nodes: tuple[PlanNode, ...]

    def __post_init__(self) -> None:
        ids = {node.node_id for node in self.nodes}
        if len(ids) != len(self.nodes):
            raise ValueError("execution plan node ids must be unique")
        missing = {dependency for node in self.nodes for dependency in node.dependencies} - ids
        if missing:
            raise ValueError(f"execution plan has unknown dependencies: {sorted(missing)}")

    def node(self, node_id: str) -> PlanNode:
        for node in self.nodes:
            if node.node_id == node_id:
                return node
        raise KeyError(f"execution plan node is unavailable: {node_id}")


def plan_jobs(jobs: Iterable[Job], config: "AppConfig | None" = None) -> ExecutionPlan:
    values = tuple(jobs)
    nodes: list[PlanNode] = []
    prior_final: str | None = None
    for job in values:
        if not job.units:
            raise ValueError(f"job does not expose execution units: {job.job_id}")
        begin_id = f"{job.job_id}.__begin__"
        finalize_id = f"{job.job_id}.__finalize__"
        nodes.append(PlanNode(begin_id, job.job_id, "__begin__", "lifecycle", "begin",
                              (prior_final,) if prior_final else (), 1, "lifecycle"))
        for unit in job.units:
            step_id, task_id = unit.unit_id.split(".")
            dependencies = tuple(f"{job.job_id}.{dependency}" for dependency in unit.dependencies)
            if not dependencies:
                dependencies = (begin_id,)
            workers = (config.job(job.job_id).step(step_id).task(task_id).workers
                       if config is not None else job.configured_workers(step_id, task_id))
            nodes.append(PlanNode(f"{job.job_id}.{unit.unit_id}", job.job_id, unit.unit_id,
                                  step_id, task_id, dependencies, workers, step_id))
        leaves = tuple(
            f"{job.job_id}.{unit.unit_id}" for unit in job.units
            if not any(unit.unit_id in other.dependencies for other in job.units)
        )
        nodes.append(PlanNode(finalize_id, job.job_id, "__finalize__", "lifecycle", "finalize",
                              leaves or (begin_id,), 1, "lifecycle"))
        prior_final = finalize_id
    return ExecutionPlan(tuple(job.job_id for job in values), tuple(nodes))
