"""Small common boundary for bootstrap jobs.

The mature pipeline lifecycle remains in place while jobs migrate.  This boundary deliberately owns
only stable identity, typed parameters, handler execution, semantic validation, and terminal results;
it does not duplicate Dagster scheduling or the existing evidence publication state machine.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Generic, Mapping, Protocol, TypeVar


Parameters = TypeVar("Parameters")
Output = TypeVar("Output")


@dataclass(frozen=True)
class JobContext:
    run_id: str
    run_root: Path
    attempt_root: Path


@dataclass(frozen=True)
class JobResult(Generic[Output]):
    status: str
    output: Output | None
    error: str | None = None


class JobHandler(Protocol[Parameters, Output]):
    def __call__(self, context: JobContext, parameters: Parameters) -> Output: ...


class JobValidator(Protocol[Output]):
    def __call__(self, context: JobContext, output: Output) -> None: ...


@dataclass(frozen=True)
class JobSpec(Generic[Parameters, Output]):
    job_id: str
    configuration_namespace: str
    resource_class: str
    handler: JobHandler[Parameters, Output]
    validator: JobValidator[Output]


class JobRuntime:
    """Execute a registered handler and validate before returning a publishable result."""

    def __init__(self, specs: Mapping[str, JobSpec[Any, Any]]):
        self._specs = dict(specs)
        if len(self._specs) != len(specs):
            raise ValueError("duplicate job identity")
        for job_id, spec in self._specs.items():
            if job_id != spec.job_id:
                raise ValueError(f"job registry key {job_id!r} diverges from spec identity {spec.job_id!r}")

    def spec(self, job_id: str) -> JobSpec[Any, Any]:
        try:
            return self._specs[job_id]
        except KeyError:
            raise ValueError(f"unknown job identity {job_id!r}") from None

    def execute(self, job_id: str, context: JobContext, parameters: Any) -> JobResult[Any]:
        spec = self.spec(job_id)
        try:
            output = spec.handler(context, parameters)
            spec.validator(context, output)
        except Exception as exc:
            return JobResult("FAILED", None, f"{type(exc).__name__}: {exc}")
        return JobResult("OK", output)
