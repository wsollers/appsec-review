from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from appsec_review.config import JobConfig
from appsec_review.observability import EventLog


@dataclass(frozen=True, slots=True)
class JobContext:
    run_id: str
    attempt_id: str
    trigger: str
    repository_root: Path
    run_root: Path
    attempt_root: Path
    config: JobConfig
    events: EventLog


class JobHandler(Protocol):
    def __call__(self, context: JobContext) -> Mapping[str, Any]: ...


class JobValidator(Protocol):
    def __call__(self, context: JobContext, result: Mapping[str, Any] | None) -> None: ...


@dataclass(frozen=True, slots=True)
class Job:
    """A lifecycle assembled from one handler and explicit validator lists."""

    job_id: str
    name: str
    handler: JobHandler
    input_validators: tuple[JobValidator, ...] = ()
    output_validators: tuple[JobValidator, ...] = ()

    def execute(self, context: JobContext) -> Mapping[str, Any]:
        for validator in self.input_validators:
            validator(context, None)
        result = self.handler(context)
        for validator in self.output_validators:
            validator(context, result)
        return result
