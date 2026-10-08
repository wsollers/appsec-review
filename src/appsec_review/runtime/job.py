from __future__ import annotations

from dataclasses import dataclass
import hashlib
import inspect
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
    metadata_root: Path
    orchestration: Mapping[str, str]
    config: JobConfig
    events: EventLog
    target_root: Path | None = None
    source_fingerprint: str = "none"


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
    schema_identity: str = "appsec-review/job-result/1"
    implementation_identity: str | None = None
    validation_identity: str | None = None

    def identities(self) -> Mapping[str, str]:
        def identity(values: tuple[object, ...], explicit: str | None = None) -> str:
            digest = hashlib.sha256()
            if explicit is not None:
                digest.update(explicit.encode())
            for value in values:
                value = getattr(value, "__func__", value)
                try:
                    payload = inspect.getsource(value).encode()
                except (OSError, TypeError):
                    payload = repr(value).encode()
                digest.update(payload)
            return digest.hexdigest()
        return {
            "implementation": identity((self.handler, Job.execute), self.implementation_identity),
            "schema": self.schema_identity,
            "validation": identity((*self.input_validators, *self.output_validators), self.validation_identity),
        }

    def execute(self, context: JobContext) -> Mapping[str, Any]:
        for validator in self.input_validators:
            validator(context, None)
        result = self.handler(context)
        for validator in self.output_validators:
            validator(context, result)
        return result
