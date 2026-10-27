from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, TYPE_CHECKING

from appsec_review.config import JobConfig, ToolCapabilityConfig
from appsec_review.config.assurance import ComponentReleases, ReviewPolicy
from appsec_review.observability import EventLog
from appsec_review.runtime.datasets import DatasetDeclaration, validate_declarations

if TYPE_CHECKING:
    from appsec_review.runtime.units import Unit


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
    tools: ToolCapabilityConfig = ToolCapabilityConfig()
    target_root: Path | None = None
    source_fingerprint: str = "none"
    input_manifest_path: Path | None = None
    input_manifest_sha256: str | None = None
    review_policy: ReviewPolicy = ReviewPolicy()
    # Authenticated evidence identity, not permission to read a target checkout.
    evidence_target_snapshot: str | None = None


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
    # Legacy callbacks are not invoked; identities() uses operator declarations only.
    runtime_identity: Callable[[Path], str] | None = None
    units: tuple["Unit", ...] = ()
    result_transform: Callable[[JobContext, Mapping[str, Any]], Mapping[str, Any]] | None = None
    worker_lookup: Callable[[str, str], int] | None = None
    # Cheap deterministic identity of job inputs the target fingerprint does not cover, such as
    # version-control history. Recorded in the handoff and re-probed by resume planning.
    input_identity: Callable[[Path | None], str] | None = None
    # Publication contract: every output kind this job may emit, and the accepted upstream jobs
    # whose handoffs it reads. The dataset audit compares both with what a run actually produced.
    datasets: tuple[DatasetDeclaration, ...] = ()
    consumes: tuple[str, ...] = ()
    # Live readiness gates must execute for every graph dispatch, even when the application run
    # can otherwise reuse accepted work.  A non-propagating gate orders downstream jobs without
    # becoming part of their immutable input identity.
    always_execute: bool = False
    propagate_handoff: bool = True

    def __post_init__(self) -> None:
        validate_declarations(self.job_id, self.datasets)
        if self.job_id in self.consumes or len(self.consumes) != len(set(self.consumes)):
            raise ValueError(f"job consumes itself or repeats an upstream job: {self.job_id}")

    def probe_input_identity(self, target_root: Path | None) -> str | None:
        return self.input_identity(target_root) if self.input_identity is not None else None

    def configured_workers(self, step_id: str, task_id: str) -> int:
        return self.worker_lookup(step_id, task_id) if self.worker_lookup is not None else 1

    def finalize_result(self, context: JobContext, result: Mapping[str, Any]) -> Mapping[str, Any]:
        return self.result_transform(context, result) if self.result_transform is not None else result

    def identities(self, repository_root: Path, releases: ComponentReleases | None = None) -> Mapping[str, str]:
        declared = releases.values if releases is not None else {}
        return {
            "implementation": declared.get(self.job_id, declared.get("platform", "undeclared")),
            "schema": self.schema_identity,
            "validation": declared.get("validation", "undeclared"),
        }

    def execute(self, context: JobContext) -> Mapping[str, Any]:
        for validator in self.input_validators:
            validator(context, None)
        result = self.finalize_result(context, self.handler(context))
        for validator in self.output_validators:
            validator(context, result)
        return result
