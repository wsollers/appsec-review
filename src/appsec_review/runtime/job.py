from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol, TYPE_CHECKING

from appsec_review.config import JobConfig, ToolCapabilityConfig
from appsec_review.config.assurance import ComponentReleases, ReviewPolicy
from appsec_review.observability import EventLog
from appsec_review.runtime.datasets import DatasetDeclaration, validate_declarations
from appsec_review.runtime.contracts import JobContract

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
    upstream_handoffs: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    contract: JobContract | None = None
    external_input_selection: Mapping[str, Any] | None = None


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
    # Legacy callbacks are not invoked; release manifests are computed at build time.
    runtime_identity: Callable[[Path], str] | None = None
    units: tuple["Unit", ...] = ()
    result_transform: Callable[[JobContext, Mapping[str, Any]], Mapping[str, Any]] | None = None
    worker_lookup: Callable[[str, str], int] | None = None
    # Cheap deterministic identity of job inputs the target fingerprint does not cover, such as
    # version-control history. Recorded in the handoff and re-probed by resume planning.
    input_identity: Callable[[Path | None], str] | None = None
    # Source discovery may also need the accepted, bounded catalog of this run.
    run_input_identity: Callable[[Path | None, Path], str] | None = None
    # A closed external-input-selection/1 document, frozen with its hash before execution.
    external_input_identity: Callable[[Path | None, Path, Path], str] | None = None
    # Publication contract: every output kind this job may emit, and the accepted upstream jobs
    # whose handoffs it reads. The dataset audit compares both with what a run actually produced.
    datasets: tuple[DatasetDeclaration, ...] = ()
    consumes: tuple[str, ...] = ()
    # When set, every gap a unit reports must be a producer-gap/1 record (interchange.producer_gap);
    # free text and ad-hoc records are rejected before the result is written. Jobs opt in as they
    # migrate; tests/test_gap_contract.py keeps the list of jobs still allowed free-text gaps.
    strict_gaps: bool = False
    # Live readiness gates must execute for every graph dispatch, even when the application run
    # can otherwise reuse accepted work.  A non-propagating gate orders downstream jobs without
    # becoming part of their immutable input identity.
    always_execute: bool = False
    propagate_handoff: bool = True
    contract: JobContract | None = None

    def __post_init__(self) -> None:
        validate_declarations(self.job_id, self.datasets)
        if self.contract is not None:
            self.contract.validate(self.job_id)
            if self.consumes and self.consumes != self.contract.consumes:
                raise ValueError(f"legacy consumes differs from typed contract: {self.job_id}")
            object.__setattr__(self, "consumes", self.contract.consumes)
            object.__setattr__(self, "always_execute", self.contract.always_execute)
            object.__setattr__(self, "propagate_handoff", self.contract.propagate_handoff)
            if (any(item.channel.value != "handoff" for item in self.contract.inputs)
                    and not self.always_execute and self.external_input_identity is None
                    and self.run_input_identity is None and self.input_identity is None):
                raise ValueError(f"external inputs require an identity probe or fresh execution: {self.job_id}")
        if self.job_id in self.consumes or len(self.consumes) != len(set(self.consumes)):
            raise ValueError(f"job consumes itself or repeats an upstream job: {self.job_id}")

    def probe_input_identity(self, target_root: Path | None, run_root: Path | None = None, *,
                             repository_root: Path | None = None) -> str | None:
        return self.bind_input_identity(target_root, run_root, repository_root=repository_root)[0]

    def bind_input_identity(self, target_root: Path | None, run_root: Path | None = None, *,
                            repository_root: Path | None = None
                            ) -> tuple[str | None, Mapping[str, Any] | None]:
        """Probe once so the reuse identity and admitted external selections cannot diverge."""
        identity = (self.run_input_identity(target_root, run_root)
                    if self.run_input_identity is not None and run_root is not None else
                    self.input_identity(target_root) if self.input_identity is not None else None)
        if self.external_input_identity is not None:
            if run_root is None or repository_root is None:
                raise ValueError("external input identity requires the bound run and repository")
            import json
            from appsec_review.runtime.inputs import read_external_selection
            from appsec_review.storage.atomic import canonical_json_sha256
            selected = read_external_selection(json.loads(
                self.external_input_identity(target_root, run_root, repository_root)), self.contract)
            return canonical_json_sha256({
                "schema": "appsec-review/job-external-inputs/1", "source": identity,
                "external": selected}), selected
        return identity, None

    def configured_workers(self, step_id: str, task_id: str) -> int:
        return self.worker_lookup(step_id, task_id) if self.worker_lookup is not None else 1

    def finalize_result(self, context: JobContext, result: Mapping[str, Any]) -> Mapping[str, Any]:
        return self.result_transform(context, result) if self.result_transform is not None else result

    def identities(self, repository_root: Path, releases: ComponentReleases | None = None) -> Mapping[str, str]:
        from appsec_review.runtime.release import identities
        return identities(self.job_id, self.schema_identity, repository_root,
                          releases.values if releases is not None else {})

    def execute(self, context: JobContext) -> Mapping[str, Any]:
        for validator in self.input_validators:
            validator(context, None)
        result = self.finalize_result(context, self.handler(context))
        for validator in self.output_validators:
            validator(context, result)
        return result
