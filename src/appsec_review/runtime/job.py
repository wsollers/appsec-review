from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
import re
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
    optional_prior_handoffs: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    contract: JobContract | None = None
    external_input_selection: Mapping[str, Any] | None = None
    resolved_config_sha256: str | None = None
    # Development input overrides resolved once when this attempt was claimed (claim
    # ``development_input_overrides``); every step and task reads these exact snapshot bytes.
    development_inputs: tuple[Mapping[str, Any], ...] = ()

    def development_input(self, producer: str, output_kind: str, path: str) -> Mapping[str, Any] | None:
        return next((record for record in self.development_inputs
                     if (record["producer"], record["output_kind"], record["original"]["path"])
                     == (producer, output_kind, path)), None)

    def input_file(self, producer: str, output_kind: str, reference: Mapping[str, Any], *,
                   prior: bool = False) -> InputFile:
        """The single decision of which bytes this attempt reads for one declared upstream output.

        Ordinary attempts read the producer's accepted artifact. An attempt whose claim resolved a
        development override reads its replacement snapshot instead; the original reference is kept
        alongside it, and the producer's file, receipt and hash are never touched.
        """
        from appsec_review.storage import file_sha256
        from appsec_review.storage.shared import safe_path
        original = {key: reference[key] for key in ("path", "sha256", "size_bytes") if key in reference}
        record = None if prior else self.development_input(producer, output_kind, str(reference.get("path")))
        if record is None:
            return InputFile(safe_path(self.run_root, str(reference.get("path", ""))), original, original, False)
        if record["original"]["sha256"] != reference.get("sha256"):
            raise ValueError(f"development override was resolved for other {producer} bytes: {reference.get('path')}")
        replacement = record["replacement"]
        # Claims only carry run-owned snapshots; a repository working copy is the pre-dispatch check.
        base = self.run_root if replacement["root"] == "run" else self.repository_root
        path = safe_path(base, replacement["path"])
        if not path.is_file() or file_sha256(path) != replacement["sha256"]:
            raise ValueError(f"development replacement changed after it was resolved: {replacement['path']}")
        identity = {"path": replacement["path"], "sha256": replacement["sha256"],
                    "size_bytes": replacement["size_bytes"]}
        return InputFile(path, identity, original, True)


@dataclass(frozen=True, slots=True)
class InputFile:
    """The file a reader opens and the identity its bytes must have, with the original reference."""
    path: Path
    identity: Mapping[str, Any]
    original: Mapping[str, Any]
    replaced: bool


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

    def resolve_development_inputs(self, context: JobContext, *,
                                   snapshot: bool = True) -> tuple[dict[str, Any], ...]:
        """Resolve this job's development input overrides once, for one fresh whole-job attempt.

        Each override must name an artifact of a declared, supplied handoff input. A differing hash
        is the point of the override and is recorded, not rejected. With ``snapshot`` the edited copy
        is streamed once into the attempt; ``snapshot=False`` describes the working copy for the
        pre-dispatch lookup check and writes nothing.
        """
        development = context.config.development
        if development is None:
            return ()
        if self.contract is None:
            raise ValueError(f"development input overrides require a typed input contract: {self.job_id}")
        from appsec_review.indexing.inventory import compile_glob
        from appsec_review.retrieval.core import _accepted_handoff
        from appsec_review.runtime.contracts import InputChannel
        from appsec_review.runtime.inputs import producer_contract
        from appsec_review.storage import file_sha256
        from appsec_review.storage.shared import safe_path
        records = []
        for index, item in enumerate(development.input_overrides):
            requirement = next((value for value in self.contract.inputs
                                if value.channel is InputChannel.HANDOFF and value.producer == item.producer
                                and value.output_kind == item.output_kind), None)
            if requirement is None:
                raise ValueError(f"development override names an undeclared input of {self.job_id}: "
                                 f"{item.producer}/{item.output_kind}")
            digest = context.upstream_handoffs.get(item.producer)
            if digest is None:
                raise ValueError(f"development override producer is not supplied to this attempt: {item.producer}")
            handoff, _ = _accepted_handoff(context.run_root, item.producer, digest)
            declaration = next((value for value in producer_contract(context.run_root, handoff)
                                if value.output_kind == item.output_kind), None)
            declared = [ref for ref in handoff["artifacts"] if declaration is not None
                        and any(compile_glob(pattern).fullmatch(ref["path"]) for pattern in declaration.artifacts)]
            original = next((ref for ref in declared if ref["path"] == item.artifact), None)
            if original is None:
                raise ValueError(
                    f"development override artifact is not a declared {item.producer}/{item.output_kind} "
                    f"output of the supplied handoff: {item.artifact}; declared: "
                    + (", ".join(sorted(ref["path"] for ref in declared)[:20]) or "none"))
            source = safe_path(context.repository_root, item.replacement)
            if not source.is_file():
                raise ValueError(f"development replacement is missing: {item.replacement}")
            if snapshot:
                name = re.sub(r"[^A-Za-z0-9._-]", "_", PurePosixPath(item.artifact).name)
                relative = (context.attempt_root.relative_to(context.run_root).as_posix()
                            + f"/inputs/development/{index:02d}-{name}")
                replacement = {"root": "run", **_snapshot_copy(context.run_root, relative, source)}
            else:
                replacement = {"root": "repository", "path": item.replacement,
                               "sha256": file_sha256(source), "size_bytes": source.stat().st_size}
            records.append({
                "producer": item.producer, "output_kind": item.output_kind, "schema": requirement.schema,
                "producer_handoff_sha256": digest,
                "original": {key: original[key] for key in ("path", "sha256", "size_bytes")},
                "source": item.replacement, "replacement": replacement,
            })
        return tuple(records)

    def development_reuse_reasons(self, config: JobConfig, repository_root: Path,
                                  claim: Mapping[str, Any]) -> list[str]:
        """Why an accepted attempt cannot stand for the current development setting.

        A development result never stands in for an ordinary one (or the reverse), and an edited
        copy that changed since the accepted attempt requires a fresh whole-job attempt.
        """
        from appsec_review.storage import file_sha256
        from appsec_review.storage.shared import safe_path
        recorded = sorted((item["producer"], item["output_kind"], item["original"]["path"], item["source"],
                           item["replacement"]["sha256"])
                          for item in claim.get("development_input_overrides", ()))
        if config.development is None:
            return ["accepted attempt read development input overrides"] if recorded else []
        current = []
        for item in config.development.input_overrides:
            source = safe_path(repository_root, item.replacement)
            if not source.is_file():
                return [f"development replacement is missing: {item.replacement}"]
            current.append((item.producer, item.output_kind, item.artifact, item.replacement, file_sha256(source)))
        return [] if sorted(current) == recorded else ["development input overrides or their edited copies changed"]

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


def _snapshot_copy(run_root: Path, relative: str, source: Path) -> dict[str, Any]:
    """Stream ``source`` once into a new run-owned file; the recorded hash is of the copied bytes."""
    import hashlib
    import os
    import tempfile
    from appsec_review.storage.shared import reference, safe_path
    path = safe_path(run_root, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    descriptor, temporary = tempfile.mkstemp(prefix=".snapshot-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as target, source.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        os.link(temporary, path)
    finally:
        os.unlink(temporary)
    return reference(run_root, path, expected_sha256=digest.hexdigest())
