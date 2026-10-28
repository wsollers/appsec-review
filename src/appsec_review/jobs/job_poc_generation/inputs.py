"""Verified inputs of ``job_poc_generation``: the accepted review and its packages.

Nothing is read from the target tree. The review handoff is re-verified from
bytes with the shared ``load_accepted_review`` and ``bound_artifacts`` helpers, the
candidates are read from the verified review handoff, and a candidate's review package is loaded by
its recorded hash. The retrieval core that builds the model-facing package view is pinned to the
manifest the review accepted.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from appsec_review.jobs.bound_artifacts import read_bound_json, resolve_bound
from appsec_review.jobs.accepted_review import REVIEW_JOB, VerifiedReview, load_accepted_review
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review.models import IntegrityError

from .candidates import PocCandidate, check_against_review, read_candidates

LANES = ("lead", "hunt")


@dataclass(frozen=True, slots=True)
class VerifiedInputs:
    run_id: str
    review_job_handoff: dict[str, str]
    review_handoff: dict[str, str]
    review_status: str
    manifest_sha256: str
    manifest_path: str
    candidates: tuple[PocCandidate, ...] | None
    findings: Mapping[str, Mapping[str, Any]]            # finding_package_id -> projected finding package
    package_records: Mapping[str, Mapping[str, Any]]     # package_id -> {path, sha256, lane}
    language_build_handoff_sha256: str | None = None
    bindings: tuple[dict[str, str], ...] = ()

    def identity(self) -> dict[str, Any]:
        return {"run_id": self.run_id,
                "review_job_handoff": self.review_job_handoff, "review_handoff": self.review_handoff,
                "manifest_sha256": self.manifest_sha256}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise IntegrityError(message)


def verify_inputs(run_root: Path, *, review_schemas: SchemaSet,
                  max_packages: int = 10_000) -> VerifiedInputs:
    """Re-verify the accepted review directly, without depending on publication."""
    run_root = Path(run_root).resolve()
    verified: VerifiedReview = load_accepted_review(run_root, review_schemas,
                                                    max_packages=max_packages)
    document = verified.document
    inputs = document["inputs"]
    review = read_bound_json(run_root, inputs["review_handoff"])
    job_handoff = read_bound_json(run_root, inputs["job_handoff"])
    outputs = job_handoff["outputs"]
    # The accepted handoff keeps only each unit's artifact reference; the accepted scope is that artifact.
    scope = read_bound_json(run_root, outputs["scope.accept_manifest"]["artifact"])
    _require(scope["manifest_sha256"] == document["review"]["accepted_manifest_sha256"],
             "the accepted scope does not name the review's manifest")
    findings = {item["finding_package_id"]: item for item in document["packages"]}
    candidates = read_candidates(review)
    if candidates is not None:
        problems = check_against_review(candidates, findings)
        _require(not problems, "poc_candidates disagree with the verified review: " + "; ".join(problems[:3]))
    records: dict[str, Mapping[str, Any]] = {}
    for lane in LANES:
        lane_document = read_bound_json(run_root, outputs[f"packages.assemble_{lane}_packages"]["artifact"])
        for record in lane_document["packages"]:
            records[record["package_id"]] = {"path": record["path"], "sha256": record["sha256"], "lane": lane}
    return VerifiedInputs(
        str(document["run_id"]), dict(inputs["job_handoff"]),
        dict(inputs["review_handoff"]), str(document["review"]["status"]), str(scope["manifest_sha256"]),
        str(scope["manifest_path"]), candidates, findings, records, bindings=tuple(document["bindings"]))


def load_package(run_root: Path, inputs: VerifiedInputs, package_id: str) -> Mapping[str, Any] | None:
    """The stored review package of ``package_id`` (hash-checked), or ``None`` when the run has no such package."""
    record = inputs.package_records.get(package_id)
    if record is None:
        return None
    return read_bound_json(Path(run_root), {"path": record["path"], "sha256": record["sha256"]})


def retrieval_core(run_root: Path, inputs: VerifiedInputs) -> Any:
    """The retrieval core pinned to the manifest the review accepted (it reads the target through the index)."""
    from appsec_review.retrieval.core import RetrievalCore

    return RetrievalCore(Path(run_root).parent, inputs.run_id, manifest_sha256=inputs.manifest_sha256,
                         manifest_path=Path(run_root) / inputs.manifest_path)


def sink_of(package: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """The function that holds the sink, from the package neighborhood; ``None`` when the package names none."""
    function = (package.get("neighborhood") or {}).get("function")
    if not isinstance(function, Mapping) or not function.get("name") or not function.get("path"):
        return None
    return {"name": str(function["name"]), "path": str(function["path"]),
            "line": int(function.get("start_line") or 0), "symbol": function.get("symbol")}


def evidence_summary(candidate: PocCandidate, limit: int = 32) -> Sequence[str]:
    return candidate.evidence_refs[:limit]


__all__ = ["REVIEW_JOB", "VerifiedInputs", "evidence_summary", "load_package", "retrieval_core", "sink_of",
           "verify_inputs"]
