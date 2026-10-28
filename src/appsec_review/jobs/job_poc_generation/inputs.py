"""Verified inputs of ``job_poc_generation``: the accepted gate, the accepted review and its packages.

Nothing is read from the target tree. The gate handoff and the review handoff are re-verified from
bytes with the helpers the gate itself uses (``load_accepted_review`` and ``bound_artifacts``), the
candidates are read from the verified review handoff, and a candidate's review package is loaded by
its recorded hash. The retrieval core that builds the model-facing package view is pinned to the
manifest the review accepted.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.bound_artifacts import read_bound_json, resolve_bound
from appsec_review.jobs.engineering_contracts import (
    FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA, FINAL_PUBLICATION_GATE_SCHEMA,
)
from appsec_review.jobs.job_final_publication_gate import JOB_ID as GATE_JOB
from appsec_review.jobs.job_final_publication_gate.verify import REVIEW_JOB, VerifiedReview, load_accepted_review
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review.models import IntegrityError

from .candidates import PocCandidate, check_against_review, read_candidates

LANES = ("lead", "hunt")


@dataclass(frozen=True, slots=True)
class VerifiedInputs:
    run_id: str
    gate_handoff: dict[str, str]
    gate_document: dict[str, str]
    review_job_handoff: dict[str, str]
    review_handoff: dict[str, str]
    review_status: str
    manifest_sha256: str
    manifest_path: str
    candidates: tuple[PocCandidate, ...]
    findings: Mapping[str, Mapping[str, Any]]            # finding_package_id -> projected finding package
    package_records: Mapping[str, Mapping[str, Any]]     # package_id -> {path, sha256, lane}
    language_build_handoff_sha256: str | None = None

    def identity(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "gate_handoff": self.gate_handoff, "gate_document": self.gate_document,
                "review_job_handoff": self.review_job_handoff, "review_handoff": self.review_handoff,
                "manifest_sha256": self.manifest_sha256}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise IntegrityError(message)


def verify_gate(run_root: Path, schemas: SchemaSet) -> tuple[dict[str, str], dict[str, str], Mapping[str, Any]]:
    """The accepted gate handoff, its document and the document itself, every binding re-hashed."""
    try:
        accepted = accepted_handoff(run_root, GATE_JOB)
    except ValueError as exc:
        raise IntegrityError(f"accepted {GATE_JOB} handoff cannot be verified: {exc}") from exc
    _require(accepted is not None and accepted.handoff.get("job_id") == GATE_JOB,
             f"an accepted {GATE_JOB} handoff is required")
    published = (accepted.handoff.get("outputs") or {}).get("acceptance.publish_handoff")
    _require(isinstance(published, Mapping) and published.get("schema") == FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA,
             "accepted gate handoff does not publish a supported gate document")
    reference = published["artifact"]
    gate = read_bound_json(run_root, reference)
    errors = schemas.errors("final-publication-gate", gate)
    _require(not errors, f"gate document does not satisfy its schema: {'; '.join(errors[:3])}")
    _require(gate["schema"] == FINAL_PUBLICATION_GATE_SCHEMA, "gate document schema is unsupported")
    for binding in gate["bindings"]:
        resolve_bound(run_root, binding)
    return ({"path": accepted.path, "sha256": accepted.sha256},
            {"path": reference["path"], "sha256": reference["sha256"]}, gate)


def verify_inputs(run_root: Path, *, review_schemas: SchemaSet, gate_schemas: SchemaSet,
                  max_packages: int = 10_000) -> VerifiedInputs:
    """Re-verify the gate and the review it was built from, and read the PoC candidates."""
    run_root = Path(run_root).resolve()
    gate_handoff, gate_document, gate = verify_gate(run_root, gate_schemas)
    verified: VerifiedReview = load_accepted_review(run_root, review_schemas,
                                                    max_packages=max_packages)
    document = verified.document
    inputs = document["inputs"]
    _require(gate["inputs"]["review_handoff"] == inputs["review_handoff"]
             and gate["review"]["ledger_head_sha256"] == document["review"]["ledger_head_sha256"]
             and gate["review"]["accepted_manifest_sha256"] == document["review"]["accepted_manifest_sha256"],
             "the accepted gate was not built from the accepted review")
    review = read_bound_json(run_root, inputs["review_handoff"])
    job_handoff = read_bound_json(run_root, inputs["job_handoff"])
    outputs = job_handoff["outputs"]
    # The accepted handoff keeps only each unit's artifact reference; the accepted scope is that artifact.
    scope = read_bound_json(run_root, outputs["scope.accept_manifest"]["artifact"])
    _require(scope["manifest_sha256"] == document["review"]["accepted_manifest_sha256"],
             "the accepted scope does not name the review's manifest")
    findings = {item["finding_package_id"]: item for item in document["packages"]}
    candidates = read_candidates(review)
    problems = check_against_review(candidates, findings)
    _require(not problems, "poc_candidates disagree with the verified review: " + "; ".join(problems[:3]))
    records: dict[str, Mapping[str, Any]] = {}
    for lane in LANES:
        lane_document = read_bound_json(run_root, outputs[f"packages.assemble_{lane}_packages"]["artifact"])
        for record in lane_document["packages"]:
            records[record["package_id"]] = {"path": record["path"], "sha256": record["sha256"], "lane": lane}
    return VerifiedInputs(
        str(document["run_id"]), gate_handoff, gate_document, dict(inputs["job_handoff"]),
        dict(inputs["review_handoff"]), str(document["review"]["status"]), str(scope["manifest_sha256"]),
        str(scope["manifest_path"]), candidates, findings, records)


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
           "verify_gate", "verify_inputs"]
