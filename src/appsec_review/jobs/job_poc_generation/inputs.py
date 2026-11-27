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
    candidates: tuple[PocCandidate, ...]
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
    from appsec_review.jobs.bound_artifacts import source_context_core
    return source_context_core(Path(run_root), {"path": inputs.manifest_path, "sha256": inputs.manifest_sha256})


def sink_of(package: Mapping[str, Any], *, core: Any = None) -> Mapping[str, Any] | None:
    """The function that holds the sink, from the package neighborhood or Hunt enclosing symbol via core."""
    neighborhood = package.get("neighborhood") or {}
    function = neighborhood.get("function")
    if isinstance(function, Mapping) and function.get("name") and function.get("path"):
        return {"name": str(function["name"]), "path": str(function["path"]),
                "line": int(function.get("start_line") or 0), "symbol": function.get("symbol")}
    if core is None or not hasattr(core, "find"):
        return None
    operation = (package.get("scope") or {}).get("operation") or {}
    sinks = [row for row in (neighborhood.get("sinks") or ()) if isinstance(row, Mapping)]
    anchor_ids: list[str] = []
    for row in sinks:
        ref = row.get("ref")
        if isinstance(ref, str) and ref and ref not in anchor_ids:
            anchor_ids.append(ref)
    for ref in (operation.get("anchor_ids") or ()):
        if isinstance(ref, str) and ref and ref not in anchor_ids:
            anchor_ids.append(ref)
    op_path = str(operation.get("path") or (sinks[0].get("path") if sinks else "") or "")
    op_line = int(operation.get("line") or (sinks[0].get("line") if sinks else 0) or 0)
    for anchor_id in anchor_ids:
        found = core.find(identity=anchor_id, limit=1).get("results", ())
        if not found:
            continue
        item = found[0]
        loc = item.get("location") or {}
        item_path = str(loc.get("path") or op_path)
        item_line = int(loc.get("start_line") or loc.get("line") or op_line or 0)
        if item.get("kind") == "symbol" and item.get("name") and item_path:
            return {"name": str(item["name"]), "path": item_path, "line": item_line,
                    "symbol": item.get("identity")}
        payload = item.get("payload") or {}
        inner = payload.get("result") if isinstance(payload.get("result"), Mapping) else payload
        enclosing = inner.get("enclosing_function") if isinstance(inner, Mapping) else None
        if isinstance(enclosing, str) and enclosing and item_path:
            return {"name": enclosing, "path": item_path, "line": item_line, "symbol": None}
        if isinstance(enclosing, Mapping) and enclosing.get("name") and item_path:
            return {"name": str(enclosing["name"]), "path": item_path,
                    "line": int(enclosing.get("start_line") or item_line),
                    "symbol": enclosing.get("identity") or enclosing.get("symbol")}
        if item_path and not op_path:
            op_path = item_path
        if item_line and not op_line:
            op_line = item_line
    if op_path and op_line > 0:
        best: tuple[int, int, Mapping[str, Any]] | None = None
        for sym in core.find(path=op_path, kind="symbol", limit=100).get("results", ()):
            name = sym.get("name")
            loc = sym.get("location") or {}
            start = int(loc.get("start_line") or loc.get("line") or 0)
            end = int(loc.get("end_line") or start)
            if not isinstance(name, str) or not name or start <= 0 or end < start:
                continue
            if start <= op_line <= end:
                span = end - start
                rank = (span, -start)
                if best is None or rank < (best[0], best[1]):
                    best = (span, -start, sym)
        if best is not None:
            sym = best[2]
            loc = sym.get("location") or {}
            return {"name": str(sym["name"]), "path": str(loc.get("path") or op_path),
                    "line": int(loc.get("start_line") or op_line), "symbol": sym.get("identity")}
    return None


def evidence_summary(candidate: PocCandidate, limit: int = 32) -> Sequence[str]:
    return candidate.evidence_refs[:limit]


__all__ = ["REVIEW_JOB", "VerifiedInputs", "evidence_summary", "load_package", "retrieval_core", "sink_of",
           "verify_inputs"]
