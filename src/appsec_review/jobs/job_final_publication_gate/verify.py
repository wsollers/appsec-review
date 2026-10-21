"""Re-verify the accepted inference review handoff and everything it binds, from bytes.

Nothing here reinterprets a claim state or a ``ship-block-policy/1`` status. The gate proves that the
accepted handoff, the merged claim ledger, the finding packages, the score packages and the package
manifests still hash to what was accepted and still agree with one another, then projects their
accepted fields. Any disagreement is an :class:`IntegrityError`, which fails the job.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.bound_artifacts import read_bound_json, resolve_bound
from appsec_review.jobs.job_inference_security_review import stages
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review import ship_block
from appsec_review.review.ledger import project
from appsec_review.review.models import IntegrityError
from appsec_review.review.packages import verify_package_manifest
from appsec_review.storage import canonical_json

REVIEW_JOB = "job_inference_security_review"
REVIEW_SCHEMA = "appsec-review/inference-security-review/1"
HANDOFF_SCHEMA = "appsec-review/inference-review-handoff/2"
DIMENSIONS = ("technical_severity", "exploitability_confidence", "environmental_business_impact",
              "remediation_priority")
ATTACK_CHAIN_UNAVAILABLE = ("No attack-chain manifest exists: attack-chain composition and refutation "
                            "(design slice 3) is not built, so no chain package can be published.")
POC_UNAVAILABLE = ("No proof-of-trigger status manifest exists: the PoC lane is plan-only and no execution "
                   "path is built (decision 3), so no PoC outcome can be published.")


@dataclass(frozen=True, slots=True)
class VerifiedReview:
    """The re-verified, projected accepted state the classifier works from."""

    document: dict[str, Any]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise IntegrityError(message)


def _unit_output(outputs: Mapping[str, Any], unit_id: str) -> Mapping[str, Any]:
    value = outputs.get(unit_id)
    _require(isinstance(value, Mapping), f"accepted review handoff lacks the output of {unit_id}")
    return value


def _ref(value: Any, what: str) -> dict[str, str]:
    _require(isinstance(value, Mapping) and isinstance(value.get("path"), str)
             and isinstance(value.get("sha256"), str), f"accepted review handoff lacks a {what} reference")
    return {"path": value["path"], "sha256": value["sha256"]}


def _dimension(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    return {"scale": value["scale"], "rating": value["rating"], "value": value.get("value")}


def project_score(reference: Mapping[str, str], package: Mapping[str, Any]) -> dict[str, Any]:
    """The four separate score dimensions of one score package; they are never combined."""
    native = package.get("native") or {}
    provider = package["provider"]
    return {
        "score_id": package["score_id"], "sha256": reference["sha256"],
        "provider": {"id": provider["id"], "interface": provider["interface"],
                     "implementation": provider["implementation"]},
        "native": {"nomenclature": native.get("nomenclature"), "rating": native.get("rating"),
                   "score": native.get("score")},
        **{name: _dimension(package.get(name)) for name in DIMENSIONS},
        "missing_factors": sorted(package.get("missing_factors", ())),
        "severity_assessment": dict(package["severity_assessment"]),
    }


def project_finding(reference: Mapping[str, str], package: Mapping[str, Any],
                    scores: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """The accepted fields of one finding package; the ship-block decision is copied verbatim."""
    block = package["ship_block"]
    severity = block["inputs"]["technical_severity"]
    return {
        "finding_package_id": package["finding_package_id"], "sha256": reference["sha256"],
        "path": reference["path"], "claim_id": package["claim_id"], "adjudication_id": package["adjudication_id"],
        "lane": package["lane"], "state": package["state"], "label": package["label"], "title": package["title"],
        "ship_block": {
            "policy": block["policy"], "policy_sha256": block["policy_sha256"], "status": block["status"],
            "reasons": list(block["reasons"]), "technical_severity": severity["rating"],
            "technical_severity_score_id": severity["score_id"],
            "technical_severity_floor": severity["severity_floor"],
            "technical_severity_ceiling": severity["severity_ceiling"],
            "missing_factors": list(severity["missing_factors"]),
            "distinct_verification_required": block["conditions"]["distinct_verification_required"],
            "verifier_model_distinct": block["conditions"]["verifier_model_distinct"]},
        "independence": dict(package["independence"]),
        "judge_verdict": None if package["judge_verdict"] is None else {
            "verdict": package["judge_verdict"]["verdict"],
            "disagrees_with_state": package["judge_verdict"]["disagrees_with_state"],
            "verdict_ids": [item["verdict_id"] for item in package["judge_verdict"]["judges"]]},
        "verification_review_id": package["verification_review_id"],
        "direct_evidence": list(package["direct_evidence"]),
        "analyst_assessed_evidence": list(package["analyst_assessed_evidence"]),
        "missing_predicates": list(package["missing_predicates"]),
        "gap_ids": list(package["gaps"]),
        "scores": list(scores),
        "poc": None if package["poc"] is None else {"status": package["poc"]["status"],
                                                     "result_id": package["poc"]["result_id"]},
        "attack_chains": list(package["attack_chains"]),
    }


def _verify_ledger(run_root: Path, outputs: Mapping[str, Any], review: Mapping[str, Any]
                   ) -> tuple[dict[str, str], dict[str, str], dict[str, str], Any]:
    # The accepted handoff keeps only each unit's artifact reference; the ledger, its projection and
    # their hashes are the receipt and its sibling files.
    receipt_ref = _ref(_unit_output(outputs, "publication.publish_claim_ledger").get("artifact"), "ledger receipt")
    receipt = read_bound_json(run_root, receipt_ref)
    _require(receipt.get("schema") == "appsec-review/claim-ledger-head/1"
             and receipt.get("ledger_head_sha256") == review["ledger_head_sha256"]
             and receipt.get("projection_sha256") == review["projection_sha256"],
             "claim ledger receipt does not match the handoff")
    directory = PurePosixPath(receipt_ref["path"]).parent
    ledger_ref = {"path": (directory / "claim-ledger.jsonl").as_posix(), "sha256": receipt["ledger_sha256"]}
    projection_ref = {"path": (directory / "projection.json").as_posix(), "sha256": receipt["projection_file_sha256"]}
    ledger_path = resolve_bound(run_root, ledger_ref)
    projection_path = resolve_bound(run_root, projection_ref)
    paths = []
    for shard in review["shards"]:
        path = resolve_bound(run_root, shard)
        _require(sum(1 for _ in path.read_bytes().splitlines()) == shard["rows"],
                 f"ledger shard row count changed: {shard['path']}")
        paths.append(path)
    merged = stages.merge_verified(paths)                      # also proves the hash chain per shard
    _require(merged.head == review["ledger_head_sha256"], "claim ledger head does not match the handoff")
    ledger = project(merged.events)
    _require(ledger.sha256() == review["projection_sha256"], "claim projection does not match the handoff")
    _require(ledger_path.read_bytes() == b"".join(canonical_json(event) for event in merged.events),
             "published claim ledger does not revalidate from its shards")
    _require(projection_path.read_bytes() == canonical_json(ledger.to_json()),
             "published claim projection does not revalidate from the ledger")
    _require([gap.gap_id for gap in ledger.gaps] == list(review["gap_ids"]),
             "handoff gap identifiers do not match the claim ledger")
    return receipt_ref, ledger_ref, projection_ref, ledger


def _verify_package_manifests(run_root: Path, outputs: Mapping[str, Any], review: Mapping[str, Any]) -> None:
    contents = {}
    for lane in ("lead", "hunt"):
        document = read_bound_json(run_root, _ref(_unit_output(outputs, f"packages.assemble_{lane}_packages")
                                                  .get("artifact"), f"{lane} package set"))
        reference = _ref(document.get("package_manifest"), f"{lane} package manifest")
        manifest = verify_package_manifest(resolve_bound(run_root, reference))
        _require(manifest["content_sha256"] == document["package_manifest_content_sha256"],
                 f"{lane} package manifest does not match its lane document")
        contents[lane] = manifest["content_sha256"]
    _require(contents["hunt"] == review["package_manifest_sha256"],
             "package manifest does not match the handoff")


def load_accepted_review(run_root: Path, schemas: SchemaSet, *, max_packages: int) -> VerifiedReview:
    """Verify the accepted review and project the fields the gate and report need."""
    run_root = Path(run_root).resolve()
    try:
        accepted = accepted_handoff(run_root, REVIEW_JOB)
    except ValueError as exc:
        raise IntegrityError(f"accepted {REVIEW_JOB} handoff cannot be verified: {exc}") from exc
    _require(accepted is not None, f"an accepted {REVIEW_JOB} handoff is required")
    job_handoff = accepted.handoff
    _require(job_handoff.get("job_id") == REVIEW_JOB, "accepted handoff belongs to a different job")
    outputs = job_handoff.get("outputs")
    _require(isinstance(outputs, Mapping), "accepted review handoff has no unit outputs")
    published = _unit_output(outputs, "publication.publish_handoff")
    _require(published.get("schema") == REVIEW_SCHEMA, "accepted review handoff schema is unsupported")
    review_ref = _ref(published.get("artifact"), "review handoff")
    review = read_bound_json(run_root, review_ref)
    errors = schemas.errors("handoff", review)
    _require(not errors, f"review handoff does not satisfy its schema: {'; '.join(errors[:3])}")
    _require(review["schema"] == HANDOFF_SCHEMA, "review handoff schema is unsupported")
    scope = read_bound_json(run_root, _ref(_unit_output(outputs, "scope.accept_manifest").get("artifact"),
                                           "accepted scope"))
    _require(scope.get("manifest_sha256") == review["accepted_manifest_sha256"],
             "accepted manifest identity does not match the handoff")
    _require("package_manifest_sha256" in review and "coverage_matrix" in review,
             "review handoff lacks its package manifest or coverage matrix")
    _require(len(review["finding_packages"]) <= max_packages,
             f"{len(review['finding_packages'])} finding packages exceed the configured bound of {max_packages}")
    _verify_package_manifests(run_root, outputs, review)
    receipt_ref, ledger_ref, projection_ref, ledger = _verify_ledger(run_root, outputs, review)

    coverage_ref = _ref(review["coverage_matrix"], "coverage matrix")
    coverage = read_bound_json(run_root, coverage_ref)
    _require(len(coverage["rows"]) == review["coverage_matrix"]["rows"], "coverage matrix row count changed")

    finding_root = PurePosixPath(review_ref["path"]).parent / "findings"
    score_root = PurePosixPath(_ref(_unit_output(outputs, "scoring.score_claims").get("artifact"),
                                    "score set")["path"]).parent / "scores"
    scores: dict[str, tuple[dict[str, str], Mapping[str, Any]]] = {}
    for item in review["score_packages"]:
        reference = {"path": (score_root / f"{item['score_id']}.json").as_posix(), "sha256": item["sha256"]}
        package = read_bound_json(run_root, reference)
        errors = schemas.errors("score-package", package)
        _require(not errors, f"score package does not satisfy its schema: {'; '.join(errors[:3])}")
        _require(package["score_id"] == item["score_id"], "score package identity does not match its file")
        _require(package["claim_id"] in ledger.claims, "score package names a claim absent from the ledger")
        scores[item["score_id"]] = (reference, package)

    findings: list[tuple[dict[str, str], Mapping[str, Any]]] = []
    for item in review["finding_packages"]:
        reference = {"path": (finding_root / f"{item['finding_package_id']}.json").as_posix(),
                     "sha256": item["sha256"]}
        package = read_bound_json(run_root, reference)
        errors = schemas.errors("finding-package", package)
        _require(not errors, f"finding package does not satisfy its schema: {'; '.join(errors[:3])}")
        _require(package["finding_package_id"] == item["finding_package_id"],
                 "finding package identity does not match its file")
        view = ledger.claims.get(package["claim_id"])
        _require(view is not None and view.claim.state.value == package["state"],
                 f"finding package state disagrees with the claim ledger: {package['finding_package_id']}")
        _require(package["provenance"] == {"run_manifest_sha256": review["accepted_manifest_sha256"],
                                           "ledger_head_sha256": review["ledger_head_sha256"]},
                 "finding package provenance does not match the handoff")
        _require(package["ship_block"]["policy_sha256"] == review["ship_block"]["policy_sha256"],
                 "finding package ship-block policy hash does not match the handoff")
        _require(set(package["scores"]) <= set(scores), "finding package names a score package the handoff lacks")
        judged = package["judge_verdict"]
        recorded = {item.verdict_id: item for item in ledger.judge_verdicts.get(package["claim_id"], ())}
        _require(judged is None and not recorded or judged is not None and
                 {item["verdict_id"] for item in judged["judges"]} == set(recorded)
                 and all(recorded[item["verdict_id"]].verdict.value == item["verdict"] for item in judged["judges"]),
                 f"finding package judge verdict disagrees with the claim ledger: {package['finding_package_id']}")
        findings.append((reference, package))

    listed = {item["finding_package_id"]: item["sha256"] for item in review["finding_packages"]}
    for candidate in review["poc_candidates"]:
        reference = candidate["finding_package"]
        package = next((value for _ref, value in findings if value["finding_package_id"] == reference["finding_package_id"]),
                       None)
        _require(package is not None and listed.get(reference["finding_package_id"]) == reference["sha256"]
                 and package["claim_id"] == candidate["claim_id"] and package["state"] == candidate["state"]
                 and package["judge_verdict"] is not None
                 and package["judge_verdict"]["verdict"] == candidate["judge_verdict"],
                 f"proof-of-concept candidate disagrees with its finding package: {candidate['claim_id']}")
    intake = {item["finding_package_id"]: item for item in review["remediation_intake"]}
    backlog = {item["finding_package_id"]: item for item in review["verification_backlog"]}
    by_id = {package["finding_package_id"]: package for _reference, package in findings}
    digests = {item["finding_package_id"]: item["sha256"] for item in review["finding_packages"]}
    _require(not set(intake) & set(backlog) and set(intake) | set(backlog) == set(by_id),
             "remediation intake and verification backlog do not partition the finding packages")
    for table, state in ((intake, "confirmed"), (backlog, "supported")):
        for identity, row in table.items():
            package = by_id[identity]
            _require(package["state"] == state and row["sha256"] == digests[identity]
                and row["claim_id"] == package["claim_id"] and row["lane"] == package["lane"]
                and row["ship_block_status"] == package["ship_block"]["status"],
                f"handoff partition row disagrees with its finding package: {identity}")
    recount = ship_block.summarize({"lane": package["lane"], "status": package["ship_block"]["status"]}
                                   for package in by_id.values())
    _require(recount["by_status"] == review["ship_block"]["by_status"]
             and recount["by_lane"] == review["ship_block"]["by_lane"],
             "handoff ship-block counts do not match the finding packages")

    projected = [project_finding(reference, package, [project_score(*scores[score_id])
                                                      for score_id in sorted(package["scores"])])
                 for reference, package in sorted(findings, key=lambda row: row[1]["finding_package_id"])]
    job_handoff_ref = {"path": accepted.path, "sha256": accepted.sha256}
    bindings = {(item["path"], item["sha256"]) for item in (
        job_handoff_ref, review_ref, receipt_ref, ledger_ref, projection_ref, coverage_ref,
        *review["shards"], *(reference for reference, _ in findings), *(reference for reference, _ in scores.values()))}
    accounting = review["accounting"]
    document = {
        "run_id": review["run_id"],
        "review": {"status": review["status"], "review_incomplete": accounting["review_incomplete"],
                   "accepted_manifest_sha256": review["accepted_manifest_sha256"],
                   "configuration_sha256": review["configuration_sha256"],
                   "ledger_head_sha256": review["ledger_head_sha256"],
                   "projection_sha256": review["projection_sha256"],
                   "ship_block_policy_sha256": review["ship_block"]["policy_sha256"],
                   "package_manifest_sha256": review["package_manifest_sha256"]},
        "inputs": {"job_handoff": job_handoff_ref, "review_handoff": review_ref, "claim_ledger": ledger_ref,
                   "projection": projection_ref, "coverage_matrix": coverage_ref},
        "accounting": {key: accounting[key] for key in (
            "outcome", "review_incomplete", "incomplete_gap_ratio", "gap_ratio", "claims_total",
            "duplicate_proposals", "claims_by_state", "gaps_by_class")},
        "lanes": [{key: lane[key] for key in ("lane", "outcome", "gapped_cells", "gapped_packages", "cells_missing")}
                  for lane in accounting["lanes"]],
        "ship_block": {"policy": review["ship_block"]["policy"], "policy_sha256": review["ship_block"]["policy_sha256"],
                       "by_status": review["ship_block"]["by_status"], "by_lane": review["ship_block"]["by_lane"]},
        "verification": {"require_distinct_model_for_ship_blocking":
                         review["verification"]["require_distinct_model_for_ship_blocking"],
                         "distinct": review["verification"]["distinct"], "warning": review["verification"]["warning"]},
        "coverage": {"rows": len(coverage["rows"]), "summary": dict(coverage["summary"]),
                     "statement": coverage["statement"]},
        "partition": {"confirmed": sorted(intake), "supported": sorted(backlog)},
        "possible_duplicate_pairs": len(review.get("possible_duplicates", ())),
        "packages": projected,
        "gap_ids": list(review["gap_ids"]),
        "bindings": [{"path": path, "sha256": digest} for path, digest in sorted(bindings)],
    }
    return VerifiedReview(document)


__all__ = ["ATTACK_CHAIN_UNAVAILABLE", "POC_UNAVAILABLE", "REVIEW_JOB", "VerifiedReview", "load_accepted_review",
           "project_finding", "project_score"]
