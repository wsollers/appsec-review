"""Verify accepted producers and resolve only the finding's cited accepted identities."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.bound_artifacts import read_bound_json, resolve_bound
from appsec_review.jobs.completion_contracts import (
    ATTACK_CHAIN_MANIFEST_SCHEMA, FindingBinding, REMEDIATION_PLANNING_HANDOFF_SCHEMA,
    REMEDIATION_PLAN_SCHEMA, REMEDIATION_PLANNING_SCHEMA, REMEDIATION_VALIDATION_HANDOFF_SCHEMA,
    REMEDIATION_VALIDATION_SCHEMA, REMEDIATION_VALIDATION_SUMMARY_SCHEMA,
    verify_nonexecution_assurance,
)
from appsec_review.jobs.engineering_contracts import POC_GENERATION_HANDOFF_SCHEMA, POC_GENERATION_SCHEMA
from appsec_review.review.models import IntegrityError
from appsec_review.reporting.dossiers import POC_STATUSES
from .settings import DossierPublicationSettings

REVIEW_JOB = "job_inference_security_review"
PRODUCERS = {
    "job_poc_generation": ("publish.publish_handoff", POC_GENERATION_HANDOFF_SCHEMA, POC_GENERATION_SCHEMA, "candidates"),
    "job_remediation_planning": ("acceptance.publish_handoff", REMEDIATION_PLANNING_HANDOFF_SCHEMA,
                                REMEDIATION_PLANNING_SCHEMA, "items"),
    "job_remediation_validation": ("acceptance.publish_handoff", REMEDIATION_VALIDATION_HANDOFF_SCHEMA,
                                  REMEDIATION_VALIDATION_SUMMARY_SCHEMA, "items"),
}
UPSTREAM_KEYS = {"job_poc_generation": "poc_handoff", "job_remediation_planning": "remediation_planning_handoff",
                 "job_remediation_validation": "remediation_validation_handoff"}


def bound_json(root: Path, reference: Mapping[str, Any], maximum: int) -> Any:
    path = resolve_bound(root, reference)
    if path.stat().st_size > maximum:
        raise IntegrityError("dossier input exceeds max_artifact_bytes: " + reference["path"])
    return read_bound_json(root, reference)


def finding_binding(row: Mapping[str, Any]) -> FindingBinding:
    """PoC keeps its existing finding_package field; new remediation records use finding."""
    if "finding" in row:
        return FindingBinding.from_mapping(row["finding"])
    package = row.get("finding_package") or {}
    return FindingBinding(row.get("claim_id"), package.get("finding_package_id"), package.get("sha256"))


def _references(value: Any):
    if isinstance(value, Mapping):
        if "path" in value and "sha256" in value:
            yield value
        else:
            for item in value.values():
                yield from _references(item)
    elif isinstance(value, list):
        for item in value:
            yield from _references(item)


def accepted_producer(root: Path, job: str, review: Mapping[str, str], findings: Mapping[str, Any],
                      settings: DossierPublicationSettings) -> dict[str, Any] | None:
    try:
        accepted = accepted_handoff(root, job)
    except ValueError as exc:
        raise IntegrityError(f"dossier producer handoff cannot be verified: {job}: {exc}") from exc
    if accepted is None:
        return None
    unit, handoff_schema, summary_schema, key = PRODUCERS[job]
    publication = (accepted.handoff.get("outputs") or {}).get(unit)
    if (accepted.handoff.get("job_id") != job or not isinstance(publication, Mapping)
            or publication.get("schema") != handoff_schema):
        raise IntegrityError("unsupported accepted dossier producer: " + job)
    document = bound_json(root, publication["artifact"], settings.max_artifact_bytes)
    if (document.get("schema") != summary_schema or document.get("run_id") != root.name
            or document.get("upstream", {}).get("review_handoff") != dict(review)):
        raise IntegrityError("dossier producer is not bound to this run's accepted review: " + job)
    items = document.get(key)
    if (not isinstance(items, list) or publication.get("item_count") != len(items)
            or not isinstance(document.get("gaps"), list) or publication.get("gaps") != document["gaps"]):
        raise IntegrityError("dossier producer has inexact item/gap accounting: " + job)
    seen = set()
    for row in items:
        binding = finding_binding(row)
        expected = findings.get(binding.finding_package_id)
        if expected is None or binding.as_dict() != {
                name: expected[name] for name in ("claim_id", "finding_package_id", "sha256")}:
            raise IntegrityError("dossier producer mixes accepted finding identities: " + job)
        if binding.finding_package_id in seen:
            raise IntegrityError("dossier producer repeats a finding outcome: " + job)
        seen.add(binding.finding_package_id)
        if job != "job_poc_generation" and expected["state"] != "confirmed":
            raise IntegrityError("remediation attachment is not for a confirmed finding")
        if job == "job_poc_generation":
            verify_nonexecution_assurance(row)
            if row.get("status") not in POC_STATUSES:
                raise IntegrityError("unsupported accepted PoC status")
        if not isinstance(row.get("status"), str) or not row["status"]:
            raise IntegrityError("dossier producer has no terminal status: " + job)
        if job != "job_poc_generation":
            key = "plan" if job == "job_remediation_planning" else "validation"
            reference = row.get(key)
            if reference is not None:
                attachment = bound_json(root, reference, settings.max_artifact_bytes)
                schema = REMEDIATION_PLAN_SCHEMA if key == "plan" else REMEDIATION_VALIDATION_SCHEMA
                if (attachment.get("schema") != schema or attachment.get("run_id") != root.name
                        or attachment.get("finding") != binding.as_dict()
                        or attachment.get("status") != row["status"]
                        or attachment.get("upstream", {}).get("review_handoff") != dict(review)):
                    raise IntegrityError("remediation artifact disagrees with its accepted summary: " + key)
                verify_nonexecution_assurance(attachment.get("assurance") or {})
    for reference in _references(document):
        resolve_bound(root, reference)
    if job == "job_poc_generation" and "counts" in document:
        counts = document["counts"]
        statuses = {status: sum(row["status"] == status for row in items) for status in POC_STATUSES}
        omitted = document.get("omitted_claims", ())
        if (counts.get("candidates") != len(items) or counts.get("omitted") != len(omitted)
                or counts.get("by_status") != statuses):
            raise IntegrityError("PoC producer candidate accounting is not exact")
    return {"handoff": {"path": accepted.path, "sha256": accepted.sha256},
            "artifact": dict(publication["artifact"]), "document": document}


def load_inputs(root: Path, verified: Mapping[str, Any], settings: DossierPublicationSettings) -> dict[str, Any]:
    if verified["run_id"] != root.name:
        raise IntegrityError("dossier accepted review belongs to another run")
    findings = {row["finding_package_id"]: row for row in verified["packages"]}
    if len(findings) != len(verified["packages"]) or len(findings) > settings.max_packages:
        raise IntegrityError("dossier accepted finding accounting is invalid or exceeds max_packages")
    projection = bound_json(root, verified["inputs"]["projection"], settings.max_artifact_bytes)
    claims = {row["claim_id"]: row for row in projection["claims"]}
    for finding in findings.values():
        if finding["claim_id"] not in claims or claims[finding["claim_id"]]["state"] != finding["state"]:
            raise IntegrityError("dossier finding is absent from the accepted claim projection")
    review_ref = verified["inputs"]["review_handoff"]
    review = bound_json(root, review_ref, settings.max_artifact_bytes)
    accepted_job = bound_json(root, verified["inputs"]["job_handoff"], settings.max_artifact_bytes)
    scope_output = accepted_job["outputs"]["scope.accept_manifest"]
    scope = bound_json(root, scope_output["artifact"], settings.max_artifact_bytes)
    manifest = {"path": scope["manifest_path"], "sha256": scope["manifest_sha256"]}
    resolve_bound(root, manifest)
    producers = {job: accepted_producer(root, job, review_ref, findings, settings) for job in PRODUCERS}
    planning = producers["job_remediation_planning"]
    validation = producers["job_remediation_validation"]
    if validation is not None:
        if planning is None:
            raise IntegrityError("accepted remediation validation has no accepted planning producer")
        planned_ref = validation["document"]["upstream"].get("planning_handoff")
        if planned_ref != planning["handoff"]:
            raise IntegrityError("remediation validation is bound to another planning handoff")
    chain_ref = review.get("attack_chain_manifest")
    chains = None
    if chain_ref is not None:
        chains = bound_json(root, chain_ref, settings.max_artifact_bytes)
        if chains.get("schema") != ATTACK_CHAIN_MANIFEST_SCHEMA or chains.get("run_id") != root.name:
            raise IntegrityError("dossier attack-chain manifest belongs to another run or schema")
        for reference in _references(chains):
            resolve_bound(root, reference)
    upstream = {"review_handoff": dict(review_ref),
                **{UPSTREAM_KEYS[job]: None if producer is None else producer["handoff"]
                   for job, producer in producers.items()}}
    return {"schema": "appsec-review/dossier-inputs/1", "run_id": root.name,
            "verified_review": dict(verified), "projection": projection, "source_manifest": manifest,
            "producers": producers, "upstream": upstream, "attack_chain_manifest": chain_ref, "chains": chains}


def verify_snapshot(root: Path, document: Mapping[str, Any], settings: DossierPublicationSettings) -> None:
    """Rehash and prove current accepted pointers still select the exact loaded input snapshot."""
    for reference in _references(document):
        resolve_bound(root, reference)
    expected = {REVIEW_JOB: document["verified_review"]["inputs"]["job_handoff"],
                **{job: None if value is None else value["handoff"]
                   for job, value in document["producers"].items()}}
    for job, reference in expected.items():
        try:
            accepted = accepted_handoff(root, job)
        except ValueError as exc:
            raise IntegrityError("dossier input acceptance changed: " + job) from exc
        actual = None if accepted is None else {"path": accepted.path, "sha256": accepted.sha256}
        if actual != reference:
            raise IntegrityError("dossier accepted upstream changed during publication: " + job)


__all__ = ["UPSTREAM_KEYS", "bound_json", "finding_binding", "load_inputs", "verify_snapshot"]
