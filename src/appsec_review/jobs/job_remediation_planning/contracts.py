"""Closed model answer validation and hash-bound planning contract checks."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from appsec_review.config.remediation import RemediationBounds, exact
from appsec_review.jobs.bound_artifacts import read_bound_json
from appsec_review.jobs.completion_contracts import REMEDIATION_PLAN_SCHEMA, FindingBinding
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review.models import IntegrityError
from appsec_review.storage import canonical_json
from .patches import ExactPatch, PatchError, parse_patch, patched_bytes

STATUSES = ("proposal_generated", "manual_design_required", "insufficient_evidence", "capped")
ANSWER_FIELDS = {"status", "reason", "violated_invariant", "corrected_invariant", "evidence_ids", "patch",
                 "compatibility_effects", "affected_interfaces", "residual_risks", "deployment_prerequisites",
                 "regression_spec", "validation_checks", "scope_limitations"}
REGRESSION_FIELDS = {"fixtures", "assertions", "positive_cases", "negative_cases", "before", "after",
                     "safety_assertion"}
LIST_FIELDS = {"compatibility_effects", "affected_interfaces", "residual_risks", "deployment_prerequisites",
               "validation_checks", "scope_limitations"}


def text(value: Any, bounds: RemediationBounds, where: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > bounds.max_text_chars:
        raise ValueError(f"{where} requires bounded nonempty text")
    return value


def texts(value: Any, bounds: RemediationBounds, where: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list) or len(value) > bounds.max_list_items or (nonempty and not value):
        raise ValueError(f"{where} requires a bounded {'nonempty ' if nonempty else ''}list")
    return [text(item, bounds, where) for item in value]


@dataclass(frozen=True, slots=True)
class PlanAnswer:
    document: Mapping[str, Any]
    patch: ExactPatch | None

    @classmethod
    def from_mapping(cls, value: Any, bounds: RemediationBounds, *, evidence_ids: set[str]) -> PlanAnswer:
        body = exact(value, ANSWER_FIELDS, "remediation writer answer")
        if body["status"] not in STATUSES[:3]:
            raise ValueError("writer status must be proposal_generated, manual_design_required or insufficient_evidence")
        for key in ("reason", "violated_invariant", "corrected_invariant"):
            text(body[key], bounds, key)
        cites = texts(body["evidence_ids"], bounds, "evidence_ids", nonempty=True)
        if len(set(cites)) != len(cites) or not set(cites) <= evidence_ids:
            raise ValueError("writer cites evidence outside the accepted confirmed finding")
        for key in LIST_FIELDS:
            texts(body[key], bounds, key)
        regression = exact(body["regression_spec"], REGRESSION_FIELDS, "regression_spec")
        for key in ("fixtures", "assertions", "positive_cases", "negative_cases"):
            texts(regression[key], bounds, f"regression_spec.{key}", nonempty=True)
        for key in ("before", "after", "safety_assertion"):
            text(regression[key], bounds, f"regression_spec.{key}")
        patch = parse_patch(body["patch"], bounds) if body["patch"] is not None else None
        if (body["status"] == "proposal_generated") != (patch is not None):
            raise ValueError("only a proposal_generated answer must include an exact patch")
        return cls(body, patch)


def verify_patch_scope(patch: ExactPatch, source_files: Mapping[str, Mapping[str, Any]], builds: Any,
                       bounds: RemediationBounds) -> None:
    for row in patch.document["files"]:
        name = row["path"]
        if row["before_sha256"] is not None:
            if name not in source_files or source_files[name]["sha256"] != row["before_sha256"]:
                raise PatchError("patch edit was not read from admitted source evidence")
            source = source_files[name]
        else:
            parents = {PurePosixPath(key).parent: value for key, value in source_files.items()}
            if PurePosixPath(name).parent not in parents or PurePosixPath(name).suffix not in {
                    ".h", ".hpp", ".c", ".cc", ".cpp", ".cxx"}:
                raise PatchError("new file is outside the evidence-related source directory")
            source = parents[PurePosixPath(name).parent]
        located = builds.locate(source["path"])
        if located.unit is None or located.unit.identity() != source["build"]:
            raise IntegrityError("proposal source build identity changed")
        patched_bytes(ExactPatch({"schema": patch.document["schema"], "files": [row]}),
                      located.unit.workspace, located.unit.workspace_manifest, bounds)


def verify_plan(run_root: Path, reference: Mapping[str, Any], *, review_handoff: Mapping[str, Any],
                finding: Mapping[str, Any], schemas: SchemaSet) -> dict[str, Any]:
    plan = read_bound_json(run_root, reference)
    errors = schemas.errors("plan", plan)
    if errors:
        raise IntegrityError(f"remediation plan schema mismatch: {'; '.join(errors[:3])}")
    if (plan["schema"] != REMEDIATION_PLAN_SCHEMA or plan["run_id"] != run_root.name
            or plan["upstream"]["review_handoff"] != review_handoff
            or FindingBinding.from_mapping(plan["finding"]).as_dict() != dict(finding)):
        raise IntegrityError("remediation plan is bound to another run, review or finding")
    context = read_bound_json(run_root, plan["provenance"]["source_context"])
    receipt = read_bound_json(run_root, plan["provenance"]["writer_receipt"])
    patch = read_bound_json(run_root, plan["patch"]) if plan["patch"] is not None else None
    answer = {key: plan[key] for key in ANSWER_FIELDS if key != "patch"}
    answer["patch"] = patch
    if (context.get("finding") != dict(finding) or context.get("adjudication_id") != plan["adjudication_id"]
            or receipt.get("role") != "remediation_writer" or receipt.get("status") != "answered"
            or receipt.get("cell_id") != f"remediation-writer:{finding['claim_id']}"
            or receipt.get("guidance_bundle_sha256") != plan["provenance"]["guidance_bundle_sha256"]
            or receipt.get("result_sha256") != hashlib.sha256(canonical_json(answer)).hexdigest()
            or (plan["status"] == "proposal_generated") != (patch is not None)):
        raise IntegrityError("remediation plan disagrees with its source context or writer receipt")
    return plan
