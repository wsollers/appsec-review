"""Verify the accepted planning handoff and every exact confirmed finding binding."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.bound_artifacts import read_bound_json
from appsec_review.jobs.completion_contracts import REMEDIATION_PLANNING_HANDOFF_SCHEMA, REMEDIATION_PLANNING_JOB
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.jobs.job_remediation_planning.contracts import verify_plan
from appsec_review.jobs.job_remediation_planning.inputs import binding, confirmed_findings
from appsec_review.review.models import IntegrityError


def load_planning(run_root: Path, review: Mapping[str, Any], schemas: SchemaSet
                  ) -> tuple[dict[str, str], dict[str, Any]]:
    try:
        accepted = accepted_handoff(run_root, REMEDIATION_PLANNING_JOB)
    except ValueError as exc:
        raise IntegrityError(f"accepted remediation planning handoff cannot be verified: {exc}") from exc
    if accepted is None:
        raise IntegrityError("an accepted remediation planning handoff is required")
    handoff = accepted.handoff
    if handoff.get("job_id") != REMEDIATION_PLANNING_JOB:
        raise IntegrityError("accepted remediation planning handoff belongs to another job")
    output = handoff.get("outputs", {}).get("acceptance.publish_handoff")
    if not isinstance(output, Mapping) or output.get("schema") != REMEDIATION_PLANNING_HANDOFF_SCHEMA:
        raise IntegrityError("accepted remediation planning publication schema is unsupported")
    summary = read_bound_json(run_root, output["artifact"])
    errors = schemas.errors("planning", summary)
    if errors:
        raise IntegrityError(f"accepted remediation planning summary schema mismatch: {'; '.join(errors[:3])}")
    expected = [binding(item) for item in confirmed_findings(review)]
    if (summary["run_id"] != run_root.name or summary["upstream"]["review_handoff"] != review["inputs"]["review_handoff"]
            or [item["finding"] for item in summary["items"]] != expected
            or output["item_count"] != len(expected) or output["gaps"] != summary["gaps"]
            or summary["gaps"] != sorted({gap for row in summary["items"] for gap in row["gap_ids"]})):
        raise IntegrityError("accepted planning input has cross-review mixing or inexact candidate accounting")
    for row in summary["items"]:
        if row["status"] == "proposal_generated" and row["plan"] is None:
            raise IntegrityError("accepted planning proposal has no plan")
        if row["plan"] is not None:
            plan = verify_plan(run_root, row["plan"], review_handoff=review["inputs"]["review_handoff"],
                               finding=row["finding"], schemas=schemas)
            if plan["status"] != row["status"] or plan["reason"] != row["reason"]:
                raise IntegrityError("accepted planning outcome disagrees with its plan")
    return {"path": accepted.path, "sha256": accepted.sha256}, summary
