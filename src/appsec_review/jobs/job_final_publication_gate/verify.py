"""Accepted review authority and snapshot-only certified gate verification."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from appsec_review.indexing.store import AcceptedHandoff, accepted_handoff
from appsec_review.jobs.accepted_review import (
    REVIEW_JOB, VerifiedReview, load_accepted_review, project_finding, project_score,
)
from appsec_review.jobs.bound_artifacts import read_bound_json, resolve_bound
from appsec_review.jobs.engineering_contracts import (
    FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA, FINAL_PUBLICATION_GATE_SCHEMA,
)
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review.models import IntegrityError

__all__ = [
    "REVIEW_JOB", "VerifiedReview", "load_accepted_review", "project_finding", "project_score",
    "load_accepted_gate", "verify_gate_snapshot",
]


def verify_gate_snapshot(run_root: Path, gate: Mapping[str, Any]) -> None:
    """Rehash certified bindings without consulting optional producers' current pointers."""
    if gate["run_id"] != run_root.name:
        raise IntegrityError("gate snapshot belongs to another run")
    bindings = {(row["path"], row["sha256"]) for row in gate["bindings"]}
    for row in gate["bindings"]:
        resolve_bound(run_root, row)

    def included(value: Any) -> None:
        if isinstance(value, Mapping):
            if {"path", "sha256"} <= set(value) and (value["path"], value["sha256"]) not in bindings:
                raise IntegrityError("gate attachment is not among its certified bindings")
            for item in value.values():
                included(item)
        elif isinstance(value, list):
            for item in value:
                included(item)

    included(gate["inputs"])
    included(gate["capabilities"])
    included(gate["attachments"])


def load_accepted_gate(run_root: Path, schemas: SchemaSet, *,
                       expected_handoff_sha256: str | None = None) -> tuple[AcceptedHandoff, dict[str, Any]]:
    """Verify the accepted gate and its complete certified snapshot, never live optional heads."""
    job_id = "job_final_publication_gate"
    try:
        accepted = accepted_handoff(run_root, job_id)
    except ValueError as exc:
        raise IntegrityError(f"accepted {job_id} handoff cannot be verified: {exc}") from exc
    if accepted is None or accepted.handoff.get("job_id") != job_id:
        raise IntegrityError(f"an accepted {job_id} handoff is required")
    if expected_handoff_sha256 is not None and expected_handoff_sha256 != accepted.sha256:
        raise IntegrityError("accepted gate differs from the projection attempt's upstream identity")
    published = (accepted.handoff.get("outputs") or {}).get("acceptance.publish_handoff")
    if not isinstance(published, Mapping) or published.get("schema") != FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA:
        raise IntegrityError("accepted gate handoff does not publish a supported gate document")
    gate = read_bound_json(run_root, published["artifact"])
    errors = schemas.errors("final-publication-gate", gate)
    if errors:
        raise IntegrityError(f"final-publication-gate does not satisfy its schema: {'; '.join(errors[:3])}")
    if not isinstance(gate, dict):
        raise IntegrityError("gate document is not a JSON object")
    if gate["schema"] != FINAL_PUBLICATION_GATE_SCHEMA or published.get("item_count") != gate["package_counts"]["total"]:
        raise IntegrityError("gate document disagrees with its accepted handoff")
    counts = gate["package_counts"]
    if counts["total"] != len(gate["packages"]) or sorted(
            item["finding_package_id"] for item in gate["packages"]) != sorted(
            identity for ids in gate["buckets"].values() for identity in ids):
        raise IntegrityError("gate package accounting is not exact")
    verify_gate_snapshot(run_root, gate)
    return accepted, gate
