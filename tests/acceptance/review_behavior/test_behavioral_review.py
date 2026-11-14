"""Read-only manual acceptance of an explicitly supplied completed T-146 review.

APPSEC_BEHAVIOR_REVIEW_ACCEPTANCE_RUN names a run directory. This does not launch a review,
execute a target, grade against an answer key or turn a gap into a clean result.
"""
import json
import os
from pathlib import Path

import pytest

from appsec_review.acceptance.system import accepted_final_report
from appsec_review.indexing.store import accepted_handoff
from appsec_review.jobs.bound_artifacts import read_bound_json
from appsec_review.observability.findings.run_adapter import findings_from_documents, load_run
from appsec_review.review.packages import verify_package_manifest
from appsec_review.runtime.inputs import read_input_observations

pytestmark = pytest.mark.time_budget(120, reason="bounded read-only completed review acceptance")
ENV = "APPSEC_BEHAVIOR_REVIEW_ACCEPTANCE_RUN"


def run_root():
    selected = os.environ.get(ENV)
    if not selected:
        pytest.skip(f"manual prerequisite: {ENV} must name a completed review run")
    return Path(selected).resolve(strict=True)


def test_operation_accounting_and_original_evidence_survive_publication():
    root = run_root()
    report, core, _ = accepted_final_report(root)
    accepted = accepted_handoff(root, "job_inference_security_review")
    assert accepted is not None, "no accepted inference review"
    lane_ref = accepted.handoff["outputs"]["packages.assemble_hunt_packages"]["artifact"]
    lane = read_bound_json(root, lane_ref)
    manifest_ref = lane["package_manifest"]
    read_bound_json(root, manifest_ref)
    manifest = verify_package_manifest(root / manifest_ref["path"], run_root=root)
    assert manifest["assembly_rule"] == "appsec-review/assemble-review-packages/14"
    assert all("source_ids" in unit and "coverage_scope" in unit for unit in manifest["units"])
    assert all(unit["source_ids"] or unit["lead_count"] for unit in manifest["units"])
    operations = [unit for unit in manifest["units"] if unit["coverage_scope"] == "operation"]
    assert operations, "acceptance target must contain at least one supported graph operation"
    for unit in operations:
        operation = unit["operation"]
        assert operation["authority"] == "routing_context"
        assert all(core.find(identity=identity, limit=1)["results"] for identity in operation["anchor_ids"])
    assert report["status"]["review_complete"] is False or not report["gap_ids"]
    if manifest["behavior_model"] is not None:
        reads = read_input_observations(root, accepted.handoff)
        assert reads is not None
        assert {"generated_dfd", "generated_threat_model", "generated_model_evidence"} <= {
            row["output_kind"] for row in reads["reads"] if row["producer"] == "job_threat_model_generation"}


def test_developer_actionability_never_credits_a_compile_only_runtime_fix():
    records, gaps = findings_from_documents(load_run(run_root()))
    assert records, "acceptance requires at least one located finding/backlog record to assess actionability"
    for record in records:
        assert record["actionability"]["remediation_validated"] in (False, None)
        assert record["actionability"]["entry_to_sink_path"] in (True, False, None)
    assert isinstance(gaps, list)
