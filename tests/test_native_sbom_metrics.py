from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.jobs.engineering_contracts import DEPENDENCY_INTELLIGENCE_HANDOFF_SCHEMA
from appsec_review.jobs.job_dependency_intelligence.native_sbom_contracts import (
    GAP_KINDS, METRIC_COUNTERS, METRICS_SCHEMA,
)
from appsec_review.observability import PipelineLog, aggregate_run_metrics
from appsec_review.storage import atomic_json, file_sha256


JOB = "job_dependency_intelligence"
UNIT = "publication.publish_sbom"
SNAPSHOT = "a" * 64
INPUT = "b" * 64


@pytest.fixture
def run_root(tmp_path: Path) -> Path:
    root = tmp_path / "run"
    root.mkdir()
    return root


def _ref(root: Path, path: Path) -> dict:
    return {"path": path.relative_to(root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def _write(root: Path, relative: str, document: object) -> dict:
    path = root / relative
    atomic_json(path, document)
    return _ref(root, path)


def _case(root: Path, *, attempt: str = "attempt_0001", status: str = "SUCCEEDED",
          packages: int = 2, empty: bool = False) -> dict:
    base = f"data/jobs/{JOB}/attempts/{attempt}"
    unit = f"{base}/steps/publication/tasks/publish_sbom"
    _write(root, f"{base}/claim.json", {
        "schema": "appsec-review/attempt-claim/1", "run_id": root.name, "job_id": JOB,
        "attempt_id": attempt, "source_fingerprint": SNAPSHOT,
    })
    count = 0 if empty else packages
    artifact = None if status == "FAILED" else _write(root, f"{unit}/enriched.spdx.json", {
        "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "dataLicense": "CC0-1.0",
        "name": f"fixture-{packages}",
        "documentNamespace": f"https://example.invalid/sbom/{attempt}/{count}",
        "creationInfo": {"creators": ["Tool: native-sbom-metrics-test"],
                         "created": "2026-10-28T00:00:00Z"},
        "packages": [{"SPDXID": f"SPDXRef-Package-{index}", "name": f"fixture-package-{index}",
                      "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                      "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
                      "copyrightText": "NOASSERTION"} for index in range(count)],
        "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                           "relatedSpdxElement": f"SPDXRef-Package-{index}"} for index in range(count)],
    })
    counters = dict.fromkeys(METRIC_COUNTERS, 0)
    if not empty:
        counters.update({"eligible_files": 3, "selected_files": 3, "read_files": 3,
                         "bytes_read": 42, "candidates_total": packages,
                         "identities_corroborated": packages, "releases_unknown": packages,
                         "native_additions": packages, "output_packages": packages})
    counters["output_bytes"] = artifact["size_bytes"] if artifact else 0
    counters["output_relationships"] = count if artifact else 0
    document = {
        "schema": METRICS_SCHEMA, "source_fingerprint": SNAPSHOT,
        "run_id": root.name, "job_id": JOB, "attempt_id": attempt, "unit_id": UNIT,
        "status": status, "discovery_status": "SUCCEEDED",
        "conversion_status": "FAILED" if status == "COMPLETED_WITH_GAPS" else "SUCCEEDED",
        "validation_status": "FAILED" if status == "FAILED" else "SUCCEEDED",
        "input_fingerprint": INPUT, "sbom_sha256": artifact["sha256"] if artifact else None,
        "counters": counters,
        "gaps_by_kind": ({"input_missing": 1} if status == "COMPLETED_WITH_GAPS" else
                         {"sbom_validation_failed": 1} if status == "FAILED" else {}),
    }
    return {"base": base, "unit": unit, "document": document, "artifact": artifact,
            "provenance": _write(root, f"{unit}/native-sbom-provenance.json", {"schema": "fixture"}),
            "metrics": _write(root, f"{unit}/native-sbom-metrics.json", document)}


def _update_metrics(root: Path, case: dict) -> None:
    case["metrics"] = _write(root, case["metrics"]["path"], case["document"])


def _accept(root: Path, case: dict, *, sbom: object = ...) -> dict:
    if sbom is ...:
        sbom = {
            "format": "spdx-json", "spec_version": "2.3", "status": case["document"]["status"],
            "input_fingerprint": INPUT, "artifact": case["artifact"], "baseline": None,
            "provenance": case["provenance"], "metrics": case["metrics"],
        }
    publication = {"schema": DEPENDENCY_INTELLIGENCE_HANDOFF_SCHEMA,
                   "source_fingerprint": SNAPSHOT}
    if sbom is not None:
        publication["sbom"] = sbom
    case["publication"] = publication
    publication_ref = _write(root, f"{case['base']}/dependency-intelligence-handoff.json", publication)
    handoff = {
        "schema": "appsec-review/job-handoff/1", "job_id": JOB,
        "attempt_id": case["document"]["attempt_id"], "status": "ACCEPTED",
        "source_fingerprint": SNAPSHOT,
        "outputs": {"acceptance.publish_handoff": {"artifact": publication_ref}},
        "artifacts": [publication_ref, case["metrics"], case["provenance"]],
    }
    if case["artifact"] is not None:
        handoff["artifacts"].append(case["artifact"])
    case["handoff"] = handoff
    return _save_handoff(root, case)


def _save_handoff(root: Path, case: dict) -> dict:
    handoff_ref = _write(root, f"{case['base']}/handoff.json", case["handoff"])
    _write(root, f"data/jobs/{JOB}/latest.json", {
        "schema": "appsec-review/latest-handoff/1",
        "attempt_id": case["document"]["attempt_id"],
        "handoff_path": handoff_ref["path"], "handoff_sha256": handoff_ref["sha256"],
    })
    return handoff_ref


def _event(root: Path, case: dict, **overrides) -> None:
    details = {"unit_id": UNIT, "metrics_receipt": case["metrics"], "input_fingerprint": INPUT}
    details.update(overrides)
    PipelineLog(root).write(
        "NATIVE_SBOM_RESULT", run_id=root.name, job_id=JOB,
        attempt_id=case["document"]["attempt_id"], step_id="publication", task_id="publish_sbom",
        details=details,
    )


def _summary(root: Path) -> dict:
    return aggregate_run_metrics(root)["native_sbom"]


@pytest.mark.parametrize(("status", "empty"), [
    ("SUCCEEDED", False), ("SUCCEEDED", True), ("COMPLETED_WITH_GAPS", False), ("FAILED", False),
])
def test_native_sbom_receipt_reports_success_partial_true_zero_and_failure(
        run_root: Path, status: str, empty: bool) -> None:
    case = _case(run_root, status=status, empty=empty)
    _accept(run_root, case)
    _event(run_root, case)
    summary = _summary(run_root)
    assert summary["availability"] == "available"
    assert summary["accounting_complete"]
    assert summary["attempt_count"] == summary["fresh_work"] == 1
    assert summary["attempt_outcomes"] == {status: 1}
    assert summary["reused_publication_count"] == 0
    row = summary["attempts"][0]
    assert row["publication_status"] == status
    assert row["counters"] == case["document"]["counters"]
    assert set(row["counters"]) == set(METRIC_COUNTERS)
    assert set(row["gaps_by_kind"]) == GAP_KINDS
    assert row["resources"] is row["duration_ms"] is None
    assert row["resource_timing_unavailable_reason"]
    inventory = summary["current_inventory"]
    assert inventory["availability"] == ("not_available" if status == "FAILED" else "available")
    assert inventory["status"] == status
    expected_packages = None if status == "FAILED" else 0 if empty else 2
    assert inventory["counters"]["output_packages"] == expected_packages
    assert inventory["sbom_sha256"] == case["document"]["sbom_sha256"]
    assert not summary["gaps"]


def test_identical_repeated_results_are_not_another_attempt(run_root: Path) -> None:
    case = _case(run_root)
    _accept(run_root, case)
    _event(run_root, case)
    _event(run_root, case)
    summary = _summary(run_root)
    assert summary["attempt_count"] == summary["fresh_work"] == 1
    assert summary["current_inventory"]["counters"]["output_packages"] == 2
    assert summary["accounting_complete"] and not summary["gaps"]


def test_conflicting_duplicates_invalidate_attempt_and_matching_current_inventory(run_root: Path) -> None:
    case = _case(run_root)
    _accept(run_root, case)
    _event(run_root, case)
    changed = {**case["document"], "counters": {**case["document"]["counters"], "read_files": 1}}
    conflict = _write(run_root, f"{case['unit']}/conflict.json", changed)
    _event(run_root, case, metrics_receipt=conflict)
    summary = _summary(run_root)
    assert summary["attempt_count"] == summary["fresh_work"] == 1
    assert summary["attempt_outcomes"] == {"INTEGRITY_ERROR": 1}
    assert set(summary["attempts"][0]["counters"].values()) == {None}
    assert summary["current_inventory"]["availability"] == "not_available"
    assert summary["availability"] == "partial" and not summary["accounting_complete"]
    assert any("conflicting duplicate" in gap for gap in summary["gaps"])


@pytest.mark.parametrize("field", [
    "schema", "source_fingerprint", "run_id", "job_id", "attempt_id", "unit_id",
    "input_fingerprint", "status", "discovery_status", "conversion_status", "validation_status",
    "sbom_sha256",
])
def test_receipt_schema_provenance_and_closed_dispositions_are_bound(
        run_root: Path, field: str) -> None:
    case = _case(run_root)
    case["document"][field] = "invalid"
    _update_metrics(run_root, case)
    _event(run_root, case)
    summary = _summary(run_root)
    assert summary["attempt_outcomes"] == {"INTEGRITY_ERROR": 1}
    assert summary["availability"] == "partial"
    assert set(summary["attempts"][0]["counters"].values()) == {None}
    assert summary["gaps"]


@pytest.mark.parametrize("bad_value", [-1, True, 1.5, None, "1"])
def test_nonnegative_integer_counters_are_required(run_root: Path, bad_value: object) -> None:
    case = _case(run_root)
    case["document"]["counters"]["read_files"] = bad_value
    _update_metrics(run_root, case)
    _event(run_root, case)
    assert _summary(run_root)["attempt_outcomes"] == {"INTEGRITY_ERROR": 1}


@pytest.mark.parametrize("mutation", [
    "missing_counter", "extra_counter", "extra_gap", "bad_gap", "extra_field",
    "missing_field", "bad_status_type", "success_with_gaps", "success_without_validation",
    "success_with_failed_conversion", "failed_with_artifact", "failed_with_successful_validation",
])
def test_invalid_receipt_shapes_and_contradictory_outcomes_remain_unknown(
        run_root: Path, mutation: str) -> None:
    case = _case(run_root)
    doc = case["document"]
    if mutation == "missing_counter":
        del doc["counters"]["read_files"]
    elif mutation == "extra_counter":
        doc["counters"]["package-name"] = 1
    elif mutation == "extra_gap":
        doc["gaps_by_kind"]["unregistered"] = 1
    elif mutation == "bad_gap":
        doc["gaps_by_kind"]["bounds"] = True
    elif mutation == "extra_field":
        doc["raw_argv"] = ["compiler"]
    elif mutation == "missing_field":
        del doc["validation_status"]
    elif mutation == "bad_status_type":
        doc["status"] = []
    elif mutation == "success_with_gaps":
        doc["gaps_by_kind"]["bounds"] = 1
    elif mutation == "success_without_validation":
        doc["validation_status"] = "FAILED"
    elif mutation == "success_with_failed_conversion":
        doc["conversion_status"] = "FAILED"
    elif mutation == "failed_with_artifact":
        doc["status"] = "FAILED"
    elif mutation == "failed_with_successful_validation":
        doc["status"] = "FAILED"
        doc["sbom_sha256"] = None
    _update_metrics(run_root, case)
    _event(run_root, case)
    summary = _summary(run_root)
    assert summary["attempt_outcomes"] == {"INTEGRITY_ERROR": 1}
    assert set(summary["attempts"][0]["counters"].values()) == {None}


@pytest.mark.parametrize("damage", ["missing", "corrupt", "size", "hash", "malformed_json", "not_object"])
def test_missing_corrupt_and_malformed_receipts_are_accounting_gaps(
        run_root: Path, damage: str) -> None:
    case = _case(run_root)
    path = run_root / case["metrics"]["path"]
    if damage == "missing":
        path.unlink()
    elif damage == "corrupt":
        path.write_bytes(b"changed")
    elif damage == "size":
        case["metrics"]["size_bytes"] += 1
    elif damage == "hash":
        case["metrics"]["sha256"] = "f" * 64
    else:
        path.write_bytes(b"{" if damage == "malformed_json" else b"[]")
        case["metrics"] = _ref(run_root, path)
    _event(run_root, case)
    summary = _summary(run_root)
    assert summary["attempt_outcomes"] == {"INTEGRITY_ERROR": 1}
    assert summary["gaps"] and not summary["accounting_complete"]


@pytest.mark.parametrize("reference", [
    None, {}, {"path": "../outside.json", "sha256": "a" * 64, "size_bytes": 1},
    {"path": "data\\metrics.json", "sha256": "a" * 64, "size_bytes": 1},
    {"path": "data/metrics.json", "sha256": "a" * 64, "size_bytes": True},
    {"path": "/absolute.json", "sha256": "a" * 64, "size_bytes": 1},
])
def test_incomplete_and_noncanonical_references_are_rejected(run_root: Path, reference: object) -> None:
    case = _case(run_root)
    _event(run_root, case, metrics_receipt=reference)
    summary = _summary(run_root)
    assert summary["attempt_outcomes"] == {"INTEGRITY_ERROR": 1}
    assert summary["current_inventory"]["availability"] == "not_available"


@pytest.mark.parametrize("directory", [False, True])
def test_every_metrics_path_symlink_component_is_rejected(run_root: Path, directory: bool) -> None:
    case = _case(run_root)
    original = run_root / case["metrics"]["path"]
    link = run_root / "data" / "link"
    try:
        link.symlink_to(original.parent if directory else original, target_is_directory=directory)
    except OSError as exc:
        pytest.skip(f"host cannot create test symlinks: {exc}")
    path = link / original.name if directory else link
    case["metrics"] = {**case["metrics"], "path": path.relative_to(run_root).as_posix()}
    _event(run_root, case)
    summary = _summary(run_root)
    assert summary["attempt_outcomes"] == {"INTEGRITY_ERROR": 1}
    assert any("symlink" in gap for gap in summary["gaps"])


def test_failure_before_metrics_receipt_is_not_clean_empty(run_root: Path) -> None:
    PipelineLog(run_root).write("JOB_FAILED", run_id=run_root.name, job_id=JOB,
                                attempt_id="attempt_0001")
    summary = _summary(run_root)
    assert summary["attempt_outcomes"] == {"FAILED": 1}
    assert summary["fresh_work"] == 1
    assert summary["availability"] == "partial"
    row = summary["attempts"][0]
    assert not row["accounting_complete"]
    assert row["discovery_status"] is row["validation_status"] is None
    assert set(row["counters"].values()) == set(row["gaps_by_kind"].values()) == {None}
    assert summary["current_inventory"]["counters"]["output_packages"] is None
    assert any("no metrics receipt" in gap for gap in summary["gaps"])


@pytest.mark.parametrize("event", ["TASK_FAILED", "OPERATION_COMPLETED"])
def test_native_lifecycle_failure_is_visible_without_result_event(run_root: Path, event: str) -> None:
    PipelineLog(run_root).write(event, run_id=run_root.name, job_id=JOB, attempt_id="attempt_0001",
        details={"unit_id": UNIT, "operation_id": "native-sbom.publication", "terminal_status": "FAILED"})
    assert _summary(run_root)["attempt_outcomes"] == {"FAILED": 1}


def test_latest_accepted_inventory_is_not_latest_result_or_sum_of_retries(run_root: Path) -> None:
    first = _case(run_root, packages=2)
    second = _case(run_root, attempt="attempt_0002", packages=7)
    _accept(run_root, first)
    _event(run_root, first)
    _event(run_root, second)
    summary = _summary(run_root)
    assert summary["fresh_work"] == summary["attempt_count"] == 2
    assert summary["attempt_outcomes"] == {"SUCCEEDED": 2}
    assert summary["current_inventory"]["counters"]["output_packages"] == 2
    _accept(run_root, second)
    summary = _summary(run_root)
    assert summary["current_inventory"]["counters"]["output_packages"] == 7
    assert [row["counters"]["output_packages"] for row in summary["attempts"]] == [2, 7]


def test_failed_retry_keeps_previous_accepted_inventory(run_root: Path) -> None:
    first = _case(run_root)
    _accept(run_root, first)
    _event(run_root, first)
    PipelineLog(run_root).write("JOB_FAILED", run_id=run_root.name, job_id=JOB, attempt_id="attempt_0002")
    summary = _summary(run_root)
    assert summary["attempt_outcomes"] == {"FAILED": 1, "SUCCEEDED": 1}
    assert summary["current_inventory"]["counters"]["output_packages"] == 2
    assert not summary["accounting_complete"]


def test_reuse_resolves_accepted_metrics_without_manufacturing_fresh_work(run_root: Path) -> None:
    case = _case(run_root)
    handoff = _accept(run_root, case)
    log = PipelineLog(run_root)
    for _ in range(2):
        log.write("JOB_REUSED", run_id=run_root.name, job_id=JOB, attempt_id="attempt_0001",
                  details={"handoff_sha256": handoff["sha256"]})
        log.write("TASK_REUSED", run_id=run_root.name, job_id=JOB, attempt_id="attempt_0001",
                  details={"unit_id": UNIT})
    summary = _summary(run_root)
    assert summary["fresh_work"] == 0 and summary["reused_publication_count"] == 1
    assert summary["attempt_count"] == 1 and summary["attempts"][0]["reused"]
    assert summary["attempts"][0]["counters"]["read_files"] == 3
    assert summary["current_inventory"]["counters"]["output_packages"] == 2
    assert summary["attempts"][0]["resources"] is summary["attempts"][0]["duration_ms"] is None
    assert summary["accounting_complete"] and not summary["gaps"]


def test_task_reuse_does_not_count_other_dependency_tasks(run_root: Path) -> None:
    case = _case(run_root)
    _accept(run_root, case)
    PipelineLog(run_root).write("TASK_REUSED", run_id=run_root.name, job_id=JOB,
        attempt_id="attempt_0001", details={"unit_id": "scorecards.fetch"})
    summary = _summary(run_root)
    assert summary["fresh_work"] == summary["reused_publication_count"] == summary["attempt_count"] == 0
    assert summary["current_inventory"]["counters"]["output_packages"] == 2


def test_historical_reuse_and_latest_inventory_are_separate(run_root: Path) -> None:
    first = _case(run_root)
    old_handoff = _accept(run_root, first)
    PipelineLog(run_root).write("JOB_REUSED", run_id=run_root.name, job_id=JOB,
        attempt_id="attempt_0001", details={"handoff_sha256": old_handoff["sha256"]})
    second = _case(run_root, attempt="attempt_0002", packages=7)
    _accept(run_root, second)
    _event(run_root, second)
    summary = _summary(run_root)
    assert summary["fresh_work"] == summary["reused_publication_count"] == 1
    assert summary["current_inventory"]["counters"]["output_packages"] == 7
    assert summary["attempts"][0]["counters"]["output_packages"] == 2
    assert not summary["gaps"]


def test_reuse_binds_advertised_handoff_hash(run_root: Path) -> None:
    case = _case(run_root)
    _accept(run_root, case)
    PipelineLog(run_root).write("JOB_REUSED", run_id=run_root.name, job_id=JOB,
        attempt_id="attempt_0001", details={"handoff_sha256": "f" * 64})
    summary = _summary(run_root)
    assert summary["fresh_work"] == summary["reused_publication_count"] == 0
    assert summary["attempt_outcomes"] == {"INTEGRITY_ERROR": 1}
    assert summary["gaps"]


def test_missing_reused_handoff_is_an_accounting_gap_not_legacy(run_root: Path) -> None:
    PipelineLog(run_root).write("TASK_REUSED", run_id=run_root.name, job_id=JOB,
        attempt_id="attempt_0001", details={"unit_id": UNIT})
    summary = _summary(run_root)
    assert summary["availability"] == "partial"
    assert summary["attempt_outcomes"] == {"INTEGRITY_ERROR": 1}
    assert summary["fresh_work"] == summary["reused_publication_count"] == 0
    assert set(summary["attempts"][0]["counters"].values()) == {None}
    assert summary["gaps"]


def test_historical_reuse_can_resolve_handoff_without_latest_pointer(run_root: Path) -> None:
    case = _case(run_root)
    handoff = _accept(run_root, case)
    (run_root / "data" / "jobs" / JOB / "latest.json").unlink()
    PipelineLog(run_root).write("JOB_REUSED", run_id=run_root.name, job_id=JOB,
        attempt_id="attempt_0001", details={"handoff_sha256": handoff["sha256"]})
    summary = _summary(run_root)
    assert summary["fresh_work"] == 0 and summary["reused_publication_count"] == 1
    assert summary["attempts"][0]["counters"]["output_packages"] == 2
    assert summary["current_inventory"]["availability"] == "not_available"
    assert summary["availability"] == "partial" and summary["gaps"]


@pytest.mark.parametrize("damage", [
    "framework_schema", "framework_status", "framework_snapshot", "framework_attempt",
    "publication_schema", "publication_snapshot", "missing_metrics_member",
    "conflicting_metrics_member", "missing_publication_member", "metrics_size",
    "metrics_hash", "sbom_fingerprint", "sbom_status", "sbom_artifact", "missing_provenance",
    "invalid_advertisement",
])
def test_advertised_accepted_publication_must_bind_framework_document_and_metrics(
        run_root: Path, damage: str) -> None:
    case = _case(run_root)
    _accept(run_root, case)
    handoff, publication = case["handoff"], case["publication"]
    if damage.startswith("framework_"):
        field = {"framework_schema": "schema", "framework_status": "status",
                 "framework_snapshot": "source_fingerprint", "framework_attempt": "attempt_id"}[damage]
        handoff[field] = "invalid"
    elif damage in {"missing_metrics_member", "missing_publication_member"}:
        ref = case["metrics"] if damage == "missing_metrics_member" else (
            handoff["outputs"]["acceptance.publish_handoff"]["artifact"])
        handoff["artifacts"].remove(ref)
    elif damage == "conflicting_metrics_member":
        handoff["artifacts"].append({**case["metrics"], "size_bytes": 0})
    elif damage in {"metrics_size", "metrics_hash"}:
        publication["sbom"]["metrics"] = {
            **case["metrics"], "size_bytes" if damage == "metrics_size" else "sha256":
                0 if damage == "metrics_size" else "f" * 64,
        }
    elif damage == "publication_schema":
        publication["schema"] = "invalid"
    elif damage == "publication_snapshot":
        publication["source_fingerprint"] = "f" * 64
    elif damage == "sbom_fingerprint":
        publication["sbom"]["input_fingerprint"] = "f" * 64
    elif damage == "sbom_status":
        publication["sbom"]["status"] = "FAILED"
    elif damage == "sbom_artifact":
        publication["sbom"]["artifact"] = None
    elif damage == "missing_provenance":
        del publication["sbom"]["provenance"]
    elif damage == "invalid_advertisement":
        publication["sbom"] = {}
    output = handoff["outputs"]["acceptance.publish_handoff"]
    old_ref = output["artifact"]
    new_ref = _write(run_root, old_ref["path"], publication)
    output["artifact"] = new_ref
    handoff["artifacts"] = [new_ref if item == old_ref else item for item in handoff["artifacts"]]
    _save_handoff(run_root, case)
    summary = _summary(run_root)
    assert summary["availability"] == "partial"
    assert summary["current_inventory"]["availability"] == "not_available"
    assert set(summary["current_inventory"]["counters"].values()) == {None}
    assert not summary["accounting_complete"] and summary["gaps"]


@pytest.mark.parametrize("member", ["publication", "metrics", "artifact", "provenance"])
def test_accepted_artifact_tampering_is_not_silently_zero_inventory(
        run_root: Path, member: str) -> None:
    case = _case(run_root)
    _accept(run_root, case)
    ref = (case["handoff"]["outputs"]["acceptance.publish_handoff"]["artifact"]
           if member == "publication" else case[member])
    (run_root / ref["path"]).write_bytes(b"changed")
    summary = _summary(run_root)
    assert summary["availability"] == "partial"
    assert summary["current_inventory"]["counters"]["output_packages"] is None
    assert summary["gaps"]


def test_legacy_runs_and_handoffs_without_feature_are_unavailable_not_clean(run_root: Path) -> None:
    summary = _summary(run_root)
    assert summary["availability"] == "not_available"
    assert not summary["accounting_complete"]
    assert set(summary["current_inventory"]["counters"].values()) == {None}
    case = _case(run_root)
    handoff = _accept(run_root, case, sbom=None)
    PipelineLog(run_root).write("JOB_REUSED", run_id=run_root.name, job_id=JOB,
        attempt_id="attempt_0001", details={"handoff_sha256": handoff["sha256"]})
    summary = _summary(run_root)
    assert summary["availability"] == "not_available"
    assert summary["fresh_work"] == summary["reused_publication_count"] == 0
    assert summary["current_inventory"]["status"] is None
    assert not summary["gaps"]


def test_summary_is_json_serializable_and_contains_only_closed_counter_dimensions(run_root: Path) -> None:
    case = _case(run_root)
    _accept(run_root, case)
    _event(run_root, case)
    summary = _summary(run_root)
    encoded = json.dumps(summary)
    assert "fixture-" not in encoded and "raw_argv" not in encoded
    assert set(summary["current_inventory"]["counters"]) == set(METRIC_COUNTERS)
    assert set(summary["current_inventory"]["gaps_by_kind"]) == GAP_KINDS
