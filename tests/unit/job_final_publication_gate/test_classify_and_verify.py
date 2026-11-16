"""Classification, bucketing, limitation, and snapshot-verifier unit tests."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.indexing.store import AcceptedHandoff
from appsec_review.jobs.bound_artifacts import artifact_ref
from appsec_review.jobs.engineering_contracts import (
    FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA, FINAL_PUBLICATION_GATE_SCHEMA,
)
from appsec_review.jobs.job_final_publication_gate import classify as gate_classify
from appsec_review.jobs.job_final_publication_gate import verify as gate_verify
from appsec_review.review.models import IntegrityError
from appsec_review.storage import atomic_json
from tests.unit.review_decision_audit_wiring.helpers import HASH, package, verified_document


def test_clean_review_is_publishable_and_not_run_stages_keep_completed_status() -> None:
    doc = verified_document()
    classified = gate_classify.classify(doc)
    assert classified["status"] == "PUBLISHABLE"
    assert classified["package_counts"] == {
        "total": 2, "publishable": 1, "verification_backlog": 1, "withheld": 0, "exact": True,
    }
    kinds = {row["limitation_id"]: row["kind"] for row in classified["limitations"]}
    assert kinds["poc_lane_not_run"] == "not_run"
    assert kinds["attack_chain_composition_not_run"] == "not_run"
    assert kinds["remediation_planning_not_run"] == "not_run"
    assert kinds["remediation_validation_not_run"] == "not_run"
    assert kinds["dossiers_not_run"] == "not_run"
    assert all(kind != "gap" for kind in kinds.values())


def test_withheld_reasons_and_partition_enforcement() -> None:
    doc = verified_document()
    pkg0 = doc["packages"][0]
    pkg0["poc"] = {"status": "compile_verified", "result_id": None}
    pkg0["attack_chains"] = ["chain-" + "1" * 64]
    classified = gate_classify.classify(doc)
    assert classified["status"] == "PUBLISHABLE_WITH_LIMITATIONS"
    assert classified["package_counts"]["withheld"] == 1
    placed0 = next(p for p in classified["packages"] if p["finding_package_id"] == pkg0["finding_package_id"])
    assert placed0["bucket"] == "withheld"
    assert placed0["withheld_reasons"] == ["poc_outcome_unavailable", "attack_chain_unavailable"]
    ids = [row["limitation_id"] for row in classified["limitations"]]
    assert "withheld_packages" in ids

    unpartitioned = verified_document()
    unpartitioned["partition"]["confirmed"] = []
    with pytest.raises(IntegrityError, match="not in the handoff partition"):
        gate_classify.classify(unpartitioned)


def test_package_counts_reject_a_package_in_no_bucket() -> None:
    pkg = {**package(0, "confirmed"), "bucket": "invalid_bucket"}
    with pytest.raises(IntegrityError, match="in no bucket or in more than one"):
        gate_classify.package_counts([pkg])


def test_all_degraded_empty_incomplete_and_scoring_limitations_are_named_gaps() -> None:
    doc = verified_document()
    doc["review"]["status"] = "DEGRADED"
    doc["review"]["review_incomplete"] = True
    doc["accounting"]["gap_ratio"] = 0.25
    doc["accounting"]["incomplete_gap_ratio"] = 0.10
    doc["accounting"]["gaps_by_class"] = {"model_timeout": 2, "zero_class": 0}
    doc["gap_ids"] = ["gap-1", "gap-2"]
    doc["lanes"] = [{
        "lane": "hunt", "outcome": "DEGRADED", "gapped_cells": 2, "gapped_packages": 1, "cells_missing": 1,
    }]
    doc["coverage"] = {"rows": 4, "summary": {"reviewed": 3, "gapped": 1}, "statement": "1 cell gapped"}
    doc["verification"]["warning"] = "red model reused"
    doc["possible_duplicate_pairs"] = 2
    doc["capabilities"]["poc_generation"] = {
        "enabled": True, "disposition": "GAP", "reason": "missing PoC handoff",
        "gap_count": 0, "omitted_count": 0,
    }
    doc["packages"][0]["ship_block"]["status"] = "ship_blocking_pending_distinct_verification"
    doc["packages"][0]["ship_block"]["reasons"] = ["technical_severity_unrated"]
    doc["packages"][1]["ship_block"]["status"] = "decision_pending"
    doc["packages"][1]["scores"] = []

    classified = gate_classify.classify(doc)
    assert classified["status"] == "PUBLISHABLE_WITH_LIMITATIONS"
    by_id = {row["limitation_id"]: row for row in classified["limitations"]}
    expected_gaps = {
        "review_degraded",
        "review_incomplete",
        "lane_degraded",
        "gaps_recorded",
        "coverage_incomplete",
        "pending_distinct_verification",
        "technical_severity_unrated",
        "decision_pending",
        "findings_without_scores",
        "possible_duplicates",
        "poc_generation_gap",
    }
    assert expected_gaps <= set(by_id)
    assert all(by_id[name]["kind"] == "gap" for name in expected_gaps)
    assert "red model reused" in by_id["pending_distinct_verification"]["statement"]
    assert "model_timeout 2" in by_id["gaps_recorded"]["statement"]
    assert "zero_class" not in by_id["gaps_recorded"]["statement"]

    empty = verified_document()
    empty["review"]["status"] = "EMPTY"
    empty["packages"] = []
    empty["partition"] = {"confirmed": [], "supported": []}
    empty_classified = gate_classify.classify(empty)
    assert empty_classified["status"] == "PUBLISHABLE_WITH_LIMITATIONS"
    assert any(
        row["limitation_id"] == "review_empty" and row["kind"] == "gap"
        for row in empty_classified["limitations"]
    )


def test_load_accepted_gate_rejects_corrupt_missing_wrong_job_and_non_object_documents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "run"
    schemas = SimpleNamespace(errors=lambda _name, _doc: [])

    def raise_value_error(_root, _job_id):
        raise ValueError("bad pointer")

    monkeypatch.setattr(gate_verify, "accepted_handoff", raise_value_error)
    with pytest.raises(IntegrityError, match="cannot be verified: bad pointer"):
        gate_verify.load_accepted_gate(root, schemas)

    monkeypatch.setattr(gate_verify, "accepted_handoff", lambda _root, _job_id: None)
    with pytest.raises(IntegrityError, match="accepted job_final_publication_gate handoff is required"):
        gate_verify.load_accepted_gate(root, schemas)

    wrong_job = AcceptedHandoff("job_final_publication_gate", {"job_id": "other_job"}, "a" * 64, "data/h.json")
    monkeypatch.setattr(gate_verify, "accepted_handoff", lambda _root, _job_id: wrong_job)
    with pytest.raises(IntegrityError, match="accepted job_final_publication_gate handoff is required"):
        gate_verify.load_accepted_gate(root, schemas)

    missing_pub = AcceptedHandoff("job_final_publication_gate", {"job_id": "job_final_publication_gate"}, "a" * 64, "data/h.json")
    monkeypatch.setattr(gate_verify, "accepted_handoff", lambda _root, _job_id: missing_pub)
    with pytest.raises(IntegrityError, match="does not publish a supported gate document"):
        gate_verify.load_accepted_gate(root, schemas)

    gate_list_path = root / "data" / "gate-list.json"
    atomic_json(gate_list_path, ["not-an-object"])
    list_ref = artifact_ref(root, gate_list_path)
    non_object_handoff = AcceptedHandoff(
        "job_final_publication_gate",
        {
            "job_id": "job_final_publication_gate",
            "outputs": {
                "acceptance.publish_handoff": {
                    "schema": FINAL_PUBLICATION_GATE_HANDOFF_SCHEMA,
                    "artifact": list_ref,
                    "item_count": 0,
                }
            },
        },
        "a" * 64,
        "data/h.json",
    )
    monkeypatch.setattr(gate_verify, "accepted_handoff", lambda _root, _job_id: non_object_handoff)
    with pytest.raises(IntegrityError, match="gate document is not a JSON object"):
        gate_verify.load_accepted_gate(root, schemas)
    assert FINAL_PUBLICATION_GATE_SCHEMA.startswith("appsec-review/final-publication-gate/")
