from copy import deepcopy
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from appsec_review.jobs.engineering_contracts import FINAL_PUBLICATION_GATE_SCHEMA
from appsec_review.jobs.job_final_publication_gate import classify as classifier
from appsec_review.jobs.job_inference_security_review.schemas import SchemaSet
from appsec_review.review.decision_audit import contracts as c
from appsec_review.review.models import IntegrityError

from .helpers import HASH, ROOT, audit_fixture, verified_document


@pytest.mark.parametrize("reason,limitation,kind", [
    (None, "decision_audit_scope", "notice"),
    ("disabled", "decision_audit_not_run", "not_run"),
    ("legacy_unrecorded", "decision_audit_not_run", "not_run"),
    ("capacity_exceeded", "decision_audit_unavailable", "gap"),
    ("input_unavailable", "decision_audit_unavailable", "gap"),
])
def test_closed_public_gate_preserves_findings_and_original_gap_ids(reason, limitation, kind):
    verified = verified_document()
    before = deepcopy(verified)
    verified["_decision_audit"] = classifier.decision_audit_summary(audit_fixture(reason=reason), HASH)
    classification = classifier.classify(verified)
    document = classifier.gate_document(FINAL_PUBLICATION_GATE_SCHEMA, verified, classification)
    assert SchemaSet(ROOT / "docs/schemas/final-report").errors("final-publication-gate", document) == []
    assert document["inputs"] == before["inputs"]
    assert document["capabilities"] == before["capabilities"]
    assert document["gap_ids"] == before["gap_ids"] == []
    assert document["ship_block"] == before["ship_block"]
    for package, original in zip(document["packages"], sorted(before["packages"], key=lambda row: row["finding_package_id"])):
        assert {key: value for key, value in package.items() if key not in {"bucket", "withheld_reasons"}} == original
        assert package["bucket"] == ("publishable" if original["state"] == "confirmed" else "verification_backlog")
        assert package["withheld_reasons"] == []
    limitations = {row["limitation_id"]: row for row in document["limitations"]}
    assert limitations[limitation]["kind"] == kind
    assert document["status"] == ("PUBLISHABLE_WITH_LIMITATIONS" if kind == "gap" else "PUBLISHABLE")
    assert [row["limitation_id"] for row in document["limitations"]] == [
        name for name in classifier.LIMITATION_ORDER if name in limitations]
    assert "_decision_audit" not in document
    assert "private" not in json.dumps(document)
    assert "manifest" not in verified["_decision_audit"]


def test_partial_coverage_counts_population_classes_not_mixed_units():
    coverage = {
        c.Population.LEADS: c.CoverageCount(c.Population.LEADS, 99, 0, 99, 0, c.CoverageReason.BOUNDED_OMISSION),
        c.Population.CELLS: c.CoverageCount(c.Population.CELLS, 23, 0, 0, 23, c.CoverageReason.INPUT_UNAVAILABLE),
        c.Population.PROPOSALS: c.CoverageCount(c.Population.PROPOSALS, None, 0, 0, None,
                                               c.CoverageReason.LEGACY_UNAVAILABLE),
    }
    audit = audit_fixture(partial=coverage)
    verified = verified_document()
    baseline = classifier.classify(verified)
    verified["_decision_audit"] = classifier.decision_audit_summary(audit, HASH)
    result = classifier.classify(verified)
    limitation = next(row for row in result["limitations"] if row["limitation_id"] == "decision_audit_partial")
    assert limitation["count"] == 3 and limitation["kind"] == "gap"
    assert "99" not in limitation["statement"] and "23" not in limitation["statement"]
    assert all(population.value in limitation["statement"] for population in coverage)
    assert result["packages"] == baseline["packages"] and result["buckets"] == baseline["buckets"]
    assert result["status"] == "PUBLISHABLE_WITH_LIMITATIONS"
    assert SchemaSet(ROOT / "docs/schemas/final-report").errors(
        "final-publication-gate", classifier.gate_document(FINAL_PUBLICATION_GATE_SCHEMA, verified, result)) == []


def test_source_only_unknown_membership_is_a_proposal_coverage_gap_without_leaking_ids():
    audit = replace(audit_fixture(), lead_membership_unavailable=("secret-lead-identifier",))
    summary = classifier.decision_audit_summary(audit, HASH)
    assert summary["incomplete_populations"] == ["emitted_proposals"]
    assert "secret" not in json.dumps(summary)


def test_historical_verified_unit_without_sidecar_remains_explicit_not_run():
    result = classifier.classify(verified_document())
    limitation = next(row for row in result["limitations"] if row["limitation_id"] == "decision_audit_not_run")
    assert limitation["kind"] == "not_run"
    assert "historical" in limitation["statement"]
    assert result["status"] == "PUBLISHABLE"


@pytest.mark.parametrize("change", ["none", "dict", "foreign-handoff", "manifest-type", "reference-type",
                                   "available-reason", "available-disabled", "reference-digest",
                                   "unavailable-reference", "unavailable-records", "unavailable-continuations",
                                   "unknown-reason", "disabled-enabled", "gap-disabled"])
def test_opt_in_gate_refuses_missing_or_incoherent_typed_sidecar(change):
    audit = audit_fixture()
    if change == "none":
        audit = None
    elif change == "dict":
        audit = {"available": True}
    elif change == "foreign-handoff":
        audit = replace(audit, accepted_handoff_sha256="0" * 64)
    elif change == "manifest-type":
        audit = replace(audit, manifest="not a manifest")
    elif change == "reference-type":
        audit = replace(audit, reference=None)
    elif change == "available-reason":
        audit = replace(audit, unavailable_reason="input_unavailable")
    elif change == "available-disabled":
        audit = replace(audit, settings=replace(audit.settings, enabled=False))
    elif change == "reference-digest":
        audit = replace(audit, reference=replace(audit.reference, sha256="0" * 64))
    else:
        reference = audit.reference
        audit = audit_fixture(reason="disabled")
        if change == "unavailable-reference":
            audit = replace(audit, reference=reference)
        elif change == "unavailable-records":
            audit = replace(audit, records=(SimpleNamespace(record_id="corrupt"),))
        elif change == "unavailable-continuations":
            audit = replace(audit, continuations=(("foreign", ()),))
        elif change == "unknown-reason":
            audit = replace(audit, unavailable_reason="SECRET arbitrary metadata")
        elif change == "disabled-enabled":
            audit = replace(audit, settings=replace(audit.settings, enabled=True))
        else:
            audit = replace(audit, unavailable_reason="capacity_exceeded")
    with pytest.raises(IntegrityError):
        classifier.decision_audit_summary(audit, HASH)


@pytest.mark.parametrize("reason", [None, "disabled", "legacy_unrecorded", "capacity_exceeded", "input_unavailable"])
def test_audit_state_never_hides_other_package_reference_or_ship_block_limitations(reason):
    verified = verified_document()
    verified["packages"][0]["poc"] = {"status": "unavailable", "result_id": None}
    verified["packages"][1]["ship_block"]["status"] = "decision_pending"
    verified["gap_ids"] = ["gap-" + HASH]
    verified["accounting"]["gaps_by_class"] = {"coverage": 1}
    baseline = classifier.classify(verified)
    verified["_decision_audit"] = classifier.decision_audit_summary(audit_fixture(reason=reason), HASH)
    result = classifier.classify(verified)
    assert result["packages"] == baseline["packages"] and result["buckets"] == baseline["buckets"]
    assert set(result["buckets"]["withheld"]) == {verified["packages"][0]["finding_package_id"]}
    assert {"gaps_recorded", "withheld_packages", "decision_pending"} <= {
        row["limitation_id"] for row in result["limitations"]}
    assert verified["gap_ids"] == ["gap-" + HASH]
