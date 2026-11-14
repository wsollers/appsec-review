"""Code-level actionability projections; no run, engine, model or target is opened."""
from copy import deepcopy

import pytest

from appsec_review.jobs.completion_contracts import nonexecution_assurance
from appsec_review.observability.findings.run_adapter import RunDocuments, findings_from_documents
from appsec_review.review.models import IntegrityError


def documents():
    finding = {"finding_package_id": "finding-1", "claim_id": "claim-1", "sha256": "a" * 64,
               "lane": "hunt", "state": "confirmed", "direct_evidence": ["relation-1"],
               "ship_block": {"status": "needs_verification", "technical_severity": "high"},
               "missing_predicates": []}
    relation = {"relation_id": "relation-1", "claim_id": "claim-1", "kind": "supports",
                "predicate": "source_to_sink_reachability", "complete": True,
                "admissibility": "direct_for_mapped_predicate"}
    return RunDocuments(
        {"findings": [finding], "verification_backlog": [], "withheld": []},
        {"claims": [{"claim_id": "claim-1", "state": "confirmed", "preconditions": []}],
         "relations": {"claim-1": [relation]}},
        {"finding-1": {"locations": [{"path": "api.py", "start_line": 3, "end_line": 8}],
                       "citations": {"total": 1, "unresolved": 0}}}, ())


def result(value):
    return findings_from_documents(value)[0][0]["actionability"]


def test_counted_complete_reachability_is_required():
    value = documents()
    before = deepcopy(value)
    assert result(value)["entry_to_sink_path"] is True
    assert value == before


@pytest.mark.parametrize("changes", [
    {"predicate": "affected_construct"}, {"kind": "qualifies"}, {"kind": "contradicts"},
    {"complete": False}, {"admissibility": "analyst_assessed"}, {"admissibility": "indirect"},
    {"relation_id": "not-counted"}, {"claim_id": "another-claim"}, {"provenance": {"judge": "cell"}},
], ids=["unrelated", "qualifies", "contradicts", "partial", "analyst", "indirect",
        "uncounted", "foreign", "judge"])
def test_inadequate_relations_do_not_manufacture_a_path(changes):
    value = documents()
    value.projection["relations"]["claim-1"][0].update(changes)
    assert result(value)["entry_to_sink_path"] is None


def test_missing_relation_and_explicit_missing_predicate_differ():
    value = documents()
    value.projection["relations"] = {}
    assert result(value)["entry_to_sink_path"] is None
    value.report["findings"][0]["missing_predicates"] = ["source_to_sink_reachability"]
    assert result(value)["entry_to_sink_path"] is False


def attachment(value, section, status, key):
    finding = value.report["findings"][0]
    item = {"finding": {name: finding[name] for name in ("claim_id", "finding_package_id", "sha256")},
            "status": status, key: {"path": "protected/artifact.json", "sha256": "b" * 64},
            **nonexecution_assurance()}
    value.report[section] = {"items": [item]}
    return item


@pytest.mark.parametrize("status", ["build_checked", "static_checked", "inconclusive", "rejected",
                                   "manual_validation_required"])
def test_compile_or_static_checks_never_mean_a_runtime_validated_fix(status):
    value = documents()
    attachment(value, "remediation_planning", "proposal_generated", "plan")
    attachment(value, "remediation_validation", status, "validation")
    assert result(value)["remediation"] is True
    assert result(value)["remediation_validated"] is False
    assert value.report["findings"][0]["state"] == "confirmed"


def test_missing_attachments_are_unknown_and_manual_plan_is_not_a_patch():
    value = documents()
    assert result(value)["remediation"] is None
    assert result(value)["remediation_validated"] is None
    row = attachment(value, "remediation_planning", "manual_design_required", "plan")
    row["plan"] = None
    assert result(value)["remediation"] is False


@pytest.mark.parametrize("field,replacement", [("claim_id", "other"), ("sha256", "c" * 64)])
def test_attachment_identity_mismatch_fails(field, replacement):
    value = documents()
    row = attachment(value, "remediation_planning", "proposal_generated", "plan")
    row["finding"][field] = replacement
    with pytest.raises(ValueError, match="different finding identity"):
        result(value)


def test_duplicate_attachments_fail():
    value = documents()
    row = attachment(value, "remediation_planning", "proposal_generated", "plan")
    value.report["remediation_planning"]["items"].append(deepcopy(row))
    with pytest.raises(ValueError, match="repeats"):
        result(value)


def test_foreign_finding_cannot_supply_a_plan():
    value = documents()
    row = attachment(value, "remediation_planning", "proposal_generated", "plan")
    row["finding"]["finding_package_id"] = "other"
    assert result(value)["remediation"] is None


def test_validation_without_plan_fails():
    value = documents()
    attachment(value, "remediation_validation", "static_checked", "validation")
    with pytest.raises(ValueError, match="no accepted plan"):
        result(value)


def test_compile_only_attachment_cannot_claim_runtime_execution():
    value = documents()
    attachment(value, "remediation_planning", "proposal_generated", "plan")
    row = attachment(value, "remediation_validation", "static_checked", "validation")
    row["runtime_verified"] = True
    with pytest.raises(IntegrityError, match="runtime"):
        result(value)
