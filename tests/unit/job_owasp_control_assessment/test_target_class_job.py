"""T-5008 Done-when (c), job level: a CLI-only target ends the OWASP job after applicability.

No batch, no OWASP_WORKER_STARTED event, no control_evidence fact; the only gaps are the fixture
catalogs' own, so with complete catalogs the handoff is SUCCEEDED.
"""
from __future__ import annotations

import json

from appsec_review.observability import PipelineLog
from tests.test_owasp_assessment_job import ScriptedAssessment, accepted_fixture, execute


def test_cli_target_ends_after_applicability_with_a_not_applicable_ledger(tmp_path) -> None:
    fixture = accepted_fixture(tmp_path, facets="cli")
    transport = ScriptedAssessment()
    outputs = execute(fixture, transport)
    assert transport.calls == []
    classifications = outputs["characterization.classify_components"]["classifications"]
    assert {item["component_id"]: item["target_classes"] for item in classifications} == {
        "component:0001": ["target:cli"], "component:0002": ["target:cli"]}
    matrix = outputs["applicability.build_matrix"]
    assert set(matrix["outcome_counts"]) == {"not_applicable"} and matrix["dispatchable_rows"] == 0
    ledger = matrix["ledger"]
    assert ledger["schema"] == "appsec-review/target-class-ledger/1"
    assert {entry["verdict"] for entry in ledger["entries"]} == {"not_applicable"}
    assert all(entry["citations"] for entry in ledger["entries"])
    assert outputs["batching.partition_work"]["batch_count"] == 0
    events, _truncated = PipelineLog(fixture.run_root).read()
    assert not any("OWASP_WORKER_STARTED" in json.dumps(record) for record in events)
    assert all(outputs[f"validation.cell_0{index}"]["assigned_batch_count"] == 0 for index in range(1, 5))
    handoff = outputs["publication.publish_handoff"]
    report = json.loads((fixture.run_root / handoff["artifact"]["path"]).read_text(encoding="utf-8"))
    catalog_gaps = set(outputs["standards_selection.ingest_catalogs"]["gaps"])
    assert set(report["gaps"]) == catalog_gaps, "the not-applicable ledger is a result, not a gap"
    assert handoff["terminal_status"] == ("COMPLETED_WITH_GAPS" if catalog_gaps else "SUCCEEDED")
    # D5: a typed coverage disposition travels with the status (outcomes.json recorded None before).
    assert outputs["join.deterministic_join"]["coverage_disposition"] == "complete"
    assert handoff["coverage_disposition"] == report["coverage_disposition"] == (
        "partial" if catalog_gaps else "complete")
    assert outputs["characterization.load_inputs"]["gaps"] == []
    assert outputs["characterization.load_inputs"]["terminal_status"] == "SUCCEEDED"
    assert report["coverage"]["applicable_rows"] == 0 and report["coverage"]["dispatched_rows"] == 0
    assert report["target_class_ledger"] == ledger
    joined = outputs["join.deterministic_join"]["joined"]["results"]
    assert joined and {row["applicability"] for row in joined} == {"not_applicable"}
    assert {row["control_status"] for row in joined} == {"not_assessed"}
    # Projection: a not_applicable row is a ledger entry, never a control_evidence fact.
    from appsec_review.indexing.products import control_evidence_candidate
    assert not any(control_evidence_candidate(row) for row in joined)
    assert control_evidence_candidate({**joined[0], "applicability": "applicable"})
    assert control_evidence_candidate({**joined[0], "applicability": "cannot_determine"})


def test_network_service_target_admits_only_the_transport_agnostic_asvs_chapters(tmp_path) -> None:
    """D3 (run 2026-11-16-0005): a non-HTTP listener is target:network-service beside target:cli.

    The fixture's svc handler is a Python network service with a SQL subject, so the one admitted control
    with a reviewed procedure (V1.2.4) is assessed; the other admitted rows have no procedure and the
    web-only chapters cite the class. The C component stays a plain CLI.
    """
    fixture = accepted_fixture(tmp_path, facets="network-service")
    transport = ScriptedAssessment()
    outputs = execute(fixture, transport)
    classifications = outputs["characterization.classify_components"]["classifications"]
    svc = next(item for item in classifications if item["component_id"] == "component:0001")
    assert svc["target_classes"] == ["target:cli", "target:network-service"] and "network" in svc["roles"]
    assert svc["source_support"]["supported_files"] >= 1 and svc["target_class_unread"] is False
    matrix = outputs["applicability.build_matrix"]
    ledger = {(entry["component_id"], entry["family"]): entry for entry in matrix["ledger"]["entries"]}
    asvs = ledger[("component:0001", "ASVS")]
    assert asvs["verdict"] == "partially_applicable" and asvs["basis_class"] == "target:network-service"
    assert asvs["admitted_chapters"] == ["V1", "V2", "V5", "V7", "V16"] and asvs["citations"]
    assert ledger[("component:0001", "MASVS")]["verdict"] == "not_applicable"
    assert ledger[("component:0002", "ASVS")]["verdict"] == "not_applicable"
    svc_rows = [row for row in matrix["rows"] if row["component_id"] == "component:0001" and row["standard"] == "ASVS"]
    admitted = [row for row in svc_rows if row["control_id"].split(".")[0] in {"V1", "V2", "V5", "V7", "V16"}]
    web_only = [row for row in svc_rows if row not in admitted]
    assert web_only and {row["outcome"] for row in web_only} == {"not_applicable"}
    assert all("target:network-service admits ASVS only for the transport-agnostic chapters" in row["reason"]
               and "web-only" in row["reason"] for row in web_only)
    assert all(row["admitted_chapters"] == ["V1", "V2", "V5", "V7", "V16"] and row["basis_class"] == "target:network-service"
               for row in svc_rows)
    dispatched = [row for row in admitted if row["outcome"] in {"applicable", "conditional"}]
    assert [row["control_id"] for row in dispatched] == ["V1.2.4"]
    assert {row["outcome"] for row in admitted if row not in dispatched} == {"unsupported_missing_evidence"}
    assert all("no reviewed versioned proof procedure" in row["reason"] for row in admitted if row not in dispatched)
    assert outputs["batching.partition_work"]["batch_count"] == 1 and transport.calls
    assert outputs["join.deterministic_join"]["coverage_disposition"] == "partial"
    joined = outputs["join.deterministic_join"]["joined"]["results"]
    assert sum(row["applicability"] in {"applicable", "conditional"} for row in joined) == 1
    selection = outputs["standards_selection.select_profiles"]["selection"]
    assert all(item["reasons"] for item in selection["selections"])
