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
