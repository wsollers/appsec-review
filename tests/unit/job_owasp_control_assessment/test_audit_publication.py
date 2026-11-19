"""T-5154/5155: coverage and qualification survive the real join/publication boundary."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_owasp_control_assessment import job
from appsec_review.inference import ModelResult
from appsec_review.owasp_workbench import assessment
from appsec_review.owasp_workbench import (
    assess_batch, build_applicability, build_finding_packages, classify_components,
    control_records, deterministic_join, load_catalogs, partition_work, select_profiles,
    standards_manifest, target_class_ledger, verify_results,
)
from appsec_review.owasp_workbench.engine import extract_verified_control_gaps
from appsec_review.owasp_workbench.evidence import component_evidence
from tests.test_owasp_assessment_job import _base_app_config
from tests.test_owasp_workbench import WEB, citation, component
from tests.unit.job_owasp_control_assessment.test_audit_assessment import (
    BATCH, PROFILE, SQL, assessment_package, proposal_for,
)


ROOT = Path(__file__).resolve().parents[3]


def publish(tmp_path, *, classes, rows, results, configured, loaded_gaps=()):
    catalogs = load_catalogs(ROOT, configured["standards"])
    outputs = {
        "standards_selection.ingest_catalogs": {"manifest": standards_manifest(catalogs)},
        "standards_selection.select_profiles": {"selection": select_profiles(catalogs)},
        "characterization.load_inputs": {"gaps": list(loaded_gaps), "limitations": []},
        "characterization.classify_components": {"classifications": classes},
        "applicability.build_matrix": {"rows": rows, "ledger": target_class_ledger(classes, rows)},
        "verification.independent_review": {"verified_results": results, "batch_results": []},
        "publication.publish_indexes": {"manifest": {}},
        **{f"validation.{cell}": {"failed_batch_count": 0} for cell in job.CELLS},
    }
    unit = SimpleNamespace(
        job=SimpleNamespace(config=SimpleNamespace(settings=configured), repository_root=ROOT,
                            run_root=tmp_path, run_id="unit-run", attempt_root=tmp_path / "attempt",
                            events=SimpleNamespace(write=lambda *args, **kwargs: None)),
        unit_id="join.deterministic_join", output=outputs.__getitem__)
    handlers = {item.unit_id: item.handler for item in job.build_job().units}
    outputs[unit.unit_id] = handlers[unit.unit_id](unit)
    unit.unit_id = "publication.publish_handoff"
    receipt = handlers[unit.unit_id](unit)
    report = json.loads((tmp_path / receipt["artifact"]["path"]).read_text())
    return outputs, receipt, report


@pytest.mark.parametrize("source", ["load", "classification", "both", "none"])
def test_characterization_gaps_survive_no_dispatch_publication(tmp_path, source, accepted):
    configured = deepcopy(dict(_base_app_config().job("job_owasp_control_assessment").settings))
    catalogs = load_catalogs(ROOT, configured["standards"])
    assert standards_manifest(catalogs)["gaps"] == []
    tag_gap = "api: tag record cap omitted 1 target class or facet records; the component classification is unread"
    exclusion = "1 accepted source files outside the first-party disposition excluded (vendored 1)"
    raw = component("api", ["target:cli"])
    boundary = accepted({"app.py": "print('inert')\n"})
    raw["evidence"] = [boundary.resolver.materialize("component", component_id="api")["reference"]]
    if source in {"classification", "both"}:
        raw.update(gaps=[tag_gap], tag_records_omitted=1)
    classes = classify_components([raw], assessment_mode="assessment")
    rows = build_applicability(catalogs, classes, select_profiles(catalogs), assessment_mode="assessment")
    assert rows and {row["outcome"] for row in rows} == {"not_applicable"}
    loaded_gaps = [exclusion] if source == "load" else [tag_gap] if source == "both" else []
    outputs, receipt, report = publish(tmp_path, classes=classes, rows=rows, results=[],
                                       configured=configured, loaded_gaps=loaded_gaps)
    expected = [exclusion] if source == "load" else [tag_gap] if source != "none" else []
    assert report["gaps"] == expected
    expected_status = "COMPLETED_WITH_GAPS" if expected else "SUCCEEDED"
    assert receipt["terminal_status"] == expected_status
    assert outputs["join.deterministic_join"]["terminal_status"] == expected_status
    assert receipt["coverage_disposition"] == report["coverage_disposition"] == (
        "partial" if expected else "complete")
    assert report["coverage"]["dispatched_rows"] == 0
    assert report["coverage"]["unresolved_rows"] == 0


def test_partial_adverse_row_is_counted_as_unresolved(tmp_path, accepted, settings):
    configured = deepcopy(dict(_base_app_config().job("job_owasp_control_assessment").settings))
    catalogs = load_catalogs(ROOT, configured["standards"])
    raw = component("api", WEB)
    boundary = accepted({"app.py": SQL + "# outside\n" * 200})
    raw["evidence"] = [boundary.resolver.materialize("component", component_id="api")["reference"]]
    raw["source_support"] = {"languages": ["python"], "supported_files": 1}
    classes = classify_components([raw], assessment_mode="assessment")
    rows = [row for row in build_applicability(catalogs, classes, select_profiles(catalogs),
                                              assessment_mode="assessment")
            if row["control_id"] == "V1.2.4"]
    assert len(rows) == 1 and rows[0]["outcome"] == "applicable"
    [evidence], _ = component_evidence(boundary.resolver, "api", boundary.files, settings)
    package = assessment_package(evidence, row_id=rows[0]["row_id"])

    def infer(request, **_):
        return ModelResult({"schema": assessment.TURN_SCHEMA, "action": "final", "results": [{
            "row_id": package["row_id"], **proposal_for(package, evidence["reference"], "not_satisfied")}]})

    batch = assessment.run_batch(
        repository_root=ROOT, run_root=tmp_path, batch=BATCH, packages=[package], settings=settings,
        worker_profile=PROFILE, reviewer_profile=PROFILE, resolver=boundary.resolver, infer=infer,
        independent=False)
    results = batch["results"]
    assert results[0]["status"] == "not_satisfied" and results[0]["coverage_completeness"] == "partial"
    joined = deterministic_join(rows, results)
    assert job.coverage_disposition(joined["results"]) == "partial"
    _, receipt, report = publish(tmp_path, classes=classes, rows=rows, results=results, configured=configured)
    assert receipt["coverage_disposition"] == "partial"
    assert report["coverage"]["unresolved_rows"] == 1
    assert report["coverage"]["dispatched_rows"] == 1
    assert report["coverage"]["independent_review_attempted_rows"] == 0


def test_adverse_qualification_publishes_without_a_target_manifest(tmp_path):
    configured = deepcopy(dict(_base_app_config().job("job_owasp_control_assessment").settings))
    configured["mode"] = "qualification"
    configured["model"]["enabled"] = False
    configured["models"][configured["reviewer_profile"]]["enabled"] = False
    catalogs = load_catalogs(ROOT, configured["standards"])
    selection = select_profiles(catalogs)
    classes = classify_components([component("api", WEB)])
    rows = [row for row in build_applicability(catalogs, classes, selection)
            if row["control_id"] == "V1.2.4"]
    [batch] = partition_work(rows, ROOT)["batches"]
    packages = build_finding_packages(
        batch, rows, control_records(catalogs, asvs_level=2, masvs_profile="L2"), classes,
        [{"component_id": "api", "control_id": "V1.2.4", "disposition": "refutes",
          "citation": citation("synthetic:refutation")}], retrieval_manifest={"fixture": "inert"})
    assessed = assess_batch(batch, packages)
    verified = verify_results([assessed])
    assert verified[0]["status"] == "not_satisfied" and not verified[0]["lead_eligible"]
    _, receipt, report = publish(tmp_path, classes=classes, rows=rows, results=verified, configured=configured)
    assert receipt["terminal_status"] == "SUCCEEDED"
    assert report["assessment_mode"] == "qualification"
    assert report["coverage"]["assessed_rows"] == report["coverage"]["dispatched_rows"] == 0
    gaps = json.loads((tmp_path / receipt["gap_summary_artifact"]["path"]).read_text())
    assert gaps == extract_verified_control_gaps("unit-run", "qualification",
                                                deterministic_join(rows, verified)["results"])
    assert gaps["controls_assessed"] == gaps["verified_gaps_indexed"] == 0
    assert gaps["control_gaps"] == gaps["coverage_gaps"] == []
