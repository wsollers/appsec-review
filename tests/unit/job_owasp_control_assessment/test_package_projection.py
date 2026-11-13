import pytest
from dataclasses import replace

from appsec_review.owasp_workbench.evidence import component_evidence
from appsec_review.owasp_workbench.engine import build_finding_packages
from appsec_review.owasp_workbench.obligations import PROCEDURES


def package(accepted, maximum):
    fixture = accepted({"api.py": "def query(value):\n    return db.execute('SELECT x FROM t WHERE id = ' + value)\n"})
    ref = fixture.resolver.materialize(fixture.files[0].identity, component_id="api")
    evidence = [{"component_id": "api", "category": "declaration", "evidence_id": str(number)}
                for number in range(100)] + [{"component_id": "api", **ref}]
    rule = next(item for item in PROCEDURES if item.control == "V1.2.4")
    control_id = "ASVS:5.0.0:V1.2.4"
    row = {"row_id": "r", "target_id": fixture.scope.target_snapshot, "project_id": "project",
           "component_id": "api", "standard": "ASVS", "version": "5.0.0", "profile": "L2",
           "control_identity": control_id, "control_id": "V1.2.4", "evidence_mode": "static_source",
           "required_tools": []}
    control = {"control_identity": control_id, "family": "ASVS", "id": "V1.2.4", "version": "5.0.0",
               "title": "SQL", "text": rule.control_text}
    result, = build_finding_packages(
        {"batch_id": "batch", "row_ids": ["r"], "required_tools": []}, [row], [control],
        [{"component_id": "api", "roles": ["application_api_server"], "evidence": []}], evidence,
        retrieval_manifest={}, assessment_mode="assessment", max_evidence=maximum)
    return result


def test_configured_evidence_beyond_the_old_100_record_limit_reaches_worker(accepted):
    result = package(accepted, 101)
    assert len(result["evidence_references"]) == 101
    assert any(item["supported"] for item in result["proof_obligations"])
    assert result["evidence_references"][-1]["source_subject"]["complete"]


def test_omitted_evidence_cannot_generate_an_unanswerable_obligation(accepted):
    result = package(accepted, 100)
    assert len(result["evidence_references"]) == 100
    assert not any(item["supported"] for item in result["proof_obligations"])
    assert any("omitted 1" in gap for gap in result["limitations"])


@pytest.mark.parametrize("maximum", [0, 201, True])
def test_projection_bound_is_closed(accepted, maximum):
    with pytest.raises(ValueError, match="between 1 and 200"):
        package(accepted, maximum)


def test_unsupported_indexed_file_cannot_starve_supported_subjects(accepted, settings):
    fixture = accepted({
        "a.c": "void service(void) {}\n",
        "z.py": "def query(value):\n    return db.execute('SELECT x FROM t WHERE id = ' + value)\n",
    }, hints=(("a.c", 1, 1),), languages={"a.c": "C", "z.py": "Python"})
    evidence, gaps = component_evidence(
        fixture.resolver, "api", fixture.files, replace(settings, max_discovery_files=1))
    assert len(evidence) == 1
    assert evidence[0]["reference"]["locator"]["path"] == "z.py"
    assert any("max_discovery_files" in gap for gap in gaps)
