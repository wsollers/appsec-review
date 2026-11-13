from __future__ import annotations

from copy import deepcopy

import pytest

from appsec_review.owasp_workbench.assessment import accept_obligations
from appsec_review.owasp_workbench.evidence import component_evidence
from appsec_review.owasp_workbench.obligations import PROCEDURES, instantiate, subjects
from appsec_review.retrieval.model import EntityKind, LogicalIdentity


SQL = "def lookup(cursor, name):\n    return cursor.execute('SELECT id FROM users WHERE name = ?', (name,))\n"
AUTH = "@app.get('/records')\ndef records():\n    return service.records()\n"


def package_for(evidence, rule=PROCEDURES[0]):
    ref = evidence["reference"]
    control = {"family": rule.family, "version": rule.version, "id": rule.control}
    row = {"row_id": "row", "control_identity": f"{rule.family}:{rule.version}:{rule.control}",
           "component_id": "api", "run_id": ref["run_id"], "target_id": ref["target_snapshot"],
           "evidence_mode": "static_source"}
    return {"control": control, "component": {"component_id": "api"},
            "proof_obligations": instantiate(control, row, [evidence], max_subjects=8)}


def proposal_for(package, reference, outcome="satisfied", **changes):
    obligation = next(item for item in package["proof_obligations"] if item["supported"])
    return {"obligations": [{
        "obligation_id": obligation["obligation_id"], "subject_id": obligation["subject_id"],
        "outcome": outcome, "rationale": "Bounded analyst assessment, not an extractor verdict.",
        "supporting": [reference] if outcome == "satisfied" else [],
        "contradictory": [reference] if outcome == "not_satisfied" else [],
        "assumptions": [], "evidence_requests": [], "hypotheses": [], "limitations": [], **changes,
    }]}


@pytest.mark.parametrize("outcome", ["satisfied", "not_satisfied"])
def test_complete_subject_can_be_assessed_without_treating_other_source_as_complete(accepted, settings, outcome):
    boundary = accepted({"app.py": "# outside\n" * 200 + SQL + "# outside\n" * 5})
    [item], _ = component_evidence(boundary.resolver, "api", boundary.files, settings)
    package = package_for(item)
    scoped, coverage = accept_obligations(package, proposal_for(package, item["reference"], outcome), boundary.resolver)
    assert scoped["outcome"] == outcome
    assert scoped["citation_checks"][0]["subject_binding"]
    assert coverage["outcome"] == "cannot_verify"
    assert "205 file lines outside subject remain unassessed" in coverage["gaps"][0]


@pytest.mark.parametrize("control", [2, 3])
@pytest.mark.parametrize("outcome", ["satisfied", "not_satisfied"])
def test_complete_route_alone_cannot_decide_external_authorization(accepted, settings, control, outcome):
    boundary = accepted({"app.py": "# external application policy\n" * 200 + AUTH})
    [item], _ = component_evidence(boundary.resolver, "api", boundary.files, settings)
    package = package_for(item, PROCEDURES[control])
    results = accept_obligations(package, proposal_for(package, item["reference"], outcome), boundary.resolver)
    assert results[0]["outcome"] == "cannot_verify"
    assert any("external authorization policy" in gap for gap in results[0]["gaps"])
    assert not results[0]["hypotheses"]


def test_function_equal_to_file_still_cannot_establish_external_auth_policy(accepted, settings):
    boundary = accepted({"app.py": AUTH})
    [item], _ = component_evidence(boundary.resolver, "api", boundary.files, settings)
    assert item["source_subject"]["kind"] == "function" and not item["truncated"]
    package = package_for(item, PROCEDURES[2])
    [result] = accept_obligations(package, proposal_for(package, item["reference"]), boundary.resolver)
    assert result["outcome"] == "cannot_verify"
    assert any("external authorization policy" in gap for gap in result["gaps"])


@pytest.mark.parametrize("field,value", [
    ("content_sha256", "f" * 64), ("component_id", "foreign"), ("run_id", "foreign"),
    ("source_identity", "unknown"), ("target_snapshot", "foreign"),
], ids=["content", "component", "run", "identity", "target"])
def test_forged_reference_rejected_by_real_reresolution(accepted, settings, field, value):
    boundary = accepted({"app.py": "# padding\n" * 200 + SQL})
    [item], _ = component_evidence(boundary.resolver, "api", boundary.files, settings)
    forged = deepcopy(item["reference"])
    forged[field] = value
    with pytest.raises(ValueError):
        boundary.resolver.resolve(forged, component_id="api")
    assert boundary.resolver.metrics["denials"] == 1


@pytest.mark.parametrize("change", ["lines", "custody", "publication", "file_hash"])
def test_locator_or_publication_forgery_cannot_reuse_subject(accepted, settings, change):
    boundary = accepted({"app.py": "# padding\n" * 200 + SQL})
    [item], _ = component_evidence(boundary.resolver, "api", boundary.files, settings)
    forged = deepcopy(item["reference"])
    if change == "lines":
        forged["locator"]["lines"] = [202, 202]
    elif change == "custody":
        forged["locator"]["source_custody"] = {"source_domain": "generated"}
    elif change == "file_hash":
        forged["locator"]["file_sha256"] = "f" * 64
    else:
        forged["publication"]["sha256"] = "f" * 64
    with pytest.raises(ValueError):
        boundary.resolver.resolve(forged, component_id="api")


def test_different_authentic_site_in_same_file_cannot_prove_obligation(accepted, settings):
    source = SQL + "\n" + SQL.replace("lookup", "other").replace("SELECT id", "SELECT no")
    boundary = accepted({"app.py": source})
    first, second = component_evidence(boundary.resolver, "api", boundary.files, settings)[0]
    assert subjects(PROCEDURES[0], first) != subjects(PROCEDURES[0], second)
    package = package_for(first)
    result = accept_obligations(package, proposal_for(package, second["reference"]), boundary.resolver)[0]
    assert result["outcome"] == "cannot_verify"
    assert result["citation_checks"][0]["resolution"] == "resolved"
    assert not result["citation_checks"][0]["subject_binding"]


def test_clipped_complete_looking_statement_is_not_complete_function(accepted):
    boundary = accepted({"app.py": SQL})
    identity = boundary.files[0].identity
    full = boundary.resolver.materialize(identity, component_id="api")
    narrow = boundary.resolver.materialize(identity, component_id="api",
        locator={**full["reference"]["locator"], "lines": [2, 2]})
    assert narrow["truncated"] and "source_subject" not in narrow
    assert subjects(PROCEDURES[0], narrow) == subjects(PROCEDURES[0], full)
    package = package_for(full)
    result = accept_obligations(package, proposal_for(package, narrow["reference"]), boundary.resolver)[0]
    assert result["outcome"] == "cannot_verify"
    assert any("incomplete" in gap for gap in result["gaps"])


@pytest.mark.parametrize("field", ["assumptions", "evidence_requests"])
def test_complete_subject_does_not_remove_existing_prerequisite_gate(accepted, field):
    boundary = accepted({"app.py": SQL})
    item = boundary.resolver.materialize(boundary.files[0].identity, component_id="api")
    package = package_for(item)
    result = accept_obligations(package, proposal_for(package, item["reference"],
        **{field: ["Resolve query driver binding semantics."]}), boundary.resolver)[0]
    assert result["outcome"] == "cannot_verify"
    assert any("prerequisites remain assumed or requested" in gap for gap in result["gaps"])


def test_forged_complete_metadata_cannot_override_real_source_redaction(accepted):
    source = SQL.replace("return cursor", "password = 'secret-value'\n    return cursor")
    boundary = accepted({"app.py": source})
    real = boundary.resolver.materialize(boundary.files[0].identity, component_id="api")
    forged = {**real, "excerpt": source.rstrip(), "redaction": {"applied": False}}
    package = package_for(forged)
    result = accept_obligations(package, proposal_for(package, real["reference"]), boundary.resolver)[0]
    assert result["outcome"] == "cannot_verify"
    assert not result["supporting"]


def test_materialize_keeps_parse_failure_and_character_clipping_nondecisive(accepted):
    boundary = accepted({"broken.py": "def broken(:\n", "long.py": SQL + "#" + "x" * 17000})
    broken = boundary.resolver.materialize(boundary.files[0].identity, component_id="api")
    assert "source_subject" not in broken and not subjects(PROCEDURES[0], broken)
    long = boundary.resolver.materialize(boundary.files[1].identity, component_id="api")
    assert long["truncated"] and len(long["excerpt"]) == 16000
    assert not subjects(PROCEDURES[0], long)


def test_same_site_with_different_complete_context_is_order_independent(accepted, settings):
    boundary = accepted({"app.py": "# outside\n" + SQL})
    [selected], _ = component_evidence(boundary.resolver, "api", boundary.files, settings)
    full = boundary.resolver.materialize(boundary.files[0].identity, component_id="api")
    rule = PROCEDURES[0]
    control = {"family": rule.family, "version": rule.version, "id": rule.control}
    row = {"row_id": "row", "control_identity": f"{rule.family}:{rule.version}:{rule.control}",
           "component_id": "api", "evidence_mode": "static_source"}
    assert subjects(rule, full) == subjects(rule, selected)
    assert instantiate(control, row, [full, selected], max_subjects=8) == instantiate(
        control, row, [selected, full], max_subjects=8)


def test_complete_indexed_span_retains_outside_file_omission(accepted):
    boundary = accepted({"app.py": "# before\n" * 10 + SQL})
    identity = LogicalIdentity.derive(EntityKind.SOURCE_SPAN, boundary.scope.target_snapshot,
                                       {"path": "app.py", "lines": [11, 12]}).value
    entity = deepcopy(boundary.entities[boundary.files[0].identity])
    entity.update(identity=identity, kind="source_span")
    entity["location"]["start_line"] = 11
    entity["location"]["start_byte"] = len("# before\n" * 10)
    boundary.entities[identity] = entity
    item = boundary.resolver.materialize(identity, component_id="api")
    assert not item["truncated"] and item["source_subject"]["complete"]
    assert any("10 file lines outside subject" in gap for gap in item["limitations"])


def test_untruncated_index_statement_is_still_not_complete_enclosing_subject(accepted):
    boundary = accepted({"app.py": SQL})
    full = boundary.resolver.materialize(boundary.files[0].identity, component_id="api")
    identity = LogicalIdentity.derive(EntityKind.SOURCE_SPAN, boundary.scope.target_snapshot,
                                       {"path": "app.py", "lines": [2, 2]}).value
    entity = deepcopy(boundary.entities[boundary.files[0].identity])
    entity.update(identity=identity, kind="source_span")
    entity["location"].update(start_line=2, start_byte=len(SQL.splitlines(keepends=True)[0]))
    boundary.entities[identity] = entity
    statement = boundary.resolver.materialize(identity, component_id="api")
    assert not statement["truncated"] and "source_subject" not in statement
    assert subjects(PROCEDURES[0], statement) == subjects(PROCEDURES[0], full)
    package = package_for(full)
    [result] = accept_obligations(package, proposal_for(package, statement["reference"]), boundary.resolver)
    assert result["outcome"] == "cannot_verify"
    assert any("incomplete" in gap for gap in result["gaps"])
