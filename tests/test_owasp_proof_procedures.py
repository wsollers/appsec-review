"""Source-grounded procedure/identity tests; no model verdicts or agreement are simulated."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.owasp_workbench.assessment import accept_obligations
from appsec_review.owasp_workbench.evidence import EvidenceResolver
from appsec_review.owasp_workbench.obligations import (
    PROCEDURES, VERSION, instantiate, procedure_for, subjects,
)
from appsec_review.owasp_workbench.standards import control_records, digest, load_catalogs
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, RetrievalCore,
    SourceLocation, index_fingerprint, write_manifest,
)
from appsec_review.review.scope import accept_manifest
from appsec_review.storage import atomic_json, file_sha256


ROOT = Path(__file__).resolve().parents[1]
RUN_ID = "2026-10-28-0001"
COMPONENT = "api"
SQL = "def lookup(cursor, name):\n    return cursor.execute('SELECT id FROM users WHERE name = ?', (name,))\n"
PASSWORD = "def register(password):\n    if len(password) < 8:\n        raise ValueError('too short')\n    return create_user(password)\n"
AUTH = "@app.delete('/users/{id}')\ndef delete_user(id, actor):\n    require_permission(actor, 'delete_user')\n    return service.delete_user(id)\n"


@pytest.fixture(scope="module")
def catalogs():
    settings = load_config(ROOT / "appsec-review.toml").job("job_owasp_control_assessment").settings
    return load_catalogs(ROOT, settings["standards"])


@pytest.fixture(scope="module")
def controls(catalogs) -> dict:
    return {item["id"]: item for item in control_records(catalogs, asvs_level=3, masvs_profile="L2")}


def _accepted(tmp_path: Path, source: str, *, path: str = "app.py"):
    """Publish actual source bytes through the real accepted-manifest/resolution boundary."""
    run_root = tmp_path / "runs" / RUN_ID
    target = tmp_path / "target"
    file = target / path
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_bytes(source.encode("utf-8"))
    sha = file_sha256(file)
    snapshot = "target-sha256:" + digest({"path": path, "sha256": sha})
    location = SourceLocation(snapshot, path, sha, 0, file.stat().st_size,
                              1, len(source.splitlines()), 1, 1, {}, "fixture-exact", 1.0)
    file_id = LogicalIdentity.derive(EntityKind.SOURCE_FILE, snapshot, {"path": path, "sha256": sha})
    span_id = LogicalIdentity.derive(EntityKind.SOURCE_SPAN, snapshot, {"path": path, "span": "whole"})
    component_id = LogicalIdentity.derive(EntityKind.COMPONENT, snapshot, {"id": COMPONENT})
    indexes = []
    for name, records in (
        ("source", [
            EntityRecord(file_id, path, path, source, {"language": "Python"}, location),
            EntityRecord(span_id, "whole", path, source, {"language": "Python"}, location),
        ]),
        ("components", [
            EntityRecord(component_id, COMPONENT, "application", "fixture application", {"root": "."}),
        ]),
    ):
        fingerprint = index_fingerprint(
            name=name, target_snapshot=snapshot, producer_artifacts=[{"sha256": sha}],
            tool_identity={"tool": "source-fixture"}, parser_identity="fixture/1",
            normalizer_identity="fixture/1", mapping_identity="fixture/1")
        shard_path = run_root / "data" / "indices" / name / f"{fingerprint}.sqlite"
        builder = IndexBuilder(shard_path, name=name, fingerprint=fingerprint, target_snapshot=snapshot)
        for record in records:
            builder.add_entity(record)
        builder.add_coverage(name, "complete", None)
        indexes.append(IndexIdentity(
            name, "appsec-review/retrieval-index/2", builder.build(), fingerprint,
            shard_path.relative_to(run_root).as_posix(), {"job": "job_target_catalog"}))
    manifest = run_root / "data" / "indices" / "manifests" / "fixture.json"
    write_manifest(manifest, run_id=RUN_ID, target_snapshot=snapshot, target_root=target, indexes=indexes)
    artifact = {"path": manifest.relative_to(run_root).as_posix(), "sha256": file_sha256(manifest),
                "size_bytes": manifest.stat().st_size}
    handoff = run_root / "data" / "jobs" / "fixture" / "attempts" / "attempt_0001" / "handoff.json"
    atomic_json(handoff, {"schema": "appsec-review/job-handoff/1", "status": "ACCEPTED",
                         "job_id": "fixture", "attempt_id": "attempt_0001",
                         "artifacts": [artifact], "outputs": {}})
    atomic_json(run_root / "data" / "indices" / "accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": RUN_ID,
        "handoff_path": handoff.relative_to(run_root).as_posix(), "handoff_sha256": file_sha256(handoff),
        "manifest_path": artifact["path"], "manifest_sha256": artifact["sha256"],
    })
    resolver = EvidenceResolver(RetrievalCore(tmp_path / "runs", RUN_ID), accept_manifest(run_root))
    evidence = resolver.materialize(file_id.value, component_id=COMPONENT)
    assert resolver.resolve(evidence["reference"], component_id=COMPONENT) == evidence
    return resolver, evidence, span_id.value


def _row(control: dict, evidence: dict) -> dict:
    return {"row_id": "row:" + control["id"], "control_identity": control["control_identity"],
            "component_id": COMPONENT, "run_id": evidence["reference"]["run_id"],
            "target_id": evidence["reference"]["target_snapshot"],
            "evidence_mode": control["evidence_mode"]}


def _obligations(control: dict, evidence: dict, *, max_subjects: int = 8) -> list[dict]:
    return instantiate(control, _row(control, evidence), [evidence], max_subjects=max_subjects)


def test_procedures_match_actual_pinned_controls_not_fixture_paraphrases(catalogs, controls) -> None:
    assert VERSION == "owasp-proof-obligations/2"
    assert {rule.control for rule in PROCEDURES} == {
        "V1.2.4", "V6.2.1", "V8.2.1", "V8.3.1", "MASVS-NETWORK-1"}
    for rule in PROCEDURES:
        catalog = catalogs[rule.family]
        control = controls[rule.control]
        assert not catalog.fixture
        assert rule.version == catalog.version and rule.upstream_commit == catalog.source["commit"]
        assert rule.control_text == control["text"]
        assert procedure_for(control) is rule
        assert rule.procedure_version == VERSION
        assert all((rule.invariant, rule.subject_scope, rule.prerequisites, rule.required_categories,
                    rule.support, rule.contradiction, rule.effective_control_questions,
                    rule.satisfied, rule.not_satisfied, rule.cannot_verify, rule.static_limits))
        assert control["source"]["path"] in catalog.coverage["sources"]
    assert "explicit permissions" in controls["V8.2.1"]["text"]
    assert "trusted service layer" in controls["V8.3.1"]["text"]
    assert "15 characters" in procedure_for(controls["V6.2.1"]).control_text
    assert any("recommendation" in text for text in procedure_for(controls["V6.2.1"]).satisfied)


def test_network_mastg_crosswalk_remains_supporting_guidance_only(catalogs, controls) -> None:
    crosswalk = {test["id"]: test["supports"] for test in catalogs["MASTG"].records}
    assert "MASVS-NETWORK-1" in crosswalk["MASTG-TEST-0019"]
    assert "MASVS-NETWORK-1" in crosswalk["MASTG-TEST-0020"]
    network = controls["MASVS-NETWORK-1"]
    assert catalogs["MASTG"].identity("MASTG-TEST-0019") in network["supporting_tests"]
    rule = procedure_for(network)
    assert rule.evidence_mode == "dynamic_runtime"
    assert "runtime_observation" in rule.required_categories
    assert "all network traffic" in network["text"]
    assert "cannot establish" in rule.subject_scope


@pytest.mark.parametrize(("native", "source", "name"), [
    ("V1.2.4", SQL, "query call cursor.execute"),
    ("V1.2.4", SQL.replace("'SELECT id FROM users WHERE name = ?', (name,)",
                           "f\"SELECT id FROM users WHERE name = '{name}'\""), "query call cursor.execute"),
    ("V6.2.1", PASSWORD, "password comparison in register"),
    ("V6.2.1", PASSWORD.replace("< 8", "< 4"), "password comparison in register"),
    ("V8.2.1", AUTH, "DELETE /users/{id} -> delete_user"),
    ("V8.2.1", AUTH.replace("    require_permission(actor, 'delete_user')\n", ""),
     "DELETE /users/{id} -> delete_user"),
    ("V8.3.1", AUTH, "DELETE /users/{id} -> delete_user"),
    ("V8.3.1", AUTH.replace("    require_permission(actor, 'delete_user')\n", ""),
     "DELETE /users/{id} -> delete_user"),
])
def test_positive_and_adverse_source_paths_are_questions_not_verdicts(
        tmp_path: Path, controls, native: str, source: str, name: str) -> None:
    resolver, evidence, _ = _accepted(tmp_path, source)
    [obligation] = _obligations(controls[native], evidence)
    assert obligation["supported"] and obligation["subject"]["name"] == name
    assert obligation["rule_version"] == VERSION
    assert obligation["control_identity"] == controls[native]["control_identity"]
    assert obligation["evidence_ids"] == [evidence["evidence_id"]]
    assert obligation["subject_id"] in subjects(procedure_for(controls[native]), evidence)
    assert set(obligation["criteria"]) == {"satisfied", "not_satisfied", "cannot_verify"}
    assert "outcome" not in obligation
    assert obligation["scope"]["source"]["file_sha256"] == evidence["reference"]["locator"]["file_sha256"]
    package = {"control": controls[native], "component": {"component_id": COMPONENT},
               "proof_obligations": [obligation]}
    [accepted] = accept_obligations(package, None, resolver)
    assert accepted["outcome"] == "cannot_verify"
    assert not accepted["hypotheses"]


@pytest.mark.parametrize(("native", "source"), [
    ("V1.2.4", "# cursor.execute('SELECT x')\nmessage = \"cursor.execute('SELECT x')\"\n"),
    ("V1.2.4", "def lookup(cursor, unknown_query):\n    return cursor.execute(unknown_query)\n"),
    ("V1.2.4", "def task(worker):\n    return worker.execute('compile')\n"),
    ("V6.2.1", "min_password_length = 8\n"),
    ("V6.2.1", "def metrics(password):\n    return len(password) > 8\n"),
    ("V6.2.1", "def register(password):\n    return create_user(password)\n"),
    ("V8.2.1", "def admin():\n    return service.delete_user(1)\n"),
    ("V8.3.1", "message = \"@app.get('/admin')\"\n"),
    ("V8.2.1", "@app.route(computed_path)\ndef admin():\n    pass\n"),
])
def test_lexical_hints_opaque_sites_and_missing_subjects_stay_unresolved(
        tmp_path: Path, controls, native: str, source: str) -> None:
    _, evidence, _ = _accepted(tmp_path, source)
    assert subjects(procedure_for(controls[native]), evidence) == []
    [gap] = _obligations(controls[native], evidence)
    assert not gap["supported"] and gap["subject_id"] is None
    assert gap["required_outcome"] == "cannot_verify"
    assert "no resolving subject" in gap["reason"]


@pytest.mark.parametrize(("source", "native", "count"), [
    ("def lookup(cursor):\n    cursor.execute('SELECT 1'); cursor.execute('SELECT 2')\n", "V1.2.4", 2),
    ("def validate_password(password):\n    return len(password) >= 8 and len(password) < 100\n",
     "V6.2.1", 2),
    ("@app.get('/a')\n@app.post('/b')\ndef action():\n    return service.action()\n", "V8.2.1", 2),
    ("@app.get('/a')\ndef first():\n    pass\n\n@app.get('/b')\ndef second():\n    pass\n", "V8.3.1", 2),
])
def test_multisite_subjects_preserve_distinct_actual_spans(
        tmp_path: Path, controls, source: str, native: str, count: int) -> None:
    _, evidence, _ = _accepted(tmp_path, source)
    obligations = _obligations(controls[native], evidence)
    assert len(obligations) == count and all(item["supported"] for item in obligations)
    assert len({item["subject_id"] for item in obligations}) == count
    assert len({digest(item["subject"]["locator"]) for item in obligations}) == count
    assert len({item["subject"]["source_identity"] for item in obligations}) == 1
    for item in obligations:
        locator = item["subject"]["locator"]
        assert locator["path"] == "app.py"
        assert locator["column_unit"] == "zero-based UTF-8 bytes; end exclusive"
        assert item["obligation_id"].endswith(item["subject_id"])


def test_same_site_survives_narrower_excerpt_and_distinct_resolving_entities(tmp_path: Path, controls) -> None:
    resolver, evidence, span_identity = _accepted(tmp_path, SQL)
    locator = {**evidence["reference"]["locator"], "lines": [2, 2]}
    narrowed = resolver.materialize(evidence["reference"]["source_identity"], component_id=COMPONENT,
                                    locator=locator)
    span = resolver.materialize(span_identity, component_id=COMPONENT)
    rule = procedure_for(controls["V1.2.4"])
    assert narrowed["truncated"] and not evidence["truncated"] and not span["truncated"]
    assert resolver.resolve(narrowed["reference"], component_id=COMPONENT) == narrowed
    assert subjects(rule, evidence) == subjects(rule, narrowed) == subjects(rule, span)
    obligations = instantiate(controls["V1.2.4"], _row(controls["V1.2.4"], evidence),
                              [span, narrowed, evidence, evidence], max_subjects=1)
    assert instantiate(controls["V1.2.4"], _row(controls["V1.2.4"], evidence),
                       [evidence, evidence, narrowed, span], max_subjects=1) == obligations
    obligation, gap = obligations
    assert obligation["supported"]
    assert obligation["subject"]["locator"]["lines"] == [2, 2]
    assert obligation["subject"]["locator"]["columns"] == [11, len(SQL.splitlines()[1])]
    assert obligation["evidence_ids"] == sorted({span["evidence_id"], narrowed["evidence_id"],
                                               evidence["evidence_id"]})
    assert not gap["supported"] and gap["required_outcome"] == "cannot_verify"
    assert "1 accepted subject lines omitted" in gap["reason"]


def test_multiline_utf8_offsets_and_dedented_context_are_real_file_coordinates(tmp_path: Path, controls) -> None:
    source = "def lookup(cursor):\n    café = 'é'; return cursor.execute(\n        'SELECT 1'\n    )\n"
    resolver, evidence, _ = _accepted(tmp_path, source)
    locator = {**evidence["reference"]["locator"], "lines": [2, 4]}
    narrowed = resolver.materialize(evidence["reference"]["source_identity"], component_id=COMPONENT,
                                    locator=locator)
    [whole] = _obligations(controls["V1.2.4"], evidence)
    partial, gap = _obligations(controls["V1.2.4"], narrowed)
    assert whole["subject_id"] == partial["subject_id"]
    assert narrowed["truncated"] and not gap["supported"]
    assert gap["required_outcome"] == "cannot_verify"
    site = whole["subject"]
    assert site["locator"]["lines"] == [2, 4]
    assert site["locator"]["columns"] == [len("    café = 'é'; return ".encode()), 5]
    assert site["content_sha256"] == digest({"source": "cursor.execute(\n        'SELECT 1'\n    )"})


@pytest.mark.parametrize("change", ["path", "span", "file_hash", "site_content", "run_id",
                                  "target_snapshot", "component_id", "build_unit_id", "environment"])
def test_subject_identity_binds_content_site_and_execution_scope(
        tmp_path: Path, controls, change: str) -> None:
    _, evidence, _ = _accepted(tmp_path, SQL)
    rule = procedure_for(controls["V1.2.4"])
    altered = deepcopy(evidence)
    ref = altered["reference"]
    if change == "path":
        ref["locator"]["path"] = "other.py"
    elif change == "span":
        ref["locator"]["lines"] = [10, 11]
    elif change == "file_hash":
        ref["locator"]["file_sha256"] = "f" * 64
    elif change == "site_content":
        altered["excerpt"] = altered["excerpt"].replace("SELECT id", "SELECT no")
    else:
        ref[change] = "different-scope"
    assert subjects(rule, evidence) and subjects(rule, altered)
    assert subjects(rule, evidence) != subjects(rule, altered)
    assert subjects(replace(rule, procedure_version="changed-procedure"), evidence) != subjects(rule, evidence)


def test_subject_cap_deduplicates_before_counting_and_accounts_for_omissions(tmp_path: Path, controls) -> None:
    source = "def lookup(cursor):\n    cursor.execute('SELECT 1')\n    cursor.execute('SELECT 2')\n    cursor.execute('SELECT 3')\n"
    _, evidence, _ = _accepted(tmp_path, source)
    control = controls["V1.2.4"]
    row = _row(control, evidence)
    obligations = instantiate(control, row, [evidence, evidence], max_subjects=1)
    supported, gap = obligations
    all_ids = subjects(procedure_for(control), evidence)
    assert supported["subject_id"] == all_ids[0]
    assert gap["required_outcome"] == "cannot_verify" and not gap["supported"]
    assert gap["omitted_subject_count"] == 2 and gap["omitted_ids_truncated"]
    assert gap["omitted_subject_ids"] == [all_ids[1]]
    assert "2 subjects omitted" in gap["reason"]
    assert instantiate(control, row, [evidence, evidence], max_subjects=1) == obligations
    with pytest.raises(ValueError, match="positive integer"):
        instantiate(control, row, [evidence], max_subjects=0)


@pytest.mark.parametrize("category", ["declaration", "scanner_observation", "static_fact"])
def test_non_source_categories_never_establish_implemented_behavior(tmp_path: Path, controls, category) -> None:
    _, evidence, _ = _accepted(tmp_path, SQL)
    evidence["category"] = category
    [gap] = _obligations(controls["V1.2.4"], evidence)
    assert gap["required_outcome"] == "cannot_verify" and not gap["supported"]


@pytest.mark.parametrize("failure", ["truncated", "redacted", "ambiguous", "incomplete", "unsupported_language"])
def test_unresolvable_source_creates_a_named_coverage_gap(
        tmp_path: Path, controls, failure: str) -> None:
    path = "app.js" if failure == "unsupported_language" else "app.py"
    source = "def broken(:\n" if failure == "incomplete" else SQL
    _, evidence, _ = _accepted(tmp_path, source, path=path)
    if failure == "truncated":
        evidence["truncated"] = True
    elif failure == "redacted":
        evidence["redaction"]["applied"] = True
    elif failure == "ambiguous":
        evidence["limitations"].append("ambiguous source mapping")
    [gap] = _obligations(controls["V1.2.4"], evidence)
    assert gap["subject_id"] is None and not gap["supported"]
    assert "no resolving subject" in gap["reason"]
    assert len(gap["reason"].split(";")) >= 2


def test_material_source_coverage_limit_remains_unknown_even_with_one_named_site(tmp_path: Path, controls) -> None:
    source = SQL + "# bounded source context\n" * 125 + "opaque_later_query()\n"
    resolver, evidence, _ = _accepted(tmp_path, source)
    assert evidence["truncated"] and evidence["limitations"]
    assert resolver.resolve(evidence["reference"], component_id=COMPONENT) == evidence
    supported, gap = _obligations(controls["V1.2.4"], evidence)
    assert supported["supported"] and not gap["supported"]
    assert "8 accepted subject lines omitted" in gap["reason"]
    assert gap["required_outcome"] == "cannot_verify"
    for name, clipped_source in (
        ("character-clipped", SQL + "#" + "x" * 17000 + "\n"),
        ("line-and-character-clipped", SQL + "# context\n" * 117 + "#" + "x" * 17000
         + "\n" + "# omitted\n" * 5),
    ):
        _, clipped, _ = _accepted(tmp_path / name, clipped_source)
        assert clipped["truncated"] and len(clipped["excerpt"]) == 16000
        assert len(clipped["excerpt"].splitlines()) == clipped["reference"]["locator"]["lines"][1]
        assert subjects(procedure_for(controls["V1.2.4"]), clipped) == []
        [clipped_gap] = _obligations(controls["V1.2.4"], clipped)
        assert not clipped_gap["supported"] and clipped_gap["required_outcome"] == "cannot_verify"
        assert "excerpt character cap reached" in clipped_gap["reason"]


def test_runtime_network_is_unsupported_even_if_runtime_category_is_claimed(tmp_path: Path, controls) -> None:
    resolver, evidence, _ = _accepted(tmp_path, "connection = 'https://example.test'\n")
    control = controls["MASVS-NETWORK-1"]
    for category in ("source", "runtime_observation"):
        evidence["category"] = category
        assert subjects(procedure_for(control), evidence) == []
        [gap] = _obligations(control, evidence)
        assert not gap["supported"] and gap["required_outcome"] == "cannot_verify"
        assert gap["evidence_mode"] == "dynamic_runtime"
        assert "no accepted environment-bound runtime evidence adapter" in gap["reason"]
        package = {"control": control, "component": {"component_id": COMPONENT},
                   "proof_obligations": [gap]}
        [result] = accept_obligations(package, None, resolver)
        assert result["outcome"] == "cannot_verify"


def test_other_full_catalog_controls_and_changed_standard_text_remain_unresolved(
        tmp_path: Path, controls) -> None:
    _, evidence, _ = _accepted(tmp_path, SQL)
    supported = {rule.control for rule in PROCEDURES}
    other = [control for control in controls.values() if control["id"] not in supported]
    assert len(other) > 300
    assert all(procedure_for(control) is None for control in other)
    for control in (controls["V8.3.2"], {**controls["V1.2.4"], "text": "different requirement"},
                    {**controls["V1.2.4"], "version": "4.0.3"}):
        assert procedure_for(control) is None
        [gap] = _obligations(control, evidence)
        assert not gap["supported"] and gap["required_outcome"] == "cannot_verify"
    mismatched = {**_row(controls["V1.2.4"], evidence), "control_identity": "ASVS:5.0.0:V8.2.1"}
    [gap] = instantiate(controls["V1.2.4"], mismatched, [evidence], max_subjects=1)
    assert not gap["supported"] and "identity does not match" in gap["reason"]


def test_out_of_row_scope_is_not_silently_instantiated(tmp_path: Path, controls) -> None:
    _, evidence, _ = _accepted(tmp_path, SQL)
    row = {**_row(controls["V1.2.4"], evidence), "component_id": "another-component"}
    [gap] = instantiate(controls["V1.2.4"], row, [evidence], max_subjects=1)
    assert not gap["supported"] and "outside the row" in gap["reason"]


def test_acceptance_re_resolves_and_rejects_another_site_in_the_same_entity(tmp_path: Path, controls) -> None:
    source = "cursor.execute('SELECT 1')\ncursor.execute('SELECT 2')\n"
    resolver, evidence, _ = _accepted(tmp_path, source)
    control = controls["V1.2.4"]
    obligations = _obligations(control, evidence)
    first_only = resolver.materialize(evidence["reference"]["source_identity"], component_id=COMPONENT,
        locator={**evidence["reference"]["locator"], "lines": [1, 1]})
    assert first_only["truncated"]
    package = {"control": control, "component": {"component_id": COMPONENT},
               "proof_obligations": obligations}
    # This exercises citation/subject binding, deliberately making no satisfied/adverse predicate claim.
    proposal = {"obligations": [
        {"obligation_id": item["obligation_id"], "subject_id": item["subject_id"],
         "outcome": "cannot_verify", "rationale": "Predicate prerequisites remain unresolved.",
         "supporting": [first_only["reference"]], "contradictory": [], "assumptions": [],
         "evidence_requests": ["Resolve driver and provenance."], "hypotheses": [], "limitations": []}
        for item in obligations]}
    first, second = accept_obligations(package, proposal, resolver)
    assert first["citation_checks"][0]["resolution"] == "resolved"
    assert first["citation_checks"][0]["subject_binding"]
    assert not first["supporting"]
    assert "truncated" in first["gaps"][0]
    assert second["citation_checks"][0]["resolution"] == "resolved"
    assert not second["citation_checks"][0]["subject_binding"] and not second["supporting"]
    assert "named subject" in second["gaps"][0]
    assert first["outcome"] == second["outcome"] == "cannot_verify"
