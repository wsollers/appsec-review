"""SARIF regressions over the real protected dossier and gate-bound reader."""
from __future__ import annotations

import copy
import hashlib

import pytest

from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound_json
from appsec_review.jobs.completion_contracts import (
    REMEDIATION_VALIDATION_HANDOFF_SCHEMA, REMEDIATION_VALIDATION_SUMMARY_SCHEMA,
)
from appsec_review.jobs.job_dossier_publication import inputs
from appsec_review.jobs.job_dossier_publication.job import _remediation
from appsec_review.jobs.job_final_report_publication.sarif import gate_sarif
from appsec_review.jobs.job_remediation_planning.patches import parse_patch, patched_bytes
from appsec_review.reporting.dossier_render import render_dossier
from appsec_review.reporting.dossiers import DossierLimits, build_dossier
from appsec_review.reporting.sarif_export import export_sarif_bundle, validate_sarif_log
from appsec_review.review.models import IntegrityError
from appsec_review.storage import atomic_bytes, atomic_json
from tests.remediation_support import bounds
from tests.dossier_fixture import ROOT, settings
from tests.unit.job_dossier_publication.test_coverage_edges import (
    _accepted_exact_remediation, _seed_env,
)


def _finding(identity="finding-1", severity="low", **fields):
    return {
        "finding_id": identity, "title": "other (CWE-9999)", "severity": severity,
        "cwe": "CWE-9999", "security_predicate": "other", "path": "src/example.c",
        "start_line": 4, **fields,
    }


def _limitations(bundle):
    return bundle.sarif_log["runs"][0]["properties"]["optional_capability_limitations"]


def _render(root, model, name):
    item = render_dossier(root, root / name, model,
                          settings=settings(render_pdf=False), repository_root=ROOT,
                          executor_factory=lambda *_: pytest.fail("No container is admitted"))
    refs = [ref for ref in item["files"].values() if ref is not None]
    refs.extend(read_bound_json(root, item["files"]["receipt"])["additional_formats"].values())
    return item, refs


def _bound(tmp_path, monkeypatch, *, status="build_checked", limits=None, proposal=None, check_change=None):
    env = _seed_env(tmp_path, monkeypatch)
    patch_ref = _accepted_exact_remediation(env, validation_status=status, proposal=proposal)
    if status:
        job = "job_remediation_validation"
        publication = env.accepted[job].handoff["outputs"][inputs.PRODUCERS[job][0]]
        summary = read_bound_json(env.root, publication["artifact"])
        ref = summary["items"][0]["validation"]
        validation = read_bound_json(env.root, ref)
        validation["checks"]["policy"] = {"status": "passed", "reason": "bounded inert source edits",
                                        "artifact": None}
        if check_change:
            dimension, value = check_change
            validation["checks"][dimension]["status"] = value
        atomic_json(env.root / ref["path"], validation)
        summary["items"][0]["validation"] = artifact_ref(env.root, env.root / ref["path"])
        env.producer(job, REMEDIATION_VALIDATION_SUMMARY_SCHEMA, REMEDIATION_VALIDATION_HANDOFF_SCHEMA,
                     summary["items"], extra={"planning_handoff": summary["upstream"]["planning_handoff"]})
    loaded = inputs.load_inputs(env.root, env.verified, settings())
    remedies = _remediation(env.root, loaded, env.binding["finding_package_id"], settings())
    model = build_dossier(kind="confirmed_finding", **{**env.source, "remediation": remedies},
                          limits=limits or DossierLimits())
    item, refs = _render(env.root, model, "dossier")
    for row in remedies:
        refs.append(row["artifact"])
    refs.append(patch_ref)
    gate = {"bindings": refs}
    report = {"run_id": env.root.name, "findings": [env.source["finding"]],
              "dossiers": {"items": [item]}, "limitations": []}
    return env, gate, report, model, patch_ref


@pytest.mark.parametrize("metadata", [{}, {"radar_domain": "unknown"}, {"cwe": None}])
def test_unmapped_finding_is_explicitly_unclassified(metadata):
    bundle = export_sarif_bundle([_finding(**metadata)])
    run = bundle.sarif_log["runs"][0]
    result = run["results"][0]
    rule = run["tool"]["driver"]["rules"][result["ruleIndex"]]
    for value in (result, rule):
        assert value["properties"]["radar_domain"]["domain_id"] == "unclassified"
        assert value["properties"]["owasp_2025"] == []
        assert "radar:authentication_session" not in value["properties"]["tags"]
    assert run["taxonomies"][1]["taxa"] == []
    assert result["ruleId"].startswith("appsec-review/unclassified/")


@pytest.mark.parametrize("explicit_rule", [None, "scanner/bounds"])
def test_rule_severity_and_taxa_do_not_depend_on_finding_order_or_identity(explicit_rule):
    shared = {"cwe": "CWE-120", "security_predicate": "memory_corruption"}
    if explicit_rule:
        shared["rule_id"] = explicit_rule
    findings = [_finding("a-low", "low", **shared), _finding("z-critical", "critical", **shared)]
    first = export_sarif_bundle(findings)
    assert first.sarif_bytes == export_sarif_bundle(list(reversed(findings))).sarif_bytes
    run = first.sarif_log["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == 2
    for result in run["results"]:
        severity = result["properties"]["severity"]
        rule = rules[result["ruleIndex"]]
        assert rule["properties"]["security-severity"] == {"low": "2.5", "critical": "9.5"}[severity]
        assert rule["defaultConfiguration"]["level"] == result["level"]
    renamed = [{**row, "finding_id": "renamed-" + row["severity"]} for row in findings]
    assert export_sarif_bundle(renamed).sarif_log["runs"][0]["tool"] == run["tool"]


@pytest.mark.parametrize("status", ["static_checked", "build_checked"])
def test_bound_exact_fix_is_exported_without_upgrading_its_assurance(tmp_path, monkeypatch, status):
    env, gate, report, model, patch_ref = _bound(tmp_path, monkeypatch, status=status)
    bundle = gate_sarif(env.root, gate, report)
    result = bundle.sarif_log["runs"][0]["results"][0]
    assert "codeFlows" not in result
    assert bundle.telemetry["reporting.sarif_fixes_emitted"] == 1
    fix = result["fixes"][0]
    edit = model["remediation"][0]["patch"]["files"][0]["edits"][0]
    replacement = fix["artifactChanges"][0]["replacements"][0]
    assert replacement["deletedRegion"] == {"byteOffset": edit["start"], "byteLength": edit["end"] - edit["start"]}
    assert replacement["insertedContent"] == {"text": edit["new"]}
    assert fix["properties"]["validation_status"] == status
    assert fix["properties"]["patch"] == patch_ref
    assert fix["properties"]["runtime_regression"] == "not_performed_by_policy"
    assert "not a resolved finding" in fix["description"]["text"]
    assert bundle.gaps == () and bundle.result["terminal_status"] == "SUCCEEDED"
    assert [row["reason"] for row in _limitations(bundle)] == [
        f"sarif_codeflow_omitted:{env.binding['finding_package_id']}:ordered_trace_not_in_accepted_dossier_contract"]
    assert model["sources"][0]["excerpt"] not in bundle.sarif_bytes.decode()


@pytest.mark.parametrize("status", [None, "rejected", "inconclusive", "manual_validation_required"])
def test_unqualified_remediation_is_an_explicit_fix_omission(tmp_path, monkeypatch, status):
    env, gate, report, _, _ = _bound(tmp_path, monkeypatch, status=status)
    bundle = gate_sarif(env.root, gate, report)
    result = bundle.sarif_log["runs"][0]["results"][0]
    assert "fixes" not in result
    assert any("sarif_fix_omitted:" in row["reason"] for row in _limitations(bundle))
    assert bundle.gaps == () and bundle.result["terminal_status"] == "SUCCEEDED"


@pytest.mark.parametrize("change", [
    ("policy", "unsafe"), ("static_checks", "failed"), ("semantic_review", "analyst_contradicted"),
    ("build", "not_performed"),
], ids=["unsafe-policy", "failed-static", "contradicted", "unperformed-build"])
def test_success_label_does_not_override_actual_qualification_checks(tmp_path, monkeypatch, change):
    env, gate, report, _, _ = _bound(tmp_path, monkeypatch, check_change=change)
    bundle = gate_sarif(env.root, gate, report)
    assert "fixes" not in bundle.sarif_log["runs"][0]["results"][0]
    assert any("validation_checks_do_not_qualify" in row["reason"] for row in _limitations(bundle))
    assert bundle.gaps == () and bundle.result["terminal_status"] == "SUCCEEDED"


@pytest.mark.parametrize("private", [False, True], ids=["bounded", "redacted"])
def test_private_or_truncated_patch_is_never_an_applicable_sarif_fix(tmp_path, monkeypatch, private):
    proposal = None if not private else {
        "schema": "appsec-review/remediation-exact-patch/1", "files": [
            {"path": "src/example.c", "before_sha256": "a" * 64, "absence_proof": False,
             "edits": [{"start": 2, "end": 3, "old": "a", "new": 'password = "PRIVATE_PATCH_SECRET";'}]}]}
    limits = DossierLimits() if private else DossierLimits(code_chars=8)
    env, gate, report, _, _ = _bound(tmp_path, monkeypatch, limits=limits, proposal=proposal)
    bundle = gate_sarif(env.root, gate, report)
    assert "fixes" not in bundle.sarif_log["runs"][0]["results"][0]
    assert any("patch_projection_is_not_exact" in row["reason"] for row in _limitations(bundle))
    assert bundle.gaps == () and bundle.result["terminal_status"] == "SUCCEEDED"
    assert b"PRIVATE_PATCH_SECRET" not in bundle.sarif_bytes


def test_sarif_byte_edits_match_producer_patch_for_multibyte_text_and_new_files(tmp_path, monkeypatch):
    original = '// 🧪\nconst char *name = "é";\n'.encode()
    start = original.index("é".encode())
    digest = hashlib.sha256(original).hexdigest()
    proposal = {"schema": "appsec-review/remediation-exact-patch/1", "files": [
        {"path": "src/new.c", "before_sha256": None, "absence_proof": True,
         "edits": [{"start": 0, "end": 0, "old": "", "new": "safe();"}]},
        {"path": "src/example.c", "before_sha256": digest, "absence_proof": False,
         "edits": [{"start": start, "end": start + 2, "old": "é", "new": "à"}]},
    ]}
    env, gate, report, _, _ = _bound(tmp_path, monkeypatch, proposal=proposal)
    baseline = env.root / "source"
    atomic_bytes(baseline / "src" / "example.c", original)
    expected = patched_bytes(parse_patch(proposal, bounds()), baseline, {"src/example.c": digest}, bounds())
    bundle = gate_sarif(env.root, gate, report)
    changes = bundle.sarif_log["runs"][0]["results"][0]["fixes"][0]["artifactChanges"]
    assert [change["artifactLocation"]["uri"] for change in changes] == ["src/example.c", "src/new.c"]
    for change in changes:
        path = change["artifactLocation"]["uri"]
        data = original if path == "src/example.c" else b""
        for replacement in reversed(change["replacements"]):
            region = replacement["deletedRegion"]
            offset, length = region["byteOffset"], region["byteLength"]
            data = data[:offset] + replacement["insertedContent"]["text"].encode() + data[offset + length:]
        assert data == expected[path]
    assert changes[0]["replacements"][0]["deletedRegion"] == {"byteOffset": start, "byteLength": 2}
    assert start != len(original[:start].decode())
    assert changes[1]["properties"] == {"before_sha256": None, "absence_proof": True}


@pytest.mark.parametrize("region", [
    None, {}, {"startLine": 0}, {"startLine": True}, {"startLine": "1"},
    {"startLine": 3, "endLine": 2}, {"startLine": 1, "startColumn": 0},
    {"startLine": 1, "startColumn": 3, "endColumn": 2},
    {"byteOffset": 0}, {"byteLength": 0},
    {"byteOffset": -1, "byteLength": 1}, {"byteOffset": 0, "byteLength": -1},
    {"byteOffset": True, "byteLength": 1}, {"byteOffset": 0, "byteLength": False},
    {"byteOffset": 0.5, "byteLength": 1}, {"byteOffset": 0, "byteLength": "1"},
    {"startLine": 0, "byteOffset": 0, "byteLength": 1},
    {"startLine": 1, "byteOffset": 0, "byteLength": -1},
], ids=["null", "empty", "zero-line", "bool-line", "string-line", "reversed-lines", "zero-column",
        "reversed-columns", "no-length", "no-offset", "negative-offset", "negative-length",
        "bool-offset", "bool-length", "float-offset", "string-length", "invalid-line-with-bytes",
        "invalid-bytes-with-line"])
def test_validator_rejects_malformed_replacement_coordinates(region):
    bundle = export_sarif_bundle([_finding(remediation={
        "validated": True, "replacement_text": "safe();",
    })])
    log = bundle.sarif_log
    log["runs"][0]["results"][0]["fixes"][0]["artifactChanges"][0]["replacements"][0]["deletedRegion"] = region
    with pytest.raises(ValueError, match="replacement deletedRegion"):
        validate_sarif_log(log)


@pytest.mark.parametrize("region", [
    {"startLine": 1, "endLine": 2}, {"startLine": 1, "startColumn": 2, "endColumn": 2},
    {"byteOffset": 0, "byteLength": 0}, {"byteOffset": 9, "byteLength": 3},
])
def test_validator_keeps_line_regions_and_accepts_explicit_byte_regions(region):
    bundle = export_sarif_bundle([_finding(remediation={
        "validated": True, "replacement_text": "safe();",
    })])
    log = bundle.sarif_log
    log["runs"][0]["results"][0]["fixes"][0]["artifactChanges"][0]["replacements"][0]["deletedRegion"] = region
    validate_sarif_log(log)


def test_legacy_timeline_and_remediation_guide_are_not_export_authority(tmp_path, monkeypatch):
    env, gate, report, model, _ = _bound(tmp_path, monkeypatch, status=None)
    model["taint_path_timeline"] = [
        {"step_index": index, "location": f"private.c:{line}", "role": role, "symbol": "private",
         "taint_transform": "PRIVATE_LEGACY_TRACE", "guard_disposition": "not_recorded"}
        for index, line, role in ((1, 4, "source"), (2, 9, "sink"))
    ]
    model["remediation_guide"].update(validated=True, replacement_text="PRIVATE_LEGACY_PATCH")
    item, refs = _render(env.root, model, "legacy")
    report["dossiers"]["items"] = [item]
    gate["bindings"].extend(refs)
    bundle = gate_sarif(env.root, gate, report)
    assert b"PRIVATE_LEGACY" not in bundle.sarif_bytes
    assert "codeFlows" not in bundle.sarif_log["runs"][0]["results"][0]
    assert len(_limitations(bundle)) == 2
    assert bundle.gaps == () and bundle.result["terminal_status"] == "SUCCEEDED"


def test_poc_dossier_cannot_replace_the_confirmed_finding_projection(tmp_path, monkeypatch):
    env, gate, report, _, _ = _bound(tmp_path, monkeypatch)
    expected = gate_sarif(env.root, gate, report)
    poc = build_dossier(kind="poc", **{**env.source, "excerpts": [], "remediation": []})
    item, refs = _render(env.root, poc, "poc-dossier")
    report["dossiers"]["items"].append(item)
    gate["bindings"].extend(refs)
    for items in (report["dossiers"]["items"], list(reversed(report["dossiers"]["items"]))):
        actual = gate_sarif(env.root, gate, {**report, "dossiers": {"items": items}})
        assert actual.sarif_bytes == expected.sarif_bytes
        assert actual.gaps == expected.gaps


def test_gate_does_not_read_an_unbound_patch_or_accept_tampered_bytes(tmp_path, monkeypatch):
    env, gate, report, _, patch_ref = _bound(tmp_path, monkeypatch)
    unbound = copy.deepcopy(gate)
    unbound["bindings"].remove(patch_ref)
    (env.root / patch_ref["path"]).unlink()
    bundle = gate_sarif(env.root, unbound, report)
    assert "fixes" not in bundle.sarif_log["runs"][0]["results"][0]
    assert any("patch_not_gate_bound" in gap["reason"] for gap in bundle.gaps)
    assert bundle.result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert [row["capability"] for row in _limitations(bundle)] == ["codeFlows"]
    atomic_json(env.root / patch_ref["path"], {"tampered": True})
    with pytest.raises(IntegrityError, match="hash|sha256|changed"):
        gate_sarif(env.root, gate, report)


def test_missing_required_validation_binding_is_not_an_optional_fix_limitation(tmp_path, monkeypatch):
    env, gate, report, model, _ = _bound(tmp_path, monkeypatch)
    validation = next(row["artifact"] for row in model["remediation"] if row["stage"] == "Validation")
    gate["bindings"].remove(validation)
    (env.root / validation["path"]).unlink()
    bundle = gate_sarif(env.root, gate, report)
    assert bundle.result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert len(bundle.gaps) == 1 and "validation_not_gate_bound" in bundle.gaps[0]["reason"]
    assert [row["capability"] for row in _limitations(bundle)] == ["codeFlows"]
    assert "fixes" not in bundle.sarif_log["runs"][0]["results"][0]


def test_ambiguous_validation_rows_remain_a_required_gap(tmp_path, monkeypatch):
    env, gate, report, model, _ = _bound(tmp_path, monkeypatch)
    model["remediation"].append(copy.deepcopy(
        next(row for row in model["remediation"] if row["stage"] == "Validation")))
    item, refs = _render(env.root, model, "ambiguous")
    report["dossiers"]["items"] = [item]
    gate["bindings"].extend(refs)
    bundle = gate_sarif(env.root, gate, report)
    assert bundle.result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert len(bundle.gaps) == 1 and "ambiguous_remediation_validation" in bundle.gaps[0]["reason"]
    assert [row["capability"] for row in _limitations(bundle)] == ["codeFlows"]
    assert "fixes" not in bundle.sarif_log["runs"][0]["results"][0]
