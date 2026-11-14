"""Producer causes survive receipt, handler, publication and real control accounting."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace

import pytest

from appsec_review.interchange import GapCode, producer_gap, validate_unit_output
from appsec_review.container_runtime import BuildProfile
from appsec_review.container_runtime.project_images import dependency_hashes, project_recipe_identity
from appsec_review.jobs.build_topology_artifacts import bind_actions
from appsec_review.jobs.build_topology import (
    compile_build_topology, refine_build_topology, topology_evidence_bundle,
)
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build import job as language_job
from appsec_review.jobs.job_project_build.enforcement import scoped_gaps
from appsec_review.jobs.job_target_analysis_plan import job as plan_job
from appsec_review.retrieval import write_manifest
from appsec_review.runtime.handoff import build_outcomes
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from appsec_review.storage.shared import reference
from tests.test_native_target_enforcement import _native, _profile
from tests.capture_fakes import fixture_compiler_profiles, simulated_executor
from tests.unit.job_language_build.support import FAMILIES, accepted, unit_context, units


BUILD_UNIT = "build-unit-" + "d" * 20


def _fixture(tmp_path, monkeypatch, family="native", *, windows=False, mode="legacy"):
    context = unit_context(tmp_path, f"load.{family}")
    action = _native()
    action["build_unit_id"] = BUILD_UNIT
    action["recipe"] = None
    if family == "dotnet":
        text = ('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
                f'<TargetFramework>{"net8.0-windows" if windows else "net8.0"}</TargetFramework>'
                '</PropertyGroup></Project>')
        document = {"path": "app.csproj", "content": text,
                    "sha256": hashlib.sha256(text.encode()).hexdigest(), "size_bytes": len(text)}
        action.update(family=family, build_system="dotnet",
                      markers=[{key: document[key] for key in ("path", "sha256", "size_bytes")}],
                      descriptor_package={"documents": [document], "bounds": {}, "gaps": []})
    for item in action["descriptor_package"]["documents"]:
        (context.job.target_root / item["path"]).write_text(item["content"], encoding="utf-8")
    snapshot = source_fingerprint(context.job.target_root)
    context.job.source_fingerprint = snapshot
    graph = compile_build_topology([action], source_fingerprint=snapshot, profiles=_profile())
    plan = {"build_topology": {
        "executable_graph": graph, "build_actions": [action],
        "planning_refinement": refine_build_topology(graph, [action], profiles=_profile()),
        "evidence_bundle": topology_evidence_bundle(
            [action], source_fingerprint=snapshot, profiles=_profile()),
    }}
    # Only the admitted-document I/O boundaries are replaced, not their consumers/validators.
    monkeypatch.setattr(plan_job, "load_accepted_plan", lambda root: plan)
    document = accepted(execution_mode=mode)
    document.update(source_fingerprint=snapshot, execution_graph=graph)
    monkeypatch.setattr(language_job, "load_accepted_builds", lambda root, **kwargs: document)
    return context, action, document


def _cause(context, *, unit_id=None, scope_id=BUILD_UNIT, reason="accepted image preparation failed",
           code=GapCode.PRODUCER_REPORTED_GAP):
    path = context.job.run_root / "data" / "upstream-proof.json"
    atomic_json(path, {"diagnostic": "synthetic image preparation failure"})
    return producer_gap(code, reason, unit_id=unit_id, scope_id=scope_id,
                        retryable=True, evidence_refs=[reference(context.job.run_root, path)])


def _probe(action, gaps, *, status="BLOCKED"):
    return {**action, "terminal_status": status, "artifacts": [], "commands": [], "gaps": gaps}


def _unit(context, unit_id, outputs):
    step, task = unit_id.split(".")
    return SimpleNamespace(
        job=context.job, unit_id=unit_id, step_id=step, task_id=task,
        unit_root=context.job.attempt_root / "steps" / step / "tasks" / task,
        output=lambda key: outputs[key])


def _account(context, results):
    job = language_job.build_job()
    assert job.strict_gaps is False
    for unit_id, result in results.items():
        validate_unit_output(result, unit_id=unit_id, strict_gaps=job.strict_gaps)
        base = _unit(context, unit_id, {}).unit_root
        atomic_json(base / "result.json", result)
        atomic_json(base / "status.json", {
            "unit_id": unit_id, "step_id": unit_id.split(".")[0], "task_id": unit_id.split(".")[1],
            "status": "SUCCEEDED", "result_sha256": file_sha256(base / "result.json"),
        })
    return build_outcomes(
        context.job.run_root, run_id=context.job.run_id, job_id=job.job_id,
        attempt_id=context.job.attempt_id, target_snapshot=context.job.source_fingerprint,
        unit_ids=list(results), strict_gaps=job.strict_gaps)


def _assert_cause(value, cause):
    matches = [gap for gap in value["gaps"] if isinstance(gap, dict) and gap["gap_id"] == cause["gap_id"]]
    assert len(matches) == 1
    assert matches[0] == cause
    assert canonical_json(matches[0]) == canonical_json(cause)


def _consume(context, action, document, causes, path):
    probe = _probe(action, causes)
    if path == "upstream":
        return language_job.upstream_build_failure_receipt(probe, document)
    if path == "dotnet":
        return language_job._unavailable_dotnet_receipt(
            _unit(context, "execute.dotnet", {}), probe, document)
    document["probe_receipts"] = [probe]
    return units()["load.dotnet"].handler(_unit(context, "load.dotnet", {}))


def _consume_group(context, action, document, causes, path):
    if path in {"upstream", "dotnet", "load"}:
        return _consume(context, action, document, causes, path)
    probe = _probe(action, [])
    if path.startswith("controller-"):
        preparation = {"action": action, "terminal_status": "BLOCKED", "gaps": []}
        (preparation if path == "controller-preparation" else probe)["gaps"] = causes
        document.update(execution_mode="iterative", probe_receipts=[probe],
                        images={"dotnet": {"entries": [preparation]}})
        return units()["iterations.dispatch"].handler(_unit(context, "iterations.dispatch", {}))
    loaded = {"accepted": document, "dispatches": [], "engine_receipts": []}
    outputs = {"load.dotnet": loaded}
    if path == "legacy-receipt":
        probe["gaps"] = causes
        loaded["non_run_receipts"] = [probe]
    else:
        document["execution_mode"] = "iterative"
        probe["gaps" if path == "iterative-gaps" else "delivery_gaps"] = causes
        outputs["iterations.dispatch"] = {"receipts": [probe]}
    return units()["execute.dotnet"].handler(_unit(context, "execute.dotnet", outputs))


GROUP_PATHS = (
    "upstream", "dotnet", "load", "legacy-receipt", "iterative-gaps", "iterative-delivery",
    "controller-preparation", "controller-probe",
)


@pytest.mark.parametrize("path", GROUP_PATHS)
@pytest.mark.parametrize("causes", ["diagnostic text", {"reason": "diagnostic text"}, None],
                         ids=["string", "mapping", "null"])
def test_original_cause_group_must_be_a_json_array(tmp_path, monkeypatch, path, causes):
    context, action, document = _fixture(tmp_path, monkeypatch, "dotnet")
    before = deepcopy(causes)
    with pytest.raises(ValueError, match="gaps must be an array"):
        _consume_group(context, action, document, causes, path)
    assert causes == before


@pytest.mark.parametrize("path", GROUP_PATHS)
def test_tuple_cause_groups_preserve_json_array_equivalence(tmp_path, monkeypatch, path):
    context, action, document = _fixture(tmp_path, monkeypatch, "dotnet")
    cause = _cause(context)
    causes = (cause, dict(reversed(list(cause.items()))))
    before = deepcopy(causes)
    result = _consume_group(context, action, document, causes, path)
    _assert_cause(result, cause)
    assert causes == before


@pytest.mark.parametrize("path", ["upstream", "load", "controller-preparation", "controller-probe"])
def test_empty_cause_groups_preserve_the_no_reason_fallback(tmp_path, monkeypatch, path):
    context, action, document = _fixture(tmp_path, monkeypatch, "dotnet")
    result = _consume_group(context, action, document, (), path)
    assert len(result["gaps"]) == 1
    assert "no reason recorded" in result["gaps"][0]
    assert result["terminal_status"] in {"BLOCKED", "COMPLETED_WITH_GAPS"}


def test_upstream_failure_receipt_preserves_the_typed_cause(tmp_path, monkeypatch):
    context, action, document = _fixture(tmp_path, monkeypatch)
    cause = _cause(context, reason=f"{BUILD_UNIT}: {BUILD_UNIT}: accepted image preparation failed")
    probe = _probe(action, [cause])
    before = deepcopy(probe)
    receipt = language_job.upstream_build_failure_receipt(probe, document)
    assert receipt["terminal_status"] == "BLOCKED"
    assert receipt["upstream_failure"] == {
        "job_id": "job_project_build", "terminal_status": "BLOCKED",
        "reason": "accepted image preparation failed",
    }
    _assert_cause(receipt, cause)
    _assert_cause(_account(context, {"load.native": receipt}), cause)
    assert probe == before


def test_load_dotnet_preserves_a_typed_unavailable_probe(tmp_path, monkeypatch):
    context, action, document = _fixture(tmp_path, monkeypatch, "dotnet")
    cause = _cause(context)
    probe = _probe(action, [cause])
    document["probe_receipts"] = [probe]
    before = deepcopy(document)
    result = units()["load.dotnet"].handler(context)
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert result["dispatches"] == [] and result["unavailable"] == [probe]
    _assert_cause(result, cause)
    _assert_cause(_account(context, {"load.dotnet": result}), cause)
    assert document == before


@pytest.mark.parametrize("windows", [False, True], ids=["blocked", "platform-na"])
def test_unavailable_dotnet_receipt_preserves_a_typed_upstream_gap(tmp_path, monkeypatch, windows):
    context, action, document = _fixture(tmp_path, monkeypatch, "dotnet", windows=windows)
    cause = _cause(context)
    probe = _probe(action, [cause])
    before = deepcopy(probe)
    receipt = language_job._unavailable_dotnet_receipt(
        _unit(context, "execute.dotnet", {}), probe, document)
    assert receipt["terminal_status"] == ("NOT_APPLICABLE" if windows else "BLOCKED")
    assert receipt["build_unit_id"] == BUILD_UNIT and receipt["artifacts"] == []
    assert receipt["project_topology"][0]["windows_only"] is windows
    _assert_cause(receipt, cause)
    _assert_cause(_account(context, {"execute.dotnet": receipt}), cause)
    assert probe == before


@pytest.mark.parametrize("path", ["upstream", "dotnet", "load"])
def test_dedup_preserves_distinct_scopes_causes_and_legacy_diagnostics(tmp_path, monkeypatch, path):
    context, action, document = _fixture(tmp_path, monkeypatch, "dotnet")
    cause = _cause(context)
    other_scope = _cause(context, scope_id="build-unit-" + "e" * 20)
    other_cause = _cause(context, code=GapCode.PRODUCER_FAILED)
    reordered = dict(reversed(list(cause.items())))
    causes = [cause, reordered, other_scope, other_cause, "first legacy", "second legacy", "first legacy"]
    before = deepcopy(causes)
    result = _consume(context, action, document, causes, path)
    for item in (cause, other_scope, other_cause):
        _assert_cause(result, item)
    records = [gap for gap in result["gaps"] if isinstance(gap, dict)]
    assert records == [cause, other_scope, other_cause]
    texts = [gap for gap in result["gaps"] if isinstance(gap, str)]
    assert sum("first legacy" in text for text in texts) == 1
    assert sum("second legacy" in text for text in texts) == 1
    assert all("{'code':" not in text for text in texts)
    again = _consume(context, action, document, [reordered, *causes[1:]], path)
    assert canonical_json(again["gaps"]) == canonical_json(result["gaps"])
    assert causes == before


@pytest.mark.parametrize("path", ["upstream", "dotnet", "load"])
@pytest.mark.parametrize("field,value", [
    ("schema", "appsec-review/producer-gap/999"), ("gap_id", "not-a-hash"),
    ("code", "unregistered"), ("reason", ""), ("reason", None), ("retryable", "yes"),
    ("unit_id", 5), ("scope_id", []), ("evidence_refs", None),
    ("evidence_refs", [{"path": "../escape", "sha256": "a" * 64, "size_bytes": 1}]),
    ("unexpected", True),
], ids=["schema", "id", "code", "empty-reason", "null-reason", "retry", "unit", "scope",
        "null-evidence", "unsafe-evidence", "extra"])
def test_malformed_records_are_rejected_without_stringification(tmp_path, monkeypatch, path, field, value):
    context, action, document = _fixture(tmp_path, monkeypatch, "dotnet")
    cause = {**_cause(context), field: value}
    before = deepcopy(cause)
    with pytest.raises(ValueError, match="producer-gap/1"):
        _consume(context, action, document, [cause], path)
    assert cause == before


@pytest.mark.parametrize("path", ["upstream", "dotnet", "load"])
@pytest.mark.parametrize("damage", ["empty", "missing-reason", "missing-evidence", "mapping-evidence"])
def test_incomplete_records_fail_at_the_real_validation_boundary(tmp_path, monkeypatch, path, damage):
    context, action, document = _fixture(tmp_path, monkeypatch, "dotnet")
    cause = _cause(context)
    if damage == "empty":
        cause = {}
    elif damage == "mapping-evidence":
        cause["evidence_refs"] = {}
    else:
        del cause["reason" if damage == "missing-reason" else "evidence_refs"]
    before = deepcopy(cause)
    with pytest.raises(ValueError):
        result = _consume(context, action, document, [cause], path)
        _account(context, {"load.dotnet": result})
    assert cause == before


def test_wire_equivalent_container_normalization_does_not_change_cause_identity(tmp_path, monkeypatch):
    context, action, document = _fixture(tmp_path, monkeypatch)
    cause = _cause(context)
    equivalent = {**cause, "evidence_refs": tuple(cause["evidence_refs"])}
    before = deepcopy(equivalent)
    result = _consume(context, action, document, (equivalent,), "upstream")
    _assert_cause(result, cause)
    _assert_cause(_account(context, {"load.native": result}), cause)
    assert equivalent == before


@pytest.mark.parametrize("unit_id", [None, "load.native", "probe.native"], ids=["null", "matching", "foreign"])
def test_original_unit_identity_is_preserved_and_accounting_enforces_ownership(
        tmp_path, monkeypatch, unit_id):
    context, action, document = _fixture(tmp_path, monkeypatch)
    cause = _cause(context, unit_id=unit_id)
    result = _consume(context, action, document, [cause], "upstream")
    _assert_cause(result, cause)
    if unit_id == "probe.native":
        with pytest.raises(ValueError, match="belongs to another unit"):
            _account(context, {"load.native": result})
    else:
        _assert_cause(_account(context, {"load.native": result}), cause)
        if unit_id is not None:
            with pytest.raises(ValueError, match="belongs to another unit"):
                _account(context, {"execute.native": result})


@pytest.mark.parametrize("conflict", ["retryable", "evidence"])
def test_same_identity_conflicts_are_not_hidden_by_dedup(tmp_path, monkeypatch, conflict):
    context, action, document = _fixture(tmp_path, monkeypatch)
    cause = _cause(context)
    changed = {**cause, **({"retryable": False} if conflict == "retryable" else {"evidence_refs": []})}
    result = _consume(context, action, document, [cause, changed], "upstream")
    assert result["gaps"] == [cause, changed]
    with pytest.raises(ValueError, match="conflicting producer gap identities"):
        _account(context, {"load.native": result})


@pytest.mark.parametrize("damage", ["missing", "tampered"])
def test_preserved_evidence_is_really_verified(tmp_path, monkeypatch, damage):
    context, action, document = _fixture(tmp_path, monkeypatch)
    cause = _cause(context)
    result = _consume(context, action, document, [cause], "upstream")
    path = context.job.run_root / cause["evidence_refs"][0]["path"]
    if damage == "missing":
        path.unlink()
    else:
        path.write_text("changed", encoding="utf-8")
    with pytest.raises((ValueError, OSError)):
        _account(context, {"load.native": result})


@pytest.mark.parametrize("status", ["SUCCEEDED", "NOT_APPLICABLE", "SKIPPED_NA", "SKIPPED_POLICY"])
def test_not_needed_probe_dispositions_remain_absent_from_failed_receipts(tmp_path, monkeypatch, status):
    context, action, document = _fixture(tmp_path, monkeypatch)
    document["probe_receipts"] = [_probe(action, [], status=status)]
    result = units()["load.native"].handler(context)
    assert result["gaps"] == [] and result["non_run_receipts"] == []
    execution = units()["execute.native"].handler(_unit(context, "execute.native", {"load.native": result}))
    assert execution == {"receipts": [], "receipt_count": 0, "gaps": [], "terminal_status": "NOT_APPLICABLE"}


@pytest.mark.parametrize("family", ["native", "dotnet"])
@pytest.mark.parametrize("mode", ["legacy", "iterative"])
def test_causes_reach_real_publication_and_control_accounting(tmp_path, monkeypatch, family, mode):
    context, action, document = _fixture(tmp_path, monkeypatch, family, mode=mode)
    cause = _cause(context)
    actual_producer_gap = scoped_gaps(["image preparation failed"], "probe.native", BUILD_UNIT)[0]
    assert actual_producer_gap["unit_id"] is None
    assert actual_producer_gap["scope_id"] == BUILD_UNIT
    document["probe_receipts"] = [_probe(action, [cause, dict(reversed(list(cause.items()))),
                                               actual_producer_gap])]
    document["images"] = {family: {"entries": [{
        "action": action, "terminal_status": "BLOCKED",
        "gaps": ["image preparation failed", "secondary preparation diagnostic"],
    }]}}
    before = deepcopy(document)
    handlers = units(executor_factory=lambda *_: pytest.fail("no build should execute"))
    outputs = {}
    if mode == "iterative":
        outputs["iterations.dispatch"] = handlers["iterations.dispatch"].handler(
            _unit(context, "iterations.dispatch", outputs))
        assert outputs["iterations.dispatch"]["states"] == {BUILD_UNIT: "BLOCKED"}
        _assert_cause(outputs["iterations.dispatch"], cause)
        _assert_cause(outputs["iterations.dispatch"], actual_producer_gap)
        assert len(document["execution_graph"]["nodes"]) == 1
    else:
        outputs["iterations.dispatch"] = {"receipts": [], "gaps": [], "graph": None}
    for lane in FAMILIES:
        for step in ("load", "execute"):
            unit_id = f"{step}.{lane}"
            outputs[unit_id] = handlers[unit_id].handler(_unit(context, unit_id, outputs))
    _assert_cause(outputs[f"load.{family}"], cause)
    _assert_cause(outputs[f"execute.{family}"], cause)
    receipt, = outputs[f"execute.{family}"]["receipts"]
    assert receipt["terminal_status"] == "BLOCKED" and receipt["artifacts"] == []
    if mode == "iterative":
        assert any("secondary preparation diagnostic" in gap for gap in receipt["gaps"] if isinstance(gap, str))
    prior = context.job.run_root / "data/indices/manifests/prior.json"
    write_manifest(prior, run_id=context.job.run_id, target_snapshot=context.job.source_fingerprint,
                   target_root=context.job.target_root, indexes=[])
    context.job.input_manifest_path = prior
    context.job.input_manifest_sha256 = file_sha256(prior)
    published = handlers["acceptance.publish_handoff"].handler(
        _unit(context, "acceptance.publish_handoff", outputs))
    outputs["acceptance.publish_handoff"] = published
    payload = json.loads((context.job.run_root / published["artifact"]["path"]).read_bytes())
    assert payload["receipts"] == [receipt]
    for value in (payload, published, _account(context, outputs)):
        _assert_cause(value, cause)
        _assert_cause(value, actual_producer_gap)
    assert published["terminal_status"] == "COMPLETED_WITH_GAPS"
    manifest = json.loads((context.job.run_root / published["index_manifest"]["path"]).read_bytes())
    assert all(isinstance(gap, str) for gap in manifest["indexes"][-1]["gaps"])
    assert cause["reason"] in manifest["indexes"][-1]["gaps"]
    assert document == before


def test_real_native_receipt_survives_execute_processing_merge(tmp_path, monkeypatch):
    context, source, document = _fixture(tmp_path, monkeypatch)
    action = deepcopy(source)
    action["recipe"] = {**_native()["recipe"], "build_unit_id": BUILD_UNIT}
    action.update(source_fingerprint=context.job.source_fingerprint,
                  workflow="lang_jobflow_build", build_dependencies=[])
    profile = BuildProfile("native", "synthetic-native:local", "sha256:" + "a" * 64, "1000:1000")
    hashes = dependency_hashes(context.job.target_root, action["recipe"])
    action["recipe_identity"] = project_recipe_identity(
        {**action["recipe"], "build_system": action["build_system"]}, profile, hashes,
        releases=context.job.review_policy.releases)
    action["image"] = {"image_tag": profile.tag, "image_id": profile.image_id,
                       "base_image_id": profile.image_id, "user": profile.user,
                       "dependency_hashes": hashes}
    action, = bind_actions(context.job.run_root, [action], profiles=_profile(),
                           releases=context.job.review_policy.releases.view())
    probe = {**_probe(action, [], status="SUCCEEDED"), "image_id": profile.image_id}
    action["probe_identity"] = hashlib.sha256(canonical_json(probe)).hexdigest()
    document.update(build_dispatches=[action], probe_receipts=[probe])
    before = deepcopy(document)
    calls = []

    def factory(unit, image):
        def behavior(command, workspace, working_directory, environment, simulation):
            calls.append(command)
            simulation.exec("/capture/wrappers/clang", command)
            simulation.exec("/usr/bin/clang", command)
            simulation.tool_call("clang", command[1:], executable="/usr/bin/clang")
            return 2, b"", b"synthetic compiler failure"

        executor = simulated_executor(image, behavior)
        executor.compiler_profiles = lambda **kwargs: fixture_compiler_profiles(image)
        return executor

    handlers = units(executor_factory=factory)
    loaded = handlers["load.native"].handler(context)
    assert len(loaded["dispatches"]) == 1
    result = handlers["execute.native"].handler(
        _unit(context, "execute.native", {"load.native": loaded}))
    assert len(calls) == 1
    receipt, = result["receipts"]
    assert receipt["terminal_status"] == "FAILED"
    assert receipt["artifacts"] == []
    records = [gap for gap in receipt["gaps"] if isinstance(gap, dict)]
    assert records and any("build command" in gap["reason"] for gap in records)
    assert all(gap["unit_id"] is None and gap["scope_id"] == BUILD_UNIT for gap in records)
    assert receipt["processing_decisions"] and any(
        value["disposition"] == "GAP" for value in receipt["processing_decisions"])
    accounted = _account(context, {"execute.native": result})
    for cause in records:
        _assert_cause(result, cause)
        _assert_cause(accounted, cause)
    assert document == before
