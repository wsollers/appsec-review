from __future__ import annotations

import copy
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import PlanningFeedbackSettings
from appsec_review.inference import ModelResult
from appsec_review.jobs.build_discovery import discover_build_units
from appsec_review.jobs.job_target_analysis_plan import build_job
from appsec_review.jobs.job_target_analysis_plan.job import _verify_source_topology
from appsec_review.jobs.job_target_analysis_plan.planning import (
    PROPOSAL_SCHEMA, ambiguity_reasons, bounded_feedback, deterministic_plan,
    prepare_feedback_request, summarize_catalog, validate_plan,
)
from appsec_review.storage import canonical_json


ROOT = Path(__file__).parents[1]


def _catalog(count=14, padding=8000):
    texts = {}
    for index in range(count):
        size = padding if isinstance(padding, int) else padding[index]
        texts[f"node-{index:02d}/package.json"] = json.dumps({
            "name": f"synthetic-{index}", "scripts": {"build": "synthetic-compiler"},
            "description": ("x " * ((size + 1) // 2))[:size],
        })
    files = [{"path": path, "sha256": hashlib.sha256(text.encode()).hexdigest(),
              "size_bytes": len(text.encode()), "language": "JSON"} for path, text in texts.items()]
    units = discover_build_units(files)
    assert len(units) == count
    for unit in units:
        unit["descriptor_package"] = {"documents": [
            {"path": item["path"], "sha256": item["sha256"], "content": texts[item["path"]]}
            for item in files if str(Path(item["path"]).parent) == unit["root"]],
            "bounds": {}, "gaps": []}
    return {
        "source_fingerprint": "synthetic-byte-partitions", "catalog_handoff_sha256": "c" * 64,
        "files": files, "components": [], "projects": [], "build_files": [],
        "build_units": units, "gaps": [], "accepted_artifacts": [], "compile_databases": [],
    }


def _resolve(tmp_path, catalog, *, limits=None, max_input_tokens=200000, abstain=False):
    limits = limits or PlanningFeedbackSettings()
    summary = summarize_catalog(catalog, max_items=2000, max_bytes=524288, sample_per_prefix=20)
    plan = deterministic_plan(catalog, summary)
    plan["build_environment"] = None
    outputs = {
        "catalog_summary.load_accepted_catalog": {"catalog": catalog},
        "catalog_summary.summarize_components": {"summary": summary},
        "analysis_decisions.apply_deterministic_rules": {
            "plan": plan, "ambiguities": ambiguity_reasons(summary)},
    }
    requests = []

    def infer(request, *, timeout_seconds):
        requests.append(request)
        assert timeout_seconds > 0
        assert len(canonical_json(asdict(request))) <= min(limits.max_request_bytes, max_input_tokens * 4)
        if abstain:
            return ModelResult({"schema": PROPOSAL_SCHEMA, "action": "final", "component_proposals": [],
                                "build_recipes": [], "hints": [], "abstentions": [
                                    {"build_unit_id": unit_id, "reason": "inert synthetic abstention"}
                                    for unit_id in request.allowed_build_units]})
        recipes = [{
            "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
            "image_profile": "node", "source_dir": unit["root"], "build_dir": unit["root"] + "/build",
            "system_packages": [], "environment": {},
            "dependency_files": [item["path"] for item in unit["markers"]],
            "configure_commands": [], "build_commands": [["npm", "run", "build"]],
            "expected_outputs": [unit["root"] + "/build"], "network_required": True,
            "reason": "inert synthetic descriptor-backed recipe",
        } for unit in request.summary["build_units"]]
        return ModelResult({"schema": PROPOSAL_SCHEMA, "action": "final", "component_proposals": [],
                            "build_recipes": recipes, "hints": [], "abstentions": []})

    job = build_job(infer=infer)
    unit = SimpleNamespace(
        unit_id="analysis_decisions.resolve_ambiguity", output=outputs.__getitem__,
        job=SimpleNamespace(
            config=SimpleNamespace(settings={"feedback": asdict(limits), "model": {
                "enabled": True, "provider": "offline-scripted", "model": "synthetic/1", "reasoning": "low",
                "max_input_tokens": max_input_tokens, "max_output_tokens": 64000,
                "retries": 3, "timeout_seconds": 300, "workers": 2}}),
            tools=SimpleNamespace(enable_swift=False), repository_root=ROOT, run_root=tmp_path,
            run_id="synthetic-byte-partitions", attempt_id="attempt_0001", target_root=None))
    result = next(item for item in job.units if item.unit_id == unit.unit_id).handler(unit)
    validate_plan(result["plan"], catalog)
    _verify_source_topology(canonical_json(result["plan"]))
    return result, requests


def _combined_request(requests):
    units = sorted((unit for request in requests for unit in request.summary["build_units"]),
                   key=lambda unit: unit["build_unit_id"])
    return replace(requests[0], summary={**requests[0].summary, "build_units": units},
                   allowed_build_units=tuple(unit["build_unit_id"] for unit in units),
                   allowed_paths=tuple(sorted({path for request in requests for path in request.allowed_paths})))


def test_initial_byte_overflow_partitions_before_any_model_call_without_losing_units(tmp_path, record_property):
    catalog = _catalog()
    original = copy.deepcopy(catalog)
    result, requests = _resolve(tmp_path, catalog)
    assert result["validation_rejections"] == 0, (result["gaps"], result["model_calls"])
    assert result["gaps"] == []
    assert result["plan"]["model"]["status"] == "ACCEPTED"
    assert len(requests) > 1
    assert result["model_calls"] == len(requests)
    combined = _combined_request(requests)
    before_bytes = len(prepare_feedback_request(combined)[1])
    assert before_bytes > 131072
    before = bounded_feedback(
        lambda *_a, **_kw: pytest.fail("overlarge initial scope must not call a model"),
        combined, catalog=catalog, limits=PlanningFeedbackSettings(), read_document=None,
        cache_root=tmp_path / "unsplit-cache", identity={"synthetic": "original-count-only-partition"})
    assert before["calls"] == before["metrics"]["request_bytes"] == 0
    assert before["status"] == "BUDGET_EXCEEDED"
    assert before["errors"] == ["feedback_request_byte_bound"]
    record_property("before_bytes", before_bytes)
    record_property("after_bytes", json.dumps(sorted(len(prepare_feedback_request(request)[1])
                                                   for request in requests)))
    record_property("after_scope_units", json.dumps(sorted(len(request.allowed_build_units) for request in requests)))
    ids = [unit_id for request in requests for unit_id in request.allowed_build_units]
    assert sorted(ids) == sorted(unit["build_unit_id"] for unit in catalog["build_units"])
    assert len(ids) == len(set(ids)) == 14
    for request in requests:
        units = request.summary["build_units"]
        assert len(units) <= 16
        assert request.allowed_build_systems == ("node",)
        assert request.allowed_image_profiles == ("node",)
        assert request.allowed_components == request.allowed_scanners == ()
        assert set(request.allowed_paths) == {
            document["path"] for unit in units for document in unit["descriptor_package"]["documents"]}
        for unit in units:
            accepted = next(item for item in original["build_units"]
                            if item["build_unit_id"] == unit["build_unit_id"])
            assert unit["descriptor_package"] == accepted["descriptor_package"]
    assert catalog == original
    actions = result["plan"]["build_topology"]["build_actions"]
    assert len(actions) == 14
    assert all(action["recipe"] is not None and action["executable"] is False for action in actions)


@pytest.mark.parametrize("count,units_per_scope,expected", [(3, 16, [3]), (17, 16, [1, 16]), (5, 2, [1, 2, 2])])
def test_count_bound_and_fitting_scopes_remain_unchanged(tmp_path, count, units_per_scope, expected):
    catalog = _catalog(count, padding=0)
    result, requests = _resolve(tmp_path, catalog, limits=replace(
        PlanningFeedbackSettings(), units_per_scope=units_per_scope))
    assert sorted(len(request.allowed_build_units) for request in requests) == expected
    assert result["gaps"] == [] and result["validation_rejections"] == 0
    assert sorted(unit_id for request in requests for unit_id in request.allowed_build_units) == sorted(
        unit["build_unit_id"] for unit in catalog["build_units"])


def test_token_byte_bound_partitions_even_when_configured_bytes_would_fit(tmp_path):
    catalog = _catalog(4, padding=17000)
    result, requests = _resolve(tmp_path, catalog, max_input_tokens=20000)
    assert 80000 < len(prepare_feedback_request(_combined_request(requests))[1]) <= 131072
    assert len(requests) == 2 and result["gaps"] == []
    assert all(len(prepare_feedback_request(request)[1]) <= 80000 for request in requests)


def test_scope_cap_counts_byte_partitions_without_dropping_unresolved_actions(tmp_path):
    catalog = _catalog()
    result, requests = _resolve(tmp_path, catalog, limits=replace(PlanningFeedbackSettings(), max_scopes=1))
    assert len(requests) == len(result["plan"]["feedback"]) == result["model_calls"] == 1
    assert result["gaps"] == ["feedback_scope_bound: 1 deterministic partitions were not inferred"]
    assert result["plan"]["model"]["status"] == "PARTIAL"
    assert requests[0].allowed_build_units == tuple(sorted(unit["build_unit_id"]
                                                         for unit in catalog["build_units"])[:7])
    actions = result["plan"]["build_topology"]["build_actions"]
    assert len(actions) == 14
    assert {action["build_unit_id"] for action in actions if action["recipe"] is not None} == set(
        requests[0].allowed_build_units)
    assert all(action["requires_inference"] and action["executable"] is False
               for action in actions if action["recipe"] is None)


def test_oversized_single_unit_keeps_explicit_gap_and_does_not_block_fitting_neighbors(tmp_path):
    catalog = _catalog(3, padding=(140000, 0, 0))
    result, requests = _resolve(tmp_path, catalog)
    assert len(requests) == result["model_calls"] == 1
    feedback = result["plan"]["feedback"]
    assert [value["status"] for value in feedback] == ["BUDGET_EXCEEDED", "ACCEPTED"]
    assert feedback[0]["calls"] == feedback[0]["metrics"]["request_bytes"] == 0
    assert result["plan"]["contradictions"] == ["feedback_request_byte_bound"]
    actions = result["plan"]["build_topology"]["build_actions"]
    assert len(actions) == 3
    assert [action["root"] for action in actions if action["recipe"] is None] == ["node-00"]
    assert len(requests[0].allowed_build_units) == 2


def test_partition_order_and_guidance_cache_identity_are_repeatable(tmp_path):
    catalog = _catalog()
    first, first_requests = _resolve(tmp_path, catalog)
    second, second_requests = _resolve(tmp_path, catalog)
    assert second_requests == [] and second["model_calls"] == 0
    assert all(value["cache_hit"] for value in second["plan"]["feedback"])
    assert [value["cache_key"] for value in second["plan"]["feedback"]] == [
        value["cache_key"] for value in first["plan"]["feedback"]]
    assert second["plan"]["build_topology"] == first["plan"]["build_topology"]
    reordered = copy.deepcopy(catalog)
    reordered["build_units"].reverse()
    reordered["files"].reverse()
    third, third_requests = _resolve(tmp_path / "reordered", reordered)
    assert sorted(request.allowed_build_units for request in third_requests) == sorted(
        request.allowed_build_units for request in first_requests)
    assert {request.summary["guidance_bundle_sha256"] for request in third_requests} == {
        request.summary["guidance_bundle_sha256"] for request in first_requests}
    for key, value in first["plan"]["build_topology"].items():
        actual = third["plan"]["build_topology"][key]
        if key in {"build_actions", "build_systems"}:
            assert sorted(actual, key=lambda item: item["build_unit_id"]) == sorted(
                value, key=lambda item: item["build_unit_id"])
        else:
            assert actual == value


def test_partition_sizing_uses_sanitized_bytes_and_preserves_additive_inventory(tmp_path):
    catalog = _catalog(2, padding=0)
    content = "API_TOKEN=" + "synthetic " * 16000
    document = {"path": "node-00/settings.env", "sha256": hashlib.sha256(content.encode()).hexdigest(),
                "content": content}
    unit = next(unit for unit in catalog["build_units"] if unit["root"] == "node-00")
    unit["descriptor_package"]["documents"].append(document)
    catalog["files"].append({"path": document["path"], "sha256": document["sha256"],
                             "size_bytes": len(content.encode())})
    extra = {"path": "node-01/note.txt", "sha256": hashlib.sha256(b"inert note").hexdigest(), "size_bytes": 10}
    catalog["files"].append(extra)
    original = copy.deepcopy(catalog)
    result, requests = _resolve(tmp_path, catalog)
    assert len(requests) == 1 and result["gaps"] == []
    request = requests[0]
    assert request.summary["evidence_inventory"] == [extra]
    assert request.summary["evidence_inventory_omitted"] == 0
    assert extra["path"] in request.allowed_paths
    received = next(unit for unit in request.summary["build_units"] if unit["root"] == "node-00")
    assert next(item["content"] for item in received["descriptor_package"]["documents"]
                if item["path"] == document["path"]) == "[REDACTED assignment]"
    assert catalog == original


def test_byte_splitting_retains_family_system_and_image_profile_boundaries(tmp_path):
    catalog = _catalog(2, padding=80000)
    texts = {
        "android/build.gradle": "plugins { id 'com.android.application' }\n",
        "jvm/build.gradle": "plugins { id 'java' }\n",
        "native/CMakeLists.txt": "project(control)\nadd_executable(control main.c)\n",
        "make/Makefile": "all:\n\ttrue\n",
    }
    files = [{"path": path, "sha256": hashlib.sha256(text.encode()).hexdigest(),
              "size_bytes": len(text.encode())} for path, text in texts.items()]
    units = discover_build_units(files)
    assert len(units) == 4
    for unit in units:
        unit["descriptor_package"] = {"documents": [
            {"path": item["path"], "sha256": item["sha256"], "content": texts[item["path"]]}
            for item in files if str(Path(item["path"]).parent) == unit["root"]],
            "bounds": {}, "gaps": []}
        if unit["root"] == "android":
            unit["descriptor_facts"] = {"kind": "android-gradle-application"}
    catalog["files"].extend(files)
    catalog["build_units"].extend(units)
    result, requests = _resolve(tmp_path, catalog, abstain=True)
    assert result["validation_rejections"] == 0
    assert len(requests) == 6
    keys = []
    for request in requests:
        keys.append((request.summary["build_units"][0]["family"], request.allowed_build_systems[0],
                     request.allowed_image_profiles[0]))
        assert all((unit["family"], unit["build_system"], unit["required_image_profile"]) == keys[-1]
                   for unit in request.summary["build_units"])
    assert sorted(keys) == [
        ("java", "gradle", "android"), ("java", "gradle", "java"),
        ("native", "cmake", "native"), ("native", "make", "native"),
        ("node", "node", "node"), ("node", "node", "node")]
    assert sorted(unit_id for request in requests for unit_id in request.allowed_build_units) == sorted(
        unit["build_unit_id"] for unit in catalog["build_units"])
