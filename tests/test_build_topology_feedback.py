from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.config import PlanningFeedbackSettings
from appsec_review.inference import ModelRequest, ModelResult
from appsec_review.jobs.build_discovery import discover_build_units
from appsec_review.jobs.build_topology import compile_build_topology, topology_evidence_bundle
from appsec_review.jobs.job_target_analysis_plan.planning import (
    PROPOSAL_SCHEMA, bounded_feedback, deterministic_plan, evidence_catalog, feedback_request, merge_proposal,
    model_safe, summarize_catalog, validate_plan, validate_proposal,
)


def _inputs():
    texts = {"native/CMakeLists.txt": "project(control)\nadd_executable(control main.c)\n",
             "native/main.c": "int main(void) { return 0; }\n",
             "native/extra.h": "typedef int extra;\n"}
    files = [{"path": path, "sha256": hashlib.sha256(text.encode()).hexdigest(),
              "size_bytes": len(text.encode())} for path, text in texts.items()]
    units = discover_build_units(files)
    assert len(units) == 1
    unit = units[0]
    unit["descriptor_package"] = {"documents": [
        {"path": item["path"], "sha256": item["sha256"], "content": texts[item["path"]]}
        for item in files if item["path"] != "native/extra.h"],
        "bounds": {}, "gaps": []}
    catalog = {"source_fingerprint": "synthetic-feedback-source", "catalog_handoff_sha256": "c" * 64,
               "files": files, "components": [], "projects": [], "build_files": [],
               "build_units": units, "gaps": [], "accepted_artifacts": [], "compile_databases": []}
    request = ModelRequest(
        schema=PROPOSAL_SCHEMA, persona="synthetic persona", role="synthetic role",
        guidance="synthetic bounded proposal/3 guidance", summary={"build_units": units},
        allowed_scanners=(), allowed_build_systems=("cmake",), allowed_components=(),
        allowed_paths=tuple(item["path"] for item in files),
        allowed_build_units=(unit["build_unit_id"],), allowed_image_profiles=("native",),
        provider="offline-scripted", model="synthetic-model/1", reasoning="low",
        max_input_tokens=32000, max_output_tokens=16000)
    recipe = {"schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
              "image_profile": "native", "source_dir": "native", "build_dir": "native/build",
              "system_packages": [], "environment": {}, "dependency_files": ["native/CMakeLists.txt"],
              "configure_commands": [],
              "build_commands": [["clang", "--target=x86_64-unknown-linux-gnu", "-c", "main.c",
                                  "-o", "build/control.o"]],
              "expected_outputs": ["native/build"], "network_required": False,
              "reason": "explicit synthetic accepted compiler command"}
    final = {"schema": PROPOSAL_SCHEMA, "action": "final", "component_proposals": [],
             "build_recipes": [recipe], "hints": [], "abstentions": []}
    return catalog, request, final, texts


def _run(tmp_path, responses, *, limits=None, identity=None, read=None):
    catalog, request, final, texts = _inputs()
    calls = []
    responses = iter(responses)
    def infer(current, *, timeout_seconds):
        assert 0 < timeout_seconds <= 300
        calls.append(current)
        value = next(responses)
        if isinstance(value, Exception):
            raise value
        return ModelResult(value)
    result = bounded_feedback(
        infer, request, catalog=catalog, limits=limits or PlanningFeedbackSettings(),
        read_document=read or (lambda item, bound: texts[item["path"]].encode()[:bound + 1]),
        cache_root=tmp_path / "cache",
        identity=identity or {"environment": "ABSENT", "profiles": None, "rules": "synthetic/1"})
    return result, calls


def test_proposal3_final_uses_actual_validator_and_immutable_complete_cache(tmp_path):
    catalog, _, final, _ = _inputs()
    assert validate_proposal(final, catalog=catalog) == []
    result, calls = _run(tmp_path, [final])
    assert result["status"] == "ACCEPTED" and len(calls) == result["calls"] == 1
    cached, second = _run(tmp_path, [])
    assert cached["cache_hit"] is True and cached["calls"] == 0 and not second
    assert cached["cache_key"] == result["cache_key"]
    assert cached["proposal"] == result["proposal"]


def _component_inputs():
    texts = {
        "CMakeLists.txt": "project(control)\n",
        "lib/CMakeLists.txt": "project(lib)\nadd_library(control_lib STATIC core.c)\n",
        "lib/core.c": "int control(void) { return 1; }\n",
        "app/CMakeLists.txt": "project(app)\nadd_executable(control_app main.c)\ntarget_link_libraries(control_app control_lib)\n",
        "app/main.c": "int main(void) { return 0; }\n",
    }
    files = [{"path": path, "sha256": hashlib.sha256(text.encode()).hexdigest(),
              "size_bytes": len(text.encode())} for path, text in texts.items()]
    units = discover_build_units(files)
    for unit in units:
        unit["descriptor_package"] = {"documents": [
            {"path": item["path"], "sha256": item["sha256"], "content": texts[item["path"]]}
            for item in files if str(Path(item["path"]).parent) == unit["root"]],
            "bounds": {}, "gaps": []}
    components = [{"component_id": "component:" + name, "root": root,
                   "manifest": "CMakeLists.txt" if root == "." else root + "/CMakeLists.txt"}
                  for name, root in (("root", "."), ("lib", "lib"), ("app", "app"))]
    catalog = {"source_fingerprint": "synthetic-component-source", "catalog_handoff_sha256": "c" * 64,
               "files": files, "components": components, "projects": [], "build_files": [],
               "build_units": units, "gaps": [], "accepted_artifacts": [], "compile_databases": []}
    proposal = {"schema": PROPOSAL_SCHEMA, "action": "final", "hints": [], "build_recipes": [],
                "abstentions": [{"build_unit_id": unit["build_unit_id"],
                                 "reason": "component API proposal does not supply a recipe"}
                                for unit in units],
                "component_proposals": [
                    {"component_id": "component:app", "scanner_ids": ["tool-semgrep"],
                     "build_systems": ["cmake"], "scope_paths": ["app/main.c"],
                     "dependencies": ["component:lib"], "reason": "accepted descriptor relationship"},
                    {"component_id": "component:lib", "scanner_ids": ["tool-semgrep"],
                     "build_systems": ["cmake"], "scope_paths": ["lib/core.c"],
                     "dependencies": [], "reason": "accepted source component"}]}
    return catalog, proposal


def test_catalog_grounded_component_api_preserves_the_single_whole_bundle_compiler():
    catalog, proposal = _component_inputs()
    original = copy.deepcopy(catalog)
    plan = deterministic_plan(catalog, summarize_catalog(
        catalog, max_items=100, max_bytes=65536, sample_per_prefix=10))
    graph = plan["build_topology"]["executable_graph"]
    roots = {node["build_unit_id"]: node["root"] for node in graph["nodes"]}
    assert any(roots[edge["consumer_build_unit_id"]] == "app" and
               roots[edge["producer_build_unit_id"]] == "lib" for edge in graph["edges"])
    assert validate_proposal(proposal, catalog=catalog) == []
    assert validate_proposal(proposal, catalog=catalog,
        allowed_components=("component:app", "component:lib"),
        allowed_paths=("app/main.c", "lib/core.c"), allowed_scanners=("tool-semgrep",),
        allowed_build_systems=("cmake",)) == []
    variants = [proposal, {**proposal, "component_proposals": []},
                {**proposal, "component_proposals": proposal["component_proposals"][:1]},
                {**proposal, "component_proposals": list(reversed(proposal["component_proposals"]))}]
    for value in variants:
        merged = merge_proposal(plan, value, catalog)
        validate_plan(merged, catalog)
        assert merged["build_topology"]["executable_graph"] == graph
        assert merged["components"][0]["scope"] == plan["components"][0]["scope"]
    assert catalog == original


@pytest.mark.parametrize("change,expected", [
    ("foreign_component", "accepted bounded catalog identity"),
    ("foreign_path", "accepted bounded path"),
    ("unsupported_scanner", "scanner selection is not allowlisted"),
    ("inapplicable_scanner", "deterministic safety rules"),
    ("non_derived_system", "not derived from accepted component"),
    ("foreign_dependency", "accepted component identity"),
    ("non_derived_dependency", "not derived from deterministic"),
    ("self_dependency", "accepted component identity"),
    ("cycle", "contain a cycle"),
    ("component_boundary", "accepted bounded catalog identity"),
    ("path_boundary", "accepted bounded path"),
    ("scanner_boundary", "scanner selection is not allowlisted"),
    ("system_boundary", "build system is not allowlisted"),
])
def test_component_api_rejects_foreign_non_derived_cyclic_and_request_boundary_claims(change, expected):
    catalog, proposal = _component_inputs()
    item = proposal["component_proposals"][0]
    boundaries = {}
    if change == "foreign_component":
        item["component_id"] = "component:foreign"
    elif change == "foreign_path":
        item["scope_paths"] = ["lib/core.c"]
    elif change == "unsupported_scanner":
        item["scanner_ids"] = ["tool-arbitrary-shell"]
    elif change == "inapplicable_scanner":
        item["scanner_ids"] = ["tool-mobsfscan"]
    elif change == "non_derived_system":
        item["build_systems"] = ["go"]
    elif change == "foreign_dependency":
        item["dependencies"] = ["component:foreign"]
    elif change == "self_dependency":
        item["dependencies"] = ["component:app"]
    elif change in {"non_derived_dependency", "cycle"}:
        proposal["component_proposals"][1]["dependencies"] = ["component:app"]
        if change == "non_derived_dependency":
            item["dependencies"] = []
    else:
        boundaries[{"component_boundary": "allowed_components", "path_boundary": "allowed_paths",
                    "scanner_boundary": "allowed_scanners", "system_boundary": "allowed_build_systems"}[change]] = ()
    errors = validate_proposal(proposal, catalog=catalog, **boundaries)
    assert any(expected in error for error in errors)
    if not boundaries:
        plan = deterministic_plan(catalog, summarize_catalog(
            catalog, max_items=100, max_bytes=65536, sample_per_prefix=10))
        with pytest.raises(ValueError, match="invalid bounded component proposal"):
            merge_proposal(plan, proposal, catalog)


@pytest.mark.parametrize("boundary", ["components", "scanners"])
def test_actual_feedback_enforces_empty_request_component_and_scanner_allowlists(tmp_path, boundary):
    catalog, request, final, texts = _inputs()
    catalog["components"] = [{"component_id": "component:native", "root": "native", "manifest": None}]
    final["component_proposals"] = [{
        "component_id": "component:native", "scanner_ids": ["tool-semgrep"],
        "build_systems": ["cmake"], "scope_paths": ["native/main.c"], "dependencies": [],
        "reason": "catalog-grounded but outside this actual worker request"}]
    assert validate_proposal(final, catalog=catalog) == []
    if boundary == "scanners":
        request = replace(request, allowed_components=("component:native",))
    calls = []
    def infer(current, *, timeout_seconds):
        calls.append(current)
        return ModelResult(final)
    result = bounded_feedback(infer, request, catalog=catalog, limits=PlanningFeedbackSettings(),
        read_document=lambda *_: pytest.fail("final cannot request evidence"), cache_root=tmp_path / "cache",
        identity={"environment": "ABSENT"})
    assert result["status"] == "BUDGET_EXCEEDED" and result["calls"] == len(calls) == 4
    expected = "accepted bounded catalog identity" if boundary == "components" else "scanner selection"
    assert any(expected in error for error in result["errors"])
    assert not list((tmp_path / "cache").glob("*.json"))
    cached = {"key": result["cache_key"], "status": "COMPLETE", "proposal": final, "documents": []}
    (tmp_path / "cache").mkdir(exist_ok=True)
    (tmp_path / "cache" / (result["cache_key"] + ".json")).write_bytes(json.dumps(cached).encode())
    with pytest.raises(ValueError, match="complete validated final"):
        bounded_feedback(lambda *_a, **_kw: pytest.fail("out-of-request cache must not call a model"),
            request, catalog=catalog, limits=PlanningFeedbackSettings(),
            read_document=lambda *_: pytest.fail("out-of-request cache cannot retrieve evidence"),
            cache_root=tmp_path / "cache", identity={"environment": "ABSENT"})


def test_actual_feedback_evidence_and_cache_honor_explicit_request_paths(tmp_path):
    catalog, request, final, texts = _inputs()
    request = replace(request, allowed_paths=("native/CMakeLists.txt", "native/main.c"))
    document = next(item for item in catalog["files"] if item["path"] == "native/extra.h")
    need = {"schema": PROPOSAL_SCHEMA, "action": "need_evidence", "requests": [{
        "path": document["path"], "sha256": document["sha256"], "reason": "outside explicit request"}]}
    calls = []
    def infer(current, *, timeout_seconds):
        calls.append(current)
        if len(calls) == 1:
            return ModelResult(need)
        assert current.repair_errors == ("evidence_identity_or_scope_rejected",)
        return ModelResult(final)
    result = bounded_feedback(infer, request, catalog=catalog, limits=PlanningFeedbackSettings(),
        read_document=lambda *_: pytest.fail("unoffered source must not be read"),
        cache_root=tmp_path / "cache", identity={})
    assert result["status"] == "ACCEPTED" and result["calls"] == len(calls) == 2
    assert result["documents"] == []
    cache = tmp_path / "cache" / (result["cache_key"] + ".json")
    cached = json.loads(cache.read_bytes())
    cached["documents"] = [{"path": document["path"], "sha256": document["sha256"],
                            "content": texts[document["path"]]}]
    cache.write_bytes(json.dumps(cached).encode())
    with pytest.raises(ValueError, match="complete validated final"):
        bounded_feedback(lambda *_a, **_kw: pytest.fail("out-of-request cache must not call a model"),
            request, catalog=catalog, limits=PlanningFeedbackSettings(),
            read_document=lambda *_: pytest.fail("cache cannot retrieve unoffered evidence"),
            cache_root=tmp_path / "cache", identity={})


def test_evidence_round_resolves_exact_bytes_without_model_graph_authority(tmp_path):
    catalog, _, final, texts = _inputs()
    item = next(item for item in catalog["files"] if item["path"] == "native/extra.h")
    need = {"schema": PROPOSAL_SCHEMA, "action": "need_evidence",
            "requests": [{**{key: item[key] for key in ("path", "sha256")}, "reason": "inspect include"}]}
    result, calls = _run(tmp_path, [need, final])
    assert result["calls"] == len(calls) == 2 and result["status"] == "ACCEPTED"
    assert result["documents"] == [{"path": item["path"], "sha256": item["sha256"],
                                    "content": texts[item["path"]]}]
    assert calls[1].summary["evidence"] == result["documents"]
    augmented = evidence_catalog(catalog, result["documents"])
    graph = compile_build_topology(augmented["build_units"], source_fingerprint=catalog["source_fingerprint"])
    for hints in ([], graph["facts"], graph["facts"][:1], list(reversed(graph["facts"]))):
        assert compile_build_topology(augmented["build_units"],
            source_fingerprint=catalog["source_fingerprint"], hints=hints) == graph
    plan = deterministic_plan(augmented, summarize_catalog(
        augmented, max_items=100, max_bytes=65536, sample_per_prefix=10))
    plan["planning_evidence"] = result["documents"]
    plan = merge_proposal(plan, final, augmented)
    validate_plan(plan, catalog)


@pytest.mark.parametrize("change", ["foreign_path", "wrong_hash", "extra_field", "too_many", "wrong_action"])
def test_evidence_request_shape_identity_and_scope_reject_before_read(tmp_path, change):
    catalog, _, final, _ = _inputs()
    item = next(item for item in catalog["files"] if item["path"] == "native/extra.h")
    request = {key: item[key] for key in ("path", "sha256")}
    request["reason"] = "bounded synthetic evidence"
    need = {"schema": PROPOSAL_SCHEMA, "action": "need_evidence", "requests": [request]}
    if change == "foreign_path":
        request["path"] = "../foreign"
    elif change == "wrong_hash":
        request["sha256"] = "f" * 64
    elif change == "extra_field":
        request["command"] = ["cat", request["path"]]
    elif change == "too_many":
        need["requests"] *= 9
    else:
        need["action"] = "execute"
    result, calls = _run(tmp_path, [need, final],
                         read=lambda *_: pytest.fail("invalid evidence must not be read"))
    assert len(calls) == 2 and calls[1].repair_errors
    assert result["documents"] == [] and result["status"] == "ACCEPTED"


@pytest.mark.parametrize("kind", ["invalid", "timeout", "abstention", "oversized"])
def test_exhausted_or_partial_feedback_never_becomes_a_complete_cache(tmp_path, kind):
    _, _, final, _ = _inputs()
    if kind == "invalid":
        reply = {"schema": PROPOSAL_SCHEMA, "action": "final"}
    elif kind == "timeout":
        reply = TimeoutError("synthetic timeout")
    elif kind == "abstention":
        reply = {**final, "build_recipes": [],
                 "abstentions": [{"build_unit_id": final["build_recipes"][0]["build_unit_id"],
                                   "reason": "missing compiler evidence"}]}
    else:
        reply = {**final, "oversized": "x" * 65537}
    result, calls = _run(tmp_path, [reply] * 4)
    assert result["status"] == ("PARTIAL" if kind == "abstention" else "BUDGET_EXCEEDED")
    assert len(calls) == (1 if kind == "abstention" else 4)
    assert not list((tmp_path / "cache").glob("*.json"))
    assert result["gap"]


@pytest.mark.parametrize("identity", [
    {"environment": "changed", "profiles": None, "rules": "synthetic/1"},
    {"environment": "ABSENT", "profiles": "changed", "rules": "synthetic/1"},
    {"environment": "ABSENT", "profiles": None, "rules": "changed"},
])
def test_feedback_cache_identity_cannot_reuse_changed_environment_profile_or_rules(tmp_path, identity):
    _, _, final, _ = _inputs()
    first, _ = _run(tmp_path, [final])
    second, calls = _run(tmp_path, [final], identity=identity)
    assert not second["cache_hit"] and len(calls) == 1
    assert first["cache_key"] != second["cache_key"]


def test_corrupt_cache_and_changed_source_bytes_block_instead_of_falling_back(tmp_path):
    _, _, final, _ = _inputs()
    result, _ = _run(tmp_path, [final])
    (tmp_path / "cache" / (result["cache_key"] + ".json")).write_bytes(b"{}")
    with pytest.raises(ValueError, match="cache identity"):
        _run(tmp_path, [])
    catalog, _, _, _ = _inputs()
    item = next(item for item in catalog["files"] if item["path"] == "native/extra.h")
    need = {"schema": PROPOSAL_SCHEMA, "action": "need_evidence",
            "requests": [{"path": item["path"], "sha256": item["sha256"], "reason": "inspect"}]}
    with pytest.raises(ValueError, match="source identity changed"):
        _run(tmp_path / "new", [need], read=lambda *_: b"changed")


def test_internal_deadline_and_unexpected_model_bug_are_distinct(tmp_path):
    catalog, request, _, texts = _inputs()
    times = iter((0, 301, 301))
    result = bounded_feedback(
        lambda *_args, **_kwargs: pytest.fail("deadline must prevent the call"), request,
        catalog=catalog, limits=PlanningFeedbackSettings(), read_document=lambda *_: b"",
        cache_root=tmp_path / "cache", identity={}, clock=lambda: next(times))
    assert result["calls"] == 0 and result["gap"].endswith("internal_feedback_deadline")
    with pytest.raises(RuntimeError, match="synthetic unexpected bug"):
        _run(tmp_path, [RuntimeError("synthetic unexpected bug")])


def test_model_hints_cannot_graft_facts_and_developer_environment_is_not_target_proof():
    catalog, _, final, _ = _inputs()
    final["hints"] = ["f" * 64]
    assert "hints must resolve" in "; ".join(validate_proposal(final, catalog=catalog))
    safe = model_safe({"environment": {"API_TOKEN": "private"}, "content": "URL=https://u:p@host\n"})
    assert "private" not in json.dumps(safe) and "u:p@" not in json.dumps(safe)
    before = copy.deepcopy(catalog)
    evidence_catalog(catalog, [])
    assert catalog == before


def test_unity_and_shared_container_declarations_are_scoped_partial_and_canonical():
    def document(path, text):
        return {"path": path, "sha256": hashlib.sha256(text.encode()).hexdigest(), "content": text}
    docker = document("Dockerfile", "FROM base AS i686\nCOPY --from=i686 /x /y\n")
    unity = document("game/ProjectSettings/ProjectSettings.asset", "scriptingBackend: 1\n")
    meta = document("game/Assets/plugin.dll.meta", "PluginImporter:\n  CPU: x86\n  OS: AnyOS\n")
    cmake = document("native/CMakeLists.txt", "project(control)\n")
    units = [{"build_unit_id": "unity-control", "root": "game", "family": "dotnet",
              "build_system": "unity", "markers": [{key: unity[key] for key in ("path", "sha256")}],
              "descriptor_package": {"documents": [unity, meta, docker], "bounds": {}, "gaps": []}},
             {"build_unit_id": "native-control", "root": "native", "family": "native",
              "build_system": "cmake", "markers": [{key: cmake[key] for key in ("path", "sha256")}],
              "descriptor_package": {"documents": [cmake, docker], "bounds": {}, "gaps": []}}]
    before = copy.deepcopy(units)
    graph = compile_build_topology(units, source_fingerprint="synthetic-unity-container")
    facts = graph["facts"]
    assert len([item for item in facts if item["predicate"] == "container:from"]) == 1
    assert any(item["predicate"] == "unity:raw_declaration" and item["value"]["raw"] == "x86" for item in facts)
    unity_ids = {item["fact_id"] for item in facts if item["predicate"].startswith("unity:")}
    assert all(item["build_unit_id"] == "unity-control" for item in graph["bindings"]
               if item["fact_id"] in unity_ids)
    assert not graph["edges"] and not graph["declarations"]
    assert "i686" not in {str(item.get("variant", {}).get("target_arch")) for item in graph["nodes"]}
    assert {item["code"] for item in graph["coverage_gaps"]} >= {
        "unity_declarations_partial", "container_declarations_advisory"}
    bundle = topology_evidence_bundle(units, source_fingerprint="synthetic-unity-container")
    for hints in ([], facts, facts[:1], list(reversed(facts))):
        assert compile_build_topology(units, source_fingerprint="synthetic-unity-container", hints=hints) == graph
        assert topology_evidence_bundle(units, source_fingerprint="synthetic-unity-container") == bundle
    assert units == before
    missing_marker = copy.deepcopy(units)
    missing_marker[1]["markers"] = []
    with pytest.raises(ValueError, match="requires resolving descriptor evidence"):
        compile_build_topology(missing_marker, source_fingerprint="synthetic-unity-container")


def test_additive_inventory_is_usable_exact_and_bounded_before_the_first_call():
    from dataclasses import asdict
    from appsec_review.storage import canonical_json
    catalog, request, _, _ = _inputs()
    before = copy.deepcopy(catalog)
    offered = feedback_request(request, catalog, PlanningFeedbackSettings())
    assert offered.summary["evidence_inventory"] == [{
        key: catalog["files"][2][key] for key in ("path", "sha256", "size_bytes")}]
    assert offered.summary["evidence_inventory_omitted"] == 0
    assert "native/extra.h" in offered.allowed_paths
    assert len(canonical_json(model_safe(asdict(offered)))) <= 131072
    assert catalog == before and "evidence_inventory" not in request.summary


def test_real_planner_requests_and_publishes_exact_additive_evidence(tmp_path):
    from appsec_review.config import load_config
    from appsec_review.jobs.cataloging import source_fingerprint
    from appsec_review.jobs.job_review_intake import build_job as intake_job
    from appsec_review.jobs.job_target_catalog import build_job as catalog_job
    from appsec_review.jobs.job_target_analysis_plan import build_job, load_accepted_plan
    from appsec_review.runtime import GraphRunner
    target = tmp_path / "target"
    (target / "native").mkdir(parents=True)
    # A CMakeLists.txt with only project() declares no build point and is not a unit (T-056.2);
    # the control project needs a target to be discovered.
    (target / "native/CMakeLists.txt").write_bytes(b"project(control)\nadd_executable(control main.c)\n")
    (target / "native/main.c").write_bytes(b"int main(void) { return 0; }\n")
    (target / "native/note.txt").write_bytes(b"explicitly synthetic additive evidence\r\n")
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_bytes((Path(__file__).parents[1] / "appsec-review.toml").read_bytes())
    config = load_config(config_path)
    calls = []
    def infer(request, *, timeout_seconds):
        calls.append(request)
        if len(calls) == 1:
            identity = next(item for item in request.summary["evidence_inventory"]
                            if item["path"] == "native/note.txt")
            return ModelResult({"schema": PROPOSAL_SCHEMA, "action": "need_evidence", "requests": [{
                "path": identity["path"], "sha256": identity["sha256"], "reason": "read exact accepted notes"}]})
        assert request.summary["evidence"][0]["content"].endswith("\r\n")
        _, _, final, _ = _inputs()
        unit = request.summary["build_units"][0]
        final["build_recipes"][0]["build_unit_id"] = unit["build_unit_id"]
        return ModelResult(final)
    result = GraphRunner(config, [intake_job(), catalog_job(), build_job(infer=infer)]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    run_root = config.runtime.runs_dir / result["run_id"]
    plan = load_accepted_plan(run_root)
    assert len(calls) == 2 and plan["feedback"][0]["calls"] == 2
    assert plan["feedback"][0]["metrics"]["evidence_bytes"] == len(
        b"explicitly synthetic additive evidence\r\n")
    assert plan["planning_evidence"][0]["path"] == "native/note.txt"
    assert plan["planning_evidence"][0]["sha256"] == hashlib.sha256(
        b"explicitly synthetic additive evidence\r\n").hexdigest()
    assert plan["build_environment"]["mode"] == "NOT_RUN"
    assert plan["build_environment"]["availability"] == "ABSENT"
    pointer = json.loads((run_root / "data/jobs/job_target_analysis_plan/latest.json").read_bytes())
    claim = json.loads((run_root / Path(pointer["handoff_path"]).parent / "claim.json").read_bytes())
    launch = json.loads(claim["orchestration"]["build_environment_contract"])
    assert launch == {key: plan["build_environment"][key] for key in launch}
    assert set(launch) == {"schema", "workflow", "expected_producer", "mode", "reference", "reason"}


def test_unrelated_descendant_container_cannot_bind_to_another_unit():
    document = {"path": "owner/unrelated/Dockerfile", "content": "FROM windows-x86\n"}
    document["sha256"] = hashlib.sha256(document["content"].encode()).hexdigest()
    cmake = {"path": "owner/CMakeLists.txt", "content": "project(control)\n"}
    cmake["sha256"] = hashlib.sha256(cmake["content"].encode()).hexdigest()
    units = [{"build_unit_id": "owner-control", "root": "owner", "family": "native",
              "build_system": "cmake", "markers": [{key: cmake[key] for key in ("path", "sha256")}],
              "descriptor_package": {"documents": [cmake, document], "bounds": {}, "gaps": []}}]
    before = copy.deepcopy(units)
    graph = compile_build_topology(units, source_fingerprint="synthetic-container-collision")
    container_ids = {fact["fact_id"] for fact in graph["facts"]
                     if fact["predicate"].startswith("container:")}
    assert container_ids
    assert not any(binding["fact_id"] in container_ids for binding in graph["bindings"])
    own_ids = {fact["fact_id"] for fact in graph["facts"] if fact["path"] == cmake["path"]}
    assert own_ids and any(binding["fact_id"] in own_ids and binding["build_unit_id"] == "owner-control"
                           for binding in graph["bindings"])
    assert not graph["edges"]
    assert units == before
    missing_marker = copy.deepcopy(units)
    missing_marker[0]["markers"] = []
    with pytest.raises(ValueError, match="requires resolving descriptor evidence"):
        compile_build_topology(missing_marker, source_fingerprint="synthetic-container-collision")


def test_container_context_neither_taints_closed_native_proof_nor_supplies_missing_target():
    from tests.test_native_target_enforcement import _native, _profile
    from appsec_review.jobs.build_topology import refine_build_topology
    unit = _native(extra_documents={"Dockerfile": "FROM windows-x86 AS i686\nARG TARGETARCH=x86\n"})
    profile = _profile()
    graph = compile_build_topology([unit], source_fingerprint="synthetic-container-native", profiles=profile)
    assert any(fact["predicate"] == "container:from" for fact in graph["facts"])
    proof = refine_build_topology(graph, [unit], profiles=profile)["units"][0]["enforcement"][0]
    assert proof["status"] == "proven"
    assert proof["proven_axes"]["os"] == "linux" and proof["proven_axes"]["isa"] == "x86_64"
    unit["recipe"]["build_commands"] = [["clang", "-c", "main.c", "-o", "build/main.o"]]
    graph = compile_build_topology([unit], source_fingerprint="synthetic-container-native")
    missing = refine_build_topology(graph, [unit])["units"][0]["enforcement"][0]
    assert missing["status"] == "unknown"
    assert "compiler_target_unknown" in missing["unresolved_inputs"]


@pytest.mark.parametrize("limit,accepted", [(16777216, False), (33554432, True)])
def test_catalog_reader_has_explicit_per_kind_bounds_without_losing_hashes(tmp_path, limit, accepted):
    from appsec_review.jobs.job_target_analysis_plan.job import _read_artifact
    payload = b'{"padding":"' + b"x" * 16777216 + b'"}'
    path = tmp_path / "bounded-catalog.json"
    path.write_bytes(payload)
    identity = {"path": path.name, "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest()}
    if accepted:
        assert len(_read_artifact(tmp_path, identity, byte_limit=limit)["padding"]) == 16777216
        with pytest.raises(ValueError, match="identity changed"):
            _read_artifact(tmp_path, {**identity, "sha256": "f" * 64}, byte_limit=limit)
        with pytest.raises(ValueError, match="identity changed"):
            _read_artifact(tmp_path, {**identity, "size_bytes": len(payload) - 1}, byte_limit=limit)
    else:
        with pytest.raises(ValueError, match="byte bound"):
            _read_artifact(tmp_path, identity, byte_limit=limit)
    with pytest.raises(ValueError, match="unsupported.*byte limit"):
        _read_artifact(tmp_path, identity, byte_limit=33554433)


@pytest.mark.parametrize("action", ["need_evidence", "final"])
def test_proposal3_checked_in_schema_uses_only_local_resources(action):
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
    directory = Path(__file__).parents[1] / "docs/schemas"
    schemas, resources = {}, []
    for name in ("target-analysis-proposal", "build-recipe"):
        path = (directory / (name + ".schema.json")).resolve()
        schema = json.loads(path.read_bytes())
        schema["$id"] = path.as_uri()
        Draft202012Validator.check_schema(schema)
        schemas[name] = schema
        resources.append((path.as_uri(), Resource.from_contents(schema)))
    catalog, _, final, _ = _inputs()
    item = catalog["files"][2]
    proposal = final if action == "final" else {
        "schema": PROPOSAL_SCHEMA, "action": "need_evidence",
        "requests": [{"path": item["path"], "sha256": item["sha256"], "reason": "exact evidence"}]}
    validator = Draft202012Validator(schemas["target-analysis-proposal"],
                                     registry=Registry().with_resources(resources))
    validator.validate(proposal)
    if action == "final":
        assert not validator.is_valid({**proposal, "component_proposals": [{"component_id": "invented"}]})


def _transport(monkeypatch, tmp_path, send):
    from contextvars import ContextVar
    from types import SimpleNamespace
    import appsec_review.inference as inference
    from appsec_review.runtime import execution_safety as safety
    from appsec_review.storage import shared
    class Controller:
        def __init__(self):
            self.events = []
            self.stop_on_check = False

        def request(self, operation, **details):
            self.events.append((operation, details))
            if operation == "check" and self.stop_on_check:
                raise safety.ReviewStopped("trusted orchestration deadline")
            return {"permit": "synthetic-inference-permit"} if operation == "admit" else {}
    controller = Controller()
    monkeypatch.setattr(safety, "_ACTIVE", ContextVar("synthetic-controller", default=controller))
    monkeypatch.setattr(shared, "current", lambda: SimpleNamespace(run_root=tmp_path))
    monkeypatch.setitem(inference.PROVIDERS, "offline-scripted", send)
    return inference.infer, controller


@pytest.mark.parametrize("kind", ["output", "timeout"])
def test_proposal3_transport_first_error_refuses_repair_before_raw_retention(
        tmp_path, monkeypatch, kind):
    from appsec_review.inference import ModelOutputError
    from appsec_review.runtime import execution_safety as safety
    secret = "synthetic-sensitive-provider-data"
    calls = []
    def send(request, *, timeout_seconds):
        calls.append(request)
        if kind == "output":
            raise ModelOutputError(secret, raw_response=secret, rejected_output=secret) from ValueError(secret)
        raise TimeoutError(secret) from ValueError(secret)
    infer, controller = _transport(monkeypatch, tmp_path, send)
    catalog, request, _, _ = _inputs()
    with pytest.raises(safety.ReviewStopped):
        bounded_feedback(infer, request, catalog=catalog, limits=PlanningFeedbackSettings(),
            read_document=lambda *_: pytest.fail("invalid output must not read evidence"),
            cache_root=tmp_path / "cache", identity={})
    assert len(calls) == 1
    assert not list((tmp_path / "cache").glob("*.json"))
    records = [json.loads(path.read_bytes()) for path in (tmp_path / "data/execution-failures").glob("*.json")]
    assert len(records) == 2
    records = [record for record in records if record["action"] != "inference.execution"]
    assert len(records) == 1
    assert all(record["raw_response"] is None and record["repairable"] is True
               and record["outcome"] == "REJECTED" for record in records)
    assert secret not in json.dumps(records)
    assert len([item for item in controller.events if item[0] == "admit"]) == 1
    assert any(item[0] == "check" for item in controller.events)
    assert [item[1]["succeeded"] for item in controller.events if item[0] == "finish"] == [False]
    assert len([item for item in controller.events if item[0] == "failure"]) == 1


@pytest.mark.parametrize("kind", ["output", "timeout"])
def test_proposal3_transport_repair_signal_has_no_original_exception_chain(tmp_path, monkeypatch, kind):
    from contextvars import ContextVar
    from appsec_review.inference import ModelOutputError
    from appsec_review.runtime import execution_safety as safety
    secret = "synthetic-sensitive-provider-data"
    def send(request, *, timeout_seconds):
        if kind == "output":
            raise ModelOutputError(secret, raw_response=secret, rejected_output=secret) from ValueError(secret)
        raise TimeoutError(secret) from ValueError(secret)
    infer, _ = _transport(monkeypatch, tmp_path, send)
    # Ordinary repair mode receives a typed signal; first-error mode stops instead.
    monkeypatch.setattr(safety, "_ACTIVE", ContextVar("ordinary-repair-mode", default=None))
    _, request, _, _ = _inputs()
    with pytest.raises(ModelOutputError if kind == "output" else TimeoutError) as caught:
        infer(request, timeout_seconds=30)
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert secret not in str(caught.value)
    assert getattr(caught.value, "raw_response", None) is None
    assert getattr(caught.value, "rejected_output", None) is None


def test_proposal3_transport_unexpected_failure_still_latches_before_any_repair(tmp_path, monkeypatch):
    from appsec_review.runtime import execution_safety as safety
    import traceback
    secret = "synthetic-sensitive-provider-data"
    calls = []
    def send(request, *, timeout_seconds):
        calls.append(request)
        raise RuntimeError(secret) from ValueError(secret)
    infer, controller = _transport(monkeypatch, tmp_path, send)
    catalog, request, _, _ = _inputs()
    with pytest.raises(safety.ReviewStopped) as caught:
        bounded_feedback(infer, request, catalog=catalog, limits=PlanningFeedbackSettings(),
            read_document=lambda *_: pytest.fail("fatal error must not read evidence"),
            cache_root=tmp_path / "cache", identity={})
    assert len(calls) == 1 and not list((tmp_path / "cache").glob("*.json"))
    assert secret not in "".join(traceback.format_exception(
        type(caught.value), caught.value, caught.value.__traceback__))
    records = [json.loads(path.read_bytes()) for path in (tmp_path / "data/execution-failures").glob("*.json")]
    assert len(records) == 3
    records = [record for record in records if record["action"] != "inference.execution"]
    assert len(records) == 2
    contract = next(record for record in records if record.get("category") == "contract")
    rejected = next(record for record in records if record.get("outcome") == "REJECTED")
    assert contract["exception_type"] == "RuntimeError"
    assert rejected["repairable"] is False
    assert all(record["raw_response"] is None for record in records) and secret not in json.dumps(records)
    assert len([item for item in controller.events if item[0] == "failure"]) == 1
    assert [item[1]["succeeded"] for item in controller.events if item[0] == "finish"] == [False]


@pytest.mark.parametrize("kind", ["stop", "keyboard", "deadline", "teardown"])
def test_proposal3_transport_cannot_repair_global_stop_kill_deadline_or_teardown(
        tmp_path, monkeypatch, kind):
    from appsec_review.runtime import execution_safety as safety
    calls = []
    catalog, request, final, _ = _inputs()
    stop = safety.ReviewStopped("trusted global cancellation")
    def send(current, *, timeout_seconds):
        calls.append(current)
        if kind == "stop":
            raise stop
        if kind == "keyboard":
            raise KeyboardInterrupt()
        if kind == "teardown":
            safety.fail("trusted transport cleanup failure", action="inference.cleanup")
        return ModelResult(final)
    infer, controller = _transport(monkeypatch, tmp_path, send)
    controller.stop_on_check = kind == "deadline"
    with pytest.raises(safety.ReviewStopped) as caught:
        bounded_feedback(infer, request, catalog=catalog, limits=PlanningFeedbackSettings(),
            read_document=lambda *_: pytest.fail("cancellation must not read evidence"),
            cache_root=tmp_path / "cache", identity={})
    assert len(calls) == (0 if kind == "deadline" else 1)
    assert not list((tmp_path / "cache").glob("*.json"))
    records = [json.loads(path.read_bytes()) for path in (tmp_path / "data/execution-failures").glob("*.json")]
    assert len(records) == (0 if kind == "deadline" else 2)
    if kind != "deadline":
        assert {record["action"] for record in records} == {"inference", "inference.execution"}
        transport = next(record for record in records if record["action"] == "inference")
        execution = next(record for record in records if record["action"] == "inference.execution")
        assert transport["category"] == "cancelled" and execution["error_type"] == "ReviewStopped"
        assert all(record["raw_response"] is None for record in records)
    assert [item[1]["succeeded"] for item in controller.events if item[0] == "finish"] == (
        [] if kind == "deadline" else [False])
    if kind == "stop":
        assert caught.value is stop


def test_nonproposal3_transport_keeps_its_existing_fail_closed_diagnostic_boundary(tmp_path, monkeypatch):
    from appsec_review.inference import ModelOutputError
    from appsec_review.runtime import execution_safety as safety
    original = ModelOutputError("synthetic legacy failure", raw_response="synthetic legacy envelope")
    def send(request, *, timeout_seconds):
        raise original
    infer, controller = _transport(monkeypatch, tmp_path, send)
    _, request, _, _ = _inputs()
    with pytest.raises(safety.ReviewStopped):
        infer(replace(request, schema="appsec-review/target-analysis-proposal/2"), timeout_seconds=30)
    records = [json.loads(path.read_bytes()) for path in (tmp_path / "data/execution-failures").glob("*.json")]
    assert len(records) == 1 and records[0]["raw_response"] == original.raw_response
    assert records[0]["message"] == str(original) and "repairable" not in records[0]
    assert any(item[0] == "failure" for item in controller.events)


@pytest.mark.parametrize("version", [2, 3])
def test_transport_success_keeps_one_dispatch_and_normalizes_usage_without_mutating_result(
        tmp_path, monkeypatch, version):
    _, request, final, _ = _inputs()
    result = ModelResult(final)
    calls = []
    def send(current, *, timeout_seconds):
        calls.append((current, timeout_seconds))
        return result
    infer, controller = _transport(monkeypatch, tmp_path, send)
    request = replace(request, schema="appsec-review/target-analysis-proposal/" + str(version))
    normalized = infer(request, timeout_seconds=30)
    assert normalized.proposal is result.proposal
    assert normalized.input_tokens is normalized.output_tokens is None
    assert normalized.usage_unavailable_reason == "provider_usage_missing"
    assert result.usage_unavailable_reason is None
    assert calls == [(request, 30)] and not list((tmp_path / "data/execution-failures").glob("*.json"))
    assert [item[1]["succeeded"] for item in controller.events if item[0] == "finish"] == [True]


@pytest.mark.parametrize("prefix", ['@set "', 'set "'])
@pytest.mark.parametrize("sensitive", [False, True])
@pytest.mark.parametrize("ending", ["\n", "\r\n"])
def test_quoted_batch_evidence_is_byte_exact_or_withheld_before_model_and_cache(
        tmp_path, prefix, sensitive, ending):
    catalog, request, final, _ = _inputs()
    text = prefix + ("API_TOKEN=SYNTHETIC_BOUNDARY_SENTINEL" if sensitive else
                     "SDK_ROOT=tools/sdk") + '"' + ending
    data = text.encode()
    document = {"path": "native/setup.cmd", "sha256": hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data)}
    catalog["files"].append(document)
    original_paths = request.allowed_paths
    assert document["path"] not in original_paths
    request = replace(request, allowed_paths=(*original_paths, document["path"]))
    assert request.allowed_paths == (*original_paths, document["path"])
    assert document["path"] in request.allowed_paths
    before = copy.deepcopy(catalog)
    need = {"schema": PROPOSAL_SCHEMA, "action": "need_evidence", "requests": [{
        "path": document["path"], "sha256": document["sha256"], "reason": "exact synthetic batch evidence"}]}
    calls = []
    reads = []
    def read_document(item, bound):
        assert item == document and bound == PlanningFeedbackSettings().max_document_bytes
        assert item["path"] in request.allowed_paths and len(data) <= bound
        assert hashlib.sha256(data).hexdigest() == item["sha256"]
        reads.append((copy.deepcopy(item), bound, data))
        return data
    def infer(current, *, timeout_seconds):
        calls.append(current)
        assert "SYNTHETIC_BOUNDARY_SENTINEL" not in repr(current)
        if len(calls) == 1:
            return ModelResult(need)
        if sensitive:
            assert current.repair_errors == ("sensitive_evidence_withheld",)
            assert "evidence" not in current.summary
        else:
            assert current.summary["evidence"] == [{
                "path": document["path"], "sha256": document["sha256"], "content": text}]
        return ModelResult(final)
    result = bounded_feedback(infer, request, catalog=catalog, limits=PlanningFeedbackSettings(),
        read_document=read_document, cache_root=tmp_path / "cache", identity={})
    assert result["status"] == "ACCEPTED" and result["calls"] == len(calls) == 2
    assert reads == [(document, PlanningFeedbackSettings().max_document_bytes, data)]
    assert result["documents"] == ([] if sensitive else [{
        "path": document["path"], "sha256": document["sha256"], "content": text}])
    assert catalog == before and document["sha256"] == hashlib.sha256(data).hexdigest()
    cache = tmp_path / "cache" / (result["cache_key"] + ".json")
    contents = cache.read_bytes()
    assert b"SYNTHETIC_BOUNDARY_SENTINEL" not in contents
    if sensitive:
        # A hash-consistent but sensitive old cache must fail, not replay its raw document.
        cached = json.loads(contents)
        cached["documents"] = [{"path": document["path"], "sha256": document["sha256"], "content": text}]
        cache.write_text(json.dumps(cached), encoding="utf-8")
        with pytest.raises(ValueError, match="complete validated final"):
            bounded_feedback(lambda *_a, **_kw: pytest.fail("corrupt cache must not call a model"),
                request, catalog=catalog, limits=PlanningFeedbackSettings(),
                read_document=lambda *_: pytest.fail("corrupt cache must not read evidence"),
                cache_root=tmp_path / "cache", identity={})
    else:
        cached = bounded_feedback(lambda *_a, **_kw: pytest.fail("complete cache should replay"),
            request, catalog=catalog, limits=PlanningFeedbackSettings(),
            read_document=lambda *_: pytest.fail("complete cache must retain exact bytes"),
            cache_root=tmp_path / "cache", identity={})
        assert cached["cache_hit"] is True and cached["documents"] == result["documents"]
