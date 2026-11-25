from __future__ import annotations

from contextvars import ContextVar
import copy
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import traceback
from types import SimpleNamespace

import pytest

from appsec_review.config import PlanningFeedbackSettings
import appsec_review.inference as inference
from appsec_review.inference import ModelOutputError, ModelRequest, ModelResult
from appsec_review.inference.errors import ExecutionLimit, ProviderError
from appsec_review.jobs.build_discovery import discover_build_units
from appsec_review.jobs.build_topology import compile_build_topology
from appsec_review.jobs.job_target_catalog.reader import read_artifact
from appsec_review.jobs.job_target_analysis_plan.planning import (
    PROPOSAL_SCHEMA,
    bounded_feedback,
    deterministic_plan,
    evidence_catalog,
    feedback_request,
    merge_proposal,
    model_safe,
    summarize_catalog,
    validate_plan,
    validate_proposal,
)
from appsec_review.runtime import execution_safety as safety
from appsec_review.storage import canonical_json, shared


ROOT = Path(__file__).resolve().parents[3]


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


def _run(tmp_path, responses, *, limits=None, identity=None, read=None, on_call=None):
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
        identity=identity or {"environment": "ABSENT", "profiles": None, "rules": "synthetic/1"},
        on_call=on_call)
    return result, calls


def test_proposal3_final_uses_actual_validator_and_immutable_complete_cache(tmp_path):
    catalog, _, final, _ = _inputs()
    assert validate_proposal(final, catalog=catalog) == []
    events = []
    result, calls = _run(tmp_path, [final], on_call=lambda *args: events.append(args))
    assert result["status"] == "ACCEPTED" and len(calls) == result["calls"] == 1
    assert [ev[0] for ev in events] == ["STARTED", "COMPLETED"]
    cached, second = _run(tmp_path, [])
    assert cached["cache_hit"] is True and cached["calls"] == 0 and not second
    assert cached["cache_key"] == result["cache_key"]
    assert cached["proposal"] == result["proposal"]


@pytest.mark.parametrize("field,value", [
    ("abstention", []),
    ("abstention", {}),
    ("image_profile", {}),
    ("configure_commands", None),
    ("build_commands", [["clang", []]]),
], ids=["list-unit", "object-unit", "object-profile", "null-commands", "nested-argv"])
def test_nested_model_values_reach_bounded_repair(tmp_path, field, value):
    from appsec_review.inference.claude_cli import parse_model_payload

    catalog, request, final, _ = _inputs()
    malformed = copy.deepcopy(final)
    if field == "abstention":
        malformed["build_recipes"] = []
        malformed["abstentions"] = [{"build_unit_id": value, "reason": "unknown"}]
    else:
        malformed["build_recipes"][0][field] = value
    parsed = parse_model_payload(json.dumps(malformed), request.schema)
    assert validate_proposal(parsed, catalog=catalog)
    result, calls = _run(tmp_path, [parsed, final],
                         limits=replace(PlanningFeedbackSettings(), max_calls=2))
    assert result["status"] == "ACCEPTED"
    assert len(calls) == result["calls"] == 2
    assert calls[1].repair_errors and calls[1].prior_response is None
    exhausted, rejected = _run(tmp_path / "exhausted", [parsed, parsed],
                               limits=replace(PlanningFeedbackSettings(), max_calls=2))
    assert exhausted["status"] == "BUDGET_EXCEEDED"
    assert exhausted["proposal"] is None and exhausted["errors"]
    assert len(rejected) == exhausted["calls"] == 2
    assert not list((tmp_path / "exhausted" / "cache").glob("*.json"))


def _assert_dotnet_worker_guidance(request, run_root, worker):
    from appsec_review.guidance.compose import pin_bundle, render_prompt, verify_bundle
    from appsec_review.review.models import IntegrityError

    digest = request.summary["guidance_bundle_sha256"]
    bundle = json.loads((run_root / "data/guidance" / digest / "bundle.json").read_bytes())
    assert bundle["identity"]["worker"] == worker
    assert bundle["role_id"] == "build_engineer_dotnet"
    assert verify_bundle(bundle) == digest
    assert render_prompt(bundle) == request.guidance
    assert pin_bundle(run_root, bundle)["bundle_sha256"] == digest
    role = next(section for section in bundle["sections"] if section["name"] == "role")
    source = (ROOT / "pipeline/prompt-fragments/roles/build-engineer-dotnet.md").read_bytes()
    assert role["source_sha256"] == hashlib.sha256(source).hexdigest()
    assert role["text"] == request.role == source.decode()
    assert "current preparation requirement" in request.guidance
    assert "not proof that a download actually occurred" in request.guidance
    assert "does not alone prove an image-preparation download" not in request.guidance
    assert "this field does not control that access" in request.guidance
    assert "do not add a redundant `dotnet-sdk-*` system package" in request.guidance
    assert request.allowed_build_systems == ("dotnet",)
    assert request.allowed_scanners == request.allowed_components == ()
    changed = copy.deepcopy(bundle)
    next(section for section in changed["sections"] if section["name"] == "role")["text"] += "\nchanged"
    with pytest.raises(IntegrityError, match="guidance section hash mismatch: role"):
        verify_bundle(changed)


@pytest.mark.parametrize("reference", ["PackageReference", "PackageDownload", None],
                         ids=["package-reference", "package-download", "sdk-only"])
def test_dotnet_preparation_guidance_matches_planning_and_repair_contracts(tmp_path, reference):
    from appsec_review.config import load_config
    from appsec_review.container_runtime import ProjectImageResolver, profiles_from_settings
    from appsec_review.jobs.build_discovery import descriptor_package, validate_build_recipe
    from appsec_review.jobs.job_project_build.job import _infer_repair
    from appsec_review.jobs.job_project_build.repair import REPAIR_SCHEMA, apply_repair
    from tests.unit.job_target_analysis_plan.test_partitioning import _resolve

    content = '<Project Sdk="Microsoft.NET.Sdk">'
    if reference:
        content += f'<ItemGroup><{reference} Include="Example" Version="1.0.0" /></ItemGroup>'
    content += "</Project>"
    target = tmp_path / "target"
    (target / "dotnet").mkdir(parents=True)
    (target / "dotnet/App.csproj").write_text(content, encoding="utf-8")
    files = [{"path": "dotnet/App.csproj", "sha256": hashlib.sha256(content.encode()).hexdigest(),
              "size_bytes": len(content.encode())}]
    unit = discover_build_units(files)[0]
    unit["descriptor_package"] = descriptor_package(target, unit, files)
    catalog, _, final, _ = _inputs()
    catalog = {**catalog, "files": files, "build_units": [unit]}
    recipe = {
        "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
        "image_profile": "dotnet", "source_dir": "dotnet", "build_dir": "dotnet/obj",
        "system_packages": [], "environment": {}, "dependency_files": ["dotnet/App.csproj"],
        "configure_commands": [["dotnet", "restore", "App.csproj"]],
        "build_commands": [["dotnet", "build", "App.csproj"]], "expected_outputs": ["dotnet/bin"],
        "network_required": False, "reason": "accepted .NET descriptor",
    }
    planning_root = tmp_path / "planning"
    calls = []

    def infer_plan(request, **_kwargs):
        calls.append(request)
        _assert_dotnet_worker_guidance(request, planning_root, "build_planning")
        if len(calls) == 2:
            assert any("accepted package references require dependency egress" in error
                       for error in request.repair_errors)
        return ModelResult({**final, "build_recipes": [{
            **recipe, "network_required": bool(reference and len(calls) == 2)}]})

    planned, _ = _resolve(planning_root, catalog, custom_infer=infer_plan,
                           target_root=target, max_input_tokens=32000)
    assert planned["model_calls"] == (2 if reference else 1)
    assert planned["gaps"] == []
    action = planned["plan"]["build_topology"]["build_actions"][0]
    accepted = action["recipe"]
    assert accepted["network_required"] is bool(reference)
    assert accepted["system_packages"] == []
    assert validate_build_recipe(accepted, unit) == []
    if reference:
        assert any("accepted package references require dependency egress" in error
                   for error in validate_build_recipe({**accepted, "network_required": False}, unit))

    config = load_config(ROOT / "appsec-review.toml").job("job_project_build")
    profile = profiles_from_settings(config.settings["profiles"])["dotnet"]
    resolver = ProjectImageResolver(metadata_root=tmp_path / "metadata", target_root=target,
        runner=lambda *_a, **_kw: pytest.fail("definition must not execute image/build commands"))
    _, definition = resolver.definition({**accepted, "build_system": "dotnet"}, profile)
    assert ('RUN ["dotnet","restore"]' in definition.decode()) is bool(reference)
    repair_root = tmp_path / "repair"
    context = SimpleNamespace(job=SimpleNamespace(
        config=config, repository_root=ROOT, run_root=repair_root, run_id="dotnet-guidance",
        attempt_id="attempt_0001"), unit_root=repair_root / "repair-unit")
    repair = {"schema": REPAIR_SCHEMA, "system_packages": [],
              "environment": {"TREATWARNINGSASERRORS": "false"}, "package_manager": None,
              "dependency_restores": [], "reason": "accepted analyzer warning promoted to error"}
    repair_calls = []

    def infer_repair(request, **_kwargs):
        repair_calls.append(request)
        _assert_dotnet_worker_guidance(request, repair_root, "build_repair")
        assert request.summary["accepted_recipe"]["network_required"] is bool(reference)
        return ModelResult({**repair, "network_required": False} if len(repair_calls) == 1 else repair)

    kwargs = {"action": action, "recipe": accepted, "dockerfile": definition,
              "diagnostics": {"stderr_tail": "analyzer warning promoted to error"},
              "attempts": [], "infer": infer_repair}
    with pytest.raises(ModelOutputError, match="repair proposal fields are invalid"):
        _infer_repair(context, repair_number=1, **kwargs)
    proposal = _infer_repair(context, repair_number=2, **kwargs)
    repaired = apply_repair(accepted, proposal, build_system="dotnet")
    assert len(repair_calls) == 2
    assert repaired["network_required"] is bool(reference)
    assert repaired["system_packages"] == []
    assert validate_build_recipe(repaired, unit) == []
    _, repaired_definition = resolver.definition({**repaired, "build_system": "dotnet"}, profile)
    assert ('RUN ["dotnet","restore"]' in repaired_definition.decode()) is bool(reference)


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
    catalog, request, final, _ = _inputs()
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

    result = bounded_feedback(
        infer, request, catalog=catalog, limits=PlanningFeedbackSettings(),
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
        bounded_feedback(
            lambda *_a, **_kw: pytest.fail("out-of-request cache must not call a model"),
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

    result = bounded_feedback(
        infer, request, catalog=catalog, limits=PlanningFeedbackSettings(),
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
        bounded_feedback(
            lambda *_a, **_kw: pytest.fail("out-of-request cache must not call a model"),
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
        assert compile_build_topology(
            augmented["build_units"], source_fingerprint=catalog["source_fingerprint"], hints=hints) == graph
    plan = deterministic_plan(augmented, summarize_catalog(
        augmented, max_items=100, max_bytes=65536, sample_per_prefix=10))
    plan["planning_evidence"] = result["documents"]
    plan = merge_proposal(plan, final, augmented)
    validate_plan(plan, catalog)


@pytest.mark.parametrize("change", ["foreign_path", "wrong_hash", "extra_field", "too_many", "wrong_action", "duplicate_path"])
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
    elif change == "duplicate_path":
        need["requests"] = [request, copy.deepcopy(request)]
    else:
        need["action"] = "execute"
    result, calls = _run(
        tmp_path,
        [need, final],
        read=None if change == "duplicate_path" else (lambda *_: pytest.fail("invalid evidence must not be read")),
    )
    assert len(calls) == 2 and calls[1].repair_errors
    if change == "duplicate_path":
        assert "evidence_request_makes_no_progress" in calls[1].repair_errors
    assert result["documents"] == [] and result["status"] == "ACCEPTED"


@pytest.mark.parametrize("kind", ["invalid", "timeout", "abstention", "oversized", "provider", "byte_bound_exc", "non_mapping", "sensitive_output"])
def test_exhausted_or_partial_feedback_never_becomes_a_complete_cache(tmp_path, kind):
    _, _, final, _ = _inputs()
    events = []
    if kind == "invalid":
        reply = {"schema": PROPOSAL_SCHEMA, "action": "final"}
    elif kind == "timeout":
        reply = TimeoutError("synthetic timeout")
    elif kind == "provider":
        reply = ProviderError("synthetic provider outage")
    elif kind == "byte_bound_exc":
        reply = ModelOutputError("response exceeds byte bound")
    elif kind == "non_mapping":
        reply = ["not-a-mapping"]
    elif kind == "sensitive_output":
        reply = {**final, "abstentions": [{"build_unit_id": final["build_recipes"][0]["build_unit_id"],
                                           "reason": "API_TOKEN=SECRET_VALUE_123456"}]}
    elif kind == "abstention":
        reply = {**final, "build_recipes": [],
                 "abstentions": [{"build_unit_id": final["build_recipes"][0]["build_unit_id"],
                                   "reason": "missing compiler evidence"}]}
    else:
        reply = {**final, "oversized": "x" * 65537}
    result, calls = _run(tmp_path, [reply] * 4, on_call=lambda *args: events.append(args))
    assert result["status"] == ("PARTIAL" if kind == "abstention" else "BUDGET_EXCEEDED")
    assert len(calls) == (1 if kind in {"abstention", "provider"} else 4)
    assert not list((tmp_path / "cache").glob("*.json"))
    assert result["gap"]
    assert len(events) >= len(calls)


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
    catalog, request, final, _ = _inputs()
    with pytest.raises(ValueError, match="call timeout must be a positive integer"):
        bounded_feedback(
            lambda *_a, **_kw: None, request, catalog=catalog,
            limits=PlanningFeedbackSettings(), call_timeout_seconds=0,
            read_document=None, cache_root=tmp_path / "bad-timeout", identity={})

    result, _ = _run(tmp_path, [final])
    cache_file = tmp_path / "cache" / (result["cache_key"] + ".json")
    cache_file.write_bytes(b"{}")
    with pytest.raises(ValueError, match="cache identity"):
        _run(tmp_path, [])

    cache_file.write_bytes(json.dumps({
        "key": result["cache_key"], "proposal": final, "documents": [], "status": "PARTIAL",
    }).encode())
    with pytest.raises(ValueError, match="complete validated final"):
        _run(tmp_path, [])

    limits = PlanningFeedbackSettings()
    cache_file.write_bytes(b"x" * (2 * (limits.max_response_bytes + limits.max_evidence_bytes) + 4097))
    with pytest.raises(ValueError, match="exceeds its bound"):
        _run(tmp_path, [])

    item = next(item for item in catalog["files"] if item["path"] == "native/extra.h")
    need = {"schema": PROPOSAL_SCHEMA, "action": "need_evidence",
            "requests": [{"path": item["path"], "sha256": item["sha256"], "reason": "inspect"}]}
    with pytest.raises(ValueError, match="source identity changed"):
        _run(tmp_path / "new", [need], read=lambda *_: b"changed")


def test_feedback_evidence_bounds_utf8_and_post_call_deadlines(tmp_path):
    catalog, request, final, _ = _inputs()
    item = next(item for item in catalog["files"] if item["path"] == "native/extra.h")
    need = {"schema": PROPOSAL_SCHEMA, "action": "need_evidence",
            "requests": [{"path": item["path"], "sha256": item["sha256"], "reason": "inspect"}]}

    # 1. max_evidence_rounds=0 -> evidence_rounds_exhausted
    res_rounds, _ = _run(
        tmp_path / "rounds", [need, final],
        limits=replace(PlanningFeedbackSettings(), max_evidence_rounds=0),
    )
    assert res_rounds["status"] == "BUDGET_EXCEEDED"
    assert res_rounds["errors"] == ["evidence_rounds_exhausted"]

    # 2. Oversized document read -> evidence_document_byte_bound
    res_doc_bound, calls_doc = _run(
        tmp_path / "doc-bound", [need, final],
        limits=replace(PlanningFeedbackSettings(), max_document_bytes=4),
        read=lambda _it, _b: b"more-than-four-bytes",
    )
    assert res_doc_bound["status"] == "ACCEPTED"
    assert calls_doc[1].repair_errors == ("evidence_document_byte_bound",)

    # 3. Non-UTF8 bytes matching sha256 -> unsupported_evidence_encoding
    bad_utf8 = b"\xff\xfe\xfd"
    cat_utf8 = copy.deepcopy(catalog)
    bin_item = {"path": "native/bin.dat", "sha256": hashlib.sha256(bad_utf8).hexdigest(), "size_bytes": 3}
    cat_utf8["files"].append(bin_item)
    req_utf8 = replace(request, allowed_paths=(*request.allowed_paths, "native/bin.dat"))
    need_utf8 = {"schema": PROPOSAL_SCHEMA, "action": "need_evidence",
                 "requests": [{"path": "native/bin.dat", "sha256": bin_item["sha256"], "reason": "inspect"}]}
    seen_utf8 = []
    res_utf8 = bounded_feedback(
        lambda cur, **_kw: (seen_utf8.append(cur), ModelResult(need_utf8 if len(seen_utf8) == 1 else final))[1],
        req_utf8, catalog=cat_utf8, limits=PlanningFeedbackSettings(),
        read_document=lambda _it, _b: bad_utf8, cache_root=tmp_path / "utf8", identity={},
    )
    assert res_utf8["status"] == "ACCEPTED"
    assert seen_utf8[1].repair_errors == ("unsupported_evidence_encoding",)

    # 4. Cumulative max_evidence_bytes exceeded -> additive_evidence_byte_bound
    res_tot, calls_tot = _run(
        tmp_path / "tot-bound", [need, final],
        limits=replace(PlanningFeedbackSettings(), max_evidence_bytes=2),
    )
    assert res_tot["status"] == "ACCEPTED"
    assert calls_tot[1].repair_errors == ("additive_evidence_byte_bound",)

    # 5. Request byte bound exceeded before call -> feedback_request_byte_bound
    res_req_bound, calls_req_bound = _run(
        tmp_path / "req-bound", [final],
        limits=replace(PlanningFeedbackSettings(), max_request_bytes=16),
    )
    assert res_req_bound["status"] == "BUDGET_EXCEEDED" and calls_req_bound == []
    assert res_req_bound["errors"] == ["feedback_request_byte_bound"]

    # 6. Post-call deadline -> internal_feedback_deadline
    # Engine init calls clock() once (0); pre-call remaining() calls clock() (1);
    # engine.call checks deadline before/after (2, 3); post-call check sees 301!
    post_times = iter([0, 1, 2, 3, 301, 301, 301])
    res_post = bounded_feedback(
        lambda *_a, **_kw: ModelResult(final), request, catalog=catalog,
        limits=PlanningFeedbackSettings(), read_document=lambda *_: b"",
        cache_root=tmp_path / "post-deadline", identity={}, clock=lambda: next(post_times),
    )
    assert res_post["status"] == "BUDGET_EXCEEDED"
    assert res_post["errors"] == ["internal_feedback_deadline"]


def test_internal_deadline_and_unexpected_model_bug_are_distinct(tmp_path):
    catalog, request, _, _ = _inputs()
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
    safe = model_safe({"environment": {"API_TOKEN": "private"}, "content": "URL=******host\n"})
    assert "private" not in json.dumps(safe) and "u:p@" not in json.dumps(safe)
    before = copy.deepcopy(catalog)
    evidence_catalog(catalog, [])
    assert catalog == before


def test_additive_inventory_is_usable_exact_and_bounded_before_the_first_call():
    catalog, request, _, _ = _inputs()
    before = copy.deepcopy(catalog)
    offered = feedback_request(request, catalog, PlanningFeedbackSettings())
    assert offered.summary["evidence_inventory"] == [{
        key: catalog["files"][2][key] for key in ("path", "sha256", "size_bytes")}]
    assert offered.summary["evidence_inventory_omitted"] == 0
    assert "native/extra.h" in offered.allowed_paths
    assert len(canonical_json(model_safe(asdict(offered)))) <= 131072
    assert catalog == before and "evidence_inventory" not in request.summary

    # Force 75% byte-cap trimming in feedback_request
    tiny_limits = replace(PlanningFeedbackSettings(), max_request_bytes=1800)
    many_cat = copy.deepcopy(catalog)
    for idx in range(30):
        many_cat["files"].append({"path": f"native/extra-{idx:03d}.h", "sha256": f"{idx:064x}"[-64:], "size_bytes": 10})
    trimmed = feedback_request(request, many_cat, tiny_limits)
    assert trimmed.summary["evidence_inventory_omitted"] > 0


@pytest.mark.parametrize("limit,accepted", [(16777216, False), (33554432, True)])
def test_catalog_reader_has_explicit_per_kind_bounds_without_losing_hashes(tmp_path, limit, accepted):
    payload = b'{"padding":"' + b"x" * 16777216 + b'"}'
    path = tmp_path / "bounded-catalog.json"
    path.write_bytes(payload)
    identity = {"path": path.name, "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest()}
    if accepted:
        assert len(read_artifact(tmp_path, identity, byte_limit=limit)["padding"]) == 16777216
        with pytest.raises(ValueError, match="identity changed"):
            read_artifact(tmp_path, {**identity, "sha256": "f" * 64}, byte_limit=limit)
        with pytest.raises(ValueError, match="identity changed"):
            read_artifact(tmp_path, {**identity, "size_bytes": len(payload) - 1}, byte_limit=limit)
    else:
        with pytest.raises(ValueError, match="byte bound"):
            read_artifact(tmp_path, identity, byte_limit=limit)
    with pytest.raises(ValueError, match="unsupported.*byte limit"):
        read_artifact(tmp_path, identity, byte_limit=33554433)


@pytest.mark.parametrize("action", ["need_evidence", "final"])
def test_proposal3_checked_in_schema_uses_only_local_resources(action):
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    directory = ROOT / "docs/schemas"
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
    monkeypatch.setattr(shared, "_ACTIVE", ContextVar("synthetic-shared", default=SimpleNamespace(
        run_root=tmp_path,
        actor={"run_id": "synthetic-run", "job_id": "job_target_analysis_plan", "attempt_id": "attempt_0001"},
    )))
    monkeypatch.setitem(inference.PROVIDERS, "offline-scripted", send)
    return inference.infer, controller


@pytest.mark.parametrize("kind", ["output", "timeout"])
def test_proposal3_transport_first_error_refuses_repair_before_raw_retention(
        tmp_path, monkeypatch, kind):
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
        bounded_feedback(
            infer, request, catalog=catalog, limits=PlanningFeedbackSettings(),
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
    secret = "synthetic-sensitive-provider-data"

    def send(request, *, timeout_seconds):
        if kind == "output":
            raise ModelOutputError(secret, raw_response=secret, rejected_output=secret) from ValueError(secret)
        raise TimeoutError(secret) from ValueError(secret)

    infer, _ = _transport(monkeypatch, tmp_path, send)
    monkeypatch.setattr(safety, "_ACTIVE", ContextVar("ordinary-repair-mode", default=None))
    _, request, _, _ = _inputs()
    with pytest.raises(ModelOutputError if kind == "output" else TimeoutError) as caught:
        infer(request, timeout_seconds=30)
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert secret not in str(caught.value)
    assert getattr(caught.value, "raw_response", None) is None
    assert getattr(caught.value, "rejected_output", None) is None


def test_proposal3_transport_unexpected_failure_still_latches_before_any_repair(tmp_path, monkeypatch):
    secret = "synthetic-sensitive-provider-data"
    calls = []

    def send(request, *, timeout_seconds):
        calls.append(request)
        raise RuntimeError(secret) from ValueError(secret)

    infer, controller = _transport(monkeypatch, tmp_path, send)
    catalog, request, _, _ = _inputs()
    with pytest.raises(safety.ReviewStopped) as caught:
        bounded_feedback(
            infer, request, catalog=catalog, limits=PlanningFeedbackSettings(),
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
        bounded_feedback(
            infer, request, catalog=catalog, limits=PlanningFeedbackSettings(),
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
    before = copy.deepcopy(catalog)
    need = {"schema": PROPOSAL_SCHEMA, "action": "need_evidence", "requests": [{
        "path": document["path"], "sha256": document["sha256"], "reason": "exact synthetic batch evidence"}]}
    calls = []
    reads = []

    def read_document(item, bound):
        assert item == document and bound == PlanningFeedbackSettings().max_document_bytes
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

    result = bounded_feedback(
        infer, request, catalog=catalog, limits=PlanningFeedbackSettings(),
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
        cached = json.loads(contents)
        cached["documents"] = [{"path": document["path"], "sha256": document["sha256"], "content": text}]
        cache.write_text(json.dumps(cached), encoding="utf-8")
        with pytest.raises(ValueError, match="complete validated final"):
            bounded_feedback(
                lambda *_a, **_kw: pytest.fail("corrupt cache must not call a model"),
                request, catalog=catalog, limits=PlanningFeedbackSettings(),
                read_document=lambda *_: pytest.fail("corrupt cache must not read evidence"),
                cache_root=tmp_path / "cache", identity={})
    else:
        cached = bounded_feedback(
            lambda *_a, **_kw: pytest.fail("complete cache should replay"),
            request, catalog=catalog, limits=PlanningFeedbackSettings(),
            read_document=lambda *_: pytest.fail("complete cache must retain exact bytes"),
            cache_root=tmp_path / "cache", identity={})
        assert cached["cache_hit"] is True and cached["documents"] == result["documents"]


def test_native_planning_favors_image_clang_over_target_readme_gcc_claims(tmp_path):
    from appsec_review.guidance.compose import pin_bundle, render_prompt, verify_bundle
    from appsec_review.jobs.build_discovery import descriptor_package, validate_build_recipe
    from tests.unit.job_target_analysis_plan.test_partitioning import _resolve

    texts = {
        "CMakeLists.txt": "cmake_minimum_required(VERSION 3.20)\nproject(smoke CXX)\nadd_executable(app src/main.cpp)\n",
        "README.md": "Build notes: expected to succeed in gcc 13.3 with CMake 3.28.\n",
        "src/main.cpp": "int main() { return 0; }\n",
    }
    target = tmp_path / "target"
    files = []
    for rel, content in sorted(texts.items()):
        dest = target / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        files.append({"path": rel, "sha256": hashlib.sha256(content.encode()).hexdigest(),
                      "size_bytes": len(content.encode())})
    unit = discover_build_units(files)[0]
    unit["descriptor_package"] = descriptor_package(target, unit, files)
    assert any(doc["path"] == "README.md" for doc in unit["descriptor_package"]["documents"])
    catalog, _, final, _ = _inputs()
    catalog = {**catalog, "files": files, "build_units": [unit]}
    base_recipe = {
        "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
        "image_profile": "native", "source_dir": ".", "build_dir": "build",
        "system_packages": [], "environment": {"CC": "gcc", "CXX": "g++"},
        "dependency_files": ["CMakeLists.txt"],
        "configure_commands": [[
            "cmake", "-S", ".", "-B", "build",
            "-DCMAKE_C_COMPILER=gcc", "-DCMAKE_CXX_COMPILER=g++",
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        ]],
        "build_commands": [["cmake", "--build", "build"]],
        "expected_outputs": ["build"], "network_required": False,
        "reason": "CMake build inferred from CMakeLists.txt",
    }
    planning_root = tmp_path / "planning"
    calls = []

    def infer_plan(request, **_kwargs):
        calls.append(request)
        digest = request.summary["guidance_bundle_sha256"]
        bundle = json.loads((planning_root / "data/guidance" / digest / "bundle.json").read_bytes())
        assert bundle["role_id"] == "build_engineer_native"
        assert verify_bundle(bundle) == digest
        assert render_prompt(bundle) == request.guidance
        assert pin_bundle(planning_root, bundle)["bundle_sha256"] == digest
        assert "CC=clang" in request.guidance and "CXX=clang++" in request.guidance
        policy = request.summary["build_units"][0]["command_policy"]
        assert policy["image_environment"] == {"CC": "clang", "CXX": "clang++"}
        assert {"gcc", "g++"}.isdisjoint(policy["allowed_executables"])
        if len(calls) == 1:
            return ModelResult({**final, "build_recipes": [{
                **base_recipe, "environment": {}, "configure_commands": [],
                "build_commands": [["g++", "src/main.cpp", "-o", "build/app"]],
            }]})
        assert any("not allowlisted for native" in error for error in request.repair_errors)
        return ModelResult({**final, "build_recipes": [base_recipe]})

    planned, _ = _resolve(planning_root, catalog, custom_infer=infer_plan,
                           target_root=target, max_input_tokens=32000)
    assert planned["model_calls"] == 2
    assert planned["gaps"] == []
    action = planned["plan"]["build_topology"]["build_actions"][0]
    accepted = action["recipe"]
    assert accepted["environment"] == {}
    assert accepted["configure_commands"] == [[
        "cmake", "-S", ".", "-B", "build", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
    ]]
    assert validate_build_recipe(accepted, unit) == []
    refinement = planned["plan"]["build_topology"]["planning_refinement"]
    assert refinement["units"][0]["blockers"] == []
