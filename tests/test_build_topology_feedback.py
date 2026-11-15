from __future__ import annotations

import copy
import hashlib

import pytest

from appsec_review.inference import ModelRequest
from appsec_review.jobs.build_discovery import discover_build_units
from appsec_review.jobs.build_topology import (
    compile_build_topology,
    refine_build_topology,
    topology_evidence_bundle,
)
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA


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
