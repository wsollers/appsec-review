"""A1: independently frozen cross-family expected AND forbidden outcomes.

AUTHORED - NOT RUN. R1/R2/R3/R5/R8/R9/R10 and C2. These finite public cases
are not the 295-unit replay and do not consume private first-use/reserve labels.
Captured snippets are distinct derived documents, never original-source bytes.
"""

from __future__ import annotations

import copy
import hashlib
import json

import pytest

from appsec_review.jobs.build_topology import compile_build_topology, refine_build_topology
from tests.integration.test_build_topology_catalog_planner_publication import (
    fixture_json, frozen_synthetic, offline_reporting, run_pipeline,
)
from tests.integration.test_build_topology_consumers_recovery import compiler_profile, native_action


def source_unit(texts, *, system, family, commands, uid="independent-public"):
    unit = native_action()
    documents = [{"path": path, "content": text, "size_bytes": len(text.encode()),
                  "sha256": hashlib.sha256(text.encode()).hexdigest()} for path, text in texts.items()]
    unit.update(build_unit_id=uid, family=family, build_system=system,
                markers=[{key: documents[0][key] for key in ("path", "sha256", "size_bytes")}],
                descriptor_package={"documents": documents, "bounds": {}, "gaps": []})
    unit["recipe"].update(build_unit_id=uid, image_profile=family,
                          dependency_files=list(texts), build_commands=commands)
    return unit


def selection(system, *, os="windows", isa="x86_64"):
    return {
        "schema": "appsec-review/build-selection-policy/1", "policy_id": "independent-public/1",
        "ambiguity_policy": "block", "rules": [{
            "selectors": {"build_system": system}, "axes": {"os": os, "isa": isa},
            "provenance": "explicit synthetic acceptance policy, not source metadata",
        }],
    }


@pytest.mark.parametrize("filename,required,forbidden", [
    ("App.csproj", None, "managed_x86_incompatible"),
    ("X86.csproj", "managed_x86_incompatible", "managed_prefer32bit_incompatible"),
    ("Prefer.csproj", "managed_prefer32bit_incompatible", "managed_x86_incompatible"),
    ("Unselected.csproj", None, "managed_prefer32bit_incompatible"),
    ("Unknown.csproj", "managed_prefer32bit_applicability_unknown", "managed_prefer32bit_incompatible"),
])
def test_frozen_managed_cases_do_not_turn_32bit_incompatibility_into_native_compilation(
        filename, required, forbidden):
    text = frozen_synthetic("synthetic/managed/" + filename)
    unit = source_unit({filename: text}, system="dotnet", family="dotnet",
                       commands=[["dotnet", "build", filename, "--configuration", "Release"]])
    graph = compile_build_topology([unit], source_fingerprint="frozen-public-managed")
    bound, = refine_build_topology(graph, [unit], policy=selection("dotnet"))["units"]
    assert {operation["kind"] for operation in bound["operations"]} == {"managed_compile"}
    assert bound["enforcement"] == []
    assert forbidden not in bound["blockers"]
    if required:
        assert required in bound["blockers"]
    else:
        assert not any(reason.startswith("managed_") for reason in bound["blockers"])
    assert bound["selection"]["required_axes"]["hardware_generation"] is None


@pytest.mark.parametrize("suffix,plugin,sdk_values,arm32", [
    ("ShelterAndroidProj/app/build.gradle", "application", ("29", "16", "29"), False),
    ("android_as/app/build.gradle", "library", ("30", "23", "30"), False),
    ("ghome_google_android_as/app/build.gradle", "library", ("34", "23", "34"), True),
])
def test_captured_android_declarations_preserve_eligibility_without_selecting_native_payload(
        suffix, plugin, sdk_values, arm32):
    candidates = [document for document in fixture_json("source-documents.json")["documents"]
                  if document["path"].endswith(suffix)]
    assert len(candidates) == 1, "the admitted public source pointer must resolve uniquely"
    captured, = candidates
    excerpt = captured["excerpts"][0]
    assert hashlib.sha256(excerpt["content"].encode()).hexdigest() == excerpt["derived_utf8_sha256"]
    # Padding preserves resolving line numbers, while the new digest labels derived input honestly.
    text = "\n" * (excerpt["span"][0] - 1) + excerpt["content"]
    unit = source_unit({"app/build.gradle": text}, system="gradle", family="java",
                       commands=[["gradle", ":app:assembleRelease"]])
    unit["recipe"] = None
    graph = compile_build_topology([unit], source_fingerprint="bounded-public-android-excerpt")
    facts = graph["facts"]
    assert {f["value"] for f in facts if f["predicate"] == "android:plugin"} == {plugin}
    assert tuple(next(f["value"] for f in facts if f["predicate"] == "android:" + key)
                 for key in ("compileSdk", "minSdk", "targetSdk")) == sdk_values
    policy = {
        "schema": "appsec-review/build-selection-policy/1", "policy_id": "public-android-explicit/1",
        "ambiguity_policy": "block",
        "rules": [{"selectors": {"declared_platform": "android"}, "axes": {"os": "android"},
                   "provenance": "synthetic policy; no physical generation supplied"}],
    }
    bound, = refine_build_topology(graph, [unit], policy=policy)["units"]
    assert {op["kind"] for op in bound["operations"]} == {"managed_compile", "bytecode_transform"}
    assert not bound["enforcement"] and "recipe_missing" in bound["blockers"]
    assert bound["selection"]["required_axes"]["hardware_generation"] is None
    if arm32:
        abi = next(f["value"] for f in facts if f["predicate"] == "android:abiFilters")
        assert "armeabi-v7a" in abi and "arm64-v8a" in abi
        assert bound["selection"]["required_axes"]["isa"] is None
    assert not any(f["predicate"] == "android:external_native" for f in facts)


@pytest.mark.parametrize("system,path,command,expected", [
    ("maven", "synthetic/maven/pom.xml", ["mvn", "package"], "managed_compile"),
    ("node", "synthetic/node/package.json", ["npm", "pack"], "package"),
])
def test_frozen_nonmobile_package_or_managed_operations_are_not_native(system, path, command, expected):
    name = path.rsplit("/", 1)[1]
    unit = source_unit({name: frozen_synthetic(path)}, system=system,
                       family="java" if system == "maven" else "node", commands=[command])
    graph = compile_build_topology([unit], source_fingerprint="frozen-public-nonmobile")
    bound, = refine_build_topology(graph, [unit], policy=selection(system, os="linux"))["units"]
    assert {operation["kind"] for operation in bound["operations"]} == {expected}
    assert bound["enforcement"] == []
    assert "unenforced_native_target" not in bound["blockers"]


def test_go386_disagrees_with_explicit_x64_policy_and_cannot_borrow_host_default():
    unit = source_unit({
        "go.mod": frozen_synthetic("synthetic/go/go.mod"),
        "native.go": frozen_synthetic("synthetic/go/native.go"),
    }, system="go", family="go", commands=[["go", "build", "."]])
    unit["recipe"]["environment"] = {"GOOS": "linux", "GOARCH": "386", "CGO_ENABLED": "0"}
    graph = compile_build_topology([unit], source_fingerprint="frozen-public-go")
    bound, = refine_build_topology(graph, [unit], policy=selection("go", os="linux"))["units"]
    assert "native_compile" in {operation["kind"] for operation in bound["operations"]}
    assert bound["enforcement"]
    assert "unenforced_native_target" in bound["blockers"]
    assert all(proof["status"] != "proven" for proof in bound["enforcement"])
    assert bound["selection"]["required_axes"]["isa"] == "x86_64"
    assert bound["selection"]["required_axes"]["hardware_generation"] is None


@pytest.mark.parametrize("hook,command,invokes_native", [
    ("build", ["npm", "pack"], False),
    ("build", ["npm", "run", "build"], True),
    ("prepack", ["npm", "pack"], True),
    ("prepare", ["npm", "pack"], True),
])
def test_node_gyp_requires_effective_native_operation_including_invoked_lifecycle_hooks(
        hook, command, invokes_native):
    texts = {
        "package.json": frozen_synthetic("synthetic/node/package.json"),
        "binding.gyp": frozen_synthetic("synthetic/node/binding.gyp"),
    }
    manifest = json.loads(texts["package.json"])
    manifest["scripts"][hook] = "node-gyp rebuild"
    texts["package.json"] = json.dumps(manifest) + "\n"
    unit = source_unit(texts, system="node", family="node", commands=[command])
    graph = compile_build_topology([unit], source_fingerprint="public-node-lifecycle-control")
    bound, = refine_build_topology(
        graph, [unit], policy=selection("node", os="linux"))["units"]
    if invokes_native:
        assert "native_compile" in {op["kind"] for op in bound["operations"]}
        assert bound["enforcement"] and "unenforced_native_target" in bound["blockers"]
    else:
        assert not bound["enforcement"]
        assert {op["kind"] for op in bound["operations"]} == {"package"}
    discovery = copy.deepcopy(unit)
    discovery["recipe"] = None
    assert compile_build_topology([discovery], source_fingerprint="public-node-lifecycle-control") == graph


@pytest.mark.parametrize("extension", [".vcxproj", ".csproj"])
def test_uncaptured_solution_members_remain_unknown_not_managed_exemptions(extension):
    guid = "{11111111-1111-1111-1111-111111111111}"
    sln = (
        f'Project("{{22222222-2222-2222-2222-222222222222}}") = "member", "member{extension}", "{guid}"\n'
        f"EndProject\nGlobal\n {guid}.Release|x64.ActiveCfg = Debug|x64\n"
        f" {guid}.Release|x64.Build.0 = Debug|x64\nEndGlobal\n"
    )
    unit = source_unit({"selected.sln": sln}, system="dotnet", family="dotnet",
                       commands=[["dotnet", "build", "selected.sln",
                                  "--configuration", "Release", "/p:Platform=x64"]])
    graph = compile_build_topology([unit], source_fingerprint="synthetic-uncaptured-member")
    bound, = refine_build_topology(graph, [unit], policy=selection("dotnet"))["units"]
    assert {op["kind"] for op in bound["operations"]} == {"unknown"}
    assert {"selected_member_uncaptured", "operation_unknown"} <= set(bound["blockers"])
    assert any(f["predicate"] == "solution_mapping" and f["value"]["project"] == "Debug|x64"
               for f in graph["facts"])


@pytest.mark.parametrize("mapped,expected_status", [
    ("Debug|x64", "proven"), ("Release|Win32", "incompatible"),
])
def test_synthetic_captured_native_solution_uses_actual_mapping_and_keeps_dll_import_roles(
        mapped, expected_status):
    guid = "{11111111-1111-1111-1111-111111111111}"
    sln = (
        f'Project("{{22222222-2222-2222-2222-222222222222}}") = "member", "member.vcxproj", "{guid}"\n'
        f"EndProject\nGlobal\n {guid}.Release|x64.ActiveCfg = {mapped}\n"
        f" {guid}.Release|x64.Build.0 = {mapped}\nEndGlobal\n"
    )
    project = (
        "<Project><PropertyGroup><ConfigurationType>DynamicLibrary</ConfigurationType>"
        "<OutputFile>out/shared.dll</OutputFile><ImportLibrary>out/shared.lib</ImportLibrary>"
        "</PropertyGroup></Project>\n"
    )
    unit = source_unit({"selected.sln": sln, "member.vcxproj": project},
                       system="dotnet", family="dotnet",
                       commands=[["dotnet", "build", "selected.sln",
                                  "--configuration", "Release", "/p:Platform=x64"]])
    profile = {**compiler_profile(), "windows_capability": True,
               "driver_semantics": "msbuild-mapping/1",
               "target_axes": {"os": "windows", "isa": "x86_64", "abi": "msvc"}}
    graph = compile_build_topology([unit], source_fingerprint="synthetic-windows-map", profiles=profile)
    bound, = refine_build_topology(
        graph, [unit], policy=selection("dotnet"), profiles=profile)["units"]
    assert {op["kind"] for op in bound["operations"]} == {"native_compile", "native_link"}
    assert all(proof["status"] == expected_status for proof in bound["enforcement"])
    assert bound["enforcement"]
    assert bound["operations"][0]["selected_members"][0]["configuration"] == mapped.split("|")[0]
    assert any(d["role"] == "import_library" and d["declared_path"] == "out/shared.lib"
               for d in graph["declarations"])
    assert not any(d["role"] == "import_library" and d["declared_path"] == "out/shared.dll"
                   for d in graph["declarations"])
    if expected_status == "incompatible":
        assert "unenforced_native_target" in bound["blockers"]
    assert bound["selection"]["required_axes"]["hardware_generation"] is None


@pytest.mark.parametrize("platform,device", [("ios", "device"), ("ios", "simulator")])
def test_managed_mobile_rid_and_device_policy_are_not_native_or_hardware_generation_proof(platform, device):
    text = (
        "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup>"
        f"<TargetFramework>net8.0-{platform}</TargetFramework><OutputType>Library</OutputType>"
        "<RuntimeIdentifier>ios-arm64</RuntimeIdentifier><PublishAot>false</PublishAot>"
        "</PropertyGroup></Project>\n"
    )
    unit = source_unit({"Mobile.csproj": text}, system="dotnet", family="dotnet",
                       commands=[["dotnet", "build", "Mobile.csproj"]])
    policy = {
        "schema": "appsec-review/build-selection-policy/1", "policy_id": "explicit-mobile-device-control/1",
        "ambiguity_policy": "block", "rules": [{
            "selectors": {"declared_platform": platform},
            "axes": {"os": platform, "isa": "arm64", "device_kind": device},
            "provenance": "synthetic requested device policy; not captured hardware metadata",
        }],
    }
    graph = compile_build_topology([unit], source_fingerprint="synthetic-ios-rid")
    bound, = refine_build_topology(graph, [unit], policy=policy)["units"]
    assert {op["kind"] for op in bound["operations"]} == {"managed_compile"}
    assert bound["enforcement"] == []
    assert bound["selection"]["required_axes"]["device_kind"] == device
    assert bound["selection"]["required_axes"]["hardware_generation"] is None
    assert all(op["kind"] != "native_aot" for op in bound["operations"])


def test_android_module_reference_survives_real_publication_without_self_execution_edge(tmp_path):
    files = {
        "settings.gradle": "include ':app'\ninclude ':depsAAR:GHOME_SDK'\n",
        "app/build.gradle": (
            "apply plugin: 'com.android.library'\n"
            "dependencies { implementation project(':depsAAR:GHOME_SDK') }\n"
        ),
        "depsAAR/GHOME_SDK/build.gradle": (
            'configurations.maybeCreate("default")\n'
            'artifacts.add("default",file("opaque.aar"))\n'
        ),
    }
    _config, _target, _runner, _result, _root, plan = run_pipeline(tmp_path, files)
    graph = plan["build_topology"]["executable_graph"]
    assert any(f["predicate"] == "gradle:project" and f["value"] == ":depsAAR:GHOME_SDK"
               for f in graph["facts"])
    assert any(relation["required"] for relation in graph["relations"])
    assert all(e["producer_build_unit_id"] != e["consumer_build_unit_id"] for e in graph["edges"])
    assert all(op["kind"] != "native_compile"
               for unit in plan["build_topology"]["planning_refinement"]["units"]
               for op in unit["operations"])
