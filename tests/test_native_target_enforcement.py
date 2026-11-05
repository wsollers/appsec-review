from __future__ import annotations

import copy
import hashlib
import json
import struct
import pytest

from appsec_review.jobs.build_topology import (
    compile_build_topology, refine_build_topology, refinement_unit, validate_refinement,
)
from appsec_review.storage import canonical_json


WINDOWS_SELECTION = {
    "schema": "appsec-review/build-selection-policy/1",
    "policy_id": "synthetic-explicit-windows/1",
    "ambiguity_policy": "block",
    "rules": [{"selectors": {"build_system": "dotnet"},
               "axes": {"os": "windows", "isa": "x86_64"},
               "provenance": "explicitly-synthetic-unit-local"}],
}


def _native(*, commands=None, extra_documents=None):
    texts = {"CMakeLists.txt": "project(control)\nadd_executable(control main.c)\n",
             "main.c": "int main(void) { return 0; }\n", **(extra_documents or {})}
    documents = [{"path": path, "sha256": hashlib.sha256(text.encode()).hexdigest(),
                  "content": text, "size_bytes": len(text.encode())} for path, text in texts.items()]
    unit = {"build_unit_id": "native-control", "root": ".", "family": "native",
            "build_system": "cmake", "markers": [
                {key: documents[0][key] for key in ("path", "sha256", "size_bytes")}],
            "descriptor_package": {"documents": documents, "bounds": {}, "gaps": []},
            "build_variant": {"configuration": "Release", "target_arch": None,
                              "execution_role": "target", "linkage": None, "toolchain": None, "abi": None}}
    unit["recipe"] = {"schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                      "image_profile": "native", "source_dir": ".", "build_dir": "build",
                      "system_packages": [], "environment": {}, "dependency_files": ["CMakeLists.txt", "main.c"],
                      "configure_commands": [],
                      "build_commands": commands or [["clang", "--target=x86_64-unknown-linux-gnu", "-c", "main.c",
                                                       "-o", "build/main.o"]],
                      "expected_outputs": ["build/main.o"], "network_required": False,
                      "reason": "explicitly synthetic inline control"}
    return unit


def _profile():
    return {"schema": "appsec-review/static-compiler-profile/1", "executable": "clang",
            "driver_semantics": "clang-target/1", "compiler_sha256": "b" * 64,
            "image_digest": "sha256:" + "a" * 64, "wrapper_closure": [],
            "target_axes": {"os": "linux", "isa": "x86_64", "abi": "gnu"},
            "provenance": {"origin": "explicitly-synthetic-unit-local", "revision": "control/1"}}


def _go(environment):
    unit = _native()
    text = "module synthetic.invalid/control\n\ngo 1.23\n"
    document = {"path": "go.mod", "content": text,
                "sha256": hashlib.sha256(text.encode()).hexdigest(), "size_bytes": len(text.encode())}
    unit.update(build_unit_id="go-control", family="go", build_system="go",
                markers=[{key: document[key] for key in ("path", "sha256", "size_bytes")}],
                descriptor_package={"documents": [document], "bounds": {}, "gaps": []})
    unit["recipe"].update(build_unit_id="go-control", image_profile="go",
                          environment=environment, dependency_files=["go.mod"],
                          build_commands=[["go", "build", "-o", "build/control", "."]],
                          expected_outputs=["build/control"])
    return unit


def test_null_recipe_planning_is_unknown_without_execution_authority():
    unit = _native()
    unit["recipe"] = None
    original = copy.deepcopy(unit)
    graph = compile_build_topology([unit], source_fingerprint="synthetic-source")
    refinement = refine_build_topology(graph, [unit])
    proof = refinement["units"][0]["enforcement"][0]
    assert proof["status"] == "unknown"
    assert proof["recipe_digest"] is None and proof["operation_binding"] is None
    assert "recipe_missing" in proof["unresolved_inputs"]
    assert proof["source_evidence_refs"]
    assert unit == original
    validate_refinement(graph, refinement)


@pytest.mark.parametrize("argv,scripts,native,unknown", [
    (["npm", "pack"], {"build": "node-gyp rebuild"}, False, False),
    (["npm", "run", "build"], {"build": "node-gyp rebuild"}, True, False),
    (["npm", "run", "build"], {"build": "tsc -p tsconfig.json"}, False, False),
    (["npm", "pack"], {"prepack": "node-gyp rebuild"}, True, False),
    (["npm", "pack"], {"prepare": "node-gyp build"}, True, False),
    (["npm", "pack"], {"postbuild": "node-gyp rebuild"}, False, False),
    (["npm", "pack", "--ignore-scripts"], {"prepack": "node-gyp rebuild"}, False, False),
    (["npm", "run", "build"], {"prebuild": "node-gyp rebuild", "build": "tsc"}, True, False),
    (["npm", "ci", "--ignore-scripts"], {}, False, False),
    (["npm", "ci"], {}, True, False),
    (["node-gyp", "configure"], {}, False, True),
    (["node-gyp", "build"], {}, True, False),
    (["npm", "run", "missing"], {"build": "node-gyp rebuild"}, False, True),
    (["npm", "run", "build"], {"build": "node build.js"}, False, True),
    (["npm", "run", "build"], {"build": "npm run build"}, False, True),
])
def test_node_requested_native_stage_comes_from_applicable_captured_lifecycle_not_marker_or_command_name(
        argv, scripts, native, unknown):
    text = json.dumps({"name": "synthetic-node-control", "scripts": scripts}, indent=2) + "\n"
    documents = [{"path": path, "content": content,
                  "sha256": hashlib.sha256(content.encode()).hexdigest(), "size_bytes": len(content.encode())}
                 for path, content in {"package.json": text, "binding.gyp": '{"targets": []}\n'}.items()]
    unit = _native()
    unit.update(family="node", build_system="node", markers=[{
        key: documents[0][key] for key in ("path", "sha256", "size_bytes")}],
        descriptor_package={"documents": documents, "bounds": {}, "gaps": []})
    unit["recipe"].update(image_profile="node", dependency_files=["package.json", "binding.gyp"],
                          build_commands=[argv])
    before = copy.deepcopy(unit)
    graph = compile_build_topology([unit], source_fingerprint="synthetic-node-lifecycle")
    bound = refine_build_topology(graph, [unit])["units"][0]
    kinds = {operation["kind"] for operation in bound["operations"]}
    assert ("native_compile" in kinds) is native
    assert ("unknown" in kinds) is unknown
    assert "package" in kinds
    assert bool(bound["enforcement"]) is native
    if native:
        assert all(proof["status"] == "unknown" for proof in bound["enforcement"])
        assert "unenforced_native_target" in bound["blockers"]
    if unknown:
        assert "operation_unknown" in bound["blockers"]
    script_facts = [fact for fact in graph["facts"] if fact["predicate"] == "node:script"]
    assert len(script_facts) == len(scripts)
    for fact in script_facts:
        assert fact["path"] == "package.json" and fact["sha256"] == documents[0]["sha256"]
        assert json.dumps(fact["value"]["name"]) in text.splitlines()[fact["span"][0] - 1]
        assert fact["fact_id"] in {binding["fact_id"] for binding in graph["bindings"]}
    assert unit == before


def test_ambiguous_node_manifest_cannot_hide_a_native_lifecycle():
    unit = _native(extra_documents={
        "package.json": '{"scripts":{"prepare":"node-gyp rebuild"},"scripts":{}}\n',
        "binding.gyp": '{"targets":[]}\n'})
    document = next(item for item in unit["descriptor_package"]["documents"] if item["path"] == "package.json")
    unit.update(family="node", build_system="node", markers=[{
        key: document[key] for key in ("path", "sha256", "size_bytes")}])
    unit["recipe"].update(image_profile="node", dependency_files=["package.json", "binding.gyp"],
                          build_commands=[["npm", "pack"]])
    graph = compile_build_topology([unit], source_fingerprint="synthetic-ambiguous-node-manifest")
    bound = refine_build_topology(graph, [unit])["units"][0]
    assert "node_manifest_unresolved" in bound["blockers"]
    assert "operation_unknown" in bound["blockers"]
    assert any(fact["predicate"] == "coverage_gap" and fact["value"] == "node_manifest_unresolved"
               for fact in graph["facts"])


@pytest.mark.parametrize("captured", [True, False])
def test_direct_compiler_closes_discovered_native_components_only_from_real_accepted_source(captured):
    unit = _native()
    document = next(item for item in unit["descriptor_package"]["documents"] if item["path"] == "main.c")
    unit["native_components"] = [{key: document[key] for key in ("path", "sha256", "size_bytes")}]
    if not captured:
        unit["descriptor_package"]["documents"].remove(document)
    graph = compile_build_topology([unit], source_fingerprint="synthetic-component-direct-compiler")
    bound = refine_build_topology(graph, [unit], profiles=_profile())["units"][0]
    if captured:
        assert bound["blockers"] == []
        assert all(proof["status"] == "proven" for proof in bound["enforcement"])
    else:
        assert "unenforced_native_target" in bound["blockers"]
        assert all("compiler_source_closure_unknown" in proof["unresolved_inputs"] for proof in bound["enforcement"])


def test_complete_explicit_target_has_recipe_bound_sidecar_not_recipe_bound_graph():
    first = _native()
    second = copy.deepcopy(first)
    second["recipe"]["build_commands"][0].append("-g")
    profile = _profile()
    graph = compile_build_topology([first], source_fingerprint="synthetic-source", profiles=profile)
    reverse = compile_build_topology([second], source_fingerprint="synthetic-source", profiles=profile,
                                    hints=[{"invented_edge": "ignored"}],
                                    component_relationships=[{"kind": "depends_on", "component_id": "invented"}])
    assert canonical_json(graph) == canonical_json(reverse)
    one = refine_build_topology(graph, [first], profiles=profile)
    two = refine_build_topology(graph, [second], profiles=profile)
    proof = one["units"][0]["enforcement"][0]
    assert proof["proof_kind"] == "compiler_explicit_target" and proof["status"] == "proven"
    assert proof["proven_axes"]["os"] == "linux" and proof["proven_axes"]["isa"] == "x86_64"
    assert one["refinement_id"] != two["refinement_id"]
    assert one["units"][0]["enforcement"][0]["enforcement_id"] != two["units"][0]["enforcement"][0]["enforcement_id"]
    assert all(node["recipe_revision"] is None for node in graph["nodes"])
    assert refinement_unit(graph, one, first["build_unit_id"], first["recipe"])["recipe_digest"]


def test_m64_and_unverified_compiler_name_do_not_prove_linux():
    unit = _native(commands=[["clang", "-m64", "-c", "main.c"]])
    graph = compile_build_topology([unit], source_fingerprint="synthetic-source")
    proof = refine_build_topology(graph, [unit])["units"][0]["enforcement"][0]
    assert proof["status"] == "unknown"
    assert "compiler_target_unknown" in proof["unresolved_inputs"]
    assert "unenforced_axis:os" in proof["unresolved_inputs"]
    assert proof["proven_axes"].get("os") is None


def test_replaced_m32_recipe_is_incompatible_without_changing_accepted_graph():
    unit = _native()
    profile = _profile()
    graph = compile_build_topology([unit], source_fingerprint="synthetic-source", profiles=profile)
    sealed = canonical_json(graph)
    unit["recipe"]["build_commands"][0].append("-m32")
    refinement = refine_build_topology(graph, [unit], profiles=profile)
    assert all(proof["status"] == "incompatible" for proof in refinement["units"][0]["enforcement"])
    assert "unenforced_native_target" in refinement["units"][0]["blockers"]
    assert canonical_json(graph) == sealed


def test_missing_effective_include_taints_even_an_explicit_target():
    unit = _native(extra_documents={"main.c": '#include "missing-target.h"\nint main(void) { return 0; }\n'})
    profile = _profile()
    graph = compile_build_topology([unit], source_fingerprint="synthetic-source", profiles=profile)
    proof = refine_build_topology(graph, [unit], profiles=profile)["units"][0]["enforcement"][0]
    assert proof["status"] == "unknown"
    assert "effective_import_unknown" in proof["unresolved_inputs"]


def _solution(extension, properties, *, mapped="Debug|x64"):
    guid = "{11111111-1111-1111-1111-111111111111}"
    texts = {
        "selected.sln": f'''Project("{{22222222-2222-2222-2222-222222222222}}") = "selected", "selected{extension}", "{guid}"
EndProject
Global
 {guid}.Release|x64.ActiveCfg = {mapped}
 {guid}.Release|x64.Build.0 = {mapped}
EndGlobal
''',
        "selected" + extension: "<Project><PropertyGroup>" + properties + "</PropertyGroup></Project>\n",
    }
    documents = [{"path": path, "sha256": hashlib.sha256(text.encode()).hexdigest(),
                  "content": text, "size_bytes": len(text.encode())} for path, text in texts.items()]
    unit = _native()
    unit.update(family="dotnet", build_system="dotnet", markers=[{
        key: documents[0][key] for key in ("path", "sha256", "size_bytes")}],
        descriptor_package={"documents": documents, "bounds": {}, "gaps": []})
    unit["recipe"].update(image_profile="dotnet", dependency_files=list(texts),
                          build_commands=[["dotnet", "build", "selected.sln", "--configuration", "Release",
                                           "/p:Platform=x64"]])
    return unit


def test_release_solution_can_select_a_captured_debug_x64_native_member():
    unit = _solution(".vcxproj", "<ConfigurationType>Application</ConfigurationType>")
    profile = {**_profile(), "windows_capability": True, "driver_semantics": "msbuild-mapping/1",
               "target_axes": {"os": "windows", "isa": "x86_64", "abi": "msvc"}}
    graph = compile_build_topology([unit], source_fingerprint="synthetic-solution", profiles=profile)
    refined = refine_build_topology(graph, [unit], profiles=profile, policy=WINDOWS_SELECTION)
    operations = refined["units"][0]["operations"]
    assert {operation["kind"] for operation in operations} == {"native_compile", "native_link"}
    assert operations[0]["selected_members"][0]["configuration"] == "Debug"
    assert all(proof["status"] == "proven" for proof in refined["units"][0]["enforcement"])


def test_uncaptured_selected_member_is_unknown_not_a_managed_solution_exemption():
    unit = _solution(".vcxproj", "")
    unit["descriptor_package"]["documents"] = unit["descriptor_package"]["documents"][:1]
    graph = compile_build_topology([unit], source_fingerprint="synthetic-solution")
    bound = refine_build_topology(graph, [unit], policy=WINDOWS_SELECTION)["units"][0]
    assert {operation["kind"] for operation in bound["operations"]} == {"unknown"}
    assert "selected_member_uncaptured" in bound["blockers"]
    assert "operation_unknown" in bound["blockers"]


@pytest.mark.parametrize("override,reason", [
    ("/p:PlatformTarget=x86", "managed_x86_incompatible"),
    ("/p:Prefer32Bit=true", "managed_prefer32bit_incompatible"),
])
def test_managed_32bit_overrides_are_blocked_without_misclassifying_native(override, reason):
    unit = _solution(".csproj", "<OutputType>Exe</OutputType><PlatformTarget>AnyCPU</PlatformTarget>"
                     "<TargetFrameworkVersion>v4.8</TargetFrameworkVersion>")
    unit["recipe"]["build_commands"][0].append(override)
    graph = compile_build_topology([unit], source_fingerprint="synthetic-managed")
    bound = refine_build_topology(graph, [unit], policy=WINDOWS_SELECTION)["units"][0]
    assert {operation["kind"] for operation in bound["operations"]} == {"managed_compile"}
    assert bound["enforcement"] == []
    assert reason in bound["blockers"]


def test_unknown_additional_native_options_cannot_borrow_selected_x64_mapping():
    unit = _solution(".vcxproj", "<AdditionalOptions>/MACHINE:X86</AdditionalOptions>")
    profile = {**_profile(), "windows_capability": True, "driver_semantics": "msbuild-mapping/1",
               "target_axes": {"os": "windows", "isa": "x86_64", "abi": "msvc"}}
    graph = compile_build_topology([unit], source_fingerprint="synthetic-solution", profiles=profile)
    bound = refine_build_topology(graph, [unit], profiles=profile, policy=WINDOWS_SELECTION)["units"][0]
    assert all(proof["status"] == "unknown" for proof in bound["enforcement"])
    assert all("msbuild_effective_option_closure_unknown" in proof["unresolved_inputs"]
               for proof in bound["enforcement"])


def test_nested_false_condition_does_not_activate_an_unresolved_import():
    unit = _solution(".vcxproj", "<ConfigurationType>Application</ConfigurationType>")
    document = unit["descriptor_package"]["documents"][1]
    document["content"] = '''<Project>
<PropertyGroup Condition="'$(Configuration)' == 'Debug'">
 <TargetName Condition="'$(Platform)' == 'x64'">selected</TargetName>
</PropertyGroup>
<Import Condition="'$(Configuration)' == 'Release'" Project="missing.targets"/>
</Project>
'''
    document["sha256"] = hashlib.sha256(document["content"].encode()).hexdigest()
    document["size_bytes"] = len(document["content"].encode())
    profile = {**_profile(), "windows_capability": True, "driver_semantics": "msbuild-mapping/1",
               "target_axes": {"os": "windows", "isa": "x86_64", "abi": "msvc"}}
    graph = compile_build_topology([unit], source_fingerprint="synthetic-solution", profiles=profile)
    bound = refine_build_topology(graph, [unit], profiles=profile, policy=WINDOWS_SELECTION)["units"][0]
    assert all(proof["status"] == "proven" for proof in bound["enforcement"])
    assert all("effective_import_unknown" not in proof["unresolved_inputs"] for proof in bound["enforcement"])


def _elf_header(isa):
    bits, machine = {"x86": (1, 3), "x86_64": (2, 62), "arm64": (2, 183)}[isa]
    head = bytearray(64)
    head[:7] = b"\x7fELF" + bytes([bits, 1, 1])
    struct.pack_into("<HH", head, 16, 1, machine)
    return bytes(head)


def _archive_member(name, content):
    header = (name.ljust(16) + "0".ljust(12) + "0".ljust(6) + "0".ljust(6)
              + "100644".ljust(8) + str(len(content)).ljust(10) + "`\n").encode("ascii")
    return header + content + (b"\n" if len(content) % 2 else b"")


def test_retained_native_binary_machine_is_not_a_recipe_or_filename_claim(tmp_path):
    from appsec_review.jobs.build_workspace import ProductSpec, WorkspaceError, verify_native_product
    variant = _native()["build_variant"]
    path = tmp_path / "claimed-x64.o"
    path.write_bytes(_elf_header("x86"))
    spec = ProductSpec("target/claimed-x64.o", "generated_source", "obj", "obj", variant,
                       "native_object", {"os": "linux", "isa": "x86_64", "abi": "gnu",
                                         "sdk": None, "deployment": None, "device_kind": None,
                                         "hardware_generation": None})
    with pytest.raises(WorkspaceError, match="target differs"):
        verify_native_product(path, spec)
    path.write_bytes(_elf_header("x86_64"))
    verify_native_product(path, spec)


def test_archive_target_checks_every_member_and_blocks_a_hidden_32bit_slice(tmp_path):
    from appsec_review.jobs.build_workspace import WorkspaceError, native_product_axes
    path = tmp_path / "synthetic.a"
    path.write_bytes(b"!<arch>\n" + _archive_member("one.o/", _elf_header("x86_64"))
                     + _archive_member("two.o/", _elf_header("x86")))
    with pytest.raises(WorkspaceError, match="mixed"):
        native_product_axes(path)
    path.write_bytes(b"!<arch>\n" + _archive_member("one.o/", _elf_header("x86_64"))
                     + _archive_member("two.o/", _elf_header("x86_64")))
    assert native_product_axes(path) == {"isa": "x86_64", "bits": 64, "import_library": False}


def test_import_library_has_positive_member_semantics_not_a_lib_suffix(tmp_path):
    from appsec_review.jobs.build_workspace import native_product_axes
    path = tmp_path / "synthetic.lib"
    short_import = struct.pack("<HHHHIIHH", 0, 0xFFFF, 0, 0x8664, 0, 8, 0, 0) + b"f\0x.dll\0"
    path.write_bytes(b"!<arch>\n" + _archive_member("import/", short_import))
    assert native_product_axes(path)["import_library"] is True
    path.write_bytes(b"!<arch>\n" + _archive_member("object/", _elf_header("x86_64")))
    assert native_product_axes(path)["import_library"] is False


def test_managed_library_does_not_activate_executable_prefer32bit_policy():
    unit = _solution(".csproj", "<OutputType>Library</OutputType><PlatformTarget>AnyCPU</PlatformTarget>"
                     "<Prefer32Bit>true</Prefer32Bit><TargetFrameworkVersion>v4.8</TargetFrameworkVersion>")
    graph = compile_build_topology([unit], source_fingerprint="synthetic-managed-library")
    bound = refine_build_topology(graph, [unit], policy=WINDOWS_SELECTION)["units"][0]
    assert {operation["kind"] for operation in bound["operations"]} == {"managed_compile"}
    assert not any(reason.startswith("managed_prefer32bit") for reason in bound["blockers"])


def test_explicit_mobile_policy_uses_unconditional_android_source_declaration():
    text = "plugins { id 'com.android.application' }\n"
    unit = _native()
    document = {"path": "build.gradle", "content": text,
                "sha256": hashlib.sha256(text.encode()).hexdigest(), "size_bytes": len(text.encode())}
    unit.update(family="java", build_system="gradle", recipe=None,
                markers=[{key: document[key] for key in ("path", "sha256", "size_bytes")}],
                descriptor_package={"documents": [document], "bounds": {}, "gaps": []})
    graph = compile_build_topology([unit], source_fingerprint="synthetic-android")
    policy = {
        "schema": "appsec-review/build-selection-policy/1", "policy_id": "synthetic-explicit-mobile/1",
        "ambiguity_policy": "block",
        "rules": [{"selectors": {"declared_platform": "android"}, "axes": {"os": "android"},
                   "provenance": "explicitly-synthetic-unit-local"}],
    }
    bound = refine_build_topology(graph, [unit], policy=policy)["units"][0]
    assert bound["selection"]["required_axes"]["os"] == "android"
    assert bound["selection"]["required_axes"]["hardware_generation"] is None
    assert "recipe_missing" in bound["blockers"]


def test_linker_object_inputs_cannot_borrow_the_compilers_explicit_target():
    unit = _native(commands=[["clang", "--target=x86_64-unknown-linux-gnu", "foreign.o",
                              "-o", "build/control"]])
    graph = compile_build_topology([unit], source_fingerprint="synthetic-prebuilt", profiles=_profile())
    bound = refine_build_topology(graph, [unit], profiles=_profile())["units"][0]
    assert bound["enforcement"]
    assert all(proof["status"] == "unknown" for proof in bound["enforcement"])
    assert all("prebuilt_compiler_input_target_unknown" in proof["unresolved_inputs"]
               for proof in bound["enforcement"])


def _retained_native(tmp_path):
    from appsec_review.jobs.build_workspace import BuildWorkspace, NodeBinding, ProductSpec
    root, source = tmp_path / "run", tmp_path / "source"
    root.mkdir()
    source.mkdir()
    (source / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    workspace = BuildWorkspace(root)
    workspace.materialize(source, "synthetic-source")
    binding = NodeBinding("control", "synthetic-source", "a" * 64, "b" * 64, "c" * 64,
                          "sha256:" + "d" * 64, "synthetic-toolchain/1", (),
                          "synthetic-execution/1", "synthetic-output-policy/1")
    axes = {"os": "linux", "isa": "x86_64", "abi": "gnu", "sdk": None,
            "deployment": None, "device_kind": None, "hardware_generation": None}
    spec = ProductSpec("target/control.o", "generated_source", "control", "control",
                       _native()["build_variant"], "native_object", axes)
    return root, workspace, binding, spec


def test_native_commit_and_writer_free_retained_custody_check_actual_bytes(tmp_path):
    from appsec_review.jobs.build_workspace import ReconstructionMiss, verify_retained_product
    root, workspace, binding, spec = _retained_native(tmp_path)
    with workspace.writer() as writer:
        writer.begin_attempt(binding, "synthetic-attempt", writer.state()["generation"])
        (workspace.paths.target / "control.o").write_bytes(_elf_header("x86_64"))
        record = writer.commit([spec])
        generation = writer.state()["generation"]
        retained = verify_retained_product(root, generation, record.reference, binding)
        assert retained["binding"] == binding.view()
    entry = retained["entries"]["target/control.o"]
    blob = root / "data/shared/objects" / entry["sha256"]
    blob.chmod(0o600)
    blob.write_bytes(_elf_header("x86"))
    with pytest.raises(ReconstructionMiss, match="missing or changed"):
        verify_retained_product(root, generation, record.reference, binding)


def test_native_commit_cannot_publish_32bit_bytes_under_an_x64_contract(tmp_path):
    from appsec_review.jobs.build_workspace import WorkspaceError
    root, workspace, binding, spec = _retained_native(tmp_path)
    with workspace.writer() as writer:
        writer.begin_attempt(binding, "synthetic-attempt", writer.state()["generation"])
        (workspace.paths.target / "control.o").write_bytes(_elf_header("x86"))
        with pytest.raises(WorkspaceError, match="target differs"):
            writer.commit([spec])
        assert writer.committed_generation()["accepted"] == {}
        writer.fail_attempt("explicitly synthetic wrong-machine output")


def test_unselected_32bit_runtime_identifier_does_not_block_selected_managed_member():
    unit = _solution(".csproj", "<OutputType>library</OutputType><PlatformTarget>AnyCPU</PlatformTarget>"
                     """<RuntimeIdentifier Condition="'$(Configuration)' == 'Release'">win-x86</RuntimeIdentifier>""")
    graph = compile_build_topology([unit], source_fingerprint="synthetic-unselected-runtime")
    bound = refine_build_topology(graph, [unit], policy=WINDOWS_SELECTION)["units"][0]
    assert {operation["kind"] for operation in bound["operations"]} == {"managed_compile"}
    assert not any("runtime" in reason.lower() for reason in bound["blockers"])


@pytest.mark.parametrize("captured", [True, False])
def test_gradle_sibling_settings_binds_only_captured_requested_modules(captured):
    texts = {
        "build.gradle.kts": 'plugins { id("com.android.application") apply false }\n',
        "settings.gradle.kts": 'include(":app")\n',
    }
    if captured:
        texts["app/build.gradle.kts"] = 'plugins { id("com.android.application") }\n'
    documents = [{"path": path, "content": text, "sha256": hashlib.sha256(text.encode()).hexdigest(),
                  "size_bytes": len(text.encode())} for path, text in texts.items()]
    unit = _native()
    unit.update(family="java", build_system="gradle",
                descriptor_facts={"kind": "android-gradle-application"},
                markers=[{key: documents[0][key] for key in ("path", "sha256", "size_bytes")}],
                descriptor_package={"documents": documents, "bounds": {}, "gaps": []})
    unit["recipe"].update(image_profile="android", dependency_files=list(texts),
                          build_commands=[["gradle", "--no-daemon", ":app:assembleDebug"]],
                          expected_outputs=["app/build"])
    graph = compile_build_topology([unit], source_fingerprint="synthetic-gradle-settings")
    policy = {
        "schema": "appsec-review/build-selection-policy/1", "policy_id": "synthetic-android/1",
        "ambiguity_policy": "block",
        "rules": [{"selectors": {"declared_platform": "android"}, "axes": {"os": "android"},
                   "provenance": "synthetic-inline-intent"}],
    }
    bound = refine_build_topology(graph, [unit], policy=policy)["units"][0]
    settings_ids = {fact["fact_id"] for fact in graph["facts"] if fact["path"] == "settings.gradle.kts"}
    assert any(binding["fact_id"] in settings_ids for binding in graph["bindings"])
    if captured:
        assert any(binding["subject"] == ":app" and binding["stage"] == "module_declaration"
                   for binding in graph["bindings"])
        assert {operation["kind"] for operation in bound["operations"]} == {
            "managed_compile", "bytecode_transform"}
        assert bound["enforcement"] == [] and bound["blockers"] == []
    else:
        assert "requested_gradle_module_uncaptured" in bound["blockers"]


@pytest.mark.parametrize("platform", ["windows", "linux"])
def test_explicit_go_cgo0_target_is_proven_only_for_applicable_selection(platform):
    unit = _go({"GOOS": platform, "GOARCH": "amd64", "CGO_ENABLED": "0"})
    before = copy.deepcopy(unit)
    graph = compile_build_topology([unit], source_fingerprint="synthetic-go-preflight")
    policy = {
        "schema": "appsec-review/build-selection-policy/1", "policy_id": "synthetic-go/1",
        "ambiguity_policy": "block",
        "rules": [{"selectors": {"build_system": "go"}, "axes": {"os": platform, "isa": "x86_64"},
                   "provenance": "synthetic-explicit-platform-intent"}],
    }
    bound = refine_build_topology(graph, [unit], policy=policy)["units"][0]
    assert bound["blockers"] == []
    assert len(bound["enforcement"]) == 1
    proof = bound["enforcement"][0]
    assert proof["proof_kind"] == "go_explicit_target" and proof["status"] == "proven"
    assert proof["proven_axes"]["os"] == platform and proof["proven_axes"]["isa"] == "x86_64"
    assert proof["recipe_digest"] == bound["recipe_digest"] and proof["operation_binding"]
    assert proof["unresolved_inputs"] == []
    assert unit == before


@pytest.mark.parametrize("key,value,status,reason", [
    ("GOOS", None, "unknown", "native_target_axis_unknown:os"),
    ("GOOS", "windows", "incompatible", None),
    ("GOARCH", None, "unknown", "native_target_axis_unknown:isa"),
    ("GOARCH", "386", "incompatible", None),
    ("CGO_ENABLED", None, "unknown", "explicit_cgo_mode_missing"),
    ("CGO_ENABLED", "invalid", "unknown", "explicit_cgo_mode_missing"),
    ("CGO_ENABLED", "1", "unknown", "cgo_c_compiler_enforcement_required"),
])
def test_go_missing_or_conflicting_target_and_unproven_cgo_never_admit(key, value, status, reason):
    environment = {"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0"}
    if value is None:
        del environment[key]
    else:
        environment[key] = value
    unit = _go(environment)
    graph = compile_build_topology([unit], source_fingerprint="synthetic-go-negative")
    policy = {
        "schema": "appsec-review/build-selection-policy/1", "policy_id": "synthetic-go-linux/1",
        "ambiguity_policy": "block",
        "rules": [{"selectors": {"build_system": "go"}, "axes": {"os": "linux", "isa": "x86_64"},
                   "provenance": "synthetic-explicit-platform-intent"}],
    }
    bound = refine_build_topology(graph, [unit], policy=policy)["units"][0]
    assert "unenforced_native_target" in bound["blockers"]
    assert bound["enforcement"]
    assert all(proof["proof_kind"] == "go_explicit_target" and proof["status"] == status
               for proof in bound["enforcement"])
    if reason:
        assert all(reason in proof["unresolved_inputs"] for proof in bound["enforcement"])


@pytest.mark.parametrize("field,value", [
    ("GOOS", "windows"), ("GOARCH", "386"), ("CGO_ENABLED", "1"),
    ("GOOS", None), ("GOARCH", None), ("CGO_ENABLED", None),
    ("isa", "arm64"), ("bits", 32),
])
def test_go_produced_facts_match_every_accepted_setting_and_machine_axis(field, value):
    from appsec_review.jobs.job_language_build.go import verify_target_facts
    facts = {"build_settings": {"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0"},
             "binary_target": {"format": "elf", "isa": "x86_64", "bits": 64}}
    recipe = _go(dict(facts["build_settings"]))["recipe"]
    selected = {"enforcement": [{"proof_kind": "go_explicit_target", "status": "proven"}]}
    verify_target_facts(facts, selected, recipe)
    if field in {"isa", "bits"}:
        facts["binary_target"][field] = value
    elif value is None:
        del facts["build_settings"][field]
    else:
        facts["build_settings"][field] = value
    with pytest.raises(ValueError, match="differs from accepted enforcement"):
        verify_target_facts(facts, selected, recipe)


@pytest.mark.parametrize("scenario", ["valid", "settings", "machine", "windows-elf", "pe"])
def test_go_actual_output_admission_rejects_mismatch_before_typed_success(tmp_path, scenario):
    from appsec_review.jobs.job_language_build.go import admit_build_outputs
    from tests.capture_fakes import go_build_info, go_elf
    module = ("path\tsynthetic.invalid/control\nmod\tsynthetic.invalid/control\t(devel)\t\n"
              "build\tGOOS=linux\nbuild\tGOARCH=amd64\nbuild\tCGO_ENABLED=0\n")
    if scenario == "settings":
        module = module.replace("GOARCH=amd64", "GOARCH=386")
    elif scenario == "windows-elf":
        module = module.replace("GOOS=linux", "GOOS=windows")
    raw = bytearray(go_elf(build_info=go_build_info(module_text=module))[0])
    if scenario == "machine":
        struct.pack_into("<H", raw, 18, 183)
    elif scenario == "pe":
        raw = bytearray(b"MZ" + bytes(126))
    path = tmp_path / "synthetic-go-output"
    path.write_bytes(raw)
    artifacts = [{"kind": "executable", "path": path.name, "workspace_path": "build/control",
                  "sha256": hashlib.sha256(raw).hexdigest()}]
    platform = "windows" if scenario in {"windows-elf", "pe"} else "linux"
    unit = _go({"GOOS": platform, "GOARCH": "amd64", "CGO_ENABLED": "0"})
    graph = compile_build_topology([unit], source_fingerprint="synthetic-go-output")
    policy = {
        "schema": "appsec-review/build-selection-policy/1", "policy_id": "synthetic-go-output/1",
        "ambiguity_policy": "block",
        "rules": [{"selectors": {"build_system": "go"}, "axes": {"os": platform, "isa": "x86_64"},
                   "provenance": "synthetic-inline-intent"}],
    }
    selected = refine_build_topology(graph, [unit], policy=policy)["units"][0]
    assert selected["blockers"] == []
    recipe = unit["recipe"]
    result = admit_build_outputs(tmp_path, artifacts, selected, recipe)
    if scenario == "valid":
        assert result["terminal_status"] == "SUCCEEDED" and result["gaps"] == []
        assert len(result["artifacts"]) == 1 and len(result["build_metadata"]) == 1
        assert result["build_metadata"][0]["binary_target"] == {
            "format": "elf", "bits": 64, "isa": "x86_64"}
    else:
        assert result["terminal_status"] == "FAILED"
        assert result["artifacts"] == [] and result["build_metadata"] == []
        assert len(result["gaps"]) == 1
        assert artifacts[0]["go_build_status"] == ("unparsed" if scenario == "pe" else "target_mismatch")
        assert ("metadata was not parseable" if scenario == "pe" else "target enforcement failed") in result["gaps"][0]
        if scenario == "windows-elf":
            assert "binary format has no supported match for accepted OS" in result["gaps"][0]
