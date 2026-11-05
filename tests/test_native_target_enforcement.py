from __future__ import annotations

import copy
import hashlib
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
