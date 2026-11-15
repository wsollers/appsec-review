"""Unit tests for language-build adapters (dotnet, native, native_components, capture, rust, php, go)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from appsec_review.config import RustBuildSettings
from appsec_review.jobs.build_bookkeeping import BookkeepingExclusions
from appsec_review.jobs.job_language_build import (
    capture, dotnet, go, native, native_components, php, rust,
)


def _fake_capture(
    *,
    events: list[Any],
    tool_calls: list[Any] = (),
    gaps: tuple[str, ...] = (),
    document: dict[str, Any] | None = None,
    sha256: str = "a" * 64,
) -> Any:
    return SimpleNamespace(
        identity={"sha256": sha256},
        gaps=gaps,
        document=document or {},
        events=lambda: list(events),
        tool_calls=list(tool_calls),
    )


def test_dotnet_validation_topology_artifacts_and_invocation_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert dotnet.validate_recipe({
        "configure_commands": ["skip", [], ["dotnet", "restore"]],
        "build_commands": [["dotnet", "test"], ["dotnet", "--info"]],
    }) == (
        "dotnet subcommand is unsupported: test",
        "dotnet subcommand is unsupported: <missing>",
    )

    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "bad.csproj").write_text("<Project><unclosed>", encoding="utf-8")
    (ws / "win.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk.WindowsDesktop">'
        "<PropertyGroup><TargetFrameworks>net8.0-windows;net48</TargetFrameworks>"
        "<RuntimeIdentifiers>win-x64;linux-x64</RuntimeIdentifiers><UseWPF>true</UseWPF></PropertyGroup>"
        '<ItemGroup><ProjectReference Include="../lib/lib.csproj" />'
        '<PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup>'
        "</Project>",
        encoding="utf-8",
    )
    projects, gaps, platform_gaps = dotnet.project_topology(ws)
    assert gaps == ["bad.csproj: project XML could not be parsed"]
    assert len(projects) == 1 and projects[0]["windows_only"] is True
    assert projects[0]["project_references"] == ["../lib/lib.csproj"]
    assert projects[0]["package_references"] == [{"name": "Newtonsoft.Json", "version": "13.0.3"}]
    assert len(platform_gaps) == 1

    # selected_project_topology: legacy schema and v2 graph with uncaptured + unresolved + windows facts
    plans = [
        {"build_topology": {"executable_graph": {"schema": "appsec-review/build-topology/1"}}},
        {
            "build_topology": {
                "executable_graph": {
                    "schema": "appsec-review/build-topology/2",
                    "facts": [
                        {"path": "App/App.csproj", "line": 4, "condition": "'$(Unknown)' == '1'",
                         "predicate": "TargetFramework", "value": "net8.0"},
                        {"path": "App/App.csproj", "line": 5, "condition": None,
                         "predicate": "TargetFrameworks", "value": "net8.0-windows"},
                        {"path": "App/App.csproj", "line": 6, "condition": "'$(Configuration)' == 'Debug'",
                         "predicate": "TargetFramework", "value": "net6.0"},
                        {"path": "App/App.csproj", "line": 7, "condition": None,
                         "predicate": "RuntimeIdentifier", "value": "win-x64"},
                        {"path": "App/App.csproj", "line": 8, "condition": None,
                         "predicate": "ProjectReference", "value": {"Include": "Lib/Lib.csproj"}},
                        {"path": "App/App.csproj", "line": 9, "condition": None,
                         "predicate": "PackageReference", "value": {"Include": "Serilog", "Version": "4.0.0"}},
                        {"path": "App/App.csproj", "line": 1, "condition": None,
                         "predicate": "project_descriptor", "sha256": "b" * 64,
                         "value": {"sdk": "Microsoft.NET.Sdk"}},
                    ],
                },
                "planning_refinement": {"units": {}},
            }
        },
    ]
    monkeypatch.setattr(
        "appsec_review.jobs.job_target_analysis_plan.job.load_accepted_plan",
        lambda _rr: plans.pop(0),
    )
    assert dotnet.selected_project_topology(tmp_path, {"build_unit_id": "u1"}) == (
        [], ["legacy graph needs selected-member replanning"], [],
    )
    monkeypatch.setattr(
        "appsec_review.jobs.build_topology.refinement_unit",
        lambda *_a, **_kw: {
            "selection": {"required_axes": {"isa": "x86_64"}},
            "operations": [{
                "kind": "dotnet_build",
                "reasons": ["solution filter notice"],
                "selected_members": [
                    {"path": "Missing/Missing.csproj", "configuration": "Release", "platform": "x64", "captured": False},
                    {"path": "README.md", "configuration": "Release", "platform": "x64", "captured": True},
                    {"path": "App/App.csproj", "configuration": "Release", "platform": "x64", "captured": True},
                ],
            }],
        },
    )
    sel_projects, sel_gaps, sel_plat = dotnet.selected_project_topology(tmp_path, {"build_unit_id": "u1"})
    assert len(sel_projects) == 1 and sel_projects[0]["windows_only"] is True
    assert any("was not captured" in g for g in sel_gaps)
    assert any("applicability is unresolved" in g for g in sel_gaps)
    assert "solution filter notice" in sel_gaps
    assert len(sel_plat) == 1

    # artifact_kind + tool_identity + CAPTURE_DESCRIPTOR.build_invocation
    elf_bin = ws / "apphost"
    elf_bin.write_bytes(b"\x7fELF" + b"\x00" * 32)
    gen_cs = ws / "obj" / "Release" / "Gen.g.cs"
    gen_cs.parent.mkdir(parents=True)
    gen_cs.write_text("class Gen {}\n", encoding="utf-8")
    assert dotnet.artifact_kind(elf_bin) == "native-output"
    assert dotnet.artifact_kind(gen_cs) == "generated-source"
    assert dotnet.artifact_kind(Path("app.pdb")) == "debug-information"
    assert dotnet.artifact_kind(Path("pkg.nupkg")) == "nuget-package"
    assert dotnet.artifact_kind(Path("libnative.so")) == "native-output"
    assert dotnet.artifact_kind(Path("app.deps.json")) == "dependency-manifest"
    assert dotnet.artifact_kind(Path("app.runtimeconfig.json")) == "runtime-configuration"
    assert dotnet.artifact_kind(Path("project.assets.json")) == "nuget-assets"
    assert dotnet.artifact_kind(Path("Strings.resx")) == "resource"
    assert dotnet.artifact_kind(Path("msbuild.binlog")) == "build-intermediate"
    assert dotnet.artifact_kind(Path("notes.txt")) is None

    assert dotnet.tool_identity("/usr/bin/dotnet", ["dotnet", "/sdk/Roslyn/bincore/csc.dll", "Program.cs"]) == (
        "csc.dll", "compiler",
    )
    assert dotnet._classify_tool("/usr/bin/ilc", ["ilc", "a.dll"]) == capture.ToolIdentity("ilc", "aot-compiler")
    assert dotnet._classify_tool("/usr/bin/echo", ["echo"]) is None

    (ws / "Program.cs").write_text("class P {}\n", encoding="utf-8")
    row = dotnet.CAPTURE_DESCRIPTOR.build_invocation(
        "csc.dll", "compiler",
        ["dotnet", "Program.cs", "/r:Alias=/workspace/ref.dll", "/out:bin/app.dll", "/etc/passwd", "../escape.cs"],
        ws, ".", "origin-1",
    )
    assert [item["workspace_path"] for item in row["inputs"]] == ["Program.cs", "ref.dll"]
    assert row["inputs"][0]["mapping"] == "exact-workspace-path"
    assert row["inputs"][1]["mapping"] == "declared-path-unresolved"
    assert [item["workspace_path"] for item in row["outputs"]] == ["bin/app.dll"]


def test_native_and_native_components_and_capture_edge_cases(tmp_path: Path) -> None:
    ws = tmp_path / "run" / "data" / "build" / "native" / "workspace"
    ws.mkdir(parents=True)
    run_root = tmp_path / "run"
    (ws / "src.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")

    assert native.tool_kind("clang", ["clang", "-c", "src.c"]) == "compiler"
    assert native.tool_kind("gcc", ["gcc", "src.o", "-o", "app"]) == "linker-driver"
    assert native.tool_kind("as", ["as", "src.s"]) == "assembler"
    assert native.tool_kind("ld.lld", ["ld.lld", "src.o"]) == "linker"
    assert native.tool_kind("llvm-ar", ["llvm-ar", "rcs", "libx.a", "src.o"]) == "archiver"
    assert native.tool_kind("strip", ["strip", "app"]) == "post-link"
    assert native.tool_kind("protoc", ["protoc", "--cpp_out", "gen", "a.proto"]) == "code-generator"
    assert native.tool_kind("ninja", ["ninja"]) == "build-driver"
    assert native.tool_kind("python3", ["python3"]) is None

    # Implicit .o output when compiler has no -o; archiver .a output; code-generator --cpp_out; -Wl,-Map,
    comp_row = native.CAPTURE_DESCRIPTOR.build_invocation(
        "clang", "compiler", ["clang", "-c", "/workspace/src.c"], ws, ".", "orig",
    )
    assert comp_row["inputs"][0]["workspace_path"] == "src.c"
    assert comp_row["outputs"][0]["workspace_path"] == "src.o"

    ar_row = native.CAPTURE_DESCRIPTOR.build_invocation(
        "ar", "archiver", ["ar", "rcs", "libfoo.a", "/workspace", "/etc/hosts", "../bad.o"], ws, ".", "orig",
    )
    assert ar_row["outputs"][0]["workspace_path"] == "libfoo.a"

    gen_row = native.CAPTURE_DESCRIPTOR.build_invocation(
        "protoc", "code-generator", ["protoc", "--cpp_out", "gen", "msg.proto"], ws, ".", "orig",
    )
    assert gen_row["outputs"][0]["workspace_path"] == "gen"

    link_row = native.CAPTURE_DESCRIPTOR.build_invocation(
        "clang", "linker-driver", ["clang", "/Foobj/a.obj", "-Wl,-Map,out.map", "src.o"], ws, ".", "orig",
    )
    assert {o["workspace_path"] for o in link_row["outputs"]} == {"obj/a.obj", "out.map"}

    # capture.py validation and edge cases
    assert capture.normalized_path("relative/bin") is False
    assert capture.normalized_path("/usr/../bin/cc") is False
    assert capture.image_owned("/workspace/cc") is False
    assert capture.image_owned("/usr/bin/cc") is True
    with pytest.raises(ValueError, match="identities are required"):
        capture.CapturedBuildDescriptor("", "id", "schema", "lbl", native._classify_tool, native._row)
    with pytest.raises(ValueError, match="needs an explicit gap"):
        capture.CapturedBuildDescriptor("native", "id", "schema", "lbl", native._classify_tool, native._row)
    with pytest.raises(ValueError, match="must be positive"):
        capture.ReconciliationLimits(invocation_count=0)

    cap = _fake_capture(
        document={
            "events": {"observed": 5, "retained": 4},
            "tool_calls": {"observed": 3, "retained": 2},
            "response_files": {"records": [{"size_bytes": 42, "references": ["a", "b"]}]},
        },
        events=[
            "not-a-mapping",
            {"kind": "connect", "pid": 1, "ordinal": 1, "timestamp_ns": "bad"},
            {"kind": "process_exec", "argv": "not-a-list", "executable": "/usr/bin/clang", "result": 0},
            {"kind": "process_exec", "argv": ["clang", "-c", "src.c"], "executable": "/usr/bin/clang",
             "result": 0, "envp_captured": True, "envp_redacted_names": "not-a-list"},
            {"kind": "process_exec", "argv": ["<redacted>", "-c", "src.c"], "executable": "/usr/bin/clang", "result": 0},
            {"kind": "process_exec", "argv": ["clang", "-c", "src.c"], "executable": "/usr/bin/clang", "result": 1},
            {"kind": "process_exec", "argv": ["custom"], "executable": "/workspace/custom", "result": 0},
            {"kind": "process_exec", "argv": ["clang", "-c", "src.c"], "executable": "/usr/bin/clang",
             "result": 0, "argv_truncated": True},
            {"kind": "process_exec", "pid": 10, "ordinal": 9, "timestamp_ns": 9,
             "argv": ["clang", "-c", "src.c", "-o", "src.o"], "executable": "/usr/bin/clang",
             "result": 0, "envp_captured": True, "envp_redacted_names": ["SECRET_TOKEN"]},
            {"kind": "process_exec", "pid": 11, "ordinal": 10, "timestamp_ns": 10,
             "argv": ["clang", "src.o", "-o", "app"], "executable": "/usr/bin/clang", "result": 0},
        ],
        tool_calls=[
            "bad-call",
            {"record": {"argv": "bad", "tool": "clang"}},
            {"record": {"argv": ["<redacted>"], "tool": "clang"}},
            {"uri": "tc/1.json", "sha256": "c" * 64,
             "record": {"tool": "clang", "argv": ["clang", "-c", "other.c"], "exit_code": 0}},
            {"uri": "tc/2.json", "sha256": "d" * 64,
             "record": {"tool": "clang", "argv": ["clang", "-c", "src.c", "-o", "src.o"],
                        "exit_code": 0, "stdout": {"sha256": "e" * 64}, "stderr": {"sha256": "f" * 64}}},
        ],
    )
    res = capture.reconcile_captured_build(
        [(1, cap)], ws, ".", native.CAPTURE_DESCRIPTOR,
        limits=capture.ReconciliationLimits(invocation_count=1),
    )
    assert len(res.rows) == 1 and res.rows[0]["mapping"] == "syscall-process-exec+tool-call"
    assert res.facts["response_file_bytes"] == 42 and res.facts["response_file_references"] == 2
    assert res.facts["event_records_lost"] == 1 and res.facts["tool_call_records_lost"] == 1
    assert res.facts["envp_redacted_names"] == ["SECRET_TOKEN"]
    assert len(res.gaps) == 6  # redacted exec, redacted tool, truncated, unreconciled, malformed, row-bound

    # native_components: non-native empty, CMake correlation, missing component sources, projection
    out_root = run_root / "data" / "build" / "native" / "unit1"
    out_root.mkdir(parents=True)
    assert native_components.publish(
        out_root, run_root, dispatch={"family": "python", "native_components": []},
        workspace=ws, captures=[],
    ) == (None, [])

    build_dir = ws / "build"
    build_dir.mkdir()
    (ws / "extra.c").write_text("int x;\n", encoding="utf-8")
    (build_dir / "compile_commands.json").write_text(json.dumps([
        {"directory": "/workspace", "arguments": ["/usr/bin/clang", "-MD", "-MF", "src.d", "-c", "src.c", "-o", "build/src.o"], "file": "src.c"},
        {"directory": "/workspace", "arguments": ["/usr/bin/clang", "-c", "uncompiled.c"], "file": "uncompiled.c"},
    ]), encoding="utf-8")
    nc_cap = _fake_capture(events=[
        {"kind": "process_exec", "pid": 1, "ordinal": 1, "executable": "/usr/bin/clang", "result": 0,
         "argv": ["clang", "-cc1", "src.c"]},
        {"kind": "process_exec", "pid": 1, "ordinal": 2, "executable": "/usr/bin/clang", "result": 0,
         "argv": ["clang", "-c", "trunc.c"], "argv_truncated": True},
        {"kind": "process_exec", "pid": 1, "ordinal": 3, "executable": "/usr/bin/clang", "result": 0,
         "argv": ["clang", "src.o", "-o", "app"]},
        {"kind": "process_exec", "pid": 1, "ordinal": 4, "executable": "/usr/bin/clang", "result": 0,
         "argv": ["clang", "-c", "CMakeFiles/CMakeScratch/TryCompile-1/test.c", "-o", "test.o"]},
        {"kind": "process_exec", "pid": 1, "ordinal": 5, "executable": "/usr/bin/clang", "result": 0,
         "argv": ["clang", "-c", "src.c", "-o", "build/src.o"]},
        {"kind": "process_exec", "pid": 1, "ordinal": 6, "executable": "/usr/bin/clang", "result": 0,
         "argv": ["clang", "-c", "src.c", "-o", "build/src.o"]},
        {"kind": "process_exec", "pid": 1, "ordinal": 7, "executable": "/usr/bin/clang", "result": 0,
         "argv": ["clang", "-c", "extra.c", "-o", "build/extra.o"]},
    ])
    exclusions = BookkeepingExclusions()
    entries, nc_gaps = native_components.compile_entries(
        [(1, nc_cap)], initial_directory="/workspace", exclusions=exclusions,
    )
    assert len(entries) == 2 and any("truncated argv" in g for g in nc_gaps)
    assert len(native_components.invocation_rows([(1, nc_cap)], family="node", source_dir=".")) == 2

    db_id, pub_gaps = native_components.publish(
        out_root, run_root,
        dispatch={
            "build_unit_id": "u-native", "family": "native", "build_system": "cmake", "root": ".",
            "recipe": {"source_dir": ".", "build_dir": "build"},
            "native_components": [{"path": "src.c"}, {"path": "missing_comp.c"}],
        },
        workspace=ws, captures=[(1, nc_cap)],
    )
    assert db_id is not None and db_id["entry_count"] == 1
    assert any("lacks captured invocation: uncompiled.c" in g for g in pub_gaps)
    assert any("lacks a compile database declaration: /workspace/extra.c" in g for g in pub_gaps)
    assert any("missing_comp.c" in g for g in pub_gaps)
    published_doc = json.loads((run_root / db_id["path"]).read_text(encoding="utf-8"))
    projected = native_components.compile_commands(published_doc)
    assert len(projected) == 1 and projected[0]["file"] == "/workspace/src.c"
    with pytest.raises(ValueError, match="compile database is invalid"):
        native_components.compile_commands({"schema": "wrong"})


def test_rust_php_and_go_capture_and_admission_contracts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Rust dispatch validation, argv builders, and metadata parser
    settings = RustBuildSettings(
        toolchain="stable", target="x86_64-unknown-linux-gnu", profile="release",
        features=("feat_a",), locked=True, offline=True, capture_linker=True, diagnostic_tail_bytes=4096,
    )
    assert rust.validate_dispatch({"build_system": "make"}, settings) == (
        "Rust execution requires an accepted Cargo recipe",
    )
    bad_rust = {
        "build_system": "cargo",
        "recipe": {
            "dependency_files": ["Cargo.toml"],
            "configure_commands": [["make"], ["cargo", "test"], ["cargo", "check", "--tests"]],
            "build_commands": [
                ["cargo", "check", "--target"],
                ["cargo", "check", "--target", "bad/target", "--profile", "bad/prof", "--features", "bad/feat"],
                ["cargo", "check", "--target", "aarch64-unknown-linux-gnu", "--profile", "dev"],
            ],
        },
    }
    r_errs = rust.validate_dispatch(bad_rust, settings)
    assert "Rust recipes may execute Cargo commands only" in r_errs
    assert "Cargo subcommand is unsupported: test" in r_errs
    assert "Cargo examples, tests, benchmarks, and all-target builds are forbidden" in r_errs
    assert "Cargo option is missing its value: --target" in r_errs
    assert "Cargo target selection is invalid" in r_errs
    assert "Cargo selection is invalid: --profile" in r_errs
    assert "Cargo feature selection is invalid" in r_errs
    assert "Cargo target differs from central Rust configuration" in r_errs
    assert "Cargo profile differs from central Rust configuration" in r_errs
    assert "Rust recipe must contain a Cargo build or rustc command" in r_errs
    assert "locked Rust builds require Cargo.lock in accepted dependency inputs" in r_errs

    with pytest.raises(ValueError, match="not Cargo"):
        rust.build_argv(["rustc", "lib.rs"], settings)
    built_argv = rust.build_argv(["cargo", "build"], settings)
    assert "--offline" in built_argv and "--locked" in built_argv
    assert "--target" in built_argv and "--profile" in built_argv and "--features" in built_argv
    assert "-vv" in built_argv and "--message-format=json-render-diagnostics" in built_argv
    assert "--features" in rust.metadata_argv({}, settings)

    with pytest.raises(ValueError, match="schema is unsupported"):
        rust.parse_metadata(b'{"version": 2}')
    with pytest.raises(ValueError, match="exceeds its bound"):
        rust.parse_metadata(b'{"version": 1, "packages": [{}, {}]}', max_packages=1)
    with pytest.raises(ValueError, match="package metadata is invalid"):
        rust.parse_metadata(b'{"version": 1, "packages": [{}]}')
    parsed_meta = rust.parse_metadata(json.dumps({
        "version": 1, "workspace_root": "/workspace", "target_directory": "/workspace/target",
        "workspace_members": ["pkg#0.1.0"],
        "packages": [{
            "id": "pkg#0.1.0", "name": "pkg", "version": "0.1.0", "manifest_path": "/workspace/Cargo.toml",
            "features": {"default": []},
            "targets": ["skip", {"name": "my_macro", "kind": ["proc-macro"], "crate_types": ["proc-macro"], "src_path": "src/lib.rs"}],
        }],
        "resolve": {"nodes": [{"id": "pkg#0.1.0", "dependencies": ["dep#0.2.0"]}]},
    }).encode("utf-8"))
    assert parsed_meta["proc_macro_targets"] == [{"package_id": "pkg#0.1.0", "package_name": "pkg", "target": "my_macro"}]
    assert parsed_meta["relationships"] == [{"from": "pkg#0.1.0", "to": "dep#0.2.0", "kind": "cargo-resolve"}]

    # PHP validation, policy, and composer_metadata
    assert php.validate_php_dispatch({"build_system": "maven", "recipe": {}}) == [
        "PHP execution requires an accepted Composer or phpize recipe"
    ]
    assert php.validate_php_dispatch({"build_system": "phpize", "recipe": {"dependency_files": []}}) == [
        "phpize extension metadata is unavailable"
    ]
    assert php.validate_php_dispatch({"build_system": "phpize", "recipe": {"dependency_files": ["ext/config.m4"]}}) == []
    assert php.validate_php_dispatch({"build_system": "composer", "recipe": {"dependency_files": []}}) == [
        "Composer project metadata is unavailable"
    ]
    with pytest.raises(ValueError, match="PHP settings are required"):
        php.composer_policy({})
    with pytest.raises(ValueError, match="policy is invalid"):
        php.composer_policy({"php": {"composer_plugins": "enabled", "composer_scripts": "disabled"}})
    pol = php.composer_policy({"php": {"composer_plugins": "disabled", "composer_scripts": "disabled", "require_lockfile": True}})
    assert php.policy_argv(["composer", "install"], pol) == (
        "composer", "install", "--no-plugins", "--no-scripts", "--no-interaction",
    )
    php_ws = tmp_path / "php_ws"
    php_ws.mkdir()
    with pytest.raises(ValueError, match="unavailable"):
        php.composer_metadata(php_ws, ".")
    (php_ws / "composer.json").write_text(json.dumps({
        "name": "acme/web", "require": {"php": ">=8.2", "monolog/monolog": "^3.0"},
        "scripts": {"post-install-cmd": "echo ok"},
    }), encoding="utf-8")
    unlocked_meta, unlocked_gaps = php.composer_metadata(php_ws, ".")
    assert unlocked_meta["composer_lock"] is None and len(unlocked_gaps) == 1
    (php_ws / "composer.lock").write_text(json.dumps({
        "content-hash": "1234",
        "packages": [{"name": "composer/plugin-a", "version": "1.0.0", "dist": {"shasum": "aa"}, "require": {"psr/log": "^3.0"}}],
        "packages-dev": [{"name": "phpunit/phpunit", "version": "10.0.0"}],
    }), encoding="utf-8")
    locked_meta, locked_gaps = php.composer_metadata(php_ws, ".")
    assert locked_gaps == [] and len(locked_meta["plugins"]) == 1 and len(locked_meta["relationships"]) == 2

    # Go capture_invocations, verify_target_facts, and admit_build_outputs
    go_ws = tmp_path / "go_ws"
    (go_ws / "pkg").mkdir(parents=True)
    (go_ws / "pkg" / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
    go_cap = _fake_capture(
        events=[
            {"kind": "connect"},
            {"kind": "file_open"},
            {"kind": "process_exec", "argv": ["compile"], "executable": None, "result": 0},
            {"kind": "process_exec", "argv": ["<redacted>"], "executable": "/usr/local/go/pkg/tool/linux_amd64/compile", "result": 0},
            {"kind": "process_exec", "argv": ["compile"], "executable": "/usr/local/go/pkg/tool/linux_amd64/compile", "result": 2},
            {"kind": "process_exec", "argv": ["compile"], "executable": "/workspace/compile", "result": 0,
             "envp_captured": True, "envp_redacted_names": ["GO_SECRET"]},
            {"kind": "process_exec", "argv": ["compile", "-p", "ex/pkg"],
             "executable": "/usr/local/go/pkg/tool/linux_amd64/compile", "result": 0, "argv_truncated": True},
            {"kind": "process_exec", "ordinal": 8,
             "argv": ["compile", "-p", "ex/pkg", "-o", "/workspace/out.a", "main.go", "/etc/hosts"],
             "executable": "/usr/local/go/pkg/tool/linux_amd64/compile", "result": 0,
             "envp_captured": True, "envp_redacted_names": ["TOKEN_A"]},
        ],
        tool_calls=[
            {"uri": "tc/0.json", "sha256": "0" * 64, "record": {"tool": "go", "argv": ["<redacted>"]}},
            {"uri": "tc/1.json", "sha256": "1" * 64, "record": {"tool": "python", "argv": ["python"]}},
            {"uri": "tc/2.json", "sha256": "2" * 64, "record": {"tool": "go", "argv": ["go", "build"], "exit_code": 0}},
            {"uri": "tc/3.json", "sha256": "3" * 64,
             "record": {"tool": "go", "argv": ["go", "-p", "ex/pkg", "-o", "/workspace/out.a", "main.go", "/etc/hosts"],
                        "exit_code": 0}},
        ],
    )
    g_rows, g_facts, g_gaps = go.capture_invocations([(1, go_cap)], go_ws, {"ex/pkg": "/workspace/pkg"})
    assert len(g_rows) == 1 and g_rows[0]["package"] == "ex/pkg"
    assert g_rows[0]["inputs"][0]["workspace_path"] == "pkg/main.go"
    assert g_rows[0]["outputs"][0]["workspace_path"] == "out.a"
    assert g_facts["connect_events"] == 1 and g_facts["file_open_events"] == 1
    assert len(g_gaps) == 4

    selected = {"enforcement": [{"proof_kind": "go_explicit_target", "status": "proven"}]}
    recipe = {"environment": {"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0"}}
    valid_facts = {
        "build_id_sha256": "9" * 64, "parser": "go-buildinfo/1",
        "build_settings": {"GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0"},
        "binary_target": {"format": "elf", "isa": "x86_64", "bits": 64},
    }
    go.verify_target_facts(valid_facts, selected, recipe)
    with pytest.raises(ValueError, match="no accepted Go target proof"):
        go.verify_target_facts(valid_facts, {"enforcement": []}, recipe)
    with pytest.raises(ValueError, match="no resolving build information"):
        go.verify_target_facts({}, selected, recipe)
    with pytest.raises(ValueError, match="differs from accepted enforcement"):
        go.verify_target_facts({**valid_facts, "build_settings": {"GOOS": "darwin"}}, selected, recipe)
    with pytest.raises(ValueError, match="no supported match for accepted OS"):
        go.verify_target_facts({**valid_facts, "binary_target": {"format": "macho"}}, selected, recipe)
    with pytest.raises(ValueError, match="machine/class differs"):
        go.verify_target_facts({**valid_facts, "binary_target": {"format": "elf", "isa": "arm64", "bits": 64}}, selected, recipe)

    outcomes = [ValueError("corrupt elf"), {**valid_facts, "build_settings": {"GOOS": "windows"}}, valid_facts]
    monkeypatch.setattr(go, "build_facts", lambda _p: (_ for _ in ()).throw(outcomes.pop(0)) if isinstance(outcomes[0], Exception) else outcomes.pop(0))
    failed_adm = go.admit_build_outputs(
        tmp_path,
        [
            {"kind": "static-library", "workspace_path": "a.a", "path": "a.a", "sha256": "1" * 64},
            {"kind": "executable", "workspace_path": "bad1", "path": "bad1", "sha256": "2" * 64},
            {"kind": "executable", "workspace_path": "bad2", "path": "bad2", "sha256": "3" * 64},
        ],
        selected, recipe,
    )
    assert failed_adm["terminal_status"] == "FAILED" and len(failed_adm["gaps"]) == 2
    ok_adm = go.admit_build_outputs(
        tmp_path, [{"kind": "executable", "workspace_path": "good", "path": "good", "sha256": "4" * 64}],
        selected, recipe,
    )
    assert ok_adm["terminal_status"] == "SUCCEEDED" and ok_adm["artifacts"][0]["go_build_status"] == "resolved"
