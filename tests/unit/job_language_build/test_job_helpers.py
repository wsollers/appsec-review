"""The pure helpers of job.py and the dotnet/native adapters, as found in the pre-walk suite."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.config.assurance import ComponentReleases
from appsec_review.config.build_outputs import BuildOutputPolicy, parse_build_outputs
from appsec_review.container_runtime import BuildCommandResult
from appsec_review.jobs.job_language_build import native
from appsec_review.jobs.job_language_build.dotnet import artifact_kind, project_topology, tool_identity, validate_recipe
from appsec_review.jobs.job_language_build.job import (
    _catalog, _compile_rows, _dotnet_argv, _fingerprint, _kind, _link_rows, _stream_identity,
)
from appsec_review.storage import file_sha256


ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize("family", ["native", "dotnet", "rust", "node", "python", "go", "java"])
def test_coverage_exchange_artifacts_are_preserved_for_every_build_family(family: str) -> None:
    assert _kind(Path("coverage.xml"), family, relative="reports/coverage.xml") == "test-coverage"
    assert _kind(Path("coverage.json"), family, relative="out/coverage.json") == "test-coverage"


@pytest.mark.parametrize("family", ["native", "dotnet", "rust", "node", "python", "go", "java"])
def test_profile_exchange_artifacts_are_preserved_for_every_build_family(family: str) -> None:
    assert _kind(Path("hot.folded"), family, relative="profiles/hot.folded") == "execution-profile"
    assert _kind(Path("default.profraw"), family, relative="out/default.profraw") == "execution-profile"


def test_generic_catalog_retains_unchanged_coverage_with_origin_and_excludes_other_inputs(
        tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    coverage = workspace / "reports" / "lcov.info"
    coverage.parent.mkdir()
    coverage.write_text("SF:src/main.c\nDA:1,1\nend_of_record\n", encoding="utf-8")
    unchanged_object = workspace / "input.o"
    unchanged_object.write_bytes(b"unchanged")
    changed_coverage = workspace / "coverage.xml"
    changed_coverage.write_text("<coverage/>", encoding="utf-8")
    before = {
        "reports/lcov.info": file_sha256(coverage),
        "input.o": file_sha256(unchanged_object),
        "coverage.xml": "0" * 64,
    }

    artifacts, gaps = _catalog(tmp_path, workspace, before, 10, "native-unit", "native")

    assert not gaps
    assert [(row["workspace_path"], row["artifact_origin"]) for row in artifacts] == [
        ("coverage.xml", "build-output"),
        ("reports/lcov.info", "accepted-input"),
    ]
    assert {row["kind"] for row in artifacts} == {"test-coverage"}


def test_generic_catalog_retains_imported_and_emitted_profiles(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    imported = workspace / "profiles" / "hot.folded"
    imported.parent.mkdir()
    imported.write_text("root;hot 9\n", encoding="utf-8")
    emitted = workspace / "callgrind.out"
    emitted.write_text("events: Ir\nfn=hot\n1 9\n", encoding="utf-8")
    unchanged_object = workspace / "input.o"
    unchanged_object.write_bytes(b"unchanged")
    before = {"profiles/hot.folded": file_sha256(imported),
              "input.o": file_sha256(unchanged_object)}

    artifacts, gaps = _catalog(tmp_path, workspace, before, 10, "native-unit", "native")

    assert not gaps
    assert [(row["workspace_path"], row["kind"], row["artifact_origin"])
            for row in artifacts] == [
        ("callgrind.out", "execution-profile", "build-output"),
        ("profiles/hot.folded", "execution-profile", "accepted-input"),
    ]


def test_processing_modes_change_language_build_checkpoint_identity() -> None:
    dispatch = {
        "source_fingerprint": "1" * 64, "recipe_identity": "2" * 64,
        "family": "native", "probe_identity": "3" * 64,
        "image": {"dependency_hashes": ["4" * 64], "image_id": "sha256:" + "5" * 64},
    }
    accepted = {"project_build_handoff_sha256": "6" * 64}
    settings = {
        "command_timeout_seconds": 1, "output_bytes": 2, "artifact_count_limit": 3,
        "build_capture": {"mode": "required"},
        "compiler_artifact_collection_mode": "required",
        "compiler_artifact_collection_overrides": {}, "native": {},
    }
    baseline = _fingerprint(dispatch, accepted, settings)
    assert _fingerprint(dispatch, accepted, {
        **settings, "build_capture": {"mode": "auto"}}) != baseline
    assert _fingerprint(dispatch, accepted, {
        **settings, "compiler_artifact_collection_overrides": {"native": "auto"}}) != baseline
    declarations = {"platform": "fixture-platform", "build_toolchain": "fixture-build",
                    "validation": "fixture-validation"}
    released = _fingerprint(dispatch, accepted, settings, releases=ComponentReleases(declarations))
    assert released != baseline
    for component in declarations:
        assert _fingerprint(dispatch, accepted, settings, releases=ComponentReleases({
            **declarations, component: "changed"})) != released
    assert _fingerprint(dispatch, accepted, settings, releases=ComponentReleases({
        **declarations, "queries_python": "unrelated-query-change"})) == released
    assert _fingerprint(dispatch, accepted, settings, build_outputs=BuildOutputPolicy()) == baseline
    policy = parse_build_outputs({"exclusions": [{
        "name": "vendored-out", "patterns": ["vendor-out/"], "reason": "vendored build output"}]})
    assert _fingerprint(dispatch, accepted, settings, build_outputs=policy) != baseline


@pytest.mark.parametrize(("name", "argv", "expected"), [
    ("clang++", ("clang++", "-c", "main.cpp", "-o", "main.o"), "compiler"),
    ("gcc-14", ("gcc-14", "main.o", "-o", "app"), "linker-driver"),
    ("as", ("as", "main.s", "-o", "main.o"), "assembler"),
    ("ld.lld", ("ld.lld", "main.o", "-o", "app"), "linker"),
    ("llvm-ar", ("llvm-ar", "rcs", "libapp.a", "main.o"), "archiver"),
    ("protoc", ("protoc", "--cpp_out", "gen", "schema.proto"), "code-generator"),
    ("cmake", ("cmake", "--build", "build"), "build-driver"),
    ("python", ("python", "build.py"), None),
], ids=["compiler", "linker-driver", "assembler", "linker", "archiver", "generator",
        "build-driver", "unknown"])
def test_native_tool_classification_requires_the_observed_executable(
        name: str, argv: tuple[str, ...], expected: str | None) -> None:
    assert native.tool_kind(name, argv) == expected


def test_captured_stream_identity_retains_complete_file_beyond_preview_limit(
        tmp_path: Path) -> None:
    source = tmp_path / "capture" / "stdout"
    source.parent.mkdir()
    source.write_bytes(b"full-output" * 1024)
    destination = tmp_path / "logs" / "001.stdout"
    destination.parent.mkdir()
    result = BuildCommandResult(
        ("dotnet", "build"), 0, b"full-out", b"", False,
        stdout_bytes=source.stat().st_size, stdout_truncated=True,
        stdout_file=source,
    )

    identity = _stream_identity(tmp_path, destination, result, "stdout", 8)

    assert destination.read_bytes() == source.read_bytes()
    assert identity["storage"] == "complete-file"
    assert identity["captured_bytes"] == identity["total_bytes"] == source.stat().st_size
    assert identity["capture_limit_bytes"] is None
    assert identity["truncated"] is False
    assert identity["preview_limit_bytes"] == 8 and identity["preview_truncated"] is True


@pytest.mark.parametrize("payload", [
    b"\xff", b"{}", b"[{}]",
    json.dumps([{"directory": "/workspace/native", "file": "main.cpp",
                 "arguments": ["clang++", "bad\0arg"]}]).encode(),
], ids=["invalid-utf8", "wrong-top-level", "missing-argv", "nul-argv"])
def test_native_compile_database_malformed_output_is_an_explicit_gap(
        tmp_path: Path, payload: bytes) -> None:
    build = tmp_path / "native" / "build"
    build.mkdir(parents=True)
    (build / "compile_commands.json").write_bytes(payload)
    rows, gaps = _compile_rows(tmp_path, "native", "native/build")
    assert rows == [] and len(gaps) == 1 and "compile database was not parseable" in gaps[0]


@pytest.mark.parametrize("payload", [b"\xff", b"clang++ 'unterminated\n", b"clang++ a.o -o app\n" * 101],
                         ids=["invalid-utf8", "invalid-shell", "too-many-lines"])
def test_native_link_metadata_malformed_output_is_an_explicit_gap(
        tmp_path: Path, payload: bytes) -> None:
    link = tmp_path / "native" / "build" / "CMakeFiles" / "app.dir" / "link.txt"
    link.parent.mkdir(parents=True)
    link.write_bytes(payload)
    rows, gaps = _link_rows(tmp_path, "native/build")
    assert rows == [] and len(gaps) == 1 and "link metadata" in gaps[0]



def test_dotnet_recipe_and_capture_helpers_allow_restore_but_forbid_run(tmp_path: Path) -> None:
    recipe = {"dependency_files": ["Sample.csproj"], "configure_commands": [["dotnet", "restore", "."]],
              "build_commands": [["dotnet", "build", "."]]}
    assert validate_recipe(recipe) == ()
    assert validate_recipe({**recipe, "build_commands": [["dotnet", "run"]]}) == (
        "dotnet subcommand is unsupported: run",)
    assert _dotnet_argv(("dotnet", "build", "Sample.csproj", "--verbosity", "diagnostic")) == (
        "dotnet", "build", "Sample.csproj", "--verbosity", "diagnostic")
    assert artifact_kind(Path("obj/Debug/net8.0/Generated.cs")) == "generated-source"
    native_aot = tmp_path / "native-aot-app"
    native_aot.write_bytes(b"\x7fELFfixture")
    assert artifact_kind(native_aot) == "native-output"
    (tmp_path / "Library.vbproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework>'
        '</PropertyGroup></Project>', encoding="utf-8")
    (tmp_path / "Library.fsproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework>'
        '</PropertyGroup></Project>', encoding="utf-8")
    assert {item["path"] for item in project_topology(tmp_path)[0]} == {"Library.fsproj", "Library.vbproj"}
    assert tool_identity("dotnet", ["dotnet", "exec", "/sdk/Roslyn/bincore/csc.dll"]) == (
        "csc.dll", "compiler")
    assert tool_identity("dotnet", ["dotnet", "build", "Sample.csproj"]) == (
        "dotnet", "build-driver")
    assert tool_identity("python3", ["python3", "tool-wrapper.py", "dotnet"]) is None
