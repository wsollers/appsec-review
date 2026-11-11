from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.config.assurance import ComponentReleases
from appsec_review.config.build_outputs import BuildOutputPolicy, parse_build_outputs
from appsec_review.container_runtime import BuildCommandResult, BuildProfile, ProjectImage
from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.container_runtime.project_images import dependency_hashes, project_recipe_identity
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build, native
from appsec_review.jobs.job_language_build import job as language_build_job
from appsec_review.jobs.job_language_build.dotnet import artifact_kind, project_topology, tool_identity, validate_recipe
from appsec_review.jobs.job_language_build.job import (
    _catalog, _compile_rows, _dotnet_argv, _fingerprint, _kind, _link_rows, _stream_identity,
)
from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.retrieval import RetrievalCore
from appsec_review.jobs.job_cpp_compiled_analysis import build_job as build_cpp
from appsec_review.jobs.job_post_build_security_assessment import build_job as build_post_build
from appsec_review.jobs.job_project_build import build_job as build_projects, load_accepted_builds
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.runtime import GraphRunner, plan_jobs
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import canonical_json, file_sha256
from tests.capture_fakes import (
    SYNTHETIC_SECRET, capturing_fake, fixture_compiler_profiles, minimal_elf, simulated_executor,
)
from tests.test_native_target_enforcement import _elf_header
from tests.release_support import write_release


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


class NativeRecipeModel:
    def complete(self, request, *, timeout_seconds):
        recipes = []
        for unit in request.summary["build_units"]:
            root = unit["root"]
            recipes.append({
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": unit["family"], "source_dir": root, "build_dir": f"{root}/build",
                "system_packages": [], "environment": {"CFLAGS": "-g"},
                "dependency_files": [item["path"] for item in unit["markers"]],
                "configure_commands": [["cmake", "-S", root, "-B", f"{root}/build",
                                        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"]],
                "build_commands": [["cmake", "--build", f"{root}/build"]],
                "expected_outputs": [f"{root}/build"], "network_required": False,
                "reason": "bounded native test recipe",
            })
        return ModelResult({"schema": PROPOSAL_SCHEMA, "action": "final", "hints": [], "abstentions": [],
                            "component_proposals": [],
                            "build_recipes": recipes})


class DotnetRecipeModel:
    def complete(self, request, *, timeout_seconds):
        recipes = []
        for unit in request.summary["build_units"]:
            if unit["family"] != "dotnet":
                continue
            root = unit["root"]
            dependencies = [item["path"] for item in unit["markers"]]
            dependencies.extend(document["path"] for document in unit["descriptor_package"]["documents"]
                                if document["path"].endswith("packages.lock.json"))
            recipes.append({
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": "dotnet", "source_dir": root, "build_dir": f"{root}/obj",
                "system_packages": [], "environment": {"DOTNET_NOLOGO": "1"},
                "dependency_files": sorted(set(dependencies)),
                "configure_commands": [["dotnet", "restore", root, "--locked-mode"]],
                "build_commands": [["dotnet", "build", root, "--no-restore", "-v:diag"]],
                "expected_outputs": [f"{root}/bin", f"{root}/obj"], "network_required": True,
                "reason": "locked Linux SDK build",
            })
        return ModelResult({"schema": PROPOSAL_SCHEMA, "action": "final", "hints": [], "abstentions": [],
                            "component_proposals": [],
                            "build_recipes": recipes})


class ImageResolver:
    def __init__(self, target: Path, *, releases: ComponentReleases | None = None):
        self.target = target
        self.releases = releases

    def resolve(self, recipe, profile):
        hashes = dependency_hashes(self.target, recipe)
        identity = project_recipe_identity(recipe, profile, hashes, releases=self.releases)
        derived_id = "sha256:" + "d" * 64
        return ProjectImage("appsec-review/project-build-image/1", identity, profile.name,
            profile.image_id, "derived-native:local", derived_id, "f" * 64, True, False, hashes), b"", b""


class NativeExecutor:
    def __init__(self, calls: list[tuple[str, ...]], *, fail: bool = False,
                 fail_workdirs: set[str] | None = None, partial_output: bool = False):
        self.calls, self.fail = calls, fail
        self.fail_workdirs = fail_workdirs or set()
        self.partial_output = partial_output

    def resolve(self):
        return None

    def execute(self, argv, *, workspace, working_directory, environment):
        self.calls.append(tuple(argv))
        if (self.fail or working_directory in self.fail_workdirs) and "--build" in argv:
            if self.partial_output:
                output = workspace / working_directory / "build" / "sample"
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(b"partial")
            return BuildCommandResult(tuple(argv), 2, b"", b"bounded failure", False)
        if "--build" not in argv:
            logical = f"/workspace/{working_directory}"
            reply = workspace / working_directory / "build" / ".cmake" / "api" / "v1" / "reply"
            reply.mkdir(parents=True, exist_ok=True)
            (reply / "index-fixture.json").write_text(json.dumps({
                "objects": [{"kind": "codemodel", "jsonFile": "codemodel.json"}]}), encoding="utf-8")
            (reply / "codemodel.json").write_text(json.dumps({
                "paths": {"source": logical, "build": f"{logical}/build"},
                "configurations": [{"directories": [{"source": ".", "build": "."}],
                                    "projects": [{"name": "sample", "directoryIndexes": [0]}]}],
            }), encoding="utf-8")
        if "--build" in argv:
            root = workspace / working_directory
            build = root / "build"
            build.mkdir(parents=True, exist_ok=True)
            source = root / "main.cpp"
            obj = build / "main.o"
            target = re.search(r"add_executable\(\s*([^\s)]+)", (root / "CMakeLists.txt").read_text())[1]
            binary = build / target
            obj.write_bytes(_elf_header("x86_64"))
            binary.write_bytes(minimal_elf(interpreter="/lib64/ld-linux-x86-64.so.2"))
            (build / "compile_commands.json").write_text(json.dumps([{
                # The simulated compiler runs in the recipe's working directory, as its capture records.
                "directory": f"/workspace/{working_directory}", "file": f"/workspace/{working_directory}/main.cpp",
                "arguments": ["clang++", "-g", "-c", f"/workspace/{working_directory}/main.cpp", "-o",
                              f"/workspace/{working_directory}/build/main.o"],
                "output": f"/workspace/{working_directory}/build/main.o",
            }]), encoding="utf-8")
            link = build / "CMakeFiles" / f"{target}.dir"
            link.mkdir(parents=True, exist_ok=True)
            (link / "link.txt").write_text(
                f"clang++ {obj.as_posix()} -o {binary.as_posix()}\n", encoding="utf-8")
        return BuildCommandResult(tuple(argv), 0, b"ok", b"", False)


def native_build_executor(profile, calls: list[tuple[str, ...]], *, fail: bool = False,
                          fail_workdirs: set[str] | None = None,
                          phantom_compiler: bool = False, partial_output: bool = False):
    """The simulated native build container, for whichever job owns the build of a native unit."""
    fake = NativeExecutor(calls, fail=fail, fail_workdirs=fail_workdirs,
                          partial_output=partial_output)

    def behavior(command, workspace, working_directory, environment, simulation):
        simulation.exec("/capture/wrappers/cmake", command)
        simulation.exec("/usr/bin/cmake", command)
        simulation.tool_call("cmake", command[1:], executable="/usr/bin/cmake")
        result = fake.execute(command, workspace=workspace, working_directory=working_directory,
                              environment=environment)
        if "--build" in command and result.exit_code == 0:
            source = f"/workspace/{working_directory}/main.cpp"
            obj = f"/workspace/{working_directory}/build/main.o"
            target = re.search(r"add_executable\(\s*([^\s)]+)",
                               (workspace / working_directory / "CMakeLists.txt").read_text())[1]
            binary = f"/workspace/{working_directory}/build/{target}"
            compiler = ("clang++", "-g", "-c", source, "-o", obj)
            if phantom_compiler:
                simulation.tool_call("clang++", compiler[1:], executable="/usr/bin/clang++")
            else:
                simulation.exec("/capture/wrappers/clang++", compiler)
                simulation.exec("/usr/bin/clang++", compiler)
                simulation.tool_call("clang++", compiler[1:], executable="/usr/bin/clang++")
                linker = ("clang++", obj, "-o", binary)
                simulation.exec("/capture/wrappers/clang++", linker)
                simulation.exec("/usr/bin/clang++", linker)
                simulation.tool_call("clang++", linker[1:], executable="/usr/bin/clang++")
        return (None if result.timed_out else result.exit_code), result.stdout, result.stderr

    executor = simulated_executor(profile, behavior)
    executor.compiler_profiles = lambda **_: fixture_compiler_profiles(profile)
    return executor


def _never_rebuilt(unit, profile):
    pytest.fail("job_language_build repeated a native build that job_project_build owns")


class DotnetExecutor:
    def __init__(self, calls: list[tuple[str, ...]], *, fail: bool = False):
        self.calls, self.fail = calls, fail

    def resolve(self):
        return None

    def execute(self, argv, *, workspace, working_directory, environment):
        self.calls.append(tuple(argv))
        if self.fail and "build" in argv:
            return BuildCommandResult(tuple(argv), 1, b"compile failed", b"CS1000", False)
        if "build" in argv:
            root = workspace / working_directory
            generated = root / "obj" / "Debug" / "net8.0" / "Sample.GlobalUsings.g.cs"
            generated.parent.mkdir(parents=True, exist_ok=True)
            generated.write_text("global using System;\n", encoding="utf-8")
            output = root / "bin" / "Debug" / "net8.0"
            output.mkdir(parents=True, exist_ok=True)
            (output / "Sample.dll").write_bytes(b"MZmanaged")
            (output / "Sample.pdb").write_bytes(b"portable-pdb")
            (output / "Sample.deps.json").write_text("{}", encoding="utf-8")
            (output / "Sample.runtimeconfig.json").write_text("{}", encoding="utf-8")
            line = (f'dotnet /sdk/Roslyn/bincore/csc.dll /out:/workspace/{working_directory}/bin/'
                    f'Debug/net8.0/Sample.dll /workspace/{working_directory}/Program.cs\n')
            return BuildCommandResult(tuple(argv), 0, line.encode(), b"", False)
        return BuildCommandResult(tuple(argv), 0, b"restored", b"", False)


def dotnet_language_executor(profile, calls: list[tuple[str, ...]], *, fail: bool = False,
                             phantom_compiler: bool = False, response_file: bool = False):
    def behavior(command, workspace, working_directory, environment, simulation):
        calls.append(command)
        simulation.exec("/capture/wrappers/dotnet", command)
        simulation.exec("/usr/bin/dotnet", command)
        simulation.tool_call("dotnet", command[1:], executable="/usr/bin/dotnet")
        if "restore" in command:
            simulation.connect("203.0.113.10", 443)
            return 0, b"restored", b""
        if "build" in command:
            root = workspace / working_directory
            if fail:
                return 1, b"compile failed", b"CS1000"
            generated = root / "obj" / "Debug" / "net8.0" / "Sample.GlobalUsings.g.cs"
            generated.parent.mkdir(parents=True, exist_ok=True)
            generated.write_text("global using System;\n", encoding="utf-8")
            output = root / "bin" / "Debug" / "net8.0"
            output.mkdir(parents=True, exist_ok=True)
            (output / "Sample.dll").write_bytes(b"MZmanaged")
            (output / "Sample.pdb").write_bytes(b"portable-pdb")
            (output / "Sample.deps.json").write_text("{}", encoding="utf-8")
            (output / "Sample.runtimeconfig.json").write_text("{}", encoding="utf-8")
            compiler = ("/usr/bin/dotnet", "exec", "/sdk/Roslyn/bincore/csc.dll",
                        f"/out:/workspace/{working_directory}/bin/Debug/net8.0/Sample.dll",
                        f"/workspace/{working_directory}/Program.cs")
            if response_file:
                scratch = root / ".appsec-review-build-scratch.ABC123"
                scratch.mkdir()
                response = scratch / "csc.rsp"
                response.write_bytes(
                    f"/workspace/{working_directory}/Program.cs\n".encode())
                logical = f"/workspace/{working_directory}/.appsec-review-build-scratch.ABC123/csc.rsp"
                compiler = (*compiler, f"@{logical}")
            if phantom_compiler:
                simulation.tool_call("dotnet", compiler[1:], executable="/usr/bin/dotnet")
            else:
                simulation.exec("/usr/bin/dotnet", compiler)
                if response_file:
                    simulation.syscall(
                        f'openat(AT_FDCWD</workspace/{working_directory}>, "{logical}", O_RDONLY)',
                        f"3<{logical}>")
            # A hostile diagnostic line must never create provenance on its own.
            return 0, b"dotnet /unobserved/csc.dll /out:/workspace/phantom.dll phantom.cs\n", b""
        return 0, b"", b""
    return simulated_executor(profile, behavior)


class AnalysisExecutor:
    def __init__(self, run_root: Path):
        self.run_root = run_root

    def execute(self, request):
        root = request.scratch_root
        root.mkdir(parents=True, exist_ok=True)
        mode = "infer" if request.tool_id == "tool-infer" else request.argv[1]
        # Tools run as uid 10001; the inputs the C++ job writes for them must be readable by others.
        tool_input = (root / "compile_commands.json" if mode == "infer" else
                      root / "normalized-compile-commands.json" if mode in {"ast", "ir"} else None)
        if tool_input is not None:
            assert tool_input.stat().st_mode & 0o004, f"{tool_input.name} is unreadable by the tool user"
        if mode in {"ast", "ir"}:
            destination = root / "analysis" / mode
            destination.mkdir(parents=True, exist_ok=True)
            if mode == "ast":
                (destination / "tu-0000.json").write_text(json.dumps({
                    "kind": "TranslationUnitDecl", "inner": [{"id": "0x1", "kind": "FunctionDecl",
                    "name": "main", "loc": {"line": 1, "col": 1}, "type": {"qualType": "int ()"}}]
                }), encoding="utf-8")
            else:
                (destination / "tu-0000.ll").write_text(
                    "define i32 @main() {\nentry:\n  ret i32 0\n}\n", encoding="utf-8")
        if mode == "symbols":
            destination = root / "analysis" / "binary"
            destination.mkdir(parents=True, exist_ok=True)
            (destination / "records.json").write_text(json.dumps([{
                "path": "build/sample", "kind": "executable", "sha256": "f" * 64,
                "symbols": ["main T 0 1"], "metadata": "ELF64 NX PIE",
            }]), encoding="utf-8")
        if mode == "infer":
            destination = root / "infer-out"
            destination.mkdir(parents=True, exist_ok=True)
            (destination / "report.json").write_text("[]", encoding="utf-8")
            (destination / "logs").write_text("Found 1 source file to analyze\n", encoding="utf-8")
        raw = root / "raw"
        raw.mkdir(exist_ok=True)
        stdout, stderr, receipt = raw / "stdout.bin", raw / "stderr.bin", root / "execution.json"
        stdout.write_bytes(b""); stderr.write_bytes(b""); receipt.write_text("{}", encoding="utf-8")
        relative = lambda path: path.relative_to(self.run_root).as_posix()
        digest = "sha256:" + "b" * 64
        return ExecutionResult("appsec-review/container-execution/1", request.tool_id,
            "fixture", digest, digest, "argv", (), {}, "start", "end", 0, False, False,
            False, False, relative(stdout), relative(stderr), relative(receipt))


def _declare_release(repository_root: Path) -> None:
    # Without a measured source release every job identity is undeclared and nothing accepted is
    # reusable, so a later stage would rebuild its producers instead of consuming them.
    write_release(repository_root, builtin_registry().job_ids())


def _fixture(tmp_path: Path, *, declared_releases: bool = True):
    config_path = tmp_path / "appsec-review.toml"
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    if declared_releases:
        text = text.replace("[review_policy.releases]", '[review_policy.releases]\n'
                            'platform = "fixture-platform"\nbuild_toolchain = "fixture-build"\n'
                            'validation = "fixture-validation"', 1)
    text += """
[jobs.job_project_build.settings.variants.native]
configuration = "release"
target_arch = "x86_64"
execution_role = "target"
linkage = "static"
toolchain = "fixture-build"
abi = "native-fixture/1"
"""
    config_path.write_text(text, encoding="utf-8")
    target = tmp_path / "target"
    (target / "native").mkdir(parents=True)
    (target / "native" / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.20)\nproject(sample)\nadd_executable(sample main.cpp)\n",
        encoding="utf-8")
    (target / "native" / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
    _declare_release(tmp_path)
    return load_config(config_path), target


def _accept(config, target, producers):
    """Accept ``producers`` in one graph and return them with the run.

    A graph supplies a job only the handoffs of producers that are in that graph, so every later
    stage names these same producers ahead of its own job; the runner reuses their accepted
    handoffs when their identities still match and reruns them (with these fakes) when not.
    """
    fingerprint = source_fingerprint(target)
    outcome = GraphRunner(config, producers).run(target_root=target, source_fingerprint=fingerprint)
    return outcome["run_id"], fingerprint, producers


def _native_producers(target, calls, **build):
    """Intake through project build; job_project_build runs each independent native unit's build once."""
    return [
        build_intake(), build_catalog(), build_plan(infer=NativeRecipeModel().complete),
        build_projects(executor_factory=lambda unit, profile: native_build_executor(profile, calls, **build),
                       image_resolver_factory=lambda unit: ImageResolver(
                           target, releases=unit.job.review_policy.releases))]


def _accepted_project(config, target, calls, **build):
    return _accept(config, target, _native_producers(target, calls, **build))


def _run_native(config, target, calls, *consumers, **build):
    """Run the native producers and the consumers under test as one graph."""
    fingerprint = source_fingerprint(target)
    outcome = GraphRunner(config, [*_native_producers(target, calls, **build), *consumers]).run(
        target_root=target, source_fingerprint=fingerprint)
    return outcome, fingerprint


def _job_status(outcome, job_id: str) -> str:
    return outcome["jobs"][job_id]["status"]["status"]


def _reasons(receipt) -> list[str]:
    """Gap reasons of a receipt, whose gaps are producer-gap records or (older lanes) plain text."""
    return [gap["reason"] if isinstance(gap, dict) else gap for gap in receipt["gaps"]]


def test_native_dispatch_executes_real_build_and_publishes_provenance(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    calls: list[tuple[str, ...]] = []
    outcome, _ = _run_native(config, target, calls, build_language(executor_factory=_never_rebuilt))
    run_id = outcome["run_id"]
    # The delivery status of the built executable is deliberately unobserved.
    assert _job_status(outcome, "job_language_build") == "COMPLETED_WITH_GAPS"
    accepted = load_accepted_language_build(config.runtime.runs_dir / run_id)
    receipt = accepted["receipts"][0]
    assert receipt["terminal_status"] == "SUCCEEDED"
    assert {item["kind"] for item in receipt["artifacts"]} >= {"object", "executable", "compile-database"}
    assert {item["tool_kind"] for item in receipt["tool_invocations"]} >= {
        "compiler", "linker-driver"}
    assert all(item["mapping"].startswith("syscall-process-exec")
               for item in receipt["tool_invocations"])
    assert receipt["capture_provenance"]["complete"] is True
    assert receipt["capture_provenance"]["observed_tool_kinds"] >= ["build-driver", "compiler"]
    assert all(command["execution_capture"]["complete"] for command in receipt["commands"])
    assert '"argv":' not in json.dumps(receipt["tool_invocations"])
    protected = config.runtime.runs_dir / run_id / receipt["protected_compile_commands"]["path"]
    assert "clang++" in protected.read_text(encoding="utf-8")
    assert len(calls) == 2


@pytest.mark.parametrize("scenario", ["blocked", "succeeded", "failed"])
def test_iterative_receipts_reach_accepted_artifact_index(
        tmp_path: Path, scenario: str) -> None:
    from appsec_review.jobs.job_artifact_indexing import (
        build_job as build_artifact_index, load_accepted_artifact_index,
    )

    config, target = _fixture(tmp_path, declared_releases=scenario != "blocked")
    calls = []
    outcome, _ = _run_native(
        config, target, calls, build_language(executor_factory=_never_rebuilt), build_artifact_index(),
        fail=scenario == "failed", partial_output=True)
    run = config.runtime.runs_dir / outcome["run_id"]
    receipts = load_accepted_language_build(run)["receipts"]
    assert len(receipts) == 1
    receipt = receipts[0]
    assert receipt["terminal_status"] == scenario.upper()
    if scenario == "blocked":
        assert not calls and not receipt["artifacts"] and not receipt["commands"]
        assert any("missing release evidence" in gap for gap in _reasons(receipt))

    assert _job_status(outcome, "job_artifact_indexing") == "COMPLETED_WITH_GAPS"
    accepted = load_accepted_artifact_index(run)
    assert accepted["artifact_count"] == len(receipt["artifacts"])
    assert all(f"{receipt['build_unit_id']}: {gap}" in accepted["gaps"]
               for gap in _reasons(receipt))


def test_unsupported_and_unresolved_iteration_receipts_survive_publication(tmp_path: Path) -> None:
    from tests.test_project_build_capture import CASE, _run
    from appsec_review.jobs.job_artifact_indexing.job import _validate_receipts
    run, _, document, calls, _ = _run(tmp_path, "multiple", consume=True)
    accepted = json.loads((run / "data/jobs/job_language_build/attempts/attempt_0001/"
                          "steps/execute/tasks/native/result.json").read_bytes())
    receipts = {item["root"]: item for item in accepted["receipts"]}
    assert set(receipts) == {CASE, "unsupported", "unresolved"}
    assert len(calls) == 2
    assert receipts[CASE]["terminal_status"] == "SUCCEEDED"
    assert receipts[CASE]["enforcement"][0]["proof_kind"] == "captured_invocation"
    for root, reason in (("unsupported", "unavailable_native_project_toolchain"),
                         ("unresolved", "unresolved_ownership")):
        receipt = receipts[root]
        assert receipt["terminal_status"] == "BLOCKED" and not receipt["artifacts"] and not receipt["commands"]
        assert any(reason in gap for gap in receipt["gaps"])
    assert "unenforced_native_target" not in json.dumps(accepted)
    _, gaps = _validate_receipts(run, document["source_fingerprint"], accepted["receipts"])
    assert any("unavailable_native_project_toolchain" in gap for gap in gaps)
    assert any("unresolved_ownership" in gap for gap in gaps)


def test_controller_dispatches_registered_dagster_iterations_and_reexecutes_promoted_recipe(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import uuid
    from appsec_review.container_runtime import build_executor
    from appsec_review.jobs.build_iterations import (
        captured_replay, decode_replay_context, failure_context, read_reference, select_promotion,
    )
    from appsec_review.jobs.build_recipe_replay import RecipeCandidate, replay_recipe
    from appsec_review.jobs.build_workspace import BuildWorkspace

    config, target = _fixture(tmp_path)
    sibling = target / "sibling"
    sibling.mkdir()
    (sibling / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.20)\nproject(sibling)\n"
        "add_executable(sibling main.cpp)\n")
    (sibling / "main.cpp").write_text("int main() { return 1; }\n")
    run_id, fingerprint, producers = _accepted_project(config, target, [])
    run = config.runtime.runs_dir / run_id
    dispatch = load_accepted_builds(run)["build_dispatches"][0]
    profile = BuildProfile("native", dispatch["image"]["image_tag"],
                           dispatch["image"]["image_id"], dispatch["image"]["user"])
    calls = []
    launched = []
    failed = {"sibling"}
    docker = native_build_executor(profile, calls, fail_workdirs=failed).runner

    def boundary(argv, timeout):
        assert tuple(argv[:2]) in {
            ("docker", "image"), ("docker", "run"), ("docker", "inspect"), ("docker", "rm")}
        launched.append(tuple(argv))
        return docker(argv, timeout)

    def files(argv, timeout, stdout, stderr):
        code, out, err, expired = boundary(argv, timeout)
        stdout.write_bytes(out)
        stderr.write_bytes(err)
        return code, expired

    monkeypatch.setattr(build_executor, "_run", boundary)
    monkeypatch.setattr(build_executor, "_run_to_files", files)
    first = GraphRunner(config, [*producers, build_language()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert first["status"] == "COMPLETED_WITH_GAPS"
    receipts = {item["root"]: item for item in load_accepted_language_build(run)["receipts"]}
    assert {root: item["terminal_status"] for root, item in receipts.items()} == {
        "native": "SUCCEEDED", "sibling": "FAILED"}
    requests = list((run / "artifacts/build/iterations/requests").glob("*.json"))
    assert len(requests) == 2
    immutable_requests = {path: path.read_bytes() for path in requests}
    run_ids = {item["dagster_run_id"] for item in receipts.values()}
    assert len(run_ids) == 2
    assert all(str(uuid.UUID(value)) == value for value in run_ids)
    attempts = sorted((run / "data/jobs/job_build_iteration/attempts").iterdir())
    assert len(attempts) == 2
    statuses = [json.loads((attempt / "status.json").read_bytes()) for attempt in attempts]
    assert {status["orchestration"]["run_id"] for status in statuses} == run_ids
    for attempt in attempts:
        if (attempt / "result.json").is_file():
            result = json.loads((attempt / "result.json").read_bytes())
            assert result["outputs"]["execute.node"]["terminal_status"] == "SUCCEEDED"
    # The failed worker is still a real registered invocation; its job records failure, not success.
    assert sum(status["status"] == "FAILED" for status in statuses) == 1

    workspace = BuildWorkspace(run)
    native_bytes = (workspace.paths.target / "native/build/sample").read_bytes()
    assert not (workspace.paths.target / "sibling/build/sibling").exists()
    node_id = receipts["sibling"]["build_unit_id"]
    graph = load_accepted_builds(run)["execution_graph"]
    node = next(item for item in graph["nodes"] if item["build_unit_id"] == node_id)
    products = [{"path": "target/sibling/build/sibling", **product} for product in node["products"]]
    context_ref = failure_context(run, node_id, products)
    context = decode_replay_context(read_reference(run, context_ref))
    revised = {**context.accepted_recipe, "build_commands": [
        [*context.accepted_recipe["build_commands"][0], "--verbose"]]}
    candidate = RecipeCandidate(revised, (context.inputs["graph"],), "retry with verbose build")
    failed.clear()
    trial = replay_recipe(
        workspace, context, candidate, execute=lambda invocation: captured_replay(config, context, invocation))
    assert read_reference(run, trial)["status"] == "SUCCEEDED"
    assert not (workspace.paths.target / "sibling/build/sibling").exists()
    select_promotion(run, context.view(), trial)
    resumed = GraphRunner(config, [*producers, build_language()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id, force_from="job_language_build")
    assert resumed["status"] == "COMPLETED_WITH_GAPS"
    final = {item["root"]: item for item in load_accepted_language_build(run)["receipts"]}
    assert all(item["terminal_status"] == "SUCCEEDED" for item in final.values())
    assert final["native"]["checkpoint_reused"] is True
    assert final["native"]["dagster_run_id"] == receipts["native"]["dagster_run_id"]
    assert final["sibling"]["dagster_run_id"] not in run_ids
    assert "--verbose" in revised["build_commands"][0]
    assert [item for item in calls if "--build" in item] == [
        ("cmake", "--build", "build", "--parallel", "2"),
        ("cmake", "--build", "build", "--parallel", "2"),
        ("cmake", "--build", "build", "--parallel", "2", "--verbose"),
        ("cmake", "--build", "build", "--parallel", "2", "--verbose")]
    assert (workspace.paths.target / "native/build/sample").read_bytes() == native_bytes
    assert (workspace.paths.target / "sibling/build/sibling").is_file()
    assert all(path.read_bytes() == content for path, content in immutable_requests.items())
    assert not tuple(target.rglob("build"))
    assert launched
    from appsec_review import cli
    ledger = json.loads((run / "data/build/iterations/ledger.json").read_bytes())
    completed = read_reference(run, ledger["nodes"][node_id]["completion"])
    reference = completed["request"]
    arguments = ["--config", str(tmp_path / "appsec-review.toml"), "run", "job_build_iteration",
                 "--run-id", run_id, "--iteration-request"]
    before_delivery = list(launched)
    with pytest.raises(RuntimeError, match="build iteration invocation failed"):
        cli.main([*arguments, json.dumps(reference)])
    with pytest.raises(ValueError):
        cli.main([*arguments, json.dumps({**reference, "sha256": "0" * 64})])
    assert launched == before_delivery


def test_native_compile_database_and_wrapper_without_exec_are_not_provenance(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    outcome, _ = _run_native(config, target, [], build_language(executor_factory=_never_rebuilt),
                             phantom_compiler=True)
    assert _job_status(outcome, "job_language_build") == "COMPLETED_WITH_GAPS"
    receipt = load_accepted_language_build(config.runtime.runs_dir / outcome["run_id"])["receipts"][0]
    assert "compiler" not in {item["tool_kind"] for item in receipt["tool_invocations"]}
    assert receipt["capture_provenance"]["unreconciled_tool_calls"] == 1
    assert receipt["capture_provenance"]["complete"] is False
    assert any("no matching successful process-exec" in gap for gap in _reasons(receipt))
    assert any("compiler execution was not observed" in gap for gap in _reasons(receipt))
    assert not tuple((config.runtime.metadata_dir / "language-builds").glob("*/accepted.json"))


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


def test_native_build_failure_is_a_gap_and_topology_is_generic(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    outcome, _ = _run_native(config, target, [], build_language(executor_factory=_never_rebuilt),
                             fail=True, partial_output=True)
    assert _job_status(outcome, "job_language_build") == "COMPLETED_WITH_GAPS"
    receipt = load_accepted_language_build(config.runtime.runs_dir / outcome["run_id"])["receipts"][0]
    assert receipt["terminal_status"] == "FAILED" and receipt["gaps"]
    assert receipt["artifacts"] == []
    graph = plan_jobs((build_language(executor_factory=lambda unit, profile: NativeExecutor([])),), config)
    assert graph.node("job_language_build.execute.native").dependencies == (
        "job_language_build.load.native",)
    assert graph.node("job_language_build.execute.dotnet").dependencies == (
        "job_language_build.load.dotnet",)


def test_dispatch_validation_is_scoped_to_the_consuming_family(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint, producers = _accepted_project(config, target, [])
    run_root = config.runtime.runs_dir / run_id
    accepted = dict(load_accepted_builds(run_root))
    native_dispatch = deepcopy(accepted["build_dispatches"][0])

    bad_id = "build-unit-" + "f" * 20
    bad_dispatch = deepcopy(native_dispatch)
    bad_dispatch.update(build_unit_id=bad_id, family="java")
    # Only a native dispatch is bound to a project-build receipt; a Java unit is the language build's.
    bad_dispatch.update(execution_owner="job_language_build")
    for native_binding in ("build_receipt_sha256", "enforcement"):
        bad_dispatch.pop(native_binding, None)
    bad_dispatch["recipe"].update(build_unit_id=bad_id, image_profile="node")
    dependencies = bad_dispatch["image"]["dependency_hashes"]
    profile = BuildProfile("java", bad_dispatch["image"]["image_tag"],
                           bad_dispatch["image"]["base_image_id"], bad_dispatch["image"]["user"])
    bad_identity = project_recipe_identity(
        {**bad_dispatch["recipe"], "build_system": bad_dispatch["build_system"]},
        profile, dependencies, releases=config.review_policy.releases)
    bad_dispatch["recipe_identity"] = bad_identity
    preparation = {**deepcopy(accepted["images"]["native"]["entries"][0]),
                   "action": deepcopy(bad_dispatch), "image": bad_dispatch["image"]}
    bad_dispatch["preparation_identity"] = hashlib.sha256(canonical_json(preparation)).hexdigest()
    accepted["build_dispatches"] = [native_dispatch, bad_dispatch]
    accepted["images"]["java"] = {"entries": [preparation]}
    monkeypatch.setattr(language_build_job, "load_accepted_builds",
                        lambda _run_root, **_options: accepted)
    unit = SimpleNamespace(job=SimpleNamespace(
        run_root=run_root, target_root=target, source_fingerprint=fingerprint,
        review_policy=config.review_policy))

    dispatches, _document = language_build_job._dispatches(
        unit, families=frozenset({"native"}))

    assert [item["build_unit_id"] for item in dispatches] == [native_dispatch["build_unit_id"]]
    with pytest.raises(ValueError, match="recipe image_profile must equal required profile"):
        language_build_job._dispatches(unit, families=frozenset({"java"}))


@pytest.mark.parametrize("declared_releases", [False, True])
def test_multiple_native_units_isolate_sibling_failure_and_reuse_checkpoints(
        tmp_path: Path, declared_releases: bool) -> None:
    from collections import Counter
    config, target = _fixture(tmp_path, declared_releases=declared_releases)
    (target / "sibling").mkdir()
    (target / "sibling" / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.20)\nproject(sibling)\nadd_executable(sibling main.cpp)\n",
        encoding="utf-8")
    (target / "sibling" / "main.cpp").write_text("int main() { return 1; }\n", encoding="utf-8")
    failed = {"sibling"}
    calls: list[tuple[str, ...]] = []
    graph = GraphRunner(config, [*_native_producers(target, calls, fail_workdirs=failed),
                                 build_language(executor_factory=_never_rebuilt)])
    fingerprint = source_fingerprint(target)
    outcome = graph.run(target_root=target, source_fingerprint=fingerprint)
    run_id = outcome["run_id"]
    assert _job_status(outcome, "job_language_build") == "COMPLETED_WITH_GAPS"
    receipts = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"]
    if not declared_releases:
        assert {item["terminal_status"] for item in receipts} == {"BLOCKED"}
        assert all(any("missing release evidence" in gap for gap in _reasons(item)) for item in receipts)
        return
    assert {item["root"]: item["terminal_status"] for item in receipts} == {
        "native": "SUCCEEDED", "sibling": "FAILED"}
    from appsec_review.runtime.handoff import verify_handoff_integrity
    run_root = config.runtime.runs_dir / run_id
    latest = json.loads((run_root / "data" / "jobs" / "job_language_build" / "latest.json").read_text())
    first_handoff = json.loads((run_root / latest["handoff_path"]).read_text())
    first_by_root = {item["root"]: item for item in receipts}

    # job_project_build owns these builds, so the rerun is forced from it with the sibling repaired.
    failed.clear()
    calls.clear()
    resumed = graph.run(target_root=target, source_fingerprint=fingerprint, run_id=run_id,
                        force_from="job_project_build")
    second = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"]
    by_root = {item["root"]: item for item in second}
    verify_handoff_integrity(run_root, first_handoff)
    assert _job_status(resumed, "job_language_build") == "COMPLETED_WITH_GAPS"
    assert by_root["native"]["checkpoint_reused"] is declared_releases
    assert by_root["sibling"]["checkpoint_reused"] is False
    assert (by_root["native"]["workspace"] == first_by_root["native"]["workspace"]) is declared_releases
    assert by_root["sibling"]["workspace"] == first_by_root["native"]["workspace"]
    expected = [("cmake", "-S", ".", "-B", "build", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                      "-DCMAKE_BUILD_TYPE=RelWithDebInfo"),
                ("cmake", "--build", "build", "--parallel", "2")]
    assert Counter(calls) == Counter(expected * (1 if declared_releases else 2))
    for root, receipt in by_root.items():
        assert [item["ordinal"] for item in receipt["commands"]] == [1, 2]
        assert [item["working_directory"] for item in receipt["commands"]] == [root, root]
        assert [item["argv_sha256"] for item in receipt["commands"]] == [
            hashlib.sha256(canonical_json(list(argv))).hexdigest() for argv in expected]


def test_cpp_analysis_consumes_generic_native_build_without_rebuilding(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    outcome, _ = _run_native(
        config, target, [], build_language(executor_factory=_never_rebuilt),
        build_cpp(executor_factory=lambda unit: AnalysisExecutor(unit.job.run_root)), build_post_build())
    run_id = outcome["run_id"]
    # Joern runs in the independent job_cpg_analysis, so the compiled analysis itself is complete.
    assert _job_status(outcome, "job_cpp_compiled_analysis") == "COMPLETED_WITH_GAPS"
    result_path = Path(outcome["jobs"]["job_cpp_compiled_analysis"]["attempt_root"]) / "result.json"
    outputs = json.loads(result_path.read_text(encoding="utf-8"))["outputs"]
    assert outputs["catalog.projects"]["project_count"] == 1
    assert outputs["ast.projects"]["project_count"] == 1
    assert outputs["ir.projects"]["project_count"] == 1
    assert outputs["infer.projects"]["project_count"] == 1
    assert outputs["binary.projects"]["project_count"] == 1
    run_root = config.runtime.runs_dir / run_id
    project_id = next(iter(outputs["catalog.projects"]["projects"]))
    build_receipt = outputs["catalog.projects"]["projects"][project_id]["build_receipt"]
    assert all(file_sha256(run_root / artifact["path"]) == artifact["sha256"]
               for artifact in build_receipt["artifacts"])
    for branch in ("ast.projects", "ir.projects", "binary.projects"):
        identity = outputs[branch]["projects"][project_id]["artifact"]
        path = run_root / identity["path"]
        assert path.is_file() and path.stat().st_size == identity["size_bytes"]
        assert file_sha256(path) == identity["sha256"]
    assert _job_status(outcome, "job_post_build_security_assessment") == "COMPLETED_WITH_GAPS"
    post_result = Path(outcome["jobs"]["job_post_build_security_assessment"]["attempt_root"]) / "result.json"
    post_outputs = json.loads(post_result.read_text(encoding="utf-8"))["outputs"]
    assert post_outputs["load.accepted_cpp_build"]["cases"].keys() == outputs["catalog.projects"]["projects"].keys()
    assert post_outputs["index.native_units"]["project_count"] == 1


def _dotnet_fixture(tmp_path: Path, *, framework: str = "net8.0"):
    config_path = tmp_path / "appsec-review.toml"
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8").replace(
        "[review_policy.releases]", '[review_policy.releases]\n'
        'platform = "fixture-platform"\nbuild_toolchain = "fixture-build"\nvalidation = "fixture-validation"', 1)
    config_path.write_text(text, encoding="utf-8")
    target = tmp_path / "target"
    project = target / "dotnet"
    project.mkdir(parents=True)
    (project / "Sample.csproj").write_text(
        f'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>{framework}</TargetFramework>'
        '</PropertyGroup><ItemGroup><PackageReference Include="Example" Version="1.0.0" />'
        '</ItemGroup></Project>', encoding="utf-8")
    (project / "packages.lock.json").write_text('{"version":1,"dependencies":{}}', encoding="utf-8")
    (project / "Program.cs").write_text("public static class Program { public static void Main() {} }\n",
                                         encoding="utf-8")
    _declare_release(tmp_path)
    return load_config(config_path), target


def _accepted_dotnet(config, target, calls):
    return _accept(config, target, [
        build_intake(), build_catalog(), build_plan(infer=DotnetRecipeModel().complete),
        build_projects(executor_factory=lambda unit, profile: dotnet_language_executor(profile, calls),
                       image_resolver_factory=lambda unit: ImageResolver(
                           target, releases=unit.job.review_policy.releases))])


def test_dotnet_linux_build_catalogs_outputs_and_sanitized_mcp_evidence(tmp_path: Path) -> None:
    config, target = _dotnet_fixture(tmp_path)
    assert config.job("job_language_build").typed_settings.dotnet.require_locked_restore is False
    calls: list[tuple[str, ...]] = []
    run_id, fingerprint, producers = _accepted_dotnet(config, target, calls)
    outcome = GraphRunner(config, [*producers, build_language(
        executor_factory=lambda unit, profile: dotnet_language_executor(profile, calls))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    receipt = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"][0]
    assert receipt["family"] == "dotnet" and receipt["terminal_status"] == "SUCCEEDED"
    assert {item["kind"] for item in receipt["artifacts"]} >= {
        "managed-assembly", "debug-information", "generated-source",
        "dependency-manifest", "runtime-configuration"}
    assert {item["tool_kind"] for item in receipt["tool_invocations"]} >= {"compiler", "build-driver"}
    assert all(item["mapping"].startswith("syscall-process-exec")
               for item in receipt["tool_invocations"])
    assert receipt["capture_provenance"]["complete"] is True
    assert receipt["capture_provenance"]["connect_events"] == 1
    assert not any("phantom" in json.dumps(item) for item in receipt["tool_invocations"])
    assert receipt["project_topology"][0]["package_references"] == [{"name": "Example", "version": "1.0.0"}]
    command = receipt["commands"][1]
    assert command["stdout"]["sha256"]
    assert command["stdout"]["storage"] == "complete-file"
    assert command["stdout"]["capture_limit_bytes"] is None
    assert command["stdout"]["preview_limit_bytes"] == 8388608
    assert command["stdout"]["truncated"] is False
    mcp = RetrievalMcpAdapter(RetrievalCore(config.runtime.runs_dir, run_id))
    response = mcp.call("search", {"query": "managed-assembly", "indexes": ["build"], "limit": 10})
    rendered = json.dumps(response)
    assert "Sample.dll" in rendered
    assert "protected-commands" not in rendered and "csc.dll /out:" not in rendered


def test_dotnet_rsp_containment(tmp_path: Path) -> None:
    config, target = _dotnet_fixture(tmp_path)
    calls: list[tuple[str, ...]] = []
    run_id, fingerprint, producers = _accepted_dotnet(config, target, calls)
    outcome = GraphRunner(config, [*producers, build_language(executor_factory=lambda unit, profile:
        dotnet_language_executor(profile, calls, response_file=True))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    run_root = config.runtime.runs_dir / run_id
    receipt = load_accepted_language_build(run_root)["receipts"][0]
    provenance = receipt["capture_provenance"]
    assert provenance["complete"] is True
    assert provenance["response_file_records"] == 1
    assert provenance["response_file_references"] == 1
    assert provenance["response_file_bytes"] > 0
    records = [json.loads(path.read_text(encoding="utf-8"))
               for path in run_root.glob("data/build/dotnet/units/*/attempts/*/execution-capture/*/record.json")]
    (response,) = [item for record in records for item in record["response_files"]["records"]]
    retained = next(run_root.glob(
        "data/build/dotnet/units/*/attempts/*/execution-capture/*/response-files/*.rsp"))
    assert response["path"].endswith("/.appsec-review-build-scratch.ABC123/csc.rsp")
    assert response["sha256"] == hashlib.sha256(retained.read_bytes()).hexdigest()
    assert response["size_bytes"] == retained.stat().st_size


def test_dotnet_windows_only_project_is_explicitly_not_applicable(tmp_path: Path) -> None:
    config, target = _dotnet_fixture(tmp_path, framework="net8.0-windows")
    run_id, fingerprint, producers = _accepted_dotnet(config, target, [])
    GraphRunner(config, [*producers, build_language(
        executor_factory=lambda unit, profile: DotnetExecutor([]))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    receipt = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"][0]
    assert receipt["terminal_status"] == "NOT_APPLICABLE"
    assert "Windows-only" in receipt["gaps"][0]


def test_dotnet_failed_build_retains_bounded_diagnostics_as_a_gap(tmp_path: Path) -> None:
    config, target = _dotnet_fixture(tmp_path)
    run_id, fingerprint, producers = _accepted_dotnet(config, target, [])
    outcome = GraphRunner(config, [*producers, build_language(
        executor_factory=lambda unit, profile: dotnet_language_executor(profile, [], fail=True))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    receipt = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"][0]
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    assert receipt["terminal_status"] == "FAILED"
    assert receipt["commands"][-1]["stderr"]["sha256"]
    assert any("build command" in gap for gap in receipt["gaps"])


def test_dotnet_wrapper_record_without_successful_exec_is_a_provenance_gap(tmp_path: Path) -> None:
    config, target = _dotnet_fixture(tmp_path)
    run_id, fingerprint, producers = _accepted_dotnet(config, target, [])
    outcome = GraphRunner(config, [*producers, build_language(executor_factory=lambda unit, profile:
        dotnet_language_executor(profile, [], phantom_compiler=True))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    receipt = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"][0]
    assert "compiler" not in {item["tool_kind"] for item in receipt["tool_invocations"]}
    provenance = receipt["capture_provenance"]
    assert provenance["unreconciled_tool_calls"] == 1 and provenance["complete"] is False
    assert any("no matching successful process-exec" in gap for gap in receipt["gaps"])
    assert any("compiler execution was not observed" in gap for gap in receipt["gaps"])
    assert not tuple((config.runtime.metadata_dir / "language-builds").glob("*/accepted.json"))


def test_dotnet_envp_secret_is_redacted_scanned_and_never_retained(tmp_path: Path) -> None:
    class SecretEnvironment:
        def __init__(self, inner):
            self.inner = inner

        def resolve(self):
            return self.inner.resolve()

        def execute_captured(self, argv, *, environment, **options):
            return self.inner.execute_captured(
                argv, environment={**environment, "GITHUB_TOKEN": SYNTHETIC_SECRET}, **options)

    config, target = _dotnet_fixture(tmp_path)
    run_id, fingerprint, producers = _accepted_dotnet(config, target, [])
    outcome = GraphRunner(config, [*producers, build_language(executor_factory=lambda unit, profile:
        SecretEnvironment(dotnet_language_executor(profile, [])))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    run_root = config.runtime.runs_dir / run_id
    receipt = load_accepted_language_build(run_root)["receipts"][0]
    assert receipt["capture_provenance"]["redacted_exec_events"] == 0
    assert receipt["capture_provenance"]["complete"] is True
    assert "GITHUB_TOKEN" in receipt["capture_provenance"]["envp_redacted_names"]
    assert all(command["execution_capture"]["secret_findings"]["count"] > 0
               for command in receipt["commands"])
    assert not any(SYNTHETIC_SECRET.encode() in path.read_bytes()
                   for path in run_root.rglob("*") if path.is_file())
    assert (run_root / "data/build/iterations/ledger.json").is_file()


def test_dotnet_missing_accepted_recipe_remains_an_explicit_blocked_receipt(tmp_path: Path) -> None:
    config, target = _dotnet_fixture(tmp_path)
    run_id, fingerprint, producers = _accept(config, target, [
        build_intake(), build_catalog(), build_plan(),
        build_projects(executor_factory=lambda unit, profile: capturing_fake(profile, DotnetExecutor([])),
                       image_resolver_factory=lambda unit: ImageResolver(
                           target, releases=unit.job.review_policy.releases))])
    outcome = GraphRunner(config, [*producers, build_language(
        executor_factory=lambda unit, profile: DotnetExecutor([]))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    receipt = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"][0]
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    assert receipt["family"] == "dotnet" and receipt["terminal_status"] == "BLOCKED"
    assert any("validated inference build recipe is unavailable" in gap for gap in receipt["gaps"])


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


class UnavailableImageResolver:
    """The base build image cannot be resolved, as on a host without the pinned images."""

    def resolve(self, recipe, profile):
        raise ValueError(f"base build image identity changed: {profile.name}")


def _blocked_producers():
    return [
        build_intake(), build_catalog(), build_plan(infer=NativeRecipeModel().complete),
        build_projects(executor_factory=lambda unit, profile: capturing_fake(profile, NativeExecutor([])),
                       image_resolver_factory=lambda unit: UnavailableImageResolver())]


def test_failed_native_project_build_is_a_named_gap_in_every_native_lane_job(tmp_path: Path) -> None:
    # A planned native unit that job_project_build could not build must not read as "no native
    # code": language build, compiled analysis, Clang and the symbol index each name the unit, the
    # upstream failure and the failing job, and none of them is SUCCEEDED or NOT_APPLICABLE.
    from appsec_review.jobs.job_clang_static_analysis import build_job as build_clang
    from appsec_review.jobs.job_cpp_symbol_index import build_job as build_symbols

    config, target = _fixture(tmp_path)
    outcome = GraphRunner(config, [
        *_blocked_producers(), build_language(), build_cpp(), build_clang(), build_symbols()]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    run_root = config.runtime.runs_dir / outcome["run_id"]
    preparation = load_accepted_builds(run_root)["images"]["native"]["entries"][0]
    assert preparation["action"]["family"] == "native" and preparation["terminal_status"] == "FAILED"
    unit_id = preparation["action"]["build_unit_id"]
    receipt = load_accepted_language_build(run_root)["receipts"][0]
    assert receipt["build_unit_id"] == unit_id and receipt["terminal_status"] == "BLOCKED"
    assert receipt["upstream_failure"]["job_id"] == "job_project_build"
    assert "base build image identity changed: native" in receipt["upstream_failure"]["reason"]
    for job_id in ("job_language_build", "job_cpp_compiled_analysis", "job_clang_static_analysis",
                   "job_cpp_symbol_index"):
        status = outcome["jobs"][job_id]["status"]["status"]
        assert status == "COMPLETED_WITH_GAPS", (job_id, status)
        outputs = json.loads(
            (Path(outcome["jobs"][job_id]["attempt_root"]) / "result.json").read_bytes())["outputs"]
        gaps = [gap for output in outputs.values() for gap in output.get("gaps", ())]
        assert any(unit_id in gap and "job_project_build" in gap and "base build image identity changed" in gap
                   for gap in gaps), (job_id, gaps)


def test_target_without_native_units_keeps_the_native_lane_not_applicable(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    for path in sorted((target / "native").iterdir()):
        path.unlink()
    (target / "native").rmdir()
    (target / "notes.md").write_text("# Notes\n\nPlain text only.\n", encoding="utf-8")
    outcome, _ = _run_native(config, target, [], build_language(), build_cpp())
    language = outcome["jobs"]["job_language_build"]["handoff"]["outputs"]
    assert language["execute.native"]["terminal_status"] == "NOT_APPLICABLE"
    assert language["execute.native"].get("gaps", []) == []
    compiled = outcome["jobs"]["job_cpp_compiled_analysis"]["handoff"]["outputs"]
    assert compiled["plan.accepted_cpp_plan"]["terminal_status"] == "NOT_APPLICABLE"
    assert outcome["jobs"]["job_cpp_compiled_analysis"]["status"]["status"] == "SUCCEEDED"
