from __future__ import annotations

import json
from pathlib import Path

from appsec_review.config import load_config
from appsec_review.container_runtime import BuildCommandResult, ProjectImage
from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.container_runtime.project_images import dependency_hashes, project_recipe_identity
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_language_build import build_job as build_language, load_accepted_language_build
from appsec_review.jobs.job_language_build.dotnet import artifact_kind, parse_tool_invocations, project_topology, validate_recipe
from appsec_review.mcp import RetrievalMcpAdapter
from appsec_review.retrieval import RetrievalCore
from appsec_review.jobs.job_cpp_compiled_analysis import build_job as build_cpp
from appsec_review.jobs.job_post_build_security_assessment import build_job as build_post_build
from appsec_review.jobs.job_project_build import build_job as build_projects
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_target_analysis_plan import ModelResult, build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.runtime import GraphRunner, plan_jobs
from tests.capture_fakes import capturing_fake


ROOT = Path(__file__).parents[1]


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
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [],
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
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [],
                            "build_recipes": recipes})


class ImageResolver:
    def __init__(self, target: Path):
        self.target = target

    def resolve(self, recipe, profile):
        hashes = dependency_hashes(self.target, recipe)
        identity = project_recipe_identity(recipe, profile, hashes)
        derived_id = "sha256:" + "d" * 64
        return ProjectImage("appsec-review/project-build-image/1", identity, profile.name,
            profile.image_id, "derived-native:local", derived_id, "f" * 64, True, False, hashes), b"", b""


class NativeExecutor:
    def __init__(self, calls: list[tuple[str, ...]], *, fail: bool = False,
                 fail_workdirs: set[str] | None = None):
        self.calls, self.fail = calls, fail
        self.fail_workdirs = fail_workdirs or set()

    def resolve(self):
        return None

    def execute(self, argv, *, workspace, working_directory, environment):
        self.calls.append(tuple(argv))
        if (self.fail or working_directory in self.fail_workdirs) and "--build" in argv:
            return BuildCommandResult(tuple(argv), 2, b"", b"bounded failure", False)
        if "--build" in argv:
            root = workspace / working_directory
            build = root / "build"
            build.mkdir(parents=True, exist_ok=True)
            source = root / "main.cpp"
            obj = build / "main.o"
            binary = build / "sample"
            obj.write_bytes(b"object")
            binary.write_bytes(b"\x7fELFfixture")
            (build / "compile_commands.json").write_text(json.dumps([{
                "directory": f"/workspace/{working_directory}/build", "file": f"/workspace/{working_directory}/main.cpp",
                "arguments": ["clang++", "-g", "-c", f"/workspace/{working_directory}/main.cpp", "-o",
                              f"/workspace/{working_directory}/build/main.o"],
                "output": f"/workspace/{working_directory}/build/main.o",
            }]), encoding="utf-8")
            link = build / "CMakeFiles" / "sample.dir"
            link.mkdir(parents=True)
            (link / "link.txt").write_text(
                f"clang++ {obj.as_posix()} -o {binary.as_posix()}\n", encoding="utf-8")
        return BuildCommandResult(tuple(argv), 0, b"ok", b"", False)


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


class AnalysisExecutor:
    def __init__(self, run_root: Path):
        self.run_root = run_root

    def execute(self, request):
        root = request.scratch_root
        root.mkdir(parents=True, exist_ok=True)
        mode = "infer" if request.tool_id == "tool-infer" else request.argv[1]
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


def _fixture(tmp_path: Path):
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text((ROOT / "appsec-review.toml").read_text(encoding="utf-8"), encoding="utf-8")
    target = tmp_path / "target"
    (target / "native").mkdir(parents=True)
    (target / "native" / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.20)\nproject(sample)\nadd_executable(sample main.cpp)\n",
        encoding="utf-8")
    (target / "native" / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
    return load_config(config_path), target


def _accepted_project(config, target, calls):
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(),
        build_plan(model_client=NativeRecipeModel())]).run(target_root=target, source_fingerprint=fingerprint)
    project = build_projects(executor_factory=lambda unit, profile: capturing_fake(profile, NativeExecutor(calls)),
                             image_resolver_factory=lambda unit: ImageResolver(target))
    GraphRunner(config, [project]).run(target_root=target, source_fingerprint=fingerprint,
                                       run_id=upstream["run_id"])
    return upstream["run_id"], fingerprint


def test_native_dispatch_executes_real_build_and_publishes_provenance(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    calls: list[tuple[str, ...]] = []
    run_id, fingerprint = _accepted_project(config, target, calls)
    outcome = GraphRunner(config, [build_language(
        executor_factory=lambda unit, profile: NativeExecutor(calls))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "COMPLETED_WITH_GAPS"  # loader dependencies are deliberately unobserved.
    accepted = load_accepted_language_build(config.runtime.runs_dir / run_id)
    receipt = accepted["receipts"][0]
    assert receipt["terminal_status"] == "SUCCEEDED"
    assert {item["kind"] for item in receipt["artifacts"]} >= {"object", "executable", "compile-database"}
    assert {item["tool_kind"] for item in receipt["tool_invocations"]} >= {
        "compiler-driver", "compiler-driver-link"}
    assert '"argv":' not in json.dumps(receipt["tool_invocations"])
    protected = config.runtime.runs_dir / run_id / receipt["protected_compile_commands"]["path"]
    assert "clang++" in protected.read_text(encoding="utf-8")
    assert len(calls) == 4  # probe and real build each execute the exact two-command recipe.


def test_native_build_failure_is_a_gap_and_topology_is_generic(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted_project(config, target, [])
    outcome = GraphRunner(config, [build_language(
        executor_factory=lambda unit, profile: NativeExecutor([], fail=True))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    receipt = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"][0]
    assert receipt["terminal_status"] == "FAILED" and receipt["gaps"]
    graph = plan_jobs((build_language(executor_factory=lambda unit, profile: NativeExecutor([])),), config)
    assert graph.node("job_language_build.execute.native").dependencies == (
        "job_language_build.load.native",)
    assert graph.node("job_language_build.execute.dotnet").dependencies == (
        "job_language_build.load.dotnet",)


def test_multiple_native_units_isolate_sibling_failure_and_reuse_checkpoints(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    (target / "sibling").mkdir()
    (target / "sibling" / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.20)\nproject(sibling)\nadd_executable(sibling main.cpp)\n",
        encoding="utf-8")
    (target / "sibling" / "main.cpp").write_text("int main() { return 1; }\n", encoding="utf-8")
    run_id, fingerprint = _accepted_project(config, target, [])
    outcome = GraphRunner(config, [build_language(executor_factory=lambda unit, profile:
        NativeExecutor([], fail_workdirs={"sibling"}))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    receipts = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"]
    assert {item["root"]: item["terminal_status"] for item in receipts} == {
        "native": "SUCCEEDED", "sibling": "FAILED"}

    calls: list[tuple[str, ...]] = []
    resumed = GraphRunner(config, [build_language(executor_factory=lambda unit, profile:
        NativeExecutor(calls))]).run(target_root=target, source_fingerprint=fingerprint,
                                     run_id=run_id, force_from="job_language_build")
    second = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"]
    by_root = {item["root"]: item for item in second}
    assert resumed["status"] == "COMPLETED_WITH_GAPS"
    assert by_root["native"]["checkpoint_reused"] is True
    assert by_root["sibling"]["checkpoint_reused"] is False
    assert calls == [("cmake", "-S", ".", "-B", "build", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                      "-DCMAKE_BUILD_TYPE=RelWithDebInfo"),
                     ("cmake", "--build", "build", "--parallel", "2")]


def test_cpp_analysis_consumes_generic_native_build_without_rebuilding(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    run_id, fingerprint = _accepted_project(config, target, [])
    GraphRunner(config, [build_language(
        executor_factory=lambda unit, profile: NativeExecutor([]))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    outcome = GraphRunner(config, [build_cpp(
        executor_factory=lambda unit: AnalysisExecutor(unit.job.run_root))]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "COMPLETED_WITH_GAPS"  # Joern is unavailable in the fixture.
    result_path = Path(outcome["jobs"]["job_cpp_compiled_analysis"]["attempt_root"]) / "result.json"
    outputs = json.loads(result_path.read_text(encoding="utf-8"))["outputs"]
    assert outputs["catalog.projects"]["project_count"] == 1
    assert outputs["ast.projects"]["project_count"] == 1
    assert outputs["ir.projects"]["project_count"] == 1
    assert outputs["infer.projects"]["project_count"] == 1
    assert outputs["binary.projects"]["project_count"] == 1
    post = GraphRunner(config, [build_post_build()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert post["status"] == "COMPLETED_WITH_GAPS"
    post_result = Path(post["jobs"]["job_post_build_security_assessment"]["attempt_root"]) / "result.json"
    post_outputs = json.loads(post_result.read_text(encoding="utf-8"))["outputs"]
    assert post_outputs["load.accepted_cpp_build"]["cases"].keys() == outputs["catalog.projects"]["projects"].keys()
    assert post_outputs["index.native_units"]["project_count"] == 1


def _dotnet_fixture(tmp_path: Path, *, framework: str = "net8.0"):
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text((ROOT / "appsec-review.toml").read_text(encoding="utf-8"), encoding="utf-8")
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
    return load_config(config_path), target


def _accepted_dotnet(config, target, calls):
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(),
        build_plan(model_client=DotnetRecipeModel())]).run(target_root=target, source_fingerprint=fingerprint)
    project = build_projects(executor_factory=lambda unit, profile: capturing_fake(profile, DotnetExecutor(calls)),
                             image_resolver_factory=lambda unit: ImageResolver(target))
    GraphRunner(config, [project]).run(target_root=target, source_fingerprint=fingerprint,
                                       run_id=upstream["run_id"])
    return upstream["run_id"], fingerprint


def test_dotnet_linux_build_catalogs_outputs_and_sanitized_mcp_evidence(tmp_path: Path) -> None:
    config, target = _dotnet_fixture(tmp_path)
    assert config.job("job_language_build").typed_settings.dotnet.require_locked_restore is False
    calls: list[tuple[str, ...]] = []
    run_id, fingerprint = _accepted_dotnet(config, target, calls)
    outcome = GraphRunner(config, [build_language(
        executor_factory=lambda unit, profile: DotnetExecutor(calls))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "SUCCEEDED"
    receipt = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"][0]
    assert receipt["family"] == "dotnet" and receipt["terminal_status"] == "SUCCEEDED"
    assert {item["kind"] for item in receipt["artifacts"]} >= {
        "managed-assembly", "debug-information", "generated-source",
        "dependency-manifest", "runtime-configuration"}
    assert {item["tool_kind"] for item in receipt["tool_invocations"]} == {"compiler"}
    assert receipt["project_topology"][0]["package_references"] == [{"name": "Example", "version": "1.0.0"}]
    command = receipt["commands"][1]
    assert command["stdout"]["sha256"] and command["stdout"]["capture_limit_bytes"] == 8388608
    mcp = RetrievalMcpAdapter(RetrievalCore(config.runtime.runs_dir, run_id))
    response = mcp.call("search", {"query": "managed-assembly", "indexes": ["build"], "limit": 10})
    rendered = json.dumps(response)
    assert "Sample.dll" in rendered
    assert "protected-commands" not in rendered and "csc.dll /out:" not in rendered


def test_dotnet_windows_only_project_is_explicitly_not_applicable(tmp_path: Path) -> None:
    config, target = _dotnet_fixture(tmp_path, framework="net8.0-windows")
    run_id, fingerprint = _accepted_dotnet(config, target, [])
    GraphRunner(config, [build_language(
        executor_factory=lambda unit, profile: DotnetExecutor([]))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    receipt = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"][0]
    assert receipt["terminal_status"] == "NOT_APPLICABLE"
    assert "Windows-only" in receipt["gaps"][0]


def test_dotnet_failed_build_retains_bounded_diagnostics_as_a_gap(tmp_path: Path) -> None:
    config, target = _dotnet_fixture(tmp_path)
    run_id, fingerprint = _accepted_dotnet(config, target, [])
    outcome = GraphRunner(config, [build_language(
        executor_factory=lambda unit, profile: DotnetExecutor([], fail=True))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    receipt = load_accepted_language_build(config.runtime.runs_dir / run_id)["receipts"][0]
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    assert receipt["terminal_status"] == "FAILED"
    assert receipt["commands"][-1]["stderr"]["sha256"]
    assert any("build command" in gap for gap in receipt["gaps"])


def test_dotnet_missing_accepted_recipe_remains_an_explicit_blocked_receipt(tmp_path: Path) -> None:
    config, target = _dotnet_fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_plan()]).run(
        target_root=target, source_fingerprint=fingerprint)
    project = build_projects(executor_factory=lambda unit, profile: capturing_fake(profile, DotnetExecutor([])),
                             image_resolver_factory=lambda unit: ImageResolver(target))
    GraphRunner(config, [project]).run(target_root=target, source_fingerprint=fingerprint,
                                       run_id=upstream["run_id"])
    outcome = GraphRunner(config, [build_language(
        executor_factory=lambda unit, profile: DotnetExecutor([]))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    receipt = load_accepted_language_build(config.runtime.runs_dir / upstream["run_id"])["receipts"][0]
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    assert receipt["family"] == "dotnet" and receipt["terminal_status"] == "BLOCKED"
    assert "validated inference build recipe is unavailable" in receipt["gaps"]


def test_dotnet_recipe_and_capture_helpers_allow_restore_but_forbid_run(tmp_path: Path) -> None:
    recipe = {"dependency_files": ["Sample.csproj"], "configure_commands": [["dotnet", "restore", "."]],
              "build_commands": [["dotnet", "build", "."]]}
    assert validate_recipe(recipe) == ()
    assert validate_recipe({**recipe, "build_commands": [["dotnet", "run"]]}) == (
        "dotnet subcommand is unsupported: run",)
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
    stream = b'dotnet /sdk/Roslyn/bincore/csc.dll /out:/workspace/bin/Sample.dll source.cs\n'
    assert parse_tool_invocations([stream], tmp_path)[0]["tool_kind"] == "compiler"
