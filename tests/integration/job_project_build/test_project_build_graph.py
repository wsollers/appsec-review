"""job_project_build: the pre-walk whole-graph suite, moved out of the unit path by T-113.

Every case runs the intake, catalog, plan and project-build jobs through GraphRunner with fake
executors and image resolvers; several take ten minutes or more. They are integration tests
pending replacement by the code-level tests in tests/unit/job_project_build/ and run only when
named explicitly (``scripts/run-tests.sh --allow-heavy -- <file>``).
"""
from __future__ import annotations

from dataclasses import replace
import json
import hashlib
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest

from appsec_review.config import ProcessingMode, load_config
from tests.release_support import declare_releases
from appsec_review.container_runtime import BuildCommandResult, ProjectImage, ProjectImageResolver
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_project_build import build_job as build_projects, load_accepted_builds
from appsec_review.jobs.job_project_build.job import (
    _copy_source, _deterministic_jvm_recipe, _node_recipe_restores_dependencies,
    _probe_cache, _probe_environment,
    _validate_expected_outputs,
)
from appsec_review.jobs.build_discovery import ensure_declared_build_dir
from appsec_review.jobs.job_language_build.wasm import _copy_source as _copy_wasm_source
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_project_build.repair import REPAIR_SCHEMA, apply_repair, validate_repair_proposal
from tests.unit.job_project_build.test_project_build_helpers import _repair
from appsec_review.jobs.job_language_build.job import _copy_source as _copy_language_source
from appsec_review.runtime import GraphRunner, JobRunner, plan_jobs


ROOT = Path(__file__).resolve().parents[3]

pytestmark = pytest.mark.time_budget(
    1800, reason="pre-walk whole-graph suite (T-113): each case runs four jobs through GraphRunner; "
                 "kept for integration until its claims are covered by code-level tests")













def test_unavailable_cached_repair_keeps_original_baseline_candidate(tmp_path: Path) -> None:
    from appsec_review.config.assurance import ComponentReleases
    from appsec_review.container_runtime.image_builder import require_builder
    from appsec_review.jobs.job_project_build.job import REPAIR_CACHE_SCHEMA, _repair_cache, _reuse_accepted_repair

    config = load_config(ROOT / "appsec-review.toml")
    events = []
    unit = SimpleNamespace(job=SimpleNamespace(
        metadata_root=tmp_path, run_root=tmp_path / "run", source_fingerprint="target",
        config=config.job("job_project_build"),
        review_policy=replace(config.review_policy, releases=ComponentReleases({
            "platform": "fixture-platform", "build_toolchain": "fixture-build", "validation": "fixture-validation",
        })),
        events=SimpleNamespace(write=lambda event, **details: events.append((event, details))),
    ))
    action = {"build_unit_id": "build-unit-" + "a" * 20, "family": "native",
              "build_system": "make", "root": "."}
    recipe = {
        "schema": "appsec-review/build-recipe/1", "build_unit_id": action["build_unit_id"],
        "image_profile": "native", "source_dir": ".", "build_dir": "build",
        "system_packages": ["make"], "environment": {}, "dependency_files": ["Makefile"],
        "configure_commands": [], "build_commands": [["make"]], "expected_outputs": ["build"],
        "network_required": False, "reason": "fixture cached repair",
    }
    cache = _repair_cache(unit, "base")
    cache.parent.mkdir(parents=True)
    cache.write_text(json.dumps({
        "schema": REPAIR_CACHE_SCHEMA, "base_recipe_identity": "base", "recipe": recipe,
    }), encoding="utf-8")
    resolver = SimpleNamespace(resolve=lambda recipe, profile: require_builder())
    assert _reuse_accepted_repair(unit, action, "base", resolver, None) is None
    assert events[0][0] == "CHECKPOINT_MISSED"
    assert "derived_image_preparation_unavailable" in events[0][1]["reason"]


class RecipeModel:
    def complete(self, request, *, timeout_seconds):
        recipes = []
        for unit in request.summary["build_units"]:
            root = unit["root"]
            system = unit["build_system"]
            if system == "cmake":
                configure = [["cmake", "-S", root, "-B", f"{root}/build"]]
                build = [["cmake", "--build", f"{root}/build"]]
            else:
                configure = []
                build = [["cargo", "build", "--manifest-path", f"{root}/Cargo.toml"]]
            recipes.append({
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": unit["family"], "source_dir": root,
                "build_dir": f"{root}/{'build' if system == 'cmake' else 'target'}",
                "system_packages": [], "environment": {},
                "dependency_files": [item["path"] for item in unit["markers"]],
                "configure_commands": configure, "build_commands": build,
                "expected_outputs": [f"{root}/{'build' if system == 'cmake' else 'target'}"],
                "network_required": system == "cargo", "reason": "fixture recipe",
            })
        return ModelResult({"schema": PROPOSAL_SCHEMA, "action": "final", "hints": [], "abstentions": [],
                            "component_proposals": [],
                            "build_recipes": recipes})


class NodeRestoreRecipeModel:
    def complete(self, request, *, timeout_seconds):
        recipes = []
        for unit in request.summary["build_units"]:
            root = unit["root"]
            addon = root.endswith("case-087")
            output = (f"{root}/build/Release/case087.node" if addon
                      else f"{root}/dist/bundle.js")
            recipes.append({
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": "node", "source_dir": root,
                "build_dir": f"{root}/{'build' if addon else 'dist'}",
                "system_packages": [], "environment": {},
                "dependency_files": [f"{root}/package.json", f"{root}/package-lock.json"],
                "configure_commands": [["npm", "ci"]],
                "build_commands": [["npm", "run", "build"]],
                "expected_outputs": [output], "network_required": True,
                "reason": "locked fixture restore and build",
            })
        return ModelResult({"schema": PROPOSAL_SCHEMA, "action": "final", "hints": [], "abstentions": [],
                            "component_proposals": [],
                            "build_recipes": recipes})


class FakeBuildExecutor:
    def __init__(self, calls):
        self.calls = calls

    def resolve(self):
        return None

    def execute(self, argv, *, workspace, working_directory, environment):
        self.calls.append(tuple(argv))
        if argv[0] == "cmake" and "--build" in argv:
            output = workspace / "native" / "build" / "observer"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(b"\x7fELFfixture")
        if argv[0] == "cargo":
            output = workspace / "rust" / "target" / "debug" / "sample"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(b"\x7fELFfixture")
        return BuildCommandResult(tuple(argv), 0, b"ok", b"", False)

    def execute_captured(self, argv, *, workspace, working_directory, environment,
                         capture_directory, capture_config, scope, **_options):
        result = self.execute(argv, workspace=workspace, working_directory=working_directory,
                              environment=environment)
        capture_directory.mkdir(parents=True)
        events = capture_directory / "events.jsonl"
        stdout = capture_directory / "stdout"
        stderr = capture_directory / "stderr"
        events.write_bytes(b"")
        stdout.write_bytes(b"ok")
        stderr.write_bytes(b"")
        secret_scan = capture_directory / "secret-scan"
        secret_scan.mkdir()
        scan_stdout, scan_stderr = secret_scan / "stdout", secret_scan / "stderr"
        report, findings = secret_scan / "gitleaks.json", secret_scan / "findings.json"
        execution = secret_scan / "execution.json"
        scan_stdout.write_bytes(b"")
        scan_stderr.write_bytes(b"")
        report.write_text("[]\n", encoding="utf-8")
        findings.write_text(json.dumps({
            "schema": "appsec-review/build-capture-secret-findings/1",
            "scanner": {"tool_id": "tool-gitleaks"}, "observed": 0,
            "retained": 0, "capped": False, "findings": [],
        }, sort_keys=True) + "\n", encoding="utf-8")
        execution.write_text(json.dumps({
            "schema": "appsec-review/build-capture-secret-scan-execution/1",
            "tool_id": "tool-gitleaks", "exit_code": 0, "timed_out": False,
            "stdout": {"uri": "stdout", "sha256": hashlib.sha256(b"").hexdigest()},
            "stderr": {"uri": "stderr", "sha256": hashlib.sha256(b"").hexdigest()},
            "report": {"uri": "gitleaks.json", "sha256": hashlib.sha256(report.read_bytes()).hexdigest()},
        }, sort_keys=True) + "\n", encoding="utf-8")
        record = capture_directory / "record.json"
        record.write_text(json.dumps({
            "schema": "appsec-review/build-execution-record/1",
            "scope": {"run_id": scope.run_id, "job_id": scope.job_id,
                      "attempt_id": scope.attempt_id, "build_unit_id": scope.build_unit_id,
                      "family": scope.family},
            "coverage": {"complete": True, "gaps": []},
            "events": {"uri": "events.jsonl", "sha256": hashlib.sha256(b"").hexdigest()},
            "streams": {
                "stdout": {"uri": "stdout", "sha256": hashlib.sha256(b"ok").hexdigest()},
                "stderr": {"uri": "stderr", "sha256": hashlib.sha256(b"").hexdigest()},
            },
            "tool_calls": {"records": []},
            "secret_scan": {
                "scanner": "tool-gitleaks",
                "findings": {"uri": "secret-scan/findings.json",
                             "sha256": hashlib.sha256(findings.read_bytes()).hexdigest(),
                             "count": 0, "capped": False},
                "execution": {"uri": "secret-scan/execution.json",
                              "sha256": hashlib.sha256(execution.read_bytes()).hexdigest()},
            },
        }, sort_keys=True) + "\n", encoding="utf-8")
        return replace(result, capture_record=record)


class NodeRestoreExecutor(FakeBuildExecutor):
    def prepare_node_dependencies(self, **_kwargs):
        raise AssertionError("npm ci must not receive the immutable image dependency view")

    def execute(self, argv, *, workspace, working_directory, environment):
        self.calls.append(tuple(argv))
        assert environment["NPM_CONFIG_CACHE"] == "/tmp/appsec-npm-cache"
        if tuple(argv) == ("npm", "run", "build"):
            root = workspace / working_directory
            if working_directory.endswith("case-087"):
                output = root / "build" / "Release" / "case087.node"
                data = b"native-addon"
            else:
                output = root / "dist" / "bundle.js"
                data = b"const bundled = true;\n"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)
        return BuildCommandResult(tuple(argv), 0, b"ok", b"", False)


class CaptureGapExecutor(FakeBuildExecutor):
    def execute_captured(self, *args, **kwargs):
        result = super().execute_captured(*args, **kwargs)
        record = json.loads(result.capture_record.read_text(encoding="utf-8"))
        record["coverage"] = {"complete": False, "gaps": ["temporary response file was not retained"]}
        result.capture_record.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
        return result


class FakeImageResolver:
    def resolve(self, recipe, profile):
        identity = __import__("hashlib").sha256(
            __import__("json").dumps(recipe, sort_keys=True).encode()).hexdigest()
        return ProjectImage("appsec-review/project-build-image/1", identity, profile.name,
                            profile.image_id, profile.tag, profile.image_id, None, False, True,
                            {}), b"", b""


class RepairModel:
    def __init__(self, packages):
        self.packages = list(packages)
        self.calls = 0

    def complete(self, request, *, timeout_seconds):
        assert request.schema == REPAIR_SCHEMA
        packages = self.packages[min(self.calls, len(self.packages) - 1)]
        self.calls += 1
        return ModelResult({"schema": REPAIR_SCHEMA, "system_packages": packages,
                            "environment": {}, "package_manager": None,
                            "dependency_restores": [], "reason": "bounded fixture repair"})


class RepairImageResolver:
    def __init__(self, root: Path):
        self.root = root
        self.resolutions = []

    @staticmethod
    def _identity(recipe) -> str:
        return hashlib.sha256(json.dumps(recipe, sort_keys=True).encode()).hexdigest()

    def definition(self, recipe, profile):
        identity = self._identity(recipe)
        packages = " ".join(recipe.get("system_packages", ()))
        return identity, f"FROM {profile.tag}\nRUN apt-get install {packages}\n".encode()

    def resolve(self, recipe, profile):
        identity, dockerfile = self.definition(recipe, profile)
        packages = tuple(recipe.get("system_packages", ()))
        self.resolutions.append(packages)
        if not packages:
            return ProjectImage("appsec-review/project-build-image/1", identity, profile.name,
                                profile.image_id, profile.tag, profile.image_id, None, False, True,
                                {}), b"", b""
        image_id = "sha256:" + hashlib.sha256((identity + "image").encode()).hexdigest()
        context = self.root / "project-images" / identity / "context"
        context.mkdir(parents=True, exist_ok=True)
        dockerfile_path = context / "Dockerfile"
        dockerfile_path.write_bytes(dockerfile)
        relative = dockerfile_path.relative_to(self.root).as_posix()
        package_tag = "-".join(packages)
        return ProjectImage("appsec-review/project-build-image/1", identity, profile.name,
                            profile.image_id, f"repair-{profile.name}:{package_tag}", image_id,
                            hashlib.sha256(dockerfile).hexdigest(), True, False, {},
                            f"project-images/{identity}/manifest.json", relative), b"built", b""


class RepairingExecutor(FakeBuildExecutor):
    def __init__(self, calls, profile, *, success_package: str | None):
        super().__init__(calls)
        self.profile = profile
        self.success_package = success_package

    def execute(self, argv, *, workspace, working_directory, environment):
        if self.profile.name == "native" and argv[0] == "cmake" and "--build" not in argv:
            if self.success_package is None or self.success_package not in self.profile.tag:
                self.calls.append(tuple(argv))
                return BuildCommandResult(tuple(argv), 1, b"", b"fatal error: fixture.h: missing", False)
        return super().execute(argv, workspace=workspace,
                               working_directory=working_directory, environment=environment)
























def test_node_restore_recipes_are_prepared_without_running_dependency_fetches(tmp_path: Path) -> None:
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text((ROOT / "appsec-review.toml").read_text(encoding="utf-8"),
                           encoding="utf-8")
    target = tmp_path / "target"
    for relative in ("case-086", "case-087"):
        root = target / relative
        root.mkdir(parents=True)
        (root / "package.json").write_text(json.dumps({
            "name": root.name, "version": "1.0.0", "scripts": {"build": "fixture-build"},
        }), encoding="utf-8")
        (root / "package-lock.json").write_text(json.dumps({
            "name": root.name, "version": "1.0.0", "lockfileVersion": 3,
            "requires": True, "packages": {},
        }), encoding="utf-8")
    config = load_config(config_path)
    fingerprint = source_fingerprint(target)
    calls: list[tuple[str, ...]] = []
    outcome = GraphRunner(config, [*_producers(NodeRestoreRecipeModel().complete), build_projects(
        executor_factory=lambda unit, profile: NodeRestoreExecutor(calls),
        image_resolver_factory=lambda unit: FakeImageResolver())]).run(
            target_root=target, source_fingerprint=fingerprint)
    assert outcome["jobs"]["job_project_build"]["status"]["status"] == "SUCCEEDED"
    accepted = load_accepted_builds(config.runtime.runs_dir / outcome["run_id"])
    dispatches = {item["root"]: item for item in accepted["build_dispatches"]}
    assert set(dispatches) == {"case-086", "case-087"}
    assert all(item["recipe"]["configure_commands"] == [["npm", "ci"]] for item in dispatches.values())
    assert all(item["recipe"]["build_commands"] == [["npm", "run", "build"]] for item in dispatches.values())
    assert accepted["probe_receipts"] == [] and calls == []


















def _producers(infer=None):
    """The producers job_project_build consumes; a graph supplies only producers that are in it."""
    return [build_intake(), build_catalog(), build_plan(infer=infer) if infer is not None else build_plan()]


def _fixture(tmp_path: Path, *, declared_releases: bool = False):
    config_path = tmp_path / "appsec-review.toml"
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    if declared_releases:
        text = declare_releases(text, platform="fixture-platform", build_toolchain="fixture-build",
                                validation="fixture-validation")
    config_path.write_text(text, encoding="utf-8")
    target = tmp_path / "target"
    (target / "native").mkdir(parents=True)
    (target / "native" / "CMakeLists.txt").write_text("project(sample)\n", encoding="utf-8")
    (target / "native" / "main.cpp").write_text("int main(){}\n", encoding="utf-8")
    (target / "rust" / "src").mkdir(parents=True)
    (target / "rust" / "Cargo.toml").write_text(
        "[package]\nname='sample'\nversion='0.1.0'\n", encoding="utf-8")
    (target / "rust" / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
    return load_config(config_path), target


def test_project_build_prepares_dispatch_without_a_second_build_or_fake_probe(tmp_path: Path) -> None:
    from tests.integration.job_project_build.test_project_build_capture import _run
    _, outcome, accepted, calls, image_calls = _run(tmp_path, "cmake")
    assert outcome["status"] == "SUCCEEDED"
    assert accepted["probe_artifact_count"] > 0
    assert len(accepted["probe_receipts"]) == 1
    assert accepted["execution_mode"] == "iterative"
    dispatch, = accepted["build_dispatches"]
    assert dispatch["execution_owner"] == "job_project_build"
    assert dispatch["target_annotation"][0]["status"] == "unknown"
    assert dispatch["enforcement"][0]["status"] == "proven"
    assert len(calls) == 2 and image_calls
    assert accepted["gaps"] == []


@pytest.mark.parametrize("repair_baseline", (False, True))
def test_missing_builder_blocks_only_affected_preparation(tmp_path: Path, repair_baseline) -> None:
    from tests.integration.job_project_build.test_project_build_capture import _run
    _, outcome, accepted, calls, image_calls = _run(tmp_path, "derived" if repair_baseline else "cmake")
    native = accepted["images"]["native"]["entries"][0]
    assert not any(argv[:3] == ("docker", "buildx", "build") for argv in image_calls)
    if repair_baseline:
        assert outcome["status"] == "COMPLETED_WITH_GAPS"
        assert native["terminal_status"] == "BLOCKED"
        assert any("derived_image_preparation_unavailable" in gap for gap in native["gaps"])
        assert not calls and not accepted["build_dispatches"]
    else:
        assert outcome["status"] == native["terminal_status"] == "SUCCEEDED"
        assert {item["family"] for item in accepted["build_dispatches"]} == {"native"}
        assert len(calls) == 2


def test_native_windows_placeholder_is_blocked_without_hiding_alternate_cmake_authority(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    (target / "native/project.vcxproj").write_text(
        "<Project><PropertyGroup><Platform>Win32</Platform></PropertyGroup></Project>", encoding="utf-8")

    class Model(RecipeModel):
        def complete(self, request, *, timeout_seconds):
            if request.allowed_build_systems != ("msbuild",):
                return super().complete(request, timeout_seconds=timeout_seconds)
            unit = request.summary["build_units"][0]
            return ModelResult({"schema": PROPOSAL_SCHEMA, "action": "final", "hints": [], "abstentions": [],
                                "component_proposals": [], "build_recipes": [{
                "schema": "appsec-review/build-recipe/1", "build_unit_id": unit["build_unit_id"],
                "image_profile": "native", "source_dir": unit["root"], "build_dir": unit["root"] + "/build",
                "system_packages": [], "environment": {},
                "dependency_files": [x["path"] for x in unit["markers"]],
                "configure_commands": [], "build_commands": [["make", "-k"]], "expected_outputs": [],
                "network_required": False, "reason": "placeholder for an unavailable Windows build",
            }]})

    fingerprint = source_fingerprint(target)
    calls = []
    outcome = GraphRunner(config, [*_producers(Model().complete), build_projects(
        executor_factory=lambda unit, profile: FakeBuildExecutor(calls),
        image_resolver_factory=lambda unit: FakeImageResolver(),
    )]).run(target_root=target, source_fingerprint=fingerprint)
    accepted = load_accepted_builds(config.runtime.runs_dir / outcome["run_id"])
    windows = next(x for x in accepted["images"]["native"]["entries"]
                   if x["action"]["build_system"] == "msbuild")
    assert windows["terminal_status"] == "BLOCKED"
    assert any("unavailable_native_windows_toolchain" in gap for gap in windows["gaps"])
    assert any(x["build_system"] == "cmake" for x in accepted["build_dispatches"])
    assert not any(argv[0] == "make" for argv in calls)
    assert outcome["jobs"]["job_project_build"]["status"]["status"] == "COMPLETED_WITH_GAPS"


def test_disabled_build_capture_records_policy_skips_without_execution(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    source = config.source_path.read_text(encoding="utf-8")
    config.source_path.write_text(
        source.replace('mode = "required"', 'mode = "disabled"', 1), encoding="utf-8")
    config = load_config(config.source_path)
    fingerprint = source_fingerprint(target)
    calls: list[tuple[str, ...]] = []
    outcome = GraphRunner(config, [*_producers(RecipeModel().complete), build_projects(
        executor_factory=lambda unit, profile: FakeBuildExecutor(calls),
        image_resolver_factory=lambda unit: FakeImageResolver())]).run(
            target_root=target, source_fingerprint=fingerprint)
    accepted = load_accepted_builds(config.runtime.runs_dir / outcome["run_id"])
    assert outcome["jobs"]["job_project_build"]["status"]["status"] == "SUCCEEDED"
    assert calls == [] and accepted["probe_receipts"] == [] and accepted["build_dispatches"] == []
    assert {item["disposition"] for item in accepted["processing_decisions"]} == {"SKIPPED_POLICY"}
    assert all(item["configuration_sha256"] == config.resolved_sha256
               for item in accepted["processing_decisions"])


def test_project_build_has_independent_language_branches(tmp_path: Path) -> None:
    config, _target = _fixture(tmp_path)
    job = build_projects(executor_factory=lambda unit, profile: FakeBuildExecutor([]),
                         image_resolver_factory=lambda unit: FakeImageResolver())
    graph = plan_jobs((job,), config)
    for family in ("native", "rust", "go", "java", "node", "dotnet", "python", "php", "wasm"):
        assert graph.node(f"job_project_build.image.{family}").dependencies == (
            "job_project_build.plan.load_recipes",)
        assert graph.node(f"job_project_build.probe.{family}").dependencies == (
            f"job_project_build.image.{family}",)
        assert graph.node(f"job_project_build.build_dispatch.{family}").dependencies == (
            f"job_project_build.image.{family}", f"job_project_build.probe.{family}")
    assert len(graph.node("job_project_build.acceptance.publish_handoff").dependencies) == 19


def test_project_build_resolves_missing_cmake_recipe_deterministically(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    calls = []
    outcome = GraphRunner(config, [*_producers(), build_projects(
        executor_factory=lambda unit, profile: FakeBuildExecutor(calls),
        image_resolver_factory=lambda unit: FakeImageResolver())]).run(
            target_root=target, source_fingerprint=fingerprint)
    # Rust still requires an accepted recipe.
    assert outcome["jobs"]["job_project_build"]["status"]["status"] == "COMPLETED_WITH_GAPS"
    accepted = load_accepted_builds(config.runtime.runs_dir / outcome["run_id"])
    native = next(item for item in accepted["build_dispatches"] if item["family"] == "native")
    assert native["recipe_provenance"] == "deterministic-cmake-marker"
    assert native["recipe"]["configure_commands"][0][-2:] == [
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "-DCMAKE_BUILD_TYPE=RelWithDebInfo"]
    assert native["recipe"]["build_commands"][0][-2:] == ["--parallel", "2"]


def test_preparation_does_not_run_either_family_even_with_a_failing_executor(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)

    class Selective(FakeBuildExecutor):
        def execute(self, argv, *, workspace, working_directory, environment):
            if argv[0] == "cargo":
                self.calls.append(tuple(argv))
                return BuildCommandResult(tuple(argv), 2, b"", b"failed", False)
            return super().execute(argv, workspace=workspace,
                                   working_directory=working_directory,
                                   environment=environment)

    job = build_projects(executor_factory=lambda unit, profile: Selective([]),
                         image_resolver_factory=lambda unit: FakeImageResolver())
    outcome = GraphRunner(config, [*_producers(RecipeModel().complete), job]).run(
        target_root=target, source_fingerprint=fingerprint)
    assert outcome["jobs"]["job_project_build"]["status"]["status"] == "SUCCEEDED"
    accepted = load_accepted_builds(config.runtime.runs_dir / outcome["run_id"])
    assert accepted["probe_receipts"] == []
    assert {item["family"] for item in accepted["static_dispatches"]
            if item["workflow"] == "lang_jobflow_static"} == {"native", "rust"}
    assert {item["family"] for item in accepted["build_dispatches"]} == {"native", "rust"}


def test_preparation_does_not_fabricate_capture_or_infer_image_repairs(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    model = RepairModel((["should-not-be-installed"],))
    outcome = GraphRunner(config, [*_producers(RecipeModel().complete), build_projects(
        executor_factory=lambda unit, profile: CaptureGapExecutor([]),
        image_resolver_factory=lambda unit: RepairImageResolver(tmp_path / "image-metadata"),
        infer=model.complete,
    )]).run(target_root=target, source_fingerprint=fingerprint)
    assert outcome["jobs"]["job_project_build"]["status"]["status"] == "SUCCEEDED"
    accepted = load_accepted_builds(config.runtime.runs_dir / outcome["run_id"])
    assert {item["family"] for item in accepted["build_dispatches"]} == {"native", "rust"}
    assert model.calls == 0
    assert accepted["probe_receipts"] == []


@pytest.mark.parametrize("declared_releases", [False, True])
@pytest.mark.parametrize("same_run", [False, True])
def test_preparation_never_rebuilds_to_probe_reuse(
        tmp_path: Path, declared_releases: bool, same_run: bool) -> None:
    config, target = _fixture(tmp_path, declared_releases=declared_releases)
    fingerprint = source_fingerprint(target)
    calls: list[tuple[str, ...]] = []
    job = build_projects(executor_factory=lambda unit, profile: FakeBuildExecutor(calls),
                         image_resolver_factory=lambda unit: FakeImageResolver())
    run_ids = []
    graph = GraphRunner(config, [*_producers(RecipeModel().complete), job])
    for ordinal in range(2):
        rerun = bool(ordinal and same_run)
        outcome = graph.run(target_root=target, source_fingerprint=fingerprint,
                            run_id=run_ids[0] if rerun else None,
                            force_from="job_project_build" if rerun else None)
        run_ids.append(outcome["run_id"])
    assert calls == []
    second = load_accepted_builds(config.runtime.runs_dir / run_ids[1])
    assert second["probe_receipts"] == []
    assert {item["family"] for item in second["build_dispatches"]} == {"native", "rust"}


@pytest.mark.parametrize("spelling", ["force_buildability_probe", "force_probes"])
def test_retired_force_probe_options_are_rejected_visibly(tmp_path: Path, spelling: str) -> None:
    config_path = tmp_path / "appsec-review.toml"
    source = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    config_path.write_text(source.replace("force_buildability_probe = false",
                                          f"{spelling} = true"), encoding="utf-8")
    with pytest.raises(ValueError, match="retired"):
        load_config(config_path)


def test_forced_project_build_rerun_in_same_application_run_is_attempt_isolated(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(
        config, [build_intake(), build_catalog(), build_plan(infer=RecipeModel().complete)]
    ).run(target_root=target, source_fingerprint=fingerprint)
    calls: list[tuple[str, ...]] = []
    job = build_projects(executor_factory=lambda unit, profile: FakeBuildExecutor(calls),
                         image_resolver_factory=lambda unit: FakeImageResolver())
    runner = JobRunner(config)
    first = runner.run(job, run_id=upstream["run_id"], target_root=target,
                       source_fingerprint=fingerprint)
    second = runner.run(job, run_id=upstream["run_id"], target_root=target,
                        source_fingerprint=fingerprint)
    assert first["status"]["attempt_id"] == "attempt_0001"
    assert second["status"]["attempt_id"] == "attempt_0002"
    run_root = config.runtime.runs_dir / upstream["run_id"]
    assert calls == []
    assert not (run_root / "data/build/probes").exists()
    accepted = load_accepted_builds(run_root)
    assert accepted["probe_receipts"] == []
    assert {item["family"] for item in accepted["build_dispatches"]} == {"native", "rust"}


def test_repeated_preparation_preserves_recipe_without_speculative_image_repair(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path, declared_releases=True)
    fingerprint = source_fingerprint(target)
    model = RepairModel((["libone-dev"], ["libtwo-dev"]))
    resolver = RepairImageResolver(tmp_path / "image-metadata")
    calls: list[tuple[str, ...]] = []
    job = build_projects(
        executor_factory=lambda unit, profile: RepairingExecutor(
            calls, profile, success_package="libtwo-dev"),
        image_resolver_factory=lambda unit: resolver, infer=model.complete)
    run_ids = []
    graph = GraphRunner(config, [*_producers(RecipeModel().complete), job])
    for ordinal in range(2):
        outcome = graph.run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_ids[0] if ordinal else None,
            force_from="job_project_build" if ordinal else None)
        run_ids.append(outcome["run_id"])
        assert outcome["jobs"]["job_project_build"]["status"]["status"] == "SUCCEEDED"
        if ordinal == 0:
            first = load_accepted_builds(config.runtime.runs_dir / outcome["run_id"])

    native_dispatch = next(value for value in first["build_dispatches"] if value["family"] == "native")
    assert first["probe_receipts"] == []
    assert native_dispatch["recipe"]["system_packages"] == []
    assert calls == [] and model.calls == 0

    events = [json.loads(line) for line in (
        config.runtime.runs_dir / run_ids[0] / "data" / "logs" / "pipeline.jsonl"
    ).read_text(encoding="utf-8").splitlines()]
    repair_events = [item for item in events if item["event_type"] == "MODEL_CALL_STARTED"
                     and item["details"].get("inference_task") == "build_image_repair"]
    assert repair_events == []

    second = load_accepted_builds(config.runtime.runs_dir / run_ids[1])
    prepared = next(value for value in second["build_dispatches"] if value["family"] == "native")
    assert prepared["recipe"] == native_dispatch["recipe"]
    assert prepared["recipe_identity"] == native_dispatch["recipe_identity"]
    assert second["probe_receipts"] == []


def test_environment_repair_is_not_requested_without_an_observed_production_failure(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    requests = []

    def model(request, *, timeout_seconds):
        requests.append(request)
        return ModelResult(_repair(environment={"CARGO_NET_GIT_FETCH_WITH_CLI": "true"},
                                   dependency_restores=[{"manifest": "rust/Cargo.toml"}],
                                   reason="git dependency fetch needs the git CLI"))

    class GitFetchExecutor(FakeBuildExecutor):
        def execute(self, argv, *, workspace, working_directory, environment):
            if argv[0] == "cargo" and environment.get("CARGO_NET_GIT_FETCH_WITH_CLI") != "true":
                self.calls.append(tuple(argv))
                return BuildCommandResult(tuple(argv), 101, b"", b"failed to fetch git dependency", False)
            return super().execute(argv, workspace=workspace, working_directory=working_directory,
                                   environment=environment)

    resolver = RepairImageResolver(tmp_path / "image-metadata")
    outcome = GraphRunner(config, [*_producers(RecipeModel().complete), build_projects(
        executor_factory=lambda unit, profile: GitFetchExecutor([]),
        image_resolver_factory=lambda unit: resolver, infer=model)]).run(
            target_root=target, source_fingerprint=fingerprint)
    assert outcome["jobs"]["job_project_build"]["status"]["status"] == "SUCCEEDED"
    assert requests == []
    accepted = load_accepted_builds(config.runtime.runs_dir / outcome["run_id"])
    dispatch = next(value for value in accepted["build_dispatches"] if value["family"] == "rust")
    assert dispatch["recipe"]["environment"] == {}
    assert "image_repairs" not in dispatch["recipe"]
    assert accepted["probe_receipts"] == []


def test_preparation_does_not_exhaust_image_attempts_before_production(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    model = RepairModel((["libone-dev"], ["libtwo-dev"], ["libthree-dev"]))
    resolver = RepairImageResolver(tmp_path / "image-metadata")
    outcome = GraphRunner(config, [*_producers(RecipeModel().complete), build_projects(
        executor_factory=lambda unit, profile: RepairingExecutor([], profile, success_package=None),
        image_resolver_factory=lambda unit: resolver, infer=model.complete)]).run(
            target_root=target, source_fingerprint=fingerprint)
    assert outcome["jobs"]["job_project_build"]["status"]["status"] == "SUCCEEDED"
    accepted = load_accepted_builds(config.runtime.runs_dir / outcome["run_id"])
    assert accepted["probe_receipts"] == []
    assert model.calls == 0
    assert len(accepted["build_dispatches"]) == 2


def test_preparation_never_manufactures_failure_evidence_to_request_repairs(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    repair = RepairModel(([], ["libtwo-dev"]))
    requests = []

    def model(request, *, timeout_seconds):
        requests.append(request)
        return repair.complete(request, timeout_seconds=timeout_seconds)

    outcome = GraphRunner(config, [*_producers(RecipeModel().complete), build_projects(
        executor_factory=lambda unit, profile: RepairingExecutor([], profile, success_package="libtwo-dev"),
        image_resolver_factory=lambda unit: RepairImageResolver(tmp_path / "image-metadata"),
        infer=model)]).run(target_root=target, source_fingerprint=fingerprint)
    assert outcome["jobs"]["job_project_build"]["status"]["status"] == "SUCCEEDED"
    assert requests == []
    accepted = load_accepted_builds(config.runtime.runs_dir / outcome["run_id"])
    assert accepted["probe_receipts"] == []
    assert len(accepted["build_dispatches"]) == 2
