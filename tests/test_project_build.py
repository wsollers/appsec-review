from __future__ import annotations

from dataclasses import replace
import json
import hashlib
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest

from appsec_review.config import ProcessingMode, load_config
from appsec_review.container_runtime import BuildCommandResult, ProjectImage
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
from appsec_review.jobs.job_language_build.job import _copy_source as _copy_language_source
from appsec_review.runtime import GraphRunner, JobRunner, plan_jobs


ROOT = Path(__file__).parents[1]


def test_android_expected_output_requires_a_structurally_valid_apk(tmp_path: Path) -> None:
    recipe = {"expected_outputs": ["app/build/outputs/apk/debug/app-debug.apk"]}
    apk = tmp_path / recipe["expected_outputs"][0]
    apk.parent.mkdir(parents=True)
    assert _validate_expected_outputs(tmp_path, recipe) == [
        "required build output is missing: app/build/outputs/apk/debug/app-debug.apk"]
    apk.write_bytes(b"not a zip")
    assert _validate_expected_outputs(tmp_path, recipe) == [
        "required APK is not a valid ZIP archive: app/build/outputs/apk/debug/app-debug.apk"]
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
    assert _validate_expected_outputs(tmp_path, recipe) == [
        "required APK has invalid Android structure: app/build/outputs/apk/debug/app-debug.apk"]
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("resources.arsc", b"resources")
    assert _validate_expected_outputs(tmp_path, recipe) == []


def test_build_capture_mode_changes_project_probe_checkpoint_identity(tmp_path: Path) -> None:
    config = load_config(ROOT / "appsec-review.toml")
    job = config.job("job_project_build")
    context = dict(metadata_root=tmp_path, run_root=tmp_path / "run",
                   source_fingerprint="target", review_policy=config.review_policy)
    unit = SimpleNamespace(job=SimpleNamespace(**context, config=job))
    baseline = _probe_cache(unit, "a" * 64)
    changed_job = replace(job, build_capture=replace(
        job.build_capture, mode=ProcessingMode.AUTO))
    changed = _probe_cache(SimpleNamespace(job=SimpleNamespace(
        **context, config=changed_job)), "a" * 64)
    assert changed != baseline


def test_probe_and_repair_identity_bind_relevant_releases_target_and_run(tmp_path: Path) -> None:
    from appsec_review.config.assurance import ComponentReleases
    from appsec_review.jobs.job_project_build.job import _repair_cache, _reuse_accepted_repair
    config = load_config(ROOT / "appsec-review.toml")
    releases = {"platform": "fixture-platform", "build_toolchain": "fixture-build",
                "validation": "fixture-validation"}
    context = dict(metadata_root=tmp_path, run_root=tmp_path / "run",
                   source_fingerprint="target", config=config.job("job_project_build"),
                   review_policy=replace(config.review_policy, releases=ComponentReleases(releases)))
    for cache in (_probe_cache, _repair_cache):
        baseline = cache(SimpleNamespace(job=SimpleNamespace(**context)), "recipe")
        for component in releases:
            policy = replace(config.review_policy, releases=ComponentReleases({
                **releases, component: "changed"}))
            assert cache(SimpleNamespace(job=SimpleNamespace(
                **{**context, "review_policy": policy})), "recipe") != baseline
        for field, value in (("run_root", tmp_path / "other-run"), ("source_fingerprint", "other-target")):
            assert cache(SimpleNamespace(job=SimpleNamespace(
                **{**context, field: value})), "recipe") != baseline
        unrelated = replace(config.review_policy, releases=ComponentReleases({
            **releases, "queries_python": "unrelated-query-change"}))
        assert cache(SimpleNamespace(job=SimpleNamespace(
            **{**context, "review_policy": unrelated})), "recipe") == baseline
    events = []
    unit = SimpleNamespace(job=SimpleNamespace(**{
        **context, "review_policy": config.review_policy,
        "events": SimpleNamespace(write=lambda event, **details: events.append((event, details))),
    }))
    # Missing declarations must return before consulting an old repair or invoking its resolver.
    assert _reuse_accepted_repair(unit, {"build_unit_id": "fixture"}, "recipe", None, None) is None
    assert events == [("CHECKPOINT_MISSED", {"scope_id": "fixture", "action": "image_repair",
                                           "reason": "missing_release_identity"})]


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
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [],
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
        return ModelResult({"schema": PROPOSAL_SCHEMA, "component_proposals": [],
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


def test_probe_environment_uses_writable_networked_maven_repository() -> None:
    recipe = {"build_system": "maven", "source_dir": "projects/java/sample",
              "environment": {"MAVEN_OPTS": "-Dmaven.artifact.threads=1"}}
    assert _probe_environment(recipe)["MAVEN_OPTS"] == (
        "-Dmaven.repo.local=/tmp/appsec-review-maven "
        "-Dmaven.repo.local.tail=/opt/project-deps/maven -Dmaven.artifact.threads=1")


def test_probe_environment_supplies_writable_maven_repository_without_user_options() -> None:
    recipe = {"build_system": "maven", "source_dir": ".", "environment": {}}
    assert _probe_environment(recipe)["MAVEN_OPTS"] == (
        "-Dmaven.repo.local=/tmp/appsec-review-maven "
        "-Dmaven.repo.local.tail=/opt/project-deps/maven")


def test_probe_environment_keeps_gradle_home_writable_with_read_only_image_cache() -> None:
    # The derived image restores into /opt/project-deps/gradle, which is read-only at run time.
    # Gradle must lock and write elsewhere while still reading the restored modules.
    for recipe in ({"build_system": "gradle", "source_dir": ".", "environment": {}},
                   {"build_system": "gradle", "source_dir": ".",
                    "environment": {"GRADLE_USER_HOME": "/opt/project-deps/gradle"}}):
        environment = _probe_environment(recipe)
        assert environment["GRADLE_USER_HOME"] == "/tmp/appsec-review-gradle"
        assert environment["GRADLE_RO_DEP_CACHE"] == "/opt/project-deps/gradle/caches"
    assert "GRADLE_USER_HOME" not in _probe_environment(
        {"build_system": "maven", "source_dir": ".", "environment": {}})


def test_networked_node_restore_uses_writable_scratch_caches() -> None:
    environment = _probe_environment({
        "build_system": "node", "source_dir": "projects/javascript-bundler/case-086",
        "network_required": True, "environment": {}, "dependency_files": [
            "projects/javascript-bundler/case-086/package-lock.json"],
    })
    assert environment["NPM_CONFIG_CACHE"] == "/tmp/appsec-npm-cache"
    assert environment["PNPM_STORE_DIR"] == "/tmp/appsec-pnpm-store"
    assert environment["YARN_CACHE_FOLDER"] == "/tmp/appsec-yarn-cache"


def test_node_configure_restore_does_not_mount_immutable_image_dependencies() -> None:
    for root in ("projects/javascript-bundler/case-086", "projects/node-addon/case-087"):
        assert _node_recipe_restores_dependencies({
            "source_dir": root, "configure_commands": [["npm", "ci"]]})
    assert not _node_recipe_restores_dependencies({
        "source_dir": "projects/node/no-restore", "configure_commands": []})


def test_probe_environment_disables_cargo_incremental_state_the_host_cannot_read() -> None:
    environment = _probe_environment({"build_system": "cargo", "source_dir": "rust",
                                      "environment": {"CARGO_INCREMENTAL": "1"}})
    assert environment["CARGO_INCREMENTAL"] == "0"
    assert "CARGO_INCREMENTAL" not in _probe_environment({
        "build_system": "cmake", "source_dir": "native", "environment": {}})


def test_kotlin_direct_recipe_uses_the_profile_image_toolchain(tmp_path: Path) -> None:
    target = tmp_path / "target"
    source = target / "kotlin" / "src"
    source.mkdir(parents=True)
    kotlin = source / "Main.kt"
    kotlin.write_text("fun main() = Unit\n", encoding="utf-8")
    action = {"build_unit_id": "build-unit-kotlin", "family": "java",
              "build_system": "javac", "root": "kotlin"}
    unit = SimpleNamespace(job=SimpleNamespace(target_root=target))
    recipe = _deterministic_jvm_recipe(unit, action)
    assert recipe is not None
    # The Java image carries kotlinc and its JDK. Packages here would be stripped by planning and
    # a JAVA_HOME would name a JDK the pinned image does not contain.
    assert recipe["system_packages"] == []
    assert recipe["environment"] == {}
    assert recipe["build_commands"][0][:2] == ["kotlinc", "src/Main.kt"]


def test_project_probe_copies_accepted_parent_dependency_files(tmp_path: Path) -> None:
    target = tmp_path / "target"
    member = target / "apps" / "web"
    member.mkdir(parents=True)
    (member / "package.json").write_text("{}\n", encoding="utf-8")
    (target / "tsconfig.base.json").write_text("{}\n", encoding="utf-8")
    run_root = tmp_path / "runs" / "run-1"
    workspace = run_root / "data" / "build" / "probes" / "unit" / "attempt-001" / "workspace"
    unit = SimpleNamespace(job=SimpleNamespace(target_root=target, run_root=run_root))
    action = {"root": "apps/web", "recipe": {
        "dependency_files": ["apps/web/package.json", "tsconfig.base.json"]}}
    _copy_source(unit, action, workspace)
    assert (workspace / "apps/web/package.json").is_file()
    assert (workspace / "tsconfig.base.json").is_file()

    language_workspace = tmp_path / "language-workspace"
    _copy_language_source(unit, action, language_workspace)
    assert (language_workspace / "apps/web/package.json").is_file()
    assert (language_workspace / "tsconfig.base.json").is_file()


def test_project_probe_materializes_bounded_legacy_maven_source_layout(tmp_path: Path) -> None:
    target = tmp_path / "target"
    source = target / "projects" / "java" / "case-034"
    (source / "src").mkdir(parents=True)
    (source / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    (source / "src" / "Main.java").write_text("class Main {}\n", encoding="utf-8")
    run_root = tmp_path / "runs" / "run-1"
    workspace = run_root / "data" / "build" / "probes" / "unit" / "workspace"
    unit = SimpleNamespace(job=SimpleNamespace(target_root=target, run_root=run_root))
    root = "projects/java/case-034"
    action = {"root": root, "family": "java", "build_system": "maven", "recipe": {
        "source_dir": root, "dependency_files": [f"{root}/pom.xml"]}}
    adaptations = _copy_source(unit, action, workspace)
    materialized = workspace / root / "src" / "main" / "java" / "Main.java"
    assert materialized.read_text(encoding="utf-8") == "class Main {}\n"
    assert adaptations == [
        "materialized legacy Maven src/*.java under src/main/java in the run-owned workspace"]


def test_project_probe_keeps_maven_layout_when_pom_declares_source_directory(tmp_path: Path) -> None:
    target = tmp_path / "target"
    source = target / "projects" / "java" / "case-034"
    (source / "src").mkdir(parents=True)
    (source / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0"><build>'
        "<sourceDirectory>src</sourceDirectory></build></project>\n", encoding="utf-8")
    (source / "src" / "Main.java").write_text("class Main {}\n", encoding="utf-8")
    run_root = tmp_path / "runs" / "run-1"
    workspace = run_root / "data" / "build" / "probes" / "unit" / "workspace"
    unit = SimpleNamespace(job=SimpleNamespace(target_root=target, run_root=run_root))
    root = "projects/java/case-034"
    action = {"root": root, "family": "java", "build_system": "maven", "recipe": {
        "source_dir": root, "dependency_files": [f"{root}/pom.xml"]}}
    assert _copy_source(unit, action, workspace) == []
    assert not (workspace / root / "src" / "main").exists()
    assert (workspace / root / "src" / "Main.java").is_file()


def test_declared_build_dir_exists_before_recipe_commands_write_into_it(tmp_path: Path) -> None:
    # A recipe like `clang --target=wasm32 -o build/case091.wasm` cannot mkdir its output directory.
    root = "projects/wasm/case-091"
    target = tmp_path / "target"
    (target / root / "src").mkdir(parents=True)
    (target / root / "src" / "case091.c").write_text("int f(void){return 0;}\n", encoding="utf-8")
    run_root = tmp_path / "runs" / "run-1"
    unit = SimpleNamespace(job=SimpleNamespace(target_root=target, run_root=run_root))
    recipe = {"source_dir": root, "build_dir": f"{root}/build", "dependency_files": [],
              "expected_outputs": [f"{root}/build"]}
    action = {"root": root, "family": "wasm", "build_system": "clang", "recipe": recipe}
    for copy in (_copy_language_source, _copy_wasm_source):
        workspace = tmp_path / copy.__module__ / "workspace"
        copy(unit, action, workspace)
        assert (workspace / root / "build").is_dir()

    workspace = run_root / "data" / "build" / "probes" / "unit" / "workspace"
    _copy_source(unit, action, workspace)
    assert ensure_declared_build_dir(workspace, recipe) == f"{root}/build"
    assert ensure_declared_build_dir(workspace, recipe) is None
    assert _validate_expected_outputs(workspace, recipe, f"{root}/build") == [
        f"required build output is missing: {root}/build"]
    (workspace / root / "build" / "case091.wasm").write_bytes(b"\0asm")
    assert _validate_expected_outputs(workspace, recipe, f"{root}/build") == []

    escape = tmp_path / "escape"
    escape.mkdir()
    linked = tmp_path / "linked"
    (linked / "projects").mkdir(parents=True)
    (linked / "projects" / "wasm").symlink_to(escape, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        ensure_declared_build_dir(linked, recipe)
    assert not any(escape.iterdir())


def test_node_086_087_restore_outputs(tmp_path: Path) -> None:
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
    upstream = GraphRunner(config, [build_intake(), build_catalog(),
        build_plan(infer=NodeRestoreRecipeModel().complete)]).run(
            target_root=target, source_fingerprint=fingerprint)
    calls: list[tuple[str, ...]] = []
    outcome = GraphRunner(config, [build_projects(
        executor_factory=lambda unit, profile: NodeRestoreExecutor(calls),
        image_resolver_factory=lambda unit: FakeImageResolver())]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    assert outcome["status"] == "SUCCEEDED"
    accepted = load_accepted_builds(config.runtime.runs_dir / upstream["run_id"])
    receipts = {item["root"]: item for item in accepted["probe_receipts"]}
    assert {root: receipt["terminal_status"] for root, receipt in receipts.items()} == {
        "case-086": "SUCCEEDED",
        "case-087": "SUCCEEDED",
    }
    assert calls.count(("npm", "ci")) == 2
    assert calls.count(("npm", "run", "build")) == 2


def _repair(**fields):
    return {"schema": REPAIR_SCHEMA, "system_packages": [], "environment": {},
            "package_manager": None, "dependency_restores": [],
            "reason": "bounded repair", **fields}


def _repair_recipe(profile: str, root: str, dependency_files: list[str], *, build_system: str,
                   commands: list[list[str]], network_required: bool = False) -> dict:
    return {"schema": "appsec-review/build-recipe/1", "build_unit_id": "build-unit-" + "a" * 20,
            "image_profile": profile, "source_dir": root, "build_dir": f"{root}/build",
            "system_packages": [], "environment": {}, "dependency_files": dependency_files,
            "configure_commands": [], "build_commands": commands, "expected_outputs": [f"{root}/build"],
            "network_required": network_required, "reason": "accepted recipe"}


def _repair_unit(recipe: dict, build_system: str) -> dict:
    documents = [{"path": path} for path in recipe["dependency_files"]]
    return {"build_unit_id": recipe["build_unit_id"], "family": recipe["image_profile"],
            "root": recipe["source_dir"], "build_system": build_system,
            "required_image_profile": recipe["image_profile"], "markers": documents,
            "descriptor_package": {"documents": documents}}


def test_image_repair_accepts_only_bounded_apt_package_sets() -> None:
    recipe = _repair_recipe("native", "lib", ["lib/CMakeLists.txt"], build_system="cmake",
                            commands=[["cmake", "--build", "lib/build"]])
    proposal = _repair(system_packages=["libssl-dev", "zlib1g-dev:amd64"])
    assert validate_repair_proposal(proposal, recipe=recipe, build_system="cmake") == ()
    repaired = apply_repair(recipe, proposal, build_system="cmake")
    assert repaired["system_packages"] == ["libssl-dev", "zlib1g-dev:amd64"]
    assert "image_repairs" not in repaired
    invalid = {**proposal, "system_packages": ["libssl-dev;curl attacker"]}
    assert validate_repair_proposal(invalid, recipe=recipe, build_system="cmake")
    legacy = {"schema": "appsec-review/build-image-repair/1", "system_packages": ["libssl-dev"],
              "reason": "old shape"}
    assert validate_repair_proposal(legacy, recipe=recipe, build_system="cmake") == (
        "repair proposal fields are invalid",)


def test_image_repair_environment_is_a_typed_family_allowlist() -> None:
    from appsec_review.jobs.build_discovery import validate_build_recipe

    recipe = _repair_recipe("python", "pkg", ["pkg/pyproject.toml", "pkg/requirements-build.txt"],
                            build_system="python",
                            commands=[["python", "-m", "pip", "wheel", "--no-deps", "."]])
    proposal = _repair(environment={"PIP_BREAK_SYSTEM_PACKAGES": "1",
                                    "SETUPTOOLS_SCM_PRETEND_VERSION": "1.4.0"})
    repaired = apply_repair(recipe, proposal, build_system="python")
    assert repaired["environment"] == {"PIP_BREAK_SYSTEM_PACKAGES": "1",
                                       "SETUPTOOLS_SCM_PRETEND_VERSION": "1.4.0"}
    assert repaired["image_repairs"]["environment"] == repaired["environment"]
    assert validate_build_recipe(repaired, _repair_unit(repaired, "python")) == []
    for environment, message in (
            ({"PIP_INDEX_URL": "https://example.invalid/simple"}, "not repairable for python"),
            ({"LD_PRELOAD": "/tmp/x.so"}, "not repairable for python"),
            ({"PIP_BREAK_SYSTEM_PACKAGES": "1; curl x"}, "value is not allowed"),
            ({"NPM_CONFIG_LEGACY_PEER_DEPS": "true"}, "not repairable for python")):
        errors = validate_repair_proposal(_repair(environment=environment), recipe=recipe,
                                          build_system="python")
        assert any(message in error for error in errors), (environment, errors)
    # A later repair replaces the earlier repair environment rather than accumulating it.
    second = apply_repair(repaired, _repair(environment={"PIP_NO_BUILD_ISOLATION": "0"}),
                          build_system="python")
    assert second["environment"] == {"PIP_NO_BUILD_ISOLATION": "0"}
    # An accepted recipe's own environment is never overwritten by a repair.
    owned = {**recipe, "environment": {"PIP_BREAK_SYSTEM_PACKAGES": "1"}}
    with pytest.raises(ValueError, match="replace accepted recipe environment"):
        apply_repair(owned, proposal, build_system="python")
    with pytest.raises(ValueError, match="repeated the current repair set"):
        apply_repair(repaired, proposal, build_system="python")
    maven = _repair_recipe("java", "svc", ["svc/pom.xml"], build_system="maven",
                           commands=[["mvn", "-B", "package"]])
    assert validate_repair_proposal(_repair(environment={
        "MAVEN_ARGS": "-Denforcer.skip=true -Dmaven.compiler.release=8"}),
        recipe=maven, build_system="maven") == ()
    assert validate_repair_proposal(_repair(environment={"MAVEN_ARGS": "-Dexec.executable=sh"}),
                                    recipe=maven, build_system="maven")


def test_image_repair_dependency_restores_use_the_family_manager_on_accepted_manifests() -> None:
    from appsec_review.container_runtime.project_images import repair_restore_commands
    from appsec_review.jobs.build_discovery import validate_build_recipe

    recipe = _repair_recipe("python", "pkg", ["pkg/pyproject.toml", "pkg/requirements-build.txt"],
                            build_system="python", commands=[["python", "-m", "build", "--wheel"]])
    repaired = apply_repair(recipe, _repair(dependency_restores=[
        {"manifest": "pkg/requirements-build.txt"}]), build_system="python")
    assert repaired["image_repairs"]["dependency_restores"] == [
        {"manager": "pip", "manifest": "pkg/requirements-build.txt"}]
    assert repair_restore_commands({**repaired, "build_system": "python"}) == [(
        "/opt/project/pkg",
        ("python", "-m", "pip", "install", "--target", "/opt/project-deps", "-r",
         "requirements-build.txt"))]
    assert validate_build_recipe(repaired, _repair_unit(repaired, "python")) == []
    for manifest, message in (("pkg/pyproject.toml", "cannot restore dependencies"),
                              ("pkg/../../etc/passwd", "not an accepted dependency file"),
                              ("other/requirements.txt", "not an accepted dependency file")):
        errors = validate_repair_proposal(_repair(dependency_restores=[{"manifest": manifest}]),
                                          recipe=recipe, build_system="python")
        assert any(message in error for error in errors), (manifest, errors)
    errors = validate_repair_proposal(_repair(dependency_restores=[
        {"manifest": "pkg/requirements-build.txt", "argv": ["sh", "-c", "id"]}]),
        recipe=recipe, build_system="python")
    assert "dependency_restores entries must be objects with only manifest" in errors
    # A tampered recorded restore fails recipe validation instead of reaching the Dockerfile.
    tampered = {**repaired, "image_repairs": {**repaired["image_repairs"], "dependency_restores": [
        {"manager": "npm", "manifest": "pkg/requirements-build.txt"}]}}
    assert any("not normalized" in error
               for error in validate_build_recipe(tampered, _repair_unit(tampered, "python")))

    maven = _repair_recipe("java", "svc", ["svc/pom.xml", "svc/tools/pom.xml"],
                           build_system="maven", commands=[["mvn", "-B", "package"]])
    repaired = apply_repair(maven, _repair(dependency_restores=[{"manifest": "svc/tools/pom.xml"}]),
                            build_system="maven")
    assert repair_restore_commands({**repaired, "build_system": "maven"}) == [(
        "/opt/project/svc/tools", ("mvn", "-B", "-DskipTests", "-f", "pom.xml", "dependency:go-offline"))]
    composer = _repair_recipe("php", "web", ["web/composer.json", "web/tools/composer.json"],
                              build_system="composer", commands=[["composer", "dump-autoload"]])
    assert validate_repair_proposal(_repair(dependency_restores=[{"manifest": "web/composer.json"}]),
                                    recipe=composer, build_system="composer") == ()
    assert validate_repair_proposal(_repair(dependency_restores=[
        {"manifest": "web/tools/composer.json"}]), recipe=composer, build_system="composer")


def test_image_repair_package_manager_selects_only_a_pinned_lockless_node_manager() -> None:
    from appsec_review.container_runtime.project_images import (
        PINNED_PACKAGE_MANAGERS, _restore_command, repair_restore_commands)

    recipe = _repair_recipe("node", "web", ["web/package.json", "web/pnpm-workspace.yaml"],
                            build_system="node", commands=[["tsc", "-p", "."]])
    proposal = _repair(package_manager="pnpm", dependency_restores=[{"manifest": "web/package.json"}])
    repaired = apply_repair(recipe, proposal, build_system="node")
    assert repaired["image_repairs"]["package_manager"] == "pnpm"
    assert repair_restore_commands({**repaired, "build_system": "node"}) == [(
        "/opt/project/web", ("pnpm", "install", "--no-frozen-lockfile", "--ignore-scripts"))]
    assert _restore_command({**repaired, "build_system": "node"})[0] == "pnpm"
    for manager in ("bun", "npm@11", "corepack"):
        assert validate_repair_proposal(_repair(package_manager=manager), recipe=recipe,
                                        build_system="node")
    locked = {**recipe, "dependency_files": ["web/package.json", "web/package-lock.json"]}
    assert any("accepted lockfile" in error for error in validate_repair_proposal(
        _repair(package_manager="yarn"), recipe=locked, build_system="node"))
    runs_npm = {**recipe, "build_commands": [["npm", "run", "build"]]}
    assert any("conflicts" in error for error in validate_repair_proposal(
        _repair(package_manager="yarn"), recipe=runs_npm, build_system="node"))
    python = _repair_recipe("python", "pkg", ["pkg/pyproject.toml"], build_system="python",
                            commands=[["python", "-m", "build"]])
    assert validate_repair_proposal(_repair(package_manager="pip"), recipe=python,
                                    build_system="python")
    # The selectable versions are the ones the Node build image pins.
    dockerfile = (ROOT / "containers" / "buildenv" / "typescript" / "Dockerfile").read_text()
    pinned = PINNED_PACKAGE_MANAGERS["node"]
    assert f'version="node{pinned["npm"].rsplit(" ", 1)[1]}-pnpm{pinned["pnpm"]}-yarn{pinned["yarn"]}"' in dockerfile


def test_image_repair_vocabulary_names_no_case_identifiers() -> None:
    source = (ROOT / "src" / "appsec_review" / "jobs" / "job_project_build" / "repair.py").read_text()
    import re

    assert not re.search(r"case-?\d{3}", source) and "multivuln" not in source.lower()


def _fixture(tmp_path: Path, *, declared_releases: bool = False):
    config_path = tmp_path / "appsec-review.toml"
    text = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    if declared_releases:
        text = text.replace("[review_policy.releases]", '[review_policy.releases]\n'
                            'platform = "fixture-platform"\nbuild_toolchain = "fixture-build"\n'
                            'validation = "fixture-validation"', 1)
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


def test_project_build_executes_accepted_recipes_and_retains_binaries(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_plan(infer=RecipeModel().complete)]).run(
        target_root=target, source_fingerprint=fingerprint)
    calls = []
    job = build_projects(executor_factory=lambda unit, profile: FakeBuildExecutor(calls),
                         image_resolver_factory=lambda unit: FakeImageResolver())
    outcome = GraphRunner(config, [job]).run(target_root=target, source_fingerprint=fingerprint,
                                             run_id=upstream["run_id"])
    assert outcome["status"] == "SUCCEEDED"
    accepted = load_accepted_builds(config.runtime.runs_dir / upstream["run_id"])
    assert accepted["probe_artifact_count"] == 2
    assert {item["family"] for item in accepted["probe_receipts"]} == {"native", "rust"}
    assert {item["family"] for item in accepted["static_dispatches"]
            if item["workflow"] == "lang_jobflow_static"} == {"native", "rust"}
    assert {item["workflow"] for item in accepted["build_dispatches"]} == {"lang_jobflow_build"}
    assert all(item["executor_identity"] == "appsec-review/build-container-executor/3"
               for item in accepted["probe_receipts"])
    assert all((config.runtime.runs_dir / upstream["run_id"] / artifact["path"]).is_file()
               for build in accepted["probe_receipts"] for artifact in build["artifacts"])
    for build in accepted["probe_receipts"]:
        assert all(command["execution_capture"]["complete"] for command in build["commands"])
        assert all((config.runtime.runs_dir / upstream["run_id"] /
                    command["execution_capture"]["path"]).is_file()
                   for command in build["commands"])
    for family in ("native", "rust"):
        image_entry = accepted["images"][family]["entries"][0]
        assert image_entry["attempt_identity"] and image_entry["command_identity"]
        assert all(stream["sha256"] and stream["capture_limit"]
                   for stream in image_entry["streams"].values())
    assert calls == [
        ("cmake", "-S", ".", "-B", "build", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
         "-DCMAKE_BUILD_TYPE=RelWithDebInfo"),
        ("cmake", "--build", "build", "--parallel", "2"),
        ("cargo", "build", "--manifest-path", "Cargo.toml"),
    ]
    native = next(item for item in accepted["build_dispatches"] if item["family"] == "native")
    assert native["recipe_provenance"] == "deterministic-cmake-marker"
    assert native["recipe"]["system_packages"] == []
    assert native["descriptor_facts"] == {}


def test_disabled_build_capture_records_policy_skips_without_execution(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    source = config.source_path.read_text(encoding="utf-8")
    config.source_path.write_text(
        source.replace('mode = "required"', 'mode = "disabled"', 1), encoding="utf-8")
    config = load_config(config.source_path)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(
        config, [build_intake(), build_catalog(), build_plan(infer=RecipeModel().complete)]
    ).run(target_root=target, source_fingerprint=fingerprint)
    calls: list[tuple[str, ...]] = []
    outcome = GraphRunner(config, [build_projects(
        executor_factory=lambda unit, profile: FakeBuildExecutor(calls),
        image_resolver_factory=lambda unit: FakeImageResolver())]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    accepted = load_accepted_builds(config.runtime.runs_dir / upstream["run_id"])
    assert outcome["status"] == "SUCCEEDED"
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
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_plan()]).run(
        target_root=target, source_fingerprint=fingerprint)
    calls = []
    outcome = GraphRunner(config, [build_projects(
        executor_factory=lambda unit, profile: FakeBuildExecutor(calls),
        image_resolver_factory=lambda unit: FakeImageResolver())]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    assert outcome["status"] == "COMPLETED_WITH_GAPS"  # Rust still requires an accepted recipe.
    accepted = load_accepted_builds(config.runtime.runs_dir / upstream["run_id"])
    native = next(item for item in accepted["build_dispatches"] if item["family"] == "native")
    assert native["recipe_provenance"] == "deterministic-cmake-marker"
    assert native["recipe"]["configure_commands"][0][-2:] == [
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", "-DCMAKE_BUILD_TYPE=RelWithDebInfo"]
    assert native["recipe"]["build_commands"][0][-2:] == ["--parallel", "2"]


def test_build_failure_is_a_gap_and_preserves_other_family_outputs(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_plan(infer=RecipeModel().complete)]).run(
        target_root=target, source_fingerprint=fingerprint)

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
    outcome = GraphRunner(config, [job]).run(target_root=target, source_fingerprint=fingerprint,
                                             run_id=upstream["run_id"])
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    accepted = load_accepted_builds(config.runtime.runs_dir / upstream["run_id"])
    native = next(item for item in accepted["probe_receipts"] if item["family"] == "native")
    rust = next(item for item in accepted["probe_receipts"] if item["family"] == "rust")
    assert native["terminal_status"] == "SUCCEEDED" and native["artifacts"]
    assert rust["terminal_status"] == "FAILED" and rust["gaps"]
    assert {item["family"] for item in accepted["static_dispatches"]
            if item["workflow"] == "lang_jobflow_static"} == {"native", "rust"}
    assert {item["family"] for item in accepted["build_dispatches"]} == {"native"}


def test_capture_gap_is_reported_without_triggering_image_repair(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(
        config, [build_intake(), build_catalog(), build_plan(infer=RecipeModel().complete)]
    ).run(target_root=target, source_fingerprint=fingerprint)
    model = RepairModel((["should-not-be-installed"],))
    outcome = GraphRunner(config, [build_projects(
        executor_factory=lambda unit, profile: CaptureGapExecutor([]),
        image_resolver_factory=lambda unit: RepairImageResolver(tmp_path / "image-metadata"),
        infer=model.complete,
    )]).run(target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    accepted = load_accepted_builds(config.runtime.runs_dir / upstream["run_id"])
    assert accepted["build_dispatches"] == []
    assert model.calls == 0
    assert {item["terminal_status"] for item in accepted["probe_receipts"]} == {
        "COMPLETED_WITH_GAPS"}
    assert all(item["repair_attempt_count"] == 0 for item in accepted["probe_receipts"])
    assert all("capture:" in item["gaps"][0] for item in accepted["probe_receipts"])


@pytest.mark.parametrize("declared_releases", [False, True])
@pytest.mark.parametrize("same_run", [False, True])
def test_probe_reuse_requires_declarations_and_the_same_run(
        tmp_path: Path, declared_releases: bool, same_run: bool) -> None:
    config, target = _fixture(tmp_path, declared_releases=declared_releases)
    fingerprint = source_fingerprint(target)
    calls: list[tuple[str, ...]] = []
    job = build_projects(executor_factory=lambda unit, profile: FakeBuildExecutor(calls),
                         image_resolver_factory=lambda unit: FakeImageResolver())
    run_ids = []
    for ordinal in range(2):
        if ordinal == 0 or not same_run:
            upstream = GraphRunner(
                config, [build_intake(), build_catalog(), build_plan(infer=RecipeModel().complete)]
            ).run(target_root=target, source_fingerprint=fingerprint)
        run_ids.append(upstream["run_id"])
        GraphRunner(config, [job]).run(target_root=target, source_fingerprint=fingerprint,
                                      run_id=upstream["run_id"],
                                      force_from="job_project_build" if ordinal and same_run else None)
    reused = declared_releases and same_run
    assert len(calls) == (3 if reused else 6)
    second = load_accepted_builds(config.runtime.runs_dir / run_ids[1])
    assert {item["probe_disposition"] for item in second["probe_receipts"]} == {
        "REUSED" if reused else "PROBED"}
    assert all(item["probe_disposition"] == ("REUSED" if reused else "PROBED")
               for item in second["build_dispatches"])


def test_force_probe_override_executes_unchanged_recipe(tmp_path: Path) -> None:
    config_path = tmp_path / "appsec-review.toml"
    source = (ROOT / "appsec-review.toml").read_text(encoding="utf-8")
    config_path.write_text(source.replace("force_buildability_probe = false",
                                          "force_buildability_probe = true"), encoding="utf-8")
    target = tmp_path / "target"
    (target / "native").mkdir(parents=True)
    (target / "native" / "CMakeLists.txt").write_text("project(sample)\n", encoding="utf-8")
    (target / "native" / "main.cpp").write_text("int main(){}\n", encoding="utf-8")
    config, fingerprint = load_config(config_path), source_fingerprint(target)
    calls: list[tuple[str, ...]] = []
    job = build_projects(executor_factory=lambda unit, profile: FakeBuildExecutor(calls),
                         image_resolver_factory=lambda unit: FakeImageResolver())
    for _ in range(2):
        upstream = GraphRunner(
            config, [build_intake(), build_catalog(), build_plan(infer=RecipeModel().complete)]
        ).run(target_root=target, source_fingerprint=fingerprint)
        GraphRunner(config, [job]).run(target_root=target, source_fingerprint=fingerprint,
                                      run_id=upstream["run_id"])
    configure = ("cmake", "-S", ".", "-B", "build", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                 "-DCMAKE_BUILD_TYPE=RelWithDebInfo")
    build = ("cmake", "--build", "build", "--parallel", "2")
    assert calls == [configure, build, configure, build]


def test_forced_project_build_rerun_in_same_application_run_is_attempt_isolated(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    config.source_path.write_text(
        config.source_path.read_text(encoding="utf-8").replace(
            "force_buildability_probe = false", "force_buildability_probe = true"),
        encoding="utf-8")
    config = load_config(config.source_path)
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
    captures = sorted(path.relative_to(run_root).as_posix()
                      for path in (run_root / "data" / "build" / "probes").glob(
                          "*/attempts/attempt_*/probe-001/execution-capture/command-001/record.json"))
    assert any("/attempts/attempt_0001/" in path for path in captures)
    assert any("/attempts/attempt_0002/" in path for path in captures)


def test_failed_default_build_repairs_image_and_reuses_winning_definition(tmp_path: Path) -> None:
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
    upstream = GraphRunner(
        config, [build_intake(), build_catalog(), build_plan(infer=RecipeModel().complete)]
    ).run(target_root=target, source_fingerprint=fingerprint)
    for ordinal in range(2):
        run_ids.append(upstream["run_id"])
        outcome = GraphRunner(config, [job]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"],
            force_from="job_project_build" if ordinal else None)
        assert outcome["status"] == "SUCCEEDED"
        if ordinal == 0:
            first = load_accepted_builds(config.runtime.runs_dir / upstream["run_id"])

    native_receipt = next(value for value in first["probe_receipts"] if value["family"] == "native")
    native_dispatch = next(value for value in first["build_dispatches"] if value["family"] == "native")
    assert native_receipt["repair_attempt_count"] == 2
    assert [value["terminal_status"] for value in native_receipt["attempts"]] == [
        "FAILED", "FAILED", "SUCCEEDED"]
    for attempt in native_receipt["attempts"][1:]:
        assert attempt["attempt_identity"] and attempt["command_identity"]
        assert all(stream["sha256"] and "truncated" in stream
                   for stream in attempt["streams"].values())
    assert native_dispatch["recipe"]["system_packages"] == ["libtwo-dev"]
    assert native_dispatch["recipe_provenance"] == "inference-image-repair"
    definition = resolver.root / native_dispatch["image"]["dockerfile_path"]
    assert definition.is_file() and "libtwo-dev" in definition.read_text(encoding="utf-8")
    assert model.calls == 2

    events = [json.loads(line) for line in (
        config.runtime.runs_dir / run_ids[0] / "data" / "logs" / "pipeline.jsonl"
    ).read_text(encoding="utf-8").splitlines()]
    repair_events = [item for item in events if item["event_type"] == "MODEL_CALL_STARTED"
                     and item["details"].get("inference_task") == "build_image_repair"]
    assert [(item["details"]["family"], item["details"]["root"],
             item["details"]["build_system"], item["details"]["repair_number"])
            for item in repair_events] == [
                ("native", "native", "cmake", 1),
                ("native", "native", "cmake", 2),
            ]

    second = load_accepted_builds(config.runtime.runs_dir / run_ids[1])
    reused = next(value for value in second["build_dispatches"] if value["family"] == "native")
    assert reused["recipe"]["system_packages"] == ["libtwo-dev"]
    assert reused["recipe_provenance"] == "reused-image-repair"
    assert reused["probe_disposition"] == "REUSED"
    assert model.calls == 2


def test_typed_environment_repair_is_offered_applied_and_recorded(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(
        config, [build_intake(), build_catalog(), build_plan(infer=RecipeModel().complete)]
    ).run(target_root=target, source_fingerprint=fingerprint)
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
    outcome = GraphRunner(config, [build_projects(
        executor_factory=lambda unit, profile: GitFetchExecutor([]),
        image_resolver_factory=lambda unit: resolver, infer=model)]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    assert outcome["status"] == "SUCCEEDED"
    assert len(requests) == 1
    options = requests[0].summary["repair_options"]
    assert "CARGO_NET_GIT_FETCH_WITH_CLI" in options["environment_names"]
    assert options["restorable_manifests"] == ["rust/Cargo.toml"]
    assert options["package_managers"] == {}
    accepted = load_accepted_builds(config.runtime.runs_dir / upstream["run_id"])
    rust = next(value for value in accepted["probe_receipts"] if value["family"] == "rust")
    assert [value["terminal_status"] for value in rust["attempts"]] == ["FAILED", "SUCCEEDED"]
    assert rust["attempts"][1]["image_repairs"] == {
        "environment": {"CARGO_NET_GIT_FETCH_WITH_CLI": "true"}, "package_manager": None,
        "dependency_restores": [{"manager": "cargo", "manifest": "rust/Cargo.toml"}]}
    dispatch = next(value for value in accepted["build_dispatches"] if value["family"] == "rust")
    assert dispatch["recipe"]["environment"] == {"CARGO_NET_GIT_FETCH_WITH_CLI": "true"}
    assert dispatch["recipe"]["image_repairs"] == rust["attempts"][1]["image_repairs"]
    assert dispatch["recipe_provenance"] == "inference-image-repair"


def test_build_failure_exhausts_three_image_repair_attempts(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(
        config, [build_intake(), build_catalog(), build_plan(infer=RecipeModel().complete)]
    ).run(target_root=target, source_fingerprint=fingerprint)
    model = RepairModel((["libone-dev"], ["libtwo-dev"], ["libthree-dev"]))
    resolver = RepairImageResolver(tmp_path / "image-metadata")
    outcome = GraphRunner(config, [build_projects(
        executor_factory=lambda unit, profile: RepairingExecutor([], profile, success_package=None),
        image_resolver_factory=lambda unit: resolver, infer=model.complete)]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    accepted = load_accepted_builds(config.runtime.runs_dir / upstream["run_id"])
    native = next(value for value in accepted["probe_receipts"] if value["family"] == "native")
    assert native["terminal_status"] == "FAILED"
    assert native["repair_attempt_count"] == 3
    assert len(native["attempts"]) == 4  # Default image plus three inferred custom images.
    assert model.calls == 3
    assert native["gaps"][-1] == "build remained unavailable after 3 image repair attempts"


def test_rejected_repair_proposal_keeps_probe_failure_for_the_next_repair(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(
        config, [build_intake(), build_catalog(), build_plan(infer=RecipeModel().complete)]
    ).run(target_root=target, source_fingerprint=fingerprint)
    repair = RepairModel(([], ["libtwo-dev"]))
    requests = []

    def model(request, *, timeout_seconds):
        requests.append(request)
        return repair.complete(request, timeout_seconds=timeout_seconds)

    outcome = GraphRunner(config, [build_projects(
        executor_factory=lambda unit, profile: RepairingExecutor([], profile, success_package="libtwo-dev"),
        image_resolver_factory=lambda unit: RepairImageResolver(tmp_path / "image-metadata"),
        infer=model)]).run(target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    assert outcome["status"] == "SUCCEEDED"
    native = [request.summary["failure"] for request in requests
              if request.summary["build_unit"]["family"] == "native"]
    assert len(native) == 2
    assert "fixture.h: missing" in native[0]["stderr_tail"]
    assert "fixture.h: missing" in native[1]["stderr_tail"]
    assert native[1]["repair_error"] == {
        "error_class": "ValueError", "message": "repair proposal repeated the current repair set"}
