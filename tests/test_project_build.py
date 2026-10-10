from __future__ import annotations

from dataclasses import replace
import json
import hashlib
from pathlib import Path
from types import SimpleNamespace

from appsec_review.config import ProcessingMode, load_config
from appsec_review.container_runtime import BuildCommandResult, ProjectImage
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_project_build import build_job as build_projects, load_accepted_builds
from appsec_review.jobs.job_project_build.job import _probe_cache, _probe_environment
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from appsec_review.jobs.job_project_build.repair import REPAIR_SCHEMA, apply_repair, validate_repair_proposal
from appsec_review.runtime import GraphRunner, plan_jobs


ROOT = Path(__file__).parents[1]


def test_build_capture_mode_changes_project_probe_checkpoint_identity(tmp_path: Path) -> None:
    job = load_config(ROOT / "appsec-review.toml").job("job_project_build")
    unit = SimpleNamespace(job=SimpleNamespace(metadata_root=tmp_path, config=job))
    baseline = _probe_cache(unit, "a" * 64)
    changed_job = replace(job, build_capture=replace(
        job.build_capture, mode=ProcessingMode.AUTO))
    changed = _probe_cache(SimpleNamespace(job=SimpleNamespace(
        metadata_root=tmp_path, config=changed_job)), "a" * 64)
    assert changed != baseline


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
                         capture_directory, capture_config, scope):
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
            "report": {"uri": "gitleaks.json", "sha256": hashlib.sha256(b"[]\n").hexdigest()},
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
                            "reason": "bounded fixture repair"})


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
        "-Dmaven.repo.local=/tmp/appsec-review-maven -Dmaven.artifact.threads=1")


def test_probe_environment_supplies_writable_maven_repository_without_user_options() -> None:
    recipe = {"build_system": "maven", "source_dir": ".", "environment": {}}
    assert _probe_environment(recipe)["MAVEN_OPTS"] == (
        "-Dmaven.repo.local=/tmp/appsec-review-maven")


def test_probe_environment_disables_cargo_incremental_state_the_host_cannot_read() -> None:
    environment = _probe_environment({"build_system": "cargo", "source_dir": "rust",
                                      "environment": {"CARGO_INCREMENTAL": "1"}})
    assert environment["CARGO_INCREMENTAL"] == "0"
    assert "CARGO_INCREMENTAL" not in _probe_environment({
        "build_system": "cmake", "source_dir": "native", "environment": {}})


def test_image_repair_accepts_only_bounded_apt_package_sets() -> None:
    proposal = {"schema": REPAIR_SCHEMA, "system_packages": ["libssl-dev", "zlib1g-dev:amd64"],
                "reason": "missing development headers"}
    assert validate_repair_proposal(proposal) == ()
    recipe = {"system_packages": []}
    assert apply_repair(recipe, proposal)["system_packages"] == ["libssl-dev", "zlib1g-dev:amd64"]
    invalid = {**proposal, "system_packages": ["libssl-dev;curl attacker"]}
    assert validate_repair_proposal(invalid)


def _fixture(tmp_path: Path):
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text((ROOT / "appsec-review.toml").read_text(encoding="utf-8"), encoding="utf-8")
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
    assert all(item["executor_identity"] == "appsec-review/build-container-executor/2"
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


def test_unchanged_recipe_reuses_probe_across_application_runs(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    calls: list[tuple[str, ...]] = []
    job = build_projects(executor_factory=lambda unit, profile: FakeBuildExecutor(calls),
                         image_resolver_factory=lambda unit: FakeImageResolver())
    run_ids = []
    for _ in range(2):
        upstream = GraphRunner(
            config, [build_intake(), build_catalog(), build_plan(infer=RecipeModel().complete)]
        ).run(target_root=target, source_fingerprint=fingerprint)
        run_ids.append(upstream["run_id"])
        GraphRunner(config, [job]).run(target_root=target, source_fingerprint=fingerprint,
                                      run_id=upstream["run_id"])
    assert len(calls) == 3
    second = load_accepted_builds(config.runtime.runs_dir / run_ids[1])
    assert {item["probe_disposition"] for item in second["probe_receipts"]} == {"REUSED"}
    assert all(item["probe_disposition"] == "REUSED" for item in second["build_dispatches"])


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


def test_failed_default_build_repairs_image_and_reuses_winning_definition(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    model = RepairModel((["libone-dev"], ["libtwo-dev"]))
    resolver = RepairImageResolver(tmp_path / "image-metadata")
    calls: list[tuple[str, ...]] = []
    job = build_projects(
        executor_factory=lambda unit, profile: RepairingExecutor(
            calls, profile, success_package="libtwo-dev"),
        image_resolver_factory=lambda unit: resolver, infer=model.complete)
    run_ids = []
    for _ in range(2):
        upstream = GraphRunner(
            config, [build_intake(), build_catalog(), build_plan(infer=RecipeModel().complete)]
        ).run(target_root=target, source_fingerprint=fingerprint)
        run_ids.append(upstream["run_id"])
        outcome = GraphRunner(config, [job]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
        assert outcome["status"] == "SUCCEEDED"

    first = load_accepted_builds(config.runtime.runs_dir / run_ids[0])
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

    second = load_accepted_builds(config.runtime.runs_dir / run_ids[1])
    reused = next(value for value in second["build_dispatches"] if value["family"] == "native")
    assert reused["recipe"]["system_packages"] == ["libtwo-dev"]
    assert reused["recipe_provenance"] == "reused-image-repair"
    assert reused["probe_disposition"] == "REUSED"
    assert model.calls == 2


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
