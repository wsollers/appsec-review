"""T-113: pre-walk graph/target cases retained as acceptance, not bounded integration.

Case bodies are preserved. Shared helpers stay at their existing import paths so the
other machine's unit tier and other jobs do not require edits. Not run by this walk.
"""

from __future__ import annotations
from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from appsec_review.config import load_config
from appsec_review.container_runtime import BuildCommandResult
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_project_build import build_job as build_projects, load_accepted_builds
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.jobs.job_target_analysis_plan.planning import PROPOSAL_SCHEMA
from tests.unit.job_project_build.test_project_build_helpers import _repair
from appsec_review.runtime import GraphRunner, JobRunner

from tests.integration.job_project_build.test_project_build_graph import (
    CaptureGapExecutor,
    FakeBuildExecutor,
    FakeImageResolver,
    NodeRestoreExecutor,
    NodeRestoreRecipeModel,
    ROOT,
    RecipeModel,
    RepairImageResolver,
    RepairModel,
    RepairingExecutor,
    _fixture,
    _producers,
)

pytestmark = pytest.mark.time_budget(
    1800, reason="Retained pre-walk multi-job graph; manual acceptance only (T-113).")

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
