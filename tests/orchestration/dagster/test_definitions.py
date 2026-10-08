from __future__ import annotations

from pathlib import Path
import os
import threading
import time

import pytest

dagster = pytest.importorskip("dagster")

from appsec_review.orchestration.dagster import build_definitions
from appsec_review.orchestration.dagster.adapter import _metadata_for_outcome
from appsec_review.runtime import Job, Unit, UnitExecutor
from appsec_review.runtime.registry import JobRegistry


def _config(root: Path, *, configured_job: str = "job_fixture") -> Path:
    path = root / "appsec-review.toml"
    path.write_text(
        f"""
[runtime]
runs_dir = "runs"
data_dir = "data"

[jobs.{configured_job}]
name = "fixture"
workers = 1

[jobs.{configured_job}.schedule]
enabled = true
cron = "15 2 * * *"
timezone = "UTC"

[jobs.{configured_job}.steps.work]
workers = 1
[jobs.{configured_job}.steps.work.tasks.execute]
workers = 1
""".strip(),
        encoding="utf-8",
    )
    return path


def _registry() -> JobRegistry:
    registry = JobRegistry()
    def build():
        units = (Unit("work.execute", lambda context: {"value": 1}),)
        return Job("job_fixture", "fixture", UnitExecutor(units).execute, units=units)
    registry.register("job_fixture", build)
    return registry


def test_definitions_discover_registry_and_configure_schedule(tmp_path: Path) -> None:
    calls: list[tuple[str, dict[str, str]]] = []

    class Runner:
        def __init__(self, config):
            self.config = config

        def begin_attempt(self, job, *, trigger, orchestration, **kwargs):
            calls.append((trigger, orchestration))
            return {"run_id": "test-run", "attempt_id": "attempt_0001", "trigger": trigger,
                    "orchestration": orchestration, "attempt_path": "attempt",
                    "source_fingerprint": "none", "upstream_handoffs": {}, "started_at": "2026-10-08T00:00:00+00:00"}

        def execute_or_reuse_unit(self, job, claim, unit_id):
            return {"value": 1}

        def finalize_attempt(self, job, claim):
            return {
                "status": {
                    "run_id": "test-run",
                    "attempt_id": "attempt_0001",
                    "trigger": claim["trigger"],
                    "status": "SUCCEEDED",
                },
                "handoff_sha256": "a" * 64,
                "handoff": {},
                "attempt_root": str(tmp_path / "attempt"),
                "result": {
                    "status": "SUCCEEDED",
                    "steps": {},
                    "units": {},
                    "outputs": {},
                    "failed_units": [],
                    "skipped_units": [],
                },
            }

    definitions = build_definitions(
        _config(tmp_path), registry=_registry(), runner_factory=Runner
    )
    job = definitions.get_job_def("fixture")
    schedule = definitions.get_schedule_def("fixture_schedule")

    assert schedule.cron_schedule == "15 2 * * *"
    assert schedule.execution_timezone == "UTC"
    assert schedule.default_status is dagster.DefaultScheduleStatus.RUNNING
    assert schedule.job_name == "fixture"

    assert job.execute_in_process().success
    assert job.execute_in_process(tags={"dagster/schedule_name": schedule.name}).success
    assert [trigger for trigger, _ in calls] == ["manual", "schedule"]
    assert all(correlation["system"] == "dagster" for _, correlation in calls)
    assert all(correlation["run_id"] for _, correlation in calls)


def test_definitions_reject_registry_config_drift(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="missing_config=.*job_fixture"):
        build_definitions(_config(tmp_path, configured_job="job_other"), registry=_registry())


@pytest.mark.parametrize("job_id", ["job_artifact_indexing", "job_artifact_security_analysis"])
def test_artifact_jobs_receive_target_snapshot(tmp_path: Path, monkeypatch, job_id: str) -> None:
    target = tmp_path / "target"
    target.mkdir()
    monkeypatch.setenv("APPSEC_REVIEW_TARGET", str(target))
    begun: list[dict[str, object]] = []

    registry = JobRegistry()
    def build_artifact_job():
        units = (Unit("work.execute", lambda context: {"terminal_status": "SUCCEEDED"}),)
        return Job(job_id, "artifact job", UnitExecutor(units).execute, units=units)
    registry.register(job_id, build_artifact_job)

    class Runner:
        def __init__(self, config):
            pass

        def begin_attempt(self, job, **kwargs):
            begun.append(kwargs)
            return {"run_id": "test-run", "attempt_id": "attempt_0001", "trigger": "manual",
                    "orchestration": kwargs["orchestration"], "attempt_path": "attempt",
                    "source_fingerprint": kwargs["source_fingerprint"], "upstream_handoffs": {},
                    "started_at": "2026-10-08T00:00:00+00:00"}

        def execute_or_reuse_unit(self, job, claim, unit_id):
            return {"terminal_status": "SUCCEEDED"}

        def finalize_attempt(self, job, claim):
            return {"status": {"status": "SUCCEEDED"}, "handoff_sha256": "a" * 64,
                    "handoff": {}, "attempt_root": str(tmp_path / "attempt"),
                    "result": {"steps": {}, "units": {}, "outputs": {},
                               "failed_units": [], "skipped_units": []}}

    definitions = build_definitions(_config(tmp_path, configured_job=job_id),
                                    registry=registry, runner_factory=Runner)
    assert definitions.get_job_def("artifact_job").execute_in_process().success
    assert begun[0]["target_root"] == target.resolve()
    assert begun[0]["source_fingerprint"] != "none"


def test_application_failure_fails_dagster_run(tmp_path: Path) -> None:
    class Runner:
        def __init__(self, config):
            pass

        def begin_attempt(self, job, **kwargs):
            return {"run_id": "test-run", "attempt_id": "attempt_0001", "trigger": "manual",
                    "orchestration": {}, "attempt_path": "attempt", "source_fingerprint": "none",
                    "upstream_handoffs": {}, "started_at": "2026-10-08T00:00:00+00:00"}

        def execute_or_reuse_unit(self, job, claim, unit_id):
            raise RuntimeError("application terminal failure")

        def finalize_attempt(self, job, claim):  # pragma: no cover
            raise AssertionError

    definitions = build_definitions(
        _config(tmp_path), registry=_registry(), runner_factory=Runner
    )
    result = definitions.get_job_def("fixture").execute_in_process(raise_on_error=False)
    assert not result.success
    assert any("application terminal failure" in str(event.event_specific_data)
               for event in result.all_node_events if event.is_step_failure)


def test_metadata_maps_units_snapshots_counts_gaps_and_receipts(tmp_path: Path) -> None:
    attempt = tmp_path / "runs" / "test-run" / "attempt_0001"
    outcome = {
        "status": {
            "run_id": "test-run",
            "attempt_id": "attempt_0001",
            "trigger": "manual",
            "status": "SUCCEEDED",
        },
        "attempt_root": str(attempt),
        "result": {
            "steps": {"nvd_sync": "SUCCEEDED"},
            "units": {
                "nvd_sync.publish": {
                    "step_id": "nvd_sync", "task_id": "publish", "status": "SUCCEEDED"
                }
            },
            "outputs": {
                "nvd_sync.publish": {
                    "identity": {"snapshot_id": "sha256-example", "record_count": 42},
                    "metadata_path": "/metadata/nvd.json",
                }
            },
            "failed_units": [],
            "skipped_units": [],
        },
    }
    metadata = _metadata_for_outcome(outcome, "dagster-run")

    assert metadata["application_run_id"] == "test-run"
    assert metadata["unit_statuses"].data == {"nvd_sync.publish": "SUCCEEDED"}
    assert metadata["published_snapshot_identities"].data["nvd_sync.publish"]["identity"]["snapshot_id"] == "sha256-example"
    assert metadata["counts"].data == {
        "nvd_sync.publish.identity.record_count": 42,
    }
    assert metadata["gaps"].data == {"failed_units": [], "skipped_units": []}
    assert metadata["receipt__nvd_sync__publish"].path.endswith(
        "steps/nvd_sync/tasks/publish/status.json"
    ) or metadata["receipt__nvd_sync__publish"].path.endswith(
        "steps\\nvd_sync\\tasks\\publish\\status.json"
    )


def test_production_schedule_is_midnight_utc_and_enabled() -> None:
    config = Path(__file__).resolve().parents[3] / "appsec-review.toml"
    definitions = build_definitions(config)
    definitions.get_repository_def().load_all_definitions()
    schedule = definitions.get_schedule_def("third_party_data_sync_schedule")

    assert schedule.cron_schedule == "0 0 * * *"
    assert schedule.execution_timezone == "UTC"
    assert schedule.default_status is dagster.DefaultScheduleStatus.RUNNING
    assert definitions.get_job_def("third_party_data_sync").name == "third_party_data_sync"
    assert definitions.get_job_def("review_intake").name == "review_intake"
    assert definitions.get_job_def("target_catalog").name == "target_catalog"
    assert definitions.get_job_def("target_analysis_plan").name == "target_analysis_plan"
    assert definitions.get_job_def("project_build").name == "project_build"
    assert definitions.get_job_def("artifact_indexing").name == "artifact_indexing"
    assert definitions.get_job_def("cpp_compiled_analysis").name == "cpp_compiled_analysis"
    assert definitions.get_job_def("post_build_security_assessment").name == "post_build_security_assessment"
    assert definitions.get_job_def("ci_configuration_analysis").name == "ci_configuration_analysis"
    assert definitions.get_job_def("ci_configuration_review").name == "ci_configuration_review"
    assert definitions.get_job_def("wave1_review").name == "wave1_review"


def test_wave1_exposes_real_producer_shard_topology() -> None:
    config = Path(__file__).resolve().parents[3] / "appsec-review.toml"
    graph = build_definitions(config).get_job_def("wave1_review").graph
    names = {node.name for node in graph.node_defs}
    assert "dispatch_wave1_review" not in names
    expected = {
        "review_intake__begin", "target_catalog__begin", "target_analysis_plan__begin",
        "ci_configuration_analysis__ci_discovery__discover_definitions",
        "ci_configuration_analysis__ci_analysis__github_zizmor_scan",
        "ci_configuration_analysis__ci_observation_publication__github_zizmor_index",
        "ci_configuration_analysis__ci_correlation__correlate_findings",
        "ci_configuration_analysis__ci_coverage__join_coverage",
        "target_analysis_plan__analysis_decisions__apply_deterministic_rules",
        "target_analysis_plan__plan_acceptance__index_plan",
        "project_build__plan__load_recipes",
        "project_build__image__native",
        "project_build__static_dispatch__native",
        "project_build__probe__native",
        "project_build__build_dispatch__native",
        "project_build__acceptance__publish_handoff",
        "language_build__load__native",
        "language_build__load__dotnet",
        "language_build__load__rust",
        "language_build__load__wasm",
        "language_build__execute__native",
        "language_build__execute__dotnet",
        "language_build__execute__rust",
        "language_build__execute__wasm",
        "language_build__acceptance__publish_handoff",
        "artifact_indexing__load__accepted_builds",
        "artifact_indexing__index__catalogs",
        "artifact_indexing__index__members",
        "artifact_indexing__index__relationships",
        "artifact_indexing__acceptance__publish_handoff",
        "cpp_compiled_analysis__plan__accepted_cpp_plan",
        "cpp_compiled_analysis__catalog__projects",
        "cpp_compiled_analysis__ast__projects",
        "cpp_compiled_analysis__ir__projects",
        "cpp_compiled_analysis__infer__projects",
        "cpp_compiled_analysis__acceptance__publish_handoff",
        "post_build_security_assessment__load__accepted_cpp_build",
        "post_build_security_assessment__provenance__native_units",
        "post_build_security_assessment__inspection__native_units",
        "post_build_security_assessment__deterministic__native_units",
        "post_build_security_assessment__inference__native_units",
        "post_build_security_assessment__index__native_units",
        "post_build_security_assessment__publication__publish_handoff",
        "evidence_collection__secrets__gitleaks_scan",
        "evidence_collection__secrets__gitleaks_normalize",
        "evidence_collection__secrets__gitleaks_index",
        "evidence_collection__source_sast__semgrep_scan",
        "evidence_collection__software_inventory__syft_scan",
        "evidence_collection__vulnerability_matching__grype_scan",
        "evidence_collection__evidence_publication__assemble_manifest",
        "evidence_collection__evidence_publication__publish_handoff",
    }
    assert expected <= names

    def upstream(node: str) -> set[str]:
        mapping = graph.dependency_structure.input_to_upstream_outputs_for_node(node)
        return {output.node_name for outputs in mapping.values() for output in outputs}

    assert "evidence_collection__secrets__gitleaks_scan" in upstream(
        "evidence_collection__secrets__gitleaks_normalize")
    assert "evidence_collection__secrets__gitleaks_normalize" in upstream(
        "evidence_collection__secrets__gitleaks_index")
    assert "evidence_collection__software_inventory__syft_scan" in upstream(
        "evidence_collection__vulnerability_matching__grype_scan")
    assert "target_catalog__finalize" in upstream("ci_configuration_analysis__begin")
    assert "ci_configuration_analysis__finalize" in upstream("target_analysis_plan__begin")
    assert "target_analysis_plan__finalize" in upstream("project_build__begin")
    assert "project_build__finalize" in upstream("language_build__begin")
    assert upstream("language_build__execute__rust") == {
        "language_build__begin", "language_build__load__rust"}
    assert "language_build__execute__native" not in upstream("language_build__execute__rust")
    assert upstream("language_build__execute__wasm") == {
        "language_build__begin", "language_build__load__wasm"}
    assert "language_build__finalize" in upstream("cpp_compiled_analysis__begin")
    assert "language_build__finalize" in upstream("artifact_indexing__begin")
    assert upstream("artifact_indexing__acceptance__publish_handoff") == {
        "artifact_indexing__begin", "artifact_indexing__index__catalogs",
        "artifact_indexing__index__members", "artifact_indexing__index__relationships"}
    assert "artifact_indexing__finalize" in upstream("artifact_security_analysis__begin")
    assert len(upstream("project_build__acceptance__publish_handoff")) == 20
    assert "cpp_compiled_analysis__finalize" in upstream("post_build_security_assessment__begin")
    assert "target_analysis_plan__finalize" in upstream("evidence_collection__begin")
    assert "post_build_security_assessment__finalize" in upstream("owasp_control_assessment__begin")
    assert "evidence_collection__finalize" in upstream("owasp_control_assessment__begin")
    assert upstream("cpp_compiled_analysis__ast__projects") == {
        "cpp_compiled_analysis__begin", "cpp_compiled_analysis__catalog__projects"}
    assert upstream("cpp_compiled_analysis__ir__projects") == {
        "cpp_compiled_analysis__begin", "cpp_compiled_analysis__catalog__projects"}
    assert upstream("cpp_compiled_analysis__infer__projects") == {
        "cpp_compiled_analysis__begin", "cpp_compiled_analysis__catalog__projects"}
    cpp_barrier = upstream("cpp_compiled_analysis__acceptance__publish_handoff")
    assert len(cpp_barrier) == 8  # claim plus seven project-batched terminal branches
    post_build_barrier = upstream("post_build_security_assessment__publication__publish_handoff")
    assert len(post_build_barrier) == 2  # claim plus the generic accepted-unit index barrier
    barrier = upstream("evidence_collection__evidence_publication__assemble_manifest")
    assert "evidence_collection__secrets__gitleaks_index" in barrier
    assert "evidence_collection__source_sast__semgrep_index" in barrier
    assert "evidence_collection__vulnerability_matching__grype_index" in barrier


def test_wave1_dagster_path_runs_application_graph(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    monkeypatch.setenv("APPSEC_REVIEW_TARGET", str(target))
    config = Path(__file__).resolve().parents[3] / "appsec-review.toml"
    result = build_definitions(config).get_job_def("wave1_review").execute_in_process()
    assert result.success
    assert "evidence_collection__evidence_publication__assemble_manifest" in {
        node.name for node in build_definitions(config).get_job_def("wave1_review").graph.node_defs}


def test_multiprocess_branches_overlap_and_final_manifest_waits(tmp_path: Path, monkeypatch) -> None:
    from dagster import DagsterInstance, execute_job, reconstructable
    from tests.orchestration.dagster.concurrency_fixture import define_job

    config = tmp_path / "appsec-review.toml"
    config.write_text("""
[runtime]
runs_dir = "runs"
data_dir = "data"
metadata_dir = "runs/metadata"
[orchestration.dagster]
executor = "multiprocess"
max_concurrent = 4
[jobs.job_fixture]
name = "fixture"
workers = 4
[jobs.job_fixture.steps.slow]
workers = 1
[jobs.job_fixture.steps.slow.tasks.scan]
[jobs.job_fixture.steps.slow.tasks.normalize]
[jobs.job_fixture.steps.slow.tasks.index]
[jobs.job_fixture.steps.fast]
workers = 1
[jobs.job_fixture.steps.fast.tasks.scan]
[jobs.job_fixture.steps.fast.tasks.normalize]
[jobs.job_fixture.steps.fast.tasks.index]
[jobs.job_fixture.steps.publication]
workers = 1
[jobs.job_fixture.steps.publication.tasks.assemble]
[jobs.job_fixture.steps.publication.tasks.publish]
""".strip(), encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text("pass\n", encoding="utf-8")
    monkeypatch.setenv("APPSEC_TEST_ROOT", str(tmp_path))
    monkeypatch.setenv("APPSEC_REVIEW_TARGET", str(target))
    outcome = []
    dagster_root = tmp_path / "dagster"
    dagster_root.mkdir()
    with DagsterInstance.local_temp(tempdir=str(dagster_root)) as instance:
        thread = threading.Thread(target=lambda: outcome.append(
            execute_job(reconstructable(define_job), instance=instance)), daemon=True)
        thread.start()
        deadline = time.monotonic() + 60
        try:
            while time.monotonic() < deadline and not (tmp_path / "fast-indexed").exists():
                time.sleep(0.05)
            assert (tmp_path / "slow-started").exists()
            assert (tmp_path / "fast-indexed").exists()
            assert not (tmp_path / "manifest-assembled").exists()
        finally:
            (tmp_path / "release-slow").write_text("release", encoding="utf-8")
        thread.join(30)
    assert not thread.is_alive()
    assert outcome and outcome[0].success
    assert (tmp_path / "manifest-assembled").exists() and (tmp_path / "handoff-published").exists()
    events = [__import__("json").loads(line) for line in next((tmp_path / "runs").glob(
        "*/data/logs/pipeline.jsonl")).read_text(encoding="utf-8").splitlines()]
    assert any(item["event_type"] == "TASK_STARTED" and item["task_id"] == "scan" for item in events)
