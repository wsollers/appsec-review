from __future__ import annotations

from pathlib import Path
import json
import os
import threading
import time
from types import SimpleNamespace

import pytest

dagster = pytest.importorskip("dagster")

from appsec_review.orchestration.dagster import build_definitions
from appsec_review.orchestration.dagster.adapter import _metadata_for_outcome
from appsec_review.orchestration.dagster.error_state import record_error_state
from appsec_review.runtime import Job, Unit, UnitExecutor
from appsec_review.runtime.registry import JobRegistry
from appsec_review.runtime.datasets import artifact_only
from appsec_review.storage import shared
from tests.capture_fakes import build_capture_toml


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
""".strip() + "\n\n" + build_capture_toml(),
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


def test_real_dagster_lifecycle_publishes_and_reuses_shared_artifacts(tmp_path: Path) -> None:
    config_path = _config(tmp_path)
    with config_path.open("a") as stream:
        stream.write("\n[jobs.job_fixture.steps.work.tasks.verify]\nworkers = 1\n")
    seen_nodes = []
    fingerprint = "a" * 64

    def compute(context):
        seen_nodes.append(context.job.orchestration["node"])
        owner = shared.SharedArtifacts.for_job(context.job)
        hit = owner.lookup("fixture", fingerprint)
        if hit is None:
            receipt = owner.computed("fixture", fingerprint, shared.put_bytes(owner.run_root, b"fixture"),
                                     computation={"request": fingerprint})
        else:
            _, receipt = hit
        return {"artifact": receipt, "reused": hit is not None}

    def verify(context):
        seen_nodes.append(context.job.orchestration["node"])
        shared.verify_receipt(context.job.run_root, context.output("work.execute")["artifact"])
        return {"verified": True}

    declaration = artifact_only(
        "shared", "work", "inventory", shared.RECEIPT_SCHEMA, "Fixture computation receipts",
        artifacts=("data/jobs/job_fixture/attempts/*/shared/*/*.json",), reason="fixture, not review evidence")
    registry = JobRegistry()
    registry.register("job_fixture", lambda: Job(
        "job_fixture", "fixture", compute,
        units=(Unit("work.execute", compute), Unit("work.verify", verify, ("work.execute",))),
        datasets=(declaration,), always_execute=True))
    job = build_definitions(config_path, registry=registry).get_job_def("fixture")
    first = job.execute_in_process()
    assert first.success
    run_root, = (tmp_path / "runs").glob("????-??-??-????")
    attempts = run_root / "data/jobs/job_fixture/attempts"
    original_claim = (attempts / "attempt_0001/claim.json").read_bytes()
    second = job.execute_in_process(tags={"appsec/application_run_id": run_root.name})
    assert second.success
    assert seen_nodes == ["standalone__fixture__work__execute", "standalone__fixture__work__verify"] * 2
    receipts = []
    for number, invocation in ((1, first.run_id), (2, second.run_id)):
        attempt = attempts / f"attempt_{number:04d}"
        reference = shared.reference(run_root, attempt / f"shared/fixture/{fingerprint}.json")
        receipt = shared.verify_receipt(run_root, reference)
        receipts.append((reference, receipt))
        assert receipt["actor"]["orchestration"] == {
            "system": "dagster", "run_id": invocation, "node": "standalone__fixture__begin"}
        status = json.loads((attempt / "steps/work/tasks/execute/status.json").read_text())
        assert status["dagster_node"] == "standalone__fixture__work__execute"
        assert status["dagster_run_id"] == invocation
        assert json.loads((attempt / "handoff.json").read_text())["status"] == "ACCEPTED"
    assert receipts[0][1]["mode"] == "computed"
    assert receipts[1][1]["mode"] == "reused"
    assert receipts[1][1]["producer_receipt"] == receipts[0][0]
    assert (attempts / "attempt_0001/claim.json").read_bytes() == original_claim
    assert len(list((run_root / shared.OBJECTS).iterdir())) == 1


@pytest.mark.parametrize("mode", ("strict", "first_party_managed"))
def test_dagster_reuses_accepted_target_attempt_with_original_policy(
        tmp_path: Path, monkeypatch, mode: str) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n", encoding="utf-8")
    monkeypatch.setenv("APPSEC_REVIEW_TARGET", str(target))
    config_path = _config(tmp_path, configured_job="job_target_catalog")
    with config_path.open("a", encoding="utf-8") as stream:
        stream.write(
            '\n[jobs.job_target_catalog.settings]\nmax_document_files = 10\n'
            'max_document_file_bytes = 1024\nmax_document_records = 100\n'
            f'\n[review_policy]\nmode = "{mode}"\nproject_id = "fixture"\n'
            'approved_first_party_projects = ["fixture"]\ncustody = "application_private_v1"\n'
            f'target_root = {json.dumps(str(target))}\n'
            '\n[review_policy.releases]\nplatform = "fixture/1"\nvalidation = "fixture/1"\n')
    calls = []

    def produce(unit):
        calls.append(unit.job.attempt_id)
        return {"artifact": shared.put_bytes(unit.job.run_root, b"customer evidence")}

    registry = JobRegistry()
    registry.register("job_target_catalog", lambda: Job(
        "job_target_catalog", "fixture", produce, units=(Unit("work.execute", produce),)))
    job = build_definitions(config_path, registry=registry).get_job_def("fixture")
    assert job.execute_in_process().success
    run_root, = (tmp_path / "runs").glob("????-??-??-????")
    attempts = run_root / "data/jobs/job_target_catalog/attempts"
    claim_path = attempts / "attempt_0001/claim.json"
    original_claim = claim_path.read_bytes()
    frozen_path = run_root / "data/configuration/resolved.json"
    original_configuration = frozen_path.read_bytes()

    assert job.execute_in_process(tags={"appsec/application_run_id": run_root.name}).success
    assert calls == ["attempt_0001"]
    assert [path.name for path in attempts.iterdir()] == ["attempt_0001"]
    assert claim_path.read_bytes() == original_claim
    assert frozen_path.read_bytes() == original_configuration


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


@pytest.mark.parametrize("job_id", ["job_artifact_indexing", "job_artifact_security_analysis",
                                    "job_review_data_indexing", "job_review_package_assembly"])
def test_target_bound_jobs_receive_target_snapshot(tmp_path: Path, monkeypatch, job_id: str) -> None:
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
            return {"status": {"run_id": "test-run", "attempt_id": "attempt_0001",
                               "trigger": "manual", "status": "SUCCEEDED"},
                    "handoff_sha256": "a" * 64,
                    "handoff": {}, "attempt_root": str(tmp_path / "attempt"),
                    "result": {"steps": {}, "units": {}, "outputs": {},
                               "failed_units": [], "skipped_units": []}}

    definitions = build_definitions(_config(tmp_path, configured_job=job_id),
                                    registry=registry, runner_factory=Runner)
    assert definitions.get_job_def("fixture").execute_in_process().success
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


def test_error_state_records_terminal_run_and_last_five_events(tmp_path: Path) -> None:
    class Instance:
        def get_run_by_id(self, run_id):
            assert run_id == "failed-run"
            return SimpleNamespace(job_name="wave1_review", status=dagster.DagsterRunStatus.FAILURE,
                                   tags={"appsec/application_run_id": "app-run"})

        def get_records_for_run(self, run_id, **options):
            assert run_id == "failed-run"
            assert options["limit"] == 5 and options["ascending"] is False
            entries = [SimpleNamespace(event_log_entry=SimpleNamespace(
                message=f"failure {index}\nmore detail",
                dagster_event=SimpleNamespace(event_type_value="STEP_FAILURE",
                                              step_key=f"step_{index}",
                                              event_specific_data=SimpleNamespace(error=SimpleNamespace(
                                                  message="Dagster wrapper", cause=SimpleNamespace(
                                                      message=f"root cause {index}\nmore detail",
                                                      cause=None))))))
                       for index in range(5, 0, -1)]
            return SimpleNamespace(records=entries)

    path = record_error_state(Instance(), "failed-run", tmp_path)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 6
    assert "status=FAILURE" in lines[0] and "application_run_id=app-run" in lines[0]
    assert "step=step_1" in lines[1] and "step=step_5" in lines[-1]
    assert "root cause 1 more detail" in lines[1]
    assert all("\n" not in line for line in lines)


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
    assert definitions.get_job_def("model_connectivity").name == "model_connectivity"
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
    assert definitions.get_job_def("wave1_error_state").name == "wave1_error_state"
    for name in ("wave1_failure_state", "wave1_canceled_state", "wave1_step_failure_state"):
        assert definitions.get_sensor_def(name).default_status is dagster.DefaultSensorStatus.RUNNING


def test_job_level_disabled_setting_is_transparent_to_dagster(tmp_path: Path) -> None:
    source = (Path(__file__).resolve().parents[3] / "appsec-review.toml").read_text(encoding="utf-8")
    source = source.replace(
        '[jobs.job_codeql_analysis.settings]\nenabled = true\nexecution_mode = "auto"',
        '[jobs.job_codeql_analysis.settings]\nenabled = false\nexecution_mode = "disabled"',
        1,
    )
    config = tmp_path / "appsec-review.toml"
    config.write_text(source, encoding="utf-8")

    definitions = build_definitions(config)
    job_names = {job.name for job in definitions.get_repository_def().get_all_jobs()}
    wave_nodes = {node.name for node in definitions.get_job_def("wave1_review").graph.node_defs}

    assert "codeql_analysis" not in job_names
    assert not any(name.startswith("codeql_analysis__") for name in wave_nodes)
    assert "review_prioritization__begin" in wave_nodes


def test_wave1_exposes_real_producer_shard_topology() -> None:
    config = Path(__file__).resolve().parents[3] / "appsec-review.toml"
    graph = build_definitions(config).get_job_def("wave1_review").graph
    names = {node.name for node in graph.node_defs}
    assert "dispatch_wave1_review" not in names
    assert not any(name.startswith("cpg_analysis__") for name in names)
    expected = {
        "model_connectivity__begin", "model_connectivity__connectivity__verify_models",
        "review_intake__begin", "target_catalog__begin", "target_analysis_plan__begin",
        "target_catalog__retrieval_indexes__build_target_documents",
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

    def assert_barrier_waits_for_every_branch(job: str) -> None:
        # The publish barrier waits for the job's claim plus every terminal branch of that job.
        barrier = f"{job}__acceptance__publish_handoff"
        members = {name for name in names if name.startswith(f"{job}__")} - {barrier, f"{job}__finalize"}
        feeding = set().union(*(upstream(name) for name in members))
        terminal = {f"{job}__begin"} | {name for name in members if name not in feeding}
        assert terminal <= upstream(barrier) <= members

    assert upstream("image_pin_verification__begin") == {"model_connectivity__finalize"}
    assert upstream("review_intake__begin") == {"image_pin_verification__finalize"}

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
    assert_barrier_waits_for_every_branch("project_build")
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
    assert_barrier_waits_for_every_branch("cpp_compiled_analysis")
    post_build_barrier = upstream("post_build_security_assessment__publication__publish_handoff")
    assert len(post_build_barrier) == 2  # claim plus the generic accepted-unit index barrier
    barrier = upstream("evidence_collection__evidence_publication__assemble_manifest")
    assert "evidence_collection__secrets__gitleaks_index" in barrier
    assert "evidence_collection__source_sast__semgrep_index" in barrier
    assert "evidence_collection__vulnerability_matching__grype_index" in barrier
    # Prioritization consumes the accepted Tree-sitter, Semgrep, CodeQL, and history handoffs and
    # publishes a retrieval shard, so it follows the last manifest publishers and precedes tagging.
    assert {"codeql_analysis__finalize", "owasp_control_assessment__finalize"} <= upstream(
        "review_prioritization__begin")
    assert "review_prioritization__finalize" in upstream("security_tagging__begin")
    assert "security_tagging__finalize" in upstream("review_data_indexing__begin")
    assert "review_data_indexing__finalize" in upstream("review_package_assembly__begin")
    assert upstream("review_package_assembly__publication__publish_packages") == {
        "review_package_assembly__begin"}
    assert upstream("review_prioritization__extract__semantic_evidence") >= {
        "review_prioritization__extract__syntax_metrics"}


@pytest.mark.skipif(
    Path("/.dockerenv").exists() and not Path("/var/run/docker.sock").exists(),
    reason="the deployment-test container was not given a Docker engine",
)
def _missing_catalog_images() -> list[str]:
    """Tool images the full wave-1 graph needs that this host cannot run."""
    import shutil
    import subprocess

    from appsec_review.container_runtime.catalog import load_catalog

    if shutil.which("docker") is None:
        return ["docker"]
    catalog = load_catalog(Path(__file__).resolve().parents[3])
    missing = []
    for tool_id, tool in sorted(catalog.tools.items()):
        probe = subprocess.run(("docker", "image", "inspect", tool.tag), capture_output=True, timeout=60)
        if probe.returncode != 0:
            missing.append(tool_id)
    return missing


def test_wave1_dagster_path_runs_application_graph(tmp_path: Path, monkeypatch) -> None:
    # Live tier: the real wave-1 graph runs every cataloged tool image. Skip, naming what is
    # missing, rather than fail on hosts without the images.
    missing = _missing_catalog_images()
    if missing:
        pytest.skip("live wave-1 run needs local tool images: " + ", ".join(missing))
    target = tmp_path / "target"
    target.mkdir()
    (target / "main.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    monkeypatch.setenv("APPSEC_REVIEW_TARGET", str(target))
    config = Path(__file__).resolve().parents[3] / "appsec-review.toml"
    # Keep run output under the test's temporary directory, never in the repository's runs/.
    from dataclasses import replace

    from appsec_review.orchestration.dagster import adapter

    load = adapter.load_config

    def isolated(source):
        loaded = load(source)
        runs = tmp_path / "runs"
        return replace(loaded, runtime=replace(loaded.runtime, runs_dir=runs, metadata_dir=runs / "metadata"))

    monkeypatch.setattr(adapter, "load_config", isolated)
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
""".strip() + "\n\n" + build_capture_toml(), encoding="utf-8")
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


def test_standalone_launch_binds_tagged_upstream_handoffs(tmp_path: Path) -> None:
    import hashlib
    import json

    run_root = tmp_path / "runs" / "2026-10-16-0004"
    handoff = run_root / "data" / "jobs" / "job_review_intake" / "attempts" / "attempt_0001" / "handoff.json"
    handoff.parent.mkdir(parents=True)
    handoff.write_text(json.dumps({"job_id": "job_review_intake", "status": "ACCEPTED"}), encoding="utf-8")
    digest = hashlib.sha256(handoff.read_bytes()).hexdigest()
    (run_root / "data" / "jobs" / "job_review_intake" / "latest.json").write_text(json.dumps({
        "handoff_path": handoff.relative_to(run_root).as_posix(), "handoff_sha256": digest}), encoding="utf-8")
    begun: list[dict[str, object]] = []

    class Runner:
        def __init__(self, config):
            pass

        def begin_attempt(self, job, **kwargs):
            begun.append(kwargs)
            return {"run_id": kwargs["run_id"], "attempt_id": "attempt_0001", "trigger": "manual",
                    "orchestration": kwargs["orchestration"], "attempt_path": "attempt",
                    "source_fingerprint": "none", "upstream_handoffs": kwargs["upstream_handoffs"],
                    "started_at": "2026-10-08T00:00:00+00:00"}

        def execute_or_reuse_unit(self, job, claim, unit_id):
            return {"value": 1}

        def finalize_attempt(self, job, claim):
            return {"status": {"run_id": claim["run_id"], "attempt_id": "attempt_0001",
                               "trigger": "manual", "status": "SUCCEEDED"},
                    "handoff_sha256": "b" * 64, "attempt_root": str(tmp_path / "attempt"),
                    "result": {"steps": {}, "units": {}, "outputs": {},
                               "failed_units": [], "skipped_units": []}}

    definitions = build_definitions(_config(tmp_path), registry=_registry(), runner_factory=Runner)
    job = definitions.get_job_def("fixture")
    tags = {"appsec/application_run_id": "2026-10-16-0004",
            "appsec/upstream_handoffs": json.dumps({"job_review_intake": digest})}
    assert job.execute_in_process(tags=tags).success
    assert begun[0]["run_id"] == "2026-10-16-0004"
    assert begun[0]["upstream_handoffs"] == {"job_review_intake": digest}
    tags["appsec/upstream_handoffs"] = json.dumps({"job_review_intake": "0" * 64})
    assert not job.execute_in_process(tags=tags, raise_on_error=False).success
    assert len(begun) == 1
