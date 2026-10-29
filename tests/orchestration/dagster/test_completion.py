from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

pytest.importorskip("dagster")

from appsec_review.config import load_config
from appsec_review.observability import PipelineLog
from appsec_review.orchestration.dagster import adapter
from appsec_review.orchestration.dagster.adapter import build_definitions
from appsec_review.runtime import Job, Unit
from tests.capture_fakes import build_capture_toml


@pytest.mark.parametrize("export_enabled", [True, False])
def test_real_completion_graph_certifies_every_producer_before_gate_only_report(tmp_path, export_enabled) -> None:
    config = Path(__file__).resolve().parents[3] / "appsec-review.toml"
    if not export_enabled:
        source = config.read_text(encoding="utf-8")
        header = "[jobs.job_openvex_export.settings]\nenabled = true"
        assert source.count(header) == 1
        config = tmp_path / "appsec-review.toml"
        config.write_text(source.replace(header, header.replace("true", "false"), 1), encoding="utf-8")
    definitions = build_definitions(config)
    definitions.get_repository_def().load_all_definitions()
    graph = definitions.get_job_def("wave1_review").graph
    expected = {
        "poc_generation": ("inference_security_review",),
        "remediation_planning": ("inference_security_review", "poc_generation"),
        "remediation_validation": ("remediation_planning",),
        "dossier_publication": (
            "inference_security_review", "poc_generation",
            "remediation_planning", "remediation_validation"),
        "final_publication_gate": (
            "inference_security_review", "poc_generation",
            "remediation_planning", "remediation_validation", "dossier_publication"),
        "final_report_publication": ("final_publication_gate",),
    }
    for job, parents in expected.items():
        dependencies = graph.dependency_structure.input_to_upstream_outputs_for_node(f"{job}__begin")
        actual = {output.node_name for outputs in dependencies.values() for output in outputs}
        assert actual == {f"{parent}__finalize" for parent in parents}
    terminal_nodes = {"final_report_publication__finalize"}
    if export_enabled:
        dependencies = graph.dependency_structure.input_to_upstream_outputs_for_node("openvex_export__begin")
        assert {output.node_name for outputs in dependencies.values() for output in outputs} == {
            "final_publication_gate__finalize"}
        terminal_nodes.add("openvex_export__finalize")
    else:
        assert not any(node.name.startswith("openvex_export__") for node in graph.node_defs)
    completion = graph.dependency_structure.input_to_upstream_outputs_for_node("wave1_review__complete")
    assert {output.node_name for outputs in completion.values() for output in outputs} == terminal_nodes


@pytest.mark.parametrize("gap_job", [None, "job_gate", "job_report", "job_export"])
@pytest.mark.parametrize("export_enabled", [True, False])
def test_graph_completion_waits_for_all_terminals_and_merges_receipts(
        tmp_path, monkeypatch, gap_job, export_enabled):
    _execute_terminal_fixture(tmp_path, monkeypatch, gap_job=gap_job, export_enabled=export_enabled)


def test_failed_terminal_never_publishes_success_or_final_metrics(tmp_path, monkeypatch):
    _execute_terminal_fixture(tmp_path, monkeypatch, failed_job="job_export")


def test_real_split_failure_records_live_step_then_terminal_run_once(tmp_path):
    import dagster
    from appsec_review.runtime import JobRunner
    from appsec_review.orchestration.dagster.error_state import record_error_state, record_step_failures
    from appsec_review.storage import file_sha256

    source = '[runtime]\nruns_dir = "runs"\ndata_dir = "data"\n' + build_capture_toml()
    source += '\n[jobs.job_fixture]\nname = "fixture"\nworkers = 1\n'
    for step, task in (("first", "fail"), ("second", "observe"), ("publish", "export")):
        source += (f"\n[jobs.job_fixture.steps.{step}]\nworkers = 1\n"
                   f"[jobs.job_fixture.steps.{step}.tasks.{task}]\nworkers = 1\n")
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(source)
    config = load_config(config_path)
    platform = tmp_path / "containers/tool.toml"
    platform.parent.mkdir()
    platform.write_text("supplied platform, not customer evidence")
    runner = JobRunner(config)
    accepted = runner.run(Job("job_fixture", "fixture", lambda _: {},
                             units=(Unit("first.fail", lambda _: {}),)))
    root = config.runtime.runs_dir / accepted["status"]["run_id"]
    pointer = root / "data/jobs/job_fixture/latest.json"
    before = pointer.read_bytes()
    observed = []

    def fail(unit):
        file_sha256(platform)
        pytest.fail("strict scope accepted platform payload")

    with dagster.instance_for_test() as instance:
        def observe(unit):
            run_id = unit.job.orchestration["run_id"]
            assert instance.get_run_by_id(run_id).status == dagster.DagsterRunStatus.STARTED
            paths, _ = record_step_failures(instance, config.runtime.runs_dir, None)
            assert len(paths) == 1
            assert not (config.runtime.runs_dir / "metadata/dagster-error-state" / f"{run_id}.log").exists()
            assert not (root / f"data/orchestration/dagster/{run_id}.json").exists()
            observed.extend(paths)
            return {"terminal_status": "SUCCEEDED"}

        def forbidden(unit):
            pytest.fail("publication ran after a failed prerequisite")

        units = (Unit("first.fail", fail), Unit("second.observe", observe),
                 Unit("publish.export", forbidden, ("first.fail",)))
        job = Job("job_fixture", "fixture", lambda _: {}, units=units)
        graph = adapter._build_dagster_graph("wave1_review", (job,), config, JobRunner)
        result = graph.execute_in_process(instance=instance, raise_on_error=False,
            tags={"appsec/application_run_id": root.name})
        assert not result.success and len(observed) == 1
        terminal = record_error_state(instance, result.run_id, config.runtime.runs_dir)
        receipt = root / f"data/orchestration/dagster/{result.run_id}.json"
        assert json.loads(receipt.read_bytes())["status"] == "FAILURE"
        attempt = root / "data/jobs/job_fixture/attempts/attempt_0002"
        assert json.loads((attempt / "status.json").read_bytes())["status"] == "FAILED"
        assert json.loads((attempt / "steps/first/lifecycle.json").read_bytes())["status"] == "FAILED"
        assert json.loads((attempt / "steps/second/lifecycle.json").read_bytes())["status"] == "SUCCEEDED"
        assert not (attempt / "steps/publish").exists()
        assert pointer.read_bytes() == before
        assert (attempt / "rejected-handoff.json").is_file()
        retained = {path: (path.read_bytes(), path.stat().st_mtime_ns)
                    for path in (*observed, terminal, receipt)}
        record_step_failures(instance, config.runtime.runs_dir, json.dumps({result.run_id: None}))
        record_error_state(instance, result.run_id, config.runtime.runs_dir)
        assert retained == {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in retained}
        records, _ = PipelineLog(root).read()
        current = [event for event in records
                   if event.get("details", {}).get("dagster_run_id") == result.run_id]
        assert sum(event["event_type"] == "GRAPH_FAILED" for event in current) == 1
        assert sum(event["event_type"] == "RUN_COMPLETED" for event in current) == 1
        assert not any(event["event_type"] == "GRAPH_SUCCEEDED" for event in current)


def _execute_terminal_fixture(tmp_path, monkeypatch, *, gap_job=None, export_enabled=True, failed_job=None):
    job_ids = ("job_gate", "job_report", "job_export") if export_enabled else ("job_gate", "job_report")
    source = '[runtime]\nruns_dir = "runs"\ndata_dir = "data"\n' + build_capture_toml()
    for job_id in job_ids:
        source += (f'\n[jobs.{job_id}]\nname = "{job_id}"\nworkers = 1\n'
                   f"[jobs.{job_id}.steps.work]\nworkers = 1\n"
                   f"[jobs.{job_id}.steps.work.tasks.execute]\nworkers = 1\n")
    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text(source, encoding="utf-8")
    config = load_config(config_path)
    jobs = tuple(Job(job_id, job_id, lambda _: {}, units=(Unit("work.execute", lambda _: {}),))
                 for job_id in job_ids)
    digests = {job_id: hashlib.sha256(job_id.encode()).hexdigest() for job_id in job_ids}
    run_root = tmp_path / "runs" / "test-run"
    finalized = []
    metrics = []

    def assert_incomplete():
        records, _ = PipelineLog(run_root).read()
        assert not any(record["event_type"] in {
            "RUN_COMPLETED", "GRAPH_SUCCEEDED", "GRAPH_COMPLETED_WITH_GAPS"} for record in records)
        assert not list((run_root / "data" / "orchestration").glob("dagster/*.json"))
        assert not metrics

    class Runner:
        def __init__(self, _config):
            pass

        def begin_attempt(self, job, **kwargs):
            assert_incomplete()
            return {"run_id": kwargs["run_id"] or "test-run", "attempt_id": "attempt_0001",
                    "trigger": kwargs["trigger"], "orchestration": kwargs["orchestration"],
                    "attempt_path": "attempt", "source_fingerprint": "none",
                    "upstream_handoffs": kwargs["upstream_handoffs"],
                    "started_at": "2026-10-28T00:00:00+00:00"}

        def execute_or_reuse_unit(self, job, claim, unit_id):
            assert_incomplete()
            return {}

        def finalize_attempt(self, job, claim):
            assert_incomplete()
            if job.job_id == failed_job:
                raise ValueError("terminal failed")
            finalized.append(job.job_id)
            return {
                "status": {"run_id": claim["run_id"], "attempt_id": claim["attempt_id"],
                           "trigger": claim["trigger"], "status": (
                               "COMPLETED_WITH_GAPS" if job.job_id == gap_job else "SUCCEEDED")},
                "handoff_sha256": digests[job.job_id], "attempt_root": str(tmp_path / job.job_id),
                "result": {"steps": {}, "units": {}, "outputs": {}, "failed_units": [], "skipped_units": []},
            }

    def write_metrics(path):
        assert set(finalized) == set(job_ids)
        assert path == run_root
        metrics.append(path)

    monkeypatch.setattr(adapter, "write_run_metrics", write_metrics)
    job = adapter._build_dagster_graph(
        "terminal_fixture", jobs, config, Runner,
        job_dependencies={job_id: (() if job_id == "job_gate" else ("job_gate",)) for job_id in job_ids})
    result = job.execute_in_process(raise_on_error=False)
    if failed_job:
        assert not result.success
        assert_incomplete()
        return
    assert result.success
    expected_status = "COMPLETED_WITH_GAPS" if gap_job in job_ids else "SUCCEEDED"
    records, _ = PipelineLog(run_root).read()
    assert sum(record["event_type"] == "RUN_COMPLETED" for record in records) == 1
    assert sum(record["event_type"] in {
        "GRAPH_SUCCEEDED", "GRAPH_COMPLETED_WITH_GAPS"} for record in records) == 1
    receipt = json.loads((run_root / "data" / "orchestration" / "dagster" / f"{result.run_id}.json").read_bytes())
    assert receipt["completion_status"] == expected_status
    assert receipt["handoff_sha256"] == digests
    assert receipt["decisions"] == [{"job_id": job_id, "action": "execute"} for job_id in job_ids]
    assert metrics == [run_root]
    completed = result.output_for_node("terminal_fixture__complete")
    assert completed["completion_status"] == expected_status
    assert completed["completed_handoffs"] == digests
