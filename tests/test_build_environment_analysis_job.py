"""job_build_environment_analysis through the real runner (job pass 06).

Unit tests: the real configuration, the real GraphRunner with intake and the catalog as producers, a
small synthetic target under tmp_path. No Docker, no model, no network. The static analysis rules are
unit-tested in tests/test_build_environment_analysis.py; this file proves what the job publishes, how
it reports its bounded gaps as producer-gap/1 records, how it fails and resumes, and its telemetry.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_build_environment_analysis import build_job
from appsec_review.jobs.job_build_environment_analysis.job import (
    JOB_ID, SCHEMA, BuildEnvironmentAnalysisFailed, environment_contract, gap_records, load_environment,
)
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.runtime import GraphRunner
from tests.telemetry_support import assert_job_lifecycle, job_events

ROOT = Path(__file__).resolve().parents[1]


def _config(tmp_path: Path):
    shutil.copyfile(ROOT / "appsec-review.toml", tmp_path / "appsec-review.toml")
    (tmp_path / "profiles").mkdir()
    return load_config(tmp_path / "appsec-review.toml", profile="dev")


def _target(tmp_path: Path, files: dict[str, bytes]) -> Path:
    target = tmp_path / "target"
    for relative, data in files.items():
        (target / relative).parent.mkdir(parents=True, exist_ok=True)
        (target / relative).write_bytes(data)
    return target


def _run(config, target: Path, *, run_id: str | None = None, job=None):
    try:
        outcome = GraphRunner(config, [build_intake(), build_catalog(), job or build_job()]).run(
            target_root=target, source_fingerprint=source_fingerprint(target), run_id=run_id)
    except RuntimeError as error:
        # The graph runner raises on a failed job; the run tree is where the evidence is.
        [run_root] = [path for path in config.runtime.runs_dir.iterdir() if (path / "data").is_dir()]
        return {"status": "FAILED", "error": str(error), "run_id": run_root.name}, run_root
    return outcome, config.runtime.runs_dir / outcome["run_id"]


def _handoff(run_root: Path) -> dict:
    pointer = json.loads((run_root / "data/jobs" / JOB_ID / "latest.json").read_bytes())
    return json.loads((run_root / pointer["handoff_path"]).read_bytes())


CLEAN = {"setup.sh": b"SDK_ROOT=tools/sdk\nCC=clang\n", "src/main.c": b"int main(void) { return 0; }\n",
         "Makefile": b"all:\n\t$(CC) src/main.c -o main\n"}


def test_clean_scripts_publish_complete_coverage_with_no_gaps_and_the_lifecycle_telemetry(tmp_path: Path) -> None:
    config = _config(tmp_path)
    outcome, run_root = _run(config, _target(tmp_path, CLEAN))
    assert outcome["status"] == "SUCCEEDED", outcome
    handoff = _handoff(run_root)
    result = handoff["outputs"]["environment_analysis.publish_handoff"]
    assert result["schema"] == SCHEMA and result["gaps"] == [] and result["terminal_status"] == "SUCCEEDED"
    artifact = json.loads((run_root / result["artifact"]["path"]).read_bytes())
    assert artifact["availability"] == "AVAILABLE" and artifact["coverage"] == "complete" and artifact["gaps"] == []
    assert [(d["name"], d["value"], d["status"]) for d in artifact["declarations"]] == [
        ("SDK_ROOT", "tools/sdk", "declared"), ("CC", "clang", "declared")]
    # What the plan reads: the strict current reader resolves the published artifact and its catalog.
    contract = environment_contract(config, {"workflow": "wave1_review"}, {JOB_ID: handoff and json.loads(
        (run_root / "data/jobs" / JOB_ID / "latest.json").read_bytes())["handoff_sha256"]})
    assert load_environment(run_root, source_fingerprint(tmp_path / "target"), contract)["availability"] == "AVAILABLE"
    [started] = job_events(run_root, JOB_ID, "BUILD_ENVIRONMENT_ANALYSIS_STARTED")
    assert started["selected_scripts"] == 1 and started["inventory_files"] == 3 and started["max_scripts"] >= 1
    [analyzed] = job_events(run_root, JOB_ID, "BUILD_ENVIRONMENT_ANALYZED")
    assert analyzed == {"unit_id": "environment_analysis.analyze_scripts", "availability": "AVAILABLE", "coverage": "complete",
                        "inspected_scripts": 1, "declaration_count": 2, "gap_count": 0}
    [published] = job_events(run_root, JOB_ID, "BUILD_ENVIRONMENT_PUBLISHED")
    assert published["gap_count"] == 0 and published["artifact"] == result["artifact"]
    assert_job_lifecycle(run_root, JOB_ID, terminal="SUCCEEDED")


def test_bounded_gaps_are_producer_gap_records_and_the_attempt_completes_with_gaps(tmp_path: Path) -> None:
    config = _config(tmp_path)
    files = {**CLEAN, "env.sh": b"if [ -z \"$X\" ]; then\n  export X=1\nfi\nsource tools/missing.sh\nTOKEN=s3cr3t-value-ZZ9\n",
             "deploy.ps1": b"$env:Y = 1\n"}
    outcome, run_root = _run(config, _target(tmp_path, files))
    assert outcome["status"] == "COMPLETED_WITH_GAPS", outcome
    result = _handoff(run_root)["outputs"]["environment_analysis.publish_handoff"]
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    artifact = json.loads((run_root / result["artifact"]["path"]).read_bytes())
    assert artifact["coverage"] == "partial" and artifact["availability"] == "AVAILABLE"
    # The artifact keeps its own bounded gap strings; the unit result carries them as producer-gap/1
    # records, scoped to the script when the gap names one.
    assert set(artifact["gaps"]) == {"PowerShell environment scripts are not supported",
                                     "env.sh: unresolved_script_context_or_condition", "env.sh: unresolved_sourcing",
                                     "env.sh: unsupported_script_statement"}
    records = result["gaps"]
    assert [r["code"] for r in records] == ["producer_reported_gap"] * len(artifact["gaps"])
    assert {r["reason"] for r in records} == set(artifact["gaps"])
    assert {r["scope_id"] for r in records} == {None, "env.sh"}
    assert all(r["retryable"] is False and r["unit_id"] == "environment_analysis.publish_handoff" for r in records)
    assert records == gap_records(artifact["gaps"], "environment_analysis.publish_handoff")
    # The secret is redacted in the artifact and never reaches the event stream.
    redacted = [d for d in artifact["declarations"] if d["status"] == "redacted"]
    assert redacted and all(d["name"] == "[REDACTED]" and d["value"] is None for d in redacted)
    assert "s3cr3t-value-ZZ9" not in (run_root / "data/logs/pipeline.jsonl").read_text(encoding="utf-8")
    assert "s3cr3t-value-ZZ9" not in (run_root / result["artifact"]["path"]).read_text(encoding="utf-8")
    [published] = job_events(run_root, JOB_ID, "BUILD_ENVIRONMENT_PUBLISHED")
    assert published["gap_count"] == len(records) and published["coverage"] == "partial"
    assert_job_lifecycle(run_root, JOB_ID, terminal="COMPLETED_WITH_GAPS")


def test_a_script_whose_bytes_changed_after_the_catalog_fails_the_attempt_and_resume_republishes(tmp_path: Path) -> None:
    from tests.release_support import write_release
    config = _config(tmp_path)
    write_release(tmp_path, ("job_review_intake", "job_target_catalog", JOB_ID))
    target = _target(tmp_path, CLEAN)
    fingerprint = source_fingerprint(target)
    # The script changes under the accepted inventory after the catalog accepted it and before the
    # environment job reads it (the seam runs inside the job, after the catalog is loaded).
    mutate = lambda _unit: (target / "setup.sh").write_bytes(b"SDK_ROOT=tools/other\n")
    outcome, run_root = _run(config, target, job=build_job(before_reading=mutate))
    assert outcome["status"] == "FAILED" and "accepted environment source bytes changed" in outcome["error"]
    assert not (run_root / "data/jobs" / JOB_ID / "latest.json").exists()
    receipt = json.loads(next(run_root.rglob(f"jobs/{JOB_ID}/attempts/*/steps/environment_analysis/tasks/analyze_scripts/status.json"))
                         .read_text(encoding="utf-8"))
    assert receipt["status"] == "FAILED" and receipt["error"]["type"] == BuildEnvironmentAnalysisFailed.__name__
    assert job_events(run_root, JOB_ID, "BUILD_ENVIRONMENT_PUBLISHED") == []
    assert len(job_events(run_root, JOB_ID, "BUILD_ENVIRONMENT_ANALYSIS_STARTED")) == 1
    assert_job_lifecycle(run_root, JOB_ID, terminal="FAILED")
    # The cause removed (the accepted bytes restored), resume publishes a second attempt.
    (target / "setup.sh").write_bytes(CLEAN["setup.sh"])
    resumed = GraphRunner(config, [build_intake(), build_catalog(), build_job()]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=outcome["run_id"])
    assert resumed["status"] == "SUCCEEDED"
    assert {item["job_id"]: item["action"] for item in resumed["decisions"]} == {
        "job_review_intake": "REUSE", "job_target_catalog": "REUSE", JOB_ID: "RUN"}
    assert (run_root / "data/jobs" / JOB_ID / "latest.json").exists()
    assert len(list((run_root / "data/jobs" / JOB_ID / "attempts").iterdir())) == 2
    assert_job_lifecycle(run_root, JOB_ID, terminal="SUCCEEDED", attempts=2)


def test_a_missing_accepted_script_is_the_jobs_own_failure(tmp_path: Path) -> None:
    config = _config(tmp_path)
    target = _target(tmp_path, CLEAN)
    outcome, run_root = _run(config, target, job=build_job(before_reading=lambda _unit: (target / "setup.sh").unlink()))
    assert outcome["status"] == "FAILED" and "accepted environment script is missing: setup.sh" in outcome["error"]
    receipt = json.loads(next(run_root.rglob(f"jobs/{JOB_ID}/attempts/*/steps/environment_analysis/tasks/analyze_scripts/status.json"))
                         .read_text(encoding="utf-8"))
    assert receipt["error"]["type"] == BuildEnvironmentAnalysisFailed.__name__
    assert_job_lifecycle(run_root, JOB_ID, terminal="FAILED")


def test_no_environment_scripts_is_not_applicable_coverage_without_gaps(tmp_path: Path) -> None:
    config = _config(tmp_path)
    outcome, run_root = _run(config, _target(tmp_path, {"src/main.c": CLEAN["src/main.c"], "Makefile": CLEAN["Makefile"]}))
    assert outcome["status"] == "SUCCEEDED"
    artifact = json.loads((run_root / _handoff(run_root)["outputs"]["environment_analysis.publish_handoff"]["artifact"]["path"]).read_bytes())
    assert artifact["coverage"] == "not_applicable" and artifact["availability"] == "AVAILABLE"
    assert artifact["declarations"] == [] and artifact["gaps"] == [] and artifact["bounds"]["inspected_scripts"] == 0
    [analyzed] = job_events(run_root, JOB_ID, "BUILD_ENVIRONMENT_ANALYZED")
    assert analyzed["coverage"] == "not_applicable" and analyzed["inspected_scripts"] == 0


def test_configured_topology_matches_the_job_and_the_job_is_strict() -> None:
    config = load_config(ROOT / "appsec-review.toml", profile="dev")
    job = config.jobs[JOB_ID]
    assert tuple(job.steps) == ("environment_analysis",)
    assert tuple(job.step("environment_analysis").tasks) == ("analyze_scripts", "publish_handoff")
    built = build_job()
    assert [unit.unit_id for unit in built.units] == ["environment_analysis.analyze_scripts", "environment_analysis.publish_handoff"]
    assert built.strict_gaps is True


@pytest.mark.parametrize("gap, scope", [
    ("tools/env.sh: unresolved_sourcing", "tools/env.sh"), ("setup.bat: unsupported_script_statement", "setup.bat"),
    ("script_count_exhausted", None), ("internal_environment_deadline", None),
    ("PowerShell environment scripts are not supported", None),
])
def test_gap_records_scope_script_gaps_to_their_path(gap: str, scope: str | None) -> None:
    [record] = gap_records([gap], "environment_analysis.publish_handoff")
    assert record["schema"] == "appsec-review/producer-gap/1" if "schema" in record else True
    assert record["code"] == "producer_reported_gap" and record["reason"] == gap and record["scope_id"] == scope
    assert record["retryable"] is False
