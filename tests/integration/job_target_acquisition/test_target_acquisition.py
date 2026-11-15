"""Pre-walk suite pending replacement (pre-walk-pending-replacement).

These six original graph/runner scenarios are preserved, not executed by the unit lane.
Source-control and CLI helper scenarios remain in the original pre-walk module.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import raw_snapshot, source_fingerprint
from appsec_review.target_acquisition.acquire import MANIFEST_SCHEMA, SYSTEM_MANIFEST_SCHEMA
from tests.test_target_acquisition import (
    ROOT, SYSTEM, available_models, git_component, make_repo, needs_git, system_config,
)


def test_review_intake_publishes_the_acquisition_record(tmp_path: Path) -> None:
    from appsec_review.jobs.job_review_intake import build_job as build_intake
    from appsec_review.runtime import GraphRunner

    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text((ROOT / "appsec-review.toml").read_text(encoding="utf-8"), encoding="utf-8")
    config = load_config(config_path)
    target = config.runtime.repository_root / "targets" / "acquired"
    target.mkdir(parents=True)
    (target / "main.py").write_text("def main():\n    return 1\n", encoding="utf-8")
    record_dir = config.runtime.repository_root / "data" / "target-acquisitions" / "acquired"
    record_dir.mkdir(parents=True)
    (record_dir / "manifest.json").write_text(json.dumps({
        "schema": MANIFEST_SCHEMA, "acquisition_id": "acquired@1", "target_path": "targets/acquired",
        "status": "PARTIAL", "identity": {"kind": "perforce", "changelist": 5}, "identity_sha256": "1" * 64,
        "tree": raw_snapshot(target), "gaps": [{"path": "a.h", "reason": "perforce_digest_unverified"}]}),
        encoding="utf-8")

    def available(provider: str, names, *, timeout_seconds: int):
        return {"provider": provider, "transport": True, "method": "catalog", "listed": sorted(names),
                "error": None, "models": {name: {"available": True, "detail": "listed by the provider"}
                                          for name in names}}

    outcome = GraphRunner(config, [build_intake(check_models=available)]).run(
        target_root=target, source_fingerprint=source_fingerprint(target))
    # The acquisition's own gap is carried into the intake as a path-scoped record.
    assert outcome["status"] == "COMPLETED_WITH_GAPS", outcome
    run_root = config.runtime.runs_dir / outcome["run_id"]
    intake = json.loads(next(run_root.rglob("review-intake.json")).read_text(encoding="utf-8"))
    acquisition = intake["fingerprint"]["acquisition"]
    assert acquisition["acquisition_id"] == "acquired@1" and acquisition["tree_matches"] is True
    assert (run_root / acquisition["manifest"]).is_file()
    assert [gap["reason"] for gap in acquisition["gaps"]] == ["perforce_digest_unverified"]
    pointer = json.loads((run_root / "data/jobs/job_review_intake/latest.json").read_text(encoding="utf-8"))
    handoff = json.loads((run_root / pointer["handoff_path"]).read_text(encoding="utf-8"))
    [record] = handoff["outputs"]["publish_intake.publish_handoff"]["gaps"]
    assert record["code"] == "producer_reported_gap" and record["scope_id"] == "a.h"
    assert record["reason"] == "a.h: perforce_digest_unverified" and record["retryable"] is False


@needs_git
def test_acquisition_gate_composes_the_system_before_intake(tmp_path: Path) -> None:
    from appsec_review.jobs.job_review_intake import build_job as build_intake
    from appsec_review.jobs.job_target_acquisition import build_job as build_acquisition
    from appsec_review.runtime import GraphRunner
    from appsec_review.runtime.launch import SYSTEM_ENVIRONMENT

    from tests.release_support import write_release

    service = make_repo(tmp_path / "service", {"app.py": "def main():\n    return 1\n"})
    library = make_repo(tmp_path / "library", {"lib.py": "VALUE = 1\n"})
    config = load_config(system_config(tmp_path, git_component("service", tmp_path / "service", service) +
                                       git_component("library", tmp_path / "library", library)))
    # Reuse on resume requires measured implementation identities for the jobs in the graph.
    write_release(tmp_path, ("job_target_acquisition", "job_review_intake"))
    target = config.runtime.repository_root / "targets" / SYSTEM
    jobs = [build_acquisition(environ={SYSTEM_ENVIRONMENT: SYSTEM}), build_intake(check_models=available_models)]
    runner = GraphRunner(config, jobs)
    outcome = runner.run(target_root=target, source_fingerprint=None)
    assert outcome["status"] == "SUCCEEDED", outcome
    assert sorted(path.name for path in target.iterdir()) == ["library", "service"]
    run_root = config.runtime.runs_dir / outcome["run_id"]
    acquired = json.loads(next(run_root.rglob("target-acquisition-result.json")).read_text(encoding="utf-8"))
    assert acquired["status"] == "COMPLETE" and set(acquired["components"]) == {"service", "library"}
    copy = next(run_root.rglob("system-manifest.json"))
    assert hashlib.sha256(copy.read_bytes()).hexdigest() == acquired["manifest_sha256"]
    intake = json.loads(next(run_root.rglob("review-intake.json")).read_text(encoding="utf-8"))
    acquisition = intake["fingerprint"]["acquisition"]
    assert acquisition["schema"] == SYSTEM_MANIFEST_SCHEMA and acquisition["tree_matches"] is True
    assert acquisition["acquisition_id"] == acquired["acquisition_id"]
    events = [json.loads(line)["event_type"] for line in
              (run_root / "data" / "logs" / "pipeline.jsonl").read_text(encoding="utf-8").splitlines()]
    assert events.index("TARGET_FINGERPRINTED") > events.index("RUN_STARTED")

    # Resuming re-verifies the live gate and reuses the intake bound to the unchanged composed tree.
    decisions = {item["job_id"]: item["action"] for item in runner.run(
        target_root=target, source_fingerprint=None, run_id=outcome["run_id"])["decisions"]}
    assert decisions == {"job_target_acquisition": "RUN", "job_review_intake": "REUSE"}
    # Re-verification left the system manifest's bytes alone (intake's input identity depends on it)
    # and recorded what this pass did in the verification sidecar instead.
    records = config.runtime.repository_root / "data" / "target-acquisitions" / SYSTEM
    assert hashlib.sha256((records / "manifest.json").read_bytes()).hexdigest() == acquired["manifest_sha256"]
    verification = json.loads((records / "verification.json").read_text(encoding="utf-8"))
    assert verification["manifest_sha256"] == acquired["manifest_sha256"]
    assert {key: value["action"] for key, value in verification["components"].items()} == {
        "service": "verified", "library": "verified"}
    from tests.telemetry_support import assert_job_lifecycle, job_events
    summary = assert_job_lifecycle(run_root, "job_target_acquisition", terminal="SUCCEEDED", attempts=2)
    assert summary["event_counts"]["JOB_SUCCEEDED"] >= 2
    first, second = job_events(run_root, "job_target_acquisition", "TARGET_ACQUISITION_COMPLETED")
    assert (first["acquired_count"], first["verified_count"], first["gap_count"]) == (2, 0, 0)
    assert (second["acquired_count"], second["verified_count"], second["gap_count"]) == (0, 2, 0)


@needs_git
def test_acquisition_gate_publishes_a_partial_system_with_gap_records(tmp_path: Path) -> None:
    from appsec_review.interchange import GAP_SCHEMA
    from appsec_review.jobs.job_target_acquisition import build_job as build_acquisition
    from appsec_review.runtime import GraphRunner
    from appsec_review.runtime.launch import SYSTEM_ENVIRONMENT
    from tests.telemetry_support import assert_job_lifecycle, job_events

    service = make_repo(tmp_path / "service", {"app.py": "def main():\n    return 1\n"})
    missing = "0123456789abcdef0123456789abcdef01234567"
    config = load_config(system_config(tmp_path, git_component("service", tmp_path / "service", service) +
                                       git_component("broken", tmp_path / "service", missing)))
    target = config.runtime.repository_root / "targets" / SYSTEM
    outcome = GraphRunner(config, [build_acquisition(environ={SYSTEM_ENVIRONMENT: SYSTEM})]).run(
        target_root=target, source_fingerprint=None)
    assert outcome["status"] == "COMPLETED_WITH_GAPS", outcome
    run_root = config.runtime.runs_dir / outcome["run_id"]
    pointer = json.loads((run_root / "data/jobs/job_target_acquisition/latest.json").read_text(encoding="utf-8"))
    handoff = json.loads((run_root / pointer["handoff_path"]).read_text(encoding="utf-8"))
    acquire = handoff["outputs"]["acquisition.acquire_components"]
    assert acquire["terminal_status"] == "COMPLETED_WITH_GAPS"
    [gap] = acquire["gaps"]
    assert gap["schema"] == GAP_SCHEMA and gap["code"] == "producer_failed" and gap["retryable"] is True
    assert gap["scope_id"] == "broken" and gap["reason"].startswith("broken: component_acquisition_failed")
    assert handoff["outputs"]["publication.publish_handoff"]["gaps"] == []
    record = json.loads(next(run_root.rglob("target-acquisition-result.json")).read_text(encoding="utf-8"))
    assert record["status"] == "PARTIAL" and record["components"]["broken"]["status"] == "FAILED"
    assert record["acquisition_gaps"][0]["reason"] == "component_acquisition_failed"
    assert record["verification"].endswith("verification.json") and record["completed_at"]
    assert sorted(path.name for path in target.iterdir()) == ["service"]
    assert_job_lifecycle(run_root, "job_target_acquisition", terminal="COMPLETED_WITH_GAPS")
    [completed] = job_events(run_root, "job_target_acquisition", "TARGET_ACQUISITION_COMPLETED")
    assert completed["status"] == "PARTIAL" and completed["gap_count"] == 1 and completed["component_count"] == 2


def test_acquisition_gate_fails_typed_when_no_component_is_available(tmp_path: Path) -> None:
    from appsec_review.jobs.job_target_acquisition import build_job as build_acquisition
    from appsec_review.jobs.job_target_acquisition.job import TargetAcquisitionFailed
    from appsec_review.runtime import GraphRunner
    from appsec_review.runtime.launch import SYSTEM_ENVIRONMENT
    from tests.telemetry_support import assert_job_lifecycle, job_events

    config = load_config(system_config(tmp_path, git_component("svc", tmp_path / "absent", "a" * 40)))
    target = config.runtime.repository_root / "targets" / SYSTEM
    with pytest.raises(RuntimeError, match="is FAILED"):
        GraphRunner(config, [build_acquisition(environ={SYSTEM_ENVIRONMENT: SYSTEM})]).run(
            target_root=target, source_fingerprint=None)
    [run_root] = [path for path in config.runtime.runs_dir.iterdir() if (path / "data").is_dir()]
    assert not (run_root / "data/jobs/job_target_acquisition/latest.json").exists()
    status = json.loads(next(run_root.rglob("tasks/acquire_components/status.json")).read_text(encoding="utf-8"))
    assert status["status"] == "FAILED" and status["error"]["type"] == TargetAcquisitionFailed.__name__
    assert "svc: FAILED:" in status["error"]["message"]
    record = json.loads(next(run_root.rglob("target-acquisition-result.json")).read_text(encoding="utf-8"))
    assert record["status"] == "FAILED" and [gap["code"] for gap in record["gaps"]] == ["producer_failed"]
    summary = assert_job_lifecycle(run_root, "job_target_acquisition", terminal="FAILED")
    assert summary["event_counts"]["TARGET_ACQUISITION_FAILED"] == 1
    [failed] = job_events(run_root, "job_target_acquisition", "TARGET_ACQUISITION_FAILED")
    assert failed["status"] == "FAILED" and failed["system_id"] == SYSTEM


def test_acquisition_gate_refuses_an_unconfigured_system_id(tmp_path: Path) -> None:
    from appsec_review.jobs.job_target_acquisition import build_job as build_acquisition
    from appsec_review.runtime import GraphRunner
    from appsec_review.runtime.launch import SYSTEM_ENVIRONMENT

    config = load_config(system_config(tmp_path, git_component("svc", tmp_path / "absent", "a" * 40)))
    with pytest.raises(RuntimeError, match="not configured under"):
        GraphRunner(config, [build_acquisition(environ={SYSTEM_ENVIRONMENT: "other-system"})]).run(
            target_root=config.runtime.repository_root / "targets" / "other-system", source_fingerprint=None)


def test_acquisition_gate_without_a_requested_system_changes_nothing(tmp_path: Path) -> None:
    from appsec_review.jobs.job_target_acquisition import build_job as build_acquisition
    from appsec_review.runtime import JobRunner

    config_path = tmp_path / "appsec-review.toml"
    config_path.write_text((ROOT / "appsec-review.toml").read_text(encoding="utf-8"), encoding="utf-8")
    config = load_config(config_path)
    outcome = JobRunner(config).run(build_acquisition(environ={}), target_root=None, source_fingerprint="none")
    result = json.loads(next(Path(outcome["attempt_root"]).rglob("target-acquisition-result.json")).read_text(
        encoding="utf-8"))
    assert result["status"] == "NOT_REQUESTED"
    assert not (config.runtime.repository_root / "targets").exists()
