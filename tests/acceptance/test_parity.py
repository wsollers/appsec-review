from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys

import pytest

from appsec_review.acceptance.state import StepwiseState

ROOT = Path(__file__).parents[2]
BIN = ROOT / "deploy" / "dagster" / "bin"
sys.path.insert(0, str(BIN))
SPEC = importlib.util.spec_from_file_location("stepwise_parity", BIN / "stepwise.py")
assert SPEC is not None and SPEC.loader is not None
stepwise = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stepwise)

RUN = "2026-10-18-0001"
JOB = "job_target_catalog"
TOPOLOGY = {"graph": "wave1_review", "jobs": [
    {"job_id": "job_review_intake", "name": "review_intake", "upstream_handoffs": []},
    {"job_id": JOB, "name": "target_catalog", "upstream_handoffs": ["job_review_intake"]}]}
IDENTITY = {"implementation_identity": "i", "schema_identity": "s", "validation_identity": "v",
            "resolved_config_sha256": "c", "job_config_sha256": "j", "source_fingerprint": "f",
            "input_identity": None, "upstream_handoff_sha256": {"job_review_intake": "u"}}


def _attempt(run_root: Path, serial: int, *, dagster_run_id: str | None, findings: int, **identity) -> None:
    attempt = run_root / "data" / "jobs" / JOB / "attempts" / f"attempt_{serial:04d}"
    attempt.mkdir(parents=True)
    orchestration = {"system": "dagster", "run_id": dagster_run_id} if dagster_run_id else {"system": "local"}
    (attempt / "claim.json").write_text(json.dumps({"orchestration": orchestration}), encoding="utf-8")
    (attempt / "status.json").write_text(json.dumps({"status": "SUCCEEDED"}), encoding="utf-8")
    (attempt / "result.json").write_text(json.dumps({"outputs": {"catalog.files": {
        "findings": [{"path": f"src/{index}.cpp"} for index in range(findings)], "gaps": []}}}), encoding="utf-8")
    (attempt / "handoff.json").write_text(json.dumps({"status": "ACCEPTED", "artifacts": [],
                                                      **IDENTITY, **identity}), encoding="utf-8")


@pytest.fixture
def walk(tmp_path, monkeypatch):
    for name, value in (("ROOT", tmp_path), ("STATE_ROOT", tmp_path / "runs" / "metadata" / "stepwise"),
                        ("PARITY_ROOT", tmp_path / "runs" / "metadata" / "stepwise" / "parity"),
                        ("SEED_STORE", tmp_path / "data" / "acceptance-seeds")):
        monkeypatch.setattr(stepwise, name, value)
    (tmp_path / "data" / "caches").mkdir(parents=True)
    monkeypatch.setattr(stepwise, "_ids", lambda: (1000, 1000))
    monkeypatch.setattr(stepwise, "packaged_topology", lambda: TOPOLOGY)
    environment = {stepwise.MODEL_RECORDING: "record", "APPSEC_REVIEW_TARGET": "/opt/app/targets/relay"}
    monkeypatch.setattr(stepwise, "compose", lambda *arguments: environment[arguments[-1].split()[1]]
                        if arguments[3] == "sh" else environment[arguments[-1]])
    monkeypatch.setattr(stepwise, "get_run", lambda url, run_id: {"status": "SUCCESS"})
    monkeypatch.setattr(stepwise, "git", lambda *arguments, cwd: "commit")
    monkeypatch.setattr(stepwise, "audit_job_writes", lambda *arguments, **options: [])
    seeds: list[str] = []

    def seed_run(args, tag, after_job):
        seeds.append(after_job)
        run_root = tmp_path / "runs" / RUN
        (run_root / "data" / "jobs").mkdir(parents=True)
        (run_root / "seeded.txt").write_text(after_job, encoding="utf-8")
        state = StepwiseState.create(RUN, target="/opt/app/targets/relay", topology=TOPOLOGY)
        state.mark_seeded(after_job, corpus_tag=tag, handoffs={})
        path = StepwiseState.path_for(stepwise.STATE_ROOT, RUN)
        state.save(path)
        return state, path

    def launch_next(args, state, path):
        state.record_launch(JOB, "dagster-1")
        state.save(path)
        _attempt(tmp_path / "runs" / RUN, 1, dagster_run_id="dagster-1", findings=2)
        (tmp_path / "data" / "caches" / "tool-output.json").write_text("{}", encoding="utf-8")
        return 0

    monkeypatch.setattr(stepwise, "seed_run", seed_run)
    monkeypatch.setattr(stepwise, "launch_next", launch_next)
    return tmp_path, seeds


def _args(**overrides) -> argparse.Namespace:
    return argparse.Namespace(**{"tag": "cpp-multivuln-v1", "job": JOB, "target": None, "replace": False,
                                 "restore_shared": False, "allow_shared_drift": False, "url": "u",
                                 "interval_seconds": 1, "show": 10, **overrides})


def _local(tmp_path: Path, findings: int, **identity):
    def run_local(job_id, app_run_id, target, replay, log):
        run_root = tmp_path / "runs" / app_run_id
        # The local side starts from the seed alone: no Dagster attempt, no Dagster cache entry.
        assert (run_root / "seeded.txt").read_text(encoding="utf-8") == "job_review_intake"
        assert not (run_root / "data" / "jobs" / JOB).exists()
        assert not (tmp_path / "data" / "caches" / "tool-output.json").exists()
        assert target == tmp_path / "targets" / "relay" and replay.is_dir()
        _attempt(run_root, 1, dagster_run_id=None, findings=findings, **identity)
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("ok\n", encoding="utf-8")
        return 0
    return run_local


def _report(tmp_path: Path) -> dict:
    return json.loads(next((tmp_path / "runs" / "metadata" / "stepwise" / "parity").rglob("report.json"))
                      .read_text(encoding="utf-8"))


def test_matching_outputs_pass_and_leave_the_dagster_side_in_place(walk, monkeypatch) -> None:
    tmp_path, seeds = walk
    monkeypatch.setattr(stepwise, "_run_local", _local(tmp_path, findings=2))

    assert stepwise.command_parity(_args()) == 0
    assert seeds == ["job_review_intake", "job_review_intake"]
    claim = tmp_path / "runs" / RUN / "data" / "jobs" / JOB / "attempts" / "attempt_0001" / "claim.json"
    assert json.loads(claim.read_text(encoding="utf-8"))["orchestration"]["system"] == "dagster"
    assert (tmp_path / "data" / "caches" / "tool-output.json").is_file()
    assert StepwiseState.load(StepwiseState.path_for(stepwise.STATE_ROOT, RUN)).job(JOB)["dagster_run_ids"] == [
        "dagster-1"]
    assert _report(tmp_path)["verdict"] == "PARITY OK"


def test_a_finding_difference_stops_the_walk_with_the_delta(walk, monkeypatch, capsys) -> None:
    tmp_path, _ = walk
    monkeypatch.setattr(stepwise, "_run_local", _local(tmp_path, findings=1))

    assert stepwise.command_parity(_args()) == 3
    report = _report(tmp_path)
    assert report["verdict"] == "DIFFERENT"
    assert {item["class"] for item in report["differences"]} >= {"finding-removed"}
    assert "finding-removed" in capsys.readouterr().out


def test_different_code_or_inputs_invalidate_the_comparison(walk, monkeypatch) -> None:
    tmp_path, _ = walk
    monkeypatch.setattr(stepwise, "_run_local", _local(tmp_path, findings=2, implementation_identity="other"))

    assert stepwise.command_parity(_args()) == 3
    report = _report(tmp_path)
    assert report["verdict"] == "INVALID COMPARISON"
    assert report["identity_mismatches"] == [
        {"key": "implementation_identity", "dagster": "i", "local": "other"}]


def test_parity_refuses_a_code_location_that_does_not_record(walk, monkeypatch) -> None:
    monkeypatch.setattr(stepwise, "compose", lambda *arguments: "")
    with pytest.raises(RuntimeError, match="=record"):
        stepwise.command_parity(_args())
