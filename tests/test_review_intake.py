"""job_review_intake through the real runner: the four independent steps, their failure paths, and
what the intake handoff, artifacts and telemetry carry.

Unit tests: the real configuration file, the real GraphRunner, a fake only at the provider boundary;
no Docker, no model, no network, no targets/ checkout. The model-preflight decision itself is covered
in tests/test_model_preflight.py; the acquisition record in tests/test_target_acquisition.py.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil

import pytest

from appsec_review.config import load_config
from appsec_review.interchange import GAP_SCHEMA
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_review_intake import build_job
from appsec_review.jobs.job_review_intake.job import (
    ModelPreflightBlocked, TOPOLOGY, TargetIntakeError, coverage_gap_records,
)
from appsec_review.runtime import GraphRunner
from tests.telemetry_support import assert_job_lifecycle, job_events

ROOT = Path(__file__).resolve().parents[1]
JOB_ID = "job_review_intake"


def _checkout(tmp_path: Path, *, extra: str = "") -> Path:
    shutil.copyfile(ROOT / "appsec-review.toml", tmp_path / "appsec-review.toml")
    (tmp_path / "profiles").mkdir()
    if extra:
        with (tmp_path / "appsec-review.toml").open("a", encoding="utf-8") as stream:
            stream.write(extra)
    return tmp_path / "appsec-review.toml"


def _target(tmp_path: Path, files: dict[str, str] | None = None) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    for name, content in (files or {"main.py": "def main():\n    return 1\n"}).items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return target


def _available(provider: str, names, *, timeout_seconds: int):
    return {"provider": provider, "transport": True, "method": "catalog", "listed": sorted(names), "error": None,
            "models": {name: {"available": True, "detail": "listed"} for name in names}}


def _down(provider: str, names, *, timeout_seconds: int):
    return {"provider": provider, "transport": False, "method": "catalog", "listed": [], "error": "connection refused",
            "models": {}}


def _run(config, target: Path, job, *, fingerprint: str | None = None):
    try:
        outcome = GraphRunner(config, [job]).run(target_root=target,
                                                 source_fingerprint=fingerprint or source_fingerprint(target))
    except RuntimeError as error:
        outcome = {"status": "FAILED", "error": str(error)}
    [run_root] = [path for path in config.runtime.runs_dir.iterdir() if (path / "data").is_dir()]
    return outcome, run_root


def _attempt(run_root: Path) -> Path:
    return next((run_root / "data/jobs" / JOB_ID / "attempts").iterdir())


def _handoff(run_root: Path) -> dict:
    pointer = json.loads((run_root / "data/jobs" / JOB_ID / "latest.json").read_text(encoding="utf-8"))
    return json.loads((run_root / pointer["handoff_path"]).read_text(encoding="utf-8"))


# ------------------------------------------------------------------ success path

def test_intake_publishes_configuration_target_models_and_binaries_with_telemetry(tmp_path: Path) -> None:
    config = load_config(_checkout(tmp_path), profile="dev")
    target = _target(tmp_path)
    outcome, run_root = _run(config, target, build_job(check_models=_available))
    assert outcome["status"] == "SUCCEEDED", outcome
    handoff = _handoff(run_root)
    publish = handoff["outputs"]["publish_intake.publish_handoff"]
    assert publish["terminal_status"] == "SUCCEEDED" and publish["gaps"] == []
    intake = json.loads((run_root / publish["artifact"]["path"]).read_text(encoding="utf-8"))
    assert intake["schema"] == "appsec-review/review-intake/1"
    assert intake["target"] == {"path": str(target.resolve()), "kind": "directory"}
    assert intake["fingerprint"]["sha256"] == source_fingerprint(target)
    assert intake["fingerprint"]["coverage"]["file_count"] == 1 and intake["fingerprint"]["acquisition"] is None
    assert intake["configuration"]["profile"] == "dev"
    frozen = run_root / intake["configuration"]["path"]
    assert intake["configuration"]["sha256"] == hashlib.sha256(frozen.read_bytes()).hexdigest()
    assert intake["model_preflight"]["verified"] == ["claude-cli/claude-haiku-5-5"]
    assert intake["binary_evidence"]["binaries"] == [] and intake["binary_evidence"]["gaps"] == []
    for unit_id in ("model_preflight.verify_models", "prepare_target.validate_target",
                    "binary_evidence.resolve_publications"):
        assert handoff["outputs"][unit_id]["gaps"] == [], unit_id
    assert_job_lifecycle(run_root, JOB_ID, terminal="SUCCEEDED")
    [preflight] = job_events(run_root, JOB_ID, "MODEL_PREFLIGHT_COMPLETED")
    assert preflight["unavailable_count"] == 0 and preflight["model_count"] >= 1
    [binaries] = job_events(run_root, JOB_ID, "BINARY_EVIDENCE_RESOLVED")
    assert binaries == {"unit_id": "binary_evidence.resolve_publications", "configured": 0, "resolved": 0,
                        "unavailable": 0}


def test_intake_is_reused_on_resume_when_nothing_changed(tmp_path: Path) -> None:
    config = load_config(_checkout(tmp_path), profile="dev")
    from tests.release_support import write_release
    write_release(tmp_path, (JOB_ID,))
    target = _target(tmp_path)
    fingerprint = source_fingerprint(target)
    first = GraphRunner(config, [build_job(check_models=_available)]).run(target_root=target, source_fingerprint=fingerprint)
    second = GraphRunner(config, [build_job(check_models=_available)]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=first["run_id"])
    assert [(item["job_id"], item["action"]) for item in second["decisions"]] == [(JOB_ID, "REUSE")]
    run_root = config.runtime.runs_dir / first["run_id"]
    assert len(list((run_root / "data/jobs" / JOB_ID / "attempts").iterdir())) == 1
    assert_job_lifecycle(run_root, JOB_ID, terminal="SUCCEEDED", attempts=1)


# ------------------------------------------------------------------ coverage gaps

def test_coverage_gaps_are_path_scoped_records_and_configured_exclusions_are_not_gaps() -> None:
    gaps = [{"path": ".git", "reason": "excluded_directory"},
            {"path": "link", "reason": "symlink_excluded"},
            {"path": "dev/null", "reason": "non_regular_descriptor"}]
    records = coverage_gap_records("prepare_target.validate_target", gaps)
    assert [(gap["scope_id"], gap["code"], gap["retryable"]) for gap in records] == [
        ("link", "producer_reported_gap", False), ("dev/null", "producer_reported_gap", False)]
    assert all(gap["schema"] == GAP_SCHEMA and gap["unit_id"] == "prepare_target.validate_target" for gap in records)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks are unavailable on this platform")
def test_a_symlink_in_the_target_is_a_named_coverage_gap_and_the_intake_still_publishes(tmp_path: Path) -> None:
    config = load_config(_checkout(tmp_path), profile="dev")
    target = _target(tmp_path)
    try:
        os.symlink(target / "main.py", target / "alias.py")
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - platform without symlink rights
        pytest.skip(f"cannot create a symlink here: {exc}")
    outcome, run_root = _run(config, target, build_job(check_models=_available))
    assert outcome["status"] == "COMPLETED_WITH_GAPS", outcome
    handoff = _handoff(run_root)
    validate = handoff["outputs"]["prepare_target.validate_target"]
    [gap] = validate["gaps"]
    assert gap["scope_id"] == "alias.py" and gap["reason"] == "alias.py: symlink_excluded"
    publish = handoff["outputs"]["publish_intake.publish_handoff"]
    assert publish["terminal_status"] == "COMPLETED_WITH_GAPS" and [g["scope_id"] for g in publish["gaps"]] == ["alias.py"]
    intake = json.loads((run_root / publish["artifact"]["path"]).read_text(encoding="utf-8"))
    assert intake["fingerprint"]["coverage"]["coverage_gaps"] == [{"path": "alias.py", "reason": "symlink_excluded"}]
    assert_job_lifecycle(run_root, JOB_ID, terminal="COMPLETED_WITH_GAPS")


# ------------------------------------------------------------------ failure paths

def test_an_empty_target_fails_intake_typed_and_publishes_nothing(tmp_path: Path) -> None:
    config = load_config(_checkout(tmp_path), profile="dev")
    target = tmp_path / "target"
    target.mkdir()
    (target / "image.bin").write_bytes(b"\x00\xff" * 64)
    outcome, run_root = _run(config, target, build_job(check_models=_available))
    assert outcome["status"] == "FAILED" and "no bounded text files" in outcome["error"]
    assert not (run_root / "data/jobs" / JOB_ID / "latest.json").exists()
    receipt = json.loads((_attempt(run_root) / "steps/prepare_target/tasks/validate_target/status.json")
                         .read_text(encoding="utf-8"))
    assert receipt["status"] == "FAILED" and receipt["error"]["type"] == TargetIntakeError.__name__
    # Independent steps still ran and left their evidence; the failure is scoped to the target step.
    assert (_attempt(run_root) / "steps/model_preflight/tasks/verify_models/model-preflight.json").is_file()
    assert_job_lifecycle(run_root, JOB_ID, terminal="FAILED")


def test_a_target_that_changed_after_planning_fails_the_fingerprint_unit(tmp_path: Path) -> None:
    config = load_config(_checkout(tmp_path), profile="dev")
    target = _target(tmp_path)
    planned = source_fingerprint(target)
    (target / "main.py").write_text("def main():\n    return 2\n", encoding="utf-8")
    outcome, run_root = _run(config, target, build_job(check_models=_available), fingerprint=planned)
    assert outcome["status"] == "FAILED" and "target changed after resume planning" in outcome["error"]
    receipt = json.loads((_attempt(run_root) / "steps/prepare_target/tasks/fingerprint_target/status.json")
                         .read_text(encoding="utf-8"))
    assert receipt["status"] == "FAILED" and receipt["error"]["type"] == TargetIntakeError.__name__
    assert not (run_root / "data/jobs" / JOB_ID / "latest.json").exists()
    assert_job_lifecycle(run_root, JOB_ID, terminal="FAILED")


def test_a_required_model_down_at_intake_fails_typed(tmp_path: Path) -> None:
    config = load_config(_checkout(tmp_path), profile="dev")
    target = _target(tmp_path)
    outcome, run_root = _run(config, target, build_job(check_models=_down))
    assert outcome["status"] == "FAILED" and "model preflight blocked the review" in outcome["error"]
    receipt = json.loads((_attempt(run_root) / "steps/model_preflight/tasks/verify_models/status.json")
                         .read_text(encoding="utf-8"))
    assert receipt["error"]["type"] == ModelPreflightBlocked.__name__
    document = json.loads((_attempt(run_root) / "steps/model_preflight/tasks/verify_models/model-preflight.json")
                          .read_text(encoding="utf-8"))
    assert [item["detail"] for item in document["unavailable"]] == ["connection refused"]
    summary = assert_job_lifecycle(run_root, JOB_ID, terminal="FAILED")
    assert summary["event_counts"]["MODEL_PREFLIGHT_COMPLETED"] == 1
    [preflight] = job_events(run_root, JOB_ID, "MODEL_PREFLIGHT_COMPLETED")
    assert preflight["unavailable_count"] == 1


def test_an_unwired_check_is_recorded_as_not_applicable_not_hidden(tmp_path: Path) -> None:
    """Fixture intakes (built without a provider check) publish; the hard gate is job_model_connectivity."""
    config = load_config(_checkout(tmp_path), profile="dev")
    target = _target(tmp_path)
    outcome, run_root = _run(config, target, build_job())
    assert outcome["status"] == "SUCCEEDED", outcome
    verify = _handoff(run_root)["outputs"]["model_preflight.verify_models"]
    assert verify["terminal_status"] == "NOT_APPLICABLE"
    result = json.loads((_attempt(run_root) / "steps/model_preflight/tasks/verify_models/result.json")
                        .read_text(encoding="utf-8"))
    assert result["reason"].startswith("no model availability check is wired") and result["verified"] == []
    assert job_events(run_root, JOB_ID, "MODEL_PREFLIGHT_COMPLETED") == []


# ------------------------------------------------------------------ binaries

def test_an_optional_binary_without_a_publication_is_a_retryable_gap(tmp_path: Path) -> None:
    binary = tmp_path / "vendor.so"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    extra = (f'\n[[binary_decompilation.binaries]]\nid = "vendor"\npath = "{binary.as_posix()}"\n'
             f'sha256 = "{hashlib.sha256(binary.read_bytes()).hexdigest()}"\nauthorization = "owned test input"\n'
             'required = false\n')
    config = load_config(_checkout(tmp_path, extra=extra), profile="dev")
    target = _target(tmp_path)
    outcome, run_root = _run(config, target, build_job(check_models=_available))
    assert outcome["status"] == "COMPLETED_WITH_GAPS", outcome
    resolve = _handoff(run_root)["outputs"]["binary_evidence.resolve_publications"]
    assert resolve["terminal_status"] == "COMPLETED_WITH_GAPS"
    [gap] = resolve["gaps"]
    assert gap["code"] == "input_unavailable" and gap["scope_id"] == "vendor" and gap["retryable"] is True
    assert gap["reason"].startswith("binary vendor has no usable decompilation publication")
    [event] = job_events(run_root, JOB_ID, "BINARY_EVIDENCE_RESOLVED")
    assert (event["configured"], event["resolved"], event["unavailable"]) == (1, 0, 1)


def test_a_required_binary_without_a_publication_fails_intake(tmp_path: Path) -> None:
    binary = tmp_path / "vendor.so"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
    extra = (f'\n[[binary_decompilation.binaries]]\nid = "vendor"\npath = "{binary.as_posix()}"\n'
             f'sha256 = "{hashlib.sha256(binary.read_bytes()).hexdigest()}"\nauthorization = "owned test input"\n'
             'required = true\n')
    config = load_config(_checkout(tmp_path, extra=extra), profile="dev")
    target = _target(tmp_path)
    # The external input identity is computed at claim time, so a required binary with no
    # publication refuses the claim: no attempt, no unit, nothing to resume from but the fix.
    with pytest.raises(ValueError, match="required binary vendor has no usable decompilation"):
        GraphRunner(config, [build_job(check_models=_available)]).run(
            target_root=target, source_fingerprint=source_fingerprint(target))
    assert list(config.runtime.runs_dir.glob(f"*/data/jobs/{JOB_ID}/attempts/*/steps")) == []


# ------------------------------------------------------------------ configuration

def test_configured_topology_matches_the_job_and_the_job_is_strict() -> None:
    config = load_config(ROOT / "appsec-review.toml", profile="dev")
    job = config.jobs[JOB_ID]
    assert tuple(job.steps) == tuple(TOPOLOGY)
    for step, tasks in TOPOLOGY.items():
        assert tuple(job.step(step).tasks) == tasks
    built = build_job(check_models=_available)
    assert built.strict_gaps and not built.always_execute and built.propagate_handoff
    assert [unit.unit_id for unit in built.units] == [f"{step}.{task}" for step, tasks in TOPOLOGY.items() for task in tasks]
