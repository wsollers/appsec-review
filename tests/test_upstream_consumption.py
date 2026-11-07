"""A consumer reads the producer attempt its claim pinned, never whatever latest.json says."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.runtime.consume import (
    UpstreamIntegrityError, UpstreamNotPinnedError, accepted_latest, accepted_upstream,
    consumable_handoffs, current_pins, has_accepted_upstream, upstream_scope,
)
from appsec_review.storage import file_sha256
from tests.test_job_runtime import write_config


def _runner(tmp_path: Path, *job_ids: str):
    from tests.release_support import write_release
    write_release(tmp_path, job_ids)
    path = write_config(tmp_path)
    with path.open("a", encoding="utf-8") as stream:
        stream.write('\n[review_policy.releases]\nplatform = "fixture/1"\nvalidation = "fixture/1"\n')
        for job_id in job_ids:
            if job_id != "job_fixture":
                stream.write(f'\n[jobs.{job_id}]\nname = "{job_id}"\nworkers = 1\n')
    config = load_config(path)
    return config, JobRunner(config)


def _job(job_id: str, handler, consumes=()):
    return Job(job_id, "fixture" if job_id == "job_fixture" else job_id, handler, units=(Unit("work.only", handler),),
               consumes=tuple(consumes))


def _publish(runner, job, run_id=None, upstream=None):
    kwargs = {"source_fingerprint": "snapshot"}
    if run_id is not None:
        kwargs["run_id"] = run_id
    if upstream is not None:
        kwargs["upstream_handoffs"] = upstream
    return runner.run(job, **kwargs)


def test_unscoped_read_follows_the_verified_pointer_and_reports_it_unpinned(tmp_path: Path) -> None:
    config, runner = _runner(tmp_path, "job_fixture")
    outcome = _publish(runner, _job("job_fixture", lambda unit: {"value": 1}))
    run_root = config.runtime.runs_dir / outcome["status"]["run_id"]
    accepted = accepted_upstream(run_root, "job_fixture")
    assert accepted.pinned is False
    assert accepted.sha256 == outcome["handoff_sha256"]
    assert accepted.handoff["job_id"] == "job_fixture"
    assert has_accepted_upstream(run_root, "job_fixture")
    assert accepted_upstream(run_root, "job_absent", required=False) is None
    with pytest.raises(UpstreamIntegrityError, match="required"):
        accepted_upstream(run_root, "job_absent")
    assert current_pins(run_root) is None


def test_scoped_read_returns_the_pinned_attempt_even_after_latest_moved(tmp_path: Path) -> None:
    config, runner = _runner(tmp_path, "job_fixture")
    first = _publish(runner, _job("job_fixture", lambda unit: {"value": 1}))
    run_root = config.runtime.runs_dir / first["status"]["run_id"]
    second = _publish(runner, _job("job_fixture", lambda unit: {"value": 2}), run_id=first["status"]["run_id"])
    assert second["handoff_sha256"] != first["handoff_sha256"]
    pointer = json.loads((run_root / "data/jobs/job_fixture/latest.json").read_text(encoding="utf-8"))
    assert pointer["handoff_sha256"] == second["handoff_sha256"]
    with upstream_scope(run_root, "job_consumer", {"job_fixture": first["handoff_sha256"]}):
        assert current_pins(run_root) == {"job_fixture": first["handoff_sha256"]}
        accepted = accepted_upstream(run_root, "job_fixture")
        assert accepted.pinned is True
        assert accepted.sha256 == first["handoff_sha256"]
        assert accepted.handoff["attempt_id"] == first["status"]["attempt_id"]
        assert accepted.path.startswith("data/jobs/job_fixture/attempts/")
        assert file_sha256(run_root / accepted.path) == first["handoff_sha256"]
    # The job's own prior attempt is read by pointer, explicitly, for checkpoint reuse only.
    assert accepted_latest(run_root, "job_fixture").sha256 == second["handoff_sha256"]


def test_scoped_read_refuses_an_accepted_producer_the_claim_did_not_pin(tmp_path: Path) -> None:
    config, runner = _runner(tmp_path, "job_fixture")
    outcome = _publish(runner, _job("job_fixture", lambda unit: {"value": 1}))
    run_root = config.runtime.runs_dir / outcome["status"]["run_id"]
    with upstream_scope(run_root, "job_consumer", {}):
        with pytest.raises(UpstreamNotPinnedError, match="job_consumer reads job_fixture"):
            accepted_upstream(run_root, "job_fixture")
        assert accepted_upstream(run_root, "job_fixture", required=False) is None
        assert not has_accepted_upstream(run_root, "job_fixture")
        # A producer with no accepted handoff at all is simply required/absent, not a pin violation.
        with pytest.raises(UpstreamIntegrityError, match="accepted job_absent handoff is required"):
            accepted_upstream(run_root, "job_absent")


def test_scoped_read_fails_closed_when_the_pinned_bytes_are_gone_or_changed(tmp_path: Path) -> None:
    config, runner = _runner(tmp_path, "job_fixture")
    outcome = _publish(runner, _job("job_fixture", lambda unit: {"value": 1}))
    run_root = config.runtime.runs_dir / outcome["status"]["run_id"]
    with upstream_scope(run_root, "job_consumer", {"job_fixture": "0" * 64}):
        with pytest.raises(UpstreamIntegrityError, match="pinned digest"):
            accepted_upstream(run_root, "job_fixture")
    pointer_path = run_root / "data/jobs/job_fixture/latest.json"
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    handoff_path = run_root / pointer["handoff_path"]
    handoff_path.write_text(handoff_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(UpstreamIntegrityError, match="changed"):
        accepted_upstream(run_root, "job_fixture")


def test_scope_validates_its_pins_and_identities(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        with upstream_scope(tmp_path, "job_consumer", {"job_fixture": "nope"}):
            pass
    with pytest.raises(ValueError, match="consumer job identity"):
        with upstream_scope(tmp_path, "Bad Id", {}):
            pass
    with pytest.raises(ValueError, match="upstream job identity"):
        accepted_upstream(tmp_path, "../escape")


def test_runner_pins_declared_producers_accepted_before_the_claim(tmp_path: Path) -> None:
    """A consumer running after its producer, in a graph that did not project it, still reads the
    attempt that was accepted when its claim was written, and never a later one."""
    config, runner = _runner(tmp_path, "job_fixture", "job_consumer")
    producer = _job("job_fixture", lambda unit: {"value": 1})
    first = _publish(runner, producer)
    run_id = first["status"]["run_id"]
    run_root = config.runtime.runs_dir / run_id
    seen: dict[str, str] = {}

    def consume(unit):
        accepted = accepted_upstream(unit.job.run_root, "job_fixture")
        seen["sha256"] = accepted.sha256
        seen["pinned"] = accepted.pinned
        with pytest.raises(UpstreamIntegrityError):
            accepted_upstream(unit.job.run_root, "job_other")
        return {"value": 2}

    consumer = _job("job_consumer", consume, consumes=("job_fixture",))
    pins = consumable_handoffs(run_root, "job_consumer", consumer.consumes, {})
    assert pins == {"job_fixture": first["handoff_sha256"]}
    outcome = _publish(runner, consumer, run_id=run_id)
    assert seen == {"sha256": first["handoff_sha256"], "pinned": True}
    claim = json.loads((run_root / "data/jobs/job_consumer/attempts" / outcome["status"]["attempt_id"]
                        / "claim.json").read_text(encoding="utf-8"))
    assert claim["consumable_handoffs"] == {"job_fixture": first["handoff_sha256"]}
    assert claim["upstream_handoffs"] == {}


def test_runner_refuses_a_read_of_an_undeclared_accepted_producer(tmp_path: Path) -> None:
    config, runner = _runner(tmp_path, "job_fixture", "job_consumer")
    first = _publish(runner, _job("job_fixture", lambda unit: {"value": 1}))
    run_id = first["status"]["run_id"]

    def consume(unit):
        return {"value": accepted_upstream(unit.job.run_root, "job_fixture").handoff["attempt_id"]}

    with pytest.raises(RuntimeError, match="partial failure"):
        _publish(runner, _job("job_consumer", consume), run_id=run_id)
    run_root = config.runtime.runs_dir / run_id
    traceback = next((run_root / "data/jobs/job_consumer/attempts").glob("*/steps/work/tasks/only/traceback.txt"))
    assert "is not pinned by the attempt claim" in traceback.read_text(encoding="utf-8")
