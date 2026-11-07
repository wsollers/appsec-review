"""A consumer reads the producer attempt its claim pinned, never whatever latest.json says."""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.runtime.contracts import InputRequirement, JobContract
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


def _contract(*producers):
    return JobContract(inputs=tuple(InputRequirement(name, "handoff", "appsec-review/job-handoff/2")
                                    for name in producers))


def _job(job_id: str, handler, consumes=()):
    return Job(job_id, "fixture" if job_id == "job_fixture" else job_id, handler, units=(Unit("work.only", handler),),
               contract=_contract(*consumes))


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
    with upstream_scope(run_root, "job_consumer", {"job_fixture": first["handoff_sha256"]},
                        contract=_contract("job_fixture")):
        assert current_pins(run_root) == {"job_fixture": first["handoff_sha256"]}
        accepted = accepted_upstream(run_root, "job_fixture")
        assert accepted.pinned is True
        assert accepted.sha256 == first["handoff_sha256"]
        assert accepted.handoff["attempt_id"] == first["status"]["attempt_id"]
        assert accepted.path.startswith("data/jobs/job_fixture/attempts/")
        assert file_sha256(run_root / accepted.path) == first["handoff_sha256"]
    # The job's own prior attempt is read by pointer, explicitly, for checkpoint reuse only.
    assert accepted_latest(run_root, "job_fixture").sha256 == second["handoff_sha256"]
    with upstream_scope(run_root, "job_fixture", {}, contract=JobContract()):
        assert accepted_latest(run_root, "job_fixture").sha256 == second["handoff_sha256"]


def test_scoped_read_refuses_an_accepted_producer_the_claim_did_not_pin(tmp_path: Path) -> None:
    config, runner = _runner(tmp_path, "job_fixture")
    outcome = _publish(runner, _job("job_fixture", lambda unit: {"value": 1}))
    run_root = config.runtime.runs_dir / outcome["status"]["run_id"]
    with upstream_scope(run_root, "job_consumer", {}, contract=_contract("job_fixture", "job_absent")):
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
    with upstream_scope(run_root, "job_consumer", {"job_fixture": "0" * 64},
                        contract=_contract("job_fixture")):
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
    """Unspecified standalone supply selects the typed declared producer at claim time."""
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
        return {"value": 2}

    consumer = _job("job_consumer", consume, consumes=("job_fixture",))
    pins = consumable_handoffs(run_root, "job_consumer", consumer.consumes, {})
    assert pins == {"job_fixture": first["handoff_sha256"]}
    outcome = _publish(runner, consumer, run_id=run_id)
    assert seen == {"sha256": first["handoff_sha256"], "pinned": True}
    claim = json.loads((run_root / "data/jobs/job_consumer/attempts" / outcome["status"]["attempt_id"]
                        / "claim.json").read_text(encoding="utf-8"))
    assert claim["consumable_handoffs"] == {"job_fixture": first["handoff_sha256"]}
    assert claim["upstream_handoffs"] == {"job_fixture": first["handoff_sha256"]}
    from appsec_review.runtime.inputs import read_input_observations
    reads = read_input_observations(run_root, outcome["handoff"])
    assert reads["reads"][0]["handoff_sha256"] == first["handoff_sha256"]
    assert reads["reads"][0]["read"] and reads["reads"][0]["cited"] is None


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
    assert "undeclared consumption by job_consumer: job_fixture/handoff" in traceback.read_text(encoding="utf-8")


def test_available_declared_producer_is_not_supplied_by_empty_projection(tmp_path: Path) -> None:
    config, runner = _runner(tmp_path, "job_fixture", "job_consumer")
    first = _publish(runner, _job("job_fixture", lambda unit: {"value": 1}))
    root = config.runtime.runs_dir / first["status"]["run_id"]

    def consume(unit):
        assert accepted_upstream(unit.job.run_root, "job_fixture", required=False) is None
        return {"value": 2}

    outcome = _publish(runner, _job("job_consumer", consume, ("job_fixture",)), root.name, upstream={})
    claim = json.loads((Path(outcome["attempt_root"]) / "claim.json").read_bytes())
    assert claim["consumable_handoffs"] == {"job_fixture": first["handoff_sha256"]}
    assert claim["upstream_handoffs"] == {}
    from appsec_review.runtime.inputs import read_input_observations
    assert read_input_observations(root, outcome["handoff"])["reads"] == []


@pytest.mark.parametrize("boundary", ("unified", "latest", "foreign-root", "foreign-latest"))
def test_caught_unauthorized_reader_failure_is_sticky(tmp_path: Path, boundary: str) -> None:
    config, runner = _runner(tmp_path, "job_fixture", "job_consumer")
    first = _publish(runner, _job("job_fixture", lambda unit: {"value": 1}))
    root = config.runtime.runs_dir / first["status"]["run_id"]

    def consume(unit):
        with pytest.raises(ValueError):
            if boundary == "latest":
                accepted_latest(root, "job_fixture")
            elif boundary == "foreign-latest":
                accepted_latest(root / "foreign", "job_fixture")
            elif boundary == "foreign-root":
                accepted_upstream(root / "foreign", "job_fixture", required=False)
            else:
                accepted_upstream(root, "job_fixture", required=False)
        return {"value": "must not publish despite caught exception"}

    consumer = replace(_job("job_consumer", consume), contract=JobContract(schedule_after=("job_fixture",)))
    assert consumer.consumes == ()
    assert consumable_handoffs(root, consumer.job_id, consumer.consumes, {}) == {}
    with pytest.raises(RuntimeError, match="input contract violation"):
        _publish(runner, consumer, root.name, upstream={})
    assert not (root / "data/jobs/job_consumer/latest.json").exists()


def test_typed_unit_observes_admitted_old_pin_after_latest_moves(tmp_path: Path) -> None:
    config, runner = _runner(tmp_path, "job_fixture", "job_consumer")
    producer = _job("job_fixture", lambda unit: {"value": 1})
    first = _publish(runner, producer)
    root = config.runtime.runs_dir / first["status"]["run_id"]

    def consume(unit):
        assert accepted_upstream(root, "job_fixture").sha256 == first["handoff_sha256"]
        return {"value": 2}

    consumer = _job("job_consumer", consume, ("job_fixture",))
    claim = runner.begin_attempt(consumer, run_id=root.name, source_fingerprint="snapshot",
                                 upstream_handoffs={"job_fixture": first["handoff_sha256"]})
    second = _publish(runner, _job("job_fixture", lambda unit: {"value": 3}), root.name)
    assert second["handoff_sha256"] != first["handoff_sha256"]
    runner.execute_or_reuse_unit(consumer, claim, "work.only")
    receipt = json.loads((root / claim["attempt_path"] / "steps/work/tasks/only/status.json").read_bytes())
    assert receipt["input_consumption"]["reads"][0]["handoff_sha256"] == first["handoff_sha256"]
    assert receipt["input_consumption"]["reads"][0]["cited"] is None
