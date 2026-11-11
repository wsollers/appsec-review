"""Operator corpus names are independent of verified target Git tags."""
from __future__ import annotations

import json
import os
import shlex
from types import SimpleNamespace
from uuid import UUID

import pytest

from appsec_review.acceptance.state import StepwiseState
from appsec_review.runtime import JobRunner
from tests.test_repair_admission import fixture
from tests.test_stepwise_rewind import stepwise


TARGET_TAG = "appsec-multi-vuln-c094-v1"
CORPUS = "appsec-multi-vuln-c094-scoped-v1"
HEAD = "c" * 40


def _walk(tmp_path, monkeypatch, *, target_commit=HEAD):
    config, (job,), _ = fixture(tmp_path)
    deployment = tmp_path / "deploy/dagster"
    deployment.mkdir(parents=True)
    (deployment / ".env").write_text(f"APPSEC_UID={os.getuid()}\nAPPSEC_GID={os.getgid()}\n")
    for key, value in {
        "ROOT": tmp_path, "STATE_ROOT": tmp_path / "runs/metadata/stepwise", "DEPLOYMENT": deployment,
        "ACCEPTANCE_ROOT": tmp_path / "test/acceptance", "SEED_STORE": tmp_path / "data/acceptance-seeds",
    }.items():
        monkeypatch.setattr(stepwise, key, value)
    calls = []

    def git(*args, cwd):
        calls.append(args)
        if args[0] in {"status", "check-ref-format"}:
            return ""
        if args == ("rev-parse", "HEAD"):
            return HEAD
        if args == ("rev-parse", "--verify", f"refs/tags/{TARGET_TAG}^{{commit}}"):
            return target_commit
        raise RuntimeError("target Git tag does not exist")

    monkeypatch.setattr(stepwise, "git", git)
    monkeypatch.setattr(stepwise, "get_run", lambda *_: {"status": "SUCCESS"})
    dispatch = str(UUID(int=1))
    result = JobRunner(config).run(job, orchestration={"system": "dagster", "run_id": dispatch})
    run_id = result["status"]["run_id"]
    topology = {"graph": "wave1_review", "jobs": [{
        "job_id": job.job_id, "name": job.name, "dependencies": [], "upstream_handoffs": [],
        "propagate_handoff": True}]}
    state = StepwiseState.create(run_id, target="/opt/app/targets/fixture", topology=topology)
    state.record_launch(job.job_id, dispatch)
    state_path = stepwise.STATE_ROOT / run_id / "state.json"
    state.save(state_path)
    old = stepwise.ACCEPTANCE_ROOT / TARGET_TAG
    old.mkdir(parents=True)
    (old / "historical.json").write_bytes(b"preserve old full-corpus key\n")
    return SimpleNamespace(job=job.job_id, run_id=run_id, state=state_path, old=old, calls=calls)


@pytest.mark.parametrize("explicit", [False, True], ids=["default-tag", "separate-namespace"])
def test_accept_records_corpus_and_verified_target_tag_without_old_key_writes(tmp_path, monkeypatch, explicit):
    walk = _walk(tmp_path, monkeypatch)
    namespace = CORPUS if explicit else TARGET_TAG
    if explicit:
        (walk.old / f"{walk.job}.json").write_bytes(b"old key must not be overwritten\n")
        (walk.old / f"{walk.job}.provenance.json").write_bytes(b"old provenance must not be overwritten\n")
    before = {path.name: path.read_bytes() for path in walk.old.iterdir()}
    command = ["--url", "http://127.0.0.1:3000/graphql", "accept",
               "--job", walk.job, "--app-run", walk.run_id, "--tag", namespace]
    if explicit:
        command.extend(("--target-tag", TARGET_TAG))
    assert stepwise.main(command) == 0
    destination = stepwise.ACCEPTANCE_ROOT / namespace
    provenance = json.loads((destination / f"{walk.job}.provenance.json").read_bytes())
    assert provenance["corpus_tag"] == namespace
    assert provenance["target_tag"] == TARGET_TAG
    assert provenance["target_commit"] == HEAD
    header, _ = stepwise.resolve_chain(destination / "seeds", walk.job)
    assert header["target_tag"] == TARGET_TAG and header["target_commit"] == HEAD
    assert StepwiseState.load(walk.state).corpus_tag == namespace
    assert ("rev-parse", "--verify", f"refs/tags/{TARGET_TAG}^{{commit}}") in walk.calls
    assert not any(CORPUS in arg for call in walk.calls for arg in call)
    assert all((walk.old / name).read_bytes() == value for name, value in before.items())


@pytest.mark.parametrize("bad", ["missing", "different-head"])
def test_accept_refuses_missing_or_moved_target_tag_before_writing_keys(tmp_path, monkeypatch, bad):
    walk = _walk(tmp_path, monkeypatch, target_commit="d" * 40 if bad == "different-head" else HEAD)
    before = {path.name: path.read_bytes() for path in walk.old.iterdir()}
    assert stepwise.main([
        "--url", "http://127.0.0.1:3000/graphql", "accept", "--job", walk.job, "--app-run", walk.run_id,
        "--tag", CORPUS, "--target-tag", "missing" if bad == "missing" else TARGET_TAG,
    ]) == 2
    assert not (stepwise.ACCEPTANCE_ROOT / CORPUS).exists()
    assert StepwiseState.load(walk.state).job(walk.job)["status"] != "accepted"
    assert {path.name: path.read_bytes() for path in walk.old.iterdir()} == before


@pytest.mark.parametrize("target_tag", [None, TARGET_TAG], ids=["default", "explicit"])
def test_parity_accept_instruction_carries_explicit_target_tag(target_tag):
    command = shlex.split(stepwise.acceptance_command("job_fixture", CORPUS, "run-1", target_tag))
    assert command[command.index("--tag") + 1] == CORPUS
    if target_tag is None:
        assert "--target-tag" not in command
    else:
        assert command[command.index("--target-tag") + 1] == TARGET_TAG
