"""Offline operator transitions with real runner publications and repair admission."""

from copy import deepcopy
from dataclasses import replace
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from uuid import UUID

import pytest

from appsec_review.acceptance.state import StateError, StepwiseState
from appsec_review.runtime import JobRunner, Unit
from appsec_review.runtime.repair import admit_repair, plan_repair, verify_dispatch_stop
from appsec_review.storage import atomic_json
from appsec_review.storage.shared import reference, verify_reference
from tests.release_support import write_release
from tests.test_repair_admission import fixture

BIN = Path(__file__).parents[1] / "deploy/dagster/bin"
sys.path.insert(0, str(BIN))
SPEC = importlib.util.spec_from_file_location("stepwise_rewind_tests", BIN / "stepwise.py")
stepwise = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stepwise)
rewind = stepwise.stepwise_rewind
IDS = ("job_a", "job_b", "job_c", "job_d", "job_e")
DEPENDENCIES = {"job_a": [], "job_b": ["job_a"], "job_c": [], "job_d": ["job_b", "job_c"], "job_e": ["job_d"]}
TOPOLOGY = {"graph": "wave1_review", "jobs": [
    {"job_id": name, "name": name, "dependencies": DEPENDENCIES[name],
     "upstream_handoffs": DEPENDENCIES[name], "propagate_handoff": True} for name in IDS]}


class Instance:
    def __init__(self):
        self.runs = {}
        self.health = "NOT_FOUND"
        self.run_launcher = SimpleNamespace(
            supports_check_run_worker_health=True,
            check_run_worker_health=lambda run: SimpleNamespace(status=SimpleNamespace(value=self.health)))

    def get_runs(self, *, filters):
        return [run for run in self.runs.values()
                if all(run.tags.get(key) == value for key, value in filters.tags.items())]

    def get_run_by_id(self, run_id):
        return self.runs.get(run_id)


@pytest.fixture
def walk(tmp_path, monkeypatch):
    config, jobs, _ = fixture(tmp_path, IDS)
    jobs = tuple(replace(job, units=(Unit("work.only", lambda context: {
        "value": 7, "semantic_path": "safe/original"}),)) if job.job_id == "job_b" else job for job in jobs)
    instance = Instance()
    deployment = tmp_path / "deploy/dagster"
    deployment.mkdir(parents=True)
    (deployment / ".env").write_text(f"APPSEC_UID={os.getuid()}\nAPPSEC_GID={os.getgid()}\n")
    for key, value in {
        "ROOT": tmp_path, "STATE_ROOT": tmp_path / "runs/metadata/stepwise", "DEPLOYMENT": deployment,
        "ACCEPTANCE_ROOT": tmp_path / "test/acceptance", "SEED_STORE": tmp_path / "data/acceptance-seeds",
    }.items():
        monkeypatch.setattr(stepwise, key, value)
    # External Git and Dagster queries only; normalization, audit, snapshots, guards and writes are real.
    monkeypatch.setattr(stepwise, "git", lambda *args, **kwargs: "" if args[0] == "status" else "testcommit")
    monkeypatch.setattr(stepwise, "get_run", lambda url, dispatch: {
        "status": "SUCCESS" if instance.runs[dispatch].is_finished else "STARTED"})
    runner = JobRunner(config)
    context = SimpleNamespace(config=config, jobs=jobs, instance=instance, runner=runner, root=tmp_path)
    run_id = None
    for index, job in enumerate(jobs[:4]):
        dispatch = str(UUID(int=index + 1))
        upstream = {name: json.loads((context.run_root / f"data/jobs/{name}/latest.json").read_bytes())["handoff_sha256"]
                    for name in DEPENDENCIES[job.job_id]}
        result = runner.run(job, run_id=run_id, upstream_handoffs=upstream,
                            orchestration={"system": "dagster", "run_id": dispatch})
        if run_id is None:
            run_id = result["status"]["run_id"]
            context.run_root = config.runtime.runs_dir / run_id
            context.path = stepwise.STATE_ROOT / run_id / "state.json"
            state = StepwiseState.create(run_id, target="/opt/app/targets/fixture", topology=TOPOLOGY)
        else:
            state = StepwiseState.load(context.path)
        instance.runs[dispatch] = SimpleNamespace(
            run_id=dispatch, is_finished=True, tags={"appsec/application_run_id": run_id})
        verify_dispatch_stop(config, context.run_root, dispatch, instance=instance)
        state.record_launch(job.job_id, dispatch)
        state.save(context.path)
        args = SimpleNamespace(app_run=run_id, job=job.job_id, tag="fixture-v1", url="offline", show=3)
        if index < 3:
            assert stepwise.command_accept(args) == 0
        else:
            assert stepwise.command_check(args) == 0
    context.args = args
    context.args.job = "job_b"
    (tmp_path / "release-src/job_b/job.py").write_text("VERSION = 2\n")
    write_release(tmp_path, IDS)
    context.plan = plan_repair(config, context.run_root, jobs, "none", dependencies=DEPENDENCIES)
    assert context.plan["admissible"], context.plan["refusals"]
    assert [entry["action"] for entry in context.plan["decisions"]] == [
        "REUSE", "RUN", "REUSE", "INVALIDATE", "INVALIDATE"]
    context.binding = admit_repair(config, context.run_root, jobs, context.plan, dependencies=DEPENDENCIES)
    context.plan_path = tmp_path / "repair-plan.json"
    atomic_json(context.plan_path, context.plan)
    context.args.plan = context.plan_path

    def compose(*args):
        assert args[:5] == ("exec", "-T", "code-location", "python", "-c")
        assert args[5] == rewind.RUNTIME_PROBE
        return json.dumps(rewind.inspect_runtime(config, context.run_root, TOPOLOGY,
                                                json.loads(args[7]), instance,
                                                verify_stops=args[8:] == ("verify-stops",)))
    monkeypatch.setattr(stepwise, "compose", compose)
    return context


def replay(walk, *, value=7, semantic_path="safe/original"):
    state = StepwiseState.load(walk.path)
    dispatch = str(UUID(int=100))
    state.record_launch("job_b", dispatch)
    state.save(walk.path)
    job = replace(walk.jobs[1], units=(Unit("work.only", lambda context: {
        "value": value, "semantic_path": semantic_path}),))
    pointer = json.loads((walk.run_root / "data/jobs/job_a/latest.json").read_bytes())
    result = walk.runner.run(job, run_id=state.app_run_id, upstream_handoffs={"job_a": pointer["handoff_sha256"]},
                             orchestration={"system": "dagster", "run_id": dispatch})
    walk.instance.runs[dispatch] = SimpleNamespace(
        run_id=dispatch, is_finished=True, tags={"appsec/application_run_id": state.app_run_id})
    return result


def test_rewind_preserves_independent_pending_and_original_evidence(walk):
    before = StepwiseState.load(walk.path)
    baseline = stepwise.ACCEPTANCE_ROOT / "fixture-v1/job_b.json"
    key_bytes = baseline.read_bytes()
    assert stepwise.main(["--url", "http://127.0.0.1:1234/graphql", "rewind",
                          "--app-run", walk.args.app_run, "--plan", str(walk.plan_path)]) == 0
    after = StepwiseState.load(walk.path)
    assert after.next_job()["job_id"] == "job_b"
    assert [item["status"] for item in after.jobs] == ["accepted", "pending", "accepted", "pending", "pending"]
    for name in ("job_a", "job_c", "job_e"):
        assert after.job(name) == before.job(name)
    for name in ("job_b", "job_d"):
        assert after.job(name)["dagster_run_ids"] == []
        assert after.job(name)["check"] is None
        assert after.job(name)["handoff_sha256"] is None
    ref = after.job("job_b")["replays"][0]["evidence"]
    evidence = rewind.read_evidence(walk.path.parent, ref)
    assert evidence["state"] == before.as_dict()
    assert evidence["binding"] == walk.binding
    assert evidence["plan"] == walk.plan
    assert verify_reference(walk.path.parent, evidence["baselines"]["job_b"]["key"]).read_bytes() == key_bytes
    assert baseline.read_bytes() == key_bytes
    with pytest.raises(StateError, match="has not been launched"):
        stepwise.command_accept(walk.args)
    state_bytes = walk.path.read_bytes()
    assert stepwise.command_rewind(walk.args) == 0
    assert walk.path.read_bytes() == state_bytes


def test_matching_replay_reaccepts_without_replacing_key_provenance_or_seed(walk):
    key_root = stepwise.ACCEPTANCE_ROOT / "fixture-v1"
    original = {path: path.read_bytes() for path in key_root.rglob("*") if path.is_file()}
    assert stepwise.command_rewind(walk.args) == 0
    result = replay(walk)
    assert stepwise.command_check(walk.args) == 0
    assert (walk.run_root / f"data/recovery/dispatches/{UUID(int=100)}.json").is_file()
    checked = StepwiseState.load(walk.path).job("job_b")
    assert checked["check"]["replay_comparison"]["passed"]
    assert {change["field"] for change in checked["check"]["replay_comparison"]["admitted_control_changes"]} == {
        "repair_admission_sha256", "unit_reuse"}
    checked_bytes = walk.path.read_bytes()
    assert stepwise.command_rewind(walk.args) == 0
    assert walk.path.read_bytes() == checked_bytes
    assert stepwise.command_accept(walk.args) == 0
    state = StepwiseState.load(walk.path)
    assert state.next_job()["job_id"] == "job_d"
    assert state.job("job_b")["handoff_sha256"] == result["handoff_sha256"]
    receipt = json.loads(verify_reference(
        walk.path.parent, state.job("job_b")["replays"][-1]["acceptance"]).read_bytes())
    assert receipt["comparison"]["passed"]
    assert receipt["provenance"]["attempt"] == "attempt_0002"
    assert all(path.read_bytes() == content for path, content in original.items())
    state_bytes = walk.path.read_bytes()
    assert stepwise.command_rewind(walk.args) == 0
    assert walk.path.read_bytes() == state_bytes
    assert len(state.job("job_b")["replays"]) == 1


def test_recover_verifies_all_claimed_archived_and_untracked_dispatches_without_launch(walk):
    original = StepwiseState.load(walk.path).as_dict()
    for index in (1, 2, 3, 4):
        (walk.run_root / f"data/recovery/dispatches/{UUID(int=index)}.json").unlink()
    untracked = str(UUID(int=222))
    walk.instance.runs[untracked] = SimpleNamespace(
        run_id=untracked, is_finished=True, tags={"appsec/application_run_id": walk.args.app_run})
    walk.args.plan = None
    assert stepwise.command_recover(walk.args) == 0
    assert StepwiseState.load(walk.path).as_dict() == original
    assert (walk.run_root / f"data/recovery/dispatches/{untracked}.json").is_file()
    walk.args.plan = walk.plan_path
    assert stepwise.command_recover(walk.args) == 0
    state = StepwiseState.load(walk.path)
    assert rewind.recorded_dispatches(walk.path.parent, state) == [str(UUID(int=i)) for i in (1, 2, 3, 4)]
    assert state.job("job_c") == original["jobs"][2]
    replay(walk)
    assert not (walk.run_root / f"data/recovery/dispatches/{UUID(int=100)}.json").exists()
    assert stepwise.command_check(walk.args) == 0
    assert (walk.run_root / f"data/recovery/dispatches/{UUID(int=100)}.json").is_file()
    assert len(walk.instance.runs) == 6


@pytest.mark.parametrize("condition", ["active", "unknown", "foreign", "missing", "untracked-active"])
def test_recover_refuses_uncertain_dispatches_without_rewinding(walk, condition):
    dispatch = str(UUID(int=1))
    if condition == "active":
        walk.instance.runs[dispatch].is_finished = False
    elif condition == "unknown":
        walk.instance.health = "UNKNOWN"
    elif condition == "foreign":
        walk.instance.runs[dispatch].tags["appsec/application_run_id"] = "foreign"
    elif condition == "missing":
        del walk.instance.runs[dispatch]
    else:
        walk.instance.runs["queued"] = SimpleNamespace(
            run_id="queued", is_finished=False, tags={"appsec/application_run_id": walk.args.app_run})
    before = walk.path.read_bytes()
    with pytest.raises(StateError, match="verified stopped execution"):
        stepwise.command_recover(walk.args)
    assert walk.path.read_bytes() == before


@pytest.mark.parametrize("change", [{"value": 8}, {"semantic_path": "different/path"}], ids=["numeric", "semantic-path"])
def test_semantic_mismatch_fails_check_and_acceptance(walk, change):
    assert stepwise.command_rewind(walk.args) == 0
    baseline = (stepwise.ACCEPTANCE_ROOT / "fixture-v1/job_b.json").read_bytes()
    replay(walk, **change)
    assert stepwise.command_check(walk.args) == 1
    item = StepwiseState.load(walk.path).job("job_b")
    comparison = item["check"]["replay_comparison"]
    assert item["status"] == "failed"
    assert not comparison["passed"]
    assert any(entry["path"] == f"outputs.work.only.{next(iter(change))}" and entry["class"] == "coverage"
               for entry in comparison["differences"])
    with pytest.raises(StateError, match="fails its check"):
        stepwise.command_accept(walk.args)
    assert (stepwise.ACCEPTANCE_ROOT / "fixture-v1/job_b.json").read_bytes() == baseline


@pytest.mark.parametrize("damage", ["foreign", "unadmitted", "plan-hash", "admission-bytes",
                                  "stale-attempt", "status-hash", "config-hash", "topology", "deployment",
                                  "superseded-admission", "release-bytes"])
def test_foreign_unadmitted_stale_or_corrupt_repair_cannot_rewind(walk, damage):
    if damage == "foreign":
        walk.plan["run_id"] = "2026-01-01-9999"
        walk.plan["plan_sha256"] = rewind.digest({k: v for k, v in walk.plan.items() if k != "plan_sha256"})
        atomic_json(walk.plan_path, walk.plan)
    elif damage == "unadmitted":
        binding = deepcopy(walk.binding)
        binding["repair"] = None
        atomic_json(walk.run_root / "data/recovery/current.json", binding)
    elif damage == "plan-hash":
        walk.plan["decisions"][1]["action"] = "REUSE"
        atomic_json(walk.plan_path, walk.plan)
    elif damage == "admission-bytes":
        (walk.run_root / walk.binding["repair"]["path"]).write_text("{}")
    elif damage == "release-bytes":
        (walk.run_root / walk.binding["release"]["path"]).write_text("{}")
    elif damage == "superseded-admission":
        fresh = plan_repair(walk.config, walk.run_root, walk.jobs, "none", dependencies=DEPENDENCIES)
        assert fresh["plan_sha256"] != walk.plan["plan_sha256"]
        admit_repair(walk.config, walk.run_root, walk.jobs, fresh, dependencies=DEPENDENCIES)
    elif damage == "stale-attempt":
        walk.runner.run(
            walk.jobs[3], run_id=walk.args.app_run, orchestration={"system": "dagster", "run_id": "untracked"})
        walk.instance.runs["untracked"] = SimpleNamespace(
            run_id="untracked", is_finished=True, tags={"appsec/application_run_id": walk.args.app_run})
        verify_dispatch_stop(walk.config, walk.run_root, "untracked", instance=walk.instance)
    elif damage == "status-hash":
        path = walk.run_root / walk.plan["attempt_snapshots"]["job_b"]["status"]["path"]
        path.write_bytes(path.read_bytes() + b"\n")
    elif damage == "config-hash":
        path = walk.run_root / "data/configuration/resolved.json"
        path.write_bytes(path.read_bytes() + b"\n")
    elif damage == "topology":
        state = StepwiseState.load(walk.path)
        state.topology[1]["dependencies"] = []
        state.save(walk.path)
    elif damage == "deployment":
        (walk.root / "release-src/job_b/job.py").write_text("VERSION = 3\n")
        write_release(walk.root, IDS)
    before = walk.path.read_bytes()
    with pytest.raises((StateError, ValueError), match="different|admitted|intact|mismatch|stale|changed|differs|integrity"):
        stepwise.command_recover(walk.args)
    assert walk.path.read_bytes() == before
    assert not (walk.path.parent / "rewinds").exists()


@pytest.mark.parametrize("condition", ["active", "unknown-worker", "queued-untracked", "missing-receipt", "unknown-worker-record"])
def test_live_or_uncertain_execution_is_refused(walk, condition):
    if condition == "active":
        walk.instance.runs[str(UUID(int=2))].is_finished = False
    elif condition == "unknown-worker":
        walk.instance.health = "UNKNOWN"
    elif condition == "queued-untracked":
        walk.instance.runs["queued"] = SimpleNamespace(
            run_id="queued", is_finished=False, tags={"appsec/application_run_id": walk.args.app_run})
    elif condition == "missing-receipt":
        (walk.run_root / f"data/recovery/dispatches/{UUID(int=2)}.json").unlink()
    else:
        atomic_json(walk.run_root / "data/recovery/workers/unknown.json", {"status": "UNKNOWN"})
    before = walk.path.read_bytes()
    with pytest.raises(StateError, match="verified stopped execution"):
        stepwise.command_rewind(walk.args)
    assert walk.path.read_bytes() == before


@pytest.mark.parametrize("which", ["key", "provenance", "claim", "evidence"])
def test_preserved_evidence_corruption_is_never_accepted(walk, which):
    assert stepwise.command_rewind(walk.args) == 0
    state = StepwiseState.load(walk.path)
    ref = state.job("job_b")["replays"][0]["evidence"]
    evidence = rewind.read_evidence(walk.path.parent, ref)
    path = verify_reference(walk.path.parent, ref if which == "evidence" else evidence["baselines"]["job_b"][which])
    original = path.read_bytes()
    changed = original.replace(b"job_b", b"job_z", 1)
    assert changed != original and len(changed) == len(original)
    path.write_bytes(changed)
    replay(walk)
    with pytest.raises(ValueError, match="integrity|digest"):
        stepwise.command_accept(walk.args)
    assert StepwiseState.load(walk.path).job("job_b")["status"] != "accepted"


def test_mutable_corpus_cannot_replace_the_preserved_comparison(walk):
    assert stepwise.command_rewind(walk.args) == 0
    replay(walk, value=99)
    baseline = stepwise.ACCEPTANCE_ROOT / "fixture-v1/job_b.json"
    document = json.loads(baseline.read_bytes())
    document["outputs"]["work.only"]["value"] = 99
    atomic_json(baseline, document)
    assert stepwise.command_check(walk.args) == 1
    assert StepwiseState.load(walk.path).job("job_b")["check"]["replay_comparison"]["baseline"]["key"]


def test_missing_new_attempt_cannot_reaccept_the_old_publication(walk):
    assert stepwise.command_rewind(walk.args) == 0
    state = StepwiseState.load(walk.path)
    dispatch = str(UUID(int=100))
    state.record_launch("job_b", dispatch)
    state.save(walk.path)
    walk.instance.runs[dispatch] = SimpleNamespace(
        run_id=dispatch, is_finished=True, tags={"appsec/application_run_id": state.app_run_id})
    with pytest.raises(StateError, match="fresh dispatch/attempt"):
        stepwise.command_accept(walk.args)
    assert StepwiseState.load(walk.path).job("job_b")["status"] == "launched"


def test_rewind_retries_after_archive_publication_without_duplicating_history(walk, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(StepwiseState, "save", lambda *args: (_ for _ in ()).throw(OSError("interrupted")))
        with pytest.raises(OSError, match="interrupted"):
            stepwise.command_rewind(walk.args)
    assert stepwise.command_rewind(walk.args) == 0
    state = StepwiseState.load(walk.path)
    assert len(state.job("job_b")["replays"]) == 1
    assert len(list((walk.path.parent / "rewinds").glob("*/evidence.json"))) == 1


def test_second_admitted_repair_keeps_the_original_key_and_prior_acceptance(walk):
    assert stepwise.command_rewind(walk.args) == 0
    replay(walk)
    assert stepwise.command_accept(walk.args) == 0
    state = StepwiseState.load(walk.path)
    prior = deepcopy(state.job("job_b")["replays"])
    # Finish the previously checked decision through a fresh real runner attempt.
    dispatch = str(UUID(int=101))
    state.record_launch("job_d", dispatch)
    state.save(walk.path)
    upstream = {name: json.loads((walk.run_root / f"data/jobs/{name}/latest.json").read_bytes())["handoff_sha256"]
                for name in DEPENDENCIES["job_d"]}
    walk.runner.run(walk.jobs[3], run_id=state.app_run_id, upstream_handoffs=upstream,
                    orchestration={"system": "dagster", "run_id": dispatch})
    walk.instance.runs[dispatch] = SimpleNamespace(
        run_id=dispatch, is_finished=True, tags={"appsec/application_run_id": state.app_run_id})
    verify_dispatch_stop(walk.config, walk.run_root, dispatch, instance=walk.instance)
    walk.args.job = "job_d"
    assert stepwise.command_accept(walk.args) == 0
    (walk.root / "release-src/job_b/job.py").write_text("VERSION = 3\n")
    write_release(walk.root, IDS)
    plan = plan_repair(walk.config, walk.run_root, walk.jobs, "none", dependencies=DEPENDENCIES)
    assert plan["admissible"]
    admit_repair(walk.config, walk.run_root, walk.jobs, plan, dependencies=DEPENDENCIES)
    atomic_json(walk.plan_path, plan)
    assert stepwise.command_rewind(walk.args) == 0
    state = StepwiseState.load(walk.path)
    assert state.job("job_b")["replays"][:-1] == prior
    evidence = rewind.read_evidence(walk.path.parent, state.job("job_b")["replays"][-1]["evidence"])
    original = rewind.read_evidence(walk.path.parent, prior[0]["evidence"])
    assert evidence["baselines"]["job_b"]["key"]["sha256"] == original["baselines"]["job_b"]["key"]["sha256"]
    assert evidence["baselines"]["job_b"]["claim"]["sha256"] == original["baselines"]["job_b"]["claim"]["sha256"]


@pytest.fixture(params=["job_model_connectivity", "job_review_intake"])
def inventory_walk(tmp_path, monkeypatch, request):
    job_id = request.param
    config, (job,), _ = fixture(tmp_path, (job_id,))
    suffix = rewind.MODEL_PREFLIGHT_ARTIFACTS[job_id]
    step, task, filename = suffix.split("/")[1], suffix.split("/")[3], suffix.split("/")[-1]
    report = {
        "schema": "appsec-review/model-preflight/1",
        "required": [{"provider": "copilot-sdk", "model": name, "enabled": True,
                      "job_id": job_id, "setting": "settings.model"}
                     for name in ("claude-opus-5.5", "claude-sonnet-5.5")],
        "not_required": [{"provider": "copilot-sdk", "model": "optional-checked", "enabled": False,
                          "job_id": job_id, "setting": "settings.optional", "reason": "model setting disabled"}],
        "providers": {"copilot-sdk": {
            "provider": "copilot-sdk", "method": "catalog", "error": None, "transport": True,
            "listed": ["claude-opus-5.5", "claude-sonnet-5.5", "optional-checked", "unrelated-old"],
            "models": {name: {"available": True, "detail": "listed and enabled for the Copilot worker account"}
                       for name in ("claude-opus-5.5", "claude-sonnet-5.5", "optional-checked")},
        }},
        "unavailable": [], "unavailable_not_required": [], "gaps": [],
    }

    def produce(unit):
        path = unit.unit_root / filename
        atomic_json(path, report)
        return {"artifact": reference(unit.job.run_root, path), "verified": ["copilot-sdk/claude-opus-5.5",
                                                                          "copilot-sdk/claude-sonnet-5.5"]}

    job = replace(job, units=(Unit(f"{step}.{task}", produce),))
    deployment = tmp_path / "deploy/dagster"
    deployment.mkdir(parents=True)
    (deployment / ".env").write_text(f"APPSEC_UID={os.getuid()}\nAPPSEC_GID={os.getgid()}\n")
    for key, value in {
        "ROOT": tmp_path, "STATE_ROOT": tmp_path / "runs/metadata/stepwise", "DEPLOYMENT": deployment,
        "ACCEPTANCE_ROOT": tmp_path / "test/acceptance", "SEED_STORE": tmp_path / "data/acceptance-seeds",
    }.items():
        monkeypatch.setattr(stepwise, key, value)
    monkeypatch.setattr(stepwise, "git", lambda *args, **kwargs: "" if args[0] == "status" else "testcommit")
    monkeypatch.setattr(stepwise, "get_run", lambda *args: {"status": "SUCCESS"})
    runner = JobRunner(config)
    original = runner.run(job, orchestration={"system": "dagster", "run_id": str(UUID(int=1))})
    run_id = original["status"]["run_id"]
    run_root = config.runtime.runs_dir / run_id
    instance = Instance()
    instance.runs[str(UUID(int=1))] = SimpleNamespace(
        run_id=str(UUID(int=1)), is_finished=True, tags={"appsec/application_run_id": run_id})
    verify_dispatch_stop(config, run_root, str(UUID(int=1)), instance=instance)
    topology = {"graph": "wave1_review", "jobs": [{"job_id": job_id, "name": job_id,
                 "dependencies": [], "upstream_handoffs": [], "propagate_handoff": True}]}
    state = StepwiseState.create(run_id, target="/opt/app/targets/fixture", topology=topology)
    state.record_launch(job_id, str(UUID(int=1)))
    path = stepwise.STATE_ROOT / run_id / "state.json"
    state.save(path)
    args = SimpleNamespace(app_run=run_id, job=job_id, tag="inventory-v1", url="offline", show=3)
    assert stepwise.command_accept(args) == 0
    (tmp_path / f"release-src/{job_id}/job.py").write_text("VERSION = 2\n")
    write_release(tmp_path, (job_id,))
    plan = plan_repair(config, run_root, (job,), "none", dependencies={job_id: []})
    assert plan["admissible"]
    admit_repair(config, run_root, (job,), plan, dependencies={job_id: []})
    state = StepwiseState.load(path)
    masks = stepwise.masks_for(run_id, state.target)
    runtime = rewind.inspect_runtime(config, run_root, topology, [str(UUID(int=1))], instance)
    assert rewind.apply_rewind(tmp_path, path, stepwise.ACCEPTANCE_ROOT, state, plan, runtime, masks)

    def compose(*args):
        assert args[:5] == ("exec", "-T", "code-location", "python", "-c")
        assert args[5] == rewind.RUNTIME_PROBE
        return json.dumps(rewind.inspect_runtime(
            config, run_root, topology, json.loads(args[7]), instance,
            verify_stops=args[8:] == ("verify-stops",)))
    monkeypatch.setattr(stepwise, "compose", compose)

    def rerun():
        state = StepwiseState.load(path)
        state.record_launch(job_id, str(UUID(int=2)))
        state.save(path)
        result = runner.run(job, run_id=run_id, orchestration={"system": "dagster", "run_id": str(UUID(int=2))})
        instance.runs[str(UUID(int=2))] = SimpleNamespace(
            run_id=str(UUID(int=2)), is_finished=True, tags={"appsec/application_run_id": run_id})
        return result

    return SimpleNamespace(report=report, rerun=rerun, args=args, path=path, run_root=run_root,
                           job_id=job_id, masks=masks, original=original)


@pytest.mark.parametrize("mode", ["add", "remove", "replace"])
def test_inventory_only_drift_is_reported_and_reaccepted(inventory_walk, mode, capsys):
    walk = inventory_walk
    original_key = stepwise.ACCEPTANCE_ROOT / f"inventory-v1/{walk.job_id}.json"
    old_key = original_key.read_bytes()
    old_artifact = walk.run_root / walk.original["handoff"]["resolving_paths"]["attempt"] / rewind.MODEL_PREFLIGHT_ARTIFACTS[walk.job_id]
    old_bytes = old_artifact.read_bytes()
    listed = walk.report["providers"]["copilot-sdk"]["listed"]
    added = ["gemini-4-carbon"] if mode in {"add", "replace"} else []
    removed = ["unrelated-old"] if mode in {"remove", "replace"} else []
    listed[:] = sorted((set(listed) | set(added)) - set(removed))
    result = walk.rerun()
    assert stepwise.command_check(walk.args) == 0
    comparison = StepwiseState.load(walk.path).job(walk.job_id)["check"]["replay_comparison"]
    assert comparison["passed"]
    assert any("/verify_models/" in entry["path"] for entry in comparison["unadjusted_differences"])
    change, = comparison["advertised_inventory_changes"]
    assert change["added"] == added and change["removed"] == removed
    assert change["previous_count"] == 4 and change["current_count"] == len(listed)
    assert verify_reference(walk.run_root, change["expected_reference"]).read_bytes() == old_bytes
    assert json.loads(verify_reference(walk.run_root, change["actual_reference"]).read_bytes()) == walk.report
    assert stepwise.command_accept(walk.args) == 0
    item = StepwiseState.load(walk.path).job(walk.job_id)
    assert item["handoff_sha256"] == result["handoff_sha256"]
    receipt = json.loads(verify_reference(walk.path.parent, item["replays"][-1]["acceptance"]).read_bytes())
    assert receipt["comparison"]["advertised_inventory_changes"] == [change]
    assert original_key.read_bytes() == old_key and old_artifact.read_bytes() == old_bytes
    output = capsys.readouterr().out
    assert f"added={json.dumps(added)} removed={json.dumps(removed)}" in output


@pytest.mark.parametrize("damage", ["required-listed", "optional-checked-listed", "required-setting",
                                  "availability", "detail", "error", "transport", "method", "gap",
                                  "checked-set"])
def test_inventory_drift_does_not_hide_semantic_changes(inventory_walk, damage):
    walk = inventory_walk
    provider = walk.report["providers"]["copilot-sdk"]
    provider["listed"].append("gemini-4-carbon")
    if damage == "required-listed":
        provider["listed"].remove("claude-opus-5.5")
    elif damage == "optional-checked-listed":
        provider["listed"].remove("optional-checked")
    elif damage == "required-setting":
        walk.report["required"][0]["model"] = "different-required"
    elif damage == "availability":
        provider["models"]["claude-opus-5.5"]["available"] = False
    elif damage == "detail":
        provider["models"]["claude-opus-5.5"]["detail"] = "different/semantic/result"
    elif damage == "error":
        provider["error"] = "provider failed"
    elif damage == "transport":
        provider["transport"] = False
    elif damage == "method":
        provider["method"] = "changed-method"
    elif damage == "gap":
        walk.report["gaps"] = ["unavailable"]
    else:
        del provider["models"]["optional-checked"]
    walk.rerun()
    assert stepwise.command_check(walk.args) == 1
    comparison = StepwiseState.load(walk.path).job(walk.job_id)["check"]["replay_comparison"]
    assert not comparison["passed"] and comparison["advertised_inventory_changes"] == []
    assert any(entry["class"] == "coverage" and "/verify_models/" in entry["path"]
               for entry in comparison["differences"])
    with pytest.raises(StateError, match="fails its check"):
        stepwise.command_accept(walk.args)
    assert StepwiseState.load(walk.path).job(walk.job_id)["status"] == "failed"


@pytest.mark.parametrize("side", ["old-signature", "new-signature", "old-bytes", "new-bytes"])
def test_inventory_accounting_requires_resolving_artifact_signatures(inventory_walk, side):
    walk = inventory_walk
    walk.report["providers"]["copilot-sdk"]["listed"].append("gemini-4-carbon")
    result = walk.rerun()
    state = StepwiseState.load(walk.path)
    evidence = rewind.read_evidence(walk.path.parent, state.job(walk.job_id)["replays"][0]["evidence"])
    baseline = evidence["baselines"][walk.job_id]
    expected = json.loads(verify_reference(walk.path.parent, baseline["key"]).read_bytes())
    attempt = Path(result["attempt_root"])
    actual = stepwise.normalize_job_output(walk.run_root, walk.job_id, walk.masks, attempt_root=attempt)
    candidate = expected if side.startswith("old") else actual
    signature = next(entry for entry in candidate["artifacts"] if "/verify_models/" in entry["path"]
                     and entry["path"].endswith(("/model-connectivity.json", "/model-preflight.json")))
    if side.endswith("signature"):
        signature["sha256"] = "0" * 64
    else:
        selected = Path(walk.original["attempt_root"]) if side.startswith("old") else attempt
        path = selected / rewind.MODEL_PREFLIGHT_ARTIFACTS[walk.job_id]
        data = path.read_bytes()
        changed = data.replace(b"unrelated-old", b"unrelated-new")
        assert len(changed) == len(data) and changed != data
        path.write_bytes(changed)
    with pytest.raises(ValueError, match="signature|digest|integrity"):
        rewind.advertised_inventory_changes(walk.run_root, walk.path.parent, baseline, walk.job_id,
                                           json.loads((attempt / "claim.json").read_bytes()),
                                           expected, actual, walk.masks)
