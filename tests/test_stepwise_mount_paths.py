"""Offline source-history mount alias proof, with real publications and operator comparisons."""

from copy import deepcopy
from dataclasses import replace
import json
import os
from pathlib import Path
import time
from types import SimpleNamespace
from uuid import UUID

import pytest

from appsec_review.acceptance.state import StateError, StepwiseState
from appsec_review.runtime import JobRunner, Unit
from appsec_review.runtime.repair import admit_repair, plan_repair, verify_dispatch_stop
from appsec_review.storage import atomic_json, canonical_json
from appsec_review.storage.shared import immutable_bytes, reference, verify_reference
from tests.release_support import write_release
from tests.test_repair_admission import fixture
from tests.test_stepwise_rewind import Instance, rewind, stepwise

JOB = "job_source_history_analysis"
EXECUTIONS = {"acquire.git_history": ("log", "messages"), "resolve_sources.bind_snapshot": ("tree",)}
DESKTOP = "/run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/Test-Distro"


@pytest.fixture
def mount_walk(tmp_path, monkeypatch, request):
    config, (job,), _ = fixture(tmp_path, (JOB,))
    target = tmp_path / "targets/fixture"
    target.mkdir(parents=True)
    control = SimpleNamespace(change=lambda document, unit: None, receipt_change=lambda document: None)

    def produce(unit):
        old = unit.job.attempt_id == "attempt_0001"
        executions, artifacts = [], []
        for name in EXECUTIONS[unit.unit_id]:
            scratch = unit.unit_root / f"scratch/executions/{name}"
            path = scratch / "execution.json"
            sources = (target, scratch, unit.unit_root / "scratch/gitdir")
            mounts = []
            for source, destination, readonly in zip(sources, ("/target", "/scratch", "/gitdir"), (True, False, True)):
                root = tmp_path / ("targets" if destination == "/target" else "runs")
                alias = f"{DESKTOP}/{'a' * 64 if destination == '/target' else 'b' * 64}"
                mounts.append({"source": str(source), "target": destination, "read_only": readonly,
                               "runtime_source": f"{alias}/{source.relative_to(root)}" if old else str(source)})
            execution = {"schema": "appsec-review/container-execution/1", "tool_id": "tool-git",
                         "receipt_path": path.relative_to(unit.job.run_root).as_posix(),
                         "mounts": mounts, "exit_code": 0, "timed_out": False, "terminal_status": "SUCCEEDED"}
            executions.append(execution)
        document = {"executions": executions, "gaps": [], "terminal_status": "SUCCEEDED", "count": 7}
        if old and hasattr(request, "param"):
            mount = executions[0]["mounts"][1]
            if request.param == "foreign-root":
                mount["runtime_source"] = mount["runtime_source"].replace("/run/desktop/", "/foreign/desktop/")
            elif request.param == "inconsistent-root":
                mount["runtime_source"] = mount["runtime_source"].replace("b" * 64, "d" * 64)
            elif request.param == "different-suffix":
                mount["runtime_source"] += "/different"
            elif request.param == "traversal":
                mount["runtime_source"] += "/../log"
            else:
                raise AssertionError(request.param)
        elif not old:
            control.change(document, unit.unit_id)
        for execution in executions:
            path = unit.job.run_root / execution["receipt_path"]
            receipt = deepcopy(execution)
            if not old:
                control.receipt_change(receipt)
            atomic_json(path, receipt)
            if unit.unit_id == "acquire.git_history":
                artifacts.append(reference(unit.job.run_root, path))
        document["artifacts"] = artifacts
        return document

    job = replace(job, units=tuple(Unit(name, produce) for name in EXECUTIONS))
    deployment = tmp_path / "deploy/dagster"
    deployment.mkdir(parents=True)
    (deployment / ".env").write_text(f"APPSEC_UID={os.getuid()}\nAPPSEC_GID={os.getgid()}\n")
    for key, value in {
        "ROOT": tmp_path, "CONTAINER_ROOT": str(tmp_path), "STATE_ROOT": tmp_path / "runs/metadata/stepwise",
        "DEPLOYMENT": deployment, "ACCEPTANCE_ROOT": tmp_path / "test/acceptance",
        "SEED_STORE": tmp_path / "data/acceptance-seeds",
    }.items():
        monkeypatch.setattr(stepwise, key, value)
    monkeypatch.setattr(stepwise, "git", lambda *args, **kwargs: "" if args[0] == "status" else "testcommit")
    started = {str(UUID(int=1)): time.time()}
    monkeypatch.setattr(stepwise, "get_run", lambda url, dispatch: {
        "status": "SUCCESS", "startTime": started[dispatch]})
    instance, runner = Instance(), JobRunner(config)
    original = runner.run(job, target_root=target, source_fingerprint="c" * 64,
                          orchestration={"system": "dagster", "run_id": str(UUID(int=1))})
    run_root = config.runtime.runs_dir / original["status"]["run_id"]
    run_id = run_root.name
    instance.runs[str(UUID(int=1))] = SimpleNamespace(
        run_id=str(UUID(int=1)), is_finished=True, tags={"appsec/application_run_id": run_id})
    verify_dispatch_stop(config, run_root, str(UUID(int=1)), instance=instance)
    topology = {"graph": "wave1_review", "jobs": [{"job_id": JOB, "name": JOB, "dependencies": [],
                 "upstream_handoffs": [], "propagate_handoff": True}]}
    state = StepwiseState.create(run_id, target=str(target), topology=topology)
    state.record_launch(JOB, str(UUID(int=1)))
    path = stepwise.STATE_ROOT / run_id / "state.json"
    state.save(path)
    args = SimpleNamespace(app_run=run_id, job=JOB, tag="mount-v1", url="offline", show=3)
    assert stepwise.command_accept(args) == 0

    def repair(version):
        for dispatch in instance.runs:
            if not (run_root / f"data/recovery/dispatches/{dispatch}.json").exists():
                verify_dispatch_stop(config, run_root, dispatch, instance=instance)
        (tmp_path / f"release-src/{JOB}/job.py").write_text(f"VERSION = {version}\n")
        write_release(tmp_path, (JOB,))
        plan = plan_repair(config, run_root, (job,), "c" * 64, target_root=target, dependencies={JOB: []})
        assert plan["admissible"], plan["refusals"]
        admit_repair(config, run_root, (job,), plan, dependencies={JOB: []})
        state = StepwiseState.load(path)
        runtime = rewind.inspect_runtime(config, run_root, topology, list(instance.runs), instance)
        return rewind.apply_rewind(tmp_path, path, stepwise.ACCEPTANCE_ROOT, state, plan, runtime,
                                   stepwise.masks_for(run_id, str(target)))

    assert repair(2)

    def compose(*args):
        assert args[:5] == ("exec", "-T", "code-location", "python", "-c")
        assert args[5] == rewind.RUNTIME_PROBE
        return json.dumps(rewind.inspect_runtime(
            config, run_root, topology, json.loads(args[7]), instance,
            verify_stops=args[8:] == ("verify-stops",)))
    monkeypatch.setattr(stepwise, "compose", compose)

    def rerun(*, audit_window=False):
        if audit_window:
            # The real write audit includes a two-second window before the dispatch start.
            time.sleep(2.01)
        started[str(UUID(int=2))] = time.time()
        state = StepwiseState.load(path)
        state.record_launch(JOB, str(UUID(int=2)))
        state.save(path)
        result = runner.run(job, run_id=run_id, target_root=target, source_fingerprint="c" * 64,
                            orchestration={"system": "dagster", "run_id": str(UUID(int=2))})
        instance.runs[str(UUID(int=2))] = SimpleNamespace(
            run_id=str(UUID(int=2)), is_finished=True, tags={"appsec/application_run_id": run_id})
        return result

    return SimpleNamespace(root=tmp_path, run_root=run_root, path=path, args=args, rerun=rerun,
                           control=control, original=original, repair=repair,
                           masks=stepwise.masks_for(run_id, str(target)))


def test_verified_mount_aliases_preserve_evidence_and_reacceptance(mount_walk):
    walk = mount_walk
    key_root = stepwise.ACCEPTANCE_ROOT / "mount-v1"
    original = {path: path.read_bytes() for path in key_root.rglob("*") if path.is_file()}
    attempt = Path(walk.original["attempt_root"])
    raw = {path: path.read_bytes() for path in attempt.rglob("*.json")}
    walk.rerun(audit_window=True)
    assert stepwise.command_check(walk.args) == 0
    comparison = StepwiseState.load(walk.path).job(JOB)["check"]["replay_comparison"]
    assert comparison["passed"]
    changes = comparison["verified_mount_path_changes"]
    assert len(changes) == 4
    assert sum(len(change["mounts"]) for change in changes) == 15
    assert sum(entry["class"] != "volatile" for entry in comparison["unadjusted_differences"]) >= 13
    for change in changes:
        for side in ("expected", "actual"):
            verify_reference(walk.run_root, change[f"{side}_reference"])
        assert change["expected_signature"] != change["actual_signature"]
    checked_state = walk.path.read_bytes()
    assert stepwise.command_accept(walk.args) == 0
    accepted = StepwiseState.load(walk.path).job(JOB)
    receipt = json.loads(verify_reference(walk.path.parent, accepted["replays"][-1]["acceptance"]).read_bytes())
    assert receipt["comparison"]["verified_mount_path_changes"] == changes
    saved_receipt = verify_reference(walk.path.parent, accepted["replays"][-1]["acceptance"]).read_bytes()
    walk.path.write_bytes(checked_state)  # Retry after a receipt write but before operator state persistence.
    assert stepwise.command_accept(walk.args) == 0
    assert verify_reference(walk.path.parent, accepted["replays"][-1]["acceptance"]).read_bytes() == saved_receipt
    assert all(path.read_bytes() == content for path, content in original.items())
    assert all(path.read_bytes() == content for path, content in raw.items())
    assert walk.repair(3)
    evidence = rewind.read_evidence(walk.path.parent, StepwiseState.load(walk.path).job(JOB)["replays"][-1]["evidence"])
    assert verify_reference(walk.path.parent, evidence["baselines"][JOB]["key"]).read_bytes() == original[key_root / f"{JOB}.json"]


def inputs(walk, result):
    state = StepwiseState.load(walk.path)
    baseline = rewind.read_evidence(walk.path.parent, state.job(JOB)["replays"][-1]["evidence"])["baselines"][JOB]
    expected = json.loads(verify_reference(walk.path.parent, baseline["key"]).read_bytes())
    attempt = Path(result["attempt_root"])
    actual = stepwise.normalize_job_output(walk.run_root, JOB, walk.masks, attempt_root=attempt)
    claim = json.loads((attempt / "claim.json").read_bytes())
    return state, baseline, expected, actual, claim


def compare(walk, result, actual=None):
    state, _, _, document, _ = inputs(walk, result)
    return rewind.replay_comparison(walk.run_root, walk.path.parent, state, state.job(JOB),
                                    Path(result["attempt_root"]), document if actual is None else actual, walk.masks)


@pytest.mark.parametrize("damage", [
    "source", "native-root", "relative-suffix", "target", "read-only", "integer-read-only", "traversal",
    "content", "unrelated-path", "schema", "tool", "missing-mount", "extra-mount", "partial-proof", "receipt-copy",
])
def test_mount_mapping_does_not_hide_nonqualifying_changes(mount_walk, damage):
    walk = mount_walk

    def change(document, unit):
        mount = document["executions"][0]["mounts"][1]
        if damage == "source":
            mount["source"] += "/other"
        elif damage == "native-root":
            mount["runtime_source"] = "/foreign" + mount["runtime_source"]
        elif damage == "relative-suffix":
            mount["runtime_source"] += "/other"
        elif damage == "target":
            mount["target"] = "/other"
        elif damage == "read-only":
            mount["read_only"] = True
        elif damage == "integer-read-only":
            mount["read_only"] = 0
        elif damage == "traversal":
            mount["runtime_source"] += "/../log"
        elif damage == "content":
            document["count"] += 1
        elif damage == "unrelated-path":
            document["diagnostic"] = mount["runtime_source"]
        elif damage == "schema":
            document["executions"][0]["schema"] = "other/1"
        elif damage == "tool":
            document["executions"][0]["tool_id"] = "other"
        elif damage == "missing-mount":
            document["executions"][0]["mounts"].pop()
        elif damage == "extra-mount":
            document["executions"][0]["mounts"].append(deepcopy(mount))
        elif damage == "partial-proof" and unit == "resolve_sources.bind_snapshot":
            mount["runtime_source"] += "/other"

    walk.control.change = change
    if damage == "receipt-copy":
        walk.control.receipt_change = lambda document: document.update(exit_code=1)
    result = walk.rerun()
    _, baseline, expected, actual, claim = inputs(walk, result)
    saved = deepcopy(actual)
    if damage in {"traversal", "receipt-copy"}:
        with pytest.raises(StateError, match="canonical|receipt differs"):
            rewind.verified_mount_path_changes(walk.run_root, walk.path.parent, baseline, JOB,
                                               claim, expected, actual, walk.masks)
    else:
        assert rewind.verified_mount_path_changes(walk.run_root, walk.path.parent, baseline, JOB,
                                                  claim, expected, actual, walk.masks) == []
        comparison = compare(walk, result)
        assert not comparison["passed"] and comparison["verified_mount_path_changes"] == []
    assert actual == saved


@pytest.mark.parametrize("mount_walk", ["foreign-root", "inconsistent-root", "different-suffix", "traversal"], indirect=True)
def test_unknown_original_alias_is_not_inferred_from_path_shape(mount_walk):
    walk = mount_walk
    result = walk.rerun()
    try:
        comparison = compare(walk, result)
    except StateError as error:
        assert "canonical" in str(error)
    else:
        assert not comparison["passed"] and comparison["verified_mount_path_changes"] == []


@pytest.mark.parametrize("side", ["old", "new"])
@pytest.mark.parametrize("damage", ["signature", "raw-hash", "raw-size", "missing-reference", "bytes", "missing-file"])
def test_mount_accounting_requires_original_and_current_raw_pins(mount_walk, side, damage):
    walk = mount_walk
    result = walk.rerun()
    _, baseline, expected, actual, claim = inputs(walk, result)
    candidate = expected if side == "old" else actual
    suffix = "/scratch/executions/log/execution.json"
    signature = next(entry for entry in candidate["artifacts"] if entry["path"].endswith(suffix))
    raw = next(entry for entry in candidate["volatile"]["artifacts"] if entry["path"] == signature["path"])
    if damage == "signature":
        signature["sha256"] = "0" * 64
    elif damage == "raw-hash":
        raw["sha256"] = "0" * 64
    elif damage == "raw-size":
        raw["size_bytes"] += 1
    elif damage == "missing-reference":
        candidate["volatile"]["artifacts"].remove(raw)
    else:
        root = Path(walk.original["attempt_root"] if side == "old" else result["attempt_root"])
        path = root / ("steps/acquire/tasks/git_history" + suffix)
        if damage == "bytes":
            data = path.read_bytes()
            path.write_bytes(data.replace(b'"tool-git"', b'"tool-bad"'))
        else:
            path.unlink()
    if side == "old" and damage not in {"bytes", "missing-file"}:
        # A self-consistent archived key still must resolve to the original publication and bytes.
        baseline = {**baseline, "key": immutable_bytes(
            walk.path.parent, "proof-fixtures/damaged-key.json", canonical_json(expected))}
    saved = deepcopy(actual)
    with pytest.raises(ValueError, match="evidence|reference|signature|digest|integrity"):
        rewind.verified_mount_path_changes(walk.run_root, walk.path.parent, baseline, JOB,
                                           claim, expected, actual, walk.masks)
    assert actual == saved


@pytest.mark.parametrize("field", ["source_fingerprint", "resolved_config_sha256", "target_root",
                                   "repository_root", "repair_admission_sha256"])
def test_mount_proof_cannot_override_claim_or_admission_mismatch(mount_walk, field):
    walk = mount_walk
    result = walk.rerun()
    attempt = Path(result["attempt_root"])
    claim = json.loads((attempt / "claim.json").read_bytes())
    claim[field] = "different"
    atomic_json(attempt / "claim.json", claim)
    with pytest.raises(ValueError, match="claim|admitted repair|signature|unchanged"):
        compare(walk, result)


@pytest.mark.parametrize("damage", ["provenance", "output-copy", "missing-result-pin", "ambiguous-signature",
                                   "stale-dispatch", "superseded-binding"])
def test_mount_proof_requires_complete_current_and_original_evidence(mount_walk, damage):
    walk = mount_walk
    result = walk.rerun()
    state, baseline, expected, actual, claim = inputs(walk, result)
    if damage == "provenance":
        origin = json.loads(verify_reference(walk.path.parent, baseline["provenance"]).read_bytes())
        origin["dagster_run_id"] = str(UUID(int=999))
        baseline = {**baseline, "provenance": immutable_bytes(
            walk.path.parent, "proof-fixtures/foreign-provenance.json", canonical_json(origin))}
    elif damage == "output-copy":
        actual["outputs"]["acquire.git_history"]["executions"][0]["mounts"][0]["runtime_source"] = "/other"
    elif damage == "missing-result-pin":
        actual["volatile"]["artifacts"] = [
            item for item in actual["volatile"]["artifacts"] if not item["path"].endswith("/bind_snapshot/result.json")]
    elif damage == "ambiguous-signature":
        actual["artifacts"].append(deepcopy(next(
            item for item in actual["artifacts"] if item["path"].endswith("/bind_snapshot/result.json"))))
    elif damage == "stale-dispatch":
        state.job(JOB)["dagster_run_ids"][-1] = str(UUID(int=1))
    else:
        assert walk.repair(3)
    saved = deepcopy(actual)
    with pytest.raises(ValueError, match="provenance|copy|reference|signature|fresh dispatch|superseded"):
        if damage in {"stale-dispatch", "superseded-binding"}:
            rewind.replay_comparison(walk.run_root, walk.path.parent, state, state.job(JOB),
                                      Path(result["attempt_root"]), actual, walk.masks)
        else:
            rewind.verified_mount_path_changes(walk.run_root, walk.path.parent, baseline, JOB,
                                               claim, expected, actual, walk.masks)
    assert actual == saved
