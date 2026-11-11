"""Closed CI Checkov mount proof using real publication, normalization and repair helpers."""

from copy import deepcopy
from dataclasses import replace
import json
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from appsec_review.acceptance.state import StateError, StepwiseState
from appsec_review.jobs.job_ci_configuration_analysis.job import _normalize, _write
from appsec_review.runtime import JobRunner, Unit
from appsec_review.runtime.repair import admit_repair, plan_repair, verify_dispatch_stop
from appsec_review.storage import canonical_json
from appsec_review.storage.shared import immutable_bytes, verify_reference
from tests.release_support import write_release
from tests.test_repair_admission import fixture
from tests.test_stepwise_rewind import Instance, rewind, stepwise

JOB = "job_ci_configuration_analysis"
PROVIDERS = ("azure", "bitbucket", "gitlab")
DESKTOP = "/run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/Test-Distro"
IMAGE = "sha256:" + "d" * 64


@pytest.fixture
def ci_walk(tmp_path, monkeypatch, request):
    config, (job,), _ = fixture(tmp_path, (JOB,))
    target = tmp_path / "targets/fixture"
    target.mkdir(parents=True)
    control = SimpleNamespace(raw=lambda document, provider: None, result=lambda document, unit: None)
    providers = (*PROVIDERS, "github") if getattr(request, "param", None) == "github" else PROVIDERS

    def scan(unit):
        provider = unit.task_id.split("_")[0]
        scratch = unit.unit_root / "scratch/file_0001"
        runtime = str(scratch) if unit.job.attempt_id == "attempt_0001" else (
            f"{DESKTOP}/{'b' * 64}/{scratch.relative_to(tmp_path / 'runs')}")
        execution = {
            "schema": "appsec-review/container-execution/1", "tool_id": "tool-checkov",
            "receipt_path": (scratch / "execution.json").relative_to(unit.job.run_root).as_posix(),
            "image_id": IMAGE, "image_digest": IMAGE, "image_tag": "checkov:fixture",
            "argv_identity": "e" * 64, "environment_sha256": {}, "exit_code": 0, "timed_out": False,
            "mounts": [{"source": str(target), "target": "/target", "read_only": True,
                        "runtime_source": f"{DESKTOP}/{'a' * 64}/fixture"},
                       {"source": str(scratch), "target": "/scratch", "read_only": False,
                        "runtime_source": runtime}],
        }
        raw = {
            "schema": "appsec-review/ci-raw-observations/1", "provider": provider,
            "tool_id": "tool-checkov", "tool_name": "checkov", "framework": f"{provider}_ci",
            "definitions": [{"path": f"{provider}.yml", "sha256": "f" * 64, "size_bytes": 17}],
            "records": [{"provider": provider, "tool_id": "tool-checkov", "path": f"{provider}.yml",
                         "native_rule_id": "rule", "message": "finding", "severity": "medium"}],
            "gaps": [], "executions": [execution], "image_id": IMAGE, "ruleset_identity": None,
            "not_applicable_inputs": {"count": 0, "items": []}, "terminal_status": "SUCCEEDED",
        }
        if unit.job.attempt_id != "attempt_0001":
            control.raw(raw, provider)
        document = {"provider": provider, "tool_id": "tool-checkov", "terminal_status": raw["terminal_status"],
                    "raw_artifact": _write(unit, "raw-observations.json", raw), "record_count": len(raw["records"]),
                    "gaps": raw["gaps"], "executions": deepcopy(raw["executions"]),
                    "not_applicable_inputs": raw["not_applicable_inputs"]}
        if unit.job.attempt_id != "attempt_0001":
            control.result(document, unit.unit_id)
        return document

    def normalize(unit):
        provider = unit.task_id.split("_")[0]
        document = dict(_normalize(unit, f"ci_analysis.{provider}_checkov_scan"))
        if unit.job.attempt_id != "attempt_0001":
            control.result(document, unit.unit_id)
        return document

    job = replace(job, units=tuple(
        Unit(f"ci_analysis.{provider}_checkov_scan", scan) for provider in providers) + tuple(
        Unit(f"ci_normalization.{provider}_checkov_normalize", normalize,
             dependencies=(f"ci_analysis.{provider}_checkov_scan",)) for provider in providers))
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
    monkeypatch.setattr(stepwise, "get_run", lambda *args: {"status": "SUCCESS"})
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
    args = SimpleNamespace(app_run=run_id, job=JOB, tag="ci-mount-v1", url="offline", show=3)
    assert stepwise.command_accept(args) == 0
    (tmp_path / f"release-src/{JOB}/job.py").write_text("VERSION = 2\n")
    write_release(tmp_path, (JOB,))
    plan = plan_repair(config, run_root, (job,), "c" * 64, target_root=target, dependencies={JOB: []})
    assert plan["admissible"], plan["refusals"]
    admit_repair(config, run_root, (job,), plan, dependencies={JOB: []})
    state = StepwiseState.load(path)
    masks = stepwise.masks_for(run_id, str(target))
    runtime = rewind.inspect_runtime(config, run_root, topology, list(instance.runs), instance)
    assert rewind.apply_rewind(tmp_path, path, stepwise.ACCEPTANCE_ROOT, state, plan, runtime, masks)

    def compose(*args):
        assert args[:5] == ("exec", "-T", "code-location", "python", "-c")
        assert args[5] == rewind.RUNTIME_PROBE
        return json.dumps(rewind.inspect_runtime(config, run_root, topology, json.loads(args[7]), instance,
                                                verify_stops=args[8:] == ("verify-stops",)))
    monkeypatch.setattr(stepwise, "compose", compose)

    def rerun():
        state = StepwiseState.load(path)
        state.record_launch(JOB, str(UUID(int=2)))
        state.save(path)
        result = runner.run(job, run_id=run_id, target_root=target, source_fingerprint="c" * 64,
                            orchestration={"system": "dagster", "run_id": str(UUID(int=2))})
        instance.runs[str(UUID(int=2))] = SimpleNamespace(
            run_id=str(UUID(int=2)), is_finished=True, tags={"appsec/application_run_id": run_id})
        return result

    return SimpleNamespace(root=tmp_path, run_root=run_root, path=path, args=args, rerun=rerun,
                           control=control, original=original, masks=masks)


def test_ci_aliases_preserve_nine_artifacts_and_reacceptance(ci_walk):
    walk = ci_walk
    original = {path: path.read_bytes() for path in (stepwise.ACCEPTANCE_ROOT / "ci-mount-v1").rglob("*")
                if path.is_file()}
    raw = {path: path.read_bytes() for path in Path(walk.original["attempt_root"]).rglob("*.json")}
    walk.rerun()
    assert stepwise.command_check(walk.args) == 0
    comparison = StepwiseState.load(walk.path).job(JOB)["check"]["replay_comparison"]
    assert comparison["passed"]
    changes = comparison["verified_mount_path_changes"]
    assert len(changes) == 9
    assert sum(entry["path"].endswith(".runtime_source")
               for entry in comparison["unadjusted_differences"]) == 6
    assert len({change["artifact"] for change in changes}) == 9
    assert sum(len(change["mounts"]) for change in changes) == 18
    for change in changes:
        for side in ("expected", "actual"):
            verify_reference(walk.run_root, change[f"{side}_reference"])
        assert change["expected_signature"] != change["actual_signature"]
    checked = walk.path.read_bytes()
    assert stepwise.command_accept(walk.args) == 0
    item = StepwiseState.load(walk.path).job(JOB)
    receipt = verify_reference(walk.path.parent, item["replays"][-1]["acceptance"])
    saved = receipt.read_bytes()
    assert json.loads(saved)["comparison"]["verified_mount_path_changes"] == changes
    walk.path.write_bytes(checked)
    assert stepwise.command_accept(walk.args) == 0
    assert receipt.read_bytes() == saved
    assert all(path.read_bytes() == data for path, data in original.items())
    assert all(path.read_bytes() == data for path, data in raw.items())


def inputs(walk, result):
    state = StepwiseState.load(walk.path)
    baseline = rewind.read_evidence(walk.path.parent, state.job(JOB)["replays"][-1]["evidence"])["baselines"][JOB]
    expected = json.loads(verify_reference(walk.path.parent, baseline["key"]).read_bytes())
    attempt = Path(result["attempt_root"])
    actual = stepwise.normalize_job_output(walk.run_root, JOB, walk.masks, attempt_root=attempt)
    return baseline, expected, actual, json.loads((attempt / "claim.json").read_bytes())


def compare(walk, result):
    state = StepwiseState.load(walk.path)
    _, _, actual, _ = inputs(walk, result)
    return rewind.replay_comparison(walk.run_root, walk.path.parent, state, state.job(JOB),
                                    Path(result["attempt_root"]), actual, walk.masks)


@pytest.mark.parametrize("damage", [
    "source", "target", "read-only", "suffix", "traversal", "foreign-root", "inconsistent-root",
    "tool", "image", "image-tag", "raw-image", "argv", "definitions", "definition-hash", "definition-size",
    "records", "status", "gaps", "unrelated-path", "execution-count", "mount-count", "partial-proof",
])
def test_ci_proof_rejects_non_mount_or_unproved_changes(ci_walk, damage):
    walk = ci_walk

    def change(raw, provider):
        execution = raw["executions"][0]
        mount = execution["mounts"][1]
        if damage == "source":
            mount["source"] += "/other"
        elif damage == "target":
            mount["target"] = "/other"
        elif damage == "read-only":
            mount["read_only"] = True
        elif damage == "suffix":
            mount["runtime_source"] += "/other"
        elif damage == "traversal":
            mount["runtime_source"] += "/../file_0001"
        elif damage == "foreign-root":
            mount["runtime_source"] = mount["runtime_source"].replace("/run/desktop/", "/foreign/")
        elif damage == "inconsistent-root" and provider == "gitlab":
            mount["runtime_source"] = mount["runtime_source"].replace("b" * 64, "c" * 64)
        elif damage == "tool":
            execution["tool_id"] = "other"
        elif damage == "image":
            execution["image_id"] = "sha256:" + "f" * 64
        elif damage == "image-tag":
            execution["image_tag"] = "other:version"
        elif damage == "raw-image":
            raw["image_id"] = "sha256:" + "f" * 64
        elif damage == "argv":
            execution["argv_identity"] = "f" * 64
        elif damage == "definitions":
            raw["definitions"][0]["path"] = "other.yml"
        elif damage == "definition-hash":
            raw["definitions"][0]["sha256"] = "e" * 64
        elif damage == "definition-size":
            raw["definitions"][0]["size_bytes"] += 1
        elif damage == "records":
            raw["records"][0]["message"] = "different finding"
        elif damage == "status":
            raw["terminal_status"] = "PARTIAL"
        elif damage == "gaps":
            raw["gaps"] = ["different coverage"]
        elif damage == "unrelated-path":
            raw["diagnostic"] = mount["runtime_source"]
        elif damage == "execution-count":
            raw["executions"].append(deepcopy(execution))
        elif damage == "mount-count":
            execution["mounts"].append(deepcopy(mount))
        elif damage == "partial-proof" and provider == "gitlab":
            mount["source"] += "/other"

    walk.control.raw = change
    result = walk.rerun()
    baseline, expected, actual, claim = inputs(walk, result)
    saved = deepcopy(actual)
    if damage == "traversal":
        with pytest.raises(StateError, match="canonical"):
            rewind.verified_mount_path_changes(walk.run_root, walk.path.parent, baseline, JOB,
                                               claim, expected, actual, walk.masks)
    else:
        assert rewind.verified_mount_path_changes(walk.run_root, walk.path.parent, baseline, JOB,
                                                  claim, expected, actual, walk.masks) == []
        assert not compare(walk, result)["passed"]
    assert actual == saved


@pytest.mark.parametrize("step", ["ci_analysis", "ci_normalization"])
def test_ci_proof_rejects_conflicting_execution_copies(ci_walk, step):
    walk = ci_walk

    def change(document, unit):
        if unit.startswith(step + "."):
            document["executions"][0]["exit_code"] = 1
    walk.control.result = change
    result = walk.rerun()
    with pytest.raises(StateError, match="copy or raw reference"):
        compare(walk, result)


@pytest.mark.parametrize("side", ["old", "new"])
@pytest.mark.parametrize("part", ["scan", "normalize", "raw"])
@pytest.mark.parametrize("damage", ["signature", "bytes", "missing-pin"])
def test_ci_proof_verifies_all_artifact_roles_on_both_sides(ci_walk, side, part, damage):
    walk = ci_walk
    result = walk.rerun()
    baseline, expected, actual, claim = inputs(walk, result)
    candidate = expected if side == "old" else actual
    suffix = {"scan": "/steps/ci_analysis/tasks/azure_checkov_scan/result.json",
              "normalize": "/steps/ci_normalization/tasks/azure_checkov_normalize/result.json",
              "raw": "/artifacts/ci/5e0cb2437852/raw-observations.json"}[part]
    signature = next(entry for entry in candidate["artifacts"] if entry["path"].endswith(suffix))
    if damage == "signature":
        signature["sha256"] = "0" * 64
    elif damage == "missing-pin":
        candidate["volatile"]["artifacts"] = [
            entry for entry in candidate["volatile"]["artifacts"] if entry["path"] != signature["path"]]
    else:
        attempt = Path(walk.original["attempt_root"] if side == "old" else result["attempt_root"])
        path = attempt / suffix.lstrip("/")
        path.write_bytes(path.read_bytes() + b" ")
    if side == "old" and damage != "bytes":
        baseline = {**baseline, "key": immutable_bytes(
            walk.path.parent, "proof-fixtures/invalid-key.json", canonical_json(expected))}
    saved = deepcopy(actual)
    with pytest.raises(ValueError, match="signature|reference|integrity|digest"):
        rewind.verified_mount_path_changes(walk.run_root, walk.path.parent, baseline, JOB,
                                           claim, expected, actual, walk.masks)
    assert actual == saved


@pytest.mark.parametrize("ci_walk", ["github"], indirect=True)
def test_other_checkov_branch_is_not_accounted(ci_walk):
    result = ci_walk.rerun()
    comparison = compare(ci_walk, result)
    assert not comparison["passed"]
    assert len(comparison["verified_mount_path_changes"]) == 9
    assert any("github_checkov" in entry["path"] and entry["class"] != "volatile"
               for entry in comparison["differences"])
