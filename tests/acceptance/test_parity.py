from __future__ import annotations

import argparse
import hashlib
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


def _attempt(run_root: Path, serial: int, *, dagster_run_id: str | None, findings: int, root: str = "",
             **identity) -> None:
    """A consistent accepted attempt: claim, status, handoff and latest pointer agree."""
    attempt = run_root / "data" / "jobs" / JOB / "attempts" / f"attempt_{serial:04d}"
    attempt.mkdir(parents=True)
    orchestration = {"system": "dagster", "run_id": dagster_run_id} if dagster_run_id else {"system": "local"}
    handoff = {**IDENTITY, **identity}
    common = {"job_id": JOB, "attempt_id": attempt.name, "run_id": RUN}
    (attempt / "claim.json").write_text(json.dumps({
        **common, "orchestration": orchestration, "target_root": f"{root or '/opt/app/targets/relay/'}",
        "source_fingerprint": handoff["source_fingerprint"], "input_identity": handoff["input_identity"],
        "upstream_handoffs": handoff["upstream_handoff_sha256"]}), encoding="utf-8")
    (attempt / "status.json").write_text(json.dumps({**common, "status": "SUCCEEDED"}), encoding="utf-8")
    (attempt / "result.json").write_text(json.dumps({"outputs": {"catalog.files": {
        "findings": [{"path": f"{root}src/{index}.cpp"} for index in range(findings)], "gaps": []}}}), encoding="utf-8")
    (attempt / "handoff.json").write_text(json.dumps({
        "job_id": JOB, "attempt_id": attempt.name, "status": "ACCEPTED", "completion_status": "SUCCEEDED",
        "artifacts": [], **handoff}), encoding="utf-8")
    digest = hashlib.sha256((attempt / "handoff.json").read_bytes()).hexdigest()
    (attempt.parent.parent / "latest.json").write_text(json.dumps({
        "attempt_id": attempt.name, "handoff_path": (attempt / "handoff.json").relative_to(run_root).as_posix(),
        "handoff_sha256": digest}), encoding="utf-8")


@pytest.fixture
def walk(tmp_path, monkeypatch):
    for name, value in (("ROOT", tmp_path), ("STATE_ROOT", tmp_path / "runs" / "metadata" / "stepwise"),
                        ("PARITY_ROOT", tmp_path / "runs" / "metadata" / "stepwise" / "parity"),
                        ("SEED_STORE", tmp_path / "data" / "acceptance-seeds")):
        monkeypatch.setattr(stepwise, name, value)
    (tmp_path / "data" / "caches").mkdir(parents=True)
    monkeypatch.setattr(stepwise, "_ids", lambda: (1000, 1000))
    monkeypatch.setattr(stepwise, "daemon_sources", lambda: {})
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
        (run_root / "data" / "jobs" / "job_review_intake").mkdir(parents=True)
        (run_root / "data" / "jobs" / "job_review_intake" / "latest.json").write_text(
            json.dumps({"handoff_sha256": "u"}), encoding="utf-8")
        (run_root / "seeded.txt").write_text(after_job, encoding="utf-8")
        state = StepwiseState.create(RUN, target="/opt/app/targets/relay", topology=TOPOLOGY)
        state.mark_seeded(after_job, corpus_tag=tag, handoffs={})
        path = StepwiseState.path_for(stepwise.STATE_ROOT, RUN)
        state.save(path)
        return state, path

    def launch_next(args, state, path):
        state.record_launch(JOB, "dagster-1")
        state.save(path)
        _attempt(tmp_path / "runs" / RUN, 1, dagster_run_id="dagster-1", findings=2,
                 root=getattr(launch_next, "root", "/opt/app/targets/relay/"))
        (tmp_path / "data" / "caches" / "tool-output.json").write_text("{}", encoding="utf-8")
        return 0

    monkeypatch.setattr(stepwise, "seed_run", seed_run)
    monkeypatch.setattr(stepwise, "launch_next", launch_next)
    return tmp_path, seeds


def _args(**overrides) -> argparse.Namespace:
    return argparse.Namespace(**{"tag": "cpp-multivuln-v1", "job": JOB, "target": None, "replace": False,
                                 "restore_shared": False, "allow_shared_drift": False, "url": "u",
                                 "interval_seconds": 1, "show": 10, **overrides})


def _local(tmp_path: Path, findings: int, *, root: str | None = None, **identity):
    def run_local(job_id, app_run_id, target, replay, log):
        run_root = tmp_path / "runs" / app_run_id
        # The local side starts from the seed alone: no Dagster attempt, no Dagster cache entry.
        assert (run_root / "seeded.txt").read_text(encoding="utf-8") == "job_review_intake"
        assert not (run_root / "data" / "jobs" / JOB).exists()
        assert not (tmp_path / "data" / "caches" / "tool-output.json").exists()
        assert target == tmp_path / "targets" / "relay" and replay.is_dir()
        _attempt(run_root, 1, dagster_run_id=None, findings=findings,
                 root=f"{tmp_path}/targets/relay/" if root is None else root, **identity)
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


def test_each_side_must_spell_paths_for_its_own_environment(walk, monkeypatch) -> None:
    tmp_path, _ = walk
    # Dagster recorded the host spelling of the target: correct content, wrong environment.
    monkeypatch.setattr(stepwise.launch_next, "root", f"{tmp_path}/targets/relay/", raising=False)
    monkeypatch.setattr(stepwise, "_run_local", _local(tmp_path, findings=2))

    assert stepwise.command_parity(_args()) == 3
    report = _report(tmp_path)
    assert report["verdict"] == "DIFFERENT"
    assert {item["class"] for item in report["differences"]} >= {"finding-added", "finding-removed"}


def test_dagster_paths_may_use_the_daemon_visible_mount_sources(walk, monkeypatch) -> None:
    tmp_path, _ = walk
    staging = "/run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/Ubuntu-24.04/abc"
    monkeypatch.setattr(stepwise, "daemon_sources", lambda: {"/opt/app/runs": staging,
                                                             "/opt/app/targets": f"{tmp_path}/targets"})
    # A tool mount recorded by Dagster with the daemon's spelling of the target is correct there.
    monkeypatch.setattr(stepwise.launch_next, "root", f"{tmp_path}/targets/relay/", raising=False)
    monkeypatch.setattr(stepwise, "_run_local", _local(tmp_path, findings=2))

    assert stepwise.command_parity(_args()) == 0
    masks = stepwise.side_masks(RUN, "/opt/app/targets/relay", "dagster")
    assert masks.text(f"{staging}/{RUN}/data/x.json") == "<run>/data/x.json"


def test_an_inconsistent_identifier_or_hash_on_either_side_fails(walk, monkeypatch) -> None:
    tmp_path, _ = walk

    def run_local(job_id, app_run_id, target, replay, log):
        _local(tmp_path, findings=2)(job_id, app_run_id, target, replay, log)
        # The local side binds an upstream handoff the run never accepted.
        handoff = tmp_path / "runs" / app_run_id / "data" / "jobs" / JOB / "attempts" / "attempt_0001" / "handoff.json"
        document = json.loads(handoff.read_text(encoding="utf-8"))
        handoff.write_text(json.dumps({**document, "upstream_handoff_sha256": {"job_review_intake": "x"}}),
                           encoding="utf-8")
        return 0

    monkeypatch.setattr(stepwise, "_run_local", run_local)
    assert stepwise.command_parity(_args()) == 3
    paths = {item["path"] for item in _report(tmp_path)["differences"] if item["class"] == "integrity"}
    assert {"local:upstream.job_review_intake", "local:handoff.upstream_handoff_sha256",
            "local:latest.json.handoff_sha256"} <= paths


def test_the_local_command_is_plain_or_runs_under_a_rootless_opt_app_namespace() -> None:
    import importlib.util
    import sys

    bin_dir = Path(__file__).parents[2] / "deploy" / "dagster" / "bin"
    sys.path.insert(0, str(bin_dir))
    spec = importlib.util.spec_from_file_location("stepwise_command", bin_dir / "stepwise.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    root = Path("/home/u/checkout")
    plain = module.local_command("job_x", "2026-10-19-0002", "/home/u/checkout/targets/t", container_paths=False,
                                 root=root)
    assert plain[:3] == ["/home/u/checkout/.venv/bin/python", "-m", "appsec_review"]
    assert plain[plain.index("--target") + 1] == "/home/u/checkout/targets/t"
    assert "unshare" not in plain

    inside = module.local_command("job_x", "2026-10-19-0002", "/opt/app/targets/t", container_paths=True, root=root)
    assert inside[:3] == ["unshare", "-Urm", "sh"]
    assert "mount --bind \"$1\" /opt/app" in inside[4]
    assert inside[6] == str(root) and inside[7] == "/opt/app/.venv/bin/python"
    assert inside[inside.index("--target") + 1] == "/opt/app/targets/t" and inside[-1] == "--upstream-from-run"


def test_recorded_calls_that_never_reached_a_model_are_reported(tmp_path) -> None:
    import json

    recordings = tmp_path / "job_dependency_intelligence"
    recordings.mkdir()
    (recordings / "a.0000.json").write_text(json.dumps({"result": {"proposal": {}}}), encoding="utf-8")
    assert stepwise.unavailable_model_calls(tmp_path) == []

    (recordings / "b.0000.json").write_text(json.dumps({"error": {
        "type": "FileNotFoundError", "message": "configured Claude CLI is unavailable: claude"}}), encoding="utf-8")
    (recordings / "c.0000.json").write_text(json.dumps({"error": {
        "type": "ModelOutputError", "message": "expected exactly one proposal, found 0"}}), encoding="utf-8")
    assert stepwise.unavailable_model_calls(tmp_path) == [
        "job_dependency_intelligence: configured Claude CLI is unavailable: claude"]
