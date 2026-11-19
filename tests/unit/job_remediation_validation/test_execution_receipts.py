"""T-5083: real validation dispatch/custody with inert compiler and admission transports."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from appsec_review.container_runtime import build_executor
from appsec_review.jobs.bound_artifacts import read_bound, read_bound_json
from appsec_review.jobs.job_remediation_validation import build_job
from appsec_review.jobs.job_remediation_validation.compiler import compare_build
from appsec_review.runtime import execution_safety as safety
from tests import remediation_support as support
from tests.unit.job_remediation_validation.test_coverage_edges import _seed_env, _val_ctx


@contextmanager
def _first_error(root: Path, monkeypatch: pytest.MonkeyPatch):
    envelope = safety.policy(str(uuid4()), {
        "source_commit": "a" * 40, "target_commit": "b" * 40,
        "configuration": {"fixture": True},
    })
    guardian = safety.AdmissionGuardian(envelope, root, resolved_config_sha256="c" * 64)
    guardian.root.mkdir(parents=True)

    def request(client, command, **fields):
        response = guardian._dispatch({
            "policy_sha256": client.digest, "command": command, **fields,
        })
        if response.get("ok") is not True:
            raise safety.ReviewStopped(response["reason"])
        return response

    monkeypatch.setattr(safety.SafetyClient, "request", request)
    with safety.safety_scope(envelope):
        yield guardian


def _validation(tmp_path, monkeypatch, *, codes=(0, 0), mutate=None, failure=None):
    env = _seed_env(tmp_path, monkeypatch)
    unit = env.builds.locate("native/src/parse.c").unit
    calls = []

    def runner(argv, timeout):
        argv = tuple(argv)
        calls.append(argv)
        if argv[:3] == ("docker", "image", "inspect"):
            return 0, unit.image_id.encode(), b"", False
        if argv[:2] == ("docker", "inspect"):
            return 0, b'[{"Destination":"/","Source":"/"}]', b"", False
        if argv[:2] == ("docker", "rm"):
            return 0, b"", b"", False
        if argv[:3] == ("docker", "container", "inspect"):
            if failure == "cleanup":
                return 0, b"true", b"", False
            return 1, b"", f"No such container: {argv[3]}".encode(), False
        assert argv[:2] == ("docker", "run"), argv
        number = sum(call[:2] == ("docker", "run") for call in calls)
        workspace = Path(argv[argv.index("--mount") + 1].split("src=")[1].split(",dst=")[0])
        assert argv[argv.index("--entrypoint") + 1] == "/usr/bin/clang"
        assert "-fsyntax-only" in argv and "--no-default-config" in argv
        assert argv[argv.index("--network") + 1] == "none"
        assert not {"sh", "bash", "make", "cmake", "ld", "-o"} & set(argv)
        assert [arg for arg in argv if arg.startswith("type=bind,")] == [
            f"type=bind,src={workspace},dst=/workspace",
        ]
        if failure == "exception":
            raise OSError("compiler transport unavailable")
        if failure == "stop":
            raise safety.ReviewStopped("explicit operator stop")
        if failure == "cancel":
            safety.latch("operator cancelled", action="operator")
        if mutate is not None and number == 1:
            path = workspace / mutate
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"unexpected compiler write\n")
        return codes[number - 1], b"compiler stdout", b"compiler stderr", failure == "timeout"

    monkeypatch.setattr(build_executor, "_run", runner)
    monkeypatch.setattr(build_executor, "default_image_verifier",
                        lambda: SimpleNamespace(verify=lambda *_a, **_kw: None))
    job = build_job(infer=support.Writer(), builds_factory=lambda _r: env.builds)
    context = _val_ctx(env.root, support.validation_settings())
    return env, job, context, calls


@pytest.mark.parametrize("codes,status,reason", [
    ((0, 0), "build_checked", "identical pinned native syntax checks passed before and after; no runtime proof"),
    ((1,), "inconclusive", "baseline_build_failed"),
    ((0, 1), "rejected", "patched_build_failed"),
], ids=["passed", "baseline-rejected", "patch-rejected"])
def test_safety_compiler_comparison_retains_receipts_without_source_changes(
        tmp_path, monkeypatch, codes, status, reason):
    env, job, context, calls = _validation(tmp_path, monkeypatch, codes=codes)
    before = env.src_file.read_bytes()
    with _first_error(env.root / "metadata", monkeypatch) as guardian:
        result = job.execute(context)
        assert not result["failed_units"], result
        safety.check_running()
        assert not guardian.stopped.is_set()
        assert guardian.state["first_error"] is None
        assert guardian.state["active"] == {}
    summary = read_bound_json(env.root, result["outputs"]["acceptance.publish_handoff"]["artifact"])
    row = summary["items"][0]
    assert (row["status"], row["reason"]) == (status, reason)
    validation = read_bound_json(env.root, row["validation"])
    comparison = read_bound_json(env.root, validation["checks"]["build"]["artifact"])
    for phase, code in zip(("baseline", "patched"), codes):
        record = comparison[phase]
        assert record["exit_code"] == code
        references = record["execution_evidence"]
        assert read_bound(env.root, references["stdout"]) == b"compiler stdout"
        assert read_bound(env.root, references["stderr"]) == b"compiler stderr"
        outcome = read_bound_json(env.root, references["outcome"])
        assert outcome["exit_code"] == code and outcome["timed_out"] is False
        assert outcome["cleanup"] == "SUCCEEDED"
        assert all("/compiler-execution/" in ref["path"] and "/scratch/" not in ref["path"]
                   for ref in references.values())
    if len(codes) == 1:
        assert comparison["patched"] is None
    assert validation["assurance"]["runtime_verified"] is False
    assert validation["checks"]["runtime_regression"]["status"] == "not_performed_by_policy"
    assert read_bound_json(env.root, validation["cleanup"])["removed"] is True
    assert env.src_file.read_bytes() == before
    assert sum(call[:2] == ("docker", "run") for call in calls) == len(codes)
    assert len(list(context.attempt_root.rglob("outcome.json"))) == len(codes)
    assert not list(context.attempt_root.rglob("scratch"))


@pytest.mark.parametrize("mutation", [
    "native/src/parse.c", ".appsec-execution/forged/stdout", ".appsec-other/hidden.c",
])
def test_safety_receipt_separation_does_not_exclude_target_owned_paths(tmp_path, monkeypatch, mutation):
    env, job, context, _calls = _validation(tmp_path, monkeypatch, mutate=mutation)
    before = env.src_file.read_bytes()
    with _first_error(env.root / "metadata", monkeypatch):
        result = job.execute(context)
    assert result["failed_units"] == ["assess.validate"]
    traceback = context.attempt_root / "steps" / "assess" / "tasks" / "validate" / "traceback.txt"
    assert "commissioned compiler changed its read-only source workspace" in traceback.read_text()
    assert "acceptance.publish_handoff" not in result["outputs"]
    assert env.src_file.read_bytes() == before
    assert not list(context.attempt_root.rglob("scratch"))


@pytest.mark.parametrize("code,failure,reason", [
    (2, None, "build command failed"),
    (125, None, "build command failed"),
    (126, None, "build command failed"),
    (127, None, "build command failed"),
    (-9, None, "build command failed"),
    (137, None, "build command failed"),
    (1, "timeout", "build command failed"),
    (1, "exception", "compiler transport unavailable"),
    (1, "cleanup", "container removal is unconfirmed"),
    (1, "stop", "explicit operator stop"),
    (1, "cancel", "stopped|build command failed"),
], ids=["abnormal", "docker-error", "cannot-invoke", "missing-tool", "signal", "killed",
        "timeout", "transport", "cleanup", "stop", "cancel"])
def test_comparison_preserves_infrastructure_failures_and_explicit_stops(
        tmp_path, monkeypatch, code, failure, reason):
    env, job, context, calls = _validation(tmp_path, monkeypatch, codes=(code,), failure=failure)
    with _first_error(env.root / "metadata", monkeypatch) as guardian:
        with pytest.raises(safety.ReviewStopped, match=reason):
            job.execute(context)
        if failure != "stop":
            assert guardian.stopped.is_set()
        if failure == "cancel":
            assert guardian.state["first_error"]["reason"] == "operator cancelled"
    assert sum(call[:2] == ("docker", "run") for call in calls) == 1
    assert any(call[:2] == ("docker", "rm") for call in calls)
    assert not list(context.attempt_root.rglob("scratch"))
    assert not list(context.attempt_root.rglob("validation.json"))
    if failure not in {"exception", "stop"}:
        receipts = list(context.attempt_root.rglob("outcome.json"))
        assert len(receipts) == 1 and "compiler-execution" in receipts[0].parts
        assert (receipts[0].parent / "stderr").read_bytes() == b"compiler stderr"


def test_receipts_are_retained_without_first_error_policy(tmp_path, monkeypatch):
    env, job, context, calls = _validation(tmp_path, monkeypatch)
    assert not safety.active()
    result = job.execute(context)
    assert not result["failed_units"], result
    summary = read_bound_json(env.root, result["outputs"]["acceptance.publish_handoff"]["artifact"])
    row = summary["items"][0]
    assert row["status"] == "build_checked"
    validation = read_bound_json(env.root, row["validation"])
    comparison = read_bound_json(env.root, validation["checks"]["build"]["artifact"])
    for phase in ("baseline", "patched"):
        outcome = read_bound_json(env.root, comparison[phase]["execution_evidence"]["outcome"])
        assert outcome["cleanup"] == "SUCCEEDED"
    assert sum(call[:2] == ("docker", "rm") for call in calls) == 2
    assert not list(context.attempt_root.rglob("scratch"))


def test_ordinary_builds_still_stop_on_exit_one(tmp_path, monkeypatch):
    env, _job, _context, calls = _validation(tmp_path, monkeypatch, codes=(1,))
    unit = env.builds.locate("native/src/parse.c").unit
    executor = build_executor.BuildContainerExecutor(
        build_executor.BuildProfile("native", unit.image_tag, unit.image_id, unit.image_user),
        timeout_seconds=5, output_bytes=1024, network="none",
    )
    with _first_error(env.root / "metadata", monkeypatch) as guardian:
        with pytest.raises(safety.ReviewStopped, match="build command failed"):
            executor.execute(
                ("/usr/bin/clang", "-fsyntax-only", "--no-default-config", "/workspace/native/src/parse.c"),
                workspace=env.workspace, working_directory=".", environment={},
            )
        assert guardian.stopped.is_set()
    assert sum(call[:2] == ("docker", "run") for call in calls) == 1
    assert len(list((env.workspace / ".appsec-execution").rglob("outcome.json"))) == 1


@pytest.mark.parametrize("destination", [
    "workspace", "child", "ancestor", "symlink", "install", "instrumentation", "mounted-evidence",
])
def test_execution_receipts_cannot_share_a_container_mount(tmp_path, destination):
    workspace = tmp_path / "workspace"
    install = tmp_path / "install"
    instrumentation = tmp_path / "instrumentation"
    mounted_evidence = tmp_path / "mounted-evidence"
    for path in (workspace, install, instrumentation, mounted_evidence):
        path.mkdir()
    link = tmp_path / "alias"
    link.symlink_to(tmp_path / "unmounted", target_is_directory=True)
    root = {
        "workspace": workspace, "child": workspace / "receipts", "ancestor": tmp_path,
        "symlink": link, "install": install / "receipts",
        "instrumentation": instrumentation / "receipts", "mounted-evidence": mounted_evidence / "receipts",
    }[destination]
    executor = build_executor.BuildContainerExecutor(
        build_executor.BuildProfile("native", "fixture:1", "sha256:" + "a" * 64, "10001:10001"),
        timeout_seconds=5, output_bytes=1024, execution_evidence_root=root,
        runner=lambda *_a: pytest.fail("unsafe receipt destination reached the process boundary"),
        image_verifier=SimpleNamespace(verify=lambda *_a, **_kw: None),
    )
    with pytest.raises(ValueError, match="separate host-owned directory"):
        executor.execute(
            ("/usr/bin/clang", "-fsyntax-only", "/workspace/main.c"),
            workspace=workspace, working_directory=".", environment={}, install_dir=install,
            instrumentation_root=instrumentation, instrumentation_evidence_root=mounted_evidence,
        )


@pytest.mark.parametrize("codes", [
    frozenset({1}), frozenset({0, True}), frozenset({0, -9}),
    frozenset({0, 125}), frozenset({0, 126}), frozenset({0, 127}), frozenset({0, 137}),
], ids=["no-success", "boolean", "signal", "docker-error", "cannot-invoke", "missing-tool", "killed"])
def test_expected_exit_policy_cannot_admit_infrastructure_outcomes(codes):
    with pytest.raises(ValueError, match="expected exits"):
        build_executor.BuildContainerExecutor(
            build_executor.BuildProfile("native", "fixture:1", "sha256:" + "a" * 64, "10001:10001"),
            timeout_seconds=5, output_bytes=1024, expected_exit_codes=codes,
        )


@pytest.mark.parametrize("missing", ["outcome", "stdout", "stderr"])
def test_missing_execution_receipt_is_not_an_unavailable_compiler(tmp_path, monkeypatch, missing):
    env = _seed_env(tmp_path, monkeypatch)
    paths = {name: env.root / name for name in ("outcome", "stdout", "stderr")}
    for path in paths.values():
        path.write_bytes(b"retained compiler evidence")
    paths[missing].unlink()
    outcome = SimpleNamespace(
        exit_code=0, timed_out=False, stdout=b"retained compiler evidence", stderr=b"retained compiler evidence",
        execution_receipt=paths["outcome"], stdout_file=paths["stdout"], stderr_file=paths["stderr"],
    )
    executor = SimpleNamespace(resolve=lambda: None, execute=lambda *_a, **_kw: outcome)
    unit = env.builds.locate("native/src/parse.c").unit
    with pytest.raises(FileNotFoundError):
        compare_build(unit, env.workspace, env.workspace, executor, output_bytes=1024, run_root=env.root)
