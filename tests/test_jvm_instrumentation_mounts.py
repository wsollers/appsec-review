from pathlib import Path

import pytest

from appsec_review.container_runtime.build_executor import BuildContainerExecutor, BuildProfile
from appsec_review.runtime.scope import review_scope, supplied_run_path
from appsec_review.storage.atomic import file_sha256


def _executor(tmp_path, monkeypatch, *, fail=False):
    workspace, supplied, evidence = (tmp_path / name for name in ("workspace", "instrumentation", "evidence"))
    for path in (workspace, supplied, evidence):
        path.mkdir()
    (supplied / "wrapper").write_text("supplied executable\n")
    calls = []

    def runner(command, timeout):
        calls.append(command)
        (evidence / "record.json").write_text("{}")
        (evidence / "record.json").chmod(0o666)
        if fail:
            raise RuntimeError("fixture worker failure")
        return 0, b"", b"", False

    executor = BuildContainerExecutor(
        BuildProfile("java", "fixture:java", "sha256:" + "a" * 64, "10001:10001"),
        timeout_seconds=10, output_bytes=1024, runner=runner)
    monkeypatch.setattr(executor, "_bind_source", lambda path: path)
    return executor, workspace, supplied, evidence, calls


@pytest.mark.parametrize("fail", [False, True])
def test_separate_readonly_instrumentation_and_writable_evidence_mounts(tmp_path, monkeypatch, fail):
    executor, workspace, supplied, evidence, calls = _executor(tmp_path, monkeypatch, fail=fail)
    arguments = dict(workspace=workspace, working_directory=".", environment={},
                     instrumentation_root=supplied, instrumentation_evidence_root=evidence)
    if fail:
        with pytest.raises(RuntimeError, match="fixture worker"):
            executor.execute(("javac", "-version"), **arguments)
    else:
        assert executor.execute(("javac", "-version"), **arguments).exit_code == 0
    assert len(calls) == 1
    command = calls[0]
    assert f"type=bind,src={supplied},dst=/appsec-jvm,readonly" in command
    assert f"type=bind,src={evidence},dst=/appsec-jvm-evidence" in command
    assert not (evidence / "record.json").stat().st_mode & 0o022
    assert not workspace.stat().st_mode & 0o022
    assert (supplied / "wrapper").read_text() == "supplied executable\n"


@pytest.mark.parametrize("bad", ["missing-pair", "overlapping-workspace", "overlapping-evidence", "symlink"])
def test_instrumentation_mounts_reject_unpaired_or_overlapping_roots(tmp_path, monkeypatch, bad):
    executor, workspace, supplied, evidence, calls = _executor(tmp_path, monkeypatch)
    if bad == "missing-pair":
        evidence = None
    elif bad == "overlapping-workspace":
        supplied = workspace
    elif bad == "overlapping-evidence":
        evidence = supplied
    else:
        alias = tmp_path / "alias"
        alias.symlink_to(supplied, target_is_directory=True)
        supplied = alias
    with pytest.raises(ValueError, match="roots"):
        executor.execute(("javac", "-version"), workspace=workspace, working_directory=".", environment={},
                         instrumentation_root=supplied, instrumentation_evidence_root=evidence)
    assert calls == []


def test_only_reserved_jvm_payload_paths_are_excluded(tmp_path):
    repository, run, target = (tmp_path / name for name in ("repository", "run", "target"))
    relative = "data/build/jvm/units/unit-one/instrumentation/wrapper.py"
    transient = "data/build/jvm/units/unit-one/instrumentation-evidence/jdk/mirror/bin/java"
    record = "data/build/jvm/units/unit-one/instrumentation-evidence/invocations.d/one.json"
    for path in (run / relative, run / transient, run / record, target / relative):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"fixture")
    assert supplied_run_path(relative) and supplied_run_path(transient)
    assert not supplied_run_path(record)
    with review_scope(repository, run, target):
        for path in (run / relative, run / transient):
            with pytest.raises(ValueError, match="platform payload hashing"):
                file_sha256(path)
        assert file_sha256(run / record)
        assert file_sha256(target / relative)
