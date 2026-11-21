"""Signal results cross the real subprocess/Git/acquisition adapters; no process is started."""

import json
from pathlib import Path
import subprocess

import pytest

from appsec_review.interchange import validate_unit_output
from appsec_review.jobs.job_target_acquisition.job import TargetAcquisitionFailed
from appsec_review.target_acquisition import git_source, safety
from appsec_review.target_acquisition.safety import AcquisitionError

from .support import ACQUISITION, PUBLICATION, SELECTION, artifact_document, handler, unit_context
from .test_review_evidence import BASE, CURRENT, TREE, _frozen, responses_for


def subprocess_boundary(monkeypatch, *, phase, returncode):
    calls = []

    def run(argv, *, cwd, env, stdin, capture_output, timeout, check):
        assert stdin == subprocess.DEVNULL and capture_output and not check
        assert timeout > 0 and env["GIT_TERMINAL_PROMPT"] == "0"
        command = argv[1]
        calls.append(tuple(argv))
        failed = (
            phase == "base" and command == "cat-file" and argv[-1] == f"{BASE}^{{commit}}"
            or phase == "names" and command == "diff" and "--name-status" in argv
            or phase == "patch" and command == "diff" and "--binary" in argv
        )
        if failed:
            return subprocess.CompletedProcess(argv, returncode, b"unusable partial output", b"fixture result")
        output = b""
        if command == "init":
            (Path(argv[-1]) / ".git").mkdir()
        elif command in ("remote", "fetch", "cat-file"):
            pass
        elif command == "checkout":
            (cwd / "source.txt").write_bytes(b"inert source\n")
        elif command == "rev-parse":
            assert argv[-1] in ("HEAD^{commit}", "HEAD^{tree}")
            output = ((CURRENT if argv[-1] == "HEAD^{commit}" else TREE) + "\n").encode()
        elif command == "--version":
            output = b"git unit subprocess fixture\n"
        elif command == "ls-files":
            output = f"100644 {'e' * 40} 0\tsource.txt\0".encode()
        elif command == "diff":
            output = b"M\0source.txt\0" if "--name-status" in argv else b"fixture patch\n"
        else:
            raise AssertionError(f"unexpected external command: {argv}")
        return subprocess.CompletedProcess(argv, 0, output, b"")

    monkeypatch.setattr(safety.subprocess, "run", run)
    return calls


@pytest.mark.parametrize("phase", ["base", "names", "patch"], ids=["base", "names", "patch"])
@pytest.mark.parametrize("returncode", [-2, -15, -9, 1], ids=["sigint", "sigterm", "sigkill", "ordinary"])
def test_git_adapter_rejects_signals_before_optional_diff_gaps(phase, returncode, tmp_path, monkeypatch):
    calls = subprocess_boundary(monkeypatch, phase=phase, returncode=returncode)
    git = git_source.Git("git", scratch=tmp_path / "scratch", allow_local=False, timeout=5)
    if returncode < 0:
        with pytest.raises(AcquisitionError, match=f"terminated by signal {-returncode}"):
            git_source.change_diff(git, tmp_path, BASE, CURRENT, 1024)
    else:
        patch, changed, gaps = git_source.change_diff(git, tmp_path, BASE, CURRENT, 1024)
        assert patch is None
        assert changed == ([{"status": "M", "score": None, "paths": ["source.txt"]}] if phase == "patch" else None)
        assert [g["reason"] for g in gaps] == [
            "change_base_unavailable" if phase == "base" else "change_diff_failed"]
    assert len(calls) == {"base": 1, "names": 2, "patch": 3}[phase]


@pytest.mark.parametrize("phase", ["base", "names", "patch"], ids=["base", "names", "patch"])
@pytest.mark.parametrize("returncode", [-2, -15, -9, 1], ids=["sigint", "sigterm", "sigkill", "ordinary"])
def test_signal_results_refuse_component_publication_without_global_stop(phase, returncode, tmp_path, monkeypatch):
    frozen = _frozen(tmp_path, "gerrit", responses_for("gerrit"), "bundle")
    subprocess_boundary(monkeypatch, phase=phase, returncode=returncode)
    kwargs = {"environ": {"APPSEC_REVIEW_SYSTEM": "sys"}}
    selection, _ = unit_context(tmp_path, SELECTION, frozen=frozen)
    plan = handler(SELECTION, **kwargs)(selection)
    context, _ = unit_context(tmp_path, ACQUISITION, frozen=frozen, outputs={SELECTION: plan})
    target = tmp_path / "checkouts" / "sys" / "review"
    record_dir = tmp_path / "acquisition-records" / "sys" / "components" / "review"
    if returncode < 0:
        with pytest.raises(TargetAcquisitionFailed, match=f"terminated by signal {-returncode}"):
            handler(ACQUISITION, **kwargs)(context)
        result = json.loads((context.unit_root / "target-acquisition-result.json").read_bytes())
        assert result["status"] == "FAILED" and result["components"]["review"]["status"] == "FAILED"
        assert not target.exists() and not record_dir.exists()
        failure = tmp_path / result["components"]["review"]["failure_record"]
        assert f"terminated by signal {-returncode}" in json.loads(failure.read_bytes())["error"]
        assert not list(context.job.run_root.rglob("target-acquisition-handoff.json"))
    else:
        result = handler(ACQUISITION, **kwargs)(context)
        assert result["status"] == "PARTIAL"
        assert (target / "source.txt").read_bytes() == b"inert source\n"
        assert (record_dir / "manifest.json").is_file()
        assert not (record_dir / "change.diff").exists()
        assert (record_dir / "changed-paths.json").exists() == (phase == "patch")
        validate_unit_output(result, unit_id=ACQUISITION, strict_gaps=True)
        publication, _ = unit_context(tmp_path, PUBLICATION, frozen=frozen, outputs={ACQUISITION: result})
        handoff = handler(PUBLICATION, **kwargs)(publication)
        assert artifact_document(publication, handoff["artifact"])["status"] == "PARTIAL"
