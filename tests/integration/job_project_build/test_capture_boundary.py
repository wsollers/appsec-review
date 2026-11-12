"""One real captured compiler command through the same verifier used by project-build's native lane."""

from __future__ import annotations

import json

import pytest

from appsec_review.container_runtime import CaptureScope, verify_capture_record
from appsec_review.container_runtime.build_capture import CaptureIntegrityError
from appsec_review.jobs.job_language_build.job import _captured_command
from appsec_review.jobs.job_project_build.enforcement import scoped_gaps
from appsec_review.jobs.job_project_build.repair import FailureKind, diagnose_failure

from .support import (
    BUILD_UNIT, assert_declared_files, boundary_run, executor_for, publish_receipt, require_capture_scanner,
)


@pytest.mark.parametrize("scenario", ("success", "compiler-failure", "tampered-output"))
def test_real_capture_is_verified_and_failures_remain_evidence(tmp_path, scenario):
    executor = executor_for("native")
    require_capture_scanner()
    run = boundary_run(tmp_path)
    source = "#error integration_compile_failure\n" if scenario == "compiler-failure" else "int value() { return 7; }\n"
    (run.workspace / "main.cpp").write_text(source, encoding="utf-8")
    capture = run.workspace.parent / "execution-capture/command-001"
    result, verified, identity = _captured_command(
        run.context(), executor, ("clang++", "-c", "main.cpp", "-o", "main.o"),
        workspace=run.workspace, working_directory=".", environment={},
        capture_directory=capture, build_unit_id=BUILD_UNIT, family="native",
    )
    assert not result.timed_out
    assert verified.gaps == () and identity["complete"] is True
    assert identity["secret_scan"]["exit_code"] == 0
    events = [json.loads(line) for line in (capture / "events.jsonl").read_text().splitlines()]
    assert any(row["kind"] == "process_exec" and "-c" in row.get("argv", ()) for row in events)
    if scenario == "tampered-output":
        (capture / "events.jsonl").write_bytes(b"{}\n")
        scope = CaptureScope("2026-01-01-0001", "job_project_build", "attempt_0001", BUILD_UNIT, "native")
        with pytest.raises(CaptureIntegrityError):
            verify_capture_record(verified.record_path, run_root=run.root, scope=scope)
    elif scenario == "compiler-failure":
        assert result.exit_code != 0 and not (run.workspace / "main.o").exists()
        diagnosis = diagnose_failure(exit_code=result.exit_code, stderr=result.stderr.decode())
        assert diagnosis.kind is FailureKind.COMPILER_LINKER and not diagnosis.image_repairable
        gaps = scoped_gaps([f"build command 1 exited {result.exit_code}"], "probe.native", BUILD_UNIT)
        publication, document = publish_receipt(run, {
            "build_unit_id": BUILD_UNIT, "family": "native", "terminal_status": "FAILED",
            "artifacts": [], "gaps": gaps, "commands": [{"execution_capture": identity}],
        })
        assert publication["terminal_status"] == "COMPLETED_WITH_GAPS"
        assert document["gaps"] == gaps
        assert gaps[0]["schema"] == "appsec-review/producer-gap/1"
        assert gaps[0]["scope_id"] == BUILD_UNIT
    else:
        assert result.exit_code == 0 and (run.workspace / "main.o").is_file()
    assert_declared_files(run)
