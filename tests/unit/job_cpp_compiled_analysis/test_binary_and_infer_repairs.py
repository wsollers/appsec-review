"""Focused unit tests for Infer 4g memory limit, strict binary tool receipts, 10k truncation, and CMakeFiles filtering."""
from __future__ import annotations

import json
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.jobs.job_cpp_compiled_analysis import job as cpp_job
from appsec_review.runtime import UnitContext
from appsec_review.storage import file_sha256

DIGEST = "sha256:" + "1" * 64


def _ok_tools(*, nm_truncated: bool = False, nm_exit: int = 0, readelf_exit: int = 0) -> dict[str, object]:
    return {
        "nm": {"exit_code": nm_exit, "timed_out": False, "output_truncated": nm_truncated, "stderr": ""},
        "readelf": {"exit_code": readelf_exit, "timed_out": False, "output_truncated": False, "stderr": ""},
    }


def _binary_unit(tmp_path: Path) -> tuple[Path, UnitContext, Path]:
    run_root = tmp_path / "run"
    unit_root = (
        run_root / "data" / "jobs" / "job_cpp_compiled_analysis" / "attempts" / "attempt_0001"
        / "steps" / "binary" / "tasks" / "projects"
    )
    unit_root.mkdir(parents=True, exist_ok=True)
    job = SimpleNamespace(
        run_root=run_root, repository_root=tmp_path, attempt_id="attempt_0001",
        source_fingerprint="c" * 64, config=SimpleNamespace(job_id="job_cpp_compiled_analysis", settings={}),
    )
    unit = UnitContext(job, "binary.projects", "binary", "projects", unit_root, MappingProxyType({}))
    return run_root, unit, cpp_job._case_root(unit, "case-1")


def test_infer_execution_requests_4g_memory_limit(tmp_path: Path) -> None:
    captured_requests = []

    class RecordingExecutor:
        def execute(self, request):
            captured_requests.append(request)
            raw = request.scratch_root / "raw"
            raw.mkdir(parents=True, exist_ok=True)
            (raw / "stdout.bin").write_bytes(b"")
            (raw / "stderr.bin").write_bytes(b"")
            (request.scratch_root / "execution.json").write_text("{}", encoding="utf-8")
            infer_out = request.scratch_root / "infer-out"
            infer_out.mkdir(parents=True, exist_ok=True)
            (infer_out / "report.json").write_text("[]", encoding="utf-8")
            rel = lambda p: p.relative_to(run_root).as_posix()
            return ExecutionResult(
                "appsec-review/container-execution/1", "tool-infer",
                "appsec-review/tool-infer:1.0.0", DIGEST, DIGEST, "argv", (), {},
                "start", "end", 0, False, False, False, False,
                rel(raw / "stdout.bin"), rel(raw / "stderr.bin"), rel(request.scratch_root / "execution.json"),
                None, False,
            )

    run_root = tmp_path / "run"
    unit_root = (
        run_root / "data" / "jobs" / "job_cpp_compiled_analysis" / "attempts" / "attempt_0001"
        / "steps" / "infer" / "tasks" / "projects"
    )
    unit_root.mkdir(parents=True, exist_ok=True)
    job = SimpleNamespace(
        run_root=run_root, repository_root=tmp_path, attempt_id="attempt_0001",
        source_fingerprint="b" * 64, config=SimpleNamespace(job_id="job_cpp_compiled_analysis", settings={}),
    )
    unit = UnitContext(job, "infer.projects", "infer", "projects", unit_root, MappingProxyType({}))
    case_root = cpp_job._case_root(unit, "case-1")
    (case_root / "source").mkdir(parents=True, exist_ok=True)
    cdb = case_root / "normalized-compile-commands.json"
    cdb.write_text("[]", encoding="utf-8")
    catalog = {
        "compile_database": cpp_job._artifact(run_root, cdb),
        "compile_commands": [{"target_path": "src/main.cpp", "arguments": ["clang++", "-c", "/scratch/source/src/main.cpp"]}],
        "mapping": {"project_id": "cpp:root", "root": ".", "case_snapshot": "b" * 64},
    }
    cpp_job._run_infer(unit, "case-1", catalog, lambda _u: RecordingExecutor())
    assert len(captured_requests) == 1
    assert captured_requests[0].memory == "4g"


def test_binary_index_rejects_missing_or_failed_tool_receipts_fail_closed(tmp_path: Path) -> None:
    run_root, unit, case_root = _binary_unit(tmp_path)
    build_dir = case_root / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    obj_a = build_dir / "missing_tools.o"
    obj_b = build_dir / "failed_nm.o"
    obj_a.write_bytes(b"\x7fELFa")
    obj_b.write_bytes(b"\x7fELFb")

    records_path = case_root / "analysis" / "binary" / "records.json"
    records_path.parent.mkdir(parents=True, exist_ok=True)
    records_path.write_text(json.dumps([
        {
            "path": "build/missing_tools.o",
            "sha256": file_sha256(obj_a),
            "kind": "object",
            "symbols": ["0000000000000000 T alpha"],
            "metadata": "ELF Header:\n",
        },
        {
            "path": "build/failed_nm.o",
            "sha256": file_sha256(obj_b),
            "kind": "object",
            "symbols": ["0000000000000000 T beta"],
            "metadata": "ELF Header:\n",
            "tools": _ok_tools(nm_exit=1),
        },
    ]), encoding="utf-8")
    catalog = {
        "mapping": {"project_id": "cpp:root", "case_snapshot": "c" * 64},
        "artifact_catalog": cpp_job._artifact(run_root, obj_a),
        "outputs": [
            {"path": "build/missing_tools.o", "sha256": file_sha256(obj_a), "kind": "object"},
            {"path": "build/failed_nm.o", "sha256": file_sha256(obj_b), "kind": "object"},
        ],
    }
    execution = {
        "execution": cpp_job._artifact(run_root, records_path),
        "image_id": "sha256:" + "d" * 64,
        "exit_code": 0,
    }
    result = cpp_job._binary_index(unit, "case-1", catalog, execution)
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert result["symbol_count"] == 0
    assert any("tool receipts unavailable" in gap for gap in result["gaps"])
    assert any("nm failed with exit 1" in gap for gap in result["gaps"])


def test_binary_index_emits_truncation_gap_at_exact_10000_symbols(tmp_path: Path) -> None:
    run_root, unit, case_root = _binary_unit(tmp_path)
    build_dir = case_root / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    obj = build_dir / "huge.o"
    obj.write_bytes(b"\x7fELFhuge")

    records_path = case_root / "analysis" / "binary" / "records.json"
    records_path.parent.mkdir(parents=True, exist_ok=True)
    records_path.write_text(json.dumps([{
        "path": "build/huge.o",
        "sha256": file_sha256(obj),
        "kind": "object",
        "symbols": [f"0000000000000000 T sym_{i}" for i in range(10000)],
        "metadata": "ELF Header:\n",
        "tools": _ok_tools(),
    }]), encoding="utf-8")
    catalog = {
        "mapping": {"project_id": "cpp:root", "case_snapshot": "c" * 64},
        "artifact_catalog": cpp_job._artifact(run_root, obj),
        "outputs": [{"path": "build/huge.o", "sha256": file_sha256(obj), "kind": "object"}],
    }
    execution = {
        "execution": cpp_job._artifact(run_root, records_path),
        "image_id": "sha256:" + "d" * 64,
        "exit_code": 0,
    }
    result = cpp_job._binary_index(unit, "case-1", catalog, execution)
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert result["symbol_count"] == 10000
    assert any("symbols truncated at 10000" in gap for gap in result["gaps"])


def test_binary_index_filters_cmakefiles_bookkeeping_before_4096_cap(tmp_path: Path) -> None:
    run_root, unit, case_root = _binary_unit(tmp_path)
    build_dir = case_root / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    real_so = build_dir / "libtarget.so"
    real_so.write_bytes(b"\x7fELFso")

    probe_entries = [
        {
            "path": f"build/CMakeFiles/3.28.3/CompilerIdC/probe_{i}.o",
            "sha256": "e" * 64,
            "kind": "object",
            "symbols": [],
            "metadata": "ELF Header:\n",
            "tools": _ok_tools(),
        }
        for i in range(4105)
    ]
    records_path = case_root / "analysis" / "binary" / "records.json"
    records_path.parent.mkdir(parents=True, exist_ok=True)
    records_path.write_text(json.dumps([
        *probe_entries,
        {
            "path": "build/libtarget.so",
            "sha256": file_sha256(real_so),
            "kind": "shared_library",
            "symbols": ["0000000000000010 T exported_api"],
            "metadata": "ELF Header:\n",
            "tools": _ok_tools(),
        },
    ]), encoding="utf-8")
    catalog = {
        "mapping": {"project_id": "cpp:root", "case_snapshot": "c" * 64},
        "artifact_catalog": cpp_job._artifact(run_root, real_so),
        "outputs": [{"path": "build/libtarget.so", "sha256": file_sha256(real_so), "kind": "shared_library"}],
    }
    execution = {
        "execution": cpp_job._artifact(run_root, records_path),
        "image_id": "sha256:" + "d" * 64,
        "exit_code": 0,
    }
    result = cpp_job._binary_index(unit, "case-1", catalog, execution)
    assert result["terminal_status"] == "SUCCEEDED"
    assert result["gaps"] == []
    assert result["symbol_count"] == 1
