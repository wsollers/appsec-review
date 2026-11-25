"""Focused unit tests for Wave-2/Wave-3 C++ and evidence collection pipeline repairs."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from types import MappingProxyType, SimpleNamespace

from appsec_review.config.seeding import SeededSettings
from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.jobs.cpp_index_scopes import IndexScope
from appsec_review.jobs.job_clang_static_analysis import JOB_ID as CSA_JOB_ID, TOOL_ID as CSA_TOOL_ID, seeded as csa_seeded
from appsec_review.jobs.job_clang_static_analysis.job import OUTPUT_SCHEMA, _analyze_scope
from appsec_review.jobs.job_cpp_compiled_analysis import job as cpp_job
from appsec_review.jobs.job_evidence_collection.job import _build_producer_shard
from appsec_review.jobs.job_post_build_security_assessment.job import _compact_inference_request
from appsec_review.runtime import UnitContext
from appsec_review.seeding.ledger import ScopeSeeds, Seed, SeedPlan, SeedSource
from appsec_review.storage import canonical_json, file_sha256

from tests.unit.job_clang_static_analysis.support import DIGEST, SETTINGS, _scope
from tests.unit.job_evidence_collection.support import make_unit_context


def test_gitleaks_producer_shard_uses_normalized_artifact_when_raw_path_is_redacted(tmp_path: Path) -> None:
    norm_rel = "data/jobs/job_evidence_collection/attempts/attempt_0001/steps/secrets/tasks/gitleaks_scan/evidence.json"
    unit, _, _ = make_unit_context(
        tmp_path,
        unit_id="secrets.gitleaks_index",
        outputs={},
    )
    run_sh_sha = file_sha256(unit.job.target_root / "run.sh")
    evidence_doc = {
        "tool_id": "tool-gitleaks",
        "records": [{
            "evidence_id": "e" * 64,
            "native_rule_id": "generic-api-key",
            "message": "secret detected",
            "severity": "HIGH",
            "location": {
                "path": "run.sh",
                "source_sha256": run_sh_sha,
                "start_line": 1,
                "end_line": 1,
            },
        }],
    }
    norm_path = unit.job.run_root / norm_rel
    norm_path.parent.mkdir(parents=True, exist_ok=True)
    norm_path.write_bytes(canonical_json(evidence_doc))
    norm_sha = file_sha256(norm_path)

    normalize_out = {
        "terminal_status": "SUCCEEDED",
        "tool_id": "tool-gitleaks",
        "artifact": {"path": norm_rel, "sha256": norm_sha, "size_bytes": norm_path.stat().st_size},
        "normalized_artifact": {"path": norm_rel, "sha256": norm_sha, "size_bytes": norm_path.stat().st_size},
        "not_applicable_inputs": [],
        "gaps": [],
    }
    unit_with_out = UnitContext(
        unit.job, unit.unit_id, unit.step_id, unit.task_id, unit.unit_root,
        MappingProxyType({"secrets.gitleaks_normalize": normalize_out}),
    )
    shard_out = _build_producer_shard(unit_with_out, "secrets.gitleaks_normalize")
    shard_file = unit.job.run_root / shard_out["index_identity"]["relative_path"]
    with sqlite3.connect(shard_file) as db:
        row = db.execute("SELECT payload_json FROM entities WHERE kind = 'evidence_artifact'").fetchone()
    assert row is not None
    payload = json.loads(row[0])
    assert payload["artifact"]["path"] == norm_rel
    assert payload["artifact"]["path"] != "<redacted>"


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
    unit_root = run_root / "data" / "jobs" / "job_cpp_compiled_analysis" / "attempts" / "attempt_0001" / "steps" / "infer" / "tasks" / "projects"
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


def test_cpp_binary_index_accepts_v1_records_without_tool_receipts_and_skips_cmake_probes(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    unit_root = run_root / "data" / "jobs" / "job_cpp_compiled_analysis" / "attempts" / "attempt_0001" / "steps" / "binary" / "tasks" / "projects"
    unit_root.mkdir(parents=True, exist_ok=True)
    job = SimpleNamespace(
        run_root=run_root, repository_root=tmp_path, attempt_id="attempt_0001",
        source_fingerprint="c" * 64, config=SimpleNamespace(job_id="job_cpp_compiled_analysis", settings={}),
    )
    unit = UnitContext(job, "binary.projects", "binary", "projects", unit_root, MappingProxyType({}))
    case_root = cpp_job._case_root(unit, "case-1")
    build_dir = case_root / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    real_obj = build_dir / "main.o"
    real_obj.write_bytes(b"\x7fELFreal")
    cmake_probe = build_dir / "CMakeFiles" / "3.28.3" / "CompilerIdCXX" / "a.out"
    cmake_probe.parent.mkdir(parents=True, exist_ok=True)
    cmake_probe.write_bytes(b"\x7fELFprobe")

    records_path = case_root / "analysis" / "binary" / "records.json"
    records_path.parent.mkdir(parents=True, exist_ok=True)
    records_path.write_text(json.dumps([
        {
            "path": "build/main.o",
            "sha256": file_sha256(real_obj),
            "kind": "object",
            "symbols": ["0000000000000000 T main"],
            "metadata": "ELF Header:\n  Class: ELF64\n",
        },
        {
            "path": "build/CMakeFiles/3.28.3/CompilerIdCXX/a.out",
            "sha256": file_sha256(cmake_probe),
            "kind": "executable",
            "symbols": [],
            "metadata": "ELF Header:\n",
        },
    ]), encoding="utf-8")

    catalog = {
        "mapping": {"project_id": "cpp:root", "case_snapshot": "c" * 64},
        "artifact_catalog": cpp_job._artifact(run_root, real_obj),
        "outputs": [{"path": "build/main.o", "sha256": file_sha256(real_obj), "kind": "object"}],
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


def test_clang_static_reconciles_v1_units_without_compile_unit_id_and_rejects_ambiguous_variants(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    run_root = tmp_path / "run"
    unit_root = run_root / "data" / "jobs" / CSA_JOB_ID / "attempts" / "attempt_0001" / "steps" / "analyze" / "tasks" / "scopes"
    unit_root.mkdir(parents=True, exist_ok=True)
    job = SimpleNamespace(
        run_root=run_root, repository_root=tmp_path, target_root=tmp_path / "target",
        source_fingerprint="f" * 64, config=SimpleNamespace(job_id=CSA_JOB_ID, settings=SETTINGS),
        attempt_id="attempt_0001",
    )
    unit = UnitContext(job, "analyze.scopes", "analyze", "scopes", unit_root, MappingProxyType({}))

    class LegacyV1Executor:
        def execute(self, request):
            action = request.argv[1]
            engine = "clang-tidy" if action == "tidy" else "clang-static-analyzer"
            scratch = request.scratch_root
            raw = scratch / "raw"
            raw.mkdir(parents=True, exist_ok=True)
            (raw / "stdout.bin").write_bytes(b"")
            (raw / "stderr.bin").write_bytes(b"")
            (scratch / "execution.json").write_text("{}", encoding="utf-8")
            rows = json.loads((scratch / "compile_commands.json").read_text())
            (scratch / f"{action}.json").write_text(json.dumps({
                "schema": OUTPUT_SCHEMA, "engine": engine, "truncated": False,
                "units": [{"file": r["file"], "exit_code": 0, "message": ""} for r in rows],
                "diagnostics": [{
                    "rule_id": "core.NullDereference",
                    "message": "Dereference of null pointer",
                    "severity": "warning",
                    "path": "/target/source/main.cpp",
                    "line": 1, "column": 30, "notes": [],
                }],
            }), encoding="utf-8")
            rel = lambda p: p.relative_to(run_root).as_posix()
            return ExecutionResult(
                "appsec-review/container-execution/1", CSA_TOOL_ID,
                "appsec-review/tool-clang-static-analysis:1.0.0", DIGEST, DIGEST, "argv", (), {},
                "start", "end", 0, False, False, False, False,
                rel(raw / "stdout.bin"), rel(raw / "stderr.bin"), rel(scratch / "execution.json"),
                request.file_size_limit_bytes, False,
            )

    seed = Seed("main.cpp", 1, 1, (SeedSource("semgrep", "null-deref", "high", "id1", "upstream_observation"),), 1)
    scope_seeds = ScopeSeeds("case-a", (seed,), 1, 0)
    plan = SeedPlan({"case-a": scope_seeds}, 0, 0)
    hood = csa_seeded.Neighborhood(
        ranges={"fn:main": ("main.cpp", 1, 1)},
        depth={"fn:main": 0},
        seed_functions={("main.cpp", 1, 1): ("fn:main",)},
        compile_units={"fn:main": "cu-1"},
    )
    seeded_settings = SeededSettings(mode="seeded", depth=2, seed_limit=200, unit_limit=200, include_scan_files=10)
    run = csa_seeded.Run(seeded_settings, plan, scope_seeds, hood)

    result = _analyze_scope(unit, scope, lambda _u: LegacyV1Executor(), run)
    assert result["gaps"] == []
    assert result["seeded"]["resolved_seed_count"] == 1
    assert result["diagnostic_labels"] == {"at_seed": 2}

    # Same-file multi-variant scopes without compile_unit_id remain fail-closed incomplete
    variant_scope = IndexScope(
        scope_id="cpp-scope-variants", case_id="case-a", project_id="cpp:native", root="native",
        case_snapshot="a" * 64, case_root=scope.case_root, files=scope.files,
        compile_commands=(
            {"target_path": "native/main.cpp", "arguments": ["clang++-18", "-DA", "/scratch/source/main.cpp"]},
            {"target_path": "native/main.cpp", "arguments": ["clang++-18", "-DB", "/scratch/source/main.cpp"]},
        ),
        compile_database=scope.compile_database,
        _by_relative=scope._by_relative,
    )
    ambiguous = _analyze_scope(unit, variant_scope, lambda _u: LegacyV1Executor())
    assert any("incomplete compile-unit outcomes" in g for g in ambiguous["gaps"])


def test_post_build_compact_inference_request_fits_token_safe_budget_and_keeps_failures() -> None:
    big_symbols = [f"_Z6symbol_{i:04d}v" for i in range(600)]
    request = {
        "project_id": "root",
        "build_system": "cmake",
        "actions": [
            {
                "build_action_id": f"act-{i:03d}",
                "classification": "compile" if i < 32 else "unknown",
                "toolchain": {"executable": "/usr/bin/clang++", "extra_blob": "x" * 2000},
                "argv": ["clang++", "-O2", "-g", f"src/file_{i}.cpp"],
                "discovered_inputs": [f"/usr/include/header_{j}.h" for j in range(150)],
                "outputs": [f"build/file_{i}.o"],
                "compile_unit_id": f"cu-{i:03d}",
            }
            for i in range(60)
        ],
        "artifacts": [
            {
                "artifact_id": f"art-{i:03d}",
                "sha256": f"{i:064x}",
                "format": "ELF",
                "kind": "executable" if i < 2 else "object",
                "architecture": "x86_64",
                "bits": 64,
                "debug": {"has_dwarf": True},
                "hardening": {"pie": i == 0, "nx": True, "relro": "full"},
                "symbols": big_symbols,
                "exports": big_symbols,
                "imports": big_symbols,
                "sections": [f".text.{j}" for j in range(200)],
                "gaps": [],
            }
            for i in range(40)
        ],
        "deterministic_results": [
            {
                "check_id": "HARDENING_PIE" if i < 5 else "HARDENING_NX",
                "scope": f"art-{i % 40:03d}",
                "status": "FAIL" if i < 5 else ("NOT_APPLICABLE" if i % 3 == 0 else "PASS"),
                "evidence": [f"evidence-{i}"],
                "verbose_blob": "y" * 500,
            }
            for i in range(700)
        ],
        "coverage_gaps": [f"gap-{i}" for i in range(80)],
    }
    raw = canonical_json(request)
    assert len(raw) > 500_000

    compacted, encoded = _compact_inference_request(request, 32_000 * 4)
    assert len(encoded) <= 40_000
    fail_checks = [c for c in compacted["deterministic_results"] if c["status"] == "FAIL"]
    assert len(fail_checks) == 5
    assert all("symbols" not in art and "sections" not in art for art in compacted["artifacts"])
    assert all(act["classification"] != "unknown" for act in compacted["actions"])
