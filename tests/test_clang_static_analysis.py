from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
from types import MappingProxyType, SimpleNamespace

from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.jobs.cpp_index_scopes import IndexScope
from appsec_review.jobs.engineering_contracts import CLANG_STATIC_HANDOFF_SCHEMA
from appsec_review.jobs.job_clang_static_analysis import JOB_ID, TOOL_ID, build_job
from appsec_review.jobs.job_clang_static_analysis.job import (
    ENGINES, OUTPUT_SCHEMA, _analyze_scope, _read_output,
)
from appsec_review.runtime import UnitContext
from appsec_review.storage import file_sha256


DIGEST = "sha256:" + "c" * 64
SETTINGS = {
    "workers": 2,
    "max_output_bytes": 65536,
    "max_diagnostics_per_scope": 20,
    "clang_tidy_checks": ["bugprone-*", "cert-*"],
    "clang_analyzer_checkers": ["core", "unix", "security", "alpha.security.*"],
}


def _scope(tmp_path: Path) -> IndexScope:
    run_root = tmp_path / "run"
    case_root = run_root / "data" / "cpp" / "projects" / "case-a"
    source = case_root / "source" / "main.cpp"
    source.parent.mkdir(parents=True)
    source.write_text("int main() { int *p = 0; return *p; }\n", encoding="utf-8")
    compile_db = case_root / "build" / "normalized-compile-commands.json"
    compile_db.parent.mkdir()
    compile_db.write_text("[]", encoding="utf-8")
    source_sha = file_sha256(source)
    accepted = {"target_path": "native/main.cpp", "scratch_path": "source/main.cpp",
                "sha256": source_sha}
    return IndexScope(
        scope_id="cpp-scope-a", case_id="case-a", project_id="cpp:native", root="native",
        case_snapshot="a" * 64, case_root=case_root, files=(accepted,),
        compile_commands=({"target_path": "native/main.cpp",
                           "arguments": ["clang++-18", "/scratch/source/main.cpp"]},),
        compile_database={"path": compile_db.relative_to(run_root).as_posix(),
                          "sha256": file_sha256(compile_db), "size_bytes": compile_db.stat().st_size},
        _by_relative={"main.cpp": accepted},
    )


def _unit(tmp_path: Path) -> UnitContext:
    run_root = tmp_path / "run"
    attempt = run_root / "data" / "jobs" / JOB_ID / "attempts" / "attempt_0001"
    unit_root = attempt / "steps" / "analyze" / "tasks" / "scopes"
    unit_root.mkdir(parents=True, exist_ok=True)
    job = SimpleNamespace(
        run_root=run_root, repository_root=tmp_path, target_root=tmp_path / "target",
        source_fingerprint="f" * 64, config=SimpleNamespace(settings=SETTINGS),
        attempt_id="attempt_0001",
    )
    return UnitContext(job, "analyze.scopes", "analyze", "scopes", unit_root,
                       MappingProxyType({}))


class FakeExecutor:
    def __init__(self, run_root: Path, *, fail: str | None = None,
                 malformed: str | None = None, too_many: str | None = None):
        self.run_root = run_root
        self.fail = fail
        self.malformed = malformed
        self.too_many = too_many
        self.calls: list[str] = []

    def execute(self, request):
        action = request.argv[1]
        engine = "clang-tidy" if action == "tidy" else "clang-static-analyzer"
        self.calls.append(engine)
        scratch = request.scratch_root
        raw = scratch / "raw"
        raw.mkdir(parents=True, exist_ok=True)
        (raw / "stdout.bin").write_bytes(b"")
        (raw / "stderr.bin").write_bytes(b"")
        receipt = scratch / "execution.json"
        receipt.write_text("{}", encoding="utf-8")
        output = scratch / f"{action}.json"
        if engine == self.malformed:
            output.write_text("{", encoding="utf-8")
        else:
            count = 21 if engine == self.too_many else 1
            output.write_text(json.dumps({
                "schema": OUTPUT_SCHEMA, "engine": engine, "truncated": False,
                "diagnostics": [{"rule_id": "bugprone-use-after-move" if action == "tidy" else "core.NullDereference",
                                 "message": "fixture diagnostic", "severity": "warning",
                                 "path": "/target/source/main.cpp", "line": 1, "column": 30,
                                 "notes": [{"message": "path node", "line": 1, "column": 20}]}
                                for _ in range(count)],
            }), encoding="utf-8")
        relative = lambda path: path.relative_to(self.run_root).as_posix()
        exit_code = 7 if engine == self.fail else 0
        return ExecutionResult(
            "appsec-review/container-execution/1", TOOL_ID,
            "appsec-review/tool-clang-static-analysis:1.0.0", DIGEST, DIGEST, "argv", (), {},
            "start", "end", exit_code, False, False, False, False,
            relative(raw / "stdout.bin"), relative(raw / "stderr.bin"), relative(receipt),
            request.file_size_limit_bytes, False,
        )


def test_positive_scope_runs_both_engines_and_publishes_observations(tmp_path: Path) -> None:
    scope, unit = _scope(tmp_path), _unit(tmp_path)
    executor = FakeExecutor(unit.job.run_root)
    result = _analyze_scope(unit, scope, lambda _unit: executor)
    assert executor.calls == list(ENGINES)
    assert result["terminal_status"] == "SUCCEEDED"
    assert result["observation_count"] == 2
    assert result["gaps"] == []
    shard = unit.job.run_root / result["index_identity"]["relative_path"]
    assert shard.is_file() and file_sha256(shard) == result["index_identity"]["sha256"]
    with sqlite3.connect(shard) as database:
        entities = {row[0] for row in database.execute("SELECT identity FROM entities")}
        relations = database.execute("SELECT source_id, target_id FROM relations").fetchall()
    assert relations
    assert all(source in entities and target in entities for source, target in relations)


def test_no_applicable_target_is_not_clean_coverage(monkeypatch, tmp_path: Path) -> None:
    import appsec_review.jobs.job_clang_static_analysis.job as module
    monkeypatch.setattr(module, "accepted_cpp_scopes", lambda _root: ({}, [], {}))
    job = build_job(executor_factory=lambda _unit: None)
    handler = next(unit.handler for unit in job.units if unit.unit_id == "analyze.scopes")
    context = _unit(tmp_path)
    context = UnitContext(context.job, context.unit_id, context.step_id, context.task_id,
                          context.unit_root, MappingProxyType({"load.accepted_cpp": {"scopes": []}}))
    result = handler(context)
    assert result["terminal_status"] == "NOT_APPLICABLE"
    assert result["scope_count"] == 0


def test_missing_compile_context_is_an_explicit_gap(monkeypatch, tmp_path: Path) -> None:
    import appsec_review.jobs.job_clang_static_analysis.job as module
    monkeypatch.setattr(module, "accepted_cpp_scopes",
                        lambda _root: ({}, [], {"case-a": "accepted C++ project has no compile commands"}))
    job = build_job(executor_factory=lambda _unit: None)
    handler = next(unit.handler for unit in job.units if unit.unit_id == "analyze.scopes")
    context = _unit(tmp_path)
    context = UnitContext(context.job, context.unit_id, context.step_id, context.task_id,
                          context.unit_root, MappingProxyType({"load.accepted_cpp": {"scopes": []}}))
    result = handler(context)
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert result["gaps"] == ["case-a: accepted C++ project has no compile commands"]


def test_one_analyzer_failure_is_a_scope_gap_without_erasing_other_results(tmp_path: Path) -> None:
    scope, unit = _scope(tmp_path), _unit(tmp_path)
    executor = FakeExecutor(unit.job.run_root, fail="clang-static-analyzer")
    result = _analyze_scope(unit, scope, lambda _unit: executor)
    assert result["observation_count"] == 1
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert "clang-static-analyzer exited with status 7" in result["gaps"]


def test_malformed_and_unbounded_outputs_are_gaps(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    records, gaps = _read_output(malformed, engine="clang-tidy", max_bytes=1024,
                                 max_diagnostics=20)
    assert records == [] and gaps == ["clang-tidy result was malformed JSON"]

    unbounded = tmp_path / "unbounded.json"
    unbounded.write_text(json.dumps({"schema": OUTPUT_SCHEMA, "engine": "clang-tidy",
                                     "truncated": False, "diagnostics": [{}] * 21}), encoding="utf-8")
    records, gaps = _read_output(unbounded, engine="clang-tidy", max_bytes=65536,
                                 max_diagnostics=20)
    assert records == [] and "exceeded the 20-diagnostic bound" in gaps[0]


def test_handoff_schema_and_summary_artifact_are_immutable(monkeypatch, tmp_path: Path) -> None:
    import appsec_review.jobs.job_clang_static_analysis.job as module
    manifest = tmp_path / "run" / "manifest.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text("{}", encoding="utf-8")
    identity = {"path": "manifest.json", "sha256": file_sha256(manifest),
                "size_bytes": manifest.stat().st_size}
    monkeypatch.setattr(module, "publish_scope_indexes", lambda *_args, **_kwargs: identity)
    job = build_job(executor_factory=lambda _unit: None)
    handler = next(unit.handler for unit in job.units if unit.unit_id == "acceptance.publish_handoff")
    context = _unit(tmp_path)
    outputs = {
        "load.accepted_cpp": {"upstream": {"handoff_sha256": "a" * 64}, "unavailable": {}},
        "analyze.scopes": {"scopes": [], "gaps": [], "terminal_status": "NOT_APPLICABLE"},
    }
    context = UnitContext(context.job, "acceptance.publish_handoff", "acceptance", "publish_handoff",
                          context.unit_root, MappingProxyType(outputs))
    result = handler(context)
    assert job.schema_identity == CLANG_STATIC_HANDOFF_SCHEMA
    assert result["schema"] == CLANG_STATIC_HANDOFF_SCHEMA
    summary = context.job.run_root / result["artifact"]["path"]
    assert file_sha256(summary) == result["artifact"]["sha256"]
    assert json.loads(summary.read_text(encoding="utf-8"))["schema"] == CLANG_STATIC_HANDOFF_SCHEMA
