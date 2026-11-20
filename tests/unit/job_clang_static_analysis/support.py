"""Shared unit-test fixtures and fake executor for job_clang_static_analysis."""
from __future__ import annotations

import json
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.jobs.cpp_index_scopes import IndexScope
from appsec_review.jobs.job_clang_static_analysis import JOB_ID, TOOL_ID
from appsec_review.jobs.job_clang_static_analysis.job import OUTPUT_SCHEMA
from appsec_review.runtime import UnitContext
from appsec_review.storage import file_sha256


DIGEST = "sha256:" + "c" * 64
SETTINGS = {
    "workers": 2,
    "max_output_bytes": 65536,
    "max_diagnostics_per_scope": 20,
    "clang_tidy_checks": ["bugprone-*", "cert-*"],
    "clang_analyzer_checkers": ["core", "unix", "security", "alpha.security"],
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
                 malformed: str | None = None, too_many: str | None = None,
                 duplicate: str | None = None):
        self.run_root = run_root
        self.fail = fail
        self.malformed = malformed
        self.too_many = too_many
        self.duplicate = duplicate
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
            count = 21 if engine == self.too_many else 2 if engine == self.duplicate else 1
            output.write_text(json.dumps({
                "schema": OUTPUT_SCHEMA, "engine": engine, "truncated": False,
                "units": [{"file": row["file"], "exit_code": 7 if engine == self.fail else 0,
                           "message": "fixture failure" if engine == self.fail else ""}
                          for row in json.loads((scratch / "compile_commands.json").read_text())],
                "diagnostics": [{"rule_id": "bugprone-use-after-move" if action == "tidy" else "core.NullDereference",
                                 "message": "fixture diagnostic", "severity": "warning",
                                 "path": "/target/source/main.cpp", "line": 1, "column": 30,
                                 "notes": [{"message": "path node", "path": "/target/source/main.cpp",
                                            "line": 1, "column": 20}]}
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
