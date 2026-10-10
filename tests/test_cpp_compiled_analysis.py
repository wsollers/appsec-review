from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.jobs.cataloging import inventory, source_fingerprint
from appsec_review.jobs.job_cpp_compiled_analysis import PROJECT_TASKS, build_job
from appsec_review.jobs.job_cpp_compiled_analysis.job import (
    _infer_compile_database,
    _load_ast_document,
    _project_key,
    normalize_compile_db,
    normalize_link_commands,
)
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner, plan_jobs


ROOT = Path(__file__).parents[1]
DIGEST = "sha256:" + "b" * 64


def _project(target: Path, relative: str, *, library: bool) -> str:
    root = target / Path(*PurePosixPath(relative).parts)
    root.mkdir(parents=True)
    (root / "main.cpp").write_text(
        "extern int helper(); int main() { return helper(); }\n" if library else
        "int main() { return 0; }\n", encoding="utf-8")
    if library:
        (root / "helper.cpp").write_text("int helper() { return 0; }\n", encoding="utf-8")
        body = (
            "add_library(helper STATIC helper.cpp)\n"
            "add_executable(observer main.cpp)\n"
            "target_link_libraries(observer PRIVATE helper)\n"
        )
    else:
        body = "add_executable(observer main.cpp)\n"
    (root / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.20)\nproject(sample LANGUAGES CXX)\n" + body,
        encoding="utf-8")
    return _project_key(PurePosixPath(relative))


def _target(root: Path) -> tuple[Path, tuple[str, str]]:
    target = root / "target"
    first = _project(target, "projects/native/alpha", library=True)
    second = _project(target, "projects/examples/beta", library=False)
    return target, (first, second)


class FakeNativeExecutor:
    def __init__(self, run_root: Path, calls: list[tuple[str, str]], fail: tuple[str, str] | None = None):
        self.run_root = run_root
        self.calls = calls
        self.fail = fail

    def execute(self, request):
        root = request.scratch_root
        root.mkdir(parents=True, exist_ok=True)
        infer = request.tool_id == "tool-infer"
        mode = "infer" if infer else request.argv[1]
        project_root = request.target_root if infer else root
        # Tools run as uid 10001; the inputs the job writes for them must be readable by others.
        tool_input = (root / "compile_commands.json" if infer else
                      root / "normalized-compile-commands.json" if mode in {"ast", "ir"} else None)
        if tool_input is not None:
            assert tool_input.stat().st_mode & 0o004, f"{tool_input.name} is unreadable by the tool user"
        project = project_root.name
        self.calls.append((project, mode))
        exit_code = 9 if self.fail == (project, mode) else 0
        sources = sorted(path.name for path in (project_root / "source").glob("*.cpp"))
        if mode == "compile" and exit_code == 0:
            build = root / "build"
            build.mkdir(exist_ok=True)
            (build / "compile_commands.json").write_text(json.dumps([{
                "directory": "/scratch/source", "file": f"/scratch/source/{source}",
                "arguments": ["clang++-18", "-std=c++20", "-c", f"/scratch/source/{source}",
                              "-o", f"/scratch/build/{Path(source).stem}.o"],
            } for source in sources]), encoding="utf-8")
            for source in sources:
                (build / f"{Path(source).stem}.o").write_bytes(b"object:" + source.encode())
            links = [{"output_path": "build/observer", "input_paths": ["build/main.o"]}]
            if "helper.cpp" in sources:
                (build / "libhelper.a").write_bytes(b"archive")
                links = [
                    {"output_path": "build/libhelper.a", "input_paths": ["build/helper.o"]},
                    {"output_path": "build/observer",
                     "input_paths": ["build/main.o", "build/libhelper.a"]},
                ]
            (build / "link-commands.json").write_text(json.dumps(links), encoding="utf-8")
            (build / "observer").write_bytes(b"\x7fELFfixture")
        if mode == "ast" and exit_code == 0:
            destination = root / "analysis" / "ast"
            destination.mkdir(parents=True, exist_ok=True)
            for index, source in enumerate(sources):
                node = {"id": f"0x{index + 1}", "kind": "FunctionDecl", "name": Path(source).stem,
                        "loc": {"line": 1, "col": 1}, "type": {"qualType": "int ()"}}
                (destination / f"tu-{index:04d}.json").write_text(json.dumps({
                    "kind": "TranslationUnitDecl", "inner": [node, node]
                }), encoding="utf-8")
        if mode == "ir" and exit_code == 0:
            destination = root / "analysis" / "ir"
            destination.mkdir(parents=True, exist_ok=True)
            for index, source in enumerate(sources):
                if source == "main.cpp" and "helper.cpp" in sources:
                    text = "define i32 @main() {\nentry:\n  %1 = call i32 @helper()\n  ret i32 %1\n}\n"
                else:
                    text = f"define i32 @{Path(source).stem}() {{\nentry:\n  ret i32 0\n}}\n"
                (destination / f"tu-{index:04d}.ll").write_text(text, encoding="utf-8")
        if mode == "symbols" and exit_code == 0:
            destination = root / "analysis" / "binary"
            destination.mkdir(parents=True, exist_ok=True)
            (destination / "records.json").write_text(json.dumps([{
                "path": "build/observer", "kind": "executable", "sha256": "f" * 64,
                "symbols": ["main T 0 1"], "metadata": "ELF64 NX PIE",
            }]), encoding="utf-8")
        if mode == "infer" and exit_code == 0:
            destination = root / "infer-out"
            destination.mkdir(parents=True, exist_ok=True)
            (destination / "report.json").write_text(json.dumps([{
                "bug_type": "NULLPTR_DEREFERENCE", "qualifier": "fixture null dereference",
                "severity": "ERROR", "category": "Null pointer dereference", "line": 1,
                "column": 1, "procedure": "main", "file": "/target/source/main.cpp",
                "key": f"{project}:main:NULLPTR_DEREFERENCE", "bug_trace": [],
            }]), encoding="utf-8")
            (destination / "logs").write_text(
                f"Found {len(sources)} source file{'s' if len(sources) != 1 else ''} to analyze\n",
                encoding="utf-8")
        raw = root / "raw"
        raw.mkdir(exist_ok=True)
        stdout, stderr, receipt = raw / "stdout.bin", raw / "stderr.bin", root / "execution.json"
        stdout.write_bytes(b"")
        stderr.write_bytes(b"fixture failure" if exit_code else b"")
        receipt.write_text("{}", encoding="utf-8")
        relative = lambda path: path.relative_to(self.run_root).as_posix()
        return ExecutionResult("appsec-review/container-execution/1", request.tool_id,
            "appsec-review/tool-infer:1.3.0" if infer else "appsec-review/tool-native-cpp:1.0.0",
            DIGEST, DIGEST, "argv", (), {}, "start", "end",
            exit_code, False, False, False, False, relative(stdout), relative(stderr), relative(receipt))


def _fixture(tmp_path: Path):
    shutil.copy2(ROOT / "appsec-review.toml", tmp_path / "appsec-review.toml")
    target, keys = _target(tmp_path)
    return load_config(tmp_path / "appsec-review.toml"), target, keys


def test_compile_database_normalization_preserves_only_reviewed_build_semantics(tmp_path: Path) -> None:
    root = tmp_path / "project"
    (root / "build").mkdir(parents=True)
    (root / "source").mkdir()
    (root / "source" / "main.cpp").write_text("int main(){}\n", encoding="utf-8")
    (root / "build" / "compile_commands.json").write_text(json.dumps([{
        "directory": str(root / "build"), "file": str(root / "source" / "main.cpp"),
        "command": f"c++ -DVALUE=1 -I{root / 'source'} -std=c++20 -c {root / 'source' / 'main.cpp'} -o x.o",
    }, {
        "directory": str(root / "build"), "file": str(root / "source" / "main.cpp"),
        "arguments": ["clang++-18", "-cc1", "-emit-obj", str(root / "source" / "main.cpp")],
    }]), encoding="utf-8")
    source_sha = hashlib.sha256((root / "source" / "main.cpp").read_bytes()).hexdigest()
    rows = normalize_compile_db(root, {"project_key": "project-a", "project_id": "cpp:projects/native/a",
        "case_snapshot": "a" * 64, "root": "projects/native/a", "files": [{
            "target_path": "projects/native/a/main.cpp", "scratch_path": "source/main.cpp",
            "sha256": source_sha,
        }]})
    assert rows[0]["target_path"] == "projects/native/a/main.cpp"
    assert rows[0]["project_key"] == "project-a"
    assert rows[0]["arguments"][0] == "clang++-18"
    assert "-DVALUE=1" in rows[0]["arguments"] and "-std=c++20" in rows[0]["arguments"]
    assert "-c" not in rows[0]["arguments"] and "-o" not in rows[0]["arguments"]
    assert rows[0]["output_path"] == "build/x.o"
    assert len(rows) == 1


def test_infer_compile_database_uses_stable_read_only_container_paths() -> None:
    value = _infer_compile_database({
        "mapping": {"root": "projects/native/a"},
        "compile_commands": [{
            "target_path": "projects/native/a/main.cpp",
            "arguments": ["clang++-18", "-I/scratch/source/include", "-std=c++20",
                          "/scratch/source/main.cpp"],
        }],
    })
    assert value == [{
        "directory": "/target/source",
        "file": "/target/source/main.cpp",
        "arguments": ["clang++", "-I/target/source/include", "-std=c++20",
                      "/target/source/main.cpp"],
    }]


def test_clang_ast_loader_accepts_bounded_concatenated_declarations(tmp_path: Path) -> None:
    path = tmp_path / "ast.json"
    path.write_text('{"kind":"FunctionDecl","name":"first"}\n'
                    '{"kind":"FunctionDecl","name":"second"}\n', encoding="utf-8")
    document = _load_ast_document(path)
    assert document["kind"] == "TranslationUnitDecl"
    assert [item["name"] for item in document["inner"]] == ["first", "second"]


def test_snapshot_identity_covers_catalog_excluded_bytes(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "vendor").mkdir(parents=True)
    (target / "main.cpp").write_text("int main() {}\n", encoding="utf-8")
    vendored = target / "vendor" / "dependency.cpp"
    vendored.write_text("int dependency() { return 1; }\n", encoding="utf-8")
    before = inventory(target)
    assert not any(item["path"].startswith("vendor/") for item in before["files"])
    first = source_fingerprint(target)
    vendored.write_text("int dependency() { return 2; }\n", encoding="utf-8")
    assert first != source_fingerprint(target)


def test_native_link_receipts_include_versioned_archiver_without_self_links(tmp_path: Path) -> None:
    source = ROOT / "containers" / "tools" / "native-cpp" / "native.py"
    spec = importlib.util.spec_from_file_location("native_cpp_driver", source)
    assert spec and spec.loader
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    build = tmp_path / "build"
    links = build / "CMakeFiles" / "core.dir"
    links.mkdir(parents=True)
    (links / "link.txt").write_text(
        "/usr/bin/llvm-ar-18 qc libcore.a CMakeFiles/core.dir/unit.o\n", encoding="utf-8")
    driver.ROOT = tmp_path
    driver.BUILD = build
    driver.emit_link_commands()
    receipts = json.loads((build / "link-commands.json").read_text(encoding="utf-8"))
    assert receipts[0]["output_path"] == "build/libcore.a"
    assert receipts[0]["input_paths"] == ["build/CMakeFiles/core.dir/unit.o"]

    (links / "link.txt").write_text(
        "clang++ -shared -Wl,-soname,libcore.so CMakeFiles/core.dir/unit.o -o libcore.so\n",
        encoding="utf-8")
    driver.emit_link_commands()
    receipts = json.loads((build / "link-commands.json").read_text(encoding="utf-8"))
    assert receipts[0]["output_path"] == "build/libcore.so"
    assert receipts[0]["input_paths"] == ["build/CMakeFiles/core.dir/unit.o"]


def test_link_normalization_keeps_only_cataloged_artifact_edges() -> None:
    outputs = [
        {"path": "build/unit.o", "kind": "object"},
        {"path": "build/libcore.so", "kind": "library"},
    ]
    assert normalize_link_commands([{
        "output_path": "build/libcore.so",
        "input_paths": ["build/-Wl,-soname,libcore.so", "build/unit.o", "build/unit.o"],
        "receipt": "CMakeFiles/core.dir/link.txt",
        "command_sha256": "a" * 64,
    }], outputs) == [{
        "output_path": "build/libcore.so",
        "input_paths": ["build/unit.o"],
        "receipt": "CMakeFiles/core.dir/link.txt",
        "command_sha256": "a" * 64,
    }]

def test_cpp_job_graph_is_project_batched_and_repository_independent(tmp_path: Path) -> None:
    config, _, _ = _fixture(tmp_path)
    job = build_job(executor_factory=lambda unit: None)
    plan = plan_jobs((job,), config)
    assert PROJECT_TASKS == ("projects",)
    assert len(job.units) == 9
    assert plan.node("job_cpp_compiled_analysis.ast.projects").dependencies == (
        "job_cpp_compiled_analysis.catalog.projects",)
    assert plan.node("job_cpp_compiled_analysis.ir.projects").dependencies == (
        "job_cpp_compiled_analysis.catalog.projects",)
    assert plan.node("job_cpp_compiled_analysis.infer.projects").dependencies == (
        "job_cpp_compiled_analysis.catalog.projects",)
    final = plan.node("job_cpp_compiled_analysis.acceptance.publish_handoff")
    assert len(final.dependencies) == 5
    assert not any("case001" in node.node_id for node in plan.nodes)
    assert not any(node.node_id.endswith(("configure.projects", "compile.projects")) for node in plan.nodes)


def test_cpp_job_discovers_projects_and_indexes_cross_tu_library_topology(tmp_path: Path) -> None:
    config, target, keys = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_plan()]).run(
        target_root=target, source_fingerprint=fingerprint)
    with pytest.raises(RuntimeError, match="plan.accepted_cpp_plan"):
        GraphRunner(config, [build_job(executor_factory=lambda unit: None)]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    traceback_path = (config.runtime.runs_dir / upstream["run_id"] / "data" / "jobs" /
        "job_cpp_compiled_analysis" / "attempts" / "attempt_0001" / "steps" / "plan" /
        "tasks" / "accepted_cpp_plan" / "traceback.txt")
    assert "accepted job_language_build handoff is required" in traceback_path.read_text(encoding="utf-8")


def test_infer_failure_is_a_project_scoped_gap(tmp_path: Path) -> None:
    source = (ROOT / "src" / "appsec_review" / "jobs" / "job_cpp_compiled_analysis" / "job.py").read_text()
    assert "load_accepted_language_build" in source
    assert "load_accepted_plan(unit.job.run_root)" not in source


def test_project_failure_is_scoped_and_retry_reuses_other_checkpoints(tmp_path: Path) -> None:
    config, _, _ = _fixture(tmp_path)
    job = build_job(executor_factory=lambda unit: None)
    assert {unit.unit_id for unit in job.units}.isdisjoint({"configure.projects", "compile.projects"})
    assert config.job("job_cpp_compiled_analysis").steps.keys().isdisjoint({"configure", "compile"})
