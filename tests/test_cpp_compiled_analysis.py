from __future__ import annotations

import json
import hashlib
import importlib.util
from pathlib import Path
import shutil
import sqlite3

from appsec_review.config import load_config
from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.jobs.cataloging import inventory, source_fingerprint
from appsec_review.jobs.job_cpp_compiled_analysis import CASE_IDS, build_job
from appsec_review.jobs.job_cpp_compiled_analysis.job import _load_ast_document, normalize_compile_db
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner, plan_jobs


ROOT = Path(__file__).parents[1]
DIGEST = "sha256:" + "b" * 64


def _target(root: Path) -> Path:
    target = root / "target"
    systems = {
        "case-001": "cmake", "case-002": "cmake", "case-003": "cmake",
        "case-026": "cmake", "case-027": "cmake", "case-028": "cmake",
        "case-029": "cmake", "case-030": "cmake", "case-036": "make",
        "case-037": "autotools", "case-038": "msbuild", "case-045": "cmake", "case-063": "cmake",
    }
    for name, system in systems.items():
        case = target / "projects" / "cpp" / name
        case.mkdir(parents=True)
        (case / "main.cpp").write_text(
            "extern int hello(); int main() { return hello(); }\n" if name == "case-001" else
            "int main() { return 0; }\n", encoding="utf-8")
        if name == "case-001":
            (case / "hello.cpp").write_text("int hello() { return 0; }\n", encoding="utf-8")
        if system == "cmake":
            (case / "CMakeLists.txt").write_text(
                (f"cmake_minimum_required(VERSION 3.16)\nproject({name})\n"
                 "add_library(hello STATIC hello.cpp)\nadd_executable(case001 main.cpp)\n"
                 "target_link_libraries(case001 PRIVATE hello)\n" if name == "case-001" else
                 f"cmake_minimum_required(VERSION 3.16)\nproject({name})\nadd_executable({name} main.cpp)\n"),
                encoding="utf-8")
        elif system == "make":
            (case / "Makefile").write_text("all:\n\t$(CXX) -o case main.cpp\n", encoding="utf-8")
        elif system == "autotools":
            (case / "configure.ac").write_text("AC_INIT([case],[1])\nAC_PROG_CXX\nAC_OUTPUT\n", encoding="utf-8")
            (case / "Makefile.am").write_text("bin_PROGRAMS=case\ncase_SOURCES=main.cpp\n", encoding="utf-8")
        else:
            project = case / "msbuild"
            project.mkdir()
            (project / "case038.vcxproj").write_text("<Project></Project>\n", encoding="utf-8")
    return target


class FakeNativeExecutor:
    def __init__(self, run_root: Path, calls: list[tuple[str, str]], fail: tuple[str, str] | None = None):
        self.run_root = run_root
        self.calls = calls
        self.fail = fail

    def execute(self, request):
        root = request.scratch_root
        root.mkdir(parents=True, exist_ok=True)
        mode = request.argv[1]
        case = root.name
        self.calls.append((case, mode))
        exit_code = 9 if self.fail == (case, mode) else 0
        if mode == "compile" and exit_code == 0:
            build = root / "build"
            build.mkdir(exist_ok=True)
            sources = ["hello.cpp", "main.cpp"] if case == "case-001" else ["main.cpp"]
            (build / "compile_commands.json").write_text(json.dumps([{
                "directory": "/scratch/source", "file": f"/scratch/source/{source}",
                "arguments": ["clang++-18", "-std=c++17", "-c", f"/scratch/source/{source}",
                              "-o", f"/scratch/build/{Path(source).stem}.o"],
            } for source in sources]), encoding="utf-8")
            for source in sources:
                (build / f"{Path(source).stem}.o").write_bytes(b"object:" + source.encode())
            links = []
            if case == "case-001":
                (build / "libhello.a").write_bytes(b"archive")
                links.append({"output_path": "build/libhello.a", "input_paths": ["build/hello.o"]})
                links.append({"output_path": "build/case", "input_paths": ["build/main.o", "build/libhello.a"]})
            else:
                links.append({"output_path": "build/case", "input_paths": ["build/main.o"]})
            (build / "link-commands.json").write_text(json.dumps(links), encoding="utf-8")
            (build / "case").write_bytes(b"\x7fELFfixture")
        if mode == "ast" and exit_code == 0:
            destination = root / "analysis" / "ast"
            destination.mkdir(parents=True, exist_ok=True)
            names = ["hello", "main"] if case == "case-001" else ["main"]
            for index, name in enumerate(names):
                node = {"id": "0x1", "kind": "FunctionDecl", "name": name,
                        "loc": {"line": 1, "col": 1}, "type": {"qualType": "int ()"}}
                (destination / f"tu-{index:04d}.json").write_text(json.dumps({
                    "kind": "TranslationUnitDecl", "inner": [node, node]
                }), encoding="utf-8")
        if mode == "ir" and exit_code == 0:
            destination = root / "analysis" / "ir"
            destination.mkdir(parents=True, exist_ok=True)
            if case == "case-001":
                (destination / "tu-0000.ll").write_text("define i32 @hello() {\nentry:\n  ret i32 0\n}\n", encoding="utf-8")
                (destination / "tu-0001.ll").write_text(
                    "define i32 @main() {\nentry:\n  %1 = call i32 @hello()\n"
                    "  %2 = call i32 @hello()\n  ret i32 %2\n}\n", encoding="utf-8")
            else:
                (destination / "tu-0000.ll").write_text("define i32 @main() {\nentry:\n  ret i32 0\n}\n", encoding="utf-8")
        if mode == "symbols" and exit_code == 0:
            destination = root / "analysis" / "binary"
            destination.mkdir(parents=True, exist_ok=True)
            (destination / "records.json").write_text(json.dumps([{
                "path": "build/case", "kind": "executable",
                "sha256": "f" * 64,
                "symbols": ["main T 0 1", "main T 0 1"] if case == "case-030" else ["main T 0 1"],
                "metadata": "ELF64 NX PIE",
            }]), encoding="utf-8")
        raw = root / "raw"
        raw.mkdir(exist_ok=True)
        stdout, stderr, receipt = raw / "stdout.bin", raw / "stderr.bin", root / "execution.json"
        stdout.write_bytes(b"")
        stderr.write_bytes(b"fixture failure" if exit_code else b"")
        receipt.write_text("{}", encoding="utf-8")
        relative = lambda path: path.relative_to(self.run_root).as_posix()
        return ExecutionResult("appsec-review/container-execution/1", request.tool_id,
            "appsec-review/tool-native-cpp:1.0.0", DIGEST, DIGEST, "argv", (), {}, "start", "end",
            exit_code, False, False, False, False, relative(stdout), relative(stderr), relative(receipt))


def _fixture(tmp_path: Path):
    shutil.copy2(ROOT / "appsec-review.toml", tmp_path / "appsec-review.toml")
    return load_config(tmp_path / "appsec-review.toml"), _target(tmp_path)


def test_compile_database_normalization_preserves_only_reviewed_build_semantics(tmp_path: Path) -> None:
    root = tmp_path / "case"
    (root / "build").mkdir(parents=True)
    (root / "source").mkdir()
    (root / "source" / "main.cpp").write_text("int main(){}\n", encoding="utf-8")
    (root / "build" / "compile_commands.json").write_text(json.dumps([{
        "directory": str(root / "build"), "file": str(root / "source" / "main.cpp"),
        "command": f"c++ -DVALUE=1 -I{root / 'source'} -std=c++17 -c {root / 'source' / 'main.cpp'} -o x.o",
    }, {
        "directory": str(root / "build"), "file": str(root / "source" / "main.cpp"),
        "arguments": ["clang++-18", "-cc1", "-emit-obj", str(root / "source" / "main.cpp")],
    }]), encoding="utf-8")
    source_sha = hashlib.sha256((root / "source" / "main.cpp").read_bytes()).hexdigest()
    rows = normalize_compile_db(root, {"case_id": "case-001", "project_id": "cpp:case-001",
        "case_snapshot": "a" * 64, "root": "projects/cpp/case-001", "files": [{
            "target_path": "projects/cpp/case-001/main.cpp", "scratch_path": "source/main.cpp",
            "sha256": source_sha,
        }]})
    assert rows[0]["target_path"] == "projects/cpp/case-001/main.cpp"
    assert rows[0]["arguments"][0] == "clang++-18"
    assert "-DVALUE=1" in rows[0]["arguments"] and "-std=c++17" in rows[0]["arguments"]
    assert "-c" not in rows[0]["arguments"] and "-o" not in rows[0]["arguments"]
    assert rows[0]["arguments"][-1] == "/scratch/source/main.cpp"
    assert rows[0]["output_path"] == "build/x.o"
    assert len(rows[0]["compile_unit_id"]) == 64
    assert len(rows) == 1


def test_clang_ast_loader_accepts_bounded_concatenated_declarations(tmp_path: Path) -> None:
    path = tmp_path / "ast.json"
    path.write_text(
        '{"kind":"FunctionDecl","name":"first"}\n'
        '{"kind":"FunctionDecl","name":"second"}\n',
        encoding="utf-8",
    )
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
    second = source_fingerprint(target)
    assert first != second
    assert before["snapshot"]["coverage"].startswith("all regular target bytes")


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
        "/usr/bin/llvm-ar-18 qc libcore.a CMakeFiles/core.dir/unit.o\n",
        encoding="utf-8",
    )
    driver.ROOT = tmp_path
    driver.BUILD = build
    driver.emit_link_commands()

    receipts = json.loads((build / "link-commands.json").read_text(encoding="utf-8"))
    assert receipts[0]["output_path"] == "build/libcore.a"
    assert receipts[0]["input_paths"] == ["build/CMakeFiles/core.dir/unit.o"]
    assert receipts[0]["output_path"] not in receipts[0]["input_paths"]

    source_file = tmp_path / "external.cpp"
    source_file.write_text(
        'extern "C" int workspace_open() { return 1; }\n'
        'extern "C" int workspace_close() { return 0; }\n',
        encoding="utf-8",
    )
    assert driver.ast_filter(str(source_file)) == "workspace_"


def test_cpp_job_topology_is_one_lane_with_thirteen_resumable_cases(tmp_path: Path) -> None:
    config, _ = _fixture(tmp_path)
    job = build_job(executor_factory=lambda unit: None)
    plan = plan_jobs((job,), config)
    assert len(CASE_IDS) == 13 and len(job.units) == 132
    compile_nodes = [node for node in plan.nodes if node.step_id == "compile"]
    assert len(compile_nodes) == 13 and {node.workers for node in compile_nodes} == {1}
    ast = plan.node("job_cpp_compiled_analysis.ast.case001")
    ir = plan.node("job_cpp_compiled_analysis.ir.case001")
    assert ast.dependencies == ir.dependencies == ("job_cpp_compiled_analysis.catalog.case001",)
    final = plan.node("job_cpp_compiled_analysis.acceptance.publish_handoff")
    assert len(final.dependencies) == 78


def test_cpp_job_publishes_successes_and_independent_tool_gaps(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_plan()]).run(
        target_root=target, source_fingerprint=fingerprint)
    calls: list[tuple[str, str]] = []
    factory = lambda unit: FakeNativeExecutor(unit.job.run_root, calls, ("case-002", "ast"))
    outcome = GraphRunner(config, [build_job(executor_factory=factory)]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    result = outcome["jobs"]["job_cpp_compiled_analysis"]["result"]["outputs"]
    assert result["compile.case001"]["terminal_status"] == "SUCCEEDED"
    assert result["ast.case002"]["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert result["ir.case002"]["terminal_status"] == "SUCCEEDED"
    assert result["codeql.case001"]["gaps"][0].startswith("BLOCKED: CodeQL")
    assert result["joern.case001"]["gaps"][0].startswith("BLOCKED: a hash-pinned Joern")
    accepted = result["acceptance.publish_handoff"]
    assert accepted["item_count"] >= 78 and accepted["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert result["configure.case038"]["terminal_status"] == "UNAVAILABLE"
    assert result["compile.case038"]["terminal_status"] == "BLOCKED_BY_CONFIGURE"
    retrieval = RetrievalCore(config.runtime.runs_dir, upstream["run_id"])
    page = retrieval.search(query="main", limit=10)
    assert page["results"]
    assert ("case-001", "ir") in calls and ("case-002", "symbols") in calls

    manifest = json.loads((tmp_path / "runs" / upstream["run_id"] /
                           accepted["index_manifest"]["path"]).read_text(encoding="utf-8"))
    build_shard = next(item for item in manifest["indexes"] if item["shard_id"] == "cpp-case-001-compiled")
    with sqlite3.connect(tmp_path / "runs" / upstream["run_id"] / build_shard["relative_path"]) as database:
        relations = database.execute("SELECT kind, exact, ambiguity FROM relations").fetchall()
    assert ("COMPILES_TO", 1, None) in relations and ("LINKS_INTO", 1, None) in relations
    assert all(exact == 1 and ambiguity is None for _, exact, ambiguity in relations)


def test_build_failure_is_a_case_gap_and_does_not_discard_other_cases(tmp_path: Path) -> None:
    config, target = _fixture(tmp_path)
    fingerprint = source_fingerprint(target)
    upstream = GraphRunner(config, [build_intake(), build_catalog(), build_plan()]).run(
        target_root=target, source_fingerprint=fingerprint)
    calls: list[tuple[str, str]] = []
    factory = lambda unit: FakeNativeExecutor(unit.job.run_root, calls, ("case-003", "compile"))
    outcome = GraphRunner(config, [build_job(executor_factory=factory)]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"])
    outputs = outcome["jobs"]["job_cpp_compiled_analysis"]["result"]["outputs"]
    assert outputs["compile.case003"]["terminal_status"] == "FAILED_AS_GAP"
    assert outputs["ast.case003"]["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert outputs["compile.case001"]["terminal_status"] == "SUCCEEDED"
    assert ("case-003", "ast") not in calls and ("case-001", "ast") in calls

    first_calls = list(calls)
    retry_factory = lambda unit: FakeNativeExecutor(unit.job.run_root, calls)
    resumed = GraphRunner(config, [build_job(executor_factory=retry_factory)]).run(
        target_root=target, source_fingerprint=fingerprint, run_id=upstream["run_id"],
        force_from="job_cpp_compiled_analysis")
    retry_calls = calls[len(first_calls):]
    assert ("case-003", "compile") in retry_calls
    assert ("case-003", "ast") in retry_calls and ("case-003", "ir") in retry_calls
    assert not any(case != "case-003" or mode == "configure" for case, mode in retry_calls)
    retry_outputs = resumed["jobs"]["job_cpp_compiled_analysis"]["result"]["outputs"]
    assert retry_outputs["configure.case003"]["checkpoint_reused"] is True
    assert retry_outputs["ast.case001"]["checkpoint_reused"] is True
