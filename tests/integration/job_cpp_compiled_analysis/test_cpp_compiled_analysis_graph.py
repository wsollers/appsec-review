from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path, PurePosixPath
import shutil
import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_cpp_compiled_analysis import build_job
from appsec_review.jobs.job_cpp_compiled_analysis.job import _project_key
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.jobs.job_target_analysis_plan import build_job as build_plan
from appsec_review.retrieval import RetrievalCore
from appsec_review.runtime import GraphRunner


ROOT = Path(__file__).resolve().parents[3]
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
    def __init__(self, run_root: Path, calls: list[tuple[str, str]], fail: tuple[str, str] | None = None,
                 *, infer_path: str = "/target/source/main.cpp"):
        self.run_root = run_root
        self.calls = calls
        self.fail = fail
        self.infer_path = infer_path

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
        sources = ([row["file"] for row in json.loads((root / "compile_commands.json").read_bytes())]
                   if infer else sorted(path.name for path in (project_root / "source").glob("*.cpp")))
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
                "column": 1, "procedure": "main", "file": self.infer_path,
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


@pytest.mark.parametrize("reported_path,resolved", [
    ("/target/source/src/main.cpp", True),
    ("source/src/main.cpp", True),
    ("source\\src\\main.cpp", True),
    ("/foreign/source/src/main.cpp", False),
    ("/target/source/../src/main.cpp", False),
    ("src/main.cpp", False),
], ids=["absolute", "relative", "backslashes", "foreign", "traversal", "bare"])
def test_infer_paths_resolve_only_through_the_published_source_mapping(
        tmp_path: Path, reported_path: str, resolved: bool) -> None:
    from appsec_review.jobs.job_cpp_compiled_analysis.job import (
        _artifact, _case_root, _infer_index, _run_infer,
    )
    from appsec_review.retrieval import IndexIdentity, write_manifest
    from appsec_review.runtime import Job, JobRunner, Unit
    from appsec_review.storage import atomic_json, file_sha256

    shutil.copy2(ROOT / "appsec-review.toml", tmp_path / "appsec-review.toml")
    config = load_config(tmp_path / "appsec-review.toml")
    target = tmp_path / "target"
    project_root = "projects/native/fixture"
    project = _project_key(PurePosixPath(project_root))
    target_path = project_root + "/src/main.cpp"
    (target / project_root / "src").mkdir(parents=True)
    (target / target_path).write_text("int main() { return 0; }\n", encoding="utf-8")
    source_sha = file_sha256(target / target_path)
    snapshot = source_fingerprint(target)
    calls = []

    def infer(unit):
        root = _case_root(unit, project)
        (root / "source/src").mkdir(parents=True)
        shutil.copyfile(target / target_path, root / "source/src/main.cpp")
        rows = [{"target_path": target_path, "arguments": [
            "clang++-18", "-g", "/scratch/source/src/main.cpp"]}]
        database = root / "normalized-compile-commands.json"
        atomic_json(database, rows)
        catalog = {"mapping": {
            "root": project_root, "project_id": "cpp:" + project_root,
            "case_snapshot": snapshot, "files": [{
                "target_path": target_path, "scratch_path": "source/src/main.cpp", "sha256": source_sha}]},
            "compile_commands": rows, "compile_database": _artifact(unit.job.run_root, database)}
        execution = _run_infer(unit, project, catalog, executor_factory=lambda context:
            FakeNativeExecutor(context.job.run_root, calls, infer_path=reported_path))
        result = _infer_index(unit, project, catalog, execution)
        manifest = unit.job.run_root / "data/indices/manifests/infer-fixture.json"
        write_manifest(manifest, run_id=unit.job.run_id, target_snapshot=snapshot,
                       target_root=target, indexes=[IndexIdentity(**result["index_identity"])])
        return {**result, "execution": execution,
                "index_manifest": _artifact(unit.job.run_root, manifest)}

    original = build_job()
    job = Job(original.job_id, original.name, lambda _: {}, units=(Unit("infer.projects", infer),),
              datasets=original.datasets, schema_identity=original.schema_identity)
    outcome = JobRunner(config).run(job, target_root=target, source_fingerprint=snapshot)
    output = json.loads((Path(outcome["attempt_root"]) /
                         "steps/infer/tasks/projects/result.json").read_bytes())
    run_id = outcome["status"]["run_id"]
    core = RetrievalCore(config.runtime.runs_dir, run_id)
    records = core.search(query="NULLPTR_DEREFERENCE", indexes=("observations",))["results"]
    assert calls == [(project, "infer")]
    assert output["observation_count"] == len(records) == int(resolved)
    assert output["captured_source_files"] == output["expected_source_files"] == 1
    if resolved:
        assert output["gaps"] == []
        assert records[0]["payload"]["target_path"] == target_path
        assert records[0]["payload"]["source_sha256"] == source_sha
    else:
        assert any("did not resolve to accepted source" in gap for gap in output["gaps"])


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


@pytest.mark.parametrize("status,checkpointable,retry", [
    ("SUCCEEDED", False, False),
    ("COMPLETED_WITH_GAPS", False, True),
    ("COMPLETED_WITH_GAPS", True, False),
])
def test_cpp_handoff_dispositions_control_accepted_attempt_reuse(
        tmp_path, monkeypatch, status, checkpointable, retry):
    from appsec_review.jobs.job_cpp_compiled_analysis import job as cpp_job
    from appsec_review.retrieval.index import write_manifest
    from appsec_review.runtime import JobRunner
    from appsec_review.runtime.resume import ResumePlanner
    from appsec_review.storage import file_sha256
    from tests.fixtures.graph.job.builder import configured

    config = configured(tmp_path)
    gaps = ["fixture branch incomplete"] if status != "SUCCEEDED" else []

    def upstream(context):
        path = context.run_root / "upstream.json"
        return path, file_sha256(path)

    def stage(unit):
        if unit.unit_id == "plan.accepted_cpp_plan":
            write_manifest(unit.job.run_root / "upstream.json", run_id=unit.job.run_id,
                           target_snapshot="fixture", target_root=tmp_path, indexes=[])
            return {"plan": {"project_count": 2}}
        if unit.step_id not in cpp_job.BRANCHES:
            return {}
        branch_status = status if unit.step_id == "ir" else "SUCCEEDED"
        return {"projects": {
            "healthy": {"terminal_status": "SUCCEEDED", "gaps": []},
            "incomplete": {"terminal_status": branch_status,
                           "gaps": gaps if unit.step_id == "ir" else [],
                           "checkpointable": checkpointable},
        }}

    monkeypatch.setattr(cpp_job, "resolve_context_manifest", upstream)
    original = build_job()
    units = tuple(unit if unit.unit_id == "acceptance.publish_handoff" else replace(unit, handler=stage)
                  for unit in original.units)
    job = replace(original, units=units, input_validators=())
    outcome = JobRunner(config).run(job, source_fingerprint="fixture")
    handoff = outcome["handoff"]
    dispositions = handoff["outputs"]["acceptance.publish_handoff"]["dispositions"]
    assert len(dispositions) == 2 * len(cpp_job.BRANCHES)
    incomplete = next(item for item in dispositions
                      if item["project_key"] == "incomplete" and item["branch"] == "ir")
    assert incomplete["terminal_status"] == status
    assert (incomplete.get("disposition") == "GAP") is retry
    assert all(item.get("disposition") != "GAP" for item in dispositions if item != incomplete)
    reference = handoff["outputs"]["acceptance.publish_handoff"]["artifact"]
    run_root = config.runtime.runs_dir / outcome["status"]["run_id"]
    summary = json.loads((run_root / reference["path"]).read_bytes())
    assert summary["dispositions"]["incomplete:ir"] == status
    reasons, _ = ResumePlanner(config, run_root, (job,), "fixture").accepted(job, {})
    assert reasons == (("accepted job contains a retriable failed producer",) if retry else ())
