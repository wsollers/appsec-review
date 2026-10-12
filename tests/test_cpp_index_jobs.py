"""Independent C/C++ indexing jobs: clangd symbol index and Joern CPG generation.

Both jobs consume only the accepted job_cpp_compiled_analysis handoff. Tool containers are
replaced by a fake executor; the shared scope loading, verification, normalization, checkpoint,
and manifest composition code is real.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.jobs.cpp_index_scopes import accepted_cpp_scopes, container_compile_database
from appsec_review.jobs.job_cpg_analysis import JOERN_GAP, build_job as build_cpg
from appsec_review.jobs.job_cpp_compiled_analysis import build_job as build_cpp
from appsec_review.jobs.job_cpp_symbol_index import build_job as build_symbols
from appsec_review.jobs.job_cpp_symbol_index.clangd_yaml import parse_documents
from appsec_review.jobs.job_cpp_symbol_index.job import normalize_scope
from appsec_review.jobs.job_language_build import build_job as build_language
from appsec_review.retrieval import IndexBuilder, RelationKind
from appsec_review.retrieval.core import resolve_accepted_manifest
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.runtime import GraphRunner
from appsec_review.runtime.registry import builtin_registry
from tests.test_language_build import (
    AnalysisExecutor, _accepted_project, _fixture, native_language_executor,
)


MAIN_YAML = """--- !Symbol
ID:              AAAAAAAAAAAAAAA1
Name:            main
Scope:           ''
SymInfo:
  Kind:            Function
  Lang:            C
CanonicalDeclaration:
  FileURI:         'file:///target/source/main.cpp'
  Start:
    Line:            0
    Column:          4
  End:
    Line:            0
    Column:          8
Definition:
  FileURI:         'file:///target/source/main.cpp'
  Start:
    Line:            0
    Column:          4
  End:
    Line:            0
    Column:          8
References:      0
Signature:       '()'
ReturnType:      'int'
...
--- !Symbol
ID:              BBBBBBBBBBBBBBB2
Name:            printf
Scope:           ''
SymInfo:
  Kind:            Function
  Lang:            C
CanonicalDeclaration:
  FileURI:         'file:///usr/include/stdio.h'
  Start:
    Line:            355
    Column:          11
  End:
    Line:            355
    Column:          17
...
"""


class IndexExecutor:
    """Stand-in for the clangd-indexer and Joern containers."""

    def __init__(self, run_root: Path, calls: list[str], *, clangd_exit: int = 0, joern_exit: int = 0):
        self.run_root, self.calls = run_root, calls
        self.clangd_exit, self.joern_exit = clangd_exit, joern_exit

    def execute(self, request):
        scratch = request.scratch_root
        self.calls.append(request.tool_id)
        # The tool runs as uid 10001; its compile database must be readable by other users.
        assert (scratch / "compile_commands.json").stat().st_mode & 0o004
        database = json.loads((scratch / "compile_commands.json").read_text(encoding="utf-8"))
        assert all(row["file"].startswith("/target/source/") for row in database)
        assert (request.target_root / "source").is_dir()
        stdout, stderr, code = b"", b"", 0
        if request.tool_id == "tool-clangd-indexer":
            code = self.clangd_exit
            if code == 0:
                stdout = MAIN_YAML.encode()
                stderr = "".join(f"[{index}/{len(database)}] Processing file {row['file']}\n"
                                 for index, row in enumerate(database, 1)).encode()
        elif request.tool_id == "tool-joern":
            code = self.joern_exit
            if code == 0:
                (scratch / "cpg.bin").write_bytes(b"fixture-cpg")
        raw = scratch / "raw"
        raw.mkdir(exist_ok=True)
        (raw / "stdout.bin").write_bytes(stdout)
        (raw / "stderr.bin").write_bytes(stderr)
        receipt = scratch / "execution.json"
        receipt.write_text(json.dumps({"tool_id": request.tool_id, "argv": list(request.argv)}), encoding="utf-8")
        relative = lambda path: path.relative_to(self.run_root).as_posix()
        digest = "sha256:" + "c" * 64
        return ExecutionResult("appsec-review/container-execution/1", request.tool_id, "fixture",
                               digest, digest, "argv", (), {}, "start", "end", code, False, False,
                               False, False, relative(raw / "stdout.bin"), relative(raw / "stderr.bin"),
                               relative(receipt))


def _accepted_cpp(tmp_path: Path, *, max_cpg_bytes: int | None = None):
    config, target = _fixture(tmp_path)
    if max_cpg_bytes is not None:
        config = _with_cpg_limit(tmp_path, max_cpg_bytes)
    run_id, fingerprint = _accepted_project(config, target, [])
    GraphRunner(config, [build_language(
        executor_factory=lambda unit, profile: native_language_executor(profile, []))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    outcome = GraphRunner(config, [build_cpp(
        executor_factory=lambda unit: AnalysisExecutor(unit.job.run_root))]).run(
            target_root=target, source_fingerprint=fingerprint, run_id=run_id)
    assert outcome["status"] == "SUCCEEDED"
    return config, target, run_id, fingerprint


def _run(config, target, run_id, fingerprint, job, **options):
    return GraphRunner(config, [job]).run(target_root=target, source_fingerprint=fingerprint,
                                          run_id=run_id, **options)


def _outputs(outcome, job_id: str) -> dict:
    path = Path(outcome["jobs"][job_id]["attempt_root"]) / "result.json"
    return json.loads(path.read_text(encoding="utf-8"))["outputs"]


def _rows(run_root: Path, identity: dict, query: str) -> list[tuple]:
    with sqlite3.connect(run_root / identity["relative_path"]) as database:
        return database.execute(query).fetchall()


def test_registry_and_configuration_declare_both_independent_jobs(tmp_path: Path) -> None:
    config, _ = _fixture(tmp_path)
    registry = builtin_registry()
    for job_id, steps in (("job_cpp_symbol_index", ["load", "index", "acceptance"]),
                          ("job_cpg_analysis", ["load", "generate", "acceptance"])):
        assert registry.build(job_id).job_id == job_id
        assert list(config.job(job_id).steps) == steps
    assert "joern" not in config.job("job_cpp_compiled_analysis").steps


def test_symbol_index_publishes_accepted_symbols_with_complete_coverage(tmp_path: Path) -> None:
    config, target, run_id, fingerprint = _accepted_cpp(tmp_path)
    run_root = config.runtime.runs_dir / run_id
    calls: list[str] = []
    outcome = _run(config, target, run_id, fingerprint,
                   build_symbols(executor_factory=lambda unit: IndexExecutor(unit.job.run_root, calls)))
    assert outcome["status"] == "SUCCEEDED" and calls == ["tool-clangd-indexer"]
    outputs = _outputs(outcome, "job_cpp_symbol_index")
    (scope,) = outputs["index.scopes"]["scopes"]
    assert scope["counts"]["symbols"] == 1 and scope["counts"]["external_symbols"] == 1
    assert scope["counts"]["processed_translation_units"] == scope["counts"]["translation_units"] == 1
    identity = scope["index_identity"]
    (entity,) = _rows(run_root, identity, "SELECT kind, native_id, name, payload_json FROM entities")
    assert entity[:3] == ("symbol", "AAAAAAAAAAAAAAA1", "main")
    payload = json.loads(entity[3])
    assert payload["definition"] == {"path": "native/main.cpp", "line": 1, "column": 5,
                                     "end_line": 1, "end_column": 9}
    (location,) = _rows(run_root, identity, "SELECT path, start_line, start_column, mapping_method FROM locations")
    assert location == ("native/main.cpp", 1, 5, "clangd-uri-exact-path")
    assert _rows(run_root, identity, "SELECT status FROM coverage") == [("complete",)]
    manifest = outputs["acceptance.publish_handoff"]["index_manifest"]
    document, _ = load_verified_manifest(run_root, run_root / manifest["path"], manifest["sha256"])
    producers = {item["producer"]["job"] for item in document["indexes"]}
    assert {"job_cpp_symbol_index", "job_cpp_compiled_analysis"} <= producers


def test_cpg_job_retains_the_cpg_but_claims_no_coverage(tmp_path: Path) -> None:
    config, target, run_id, fingerprint = _accepted_cpp(tmp_path)
    run_root = config.runtime.runs_dir / run_id
    outcome = _run(config, target, run_id, fingerprint,
                   build_cpg(executor_factory=lambda unit: IndexExecutor(unit.job.run_root, [])))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    generated = _outputs(outcome, "job_cpg_analysis")["generate.scopes"]
    (scope,) = generated["scopes"]
    assert scope["observation_count"] == 0 and scope["gaps"] == [JOERN_GAP]
    assert (run_root / scope["cpg"]["path"]).read_bytes() == b"fixture-cpg"
    identity = scope["index_identity"]
    assert _rows(run_root, identity, "SELECT status, gap FROM coverage") == [("unavailable", JOERN_GAP)]
    ((payload,),) = _rows(run_root, identity, "SELECT payload_json FROM entities")
    assert json.loads(payload)["status"] == "BLOCKED" and json.loads(payload)["cpg"] == scope["cpg"]


def test_failed_c2cpg_is_a_named_gap_without_a_cpg(tmp_path: Path) -> None:
    config, target, run_id, fingerprint = _accepted_cpp(tmp_path)
    outcome = _run(config, target, run_id, fingerprint, build_cpg(
        executor_factory=lambda unit: IndexExecutor(unit.job.run_root, [], joern_exit=3)))
    (scope,) = _outputs(outcome, "job_cpg_analysis")["generate.scopes"]["scopes"]
    assert scope["cpg"] is None and scope["gaps"] == ["Joern c2cpg exited with status 3", JOERN_GAP]


def test_failed_clangd_run_is_scoped_unavailable_coverage(tmp_path: Path) -> None:
    config, target, run_id, fingerprint = _accepted_cpp(tmp_path)
    run_root = config.runtime.runs_dir / run_id
    outcome = _run(config, target, run_id, fingerprint, build_symbols(
        executor_factory=lambda unit: IndexExecutor(unit.job.run_root, [], clangd_exit=1)))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    (scope,) = _outputs(outcome, "job_cpp_symbol_index")["index.scopes"]["scopes"]
    assert scope["counts"]["coverage"] == "unavailable" and scope["counts"]["symbols"] == 0
    assert "clangd-indexer exited with status 1" in scope["gaps"]
    assert _rows(run_root, scope["index_identity"], "SELECT status FROM coverage") == [("unavailable",)]


@pytest.mark.parametrize("order", ["cpg-first", "symbols-first"])
def test_jobs_are_independent_and_never_drop_each_others_shards(tmp_path: Path, order: str) -> None:
    config, target, run_id, fingerprint = _accepted_cpp(tmp_path)
    run_root = config.runtime.runs_dir / run_id
    jobs = [build_cpg(executor_factory=lambda unit: IndexExecutor(unit.job.run_root, [])),
            build_symbols(executor_factory=lambda unit: IndexExecutor(unit.job.run_root, []))]
    if order == "symbols-first":
        jobs.reverse()
    for job in jobs:  # each runs alone against the accepted C++ handoff
        _run(config, target, run_id, fingerprint, job)
    path, sha = resolve_accepted_manifest(run_root)
    document, _ = load_verified_manifest(run_root, path, sha)
    producers = {item["producer"]["job"] for item in document["indexes"]}
    assert {"job_cpp_compiled_analysis", "job_cpp_symbol_index", "job_cpg_analysis"} <= producers


def test_rerun_reuses_verified_scope_checkpoints(tmp_path: Path) -> None:
    config, target, run_id, fingerprint = _accepted_cpp(tmp_path)
    calls: list[str] = []
    job = lambda: build_symbols(executor_factory=lambda unit: IndexExecutor(unit.job.run_root, calls))
    _run(config, target, run_id, fingerprint, job())
    outcome = _run(config, target, run_id, fingerprint, job(), force_from="job_cpp_symbol_index")
    (scope,) = _outputs(outcome, "job_cpp_symbol_index")["index.scopes"]["scopes"]
    assert calls == ["tool-clangd-indexer"] and scope["checkpoint_reused"] is True


def test_scope_loading_rejects_sources_changed_after_acceptance(tmp_path: Path) -> None:
    config, _target, run_id, _fingerprint = _accepted_cpp(tmp_path)
    run_root = config.runtime.runs_dir / run_id
    _accepted, (scope,), unavailable = accepted_cpp_scopes(run_root)
    assert unavailable == {} and scope.files
    (scope.case_root / scope.files[0]["scratch_path"]).write_text("int main() { return 1; }\n", encoding="utf-8")
    with pytest.raises(ValueError, match="materialized source changed after acceptance"):
        accepted_cpp_scopes(run_root)


def test_container_compile_database_rebases_paths_and_normalizes_the_driver() -> None:
    rows = container_compile_database("native", [
        {"target_path": "native/a.cpp", "arguments": ["g++-13", "-I/scratch/source/inc", "-std=c++20"]},
        {"target_path": "native/b.c", "arguments": ["clang-cl", "/DWIN32", "-I/scratch/build/gen"]},
    ])
    assert rows == [
        {"directory": "/target/source", "file": "/target/source/a.cpp",
         "arguments": ["clang++", "-I/target/source/inc", "-std=c++20"]},
        {"directory": "/target/source", "file": "/target/source/b.c",
         "arguments": ["clang", "/DWIN32", "-I/target/build/gen"]},
    ]
    with pytest.raises(ValueError, match="outside the accepted project root"):
        container_compile_database("native", [{"target_path": "other/x.cpp", "arguments": ["cc"]}])


def test_normalizer_emits_aggregated_call_and_reference_edges_between_accepted_symbols(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "p").mkdir(parents=True)
    (target / "p" / "a.cpp").write_text("int helper();\nint main() { return helper(); }\n", encoding="utf-8")
    import hashlib
    sha = hashlib.sha256((target / "p" / "a.cpp").read_bytes()).hexdigest()
    entry = {"target_path": "p/a.cpp", "scratch_path": "source/a.cpp", "sha256": sha}
    scope = SimpleNamespace(project_id="cpp:p", case_snapshot="d" * 64,
                            accepted_file=lambda path: entry if path == "/target/source/a.cpp" else None,
                            container_compile_database=lambda: [{"file": "/target/source/a.cpp"}])
    symbol = ("--- !Symbol\nID:              {id}\nName:            {name}\nScope:           ''\n"
              "Definition:\n  FileURI:         'file:///target/source/a.cpp'\n  Start:\n"
              "    Line:            {line}\n    Column:          4\n...\n")
    reference = ("  - Kind:            {kind}\n    Location:\n      FileURI:         'file:///target/source/a.cpp'\n"
                 "      Start:\n        Line:            1\n        Column:          {column}\n"
                 "    Container:\n      ID:              {container}\n")
    text = (symbol.format(id="1111111111111111", name="helper", line=0) +
            symbol.format(id="2222222222222222", name="main", line=1) +
            "--- !Refs\nID:              1111111111111111\nReferences:\n" +
            reference.format(kind=28, column=20, container="2222222222222222") +
            reference.format(kind=28, column=30, container="2222222222222222") +
            reference.format(kind=12, column=40, container="2222222222222222") +
            reference.format(kind=4, column=50, container="'0000000000000000'") + "...\n")
    run_root = tmp_path / "run"
    (run_root / "raw").mkdir(parents=True)
    (run_root / "raw" / "stdout").write_text(text, encoding="utf-8")
    (run_root / "raw" / "stderr").write_text("[1/1] Processing file /target/source/a.cpp\n", encoding="utf-8")
    unit = SimpleNamespace(job=SimpleNamespace(run_root=run_root, target_root=target, source_fingerprint="e" * 64))
    builder = IndexBuilder(run_root / "shard.sqlite", name="analysis", fingerprint="f" * 64,
                           target_snapshot="e" * 64, shard_id="clangd-test")
    counts = normalize_scope(unit, scope, {"timed_out": False, "oom_killed": False, "exit_code": 0,
                                           "stdout_truncated": False, "stdout_path": "raw/stdout",
                                           "stderr_path": "raw/stderr"},
                             {"max_documents_per_scope": 100, "max_symbols_per_scope": 100,
                              "max_relations_per_scope": 100, "locations_per_relation": 1},
                             builder, "clangd-test")
    assert counts["symbols"] == 2 and counts["relations"] == 2 and counts["unresolved_references"] == 1
    edges = {relation.kind: relation for relation in builder.relations}
    assert set(edges) == {RelationKind.CALLS, RelationKind.REFERENCES}
    assert edges[RelationKind.CALLS].payload["occurrences"] == 2
    assert edges[RelationKind.CALLS].payload["locations"] == [
        {"path": "p/a.cpp", "line": 2, "column": 21, "ref_kind": 28}]
    assert counts["coverage"] == "complete"


def test_clangd_yaml_parser_accepts_the_subset_and_rejects_everything_else() -> None:
    documents, truncated, capped = parse_documents(MAIN_YAML, document_limit=10)
    assert [document.tag for document in documents] == ["Symbol", "Symbol"] and not truncated and not capped
    assert documents[0].value["Definition"]["Start"] == {"Line": "0", "Column": "4"}
    folded, _, _ = parse_documents("--- !Symbol\nID:              X\nDocumentation:   'line one\n"
                                   "  it''s two'\n...\n", document_limit=10)
    assert folded[0].value["Documentation"] == "line one it's two"
    _, truncated, _ = parse_documents(MAIN_YAML + "--- !Symbol\nID:              Z\n", document_limit=10)
    assert truncated is True
    documents, _, capped = parse_documents(MAIN_YAML, document_limit=1)
    assert len(documents) == 1 and capped is True
    for bad in ('--- !Symbol\nName: "double"\n...\n', "--- !Symbol\nID: a\nID: b\n...\n",
                "stray\n", "--- !Symbol\n  - orphan: x\nName: y\n...\n"):
        with pytest.raises(ValueError):
            parse_documents(bad, document_limit=10)


# --- CPG size limit enforced during generation, and strict checkpoint revalidation -----------------

import os
import resource
import subprocess
import sys

from appsec_review.config import load_config
from appsec_review.container_runtime.executor import FILE_SIZE_SIGNAL_EXIT
from appsec_review.jobs.cpp_index_scopes import CheckpointIntegrityError
from appsec_review.storage import file_sha256


class RLimitJoern(IndexExecutor):
    """A fake c2cpg that really writes ``attempt`` bytes under the request's RLIMIT_FSIZE."""

    def __init__(self, run_root: Path, calls: list[str], attempt: int):
        super().__init__(run_root, calls)
        self.attempt = attempt
        self.limits: list[int | None] = []

    def execute(self, request):
        assert request.tool_id == "tool-joern"
        self.limits.append(request.file_size_limit_bytes)
        scratch = request.scratch_root
        writer = ("import sys\nwith open(sys.argv[1], 'wb') as out:\n"
                  "    remaining = int(sys.argv[2])\n"
                  "    while remaining:\n"
                  "        step = min(remaining, 65536)\n"
                  "        out.write(b'c' * step)\n        out.flush()\n        remaining -= step\n")

        def limit() -> None:
            if request.file_size_limit_bytes is not None:
                resource.setrlimit(resource.RLIMIT_FSIZE, (request.file_size_limit_bytes,) * 2)

        completed = subprocess.run([sys.executable, "-c", writer, str(scratch / "cpg.bin"), str(self.attempt)],
                                   preexec_fn=limit, capture_output=True, check=False, timeout=60)
        code = 128 - completed.returncode if completed.returncode < 0 else completed.returncode
        raw = scratch / "raw"
        raw.mkdir(exist_ok=True)
        (raw / "stdout.bin").write_bytes(b"")
        (raw / "stderr.bin").write_bytes(completed.stderr[-4096:])
        receipt = scratch / "execution.json"
        receipt.write_text(json.dumps({"tool_id": request.tool_id, "exit_code": code,
                                       "limits": {"file_size_bytes": request.file_size_limit_bytes}}),
                           encoding="utf-8")
        relative = lambda path: path.relative_to(self.run_root).as_posix()
        digest = "sha256:" + "c" * 64
        self.calls.append(request.tool_id)
        return ExecutionResult("appsec-review/container-execution/1", request.tool_id, "fixture",
                               digest, digest, "argv", (), {}, "start", "end", code, False, False,
                               False, False, relative(raw / "stdout.bin"), relative(raw / "stderr.bin"),
                               relative(receipt), request.file_size_limit_bytes, code == FILE_SIZE_SIGNAL_EXIT)


def _with_cpg_limit(tmp_path: Path, limit: int):
    path = tmp_path / "appsec-review.toml"
    text = path.read_text(encoding="utf-8")
    text = text.replace("max_cpg_bytes = 2147483648", f"max_cpg_bytes = {limit}")
    path.write_text(text, encoding="utf-8")
    return load_config(path)


LIMIT = 256 * 1024


def test_cpg_limit_stops_c2cpg_while_writing_and_discards_the_partial_cpg(tmp_path: Path) -> None:
    config, target, run_id, fingerprint = _accepted_cpp(tmp_path, max_cpg_bytes=LIMIT)
    run_root = config.runtime.runs_dir / run_id
    joern = RLimitJoern(run_root, [], attempt=64 * LIMIT)  # tries to write 16 MiB
    outcome = _run(config, target, run_id, fingerprint, build_cpg(executor_factory=lambda unit: joern))
    assert outcome["status"] == "COMPLETED_WITH_GAPS"
    (scope,) = _outputs(outcome, "job_cpg_analysis")["generate.scopes"]["scopes"]
    assert joern.limits == [LIMIT + 1], "the limit is applied to the execution, not checked afterwards"
    # Like the JVM, the writer ignores SIGXFSZ: the kernel fails the write with EFBIG instead, so
    # the job recognises the stop from the bounded file size, not only from a 128 + SIGXFSZ exit.
    assert scope["execution"]["file_size_limit_reached"] is False and scope["execution"]["exit_code"] == 1
    assert scope["resource_limit"] == {"mechanism": "RLIMIT_FSIZE", "max_cpg_bytes": LIMIT,
                                       "enforced_bytes": LIMIT + 1, "disposition": "LIMIT_REACHED",
                                       "observed_bytes": LIMIT + 1}, "growth stopped at the bound"
    assert scope["cpg"] is None
    assert not list((run_root / "data" / "code-index" / "joern").rglob("cpg.bin")), "partial CPG retained"
    assert scope["gaps"][0] == (f"Joern c2cpg reached the {LIMIT}-byte CPG limit while writing; "
                                "the partial CPG was discarded")
    coverage = _rows(run_root, scope["index_identity"], "SELECT status, gap FROM coverage")
    assert coverage[0][0] == "unavailable" and "CPG limit" in coverage[0][1]
    manifest = json.loads((run_root / scope["cpg_manifest"]["path"]).read_text(encoding="utf-8"))
    assert manifest["resource_limit"]["disposition"] == "LIMIT_REACHED" and manifest["cpg"] is None
    receipt = json.loads((run_root / scope["execution"]["receipt"]["path"]).read_text(encoding="utf-8"))
    assert receipt["limits"]["file_size_bytes"] == LIMIT + 1


@pytest.mark.parametrize("size", [LIMIT, LIMIT - 1])
def test_cpg_immediately_below_the_limit_is_retained_complete(tmp_path: Path, size: int) -> None:
    config, target, run_id, fingerprint = _accepted_cpp(tmp_path, max_cpg_bytes=LIMIT)
    run_root = config.runtime.runs_dir / run_id
    joern = RLimitJoern(run_root, [], attempt=size)
    outcome = _run(config, target, run_id, fingerprint, build_cpg(executor_factory=lambda unit: joern))
    (scope,) = _outputs(outcome, "job_cpg_analysis")["generate.scopes"]["scopes"]
    assert scope["resource_limit"]["disposition"] == "WITHIN_LIMIT"
    path = run_root / scope["cpg"]["path"]
    assert path.stat().st_size == size == scope["cpg"]["size_bytes"]
    assert file_sha256(path) == scope["cpg"]["sha256"] and path.read_bytes() == b"c" * size
    assert scope["gaps"] == [JOERN_GAP]


def _checkpointed(tmp_path: Path, max_cpg_bytes: int | None = None):
    config, target, run_id, fingerprint = _accepted_cpp(tmp_path, max_cpg_bytes=max_cpg_bytes)
    run_root = config.runtime.runs_dir / run_id
    calls: list[str] = []
    job = lambda: build_cpg(executor_factory=lambda unit: IndexExecutor(unit.job.run_root, calls))
    first = _run(config, target, run_id, fingerprint, job())
    (scope,) = _outputs(first, "job_cpg_analysis")["generate.scopes"]["scopes"]
    reused = _run(config, target, run_id, fingerprint, job(), force_from="job_cpg_analysis")
    (again,) = _outputs(reused, "job_cpg_analysis")["generate.scopes"]["scopes"]
    assert again["checkpoint_reused"] is True and calls == ["tool-joern"]
    return config, target, run_id, fingerprint, run_root, scope, job, calls


REFERENCED = {
    "cpg": lambda scope: scope["cpg"]["path"],
    "cpg-manifest": lambda scope: scope["cpg_manifest"]["path"],
    "execution-receipt": lambda scope: scope["execution"]["receipt"]["path"],
    "scope-compile-database": lambda scope: scope["execution"]["compile_database"]["path"],
    "index-shard": lambda scope: scope["index_identity"]["relative_path"],
}


@pytest.mark.parametrize("change", ["delete", "mutate"])
@pytest.mark.parametrize("name", sorted(REFERENCED))
def test_cpg_checkpoint_reuse_revalidates_every_referenced_artifact(tmp_path: Path, name: str, change: str) -> None:
    config, target, run_id, fingerprint, run_root, scope, job, calls = _checkpointed(tmp_path)
    pointer = run_root / "data" / "jobs" / "job_cpg_analysis" / "latest.json"
    accepted = pointer.read_bytes()
    path = run_root / REFERENCED[name](scope)
    if change == "delete":
        path.unlink()
    else:
        path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(RuntimeError, match="generate.scopes"):
        _run(config, target, run_id, fingerprint, job(), force_from="job_cpg_analysis")
    (traceback,) = (run_root / "data" / "jobs" / "job_cpg_analysis").rglob("generate/tasks/scopes/traceback.txt")
    text = traceback.read_text(encoding="utf-8")
    assert "CheckpointIntegrityError" in text and scope["scope_id"] in text, text[-1500:]
    assert calls == ["tool-joern"], "a mutated checkpoint is a framework failure, not a reason to regenerate"
    assert pointer.read_bytes() == accepted, "no new handoff may republish the stale identities"


def test_cpg_checkpoint_rejects_a_changed_accepted_compile_database(tmp_path: Path) -> None:
    from appsec_review.jobs.cpp_index_scopes import scope_checkpoint
    config, target, run_id, fingerprint, run_root, scope, job, calls = _checkpointed(tmp_path)
    checkpoint = run_root / "data" / "code-index" / "joern" / scope["scope_id"] / "checkpoint.json"
    document = json.loads(checkpoint.read_text(encoding="utf-8"))
    _accepted, (index_scope,), _ = accepted_cpp_scopes(run_root)
    assert scope_checkpoint(checkpoint, document["identity"], run_root, index_scope) is not None
    for mutate in (lambda result: result["accepted_compile_database"].update(sha256="0" * 64),
                   lambda result: result.update(scope_id="cpp-scope-other"),
                   lambda result: result["execution"].pop("receipt")):
        altered = json.loads(json.dumps(document))
        mutate(altered["result"])
        checkpoint.write_text(json.dumps(altered), encoding="utf-8")
        with pytest.raises(CheckpointIntegrityError):
            scope_checkpoint(checkpoint, document["identity"], run_root, index_scope,
                             required=("execution.receipt",))
    checkpoint.write_text("{not json", encoding="utf-8")
    with pytest.raises(CheckpointIntegrityError):
        scope_checkpoint(checkpoint, document["identity"], run_root, index_scope)
    checkpoint.write_text(json.dumps(document), encoding="utf-8")
    assert scope_checkpoint(checkpoint, "other-identity", run_root, index_scope) is None
    # The accepted compile database itself is verified when scopes are loaded.
    accepted = run_root / index_scope.compile_database["path"]
    accepted.write_bytes(accepted.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="accepted compile database changed"):
        accepted_cpp_scopes(run_root)


def test_cpg_checkpoint_identity_binds_the_configured_limit(tmp_path: Path) -> None:
    identities = []
    for name, limit in (("default", None), ("bounded", LIMIT)):
        (tmp_path / name).mkdir()
        _, _, _, _, run_root, scope, _, _ = _checkpointed(tmp_path / name, limit)
        checkpoint = run_root / "data" / "code-index" / "joern" / scope["scope_id"] / "checkpoint.json"
        identities.append((scope["scope_id"], json.loads(checkpoint.read_text())["identity"]))
    assert identities[0][0] == identities[1][0] and identities[0][1] != identities[1][1]
