"""Independent C/C++ indexing jobs: clangd symbol index and Joern CPG generation.

Both jobs consume only the accepted job_cpp_compiled_analysis handoff. Tool containers are
replaced by a fake executor; the shared scope loading, verification, normalization, checkpoint,
and manifest composition code is real.
"""

from __future__ import annotations

import json
from pathlib import Path
import resource
import sqlite3
import subprocess
import sys

import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime.executor import ExecutionResult, FILE_SIZE_SIGNAL_EXIT
from appsec_review.jobs.cpp_index_scopes import container_compile_database
from appsec_review.jobs.job_cpp_compiled_analysis import build_job as build_cpp
from appsec_review.jobs.job_language_build import build_job as build_language
from appsec_review.runtime import GraphRunner
from appsec_review.runtime.registry import builtin_registry


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


def _with_joern(tmp_path: Path, enabled: bool):
    path = tmp_path / "appsec-review.toml"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("enabled = false\n# Joern is memory-heavy",
                                 f"enabled = {str(enabled).lower()}\n# Joern is memory-heavy"), encoding="utf-8")
    return load_config(path)


def _whole_program(tmp_path: Path):
    """These tests cover the whole-program path; seeded mode is covered by tests/test_seeded_*.py."""
    path = tmp_path / "appsec-review.toml"
    path.write_text(path.read_text(encoding="utf-8").replace('mode = "seeded"', 'mode = "whole_program"'),
                    encoding="utf-8")
    return load_config(path)


def _accepted_cpp(tmp_path: Path, *, max_cpg_bytes: int | None = None, joern: bool = True):
    from appsec_review.jobs.cataloging import source_fingerprint
    from tests.integration.job_language_build.test_language_build_graph import (
        AnalysisExecutor, _fixture, _native_producers, _never_rebuilt,
    )

    config, target = _fixture(tmp_path)
    _whole_program(tmp_path)
    # Joern is off by default; the CPG tests below exercise the explicitly enabled path.
    config = _with_joern(tmp_path, joern)
    if max_cpg_bytes is not None:
        config = _with_cpg_limit(tmp_path, max_cpg_bytes)
    fingerprint = source_fingerprint(target)
    producers = [
        *_native_producers(target, []),
        build_language(executor_factory=_never_rebuilt),
        build_cpp(executor_factory=lambda unit: AnalysisExecutor(unit.job.run_root)),
    ]
    outcome = GraphRunner(config, producers).run(target_root=target, source_fingerprint=fingerprint)
    assert outcome["status"] in {"SUCCEEDED", "COMPLETED_WITH_GAPS"}
    return config, target, outcome["run_id"], fingerprint


def _run(config, target, run_id, fingerprint, job, **options):
    return GraphRunner(config, [job]).run(target_root=target, source_fingerprint=fingerprint,
                                          run_id=run_id, **options)


def _outputs(outcome, job_id: str) -> dict:
    path = Path(outcome["jobs"][job_id]["attempt_root"]) / "result.json"
    return json.loads(path.read_text(encoding="utf-8"))["outputs"]


def _rows(run_root: Path, identity: dict, query: str) -> list[tuple]:
    with sqlite3.connect(run_root / identity["relative_path"]) as database:
        return database.execute(query).fetchall()


def test_registry_and_configuration_declare_both_independent_jobs() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "appsec-review.toml")
    registry = builtin_registry()
    for job_id, steps in (("job_cpp_symbol_index", ["load", "index", "acceptance"]),
                          ("job_cpg_analysis", ["load", "generate", "acceptance"])):
        assert registry.build(job_id).job_id == job_id
        assert list(config.job(job_id).steps) == steps
    assert "joern" not in config.job("job_cpp_compiled_analysis").steps


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


# --- CPG size limit enforced during generation, and strict checkpoint revalidation -----------------


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


def test_container_compile_database_accepts_a_project_at_the_target_root() -> None:
    # A CMakeLists.txt at the repository root is the project root ".", not an invalid root.
    rows = container_compile_database(".", [
        {"target_path": "src/add.c", "arguments": ["gcc", "-I/scratch/source/include"]},
    ])
    assert rows == [{"directory": "/target/source", "file": "/target/source/src/add.c",
                     "arguments": ["clang", "-I/target/source/include"]}]
    with pytest.raises(ValueError, match="outside the accepted project root"):
        container_compile_database(".", [{"target_path": "/etc/x.c", "arguments": ["cc"]}])
