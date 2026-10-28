"""Real repository SQLite-FTS helper CLI, without Docker, downloads or review services.

The two sanitized graph search documents are synthetic inputs, not real CodeQL output.
Only the selected Python helper is executed, never a compiled fixture or target binary.
"""
from __future__ import annotations

import ast
from collections import Counter
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

import pytest

from appsec_review.acceptance.lanes import LaneWorkspace
from appsec_review.storage import atomic_json, file_sha256
from tests.integration.test_graph_semantic_acceptance import ROOT, _timed_lane


HELPER = ROOT / "containers" / "tools" / "sqlite-fts" / "sqlite_fts.py"
DOCUMENTS = [
    {"identity": "graph:python:guarded", "name": "guarded command", "path": "src/app.py",
     "text": "dominating allowlist guard"},
    {"identity": "graph:python:unguarded", "name": "unguarded command", "path": "src/app.py",
     "text": "command execution near miss"},
]


def _fixture(workspace: LaneWorkspace):
    root = workspace.require_owned_path(workspace.root / "fixture")
    for name in ("input", "output", "home", "tmp"):
        (root / name).mkdir(parents=True)
    source = root / "input" / "documents.jsonl"
    _write_documents(source, DOCUMENTS)
    return root, source, root / "output" / "search.sqlite"


def _write_documents(path: Path, records) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")


def _run_helper(workspace: LaneWorkspace, label: str, *arguments: str):
    root = workspace.require_owned_path(workspace.root / "fixture")
    environment = {key: value for key, value in os.environ.items()
                   if key.upper() in {"SYSTEMROOT", "WINDIR", "COMSPEC"}}
    environment.update(workspace.environment())
    environment.update({
        "PATH": "", "HOME": str(root / "home"), "USERPROFILE": str(root / "home"),
        "TEMP": str(root / "tmp"), "TMP": str(root / "tmp"),
        "XDG_CACHE_HOME": str(root / "home"), "XDG_CONFIG_HOME": str(root / "home"),
    })
    argv = [sys.executable, "-I", "-B", str(HELPER), *arguments]
    with workspace.span("acceptance.local_helper_subprocess"):
        started = time.monotonic()
        completed = subprocess.run(
            argv, cwd=root, env=environment, stdin=subprocess.DEVNULL, capture_output=True,
            text=True, encoding="utf-8", timeout=30, check=False)
        elapsed = time.monotonic() - started
        assert elapsed < 30, f"helper elapsed cap exceeded: {elapsed:.3f}s"
        receipt = {
            "argv": argv, "helper_sha256": file_sha256(HELPER), "interpreter": sys.executable,
            "returncode": completed.returncode, "duration_ms": elapsed * 1000, "timeout_seconds": 30,
            "stdout": completed.stdout, "stderr": completed.stderr, "cwd": str(root),
        }
        atomic_json(workspace.driver_root / f"{label}.json", receipt)
        workspace.emit("ACCEPTANCE_HELPER_COMPLETED", **{key: value for key, value in receipt.items()
                                                       if key not in {"stdout", "stderr"}},
                       stdout_bytes=len(completed.stdout.encode("utf-8")),
                       stderr_bytes=len(completed.stderr.encode("utf-8")))
    return completed


def _build(workspace: LaneWorkspace, root: Path, source: Path, index: Path, *limits: str):
    return _run_helper(
        workspace, "build", "build", "--input", str(source), "--input-root", str(root / "input"),
        "--output", str(index), "--output-root", str(root / "output"), "--max-records", "4",
        "--max-input-bytes", "4096", "--max-text-bytes", "128", *limits)


def test_real_sqlite_helper_builds_verifies_and_queries_tiny_graph_documents() -> None:
    with _timed_lane("local-helper", cap_seconds=60) as workspace:
        root, source, index = _fixture(workspace)
        result = _build(workspace, root, source, index)
        assert result.returncode == 0, result.stderr
        built = json.loads(result.stdout)
        assert built["schema"] == "appsec-review/sqlite-fts-documents/1"
        assert built["record_count"] == 2 and built["input_sha256"] == file_sha256(source)
        assert Path(built["output"]) == index
        digest = file_sha256(index)
        checked = _run_helper(workspace, "verify", "verify", "--index", str(index),
                              "--input-root", str(root / "output"))
        assert checked.returncode == 0, checked.stderr
        assert json.loads(checked.stdout) == {
            "schema": built["schema"], "record_count": 2, "input_sha256": built["input_sha256"]}
        with sqlite3.connect(index.as_uri() + "?mode=ro", uri=True) as db:
            metadata = dict(db.execute("SELECT key, value FROM metadata"))
            assert metadata["tool_version"] == "1.0.0" and metadata["tokenizer"] == "unicode61"
            assert metadata["sqlite_version"] == built["sqlite_version"] == sqlite3.sqlite_version
            assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
            assert db.execute("SELECT identity, path FROM search_fts WHERE search_fts MATCH ?",
                              ("allowlist",)).fetchall() == [("graph:python:guarded", "src/app.py")]
            assert db.execute("SELECT identity FROM search_fts WHERE search_fts MATCH ?",
                              ("unguarded",)).fetchall() == [("graph:python:unguarded",)]
            assert db.execute("SELECT identity FROM search_fts WHERE search_fts MATCH ?",
                              ("compilerid",)).fetchall() == []
        assert file_sha256(index) == digest
        assert not index.with_suffix(".sqlite.building").exists()
        workspace.emit("ACCEPTANCE_HELPER_INDEX_VERIFIED", artifact_sha256=digest, record_count=2,
                       input_sha256=file_sha256(source), runtime=f"SQLite {sqlite3.sqlite_version}")


@pytest.mark.parametrize("invalid", [
    "duplicate-identity", "logical-path", "outside-input-root", "outside-output-root", "record-limit",
])
def test_real_sqlite_helper_rejects_bad_inputs_without_publishing(invalid: str) -> None:
    with _timed_lane("local-helper-negative", cap_seconds=60) as workspace:
        root, source, index = _fixture(workspace)
        limits = ()
        if invalid == "duplicate-identity":
            _write_documents(source, [DOCUMENTS[0], DOCUMENTS[0]])
            expected = "duplicate"
        elif invalid == "logical-path":
            _write_documents(source, [{**DOCUMENTS[0], "path": "..\\private.py"}])
            expected = "not logical and relative"
        elif invalid == "outside-input-root":
            source = root / "unrelated.jsonl"
            _write_documents(source, [DOCUMENTS[0]])
            expected = "path must stay under"
        elif invalid == "outside-output-root":
            index = root / "refused.sqlite"
            expected = "path must stay under"
        else:
            limits = ("--max-records", "1")
            expected = "input exceeds record limit"
        digest = file_sha256(source)
        completed = _build(workspace, root, source, index, *limits)
        assert completed.returncode == 2 and expected in completed.stderr
        assert not index.exists() and not index.with_suffix(".sqlite.building").exists()
        assert file_sha256(source) == digest


def test_real_sqlite_helper_detects_changed_record_count_read_only() -> None:
    with _timed_lane("local-helper-integrity", cap_seconds=60) as workspace:
        root, source, index = _fixture(workspace)
        built = _build(workspace, root, source, index)
        assert built.returncode == 0, built.stderr
        with sqlite3.connect(index) as db:
            db.execute("UPDATE metadata SET value = '3' WHERE key = 'record_count'")
        digest = file_sha256(index)
        completed = _run_helper(workspace, "verify", "verify", "--index", str(index),
                                "--input-root", str(root / "output"))
        assert completed.returncode == 2 and "record count mismatch" in completed.stderr
        assert file_sha256(index) == digest


def test_live_build_toolchain_definitions_cannot_silently_shadow_go_coverage() -> None:
    with _timed_lane("toolchain-definitions"):
        path = ROOT / "tests" / "test_live_build_toolchains.py"
        module = ast.parse(path.read_text(encoding="utf-8"))
        names = Counter(node.name for node in module.body
                        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)))
        assert names and all(count == 1 for count in names.values()), names
        assert {
            "_GoFixtureRecipeModel",
            "test_live_go_language_build_accepts_syscall_authoritative_capture",
            "test_live_go_capture_records_toolchain_execs_envp_and_dependency_egress",
            "test_live_go_language_build_detects_and_removes_an_envp_secret",
            "test_live_go_recipe_inference_is_validated_and_builds_the_fixture",
        } <= names.keys()
