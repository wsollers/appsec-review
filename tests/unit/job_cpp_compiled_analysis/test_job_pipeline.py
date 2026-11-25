"""Unit tests for job_cpp_compiled_analysis helpers, indexers, and all 9 unit handlers."""
from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Any
import pytest

from appsec_review.config.assurance import ComponentReleases, ReviewPolicy
from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.jobs.job_cpp_compiled_analysis import job as cpp_job
from appsec_review.retrieval import IndexIdentity, write_manifest
from appsec_review.storage import atomic_json, file_sha256


ROOT = Path(__file__).resolve().parents[3]
DIGEST = "sha256:" + "a" * 64


class _EventSink:
    def __init__(self) -> None:
        self.records: list[tuple[str, dict[str, Any]]] = []

    def write(self, event_type: str, **fields: Any) -> None:
        self.records.append((event_type, fields))


def _make_unit(
    tmp_path: Path,
    unit_id: str = "catalog.projects",
    *,
    outputs: dict[str, Any] | None = None,
    settings: dict[str, Any] | None = None,
    repository_root: Path | None = None,
    releases: dict[str, str] | None = None,
    consumable_handoffs: dict[str, Any] | None = None,
    upstream_handoffs: dict[str, Any] | None = None,
) -> Any:
    run_root = tmp_path / "run-unit-cpp"
    target_root = tmp_path / "target"
    run_root.mkdir(parents=True, exist_ok=True)
    target_root.mkdir(parents=True, exist_ok=True)
    unit_root = run_root / "units" / unit_id.replace(".", "-")
    unit_root.mkdir(parents=True, exist_ok=True)
    events = _EventSink()
    rel = releases if releases is not None else {
        "platform": "rel/1",
        "validation": "rel/1",
        "tool-native-cpp": "rel/1",
        "tool-infer": "rel/1",
    }
    store = dict(outputs or {})
    job_ctx = SimpleNamespace(
        job_id="job_cpp_compiled_analysis",
        run_id="run-unit-cpp",
        attempt_id="attempt-001",
        run_root=run_root,
        target_root=target_root,
        repository_root=repository_root if repository_root is not None else ROOT,
        source_fingerprint="f" * 64,
        config=SimpleNamespace(settings=settings if settings is not None else {"seeded": {"mode": "whole_program"}}),
        review_policy=ReviewPolicy(releases=ComponentReleases(rel)),
        events=events,
        consumable_handoffs=consumable_handoffs or {},
        upstream_handoffs=upstream_handoffs or {},
    )
    return SimpleNamespace(
        job=job_ctx,
        unit_id=unit_id,
        unit_root=unit_root,
        output=lambda name: store[name],
        _store=store,
    )


def _exec_result(run_root: Path, scratch_root: Path, tool_id: str = "tool-native-cpp",
                 exit_code: int = 0, *, timed_out: bool = False, oom_killed: bool = False) -> ExecutionResult:
    (scratch_root / "raw").mkdir(parents=True, exist_ok=True)
    stdout = scratch_root / "raw" / "stdout.bin"
    stderr = scratch_root / "raw" / "stderr.bin"
    exec_json = scratch_root / "execution.json"
    stdout.write_bytes(b"")
    stderr.write_bytes(b"")
    exec_json.write_text("{}", encoding="utf-8")
    rel = lambda p: p.relative_to(run_root).as_posix()
    return ExecutionResult(
        "appsec-review/container-execution/1", tool_id, "img:1", DIGEST, DIGEST,
        "argv", (), {}, "s", "e", exit_code, timed_out, oom_killed, False, False,
        rel(stdout), rel(stderr), rel(exec_json),
    )


def test_checkpoints_project_key_and_terminal_gap(tmp_path: Path) -> None:
    assert cpp_job._project_key(PurePosixPath("pkg/native")).startswith("project-")
    assert cpp_job._terminal_gap({"terminal_status": "SUCCEEDED", "family": "native",
                                  "native_compile_database": {"entry_count": 0}}) == (
        "capture-backed native compile database is empty"
    )
    assert cpp_job._terminal_gap({"terminal_status": "SUCCEEDED", "family": "native",
                                  "native_compile_database": {"entry_count": 2}}) is None
    assert cpp_job._terminal_gap({"terminal_status": "FAILED", "gaps": []}) == (
        "upstream C++ case action did not succeed"
    )

    # Checkpoint identity with repository catalog vs without catalog (injected_executor fallback).
    u_cat = _make_unit(tmp_path / "c1")
    u_nocat = _make_unit(tmp_path / "c2", repository_root=tmp_path / "empty-repo")
    id_cat = cpp_job._checkpoint_identity(u_cat, "case-1", "catalog", {"k": 1})
    id_nocat = cpp_job._checkpoint_identity(u_nocat, "case-1", "catalog", {"k": 1})
    assert id_cat != id_nocat

    # Missing release -> CHECKPOINT_MISSED event and None.
    u_norel = _make_unit(tmp_path / "c3", releases={})
    assert cpp_job._load_checkpoint(u_norel, "case-1", "branch-infer", "abc") is None
    assert u_norel.job.events.records[0][0] == "CHECKPOINT_MISSED"

    # Missing file, invalid JSON, wrong identity, non-SUCCEEDED skip on save & load, tampered artifact.
    assert cpp_job._load_checkpoint(u_cat, "case-1", "catalog", id_cat) is None
    ckpt_dir = cpp_job._case_root(u_cat, "case-1") / "checkpoints"
    ckpt_dir.mkdir(parents=True, exist_ok=True)
    ckpt_file = ckpt_dir / "catalog.json"
    ckpt_file.write_text("{bad json", encoding="utf-8")
    assert cpp_job._load_checkpoint(u_cat, "case-1", "catalog", id_cat) is None

    ckpt_file.write_text(json.dumps({"identity": "other", "result": {}}), encoding="utf-8")
    assert cpp_job._load_checkpoint(u_cat, "case-1", "catalog", id_cat) is None

    # _save_checkpoint ignores non-SUCCEEDED unless checkpointable=True.
    ckpt_file.unlink()
    cpp_job._save_checkpoint(u_cat, "case-1", "catalog", id_cat, {"terminal_status": "FAILED"})
    assert not ckpt_file.exists()

    # Non-SUCCEEDED in file without checkpointable=True rejected on load.
    ckpt_file.write_text(json.dumps({"identity": id_cat, "result": {"terminal_status": "FAILED"}}), encoding="utf-8")
    assert cpp_job._load_checkpoint(u_cat, "case-1", "catalog", id_cat) is None

    # Valid SUCCEEDED with artifact -> loads with checkpoint_reused=True; tampered artifact -> None.
    art_path = u_cat.job.run_root / "data" / "art.json"
    art_path.parent.mkdir(parents=True, exist_ok=True)
    art_path.write_text("{}", encoding="utf-8")
    art_meta = cpp_job._artifact(u_cat.job.run_root, art_path)
    cpp_job._save_checkpoint(u_cat, "case-1", "catalog", id_cat,
                             {"terminal_status": "SUCCEEDED", "art": art_meta})
    reused = cpp_job._load_checkpoint(u_cat, "case-1", "catalog", id_cat)
    assert reused is not None and reused["checkpoint_reused"] is True
    art_path.write_text('{"tampered": true}', encoding="utf-8")
    assert cpp_job._load_checkpoint(u_cat, "case-1", "catalog", id_cat) is None


def test_compile_and_link_normalization_edge_cases(tmp_path: Path) -> None:
    case_root = tmp_path / "case"
    (case_root / "source").mkdir(parents=True)
    (case_root / "build").mkdir(parents=True)

    # _raw_compile_db: missing raises, source fallback works.
    with pytest.raises(ValueError, match="without compile_commands.json"):
        cpp_job._raw_compile_db(case_root)
    (case_root / "source" / "compile_commands.json").write_text("[]", encoding="utf-8")
    assert cpp_job._raw_compile_db(case_root) == case_root / "source" / "compile_commands.json"

    # _mapped_path: exact /scratch/source, case_root/source, subpaths, and unmatched.
    assert cpp_job._mapped_path("/scratch/source", case_root, ".") == "."
    assert cpp_job._mapped_path(str(case_root / "source"), case_root, "pkg") == "pkg"
    assert cpp_job._mapped_path(str(case_root / "source" / "sub" / "a.c"), case_root, "pkg") == "pkg/sub/a.c"
    assert cpp_job._mapped_path("/unrelated/file.c", case_root, ".") == "/unrelated/file.c"

    # _raw_arguments validation errors.
    with pytest.raises(ValueError, match="bounded command or arguments form"):
        cpp_job._raw_arguments({"command": "x" * 131073})
    with pytest.raises(ValueError, match="arguments are invalid"):
        cpp_job._raw_arguments({"arguments": []})
    with pytest.raises(ValueError, match="arguments are invalid"):
        cpp_job._raw_arguments({"arguments": ["clang", "bad\x00arg"]})

    # _sanitize_arguments: .c driver, drop_paired (-o, -MF), drop (-c, -MMD), paired (-I dir), mapped path.
    sanitized = cpp_job._sanitize_arguments(
        {"arguments": ["gcc", "-c", "-MMD", "-MF", "a.d", "-o", "a.o",
                       "-I", str(case_root / "source" / "inc"),
                       f"-I{case_root / 'source'}", "-DDEBUG=1", "/scratch/source/a.c"]},
        case_root, "/scratch/source/a.c", "pkg",
    )
    assert sanitized[0] == "clang-18"
    assert "-I" in sanitized and "/scratch/source/inc" in sanitized
    assert "-I/scratch/source" in sanitized
    assert "-DDEBUG=1" in sanitized and sanitized[-1] == "/scratch/source/a.c"

    # _output_path: explicit output field, -o relative, /scratch/build, workspace_root/build, outside returns None.
    assert cpp_job._output_path({"arguments": ["clang", "a.c"], "output": "objs/a.o",
                                 "directory": "/scratch/build"}, case_root, ".") == "build/objs/a.o"
    assert cpp_job._output_path({"arguments": ["clang", "-o", "build", "a.c"],
                                 "directory": "/scratch"}, case_root, ".") == "build"
    assert cpp_job._output_path({"arguments": ["clang", "-o", "/scratch/build/x.o", "a.c"]},
                                case_root, ".") == "build/x.o"
    assert cpp_job._output_path({"arguments": ["clang", "-o", "/workspace/pkg/build/y.o", "a.c"]},
                                case_root, "pkg") == "build/y.o"
    assert cpp_job._output_path({"arguments": ["clang", "a.c"]}, case_root, ".") is None
    assert cpp_job._output_path({"arguments": ["clang", "-o", "/etc/outside.o", "a.c"]},
                                case_root, ".") is None

    # normalize_link_commands: non-list, unknown output, self-link ignored, empty inputs skipped.
    assert cpp_job.normalize_link_commands("not-a-list", []) == []
    outputs = [
        {"path": "build/app", "kind": "executable"},
        {"path": "build/a.o", "kind": "object"},
    ]
    links = cpp_job.normalize_link_commands([
        "not-a-dict",
        {"output_path": "unknown/out", "input_paths": ["build/a.o"]},
        {"output_path": "build/app", "input_paths": ["build/app"]},
        {"output_path": "build/app", "input_paths": ["build/a.o", "missing.o"],
         "receipt": "r1", "command_sha256": "c1"},
    ], outputs)
    assert links == [{"output_path": "build/app", "input_paths": ["build/a.o"],
                      "receipt": "r1", "command_sha256": "c1"}]

    # normalize_compile_db errors: empty, non-mapping item, -cc1 skipped, fallback suffix unique vs ambiguous, missing mapping.
    mapping = {
        "project_key": "proj-norm",
        "project_id": "cpp:.",
        "case_snapshot": "0" * 64,
        "root": ".",
        "files": [
            {"scratch_path": "source/dir1/dup.cpp", "target_path": "dir1/dup.cpp", "sha256": "1" * 64},
            {"scratch_path": "source/dir2/dup.cpp", "target_path": "dir2/dup.cpp", "sha256": "2" * 64},
            {"scratch_path": "source/unique.c", "target_path": "unique.c", "sha256": "3" * 64},
        ],
    }
    db_path = case_root / "build" / "compile_commands.json"
    db_path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="must contain 1..4096 entries"):
        cpp_job.normalize_compile_db(case_root, mapping)

    db_path.write_text(json.dumps(["bad"]), encoding="utf-8")
    with pytest.raises(ValueError, match="malformed"):
        cpp_job.normalize_compile_db(case_root, mapping)

    # A display suffix outside accepted source/build context cannot admit a source.
    db_path.write_text(json.dumps([
        {"directory": "/ext", "file": "/ext/unique.c", "arguments": ["clang", "-cc1", "unique.c"]},
        {"directory": "/ext", "file": "/ext/sub/unique.c", "command": "gcc -c /ext/sub/unique.c -o unique.o"},
    ]), encoding="utf-8")
    with pytest.raises(ValueError, match="outside accepted"):
        cpp_job.normalize_compile_db(case_root, mapping)
    db_path.write_text(json.dumps([
        {"directory": "/scratch/source", "file": "unique.c", "arguments": ["clang", "-cc1", "unique.c"]},
        {"directory": "/scratch/source", "file": "unique.c", "command": "gcc -c unique.c -o unique.o"},
    ]), encoding="utf-8")
    norm = cpp_job.normalize_compile_db(case_root, mapping)
    assert len(norm) == 1 and norm[0]["target_path"] == "unique.c"

    # Ambiguous suffix match raises.
    db_path.write_text(json.dumps([
        {"directory": "/ext", "file": "/ext/dup.cpp", "command": "g++ -c /ext/dup.cpp"},
    ]), encoding="utf-8")
    with pytest.raises(ValueError, match="outside accepted"):
        cpp_job.normalize_compile_db(case_root, mapping)

    # Unmapped file raises.
    db_path.write_text(json.dumps([
        {"directory": "/scratch/source", "file": "/scratch/source/ghost.cpp", "command": "g++ -c ghost.cpp"},
    ]), encoding="utf-8")
    with pytest.raises(ValueError, match="not in the accepted case mapping"):
        cpp_job.normalize_compile_db(case_root, mapping)


def test_replay_failures_and_ast_document_helpers(tmp_path: Path) -> None:
    root = tmp_path / "case"
    ast_dir = root / "analysis" / "ast"
    ast_dir.mkdir(parents=True)
    cmds = [{"target_path": "a.cpp"}, {"target_path": "b.cpp"}]

    # Missing, invalid JSON, wrong length, invalid index.
    assert cpp_job.replay_failures(root, "ast", cmds) is None
    receipt = ast_dir / "receipt.json"
    receipt.write_text("{invalid", encoding="utf-8")
    assert cpp_job.replay_failures(root, "ast", cmds) is None
    receipt.write_text(json.dumps([{"index": 0, "exit_code": 0}]), encoding="utf-8")
    assert cpp_job.replay_failures(root, "ast", cmds) is None
    receipt.write_text(json.dumps([{"index": 99, "exit_code": 0}, {"index": 1, "exit_code": 0}]), encoding="utf-8")
    assert cpp_job.replay_failures(root, "ast", cmds) is None

    # Timeout, missing header ('x.h' file not found), error keyword line, and generic exit without 'error'.
    receipt.write_text(json.dumps([
        {"index": 0, "timeout": True, "exit_code": 124},
        {"index": 1, "exit_code": 1, "stderr": "fatal error: 'missing_hdr.h' file not found\n"},
    ]), encoding="utf-8")
    failures = cpp_job.replay_failures(root, "ast", cmds)
    assert failures is not None
    assert "timed out" in failures[0]
    assert "header not found in tool-native-cpp: missing_hdr.h" in failures[1]

    receipt.write_text(json.dumps([
        {"index": 0, "exit_code": 1, "stderr": "note: x\nfatal error: bad syntax\n"},
        {"index": 1, "exit_code": 2, "stderr": "first line without keyword\n"},
    ]), encoding="utf-8")
    failures2 = cpp_job.replay_failures(root, "ast", cmds)
    assert failures2 is not None
    assert "exit 1: fatal error: bad syntax" in failures2[0]
    assert failures2[1] == "b.cpp: ast replay failed with exit 2"

    # _load_ast_document: whitespace-only raises, non-object JSON raises, concatenated objects merge,
    # _callee_decl resolves nested member ref and depth limit.
    empty_ast = tmp_path / "empty.json"
    empty_ast.write_text("   \n  ", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        cpp_job._load_ast_document(empty_ast)

    list_ast = tmp_path / "list.json"
    list_ast.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(ValueError, match="not an object"):
        cpp_job._load_ast_document(list_ast)

    multi_ast = tmp_path / "multi.json"
    multi_ast.write_text('{"kind": "TranslationUnitDecl", "inner": [{"kind": "FunctionDecl", "name": "f1"}]}\n'
                         '{"kind": "TranslationUnitDecl", "inner": [{"kind": "FunctionDecl", "name": "f2"}]}',
                         encoding="utf-8")
    merged = cpp_job._load_ast_document(multi_ast)
    assert merged["kind"] == "TranslationUnitDecl" and len(merged["inner"]) == 2

    nested_call = {
        "kind": "CallExpr",
        "inner": [{
            "kind": "ImplicitCastExpr",
            "inner": [{"kind": "MemberExpr", "referencedMemberDecl": {"id": "0x99", "name": "send"}}],
        }],
    }
    assert cpp_job._callee_decl(nested_call) == {"id": "0x99", "name": "send"}
    deep_call = {"kind": "CallExpr", "inner": [{"inner": [{"inner": [{"inner": [{"inner": [{"referencedDecl": {"id": "0x1"}}]}]}]}]}]}
    assert cpp_job._callee_decl(deep_call) is None
    assert cpp_job._callee_decl({"kind": "VarDecl"}) is None


def test_run_tool_and_run_infer_container_wrappers(tmp_path: Path, monkeypatch) -> None:
    unit = _make_unit(tmp_path)
    case_id = "project-wrap"
    case_root = cpp_job._case_root(unit, case_id)
    (case_root / "source").mkdir(parents=True)
    (case_root / "build").mkdir(parents=True)
    stale = case_root / "analysis" / "infer-run" / "old.txt"
    stale.parent.mkdir(parents=True)
    stale.write_text("stale", encoding="utf-8")

    # Exercise default ContainerExecutor branch via monkeypatch (no Docker calls).
    class FakeContainerExecutor:
        def __init__(self, catalog, run_root) -> None:
            self.run_root = run_root

        def execute(self, request):
            if request.tool_id == "tool-infer":
                out = request.scratch_root / "infer-out"
                out.mkdir(parents=True, exist_ok=True)
                (out / "report.json").write_text("[]", encoding="utf-8")
            return _exec_result(self.run_root, request.scratch_root, request.tool_id)

    monkeypatch.setattr(cpp_job, "ContainerExecutor", FakeContainerExecutor)
    tool_res = cpp_job._run_tool(unit, case_id, ("ast",), executor_factory=None)
    assert tool_res["exit_code"] == 0

    cataloged = {"mapping": {"root": "."},
                 "compile_commands": [{"directory": "/scratch/source", "file": "/scratch/source/a.c",
                                       "target_path": "a.c",
                                       "arguments": ["clang-18", "-c", "/scratch/source/a.c"]}]}
    infer_res = cpp_job._run_infer(unit, case_id, cataloged, executor_factory=None)
    assert not stale.exists()
    assert isinstance(infer_res["report"], dict)


def test_native_analysis_actions_and_unbuilt_gap(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "cpp_pkg").mkdir(parents=True)
    (target / "cpp_pkg" / "main.cpp").write_text("int main() { return 0; }\n", encoding="utf-8")
    (target / "py_ext").mkdir(parents=True)
    (target / "py_ext" / "mod.c").write_text("int mod(void) { return 1; }\n", encoding="utf-8")
    (target / "pure_js").mkdir(parents=True)
    (target / "pure_js" / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")

    accepted = {
        "language_build_handoff_sha256": "h" * 64,
        "receipts": [
            # Pure JS skipped.
            {"family": "javascript", "root": "pure_js", "build_unit_id": "js-1", "terminal_status": "SUCCEEDED"},
            # Mixed family with captured native_compile_database included!
            {"family": "python", "root": "py_ext", "build_unit_id": "py-1", "build_system": "setuptools",
             "terminal_status": "SUCCEEDED",
             "native_compile_database": {"entry_count": 1, "path": "db.json", "sha256": "1" * 64},
             "native_components": [{"kind": "c-ext"}]},
            # Native directory with no C/C++ files skipped.
            {"family": "native", "root": "pure_js", "build_unit_id": "empty-native", "terminal_status": "FAILED"},
            # Unbuilt native project (no workspace) included with origin "unavailable".
            {"family": "native", "root": "cpp_pkg", "build_unit_id": "cpp-1", "build_system": "cmake",
             "terminal_status": "FAILED",
             "upstream_failure": {"job_id": "job_project_build", "terminal_status": "FAILED", "reason": "cmake missing"}},
        ],
    }
    actions = cpp_job.native_analysis_actions(accepted, target)
    by_id = {a["build_unit_id"]: a for a in actions}
    assert set(by_id) == {"py-1", "cpp-1"}
    assert by_id["py-1"]["compile_database_origin"] == "captured-native-components"
    assert by_id["cpp-1"]["compile_database_origin"] == "unavailable"

    # Validation errors on native_analysis_actions.
    with pytest.raises(ValueError, match="lacks a capture-backed compile database"):
        cpp_job.native_analysis_actions({
            "language_build_handoff_sha256": "h" * 64,
            "receipts": [{"family": "native", "workspace": "ws", "root": "cpp_pkg", "build_unit_id": "x"}],
        }, target)

    with pytest.raises(ValueError, match="root is invalid"):
        cpp_job.native_analysis_actions({
            "language_build_handoff_sha256": "h" * 64,
            "receipts": [{"family": "native", "root": "../escape", "build_unit_id": "x"}],
        }, target)

    outside = tmp_path / "outside_dir"
    outside.mkdir()
    (target / "escape_link").symlink_to(outside)
    with pytest.raises(ValueError, match="escapes the target"):
        cpp_job.native_analysis_actions({
            "language_build_handoff_sha256": "h" * 64,
            "receipts": [{"family": "native", "root": "escape_link", "build_unit_id": "x"}],
        }, target)

    # unbuilt_native_gap: upstream_failure vs fallback gaps vs no reason recorded.
    g1 = cpp_job.unbuilt_native_gap(by_id["cpp-1"]["receipt"], "cpp_pkg")
    assert "job_project_build (FAILED): cmake missing" in g1
    g2 = cpp_job.unbuilt_native_gap({"build_unit_id": "u2", "terminal_status": "FAILED", "gaps": []}, "cpp_pkg")
    assert "job_language_build (FAILED): no reason recorded" in g2


def _stage_language_build(run_root: Path, target_root: Path, fingerprint: str) -> dict[str, Any]:
    """Create a realistic accepted job_language_build handoff with 1 built project + 1 unbuilt project."""
    # Project 1: built native project (app) with two translation units + native_components origin
    app_src = target_root / "app"
    app_src.mkdir(parents=True, exist_ok=True)
    (app_src / "main.cpp").write_text("int helper(); int main() { return helper(); }\n", encoding="utf-8")
    (app_src / "helper.cpp").write_text("int helper() { return 42; }\n", encoding="utf-8")

    # Project 2: unbuilt native project (broken) with a .git file to exercise .git skip in _unbuilt_project
    broken_src = target_root / "broken"
    (broken_src / ".git").mkdir(parents=True, exist_ok=True)
    (broken_src / ".git" / "ignored.c").write_text("int ig;\n", encoding="utf-8")
    (broken_src / "broken.cpp").write_text("int broken() { return 0; }\n", encoding="utf-8")

    # Materialize workspace + build outputs (.o, .a, ELF executable, link commands) + workspace_manifest
    ws = run_root / "data" / "language_build" / "workspaces" / "proj-app"
    (ws / "build").mkdir(parents=True, exist_ok=True)
    (ws / "build" / "main.o").write_bytes(b"OBJ1")
    (ws / "build" / "libhelper.a").write_bytes(b"LIB1")
    (ws / "build" / "app_bin").write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
    (ws / "build" / "notes.txt").write_text("ignored non-elf", encoding="utf-8")
    (ws / "build" / ".appsec-review-link-commands.json").write_text(json.dumps([
        {"output_path": "build/app_bin", "input_paths": ["build/main.o", "build/libhelper.a"],
         "receipt": "link-0", "command_sha256": "d" * 64},
    ]), encoding="utf-8")

    ws_files = {
        p.relative_to(ws).as_posix(): file_sha256(p)
        for p in ws.rglob("*") if p.is_file()
    }
    ws_manifest_path = run_root / "data" / "language_build" / "ws-manifest-app.json"
    atomic_json(ws_manifest_path, {"schema": "appsec-review/build-workspace-manifest/1", "files": ws_files})

    # Capture-backed native compile database document
    native_db_path = run_root / "data" / "language_build" / "native-db-app.json"
    atomic_json(native_db_path, {
        "schema": "appsec-review/native-component-compile-database/2",
        "entries": [
            {"directory": "/workspace/app", "file": "/workspace/app/main.cpp",
             "arguments": ["clang++", "-c", "/workspace/app/main.cpp", "-o", "/workspace/build/main.o"],
             "output": "/workspace/build/main.o"},
            {"directory": "/workspace/app", "file": "/workspace/app/helper.cpp",
             "arguments": ["clang++", "-c", "/workspace/app/helper.cpp", "-o", "/workspace/build/helper.o"],
             "output": "/workspace/build/helper.o"},
        ],
    })

    extra_art = run_root / "data" / "language_build" / "build-log.txt"
    extra_art.parent.mkdir(parents=True, exist_ok=True)
    extra_art.write_text("ok\n", encoding="utf-8")

    receipt_app = {
        "schema": "appsec-review/language-build-receipt/1",
        "build_unit_id": "proj-app",
        "family": "native",
        "build_system": "cmake",
        "root": "app",
        "terminal_status": "SUCCEEDED",
        "fingerprint": "b" * 64,
        "workspace": ws.relative_to(run_root).as_posix(),
        "workspace_manifest": {
            "path": ws_manifest_path.relative_to(run_root).as_posix(),
            "sha256": file_sha256(ws_manifest_path),
        },
        "native_compile_database": {
            "path": native_db_path.relative_to(run_root).as_posix(),
            "sha256": file_sha256(native_db_path),
            "entry_count": 2,
        },
        "recipe": {"build_dir": "build"},
        "link_database": {**cpp_job._artifact(run_root, ws / "build/.appsec-review-link-commands.json"),
                          "relationship_count": 1},
        "image": {"image_id": DIGEST},
        "artifacts": [{"path": extra_art.relative_to(run_root).as_posix(), "sha256": file_sha256(extra_art)}],
        "gaps": [],
    }
    receipt_broken = {
        "schema": "appsec-review/language-build-receipt/1",
        "build_unit_id": "proj-broken",
        "family": "native",
        "build_system": "make",
        "root": "broken",
        "terminal_status": "FAILED",
        "fingerprint": "c" * 64,
        "gaps": ["make failed"],
    }

    _write_language_build_handoff(run_root, fingerprint, [receipt_app, receipt_broken])
    return {"ws": ws, "ws_manifest_path": ws_manifest_path, "native_db_path": native_db_path, "extra_art": extra_art}


def _write_language_build_handoff(run_root: Path, fingerprint: str, receipts: list[dict[str, Any]]) -> None:
    from appsec_review.interchange import (
        HANDOFF_SCHEMA, handoff_input_projection, input_set_sha256,
    )

    summary_path = run_root / "data" / "language_build" / "summary.json"
    atomic_json(summary_path, {
        "schema": "appsec-review/language-build-handoff/2",
        "source_fingerprint": fingerprint,
        "receipts": receipts,
    })
    outcomes_path = run_root / "data" / "jobs" / "job_language_build" / "attempts" / "attempt_001" / "outcomes.json"
    atomic_json(outcomes_path, {"schema": "appsec-review/outcomes/1", "items": []})
    sum_ref = {
        "path": summary_path.relative_to(run_root).as_posix(),
        "sha256": file_sha256(summary_path),
        "size_bytes": summary_path.stat().st_size,
    }
    out_ref = {
        "path": outcomes_path.relative_to(run_root).as_posix(),
        "sha256": file_sha256(outcomes_path),
        "size_bytes": outcomes_path.stat().st_size,
    }
    envelope: dict[str, Any] = {
        "schema": HANDOFF_SCHEMA,
        "run_id": run_root.name,
        "job_id": "job_language_build",
        "attempt_id": "attempt_001",
        "status": "ACCEPTED",
        "completion_status": "COMPLETED_WITH_GAPS" if receipts else "NOT_APPLICABLE",
        "execution_status": "SUCCEEDED",
        "outputs": {"acceptance.publish_handoff": {"artifact": sum_ref}},
        "artifacts": [sum_ref, out_ref],
        "upstream_handoff_sha256": {},
        "resolved_config_sha256": "1" * 64,
        "job_config_sha256": "2" * 64,
        "source_fingerprint": fingerprint,
        "target_snapshot": fingerprint,
        "implementation_identity": "impl/1",
        "schema_identity": "appsec-review/language-build-handoff/2",
        "validation_identity": "val/1",
        "tool_identity": {},
        "input_identity": None,
        "input_manifest": None,
        "dataset_contract_sha256": "3" * 64,
        "input_set_sha256": "0" * 64,
        "coverage": {"disposition": "partial" if receipts else "not_applicable", "gap_count": 0, "retry_required": False},
        "outcomes": out_ref,
        "resolving_paths": {},
        "started_at": "2026-01-01T00:00:00Z",
        "completed_at": "2026-01-01T00:00:01Z",
    }
    envelope["input_set_sha256"] = input_set_sha256(handoff_input_projection(envelope))
    handoff_path = run_root / "data" / "jobs" / "job_language_build" / "attempts" / "attempt_001" / "handoff.json"
    atomic_json(handoff_path, envelope)
    atomic_json(run_root / "data" / "jobs" / "job_language_build" / "latest.json", {
        "attempt_id": "attempt_001",
        "handoff_path": handoff_path.relative_to(run_root).as_posix(),
        "handoff_sha256": file_sha256(handoff_path),
    })


def _prepared_catalog_inputs(tmp_path, *, nested_sources=False, external_links=False):
    unit = _make_unit(tmp_path, repository_root=tmp_path / "empty-repo")
    staged = _stage_language_build(unit.job.run_root, unit.job.target_root, unit.job.source_fingerprint)
    if nested_sources:
        for directory in ("src/build", "src/target"):
            path = unit.job.target_root / "app" / directory / "valid.cpp"
            path.parent.mkdir(parents=True)
            path.write_text("int valid() { return 1; }\n")
    summary = json.loads((unit.job.run_root / "data/language_build/summary.json").read_text())
    receipt = summary["receipts"][0]
    if external_links:
        local = staged["ws"] / "build/.appsec-review-link-commands.json"
        accepted = unit.job.run_root / "data/language_build/accepted-links.json"
        local.rename(accepted)
        receipt["link_database"] = {**cpp_job._artifact(unit.job.run_root, accepted), "relationship_count": 1}
        atomic_json(staged["ws_manifest_path"], {
            "schema": "appsec-review/build-workspace-manifest/1",
            "files": {p.relative_to(staged["ws"]).as_posix(): file_sha256(p)
                      for p in staged["ws"].rglob("*") if p.is_file()},
        })
        receipt["workspace_manifest"]["sha256"] = file_sha256(staged["ws_manifest_path"])
    _write_language_build_handoff(unit.job.run_root, unit.job.source_fingerprint, summary["receipts"])
    handlers = {item.unit_id: item.handler for item in cpp_job.build_job().units}
    unit._store["plan.accepted_cpp_plan"] = handlers["plan.accepted_cpp_plan"](unit)
    unit._store["prepare.projects"] = handlers["prepare.projects"](unit)
    return unit, handlers


def test_catalog_consumes_accepted_link_database_and_invalidates_changed_input(tmp_path):
    unit, handlers = _prepared_catalog_inputs(tmp_path, external_links=True)
    first = handlers["catalog.projects"](unit)["projects"]["proj-app"]
    assert first["link_commands"][0]["input_paths"] == ["build/libhelper.a", "build/main.o"]
    assert handlers["catalog.projects"](unit)["projects"]["proj-app"]["checkpoint_reused"]
    old_path = unit.job.run_root / first["link_database"]["path"]
    old_bytes = old_path.read_bytes()
    receipt = unit._store["prepare.projects"]["projects"]["proj-app"]["build_receipt"]
    changed = unit.job.run_root / "data/language_build/accepted-links-v2.json"
    atomic_json(changed, [{**first["link_commands"][0], "input_paths": ["build/main.o"]}])
    receipt["link_database"] = {**cpp_job._artifact(unit.job.run_root, changed), "relationship_count": 1}
    second = handlers["catalog.projects"](unit)["projects"]["proj-app"]
    assert not second.get("checkpoint_reused")
    assert second["link_commands"][0]["input_paths"] == ["build/main.o"]
    assert old_path.read_bytes() == old_bytes
    changed.write_text("[]")
    with pytest.raises(ValueError, match="link.*identity changed"):
        handlers["catalog.projects"](unit)


def test_prepare_retains_real_sources_named_build_and_target(tmp_path):
    unit, _ = _prepared_catalog_inputs(tmp_path, nested_sources=True)
    mapping = unit._store["prepare.projects"]["projects"]["proj-app"]["mapping"]
    paths = {row["target_path"] for row in mapping["files"]}
    assert {"app/src/build/valid.cpp", "app/src/target/valid.cpp"} <= paths


def test_compile_relationship_gap_reaches_branch_and_published_summary(tmp_path):
    unit, handlers = _prepared_catalog_inputs(tmp_path)
    catalog = handlers["catalog.projects"](unit)
    good = catalog["projects"]["proj-app"]
    good["outputs"], good["link_commands"] = [], []
    unit._store["catalog.projects"] = {"projects": {"proj-app": good}}
    output = handlers["compiled.projects"](unit)
    result = output["projects"]["proj-app"]
    assert result["terminal_status"] == output["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any("no exact compile-output" in gap for gap in output["gaps"])
    upstream = unit.job.run_root / "upstream.json"
    write_manifest(upstream, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                   target_root=unit.job.target_root, indexes=[])
    unit.job.input_manifest_path, unit.job.input_manifest_sha256 = upstream, file_sha256(upstream)
    unit._store.update({f"{name}.projects": {"projects": {}} for name in cpp_job.BRANCHES})
    unit._store["compiled.projects"] = output
    published = handlers["acceptance.publish_handoff"](unit)
    summary = json.loads((unit.job.run_root / published["artifact"]["path"]).read_text())
    assert published["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any("no exact compile-output" in gap for gap in summary["gaps"])


def test_scope_rechecks_generated_build_bytes_and_accepted_command_context(tmp_path):
    from appsec_review.jobs.cpp_index_scopes import _scope
    unit, handlers = _prepared_catalog_inputs(tmp_path)
    catalog = handlers["catalog.projects"](unit)["projects"]["proj-app"]
    scope = _scope(unit.job.run_root, "proj-app", catalog)
    assert scope.container_compile_database()[0]["directory"] == "/target/source"
    catalog["compile_commands"][0]["directory"] = "/scratch/build"
    with pytest.raises(ValueError, match="command context differs"):
        _scope(unit.job.run_root, "proj-app", catalog)
    catalog["compile_commands"][0]["directory"] = "/scratch/source"
    (scope.case_root / "build/notes.txt").write_text("changed include context")
    with pytest.raises(ValueError, match="build context changed"):
        _scope(unit.job.run_root, "proj-app", catalog)


@pytest.mark.parametrize("tamper_after_cache", [False, True], ids=["catalog-cache", "before-execution"])
def test_native_replay_reconstructs_commands_from_the_accepted_immutable_catalog(tmp_path, tamper_after_cache):
    import importlib.util
    unit, handlers = _prepared_catalog_inputs(tmp_path)
    original = handlers["catalog.projects"](unit)["projects"]["proj-app"]
    immutable = unit.job.run_root / original["compile_database"]["path"]
    accepted_bytes = immutable.read_bytes()
    accepted = json.loads(accepted_bytes)
    root = cpp_job._case_root(unit, "proj-app")
    mutable = root / "normalized-compile-commands.json"

    def tamper():
        changed = json.loads(accepted_bytes)
        changed[0]["arguments"].insert(1, "-DREVIEW_DIFFERENT_CODE=1")
        mutable.write_text(json.dumps(changed))

    tamper()
    cached = handlers["catalog.projects"](unit)["projects"]["proj-app"]
    assert cached["checkpoint_reused"]
    if tamper_after_cache:
        tamper()
    unit._store["catalog.projects"] = {"projects": {"proj-app": cached}}
    observed = []
    spec = importlib.util.spec_from_file_location("native_replay_authority", ROOT / "containers/tools/native-cpp/native.py")
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)

    class Replay:
        def execute(self, request):
            driver.ROOT = request.scratch_root
            commands = driver.load_commands("ast")
            observed.extend(commands)
            destination = request.scratch_root / "analysis/ast"
            destination.mkdir(parents=True, exist_ok=True)
            for index in range(len(commands)):
                atomic_json(destination / f"tu-{index:04d}.json", {"kind": "TranslationUnitDecl", "inner": []})
            atomic_json(destination / "receipt.json", [
                {"index": index, "source": row["file"], "exit_code": 0}
                for index, row in enumerate(commands)])
            return _exec_result(unit.job.run_root, request.scratch_root)

    replay_handlers = {item.unit_id: item.handler for item in cpp_job.build_job(executor_factory=lambda _: Replay()).units}
    result = replay_handlers["ast.projects"](unit)["projects"]["proj-app"]
    assert result["terminal_status"] == "SUCCEEDED"
    assert observed == accepted
    assert json.loads(mutable.read_text()) == accepted
    assert immutable.read_bytes() == accepted_bytes
    assert cached["compile_commands"] == original["compile_commands"]


def test_native_replay_rejects_changed_immutable_command_authority(tmp_path):
    unit, handlers = _prepared_catalog_inputs(tmp_path)
    catalog = handlers["catalog.projects"](unit)["projects"]["proj-app"]
    immutable = unit.job.run_root / catalog["compile_database"]["path"]
    changed = json.loads(immutable.read_text())
    changed[0]["arguments"].insert(1, "-DREVIEW_DIFFERENT_CODE=1")
    immutable.write_text(json.dumps(changed))
    unit._store["catalog.projects"] = {"projects": {"proj-app": catalog}}
    executions = []

    def forbidden(_unit):
        executions.append(True)
        raise AssertionError("an invalid immutable command set must be rejected before native execution")

    replay = {item.unit_id: item.handler for item in cpp_job.build_job(executor_factory=forbidden).units}
    with pytest.raises(ValueError, match="accepted compile database.*changed"):
        replay["ast.projects"](unit)
    assert executions == []


def test_partially_missing_link_inputs_keep_valid_edges_and_publish_the_gap(tmp_path):
    import sqlite3
    unit, handlers = _prepared_catalog_inputs(tmp_path)
    receipt = unit._store["prepare.projects"]["projects"]["proj-app"]["build_receipt"]
    links = unit.job.run_root / "data/language_build/partial-links.json"
    atomic_json(links, [{"output_path": "build/app_bin",
                        "input_paths": ["build/main.o", "build/missing.o"]}])
    receipt["link_database"] = {**cpp_job._artifact(unit.job.run_root, links), "relationship_count": 1}
    catalog = handlers["catalog.projects"](unit)["projects"]["proj-app"]
    assert catalog["link_commands"][0]["input_paths"] == ["build/main.o"]
    assert any("build/missing.o" in gap and "build/app_bin" in gap for gap in catalog["gaps"])
    unit._store["catalog.projects"] = {"projects": {"proj-app": catalog}}
    output = handlers["compiled.projects"](unit)
    result = output["projects"]["proj-app"]
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    with sqlite3.connect(unit.job.run_root / result["artifact"]["path"]) as db:
        assert db.execute("select count(*) from relations where kind='LINKS_INTO'").fetchone()[0] == 1
    upstream = unit.job.run_root / "partial-link-upstream.json"
    write_manifest(upstream, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                   target_root=unit.job.target_root, indexes=[])
    unit.job.input_manifest_path, unit.job.input_manifest_sha256 = upstream, file_sha256(upstream)
    unit._store.update({f"{name}.projects": {"projects": {}} for name in cpp_job.BRANCHES})
    unit._store["compiled.projects"] = output
    published = handlers["acceptance.publish_handoff"](unit)
    summary = json.loads((unit.job.run_root / published["artifact"]["path"]).read_text())
    assert published["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert any("build/missing.o" in gap for gap in summary["gaps"])


def test_full_whole_program_pipeline_units_and_publish(tmp_path: Path) -> None:
    base = _make_unit(tmp_path, "plan.accepted_cpp_plan")
    _stage_language_build(base.job.run_root, base.job.target_root, base.job.source_fingerprint)

    # Upstream context manifest with one non-cpp index ("graph") and one stale cpp index ("build").
    from appsec_review.retrieval import IndexBuilder
    prior_shard = base.job.run_root / "data" / "indices" / "graph" / "prior.sqlite"
    prior_sha, _ = IndexBuilder(
        prior_shard, name="graph", fingerprint="p" * 64,
        target_snapshot=base.job.source_fingerprint, shard_id="prior-shard",
    ).build_or_reuse()
    prior_idx = IndexIdentity(
        "graph", "appsec-review/retrieval-index/2", prior_sha, "p" * 64,
        "data/indices/graph/prior.sqlite", {"job": "job_code_graph_index"}, (), "prior-shard",
    )
    stale_shard = base.job.run_root / "data" / "indices" / "build" / "stale.sqlite"
    stale_sha, _ = IndexBuilder(
        stale_shard, name="build", fingerprint="q" * 64,
        target_snapshot=base.job.source_fingerprint, shard_id="stale-cpp",
    ).build_or_reuse()
    stale_cpp_idx = IndexIdentity(
        "build", "appsec-review/retrieval-index/2", stale_sha, "q" * 64,
        "data/indices/build/stale.sqlite", {"job": "job_cpp_compiled_analysis"}, (), "stale-cpp",
    )
    up_manifest = base.job.run_root / "data" / "indices" / "manifests" / "upstream.json"
    write_manifest(up_manifest, run_id=base.job.run_id, target_snapshot=base.job.source_fingerprint,
                   target_root=base.job.target_root, indexes=[prior_idx, stale_cpp_idx])
    ev_handoff = {
        "job_id": "job_evidence_collection",
        "output": {"index_manifest": {
            "path": up_manifest.relative_to(base.job.run_root).as_posix(),
            "sha256": file_sha256(up_manifest),
        }},
    }
    base.job.consumable_handoffs["job_evidence_collection"] = ev_handoff
    base.job.upstream_handoffs["job_evidence_collection"] = ev_handoff
    base.job.input_manifest_path = up_manifest
    base.job.input_manifest_sha256 = file_sha256(up_manifest)

    # Deterministic whole-program fake executor covering AST, IR, Infer, and Binary branches!
    class WholeProgramExecutor:
        def execute(self, req):
            root = req.scratch_root
            if req.tool_id == "tool-infer":
                out = root / "infer-out"
                out.mkdir(parents=True, exist_ok=True)
                # 1 valid resolved observation with trace + 1 unresolved path observation (replaces integration claim #1!)
                (out / "report.json").write_text(json.dumps([
                    {
                        "file": "/target/source/main.cpp",
                        "line": 1,
                        "column": 5,
                        "bug_type": "NULL_DEREFERENCE",
                        "qualifier": "pointer p could be null",
                        "severity": "ERROR",
                        "category": "Memory",
                        "procedure": "main",
                        "key": "k1",
                        "bug_trace": [{"line_number": 1, "column_number": 5, "description": "null assigned"}],
                    },
                    {
                        "file": "/usr/include/external.h",
                        "line": 10,
                        "bug_type": "UNRESOLVED_HEADER_OBS",
                    },
                ]), encoding="utf-8")
                # Capture 1 of 2 source files -> exercises capture count mismatch gap!
                (out / "logs").write_text("Found 1 source file to analyze\n", encoding="utf-8")
                return _exec_result(base.job.run_root, root, req.tool_id, 0)

            mode = req.argv[1]
            dest = root / "analysis" / ("binary" if mode == "symbols" else mode)
            dest.mkdir(parents=True, exist_ok=True)
            if mode == "ast":
                # Unit 0 valid AST with FunctionDecl, ParmVarDecl, CallExpr + duplicate node id;
                # Unit 1 malformed JSON -> exercises AST parse gap!
                (dest / "tu-0000.json").write_text(json.dumps({
                    "kind": "TranslationUnitDecl",
                    "inner": [
                        {"id": "0x1", "kind": "FunctionDecl", "name": "main", "type": {"qualType": "int ()"},
                         "loc": {"line": 1, "col": 12},
                         "inner": [
                             {"id": "0x2", "kind": "ParmVarDecl", "name": "argc", "loc": {"line": 1, "col": 17}},
                             {"id": "0x3", "kind": "CallExpr", "loc": {"line": 1, "col": 30},
                              "referencedDecl": {"id": "0x9", "name": "helper"}},
                             {"id": "0x3", "kind": "CallExpr", "loc": {"line": 1, "col": 30},
                              "referencedDecl": {"id": "0x9", "name": "helper"}},
                             {"id": "0x4", "kind": "CallExpr", "loc": {"line": 1, "col": 32}},
                             "non-mapping-ignored",
                         ]},
                    ],
                }), encoding="utf-8")
                (dest / "tu-0001.json").write_text("{corrupt ast", encoding="utf-8")
                (dest / "receipt.json").write_text(json.dumps([
                    {"index": 0, "exit_code": 0},
                    {"index": 1, "exit_code": 0},
                ]))
            elif mode == "ir":
                # Valid debug-bound definitions: exact cross-TU helper and local ambig.
                (dest / "tu-0000.ll").write_text("\n".join([
                    "define dso_local i32 @main() !dbg !1 {",
                    "entry:",
                    "  %0 = call i32 @helper()",
                    "  %1 = call i32 @helper()",
                    "  %2 = call i32 @ambig()",
                    "  ret i32 %0",
                    "}",
                    "define internal i32 @ambig() !dbg !2 {",
                    "entry:",
                    "  ret i32 1",
                    "}",
                    '!1 = distinct !DISubprogram(name: "main", file: !3, line: 1)',
                    '!2 = distinct !DISubprogram(name: "ambig", file: !3, line: 1)',
                    '!3 = !DIFile(filename: "main.cpp", directory: "/scratch/source")',
                ]), encoding="utf-8")
                (dest / "tu-0001.ll").write_text("\n".join([
                    "define dso_local i32 @helper() !dbg !1 {",
                    "entry:",
                    "  ret i32 42",
                    "}",
                    "define dso_local i32 @ambig() !dbg !2 {",
                    "entry:",
                    "  ret i32 2",
                    "}",
                    '!1 = distinct !DISubprogram(name: "helper", file: !3, line: 1)',
                    '!2 = distinct !DISubprogram(name: "ambig", file: !3, line: 1)',
                    '!3 = !DIFile(filename: "helper.cpp", directory: "/scratch/source")',
                ]), encoding="utf-8")
                (dest / "receipt.json").write_text(json.dumps([
                    {"index": 0, "exit_code": 0},
                    {"index": 1, "exit_code": 0},
                ]))
            elif mode == "symbols":
                outputs = base._store["catalog.projects"]["projects"]["proj-app"]["outputs"]
                (dest / "records.json").write_text(json.dumps([
                    {**item, "metadata": "ELF 64-bit", "symbols": ["helper T", "main T"],
                     "tools": {name: {"exit_code": 0} for name in ("nm", "readelf")}}
                    for item in outputs]), encoding="utf-8")
            return _exec_result(base.job.run_root, root, req.tool_id, 0)

    job = cpp_job.build_job(executor_factory=lambda _u: WholeProgramExecutor())
    handlers = {u.unit_id: u.handler for u in job.units}

    def run_unit(uid: str) -> Mapping[str, Any]:
        u = SimpleNamespace(
            job=base.job,
            unit_id=uid,
            unit_root=base.job.run_root / "units" / uid.replace(".", "-"),
            output=lambda dep: base._store[dep],
        )
        u.unit_root.mkdir(parents=True, exist_ok=True)
        res = handlers[uid](u)
        base._store[uid] = res
        return res

    plan_out = run_unit("plan.accepted_cpp_plan")
    assert plan_out["terminal_status"] == "SUCCEEDED"
    assert plan_out["plan"]["project_count"] == 2

    prep_out = run_unit("prepare.projects")
    assert prep_out["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert prep_out["projects"]["proj-broken"]["terminal_status"] == "BLOCKED"
    # Verify .git file was excluded from unbuilt project mapping!
    broken_paths = [f["target_path"] for f in prep_out["projects"]["proj-broken"]["mapping"]["files"]]
    assert broken_paths == ["broken/broken.cpp"]

    cat_out = run_unit("catalog.projects")
    assert cat_out["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert cat_out["projects"]["proj-app"]["terminal_status"] == "SUCCEEDED"
    assert cat_out["projects"]["proj-broken"]["terminal_status"] == "BLOCKED_BY_COMPILE"
    assert cat_out["projects"]["proj-app"]["counts"] == {
        "compile_units": 2, "objects": 1, "libraries": 1, "executables": 1,
    }
    # Re-running catalog reuses checkpoint on proj-app!
    cat_reused = handlers["catalog.projects"](base)
    assert cat_reused["projects"]["proj-app"]["checkpoint_reused"] is True

    comp_out = run_unit("compiled.projects")
    assert comp_out["projects"]["proj-app"]["terminal_status"] == "SUCCEEDED"
    assert comp_out["projects"]["proj-app"]["index_identity"]["name"] == "build"
    import sqlite3
    with sqlite3.connect(base.job.run_root / comp_out["projects"]["proj-app"]["artifact"]["path"]) as conn:
        assert conn.execute("SELECT COUNT(*) FROM relations").fetchone()[0] >= 2

    ir_out = run_unit("ir.projects")
    assert ir_out["projects"]["proj-app"]["call_edge_count"] == 2
    assert any("source_cfg_unavailable" in g for g in ir_out["projects"]["proj-app"]["gaps"])

    ast_out = run_unit("ast.projects")
    assert any("Clang AST output unavailable or invalid" in g for g in ast_out["projects"]["proj-app"]["gaps"])
    assert ast_out["projects"]["proj-app"]["entity_count"] >= 3

    infer_out = run_unit("infer.projects")
    assert infer_out["projects"]["proj-app"]["observation_count"] == 1
    assert any("Infer observation path did not resolve" in g for g in infer_out["projects"]["proj-app"]["gaps"])
    assert any("Infer captured 1 of 2 source files" in g for g in infer_out["projects"]["proj-app"]["gaps"])

    bin_out = run_unit("binary.projects")
    assert bin_out["projects"]["proj-app"]["terminal_status"] == "SUCCEEDED"
    assert bin_out["projects"]["proj-app"]["symbol_count"] >= 2
    # Second run of binary.projects reuses checkpoint!
    bin_reused = handlers["binary.projects"](base)
    assert bin_reused["projects"]["proj-app"]["checkpoint_reused"] is True

    pub_out = run_unit("acceptance.publish_handoff")
    assert pub_out["terminal_status"] == "COMPLETED_WITH_GAPS"
    # Dispositions carry GAP on non-SUCCEEDED non-checkpointable entries (replaces integration claim #3!)
    gap_disps = [d for d in pub_out["dispositions"] if d.get("disposition") == "GAP"]
    assert gap_disps
    succ_disps = [d for d in pub_out["dispositions"] if d["terminal_status"] == "SUCCEEDED"]
    assert all("disposition" not in d for d in succ_disps)
    # Prior non-cpp shard kept, stale cpp shard replaced!
    published_manifest = json.loads((base.job.run_root / pub_out["index_manifest"]["path"]).read_text(encoding="utf-8"))
    shard_ids = {idx["shard_id"] for idx in published_manifest["indexes"]}
    assert "prior-shard" in shard_ids and "stale-cpp" not in shard_ids


def test_plan_prepare_catalog_and_branch_error_paths(tmp_path: Path) -> None:
    # 1. Missing language build handoff raises ValueError (replaces integration claim #2!)
    u_missing = _make_unit(tmp_path / "missing_lb", "plan.accepted_cpp_plan")
    job = cpp_job.build_job()
    handlers = {u.unit_id: u.handler for u in job.units}
    with pytest.raises(ValueError, match="accepted job_language_build handoff is required"):
        handlers["plan.accepted_cpp_plan"](u_missing)

    # 2. Fingerprint mismatch raises ValueError; empty actions returns NOT_APPLICABLE.
    u_plan = _make_unit(tmp_path / "plan_empty", "plan.accepted_cpp_plan")
    (u_plan.job.target_root / "js").mkdir(parents=True)
    (u_plan.job.target_root / "js" / "a.js").write_text("1;\n", encoding="utf-8")
    _write_language_build_handoff(u_plan.job.run_root, u_plan.job.source_fingerprint, [])
    empty_plan = handlers["plan.accepted_cpp_plan"](u_plan)
    assert empty_plan["terminal_status"] == "NOT_APPLICABLE"

    # Empty prepare, catalog, and branch return NOT_APPLICABLE.
    u_plan._store["plan.accepted_cpp_plan"] = empty_plan
    empty_prep = handlers["prepare.projects"](u_plan)
    assert empty_prep["terminal_status"] == "NOT_APPLICABLE"
    u_plan._store["prepare.projects"] = empty_prep
    empty_cat = handlers["catalog.projects"](u_plan)
    assert empty_cat["terminal_status"] == "NOT_APPLICABLE"
    u_plan._store["catalog.projects"] = empty_cat
    assert handlers["compiled.projects"](u_plan)["terminal_status"] == "NOT_APPLICABLE"

    # Source fingerprint mismatch in plan.
    u_plan.job.source_fingerprint = "0" * 64
    with pytest.raises(ValueError, match="target snapshot differs"):
        handlers["plan.accepted_cpp_plan"](u_plan)

    # 3. Prepare workspace custody errors: missing workspace, missing manifest, bad manifest sha,
    #    invalid manifest schema, file set changed, content changed, bad artifact sha, bad native_compile_database.
    u_prep = _make_unit(tmp_path / "prep_errs", "prepare.projects")
    staged = _stage_language_build(u_prep.job.run_root, u_prep.job.target_root, u_prep.job.source_fingerprint)
    u_prep._store["plan.accepted_cpp_plan"] = handlers["plan.accepted_cpp_plan"](u_prep)
    base_action = dict(u_prep._store["plan.accepted_cpp_plan"]["plan"]["actions"][0])
    base_receipt = dict(base_action["receipt"])

    def call_prepare_with(receipt_override: dict[str, Any]) -> Mapping[str, Any]:
        act = {**base_action, "receipt": {**base_receipt, **receipt_override}}
        u_prep._store["plan.accepted_cpp_plan"] = {"plan": {"actions": [act]}}
        return handlers["prepare.projects"](u_prep)

    # Mutable source staging is cleared; retained evidence outside it survives preparation.
    stale_case = cpp_job._case_root(u_prep, base_action["project_key"])
    stale_case.mkdir(parents=True, exist_ok=True)
    (stale_case / "source").mkdir()
    (stale_case / "source/marker").write_text("old", encoding="utf-8")
    (stale_case / "evidence").mkdir()
    (stale_case / "evidence/marker").write_text("retained", encoding="utf-8")
    ok_prep = call_prepare_with({"recipe": {"build_dir": "nonexistent_build_dir"}})
    assert ok_prep["terminal_status"] == "SUCCEEDED" and not (stale_case / "source/marker").exists()
    assert (stale_case / "evidence/marker").read_text() == "retained"

    with pytest.raises(ValueError, match="workspace is unavailable or outside"):
        call_prepare_with({"workspace": "../outside"})
    with pytest.raises(ValueError, match="does not bind its workspace manifest"):
        call_prepare_with({"workspace_manifest": None})
    with pytest.raises(ValueError, match="workspace manifest identity changed"):
        call_prepare_with({"workspace_manifest": {"path": base_receipt["workspace_manifest"]["path"], "sha256": "0" * 64}})
    with pytest.raises(ValueError, match="artifact identity changed"):
        call_prepare_with({"artifacts": [{"path": "missing.txt", "sha256": "0" * 64}]})
    with pytest.raises(ValueError, match="native component compile database identity changed"):
        call_prepare_with({"native_compile_database": {"path": "missing.json", "sha256": "0" * 64}})

    # Workspace file content changed vs manifest -> raises; extra file -> file set changed; bad schema -> invalid.
    (staged["ws"] / "build" / "main.o").write_bytes(b"TAMPERED")
    with pytest.raises(ValueError, match="workspace content changed"):
        call_prepare_with({})
    (staged["ws"] / "extra.txt").write_text("extra", encoding="utf-8")
    with pytest.raises(ValueError, match="workspace file set changed"):
        call_prepare_with({})
    atomic_json(staged["ws_manifest_path"], {"schema": "wrong"})
    with pytest.raises(ValueError, match="workspace manifest is invalid"):
        call_prepare_with({"workspace_manifest": {
            "path": staged["ws_manifest_path"].relative_to(u_prep.job.run_root).as_posix(),
            "sha256": file_sha256(staged["ws_manifest_path"]),
        }})


def test_catalog_invalid_db_and_branch_failure_edges(tmp_path: Path) -> None:
    # 1. Catalog INVALID_COMPILE_DATABASE when compile_commands.json is corrupt.
    u = _make_unit(tmp_path / "cat_bad", "catalog.projects")
    case_id = "proj-bad"
    case_root = cpp_job._case_root(u, case_id)
    (case_root / "build").mkdir(parents=True)
    (case_root / "build" / "compile_commands.json").write_text("[]", encoding="utf-8")
    map_art = cpp_job._json_artifact(u, case_root / "source-mapping.json", {"files": [], "case_snapshot": "s" * 64})
    u._store["prepare.projects"] = {"projects": {
        case_id: {
            "mapping": {"files": [], "case_snapshot": "s" * 64, "project_id": "cpp:bad"},
            "artifact": map_art,
            "build_receipt": {"fingerprint": "1" * 64, "image": {"image_id": DIGEST}},
            "terminal_status": "SUCCEEDED",
            "gaps": [],
        }
    }}
    job_fail = cpp_job.build_job()
    cat_bad = {x.unit_id: x.handler for x in job_fail.units}["catalog.projects"](u)
    assert cat_bad["projects"][case_id]["terminal_status"] == "INVALID_COMPILE_DATABASE"

    # 2. Whole-program compiled with zero compile outputs/links -> partial coverage gap;
    #    AST exit=2 partial failure + IR missing .ll + Infer OOM/timeout/bad-report/source-tamper + Binary bad JSON + hard exit!=0!
    u2 = _make_unit(tmp_path / "branch_edges", "compiled.projects")
    cid = "proj-edge"
    croot = cpp_job._case_root(u2, cid)
    (croot / "source").mkdir(parents=True)
    (croot / "build").mkdir(parents=True)
    tfile = u2.job.target_root / "edge.cpp"
    tfile.write_text("int edge() { return 1; }\n", encoding="utf-8")
    (croot / "source" / "edge.cpp").write_text("int edge() { return 1; }\n", encoding="utf-8")
    mapping = {
        "project_id": "cpp:.",
        "display_name": "edge",
        "root": ".",
        "case_snapshot": "e" * 64,
        "build_system": "cmake",
        "files": [{"target_path": "edge.cpp", "scratch_path": "source/edge.cpp", "sha256": file_sha256(tfile)}],
    }
    comp_cmds = [{
        "compile_unit_id": "cu-0",
        "command_sha256": "c" * 64,
        "directory": "/scratch/source",
        "file": "/scratch/source/edge.cpp",
        "target_path": "edge.cpp",
        "source_sha256": file_sha256(tfile),
        "arguments": ["clang++-18", "/scratch/source/edge.cpp"],
        "output_path": None,
    }]
    cdb_art = cpp_job._json_artifact(u2, croot / "normalized-compile-commands.json", comp_cmds)
    out_art = cpp_job._json_artifact(u2, croot / "artifact-catalog.json", [])
    lnk_art = cpp_job._json_artifact(u2, croot / "normalized-link-commands.json", [])
    cataloged = {
        "project_key": cid,
        "mapping": mapping,
        "compile_commands": comp_cmds,
        "compile_database": cdb_art,
        "artifact_catalog": out_art,
        "link_database": lnk_art,
        "link_commands": [],
        "outputs": [],
        "image_id": DIGEST,
        "terminal_status": "SUCCEEDED",
        "gaps": [],
    }
    u2._store["catalog.projects"] = {"projects": {cid: cataloged}}

    # _build_entities with no compile output / link relation -> records partial coverage in sqlite!
    import sqlite3
    no_rel = cpp_job._build_entities(u2, cid, cataloged)
    with sqlite3.connect(u2.job.run_root / no_rel["artifact"]["path"]) as conn:
        cov_rows = conn.execute("SELECT status, gap FROM coverage").fetchall()
    assert any(st == "partial" and "no exact compile-output or captured link relation" in (rsn or "")
               for st, rsn in cov_rows)

    # Branch handler with exit=2 partial failure on AST, missing .ll on IR, malformed records.json on binary,
    # and hard exit=5 failure when receipt also has failures!
    mode_state = {"hard_fail": False}

    class EdgeExecutor:
        def execute(self, req):
            root = req.scratch_root
            if req.tool_id == "tool-infer":
                # Missing report.json + timed_out=True -> exercises timed_out + _bounded_infer_report error + missing logs
                return _exec_result(u2.job.run_root, root, req.tool_id, 124, timed_out=True)
            mode = req.argv[1]
            dest = root / "analysis" / ("binary" if mode == "symbols" else mode)
            dest.mkdir(parents=True, exist_ok=True)
            if mode == "ast":
                (dest / "receipt.json").write_text(json.dumps([
                    {"index": 0, "exit_code": 1, "stderr": "fatal error: edge.h: No such file or directory"},
                ]))
                code = 5 if mode_state["hard_fail"] else 2
                return _exec_result(u2.job.run_root, root, req.tool_id, code)
            if mode == "ir":
                # Exit 0, receipt ok, but no tu-0000.ll file -> unavailable or over bound gap
                (dest / "receipt.json").write_text(json.dumps([{"index": 0, "exit_code": 0}]))
                return _exec_result(u2.job.run_root, root, req.tool_id, 0)
            # symbols: write corrupt records.json
            (dest / "records.json").write_text("{corrupt", encoding="utf-8")
            return _exec_result(u2.job.run_root, root, req.tool_id, 0)

    edge_job = cpp_job.build_job(executor_factory=lambda _u: EdgeExecutor())
    eh = {x.unit_id: x.handler for x in edge_job.units}

    ast_partial = eh["ast.projects"](u2)
    assert any("header not found in tool-native-cpp: edge.h" in g for g in ast_partial["projects"][cid]["gaps"])

    ir_missing = eh["ir.projects"](u2)
    assert any("LLVM IR output unavailable or over bound" in g for g in ir_missing["projects"][cid]["gaps"])

    bin_corrupt = eh["binary.projects"](u2)
    assert any("no valid bounded record set" in g for g in bin_corrupt["projects"][cid]["gaps"])

    infer_timeout = eh["infer.projects"](u2)
    assert any("Infer timed out" in g for g in infer_timeout["projects"][cid]["gaps"])
    assert any("Infer report unavailable or invalid" in g for g in infer_timeout["projects"][cid]["gaps"])
    assert any("Infer capture count was unavailable" in g for g in infer_timeout["projects"][cid]["gaps"])

    # Hard fail (exit 5 + failures appended to tool_gap -> unavailable shard); delete prior AST checkpoint first
    ckpt = croot / "checkpoints" / "branch-ast.json"
    if ckpt.exists():
        ckpt.unlink()
    mode_state["hard_fail"] = True
    ast_hard = eh["ast.projects"](u2)
    assert any("failed with exit 5" in g and "header not found in tool-native-cpp: edge.h" in g
               for g in ast_hard["projects"][cid]["gaps"])

    # Infer OOM, non-zero exit, invalid report list, and tampered target file ValueError!
    exec_meta = {
        "execution": {"path": "x", "sha256": "1" * 64, "size_bytes": 1},
        "compile_database": cdb_art,
        "tool_version": "1.2",
        "image_id": DIGEST,
        "image_digest": DIGEST,
        "oom_killed": True,
        "timed_out": False,
        "exit_code": 137,
    }
    inf_dir = croot / "analysis" / "infer-run" / "infer-out"
    inf_dir.mkdir(parents=True, exist_ok=True)
    (inf_dir / "report.json").write_text('{"not": "a list"}', encoding="utf-8")
    oom_res = cpp_job._infer_index(u2, cid, cataloged, exec_meta)
    assert any("OOM-killed" in g for g in oom_res["gaps"])

    exec_meta["oom_killed"] = False
    exec_meta["exit_code"] = 3
    (inf_dir / "report.json").write_text(json.dumps([{"file": "/target/source/edge.cpp", "line": 1}]), encoding="utf-8")
    tfile.write_text("int edge() { return 999; }\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Infer observation source changed after accepted mapping"):
        cpp_job._infer_index(u2, cid, cataloged, exec_meta)


def test_infer_runs_single_worker_within_4g_and_classifies_worker_signal_kills(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from appsec_review.container_runtime.catalog import load_catalog

    repo_catalog = load_catalog(ROOT)
    assert repo_catalog.tool("tool-infer").memory == "1g"

    unit, base_handlers = _prepared_catalog_inputs(tmp_path)
    unit._store["catalog.projects"] = base_handlers["catalog.projects"](unit)
    cid = next(iter(unit._store["catalog.projects"]["projects"]))
    croot = cpp_job._case_root(unit, cid)

    seen_requests: list[Any] = []
    failed_notices: list[tuple[bool, str, str]] = []
    monkeypatch.setattr(
        "appsec_review.runtime.execution_safety.failed_result",
        lambda failed, msg, *, action="": failed_notices.append((bool(failed), msg, action)),
    )

    state = {"log_line": "[17][      debug] Subprocess 1: died after receiving signal number -7\n",
             "in_stderr": False}

    class InferSignalExecutor:
        def execute(self, req: Any) -> ExecutionResult:
            seen_requests.append(req)
            res = _exec_result(unit.job.run_root, req.scratch_root, req.tool_id, exit_code=1, oom_killed=False)
            infer_out = req.scratch_root / "infer-out"
            infer_out.mkdir(parents=True, exist_ok=True)
            (infer_out / "report.json").write_text("[]", encoding="utf-8")
            if state["in_stderr"]:
                (req.scratch_root / "raw" / "stderr.bin").write_text(state["log_line"], encoding="utf-8")
            else:
                (infer_out / "logs").write_text(
                    "[10][environment] CWD = /scratch\n" + state["log_line"], encoding="utf-8",
                )
            return res

    job_inst = cpp_job.build_job(executor_factory=lambda _u: InferSignalExecutor())
    handlers = {item.unit_id: item.handler for item in job_inst.units}

    # Case 1: OCaml worker SIGKILL (-7) in infer-out/logs while PID 1 exits 1 with executor oom_killed=False.
    infer_oom = handlers["infer.projects"](unit)
    assert len(seen_requests) == 1
    infer_argv = list(seen_requests[0].argv)
    jobs_idx = infer_argv.index("--jobs")
    assert infer_argv[jobs_idx + 1] == "1"
    assert ("--jobs", "2") not in zip(infer_argv, infer_argv[1:])
    assert seen_requests[0].memory == "4g"

    proj_oom = infer_oom["projects"][cid]
    assert proj_oom["oom_killed"] is True
    assert proj_oom["subprocess_signal"] == -7
    assert proj_oom["checkpointable"] is False
    assert not (croot / "checkpoints" / "branch-infer.json").exists()
    assert proj_oom["observation_count"] == 0
    import sqlite3
    with sqlite3.connect(unit.job.run_root / proj_oom["artifact"]["path"]) as db:
        cov_row = db.execute("select status from coverage where area = 'infer'").fetchone()
    assert cov_row == ("unavailable",)
    assert any("OOM-killed" in gap and "signal -7" in gap for gap in proj_oom["gaps"])
    assert any(failed and action == "cpp.infer" for failed, _, action in failed_notices)

    # Case 2: Non-OOM worker crash (signal -11) in stderr.bin classifies worker crash without false OOM.
    failed_notices.clear()
    state["log_line"] = "Uncaught Internal Error: Subprocess 2: died after receiving signal number -11\n"
    state["in_stderr"] = True
    infer_sig = handlers["infer.projects"](unit)
    proj_sig = infer_sig["projects"][cid]
    assert proj_sig["oom_killed"] is False
    assert proj_sig["subprocess_signal"] == -11
    assert proj_sig["checkpointable"] is False
    with sqlite3.connect(unit.job.run_root / proj_sig["artifact"]["path"]) as db:
        sig_cov_row = db.execute("select status from coverage where area = 'infer'").fetchone()
    assert sig_cov_row == ("unavailable",)
    assert any("Infer worker subprocess died after signal -11" in gap for gap in proj_sig["gaps"])
