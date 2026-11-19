"""Code-level unit tests for job_cpp_symbol_index scope normalization, checkpoints, and units."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
from types import MappingProxyType, SimpleNamespace
from typing import Any

import pytest

from appsec_review.config import load_config
from appsec_review.container_runtime.executor import ExecutionResult
from appsec_review.indexing.inventory import Claim, FileClaims, runtime_claims, scan_run_tree
from appsec_review.jobs.cpp_index_scopes import IndexScope, SCOPE_SCHEMA
from appsec_review.jobs.job_cpp_symbol_index.datasets import DATASETS
import appsec_review.jobs.job_cpp_symbol_index.job as job_mod
from appsec_review.jobs.job_cpp_symbol_index.job import (
    JOB_ID,
    SCHEMA,
    TOOL_ID,
    _accepted_location,
    _container_path,
    _index_scope,
    _not_applicable_scope,
    _position,
    build_job,
    normalize_scope,
    unresolved_system_headers,
)
from appsec_review.retrieval import IndexBuilder, RelationKind, write_manifest
from appsec_review.runtime import UnitContext
from appsec_review.storage import canonical_json, file_sha256, run_artifact


REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "cpp_symbol_index"


def _make_scope_and_unit(
    base: Path,
    *,
    sources: dict[str, str] | None = None,
    compile_commands: list[dict[str, Any]] | None = None,
    settings_override: dict[str, Any] | None = None,
) -> tuple[Path, Path, IndexScope, UnitContext]:
    run_root = base / "run"
    target_root = base / "target"
    files_text = sources or {
        "native/a.cpp": "int helper() { return 1; }\nint main() { return helper() + helper(); }\n",
    }
    case_id = "case-native"
    case_root = run_root / "data" / "cpp" / "projects" / case_id
    files_entries: list[dict[str, Any]] = []
    by_relative: dict[str, dict[str, Any]] = {}
    for rel, content in sorted(files_text.items()):
        tfile = target_root / rel
        tfile.parent.mkdir(parents=True, exist_ok=True)
        tfile.write_text(content, encoding="utf-8")
        sha = file_sha256(tfile)
        sub = rel.split("/", 1)[1] if "/" in rel else rel
        scratch_rel = f"source/{sub}"
        sfile = case_root / scratch_rel
        sfile.parent.mkdir(parents=True, exist_ok=True)
        sfile.write_text(content, encoding="utf-8")
        entry = {"target_path": rel, "scratch_path": scratch_rel, "sha256": sha}
        files_entries.append(entry)
        by_relative[sub] = entry

    cdb_rows = compile_commands if compile_commands is not None else [
        {"target_path": rel, "arguments": ["clang++", f"/scratch/source/{rel.split('/', 1)[1]}"]}
        for rel in sorted(files_text)
    ]
    cdb_path = case_root / "compile_commands.json"
    cdb_path.parent.mkdir(parents=True, exist_ok=True)
    cdb_path.write_text(json.dumps(cdb_rows), encoding="utf-8")
    cdb_art = run_artifact(run_root, cdb_path)

    case_snapshot = "a" * 64
    scope_id = "cpp-scope-" + hashlib.sha256(
        canonical_json(
            {
                "schema": SCOPE_SCHEMA,
                "case_id": case_id,
                "case_snapshot": case_snapshot,
                "compile_database": cdb_art["sha256"],
            }
        )
    ).hexdigest()[:24]
    scope = IndexScope(
        scope_id=scope_id,
        case_id=case_id,
        project_id="cpp:native",
        root="native",
        case_snapshot=case_snapshot,
        case_root=case_root,
        files=tuple(files_entries),
        compile_commands=tuple(cdb_rows),
        compile_database=cdb_art,
        _by_relative=by_relative,
    )

    config = load_config(REPO_ROOT / "appsec-review.toml")
    base_settings = dict(config.job(JOB_ID).settings)
    if settings_override:
        base_settings.update(settings_override)
    job_cfg = SimpleNamespace(
        steps=config.job(JOB_ID).steps,
        step=config.job(JOB_ID).step,
        settings=MappingProxyType(base_settings),
    )
    events_log: list[tuple[str, dict[str, Any]]] = []
    events = SimpleNamespace(write=lambda name, **kw: events_log.append((name, kw)), log=events_log)
    attempt_root = run_root / "data" / "jobs" / JOB_ID / "attempts" / "attempt_0001"
    unit_root = attempt_root / "steps" / "acceptance" / "tasks" / "publish_handoff"
    unit_root.mkdir(parents=True, exist_ok=True)
    job_ctx = SimpleNamespace(
        job_id=JOB_ID,
        run_id="run-unit-sym",
        attempt_id="attempt_0001",
        run_root=run_root,
        attempt_root=attempt_root,
        target_root=target_root,
        repository_root=REPO_ROOT,
        source_fingerprint="b" * 64,
        config=job_cfg,
        events=events,
        consumable_handoffs={},
    )
    outputs: dict[str, Any] = {}
    unit = UnitContext(
        job=job_ctx,
        unit_id="index.scopes",
        step_id="index",
        task_id="scopes",
        unit_root=unit_root,
        outputs=outputs,
    )
    return run_root, target_root, scope, unit


class FakeClangdExecutor:
    """In-memory stand-in for tool-clangd-indexer."""

    def __init__(
        self,
        run_root: Path,
        *,
        yaml_text: str = "",
        stderr_text: str | None = None,
        exit_code: int = 0,
        timed_out: bool = False,
        oom_killed: bool = False,
        stdout_truncated: bool = False,
        stderr_truncated: bool = False,
    ) -> None:
        self.run_root = run_root
        self.yaml_text = yaml_text
        self.stderr_text = stderr_text
        self.exit_code = exit_code
        self.timed_out = timed_out
        self.oom_killed = oom_killed
        self.stdout_truncated = stdout_truncated
        self.stderr_truncated = stderr_truncated
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    def execute(self, request: Any) -> ExecutionResult:
        self.calls.append((request.tool_id, tuple(request.argv)))
        scratch = request.scratch_root
        database = json.loads((scratch / "compile_commands.json").read_text(encoding="utf-8"))
        stderr = (
            self.stderr_text
            if self.stderr_text is not None
            else "".join(
                f"[{idx}/{len(database)}] Processing file {row['file']}\n"
                for idx, row in enumerate(database, 1)
            )
        )
        raw = scratch / "raw"
        raw.mkdir(parents=True, exist_ok=True)
        (raw / "stdout.bin").write_text(self.yaml_text, encoding="utf-8")
        (raw / "stderr.bin").write_text(stderr, encoding="utf-8")
        receipt = scratch / "execution.json"
        receipt.write_text(
            json.dumps({"tool_id": request.tool_id, "argv": list(request.argv)}),
            encoding="utf-8",
        )
        rel = lambda p: p.relative_to(self.run_root).as_posix()
        digest = "sha256:" + "c" * 64
        return ExecutionResult(
            "appsec-review/container-execution/1",
            request.tool_id,
            "fixture-clangd",
            digest,
            digest,
            "argv",
            (),
            {},
            "start",
            "end",
            self.exit_code,
            self.timed_out,
            self.oom_killed,
            self.stdout_truncated,
            self.stderr_truncated,
            rel(raw / "stdout.bin"),
            rel(raw / "stderr.bin"),
            rel(receipt),
        )


SAMPLE_YAML = """--- !Symbol
ID:              1111111111111111
Name:            helper
Scope:           'ns::'
SymInfo:
  Kind:          Function
  Lang:          Cpp
CanonicalDeclaration:
  FileURI:       'file:///target/source/a.cpp'
  Start:
    Line:        0
    Column:      4
  End:
    Line:        0
    Column:      10
References:      2
Signature:       '()'
ReturnType:      'int'
...
--- !Symbol
ID:              2222222222222222
Name:            main
Scope:           ''
SymInfo:         not-a-mapping
Definition:
  FileURI:       'file:///target/source/a.cpp'
  Start:
    Line:        1
    Column:      4
References:      not-a-digit
...
--- !Symbol
ID:              2222222222222222
Name:            duplicate_ignored
Scope:           ''
...
--- !Symbol
ID:              bad-id
Name:            invalid_id_ignored
...
--- !Symbol
ID:              3333333333333333
Name:            printf
Scope:           ''
CanonicalDeclaration:
  FileURI:       'file:///usr/include/stdio.h'
  Start:
    Line:        10
    Column:      4
...
--- !Refs
ID:              1111111111111111
References:
  - Kind:        28
    Location:
      FileURI:   'file:///target/source/a.cpp'
      Start:
        Line:    1
        Column:  20
    Container:
      ID:        2222222222222222
  - Kind:        28
    Location:
      FileURI:   'file:///target/source/a.cpp'
      Start:
        Line:    1
        Column:  31
    Container:
      ID:        2222222222222222
  - Kind:        badkind
    Location:
      FileURI:   'file:///usr/include/other.h'
      Start:
        Line:    5
        Column:  1
    Container:
      ID:        2222222222222222
  - Kind:        4
    Location:    not-a-mapping
    Container:
      ID:        1111111111111111
  - Kind:        4
    Container:   not-a-mapping
  - - NestedSeq: item
...
--- !Refs
ID:              9999999999999999
References:      not-a-list
...
"""


def test_location_and_uri_helpers_and_post_acceptance_tamper_detection(tmp_path: Path) -> None:
    assert _container_path(None) is None
    assert _container_path("http://example.com/a.cpp") is None
    assert _container_path("file:///target/source/a%20b.cpp") == "/target/source/a b.cpp"

    assert _position(None) is None
    assert _position({"Line": "bad", "Column": "0"}) is None
    assert _position({"Line": "2", "Column": "4"}) == (3, 5)

    _, target_root, scope, unit = _make_scope_and_unit(tmp_path)
    sizes: dict = {}
    assert _accepted_location(unit, scope, "not-a-mapping", sizes) is None
    assert _accepted_location(unit, scope, {"FileURI": "file:///usr/include/x.h"}, sizes) is None
    assert (
        _accepted_location(
            unit,
            scope,
            {"FileURI": "file:///target/source/a.cpp", "Start": None},
            sizes,
        )
        is None
    )

    loc, meta = _accepted_location(
        unit,
        scope,
        {"FileURI": "file:///target/source/a.cpp", "Start": {"Line": 0, "Column": 4}},
        sizes,
    )
    assert loc.start_line == loc.end_line == 1
    assert meta == {"path": "native/a.cpp", "line": 1, "column": 5, "end_line": 1, "end_column": 5}
    assert "native/a.cpp" in sizes

    # Mutating target file after acceptance must fail closed when sizes cache is fresh
    (target_root / "native" / "a.cpp").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ValueError, match="clangd symbol source changed after acceptance"):
        _accepted_location(
            unit,
            scope,
            {"FileURI": "file:///target/source/a.cpp", "Start": {"Line": 0, "Column": 4}},
            {},
        )


def test_normalize_scope_edges_limits_and_error_surfaces(tmp_path: Path) -> None:
    run_root, _, scope, unit = _make_scope_and_unit(tmp_path / "ok")
    raw = run_root / "raw"
    raw.mkdir(parents=True)
    (raw / "stdout").write_text(SAMPLE_YAML, encoding="utf-8")
    (raw / "stderr").write_text("[1/1] Processing file /target/source/a.cpp\n", encoding="utf-8")

    builder = IndexBuilder(
        run_root / "ok.sqlite",
        name="analysis",
        fingerprint="f" * 64,
        target_snapshot=unit.job.source_fingerprint,
        shard_id="clangd-ok",
    )
    counts = normalize_scope(
        unit,
        scope,
        {
            "timed_out": False,
            "oom_killed": False,
            "exit_code": 0,
            "stdout_truncated": False,
            "stdout_path": "raw/stdout",
            "stderr_path": "raw/stderr",
        },
        {
            "max_documents_per_scope": 100,
            "max_symbols_per_scope": 100,
            "max_relations_per_scope": 100,
            "locations_per_relation": 1,
        },
        builder,
        "clangd-ok",
    )
    assert counts["symbols"] == 2
    assert counts["external_symbols"] == 1
    assert counts["relations"] == 2
    assert counts["unresolved_references"] == 2  # bad container + non-mapping ref; self-ref resolves
    assert counts["coverage"] == "complete"
    edges = {rel.kind: rel for rel in builder.relations}
    assert set(edges) == {RelationKind.CALLS, RelationKind.REFERENCES}
    assert edges[RelationKind.CALLS].payload["occurrences"] == 2
    assert len(edges[RelationKind.CALLS].payload["locations"]) == 1  # capped at locations_per_relation=1
    assert edges[RelationKind.REFERENCES].payload["locations"] == []  # /usr/include not accepted

    # Relation limit, document cap, truncated tail, missing TUs, stdout_truncated, timeout, and OOM
    for case_name, exec_overrides, yaml_body, stderr_body, limits_override, expected_gap, expected_cov in [
        (
            "rel_and_doc_cap",
            {"stdout_truncated": True},
            SAMPLE_YAML,
            "",  # missing TU too!
            {"max_relations_per_scope": 1, "max_documents_per_scope": 6},
            "clangd relation limit reached",
            "partial",
        ),
        (
            "truncated_tail_and_timeout",
            {"timed_out": True},
            "--- !Symbol\nID: 1111111111111111\n",
            "[1/1] Processing file /target/source/a.cpp\n",
            {},
            "clangd index output ended inside a document",
            "partial",
        ),
        (
            "malformed_and_oom",
            {"oom_killed": True, "exit_code": 137},
            '--- !Symbol\nBad: "unterminated\n...\n',
            "[1/1] Processing file /target/source/a.cpp\n",
            {},
            "clangd-indexer was OOM-killed",
            "unavailable",
        ),
    ]:
        sub_run, _, sub_scope, sub_unit = _make_scope_and_unit(tmp_path / case_name)
        sub_raw = sub_run / "raw"
        sub_raw.mkdir(parents=True)
        (sub_raw / "stdout").write_text(yaml_body, encoding="utf-8")
        (sub_raw / "stderr").write_text(stderr_body, encoding="utf-8")
        sub_builder = IndexBuilder(
            sub_run / "shard.sqlite",
            name="analysis",
            fingerprint="f" * 64,
            target_snapshot=sub_unit.job.source_fingerprint,
            shard_id="clangd-sub",
        )
        base_exec = {
            "timed_out": False,
            "oom_killed": False,
            "exit_code": 0,
            "stdout_truncated": False,
            "stdout_path": "raw/stdout",
            "stderr_path": "raw/stderr",
            **exec_overrides,
        }
        base_limits = {
            "max_documents_per_scope": 100,
            "max_symbols_per_scope": 100,
            "max_relations_per_scope": 100,
            "locations_per_relation": 2,
            **limits_override,
        }
        res = normalize_scope(sub_unit, sub_scope, base_exec, base_limits, sub_builder, "clangd-sub")
        assert expected_gap in res["gaps"]
        assert res["coverage"] == expected_cov


def test_unresolved_system_headers_attributes_chains_and_direct_diagnostics() -> None:
    stderr = (
        "[1/3] Processing file /target/source/a.c\n"
        "In file included from /target/source/a.c:3:\n"
        "In file included from /target/source/inc/a.h:2:\n"
        "/target/source/inc/zc.h:4:10: fatal error: 'sys/types.h' file not found\n"
        "    4 | #include <sys/types.h>\n"
        "      |          ^~~~~~~~~~~~~\n"
        "1[2/3] Processing file /target/source/b.cpp\n"  # interleaved prefix from another thread
        "/target/source/b.cpp:2:10: fatal error: 'cstdio' file not found\n"
        "/target/source/vendor/x.c:1:10: fatal error: 'stdlib.h' file not found\n"  # not an expected unit
        "1 error generated.\n"
        "Error while processing /target/source/a.c.\n"
    )
    expected = {"/target/source/a.c", "/target/source/b.cpp", "/target/source/c.c"}
    headers, units = unresolved_system_headers(stderr, expected)
    assert headers == ["cstdio", "stdlib.h", "sys/types.h"]
    assert units == {"/target/source/a.c": ["sys/types.h"], "/target/source/b.cpp": ["cstdio"]}
    assert unresolved_system_headers("[1/1] Processing file /target/source/a.c\n", expected) == ([], {})
    assert {m.group(1) for m in job_mod._PROCESSED.finditer(stderr)} == {"/target/source/a.c", "/target/source/b.cpp"}


def test_clangd23_system_headers_not_found_is_a_named_gap_and_units_count_as_unprocessed(tmp_path: Path) -> None:
    """Run 2026-11-17-0003: tool-clangd-indexer:23.1.0 could not find libc/libstdc++ headers for
    every translation unit, yet the summary said "processed 30 of 32" with no gap naming it."""
    units = {
        "src/main.cpp": "int main() { return 0; }\n",  # direct 'cstdlib' error; its Processing line is garbled
        "src/util.c": "int util(void) { return 1; }\n",  # direct 'stdio.h' error
        "third_party/zlib/uncompr.c": "int u(void) { return 2; }\n",  # 'sys/types.h' via zlib.h -> zconf.h
        # Match the real fixture's definition coordinates without needing the third-party source.
        "third_party/zlib/inflate.c": "\n" * 156 + "int         inflateReset2() { return 3; }\n",
        "third_party/bzip2/huffman.c": "int h(void) { return 4; }\n",  # 'stdlib.h' via bzlib_private.h
        "third_party/lz4/lib/lz4hc.c": "int l(void) { return 5; }\n",  # 'stdlib.h' via #include "lz4.c"
    }
    run_root, _, scope, unit = _make_scope_and_unit(
        tmp_path / "sysroot", sources={f"native/{rel}": body for rel, body in units.items()}
    )
    raw = run_root / "raw"
    raw.mkdir(parents=True)
    (raw / "stdout").write_bytes((FIXTURES / "clangd23-documentation.yaml").read_bytes())
    (raw / "stderr").write_bytes((FIXTURES / "clangd23-system-headers.stderr").read_bytes())
    builder = IndexBuilder(
        run_root / "sysroot.sqlite",
        name="analysis",
        fingerprint="f" * 64,
        target_snapshot=unit.job.source_fingerprint,
        shard_id="clangd-sysroot",
    )
    counts = normalize_scope(
        unit,
        scope,
        {
            "timed_out": False,
            "oom_killed": False,
            "exit_code": 0,
            "stdout_truncated": False,
            "stdout_path": "raw/stdout",
            "stderr_path": "raw/stderr",
        },
        {
            "max_documents_per_scope": 100,
            "max_symbols_per_scope": 100,
            "max_relations_per_scope": 100,
            "locations_per_relation": 2,
        },
        builder,
        "clangd-sysroot",
    )
    assert counts["translation_units"] == 6
    assert counts["processed_translation_units"] == 0
    assert counts["translation_units_with_unresolved_headers"] == 6
    assert counts["omitted_translation_units"] == 1  # main.cpp's "Processing file" line is garbled
    assert counts["unresolved_system_headers"] == [
        "climits", "cstdio", "cstdlib", "stdio.h", "stdlib.h", "string.h", "sys/types.h",
    ]
    assert counts["coverage"] == "partial"
    gap = next(g for g in counts["gaps"] if g.startswith("system_headers_unresolved: "))
    assert gap == (
        "system_headers_unresolved: climits, cstdio, cstdlib, stdio.h, stdlib.h, string.h, sys/types.h "
        "not found in 6 of 6 translation units (src/main.cpp, src/util.c, third_party/bzip2/huffman.c, "
        "third_party/lz4/lib/lz4hc.c, third_party/zlib/inflate.c, third_party/zlib/uncompr.c)"
    )
    assert "clangd-indexer processed 0 of 6 translation units" in counts["gaps"]
    # The same run's documented symbols now parse: no malformed-output gap; inflateReset2 is defined in
    # the in-scope inflate.c and is admitted, the lz4 and cJSON symbols are declared outside the scope.
    assert not any("malformed" in g for g in counts["gaps"])
    assert counts["symbols"] == 1
    assert counts["external_symbols"] == 2
    assert [entity.name for entity in builder.entities] == ["inflateReset2"]


def test_failed_clangd_run_is_scoped_unavailable_coverage(tmp_path: Path) -> None:
    """Direct _index_scope failure surface (also invoked under safety._running by test_review_stop_policy)."""
    run_root, _, scope, unit = _make_scope_and_unit(tmp_path / "failed_clangd")
    executor = FakeClangdExecutor(run_root, exit_code=1, stderr_text="")
    result = _index_scope(unit, scope, lambda _u: executor)
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert result["counts"]["coverage"] == "unavailable"
    assert result["counts"]["symbols"] == 0
    assert "clangd-indexer exited with status 1" in result["gaps"]
    with sqlite3.connect(run_root / result["index_identity"]["relative_path"]) as db:
        assert db.execute("SELECT status FROM coverage").fetchall() == [("unavailable",)]


def test_index_scope_checkpoint_reuse_and_default_tool_identity_branch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_root, _, scope, unit = _make_scope_and_unit(tmp_path / "ckpt")
    executor = FakeClangdExecutor(run_root, yaml_text=SAMPLE_YAML)
    first = _index_scope(unit, scope, lambda _u: executor)
    assert first["terminal_status"] == "SUCCEEDED"
    assert len(executor.calls) == 1
    assert first["execution"]["receipt"]["path"].endswith("execution.json")

    reused = _index_scope(unit, scope, lambda _u: executor)
    assert reused["checkpoint_reused"] is True
    assert len(executor.calls) == 1

    # Exercise executor_factory=None branch using monkeypatched tool_identity and execute_scope_tool
    run_root2, _, scope2, unit2 = _make_scope_and_unit(tmp_path / "default_exec")
    fake2 = FakeClangdExecutor(run_root2, yaml_text=SAMPLE_YAML)
    orig_exec = job_mod.execute_scope_tool
    monkeypatch.setattr(job_mod, "tool_identity", lambda _repo, tid: {"tool_id": tid, "pinned": True})
    monkeypatch.setattr(
        job_mod,
        "execute_scope_tool",
        lambda u, s, tid, argv, scratch, _ef: orig_exec(u, s, tid, argv, scratch, lambda _u: fake2),
    )
    direct = _index_scope(unit2, scope2, None)
    assert direct["terminal_status"] == "SUCCEEDED"
    assert len(fake2.calls) == 1


def test_build_job_units_skipped_na_unavailable_and_inventory_claims(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_root, target_root, scope, unit = _make_scope_and_unit(tmp_path / "pipeline")
    # Seed upstream context manifest so publish_scope_indexes can compose onto it
    upstream_path = run_root / "data" / "indices" / "manifests" / "upstream.json"
    write_manifest(
        upstream_path,
        run_id=unit.job.run_id,
        target_snapshot=unit.job.source_fingerprint,
        target_root=target_root,
        indexes=(),
    )
    unit.job.input_manifest_path = upstream_path
    unit.job.input_manifest_sha256 = file_sha256(upstream_path)
    upstream_manifest = run_artifact(run_root, upstream_path)
    asm_scope = IndexScope(
        scope_id="cpp-scope-asm",
        case_id="case-asm",
        project_id="cpp:asm",
        root="asm",
        case_snapshot=scope.case_snapshot,
        case_root=scope.case_root,
        files=scope.files,
        compile_commands=({"target_path": "asm/boot.S", "arguments": ["clang", "/scratch/source/boot.S"]},),
        compile_database=scope.compile_database,
        _by_relative=scope._by_relative,
    )
    assert _not_applicable_scope(asm_scope)["terminal_status"] == "SKIPPED_NA"

    executor = FakeClangdExecutor(run_root, yaml_text=SAMPLE_YAML)
    job = build_job(executor_factory=lambda _u: executor)
    load_fn, index_fn, publish_fn = (u.handler for u in job.units)

    # 1. Snapshot mismatch rejected in load.accepted_cpp
    bad_accepted = {
        "handoff": {"source_fingerprint": "0" * 64},
        "handoff_sha256": "d" * 64,
        "manifest": upstream_manifest,
    }
    monkeypatch.setattr(job_mod, "accepted_cpp_scopes", lambda _r: (bad_accepted, [scope], {}))
    with pytest.raises(ValueError, match="target snapshot differs"):
        load_fn(unit)

    # 2. Scope set drift between load and index rejected
    good_accepted = {
        "handoff": {"source_fingerprint": unit.job.source_fingerprint},
        "handoff_sha256": "d" * 64,
        "manifest": upstream_manifest,
    }
    monkeypatch.setattr(job_mod, "accepted_cpp_scopes", lambda _r: (good_accepted, [scope], {}))
    loaded = load_fn(unit)
    unit.outputs["load.accepted_cpp"] = loaded
    monkeypatch.setattr(job_mod, "accepted_cpp_scopes", lambda _r: (good_accepted, [asm_scope], {}))
    with pytest.raises(ValueError, match="accepted C\\+\\+ scopes changed between load and index"):
        index_fn(unit)

    # 3. NOT_APPLICABLE when all scopes are SKIPPED_NA and unavailable is empty
    monkeypatch.setattr(job_mod, "accepted_cpp_scopes", lambda _r: (good_accepted, [asm_scope], {}))
    unit.outputs["load.accepted_cpp"] = load_fn(unit)
    na_indexed = index_fn(unit)
    assert na_indexed["terminal_status"] == "NOT_APPLICABLE"
    assert len(na_indexed["not_applicable_scopes"]) == 1

    # 4. Clean SUCCEEDED when runnable scope has zero gaps and unavailable is empty
    monkeypatch.setattr(job_mod, "accepted_cpp_scopes", lambda _r: (good_accepted, [scope, asm_scope], {}))
    unit.outputs["load.accepted_cpp"] = load_fn(unit)
    ok_indexed = index_fn(unit)
    assert ok_indexed["terminal_status"] == "SUCCEEDED"
    assert ok_indexed["scope_count"] == 1

    # 5. COMPLETED_WITH_GAPS with unavailable case + full publish + dataset inventory audit
    unavailable = {"case-broken": "accepted C++ project has no compile commands"}
    monkeypatch.setattr(
        job_mod,
        "accepted_cpp_scopes",
        lambda _r: (good_accepted, [scope, asm_scope], unavailable),
    )
    unit.outputs["load.accepted_cpp"] = load_fn(unit)
    gap_indexed = index_fn(unit)
    assert gap_indexed["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert "case-broken: accepted C++ project has no compile commands" in gap_indexed["gaps"]
    unit.outputs["index.scopes"] = gap_indexed

    published = publish_fn(unit)
    assert published["schema"] == SCHEMA
    assert published["terminal_status"] == "COMPLETED_WITH_GAPS"
    assert published["item_count"] == published["counts"]["symbols"] == 2
    assert any(ev[0] == "CPP_SYMBOL_INDEX_COMPLETED" for ev in unit.job.events.log)

    steps = tuple(unit.job.config.steps)
    claims = runtime_claims({JOB_ID: steps}) + [
        Claim(JOB_ID, item.step, item.output_kind, item) for item in DATASETS
    ]
    tree = scan_run_tree(run_root, FileClaims(claims), max_files=100_000)
    mine = [
        p
        for p in tree.unaccounted
        if p.startswith(("data/code-index/clangd", f"data/jobs/{JOB_ID}"))
    ]
    assert mine == []


def _symbol_document(identifier: str, *, start: tuple[int, int] = (0, 4),
                     end: tuple[int, int] = (0, 10), file: str = "a.cpp",
                     name: str = "helper") -> str:
    return (
        f"--- !Symbol\nID: {identifier}\nName: {name}\nSymInfo:\n  Kind: Function\n"
        f"Definition:\n  FileURI: 'file:///target/source/{file}'\n"
        f"  Start:\n    Line: {start[0]}\n    Column: {start[1]}\n"
        f"  End:\n    Line: {end[0]}\n    Column: {end[1]}\n...\n"
    )


def _reference_document(target: str, sources: list[str], *, kind: int = 28,
                        file: str = "a.cpp", positions: list[tuple[int, int]] | None = None) -> str:
    positions = positions or [(0, 4)] * len(sources)
    return f"--- !Refs\nID: {target}\nReferences:\n" + "".join(
        f"  - Kind: {kind}\n    Container:\n      ID: {source}\n"
        f"    Location:\n      FileURI: 'file:///target/source/{file}'\n"
        f"      Start:\n        Line: {line}\n        Column: {column}\n"
        f"      End:\n        Line: {line}\n        Column: {column + 6}\n"
        for source, (line, column) in zip(sources, positions, strict=True)
    ) + "...\n"


def _published_rows(run_root: Path, result: dict, table: str) -> list[sqlite3.Row]:
    assert table in {"locations", "relations", "coverage", "entities"}
    with sqlite3.connect(run_root / result["index_identity"]["relative_path"]) as db:
        db.row_factory = sqlite3.Row
        return db.execute(f"SELECT * FROM {table}").fetchall()


def test_recursive_calls_survive_serialization_but_self_declarations_do_not(tmp_path: Path) -> None:
    run_root, _, scope, unit = _make_scope_and_unit(
        tmp_path, sources={"native/a.cpp": "int helper() { return helper() + helper(); }\n"}
    )
    identifier = "1111111111111111"
    text = (_symbol_document(identifier)
            + _reference_document(identifier, [identifier, identifier], positions=[(0, 22), (0, 33)])
            + _reference_document(identifier, [identifier], kind=1))
    result = _index_scope(unit, scope, lambda _u: FakeClangdExecutor(run_root, yaml_text=text))
    relations = _published_rows(run_root, result, "relations")
    assert len(relations) == 1
    edge = relations[0]
    assert edge["kind"] == RelationKind.CALLS.value
    assert edge["source_id"] == edge["target_id"]
    payload = json.loads(edge["payload_json"])
    assert payload["occurrences"] == 2
    assert [loc["column"] for loc in payload["locations"]] == [23, 34]
    assert result["counts"]["unresolved_references"] == 0
    assert result["terminal_status"] == "SUCCEEDED"


def test_relation_budget_preserves_later_occurrences_of_admitted_edges(tmp_path: Path) -> None:
    run_root, _, scope, unit = _make_scope_and_unit(
        tmp_path, settings_override={"max_relations_per_scope": 1, "locations_per_relation": 1},
        sources={"native/a.cpp": "int helper() { return 1; }\n"
                 "int main() { return helper() + helper() + helper(); }\n"
                 "int other() { return helper() + helper(); }\n"},
    )
    a, b, c = ("1111111111111111", "2222222222222222", "3333333333333333")
    text = (_symbol_document(a)
            + _symbol_document(b, start=(1, 4), end=(1, 8), name="main")
            + _symbol_document(c, start=(2, 4), end=(2, 9), name="other"))
    text += _reference_document(a, [b, c, b, c, b], positions=[(1, 20), (2, 21), (1, 31), (2, 32), (1, 42)])
    result = _index_scope(unit, scope, lambda _u: FakeClangdExecutor(run_root, yaml_text=text))
    relations = _published_rows(run_root, result, "relations")
    assert len(relations) == 1
    payload = json.loads(relations[0]["payload_json"])
    assert payload["occurrences"] == 3
    assert len(payload["locations"]) == 1
    assert result["counts"]["unresolved_references"] == 2
    assert result["gaps"] == ["clangd relation limit reached"]
    assert _published_rows(run_root, result, "coverage")[0]["status"] == "partial"


@pytest.mark.parametrize(
    "source,start,end,expected_bytes",
    [
        ("int helper() {}\n", (0, 4), (0, 10), (4, 10)),
        ("// α😀\r\nint helper() {}\r\n", (1, 4), (1, 10), (15, 21)),
        ("/*😀*/ int helper() {}\n", (0, 11), (0, 17), (13, 19)),
        ("int helper", (0, 4), (0, 10), (4, 10)),
        ("int\nhelper\n", (0, 0), (1, 6), (0, 10)),
    ],
    ids=("ascii", "crlf", "utf16", "eof", "multiline"),
)
def test_symbol_byte_spans_match_verified_utf16_positions(
    tmp_path: Path, source: str, start: tuple[int, int], end: tuple[int, int],
    expected_bytes: tuple[int, int],
) -> None:
    run_root, target_root, scope, unit = _make_scope_and_unit(tmp_path, sources={"native/a.cpp": source})
    text = _symbol_document("1111111111111111", start=start, end=end)
    result = _index_scope(unit, scope, lambda _u: FakeClangdExecutor(run_root, yaml_text=text))
    location = _published_rows(run_root, result, "locations")[0]
    assert (location["start_byte"], location["end_byte"]) == expected_bytes
    assert (location["start_line"], location["start_column"]) == (start[0] + 1, start[1] + 1)
    assert (location["end_line"], location["end_column"]) == (end[0] + 1, end[1] + 1)
    assert location["file_sha256"] == file_sha256(target_root / "native/a.cpp")
    assert result["terminal_status"] == "SUCCEEDED"


@pytest.mark.parametrize(
    "start,end",
    [
        ((1000, 4), (1000, 10)),
        ((0, 1000), (0, 1001)),
        ((0, 10), (0, 4)),
        ((0, -1), (0, 4)),
        ((0, 3), (0, 4)),  # middle of the astral character's UTF-16 surrogate pair
        ((0, 4), (1, 1)),  # past the empty final line
        ((0, 4095), (0, 4095)),  # clangd packed-position overflow sentinel
    ],
    ids=("line", "column", "reversed", "negative", "surrogate", "end", "overflow"),
)
def test_unresolvable_symbol_coordinates_publish_gap_not_exact_location(
    tmp_path: Path, start: tuple[int, int], end: tuple[int, int],
) -> None:
    run_root, _, scope, unit = _make_scope_and_unit(
        tmp_path, sources={"native/a.cpp": "/*😀*/ int helper() {}\n"}
    )
    text = _symbol_document("1111111111111111", start=start, end=end)
    result = _index_scope(unit, scope, lambda _u: FakeClangdExecutor(run_root, yaml_text=text))
    assert not _published_rows(run_root, result, "locations")
    assert result["counts"]["symbols"] == 0
    assert result["counts"]["external_symbols"] == 0
    assert any("source location" in gap for gap in result["gaps"])
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"


def test_invalid_reference_location_preserves_occurrence_but_not_fabricated_position(tmp_path: Path) -> None:
    run_root, _, scope, unit = _make_scope_and_unit(tmp_path)
    a, b = "1111111111111111", "2222222222222222"
    text = (_symbol_document(a) + _symbol_document(b, start=(1, 4), end=(1, 8), name="main")
            + _reference_document(a, [b, b], positions=[(1, 20), (1000, 4)]))
    result = _index_scope(unit, scope, lambda _u: FakeClangdExecutor(run_root, yaml_text=text))
    payload = json.loads(_published_rows(run_root, result, "relations")[0]["payload_json"])
    assert payload["occurrences"] == 2
    assert payload["locations"] == [{"path": "native/a.cpp", "line": 2, "column": 21, "ref_kind": 28}]
    assert any("source location" in gap for gap in result["gaps"])
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"


def test_invalid_definition_falls_back_to_verified_declaration_with_gap(tmp_path: Path) -> None:
    run_root, _, scope, unit = _make_scope_and_unit(tmp_path)
    text = _symbol_document("1111111111111111", start=(1000, 4), end=(1000, 10))
    text = text.removesuffix("...\n") + (
        "CanonicalDeclaration:\n  FileURI: 'file:///target/source/a.cpp'\n"
        "  Start:\n    Line: 0\n    Column: 4\n  End:\n    Line: 0\n    Column: 10\n...\n"
    )
    result = _index_scope(unit, scope, lambda _u: FakeClangdExecutor(run_root, yaml_text=text))
    location = _published_rows(run_root, result, "locations")[0]
    assert (location["start_byte"], location["end_byte"]) == (4, 10)
    assert result["counts"]["symbols"] == 1
    assert result["counts"]["external_symbols"] == 0
    assert any("source location" in gap for gap in result["gaps"])
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"


def test_truncated_diagnostics_never_certify_processed_coverage(tmp_path: Path) -> None:
    run_root, target_root, scope, unit = _make_scope_and_unit(tmp_path)
    text = _symbol_document("1111111111111111")
    executor = FakeClangdExecutor(run_root, yaml_text=text, stderr_truncated=True)
    result = _index_scope(unit, scope, lambda _u: executor)
    assert result["counts"]["processed_translation_units"] == 0
    assert result["counts"]["omitted_translation_units"] == 0
    assert result["counts"]["symbols"] == 1
    assert any("diagnostics" in gap and "truncated" in gap for gap in result["gaps"])
    assert _published_rows(run_root, result, "coverage")[0]["status"] == "partial"

    upstream = run_root / "upstream.json"
    write_manifest(upstream, run_id=unit.job.run_id, target_snapshot=unit.job.source_fingerprint,
                   target_root=target_root, indexes=())
    unit.job.input_manifest_path = upstream
    unit.job.input_manifest_sha256 = file_sha256(upstream)
    unit.outputs["load.accepted_cpp"] = {"upstream": {}, "unavailable": {}}
    unit.outputs["index.scopes"] = {
        "scopes": [result], "gaps": result["gaps"], "terminal_status": result["terminal_status"],
    }
    published = build_job().units[-1].handler(unit)
    summary = json.loads((run_root / published["artifact"]["path"]).read_text())
    assert summary["counts"]["processed_translation_units"] == 0
    assert summary["gaps"] == result["gaps"]
    assert published["terminal_status"] == "COMPLETED_WITH_GAPS"


@pytest.mark.parametrize("diagnostic", ("clean", "included", "direct", "error", "prefix"))
def test_translation_unit_paths_with_spaces_are_matched_exactly(tmp_path: Path, diagnostic: str) -> None:
    run_root, _, scope, unit = _make_scope_and_unit(
        tmp_path, sources={"native/a b.cpp": "int helper() {}\n", "native/a.cpp": "int other() {}\n"}
    )
    stderr = ("1[1/2] Processing file /target/source/a b.cpp\n"
              "[2/2] Processing file /target/source/a.cpp\n")
    stderr += {
        "clean": "",
        "included": ("In file included from /target/source/a b.cpp:1:\n"
                     "/target/source/include x.h:1:10: fatal error: 'cstdio' file not found\n"),
        "direct": "/target/source/a b.cpp:1:10: fatal error: 'cstdio' file not found\n",
        "error": "Error while processing /target/source/a b.cpp.\n",
        "prefix": "",
    }[diagnostic]
    if diagnostic == "prefix":
        stderr = "[1/1] Processing file /target/source/a b.cpp.extra\n"
    text = _symbol_document("1111111111111111", file="a%20b.cpp")
    result = _index_scope(
        unit, scope, lambda _u: FakeClangdExecutor(run_root, yaml_text=text, stderr_text=stderr)
    )
    expected_processed = 2 if diagnostic == "clean" else 0 if diagnostic == "prefix" else 1
    assert result["counts"]["processed_translation_units"] == expected_processed
    assert result["counts"]["omitted_translation_units"] == (2 if diagnostic == "prefix" else 0)
    if diagnostic in {"included", "direct"}:
        assert result["counts"]["translation_units_with_unresolved_headers"] == 1
        assert "a b.cpp" in next(g for g in result["gaps"] if g.startswith("system_headers_unresolved:"))
    assert result["terminal_status"] == ("SUCCEEDED" if diagnostic == "clean" else "COMPLETED_WITH_GAPS")
