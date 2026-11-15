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
)
from appsec_review.retrieval import IndexBuilder, RelationKind, write_manifest
from appsec_review.runtime import UnitContext
from appsec_review.storage import canonical_json, file_sha256, run_artifact


REPO_ROOT = Path(__file__).resolve().parents[3]


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
        "native/a.cpp": "int helper() { return 1; }\nint main() { return helper(); }\n",
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
    ) -> None:
        self.run_root = run_root
        self.yaml_text = yaml_text
        self.stderr_text = stderr_text
        self.exit_code = exit_code
        self.timed_out = timed_out
        self.oom_killed = oom_killed
        self.stdout_truncated = stdout_truncated
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
            False,
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
        Column:  30
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
    sizes: dict[str, int] = {}
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
    assert counts["unresolved_references"] == 3  # self-ref + bad container + non-mapping ref
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
            '--- !Symbol\nBad: "double"\n...\n',
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
