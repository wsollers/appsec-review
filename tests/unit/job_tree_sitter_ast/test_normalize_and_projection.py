"""Unit tests for normalize.py and projection.py."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.jobs.job_tree_sitter_ast import GrammarLock, Scope
from appsec_review.jobs.job_tree_sitter_ast.datasets import DATASETS
from appsec_review.jobs.job_tree_sitter_ast.normalize import (
    attest_reused_shard,
    normalize_scope,
    reusable_shard,
)
from appsec_review.jobs.job_tree_sitter_ast.projection import project
from appsec_review.retrieval import IndexBuilder
from appsec_review.review.dispositions import SourceDispositions
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.shared import SharedArtifacts, publication_scope_for_owner, reference


def _lock(language: str = "Python", grammar: str = "python") -> GrammarLock:
    return GrammarLock(
        language, grammar, f"https://example.invalid/tree-sitter-{grammar}",
        "a" * 40, "MIT", f"libtree_sitter_{grammar}.so", "b" * 64,
    )


def _scope(language: str = "Python", digest: str = "c" * 64, size: int = 10) -> Scope:
    return Scope(
        "scope-python", "component:0001", "python", "source:component:0001",
        "python", language,
        ({"path": "python/app.py", "sha256": digest, "size_bytes": size, "language": language},),
    )


def _node(
    *,
    ordinal: tuple[int, ...] = (),
    kind: str = "module",
    field: str | None = None,
    named: bool = True,
    error: bool = False,
    missing: bool = False,
    start: int = 0,
    end: int = 10,
) -> dict[str, object]:
    return {
        "ordinal_path": list(ordinal),
        "field": field,
        "type": kind,
        "named": named,
        "error": error,
        "missing": missing,
        "extra": False,
        "has_error": error or missing,
        "start_byte": start,
        "end_byte": end,
        "start_point": [0, start],
        "end_point": [0, end],
    }


def test_normalization_preserves_spans_fields_malformed_flags_and_truncation(tmp_path: Path) -> None:
    scope, grammar = _scope(), _lock()
    output = {
        "schema": "appsec-review/tree-sitter-container-output/1",
        "scope_id": scope.scope_id,
        "language": scope.language,
        "records": [{
            "kind": "file",
            "path": "python/app.py",
            "status": "PARTIAL",
            "sha256": "c" * 64,
            "bytes": 10,
            "root_has_error": True,
            "truncated": True,
            "nodes": [
                _node(error=True),
                _node(ordinal=(0,), kind="ERROR", field="body", missing=True),
            ],
        }],
    }
    artifact, identity, counts = normalize_scope(
        run_root=tmp_path,
        target_snapshot="snapshot",
        scope=scope,
        grammar=grammar,
        fingerprint="f" * 64,
        container_output=output,
        producer={"job": "fixture"},
        artifact_path=tmp_path / "ast.jsonl",
        index_path=tmp_path / "ast.sqlite",
    )
    rows = [json.loads(line) for line in (tmp_path / artifact["path"]).read_text().splitlines()]
    child = next(row for row in rows if row["field"] == "body")
    assert child["location"]["start_line"] == 1 and child["location"]["start_column"] == 1
    assert child["grammar_native_type"] == "ERROR" and child["missing"] and child["syntax_only"]
    assert counts["diagnostic_count"] == 2 and counts["nodes_parsed"] == 2
    assert any("node limit" in gap for gap in identity.gaps)


def test_resume_requires_matching_fingerprint_and_both_immutable_hashes(tmp_path: Path) -> None:
    artifact, index, metadata = tmp_path / "a.jsonl", tmp_path / "a.sqlite", tmp_path / "a.json"
    assert reusable_shard(metadata, artifact, index, "f" * 64) is None

    artifact.write_bytes(b"ast\n")
    index.write_bytes(b"index")
    metadata.write_text("{corrupt", encoding="utf-8")
    assert reusable_shard(metadata, artifact, index, "f" * 64) is None

    atomic_json(metadata, {
        "fingerprint": "f" * 64,
        "artifact": {"sha256": file_sha256(artifact)},
        "index_identity": {"sha256": file_sha256(index)},
    })
    assert reusable_shard(metadata, artifact, index, "f" * 64) is not None
    assert reusable_shard(metadata, artifact, index, "0" * 64) is None
    index.write_bytes(b"changed")
    assert reusable_shard(metadata, artifact, index, "f" * 64) is None


def test_reused_shard_is_reattested_by_the_current_attempt(tmp_path: Path) -> None:
    root = tmp_path / "run-1"
    root.mkdir()

    def owner(attempt: str) -> SharedArtifacts:
        attempt_root = root / "data/jobs/job_tree_sitter_ast/attempts" / attempt
        actor = {
            "run_id": root.name,
            "job_id": "job_tree_sitter_ast",
            "attempt_id": attempt,
            "orchestration": {"system": "fixture"},
        }
        atomic_json(attempt_root / "claim.json", {
            **actor,
            "attempt_path": attempt_root.relative_to(root).as_posix(),
            "dataset_contract": dataset_contract(
                "job_tree_sitter_ast", ("load", "plan", "parse", "acceptance"), DATASETS
            ),
        })
        return SharedArtifacts(root, attempt_root, {**actor, "claim": reference(root, attempt_root / "claim.json")})

    index_path = root / "data/indices/analysis" / ("f" * 64 + ".sqlite")
    with publication_scope_for_owner(owner("attempt_0001")):
        sha = IndexBuilder(
            index_path, name="analysis", fingerprint="f" * 64, target_snapshot="snap", shard_id="scope-1"
        ).build()
    metadata = {"fingerprint": "f" * 64, "index_identity": {"name": "analysis", "shard_id": "scope-1", "sha256": sha}}
    with publication_scope_for_owner(owner("attempt_0002")):
        attest_reused_shard(root, index_path, metadata, target_snapshot="snap")
    receipts = sorted((root / "data/jobs/job_tree_sitter_ast/attempts").glob("*/shared/index-shard/*.json"))
    assert [path.parts[-4] for path in receipts] == ["attempt_0001", "attempt_0002"]
    values = [json.loads(path.read_text(encoding="utf-8")) for path in receipts]
    assert all(value["mode"] == "computed" and value["object"]["sha256"] == sha for value in values)
    assert values[0]["computation"] == values[1]["computation"]


def test_vendored_budget_exclusion_omitted_file_and_unmapped_grammar_coverage(tmp_path: Path) -> None:
    sh_bytes = b"echo hi\n"
    sh_sha = hashlib.sha256(sh_bytes).hexdigest()
    z_bytes = b"0123456789"
    z_sha = hashlib.sha256(z_bytes).hexdigest()
    dispositions = SourceDispositions(vendored=("**/third_party/**",))
    scope = Scope(
        "scope-sh", "component:0001", ".", "sh-build", ".", "Shell",
        (
            {"path": "run.sh", "sha256": sh_sha, "size_bytes": len(sh_bytes), "language": "Shell"},
            # Omit explicit 'disposition' key to exercise dispositions.classify() fallback!
            {"path": "third_party/z.sh", "sha256": z_sha, "size_bytes": 10, "language": "Shell"},
            {"path": "third_party/y.sh", "sha256": "e" * 64, "size_bytes": 10, "language": "Shell", "disposition": "vendored"},
            {"path": "omitted.sh", "sha256": "f" * 64, "size_bytes": 10, "language": "Shell"},
        ),
    )
    grammar = _lock("Shell", "bash")
    output = {
        "schema": "appsec-review/tree-sitter-container-output/1",
        "scope_id": scope.scope_id,
        "language": "Shell",
        "records": [
            {
                "kind": "file",
                "path": "run.sh",
                "status": "SUCCEEDED",
                "sha256": sh_sha,
                "bytes": len(sh_bytes),
                "grammar": "bash",
                "root_has_error": False,
                "truncated": False,
                "nodes": [_node(kind="program", end=len(sh_bytes))],
            },
            {
                "kind": "file",
                "path": "third_party/z.sh",
                "status": "PARTIAL",
                "sha256": z_sha,
                "bytes": 10,
                "grammar": "bash",
                "root_has_error": False,
                "truncated": True,
                "nodes": [_node(kind="program", end=10)],
            },
            {
                "kind": "file",
                "path": "third_party/y.sh",
                "status": "TRUNCATED",
                "reason": "scope_node_limit",
                "sha256": "e" * 64,
                "bytes": 10,
            },
        ],
    }
    _artifact, identity, counts = normalize_scope(
        run_root=tmp_path,
        target_snapshot="snapshot",
        scope=scope,
        grammar=grammar,
        fingerprint="f" * 64,
        container_output=output,
        producer={"job": "fixture"},
        artifact_path=tmp_path / "ast.jsonl",
        index_path=tmp_path / "ast.sqlite",
        source_bytes={"run.sh": sh_bytes, "third_party/z.sh": b"0123456789"},
        dispositions=dispositions,
    )
    assert counts["dispositions"] == {
        "files": {"first_party": 1, "vendored": 2},
        "nodes": {"first_party": 1, "vendored": 1},
        "excluded_files": {"vendored": 2},
    }
    assert identity.gaps == ("omitted.sh: container omitted accepted file",)

    # First-party TRUNCATED file becomes an explicit gap
    fp_scope = _scope(digest="1" * 64)
    fp_out = {
        "schema": "appsec-review/tree-sitter-container-output/1",
        "scope_id": fp_scope.scope_id,
        "language": "Python",
        "records": [{"path": "python/app.py", "sha256": "1" * 64, "status": "TRUNCATED", "reason": "file_byte_limit"}],
    }
    _, fp_id, _ = normalize_scope(
        run_root=tmp_path,
        target_snapshot="snapshot",
        scope=fp_scope,
        grammar=_lock(),
        fingerprint="a" * 64,
        container_output=fp_out,
        producer={"job": "fixture"},
        artifact_path=tmp_path / "fp.jsonl",
        index_path=tmp_path / "fp.sqlite",
    )
    assert fp_id.gaps == ("python/app.py: file_byte_limit",)


def test_normalize_scope_rejects_malformed_container_contracts(tmp_path: Path) -> None:
    src = b"x = 1\n"
    sha = hashlib.sha256(src).hexdigest()
    scope = _scope(digest=sha, size=len(src))
    grammar = _lock()

    def _call(out: dict[str, object], *, cur_scope: Scope = scope, sb: dict[str, bytes] | None = None) -> None:
        normalize_scope(
            run_root=tmp_path,
            target_snapshot="snap",
            scope=cur_scope,
            grammar=grammar,
            fingerprint="a" * 64,
            container_output=out,
            producer={"job": "fixture"},
            artifact_path=tmp_path / "err.jsonl",
            index_path=tmp_path / "err.sqlite",
            source_bytes=sb,
        )

    with pytest.raises(ValueError, match="unsupported Tree-sitter container output schema"):
        _call({"schema": "bad"})
    with pytest.raises(ValueError, match="scope identity mismatch"):
        _call({"schema": "appsec-review/tree-sitter-container-output/1", "scope_id": "wrong", "language": "Python"})

    bad_scope = Scope(
        "scope-python", "c", "p", "s", "p", "Python",
        ({"path": "python/app.py", "sha256": sha, "size_bytes": 6, "scope_role": "supplied_platform"},),
    )
    with pytest.raises(ValueError, match="out-of-scope source"):
        _call(
            {"schema": "appsec-review/tree-sitter-container-output/1", "scope_id": "scope-python", "language": "Python"},
            cur_scope=bad_scope,
        )

    with pytest.raises(ValueError, match="unaccepted or duplicate"):
        _call({
            "schema": "appsec-review/tree-sitter-container-output/1",
            "scope_id": "scope-python",
            "language": "Python",
            "records": [{"path": "unknown.py", "sha256": sha}],
        })

    with pytest.raises(ValueError, match="source hash mismatch"):
        _call({
            "schema": "appsec-review/tree-sitter-container-output/1",
            "scope_id": "scope-python",
            "language": "Python",
            "records": [{"path": "python/app.py", "sha256": "0" * 64, "status": "SUCCEEDED"}],
        })

    gen_backing = {
        "schema": "appsec-review/generated-source-backing/1",
        "object": {"path": "data/shared/objects/aa/aa.blob", "sha256": sha, "size_bytes": len(src)},
    }
    gen_scope = Scope(
        "scope-python", "c", "p", "s", "p", "Python",
        ({"path": "python/app.py", "sha256": sha, "size_bytes": len(src), "source_backing": gen_backing},),
    )
    with pytest.raises(ValueError, match="generated AST byte count differs"):
        _call(
            {
                "schema": "appsec-review/tree-sitter-container-output/1",
                "scope_id": "scope-python",
                "language": "Python",
                "records": [{"path": "python/app.py", "sha256": sha, "status": "SUCCEEDED", "bytes": 999}],
            },
            cur_scope=gen_scope,
        )

    with pytest.raises(ValueError, match="generated AST span exceeds accepted source bytes"):
        _call(
            {
                "schema": "appsec-review/tree-sitter-container-output/1",
                "scope_id": "scope-python",
                "language": "Python",
                "records": [{
                    "path": "python/app.py",
                    "sha256": sha,
                    "status": "SUCCEEDED",
                    "bytes": len(src),
                    "nodes": [_node(end=999)],
                }],
            },
            cur_scope=gen_scope,
        )

    with pytest.raises(ValueError, match="syntax projection source identity differs"):
        _call(
            {
                "schema": "appsec-review/tree-sitter-container-output/1",
                "scope_id": "scope-python",
                "language": "Python",
                "records": [{"path": "python/app.py", "sha256": sha, "status": "SUCCEEDED", "bytes": len(src), "nodes": []}],
            },
            sb={"python/app.py": b"tampered"},
        )

    with pytest.raises(ValueError, match="AST span exceeds accepted source bytes"):
        _call(
            {
                "schema": "appsec-review/tree-sitter-container-output/1",
                "scope_id": "scope-python",
                "language": "Python",
                "records": [{
                    "path": "python/app.py",
                    "sha256": sha,
                    "status": "SUCCEEDED",
                    "bytes": len(src),
                    "nodes": [_node(end=999)],
                }],
            },
            sb={"python/app.py": src},
        )


def test_projection_covers_declarators_kotlin_ts_exports_indirect_imports_and_name_bounds() -> None:
    assert project([], b"", grammar="bash", source_identity="src:1", identities={}) == {}

    with pytest.raises(ValueError, match="exceeds accepted source bytes"):
        project([_node(ordinal=(), kind="identifier", end=20)], b"short", grammar="python",
                source_identity="src:1", identities={(): "id:0"})

    # C nested pointer/function declarator unwrapping
    c_src = b"int **fn(void) { return 0; }"
    c_nodes = [
        _node(ordinal=(), kind="translation_unit", end=len(c_src)),
        _node(ordinal=(0,), kind="function_definition", end=len(c_src)),
        _node(ordinal=(0, 0), kind="pointer_declarator", field="declarator", start=4, end=14),
        _node(ordinal=(0, 0, 0), kind="function_declarator", field="declarator", start=6, end=14),
        _node(ordinal=(0, 0, 0, 0), kind="identifier", field="declarator", start=6, end=8),
    ]
    c_ids = {tuple(n["ordinal_path"]): f"id:{i}" for i, n in enumerate(c_nodes)}  # type: ignore[arg-type]
    c_proj = project(c_nodes, c_src, grammar="c", source_identity="src:c", identities=c_ids)
    assert c_proj[(0,)]["category"] == "definition"
    assert c_proj[(0,)]["written_name"] == "fn"

    # >64 nested declarators hit depth bound
    deep_nodes = [_node(ordinal=(), kind="function_definition", end=len(c_src))]
    path_acc: tuple[int, ...] = ()
    for _ in range(66):
        path_acc = (*path_acc, 0)
        deep_nodes.append(_node(ordinal=path_acc, kind="pointer_declarator", field="declarator", end=8))
    deep_lims: set[str] = set()
    project(
        deep_nodes, c_src, grammar="c", source_identity="src:c",
        identities={tuple(n["ordinal_path"]): "id" for n in deep_nodes},  # type: ignore[misc]
        limitations=deep_lims,
    )
    assert "declarator navigation depth bound reached" in deep_lims

    # Kotlin call_expression fallback without named field
    kt_src = b"runTask(1)"
    kt_nodes = [
        _node(ordinal=(), kind="source_file", end=len(kt_src)),
        _node(ordinal=(0,), kind="call_expression", end=len(kt_src)),
        _node(ordinal=(0, 0), kind="navigation_expression", end=7),
    ]
    kt_proj = project(
        kt_nodes, kt_src, grammar="kotlin", source_identity="src:kt",
        identities={(): "i0", (0,): "i1", (0, 0): "i2"},
    )
    assert kt_proj[(0,)]["category"] == "call_expression"
    assert kt_proj[(0,)]["written_name"] == "runTask"

    # TypeScript export_statement with/without source, import without named child, indirect require()
    ts_src = b"export { a }; export { b } from 'mod'; require('pkg');"
    ts_nodes = [
        _node(ordinal=(), kind="program", end=len(ts_src)),
        _node(ordinal=(0,), kind="export_statement", start=0, end=13),
        _node(ordinal=(1,), kind="export_statement", start=14, end=38),
        _node(ordinal=(1, 0), kind="string", field="source", start=32, end=37),
        _node(ordinal=(2,), kind="import_statement", start=14, end=38),
        _node(ordinal=(3,), kind="call_expression", start=39, end=53),
        _node(ordinal=(3, 0), kind="identifier", field="function", start=39, end=46),
    ]
    ts_ids = {tuple(n["ordinal_path"]): f"ts:{i}" for i, n in enumerate(ts_nodes)}  # type: ignore[arg-type]
    ts_proj = project(ts_nodes, ts_src, grammar="typescript", source_identity="src:ts", identities=ts_ids)
    assert (0,) not in ts_proj
    assert ts_proj[(1,)]["category"] == "import"
    assert ts_proj[(2,)]["category"] == "import"
    assert ts_proj[(3,)]["import_expression"] is True
    assert ts_proj[(3,)]["import_form"] == "call_expression"

    # >512-byte name, non-UTF-8 name, empty slice, error anchor, nested definitions
    long_name = b"a" * 513
    bad_utf8 = b"\xff\xfe"
    py_tail = b"\nclass Outer:\n    def inner():\n        x\n"
    buf = long_name + b" " + bad_utf8 + py_tail
    cls_start = len(long_name) + 1 + len(bad_utf8) + 1
    py_nodes = [
        _node(ordinal=(), kind="module", end=len(buf)),
        _node(ordinal=(0,), kind="identifier", start=0, end=513),
        _node(ordinal=(1,), kind="identifier", start=514, end=516),
        _node(ordinal=(2,), kind="identifier", start=0, end=0),
        _node(ordinal=(3,), kind="identifier", start=0, end=3, error=True),
        _node(ordinal=(4,), kind="class_definition", start=cls_start, end=len(buf)),
        _node(ordinal=(4, 0), kind="identifier", field="name", start=cls_start + 6, end=cls_start + 11),
        _node(ordinal=(4, 1), kind="function_definition", start=cls_start + 17, end=len(buf)),
        _node(ordinal=(4, 1, 0), kind="identifier", field="name", start=cls_start + 21, end=cls_start + 26),
        _node(ordinal=(4, 1, 1), kind="identifier", start=len(buf) - 2, end=len(buf) - 1),
    ]
    py_ids = {tuple(n["ordinal_path"]): f"py:{i}" for i, n in enumerate(py_nodes)}  # type: ignore[arg-type]
    py_lims: set[str] = set()
    py_proj = project(py_nodes, buf, grammar="python", source_identity="src:py", identities=py_ids, limitations=py_lims)
    assert py_lims == {"written names exceeding 512 bytes omitted", "non-UTF-8 written names omitted"}
    assert py_proj[(4, 1)]["enclosing_definition"] == py_ids[(4,)]
    assert py_proj[(4, 1, 1)]["syntactic_qualifiers"] == ["Outer", "inner"]
