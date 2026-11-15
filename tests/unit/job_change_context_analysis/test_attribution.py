"""Unit tests for git blame/diff parsing and Tree-sitter callable span extraction."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from appsec_review.jobs.job_change_context_analysis.attribution import (
    function_spans,
    innermost_function,
    parse_blame_commits,
    parse_blame_lines,
    parse_old_hunks,
)
from .support import HEAD, PARENT


def _node(
    path: str,
    sha: str,
    ordinal: list[int],
    kind: str,
    start_byte: int,
    end_byte: int,
    start_line: int,
    end_line: int,
    *,
    field: str | None = None,
    has_error: bool = False,
    error: bool = False,
    missing: bool = False,
) -> bytes:
    return json.dumps({
        "identity": f"node:{path}:{ordinal}",
        "path": path,
        "file_sha256": sha,
        "grammar_native_type": kind,
        "field": field,
        "has_error": has_error,
        "error": error,
        "missing": missing,
        "language": "C",
        "location": {
            "start_byte": start_byte,
            "end_byte": end_byte,
            "start_line": start_line,
            "end_line": end_line,
            "start_column": 1,
            "end_column": 1,
            "producer_location": {"ordinal_path": ordinal},
        },
    }).encode("utf-8")


def test_parse_blame_lines_commits_and_old_hunks() -> None:
    with pytest.raises(ValueError, match="blame line precedes its header"):
        parse_blame_lines(b"\torphan line\n")

    sha256_commit = "d" * 64
    porcelain = (
        b"author-mail <ignored@before.header>\n"
        + f"{HEAD} 1 1 2\n".encode()
        + b"author-mail <Alice@Example.TEST>\n"
        + b"summary initial\n"
        + b"\tline one\n"
        + f"{HEAD} 2 2\n".encode()
        + b"\tline two\n"
        + f"{sha256_commit} 3 3 1\n".encode()
        + b"\tline three\n"
    )
    assert parse_blame_lines(porcelain) == [
        (HEAD, "alice@example.test"),
        (HEAD, "alice@example.test"),
        (sha256_commit, ""),
    ]
    assert parse_blame_commits(porcelain) == [HEAD, HEAD, sha256_commit]

    diff = (
        b"diff --git a/a.py b/a.py\n"
        b"@@ -0,0 +1,4 @@\n"
        b"@@ -7 +7,2 @@ context\n"
        b"@@ -12,3 +13,0 @@\n"
    )
    assert parse_old_hunks(diff) == [(7, 1), (12, 3)]


def test_function_spans_extracts_named_and_nested_declarator_callables(tmp_path: Path) -> None:
    c_src = b"int *parse_req(void) {\n  return 0;\n}\nvoid (****deep)(void) {}\nvoid () {}\n"
    py_src = b"def \xff\xff():\n    pass\n"
    err_src = b"def broken():\n"
    (tmp_path / "a.c").write_bytes(c_src)
    (tmp_path / "b.py").write_bytes(py_src)
    (tmp_path / "err.py").write_bytes(err_src)
    c_sha = hashlib.sha256(c_src).hexdigest()
    py_sha = hashlib.sha256(py_src).hexdigest()
    err_sha = hashlib.sha256(err_src).hexdigest()

    name_start = c_src.index(b"parse_req")
    name_end = name_start + len(b"parse_req")

    records = [
        b"   ",
        _node("unwanted.py", "f" * 64, [], "module", 0, 1, 1, 1),
        _node("a.c", c_sha, [], "translation_unit", 0, len(c_src), 1, 5),
        _node("a.c", c_sha, [0], "function_definition", 0, 36, 1, 3),
        _node("a.c", c_sha, [0, 0], "pointer_declarator", 4, 20, 1, 1, field="declarator"),
        _node("a.c", c_sha, [0, 0, 0], "function_declarator", 5, 20, 1, 1, field="declarator"),
        _node("a.c", c_sha, [0, 0, 0, 0], "identifier", name_start, name_end, 1, 1, field="declarator"),
        _node("a.c", c_sha, [1], "function_definition", 37, 61, 4, 4),
        _node("a.c", c_sha, [1, 0], "p1", 42, 58, 4, 4, field="declarator"),
        _node("a.c", c_sha, [1, 0, 0], "p2", 43, 58, 4, 4, field="declarator"),
        _node("a.c", c_sha, [1, 0, 0, 0], "p3", 44, 58, 4, 4, field="declarator"),
        _node("a.c", c_sha, [1, 0, 0, 0, 0], "p4", 45, 58, 4, 4, field="declarator"),
        _node("a.c", c_sha, [2], "function_definition", 62, len(c_src), 5, 5),
        _node("b.py", py_sha, [], "module", 0, len(py_src), 1, 2),
        _node("b.py", py_sha, [0], "function_definition", 0, len(py_src), 1, 2),
        _node("b.py", py_sha, [0, 0], "identifier", 4, 6, 1, 1, field="name"),
        _node("err.py", err_sha, [], "module", 0, len(err_src), 1, 1),
        _node("err.py", err_sha, [0], "function_definition", 0, len(err_src), 1, 1, missing=True),
    ]
    spans, unreliable = function_spans(
        records,
        {
            "a.c": c_sha,
            "b.py": py_sha,
            "err.py": err_sha,
            "missing.py": PARENT + "0" * 24,
        },
        tmp_path,
    )
    assert unreliable == {
        "err.py": "function_parse_diagnostics",
        "missing.py": "function_spans_unavailable",
    }
    assert [fn["name"] for fn in spans["a.c"]] == ["parse_req", None, None]
    assert [fn["name"] for fn in spans["b.py"]] == [None]

    with pytest.raises(ValueError, match="Tree-sitter node hash does not match"):
        function_spans([_node("a.c", "0" * 64, [], "translation_unit", 0, 1, 1, 1)], {"a.c": c_sha}, tmp_path)


def test_innermost_function_selects_narrowest_enclosing_span() -> None:
    outer = {"name": "outer", "start_line": 1, "end_line": 20}
    inner = {"name": "inner", "start_line": 5, "end_line": 10}
    later = {"name": "later", "start_line": 12, "end_line": 18}
    assert innermost_function([outer, inner, later], 7) == inner
    assert innermost_function([inner, outer, later], 7) == inner
    assert innermost_function([outer, inner, later], 2) == outer
    assert innermost_function([outer, inner, later], 30) is None
