"""Function spans across every catalog language (``review.slicing.spans``).

The fixtures under ``tests/fixtures/function_spans/source`` mark each named function's first and last lines
(``BEGIN:<id>`` / ``END:<id>``) and anchor lines with their expected enclosing function (``ANCHOR:<id>``, or
``ANCHOR:none`` for code outside every named function). ``ast-golden.json.gz`` is the locked Tree-sitter
parser's real output for them; the tests replay it through the production syntax projection.
"""
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
import re

import pytest

from appsec_review.jobs.cataloging import LANGUAGES as CATALOG
from appsec_review.jobs.job_tree_sitter_ast.generated_sources import _LANGUAGES as GENERATED
from appsec_review.jobs.job_tree_sitter_ast.projection import project
from appsec_review.review.slicing import spans
from appsec_review.review.slicing.spans import Header, resolve, text_extent

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "function_spans"
SOURCE = FIXTURES / "source"
GOLDEN = json.loads(gzip.decompress((FIXTURES / "ast-golden.json.gz").read_bytes()))
MARKER = re.compile(r"\b(BEGIN|END|ANCHOR):([\w-]+)")
FILES = sorted(path.relative_to(SOURCE).as_posix() for path in SOURCE.rglob("*") if path.is_file())


def _markers(text: str) -> tuple[dict[str, tuple[int, int]], dict[int, str]]:
    begins: dict[str, int] = {}
    ends: dict[str, int] = {}
    anchors: dict[int, str] = {}
    for number, line in enumerate(text.splitlines(), 1):
        for kind, name in MARKER.findall(line):
            {"BEGIN": begins, "END": ends}.get(kind, {})[name] = number
            if kind == "ANCHOR":
                anchors[number] = name
    assert begins.keys() == ends.keys()
    return {name: (begins[name], ends[name]) for name in begins}, anchors


def _rows(relative: str, data: bytes, *, sha: str | None = None) -> list[dict]:
    record = GOLDEN["files"][relative]
    sha = sha or record["sha256"]
    identities = {tuple(node["ordinal_path"]): f"asr:ast:{relative}:{'/'.join(map(str, node['ordinal_path']))}"
                  for node in record["nodes"]}
    projection = project(record["nodes"], data, grammar=record["grammar"], source_identity=f"asr:file:{relative}",
                         identities=identities)
    rows = []
    for node in record["nodes"]:
        ordinal = tuple(node["ordinal_path"])
        payload = {"grammar_native_type": node["type"], "field": node.get("field"), "language": record["language"],
                   **{flag: bool(node.get(flag)) for flag in ("named", "error", "missing", "extra", "has_error")}}
        if ordinal in projection:
            payload["syntax"] = projection[ordinal]
        rows.append({"identity": identities[ordinal], "kind": "ast_node", "native_id": "/".join(map(str, ordinal))
                     or "root", "name": node["type"], "text": node["type"], "payload": payload,
                     "location": {"path": relative, "file_sha256": sha, "start_byte": node["start_byte"],
                                  "end_byte": node["end_byte"], "start_line": node["start_point"][0] + 1,
                                  "end_line": node["end_point"][0] + 1, "start_column": node["start_point"][1] + 1,
                                  "end_column": node["end_point"][1] + 1}})
    return rows


def _load(relative: str) -> tuple[bytes, list[str], str]:
    data = (SOURCE / relative).read_bytes()
    return data, data.decode().splitlines(), hashlib.sha256(data).hexdigest()


def _cases() -> list[tuple[str, int, str]]:
    cases = []
    for relative in FILES:
        _spans, anchors = _markers((SOURCE / relative).read_text())
        cases.extend((relative, line, name) for line, name in sorted(anchors.items()))
    return cases


CASES = _cases()


def test_fixtures_cover_every_language_and_the_golden_matches_their_bytes():
    assert {Path(relative).suffix for relative in FILES} >= {".c", ".cpp", ".cs", ".go", ".java", ".js", ".ts",
                                                             ".tsx", ".kt", ".php", ".ps1", ".py", ".rb", ".rs",
                                                             ".sh", ".swift"}
    for relative in FILES:
        spans_, anchors = _markers((SOURCE / relative).read_text())
        assert spans_ and "none" in anchors.values(), relative
        if relative in GOLDEN["files"]:
            assert GOLDEN["files"][relative]["sha256"] == hashlib.sha256((SOURCE / relative).read_bytes()).hexdigest()
            assert GOLDEN["files"][relative]["root_has_error"] is False, relative
    assert set(GOLDEN["files"]) == {relative for relative in FILES if not relative.endswith(".swift")}


def test_every_catalog_and_generated_suffix_has_a_text_rule():
    suffixes = set(CATALOG) | {suffix for suffix in GENERATED if suffix.startswith(".")}
    missing = sorted(suffix for suffix in suffixes if spans.language_of(f"x{suffix}") is None)
    assert missing == []
    assert set(spans.CALLABLES) >= set(spans.GRAMMARS.values())


@pytest.mark.parametrize(("relative", "line", "expected"), CASES, ids=[f"{r}:{n}" for r, n, _ in CASES])
def test_tree_sitter_rows_resolve_the_marked_function(relative, line, expected):
    data, lines, sha = _load(relative)
    rows = _rows(relative, data) if relative in GOLDEN["files"] else None
    marked, _anchors = _markers(data.decode())
    resolution = resolve(lines, line, relative, sha, rows=rows)
    if expected == "none":
        assert resolution.extent is None and resolution.reason, resolution
        if rows:
            assert "tree_sitter places line" in resolution.reason
        return
    assert resolution.extent is not None, resolution.reason
    assert (resolution.extent.first, resolution.extent.last) == marked[expected]
    assert resolution.extent.basis == (spans.SPAN_TREE_SITTER if rows else spans.SPAN_TEXT)
    assert resolution.notes == ()


@pytest.mark.parametrize(("relative", "line", "expected"), CASES, ids=[f"{r}:{n}" for r, n, _ in CASES])
def test_text_rules_alone_resolve_the_marked_function(relative, line, expected):
    _data, lines, sha = _load(relative)
    marked, _anchors = _markers("\n".join(lines))
    resolution = resolve(lines, line, relative, sha)
    if expected == "none":
        assert resolution.extent is None
        assert "tried: text" in resolution.reason and spans.language_of(relative).name in resolution.reason
        return
    assert resolution.extent is not None, resolution.reason
    assert (resolution.extent.first, resolution.extent.last) == marked[expected]
    assert resolution.extent.basis == spans.SPAN_TEXT


def test_tree_sitter_names_come_from_the_projection_or_the_source():
    data, lines, sha = _load("go/spans.go")
    rows = _rows("go/spans.go", data)
    names = {resolve(lines, line, "go/spans.go", sha, rows=rows).extent.name
             for line, name in _markers(data.decode())[1].items() if name != "none"}
    assert {"Add", "Join", "clean"} <= names
    data, lines, sha = _load("shell/spans.sh")
    rows = _rows("shell/spans.sh", data)
    names = {resolve(lines, line, "shell/spans.sh", sha, rows=rows).extent.name
             for line, name in _markers(data.decode())[1].items() if name != "none"}
    assert names == {"load_items", "render"}


def test_rows_of_another_file_version_are_ignored():
    data, lines, sha = _load("python/spans.py")
    rows = _rows("python/spans.py", data, sha="0" * 64)
    marked, anchors = _markers(data.decode())
    line = next(number for number, name in anchors.items() if name == "fetch")
    resolution = resolve(lines, line, "python/spans.py", sha, rows=rows)
    assert resolution.extent.basis == spans.SPAN_TEXT
    assert (resolution.extent.first, resolution.extent.last) == marked["fetch"]


def test_uncovered_or_damaged_rows_fall_back_with_a_named_note():
    data, lines, sha = _load("rust/spans.rs")
    marked, anchors = _markers(data.decode())
    line = next(number for number, name in anchors.items() if name == "helper")
    rows = [row for row in _rows("rust/spans.rs", data) if row["location"]["start_line"] < marked["helper"][0]]
    resolution = resolve(lines, line, "rust/spans.rs", sha, rows=rows)
    assert resolution.extent.basis == spans.SPAN_TEXT
    assert (resolution.extent.first, resolution.extent.last) == marked["helper"]
    assert resolution.notes and resolution.notes[0].startswith(spans.GAP_FUNCTION_FALLBACK)

    rows = _rows("rust/spans.rs", data)
    for row in rows:
        payload = row["payload"]
        if row["native_id"] == "root":
            payload["has_error"] = True
        elif payload["grammar_native_type"] == "function_item" and row["location"]["start_line"] == marked["helper"][0]:
            payload["error"] = True
    resolution = resolve(lines, line, "rust/spans.rs", sha, rows=rows)
    assert resolution.extent.basis == spans.SPAN_TEXT and "parse errors" in resolution.notes[0]


def test_graph_symbol_headers_prefer_the_step_function_then_the_nearest_header():
    _data, lines, sha = _load("kotlin/Spans.kt")
    marked, anchors = _markers("\n".join(lines))
    line = next(number for number, name in anchors.items() if name == "count")
    headers = (Header(marked["count"][0], "count", "asr:symbol:count"), Header(1, "file", "asr:symbol:file"))
    resolution = resolve(lines, line, "kotlin/Spans.kt", sha, headers=headers, function="asr:symbol:count")
    assert resolution.extent.basis == spans.SPAN_GRAPH_SYMBOL and resolution.extent.name == "count"
    assert (resolution.extent.first, resolution.extent.last) == marked["count"]
    # A header whose extent does not contain the line is skipped; the text rules still answer.
    resolution = resolve(lines, line, "kotlin/Spans.kt", sha, headers=(Header(marked["helper"][0], "helper"),))
    assert resolution.extent.basis == spans.SPAN_TEXT


def test_long_functions_are_windowed_and_marked_truncated():
    body = ["def big(x):"] + [f"    x += {index}" for index in range(300)] + ["    return x"]
    resolution = resolve(body, 30, "big.py", "f" * 64, max_lines=50)
    assert (resolution.extent.first, resolution.extent.last, resolution.extent.truncated) == (1, 50, True)
    # The header is beyond the text scan bound: a named gap, never an invented window.
    resolution = resolve(body, 250, "big.py", "f" * 64, max_lines=50)
    assert resolution.extent is None and "within 50 lines" in resolution.reason
    first, last, truncated = text_extent(body, 1, "big.py", max_lines=50)
    assert (first, last, truncated) == (1, 50, True)


def test_unknown_languages_are_named_gaps_and_text_extent_keeps_its_window():
    lines = ["procedure Main is", "begin", "  null;", "end Main;"]
    resolution = resolve(lines, 3, "main.adb", "a" * 64)
    assert resolution.extent is None and "no function-span rule for .adb" in resolution.reason
    assert text_extent(lines, 1, "main.adb") == (1, 4, False)


def test_brace_declarations_and_callbacks_are_not_functions():
    lines = ["int helper(int x);", "void run(void) {", "  register_cb(cb, ^{ go(); });", "}",
             "struct Point {", "  int x;", "};"]
    assert text_extent(lines, 5, "a.c") == (5, 7, False)
    resolution = resolve(lines, 3, "a.c", "c" * 64)
    assert (resolution.extent.first, resolution.extent.last) == (2, 4)
    assert resolve(lines, 1, "a.c", "c" * 64).extent is None
