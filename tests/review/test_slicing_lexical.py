"""lexical_identifiers slice strategy: tokens, interacters, backward definitions, gaps and bounds."""
from __future__ import annotations

import random
from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from appsec_review.review.slicing import registry
from appsec_review.review.slicing.contract import (
    Anchor, FunctionSpan, LineKey, Precision, Reason, SliceContribution, SliceRequest, SliceSources,
    SliceStrategy, StrategyState,
)
from appsec_review.review.slicing.strategies import lexical
from appsec_review.review.slicing.strategies.lexical import LexicalIdentifiers

SHA_C, SHA_PY, SHA_X = "c" * 64, "d" * 64, "e" * 64
H, I, D = Reason.FUNCTION_HEADER, Reason.INTERACTER, Reason.BACKWARD_DEF

C_SOURCE = """#include <string.h>

int copy_name(char *dst, const char *src, size_t cap)
{
    /* copy the user's name
       into dst */
    size_t n = strlen(src);   // length of "src"
    char *tmp = dst;
    int unused = 7;
    if (n == cap) {
        return -1;
    }
    size_t len = n + 1;
    memcpy(tmp, src, len);
    return 0;
}

int other(int n) { return n; }
""".splitlines()

PY_SOURCE = '''def handler(request, limit=10):
    """Return rows."""
    raw = request.args.get("q")  # user input
    query = raw.strip()
    if query == "admin":
        return None
    count: int = len(query)
    for row in rows(query):
        print(row, "total")  # query again
    total = count + limit
    cursor.execute(query, total)
'''.splitlines()


class FakeSources:
    def __init__(self, files: Mapping[tuple[str, str], Sequence[str] | None]) -> None:
        self.files = dict(files)
        self.calls: list[tuple[str, str]] = []

    def source_lines(self, path: str, file_sha256: str) -> tuple[Sequence[str] | None, str | None]:
        self.calls.append((path, file_sha256))
        lines = self.files.get((path, file_sha256))
        return (None, "file not in the accepted source index") if lines is None else (lines, None)

    def ir_flows(self, path: str) -> Sequence[Mapping[str, Any]] | None:
        raise AssertionError("the lexical strategy reads source text only")

    def svf_records(self, path: str, line: int) -> Sequence[Mapping[str, Any]] | None:
        raise AssertionError("the lexical strategy reads source text only")

    def syntax_rows(self, path: str) -> Sequence[Mapping[str, Any]] | None:
        raise AssertionError("the lexical strategy reads source text only")


def _c_key(line: int) -> LineKey:
    return LineKey("src/a.c", SHA_C, line)


def _py_key(line: int) -> LineKey:
    return LineKey("src/app.py", SHA_PY, line)


C_SPANS = (FunctionSpan("src/a.c", SHA_C, 3, 16, function="copy_name"), FunctionSpan("src/a.c", SHA_C, 18, 18))
PY_SPAN = FunctionSpan("src/app.py", SHA_PY, 1, 11, function="handler")


def _sources(**overrides: Sequence[str] | None) -> FakeSources:
    files: dict[tuple[str, str], Sequence[str] | None] = {("src/a.c", SHA_C): C_SOURCE,
                                                          ("src/app.py", SHA_PY): PY_SOURCE}
    for name, lines in overrides.items():
        files[{"c": ("src/a.c", SHA_C), "py": ("src/app.py", SHA_PY)}[name]] = lines
    return FakeSources(files)


def _expand(anchors: tuple[Anchor, ...], functions: tuple[FunctionSpan, ...],
            sources: SliceSources | None = None) -> SliceContribution:
    return LexicalIdentifiers().expand(SliceRequest(anchors, functions, sources or _sources()))


def _by_line(contribution: SliceContribution) -> dict[tuple[str, int], set[Reason]]:
    assert all(line.basis == "lexical_identifiers" and line.precision is Precision.LEXICAL
               for line in contribution.lines)
    return {(line.key.path, line.key.line): set(line.reasons) for line in contribution.lines}


def test_c_sink_slice_has_interacters_backward_defs_and_headers_confined_to_spans() -> None:
    result = _expand((Anchor(_c_key(14), Reason.SINK, "sink"),), C_SPANS)

    assert result.state is StrategyState.APPLIED and result.gaps == ()
    assert _by_line(result) == {
        ("src/a.c", 3): {H, I, D},     # header, `src` parameter
        ("src/a.c", 7): {I, D},        # `src` interacter; defines `n` (transitive, from `len = n + 1`)
        ("src/a.c", 8): {I, D},        # `char *tmp = dst`
        ("src/a.c", 13): {I, D},       # `size_t len = n + 1`
        ("src/a.c", 18): {H},          # other span: header only, its `n` is unrelated
    }
    # comment-only mention of `dst`, an unrelated local, the comparison, and the anchor itself stay out
    assert not {6, 9, 10, 14} & {line.key.line for line in result.lines}
    assert [line.key for line in result.lines] == sorted(line.key for line in result.lines)


def test_python_slice_excludes_keywords_literals_comments_and_callees() -> None:
    anchors = (Anchor(_py_key(3), Reason.SOURCE, "src"), Anchor(_py_key(11), Reason.SINK, "sink"))
    result = _expand(anchors, (PY_SPAN,))

    assert result.state is StrategyState.APPLIED
    assert _by_line(result) == {
        ("src/app.py", 1): {H, I, D},  # `request` interacter, `request`/`limit` parameters
        ("src/app.py", 3): {D},        # anchor kept only for its new reason: defines `raw` used by line 4
        ("src/app.py", 4): {I, D},
        ("src/app.py", 5): {I},        # `query == "admin"` uses but does not define `query`
        ("src/app.py", 7): {I, D},     # `count: int = ...`, reached transitively from line 10
        ("src/app.py", 8): {I},
        ("src/app.py", 10): {I, D},
    }
    # line 9 names `total` in a string and `query` in a comment only; line 6 has keywords only
    assert not {2, 6, 9} & {line.key.line for line in result.lines}


def test_tokens_drop_literals_comments_keywords_numbers_and_call_targets() -> None:
    parsed = lexical._parse(["char c = '\\''; printf(\"%s x\", y); /* z */ w = 0x1F; // v",
                             "    q = 1 /* open", "  still comment r */ + s;", "#define T 4",
                             "x = rb'k' + f\"{u}\"  # tail"], 1, 5, lexical._SLASH)
    assert [lexical._data_names(parsed[number].tokens) for number in range(1, 5)] == [
        ["c", "y", "w"], ["q"], ["s"], []]
    hashed = lexical._parse(["x = rb'k' + f\"{u}\" // 2  # tail"], 1, 1, lexical._HASH)
    assert lexical._data_names(hashed[1].tokens) == ["x"]
    assert "self" in lexical.IGNORED_IDENTIFIERS and "nullptr" in lexical.IGNORED_IDENTIFIERS
    assert "next" not in lexical.IGNORED_IDENTIFIERS and "len" not in lexical.IGNORED_IDENTIFIERS


@pytest.mark.parametrize(("text", "defines"), [
    ("n = 1;", True), ("n += 2;", True), ("n <<= 1;", True), ("n := f()", True), ("n++;", True), ("--n;", True),
    ("size_t n;", True), ("char *n = p;", True), ("std::vector<int> n;", True), ("int[] n = a;", True),
    ("n[i] = 0;", True), ("n->len = 0;", True), ("a, n = f()", True), ("n: int = 3", True),
    ("for i, n in items:", True), ("const char *n = s;", True), ("with open(p) as n:", True),
    ("var n int", True),
    ("n == 1", False), ("if (n <= 1)", False), ("n >= 1", False), ("n != 1", False), ("x = n;", False),
    ("return n;", False), ("if (a & n)", False), ("f(n, x);", False), ("x = a > n;", False),
    ("x => n", False), ("obj.n = 1;", False), ("p->n = 1;", False), ("if n == y:", False),
])
def test_definition_patterns_separate_assignments_and_declarations_from_comparisons(text: str,
                                                                                   defines: bool) -> None:
    assert lexical._defines(text, "n") is defines


def test_comparison_lines_interact_but_do_not_define() -> None:
    result = _expand((Anchor(_c_key(13), Reason.PATH_STEP, "step"),), C_SPANS[:1])

    lines = _by_line(result)
    assert lines[("src/a.c", 10)] == {I} and lines[("src/a.c", 7)] == {I, D}
    assert ("src/a.c", 14) in lines and D not in lines[("src/a.c", 14)]   # later use is not a backward def


def test_transitive_rounds_are_bounded_and_a_cut_is_a_named_gap(monkeypatch: pytest.MonkeyPatch) -> None:
    chain = ["def f(x):", "    a = x", "    b = a", "    c = b", "    sink(c)"]
    sources = FakeSources({("src/chain.py", SHA_X): chain})
    span = FunctionSpan("src/chain.py", SHA_X, 1, 5)
    anchor = (Anchor(LineKey("src/chain.py", SHA_X, 5), Reason.SINK, "sink"),)

    result = _expand(anchor, (span,), sources)
    assert result.state is StrategyState.PARTIAL
    assert {key[1] for key, reasons in _by_line(result).items() if D in reasons} == {3, 4}
    assert result.gaps == ("slice_truncated: lexical_identifiers: backward definitions in src/chain.py:1-5 "
                           "stopped after 1 transitive round(s)",)

    monkeypatch.setattr(lexical, "MAX_ROUNDS", 3)
    deeper = _expand(anchor, (span,), sources)
    assert deeper.state is StrategyState.APPLIED and deeper.gaps == ()
    assert {key[1] for key, reasons in _by_line(deeper).items() if D in reasons} == {1, 2, 3, 4}


def test_identifier_cap_per_anchor_line_is_a_named_gap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lexical, "MAX_IDENTIFIERS_PER_LINE", 2)
    result = _expand((Anchor(_c_key(14), Reason.SINK, "sink"),), C_SPANS[:1])

    assert result.state is StrategyState.PARTIAL
    assert ("slice_truncated: lexical_identifiers: anchor src/a.c:14 has 3 identifiers; only the first 2 were "
            "followed") in result.gaps
    assert ("src/a.c", 13) not in _by_line(result)        # `len` was cut, and nothing else reaches line 13


def test_unavailable_source_is_partial_or_not_applicable() -> None:
    anchors = (Anchor(_c_key(14), Reason.SINK, "sink"), Anchor(_py_key(11), Reason.SINK, "sink"))
    partial = _expand(anchors, (*C_SPANS, PY_SPAN), _sources(py=None))
    assert partial.state is StrategyState.PARTIAL
    assert partial.gaps == ("slice_source_unavailable: lexical_identifiers: src/app.py: file not in the accepted "
                            "source index",)
    assert {line.key.path for line in partial.lines} == {"src/a.c"}

    sources = _sources(py=None, c=None)
    none = _expand(anchors, (*C_SPANS, PY_SPAN), sources)
    assert none.state is StrategyState.NOT_APPLICABLE and none.lines == ()
    assert "slice_strategy_not_applicable: lexical_identifiers: no verified source text for any function span" \
        in none.gaps
    assert sorted(sources.calls) == [("src/a.c", SHA_C), ("src/app.py", SHA_PY)]   # once per file

    empty = _expand(anchors, ())
    assert empty.state is StrategyState.NOT_APPLICABLE and empty.gaps


def test_out_of_range_spans_and_anchors_are_gaps_not_errors() -> None:
    short = C_SOURCE[:14]
    result = _expand((Anchor(_c_key(14), Reason.SINK, "s"), Anchor(_c_key(15), Reason.SINK, "t")),
                     (FunctionSpan("src/a.c", SHA_C, 3, 16), FunctionSpan("src/a.c", SHA_C, 18, 20)),
                     _sources(c=short))
    assert result.state is StrategyState.PARTIAL
    assert result.gaps == (
        "slice_source_unavailable: lexical_identifiers: anchor src/a.c:15 lies beyond the file's 14 lines",
        "slice_source_unavailable: lexical_identifiers: src/a.c:18-20 lies beyond the file's 14 lines",
        "slice_source_unavailable: lexical_identifiers: src/a.c:3-16 extends beyond the file's 14 lines",
    )
    assert max(line.key.line for line in result.lines) <= 14 and ("src/a.c", 8) in _by_line(result)


def test_output_is_deterministic_under_input_reordering() -> None:
    anchors = [Anchor(_c_key(14), Reason.SINK, "a"), Anchor(_c_key(7), Reason.PATH_STEP, "b"),
               Anchor(_py_key(3), Reason.SOURCE, "c"), Anchor(_py_key(11), Reason.SINK, "d")]
    spans = [*C_SPANS, PY_SPAN]
    first = _expand(tuple(anchors), tuple(spans))
    shuffler = random.Random(7)
    for _ in range(5):
        shuffler.shuffle(anchors)
        shuffler.shuffle(spans)
        assert _expand(tuple(anchors), tuple(spans)) == first


def test_registry_loads_the_lexical_strategy() -> None:
    strategy = registry.load("lexical_identifiers")
    assert isinstance(strategy, LexicalIdentifiers) and isinstance(strategy, SliceStrategy)
    assert strategy.name == "lexical_identifiers" and strategy.precision is Precision.LEXICAL
