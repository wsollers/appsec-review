"""job_profile_data: bounded text parsers for folded-stacks, perf-script, Callgrind, and LLVM sample."""

from __future__ import annotations

import pytest

from appsec_review.jobs.job_profile_data import ProfileDocument, ProfileRow, parse_profile
from appsec_review.jobs.job_profile_data.parsers import _bounded_lines


def test_parses_folded_stacks_comments_blanks_and_bounds_frames() -> None:
    document = parse_profile(
        b"\xef\xbb\xbf# leading comment\n\nroot;dispatch;hot 9\nroot;dispatch;cold 2\n",
        "folded-stacks",
        max_frames_per_sample=2,
    )
    assert isinstance(document, ProfileDocument)
    assert all(isinstance(row, ProfileRow) for row in document.rows)
    values = {(row.symbol, row.count) for row in document.rows}
    assert values == {("dispatch", 11), ("hot", 9), ("cold", 2)}
    assert any("frame_truncation" in gap for gap in document.gaps)


def test_parses_perf_script_events_modules_unknown_and_frame_truncation() -> None:
    document = parse_profile(
        b"""ignored preamble without event
worker 123/124 [001] 42.5: cycles:
    7fff hot_fn+0x2 (libdemo.so)
    7ffe [unknown] ([unknown])
    7ffd bare_fn ()
    7ffc extra_one (libdemo.so)
    7ffb extra_two (libdemo.so)
non-indented line inside sample

worker 123/124 [001] 42.6: cycles:
    7fff hot_fn+0x2
""",
        "perf-script",
        max_frames_per_sample=3,
    )
    assert [(row.symbol, row.count, row.event, row.module) for row in document.rows] == [
        ("bare_fn", 1, "cycles", None),
        ("hot_fn+0x2", 1, "cycles", None),
        ("hot_fn+0x2", 1, "cycles", "libdemo.so"),
    ]
    gap_text = "\n".join(document.gaps)
    assert "ambiguous_symbol" in gap_text
    assert "frame_truncation" in gap_text


def test_parses_callgrind_event_costs_references_relative_positions_and_calls() -> None:
    document = parse_profile(
        b"""# header comment

version: 1
events: Ir Dr
fl=src/main.c
fn=handle
12 80 4
+1 20 1
-1 5 0
* 3 1
0 2 0
fl=
fn=second
+2 4 0
fl=(1) src/ref.c
fn=(1) hot_ref
10 7 0
fl=(1)
fn=(1)
+1 3 0
fl=(99)
fn=(99)
fn=caller
calls=1 1
5 6 0
cfl=(2) src/callee.c
cfn=(2) callee_ref
calls=2 1
6 11 1
cfl=(2)
cfn=(2)
calls=1 1
7 4 0
cfl=src/plain_callee.c
cfn=plain_callee
calls=1 1
8 9 0
""",
        "callgrind",
    )
    by_sym_src_line = {
        (row.symbol, row.event, row.source, row.line): row.count for row in document.rows
        if row.cost_kind == "self"
    }
    assert by_sym_src_line[("handle", "Ir", "src/main.c", 12)] == 88
    assert by_sym_src_line[("handle", "Ir", "src/main.c", 13)] == 20
    assert by_sym_src_line[("handle", "Ir", "src/main.c", None)] == 2
    assert by_sym_src_line[("second", "Ir", None, None)] == 4
    assert by_sym_src_line[("hot_ref", "Ir", "src/ref.c", 10)] == 7
    assert by_sym_src_line[("hot_ref", "Ir", "src/ref.c", 11)] == 3
    assert ("caller", "Ir", None, 5) not in by_sym_src_line
    assert {(row.symbol, row.source, row.line, row.callsite_line, row.count)
            for row in document.rows if row.cost_kind == "call_inclusive" and row.event == "Ir"} == {
        ("callee_ref", "src/callee.c", 1, 6, 11),
        ("callee_ref", "src/callee.c", 1, 7, 4),
        ("plain_callee", "src/plain_callee.c", 1, 8, 9),
    }
    gap_text = "\n".join(document.gaps)
    assert "ambiguous_line" in gap_text
    assert "ambiguous_source" in gap_text
    assert "ambiguous_symbol" in gap_text


def test_parses_llvm_sample_profile_function_headers_only() -> None:
    document = parse_profile(
        b"""# comment

ns::hot:120:4
 1: 100
 2.1: callee:20
unrecognized header line
cold:3:0
""",
        "llvm-sample",
    )
    assert [(row.symbol, row.count) for row in document.rows] == [("cold", 3), ("ns::hot", 120)]
    assert document.gaps == ("malformed_llvm_header: row 6 is not a supported function header",)


@pytest.mark.parametrize(("fmt", "payload", "kwargs", "match"), [
    ("pickle", b"x", {}, "unsupported profile format"),
    ("folded-stacks", b"a\x00b", {}, "contains NUL bytes"),
    ("folded-stacks", b"\xff\xfe", {}, "not UTF-8 text"),
    ("folded-stacks", b"a 1\n", {"max_rows": 0}, "bounds must be positive"),
    ("folded-stacks", b"abcdef 1\n", {"max_line_bytes": 4}, "exceeds 4 bytes"),
    ("folded-stacks", b"onlytoken\n", {}, "invalid folded-stack row"),
    ("folded-stacks", b"root;bad nope\n", {}, "invalid folded-stack row"),
    ("folded-stacks", b";;; 5\n", {}, "invalid folded-stack row"),
    ("folded-stacks", b"a -1\n", {}, "invalid folded-stack row"),
    ("folded-stacks", b"# comment only\n\n", {}, "contains no samples"),
    ("perf-script", b"no header here\n", {}, "contains no bounded samples"),
    ("perf-script", b"w 1 1.0: cycles:\n  7f unknown\n", {}, "contains no bounded samples"),
    ("callgrind", b"events: Ir\nfn=f\n12 nope\n", {}, "invalid Callgrind cost row"),
    ("callgrind", b"events: Ir\nfn=f\n", {}, "contains no event costs"),
    ("llvm-sample", b"# only comment\n 1: 5\n", {}, "contains no function headers"),
])
def test_parsers_reject_binary_empty_out_of_bounds_and_malformed_input(
    fmt: str, payload: bytes, kwargs: dict[str, int], match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        parse_profile(payload, fmt, **kwargs)


def test_bounded_lines_records_row_truncation_gap() -> None:
    lines, gaps = _bounded_lines(b"one\ntwo\nthree\n", max_rows=2, max_line_bytes=64)
    assert lines == ["one", "two"]
    assert gaps == ["row_truncation: retained 2 of 3 input lines"]
