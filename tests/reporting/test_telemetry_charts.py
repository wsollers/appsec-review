"""LaTeX rendering of the telemetry chart blocks and the configurable head label."""
from __future__ import annotations

import difflib
from dataclasses import replace
from pathlib import Path
import re

import pytest

from appsec_review.reporting import load_document, render_latex
from appsec_review.reporting.latex import (BAR_W, BAR_X0, MIN_SEG_W, TL_W, TL_X0, bar_geometry, segment_span, tick_label,
                                           timeline_ticks)
from appsec_review.reporting.model import Bar, BarChart, Document, Lane, Segment, Timeline, Truncation

from .fixture import HOSTILE, build_fixture

COORD = re.compile(r"\((-?\d+\.\d{3}),(-?\d+\.\d{3})\)")


def _doc(*blocks, **changes) -> Document:
    base = Document(title="Telemetry", run_id="2026-10-29-0001", subtitle="", status_badge="COMPLETE",
                    status_tone="confirmed", source_date_epoch=0, ledger_head="ab" * 32, blocks=tuple(blocks))
    return replace(base, **changes)


def _body(document: Document) -> str:
    return render_latex(document).split(r"\begin{document}", 1)[1]


def _bars(body: str) -> list[tuple[float, float]]:
    out = []
    for line in body.splitlines():
        if line.startswith(r"\fill[chartbar"):
            (x0, _), (x1, _) = COORD.findall(line)
            out.append((float(x0), float(x1)))
    return out


@pytest.fixture(scope="module")
def review_document(tmp_path_factory: pytest.TempPathFactory):
    return load_document(build_fixture(tmp_path_factory.mktemp("fixture")))


def test_default_head_label_leaves_review_report_unchanged(review_document) -> None:
    default = render_latex(review_document)
    assert "headlabel" not in default
    setup = default.split(r"\reportsetup{", 1)[1].split("\n")[1:8]
    assert [line.split("=", 1)[0].strip() for line in setup] == ["title", "subtitle", "run", "status", "head", "renderer", "pdftitle"]
    labelled = render_latex(replace(review_document, head_label="metrics summary sha256"))
    added = [line for line in difflib.ndiff(default.splitlines(), labelled.splitlines()) if line[:1] in "+-"]
    assert added == ["+   headlabel={metrics summary sha256},"]


def test_head_label_is_escaped(review_document) -> None:
    latex = render_latex(replace(review_document, head_label="x}\\write18{id}"))
    assert r"headlabel={x\}\textbackslash{}write18\{id\}}," in latex


def test_bar_chart_scales_to_largest_bar() -> None:
    chart = BarChart("Jobs", "seconds", (Bar("a", 10, "10 s"), Bar("b", 5, "5 s"), Bar("c", 0, "0 s"), Bar("d", 40, "40 s")))
    assert bar_geometry(chart.bars) == [(BAR_X0, BAR_X0 + BAR_W / 4), (BAR_X0, BAR_X0 + BAR_W / 8),
                                         (BAR_X0, BAR_X0), (BAR_X0, BAR_X0 + BAR_W)]
    drawn = _bars(_body(_doc(chart)))
    assert len(drawn) == 3  # the zero bar draws only its track
    assert drawn[-1] == (round(BAR_X0, 3), round(BAR_X0 + BAR_W, 3))
    assert all(0 <= x <= 1 for pair in drawn for x in pair)


@pytest.mark.parametrize("bars", [(), (Bar("a", 0, "0"), Bar("b", -3, "-3"), Bar("c", float("nan"), "?"))])
def test_bar_chart_without_data_says_so(bars) -> None:
    assert bar_geometry(bars) is None
    body = _body(_doc(BarChart("Empty", "ms", bars, caption="cap", omitted=Truncation(2, "bars", "f" * 64))))
    assert r"\chartempty{No data}" in body and "tikzpicture" not in body
    assert r"\chartcaption{cap}" in body and rf"\truncnote{{2}}{{bars}}{{{'f' * 64}}}" in body


def test_timeline_ticks_are_round_and_bounded() -> None:
    assert timeline_ticks(0) == [] and timeline_ticks(-5) == []
    assert timeline_ticks(1_012_000) == [0, 300_000, 600_000, 900_000]
    assert timeline_ticks(950) == [0, 200, 400, 600, 800]
    assert len(timeline_ticks(10 * 86_400_000)) <= 7
    assert [tick_label(t) for t in (0, 300_000, 1_500)] == ["0", "5m 00s", "1.5 s"]


def test_timeline_segments_are_clamped_and_zero_width_is_visible() -> None:
    total = 1000
    assert segment_span(Segment(0, 500), total) == pytest.approx((TL_X0, TL_X0 + TL_W / 2))
    assert segment_span(Segment(-200, 5000), total) == pytest.approx((TL_X0, TL_X0 + TL_W))  # running past the end
    x0, x1 = segment_span(Segment(500, 500), total)
    assert x1 - x0 == pytest.approx(MIN_SEG_W) and x0 < TL_X0 + TL_W / 2 < x1
    x0, x1 = segment_span(Segment(1000, 1000), total)
    assert x1 == pytest.approx(TL_X0 + TL_W) and x1 - x0 == pytest.approx(MIN_SEG_W)
    x0, x1 = segment_span(Segment(600, 100), total)  # end before start collapses to a marker
    assert x1 - x0 == pytest.approx(MIN_SEG_W)


def test_timeline_renders_axis_lanes_and_empty_cases() -> None:
    timeline = Timeline("Jobs", 60_000, (Lane("build", (Segment(0, 30_000, "confirmed", "run 1"),), "30.0 s"),
                                         Lane("review", (Segment(30_000, 30_000),), "0 ms")), caption="Wall clock")
    body = _body(_doc(timeline))
    assert body.count(r"\draw[chartgrid]") == len(timeline_ticks(60_000))
    assert r"\node[charttick] at (0.205,-3.300) {0};" in body
    assert body.count(r"\fill[chartbar") == 2 and r"\node[chartseg]" in body
    assert r"\chartcaption{Wall clock}" in body
    for empty in (replace(timeline, total_ms=0), replace(timeline, lanes=())):
        assert r"\chartempty{No timing data}" in _body(_doc(empty))


def test_tones_map_to_palette_colours_with_neutral_fallback() -> None:
    chart = BarChart("t", "", tuple(Bar(tone, 1, "1", tone) for tone in ("confirmed", "not_reachable", "neutral", "bogus}\\x")))
    fills = re.findall(r"\\fill\[chartbar,fill=([^\]]+)\]", _body(_doc(chart)))
    assert fills == ["verdict-confirmed", "verdict-not-reachable", "brand", "brand"]


def test_hostile_labels_are_inert() -> None:
    chart = BarChart(HOSTILE, HOSTILE, (Bar(HOSTILE, 1, HOSTILE, HOSTILE),), caption=HOSTILE)
    timeline = Timeline(HOSTILE, 10, (Lane(HOSTILE, (Segment(0, 10, HOSTILE, HOSTILE),), HOSTILE),), caption=HOSTILE)
    body = _body(_doc(chart, timeline, head_label=HOSTILE))
    for needle in ("\\input{", "\\write18", "\\immediate", "\\end{document}\\begin", "^^", "\x00", "\x1b", "\u202e", "\u4e2d"):
        assert needle not in body, needle
    assert body.count(r"\end{document}") == 1
    assert not re.search(r"[\x00-\x08\x0b-\x1f\x7f]", body)
    labels = re.findall(r"\\node\[chartlabel\] at \([^)]*\) \{(.*)\};$", body, re.M)
    assert labels and all(len(re.sub(r"\\[a-z]+\{\}|\{|\}|\\", "", label)) < 80 for label in labels)


def test_chart_output_is_deterministic_and_fixed_precision() -> None:
    def build():
        return _doc(BarChart("b", "s", (Bar("x", 1 / 3, "a"), Bar("y", 2 / 3, "b"))),
                    Timeline("t", 7_777, (Lane("l", (Segment(1, 7_000, "supported"),)),)))
    first, second = render_latex(build()), render_latex(build())
    assert first == second
    for x, y in COORD.findall(first):
        assert re.fullmatch(r"-?\d+\.\d{3}", x) and re.fullmatch(r"-?\d+\.\d{3}", y) and not x.startswith("-")


def test_badge_label_overrides_the_tone_words_in_both_renderers() -> None:
    from appsec_review.reporting import render_html
    from appsec_review.reporting.model import Box, Cell, Field, Fields, Table
    from appsec_review.reporting.tokens import BoxKind

    document = _doc(Box(BoxKind.PROVENANCE, "Attempt", items=(
        Fields((Field("Status", "FAILED", badge="contradicted", badge_label="TIMED OUT"),)),
        Table(("Task",), ((Cell("x", badge="contradicted", badge_label="FAILED"),),), (1.0,)))))
    body = _body(document)
    assert r"\badge{contradicted}{TIMED OUT}" in body and r"\badge{contradicted}{FAILED}" in body
    assert r"\cellbadge{\badge{contradicted}{FAILED}}" in body           # table badges fit their column
    assert r"\cellbadge{\badge{contradicted}{TIMED OUT}}" not in body
    assert "CONTRADICTED" not in body
    html = render_html(document)
    assert '<span class="badge" data-state="contradicted">TIMED OUT</span>' in html
    assert '<span class="badge" data-state="contradicted">FAILED</span>' in html


def test_chart_labels_keep_their_attempt_suffix_when_cut() -> None:
    from appsec_review.reporting.latex import TL_LABEL_CHARS, _fit
    label = _fit("job_final_report_publication (a2)", TL_LABEL_CHARS)
    assert len(label) == TL_LABEL_CHARS and label.endswith("\u2026 (a2)") and label.startswith("job_final")
    assert _fit("short (a1)", TL_LABEL_CHARS) == "short (a1)"
    assert _fit("x" * 40, 10) == "x" * 9 + "\u2026"


def test_a_box_opening_with_a_tall_table_reserves_room_for_its_title() -> None:
    from appsec_review.reporting.model import Box, Cell, Table
    from appsec_review.reporting.tokens import BoxKind

    def body(rows: int) -> str:
        table = Table(("Task",), tuple((Cell(f"t{index}"),) for index in range(rows)), (1.0,))
        return _body(_doc(Box(BoxKind.RESULT, "Steps", items=(table,))))

    assert r"\needspace{16\baselineskip}" + "\n" + r"\begin{abox}" in body(12)
    assert r"\needspace{30\baselineskip}" in body(80)
    assert r"\needspace" not in body(3)
