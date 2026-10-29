"""Fill the LaTeX template from a report document: ``report.tex`` plus the source-date file.

The renderer writes only the *content* (escaped text inside the macros that
``containers/report/latex/template/appsec-report.cls`` defines); layout and colour live in the
template. Every string is escaped by ``text.tex``/``text.tex_mono``; no run text can open a TeX
command, and the engine runs without shell escape. Charts (``BarChart``, ``Timeline``) are laid out
here in Python; the template receives only TikZ primitives with fixed-precision coordinates.
"""
from __future__ import annotations

import math
from pathlib import Path
import re
from typing import Iterable, Sequence

from .model import (Bar, BarChart, Block, Box, Bullets, Code, Document, Fields, Field, Heading, IdList, Item, Lane, Legend,
                    Note, PageBreak, Para, Segment, Stats, Table, Timeline, Truncation)
from .text import clean, tex, tex_code_line, tex_mono, token
from .tokens import badge_text, BOX_STYLES, STYLE_BY_KIND, VERDICT_COLOR, VERDICTS, EXTRA_VERDICTS, BoxKind

SKELETON = "report-skeleton.tex"
PALETTE = "appsec-palette.tex"
DEFAULT_HEAD_LABEL = "ledger head"
_ASCII = re.compile(r"[^A-Za-z0-9 ._:,/-]+")


def default_template_dir() -> Path:
    return Path(__file__).resolve().parents[3] / "containers" / "report" / "latex" / "template"


def verdict_color_name(state: str) -> str:
    return state.replace("_", "-") if state in VERDICT_COLOR else "unknown"


def badge(state: str, label: str | None = None) -> str:
    safe = token(state)
    label = label if label is not None else badge_text(safe).upper()
    return rf"\badge{{{verdict_color_name(safe)}}}{{{tex(label)}}}"


def _trunc(cut: Truncation) -> str:
    return rf"\truncnote{{{cut.omitted}}}{{{tex(cut.unit)}}}{{{cut.sha256}}}"


def _inline_cut(cut: Truncation) -> str:
    return rf"\ {{\scriptsize\itshape\muted{{(+{cut.omitted} {tex(cut.unit)}, sha256 {cut.sha256[:16]})}}}}"


def _field(row: Field) -> str:
    if row.badge:
        value = badge(row.badge, row.badge_label)
    elif row.mono:
        value = rf"\mono{{{tex_mono(row.value)}}}"
    else:
        value = tex(row.value)
    if row.truncation:
        value += _inline_cut(row.truncation)
    return rf"\kv{{{tex(row.label)}}}{{{value}}}"


def _table(item: Table) -> list[str]:
    columns = []
    for index, width in enumerate(item.widths):
        mono = any(row[index].mono for row in item.rows if index < len(row))
        columns.append(rf"{'M' if mono else 'Y'}{{\dimexpr {width:.3f}\linewidth-2\tabcolsep\relax}}")
    lines = [r"\tablestart\noindent\begin{tabular}{@{}" + "".join(columns) + r"@{}}",
             " & ".join(rf"\thead{{{tex(header)}}}" for header in item.headers) + r" \\ \midrule"]
    for row in item.rows:
        cells = []
        for cell in row:
            cells.append(badge(cell.badge, cell.badge_label) if cell.badge
                         else (tex_mono(cell.text) if cell.mono else tex(cell.text)))
        lines.append(" & ".join(cells) + r" \\")
    lines.append(r"\end{tabular}\par")
    if item.omitted:
        lines.append(_trunc(item.omitted))
    return lines


def _item(item: Item) -> list[str]:
    if isinstance(item, Para):
        text = tex(item.text)
        lines = [rf"\boxmuted{{{text}}}" if item.muted else rf"\boxpara{{{text}}}"]
        if item.truncation:
            lines.append(_trunc(item.truncation))
        return lines
    if isinstance(item, Fields):
        return [_field(row) for row in item.rows]
    if isinstance(item, Code):
        lines = [r"\begin{codebox}"]
        if item.caption:
            lines.append(rf"\codecaption{{{tex(item.caption)}}}")
        lines += [rf"\codeline{{{tex_code_line(line)}}}" for line in item.text.split("\n")] if item.text else [r"\codeline{}"]
        if item.truncation:
            lines.append(_trunc(item.truncation))
        lines.append(r"\end{codebox}")
        return lines
    if isinstance(item, Table):
        return _table(item)
    if isinstance(item, IdList):
        lines = [rf"\sublabel{{{tex(item.label)}}}"] + [rf"\idrow{{{tex_mono(identity)}}}" for identity in item.ids]
        if item.omitted:
            lines.append(_trunc(item.omitted))
        return lines
    if isinstance(item, Bullets):
        lines = [rf"\bulletitem{{{tex(text)}}}" for text in item.items]
        if item.omitted:
            lines.append(_trunc(item.omitted))
        return lines
    raise TypeError(f"unknown item {type(item).__name__}")


def _box(box: Box) -> list[str]:
    style = STYLE_BY_KIND[box.kind]
    env = "gapbox" if style.dashed else "abox"
    badges = " ".join(badge(state) for state in box.badges)
    lines = [rf"\begin{{{env}}}{{{box.kind.value}}}{{{tex(box.chip or style.chip)}}}{{{tex(box.title)}}}{{{tex(box.meta)}}}{{{badges}}}"]
    for item in box.items:
        lines.extend(_item(item))
    lines.append(rf"\end{{{env}}}")
    return lines


def _tone_color(tone: str) -> str:
    return f"verdict-{verdict_color_name(token(tone))}" if token(tone) in VERDICT_COLOR else "brand"


def _stats(block: Stats) -> list[str]:
    lines: list[str] = []
    cards = [rf"\statcard{{{tex(stat.label)}}}{{{tex(stat.value)}}}{{{_tone_color(stat.tone)}}}" for stat in block.items]
    for start in range(0, len(cards), 4):
        row = cards[start:start + 4]
        lines.append(r"\statrow{" + r"\hfill ".join(row) + "}")
    return lines


# Chart geometry. x is a fraction of \linewidth, y is in millimetres downwards; TeX only draws.
BAR_LABEL_END = 0.255
BAR_X0 = 0.27
BAR_W = 0.58
BAR_ROW = 5.0
BAR_H = 3.2
BAR_LABEL_CHARS = 40
VALUE_CHARS = 24
MIN_BAR_W = 0.003

TL_LABEL_END = 0.195
TL_X0 = 0.205
TL_W = 0.645
TL_AXIS = 4.5
TL_ROW = 6.0
TL_H = 3.6
TL_LABEL_CHARS = 32
MIN_SEG_W = 0.004
SEG_TEXT_MIN_W = 0.06
SEG_CHAR_W = 0.0072
TICK_TARGET = 6
_TICK_STEPS_MS = (1, 2, 5, 10, 20, 50, 100, 200, 500, 1_000, 2_000, 5_000, 10_000, 15_000, 30_000, 60_000, 120_000,
                  300_000, 600_000, 900_000, 1_800_000, 3_600_000, 7_200_000, 10_800_000, 21_600_000, 43_200_000, 86_400_000)


def _n(value: float) -> str:
    text = f"{value:.3f}"
    return "0.000" if text == "-0.000" else text


def _pt(x: float, y: float) -> str:
    return f"({_n(x)},{_n(y)})"


def _fit(text: str, limit: int) -> str:
    """Cleaned text cut to ``limit`` characters with an ellipsis, so a label fits its column."""
    cleaned = clean(text)
    return cleaned if len(cleaned) <= limit else cleaned[:max(limit - 1, 0)].rstrip() + "\u2026"


def _magnitude(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    number = float(value)
    return number if math.isfinite(number) and number > 0 else 0.0


def _chart_open(title: str, unit: str) -> list[str]:
    return [rf"\begin{{reportchart}}{{{tex(title)}}}{{{tex(unit)}}}"]


def _chart_close(caption: str, omitted: Truncation | None) -> list[str]:
    lines = [rf"\chartcaption{{{tex(caption)}}}"] if clean(caption) else []
    if omitted:
        lines.append(_trunc(omitted))
    lines.append(r"\end{reportchart}")
    return lines


def bar_geometry(bars: Sequence[Bar]) -> list[tuple[float, float]] | None:
    """(x0, x1) of each bar, scaled to the largest value; ``None`` when there is nothing to draw."""
    values = [_magnitude(bar.value) for bar in bars]
    largest = max(values, default=0.0)
    if largest <= 0:
        return None
    spans = []
    for value in values:
        width = value / largest * BAR_W
        if value > 0:
            width = max(width, MIN_BAR_W)
        spans.append((BAR_X0, BAR_X0 + width))
    return spans


def _bar_chart(block: BarChart) -> list[str]:
    lines = _chart_open(block.title, block.unit)
    spans = bar_geometry(block.bars)
    if spans is None:
        lines.append(r"\chartempty{No data}")
        return lines + _chart_close(block.caption, block.omitted)
    bottom = -BAR_ROW * len(block.bars)
    lines += [r"\noindent\begin{tikzpicture}[x=\linewidth,y=1mm]",
              rf"\useasboundingbox {_pt(0, 0)} rectangle {_pt(1, bottom)};"]
    labels, values = [], []
    for index, (bar, (x0, x1)) in enumerate(zip(block.bars, spans)):
        middle = -BAR_ROW * index - BAR_ROW / 2
        top, low = middle + BAR_H / 2, middle - BAR_H / 2
        lines.append(rf"\fill[charttrack] {_pt(BAR_X0, top)} rectangle {_pt(BAR_X0 + BAR_W, low)};")
        if x1 > x0:
            lines.append(rf"\fill[chartbar,fill={_tone_color(bar.tone)}] {_pt(x0, top)} rectangle {_pt(x1, low)};")
        labels.append(rf"\node[chartlabel] at {_pt(0, middle)} {{{tex(_fit(bar.label, BAR_LABEL_CHARS))}}};")
        values.append(rf"\node[chartvalue] at {_pt(x1 + 0.008, middle)} {{{tex(_fit(bar.display, VALUE_CHARS))}}};")
    lines += [r"\begin{scope}", rf"\clip {_pt(0, 0)} rectangle {_pt(BAR_LABEL_END, bottom)};", *labels, r"\end{scope}",
              r"\begin{scope}", rf"\clip {_pt(BAR_X0, 0)} rectangle {_pt(1, bottom)};", *values, r"\end{scope}",
              r"\end{tikzpicture}"]
    return lines + _chart_close(block.caption, block.omitted)


def timeline_ticks(total_ms: int) -> list[int]:
    """Round tick positions from 0 to at most ``total_ms``, at most ``TICK_TARGET`` intervals."""
    if total_ms <= 0:
        return []
    step = next((step for step in _TICK_STEPS_MS if total_ms / step <= TICK_TARGET), None)
    if step is None:
        day = _TICK_STEPS_MS[-1]
        step = day * math.ceil(total_ms / TICK_TARGET / day)
    return [index * step for index in range(int(total_ms // step) + 1)]


def tick_label(ms: int) -> str:
    from .telemetry.format import duration  # deferred: the telemetry package imports the reporting model
    return "0" if ms == 0 else duration(ms)


def segment_span(segment: Segment, total_ms: int) -> tuple[float, float]:
    """(x0, x1) of a segment clamped to the axis; a zero-width segment becomes a minimum-width marker."""
    start = max(0, min(segment.start_ms, total_ms))
    end = max(start, min(segment.end_ms, total_ms))
    x0 = TL_X0 + start / total_ms * TL_W
    x1 = TL_X0 + end / total_ms * TL_W
    if x1 - x0 < MIN_SEG_W:
        centre = (x0 + x1) / 2
        x0 = min(max(centre - MIN_SEG_W / 2, TL_X0), TL_X0 + TL_W - MIN_SEG_W)
        x1 = x0 + MIN_SEG_W
    return x0, x1


def _timeline(block: Timeline) -> list[str]:
    lines = _chart_open(block.title, duration_label(block.total_ms))
    if block.total_ms <= 0 or not block.lanes:
        lines.append(r"\chartempty{No timing data}")
        return lines + _chart_close(block.caption, block.omitted)
    total = block.total_ms
    bottom = -TL_AXIS - TL_ROW * len(block.lanes)
    lines += [r"\noindent\begin{tikzpicture}[x=\linewidth,y=1mm]",
              rf"\useasboundingbox {_pt(0, 0)} rectangle {_pt(1, bottom)};"]
    rows = [(-TL_AXIS - TL_ROW * index - TL_ROW / 2, lane) for index, lane in enumerate(block.lanes)]
    for middle, _ in rows:
        lines.append(rf"\fill[charttrack] {_pt(TL_X0, middle + TL_H / 2)} rectangle {_pt(TL_X0 + TL_W, middle - TL_H / 2)};")
    for tick in timeline_ticks(total):
        x = TL_X0 + tick / total * TL_W
        lines.append(rf"\draw[chartgrid] {_pt(x, -TL_AXIS + 0.6)} -- {_pt(x, bottom)};")
        lines.append(rf"\node[charttick] at {_pt(x, -TL_AXIS + 1.2)} {{{tex(tick_label(tick))}}};")
    labels, notes = [], []
    for middle, lane in rows:
        top, low = middle + TL_H / 2, middle - TL_H / 2
        for segment in lane.segments:
            x0, x1 = segment_span(segment, total)
            lines.append(rf"\fill[chartbar,fill={_tone_color(segment.tone)}] {_pt(x0, top)} rectangle {_pt(x1, low)};")
            chars = int((x1 - x0 - 0.008) / SEG_CHAR_W)
            if x1 - x0 >= SEG_TEXT_MIN_W and chars >= 3 and clean(segment.label):
                lines += [r"\begin{scope}", rf"\clip {_pt(x0, top)} rectangle {_pt(x1, low)};",
                          rf"\node[chartseg] at {_pt(x0 + 0.004, middle)} {{{tex(_fit(segment.label, chars))}}};",
                          r"\end{scope}"]
        labels.append(rf"\node[chartlabel] at {_pt(0, middle)} {{{tex(_fit(lane.label, TL_LABEL_CHARS))}}};")
        notes.append(rf"\node[chartnote] at {_pt(TL_X0 + TL_W + 0.012, middle)} {{{tex(_fit(lane.annotation, VALUE_CHARS))}}};")
    lines += [r"\begin{scope}", rf"\clip {_pt(0, 0)} rectangle {_pt(TL_LABEL_END, bottom)};", *labels, r"\end{scope}",
              r"\begin{scope}", rf"\clip {_pt(TL_X0 + TL_W, 0)} rectangle {_pt(1, bottom)};", *notes, r"\end{scope}",
              r"\end{tikzpicture}"]
    return lines + _chart_close(block.caption, block.omitted)


def duration_label(total_ms: int) -> str:
    return f"total {tick_label(total_ms)}" if total_ms > 0 else ""


def _legend() -> list[str]:
    lines = [r"\par{\small Every kind of content has one colour, one chip and one box. The chip text and the dashed border of the gap box "
             r"carry the meaning too, so the report reads in greyscale.}"]
    lines.append(r"\rsubsection{Kinds of box}{}{legend-boxes}")
    for style in BOX_STYLES:
        lines.append(rf"\legendrow{{{style.kind.value}}}{{{tex(style.chip)}}}{{\#{style.accent}}}{{{tex(style.meaning)}}}")
    lines.append(r"\rsubsection{Verdict states}{}{legend-verdicts}")
    for verdict in (*VERDICTS, *EXTRA_VERDICTS):
        label = badge_text(verdict.state).upper()
        lines.append(rf"\verdictrow{{{verdict_color_name(verdict.state)}}}{{{tex(label)}}}{{\#{verdict.color}}}{{{tex(verdict.meaning)}}}")
    lines.append(r"\rsubsection{How to read a package}{}{legend-reading}")
    lines.append(r"\par{\small Each reviewed package has three parts. \emph{Evidence passed in} is exactly what the application gave the model. "
                 r"\emph{Protocol interchange} is the timeline of turns: the task and tools, what the model asked, what the application "
                 r"returned or denied, and the final answer, with token counts and the model used. \emph{Outcome} is what reached the claim ledger. "
                 r"Long lists and results are cut and say so, with the SHA-256 of what was left out. Model output, target content and tool "
                 r"output are data and are never interpreted as instructions.}")
    return lines


def _block(block: Block) -> list[str]:
    if isinstance(block, Heading):
        command = {1: r"\rsection", 2: r"\rsubsection", 3: r"\rsubsubsection", 4: r"\rminor"}.get(block.level, r"\rminor")
        lines = [r"\clearpage"] if block.new_page else []
        lines.append(rf"{command}{{{tex(block.text)}}}{{{tex(block.subtitle)}}}{{{clean(block.anchor)}}}")
        return lines
    if isinstance(block, Box):
        return _box(block)
    if isinstance(block, Stats):
        return _stats(block)
    if isinstance(block, Note):
        return [rf"\par{{\small\muted{{{tex(block.text)}}}}}"]
    if isinstance(block, Legend):
        return _legend()
    if isinstance(block, PageBreak):
        return [r"\clearpage"]
    if isinstance(block, BarChart):
        return _bar_chart(block)
    if isinstance(block, Timeline):
        return _timeline(block)
    raise TypeError(f"unknown block {type(block).__name__}")


def render_latex(document: Document, template_dir: Path | None = None) -> str:
    directory = Path(template_dir) if template_dir else default_template_dir()
    try:
        skeleton = (directory / SKELETON).read_text(encoding="utf-8")
    except OSError as exc:
        raise FileNotFoundError(f"LaTeX template skeleton not found at {directory / SKELETON}; pass --template-dir") from exc
    pdftitle = _ASCII.sub("", f"{document.title} {document.run_id}").strip() or "Security review report"
    status = badge(document.status_tone, document.status_badge.replace("_", " "))
    setup = [
        r"\reportsetup{",
        rf"  title={{{tex(document.title)}}},",
        rf"  subtitle={{{tex(document.subtitle)}}},",
        rf"  run={{{tex_mono(document.run_id)}}},",
        rf"  status={{{status}}},",
        rf"  head={{{tex_mono(document.ledger_head)}}},"]
    if document.head_label != DEFAULT_HEAD_LABEL:
        setup.append(rf"  headlabel={{{tex(document.head_label)}}},")
    setup += [
        rf"  renderer={{{tex(document.renderer)}}},",
        rf"  pdftitle={{{pdftitle}}}}}"]
    preamble = "\n".join(setup)
    body: list[str] = []
    for block in document.blocks:
        body.extend(_block(block))
        body.append("")
    text = skeleton.replace("%%PREAMBLE%%", preamble).replace("%%BODY%%", "\n".join(body))
    return text if text.endswith("\n") else text + "\n"
