"""Fill the LaTeX template from a report document: ``report.tex`` plus the source-date file.

The renderer writes only the *content* (escaped text inside the macros that
``containers/report/latex/template/appsec-report.cls`` defines); layout and colour live in the
template. Every string is escaped by ``text.tex``/``text.tex_mono``; no run text can open a TeX
command, and the engine runs without shell escape.
"""
from __future__ import annotations

from pathlib import Path
import re
from typing import Iterable, Sequence

from .model import (Block, Box, Bullets, Code, Document, Fields, Field, Heading, IdList, Item, Legend, Note, PageBreak,
                    Para, Stats, Table, Truncation)
from .text import clean, tex, tex_code_line, tex_mono, token
from .tokens import badge_text, BOX_STYLES, STYLE_BY_KIND, VERDICT_COLOR, VERDICTS, EXTRA_VERDICTS, BoxKind

SKELETON = "report-skeleton.tex"
PALETTE = "appsec-palette.tex"
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
        value = badge(row.badge)
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
            cells.append(badge(cell.badge) if cell.badge else (tex_mono(cell.text) if cell.mono else tex(cell.text)))
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
    raise TypeError(f"unknown block {type(block).__name__}")


def render_latex(document: Document, template_dir: Path | None = None) -> str:
    directory = Path(template_dir) if template_dir else default_template_dir()
    try:
        skeleton = (directory / SKELETON).read_text(encoding="utf-8")
    except OSError as exc:
        raise FileNotFoundError(f"LaTeX template skeleton not found at {directory / SKELETON}; pass --template-dir") from exc
    pdftitle = _ASCII.sub("", f"{document.title} {document.run_id}").strip() or "Security review report"
    status = badge(document.status_tone, document.status_badge.replace("_", " "))
    preamble = "\n".join([
        r"\reportsetup{",
        rf"  title={{{tex(document.title)}}},",
        rf"  subtitle={{{tex(document.subtitle)}}},",
        rf"  run={{{tex_mono(document.run_id)}}},",
        rf"  status={{{status}}},",
        rf"  head={{{tex_mono(document.ledger_head)}}},",
        rf"  renderer={{{tex(document.renderer)}}},",
        rf"  pdftitle={{{pdftitle}}}}}"])
    body: list[str] = []
    for block in document.blocks:
        body.extend(_block(block))
        body.append("")
    text = skeleton.replace("%%PREAMBLE%%", preamble).replace("%%BODY%%", "\n".join(body))
    return text if text.endswith("\n") else text + "\n"
