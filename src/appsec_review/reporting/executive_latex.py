"""Pageable, restrained LaTeX for the executive document only; telemetry is unchanged."""
from __future__ import annotations

from itertools import zip_longest
import hashlib
from pathlib import Path
import re

from appsec_review.review.models import IntegrityError
from appsec_review.storage import canonical_json, platform_file_sha256
from .model import Box, Bullets, Document, Fields, Heading, Para, Table
from .text import tex

SKELETON = "technical-report-skeleton.tex"


def template_identity(directory: Path) -> dict:
    """The three files actually consumed by this renderer, not the telemetry/dossier skeleton."""
    files = []
    for name in ("appsec-report.cls", "appsec-palette.tex", SKELETON):
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise IntegrityError(f"executive template is missing or symbolic: {name}")
        files.append({"name": name, "sha256": platform_file_sha256(path)})
    return {"files": files, "sha256": hashlib.sha256(canonical_json(files)).hexdigest()}


def _chunks(text: str, size: int) -> list[str]:
    """Partition (never truncate) long table cells, including long unbroken identifiers."""
    result = []
    while len(text) > size:
        cut = text.rfind(" ", 0, size + 1)
        cut = cut + 1 if cut > size // 2 else size
        result.append(text[:cut])
        text = text[cut:]
    result.append(text)
    return result


def _table(table: Table) -> list[str]:
    columns = "".join(
        rf">{{\raggedright\arraybackslash}}p{{\dimexpr {width:.3f}\linewidth-2\tabcolsep\relax}}"
        for width in table.widths)
    header = " & ".join(rf"\textbf{{{tex(value)}}}" for value in table.headers) + r" \\ \midrule"
    lines = [r"\begingroup\technicaltablesize",
             r"\begin{longtable}{@{}" + columns + r"@{}}", r"\toprule", header, r"\endfirsthead",
             r"\toprule", header, r"\endhead", r"\bottomrule\endfoot"]
    for row in table.rows:
        fragments = [_chunks(cell.text, max(48, int(width * 650)))
                     for cell, width in zip(row, table.widths)]
        for part, cells in enumerate(zip_longest(*fragments, fillvalue="")):
            # A single original row can exceed a page. Its continuations remain in the same
            # columns, without a minipage, resizebox, or another unbreakable table wrapper.
            values = list(cells)
            if part and not values[0]:
                values[0] = "(continued)"
            rendered = [tex(value) for value in values]
            if table.headers[0] == "ID" and re.fullmatch(r"F[0-9]+", values[0]):
                rendered[0] = rf"\hyperlink{{{values[0]}}}{{{rendered[0]}}}"
            lines.append(" & ".join(rendered) + r" \\")
    lines += [r"\end{longtable}", r"\endgroup"]
    if table.omitted:
        raise ValueError("technical report must not silently omit accepted table rows")
    return lines


def render_latex(document: Document, template: Path) -> str:
    body = []
    for block in document.blocks:
        if isinstance(block, Heading):
            if block.new_page:
                body.append(r"\clearpage")
            chunks = _chunks(block.text, 360)
            body.append(rf"\technicalheading{{{tex(chunks[0])}}}{{{tex(block.anchor)}}}")
            body.extend(rf"\technicalpara{{{tex(chunk)}}}" for chunk in chunks[1:])
        elif isinstance(block, Box):
            body.append(rf"\technicalsubheading{{{tex(block.title)}}}")
            if block.meta:
                body.append(rf"\technicalnote{{{tex(block.meta)}}}")
            for item in block.items:
                if isinstance(item, Para):
                    macro = "technicalnote" if item.muted else "technicalpara"
                    body.append(rf"\{macro}{{{tex(item.text)}}}")
                    if item.truncation:
                        raise ValueError("technical report must not truncate accepted prose")
                elif isinstance(item, Fields):
                    body += [rf"\technicalfield{{{tex(row.label)}}}{{{tex(row.value)}}}" for row in item.rows]
                elif isinstance(item, Bullets):
                    body += [rf"\technicalpara{{\textbullet\ {tex(value)}}}" for value in item.items]
                    if item.omitted:
                        raise ValueError("technical report must not omit accepted list items")
                elif isinstance(item, Table):
                    body += _table(item)
                else:
                    raise TypeError(f"unsupported technical report item: {type(item).__name__}")
        else:
            raise TypeError(f"unsupported technical report block: {type(block).__name__}")
    skeleton = (template / SKELETON).read_text(encoding="utf-8")
    for key, value in (("TITLE", document.title), ("RUN", document.run_id), ("STATUS", document.status_badge),
                       ("HEAD", document.ledger_head), ("RENDERER", document.renderer)):
        skeleton = skeleton.replace("%%" + key + "%%", tex(value))
    return skeleton.replace("%%BODY%%", "\n".join(body))
