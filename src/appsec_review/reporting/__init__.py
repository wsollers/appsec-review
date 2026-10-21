"""Deterministic report rendering for a finished review run.

``load_document`` reads a run directory (read-only) into a renderer-neutral :class:`Document`;
``render_latex`` fills the LaTeX template and ``render_html`` writes one self-contained HTML page.
Both are pure functions of the run's artifacts: the same run gives byte-identical output, with no
clock, locale, network or randomness. The PDF itself is produced by the ``tool-report-latex`` image
(``scripts/render-report.sh`` and ``scripts/render-report.ps1``).
"""
from .html import render_html
from .latex import render_latex
from .loader import Selection, load_document
from .model import Document
from .tokens import Limits

__all__ = ["Document", "Limits", "Selection", "load_document", "render_html", "render_latex"]
