"""Deterministic report rendering for a finished review run.

``load_document`` reads a run directory (read-only) into a renderer-neutral :class:`Document`;
``render_latex`` fills the LaTeX template and ``render_html`` writes one self-contained HTML page.
Streamlined visual executive candidates (Candidate A, Candidate B, Candidate C) are built from
``final-report.json`` via :func:`build_executive_candidate_document` and
:func:`render_executive_candidates`. All renderers are pure functions of the run's artifacts:
the same run gives byte-identical output, with no clock, locale, network or randomness. The PDF
itself is produced by the ``tool-report-latex`` image (``scripts/render-report.sh`` and
``scripts/render-report.ps1``).
"""
from .executive_candidates import (
    CANDIDATE_IDS,
    CANDIDATE_LABELS,
    CANDIDATE_SUBTITLES,
    CANDIDATE_TITLES,
    RenderedExecutiveCandidate,
    ReportDocument,
    build_executive_candidate_document,
    normalize_candidate_id,
    render_executive_candidate_html,
    render_executive_candidate_latex,
    render_executive_candidate_markdown,
    render_executive_candidates,
)
from .html import render_html
from .latex import render_latex
from .loader import Selection, load_document
from .model import Document
from .tokens import Limits

__all__ = [
    "CANDIDATE_IDS",
    "CANDIDATE_LABELS",
    "CANDIDATE_SUBTITLES",
    "CANDIDATE_TITLES",
    "Document",
    "Limits",
    "RenderedExecutiveCandidate",
    "ReportDocument",
    "Selection",
    "build_executive_candidate_document",
    "load_document",
    "normalize_candidate_id",
    "render_executive_candidate_html",
    "render_executive_candidate_latex",
    "render_executive_candidate_markdown",
    "render_executive_candidates",
    "render_html",
    "render_latex",
]
