"""Renderer-neutral report document.

The loader builds a :class:`Document` of blocks; the LaTeX and HTML renderers walk it. All strings
in it are already cleaned and bounded (see ``text.py``), but not escaped: each renderer escapes for
its own language. Frozen dataclasses only, so the same run always yields an equal document.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Union

from .tokens import BoxKind


@dataclass(frozen=True, slots=True)
class Truncation:
    """A visible note that a field was cut: how much, and the SHA-256 of the whole."""

    omitted: int
    unit: str
    sha256: str


@dataclass(frozen=True, slots=True)
class Para:
    text: str
    truncation: Truncation | None = None
    muted: bool = False


@dataclass(frozen=True, slots=True)
class Field:
    label: str
    value: str
    mono: bool = False
    badge: str | None = None          # a verdict/state token shown as a badge instead of text
    badge_label: str | None = None    # words on that badge when they differ from the token's own text
    truncation: Truncation | None = None


@dataclass(frozen=True, slots=True)
class Fields:
    rows: tuple[Field, ...]


@dataclass(frozen=True, slots=True)
class Code:
    text: str
    truncation: Truncation | None = None
    caption: str = ""


@dataclass(frozen=True, slots=True)
class Cell:
    text: str
    mono: bool = False
    badge: str | None = None
    badge_label: str | None = None


@dataclass(frozen=True, slots=True)
class Table:
    headers: tuple[str, ...]
    rows: tuple[tuple[Cell, ...], ...]
    widths: tuple[float, ...]                   # fractions of the width, summing to at most 1
    omitted: Truncation | None = None            # rows not shown


@dataclass(frozen=True, slots=True)
class IdList:
    label: str
    ids: tuple[str, ...]
    omitted: Truncation | None = None


@dataclass(frozen=True, slots=True)
class Bullets:
    items: tuple[str, ...]
    omitted: Truncation | None = None


Item = Union[Para, Fields, Code, Table, IdList, Bullets]


@dataclass(frozen=True, slots=True)
class Box:
    kind: BoxKind
    title: str
    meta: str = ""
    badges: tuple[str, ...] = ()
    items: tuple[Item, ...] = ()
    collapsed: bool = False           # HTML: a <details> that starts closed; LaTeX ignores it
    chip: str | None = None           # overrides the kind's chip text


@dataclass(frozen=True, slots=True)
class Heading:
    level: int                         # 1 chapter-like, 2 section, 3 sub-section
    text: str
    anchor: str
    subtitle: str = ""
    new_page: bool = False


@dataclass(frozen=True, slots=True)
class Stat:
    label: str
    value: str
    tone: str = "neutral"              # a verdict token or "neutral"


@dataclass(frozen=True, slots=True)
class Stats:
    items: tuple[Stat, ...]


@dataclass(frozen=True, slots=True)
class Note:
    text: str


@dataclass(frozen=True, slots=True)
class Legend:
    """Expanded by each renderer from the design tokens."""


@dataclass(frozen=True, slots=True)
class PageBreak:
    pass


@dataclass(frozen=True, slots=True)
class Bar:
    label: str
    value: float                       # non-negative magnitude; the renderer scales to the largest bar
    display: str                       # preformatted value text shown beside the bar
    tone: str = "neutral"              # a verdict token or "neutral"


@dataclass(frozen=True, slots=True)
class BarChart:
    """Horizontal bars, one per row, in the given order."""

    title: str
    unit: str
    bars: tuple[Bar, ...]
    caption: str = ""
    omitted: Truncation | None = None  # bars not shown


@dataclass(frozen=True, slots=True)
class Segment:
    start_ms: int                      # offset from the timeline origin
    end_ms: int                        # >= start_ms
    tone: str = "neutral"              # a verdict token or "neutral"
    label: str = ""


@dataclass(frozen=True, slots=True)
class Lane:
    label: str
    segments: tuple[Segment, ...]
    annotation: str = ""               # preformatted text shown at the right of the lane


@dataclass(frozen=True, slots=True)
class Timeline:
    """A Gantt-style chart: one lane per row, segments positioned on a shared 0..total_ms axis."""

    title: str
    total_ms: int
    lanes: tuple[Lane, ...]
    caption: str = ""
    omitted: Truncation | None = None  # lanes not shown


Block = Union[Heading, Box, Stats, Note, Legend, PageBreak, BarChart, Timeline]


@dataclass(frozen=True, slots=True)
class Document:
    title: str
    run_id: str
    subtitle: str
    status_badge: str                 # review status token (COMPLETE, DEGRADED, EMPTY, UNKNOWN)
    status_tone: str                  # a verdict token whose colour the status badge takes
    source_date_epoch: int
    ledger_head: str
    blocks: tuple[Block, ...]
    named_gaps: tuple[str, ...] = ()  # artifacts the loader could not read, by name
    renderer: str = "appsec-review-report/1"
    head_label: str = "ledger head"   # what ``ledger_head`` identifies, shown on the cover and footer
