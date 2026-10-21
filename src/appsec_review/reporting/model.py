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


Block = Union[Heading, Box, Stats, Note, Legend, PageBreak]


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
