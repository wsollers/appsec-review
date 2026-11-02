"""Shared records for detector scoring against an answer key (docs/reviews/castle-style-detector-scoring.md).

This module is the contract between the key loader and scorer (``acceptance.scoring``), the run-report
extraction (``acceptance.producer_reports``) and the CASTLE corpus preparation (``acceptance.castle``).
It holds records, closed vocabularies and pinned paths only; it has no behaviour beyond validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import re

SCORING_SCHEMA = "appsec-review/detector-scoring/1"
DEFAULT_TOLERANCE = 2  # lines either side of a defect's target lines (decision 3)
DEFAULT_MAX_COMBINATION = 3  # largest producer subset searched besides the full set (decision 8)
FILE_SCOPE = "file"  # ``scope = "file"``: the case covers the whole file (CASTLE, decision 1)

_REPOSITORY = Path(__file__).resolve().parents[3]
REFERENCE_ROOT = _REPOSITORY / "data" / "reference" / "scoring"
TOP25_REFERENCE = REFERENCE_ROOT / "cwe-top25.json"  # owned by chunk A
CWE_MATCH_REFERENCE = REFERENCE_ROOT / "cwe-match.json"  # owned by chunk A
RULE_CWE_REFERENCE = REFERENCE_ROOT / "rule-cwe.json"  # owned by chunk B
DEFAULT_TOP_LIST = "castle-2025-table2"  # the standings CASTLE Table 2 used; "mitre-2024" is also pinned

_CWE = re.compile(r"^\s*(?:CWE[-_ ]?)?0*(\d{1,5})\s*$", re.IGNORECASE)


def normalize_cwe(value: object) -> str | None:
    """``"CWE-0121"``, ``"cwe 121"``, ``121`` -> ``"CWE-121"``; anything else (including 0) -> None."""

    if isinstance(value, bool):
        return None
    match = _CWE.match(str(value)) if isinstance(value, (str, int)) else None
    if match is None or int(match.group(1)) == 0:
        return None
    return f"CWE-{int(match.group(1))}"


class EntryKind(str, Enum):
    DEFECT = "defect"  # ``[[defect]]``: a seeded weakness (positive case)
    CONTROL = "control"  # ``[[control]]``: a negative control, code that must not be reported


class ReportOutcome(str, Enum):
    """How one report relates to the case it is attributed to (decision 3)."""

    HIT = "hit"  # defect case, lines overlap the target lines, a CWE is accepted for the key CWE
    LOCATION_HIT_CWE_MISS = "location_hit_cwe_miss"  # defect lines overlap, known CWEs, none accepted
    LOCATION_HIT_CWE_UNKNOWN = "location_hit_cwe_unknown"  # defect lines overlap, report has no CWE
    OFF_LOCATION = "off_location"  # inside a defect case's scope, but not on its target lines
    CONTROL = "control"  # attributed to a negative control
    UNATTRIBUTED = "unattributed"  # in a scored path but in no case's scope; never scored


@dataclass(frozen=True)
class KeyEntry:
    """One case of the key: a defect or a negative control, located in a target-relative file.

    ``lines`` are the target lines (sorted, unique, non-empty): the explicit ``lines`` list when the
    key gives one, else ``line..end_line``. ``scope`` is the attribution range ``(start, end)``,
    or ``None`` for ``scope = "file"`` (the whole file). Without ``scope_start``/``scope_end`` or
    ``scope``, the scope is ``(min(lines), max(lines))``.
    """

    id: str
    kind: EntryKind
    path: str
    cwe: str | None  # defect: the weakness; control: the weakness the code guards against (optional)
    lines: tuple[int, ...]
    scope: tuple[int, int] | None
    summary: str = ""
    pair: str | None = None  # id of the counterpart entry (a defect's fixed twin, or the reverse)
    upstream: str | None = None  # provenance name of the source test (CASTLE file name)
    producers: tuple[str, ...] = ()  # defects only: the hypothesis carried over from [[defect]]

    def __post_init__(self) -> None:
        if not self.id or not self.path or self.path.startswith("/") or "\\" in self.path:
            raise ValueError(f"key entry needs an id and a target-relative POSIX path: {self.id!r}")
        if not self.lines or list(self.lines) != sorted(set(self.lines)) or self.lines[0] < 1:
            raise ValueError(f"{self.id}: lines must be sorted, unique and positive")
        if self.kind is EntryKind.DEFECT and self.cwe is None:
            raise ValueError(f"{self.id}: a defect needs a CWE")
        if self.scope is not None and not (1 <= self.scope[0] <= self.lines[0] and self.lines[-1] <= self.scope[1]):
            raise ValueError(f"{self.id}: scope must contain the target lines")


@dataclass(frozen=True)
class ScoringKey:
    corpus: dict[str, object]
    entries: tuple[KeyEntry, ...]
    scored_paths: tuple[str, ...] = ()  # ``[corpus] scored_paths``; empty means every path is scored

    @property
    def defects(self) -> tuple[KeyEntry, ...]:
        return tuple(entry for entry in self.entries if entry.kind is EntryKind.DEFECT)

    @property
    def controls(self) -> tuple[KeyEntry, ...]:
        return tuple(entry for entry in self.entries if entry.kind is EntryKind.CONTROL)

    def is_scored(self, path: str) -> bool:
        return not self.scored_paths or any(
            path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in self.scored_paths)


@dataclass(frozen=True)
class Report:
    """One report of one producer at one target-relative location (decision 4)."""

    producer: str  # lowercase scanner name ("codeql", "cppcheck", ...), or "review" for final findings
    path: str
    start_line: int
    end_line: int
    rule: str  # native rule id; "" when the producer gave none
    cwes: frozenset[str] = field(default_factory=frozenset)  # normalized "CWE-<n>"; empty when unknown
    evidence: str = ""  # a resolvable reference: observation identity or final-finding evidence id

    def __post_init__(self) -> None:
        if not self.producer or self.producer != self.producer.lower():
            raise ValueError(f"producer must be a non-empty lowercase name: {self.producer!r}")
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError(f"{self.producer} {self.path}: invalid line range")
        if any(normalize_cwe(cwe) != cwe for cwe in self.cwes):
            raise ValueError(f"{self.producer} {self.path}: CWEs must be normalized")

    @property
    def identity(self) -> tuple[str, str, int, str]:
        """Reports of one producer with equal identity are collapsed into one (decision 4)."""

        return (self.producer, self.path, self.start_line, self.rule)
