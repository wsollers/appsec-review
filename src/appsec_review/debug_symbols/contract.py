"""Shared vocabulary for symbol producers and bounded retrieval."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    from appsec_review.config.compiler_target import CompilerTarget


INDEX_NAME = "debug_symbols"
JOB_ID = "job_debug_symbol_indexing"
RECORD_SCHEMA = "appsec-review/debug-symbol-records/1"
DECISION_SCHEMA = "appsec-review/debug-symbol-decision/2"
QUERY_TOOL = "query_debug_symbols"
MAX_LIMIT = 100


class SymbolIntegrityError(ValueError):
    """Accepted symbol inputs, execution identity, or retained evidence changed."""


class QueryMode(str, Enum):
    SYMBOL = "symbol"
    ADDRESS = "address"
    SOURCE_RANGES = "source_ranges"
    TYPE_LAYOUT = "type_layout"
    INLINE_FRAMES = "inline_frames"
    COMPILATION_UNITS = "compilation_units"
    COVERAGE = "coverage"
    GRAPH_LINKS = "graph_links"


class RecordKind(str, Enum):
    SYMBOL = "symbol"
    SOURCE_RANGE = "source_range"
    TYPE_LAYOUT = "type_layout"
    INLINE_FRAME = "inline_frame"
    COMPILATION_UNIT = "compilation_unit"
    GRAPH_LINK = "graph_link"


@dataclass(frozen=True, slots=True)
class AddressRange:
    start: int
    end: int

    def __post_init__(self) -> None:
        if (type(self.start) is not int or type(self.end) is not int
                or not 0 <= self.start < self.end <= 2**64):
            raise ValueError("debug-symbol address range must be a nonempty unsigned 64-bit interval")


@dataclass(frozen=True, slots=True)
class SourceSpan:
    # A recorded name is data, never a request to read a filesystem path.
    path: str
    line: int
    column: int = 0
    checksum: str | None = None
    checksum_kind: str | None = None

    def __post_init__(self) -> None:
        if (not isinstance(self.path, str) or not self.path or len(self.path) > 4096
                or type(self.line) is not int or self.line < 1
                or type(self.column) is not int or self.column < 0):
            raise ValueError("invalid recorded debug-symbol source span")


@dataclass(frozen=True, slots=True)
class SymbolRecord:
    key: str
    kind: RecordKind
    name: str = ""
    ranges: tuple[AddressRange, ...] = ()
    source: SourceSpan | None = None
    parent_key: str | None = None
    data: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or not self.key or len(self.key) > 4096:
            raise ValueError("invalid native debug-symbol record key")
        if not isinstance(self.kind, RecordKind):
            raise ValueError("invalid debug-symbol record kind")
        if not isinstance(self.name, str) or len(self.name) > 4096:
            raise ValueError("invalid debug-symbol record name")


@dataclass(frozen=True, slots=True)
class Extraction:
    records: tuple[SymbolRecord, ...]
    gaps: tuple[str, ...] = ()
    producer: str = ""


def selected_path(target: CompilerTarget) -> str:
    from appsec_review.config.compiler_target import CompilerTarget

    if not isinstance(target, CompilerTarget):
        raise ValueError("debug-symbol routing requires a validated compiler target")
    return "clang_dwarf" if target is CompilerTarget.CLANG else "msvc_pdb"


def record_fingerprint(artifact_sha256: str, debug_sha256: str, record_key: str) -> str:
    for digest in (artifact_sha256, debug_sha256):
        if (not isinstance(digest, str) or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)):
            raise ValueError("debug-symbol identities require lowercase SHA-256 digests")
    return hashlib.sha256(json.dumps(
        [RECORD_SCHEMA, artifact_sha256, debug_sha256, record_key],
        separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
