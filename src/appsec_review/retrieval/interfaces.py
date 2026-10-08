"""Transport-independent retrieval contracts.

Backends implement these contracts over immutable, run-scoped indices. Protocol adapters such as
MCP translate requests into these types; they do not own search semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class SearchRequest:
    """A bounded query against one named index in a review run."""

    run_id: str
    index: str
    query: str
    limit: int = 20
    cursor: str | None = None

    def __post_init__(self) -> None:
        if not self.run_id.strip():
            raise ValueError("run_id is required")
        if not self.index.strip():
            raise ValueError("index is required")
        if not self.query.strip():
            raise ValueError("query is required")
        if not 1 <= self.limit <= 100:
            raise ValueError("limit must be between 1 and 100")


@dataclass(frozen=True, slots=True)
class SearchHit:
    """One result whose source can be resolved without scanning the target."""

    source_id: str
    path: str
    start_line: int
    end_line: int
    excerpt: str
    score: float | None = None

    def __post_init__(self) -> None:
        if not self.source_id.strip():
            raise ValueError("source_id is required")
        if not self.path.strip():
            raise ValueError("path is required")
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("line range is invalid")


@dataclass(frozen=True, slots=True)
class SearchPage:
    """A bounded result page with explicit coverage gaps."""

    hits: tuple[SearchHit, ...]
    next_cursor: str | None = None
    gaps: tuple[str, ...] = ()


class SearchBackend(Protocol):
    """Implemented by deterministic index readers, independent of MCP."""

    def search(self, request: SearchRequest) -> SearchPage:
        """Return one bounded page from an already-built index."""
