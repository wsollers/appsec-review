"""Transport-independent retrieval contracts.

Backends implement these contracts over immutable, run-scoped indices. Protocol adapters such as
MCP translate requests into these types; they do not own search semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any, Mapping, Protocol


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


@dataclass(frozen=True, slots=True)
class ArtifactQueryRequest:
    """Transport-neutral exact filters for accepted produced-artifact evidence."""

    artifact_identity: str | None = None
    sha256: str | None = None
    kind: str | None = None
    format: str | None = None
    language: str | None = None
    runtime: str | None = None
    platform: str | None = None
    architecture: str | None = None
    build_unit: str | None = None
    project: str | None = None
    component: str | None = None
    producing_build_action: str | None = None
    package: str | None = None
    purl: str | None = None
    scanner: str | None = None
    tool: str | None = None
    coverage_status: str | None = None
    shard: str | None = None
    limit: int = 20
    cursor: str | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        for name, value in self.filters.items():
            maximum = 128 if name in {"coverage_status", "shard"} else 4096
            if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
                raise ValueError(f"invalid artifact query filter: {name}")
        if self.shard is not None and not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", self.shard):
            raise ValueError("invalid artifact query filter: shard")

    @property
    def filters(self) -> Mapping[str, str]:
        return {name: value for name, value in (
            ("artifact_identity", self.artifact_identity), ("sha256", self.sha256),
            ("kind", self.kind), ("format", self.format), ("language", self.language),
            ("runtime", self.runtime), ("platform", self.platform),
            ("architecture", self.architecture), ("build_unit", self.build_unit),
            ("project", self.project), ("component", self.component),
            ("producing_build_action", self.producing_build_action),
            ("package", self.package), ("purl", self.purl), ("scanner", self.scanner),
            ("tool", self.tool), ("coverage_status", self.coverage_status),
            ("shard", self.shard),
        ) if value is not None}


class ArtifactQueryBackend(Protocol):
    """Implemented by run-pinned readers; protocol adapters only serialize it."""

    def query_artifacts(self, request: ArtifactQueryRequest) -> Mapping[str, Any]:
        """Return one bounded page from accepted artifact and evidence shards."""


class RunIndexBackend:
    """Compatibility facade over the accepted SQLite retrieval core."""

    _INDEXES = {"path": "source", "symbol": "analysis", "component": "components"}

    def __init__(self, runs_dir: Path):
        self.runs_dir = Path(runs_dir).resolve()

    def search(self, request: SearchRequest) -> SearchPage:
        try:
            index_name = self._INDEXES[request.index]
        except KeyError as exc:
            raise ValueError(f"unknown retrieval index: {request.index}") from exc
        from appsec_review.retrieval.core import RetrievalCore
        response = RetrievalCore(self.runs_dir, request.run_id).search(
            query=request.query, indexes=(index_name,), limit=request.limit, cursor=request.cursor)
        hits = []
        for item in response["results"]:
            location = item.get("location") or {}
            hits.append(SearchHit(
                source_id=item["identity"], path=location.get("path", "."),
                start_line=int(location.get("start_line", 1)), end_line=int(location.get("end_line", 1)),
                excerpt=str(item.get("name", "")), score=None,
            ))
        return SearchPage(tuple(hits), response["pagination"]["next_cursor"],
                          tuple(response["coverage_gaps"]))
