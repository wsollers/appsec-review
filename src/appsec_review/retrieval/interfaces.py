"""Transport-independent retrieval contracts.

Backends implement these contracts over immutable, run-scoped indices. Protocol adapters such as
MCP translate requests into these types; they do not own search semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
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


class RunIndexBackend:
    """Search immutable Wave 1 JSON indices without rescanning the target tree."""

    _UNITS = {
        "path": "retrieval_indexes.build_path_index",
        "symbol": "retrieval_indexes.build_symbol_index",
        "component": "retrieval_indexes.build_component_index",
    }

    def __init__(self, runs_dir: Path):
        self.runs_dir = Path(runs_dir).resolve()

    def search(self, request: SearchRequest) -> SearchPage:
        try:
            unit_id = self._UNITS[request.index]
        except KeyError as exc:
            raise ValueError(f"unknown retrieval index: {request.index}") from exc
        run_root = (self.runs_dir / request.run_id).resolve()
        if run_root.parent != self.runs_dir or not run_root.is_dir():
            raise FileNotFoundError(f"run does not exist: {request.run_id}")
        pointer = json.loads((run_root / "data/jobs/job_target_catalog/latest.json").read_text(encoding="utf-8"))
        handoff = json.loads((run_root / pointer["handoff_path"]).read_text(encoding="utf-8"))
        artifact = handoff["outputs"][unit_id]["artifact"]
        index_path = (run_root / artifact["path"]).resolve()
        if run_root not in index_path.parents:
            raise ValueError("retrieval index path escapes run")
        from appsec_review.storage import file_sha256
        if file_sha256(index_path) != artifact["sha256"]:
            raise ValueError("retrieval index integrity mismatch")
        document = json.loads(index_path.read_text(encoding="utf-8"))
        query = request.query.casefold()
        matched = [item for item in document.get("items", [])
                   if query in json.dumps(item, sort_keys=True).casefold()]
        try:
            offset = int(request.cursor or "0")
        except ValueError as exc:
            raise ValueError("invalid retrieval cursor") from exc
        page = matched[offset:offset + request.limit]
        hits = []
        for item in page:
            path = item.get("path") or item.get("manifest") or item.get("root") or "."
            source_id = item.get("source_id") or item.get("manifest_sha256") or handoff["source_fingerprint"]
            hits.append(SearchHit(source_id=source_id, path=path,
                                  start_line=int(item.get("start_line", 1)),
                                  end_line=int(item.get("end_line", item.get("start_line", 1))),
                                  excerpt=json.dumps(item, sort_keys=True)[:2048]))
        next_cursor = str(offset + len(page)) if offset + len(page) < len(matched) else None
        gaps = tuple(str(item) for item in document.get("gaps", [])[:100])
        return SearchPage(tuple(hits), next_cursor, gaps)
