"""Physical shard work observed during one logical retrieval operation."""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
import sqlite3
from typing import Any, Mapping, TYPE_CHECKING

if TYPE_CHECKING:
    from .core import ShardGroup


@dataclass(slots=True)
class _QueryWork:
    tool: str
    request_hash: str
    started: float
    indexes: dict[str, ShardGroup]
    response: Mapping[str, Any] | None = None
    duration_ms: int | None = None
    result_count: int | None = None
    considered: set[str] = field(default_factory=set)
    shards_candidate: int = 0
    shards_opened: int = 0
    route_cache_hit: bool | None = None
    snapshot_cache_hits: int = 0
    snapshot_cache_misses: int = 0

    def complete(self, response: Mapping[str, Any], *, duration_ms: int | None = None,
                 result_count: int | None = None) -> None:
        if self.response is not None:
            raise RuntimeError("retrieval query already completed")
        self.response = response
        self.duration_ms = duration_ms
        self.result_count = result_count

    def consider(self, name: str) -> None:
        if name not in self.considered:
            self.considered.add(name)
            self.shards_candidate += len(dict.get(self.indexes, name, ()))

    def route(self, hit: bool) -> None:
        # A mixed lookup wasn't served wholly by warm routes. None means no route was consulted.
        self.route_cache_hit = hit and self.route_cache_hit is not False

    def include(self, child: _QueryWork) -> None:
        self.shards_candidate += child.shards_candidate
        self.shards_opened += child.shards_opened
        self.snapshot_cache_hits += child.snapshot_cache_hits
        self.snapshot_cache_misses += child.snapshot_cache_misses
        if child.route_cache_hit is not None:
            self.route(child.route_cache_hit)

    def metrics(self) -> dict[str, int | bool | None]:
        return {"shards_candidate": self.shards_candidate, "shards_opened": self.shards_opened,
                "route_cache_hit": self.route_cache_hit, "snapshot_cache_hits": self.snapshot_cache_hits,
                "snapshot_cache_misses": self.snapshot_cache_misses}


_QUERY: ContextVar[_QueryWork | None] = ContextVar("appsec_retrieval_query", default=None)


def connect_shard(uri: str, *, timeout: float = 5.0) -> sqlite3.Connection:
    """Count successful opens, including custody-only reads; the caller owns the handle."""
    database = sqlite3.connect(uri, uri=True, timeout=timeout)
    work = _QUERY.get()
    if work is not None:
        work.shards_opened += 1
    return database
