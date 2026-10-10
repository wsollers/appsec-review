"""Product model shared by every precomputed query set.

Builders read accepted shards through :class:`AcceptedShards` (a typed view over
:class:`~appsec_review.indexing.store.ShardSet`) and return a :class:`Product`. Publication goes
through :func:`appsec_review.indexing.derive.publish_derived`, so a product is keyed by its rule
version, typed settings and the exact upstream shard hashes it read: a changed rule rebuilds only
its own product and unchanged products are reused.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from appsec_review.indexing.derive import Derived, fact
from appsec_review.indexing.store import ShardSet
from appsec_review.retrieval.model import SourceLocation
from appsec_review.retrieval.precomputed import QUERY_SETS


@dataclass(frozen=True, slots=True)
class Row:
    """One accepted entity with the shard that holds it."""

    index: str
    shard_id: str
    shard_sha256: str
    identity: str
    kind: str
    native_id: str
    name: str
    payload: Mapping[str, Any]
    location: Mapping[str, Any] | None

    def source_location(self, snapshot: str) -> SourceLocation | None:
        if self.location is None:
            return None
        value = self.location
        return SourceLocation(snapshot, value["path"], value["file_sha256"], int(value["start_byte"]),
                              int(value["end_byte"]), int(value["start_line"]), int(value["end_line"]),
                              int(value["start_column"]), int(value["end_column"]),
                              {"index": self.index, "shard_id": self.shard_id, "entity": self.identity},
                              str(value["mapping_method"]), float(value["confidence"]), bool(value["ambiguous"]))


class AcceptedShards:
    """Typed rows over one fixed set of accepted (or restored) shards."""

    def __init__(self, run_root: Path, shards: Iterable[Mapping[str, Any]], snapshot: str):
        self.store = ShardSet(run_root, shards)
        self.run_root = Path(run_root)
        self.snapshot = snapshot
        self.shards = self.store.shards
        self._sha = {(str(item["name"]), str(item.get("shard_id", "default"))): str(item["sha256"])
                     for item in self.shards}

    def select(self, index: str, *, shard_prefix: str | None = None,
               job: str | None = None) -> tuple[Mapping[str, Any], ...]:
        return self.store.select(index=index, prefix=shard_prefix, job=job)

    def entities(self, shards: Iterable[Mapping[str, Any]], kinds: Iterable[str] = ()) -> Iterator[Row]:
        for row in self.store.entities(shards, kinds=tuple(kinds)):
            yield Row(row["index"], row["shard_id"], self._sha[(row["index"], row["shard_id"])], row["identity"],
                      row["kind"], row["native_id"], row["name"], row["payload"], row["location"])

    def relations(self, shards: Iterable[Mapping[str, Any]], kinds: Iterable[str] = ()) -> Iterator[Mapping[str, Any]]:
        return self.store.relations(shards, kinds=tuple(kinds))

    def coverage(self, shards: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
        return self.store.coverage(shards)


@dataclass(slots=True)
class Fact:
    fact_type: str
    key: str
    result: Mapping[str, Any]
    basis: str
    subject_identity: str | None = None
    subject_path: str | None = None
    upstream: tuple[str, ...] = ()
    coverage: str = "complete"
    location: SourceLocation | None = None
    text: str = ""


@dataclass(slots=True)
class Product:
    """Bounded facts and scoped coverage for one query set."""

    query_set: str
    rule_version: str
    facts: list[Fact] = field(default_factory=list)
    inputs: list[Mapping[str, Any]] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    status: str = "complete"
    counts: dict[str, int] = field(default_factory=dict)
    # Lead menus must never be truncated; a product that sets this fails instead of dropping facts.
    complete_or_fail: bool = False

    def __post_init__(self) -> None:
        if self.query_set not in QUERY_SETS:
            raise ValueError(f"unknown precomputed query set: {self.query_set}")

    def use(self, shards: Iterable[Mapping[str, Any]]) -> None:
        for shard in shards:
            reference = {"index": str(shard["name"]), "shard_id": str(shard.get("shard_id", "default")),
                         "sha256": str(shard["sha256"])}
            if reference not in self.inputs:
                self.inputs.append(reference)

    def unavailable(self, reason: str) -> "Product":
        self.status = "unavailable"
        self.gaps.append(reason)
        return self

    def partial(self, reason: str) -> None:
        if self.status == "complete":
            self.status = "partial"
        if reason not in self.gaps:
            self.gaps.append(reason)


def merge_product(derived: Derived, product: Product, snapshot: str, *, area: str | None = None) -> Derived:
    """Append a product's facts, gaps and a scoped coverage row to a derived shard."""
    for item in sorted(product.facts, key=lambda value: (value.fact_type, value.key)):
        derived.entities.append(fact(
            snapshot, product.query_set, product.rule_version, {"fact_type": item.fact_type, "key": item.key},
            name=f"{product.query_set} {item.fact_type}", text=item.text or f"{product.query_set} {item.fact_type} {item.key}",
            result=item.result, basis=item.basis, upstream=[{"identity": value} for value in item.upstream],
            subject_identity=item.subject_identity, subject_path=item.subject_path, status=item.coverage,
            location=item.location, fact_type=item.fact_type))
    for gap in product.gaps:
        derived.gap(gap if area is None else f"{area}: {gap}")
    for name, value in product.counts.items():
        derived.count(name if area is None else f"{area}:{name}", int(value))
    derived.coverage.append((area or product.query_set, product.status, "; ".join(product.gaps[:20])[:1000] or None))
    return derived


def to_derived(product: Product, snapshot: str, max_facts: int) -> Derived:
    """Convert one complete product; a lead menu that would exceed the bound fails instead of truncating."""
    if len(product.facts) > max_facts:
        if product.complete_or_fail:
            raise ValueError(f"{product.query_set} exceeds the fact bound ({len(product.facts)} > {max_facts}); "
                             "a complete lead menu cannot be truncated")
        product.facts = sorted(product.facts, key=lambda value: (value.fact_type, value.key))[:max_facts]
        product.partial(f"truncated: facts beyond the bound of {max_facts} were omitted")
    derived = merge_product(Derived(), product, snapshot)
    derived.count("facts", len(derived.entities))
    return derived