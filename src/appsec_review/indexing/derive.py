"""Publication of derived link and precomputed shards with content-addressed reuse.

A derived shard is keyed by its rule version, the exact identities of the accepted shards and
pinned artifacts it reads, and its bounded settings. An unchanged key reuses the immutable shard;
changing one rule rebuilds only that shard and the products that declare it as an input.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
from typing import Any

from appsec_review.indexing.store import digest
from appsec_review.retrieval.index import INDEX_SCHEMA, IndexBuilder, IndexIdentity
from appsec_review.retrieval.model import (
    EntityKind, EntityRecord, LogicalIdentity, RelationKind, RelationRecord, SourceLocation,
)
from appsec_review.retrieval.precomputed import FACT_SCHEMA
from appsec_review.storage import atomic_json, file_sha256


DERIVED_SCHEMA = "appsec-review/derived-shard/1"
AUTHORITY = "computed from accepted run-owned evidence; a fact or link is not a tool finding"


@dataclass(slots=True)
class Derived:
    """Entities, relations and coverage of one derived shard before publication."""

    entities: list[EntityRecord] = field(default_factory=list)
    relations: list[RelationRecord] = field(default_factory=list)
    coverage: list[tuple[str, str, str | None]] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)

    def count(self, name: str, amount: int = 1) -> None:
        self.counts[name] = self.counts.get(name, 0) + amount

    def gap(self, text: str) -> None:
        if text not in self.gaps:
            self.gaps.append(text)

    def relate(self, kind: RelationKind, source: str, target: str, *, exact: bool, confidence: float,
               method: str, ambiguity: str | None = None, **payload: Any) -> None:
        self.relations.append(RelationRecord(kind, source, target, exact, confidence,
                                             None if exact else (ambiguity or f"{method} join"),
                                             {"mapping_method": method, **payload}))
        self.count("exact_links" if exact else "ambiguous_links")


def location_from(snapshot: str, value: Mapping[str, Any] | None, method: str | None = None) -> SourceLocation | None:
    """Copy an accepted upstream location; the mapping method and ambiguity are preserved."""
    if not value or value.get("path") is None or value.get("file_sha256") is None:
        return None
    return SourceLocation(
        snapshot, str(value["path"]), str(value["file_sha256"]), int(value["start_byte"]), int(value["end_byte"]),
        int(value["start_line"]), int(value["end_line"]), int(value["start_column"]), int(value["end_column"]),
        {"copied_from": "accepted-upstream-location"}, method or str(value.get("mapping_method") or "upstream"),
        float(value.get("confidence") if value.get("confidence") is not None else 1.0),
        bool(value.get("ambiguous")))


def fact(snapshot: str, query_set: str, rule_version: str, key: Mapping[str, Any], *, name: str, text: str,
         result: Mapping[str, Any], basis: str, upstream: Sequence[Mapping[str, Any]],
         subject_identity: str | None = None, subject_path: str | None = None, status: str = "complete",
         gaps: Sequence[str] = (), location: Mapping[str, Any] | SourceLocation | None = None,
         fact_type: str = "fact") -> EntityRecord:
    """Build one ``precomputed_fact`` entity under the versioned fact contract."""
    identity = LogicalIdentity.derive(EntityKind.PRECOMPUTED_FACT, snapshot, {"query_set": query_set, "key": dict(key)})
    payload = {
        "schema": FACT_SCHEMA, "query_set": query_set, "fact_type": fact_type, "rule_version": rule_version,
        "subject_identity": subject_identity, "subject_path": subject_path, "result": dict(result),
        "basis": basis, "upstream": list(upstream)[:32], "coverage_status": status,
        "gaps": [str(gap)[:300] for gap in gaps][:20], "authority": AUTHORITY,
    }
    resolved = location if isinstance(location, SourceLocation) or location is None else location_from(snapshot, location)
    return EntityRecord(identity, digest(dict(key))[:32], name[:512], text[:4096], payload, resolved)


def publish_derived(
    run_root: Path, *, index: str, shard_id: str, job_id: str, unit_id: str, rule: str, rule_version: str,
    snapshot: str, inputs: Mapping[str, Any], build: Callable[[], Derived],
    producer: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Publish or reuse one derived shard; ``inputs`` must fully identify everything ``build`` reads."""
    fingerprint = digest({"schema": DERIVED_SCHEMA, "index": index, "shard_id": shard_id, "rule": rule,
                          "rule_version": rule_version, "target_snapshot": snapshot, "inputs": inputs})
    path = run_root / "data" / "indices" / index / shard_id / f"{fingerprint}.sqlite"
    checkpoint = run_root / "data" / "indexing" / "checkpoints" / index / shard_id / f"{fingerprint}.json"
    if path.is_file() and checkpoint.is_file():
        document = json.loads(checkpoint.read_text(encoding="utf-8"))
        if document.get("fingerprint") == fingerprint and \
                file_sha256(path) == document.get("index_identity", {}).get("sha256"):
            return {**document, "reused": True}
    if path.exists():
        path.unlink()  # an unverifiable leftover from an interrupted attempt; never accepted
    derived = build()
    builder = IndexBuilder(path, name=index, fingerprint=fingerprint, target_snapshot=snapshot, shard_id=shard_id)
    seen: set[str] = set()
    for entity in derived.entities:
        if entity.identity.value not in seen:
            seen.add(entity.identity.value)
            builder.add_entity(entity)
    relation_ids: set[str] = set()
    for relation in derived.relations:
        if relation.relation_id not in relation_ids:
            relation_ids.add(relation.relation_id)
            builder.add_relation(relation)
    for area, status, gap in derived.coverage:
        builder.add_coverage(area, status, gap)
    sha = builder.build()
    states = [status for _area, status, _gap in derived.coverage]
    terminal = ("UNAVAILABLE" if states and all(value == "unavailable" for value in states) else
                "PARTIAL" if derived.gaps or any(value != "complete" for value in states) else "SUCCEEDED")
    identity = IndexIdentity(index, INDEX_SCHEMA, sha, fingerprint, path.relative_to(run_root).as_posix(),
                             {"job": job_id, "unit": unit_id, "rule": rule, "rule_version": rule_version,
                              **dict(producer or {})}, tuple(gap[:300] for gap in derived.gaps[:50]), shard_id)
    document = {"schema": DERIVED_SCHEMA, "fingerprint": fingerprint, "rule": rule, "rule_version": rule_version,
                "index_identity": asdict(identity), "inputs_sha256": digest(inputs),
                "counts": {**dict(sorted(derived.counts.items())), "entities": len(seen),
                           "relations": len(relation_ids)},
                "gaps": derived.gaps[:200], "terminal_status": terminal}
    atomic_json(checkpoint, document)
    return {**document, "reused": False}
