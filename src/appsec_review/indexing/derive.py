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
from tempfile import TemporaryDirectory
from typing import Any

from appsec_review.indexing.store import digest
from appsec_review.retrieval.index import INDEX_SCHEMA, IndexBuilder, IndexIdentity
from appsec_review.retrieval.model import (
    EntityKind, EntityRecord, LogicalIdentity, RelationKind, RelationRecord, SourceLocation,
)
from appsec_review.retrieval.precomputed import FACT_SCHEMA
from appsec_review.storage import canonical_json, file_sha256
from appsec_review.storage.shared import (
    SharedArtifacts, immutable_bytes, put_bytes, put_file, reference, safe_path, verify_reference,
)


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
    shared: SharedArtifacts | None = None,
) -> dict[str, Any]:
    """Publish or reuse one derived shard; ``inputs`` must fully identify everything ``build`` reads."""
    fingerprint = digest({"schema": DERIVED_SCHEMA, "index": index, "shard_id": shard_id, "rule": rule,
                          "rule_version": rule_version, "target_snapshot": snapshot, "inputs": inputs})
    path = run_root / "data" / "indices" / index / shard_id / f"{fingerprint}.sqlite"
    checkpoint = run_root / "data" / "indexing" / "checkpoints" / index / shard_id / f"{fingerprint}.json"
    computation = {"rule": rule, "rule_version": rule_version, "inputs_sha256": digest(inputs),
                   "target_snapshot": snapshot, "unit_id": unit_id}
    if shared is not None:
        hit = shared.lookup("derived-index", fingerprint)
        if hit is not None:
            receipt, ref = hit
            document = json.loads(verify_reference(run_root, receipt["object"]).read_bytes())
            if document.get("fingerprint") != fingerprint or document.get("inputs_sha256") != digest(inputs):
                raise ValueError("shared derived checkpoint identity mismatch")
            if receipt["legacy"] is None:
                document["index_identity"]["producer"]["shared_receipt"] = receipt["producer_receipt"] or ref
            return {**document, "reused": True, "shared_receipt": ref}
    safe_path(run_root, path.relative_to(run_root).as_posix())
    safe_path(run_root, checkpoint.relative_to(run_root).as_posix())
    if path.is_file() and checkpoint.is_file():
        document = json.loads(checkpoint.read_text(encoding="utf-8"))
        identity = document.get("index_identity", {})
        if (document.get("schema") != DERIVED_SCHEMA or document.get("fingerprint") != fingerprint
                or document.get("inputs_sha256") != digest(inputs)
                or identity.get("relative_path") != path.relative_to(run_root).as_posix()
                or file_sha256(path) != identity.get("sha256")):
            raise ValueError("legacy derived checkpoint/shard integrity mismatch")
        ref = None
        if shared is not None:
            _, ref = shared.legacy("derived-index", fingerprint, reference(run_root, checkpoint),
                                   computation=computation, dependencies=(reference(run_root, path),))
        return {**document, "reused": True, "shared_receipt": ref}
    if checkpoint.exists():
        raise ValueError("derived checkpoint has no immutable shard")
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
    if shared is None:
        sha = builder.build()
        shard_ref = reference(run_root, path)
    else:
        with TemporaryDirectory(prefix=".shared-build-", dir=shared.attempt_root) as directory:
            builder.path = Path(directory) / "shard.sqlite"
            builder.build()
            shard_ref = put_file(run_root, builder.path)
        sha = shard_ref["sha256"]
        path = run_root / shard_ref["path"]
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
    ref = None
    if shared is None:
        immutable_bytes(run_root, checkpoint.relative_to(run_root).as_posix(), canonical_json(document))
    else:
        obj = put_bytes(run_root, canonical_json(document))
        ref = shared.computed("derived-index", fingerprint, obj, computation=computation,
                              dependencies=(shard_ref,))
        document["index_identity"]["producer"]["shared_receipt"] = ref
    return {**document, "reused": False, "shared_receipt": ref}
