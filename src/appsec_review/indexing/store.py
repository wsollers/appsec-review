"""Hash-verified, read-only access to accepted handoffs and immutable index shards.

Everything here runs inside an indexing job, never during an inference-time retrieval call. Shard
content is producer data: it is read as rows and never interpreted as instructions.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

from appsec_review.retrieval.index import MANIFEST_SCHEMA, IndexIdentity, load_verified_manifest
from appsec_review.retrieval.model import canonical_json
from appsec_review.storage import file_sha256


HANDOFF_SCHEMA = "appsec-review/job-handoff/1"


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class AcceptedHandoff:
    job_id: str
    handoff: Mapping[str, Any]
    sha256: str
    path: str


def accepted_handoff(run_root: Path, job_id: str) -> AcceptedHandoff | None:
    """Return the hash-verified accepted handoff of one job, or ``None`` when it has not run."""
    pointer_path = run_root / "data" / "jobs" / job_id / "latest.json"
    if not pointer_path.is_file() or pointer_path.is_symlink():
        return None
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    path = (run_root / str(pointer.get("handoff_path", ""))).resolve()
    if run_root.resolve() not in path.parents or not path.is_file():
        raise ValueError(f"accepted handoff is unavailable or outside the run: {job_id}")
    sha = file_sha256(path)
    if sha != pointer.get("handoff_sha256"):
        raise ValueError(f"accepted handoff identity changed: {job_id}")
    handoff = json.loads(path.read_text(encoding="utf-8"))
    if handoff.get("schema") != HANDOFF_SCHEMA or handoff.get("status") != "ACCEPTED":
        raise ValueError(f"handoff is not accepted: {job_id}")
    from appsec_review.storage.shared import verify_handoff, consume_handoff
    # Legacy handoffs may predate resolving_paths; their original contract is unchanged.
    if "resolving_paths" in handoff:
        verify_handoff(run_root, handoff)
        consume_handoff(run_root, handoff)
    return AcceptedHandoff(job_id, handoff, sha, path.relative_to(run_root.resolve()).as_posix())


def handoff_manifests(run_root: Path, handoff: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Verified retrieval manifests named by a handoff's unit outputs, in output order."""
    found: dict[tuple[str, str], Mapping[str, Any]] = {}
    for output in handoff.get("outputs", {}).values():
        reference = output.get("index_manifest") if isinstance(output, Mapping) else None
        if not isinstance(reference, Mapping) or not isinstance(reference.get("path"), str):
            continue
        path = (run_root / reference["path"]).resolve()
        if run_root.resolve() not in path.parents or not path.is_file():
            raise ValueError("handoff index manifest is unavailable or outside the run")
        try:
            schema = json.loads(path.read_text(encoding="utf-8")).get("schema")
        except (ValueError, AttributeError):
            schema = None
        if schema != MANIFEST_SCHEMA:
            continue  # a specialised store (for example the OWASP workbench) has its own reader
        document, sha = load_verified_manifest(run_root, path, str(reference.get("sha256", "")))
        found[(reference["path"], sha)] = {"path": reference["path"], "sha256": sha, "document": document}
    return list(found.values())


def shard_key(shard: Mapping[str, Any]) -> tuple[str, str]:
    return str(shard["name"]), str(shard.get("shard_id", "default"))


def as_identity(shard: Mapping[str, Any]) -> IndexIdentity:
    return IndexIdentity(**{**{key: shard[key] for key in (
        "name", "schema", "sha256", "fingerprint", "relative_path", "producer")},
        "gaps": tuple(shard.get("gaps", ())), "shard_id": str(shard.get("shard_id", "default"))})


def open_shard(run_root: Path, shard: Mapping[str, Any]) -> sqlite3.Connection:
    path = (run_root / str(shard["relative_path"])).resolve()
    if run_root.resolve() not in path.parents or not path.is_file():
        raise ValueError(f"index shard is unavailable: {shard_key(shard)}")
    database = sqlite3.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True)
    database.row_factory = sqlite3.Row
    return database


def shard_summary(run_root: Path, shard: Mapping[str, Any]) -> dict[str, Any]:
    """Counts and coverage straight from one shard; row counts are recomputed, not trusted."""
    with open_shard(run_root, shard) as database:
        metadata = dict(database.execute("SELECT key, value FROM metadata"))
        entities = int(database.execute("SELECT COUNT(*) FROM entities").fetchone()[0])
        relations = int(database.execute("SELECT COUNT(*) FROM relations").fetchone()[0])
        coverage = [dict(row) for row in database.execute(
            "SELECT area, status, gap FROM coverage ORDER BY area, status, gap")]
    declared_entities = sum(json.loads(metadata.get("entity_kind_counts", "{}")).values())
    declared_relations = sum(json.loads(metadata.get("relation_kind_counts", "{}")).values())
    return {"entity_count": entities, "relation_count": relations, "coverage": coverage,
            "entity_kinds": json.loads(metadata.get("entity_kind_counts", "{}")),
            "relation_kinds": json.loads(metadata.get("relation_kind_counts", "{}")),
            "counts_agree": (entities, relations) == (declared_entities, declared_relations),
            "target_snapshot": metadata.get("target_snapshot")}


_LOCATION = ("path", "file_sha256", "start_byte", "end_byte", "start_line", "end_line", "start_column",
             "end_column", "mapping_method", "confidence", "ambiguous")


class ShardSet:
    """A fixed list of accepted shards with bounded, deterministic row iteration."""

    def __init__(self, run_root: Path, shards: Iterable[Mapping[str, Any]]):
        self.run_root = Path(run_root)
        self.shards = tuple(sorted(shards, key=shard_key))

    def select(self, *, index: str | Sequence[str] | None = None, job: str | Sequence[str] | None = None,
               prefix: str | Sequence[str] | None = None,
               producer: str | Sequence[str] | None = None) -> tuple[Mapping[str, Any], ...]:
        def values(item: str | Sequence[str] | None) -> tuple[str, ...] | None:
            return None if item is None else (item,) if isinstance(item, str) else tuple(item)
        names, jobs, prefixes, producers = values(index), values(job), values(prefix), values(producer)
        return tuple(
            shard for shard in self.shards
            if (names is None or shard["name"] in names)
            and (jobs is None or shard.get("producer", {}).get("job") in jobs)
            and (prefixes is None or str(shard.get("shard_id", "default")).startswith(prefixes))
            and (producers is None or shard.get("producer", {}).get("producer") in producers))

    @staticmethod
    def identities(shards: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
        return [{"name": str(shard["name"]), "shard_id": str(shard.get("shard_id", "default")),
                 "sha256": str(shard["sha256"])} for shard in sorted(shards, key=shard_key)]

    def entities(self, shards: Iterable[Mapping[str, Any]], *, kinds: Sequence[str] = (),
                 limit: int | None = None) -> Iterator[dict[str, Any]]:
        """Yield entity rows in (shard, identity) order; ``limit`` bounds the total rows returned."""
        remaining = limit
        for shard in sorted(shards, key=shard_key):
            sql = ("SELECT e.identity, e.kind, e.native_id, e.name, e.text, e.payload_json, "
                   + ", ".join(f"l.{name}" for name in _LOCATION) +
                   " FROM entities e LEFT JOIN locations l ON l.entity_id = e.identity")
            parameters: list[Any] = []
            if kinds:
                sql += " WHERE e.kind IN (" + ",".join("?" for _ in kinds) + ")"
                parameters.extend(kinds)
            sql += " ORDER BY e.identity"
            if remaining is not None:
                sql += " LIMIT ?"
                parameters.append(remaining)
            with open_shard(self.run_root, shard) as database:
                for row in database.execute(sql, parameters):
                    location = None if row["path"] is None else {name: row[name] for name in _LOCATION}
                    yield {"identity": row["identity"], "kind": row["kind"], "native_id": row["native_id"],
                           "name": row["name"], "text": row["text"], "payload": json.loads(row["payload_json"]),
                           "location": location, "index": shard["name"],
                           "shard_id": str(shard.get("shard_id", "default")),
                           "job": shard.get("producer", {}).get("job")}
                    if remaining is not None:
                        remaining -= 1
                        if remaining <= 0:
                            return

    def relations(self, shards: Iterable[Mapping[str, Any]], *, kinds: Sequence[str] = ()) -> Iterator[dict[str, Any]]:
        for shard in sorted(shards, key=shard_key):
            sql = "SELECT relation_id, kind, source_id, target_id, exact, confidence, ambiguity, payload_json FROM relations"
            parameters: list[Any] = []
            if kinds:
                sql += " WHERE kind IN (" + ",".join("?" for _ in kinds) + ")"
                parameters.extend(kinds)
            with open_shard(self.run_root, shard) as database:
                for row in database.execute(sql + " ORDER BY relation_id", parameters):
                    yield {"kind": row["kind"], "source_id": row["source_id"], "target_id": row["target_id"],
                           "exact": bool(row["exact"]), "confidence": float(row["confidence"]),
                           "ambiguity": row["ambiguity"], "payload": json.loads(row["payload_json"]),
                           "index": shard["name"], "shard_id": str(shard.get("shard_id", "default"))}

    def coverage(self, shards: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for shard in sorted(shards, key=shard_key):
            with open_shard(self.run_root, shard) as database:
                rows.extend({"index": shard["name"], "shard_id": str(shard.get("shard_id", "default")),
                             "area": row["area"], "status": row["status"], "gap": row["gap"]}
                            for row in database.execute("SELECT area, status, gap FROM coverage ORDER BY area, status, gap"))
        return rows

    def entity_ids(self) -> set[str]:
        found: set[str] = set()
        for shard in self.shards:
            with open_shard(self.run_root, shard) as database:
                found.update(str(row[0]) for row in database.execute("SELECT identity FROM entities"))
        return found
