"""Immutable SQLite/FTS index construction and accepted-manifest verification."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterable, Mapping

from appsec_review.retrieval.model import EntityRecord, RelationRecord, canonical_json, sanitize_producer_data
from appsec_review.storage import atomic_json, file_sha256


INDEX_SCHEMA = "appsec-review/retrieval-index/2"
MANIFEST_SCHEMA = "appsec-review/index-manifest/1"
INDEX_NAMES = (
    "source", "observations", "components", "build", "artifacts", "build_security", "compiled", "analysis", "evidence",
    "history",
    "tags",
    "priority",
)


@dataclass(frozen=True, slots=True)
class IndexIdentity:
    name: str
    schema: str
    sha256: str
    fingerprint: str
    relative_path: str
    producer: Mapping[str, Any]
    gaps: tuple[str, ...] = ()
    shard_id: str = "default"

    def __post_init__(self) -> None:
        if self.name not in INDEX_NAMES:
            raise ValueError(f"unknown physical index name: {self.name}")
        if self.schema != INDEX_SCHEMA:
            raise ValueError("unsupported index schema")
        if len(self.sha256) != 64 or len(self.fingerprint) != 64:
            raise ValueError("index identity requires sha256 fingerprints")
        if not self.shard_id or len(self.shard_id) > 128 or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
            for character in self.shard_id
        ):
            raise ValueError("index shard id is invalid")
        path = Path(self.relative_path)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("index path must be run-relative")


def index_fingerprint(
    *, name: str, target_snapshot: str, producer_artifacts: Iterable[Mapping[str, Any]],
    tool_identity: Mapping[str, Any], parser_identity: str, normalizer_identity: str,
    mapping_identity: str, upstream_manifests: Iterable[str] = (),
) -> str:
    """Fingerprint only the inputs on which one physical shard depends."""
    return hashlib.sha256(canonical_json({
        "schema": INDEX_SCHEMA, "name": name, "target_snapshot": target_snapshot,
        "producer_artifacts": list(producer_artifacts), "tool_identity": tool_identity,
        "parser_identity": parser_identity, "normalizer_identity": normalizer_identity,
        "mapping_identity": mapping_identity, "upstream_manifests": sorted(upstream_manifests),
    })).hexdigest()


class IndexBuilder:
    """Build one deterministic read-only shard and atomically place it in the run."""

    def __init__(self, path: Path, *, name: str, fingerprint: str, target_snapshot: str,
                 shard_id: str = "default"):
        if name not in INDEX_NAMES:
            raise ValueError(f"unknown physical index name: {name}")
        self.path = Path(path)
        self.name = name
        self.fingerprint = fingerprint
        self.target_snapshot = target_snapshot
        self.shard_id = shard_id
        self.entities: list[EntityRecord] = []
        self.relations: list[RelationRecord] = []
        self.coverage: list[tuple[str, str, str | None]] = []

    def add_entity(self, value: EntityRecord) -> None:
        self.entities.append(value)

    def add_relation(self, value: RelationRecord) -> None:
        self.relations.append(value)

    def add_coverage(self, area: str, status: str, gap: str | None = None) -> None:
        if status not in {"complete", "partial", "unavailable", "stale"}:
            raise ValueError("invalid coverage status")
        self.coverage.append((area, status, gap))

    def build(self) -> str:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            raise ValueError(f"immutable index shard already exists: {self.name}/{self.shard_id}")
        temporary = self.path.with_name(self.path.name + ".building")
        if temporary.exists():
            temporary.unlink()
        database = sqlite3.connect(temporary)
        try:
            database.executescript("""
                PRAGMA journal_mode=DELETE;
                PRAGMA synchronous=FULL;
                PRAGMA page_size=4096;
                CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
                CREATE TABLE entities(
                    identity TEXT PRIMARY KEY, kind TEXT NOT NULL, native_id TEXT NOT NULL,
                    name TEXT NOT NULL, text TEXT NOT NULL, payload_json TEXT NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE locations(
                    location_id TEXT NOT NULL, entity_id TEXT PRIMARY KEY,
                    target_snapshot TEXT NOT NULL, path TEXT NOT NULL, file_sha256 TEXT NOT NULL,
                    start_byte INTEGER NOT NULL, end_byte INTEGER NOT NULL,
                    start_line INTEGER NOT NULL, end_line INTEGER NOT NULL,
                    start_column INTEGER NOT NULL, end_column INTEGER NOT NULL,
                    producer_location_json TEXT NOT NULL, mapping_method TEXT NOT NULL,
                    confidence REAL NOT NULL, ambiguous INTEGER NOT NULL,
                    FOREIGN KEY(entity_id) REFERENCES entities(identity)
                ) WITHOUT ROWID;
                CREATE TABLE relations(
                    relation_id TEXT PRIMARY KEY, kind TEXT NOT NULL, source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL, exact INTEGER NOT NULL, confidence REAL NOT NULL,
                    ambiguity TEXT, payload_json TEXT NOT NULL
                ) WITHOUT ROWID;
                CREATE INDEX relations_source ON relations(source_id, kind);
                CREATE INDEX relations_target ON relations(target_id, kind);
                CREATE TABLE coverage(
                    area TEXT NOT NULL, status TEXT NOT NULL, gap TEXT,
                    PRIMARY KEY(area, status, gap)
                );
                CREATE VIRTUAL TABLE search_fts USING fts5(
                    identity UNINDEXED, name, path, text, tokenize='unicode61'
                );
            """)
            metadata = {
                "schema": INDEX_SCHEMA, "name": self.name, "fingerprint": self.fingerprint,
                "target_snapshot": self.target_snapshot, "shard_id": self.shard_id,
            }
            database.executemany("INSERT INTO metadata VALUES (?, ?)", sorted(metadata.items()))
            for record in sorted(self.entities, key=lambda item: item.identity.value):
                identity = record.identity.value
                database.execute("INSERT INTO entities VALUES (?, ?, ?, ?, ?, ?)", (
                    identity, record.identity.kind.value, record.native_id[:4096], record.name[:4096],
                    record.text[:131072], json.dumps(sanitize_producer_data(record.payload), sort_keys=True),
                ))
                location_path = ""
                if record.location is not None:
                    location = record.location
                    location_path = location.path
                    database.execute("INSERT INTO locations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (
                        location.location_id, identity, location.target_snapshot, location.path,
                        location.file_sha256, location.start_byte, location.end_byte,
                        location.start_line, location.end_line, location.start_column, location.end_column,
                        json.dumps(sanitize_producer_data(location.producer_location), sort_keys=True),
                        location.mapping_method, location.confidence, int(location.ambiguous),
                    ))
                database.execute("INSERT INTO search_fts(identity, name, path, text) VALUES (?, ?, ?, ?)",
                                 (identity, record.name, location_path, record.text))
            for relation in sorted(self.relations, key=lambda item: item.relation_id):
                database.execute("INSERT INTO relations VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (
                    relation.relation_id, relation.kind.value, relation.source_id, relation.target_id,
                    int(relation.exact), relation.confidence, relation.ambiguity,
                    json.dumps(sanitize_producer_data(relation.payload or {}), sort_keys=True),
                ))
            database.executemany("INSERT INTO coverage VALUES (?, ?, ?)", sorted(set(self.coverage)))
            database.commit()
            database.execute("VACUUM")
        finally:
            database.close()
        temporary.replace(self.path)
        return file_sha256(self.path)


def write_manifest(
    path: Path, *, run_id: str, target_snapshot: str, target_root: Path,
    indexes: Iterable[IndexIdentity], upstream_manifests: Iterable[Mapping[str, str]] = (),
) -> Mapping[str, Any]:
    values = sorted(indexes, key=lambda item: (item.name, item.shard_id))
    if len(values) != len({(item.name, item.shard_id) for item in values}):
        raise ValueError("manifest contains duplicate index shard identities")
    document = {
        "schema": MANIFEST_SCHEMA, "run_id": run_id, "target_snapshot": target_snapshot,
        "target_root": str(Path(target_root).resolve()), "indexes": [asdict(item) for item in values],
        "upstream_manifests": sorted(upstream_manifests, key=lambda item: (item.get("sha256", ""), item.get("path", ""))),
    }
    document["content_sha256"] = hashlib.sha256(canonical_json(document)).hexdigest()
    atomic_json(path, document)
    return document


def load_verified_manifest(run_root: Path, path: Path, expected_sha256: str | None = None,
                           _seen: frozenset[Path] = frozenset()) -> tuple[Mapping[str, Any], str]:
    """Verify the manifest and every immutable shard before opening any database."""
    run_root = Path(run_root).resolve()
    resolved = Path(path).resolve()
    if resolved in _seen:
        raise ValueError("index manifest dependency cycle")
    seen_manifests = _seen | {resolved}
    if run_root not in resolved.parents:
        raise ValueError("index manifest path escapes run")
    actual = file_sha256(resolved)
    if expected_sha256 is not None and actual != expected_sha256:
        raise ValueError("index manifest integrity mismatch")
    document = json.loads(resolved.read_text(encoding="utf-8"))
    if document.get("schema") != MANIFEST_SCHEMA:
        raise ValueError("unsupported index manifest schema")
    content_hash = document.pop("content_sha256", None)
    if content_hash != hashlib.sha256(canonical_json(document)).hexdigest():
        raise ValueError("index manifest content hash mismatch")
    document["content_sha256"] = content_hash
    for upstream in document.get("upstream_manifests", []):
        upstream_path = (run_root / str(upstream.get("path", ""))).resolve()
        if upstream_path == resolved:
            raise ValueError("index manifest references itself")
        load_verified_manifest(run_root, upstream_path, str(upstream.get("sha256", "")), seen_manifests)
    seen: set[tuple[str, str]] = set()
    entity_ids: set[str] = set()
    relations: list[tuple[str, str, str, str]] = []
    for raw in document.get("indexes", []):
        identity = IndexIdentity(**{**raw, "gaps": tuple(raw.get("gaps", ()))})
        shard_key = (identity.name, identity.shard_id)
        if shard_key in seen:
            raise ValueError("duplicate index shard identity")
        seen.add(shard_key)
        candidate = (run_root / identity.relative_path).resolve()
        if run_root not in candidate.parents or not candidate.is_file():
            raise ValueError(f"index is unavailable: {identity.name}")
        if file_sha256(candidate) != identity.sha256:
            raise ValueError(f"index integrity mismatch: {identity.name}")
        uri = f"file:{candidate.as_posix()}?mode=ro&immutable=1"
        with sqlite3.connect(uri, uri=True) as database:
            metadata = dict(database.execute("SELECT key, value FROM metadata"))
            if (metadata.get("schema"), metadata.get("name"), metadata.get("fingerprint"),
                metadata.get("shard_id", "default")) != (
                identity.schema, identity.name, identity.fingerprint, identity.shard_id,
            ):
                raise ValueError(f"index metadata mismatch: {identity.name}/{identity.shard_id}")
            if metadata.get("target_snapshot") != document.get("target_snapshot"):
                raise ValueError(f"index target snapshot mismatch: {identity.name}/{identity.shard_id}")
            entity_ids.update(str(row[0]) for row in database.execute("SELECT identity FROM entities"))
            relations.extend((str(row[0]), str(row[1]), str(row[2]), identity.shard_id)
                             for row in database.execute(
                                 "SELECT relation_id, source_id, target_id FROM relations"))
    for relation_id, source_id, target_id, shard_id in relations:
        if source_id not in entity_ids or target_id not in entity_ids:
            raise ValueError(f"relation closure mismatch: {shard_id}/{relation_id}")
    return document, actual
