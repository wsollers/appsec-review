"""Immutable SQLite/FTS index construction and accepted-manifest verification."""

from __future__ import annotations

from appsec_review.storage.validation import validation_operation

from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from typing import Any, Iterable, Mapping

from appsec_review.retrieval.model import EntityRecord, RelationRecord, canonical_json, sanitize_producer_data
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.swift_policy import (
    is_swift_path, reject_swift_derived, swift_coverage_cell_is_gap, swift_enabled_from_run,
)


INDEX_SCHEMA = "appsec-review/retrieval-index/2"
MANIFEST_SCHEMA = "appsec-review/index-manifest/1"
INDEX_NAMES = (
    "source", "observations", "components", "build", "artifacts", "build_security", "compiled", "analysis", "evidence",
    "history",
    "tags",
    "priority",
    "precomputed",
    "inventory",
    "links", "documents",
    "graph",
    "debug_symbols",
    "binary",
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

    def _unique_entities(self) -> list[EntityRecord]:
        """Collapse repeated entities; one identity carrying different content is a producer bug."""

        unique: dict[str, EntityRecord] = {}
        for record in self.entities:
            previous = unique.setdefault(record.identity.value, record)
            if previous != record:
                raise ValueError(f"index shard {self.name}/{self.shard_id} has conflicting entities "
                                 f"for identity {record.identity.value}")
        return [unique[key] for key in sorted(unique)]

    def _unique_relations(self) -> tuple[list[RelationRecord], int]:
        """Merge relations sharing a relation_id, keeping the strongest observation.

        A relation_id covers kind, endpoints, exactness and ambiguity, so repeats differ at most in
        confidence and payload (several tool invocations reporting one output, for example). The
        kept record is chosen by confidence, then by canonical payload, so the shard is identical
        whatever order the producer emitted them in.
        """

        unique: dict[str, RelationRecord] = {}
        for relation in self.relations:
            previous = unique.get(relation.relation_id)
            if previous is None or _relation_rank(relation) > _relation_rank(previous):
                unique[relation.relation_id] = relation
        return [unique[key] for key in sorted(unique)], len(self.relations) - len(unique)

    def build(self) -> str:
        """Build, make durable, hash once and publish one complete immutable shard.

        Phases, in order: write (private temp file, no journal/sync) -> fsync (the single
        durability point) -> hash -> adopt (hard-link into the content store) -> link (named
        path) -> custody (binding/receipt/request records). Returns only after custody.
        """
        from appsec_review.observability.spans import count_work, operation_phase
        from appsec_review.storage.atomic import timed_fsync
        from appsec_review.storage.shared import adopt_private_file, current, safe_path
        from appsec_review.storage.validation import remember_digest, validation_scope, verified_digest
        owner = current()
        if owner is not None:
            safe_path(owner.run_root, self.path.relative_to(owner.run_root).as_posix())
        with operation_phase("index.prepare"):
            entities = self._unique_entities()
            relations, merged_relations = self._unique_relations()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        custody = owner is not None and self.path.is_relative_to(owner.run_root / "data" / "indices")
        with TemporaryDirectory(prefix=".building-", dir=self.path.parent) as directory:
            temporary = Path(directory) / "shard.sqlite"
            self._write_database(temporary, entities, relations, merged_relations)
            count_work("shards_built")
            count_work("entities_written", len(entities))
            count_work("relations_written", len(relations))
            if custody:
                # Same private mode as the copying content-store path it replaces.
                os.chmod(temporary, 0o600)
            descriptor = os.open(temporary, os.O_RDONLY)
            try:
                timed_fsync(descriptor)
            finally:
                os.close(descriptor)
            with operation_phase("index.digest"):
                digest = file_sha256(temporary)
            if not custody:
                self._place(temporary, digest, None)
                return digest
            root = owner.run_root
            with validation_scope(root):
                remember_digest(root, temporary, digest)
                with operation_phase("index.publish"):
                    content = adopt_private_file(root, temporary, digest)
                self._place(safe_path(root, content["path"]), digest,
                            lambda: verified_digest(root, self.path, digest))
                with operation_phase("index.custody_bind"):
                    owner.named("index-shard", self.path, computed=True, expected_sha256=digest,
                                computation={
                                    "fingerprint": self.fingerprint, "name": self.name,
                                    "shard_id": self.shard_id, "target_snapshot": self.target_snapshot,
                                    "schema": INDEX_SCHEMA})
            return digest

    def _place(self, source: Path, digest: str, verify: Any) -> None:
        from appsec_review.observability.spans import operation_phase
        try:
            # A same-filesystem link publishes complete bytes without replacing another writer.
            with operation_phase("index.link"):
                os.link(source, self.path)
        except FileExistsError:
            matches = False
            if not self.path.is_symlink() and self.path.is_file():
                try:
                    matches = (verify() if verify is not None else file_sha256(self.path)) == digest
                except ValueError:
                    matches = False
            if not matches:
                raise ValueError(
                    f"immutable index shard conflicts with existing bytes: "
                    f"{self.name}/{self.shard_id}"
                ) from None

    def _write_database(self, temporary: Path, entities: list[EntityRecord],
                        relations: list[RelationRecord], merged_relations: int) -> None:
        # The private file is unpublished until build() fsyncs and hashes it, so it needs no
        # rollback journal, per-statement sync or VACUUM. Rows are inserted in sorted order and
        # secondary indexes are created after the bulk inserts, so equal inputs give equal bytes.
        from appsec_review.observability.spans import operation_phase
        writing = operation_phase("index.sqlite_write").__enter__()
        database = sqlite3.connect(temporary)
        try:
            database.isolation_level = None
            for pragma in ("PRAGMA page_size=4096", "PRAGMA journal_mode=OFF", "PRAGMA synchronous=OFF",
                           "PRAGMA locking_mode=EXCLUSIVE"):
                database.execute(pragma)
            database.execute("BEGIN")
            for statement in _SHARD_TABLES:
                database.execute(statement)
            metadata = {
                "schema": INDEX_SCHEMA, "name": self.name, "fingerprint": self.fingerprint,
                "target_snapshot": self.target_snapshot, "shard_id": self.shard_id,
                "entity_kind_counts": json.dumps(dict(sorted(Counter(
                    item.identity.kind.value for item in entities).items()))),
                "relation_kind_counts": json.dumps(dict(sorted(Counter(
                    item.kind.value for item in relations).items()))),
                "relation_duplicates_merged": str(merged_relations),
            }
            database.executemany("INSERT INTO metadata VALUES (?, ?)", sorted(metadata.items()))
            entity_rows, location_rows, search_rows = [], [], []
            for record in entities:
                identity = record.identity.value
                entity_rows.append((
                    identity, record.identity.kind.value, record.native_id[:4096], record.name[:4096],
                    record.text[:131072], json.dumps(sanitize_producer_data(record.payload), sort_keys=True),
                ))
                location_path = ""
                if record.location is not None:
                    location = record.location
                    location_path = location.path
                    location_rows.append((
                        location.location_id, identity, location.target_snapshot, location.path,
                        location.file_sha256, location.start_byte, location.end_byte,
                        location.start_line, location.end_line, location.start_column, location.end_column,
                        json.dumps(sanitize_producer_data(location.producer_location), sort_keys=True),
                        location.mapping_method, location.confidence, int(location.ambiguous),
                    ))
                search_rows.append((identity, record.name, location_path, record.text))
            database.executemany("INSERT INTO entities VALUES (?, ?, ?, ?, ?, ?)", entity_rows)
            database.executemany(
                "INSERT INTO locations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", location_rows)
            database.executemany("INSERT INTO search_fts(identity, name, path, text) VALUES (?, ?, ?, ?)",
                                 search_rows)
            database.executemany("INSERT INTO relations VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [(
                relation.relation_id, relation.kind.value, relation.source_id, relation.target_id,
                int(relation.exact), relation.confidence, relation.ambiguity,
                json.dumps(sanitize_producer_data(relation.payload or {}), sort_keys=True),
            ) for relation in relations])
            database.executemany("INSERT INTO coverage VALUES (?, ?, ?)", sorted(set(self.coverage)))
            if self.name == "debug_symbols":
                from appsec_review.retrieval.debug_symbol_index import build_lookup
                build_lookup(database, entities)
            for statement in _SHARD_INDEXES:
                database.execute(statement)
            if self.name == "analysis":
                database.execute(_SYNTAX_LOOKUP)
            database.execute("COMMIT")
        finally:
            writing.__exit__(None, None, None)
            database.close()


_SHARD_TABLES = (
    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID",
    """CREATE TABLE entities(
        identity TEXT PRIMARY KEY, kind TEXT NOT NULL, native_id TEXT NOT NULL,
        name TEXT NOT NULL, text TEXT NOT NULL, payload_json TEXT NOT NULL
    ) WITHOUT ROWID""",
    """CREATE TABLE locations(
        location_id TEXT NOT NULL, entity_id TEXT PRIMARY KEY,
        target_snapshot TEXT NOT NULL, path TEXT NOT NULL, file_sha256 TEXT NOT NULL,
        start_byte INTEGER NOT NULL, end_byte INTEGER NOT NULL,
        start_line INTEGER NOT NULL, end_line INTEGER NOT NULL,
        start_column INTEGER NOT NULL, end_column INTEGER NOT NULL,
        producer_location_json TEXT NOT NULL, mapping_method TEXT NOT NULL,
        confidence REAL NOT NULL, ambiguous INTEGER NOT NULL,
        FOREIGN KEY(entity_id) REFERENCES entities(identity)
    ) WITHOUT ROWID""",
    """CREATE TABLE relations(
        relation_id TEXT PRIMARY KEY, kind TEXT NOT NULL, source_id TEXT NOT NULL,
        target_id TEXT NOT NULL, exact INTEGER NOT NULL, confidence REAL NOT NULL,
        ambiguity TEXT, payload_json TEXT NOT NULL
    ) WITHOUT ROWID""",
    """CREATE TABLE coverage(
        area TEXT NOT NULL, status TEXT NOT NULL, gap TEXT,
        PRIMARY KEY(area, status, gap)
    )""",
    """CREATE VIRTUAL TABLE search_fts USING fts5(
        identity UNINDEXED, name, path, text, tokenize='unicode61'
    )""",
)
_SHARD_INDEXES = (
    "CREATE INDEX relations_source ON relations(source_id, kind)",
    "CREATE INDEX relations_target ON relations(target_id, kind)",
)
_SYNTAX_LOOKUP = """CREATE INDEX syntax_lookup ON entities(
    json_extract(payload_json, '$.syntax.source_identity'),
    json_extract(payload_json, '$.syntax.category'),
    json_extract(payload_json, '$.syntax.written_name')
) WHERE kind='ast_node'"""


def _relation_rank(relation: RelationRecord) -> tuple[float, str]:
    return relation.confidence, json.dumps(sanitize_producer_data(relation.payload or {}), sort_keys=True)


def write_manifest(
    path: Path, *, run_id: str, target_snapshot: str, target_root: Path,
    indexes: Iterable[IndexIdentity], upstream_manifests: Iterable[Mapping[str, str]] = (),
) -> Mapping[str, Any]:
    values = sorted(indexes, key=lambda item: (item.name, item.shard_id))
    if len(values) != len({(item.name, item.shard_id) for item in values}):
        raise ValueError("manifest contains duplicate index shard identities")
    from appsec_review.storage.shared import current, consume_named
    owner = current()
    if owner is not None:
        for item in values:
            if item.relative_path.startswith("data/indices/"):
                consume_named(owner.run_root, owner.run_root / item.relative_path, namespace="index-shard",
                              expected_sha256=item.sha256)
            elif item.producer.get("shared_receipt") is not None:
                owner.consume_receipt(item.producer["shared_receipt"])
    document = {
        "schema": MANIFEST_SCHEMA, "run_id": run_id, "target_snapshot": target_snapshot,
        "target_root": str(Path(target_root).resolve()), "indexes": [asdict(item) for item in values],
        "upstream_manifests": sorted(upstream_manifests, key=lambda item: (item.get("sha256", ""), item.get("path", ""))),
    }
    document["content_sha256"] = hashlib.sha256(canonical_json(document)).hexdigest()
    atomic_json(path, document)
    return document


@validation_operation
def load_verified_manifest(run_root: Path, path: Path, expected_sha256: str | None = None,
                           _seen: frozenset[Path] = frozenset(),
                           verified: dict[tuple[Path, str], Mapping[str, Any]] | None = None,
                           ) -> tuple[Mapping[str, Any], str]:
    """Verify the manifest and every immutable shard before opening any database.

    ``verified`` memoizes manifests already verified in full, keyed by path and content hash, so
    an ancestor shared by several upstream lineages is verified once per call (or once per caller
    that passes the same mapping) instead of once per path through the lineage graph.
    """
    run_root = Path(run_root).resolve()
    resolved = Path(path).resolve()
    if resolved in _seen:
        raise ValueError("index manifest dependency cycle")
    seen_manifests = _seen | {resolved}
    if run_root not in resolved.parents:
        raise ValueError("index manifest path escapes run")
    from appsec_review.storage.validation import verified_digest, current_validation
    validation = current_validation(run_root)
    actual = (verified_digest(run_root, resolved, expected_sha256)
              if expected_sha256 is not None else file_sha256(resolved))
    if expected_sha256 is not None and actual != expected_sha256:
        raise ValueError("index manifest integrity mismatch")
    if verified is None:
        verified = {}
    manifest_key = ("manifest", str(resolved), actual)
    if validation is not None and manifest_key in validation.records:
        return validation.records[manifest_key], actual
    from appsec_review.observability.spans import count_work
    count_work("manifest_validations")
    if (resolved, actual) in verified:
        return verified[(resolved, actual)], actual
    document = json.loads(resolved.read_text(encoding="utf-8"))
    if document.get("schema") != MANIFEST_SCHEMA:
        raise ValueError("unsupported index manifest schema")
    content_hash = document.pop("content_sha256", None)
    if content_hash != hashlib.sha256(canonical_json(document)).hexdigest():
        raise ValueError("index manifest content hash mismatch")
    document["content_sha256"] = content_hash
    if validation is not None:
        admitted = validation.admitted_manifests.get(resolved.relative_to(run_root).as_posix())
        if admitted is not None and admitted["sha256"] == actual:
            if admitted["document"] != document:
                raise ValueError("admitted manifest differs from its validated projection")
            from appsec_review.storage.shared import safe_path
            for raw in document["indexes"]:
                candidate = safe_path(run_root, raw["relative_path"])
                if not candidate.is_file():
                    raise ValueError("admitted index output is unavailable")
            validation.records[manifest_key] = document
            return document, actual
    swift_enabled = swift_enabled_from_run(run_root)
    for upstream in document.get("upstream_manifests", []):
        upstream_path = (run_root / str(upstream.get("path", ""))).resolve()
        if upstream_path == resolved:
            raise ValueError("index manifest references itself")
        load_verified_manifest(run_root, upstream_path, str(upstream.get("sha256", "")), seen_manifests,
                               verified)
    seen: set[tuple[str, str]] = set()
    entity_ids: set[str] = set()
    relations: list[tuple[str, str, str, str]] = []
    for raw in document.get("indexes", []):
        count_work("shard_references")
        identity = IndexIdentity(**{**raw, "gaps": tuple(raw.get("gaps", ()))})
        shard_key = (identity.name, identity.shard_id)
        if shard_key in seen:
            raise ValueError("duplicate index shard identity")
        seen.add(shard_key)
        from appsec_review.storage.shared import safe_path
        candidate = safe_path(run_root, identity.relative_path)
        if identity.relative_path.startswith("data/shared/"):
            from appsec_review.storage.shared import safe_path, verify_receipt
            candidate = safe_path(run_root, identity.relative_path)
            receipt = verify_receipt(run_root, identity.producer["shared_receipt"])
            from appsec_review.storage.shared import current
            owner = current()
            if owner is not None:
                owner.consume_receipt(identity.producer["shared_receipt"])
            if not any(item["path"] == identity.relative_path and item["sha256"] == identity.sha256
                       for item in receipt["dependencies"]):
                raise ValueError("shared index is not bound to its producing receipt")
        if run_root not in candidate.parents or not candidate.is_file():
            raise ValueError(f"index is unavailable: {identity.name}")
        if verified_digest(run_root, candidate, identity.sha256) != identity.sha256:
            raise ValueError(f"index integrity mismatch: {identity.name}")
        if identity.relative_path.startswith("data/indices/"):
            from appsec_review.storage.shared import consume_named
            consume_named(run_root, candidate, namespace="index-shard", expected_sha256=identity.sha256)
        summary_key = ("shard", canonical_json({
            "identity": raw, "target_snapshot": document.get("target_snapshot"),
            "swift_enabled": swift_enabled,
        }).decode("utf-8"), identity.sha256)
        if validation is not None and summary_key in validation.records:
            cached_entities, cached_relations = validation.records[summary_key]
            entity_ids.update(cached_entities)
            relations.extend(cached_relations)
            continue
        count_work("shard_validations")
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
            # The catalog is the sole durable inventory exception. Every derived shard is checked
            # independently so a stale or externally presented Swift artifact fails closed.
            if not swift_enabled and identity.producer.get("job") != "job_target_catalog":
                if any(is_swift_path(str(row[0])) for row in database.execute("SELECT path FROM locations")):
                    raise ValueError(
                        f"index contains Swift-derived locations while tools.enable_swift=false: "
                        f"{identity.name}/{identity.shard_id}")
                for kind, payload_json in database.execute("SELECT kind, payload_json FROM entities"):
                    payload = json.loads(str(payload_json))
                    if kind == "coverage_cell" and swift_coverage_cell_is_gap(payload):
                        continue
                    reject_swift_derived(
                        payload, enabled=False,
                        context=f"index {identity.name}/{identity.shard_id}")
                for (payload_json,) in database.execute("SELECT payload_json FROM relations"):
                    reject_swift_derived(
                        json.loads(str(payload_json)), enabled=False,
                        context=f"index {identity.name}/{identity.shard_id}")
            shard_entities = frozenset(str(row[0]) for row in database.execute("SELECT identity FROM entities"))
            shard_relations = tuple((str(row[0]), str(row[1]), str(row[2]), identity.shard_id)
                                   for row in database.execute(
                                       "SELECT relation_id, source_id, target_id FROM relations"))
            entity_ids.update(shard_entities)
            relations.extend(shard_relations)
            if validation is not None:
                validation.records[summary_key] = (shard_entities, shard_relations)
    for relation_id, source_id, target_id, shard_id in relations:
        if source_id not in entity_ids or target_id not in entity_ids:
            raise ValueError(f"relation closure mismatch: {shard_id}/{relation_id}")
    verified[(resolved, actual)] = document
    if validation is not None:
        validation.records[manifest_key] = document
    return document, actual
