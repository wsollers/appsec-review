"""Indexed exact facets and unsigned interval lookup for immutable debug-symbol shards."""
from __future__ import annotations

import re
import sqlite3
from typing import Iterable

from appsec_review.debug_symbols.contract import AddressRange, RecordKind
from appsec_review.retrieval.model import EntityKind, EntityRecord, LogicalIdentity

_DIGEST = re.compile(r"[0-9a-f]{64}")
MAX_PREFIXES_PER_RECORD = 4096
MAX_LOOKUP_ROWS = 2_000_000
ARTIFACT_KINDS = frozenset({
    EntityKind.BUILD_ARTIFACT, EntityKind.EXECUTABLE, EntityKind.OBJECT_FILE,
    EntityKind.LIBRARY, EntityKind.EVIDENCE_ARTIFACT,
})


def address_prefixes(address: int) -> tuple[str, ...]:
    return tuple(f"{bits}:{address >> (64 - bits) << (64 - bits):016x}" for bits in range(65))


def interval_prefixes(start: int, end: int) -> Iterable[str]:
    """Canonical dyadic cover: at most 128 indexed blocks for a u64 interval.

    A point probes 65 exact keys, not every earlier start address in an artifact. Neither endpoints
    nor unsigned addresses are stored as SQLite signed integers.
    """
    AddressRange(start, end)
    while start < end:
        width = (end - start).bit_length() - 1
        if start:
            width = min(width, (start & -start).bit_length() - 1)
        yield f"{64 - width}:{start:016x}"
        start += 1 << width


def build_lookup(database: sqlite3.Connection, entities: list[EntityRecord]) -> None:
    # Individual statements: executescript() would implicitly commit the builder's transaction.
    for statement in (
        """CREATE TABLE debug_symbol_records(
            identity TEXT PRIMARY KEY, artifact_identity TEXT NOT NULL, record_kind TEXT NOT NULL,
            source_identity TEXT, native_key TEXT NOT NULL, parent_key TEXT
        ) WITHOUT ROWID""",
        "CREATE INDEX debug_symbol_artifact_kind ON debug_symbol_records(artifact_identity, record_kind, identity)",
        "CREATE INDEX debug_symbol_kind ON debug_symbol_records(record_kind, identity)",
        "CREATE INDEX debug_symbol_source ON debug_symbol_records(source_identity, record_kind, identity)",
        "CREATE UNIQUE INDEX debug_symbol_native ON debug_symbol_records(artifact_identity, native_key)",
        "CREATE INDEX debug_symbol_parent ON debug_symbol_records(artifact_identity, parent_key, record_kind, identity)",
        """CREATE TABLE debug_symbol_addresses(
            artifact_identity TEXT NOT NULL, prefix TEXT NOT NULL, identity TEXT NOT NULL,
            PRIMARY KEY(artifact_identity, prefix, identity)
        ) WITHOUT ROWID""",
    ):
        database.execute(statement)
    lookup_rows = 0
    for entity in entities:
        data = entity.payload
        kind = RecordKind(data.get("record_kind"))
        artifact = LogicalIdentity.parse(data.get("artifact_identity"))
        if artifact.kind not in ARTIFACT_KINDS:
            raise ValueError("debug-symbol artifact must be an accepted binary/debug artifact identity")
        for field in ("artifact_sha256", "debug_sha256"):
            if not isinstance(data.get(field), str) or not _DIGEST.fullmatch(data[field]):
                raise ValueError("debug-symbol records require artifact/debug SHA-256 digests")
        if data.get("compiler_target") not in {"clang", "msvc"}:
            raise ValueError("debug-symbol records require a closed compiler target")
        source = data.get("source_identity")
        if source is not None and LogicalIdentity.parse(source).kind not in {
            EntityKind.SOURCE_FILE, EntityKind.SOURCE_SPAN,
        }:
            raise ValueError("debug-symbol source must be a verified source identity")
        native, parent = data.get("native_key"), data.get("parent_key")
        if not isinstance(native, str) or not 1 <= len(native) <= 4096:
            raise ValueError("debug-symbol records require a bounded native_key")
        if parent is not None and (not isinstance(parent, str) or not 1 <= len(parent) <= 4096):
            raise ValueError("debug-symbol parent_key must be bounded")
        database.execute("INSERT INTO debug_symbol_records VALUES (?, ?, ?, ?, ?, ?)", (
            entity.identity.value, artifact.value, kind.value, source, native, parent))
        ranges = data.get("address_ranges", [])
        if not isinstance(ranges, (tuple, list)) or len(ranges) > 500:
            raise ValueError("debug-symbol address range count exceeds the normalized record bound")
        prefixes: set[str] = set()
        for interval in ranges:
            if not isinstance(interval, dict) or set(interval) != {"start", "end"}:
                raise ValueError("debug-symbol address range requires start/end only")
            prefixes.update(interval_prefixes(interval["start"], interval["end"]))
            if len(prefixes) > MAX_PREFIXES_PER_RECORD:
                raise ValueError("debug-symbol per-record address lookup expansion bound exceeded")
        lookup_rows += len(prefixes)
        if lookup_rows > MAX_LOOKUP_ROWS:
            raise ValueError("debug-symbol shard address lookup row bound exceeded")
        database.executemany("INSERT INTO debug_symbol_addresses VALUES (?, ?, ?)",
                             [(artifact.value, prefix, entity.identity.value) for prefix in sorted(prefixes)])
