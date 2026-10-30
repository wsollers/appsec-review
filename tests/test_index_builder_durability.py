"""IndexBuilder durability: one durability point, one content hash, adoption without copying."""
from __future__ import annotations

import errno
import os
from pathlib import Path
import random
import sqlite3

import pytest

from appsec_review.observability import EventLog
from appsec_review.observability.spans import operation_span
from appsec_review.retrieval import (
    INDEX_SCHEMA,
    EntityKind,
    EntityRecord,
    IndexBuilder,
    LogicalIdentity,
    RelationKind,
    RelationRecord,
)
from appsec_review.retrieval import index as index_module
from appsec_review.storage import file_sha256, shared
from appsec_review.storage.shared import verify_receipt
from tests.test_shared_artifacts import actor


SNAPSHOT = "snapshot"


def _records(count: int = 6) -> tuple[list[EntityRecord], list[RelationRecord]]:
    entities = [EntityRecord(LogicalIdentity.derive(EntityKind.OBJECT_FILE, SNAPSHOT, {"n": index}),
                             f"obj-{index}", f"obj-{index}.o", f"object {index}", {"index": index})
                for index in range(count)]
    relations = [RelationRecord(RelationKind.LINKS_INTO, entities[index].identity.value,
                                entities[index + 1].identity.value, True, 1.0)
                 for index in range(count - 1)]
    return entities, relations


def _builder(path: Path, entities, relations, *, shard_id: str = "durability") -> IndexBuilder:
    builder = IndexBuilder(path, name="artifacts", fingerprint="f" * 64, target_snapshot=SNAPSHOT,
                           shard_id=shard_id)
    for entity in entities:
        builder.add_entity(entity)
    for relation in relations:
        builder.add_relation(relation)
    builder.add_coverage("durability", "complete")
    return builder


@pytest.fixture
def statements(monkeypatch):
    seen: list[str] = []
    connect = sqlite3.connect

    def traced(*args, **kwargs):
        database = connect(*args, **kwargs)
        database.set_trace_callback(seen.append)
        return database

    monkeypatch.setattr(index_module.sqlite3, "connect", traced)
    return seen


@pytest.fixture
def fsyncs(monkeypatch):
    calls: list[int] = []
    real = os.fsync

    def counted(descriptor):
        calls.append(descriptor)
        return real(descriptor)

    monkeypatch.setattr(os, "fsync", counted)
    return calls


def test_build_writes_without_journal_sync_or_vacuum_and_keeps_contents(tmp_path, statements) -> None:
    entities, relations = _records()
    path = tmp_path / "shard.sqlite"

    digest = _builder(path, entities, relations).build()

    executed = [statement.strip().upper() for statement in statements]
    assert not any(statement.startswith("VACUUM") for statement in executed)
    for pragma in ("PRAGMA JOURNAL_MODE=OFF", "PRAGMA SYNCHRONOUS=OFF", "PRAGMA LOCKING_MODE=EXCLUSIVE"):
        assert pragma in executed
    assert executed.count("BEGIN") == 1 and executed.count("COMMIT") == 1
    assert digest == file_sha256(path)
    uri = f"file:{path.resolve().as_posix()}?mode=ro&immutable=1"
    with sqlite3.connect(uri, uri=True) as database:
        assert database.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        metadata = dict(database.execute("SELECT key, value FROM metadata"))
        assert {key: metadata[key] for key in ("schema", "name", "fingerprint", "shard_id",
                                               "target_snapshot")} == {
            "schema": INDEX_SCHEMA, "name": "artifacts", "fingerprint": "f" * 64,
            "shard_id": "durability", "target_snapshot": SNAPSHOT}
        assert database.execute("SELECT count(*) FROM entities").fetchone()[0] == len(entities)
        assert database.execute("SELECT count(*) FROM relations").fetchone()[0] == len(relations)
        indexes = {row[0] for row in database.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL")}
        assert {"relations_source", "relations_target"} <= indexes
        assert database.execute("SELECT count(*) FROM search_fts WHERE search_fts MATCH 'obj'").fetchone()[0]


def test_equal_inputs_in_any_order_give_identical_bytes(tmp_path) -> None:
    entities, relations = _records(40)
    first = _builder(tmp_path / "a" / "shard.sqlite", entities, relations).build()
    shuffled_entities, shuffled_relations = list(entities), list(relations)
    random.Random(7).shuffle(shuffled_entities)
    random.Random(11).shuffle(shuffled_relations)
    second = _builder(tmp_path / "b" / "shard.sqlite", shuffled_entities, shuffled_relations).build()
    assert first == second


def test_build_without_attempt_owner_fsyncs_once_and_records_no_custody(tmp_path, fsyncs) -> None:
    assert shared.current() is None
    path = tmp_path / "data" / "indices" / "artifacts" / "shard.sqlite"

    digest = _builder(path, *_records()).build()

    assert len(fsyncs) == 1
    assert digest == file_sha256(path)
    assert path.stat().st_nlink == 1
    assert not (tmp_path / "data" / "shared").exists()


def test_custody_build_adopts_without_copy_and_bounds_fsync_and_hashing(tmp_path, fsyncs) -> None:
    run = tmp_path / "runs" / "durability-run"
    owner = actor(run, 1)
    path = run / "data" / "indices" / "artifacts" / "shard.sqlite"
    events = EventLog(tmp_path / "probe-events.jsonl")
    fsyncs.clear()  # Exclude the fixture's claim.json write.

    with shared.publication_scope_for_owner(owner), operation_span(events, "test.index_build") as span:
        digest = _builder(path, *_records()).build()

    assert len(fsyncs) <= 4
    assert span.counters.get("copy_objects", 0) == 0
    assert span.counters.get("custody_alias_objects") == 1
    assert span.counters.get("target_hash_objects", 0) <= 2
    obj = run / "data" / "shared" / "objects" / digest
    assert obj.is_file() and os.path.samefile(obj, path)
    assert path.stat().st_nlink == 2  # Content-store object and named path; no temporary link.
    assert file_sha256(path) == digest
    receipts = list((owner.attempt_root / "shared" / "index-shard").glob("*.json"))
    assert len(receipts) == 1
    value = verify_receipt(run, shared.reference(run, receipts[0]))
    assert value["object"]["sha256"] == digest and value["mode"] == "computed"
    assert value["computation"]["shard_id"] == "durability"


def test_custody_build_copies_when_hard_link_crosses_filesystems(tmp_path, monkeypatch) -> None:
    run = tmp_path / "runs" / "durability-run"
    owner = actor(run, 1)
    path = run / "data" / "indices" / "artifacts" / "shard.sqlite"
    events = EventLog(tmp_path / "probe-events.jsonl")
    link = os.link

    def cross_device(source, destination, *args, **kwargs):
        if Path(source).parent.name.startswith(".building-"):
            raise OSError(errno.EXDEV, "cross-device link")
        return link(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, "link", cross_device)
    with shared.publication_scope_for_owner(owner), operation_span(events, "test.index_build") as span:
        digest = _builder(path, *_records()).build()

    assert span.counters.get("copy_objects") == 1
    assert span.counters.get("custody_alias_objects", 0) == 0
    assert file_sha256(run / "data" / "shared" / "objects" / digest) == digest == file_sha256(path)


def test_concurrent_equal_builders_converge_and_conflicting_bytes_fail(tmp_path) -> None:
    run = tmp_path / "runs" / "durability-run"
    owner = actor(run, 1)
    path = run / "data" / "indices" / "artifacts" / "shard.sqlite"
    entities, relations = _records()
    with shared.publication_scope_for_owner(owner):
        first = _builder(path, entities, relations).build()
        assert _builder(path, entities, relations).build() == first
        with pytest.raises(ValueError, match="conflicts with existing bytes"):
            _builder(path, entities[:-1], relations[:-1]).build()
    assert file_sha256(path) == first


def test_adopt_private_file_rejects_a_different_existing_object(tmp_path) -> None:
    root = tmp_path / "runs" / "adopt-run"
    root.mkdir(parents=True)
    source = root / "private.bin"
    source.write_bytes(b"private-bytes")
    digest = file_sha256(source)
    obj = root / "data" / "shared" / "objects" / digest
    obj.parent.mkdir(parents=True)
    obj.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="conflicts"):
        shared.adopt_private_file(root, source, digest)
