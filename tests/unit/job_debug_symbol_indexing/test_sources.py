"""``_Sources`` loads the accepted source inventory from the run's own index shards and resolves
reader checksums against those bytes: never a recorded path, never a file outside the run."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from appsec_review.debug_symbols.contract import SourceSpan
from appsec_review.jobs.job_debug_symbol_indexing.job import _Sources
from appsec_review.retrieval import EntityKind, EntityRecord, INDEX_SCHEMA, IndexBuilder, IndexIdentity, LogicalIdentity
from appsec_review.retrieval.model import SourceLocation
from tests.unit.job_debug_symbol_indexing.support import SNAPSHOT, job_context, manifest, source_shard, unit

CONTENT = b"int main() {\n  return 0;\n}\n"


def _sources(tmp_path, shards, *, max_input_bytes=4096, max_records=100):
    context = job_context(tmp_path)
    upstream = manifest(context.run_root, shards)
    decision = {"upstream_manifest": upstream,
                "settings": {"reader": {"max_input_bytes": max_input_bytes, "max_records": max_records}}}
    return _Sources(unit(context, "extract.clang_dwarf"), decision), context


def test_sources_index_the_accepted_inventory_by_path_and_checksum(tmp_path: Path) -> None:
    shard = source_shard(tmp_path / "2026-11-13-0001", CONTENT)
    sources, _ = _sources(tmp_path, [shard])
    digest = hashlib.sha256(CONTENT).hexdigest()
    (row,) = sources.rows
    assert (row["path"], row["sha256"]) == ("src/main.cc", digest)
    assert sources.by_path == {"src/main.cc": [row]} and sources.by_sha256 == {digest: [row]}
    assert sources.maximum == 4096 and sources.limit == 100
    result, gap = sources.resolve(SourceSpan("/private/checkout/src/main.cc", 2, 3, digest, "sha256"))
    assert gap is None and (result["start_byte"], result["end_byte"]) == (13, 25)


def test_the_byte_bound_is_capped_at_sixteen_megabytes(tmp_path: Path) -> None:
    sources, _ = _sources(tmp_path, [], max_input_bytes=10 ** 12)
    assert sources.maximum == 16 * 1024 * 1024 and sources.rows == []


def test_inventory_rows_whose_identity_does_not_derive_from_their_path_and_hash_are_ignored(tmp_path: Path) -> None:
    run_root = tmp_path / "2026-11-13-0001"
    run_root.mkdir()
    digest = hashlib.sha256(CONTENT).hexdigest()
    path = run_root / "data" / "indices" / "source" / "forged.sqlite"
    builder = IndexBuilder(path, name="source", fingerprint="b" * 64, target_snapshot=SNAPSHOT, shard_id="catalog-forged")
    forged = LogicalIdentity.derive(EntityKind.SOURCE_FILE, SNAPSHOT, {"path": "other.cc", "sha256": digest})
    location = SourceLocation(SNAPSHOT, "src/main.cc", digest, 0, len(CONTENT), 1, 3, 1, 1, {}, "inventory-exact", 1.0)
    builder.add_entity(EntityRecord(forged, "src/main.cc", "main.cc", CONTENT.decode(), {"path": "src/main.cc"}, location))
    builder.add_coverage("fixture", "complete")
    shard = IndexIdentity("source", INDEX_SCHEMA, builder.build(), "b" * 64, path.relative_to(run_root).as_posix(),
                          {}, (), "catalog-forged")
    sources, _ = _sources(tmp_path, [shard])
    assert sources.rows == []
    assert sources.resolve(SourceSpan("src/main.cc", 1, 0, digest, "sha256")) == (None, "source_checksum_unverified")


def test_the_record_limit_bounds_the_inventory_read(tmp_path: Path) -> None:
    run_root = tmp_path / "2026-11-13-0001"
    shards = [source_shard(run_root, f"int v{index};\n".encode(), path=f"src/{index}.cc") for index in range(3)]
    sources, _ = _sources(tmp_path, shards, max_records=2)
    assert len(sources.rows) == 2


def test_source_bytes_come_from_the_shared_object_store_then_hash_verified_sqlite_text(tmp_path: Path) -> None:
    run_root = tmp_path / "2026-11-13-0001"
    stored = source_shard(run_root, CONTENT, path="a.cc")
    text_only = source_shard(run_root, b"int x;\n", path="b.cc", store_object=False)
    sources, _ = _sources(tmp_path, [stored, text_only])
    a, b = sorted(sources.rows, key=lambda row: row["path"])
    assert sources._bytes(a) == CONTENT and sources._bytes(b) == b"int x;\n"
    assert set(sources.cache) == {a["sha256"], b["sha256"]}, "small files are cached by digest"


def test_changed_or_oversized_source_bytes_are_refused(tmp_path: Path) -> None:
    run_root = tmp_path / "2026-11-13-0001"
    shard = source_shard(run_root, CONTENT)
    sources, context = _sources(tmp_path, [shard], max_input_bytes=16)
    (row,) = sources.rows
    with pytest.raises(ValueError, match="exceeds byte limit"):
        sources._bytes(row)
    sources, context = _sources(tmp_path / "second", [source_shard(tmp_path / "second" / "2026-11-13-0001", CONTENT)])
    (row,) = sources.rows
    (context.run_root / "data" / "shared" / "objects" / row["sha256"]).write_bytes(b"changed")
    with pytest.raises(ValueError, match="unavailable or changed"):
        sources._bytes(row)
    assert sources.resolve(SourceSpan("src/main.cc", 1, 0, row["sha256"], "sha256")) == (None, "source_checksum_unverified")


def test_resolution_matches_recorded_path_suffixes_against_the_inventory(tmp_path: Path) -> None:
    run_root = tmp_path / "2026-11-13-0001"
    sources, _ = _sources(tmp_path, [source_shard(run_root, CONTENT, path="lib/src/main.cc")])
    digest = hashlib.sha256(CONTENT).hexdigest()
    md5 = hashlib.md5(CONTENT).hexdigest()
    for recorded in ("C:\\build\\lib\\src\\main.cc", "/work/lib/src/main.cc", "lib/src/main.cc"):
        result, gap = sources.resolve(SourceSpan(recorded, 1, 0, md5, "MD5"))
        assert gap is None and result["path"] == "lib/src/main.cc", recorded
    for recorded in ("src/main.cc", "main.cc", "unrelated.cc"):
        assert sources.resolve(SourceSpan(recorded, 1, 0, md5, "md5")) == (None, "source_checksum_unverified"), \
            "an md5 match needs the recorded name to end with the accepted path"
    result, gap = sources.resolve(SourceSpan("unrelated.cc", 1, 0, digest, "sha256"))
    assert gap is None and result["path"] == "lib/src/main.cc", "a sha256 match needs no path agreement"


def test_column_beyond_the_line_is_not_a_match(tmp_path: Path) -> None:
    run_root = tmp_path / "2026-11-13-0001"
    sources, _ = _sources(tmp_path, [source_shard(run_root, b"ab\ncd\n")])
    digest = hashlib.sha256(b"ab\ncd\n").hexdigest()
    assert sources.resolve(SourceSpan("src/main.cc", 1, 3, digest, "sha256"))[1] is None
    assert sources.resolve(SourceSpan("src/main.cc", 1, 4, digest, "sha256")) == (None, "source_checksum_unverified")
