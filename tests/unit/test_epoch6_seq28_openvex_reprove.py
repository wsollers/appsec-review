"""Regression tests for seq=28 OpenVEX cumulative-manifest and shared-receipt I/O deduplication."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pytest

from appsec_review.jobs.job_openvex_export import contracts as c
from appsec_review.jobs.job_openvex_export import inputs
from appsec_review.jobs.job_openvex_export.settings import OpenVexExportSettings
from appsec_review.retrieval.index import MANIFEST_SCHEMA
from appsec_review.storage import shared
from appsec_review.storage.validation import current_validation, validation_scope


def _settings() -> OpenVexExportSettings:
    return OpenVexExportSettings(enabled=True, timeout_seconds=120)


def test_bounded_input_reader_verify_deduplicates_unchanged_inodes_until_reprove(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_root = tmp_path / "run-seq28"
    shard_dir = run_root / "data" / "indexes"
    shard_dir.mkdir(parents=True)
    payload = b"DWARF-SHARD-" * 8192
    digest = hashlib.sha256(payload).hexdigest()
    shard_path = shard_dir / "symbols.sqlite"
    shard_path.write_bytes(payload)

    reader = inputs.BoundedInputReader(run_root, _settings())
    stream_reads = 0
    orig_read = inputs.BoundedInputReader._read

    def counting_read(self: inputs.BoundedInputReader, relative: str, expected: str | None, **kwargs: object):
        nonlocal stream_reads
        stream_reads += 1
        return orig_read(self, relative, expected, **kwargs)

    monkeypatch.setattr(inputs.BoundedInputReader, "_read", counting_read)

    ref = c.SizedArtifactRef("data/indexes/symbols.sqlite", digest, len(payload))
    for _ in range(10):
        reader.verify(ref)
    assert stream_reads == 1

    # Conflicting digest or declared size must still fail immediately on fast-path verify.
    with pytest.raises(c.ExportError) as exc_conflict:
        reader.verify(c.ArtifactRef("data/indexes/symbols.sqlite", "0" * 64))
    assert exc_conflict.value.reason == c.ExportFailureReason.IDENTITY_CONFLICT

    with pytest.raises(c.ExportError) as exc_size:
        reader.verify(c.SizedArtifactRef("data/indexes/symbols.sqlite", digest, len(payload) + 1))
    assert exc_size.value.reason == c.ExportFailureReason.INPUT_TAMPERED

    # reprove() must clear _verified_stamps and perform a fresh byte-stream hash.
    reader.reprove()
    assert stream_reads == 2

    # Same-size, same-mtime in-place byte tamper before reprove() must still be caught.
    before_stat = shard_path.stat()
    shard_path.write_bytes(b"TAMPERED----" * 8192)
    os.utime(shard_path, ns=(before_stat.st_atime_ns, before_stat.st_mtime_ns))
    with pytest.raises(c.ExportError) as exc_tamper:
        reader.reprove()
    assert exc_tamper.value.reason == c.ExportFailureReason.INPUT_TAMPERED


def test_seeded_inventory_is_not_marked_stream_verified_before_explicit_verify(
    tmp_path: Path,
) -> None:
    run_root = tmp_path / "run-seeded"
    (run_root / "data").mkdir(parents=True)
    good = b"good-bytes"
    digest = hashlib.sha256(good).hexdigest()
    target = run_root / "data" / "item.bin"
    target.write_bytes(b"bad!-bytes")

    seeded = c.SizedArtifactRef("data/item.bin", digest, len(good))
    reader = inputs.BoundedInputReader(run_root, _settings(), seed_inventory=(seeded,))
    with pytest.raises(c.ExportError) as exc_info:
        reader.verify(seeded)
    assert exc_info.value.reason == c.ExportFailureReason.INPUT_TAMPERED


def test_manifest_caches_verified_upstream_submanifests_across_distinct_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_root = tmp_path / "2026-11-25-0003"
    (run_root / "data" / "indexes").mkdir(parents=True)
    (run_root / "data" / "manifests").mkdir(parents=True)
    snapshot = "a" * 64

    shard_bytes = b"index-shard-bytes" * 1024
    shard_sha = hashlib.sha256(shard_bytes).hexdigest()
    (run_root / "data" / "indexes" / "graph.sqlite").write_bytes(shard_bytes)

    def write_manifest(name: str, upstream: list[dict[str, object]]) -> c.SizedArtifactRef:
        doc = {
            "schema": MANIFEST_SCHEMA,
            "run_id": run_root.name,
            "target_snapshot": snapshot,
            "indexes": [{"name": "graph", "shard_id": "default",
                         "relative_path": "data/indexes/graph.sqlite", "sha256": shard_sha}],
            "upstream_manifests": upstream,
        }
        raw = c.canonical_bytes(doc)
        rel = f"data/manifests/{name}.json"
        (run_root / rel).write_bytes(raw)
        return c.SizedArtifactRef(rel, hashlib.sha256(raw).hexdigest(), len(raw))

    m1 = write_manifest("m1", [])
    m2 = write_manifest("m2", [m1.to_json()])
    root_a = write_manifest("root_a", [m2.to_json()])
    root_b = write_manifest("root_b", [m2.to_json()])

    monkeypatch.setattr(
        inputs, "load_verified_manifest",
        lambda root, path, expected: (json.loads(path.read_bytes()), expected),
    )

    json_reads: list[str] = []
    orig_json = inputs.BoundedInputReader.json

    def spy_json(self: inputs.BoundedInputReader, ref: c.ArtifactRef, **kwargs: object):
        json_reads.append(ref.path)
        return orig_json(self, ref, **kwargs)

    monkeypatch.setattr(inputs.BoundedInputReader, "json", spy_json)
    reader = inputs.BoundedInputReader(run_root, _settings())
    inputs._manifest(reader, root_a.reference, run_root.name, snapshot)
    inputs._manifest(reader, root_b.reference, run_root.name, snapshot)

    assert json_reads.count(m1.path) == 1
    assert json_reads.count(m2.path) == 1


def test_immutable_bytes_skips_temp_fsync_when_identical_file_already_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_root = tmp_path / "run-shared"
    run_root.mkdir()
    fsync_calls = 0
    orig_fsync = shared.timed_fsync

    def counting_fsync(fd: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        orig_fsync(fd)

    monkeypatch.setattr(shared, "timed_fsync", counting_fsync)
    payload = b'{"schema":"receipt-test"}\n'
    with validation_scope(run_root):
        ref1 = shared.immutable_bytes(run_root, "data/shared/receipts/r1.json", payload)
        assert fsync_calls == 1
        ref2 = shared.immutable_bytes(run_root, "data/shared/receipts/r1.json", payload)
        assert fsync_calls == 1
        assert ref1 == ref2
        assert current_validation(run_root) is not None

        with pytest.raises(ValueError, match="immutable shared artifact conflicts"):
            shared.immutable_bytes(run_root, "data/shared/receipts/r1.json", b"different")
