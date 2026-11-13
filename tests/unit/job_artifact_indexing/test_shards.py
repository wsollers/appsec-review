"""job_artifact_indexing: restart-safe shard completion. A completed shard is reused only after
its metadata and integrity verify; concurrent builders of one shard serialize on the shard lock and
agree on one digest; a tampered or foreign shard stops the job."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import time

import pytest

from appsec_review.jobs.job_artifact_indexing.job import (
    ArtifactIndexIntegrityError, _acquire_shard_lock, _finish_shard, _index_identity, _shard_path, _verify_shard,
)
from appsec_review.retrieval import INDEX_SCHEMA, IndexBuilder
from appsec_review.storage import FileLock, LockUnavailable, file_sha256
from tests.unit.job_artifact_indexing.support import SNAPSHOT, unit_context


def _builder(path: Path, fingerprint: str = "f" * 64, shard_id: str = "catalog-unit-object_file") -> IndexBuilder:
    builder = IndexBuilder(path, name="artifacts", fingerprint=fingerprint, target_snapshot=SNAPSHOT, shard_id=shard_id)
    builder.add_coverage("unit:object_file", "complete")
    return builder


def test_a_shard_is_built_once_then_reused_with_the_same_digest(tmp_path: Path) -> None:
    path = tmp_path / "data/indices/artifacts/shard.sqlite"
    digest, reused = _finish_shard(_builder(path), path)
    assert reused is False and digest == file_sha256(path)
    assert _finish_shard(_builder(path), path) == (digest, True)
    assert not path.with_suffix(".sqlite.lock").exists() or path.with_suffix(".sqlite.lock").stat().st_size == 1


def test_concurrent_builders_of_one_shard_serialize_and_agree_on_one_digest(tmp_path: Path) -> None:
    path = tmp_path / "data/indices/artifacts/concurrent.sqlite"
    builders = [_builder(path, shard_id="concurrent") for _ in range(2)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda builder: _finish_shard(builder, path), builders))
    assert sorted(reused for _sha, reused in outcomes) == [False, True]
    assert len({sha for sha, _reused in outcomes}) == 1


def test_verify_shard_accepts_matching_metadata_and_names_changed_or_corrupt_shards(tmp_path: Path) -> None:
    path = tmp_path / "shard.sqlite"
    _builder(path).build()
    expected = dict(name="artifacts", fingerprint="f" * 64, shard_id="catalog-unit-object_file", target_snapshot=SNAPSHOT)
    assert _verify_shard(path, **expected) == file_sha256(path)
    for change in ({"fingerprint": "0" * 64}, {"shard_id": "other"}, {"target_snapshot": "other"}, {"name": "build"}):
        with pytest.raises(ArtifactIndexIntegrityError, match="shard metadata changed"):
            _verify_shard(path, **{**expected, **change})
    path.write_bytes(b"corrupt")
    with pytest.raises(ArtifactIndexIntegrityError, match="shard is corrupt"):
        _verify_shard(path, **expected)


def test_a_completed_shard_with_foreign_metadata_stops_the_rerun_instead_of_being_reused(tmp_path: Path) -> None:
    path = tmp_path / "data/indices/artifacts/shard.sqlite"
    _finish_shard(_builder(path), path)
    with pytest.raises(ArtifactIndexIntegrityError, match="shard metadata changed"):
        _finish_shard(_builder(path, fingerprint="0" * 64), path)
    path.write_bytes(b"corrupt")
    with pytest.raises(ArtifactIndexIntegrityError, match="shard is corrupt"):
        _finish_shard(_builder(path), path)


def test_the_shard_lock_is_waited_for_until_the_deadline_then_refused(tmp_path: Path) -> None:
    lock = tmp_path / "shard.sqlite.lock"
    with FileLock(lock):
        started = time.monotonic()
        with pytest.raises(LockUnavailable):
            _acquire_shard_lock(lock, time.monotonic() + 0.05)
        assert time.monotonic() - started >= 0.05
    held = _acquire_shard_lock(lock, time.monotonic() + 1)
    held.__exit__(None, None, None)


def test_index_identity_records_the_shard_its_producer_and_deduplicated_gaps(tmp_path: Path) -> None:
    unit = unit_context(tmp_path, "index.members")
    path = _shard_path(unit, "f" * 64, "members-unit-0000")
    assert path == tmp_path / "data/indices/artifacts" / ("f" * 64 + ".sqlite")
    identity, reused = _index_identity(unit, _builder(path, shard_id="members-unit-0000"), path,
                                       ["a: gap", "b: gap", "a: gap"], "members", {"build_unit_id": "unit", "batch": 0})
    assert reused is False
    assert identity == {"name": "artifacts", "schema": INDEX_SCHEMA, "sha256": file_sha256(path), "fingerprint": "f" * 64,
                        "relative_path": "data/indices/artifacts/" + "f" * 64 + ".sqlite",
                        "producer": {"job": "job_artifact_indexing", "unit": "index.members", "family": "members",
                                     "build_unit_id": "unit", "batch": 0},
                        "gaps": ("a: gap", "b: gap"), "shard_id": "members-unit-0000"}
