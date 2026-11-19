"""job_artifact_indexing: restart-safe shard completion. A completed shard is reused only after
its metadata and integrity verify; concurrent builders of one shard serialize on the shard lock and
agree on one digest; a tampered or foreign shard stops the job."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import time
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_artifact_indexing import job as job_module
from appsec_review.jobs.job_artifact_indexing.job import (
    ArtifactIndexIntegrityError, _acquire_shard_lock, _finish_shard, _index_identity, _shard_path, _verify_shard,
    _member_rows, _ReceiptContext, _write_batches,
)
from appsec_review.retrieval import INDEX_SCHEMA, IndexBuilder
from appsec_review.storage import FileLock, LockUnavailable, file_sha256
from tests.unit.job_artifact_indexing.support import (
    SETTINGS, SNAPSHOT, assert_published_gaps, loaded_output, unit_context, validated_artifact, validated_receipt,
)


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
    identity, reused = _index_identity(unit, _builder(path, shard_id="members-unit-0000"),
                                       ["a: gap", "b: gap", "a: gap"], "members", {"build_unit_id": "unit", "batch": 0})
    fingerprint = identity["fingerprint"]
    assert fingerprint != "f" * 64
    path = tmp_path / identity["relative_path"]
    assert reused is False
    assert identity == {"name": "artifacts", "schema": INDEX_SCHEMA, "sha256": file_sha256(path), "fingerprint": fingerprint,
                        "relative_path": f"data/indices/artifacts/{fingerprint}.sqlite",
                        "producer": {"job": "job_artifact_indexing", "unit": "index.members", "family": "members",
                                     "build_unit_id": "unit", "batch": 0},
                        "gaps": ("a: gap", "b: gap"), "shard_id": "members-unit-0000"}
    assert _verify_shard(path, name="artifacts", fingerprint=fingerprint,
                         shard_id=identity["shard_id"], target_snapshot=SNAPSHOT) == identity["sha256"]
    assert_published_gaps(tmp_path, unit.unit_id, identity["gaps"], ["a: gap", "b: gap"])


def test_verify_shard_rejects_integrity_check_failure_even_with_matching_metadata(tmp_path: Path) -> None:
    path = tmp_path / "shard.sqlite"
    _builder(path).build()
    with sqlite3.connect(path) as database:
        database.execute("PRAGMA journal_mode=DELETE")
        database.execute("CREATE TABLE broken (value INTEGER)")
        database.execute("CREATE INDEX broken_lookup ON broken(value)")
        database.execute("INSERT INTO broken VALUES (3)")
        database.execute("PRAGMA writable_schema=ON")
        database.execute("UPDATE sqlite_master SET sql='CREATE INDEX broken_lookup ON broken(value+1)' "
                         "WHERE name='broken_lookup'")
    database.close()
    with pytest.raises(ArtifactIndexIntegrityError, match="completed artifact shard is corrupt"):
        _verify_shard(path, name="artifacts", fingerprint="f" * 64,
                      shard_id="catalog-unit-object_file", target_snapshot=SNAPSHOT)


@pytest.mark.parametrize("expired", [False, True], ids=["retry", "deadline"])
def test_finish_shard_retries_builder_lock_contention_and_releases_its_own_lock(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, expired: bool) -> None:
    path = tmp_path / "shard.sqlite"
    calls = []

    def build():
        calls.append("build")
        if calls.count("build") == 1:
            raise LockUnavailable("inner publication lock")
        return "d" * 64

    clock = iter([0.0, 30.0 if expired else 1.0])
    monkeypatch.setattr(job_module.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(job_module.time, "sleep", lambda seconds: calls.append(seconds))
    builder = SimpleNamespace(build=build)
    if expired:
        with pytest.raises(LockUnavailable, match="inner publication lock"):
            _finish_shard(builder, path)
        assert calls == ["build"]
    else:
        assert _finish_shard(builder, path) == ("d" * 64, False)
        assert calls == ["build", 0.01, "build"]
    with FileLock(path.with_suffix(".sqlite.lock")):
        assert not path.exists()


def test_write_batches_persists_entities_relations_coverage_and_reuse_counts(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(job_module, "MAX_ARTIFACTS_PER_SHARD", 1)
    receipt = validated_receipt(0)
    receipt["validated_artifacts"] = [validated_artifact(f"{name}.whl", "wheel", name) for name in ("a", "b")]
    context = _ReceiptContext.build(receipt, SNAPSHOT)
    unit = unit_context(tmp_path, "index.members")
    rows = [
        _member_rows(unit, receipt["validated_artifacts"][0], [{"member": "a.py", "size_bytes": 1}]),
        _member_rows(unit, receipt["validated_artifacts"][1], []),
    ]
    kwargs = {"prefix": "members", "family": "members",
              "extractor_identity": SETTINGS["member_extractor_identity"],
              "parser_identity": SETTINGS["member_parser_identity"]}
    indexes, reused = _write_batches(unit, context, rows=iter(rows), **kwargs)
    assert reused == 0 and len(indexes) == 2
    for ordinal, index in enumerate(indexes):
        assert index["producer"] == {
            "job": "job_artifact_indexing", "unit": "index.members", "family": "members",
            "build_unit_id": "build-unit-scale", "batch": ordinal, "batch_count": 2,
        }
        with sqlite3.connect(tmp_path / index["relative_path"]) as database:
            assert database.execute("SELECT COUNT(*) FROM entities").fetchone()[0] == 1 - ordinal
            assert database.execute("SELECT COUNT(*) FROM relations").fetchone()[0] == 1 - ordinal
            assert database.execute("SELECT area, status, gap FROM coverage").fetchall() == [
                ("a.whl", "complete", None) if ordinal == 0 else
                ("b.whl", "partial", "b.whl: archive member manifest unavailable"),
            ]
    assert indexes[0]["gaps"] == ()
    assert_published_gaps(tmp_path, unit.unit_id, indexes[1]["gaps"], ["b.whl: archive member manifest unavailable"])
    again, reused = _write_batches(unit, context, rows=iter(rows), **kwargs)
    assert reused == 2 and again == indexes
    assert _write_batches(unit, context, rows=iter(()), **kwargs) == ([], 0)


@pytest.mark.parametrize("branch", ["members", "relationships"])
def test_earlier_batch_insertion_and_removal_preserve_existing_shards(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, branch: str) -> None:
    monkeypatch.setattr(job_module, "MAX_ARTIFACTS_PER_SHARD", 1)
    receipt = validated_receipt(0)
    receipt["validated_artifacts"] = [validated_artifact("z.whl", "wheel", "z")]
    receipt["package_members"] = [{"package_path": "z.whl", "member": "z.py", "size_bytes": 1}]
    unit = unit_context(tmp_path, f"index.{branch}", {
        "load.accepted_builds": loaded_output([receipt]),
    })
    handler = getattr(job_module, f"_{branch}")
    first = handler(unit)
    original, = first["indexes"]
    old_bytes = (tmp_path / original["relative_path"]).read_bytes()
    receipt["validated_artifacts"].insert(0, validated_artifact("a.whl", "wheel", "a"))
    receipt["package_members"].append({"package_path": "a.whl", "member": "a.py", "size_bytes": 1})
    inserted = handler(unit)
    assert inserted["shard_count"] == 2 and inserted["reused_count"] == 0
    assert inserted["indexes"][1]["shard_id"].endswith("-0001")
    assert inserted["indexes"][1]["relative_path"] != original["relative_path"]
    assert (tmp_path / original["relative_path"]).read_bytes() == old_bytes
    assert handler(unit)["reused_count"] == 2
    receipt["validated_artifacts"].pop(0)
    restored = handler(unit)
    assert restored["reused_count"] == 1 and restored["indexes"] == first["indexes"]
    receipt["validated_artifacts"].append(validated_artifact("zz.whl", "wheel", "zz"))
    receipt["package_members"].append({"package_path": "zz.whl", "member": "zz.py", "size_bytes": 1})
    appended = handler(unit)
    assert appended["shard_count"] == 2 and appended["reused_count"] == 1
    for key in ("shard_id", "fingerprint", "relative_path", "sha256"):
        assert appended["indexes"][0][key] == original[key]


@pytest.mark.parametrize("change", ["status", "reason", "gap"])
def test_content_identity_binds_coverage_and_all_published_gap_reasons(tmp_path: Path, change: str) -> None:
    unit = unit_context(tmp_path, "index.members")

    def publish(status: str, reason: str, gaps: list[str]):
        builder = IndexBuilder(tmp_path / "unused.sqlite", name="artifacts", fingerprint="f" * 64,
                               target_snapshot=SNAPSHOT, shard_id="members-unit-0000")
        builder.add_coverage("sample.whl", status, reason)
        return _index_identity(unit, builder, gaps, "members")

    first, reused = publish("partial", "manifest absent", ["manifest absent"])
    assert not reused
    old_bytes = (tmp_path / first["relative_path"]).read_bytes()
    status = "unavailable" if change == "status" else "partial"
    reason = "manifest unreadable" if change == "reason" else "manifest absent"
    gaps = ["manifest absent", "identity unresolved"] if change == "gap" else ["manifest absent"]
    second, reused = publish(status, reason, gaps)
    assert not reused and first["fingerprint"] != second["fingerprint"]
    with sqlite3.connect(tmp_path / second["relative_path"]) as database:
        assert database.execute("SELECT status, gap FROM coverage").fetchall() == [(status, reason)]
    assert list(second["gaps"]) == gaps
    assert (tmp_path / first["relative_path"]).read_bytes() == old_bytes
    assert publish(status, reason, gaps) == (second, True)
