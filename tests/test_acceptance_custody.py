from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import stat
import time

import pytest

from appsec_review.acceptance import custody
from appsec_review.acceptance.staging import SeedInputs, StageContext, StageKind


def seed(tmp_path: Path) -> tuple[StageContext, StageContext]:
    root = tmp_path.resolve()
    producer = StageContext(
        StageKind.PRODUCER, "micro", "prepare", "acceptance-micro", "1" * 40,
        {"micro-source": "2" * 64}, root, root / "stages" / "micro")
    producer.work_root.mkdir(parents=True)
    for name in ("target", "runs/unchanged-run-id/data/configuration", "runs/unchanged-run-id/output", "empty"):
        (producer.work_root / name).mkdir(parents=True)
    (producer.work_root / "target/source.py").write_bytes(b"source = 1\r\n")
    (producer.work_root / "appsec-review.toml").write_text(
        f'target = "{producer.work_root / "target"}"\n', encoding="utf-8")
    (producer.work_root / "overlay.toml").write_bytes(b"[micro]\nvalue = 1\n")
    (producer.work_root / "fixture-state.json").write_bytes(b'{"micro":true}\n')
    (producer.work_root / "runs/unchanged-run-id/data/configuration/frozen.json").write_bytes(b'{"frozen":1}\n')
    (producer.work_root / "runs/unchanged-run-id/output/evidence.txt").write_bytes(b"micro evidence only\r\n")
    (producer.work_root / "custody-input.json").write_text(json.dumps(SeedInputs("micro", (
        "target", "appsec-review.toml", "overlay.toml", "fixture-state.json",
        "runs/unchanged-run-id/data/configuration")).record()), encoding="utf-8")
    manifest_path = root / "custody/sealed.json"
    digest = custody.seal_seed(producer, manifest_path)
    consumer = replace(
        producer, kind=StageKind.CONSUMER, obligation_id="consume", work_root=root / "consumers/micro",
        seed_root=producer.work_root, manifest_path=manifest_path, manifest_sha256=digest)
    return producer, consumer


def test_fresh_copy_preserves_every_byte_empty_directory_and_original_absolute_references(tmp_path: Path) -> None:
    producer, consumer = seed(tmp_path)
    verified = custody.verify_seed(consumer)
    copied = custody.materialize_seed(consumer)
    assert copied == consumer.work_root
    assert custody.snapshot_tree(copied) == verified["tree"]
    assert (copied / "target/source.py").read_bytes() == b"source = 1\r\n"
    assert str(producer.work_root / "target") in (copied / "appsec-review.toml").read_text(encoding="utf-8")
    assert (copied / "runs/unchanged-run-id").is_dir()
    receipt = custody.copy_receipt_path(copied)
    assert not receipt.is_relative_to(copied)
    record = json.loads(receipt.read_bytes())
    assert record["verified"] and record["copied_bytes"] == verified["tree"]["total_bytes"]
    assert record["manifest_sha256"] == consumer.manifest_sha256
    with pytest.raises(custody.CustodyError, match="destination_exists"):
        custody.materialize_seed(consumer)


def test_each_tamper_vector_starts_from_an_independently_verified_private_copy(tmp_path: Path) -> None:
    producer, consumer = seed(tmp_path)
    custody.materialize_seed(consumer)
    first = custody.materialize_seed(consumer, consumer.work_root / "vectors/first")
    (first / "target/source.py").write_bytes(b"source = 2\r\n")
    second = custody.materialize_seed(consumer, consumer.work_root / "vectors/second")
    assert (second / "target/source.py").read_bytes() == (producer.work_root / "target/source.py").read_bytes()
    assert (first / "target/source.py").stat().st_ino != (second / "target/source.py").stat().st_ino
    with pytest.raises(custody.CustodyError, match="private"):
        custody.materialize_seed(consumer, producer.work_root / "copy")
    with pytest.raises(custody.CustodyError, match="private"):
        custody.materialize_seed(consumer, tmp_path / "outside-consumer")


@pytest.mark.parametrize("relative", [
    "target/source.py", "appsec-review.toml", "overlay.toml", "fixture-state.json",
    "runs/unchanged-run-id/data/configuration/frozen.json",
    "runs/unchanged-run-id/output/evidence.txt", "custody-input.json",
])
def test_seal_rejects_same_length_changes_without_a_stat_cache(tmp_path: Path, relative: str) -> None:
    producer, consumer = seed(tmp_path)
    path = producer.work_root / relative
    metadata = path.stat()
    original = path.read_bytes()
    path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    with pytest.raises(custody.CustodyError, match="sealed_tree_changed"):
        custody.verify_seed(consumer)


@pytest.mark.parametrize("change", ["missing", "extra", "extra-empty-directory", "torn", "manifest-change"])
def test_missing_extra_torn_or_changed_seal_fails_closed(tmp_path: Path, change: str) -> None:
    producer, consumer = seed(tmp_path)
    if change == "missing":
        (producer.work_root / "target/source.py").unlink()
    elif change == "extra":
        (producer.work_root / "extra").write_bytes(b"not in seal")
    elif change == "extra-empty-directory":
        (producer.work_root / "extra").mkdir()
    elif change == "torn":
        consumer.manifest_path.write_bytes(b'{"schema":')
    else:
        consumer.manifest_path.write_bytes(consumer.manifest_path.read_bytes() + b" ")
    with pytest.raises(custody.CustodyError):
        custody.verify_seed(consumer)


@pytest.mark.parametrize("change", ["invocation", "variant", "commit", "source"])
def test_seals_cannot_be_reused_for_another_invocation_variant_or_source(tmp_path: Path, change: str) -> None:
    _producer, consumer = seed(tmp_path)
    altered = {
        "invocation": {"invocation_id": "acceptance-other"},
        "variant": {"variant": "other"},
        "commit": {"tested_commit": "3" * 40},
        "source": {"source_identities": {"micro-source": "4" * 64}},
    }[change]
    with pytest.raises(custody.CustodyError, match="binding_mismatch"):
        custody.verify_seed(replace(consumer, **altered))


def test_prepared_inputs_stay_pinned_but_only_latest_checkpoint_tracks_mutable_output(tmp_path: Path) -> None:
    producer, _consumer = seed(tmp_path)
    inputs = custody.capture_inputs(producer)
    first = tmp_path / "custody/phase-1.json"
    first_hash = custody.checkpoint_seed(producer, first)
    custody.verify_checkpoint(producer, first, first_hash)
    (producer.work_root / "runs/unchanged-run-id/output/next.txt").write_bytes(b"real next phase")
    custody.verify_inputs(producer, inputs)
    with pytest.raises(custody.CustodyError, match="predecessor_tree_changed"):
        custody.verify_checkpoint(producer, first, first_hash)
    second = tmp_path / "custody/phase-2.json"
    second_hash = custody.checkpoint_seed(producer, second)
    custody.verify_checkpoint(producer, second, second_hash)
    (producer.work_root / "target/extra.py").write_bytes(b"changed immutable input directory")
    with pytest.raises(custody.CustodyError, match="immutable_inputs_changed"):
        custody.verify_inputs(producer, inputs)


def test_copy_verifies_actual_bytes_even_when_corruption_keeps_the_size(tmp_path: Path, monkeypatch) -> None:
    _producer, consumer = seed(tmp_path)
    copy = custody._copy_file

    def corrupted(source, destination):
        copy(source, destination)
        if destination.name == "source.py":
            destination.write_bytes(b"source = 2\r\n")

    monkeypatch.setattr(custody, "_copy_file", corrupted)
    with pytest.raises(custody.CustodyError, match="copy_bytes_changed"):
        custody.materialize_seed(consumer)
    assert not custody.copy_receipt_path(consumer.work_root).exists()


def test_copy_postprocessing_cannot_publish_after_its_budget(tmp_path: Path, monkeypatch) -> None:
    _producer, consumer = seed(tmp_path)
    copy = custody._copy_file

    def expired(source, destination):
        copy(source, destination)
        custody._DEADLINE.set(time.monotonic() - 1)

    monkeypatch.setattr(custody, "_copy_file", expired)
    with pytest.raises(custody.CustodyError, match="deadline_exceeded"):
        with custody.custody_deadline(time.monotonic() + 10):
            custody.materialize_seed(consumer)
    assert not custody.copy_receipt_path(consumer.work_root).exists()


def test_source_manifest_bytes_are_also_pinned(tmp_path: Path) -> None:
    producer, consumer = seed(tmp_path)
    path = tmp_path / "source-identities.json"
    path.write_bytes(b'{"source.py":"pinned by supervisor"}\n')
    expected = custody._file_record(path)["sha256"]
    producer = replace(producer, source_identities={"source-manifest": expected})
    manifest_path = tmp_path / "custody/pinned-source-seal.json"
    consumer = replace(consumer, source_identities=producer.source_identities, manifest_path=manifest_path,
                       manifest_sha256=custody.seal_seed(producer, manifest_path))
    custody.verify_seed(consumer)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(custody.CustodyError, match="source_manifest_changed"):
        custody.verify_seed(consumer)


def test_private_copy_retains_read_only_evidence_and_private_key_permissions(tmp_path: Path) -> None:
    producer, consumer = seed(tmp_path)
    evidence = producer.work_root / "runs/unchanged-run-id/output/evidence.txt"
    evidence.chmod(stat.S_IMODE(evidence.stat().st_mode) & ~0o222)
    key = producer.work_root / "runs/unchanged-run-id/private-key"
    key.write_bytes(b"micro private-key fixture")
    key.chmod(0o600)
    manifest_path = tmp_path / "custody/modes-sealed.json"
    consumer = replace(consumer, manifest_path=manifest_path,
                       manifest_sha256=custody.seal_seed(producer, manifest_path))
    custody.materialize_seed(consumer)
    copied = consumer.work_root / evidence.relative_to(producer.work_root)
    assert not copied.stat().st_mode & 0o222
    assert stat.S_IMODE((consumer.work_root / key.relative_to(producer.work_root)).stat().st_mode) == (
        stat.S_IMODE(key.stat().st_mode))


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_redirected_or_shared_files_are_never_sealed(tmp_path: Path, kind: str) -> None:
    producer, consumer = seed(tmp_path)
    source = producer.work_root / "target/source.py"
    destination = producer.work_root / "target/linked.py"
    try:
        if kind == "symlink":
            destination.symlink_to(source)
        else:
            os.link(source, destination)
    except OSError as error:
        pytest.skip(f"host cannot create {kind}: {error}")
    with pytest.raises(custody.CustodyError, match="redirected|hardlinked"):
        custody.verify_seed(consumer)


def test_deadline_and_enumeration_limits_fail_without_a_usable_copy(tmp_path: Path, monkeypatch) -> None:
    _producer, consumer = seed(tmp_path)
    with pytest.raises(custody.CustodyError, match="deadline_exceeded"):
        with custody.custody_deadline(time.monotonic()):
            custody.materialize_seed(consumer)
    assert not consumer.work_root.exists()
    monkeypatch.setattr(custody, "MAX_FILES", 1)
    with pytest.raises(custody.CustodyError, match="file_limit"):
        custody.verify_seed(consumer)


def test_manifest_publication_is_exclusive_and_never_part_of_its_own_tree(tmp_path: Path) -> None:
    producer, consumer = seed(tmp_path)
    with pytest.raises(FileExistsError):
        custody.seal_seed(producer, consumer.manifest_path)
    with pytest.raises(custody.CustodyError, match="outside_seed"):
        custody.seal_seed(producer, producer.work_root / "seal.json")
    with pytest.raises(custody.CustodyError, match="producer"):
        custody.seal_seed(consumer, tmp_path / "other.json")
