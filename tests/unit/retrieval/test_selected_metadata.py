"""Metadata identity and read-size boundaries use real files and publication provenance."""
from hashlib import sha256
import json
from pathlib import Path

import pytest

from appsec_review.retrieval import IndexIdentity, write_manifest
from appsec_review.retrieval.index import _SelectedReceiptPolicy, load_verified_manifest
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.storage import file_sha256
from appsec_review.storage.shared import (
    _verified_bytes, receipt_read_scope, reference, verify_receipt, verify_reference,
)
from tests.unit.retrieval.test_selected_publication import JOB, SNAPSHOT, fixture, publish, publisher


def with_excluded_payload(tmp_path, layout):
    value = fixture(tmp_path, layout)
    excluded, _, _ = publish(value.root, value.owner, layout, name="links", shard="links-excluded")
    document = json.loads(value.manifest.read_text())
    write_manifest(value.manifest, run_id=value.root.name, target_snapshot=SNAPSHOT,
        target_root=Path(document["target_root"]), indexes=(IndexIdentity(**value.identity), IndexIdentity(**excluded)))
    value.sha = file_sha256(value.manifest)
    with input_read_scope(value.context):
        manifest, _ = load_verified_manifest(value.root, value.manifest, value.sha, selection=value.selection)
    return value, excluded, manifest


@pytest.mark.parametrize("layout", ["named", "shared"])
@pytest.mark.parametrize("role", ["receipt", "checkpoint"])
@pytest.mark.parametrize("descriptor", ["canonical", "alias"])
def test_indexed_hash_cannot_be_metadata_at_another_path(tmp_path, monkeypatch, layout, role, descriptor):
    value, excluded, manifest = with_excluded_payload(tmp_path, layout)
    alias = (value.root / f"data/jobs/{JOB}/attempts/attempt_alias/shared/derived-index/{'f' * 64}.json"
             if role == "receipt" else value.root / "data/indexing/checkpoints/alias.json")
    alias.parent.mkdir(parents=True, exist_ok=True)
    alias.write_bytes((value.root / excluded["relative_path"]).read_bytes())
    alias_ref = reference(value.root, alias)
    if descriptor == "alias":
        next(raw for raw in manifest["indexes"] if raw["name"] == "links")["relative_path"] = alias_ref["path"]
    if role == "checkpoint":
        _, supplied = value.owner.legacy("derived-index", "d" * 64, alias_ref,
            computation={"case": "metadata-alias"},
            dependencies=(reference(value.root, value.root / value.identity["relative_path"]),))
    else:
        supplied = alias_ref
    opened = []
    actual_open = Path.open

    def audit_open(path, *args, **kwargs):
        if path.resolve() == alias.resolve():
            opened.append(path)
        return actual_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", audit_open)
    policy = _SelectedReceiptPolicy(value.selection, manifest, value.identity)
    with pytest.raises(ValueError), input_read_scope(value.context), receipt_read_scope(value.root, policy):
        verify_receipt(value.root, supplied)
    assert opened == []


@pytest.mark.parametrize("layout", ["named", "shared"])
def test_alternate_provenance_metadata_remains_readable(tmp_path, layout):
    value, _, manifest = with_excluded_payload(tmp_path, layout)
    consumer = publisher(value.root, "attempt_0002")
    alternate = consumer.consume_receipt(value.receipt)
    assert alternate["path"] != value.receipt["path"]
    policy = _SelectedReceiptPolicy(value.selection, manifest, value.identity)
    with input_read_scope(value.context), receipt_read_scope(value.root, policy):
        verified = verify_receipt(value.root, alternate)
    assert verified["mode"] == "reused"
    assert verified["producer_receipt"] == value.receipt


def tiny_reference(tmp_path, data=b"x"):
    path = tmp_path / "metadata.json"
    path.write_bytes(data)
    return path, {"path": path.name, "sha256": sha256(data).hexdigest(), "size_bytes": len(data)}


@pytest.mark.parametrize("size", [True, False, -1, -2, None, "1", 1.0, 2**63 - 1, 2**63,
                                  8 * 1024 * 1024, 0, 2],
                         ids=["true", "false", "negative", "read-all", "none", "string", "float",
                              "max-int", "overflow", "eight-mib", "empty-mismatch", "size-mismatch"])
def test_invalid_metadata_sizes_refuse_before_open_or_allocation(tmp_path, monkeypatch, size):
    path, ref = tiny_reference(tmp_path)
    actual_open = Path.open

    def refuse_payload_open(candidate, *args, **kwargs):
        assert candidate != path, "invalid size reached payload I/O"
        return actual_open(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "open", refuse_payload_open)
    with pytest.raises(ValueError):
        _verified_bytes(tmp_path, {**ref, "size_bytes": size})


@pytest.mark.parametrize("data", [b"", b"x", b'{"metadata":"small"}'], ids=["empty", "one-byte", "small"])
def test_exact_metadata_sizes_preserve_bytes(tmp_path, data):
    _, ref = tiny_reference(tmp_path, data)
    assert _verified_bytes(tmp_path, ref) == data


class ObservedStream:
    def __init__(self, stream, reads, after_read=None):
        self.stream, self.reads, self.after_read = stream, reads, after_read

    def __enter__(self):
        self.stream.__enter__()
        return self

    def __exit__(self, *args):
        return self.stream.__exit__(*args)

    def fileno(self):
        return self.stream.fileno()

    def read(self, size):
        self.reads.append(size)
        result = self.stream.read(size)
        if len(self.reads) == 1 and self.after_read is not None:
            self.after_read()
        return result


def test_metadata_reads_use_existing_storage_chunk_bound(tmp_path, monkeypatch):
    data = b"x" * (1024 * 1024 + 19)
    path, ref = tiny_reference(tmp_path, data)
    reads = []
    actual_open = Path.open

    def measured(candidate, *args, **kwargs):
        stream = actual_open(candidate, *args, **kwargs)
        return ObservedStream(stream, reads) if candidate == path else stream

    monkeypatch.setattr(Path, "open", measured)
    assert _verified_bytes(tmp_path, ref) == data
    assert len(reads) >= 2 and max(reads) <= 1024 * 1024


@pytest.mark.parametrize("change", ["growth", "same-size", "shrink"])
def test_metadata_changes_during_read_are_refused(tmp_path, monkeypatch, change):
    path, ref = tiny_reference(tmp_path, b"x" * (1024 * 1024 + 19))
    actual_open = Path.open
    reads = []

    def mutate():
        with actual_open(path, "ab" if change == "growth" else "r+b") as stream:
            if change == "shrink":
                stream.truncate(0)
            else:
                stream.write(b"y")

    def changing(candidate, *args, **kwargs):
        stream = actual_open(candidate, *args, **kwargs)
        return ObservedStream(stream, reads, mutate) if candidate == path else stream

    monkeypatch.setattr(Path, "open", changing)
    with pytest.raises(ValueError):
        _verified_bytes(tmp_path, ref)


def test_metadata_symlink_swap_is_refused(tmp_path, monkeypatch):
    path, ref = tiny_reference(tmp_path)
    actual_open = Path.open
    moved = path.with_name("moved")
    swapped = False

    def swapping(candidate, *args, **kwargs):
        nonlocal swapped
        if candidate == path and not swapped:
            swapped = True
            path.rename(moved)
            path.symlink_to(moved)
        return actual_open(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "open", swapping)
    with pytest.raises(ValueError):
        _verified_bytes(tmp_path, ref)


def test_default_reference_verification_still_rejects_huge_size(tmp_path):
    path, ref = tiny_reference(tmp_path)
    assert verify_reference(tmp_path, ref) == path
    with pytest.raises(ValueError):
        verify_reference(tmp_path, {**ref, "size_bytes": 2**63 - 1})
