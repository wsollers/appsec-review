from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from appsec_review.interchange import GapCode, producer_gap
from appsec_review.jobs.job_target_catalog import job as catalog
from tests.unit.job_target_catalog.support import context, source


@pytest.mark.parametrize(("value", "expected"), [
    ("legacy gap", "legacy gap"),
    (producer_gap(GapCode.PRODUCER_REPORTED_GAP, "typed gap reason", unit_id="u", scope_id="s"), "typed gap reason"),
    ({"path": "x", "reason": "excluded", "other": 1}, "x: excluded"),
    ({"z": 2, "a": 1}, '{"a":1,"z":2}'),
    ({"path": None, "reason": "unknown"}, '{"path":null,"reason":"unknown"}'),
    ([2, 1], "[2,1]"),
    (None, "null"),
], ids=["text", "producer-gap", "path-reason", "sorted", "null-path", "list", "null"])
def test_gap_text_is_stable(value, expected):
    assert catalog._gap_text(value) == expected


def test_dedup_gaps_and_inventory_gap_items_normalize_every_shape():
    first = producer_gap(GapCode.PRODUCER_REPORTED_GAP, "a.py: excluded", unit_id="u", scope_id="a.py")
    second = producer_gap(GapCode.PRODUCER_REPORTED_GAP, "unscoped reason", unit_id="u", scope_id="b.py")
    deduped = catalog._dedup_gaps([first, dict(first), second])
    assert deduped == [first, second]
    assert catalog._coverage_gap_ids([]) is None
    many = [producer_gap(GapCode.PRODUCER_REPORTED_GAP, f"r-{i}", unit_id="u", scope_id=f"s-{i}") for i in range(12)]
    assert catalog._coverage_gap_ids(many) == ",".join(item["gap_id"] for item in many[:10])

    assert catalog._inventory_gap_items({"inventory_gaps": [{"path": ".hg", "reason": "excluded_directory"}]}) == [
        {"path": ".hg", "reason": "excluded_directory"}
    ]
    assert catalog._inventory_gap_items({"gaps": [
        first,
        second,
        {"path": "docs/big.md", "reason": "oversized", "detail": "20 MiB"},
        {"path": "", "reason": ""},
        "sub/file.c: permission_denied",
        "plain inventory warning",
    ]}) == [
        {"path": "a.py", "reason": "excluded"},
        {"path": "b.py", "reason": "unscoped reason"},
        {"path": "docs/big.md", "reason": "oversized", "detail": "20 MiB"},
        {"path": ".", "reason": "gap"},
        {"path": "sub/file.c", "reason": "permission_denied"},
        {"path": "<inventory>", "reason": "plain inventory warning"},
    ]


def test_target_is_required(tmp_path):
    unit = context(tmp_path, "repository_discovery.partition_repository")
    assert catalog._target(unit) == unit.job.target_root
    unit.job.target_root = None
    with pytest.raises(catalog.CatalogConfigurationError, match="^review target is required$"):
        catalog._target(unit)


def test_fingerprint_binds_every_parser_and_producer_input(tmp_path, monkeypatch):
    unit = context(tmp_path, "retrieval_indexes.build_path_index")
    calls = []
    artifacts = [{"path": "input", "sha256": "a" * 64}]
    monkeypatch.setattr(catalog, "index_fingerprint",
                        lambda **kwargs: calls.append(kwargs) or "fingerprint")
    assert catalog._fingerprint(unit, "source", artifacts) == "fingerprint"
    assert calls == [{
        "name": "source", "target_snapshot": "fixture-snapshot",
        "producer_artifacts": artifacts, "tool_identity": {"producer": "job_target_catalog"},
        "parser_identity": "catalog-parser/2",
        "normalizer_identity": "retrieval-normalizer/1+appsec-review/delivery-propagation/2",
        "mapping_identity": "source-map/1",
    }]


def test_descriptor_read_is_accepted_hash_bound_and_inclusive(tmp_path):
    unit = context(tmp_path, "descriptor")
    entry = source(unit, "meson.build", b"project('game')\n", None)
    read, changed, unread = catalog.descriptor_reader(
        unit.job.target_root, {"meson.build": entry}, limit=entry["size_bytes"])
    assert read("unaccepted") is None
    assert read("meson.build") == "project('game')\n"
    assert changed == [] and unread == {}


@pytest.mark.parametrize("damage", ["hash", "length"], ids=["hash", "length"])
def test_descriptor_changed_bytes_fail_closed(tmp_path, damage):
    unit = context(tmp_path, "descriptor")
    entry = source(unit, "meson.build", b"original", None)
    path = unit.job.target_root / entry["path"]
    path.write_bytes(b"changed!" if damage == "hash" else b"longer changed bytes")
    read, changed, unread = catalog.descriptor_reader(unit.job.target_root, {entry["path"]: entry})
    with pytest.raises(catalog.CatalogIntegrityError, match="^engine/build descriptor differs from the accepted catalog$"):
        read(entry["path"])
    assert changed == ["meson.build"] and unread == {}


@pytest.mark.parametrize("case", ["missing", "os-error", "unicode"], ids=["missing", "os-error", "unicode"])
def test_descriptor_unreadable_is_not_invented_text(tmp_path, monkeypatch, case):
    unit = context(tmp_path, "descriptor")
    entry = source(unit, "meson.build", b"\xff" if case == "unicode" else b"text", None)
    path = unit.job.target_root / entry["path"]
    if case == "missing":
        path.unlink()
    if case == "os-error":
        def denied(_path):
            raise PermissionError("fixture descriptor read denied")
        monkeypatch.setattr(Path, "read_bytes", denied)
    read, changed, unread = catalog.descriptor_reader(unit.job.target_root, {entry["path"]: entry})
    assert read("meson.build") is None
    assert changed == [] and unread == {}


def test_descriptor_bound_records_size_without_reading_and_filters_non_descriptors(tmp_path, monkeypatch):
    def forbidden(_path):
        pytest.fail("oversized descriptor was read")
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    accepted = {"meson.build": {"size_bytes": 11, "sha256": hashlib.sha256(b"").hexdigest()}}
    read, changed, unread = catalog.descriptor_reader(tmp_path, accepted, limit=10)
    assert read("meson.build") is None
    assert changed == [] and unread == {"meson.build": 11}
    assert catalog.unread_descriptor_gaps({"notes.txt": 30, "meson.build": 11}, limit=10) == [
        "build descriptor not read: meson.build: 11 bytes exceeds the 10-byte read bound; "
        "its build points and driven directories are unknown"]


def test_descriptor_symlink_refusal_names_the_path(tmp_path):
    unit = context(tmp_path, "descriptor")
    entry = source(unit, "meson.build", b"text", None)
    path = unit.job.target_root / "meson.build"
    path.unlink()
    path.symlink_to(tmp_path / "elsewhere")
    read, _, _ = catalog.descriptor_reader(unit.job.target_root, {"meson.build": entry})
    with pytest.raises(catalog.CatalogIntegrityError, match="symlink"):
        read("meson.build")
