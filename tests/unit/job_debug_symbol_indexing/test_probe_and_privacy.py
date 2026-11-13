"""``_probe`` classifies each accepted artifact before any reader sees it, and ``_private_text`` /
``_approved_data`` keep recorded paths out of the normalized shard."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from appsec_review.jobs.job_debug_symbol_indexing.job import (
    FrameworkIntegrityError, _approved_data, _digest, _private_text, _probe,
)
from tests.unit.job_debug_symbol_indexing.support import ELF, MSF, artifact

MAXIMUM = 1024


def test_probe_verifies_and_returns_the_path_of_an_exact_binary(tmp_path: Path) -> None:
    item = artifact(tmp_path, "bin/program", ELF)
    probed = _probe(tmp_path, item, MAXIMUM)
    assert probed["path"] == tmp_path / item["reference"]["path"]
    assert probed["is_debug"] is False and "gap" not in probed
    assert probed["probe"] == {"artifact_identity": item["artifact_identity"], "expected": item["reference"],
                              "observed": {"sha256": item["reference"]["sha256"], "size_bytes": len(ELF)}}


@pytest.mark.parametrize("kind,content,debug", [
    ("executable", MSF, True), ("debug-information", b"not msf", True), ("native-symbols", ELF, True),
    ("debug-metadata", ELF, True), ("object", ELF, False),
])
def test_probe_recognises_debug_companions_by_kind_or_msf_header(tmp_path: Path, kind, content, debug) -> None:
    assert _probe(tmp_path, artifact(tmp_path, "x", content, kind), MAXIMUM)["is_debug"] is debug


def test_oversized_artifacts_are_a_named_gap_without_hashing_the_bytes(tmp_path: Path) -> None:
    item = artifact(tmp_path, "bin/big", b"x" * 64)
    probed = _probe(tmp_path, item, 63)
    assert probed["gap"] == "max_input_bytes" and "path" not in probed
    assert probed["probe"]["observed"] == {"size_bytes": 64, "error": "max_input_bytes"}


@pytest.mark.parametrize("corruption", ["missing", "no-reference", "not-a-mapping"])
def test_unavailable_bytes_or_references_are_an_integrity_gap_not_a_failure(tmp_path: Path, corruption) -> None:
    item = artifact(tmp_path, "bin/program", ELF)
    if corruption == "missing":
        (tmp_path / item["reference"]["path"]).unlink()
    elif corruption == "no-reference":
        item["reference"] = None
    else:
        item["reference"] = "data/shared/objects/x"
    probed = _probe(tmp_path, item, MAXIMUM)
    assert probed["gap"] == "artifact_integrity_unavailable" and "path" not in probed
    assert probed["probe"] == {"artifact_identity": item["artifact_identity"], "expected": item["reference"],
                              "observed": {"error": "artifact_integrity_unavailable"}}


@pytest.mark.parametrize("corruption", ["changed", "size"])
def test_bytes_that_differ_from_the_accepted_reference_are_an_integrity_failure(tmp_path: Path, corruption) -> None:
    item = artifact(tmp_path, "bin/program", ELF)
    if corruption == "changed":
        (tmp_path / item["reference"]["path"]).write_bytes(b"changed")
    else:
        item["reference"]["size_bytes"] = 1
    with pytest.raises(FrameworkIntegrityError, match="binary/debug artifact integrity verification failed"):
        _probe(tmp_path, item, MAXIMUM)


def test_escaped_artifact_reference_is_an_integrity_failure(tmp_path: Path) -> None:
    item = {"artifact_identity": "fixture", "kind": "executable",
            "reference": {"path": "../outside", "sha256": "a" * 64, "size_bytes": 1}}
    with pytest.raises(FrameworkIntegrityError, match="reference is invalid"):
        _probe(tmp_path, item, MAXIMUM)


@pytest.mark.parametrize("value", ["C:\\private\\src\\main.cc", "/home/user/main.cc", "\\\\share\\main.cc",
                                   "a /tmp/x", "D:/build/x"])
def test_private_text_hashes_anything_that_looks_like_a_filesystem_path(value) -> None:
    assert _private_text(value) == "source-name-sha256:" + hashlib.sha256(value.encode()).hexdigest()


@pytest.mark.parametrize("value", ["main", "ns::function(int)", "src/main.cc", "max_records", "a/b/c", ""])
def test_private_text_keeps_names_and_relative_paths(value) -> None:
    assert _private_text(value) == value


def test_approved_data_hashes_path_like_keys_and_private_strings_at_any_depth() -> None:
    data = {"signature": "int f()", "comp_dir": "/build/private", "file": "main.cc",
            "nested": {"source_file": "x", "members": [{"name": "C:\\p\\q", "offset": 0}]},
            "DW_AT_decl_file": 3, "size_bytes": 8}
    approved = _approved_data(data)
    assert approved == {
        "signature": "int f()", "comp_dir_sha256": _digest("/build/private"), "file_sha256": _digest("main.cc"),
        "nested": {"source_file_sha256": _digest("x"),
                   "members": [{"name": _private_text("C:\\p\\q"), "offset": 0}]},
        "DW_AT_decl_file": 3, "size_bytes": 8}
    assert "private" not in str(approved) and "C:\\" not in str(approved)
    assert _approved_data(("a", 1, None, True)) == ["a", 1, None, True]


def test_approved_data_refuses_metadata_deeper_than_the_bound() -> None:
    value: dict = {}
    nested = value
    for _ in range(17):
        nested["child"] = {}
        nested = nested["child"]
    with pytest.raises(ValueError, match="depth limit"):
        _approved_data(value)
    shallow: dict = {}
    nested = shallow
    for _ in range(15):
        nested["child"] = {}
        nested = nested["child"]
    assert _approved_data(shallow)
