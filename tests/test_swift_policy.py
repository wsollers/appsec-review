from __future__ import annotations

from pathlib import Path

import pytest

from appsec_review.jobs.job_codeql_analysis.planning import build_codeql_plan
from appsec_review.jobs.job_target_analysis_plan.job import apply_swift_catalog_policy
from appsec_review.retrieval import (
    EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, SourceLocation,
    write_manifest,
)
from appsec_review.retrieval.index import load_verified_manifest
from appsec_review.storage import file_sha256
from appsec_review.swift_policy import SWIFT_ENABLED_GAP, SWIFT_KNOWN_GAP


def _swift_file() -> dict[str, object]:
    return {"path": "Sources/App.swift", "sha256": "a" * 64, "size_bytes": 20,
            "language": "Swift", "generated": False}


def test_disabled_policy_removes_swift_from_every_planning_input_and_keeps_known_gap() -> None:
    swift = _swift_file()
    catalog = {
        "files": (swift, {"path": "main.py", "sha256": "b" * 64, "language": "Python"}),
        "accepted_artifacts": ({"path": "App.swift", "language": "Swift"},),
        "build_units": ({"build_unit_id": "swift", "language": "Swift", "root": "."},),
        "gaps": (),
    }
    disabled = apply_swift_catalog_policy(catalog, enabled=False)
    assert [item["path"] for item in disabled["files"]] == ["main.py"]
    assert disabled["accepted_artifacts"] == () and disabled["build_units"] == ()
    assert SWIFT_KNOWN_GAP in disabled["gaps"]
    assert apply_swift_catalog_policy(catalog, enabled=True)["files"] == catalog["files"]


def test_codeql_names_disabled_and_enabled_but_unsupported_swift_gaps() -> None:
    arguments = {
        "source_fingerprint": "snapshot", "files": (_swift_file(),), "receipts": (),
        "supported_extractors": ("swift",), "source_image_id": "sha256:" + "c" * 64,
        "configuration_sha256": "d" * 64,
    }
    disabled = build_codeql_plan(**arguments)
    assert disabled.scopes == () and any(SWIFT_KNOWN_GAP in gap for gap in disabled.gaps)
    enabled = build_codeql_plan(**arguments, enable_swift=True)
    assert enabled.scopes == () and SWIFT_ENABLED_GAP in enabled.gaps
    assert any("no accepted source/build executor" in gap for gap in enabled.gaps)


def test_disabled_policy_rejects_stale_swift_derived_index(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    path = run_root / "data" / "indices" / "observations" / "swift.sqlite"
    builder = IndexBuilder(path, name="observations", fingerprint="e" * 64,
                           target_snapshot="snapshot", shard_id="swift-stale")
    identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, "snapshot", {"swift": True})
    builder.add_entity(EntityRecord(
        identity, "swift", "swift observation", "must not be accepted",
        {"language": "Swift", "path": "Sources/App.swift"},
        SourceLocation("snapshot", "Sources/App.swift", "a" * 64, 0, 1, 1, 1, 1, 2,
                       {"tool": "fixture"}, "exact", 1.0),
    ))
    sha = builder.build()
    index = IndexIdentity("observations", "appsec-review/retrieval-index/2", sha, "e" * 64,
                          path.relative_to(run_root).as_posix(), {"job": "external"}, (), "swift-stale")
    manifest_path = run_root / "data" / "indices" / "manifests" / "accepted.json"
    write_manifest(manifest_path, run_id="run", target_snapshot="snapshot", target_root=tmp_path,
                   indexes=(index,))
    with pytest.raises(ValueError, match="Swift-derived"):
        load_verified_manifest(run_root, manifest_path, file_sha256(manifest_path))


def test_swift_path_and_explicit_swift_fast_paths_preserve_exact_semantics() -> None:
    from collections.abc import Sequence as AbcSequence
    from types import MappingProxyType
    from appsec_review.swift_policy import contains_swift_derived, is_swift_path

    class CustomSeq(AbcSequence):
        def __init__(self, items):
            self._items = tuple(items)
        def __getitem__(self, idx):
            return self._items[idx]
        def __len__(self):
            return len(self._items)

    assert not is_swift_path(None)
    assert not is_swift_path("")
    assert not is_swift_path("src/request.cpp")
    assert not is_swift_path(".swift")
    assert not is_swift_path("Sources/App.swift.bak")
    assert is_swift_path("Sources/App.swift")
    assert is_swift_path("Sources\\App.SWIFT")
    assert is_swift_path("Sources/App.swift/")

    assert not contains_swift_derived({"language": "C++", "path": "src/request.cpp",
                                       "counts": [1, 2.5, True, None, b"swift"]})
    assert contains_swift_derived(MappingProxyType({"source_language": " Swift "}))
    assert contains_swift_derived({"file": CustomSeq(["src/a.cpp", "Sources/App.swift"])})


def test_disabled_policy_rejects_unicode_escaped_swift_and_malformed_sqlite_json(tmp_path: Path) -> None:
    import json
    import sqlite3
    from appsec_review.retrieval import RelationKind, RelationRecord

    def build_shard(shard_id: str, mutate_sql: str, params: tuple[object, ...] = ()) -> tuple[Path, Path]:
        run_root = tmp_path / shard_id
        path = run_root / "data" / "indices" / "observations" / f"{shard_id}.sqlite"
        builder = IndexBuilder(path, name="observations", fingerprint="e" * 64,
                               target_snapshot="snapshot", shard_id=shard_id)
        e1 = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, "snapshot", {"id": 1})
        e2 = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, "snapshot", {"id": 2})
        loc = SourceLocation("snapshot", "src/request.cpp", "a" * 64, 0, 1, 1, 1, 1, 2,
                             {"tool": "fixture"}, "exact", 1.0)
        builder.add_entity(EntityRecord(e1, "cpp", "obs 1", "summary", {"language": "C++", "path": "src/request.cpp"}, loc))
        builder.add_entity(EntityRecord(e2, "cpp", "obs 2", "summary", {"language": "C++", "path": "src/request.cpp"}, loc))
        builder.add_relation(RelationRecord(RelationKind.CALLS, e1.value, e2.value, True, 1.0, payload={"path": "src/request.cpp"}))
        builder.build()
        with sqlite3.connect(path) as conn:
            conn.execute(mutate_sql, params)
            conn.commit()
        sha = file_sha256(path)
        idx = IndexIdentity("observations", "appsec-review/retrieval-index/2", sha, "e" * 64,
                            path.relative_to(run_root).as_posix(), {"job": "external"}, (), shard_id)
        manifest_path = run_root / "data" / "indices" / "manifests" / "accepted.json"
        write_manifest(manifest_path, run_id="run", target_snapshot="snapshot", target_root=tmp_path,
                       indexes=(idx,))
        return run_root, manifest_path

    # Clean C++ + SWIFT_KNOWN_GAP coverage_cell passes without error
    gap_payload = json.dumps({
        "record_type": "coverage_cell", "language": "Swift",
        "lanes": {"source": {"state": "present"}, "codeql": {"state": "unavailable"}},
    })
    clean_root, clean_manifest = build_shard(
        "clean-cpp",
        "UPDATE entities SET kind = 'coverage_cell', payload_json = ? WHERE identity = (SELECT MIN(identity) FROM entities)",
        (gap_payload,),
    )
    loaded_manifest, _ = load_verified_manifest(clean_root, clean_manifest, file_sha256(clean_manifest))
    assert len(loaded_manifest['indexes']) == 1

    # Escaped \u0053wift in entity payload_json is caught and rejected
    esc_entity_root, esc_entity_manifest = build_shard(
        "escaped-entity",
        "UPDATE entities SET payload_json = ? WHERE identity = (SELECT MIN(identity) FROM entities)",
        ('{"language": "\\u0053wift"}',),
    )
    with pytest.raises(ValueError, match="Swift-derived"):
        load_verified_manifest(esc_entity_root, esc_entity_manifest, file_sha256(esc_entity_manifest))

    # Escaped \u0073wift in relation payload_json is caught and rejected
    esc_rel_root, esc_rel_manifest = build_shard(
        "escaped-relation",
        "UPDATE relations SET payload_json = ?",
        ('{"source_path": "Sources/App.\\u0073wift"}',),
    )
    with pytest.raises(ValueError, match="Swift-derived"):
        load_verified_manifest(esc_rel_root, esc_rel_manifest, file_sha256(esc_rel_manifest))

    # Corrupt non-JSON payload_json is caught by NOT json_valid(payload_json) and rejected
    bad_json_root, bad_json_manifest = build_shard(
        "corrupt-json",
        "UPDATE entities SET payload_json = 'not-valid-json' WHERE identity = (SELECT MIN(identity) FROM entities)",
    )
    with pytest.raises(json.JSONDecodeError):
        load_verified_manifest(bad_json_root, bad_json_manifest, file_sha256(bad_json_manifest))
