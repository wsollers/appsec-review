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
