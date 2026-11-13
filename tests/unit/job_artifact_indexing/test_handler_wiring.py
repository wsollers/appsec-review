"""Code-level handler boundaries; neither the unit executor nor a job graph is run."""
from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path

import pytest

from appsec_review.jobs.job_artifact_indexing import job as indexing
from appsec_review.retrieval import INDEX_SCHEMA, IndexIdentity
from appsec_review.storage import atomic_json
from tests.unit.job_artifact_indexing.support import (
    SNAPSHOT, loaded_output, unit_context, validated_receipt,
)


def _handler(name):
    return next(unit.handler for unit in indexing.build_job().units if unit.unit_id == name)


def test_load_wires_the_verified_receipts_intake_and_manifest_without_mutating_the_inputs(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    raw = [{"build_unit_id": "unit"}]
    verified = [validated_receipt(0)]
    target = [{"target_relative_path": "prebuilt.wasm"}]
    upstream = {"path": "data/indices/manifests/language-build.json", "sha256": "b" * 64}
    accepted = {"source_fingerprint": SNAPSHOT, "receipts": raw, "gaps": [],
                "language_build_handoff_sha256": "a" * 64}
    calls = []
    unit = unit_context(tmp_path, "load.accepted_builds")
    monkeypatch.setattr(indexing, "load_accepted_language_build",
                        lambda root: calls.append(("accepted", root)) or accepted)
    monkeypatch.setattr(indexing, "_accepted_language_manifest",
                        lambda root: calls.append(("manifest", root)) or upstream)
    monkeypatch.setattr(indexing, "_validate_receipts",
                        lambda root, snapshot, receipts:
                        calls.append(("receipts", root, snapshot, receipts)) or (verified, []))
    monkeypatch.setattr(indexing, "_target_artifacts",
                        lambda context: calls.append(("intake", context)) or (target, [], "c" * 64))
    assert _handler(unit.unit_id)(unit) == {
        "receipts": verified, "receipt_count": 1, "target_artifacts": target,
        "target_catalog_handoff_sha256": "c" * 64, "producer_gaps": [],
        "language_build_handoff_sha256": "a" * 64, "upstream_manifest": upstream,
        "terminal_status": "SUCCEEDED",
    }
    assert calls == [("accepted", tmp_path), ("manifest", tmp_path),
                     ("receipts", tmp_path, SNAPSHOT, raw), ("intake", unit)]
    assert raw == [{"build_unit_id": "unit"}] and accepted["gaps"] == []


def _index(name, shard):
    return IndexIdentity(name, INDEX_SCHEMA, "d" * 64, "e" * 64,
                         f"data/indices/{name}/{shard}.sqlite",
                         {"job": "job_artifact_indexing", "unit": "index.catalogs"}, (), shard)


@pytest.mark.parametrize("target", [False, True], ids=["repository-root", "target-root"])
def test_publish_replaces_prior_artifact_shards_keeps_other_indexes_and_binds_the_written_files(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: bool) -> None:
    old_artifacts = _index("artifacts", "old")
    old_build = _index("build", "language-build")
    current = [_index("artifacts", name) for name in ("catalog-new", "members-new", "relations-new")]
    upstream = {"path": "data/indices/manifests/language-build.json", "sha256": "b" * 64}
    loaded = loaded_output([validated_receipt(2)], target_artifacts=[{"target_relative_path": "target.wasm"}],
                           upstream_manifest=upstream, catalog_handoff="c" * 64)
    outputs = {"load.accepted_builds": loaded}
    for name, index in zip(("catalogs", "members", "relationships"), current):
        outputs[f"index.{name}"] = {"indexes": [asdict(index)], "gaps": [], "reused_count": name != "members"}
    unit = unit_context(tmp_path, "acceptance.publish_handoff", outputs,
                        target_root=tmp_path / "source" if target else None)
    calls = []
    manifest_path = tmp_path / "data/indices/manifests/artifact-indexing-attempt_0001.json"

    def load_manifest(root, path, digest):
        calls.append(("read", root, path, digest))
        return {"indexes": [asdict(old_artifacts), asdict(old_build)]}, None

    def write_manifest(path, **kwargs):
        calls.append(("write", path, kwargs))
        atomic_json(path, {"schema": "appsec-review/index-manifest/1"})

    monkeypatch.setattr(indexing, "load_verified_manifest", load_manifest)
    monkeypatch.setattr(indexing, "write_manifest", write_manifest)
    result = _handler(unit.unit_id)(unit)
    assert calls[0] == ("read", tmp_path, tmp_path / upstream["path"], "b" * 64)
    assert calls[1] == ("write", manifest_path, {
        "run_id": tmp_path.name, "target_snapshot": SNAPSHOT,
        "target_root": tmp_path / "source" if target else tmp_path,
        "indexes": [old_build, *current], "upstream_manifests": (upstream,),
    })
    assert calls[2] == ("read", tmp_path, manifest_path, result["index_manifest"]["sha256"])
    assert len(calls) == 3
    document = json.loads((tmp_path / result["artifact"]["path"]).read_bytes())
    assert document == {
        "schema": indexing.SCHEMA, "source_fingerprint": SNAPSHOT,
        "language_build_handoff_sha256": "f" * 64, "target_catalog_handoff_sha256": "c" * 64,
        "target_artifacts": [{"target_relative_path": "target.wasm"}],
        "artifact_shard_count": 3, "reused_shard_count": 2, "artifact_count": 4,
        "gaps": [], "index_manifest": result["index_manifest"],
    }
    assert result["item_count"] == 3 and result["terminal_status"] == "SUCCEEDED" and result["gaps"] == []
    job = indexing.build_job()
    assert job.output_validators == () and job.result_transform is None
    assert job.finalize_result(unit.job, result) is result
