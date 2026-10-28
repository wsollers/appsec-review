from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_owasp_control_assessment import job as assessment
from appsec_review.config import load_config
from appsec_review.owasp_workbench import indexes
from appsec_review.storage import atomic_json, canonical_json, file_sha256


def _record() -> dict:
    return {"package_id": "package-first", "retrieval_manifest": {
        "path": "attempt_0001/retrieval-manifest.json", "sha256": "a" * 64}}


def _publish(root: Path, *, family: str = "finding-package", **kwargs) -> dict:
    return indexes.publish_shard(root, family=family, shard_id="batch:one",
        **{"records": [_record()], "fingerprint_inputs": {"batch": "stable", "guidance": "g"},
           "gaps": [], **kwargs})


def _accept(root: Path, shards: list[dict]) -> dict:
    return indexes.publish_manifest(root, run_id=root.name, shards=shards,
        accepted_upstream_manifest={"sha256": "a" * 64}, configuration_sha256="b" * 64)


@pytest.mark.parametrize("family", sorted(indexes.FAMILIES))
@pytest.mark.parametrize("change", ["package", "manifest_path", "manifest_hash", "gaps", "inputs"])
def test_shard_identity_binds_content_and_provenance(tmp_path: Path, family: str, change: str) -> None:
    before = _publish(tmp_path, family=family)
    path = tmp_path / before["path"]
    original = path.read_bytes()
    stat = path.stat()
    assert _publish(tmp_path, family=family) == before
    assert path.stat().st_mtime_ns == stat.st_mtime_ns

    record = _record()
    kwargs = {"records": [record]}
    if change == "package":
        record["package_id"] = "package-second"
    elif change == "manifest_path":
        record["retrieval_manifest"]["path"] = "attempt_0002/retrieval-manifest.json"
    elif change == "manifest_hash":
        record["retrieval_manifest"]["sha256"] = "c" * 64
    elif change == "gaps":
        kwargs["gaps"] = ["missing evidence"]
    else:
        kwargs["fingerprint_inputs"] = {"batch": "changed", "guidance": "g"}
    after = _publish(tmp_path, family=family, **kwargs)
    assert after["fingerprint"] != before["fingerprint"]
    assert after["path"] != before["path"]
    assert path.read_bytes() == original
    document = json.loads((tmp_path / after["path"]).read_text())
    assert document["records"] == [record]
    assert document["records_sha256"] == hashlib.sha256(canonical_json([record])).hexdigest()
    assert document["gaps"] == kwargs.get("gaps", [])
    assert after["sha256"] == file_sha256(tmp_path / after["path"])
    assert _publish(tmp_path, family=family, **kwargs) == after


def test_shard_identity_binds_schema(tmp_path: Path, monkeypatch) -> None:
    before = _publish(tmp_path)
    original = (tmp_path / before["path"]).read_bytes()
    monkeypatch.setattr(indexes, "INDEX_SCHEMA", "appsec-review/owasp-index-shard/test")
    after = _publish(tmp_path)
    assert before["path"] != after["path"]
    assert (tmp_path / before["path"]).read_bytes() == original


@pytest.mark.parametrize("family", sorted(indexes.FAMILIES))
def test_corrupt_expected_shard_is_rejected_and_reader_reports_gap(tmp_path: Path, family: str) -> None:
    root = tmp_path / "run"
    shard = _publish(root, family=family)
    _accept(root, [shard])
    reader = indexes.WorkbenchIndex(tmp_path, "run")
    assert reader.query(family=family)["results"][0]["record"] == _record()
    path = root / shard["path"]
    document = json.loads(path.read_text())
    document["records"][0]["package_id"] = "tampered"
    atomic_json(path, document)
    corrupted = path.read_bytes()
    with pytest.raises(ValueError, match="immutable OWASP index shard conflicts"):
        _publish(root, family=family)
    assert path.read_bytes() == corrupted
    result = reader.query(family=family)
    assert result["results"] == []
    assert result["coverage_gaps"] == [f"{family}/batch:one: shard resolution failed"]


def test_legacy_accepted_shard_remains_readable_after_new_publication(tmp_path: Path) -> None:
    root = tmp_path / "run"
    fingerprint = hashlib.sha256(canonical_json({
        "family": "finding-package", "shard_id": "legacy",
        "inputs": {"batch": "stable", "guidance": "g"}})).hexdigest()
    relative = f"data/indexes/owasp/finding-package/legacy/{fingerprint}.json"
    document = {"schema": indexes.INDEX_SCHEMA, "family": "finding-package",
        "shard_id": "legacy", "fingerprint": fingerprint, "records": [_record()], "gaps": [],
        "records_sha256": hashlib.sha256(canonical_json([_record()])).hexdigest()}
    atomic_json(root / relative, document)
    legacy = {"family": "finding-package", "shard_id": "legacy", "schema": indexes.INDEX_SCHEMA,
        "fingerprint": fingerprint, "path": relative, "sha256": file_sha256(root / relative),
        "record_count": 1, "gaps": []}
    manifest = _accept(root, [legacy])
    reader = indexes.WorkbenchIndex(tmp_path, "run")
    originals = {path: path.read_bytes() for path in (root / relative, root / manifest["path"])}
    current = indexes.publish_shard(root, family="finding-package", shard_id="legacy",
        records=[_record()], fingerprint_inputs={"batch": "stable", "guidance": "g"})
    assert current["path"] != legacy["path"]
    assert indexes.WorkbenchIndex(tmp_path, "run").query()["results"][0]["record"] == _record()
    _accept(root, [current])
    assert reader.query()["results"][0]["index_sha256"] == legacy["sha256"]
    assert indexes.WorkbenchIndex(tmp_path, "run").query()["results"][0]["index_sha256"] == current["sha256"]
    assert all(path.read_bytes() == content for path, content in originals.items())


def test_manifest_write_failure_preserves_accepted_pointer(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "run"
    first = _publish(root)
    _accept(root, [first])
    pointer = root / "data/indexes/owasp/accepted.json"
    original = pointer.read_bytes()
    second = _publish(root, gaps=["new gap"])

    from appsec_review.storage import shared
    publish = shared.publish_named

    def fail_manifest(root, path, payload, **kwargs):
        if path.parent.name == "manifests":
            raise OSError("manifest write failed")
        return publish(root, path, payload, **kwargs)

    monkeypatch.setattr(shared, "publish_named", fail_manifest)
    with pytest.raises(OSError, match="manifest write failed"):
        _accept(root, [second])
    assert pointer.read_bytes() == original
    assert indexes.WorkbenchIndex(tmp_path, "run").query()["results"][0]["index_sha256"] == first["sha256"]


def test_reader_rejects_changed_accepted_manifest(tmp_path: Path) -> None:
    root = tmp_path / "run"
    manifest = _accept(root, [_publish(root)])
    path = root / manifest["path"]
    document = json.loads(path.read_text())
    document["shards"] = []
    atomic_json(path, document)
    with pytest.raises(ValueError, match="accepted OWASP index manifest cannot be resolved"):
        indexes.WorkbenchIndex(tmp_path, "run")


def test_job_publishes_changed_packages_and_preserves_pointer_on_failure(tmp_path: Path) -> None:
    root = tmp_path / "run"
    package = {**_record(), "guidance": {"bundle_sha256": "g"}}
    outputs = {
        "standards_selection.ingest_catalogs": {"manifest": {
            "sources": [], "gaps": [], "fingerprint": "s"}},
        "standards_selection.select_profiles": {"selection": {"selection_fingerprint": "s"}},
        "characterization.classify_components": {"classifications": []},
        "characterization.load_inputs": {"retrieval_manifest": package["retrieval_manifest"]},
        "applicability.build_matrix": {"rows": []},
        "batching.partition_work": {"work": {"batches": [
            {"batch_id": "batch:one", "fingerprint": "stable", "component_ids": []}]}},
        "batching.build_packages": {"packages": {"batch:one": [package]}},
        "join.deterministic_join": {"joined": {"results": []}},
    }
    settings = deepcopy(dict(load_config(Path(__file__).parents[1] / "appsec-review.toml").job(
        "job_owasp_control_assessment").settings))
    resolved = root / "data" / "configuration" / "resolved.json"
    atomic_json(resolved, {"jobs": {"job_owasp_control_assessment": {"settings": settings}}})
    atomic_json(resolved.with_name("manifest.json"), {"resolved_sha256": file_sha256(resolved)})
    unit = SimpleNamespace(job=SimpleNamespace(run_root=root, run_id="run",
        source_fingerprint="source", config=SimpleNamespace(settings=settings)),
        output=outputs.__getitem__)
    publish = next(unit.handler for unit in assessment.build_job().units
                   if unit.unit_id == "publication.publish_indexes")
    first = publish(unit)
    originals = {path: path.read_bytes() for path in (root / "data/indexes/owasp").rglob("*.json")
                 if path.name != "accepted.json"}
    package["package_id"] = "package-second"
    package["retrieval_manifest"] = {"path": "attempt_0002/retrieval-manifest.json", "sha256": "c" * 64}
    outputs["characterization.load_inputs"]["retrieval_manifest"] = package["retrieval_manifest"]
    second = publish(unit)
    assert first["manifest"] != second["manifest"]
    assert indexes.WorkbenchIndex(tmp_path, "run").query(
        family="finding-package")["results"][0]["record"] == package
    assert all(path.read_bytes() == content for path, content in originals.items())

    pointer = root / "data/indexes/owasp/accepted.json"
    accepted = pointer.read_bytes()
    manifest = json.loads((root / second["manifest"]["path"]).read_text())
    shard = next(item for item in manifest["shards"] if item["family"] == "finding-package")
    corrupted = deepcopy(package)
    corrupted["package_id"] = "tampered"
    shard_path = root / shard["path"]
    document = json.loads(shard_path.read_text())
    document["records"] = [corrupted]
    atomic_json(shard_path, document)
    with pytest.raises(ValueError, match="immutable OWASP index shard conflicts"):
        publish(unit)
    assert pointer.read_bytes() == accepted
