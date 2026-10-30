"""Artifact-index throughput: per-build-unit batching, bounded work, and determinism."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import random
import sqlite3
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_artifact_indexing import build_job, canonical_artifact_identity
from appsec_review.jobs.job_artifact_indexing import job as job_module
from appsec_review.jobs.job_artifact_indexing.job import (
    ArtifactIndexIntegrityError,
    _batch_shard_id,
    _manifest_entries,
    _ReceiptContext,
    _relationships,
    _shard_layout,
    artifact_index_fingerprint,
)
from appsec_review.observability import EventLog
from appsec_review.observability.spans import operation_span
from appsec_review.retrieval import IndexBuilder, RetrievalCore
from appsec_review.runtime import GraphRunner
from appsec_review.runtime.runner import JobRunner
from appsec_review.storage import atomic_json, file_sha256
from tests.test_artifact_indexing import RUN_ID, _identity, _publish_changed_language_receipts, _seed


SNAPSHOT = "snapshot-throughput"
UNIT = "build-unit-scale"
BASELINE = Path(__file__).parent / "fixtures" / "artifact_indexing" / "per-artifact-baseline.json"
SETTINGS = {
    "catalog_parser_identity": "appsec-review/produced-artifact-catalog/1",
    "member_extractor_identity": "appsec-review/accepted-archive-member-manifest/1",
    "member_parser_identity": "appsec-review/archive-member-normalizer/1",
    "relationship_parser_identity": "appsec-review/produced-artifact-relations/2",
    "normalizer_identity": "appsec-review/artifact-normalizer/1",
    "mapping_identity": "appsec-review/receipt-workspace-mapping/1",
}


class CountingList(list):
    """A list that counts complete-iteration passes, to detect per-artifact rescans."""

    def __init__(self, *args) -> None:
        super().__init__(*args)
        self.passes = 0

    def __iter__(self):
        self.passes += 1
        return super().__iter__()


def _artifact(path: str, kind: str, content: str, unit: str = UNIT) -> dict[str, object]:
    artifact = {"workspace_path": path, "sha256": hashlib.sha256(content.encode()).hexdigest(),
                "size_bytes": len(content), "kind": kind}
    artifact["canonical_identity"] = canonical_artifact_identity(SNAPSHOT, unit, artifact).value
    return artifact


def _receipt(count: int, *, unit: str = UNIT, link_inputs: int | None = None) -> dict[str, object]:
    objects = [_artifact(f"build/obj/unit-{index:05d}.o", "object", f"object-{index}", unit)
               for index in range(count)]
    app = _artifact("build/app", "executable", "app", unit)
    linked = objects if link_inputs is None else objects[:link_inputs]
    invocations = [{"tool": "cc", "tool_kind": "compiler", "parent_command_id": "compile",
                    "mapping_confidence": 1.0, "origin": f"capture:{index}",
                    "outputs": [{"workspace_path": item["workspace_path"], "sha256": item["sha256"]}],
                    "inputs": []} for index, item in enumerate(objects)]
    invocations.append({
        "tool": "ld", "tool_kind": "linker", "parent_command_id": "link", "mapping_confidence": 1.0,
        "origin": "capture:link",
        "outputs": [{"workspace_path": app["workspace_path"], "sha256": app["sha256"]}],
        "inputs": [{"workspace_path": item["workspace_path"], "sha256": item["sha256"],
                    "mapping_confidence": 1.0} for item in linked]})
    return {
        "build_unit_id": unit, "fingerprint": "a" * 64, "family": "native",
        "recipe_identity": "b" * 64, "probe_identity": "c" * 64, "upstream_handoff_sha256": "d" * 64,
        "image": {"image_id": "sha256:" + "e" * 64}, "executor_identity": "executor/1",
        "capture_identity": "capture/1",
        "commands": [{"command_id": "compile", "argv_sha256": "1" * 64, "role": "build",
                      "tool_kind": "compiler-driver"},
                     {"command_id": "link", "argv_sha256": "2" * 64, "role": "build",
                      "tool_kind": "linker-driver"}],
        "tool_invocations": CountingList(invocations),
        "relationships": CountingList({"artifact_sha256": item["sha256"], "command_id": "compile",
                                       "confidence": 0.9, "mapping": "fixture"} for item in objects),
        "validated_artifacts": [*objects, app],
    }


def _unit(run_root: Path, receipt: dict[str, object]) -> SimpleNamespace:
    return SimpleNamespace(
        unit_id="index.relationships", output=lambda _name: {"receipts": [receipt]},
        job=SimpleNamespace(run_root=run_root, source_fingerprint=SNAPSHOT,
                            config=SimpleNamespace(settings=SETTINGS)))


def _limits(monkeypatch, *, artifacts: int | None = None, rows: int | None = None) -> None:
    if artifacts is not None:
        monkeypatch.setattr(job_module, "MAX_ARTIFACTS_PER_SHARD", artifacts)
    if rows is not None:
        monkeypatch.setattr(job_module, "MAX_ROWS_PER_SHARD", rows)


def _coverage_areas(run_root: Path, identity: dict[str, object]) -> list[str]:
    with sqlite3.connect(run_root / str(identity["relative_path"])) as database:
        return [row[0] for row in database.execute("SELECT area FROM coverage ORDER BY area")]


@pytest.mark.parametrize("count", [50, 500])
def test_one_build_unit_under_the_limits_is_one_shard(tmp_path: Path, count: int) -> None:
    receipt = _receipt(count)
    result = _relationships(_unit(tmp_path, receipt))
    assert [item["shard_id"] for item in result["indexes"]] == [f"relations-{UNIT}-0000"]
    producer = result["indexes"][0]["producer"]
    assert producer == {"job": "job_artifact_indexing", "unit": "index.relationships",
                        "family": "relationships", "build_unit_id": UNIT, "batch": 0, "batch_count": 1}
    assert len(_coverage_areas(tmp_path, result["indexes"][0])) == count + 1
    assert result["gaps"] == [] and result["terminal_status"] == "SUCCEEDED"


def test_artifact_limit_packs_sorted_artifacts_into_stable_batches(tmp_path: Path, monkeypatch) -> None:
    _limits(monkeypatch, artifacts=20)
    receipt = _receipt(50)
    result = _relationships(_unit(tmp_path, receipt))
    shard_ids = [item["shard_id"] for item in result["indexes"]]
    assert shard_ids == [f"relations-{UNIT}-{index:04d}" for index in range(3)]
    assert [(item["producer"]["batch"], item["producer"]["batch_count"]) for item in result["indexes"]] == [
        (0, 3), (1, 3), (2, 3)]
    areas = [_coverage_areas(tmp_path, item) for item in result["indexes"]]
    assert [len(batch) for batch in areas] == [20, 20, 11]
    expected = sorted(str(item["workspace_path"]) for item in receipt["validated_artifacts"])
    assert [area for batch in areas for area in batch] == expected


def test_a_single_artifact_over_the_row_limit_gets_its_own_shard(tmp_path: Path, monkeypatch) -> None:
    _limits(monkeypatch, rows=10)
    result = _relationships(_unit(tmp_path, _receipt(15)))
    areas = [_coverage_areas(tmp_path, item) for item in result["indexes"]]
    # build/app has 15 LINKS_INTO rows plus its producer; each object has two producer rows
    # (receipt attribution and tool invocation), so five objects fill a 10-row batch.
    assert areas[0] == ["build/app"]
    assert [len(batch) for batch in areas] == [1, 5, 5, 5]
    with sqlite3.connect(tmp_path / result["indexes"][0]["relative_path"]) as database:
        assert database.execute("SELECT count(*) FROM relations WHERE kind='LINKS_INTO'").fetchone()[0] == 15


def test_per_artifact_work_does_not_rescan_receipt_rows(tmp_path: Path, monkeypatch) -> None:
    passes = {}
    for label, count, artifacts in (("small", 50, None), ("large", 500, None), ("batched", 50, 20)):
        if artifacts is not None:
            _limits(monkeypatch, artifacts=artifacts)
        receipt = _receipt(count)
        _relationships(_unit(tmp_path / label, receipt))
        passes[label] = (receipt["tool_invocations"].passes, receipt["relationships"].passes)
    assert passes["small"] == passes["large"] == passes["batched"]
    assert max(passes["small"]) <= 3


def test_input_order_does_not_change_shard_identity_or_bytes(tmp_path: Path, monkeypatch) -> None:
    _limits(monkeypatch, artifacts=20)
    first = _relationships(_unit(tmp_path / "first", _receipt(50)))
    shuffled = _receipt(50)
    random.Random(3).shuffle(shuffled["validated_artifacts"])
    second = _relationships(_unit(tmp_path / "second", shuffled))
    assert [(item["shard_id"], item["fingerprint"], item["sha256"]) for item in first["indexes"]] == [
        (item["shard_id"], item["fingerprint"], item["sha256"]) for item in second["indexes"]]


def test_resume_reuses_completed_batches_and_rebuilds_only_missing_ones(tmp_path: Path, monkeypatch) -> None:
    _limits(monkeypatch, artifacts=20)
    receipt = _receipt(50)
    unit = _unit(tmp_path, receipt)
    first = _relationships(unit)
    missing = tmp_path / first["indexes"][1]["relative_path"]
    missing.unlink()
    built: list[str] = []
    original = IndexBuilder.build

    def tracked(self):
        built.append(self.shard_id)
        return original(self)

    monkeypatch.setattr(IndexBuilder, "build", tracked)
    second = _relationships(unit)
    assert built == [f"relations-{UNIT}-0001"]
    assert second["reused_count"] == second["shard_count"] - 1 == 2
    assert [item["sha256"] for item in second["indexes"]] == [item["sha256"] for item in first["indexes"]]


@pytest.mark.parametrize("unit", ["unit/escape", "unit with space", "u" * 120])
def test_batch_shard_ids_are_bounded_and_portable(unit: str) -> None:
    with pytest.raises(ArtifactIndexIntegrityError, match="shard id is invalid"):
        _batch_shard_id("relations", unit, 0)
    assert _batch_shard_id("members", "build-unit-1", 12) == "members-build-unit-1-0012"


def test_receipt_context_and_layout_binding_in_fingerprints(monkeypatch) -> None:
    receipt = _receipt(5)
    artifacts = receipt["validated_artifacts"]
    arguments = dict(name="artifacts", target_snapshot=SNAPSHOT, receipt=receipt, artifacts=artifacts,
                     upstream_manifests=_manifest_entries(receipt, artifacts), extractor_identity="none",
                     parser_identity="parser/1", normalizer_identity="normalizer/1",
                     mapping_identity="mapping/1")
    context = _ReceiptContext.build(receipt, SNAPSHOT)
    plain = artifact_index_fingerprint(**arguments)
    assert artifact_index_fingerprint(**arguments, receipt_context=context) == plain
    layout = artifact_index_fingerprint(**arguments, shard_layout=_shard_layout())
    assert layout != plain
    assert artifact_index_fingerprint(**arguments, receipt_context=context,
                                      shard_layout=_shard_layout()) == layout
    _limits(monkeypatch, rows=99)
    assert artifact_index_fingerprint(**arguments, shard_layout=_shard_layout()) != layout
    with pytest.raises(ArtifactIndexIntegrityError, match="another receipt"):
        artifact_index_fingerprint(**arguments, receipt_context=_ReceiptContext.build(_receipt(5), SNAPSHOT))


def test_batched_job_output_equals_the_per_artifact_baseline(tmp_path: Path) -> None:
    """Catalog fingerprints are unchanged and the union of rows equals the per-artifact layout."""
    config, target, snapshot, run_root, *_ = _seed(tmp_path)
    GraphRunner(config, [build_job()]).run(target_root=target, source_fingerprint=snapshot, run_id=RUN_ID)
    manifest = RetrievalCore(config.runtime.runs_dir, RUN_ID).manifest
    catalogs, relations, coverage, shard_ids = {}, [], [], []
    for item in manifest["indexes"]:
        if item["name"] != "artifacts":
            continue
        if item["shard_id"].startswith("catalog-"):
            catalogs[item["shard_id"]] = item["fingerprint"]
            continue
        shard_ids.append(item["shard_id"])
        family = item["shard_id"].split("-", 1)[0]
        with sqlite3.connect(run_root / item["relative_path"]) as database:
            relations.extend([family, *row] for row in database.execute(
                "SELECT relation_id, kind, source_id, target_id, exact, confidence, ambiguity, payload_json "
                "FROM relations"))
            coverage.extend([family, *row] for row in database.execute(
                "SELECT area, status, gap FROM coverage"))
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert snapshot == baseline["snapshot"]
    assert catalogs == baseline["catalogs"]
    assert sorted(relations) == baseline["relations"]
    assert sorted(coverage, key=json.dumps) == baseline["coverage"]
    assert sorted({gap for item in manifest["indexes"] if item["name"] == "artifacts"
                   and not item["shard_id"].startswith("catalog-") for gap in item["gaps"]}) == baseline["gaps"]
    assert sorted(shard_ids) == sorted([
        *(f"relations-build-unit-0000000000000000000{index}-0000" for index in range(1, 5)),
        "members-build-unit-00000000000000000004-0000"])


def _scaled_native_run(tmp_path: Path, count: int, *, build_families: tuple[str, ...] = ("native",)):
    tmp_path.mkdir(parents=True)
    config, target, snapshot, run_root, receipts, accepted, handoff, latest = _seed(
        tmp_path, build_families=build_families)
    receipt = receipts[0]
    unit = receipt["build_unit_id"]
    workspace = run_root / receipt["workspace"]
    artifacts, files = [], {}
    for relative, kind, content in [
            *((f"build/obj/unit-{index:05d}.o", "object", f"object-{index}".encode()) for index in range(count)),
            ("build/app", "executable", b"\x7fELFapp")]:
        path = workspace / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        files[relative] = file_sha256(path)
        artifacts.append({**_identity(run_root, path), "workspace_path": relative, "kind": kind,
                          "build_unit_id": unit, "mapping": "exact-workspace-path",
                          "mapping_confidence": 1.0})
    manifest = workspace.parent / "workspace-manifest.json"
    atomic_json(manifest, {"schema": "appsec-review/build-workspace-manifest/1",
                           "build_unit_id": unit, "files": files})
    receipt["workspace_manifest"] = _identity(run_root, manifest)
    receipt["artifacts"] = artifacts
    receipt["commands"].append({**receipt["commands"][0], "command_id": "command-link",
                                "argv_sha256": "c" * 64, "tool_kind": "linker-driver"})
    objects, app = artifacts[:-1], artifacts[-1]
    receipt["tool_invocations"] = [
        *({"tool": "cc", "tool_kind": "compiler", "parent_command_id": "command-1",
           "mapping_confidence": 1.0, "origin": f"capture:{index}", "inputs": [],
           "outputs": [{"workspace_path": item["workspace_path"], "sha256": item["sha256"]}]}
          for index, item in enumerate(objects)),
        {"tool": "ld", "tool_kind": "linker", "parent_command_id": "command-link",
         "mapping_confidence": 1.0, "origin": "capture:link",
         "outputs": [{"workspace_path": app["workspace_path"], "sha256": app["sha256"]}],
         "inputs": [{"workspace_path": item["workspace_path"], "sha256": item["sha256"],
                     "mapping_confidence": 1.0} for item in objects]}]
    _publish_changed_language_receipts(run_root, receipts, accepted, handoff, latest)
    return config, target, snapshot, run_root, handoff


@pytest.fixture
def fsyncs(monkeypatch):
    import os
    calls: list[int] = []
    real = os.fsync

    def counted(descriptor):
        calls.append(descriptor)
        return real(descriptor)

    monkeypatch.setattr(os, "fsync", counted)
    return calls


def _measure_relationships(tmp_path: Path, count: int, fsyncs: list[int], monkeypatch) -> dict[str, object]:
    config, target, snapshot, run_root, handoff = _scaled_native_run(tmp_path, count)
    job = build_job()
    runner = JobRunner(config)
    claim = runner.begin_attempt(job, run_id=RUN_ID, target_root=target, source_fingerprint=snapshot,
                                 upstream_handoffs={"job_language_build": file_sha256(handoff)})
    runner.execute_or_reuse_unit(job, claim, "load.accepted_builds")
    builds: list[dict[str, int]] = []
    original = IndexBuilder.build
    probe = EventLog(tmp_path / "probe-events.jsonl")

    def measured(self):
        before = len(fsyncs)
        # count_work feeds only the innermost span, so this keeps build work out of the unit span.
        with operation_span(probe, "test.index_build") as span:
            digest = original(self)
        builds.append({**span.counters, "fsync": len(fsyncs) - before})
        return digest

    monkeypatch.setattr(IndexBuilder, "build", measured)
    fsyncs.clear()
    result = runner.execute_or_reuse_unit(job, claim, "index.relationships")
    monkeypatch.setattr(IndexBuilder, "build", original)
    records = [json.loads(line) for path in sorted(
        (run_root / "data" / "jobs" / "job_artifact_indexing").rglob("events.jsonl"))
        for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    unit_work = [record["work"] for record in records if record.get("event") == "OPERATION_COMPLETED"
                 and record.get("operation_id") == "unit.execute"
                 and record.get("unit_id") == "index.relationships"]
    assert len(unit_work) == 1
    return {"shards": result["shard_count"], "builds": builds, "residual": unit_work[0],
            "residual_fsync": len(fsyncs) - sum(build["fsync"] for build in builds)}


def test_relationship_unit_io_is_bounded_per_shard_and_constant_elsewhere(
        tmp_path: Path, fsyncs, monkeypatch) -> None:
    runs = {"small": _measure_relationships(tmp_path / "small", 50, fsyncs, monkeypatch),
            "large": _measure_relationships(tmp_path / "large", 500, fsyncs, monkeypatch)}
    _limits(monkeypatch, artifacts=20)
    runs["batched"] = _measure_relationships(tmp_path / "batched", 50, fsyncs, monkeypatch)
    assert {label: run["shards"] for label, run in runs.items()} == {"small": 1, "large": 1, "batched": 3}
    for run in runs.values():
        assert len(run["builds"]) == run["shards"]
        for build in run["builds"]:
            assert build["fsync"] <= 4
            assert build.get("target_hash_objects", 0) <= 2
            assert build.get("copy_objects", 0) == 0
            assert build.get("custody_alias_objects") == 1
        assert run["residual"].get("copy_objects", 0) == 0
    residual = {label: (run["residual"].get("target_hash_objects", 0), run["residual_fsync"])
                for label, run in runs.items()}
    assert residual["small"] == residual["large"] == residual["batched"]
