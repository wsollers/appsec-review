"""Pre-walk throughput suite of job_artifact_indexing, pending replacement (T-113).

The two remaining cases run the job through ``GraphRunner``/``JobRunner`` over a seeded run and count
real ``fsync`` calls, so they are integration tests. Both fail at HEAD 05ac85ae for the same stale
fixture reasons as ``test_artifact_indexing_graph.py``. The batching, shard-id, receipt-context and
rescan claims moved to ``tests/unit/job_artifact_indexing/test_relationships.py`` and
``test_identities.py``. ``_scaled_native_run`` is imported by ``test_artifact_indexing_scale.py``.
"""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3

import pytest

from appsec_review.jobs.job_artifact_indexing import build_job
from appsec_review.jobs.job_artifact_indexing import job as job_module
from appsec_review.observability import EventLog
from appsec_review.observability.spans import operation_span
from appsec_review.retrieval import IndexBuilder, RetrievalCore
from appsec_review.runtime import GraphRunner
from appsec_review.runtime.runner import JobRunner
from appsec_review.storage import atomic_json, file_sha256
from tests.integration.job_artifact_indexing.test_artifact_indexing_graph import RUN_ID, _identity, _publish_changed_language_receipts, _seed

BASELINE = Path(__file__).parents[2] / "fixtures" / "artifact_indexing" / "per-artifact-baseline.json"


def _limits(monkeypatch, *, artifacts: int | None = None, rows: int | None = None) -> None:
    if artifacts is not None:
        monkeypatch.setattr(job_module, "MAX_ARTIFACTS_PER_SHARD", artifacts)
    if rows is not None:
        monkeypatch.setattr(job_module, "MAX_ROWS_PER_SHARD", rows)


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
