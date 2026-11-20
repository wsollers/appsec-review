"""Sanitizer publication through canonical admission, indexing and bounded retrieval; no execution."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import fields, replace
import json
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_language_build.datasets import DATASETS as LANGUAGE_DATASETS
from appsec_review.jobs.job_review_data_indexing import job as indexing
from appsec_review.jobs.job_sanitizer_build import job as sanitizer
from appsec_review.observability import EventLog
from appsec_review.retrieval import RetrievalCore, write_manifest
from appsec_review.runtime import JobContext, UnitContext
from appsec_review.runtime.datasets import dataset_contract
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.runtime.runner import JobRunner
from appsec_review.storage import atomic_json, canonical_json, file_sha256
from appsec_review.storage.shared import attempt_artifacts
from tests.handoff_fixture import write_fixture_handoff
from tests.sanitizer_support import ASAN_UNDEFINED, DockerFake, elf_with_symbols
from .test_handlers import ROOT, _synthetic_fixture


def _project(context, job_id, datasets, outputs, *, pins=None):
    root = context.run_root
    attempt = root / "data" / "jobs" / job_id / "attempts" / context.attempt_id
    context.attempt_root = attempt
    context.run_id = root.name
    context.config.job_id = job_id
    context.orchestration = {"system": "unit", "run_id": "sanitizer-readiness"}
    if not (attempt / "claim.json").is_file():
        atomic_json(attempt / "claim.json", {
            "dataset_contract": dataset_contract(
                job_id, sorted({item.step for item in datasets} | {key.split(".")[0] for key in outputs}), datasets)})
    completion = outputs[next(reversed(outputs))].get("terminal_status", "SUCCEEDED")
    path = write_fixture_handoff(root, attempt / "handoff.json", {
        "job_id": job_id, "completion_status": completion, "outputs": outputs,
        "artifacts": attempt_artifacts(root, attempt),
        "upstream_handoff_sha256": pins or {},
    }, target_snapshot=context.source_fingerprint)
    prior = json.loads(path.read_bytes())
    claim = json.loads((attempt / "claim.json").read_bytes())
    claim.update(component_identities={"implementation": "unit/1", "schema": "unit/1", "validation": "unit/1"},
                 started_at=prior["started_at"], job_config_sha256=prior["job_config_sha256"])
    projected = JobRunner(context.app_config)._handoff_document(
        context, claim, {"status": completion, "outputs": outputs},
        json.loads((attempt / "outcomes.json").read_bytes()), prior["outcomes"],
        accepted=True, completed=prior["completed_at"], artifacts=prior["artifacts"])
    atomic_json(path, projected)
    return path, projected


def publish_sanitizer(base, *, mode="honor_env", receipts_mode="built", max_units=4, mutate_summary=None):
    config, target, snapshot, root, receipt, ctx = _synthetic_fixture(
        base, settings_override={"max_units": max_units})
    root = root.rename(base / "2026-11-20-5182")
    ctx.job.run_root = root
    JobRunner(config)._bind_configuration(root)
    # Keep the accepted language-build fixture in its real declared protected/receipt datasets.
    private = root / "data/build/native"
    private.mkdir(parents=True)
    commands = root / "data/jobs/job_language_build/protected"
    shutil.move(str(commands), str(private / "protected"))
    normal = root / "data/language_build"
    shutil.move(str(normal), str(private / "normal"))
    for command in receipt["commands"]:
        command["protected_argv"]["path"] = command["protected_argv"]["path"].replace(
            "data/jobs/job_language_build/protected", "data/build/native/protected")
    for artifact in receipt["artifacts"]:
        artifact["path"] = artifact["path"].replace("data/language_build", "data/build/native/normal")
    receipt.update(build_outcome="built", terminal_status="COMPLETED_WITH_GAPS",
                   gaps=["provenance unavailable"])
    receipts = [receipt]
    if receipts_mode == "mixed":
        receipts += [{**deepcopy(receipt), "build_unit_id": "unit-2"},
                     {**deepcopy(receipt), "build_unit_id": "unit-jvm", "family": "jvm"}]
    elif receipts_mode == "nonnative":
        receipts = [{**receipt, "family": "jvm"}]
    manifest = root / "data/indices/manifests/language-build.json"
    write_manifest(manifest, run_id=root.name, target_snapshot=snapshot, target_root=target, indexes=[])
    document = root / "data/jobs/job_language_build/attempts/attempt_0001/artifacts/language-build/receipts.json"
    atomic_json(document, {"schema": "appsec-review/language-build-handoff/2",
                          "source_fingerprint": snapshot, "receipts": receipts})
    upstream, _ = _project(ctx.job, "job_language_build", LANGUAGE_DATASETS, {
        "acceptance.publish_handoff": {"artifact": sanitizer._artifact(root, document),
                                       "index_manifest": sanitizer._artifact(root, manifest)}})
    class AddressOnlyBuild(DockerFake):
        def _build(self, root, environment):
            (root / "address-only").write_bytes(elf_with_symbols(undefined=ASAN_UNDEFINED))

    build_fake = AddressOnlyBuild if mode == "address_only" else DockerFake
    job = sanitizer.build_job(executor_factory=lambda _u, p: build_fake(
        p, mode=mode, fail_ordinal=1 if mode == "missing_runtime" else None).executor())
    ctx.job.config.job_id = sanitizer.JOB_ID
    ctx.job.contract = job.contract
    ctx.job.upstream_handoffs = {"job_language_build": file_sha256(upstream)}
    outputs = {}
    with input_read_scope(ctx.job):
        for unit in job.units:
            step, task = unit.unit_id.split(".")
            directory = root / f"data/jobs/{sanitizer.JOB_ID}/attempts/attempt_0001/steps/{step}/tasks/{task}"
            directory.mkdir(parents=True, exist_ok=True)
            outputs[unit.unit_id] = unit.handler(UnitContext(ctx.job, unit.unit_id, step, task, directory, outputs))
    if mutate_summary is not None:
        published = outputs["acceptance.publish_handoff"]
        path = root / published["artifact"]["path"]
        document = json.loads(path.read_bytes())
        mutate_summary(document)
        atomic_json(path, document)
        published["artifact"] = sanitizer._artifact(root, path)
    path, projected = _project(ctx.job, sanitizer.JOB_ID, sanitizer.DATASETS, outputs,
                               pins=ctx.job.upstream_handoffs)
    assert "units" not in projected["outputs"]["build.units"]
    assert projected["outputs"]["acceptance.publish_handoff"]["artifact"] == outputs[
        "acceptance.publish_handoff"]["artifact"]
    return SimpleNamespace(config=config, root=root, target=target, snapshot=snapshot,
                           manifest=manifest, handoff=path, upstream=upstream, outputs=outputs)


def readiness_core(base, *, supplied=True, **kwargs):
    case = publish_sanitizer(base, **kwargs)
    attempt = case.root / f"data/jobs/{indexing.JOB_ID}/attempts/attempt_0001"
    cfg = case.config.job(indexing.JOB_ID)
    cfg = replace(cfg, workers=2, settings={**cfg.settings, "fts_image_validation": "disabled"})
    context = JobContext(
        run_id=case.root.name, attempt_id=attempt.name, trigger="unit", repository_root=ROOT,
        run_root=case.root, attempt_root=attempt, metadata_root=base / "metadata",
        orchestration={"system": "unit", "run_id": "sanitizer-readiness"}, config=cfg,
        events=EventLog(attempt / "logs/events.jsonl"), target_root=case.target,
        source_fingerprint=case.snapshot, input_manifest_path=case.manifest,
        input_manifest_sha256=file_sha256(case.manifest), contract=indexing.CONTRACT,
        upstream_handoffs={"job_language_build": file_sha256(case.upstream),
                          **({sanitizer.JOB_ID: file_sha256(case.handoff)} if supplied else {})})
    atomic_json(attempt / "claim.json", {
        "run_id": case.root.name, "job_id": indexing.JOB_ID, "attempt_id": attempt.name,
        "attempt_path": attempt.relative_to(case.root).as_posix(), "source_fingerprint": case.snapshot,
        "resolved_config_sha256": file_sha256(case.root / "data/configuration/resolved.json"),
        "input_identity": None, "upstream_handoffs": dict(context.upstream_handoffs),
        "orchestration": dict(context.orchestration), "dataset_contract": dataset_contract(
            indexing.JOB_ID, tuple(indexing.TOPOLOGY), indexing.DATASETS)})
    with input_read_scope(context) as reads:
        result = indexing.build_job().handler(context)
    assert "publish.inventory_index" in result["outputs"], result
    output = result["outputs"]["publish.inventory_index"]
    projected_context = SimpleNamespace(
        **{field.name: getattr(context, field.name) for field in fields(context)}, app_config=case.config)
    projected_context.config = SimpleNamespace(job_id=indexing.JOB_ID)
    path, _ = _project(projected_context, indexing.JOB_ID, indexing.DATASETS, result["outputs"],
                       pins=dict(context.upstream_handoffs))
    atomic_json(case.root / "data/indices/accepted.json", {
        "schema": "appsec-review/accepted-index-set/1", "run_id": case.root.name,
        "handoff_path": path.relative_to(case.root).as_posix(), "handoff_sha256": file_sha256(path),
        "manifest_path": output["index_manifest"]["path"], "manifest_sha256": output["index_manifest"]["sha256"]})
    case.reads = reads.document()["reads"]
    case.indexing_result = result
    return RetrievalCore(case.root.parent, case.root.name), case


def test_real_sanitizer_publication_reaches_per_unit_query(tmp_path, monkeypatch):
    core, case = readiness_core(tmp_path)
    original = Path.read_bytes

    def no_protected_reads(path):
        assert case.root / "data/sanitizer" not in path.parents
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", no_protected_reads)
    response = core.query_sanitizer_readiness(build_unit="unit-1", sanitizer="asan")
    assert len(response["results"]) == 1
    row = response["results"][0]["payload"]
    assert row["status"] == "ready"
    assert row["output_count"] == 2
    assert row["runtime_referenced_output_count"] == 2
    assert row["runtime_verification"] == "not_performed"
    assert row["source_fingerprint"] == case.snapshot
    assert row["run_id"] == case.root.name and row["attempt_id"] == "attempt_0001"
    assert row["handoff_sha256"] == file_sha256(case.handoff)
    assert row["summary_reference"]["sha256"] == case.outputs["acceptance.publish_handoff"]["artifact"]["sha256"]
    assert row["language_build_handoff_sha256"] == file_sha256(case.upstream)
    assert row["receipt_fingerprint"] == "1" * 64
    assert row["image_id"] == "sha256:" + "b" * 64
    assert any(read["output_kind"] == "sanitizer_build_summary" for read in case.reads)
    assert not any(read["output_kind"] == "sanitizer_build_workspaces" for read in case.reads)
    assert "protected-commands" not in json.dumps(response)
    assert "CXXFLAGS" not in json.dumps(response)
    assert not core.query_sanitizer_readiness(build_unit="foreign-unit")["results"]
    assert not core.query_sanitizer_readiness(sanitizer="a")["results"]
    assert len(core.query_sanitizer_readiness(sanitizer="UBSAN", status="ready")["results"]) == 1


@pytest.mark.parametrize("mode,status,count,referenced", [
    ("ignore_env", "partial", 2, 0),
    ("stripped", "partial", 2, None),
    ("missing_runtime", "unavailable", None, None),
    ("no_binaries", "partial", 0, 0),
])
def test_incomplete_builds_keep_measured_zero_distinct_from_unknown(tmp_path, mode, status, count, referenced):
    core, _ = readiness_core(tmp_path, mode=mode)
    response = core.query_sanitizer_readiness(build_unit="unit-1", sanitizer="address", status=status)
    row, = response["results"]
    assert row["payload"]["output_count"] == count
    assert row["payload"]["runtime_referenced_output_count"] == referenced
    assert row["payload"]["instrumented"] is False
    assert row["payload"]["gaps"] and response["coverage_gaps"]
    assert not core.query_sanitizer_readiness(status="ready")["results"]


def test_omitted_and_nonnative_units_survive_pagination_and_projection_bounds(tmp_path):
    from appsec_review.indexing.products import sanitizer_readiness

    core, case = readiness_core(tmp_path, receipts_mode="mixed", max_units=1)
    rows = []
    cursor = None
    for _ in range(7):
        response = core.query_sanitizer_readiness(limit=1, cursor=cursor)
        rows.extend(response["results"])
        cursor = response["pagination"]["next_cursor"]
        if cursor is None:
            break
    assert cursor is None
    assert len(rows) == 6 and len({row["identity"] for row in rows}) == 6
    assert {row["payload"]["record_type"] for row in rows} == {"sanitizer_readiness"}
    omitted, = core.query_sanitizer_readiness(build_unit="unit-2", sanitizer="asan")["results"]
    assert omitted["payload"]["status"] == "unavailable"
    assert omitted["payload"]["output_count"] is None and omitted["payload"]["gaps"]
    nonnative, = core.query_sanitizer_readiness(build_unit="unit-jvm", sanitizer="asan")["results"]
    assert nonnative["payload"]["status"] == "not_applicable"
    assert nonnative["payload"]["output_count"] is None and not nonnative["payload"]["gaps"]
    load = case.indexing_result["outputs"]["load.accepted_inputs"]["artifact"]
    accepted = json.loads((case.root / load["path"]).read_bytes())["sanitizer"]
    bounded = sanitizer_readiness(case.snapshot, accepted, 1)
    assert len(bounded.entities) == 1
    assert bounded.counts == {"rows": 1, "omitted_rows": 5}
    assert any("5 sanitizer readiness row(s)" in gap for gap in bounded.gaps)
    assert bounded.coverage[0][1] == "partial"
    events = [json.loads(line) for line in (case.root /
              "data/jobs/job_review_data_indexing/attempts/attempt_0001/logs/events.jsonl").read_text().splitlines()]
    telemetry = next(event["metrics"] for event in events if event["event"] == "INDEXING_TELEMETRY_RECORDED")
    assert telemetry["build_security.sanitizer_readiness_indexed"] == 6
    first = core.query_sanitizer_readiness(limit=1)
    with pytest.raises(ValueError, match="cursor"):
        core.query_sanitizer_readiness(limit=1, sanitizer="asan", cursor=first["pagination"]["next_cursor"])
    sample = core.query_sanitizer_readiness(limit=3)
    bound = (len(canonical_json(first)) + len(canonical_json(sample))) // 2
    core.limits = replace(core.limits, max_response_bytes=bound)
    paged, cursor = [], None
    for _ in range(7):
        response = core.query_sanitizer_readiness(limit=3, cursor=cursor)
        assert len(canonical_json(response)) <= bound
        paged.extend(row["identity"] for row in response["results"])
        cursor = response["pagination"]["next_cursor"]
        if cursor is None:
            break
    assert cursor is None and paged == [row["identity"] for row in rows]


def test_unsupplied_sanitizer_does_not_turn_generic_inventory_into_readiness(tmp_path):
    core, case = readiness_core(tmp_path, supplied=False)
    response = core.query_sanitizer_readiness()
    assert not response["results"]
    assert any("no admitted sanitizer" in gap for gap in response["coverage_gaps"])
    assert not any(read["producer"] == sanitizer.JOB_ID for read in case.reads)


def test_optional_sanitizer_is_not_ready_merely_because_required_evidence_succeeded(tmp_path):
    core, case = readiness_core(tmp_path, mode="address_only")
    assert case.outputs["acceptance.publish_handoff"]["terminal_status"] == "SUCCEEDED"
    address, = core.query_sanitizer_readiness(sanitizer="asan")["results"]
    undefined, = core.query_sanitizer_readiness(sanitizer="ubsan")["results"]
    assert address["payload"]["status"] == "ready" and address["payload"]["required"] is True
    assert undefined["payload"]["status"] == "partial" and undefined["payload"]["required"] is False
    assert undefined["payload"]["runtime_referenced_output_count"] == 0
    assert undefined["payload"]["gaps"]
