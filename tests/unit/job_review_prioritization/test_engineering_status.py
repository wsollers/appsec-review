"""Status seams: real producer publication slices -> JobRunner -> admitted loaders.

Normalized upstream inputs are deterministic unit fixtures. Acquisition, scanners and inference
are not executed; the producer publication, envelope lifecycle and consumer readers are real.
"""
from dataclasses import asdict, replace
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.interchange import producer_gap
from appsec_review.jobs.job_review_prioritization import composite
from appsec_review.jobs.job_review_prioritization.datasets import CONTRACT
from appsec_review.retrieval import EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity, write_manifest
from appsec_review.runtime import Job, Unit
from appsec_review.runtime.consume import accepted_upstream, upstream_scope
from appsec_review.runtime.contracts import JobContract
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.runtime.registry import builtin_registry
from appsec_review.storage import atomic_json, file_sha256
from appsec_review.storage.validation import validation_scope
from tests.unit.runtime.test_wave3_contracts import _recorded_catalog_run


CASES = (
    ("job_change_context_analysis", "publish.publish_handoff", "_load_change_context"),
    ("job_profile_data", "acceptance.publish_handoff", "_load_profile_data"),
    ("job_ci_configuration_analysis", "ci_coverage.publish_handoff", "_load_ci_leads"),
    ("job_artifact_security_analysis", "acceptance.publish_handoff", "_load_artifact_leads"),
    ("job_dependency_intelligence", "acceptance.publish_handoff", "_load_sca_reachability"),
)
CASE_IDS = ("change", "profile", "ci", "artifact", "sca")


def _ref(root, path):
    return {"path": path.relative_to(root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def _fixture_outputs(unit, producer, partial):
    root, snapshot = unit.job.run_root, unit.job.source_fingerprint

    def document(name, value):
        path = unit.unit_root / name
        atomic_json(path, value)
        return _ref(root, path)

    def shard(name, shard_id, *, observation=False):
        fingerprint = hashlib.sha256(shard_id.encode()).hexdigest()
        path = root / "data/indices" / name / f"{fingerprint}.sqlite"
        builder = IndexBuilder(path, name=name, fingerprint=fingerprint,
                               target_snapshot=snapshot, shard_id=shard_id)
        if observation:
            identity = LogicalIdentity.derive(EntityKind.TOOL_OBSERVATION, snapshot, {"fixture": shard_id})
            builder.add_entity(EntityRecord(identity, "fixture", "fixture", "fixture observation", {
                "lead_candidate": True, "rule_id": "fixture-rule", "severity_hint": "high",
                "message": "fixture observation"}))
        return asdict(IndexIdentity(name, "appsec-review/retrieval-index/2", builder.build(),
                                    fingerprint, path.relative_to(root).as_posix(),
                                    {"job": producer}, (), shard_id))

    manifest_path = root / "data/indices/manifests/status-fixture.json"
    indexes = []
    if producer == "job_artifact_security_analysis":
        indexes.append(shard("observations", "artifact-security-fixture", observation=True))
    write_manifest(manifest_path, run_id=unit.job.run_id, target_snapshot=snapshot,
                   target_root=unit.job.target_root, indexes=[IndexIdentity(**item) for item in indexes])
    manifest = _ref(root, manifest_path)
    gaps = ["fixture_normalized_input_incomplete"] if partial else []

    if producer == "job_change_context_analysis":
        ranking = document("ranking.json", {
            "files": {"fixture-file": {"path": "src/main.c",
                                       "priority": {"rank": 1, "score": 0.8, "coverage": 1.0}}},
            "rankings": {"files": ["fixture-file"]}})
        outputs = {
            "load.accepted_history": {"available": True, "history_handoff_sha256": "a" * 64,
                                      "history_identity": "fixture", "gaps": gaps},
            "load.external_sources": {"sources": {
                name: {"status": "complete", "gaps": []}
                for name in ("review", "deployment", "organization", "schedule", "test_association")}},
            "attribute.line_attribution": {"gaps": []},
            "attribute.fix_on_fix": {"gaps": []},
            "analyze.change_signals": {"gaps": []},
            "analyze.rank": {"artifact": ranking},
            "publish.index_change_context": {"manifest": manifest},
        }
    elif producer == "job_profile_data":
        outputs = {
            "load.accepted_inputs": {"upstream_handoffs": {}, "gaps": gaps},
            "normalize.profile_data": {"gaps": [], "interpretation": "unit fixture",
                                       "units": [{"build_unit_id": "u1", "rows": [
                                           {"source": "src/main.c", "symbol": "hot", "line": 1, "count": 10}]}]},
            "index.profile_data": {"index_manifest": manifest},
        }
    elif producer == "job_ci_configuration_analysis":
        from appsec_review.jobs.job_ci_configuration_analysis.job import SPECS
        gap_records = [producer_gap(
            "input_unavailable", "fixture_normalized_input_incomplete", unit_id=unit.unit_id)] if partial else []
        outputs = {
            f"ci_observation_publication.{spec.key}_index": {
                "index_identity": shard("observations", f"ci_{spec.key}")}
            for spec in SPECS}
        finding = {"lead_candidate": True, "path": "src/main.c", "line": 1,
                   "rule_id": "fixture-rule", "severity_hint": "high", "message": "fixture finding"}
        outputs["ci_correlation.correlate_findings"] = {
            "index_identity": shard("evidence", "ci_findings"), "artifact": document("findings.json", {}),
            "finding_count": 1, "findings": [finding]}
        outputs["ci_coverage.join_coverage"] = {
            "artifact": document("coverage.json", {}), "gap_records": gap_records,
            "coverage_status": "partial" if partial else "complete", "definitions_by_provider": {"github": 1}}
    elif producer == "job_artifact_security_analysis":
        from appsec_review.jobs.job_artifact_security_analysis.job import CAPABILITIES
        outputs = {f"analyze.{name}": {} for name in CAPABILITIES}
        outputs.update({
            "load.accepted_artifacts": {"language_build_handoff_sha256": "a" * 64,
                                        "artifact_index": {}, "artifact_count": 1, "producer_gaps": []},
            "index.observations": {"observation_count": 1, "finding_count": 1, "record_schema": "fixture",
                                   "index_manifest": manifest, "gaps": gaps},
        })
    else:
        reach_path = unit.job.attempt_root / "steps/publication/tasks/publish_context/sca-reachability.json"
        atomic_json(reach_path, {"schema": "appsec-review/sca-reachability/1", "advisories": [{
            "advisory_id": "OSV-fixture", "package_name": "fixture", "reachability": "symbol_reachable",
            "call_sites": [{"path": "src/main.c", "line": 1}]}]})
        outputs = {
            "inputs.load_accepted": {"upstream_handoffs": {}, "unity_inventory_artifact": None},
            "resolution.infer_repositories": {"dependencies": []},
            "repositories.deduplicate": {"repositories": []},
            "scorecards.fetch": {"records": [], "request_count": 0, "repository_count": 0, "cache_hit_count": 0},
            "publication.publish_context": {"gaps": gaps, "index_identity": None,
                                            "index_manifest": manifest, "sca_reachability": _ref(root, reach_path)},
            "publication.publish_sbom": {},
            "resolution.investigate_components": {"native_discovery": {}, "artifact": None},
            "resolution.detect_dependencies": {"native_discovery": {}},
            "resolution.curate_components": {"artifact": None},
            "publication.native_advisory_lookup": {},
        }
    return outputs, manifest


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
@pytest.mark.parametrize("state", ["complete", "partial", "failed"])
def test_actual_publication_status_reaches_admitted_engineering_loader(tmp_path: Path, case, state):
    producer, publish_id, loader_name = case
    original = builtin_registry().build(producer)
    publisher = next(unit.handler for unit in original.units if unit.unit_id == publish_id)
    first_id = original.units[0].unit_id
    runner, run_id, root, target, snapshot, _, _ = _recorded_catalog_run(tmp_path, (producer,))
    loader = getattr(composite, loader_name)

    def normalized_boundary(unit):
        outputs, manifest = _fixture_outputs(unit, producer, state == "partial")
        result = {"fixture_outputs": outputs, "fixture_manifest": manifest}
        if state == "partial" and producer == "job_ci_configuration_analysis":
            # CI publication succeeds independently of scanner completeness. The runner must retain
            # the normalized upstream gap rather than trust the final unit's SUCCEEDED status.
            result["gaps"] = outputs["ci_coverage.join_coverage"]["gap_records"]
        return result

    def publish(unit):
        seeded = unit.output(first_id)
        context = replace(unit.job, input_manifest_path=root / seeded["fixture_manifest"]["path"],
                          input_manifest_sha256=seeded["fixture_manifest"]["sha256"])
        outputs = {} if state == "failed" else seeded["fixture_outputs"]
        return publisher(replace(unit, job=context, outputs=outputs))

    job = Job(
        producer, original.name, lambda _: {}, schema_identity=original.schema_identity,
        units=(Unit(first_id, normalized_boundary), Unit(publish_id, publish, (first_id,))),
        datasets=tuple(replace(item, required=False) for item in original.datasets),
        contract=JobContract(inputs=()),
    )
    with validation_scope(root), upstream_scope(root, "job_review_prioritization", {}, contract=CONTRACT):
        assert loader(root, True)[0] == "UNAVAILABLE"
        assert loader(root, False)[0] == "DISABLED"
    if state == "failed":
        with pytest.raises(RuntimeError, match="job reported partial failure"):
            runner.run(job, run_id=run_id, target_root=target, source_fingerprint=snapshot)
        assert not (root / f"data/jobs/{producer}/latest.json").exists()
        with validation_scope(root):
            assert loader(root, True)[0] == "UNAVAILABLE"
        return

    result = runner.run(job, run_id=run_id, target_root=target, source_fingerprint=snapshot)
    context = SimpleNamespace(run_root=root, config=SimpleNamespace(job_id="job_review_prioritization"),
                              contract=CONTRACT, upstream_handoffs={producer: result["handoff_sha256"]})
    with validation_scope(root):
        handoff = accepted_upstream(root, producer).handoff
    with validation_scope(root), input_read_scope(context) as reads:
        loaded = loader(root, True)
    if state != "partial" or producer != "job_ci_configuration_analysis":
        assert loaded[0] == handoff["completion_status"]
    assert loaded[0] == ("SUCCEEDED" if state == "complete" else "COMPLETED_WITH_GAPS")
    assert loaded[1], "published payload selection must remain usable"
    receipt = next(row for row in reads.document()["reads"] if row["output_kind"] == "handoff")
    assert receipt["handoff_sha256"] == result["handoff_sha256"]
    assert receipt["target_snapshot"] == snapshot and receipt["read"] is True
    assert receipt["cited"] is None
    if producer == "job_ci_configuration_analysis" and state == "partial":
        assert handoff["outputs"][publish_id]["terminal_status"] == "SUCCEEDED"
        assert handoff["completion_status"] == "SUCCEEDED"
        assert handoff["coverage"]["disposition"] == "partial"
    with validation_scope(root), upstream_scope(root, "job_review_prioritization", {}, contract=CONTRACT):
        assert loader(root, True)[0] == "UNAVAILABLE"
    published = handoff["outputs"][publish_id]
    ref = published["artifact"]
    if producer == "job_dependency_intelligence":
        ref = composite.read_json(root, ref)["sca_reachability"]
    (root / ref["path"]).write_bytes(b"{}")
    expected = ("consumed output bytes changed" if producer == "job_dependency_intelligence"
                else "accepted artifact identity changed")
    with validation_scope(root), pytest.raises(ValueError, match=f"^{expected}$"):
        with input_read_scope(context):
            loader(root, True)


@pytest.mark.parametrize(("handoff", "publication", "expected"), [
    ({"completion_status": "COMPLETED_WITH_GAPS"}, {"terminal_status": "SUCCEEDED"}, "COMPLETED_WITH_GAPS"),
    ({"completion_status": "FAILED"}, {"terminal_status": "SUCCEEDED"}, "FAILED"),
    ({"completion_status": "UNAVAILABLE"}, {"terminal_status": "SUCCEEDED"}, "UNAVAILABLE"),
    ({"terminal_status": "FAILED"}, {"terminal_status": "SUCCEEDED"}, "FAILED"),
    ({"terminal_status": "PARTIAL"}, {"terminal_status": "SUCCEEDED"}, "PARTIAL"),
    ({}, {"terminal_status": "NOT_APPLICABLE"}, "NOT_APPLICABLE"),
    ({}, {"terminal_status": "SUCCEEDED"}, "SUCCEEDED"),
    ({}, {}, "UNAVAILABLE"),
    ({"completion_status": "SUCCEEDED", "coverage": {"disposition": "partial"}}, {}, "COMPLETED_WITH_GAPS"),
    ({"completion_status": "SUCCEEDED", "coverage": {"disposition": "unavailable"}}, {}, "UNAVAILABLE"),
    ({"completion_status": "SUCCEEDED", "execution_status": "FAILED"}, {}, "FAILED"),
    ({"coverage": {"disposition": "complete"}}, {}, "UNAVAILABLE"),
], ids=["modern-partial", "modern-failed", "modern-unavailable", "legacy-failed",
        "legacy-partial", "domain-not-applicable", "domain-success", "missing",
        "coverage-partial", "coverage-unavailable", "execution-failed", "missing-completion"])
def test_completion_status_preserves_legacy_and_non_success_controls(handoff, publication, expected):
    assert composite._completion_status(handoff, publication) == expected
