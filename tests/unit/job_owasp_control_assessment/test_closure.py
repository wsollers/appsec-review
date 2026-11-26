"""Remaining OWASP audit boundaries, through real publication and consumers."""
from copy import deepcopy
import hashlib
import json

import pytest

from appsec_review.guidance.compose import load_pinned_prompt, verify_bundle
from appsec_review.owasp_workbench.assessment import _package_guidance, prepare_guidance
from appsec_review.owasp_workbench.indexes import WorkbenchIndex
from appsec_review.review.capability import IN_PROCESS_TOOLS
from appsec_review.review.packages import PackageSettings, assemble_packages
from appsec_review.review.models import IntegrityError
from appsec_review.interchange import ProducerStatus, validate_unit_output
from appsec_review.jobs.job_owasp_control_assessment import build_job
from appsec_review.storage import canonical_json
from tests.test_owasp_assessment_job import (
    ScriptedAssessment, accepted_fixture, execute,
)
from tests.test_owasp_downstream import (
    _fixture, _publish, _record, _references, project_and_assemble,
)
from tests.test_owasp_indexes import _accept, _publish as publish_shard
from tests.test_owasp_assessment_job import ROOT


@pytest.mark.parametrize("filters", [
    {"component": "api"}, {"project": "project"}, {"control": "ASVS:5.0.0:V1.2.4"},
    {"component": "api", "project": "project", "control": "ASVS:5.0.0:V1.2.4"},
])
def test_finding_package_filters_resolve_nested_identity(tmp_path, filters):
    root = tmp_path / "run"
    record = {"package_id": "p", "component": {"component_id": "api", "project_id": "project"},
              "control": {"identity": "ASVS:5.0.0:V1.2.4", "id": "V1.2.4"}}
    _accept(root, [publish_shard(root, records=[record])])
    index = WorkbenchIndex(tmp_path, "run")
    assert [item["record"] for item in index.query(family="finding-package", **filters)["results"]] == [record]
    assert not index.query(family="finding-package", component="other")["results"]


def test_subjectless_batches_are_nondispatch_coverage_not_worker_failures(tmp_path):
    fixture = accepted_fixture(tmp_path, source="def inert():\n    return 1\n")
    transport = ScriptedAssessment()
    outputs = execute(fixture, transport)
    assert not transport.calls
    report_ref = outputs["publication.publish_handoff"]["artifact"]
    report = json.loads((fixture.run_root / report_ref["path"]).read_text())
    assert not any(report["failed_batches_by_cell"].values())
    assert report["coverage"]["dispatched_rows"] == 0
    assert report["coverage"]["unresolved_rows"] > 0
    assert outputs["publication.publish_indexes"]["invocation_guidance"] == {}
    dispositions = outputs["batching.build_packages"]["non_dispatch_dispositions"]
    assert dispositions and all(item["reason"] for item in dispositions)
    rows = outputs["join.deterministic_join"]["joined"]["results"]
    by_id = {row["row_id"]: row for row in rows}
    assert all(by_id[item["row_id"]]["execution_completion"] == "not_dispatched"
               for item in dispositions)
    assert report["non_dispatch_dispositions"] == dispositions
    events = [json.loads(line) for line in (fixture.run_root / "data/logs/pipeline.jsonl").read_text().splitlines()]
    assert not any(event["event_type"] == "OWASP_WORKER_STARTED" for event in events)


def test_strict_control_gaps_survive_accepted_publication(tmp_path):
    fixture = accepted_fixture(tmp_path, source="def inert():\n    return 1\n")
    outputs = execute(fixture, ScriptedAssessment(), publish_handoff=True)
    for unit_id, output in outputs.items():
        validate_unit_output(output, unit_id=unit_id, strict_gaps=True)
    assert build_job().strict_gaps
    result = outputs["publication.publish_handoff"]
    assert result["terminal_status"] == ProducerStatus.COMPLETED_WITH_GAPS
    assert result["gaps"] and all(gap["schema"] == "appsec-review/producer-gap/1" for gap in result["gaps"])
    report = json.loads((fixture.run_root / result["artifact"]["path"]).read_text())
    assert {gap["reason"] for gap in result["gaps"]} == set(report["gaps"])
    assert result["gap_count"] == len(result["gaps"])
    pointer = json.loads((fixture.run_root / "data/jobs/job_owasp_control_assessment/latest.json").read_text())
    handoff = json.loads((fixture.run_root / pointer["handoff_path"]).read_text())
    assert handoff["outputs"]["publication.publish_handoff"]["gaps"] == result["gaps"]


def test_published_guidance_is_actual_blinded_per_role_call_guidance(tmp_path):
    fixture = accepted_fixture(tmp_path)
    transport = ScriptedAssessment()
    outputs = execute(fixture, transport)
    packages = outputs["batching.build_packages"]["packages"]
    actual = outputs["publication.publish_indexes"]
    used = {}
    for request in transport.calls:
        bundle_path = fixture.run_root / "data/guidance" / request.guidance_bundle_sha256 / "bundle.json"
        bundle = json.loads(bundle_path.read_text())
        assert verify_bundle(bundle) == request.guidance_bundle_sha256
        assert load_pinned_prompt(fixture.run_root, request.guidance_bundle_sha256) == request.guidance_text
        batch_id = next(section["id"] for section in bundle["sections"] if section["name"] == "task")
        pin = packages[batch_id][0]["guidance_by_role"][request.role]
        assert pin["bundle_sha256"] == request.guidance_bundle_sha256
        used.setdefault(batch_id, {})[request.role] = pin
        if request.role == "independent_reviewer":
            assert "elevated or ship-blocking proposed claims" not in request.guidance_text
            assert "No previous worker conclusion" in request.guidance_text
            assert "WORKER_ONLY_REASON" not in json.dumps(request.task_input)
    assert used and actual["invocation_guidance"] == used
    identities = sorted({pin["bundle_sha256"] for roles in used.values() for pin in roles.values()})
    assert actual["fingerprints"]["global_inputs"]["guidance_bundle_sha256"] == hashlib.sha256(
        "\n".join(identities).encode()).hexdigest()
    receipt_guidance = {attempt["guidance"]
        for path in (fixture.run_root / "data/indexes/owasp/receipts").rglob("*.json")
        for attempt in json.loads(path.read_text())["attempts"]}
    assert receipt_guidance == set(identities)
    manifest = json.loads((fixture.run_root / actual["manifest"]["path"]).read_text())
    batches = {batch["batch_id"]: batch
               for batch in outputs["batching.partition_work"]["work"]["batches"]}
    for shard in manifest["shards"]:
        if shard["family"] != "finding-package":
            continue
        document = json.loads((fixture.run_root / shard["path"]).read_text())
        fingerprint = document.pop("fingerprint")
        document["inputs"] = {"batch": batches[shard["shard_id"]]["fingerprint"],
                              "guidance": used.get(shard["shard_id"], {})}
        assert fingerprint == hashlib.sha256(canonical_json(document)).hexdigest()


@pytest.mark.parametrize("damage", ["role", "batch", "tamper", "missing"])
def test_call_guidance_rejects_substitution_or_tampering(tmp_path, damage):
    batch = {"batch_id": "one", "assignment": {"persona": "api_web"}}
    pins = prepare_guidance(ROOT, tmp_path, batch)
    if damage == "role":
        pins["control_assessor"] = pins["independent_reviewer"]
    elif damage == "batch":
        batch = {**batch, "batch_id": "another"}
    elif damage == "missing":
        pins.pop("control_assessor")
    else:
        path = tmp_path / pins["control_assessor"]["path"]
        bundle = json.loads(path.read_text())
        bundle["sections"][0]["text"] = "changed guidance"
        path.write_text(json.dumps(bundle), encoding="utf-8")
    with pytest.raises(IntegrityError if damage == "tamper" else ValueError):
        _package_guidance(ROOT, tmp_path, batch, "control_assessor", [{"guidance_by_role": pins}])


def test_unassessed_coverage_is_not_projected_or_attached_to_unrelated_sources(tmp_path):
    fixture = _fixture(tmp_path)
    first, counter = _references(fixture)
    assessed = _record(first, counter)
    records = [assessed]
    for number, changes in enumerate([
        {"control_status": "not_assessed"},
        {"control_status": "cannot_verify", "obligations": []},
        {"applicability": "unsupported_missing_evidence"},
        {"applicability": "not_applicable"},
        {"worker_attempt_count": 0, "execution_completion": "not_dispatched"},
    ]):
        records.append({**deepcopy(assessed), "row_id": f"omitted-{number}", **changes})
    _publish(fixture, records)
    downstream = project_and_assemble(fixture)
    assert len(downstream.product_rows) == 1
    assert any("coverage" in gap for gap in downstream.derived.gaps)
    result = downstream.product_rows[0]["payload"]["result"]
    assert result["workbench_reference"]["query"].split()[0] in IN_PROCESS_TOOLS
    assert result["workbench_reference"]["query"] == "query_precomputed query_set=control_evidence"
    index = WorkbenchIndex(fixture.runs_dir, fixture.run_id)
    assert len(index.query(family="control-result")["results"]) == len(records)
    assembly = assemble_packages(downstream.scope, PackageSettings(unit_max_files=1, hunt_max_units=100),
                                 collection=downstream.collection)
    seen, excluded = [], []
    for package in assembly.packages:
        document = package.resolved()
        if document["scope"]["component_id"] != assessed["component_id"]:
            continue
        sources = set(document["scope"]["source_ids"])
        entries = [item for item in document["context"] if item.get("control_assessment")]
        if first["source_identity"] in sources:
            assert len(entries) == 1
            seen.append(package.package_id)
        elif sources:
            assert not entries
            excluded.append(package.package_id)
    assert seen and excluded

def test_whole_job_retry_isolates_receipts_and_shards_by_attempt(tmp_path, monkeypatch):
    import appsec_review.jobs.job_owasp_control_assessment.job as owasp_job
    from appsec_review.runtime.runner import publication_scope
    from tests.test_owasp_assessment_job import _publish_accepted_handoff, atomic_json, context_for

    fixture = accepted_fixture(tmp_path)
    orig_artifact = owasp_job._artifact
    fail_handoff = [True]

    def whole_job_context(attempt: int):
        ctx = context_for(fixture, attempt=attempt, max_batch_size=32)
        claim_path = ctx.attempt_root / "claim.json"
        claim = json.loads(claim_path.read_text(encoding="utf-8"))
        claim["recovery_boundary"] = "whole_job"
        atomic_json(claim_path, claim)
        return ctx

    def crash_handoff_artifact(unit, name, value):
        if fail_handoff[0] and name == "owasp-workbench-result.json":
            raise RuntimeError("injected post-index handoff failure")
        return orig_artifact(unit, name, value)

    monkeypatch.setattr(owasp_job, "_artifact", crash_handoff_artifact)

    # Attempt 1 writes receipts, index shards, and manifest before failing handoff publication.
    ctx1 = whole_job_context(1)
    with publication_scope(ctx1):
        res1 = build_job(infer=ScriptedAssessment(outcome="satisfied")).execute(ctx1)
    assert "publication.publish_handoff" in res1["failed_units"]
    assert list((fixture.run_root / "data/indexes/owasp/receipts/attempt_0001").glob("*.json"))
    assert list((fixture.run_root / "data/indexes/owasp/control-result/attempt_0001").rglob("*.json"))
    assert list((fixture.run_root / "data/indexes/owasp/manifests/attempt_0001").glob("*.json"))

    # Attempt 2 reruns the whole job under whole_job boundary with a different outcome without collision.
    fail_handoff[0] = False
    ctx2 = whole_job_context(2)
    with publication_scope(ctx2):
        res2 = build_job(infer=ScriptedAssessment(outcome="not_satisfied")).execute(ctx2)
    assert not res2["failed_units"]
    outputs2 = res2["outputs"]
    _publish_accepted_handoff(fixture, ctx2, outputs2)
    assert list((fixture.run_root / "data/indexes/owasp/receipts/attempt_0002").glob("*.json"))
    manifest_rel = outputs2["publication.publish_indexes"]["manifest"]["path"]
    assert manifest_rel.startswith("data/indexes/owasp/manifests/attempt_0002/")

    queried = WorkbenchIndex(fixture.runs_dir, fixture.run_id).query(
        family="control-result", component="component:0001", control="ASVS:5.0.0:V1.2.4"
    )["results"]
    assert len(queried) == 1
    assert queried[0]["record"]["control_status"] == "not_satisfied"
