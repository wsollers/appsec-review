"""T-5169/T-5170: real planning readers/publication with inert source and an external Infer double."""
from dataclasses import replace
import json

import pytest

from appsec_review.inference import ModelResult
from appsec_review.jobs.bound_artifacts import artifact_ref, read_bound_json
from appsec_review.jobs.job_poc_generation.buildctx import AcceptedBuilds, COMPILE_DATABASE_SCHEMA
from appsec_review.jobs.job_poc_generation.datasets import CONTRACT as POC_CONTRACT
from appsec_review.jobs.job_remediation_planning import build_job
from appsec_review.runtime.inputs import input_read_scope
from appsec_review.storage import atomic_json
from tests import remediation_support as support
from tests.handoff_fixture import write_fixture_handoff
from tests.unit.job_remediation_planning.test_coverage_edges import _ctx, _seed_planning, _write

BUILD = "job_language_build"
SOURCE = "native/src/parse.c"
MISSING_BUILD = f"run_owned_source_unavailable:{SOURCE}:no_native_build"
SOURCE_GAP = "source_location_unavailable:evrel-missing"


def _publish_build(env):
    manifest = _write(env.root, "workspace-manifest.json", {"files": env.manifest})
    commands = _write(env.root, "compile-commands.json", {
        "schema": COMPILE_DATABASE_SCHEMA,
        "rows": [{"tool_kind": "compiler", "argv": ["/usr/bin/clang", "-c", f"/workspace/{SOURCE}"],
                  "inputs": [{"workspace_path": SOURCE}]}],
    })
    receipt_set = _write(env.root, "language-build.json", {
        "schema": "appsec-review/language-build-handoff/2",
        "receipts": [{
            "family": "native", "build_unit_id": "build-unit-fixture", "build_system": "cmake",
            "root": ".", "fingerprint": "a" * 64, "terminal_status": "SUCCEEDED",
            "build_outcome": "built", "workspace": env.workspace.relative_to(env.root).as_posix(),
            "workspace_manifest": manifest, "protected_compile_commands": commands,
            "image": {"image_tag": "inert:fixture", "image_id": "sha256:" + "b" * 64, "user": "1:1"},
            "artifacts": [],
        }],
    })
    path = env.root / "data" / "jobs" / BUILD / "attempts" / "attempt_0001" / "handoff.json"
    write_fixture_handoff(env.root, path, {
        "job_id": BUILD, "outputs": {"acceptance.publish_handoff": {"artifact": receipt_set}},
    })
    reference = artifact_ref(env.root, path)
    atomic_json(path.parents[2] / "latest.json",
                {"handoff_path": reference["path"], "handoff_sha256": reference["sha256"]})
    return reference, receipt_set


def _context(env, job, pins=None):
    return replace(_ctx(env.root, support.planning_settings()),
                   contract=job.contract, upstream_handoffs=pins or {})


def _published(env, result):
    assert not result["failed_units"] and not result["skipped_units"], result
    published = result["outputs"]["acceptance.publish_handoff"]
    summary = read_bound_json(env.root, published["artifact"])
    assert summary["gaps"] == published["gaps"]
    assert published["item_count"] == len(summary["items"]) == 1
    return published, summary, summary["items"][0]


@pytest.mark.parametrize("available", [False, True], ids=["absent", "available-unsupplied"])
def test_optional_build_without_admitted_pin_publishes_gap_not_contract_violation(
        tmp_path, monkeypatch, available):
    env = _seed_planning(tmp_path, monkeypatch, candidate_count=1)
    if available:
        _publish_build(env)
    writer = support.Writer()
    job = build_job(infer=writer, core_factory=lambda *_: env.core, repository_root=support.ROOT)
    with input_read_scope(_context(env, job)) as reads:
        result = job.execute(reads.context)
    published, summary, row = _published(env, result)
    assert reads.violation is None and reads.document()["reads"] == []
    assert published["terminal_status"] == result["status"] == "COMPLETED_WITH_GAPS"
    assert row["status"] == "manual_design_required"
    assert row["gap_ids"] == [MISSING_BUILD, "remediation_planning:claim-1:manual_design_required"]
    assert summary["gaps"] == sorted(row["gap_ids"])
    plan = read_bound_json(env.root, row["plan"])
    context = read_bound_json(env.root, plan["provenance"]["source_context"])
    assert context["files"] == [] and context["gaps"] == plan["gaps"] == [MISSING_BUILD]
    assert plan["patch"] is None and plan["assurance"]["runtime_verified"] is False
    assert len(writer.requests) == 1
    assert writer.requests[0].task_input["task"]["source_files"] == []


def test_supplied_optional_build_uses_real_verified_source_and_records_read(tmp_path, monkeypatch):
    env = _seed_planning(tmp_path, monkeypatch, candidate_count=1)
    reference, _ = _publish_build(env)
    before = env.src_file.read_bytes()
    writer = support.Writer(retrieve=True)
    job = build_job(infer=writer, core_factory=lambda *_: env.core, repository_root=support.ROOT)
    with input_read_scope(_context(env, job, {BUILD: reference["sha256"]})) as reads:
        result = job.execute(reads.context)
    published, summary, row = _published(env, result)
    assert published["terminal_status"] == result["status"] == "SUCCEEDED"
    assert row["status"] == "proposal_generated" and summary["gaps"] == row["gap_ids"] == []
    plan = read_bound_json(env.root, row["plan"])
    source = read_bound_json(env.root, plan["provenance"]["source_context"])["files"][0]
    assert source["path"] == SOURCE and source["sha256"] == env.src_sha
    assert source["text"].encode() == before and source["build"]["build_unit_id"] == "build-unit-fixture"
    assert source["relation_id"] == "evrel-1" and source["entity_id"] == "entity-1"
    assert read_bound_json(env.root, plan["patch"])["files"][0]["before_sha256"] == env.src_sha
    [observed] = reads.document()["reads"]
    assert observed["producer"] == BUILD and observed["handoff_sha256"] == reference["sha256"]
    assert observed["read"] is True and observed["cited"] is None
    assert env.src_file.read_bytes() == before
    assert len(writer.requests) == 2 and writer.requests[1].transcript


@pytest.mark.parametrize("defect,message,sticky", [
    ("undeclared", "undeclared consumption", True),
    ("foreign", "not an accepted handoff", True),
    ("handoff-bytes", "changed after it was recorded", True),
    ("receipt-bytes", "artifact identity changed", False),
    ("source-bytes", "accepted source bytes changed", False),
])
def test_optional_does_not_hide_denied_foreign_or_tampered_builds(
        tmp_path, monkeypatch, defect, message, sticky):
    env = _seed_planning(tmp_path, monkeypatch, candidate_count=1)
    reference, receipt_set = _publish_build(env)
    writer = support.Writer()
    job = build_job(infer=writer, core_factory=lambda *_: env.core, repository_root=support.ROOT)
    context = _context(env, job, {BUILD: reference["sha256"]})
    handoff_path = env.root / reference["path"]
    if defect == "undeclared":
        context = replace(context, contract=replace(
            job.contract, inputs=tuple(item for item in job.contract.inputs if item.producer != BUILD)))
    elif defect == "foreign":
        handoff = json.loads(handoff_path.read_text())
        atomic_json(handoff_path, {**handoff, "run_id": "foreign-run"})
        reference = artifact_ref(env.root, handoff_path)
        atomic_json(handoff_path.parents[2] / "latest.json",
                    {"handoff_path": reference["path"], "handoff_sha256": reference["sha256"]})
        context = replace(context, upstream_handoffs={BUILD: reference["sha256"]})
    elif defect == "handoff-bytes":
        handoff_path.write_bytes(handoff_path.read_bytes() + b"\n")
    elif defect == "receipt-bytes":
        path = env.root / receipt_set["path"]
        path.write_bytes(path.read_bytes() + b"\n")
    else:
        env.src_file.write_bytes(b"changed source;\n")
    result = None
    if sticky:
        with pytest.raises(ValueError, match=f"input contract violation:.*{message}"):
            with input_read_scope(context) as reads:
                result = job.execute(context)
        assert reads.violation is not None
    else:
        with input_read_scope(context):
            result = job.execute(context)
    assert result["failed_units"] == ["assess.propose"]
    assert result["skipped_units"] == ["acceptance.publish_handoff"]
    assert message in result["units"]["assess.propose"]["error"]["message"]
    assert "acceptance.publish_handoff" not in result["outputs"]
    assert writer.requests == []


def test_required_build_reader_still_records_missing_input_violation(tmp_path):
    context = replace(_ctx(tmp_path / "run", support.planning_settings()),
                      contract=POC_CONTRACT)
    context = replace(context, config=replace(context.config, job_id="job_poc_generation"))
    with pytest.raises(ValueError, match="input contract violation: accepted job_language_build handoff is required"):
        with input_read_scope(context):
            assert AcceptedBuilds(context.run_root).locate(SOURCE).code == "no_native_build"


@pytest.mark.parametrize("outcome", ["invalid-output", "timeout", "invalid-patch", "proposal"])
def test_source_gaps_survive_writer_and_patch_failures_into_published_summary(tmp_path, monkeypatch, outcome):
    env = _seed_planning(tmp_path, monkeypatch, candidate_count=1)
    reference, _ = _publish_build(env)
    before = env.src_file.read_bytes()
    relations = [{"relation_id": "evrel-missing", "entity_id": "entity-missing"},
                 {"relation_id": "evrel-1", "entity_id": "entity-1"}]
    env.review_doc["packages"][0]["direct_evidence"] = [row["relation_id"] for row in relations]
    env.review_doc["inputs"]["projection"] = _write(
        env.root, "gapped-projection.json", {"relations": {"claim-1": relations}})
    find = env.core.find
    monkeypatch.setattr(env.core, "find", lambda *, identity, limit:
                        {"results": []} if identity == "entity-missing" else find(identity=identity, limit=limit))
    requests = []
    writer = support.Writer()

    def infer(request, *, timeout_seconds):
        requests.append(request)
        if outcome == "invalid-output":
            return ModelResult({"action": "final", "result": {}})
        if outcome == "timeout":
            raise TimeoutError("sensitive provider diagnostics must not be published")
        if outcome == "invalid-patch":
            patch = support.patch(SOURCE, env.src_sha, start=0)
            return ModelResult({"action": "final", "result": support.answer(["evrel-1"], patch)})
        return writer(request, timeout_seconds=timeout_seconds)

    job = build_job(infer=infer, core_factory=lambda *_: env.core, repository_root=support.ROOT)
    context = _context(env, job, {BUILD: reference["sha256"]})
    with input_read_scope(context):
        result = job.execute(context)
    published, summary, row = _published(env, result)
    assert published["terminal_status"] == result["status"] == "COMPLETED_WITH_GAPS"
    expected_gaps = [SOURCE_GAP]
    if outcome == "proposal":
        assert row["status"] == "proposal_generated"
        plan = read_bound_json(env.root, row["plan"])
        assert plan["gaps"] == [SOURCE_GAP] and plan["assurance"]["runtime_verified"] is False
        assert read_bound_json(env.root, plan["patch"])["files"][0]["before_sha256"] == env.src_sha
    else:
        expected_gaps.append("remediation_planning:claim-1:insufficient_evidence")
        assert row["status"] == "insufficient_evidence" and row["plan"] is None
        prefix = {"invalid-output": "invalid_output:", "timeout": "model_failure:TimeoutError",
                  "invalid-patch": "invalid_patch:"}[outcome]
        assert row["reason"].startswith(prefix) and len(row["reason"]) <= 200
        assert "sensitive provider diagnostics" not in row["reason"]
        assert not list(context.attempt_root.rglob("patch.json"))
    assert row["gap_ids"] == expected_gaps and summary["gaps"] == sorted(expected_gaps)
    assert len(requests) == 1
    task = requests[0].task_input["task"]
    assert task["source_gaps"] == [SOURCE_GAP] and task["accepted_evidence"] == relations
    assert task["source_files"][0]["sha256"] == env.src_sha
    source_path, = context.attempt_root.rglob("source-context.json")
    source_context = json.loads(source_path.read_text())
    assert source_context["gaps"] == [SOURCE_GAP] and source_context["relations"] == relations
    assert source_context["finding"] == row["finding"]
    receipt_path, = context.attempt_root.rglob("writer-receipt.json")
    receipt = json.loads(receipt_path.read_text())
    assert receipt["status"] == ("failed" if outcome in {"invalid-output", "timeout"} else "answered")
    if outcome in {"invalid-output", "timeout"}:
        assert receipt["reason"] == row["reason"]
    assert env.src_file.read_bytes() == before
