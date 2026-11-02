from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.config import load_config
from appsec_review.inference import ModelResult
from appsec_review.jobs.job_dependency_intelligence import build_job
from appsec_review.jobs.job_dependency_intelligence.discovery import discover_native_dependencies
from appsec_review.jobs.job_dependency_intelligence.integration import native_bounds
from appsec_review.jobs.job_dependency_intelligence.job import JOB_ID, TOPOLOGY, _validate_config
from appsec_review.jobs.job_dependency_intelligence.native_inference_contracts import (
    CURATION_SCHEMA, METADATA_SCHEMA, PLAN_SCHEMA,
)
from appsec_review.jobs.job_dependency_intelligence.native_inference_integration import (
    INFERENCE_UNITS, inference_bounds, run_native_inference, validate_inference_receipt,
    validate_inference_publication,
)
from appsec_review.observability.native_inference import aggregate_native_inference
from appsec_review.storage import atomic_json
from appsec_review.storage.shared import reference


ROOT = Path(__file__).parents[1]
SNAPSHOT = "a" * 64


class Events:
    def __init__(self, root):
        self.root, self.records = root, []

    def write(self, event, **details):
        self.records.append({
            "event_type": event, "run_id": self.root.name, "job_id": JOB_ID,
            "attempt_id": "attempt_0001", "details": details,
        })


def fixture(tmp_path):
    root = tmp_path / "2026-11-02-0001"
    target = tmp_path / "target"
    path = target / "vendor" / "foo" / "foo.h"
    path.parent.mkdir(parents=True)
    content = b'#define FOO_VERSION "1.2.3"\n'
    path.write_bytes(content)
    catalog = root / "data" / "catalog.json"
    atomic_json(catalog, {"source_fingerprint": SNAPSHOT})
    files = [{
        "domain": "target", "root_id": "target", "path": "vendor/foo/foo.h",
        "size_bytes": len(content), "sha256": hashlib.sha256(content).hexdigest(),
        "upstream": reference(root, catalog), "backing": None,
    }]
    config = load_config(ROOT / "appsec-review.toml").job(JOB_ID)
    raw = discover_native_dependencies(
        source_fingerprint=SNAPSHOT, files=files, invocations=[], artifacts=[],
        read_file=lambda record, limit: content, bounds=native_bounds(config.settings))
    raw["source_fingerprint"] = SNAPSHOT
    outputs = {
        "inputs.load_accepted": {"native_files": files, "native_workspace_roots": {}},
        "resolution.detect_dependencies": {"native_discovery_document": raw},
    }
    job = SimpleNamespace(
        run_root=root, run_id=root.name, attempt_id="attempt_0001",
        source_fingerprint=SNAPSHOT, target_root=target, repository_root=ROOT,
        config=config, events=Events(root))
    atomic_json(root / "data/jobs" / JOB_ID / "attempts/attempt_0001/claim.json", {
        "schema": "appsec-review/attempt-claim/1", "run_id": root.name, "job_id": JOB_ID,
        "attempt_id": job.attempt_id, "source_fingerprint": SNAPSHOT,
    })

    def unit(name):
        return SimpleNamespace(
            job=job, unit_id=name, unit_root=root / "units" / name,
            output=lambda key: outputs[key])

    return job, outputs, unit


class Infer:
    def __init__(self):
        self.stages = []

    def __call__(self, request, *, timeout_seconds):
        stage, payload = request.summary["stage"], request.summary["payload"]
        self.stages.append(stage)
        if stage == "curate":
            proposal = {
                "schema": CURATION_SCHEMA, "input_records": payload["input_records"],
                "libraries": [{
                    "name": "foo", "kind": "library",
                    "candidate_ids": [row["candidate_id"] for row in payload["candidates"]],
                    "supporting_paths": ["vendor/foo/foo.h"], "basis": "Named header distribution.",
                }], "sdk_groups": [], "rejected_candidate_ids": [], "uncertain_candidate_ids": [],
            }
        elif stage == "plan":
            proposal = {"schema": PLAN_SCHEMA, "candidate_id": payload["candidate_id"],
                        "files": ["vendor/foo/foo.h"], "version_patterns": ["FOO_VERSION literal"]}
        else:
            assert stage == "metadata"
            proposal = {
                "schema": METADATA_SCHEMA, "candidate_id": payload["candidate_id"],
                "claims": [{"field": "version", "value": "1.2.3", "citations": [{
                    "path": "vendor/foo/foo.h", "start_line": 1, "end_line": 1,
                    "quote": '#define FOO_VERSION "1.2.3"',
                }]}],
            }
        return ModelResult(proposal, input_tokens=10, output_tokens=8, cache_tokens=0)


def execute_stage(tmp_path, *, investigate):
    job, outputs, unit = fixture(tmp_path)
    infer = Infer()
    if investigate:
        outputs["resolution.curate_components"] = outputs["resolution.detect_dependencies"]
    output = run_native_inference(unit(INFERENCE_UNITS[int(investigate)]), infer,
                                  investigate=investigate)
    return job, output, infer


def test_configuration_and_task_graph_order_the_two_new_stages():
    config = load_config(ROOT / "appsec-review.toml").job(JOB_ID)
    _validate_config(SimpleNamespace(config=config), None)
    assert tuple(config.step("resolution").tasks) == TOPOLOGY["resolution"]
    units = {unit.unit_id: unit for unit in build_job().units}
    assert "resolution.curate_components" in units["resolution.investigate_components"].dependencies
    assert "resolution.investigate_components" in units["resolution.infer_repositories"].dependencies
    assert "resolution.investigate_components" in units["publication.publish_sbom"].dependencies


@pytest.mark.parametrize("change", [{"enabled": 1}, {"unknown": 1}, {"max_calls": 0}])
def test_inference_settings_are_closed_and_typed(change):
    original = load_config(ROOT / "appsec-review.toml").job(JOB_ID).settings
    settings = {"native_inference": dict(original["native_inference"])}
    settings["native_inference"].update(change)
    with pytest.raises(ValueError):
        inference_bounds(settings)


@pytest.mark.parametrize("investigate", [False, True])
def test_stage_runs_real_algorithm_and_persists_receipt_and_model_attempts(tmp_path, investigate):
    job, output, infer = execute_stage(tmp_path, investigate=investigate)
    receipt = validate_inference_receipt(
        job.run_root, output["inference_metrics"], source_fingerprint=SNAPSHOT,
        unit_id=INFERENCE_UNITS[int(investigate)], attempt_id=job.attempt_id)
    assert receipt["counters"]["model_calls"] == (2 if investigate else 1)
    assert receipt["counters"]["input_tokens"] == 10 * len(infer.stages)
    assert receipt["counters"]["unknown_usage_calls"] == 0
    assert receipt["duration_ms"] >= 0
    assert receipt["model_artifacts"]["size_bytes"] > 0
    assert len(output["model_artifacts"]) > 1
    candidate = output["native_discovery_document"]["candidates"][0]
    if investigate:
        assert infer.stages == ["plan", "metadata"]
        assert candidate["release"]["status"] == "corroborated"
        assert candidate["release"]["value"] == "1.2.3"
        assert receipt["counters"]["files_read"] == 1
    else:
        assert infer.stages == ["curate"]
        assert candidate["metadata"]["curation"]["status"] == "inferred"


def test_absent_transport_retains_components_and_records_gap_not_empty_success(tmp_path):
    job, outputs, unit = fixture(tmp_path)
    output = run_native_inference(unit(INFERENCE_UNITS[0]), None, investigate=False)
    assert output["native_discovery_document"]["candidates"]
    assert output["gaps"] and output["terminal_status"] == "COMPLETED_WITH_GAPS"
    receipt = validate_inference_receipt(job.run_root, output["inference_metrics"],
                                       source_fingerprint=SNAPSHOT)
    assert receipt["counters"]["model_calls"] == 0


def test_telemetry_separates_reuse_work_and_accepted_inventory(tmp_path):
    job, output, _ = execute_stage(tmp_path, investigate=False)
    unit = INFERENCE_UNITS[0]
    metadata = dict(output["inference_metrics"])
    accepted = {"source_fingerprint": SNAPSHOT, "attempt_id": job.attempt_id,
                "inference_metrics": [metadata, metadata]}
    incomplete = aggregate_native_inference(job.run_root, job.events.records, accepted=accepted)
    assert not incomplete["accounting_complete"]
    assert incomplete["availability"] == "partial"
    # A missing second-stage receipt must not make the first stage's fresh work disappear.
    assert incomplete["work_counters"]["model_calls"] == 1
    duplicate = next(row for row in job.events.records if row["event_type"] == "NATIVE_INFERENCE_RESULT")
    summary = aggregate_native_inference(job.run_root, [duplicate, duplicate])
    assert summary["fresh_work"] == 1
    assert summary["work_counters"]["model_calls"] == 1
    assert summary["current_inventory"] == {}
    reused = {"event_type": "TASK_REUSED", "run_id": job.run_id, "job_id": JOB_ID,
              "attempt_id": job.attempt_id, "details": {"unit_id": unit}}
    missing = aggregate_native_inference(job.run_root, [reused])
    assert missing["reused_stage_count"] == 1 and missing["fresh_work"] == 0
    assert missing["attempts"][0]["counters"] is None


def test_corrupt_or_conflicting_metrics_cannot_become_zero_or_success(tmp_path):
    job, output, _ = execute_stage(tmp_path, investigate=False)
    result = next(row for row in job.events.records if row["event_type"] == "NATIVE_INFERENCE_RESULT")
    changed = deepcopy(result)
    changed["details"]["input_fingerprint"] = "b" * 64
    summary = aggregate_native_inference(job.run_root, [result, changed])
    assert not summary["accounting_complete"]
    assert summary["work_counters"]["model_calls"] is None
    assert summary["attempts"][0]["status"] == "INTEGRITY_ERROR"
    path = job.run_root / output["inference_metrics"]["path"]
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError):
        validate_inference_receipt(job.run_root, output["inference_metrics"],
                                   source_fingerprint=SNAPSHOT)


def test_failed_operation_without_receipt_is_missing_accounting(tmp_path):
    job, _, _ = fixture(tmp_path)
    result = aggregate_native_inference(job.run_root, [{
        "event_type": "OPERATION_COMPLETED", "run_id": job.run_id, "job_id": JOB_ID,
        "attempt_id": job.attempt_id, "details": {
            "unit_id": INFERENCE_UNITS[1], "terminal_status": "FAILED",
        },
    }])
    assert result["attempts"][0]["counters"] is None
    assert result["work_counters"]["versions_corroborated"] is None
    assert not result["accounting_complete"]


def two_receipts(tmp_path):
    job, outputs, unit = fixture(tmp_path)
    raw_path = job.run_root / "data" / "raw-discovery.json"
    atomic_json(raw_path, outputs["resolution.detect_dependencies"]["native_discovery_document"])
    outputs[INFERENCE_UNITS[0]] = run_native_inference(unit(INFERENCE_UNITS[0]), Infer(), investigate=False)
    outputs[INFERENCE_UNITS[1]] = run_native_inference(unit(INFERENCE_UNITS[1]), Infer(), investigate=True)
    accepted = {"source_fingerprint": SNAPSHOT, "attempt_id": job.attempt_id,
                "inference_metrics": [outputs[name]["inference_metrics"] for name in INFERENCE_UNITS]}
    publication = {
        "source_fingerprint": SNAPSHOT, "sbom": {"inference_metrics": accepted["inference_metrics"]},
        "raw_native_discovery": reference(job.run_root, raw_path),
        "native_discovery": outputs[INFERENCE_UNITS[1]]["native_discovery"],
        "native_curation": outputs[INFERENCE_UNITS[0]]["artifact"],
        "native_metadata": outputs[INFERENCE_UNITS[1]]["artifact"],
    }
    framework = {"attempt_id": job.attempt_id, "artifacts": [
        publication["raw_native_discovery"],
        *[identity for name in INFERENCE_UNITS for identity in (
            outputs[name]["inference_metrics"], outputs[name]["artifact"],
            outputs[name]["native_discovery"], *outputs[name]["model_artifacts"])],
    ]}
    return job, accepted, publication, framework


def test_current_inventory_and_reuse_never_sum_component_counts(tmp_path):
    job, accepted, _, _ = two_receipts(tmp_path)
    fresh = aggregate_native_inference(job.run_root, job.events.records, accepted=accepted)
    assert fresh["accounting_complete"]
    assert fresh["work_counters"]["model_calls"] == 3
    assert fresh["current_inventory"][INFERENCE_UNITS[0]]["counters"]["curated_components"] == 1
    events = [{"event_type": "TASK_REUSED", "run_id": job.run_id, "job_id": JOB_ID,
               "attempt_id": job.attempt_id, "details": {"unit_id": name}}
              for name in INFERENCE_UNITS]
    reused = aggregate_native_inference(job.run_root, events, accepted=accepted)
    assert reused["accounting_complete"] and reused["fresh_work"] == 0
    assert reused["reused_stage_count"] == 2
    assert reused["work_counters"]["model_calls"] == 0
    assert reused["current_inventory"] == fresh["current_inventory"]


@pytest.mark.parametrize("damage", ["wrong_run", "wrong_attempt", "wrong_unit", "wrong_snapshot"])
def test_receipt_provenance_is_not_inferred_from_its_filename(tmp_path, damage):
    job, output, _ = execute_stage(tmp_path, investigate=False)
    path = job.run_root / output["inference_metrics"]["path"]
    document = json.loads(path.read_bytes())
    field = {"wrong_run": "run_id", "wrong_attempt": "attempt_id", "wrong_unit": "unit_id",
             "wrong_snapshot": "source_fingerprint"}[damage]
    document[field] = "changed"
    atomic_json(path, document)
    with pytest.raises(ValueError, match="provenance"):
        validate_inference_receipt(job.run_root, reference(job.run_root, path),
                                   source_fingerprint=SNAPSHOT, unit_id=INFERENCE_UNITS[0],
                                   attempt_id=job.attempt_id)


@pytest.mark.parametrize("damage", ["missing_member", "swapped_result", "swapped_discovery",
                                   "missing_metrics", "changed_artifact"])
def test_publication_requires_nested_membership_and_exact_stage_bindings(tmp_path, damage):
    job, _, publication, framework = two_receipts(tmp_path)
    validate_inference_publication(job.run_root, framework, publication)
    if damage == "missing_member":
        framework["artifacts"].pop()
    elif damage == "swapped_result":
        publication["native_metadata"] = publication["native_curation"]
    elif damage == "swapped_discovery":
        publication["native_discovery"] = publication["raw_native_discovery"]
    elif damage == "missing_metrics":
        publication["sbom"]["inference_metrics"] = None
    else:
        artifact = framework["artifacts"][-1]
        path = job.run_root / artifact["path"]
        path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError):
        validate_inference_publication(job.run_root, framework, publication)


def test_unknown_usage_remains_explicit_in_receipt_and_summary(tmp_path):
    job, outputs, unit = fixture(tmp_path)
    boundary = Infer()

    def missing_usage(request, *, timeout_seconds):
        response = boundary(request, timeout_seconds=timeout_seconds)
        return ModelResult(response.proposal)

    output = run_native_inference(unit(INFERENCE_UNITS[0]), missing_usage, investigate=False)
    receipt = validate_inference_receipt(job.run_root, output["inference_metrics"],
                                       source_fingerprint=SNAPSHOT)
    assert receipt["counters"]["unknown_usage_calls"] == receipt["counters"]["model_calls"] == 1
    assert receipt["usage_complete"] is False
    summary = aggregate_native_inference(job.run_root, job.events.records)
    assert summary["attempts"][0]["usage_complete"] is False


def test_retry_calls_are_counted_physically_without_duplicate_curated_inventory(tmp_path):
    job, _, unit = fixture(tmp_path)
    boundary = Infer()
    calls = []

    def retry(request, *, timeout_seconds):
        calls.append(request)
        return (ModelResult({"invalid": True}, input_tokens=2, output_tokens=1)
                if len(calls) == 1 else boundary(request, timeout_seconds=timeout_seconds))

    output = run_native_inference(unit(INFERENCE_UNITS[0]), retry, investigate=False)
    receipt = validate_inference_receipt(job.run_root, output["inference_metrics"],
                                       source_fingerprint=SNAPSHOT)
    assert receipt["counters"]["model_calls"] == 2
    assert receipt["counters"]["model_failures"] == 1
    assert receipt["counters"]["input_tokens"] == 12
    assert receipt["counters"]["curated_components"] == 1


def test_wrong_run_reuse_cannot_claim_current_inventory(tmp_path):
    job, accepted, _, _ = two_receipts(tmp_path)
    summary = aggregate_native_inference(job.run_root, [{
        "event_type": "TASK_REUSED", "run_id": "wrong", "job_id": JOB_ID,
        "attempt_id": job.attempt_id, "details": {"unit_id": INFERENCE_UNITS[0]},
    }], accepted=accepted)
    assert not summary["accounting_complete"]
    assert summary["attempts"][0]["status"] == "INTEGRITY_ERROR"


def test_job_reuse_requires_the_original_handoff_hash(tmp_path):
    job, accepted, _, _ = two_receipts(tmp_path)
    summary = aggregate_native_inference(job.run_root, [{
        "event_type": "JOB_REUSED", "run_id": job.run_id, "job_id": JOB_ID,
        "attempt_id": job.attempt_id, "details": {"handoff_sha256": "f" * 64},
    }], accepted=accepted)
    assert not summary["accounting_complete"]
    assert all(row["status"] == "INTEGRITY_ERROR" for row in summary["attempts"])
