"""File ownership is run-wide; publication acceptance remains stage-scoped."""

from dataclasses import replace
import json
from pathlib import Path

import pytest

from appsec_review.config import load_config
from appsec_review.indexing.inventory import InventoryInputs, build_inventory
from appsec_review.indexing.store import AcceptedHandoff
from appsec_review.jobs.job_inference_security_review.datasets import DATASETS as INFERENCE_DATASETS
from appsec_review.jobs.job_review_data_indexing.job import DOWNSTREAM_JOBS, registry_providers
from appsec_review.runtime import Job, JobRunner, Unit
from appsec_review.runtime.datasets import artifact_only, dataset_contract, indexed, read_dataset_contract
from appsec_review.runtime.resume import ResumePlanner
from appsec_review.storage import file_sha256
from tests.test_job_runtime import write_config
from tests.test_review_data_indexing import SNAPSHOT, _run, accepted


RUN_ID = "2026-10-10-0001"
JOB_ID = "job_inference_security_review"
STEPS = ("scope", "triage", "packages", "lead_review", "hunt_review", "merge", "adjudicate",
         "completeness", "publication", "scoring")


def _write(root: Path, relative: str, content=None) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({} if content is None else content), encoding="utf-8")
    return path


def _claim(root: Path, attempt: str, *, pinned: bool = False, invocation: str = "previous-dagster-run") -> Path:
    relative = f"data/jobs/{JOB_ID}/attempts/{attempt}"
    document = {"schema": "appsec-review/attempt-claim/1", "run_id": RUN_ID, "job_id": JOB_ID,
                "attempt_id": attempt, "attempt_path": relative, "source_fingerprint": SNAPSHOT,
                "orchestration": {"system": "dagster", "run_id": invocation}}
    if pinned:
        document["dataset_contract"] = dataset_contract(JOB_ID, STEPS, INFERENCE_DATASETS)
    return _write(root, f"{relative}/claim.json", document)


def _inputs(root: Path) -> InventoryInputs:
    return InventoryInputs(
        root, RUN_ID, SNAPSHOT, {}, {}, {}, {}, {}, [],
        file_job_steps={JOB_ID: STEPS}, file_declarations={JOB_ID: INFERENCE_DATASETS})


@pytest.mark.parametrize("pinned", [False, True])
def test_retained_attempts_are_owned_without_becoming_publication_evidence(tmp_path: Path, pinned: bool) -> None:
    before = {}
    for number in (1, 2, 42):
        attempt = f"attempt_{number:04d}"
        claim = _claim(tmp_path, attempt, pinned=pinned, invocation=f"invocation-{number}")
        before[claim] = claim.read_bytes()
        base = f"data/jobs/{JOB_ID}/attempts/{attempt}"
        for relative in ("status.json", "steps/packages/tasks/assemble_lead_packages/traceback.txt",
                         "steps/scope/tasks/accept_manifest/accepted-scope.json",
                         "steps/scope/tasks/assemble_scope/evidence-map.json",
                         "steps/triage/tasks/lead_severity/lead-triage.json"):
            path = _write(tmp_path, f"{base}/{relative}")
            before[path] = path.read_bytes()
    cache = _write(tmp_path, f"data/jobs/{JOB_ID}/triage-cache/key.json")
    before[cache] = cache.read_bytes()

    result = build_inventory(_inputs(tmp_path))

    assert result["audit"]["status"] == "PASSED"
    assert result["run_tree"]["unaccounted_count"] == 0
    assert result["rows"] == []
    assert build_inventory(_inputs(tmp_path)) == result
    for row in result["file_ownership"]:
        assert row["accounting_only"] and not row["in_publication_stage"]
        if row["attempt_id"]:
            assert row["dagster_run_id"] == f"invocation-{int(row['attempt_id'].split('_')[1])}"
            assert row["claim"]["sha256"] == file_sha256(tmp_path / row["claim"]["path"])
            assert row["contract_basis"] == (
                "pinned_attempt_contract" if pinned else "current_declarations_legacy_attempt")
        else:
            assert row["dagster_run_id"] is None and row["claim"] is None
            assert row["contract_basis"] == "shared_or_run_scoped"
    assert all(path.read_bytes() == content for path, content in before.items())


def test_fresh_run_does_not_require_downstream_outputs(tmp_path: Path) -> None:
    (tmp_path / "data").mkdir()
    result = build_inventory(_inputs(tmp_path))
    assert result["audit"]["status"] == "PASSED"
    assert result["rows"] == [] and result["file_ownership"] == []


@pytest.mark.parametrize("relative", [
    f"data/jobs/{JOB_ID}/attempts/attempt_0001/steps/scope/tasks/accept_manifest/unexpected.json",
    f"data/jobs/{JOB_ID}/attempts/attempt_0001/steps/triage/tasks/lead_severity/lead-triage.json.bak",
    f"data/jobs/{JOB_ID}/triage-cache/key.json.bak",
    "data/jobs/job_unknown/attempts/attempt_0001/claim.json",
])
def test_unrecognized_outputs_still_fail(tmp_path: Path, relative: str) -> None:
    _write(tmp_path, relative)
    result = build_inventory(_inputs(tmp_path))
    assert result["audit"]["status"] == "FAILED"
    assert result["run_tree"]["unaccounted_count"] == 1
    assert any(row["code"] == "unaccounted_file" and row["subject"] == relative
               for row in result["audit"]["violations"])


@pytest.mark.parametrize("field,value", [
    ("run_id", "another-run"), ("job_id", "job_unknown"), ("attempt_id", "attempt_0002"),
    ("attempt_path", "data/elsewhere"), ("source_fingerprint", "another-snapshot"),
    ("dataset_contract", {"schema": "bad"}),
])
def test_invalid_attempt_provenance_fails_closed(tmp_path: Path, field: str, value) -> None:
    path = _claim(tmp_path, "attempt_0001", pinned=True)
    document = json.loads(path.read_text())
    document[field] = value
    path.write_text(json.dumps(document))
    result = build_inventory(_inputs(tmp_path))
    assert result["audit"]["status"] == "FAILED"
    assert any(row["code"] == "invalid_attempt_claim" for row in result["audit"]["violations"])


def test_pinned_contract_survives_declaration_changes_without_widening_ownership(tmp_path: Path) -> None:
    _claim(tmp_path, "attempt_0001", pinned=True)
    base = f"data/jobs/{JOB_ID}/attempts/attempt_0001/steps/scope/tasks/accept_manifest"
    _write(tmp_path, f"{base}/accepted-scope.json")
    new_output = f"{base}/new-output.json"
    changed = artifact_only("new_scope", "scope", "inference_review", "application/json", "New output",
                            artifacts=(new_output,), reason="attempt-local input")
    inputs = replace(_inputs(tmp_path), file_declarations={JOB_ID: (changed,)})
    result = build_inventory(inputs)
    assert result["audit"]["status"] == "PASSED"
    _write(tmp_path, new_output)
    result = build_inventory(inputs)
    assert result["run_tree"]["unaccounted_count"] == 1
    assert result["audit"]["violations"][0]["subject"] == new_output


def test_unaccounted_count_is_not_the_bounded_violation_sample(tmp_path: Path) -> None:
    for number in range(75):
        _write(tmp_path, f"data/strays/{number:03d}.json")
    result = build_inventory(_inputs(tmp_path))
    assert result["run_tree"]["unaccounted_count"] == 75
    assert len(result["audit"]["violations"]) == 50
    assert result["audit"]["status"] == "FAILED"


def test_historical_backing_files_do_not_satisfy_required_accepted_output(tmp_path: Path) -> None:
    _claim(tmp_path, "attempt_0001")
    relative = f"data/jobs/{JOB_ID}/attempts/attempt_0001/steps/scope/tasks/accept_manifest/old-output.json"
    _write(tmp_path, relative)
    declaration = indexed("required_index", "scope", "inventory", "appsec-review/retrieval-index/2",
                          "Required current accepted output", indexes=("inventory",), route="find",
                          artifacts=(relative,), required=True)
    handoff = AcceptedHandoff(JOB_ID, {"attempt_id": "attempt_0002", "source_fingerprint": SNAPSHOT},
                              "a" * 64, "handoff.json")
    result = build_inventory(InventoryInputs(
        tmp_path, RUN_ID, SNAPSHOT, {JOB_ID: STEPS}, {JOB_ID: (declaration,)}, {}, {JOB_ID: handoff},
        {JOB_ID: {"scope.accept_manifest": "SUCCEEDED"}}, []))
    assert result["run_tree"]["unaccounted_count"] == 0
    assert any(row["code"] == "missing_required_output" for row in result["audit"]["violations"])
    row = next(row for row in result["rows"] if row["output_kind"] == "required_index")
    assert row["disposition"] == "unavailable"


def test_runner_pins_contract_for_successful_and_failed_invocations(tmp_path: Path) -> None:
    runner = JobRunner(load_config(write_config(tmp_path)))
    declaration = artifact_only("output", "work", "inventory", "application/json", "Fixture output",
                                artifacts=("data/jobs/job_fixture/attempts/*/steps/work/tasks/only/output.json",),
                                reason="fixture output")

    def write(unit):
        _write(unit.job.run_root, f"{unit.unit_root.relative_to(unit.job.run_root).as_posix()}/output.json")
        return {}

    job = Job("job_fixture", "fixture", write, units=(Unit("work.only", write),), datasets=(declaration,))
    first = runner.run(job, orchestration={"system": "dagster", "run_id": "first-invocation"})
    root = Path(first["attempt_root"])
    claim = json.loads((root / "claim.json").read_text())
    steps, datasets = read_dataset_contract(claim["dataset_contract"], job.job_id)
    assert "work" in steps and datasets == job.datasets
    assert any(item["path"].endswith("/claim.json") and item["sha256"] == file_sha256(root / "claim.json")
               for item in first["handoff"]["artifacts"])
    reused = runner.begin_or_reuse_attempt(
        job, run_id=claim["run_id"], orchestration={"system": "dagster", "run_id": "reuse-invocation"})
    assert reused["reused"] and reused["attempt_id"] == claim["attempt_id"]
    assert runner.finalize_attempt(job, reused)["reused"]
    assert json.loads((root / "claim.json").read_text())["orchestration"]["run_id"] == "first-invocation"

    def fail(unit):
        raise ValueError("expected downstream failure")

    with pytest.raises(RuntimeError, match="expected downstream failure"):
        runner.run(replace(job, units=(Unit("work.only", fail),)), run_id=claim["run_id"],
                   orchestration={"system": "dagster", "run_id": "second-invocation"})
    second = json.loads((root.parent / "attempt_0002/claim.json").read_text())
    assert second["dataset_contract"] == claim["dataset_contract"]
    assert second["orchestration"]["run_id"] != claim["orchestration"]["run_id"]
    assert second["attempt_id"] != claim["attempt_id"]
    assert json.loads((root / "claim.json").read_text()) == claim
    changed = {**claim, "trigger": "changed"}
    (root / "claim.json").write_text(json.dumps(changed))
    reasons, _ = ResumePlanner(runner.config, runner.runs.resolve(claim["run_id"]), (job,), "none").accepted(job, {})
    assert any("artifact changed:" in reason and "claim.json" in reason for reason in reasons)


def test_registry_exposes_downstream_file_contracts() -> None:
    jobs, declarations, _ = registry_providers()
    assert DOWNSTREAM_JOBS <= set(jobs)
    config = load_config(Path(__file__).resolve().parents[1] / "appsec-review.toml")
    for job in jobs:
        assert declarations[job]
        contract = dataset_contract(job, tuple(config.job(job).steps), declarations[job])
        assert read_dataset_contract(contract, job)[1] == tuple(declarations[job])


@pytest.mark.parametrize("shared_output", [False, True])
def test_indexing_can_resume_after_real_downstream_attempts(accepted, shared_output) -> None:
    config, run_id, root, target, _ids, _outcome, executor = accepted
    job_id = "job_document_issue_analysis"
    declarations = registry_providers()[1][job_id]

    def publish(unit):
        if shared_output:
            from appsec_review.storage.shared import SharedArtifacts, put_bytes
            shared = SharedArtifacts.for_job(unit.job)
            hit = shared.lookup("document-issues", "a" * 64)
            if hit is None:
                artifact = put_bytes(root, b'{"fixture":true}\n')
                receipt = shared.computed("document-issues", "a" * 64, artifact,
                                          computation={"fixture": True})
            else:
                value, receipt = hit
                artifact = value["object"]
            return {"artifact": artifact, "shared_receipt": receipt}
        path = _write(root, "data/document-issues/fixture/ledger.json", {"fixture": True})
        return {"artifact": {"path": path.relative_to(root).as_posix(), "sha256": file_sha256(path)}}

    job = Job(job_id, "document_issue_analysis", publish, units=(Unit("analysis.map_and_adjudicate", publish),),
              datasets=declarations)
    downstream = JobRunner(config).run(job, run_id=run_id, source_fingerprint=SNAPSHOT,
                                       orchestration={"system": "dagster", "run_id": "downstream-invocation"})

    def fail(unit):
        if shared_output:
            publish(unit)
        raise ValueError("expected retained failure")

    with pytest.raises(RuntimeError, match="expected retained failure"):
        JobRunner(config).run(replace(job, units=(Unit("analysis.map_and_adjudicate", fail),)),
                              run_id=run_id, source_fingerprint=SNAPSHOT,
                              orchestration={"system": "dagster", "run_id": "failed-invocation"})
    retained = {path: path.read_bytes() for path in (root / "data/jobs" / job_id).rglob("*") if path.is_file()}
    outcome = _run(config, run_id, target, executor)
    report = json.loads((Path(outcome["attempt_root"]) / "steps/audit/tasks/inventory/inventory.json").read_text())
    assert report["audit"]["status"] == "PASSED"
    assert not any(row["job_id"] in DOWNSTREAM_JOBS for row in report["rows"])
    provenance = {row["dagster_run_id"] for row in report["file_ownership"] if row["job_id"] == job_id}
    assert {"downstream-invocation", "failed-invocation"} <= provenance
    assert all(path.read_bytes() == content for path, content in retained.items())
    assert file_sha256(Path(downstream["attempt_root"]) / "handoff.json") == downstream["handoff_sha256"]
