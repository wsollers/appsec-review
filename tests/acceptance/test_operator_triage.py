"""Manual developer triage acceptance through a real stdio client; never automatic."""

from appsec_review.observability import PipelineLog
from appsec_review.storage import atomic_json
from tests.integration.test_operator_stdio import exchange
from tests.test_retrieval_core import RUN_ID


def test_failed_run_triage_finds_protected_failure_and_nonexecuting_plan(tmp_path):
    root = tmp_path / RUN_ID
    status_path = root / "data/jobs/job_project_build/attempts/attempt_0001/status.json"
    atomic_json(status_path, {"run_id": RUN_ID, "job_id": "job_project_build", "attempt_id": "attempt_0001",
                              "status": "FAILED", "orchestration": {},
                              "error": {"type": "RuntimeError", "message": "DO_NOT_EXPOSE_RAW_FAILURE"}})
    log = PipelineLog(root)
    log.write("JOB_FAILED", run_id=RUN_ID, job_id="job_project_build", attempt_id="attempt_0001", level="ERROR")
    log.write("RESUME_PLANNED", run_id=RUN_ID, details={"decisions": [
        {"job_id": "job_project_build", "action": "RUN", "reasons": ["no accepted handoff"]}]})
    before = {path: path.read_bytes() for path in root.rglob("*") if path.is_file()}
    initial = exchange(tmp_path, [
        ("inspect_attempt", {"job_id": "job_project_build", "attempt_id": "attempt_0001"}),
        ("read_logs", {"event_type": "RESUME_PLANNED"}),
    ])
    failure = initial[0]["result"]["structuredContent"]["results"][0]
    assert failure["failure"]["protected_reference"]["content_available"] is False
    ref = initial[1]["result"]["structuredContent"]["results"][0]["reference"]
    plan_response = exchange(tmp_path, [
        ("inspect_recovery_plan", {"offset": ref["offset"], "sha256": ref["sha256"]}),
        ("resume", {"run_id": RUN_ID}),
        ("read_logs", {"path": str(status_path)}),
    ])
    plan = plan_response[0]["result"]["structuredContent"]["results"][0]
    assert plan["executes"] is False
    assert plan["references"]["unit_regression"] == "tests/test_wave1_resume.py"
    assert plan["references"]["manual_replay"] == "appsec-review replay-build-recipe"
    assert all(response["error"]["code"] == -32602 for response in plan_response[1:])
    assert {path: path.read_bytes() for path in root.rglob("*") if path.is_file()} == before
    assert "DO_NOT_EXPOSE_RAW_FAILURE" not in str(initial) + str(plan_response)
