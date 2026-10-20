from __future__ import annotations

import json
from pathlib import Path

from appsec_review.acceptance.model_contract import (
    Call, baseline_document, check, load_calls, response_problems, tainted_jobs)
from appsec_review.acceptance.normalize import Masks

ROOT = Path(__file__).parents[2]
DEP = "appsec-review/native-dependency-resolution-proposal/1"
MASKS = Masks.for_run("2026-10-20-0002")
OLD = Masks.for_run("2026-10-19-0002")
REFS = ["execution-capture:command-001:event-1355", "execution-capture:command-002:event-8013"]


def _request(candidate: str = "c1", *, repair: str | None = None, event: int = 1355) -> dict:
    return {"schema": DEP, "role": "native_dependency_resolver", "repair_errors": [repair] if repair else [],
            "prior_response": None,
            "summary": {"candidate": candidate, "allowed_evidence_refs": [
                f"execution-capture:command-001:event-{event}", REFS[1]]}}


def _proposal(candidate: str = "native-dependency-1", **changes) -> dict:
    return {"schema": DEP, "candidate_id": candidate, "confidence": 0.4, "evidence_refs": [REFS[0]],
            "rationale": "linker evidence names this library", "repository": None, **changes}


def _call(request: dict, proposal: dict | None, error: str | None = None, job: str = "job_dependency_intelligence"):
    return Call(job, request, proposal, {"type": "ModelOutputError", "message": error} if error else None)


def test_a_complete_response_has_no_problems_and_an_incomplete_one_says_why() -> None:
    request = _request()
    assert response_problems(request, _proposal(), ROOT) == []
    bad = _proposal(confidence=1.5, evidence_refs=["execution-capture:command-009:event-1"], rationale=" ")
    problems = response_problems(request, bad, ROOT)
    assert any("confidence" in item for item in problems)
    assert any("did not supply" in item for item in problems)
    assert any("rationale" in item for item in problems)
    assert response_problems(request, {}, ROOT) == ["the response is empty"]
    assert any("schema" in item for item in response_problems(request, _proposal(schema="other/1"), ROOT))


def test_a_target_plan_response_is_validated_against_its_schema_file() -> None:
    request = {"schema": "appsec-review/target-analysis-proposal/2", "repair_errors": [], "prior_response": None}
    incomplete = response_problems(request, {"schema": request["schema"]}, ROOT)
    assert incomplete, "a proposal with none of its required fields must not pass the schema file"
    assert response_problems(request, {"schema": "other/1"}, ROOT)  # also names the wrong schema


def test_inputs_are_compared_as_normalized_requests_so_event_numbers_do_not_matter() -> None:
    accepted = baseline_document([_call(_request(event=1355), _proposal())], OLD, run_id="2026-10-19-0002")
    same_inputs = [_call(_request(event=8888), _proposal(evidence_refs=["execution-capture:command-001:event-8888"]))]
    report = check(accepted, same_inputs, MASKS, ROOT)
    assert report.input_problems == [] and report.response_problems == [] and not report.response_changed

    other = [_call(_request("c2"), _proposal())]
    changed = check(accepted, other, MASKS, ROOT)
    assert any("not in the baseline" in item for item in changed.input_problems)
    assert any("not sent" in item for item in changed.input_problems)


def test_repair_requests_are_not_inputs_and_a_repaired_request_is_complete() -> None:
    accepted = baseline_document([_call(_request(), _proposal())], OLD, run_id="2026-10-19-0002")
    failed_then_repaired = [_call(_request(), None, "found 0"),
                            _call(_request(repair="ModelOutputError: found 0"), _proposal("native-dependency-9"))]
    report = check(accepted, failed_then_repaired, MASKS, ROOT)
    assert report.input_problems == [] and report.response_problems == []
    assert report.failed_attempts["job_dependency_intelligence"] == 1
    assert report.response_changed == {"job_dependency_intelligence"}  # the answer differs, which is allowed


def test_a_request_that_never_gets_a_complete_response_is_a_violation() -> None:
    accepted = baseline_document([_call(_request(), _proposal())], OLD, run_id="2026-10-19-0002")
    never = [_call(_request(), None, "found 0"), _call(_request(repair="x"), _proposal(confidence=3))]
    report = check(accepted, never, MASKS, ROOT)
    assert report.failed and len(report.response_problems) == 1
    assert "no complete response in 2 attempt(s)" in report.response_problems[0]


def test_downstream_jobs_of_a_changed_response_are_tainted() -> None:
    topology = [{"job_id": "a", "upstream_handoffs": []}, {"job_id": "b", "upstream_handoffs": ["a"]},
                {"job_id": "c", "upstream_handoffs": ["b"]}, {"job_id": "d", "upstream_handoffs": []}]
    assert tainted_jobs({"b"}, topology) == {"b", "c"}
    assert tainted_jobs(set(), topology) == set()


def test_recordings_load_from_a_run_directory(tmp_path: Path) -> None:
    directory = tmp_path / "job_x"
    directory.mkdir()
    (directory / "k.0000.json").write_text(json.dumps({
        "job_id": "job_x", "request": _request(), "result": {"proposal": _proposal()}}), encoding="utf-8")
    (directory / "k.0001.json").write_text(json.dumps({
        "job_id": "job_x", "request": _request(), "result": None,
        "error": {"type": "ModelOutputError", "message": "found 0"}}), encoding="utf-8")
    (directory / "misses").mkdir()
    (directory / "misses" / "m.0000.json").write_text("{}", encoding="utf-8")
    calls = load_calls(tmp_path)
    assert [(call.proposal is not None, call.error is not None) for call in calls] == [(True, False), (False, True)]
