"""The control records beneath the handoff carry schema ids and validate against docs/schemas."""
from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
import pytest

from appsec_review.interchange import (
    ATTEMPT_STATUS_SCHEMA, GAP_SCHEMA, GapCode, ProducerStatus, TASK_RECEIPT_SCHEMA, UNIT_EXECUTION_SCHEMA,
    UNIT_OUTPUT_KEYS, UnitOutputContractError, gap_id, producer_gap, validate_unit_output,
)
from tests.test_handoff_interchange import publish, setup

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "docs/schemas/job-control.schema.json").read_text(encoding="utf-8"))
DEFS = SCHEMA["$defs"]


def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator({"$schema": SCHEMA["$schema"], "$defs": DEFS, "$ref": f"#/$defs/{name}"})


def test_schema_is_valid_and_its_vocabularies_match_the_code() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    assert set(DEFS["producerStatus"]["enum"]) == {str(item) for item in ProducerStatus}
    assert set(DEFS["producerGap"]["properties"]["code"]["enum"]) == {str(item) for item in GapCode}
    assert set(UNIT_OUTPUT_KEYS) <= set(DEFS["unitOutput"]["properties"])
    assert DEFS["taskReceipt"]["properties"]["schema"]["const"] == TASK_RECEIPT_SCHEMA
    assert DEFS["attemptStatus"]["properties"]["schema"]["const"] == ATTEMPT_STATUS_SCHEMA
    assert DEFS["producerGap"]["properties"]["schema"]["const"] == GAP_SCHEMA


def test_runner_receipts_and_results_carry_schema_ids_and_validate(tmp_path: Path) -> None:
    _, _, _, outcome, root = publish(tmp_path, lambda unit: {
        "value": 7, "terminal_status": "COMPLETED_WITH_GAPS",
        "gaps": [producer_gap("truncated", "bounded to 10 rows", unit_id="work.only", scope_id="scope-a")]})
    attempt = root / "data/jobs/job_fixture/attempts" / outcome["status"]["attempt_id"]
    receipt = json.loads((attempt / "steps/work/tasks/only/status.json").read_text(encoding="utf-8"))
    assert receipt["schema"] == TASK_RECEIPT_SCHEMA and receipt["status"] == "SUCCEEDED"
    _validator("taskReceipt").validate(receipt)
    status = json.loads((attempt / "status.json").read_text(encoding="utf-8"))
    assert status["schema"] == ATTEMPT_STATUS_SCHEMA
    _validator("attemptStatus").validate(status)
    result = json.loads((attempt / "result.json").read_text(encoding="utf-8"))
    assert result["schema"] == UNIT_EXECUTION_SCHEMA
    unit_result = json.loads((attempt / "steps/work/tasks/only/result.json").read_text(encoding="utf-8"))
    _validator("unitOutput").validate(unit_result)
    root_validator = Draft202012Validator(SCHEMA)
    for record in (receipt, status, unit_result):
        root_validator.validate(record)
    _validator("producerGap").validate(unit_result["gaps"][0])
    # A declared producer-gap/1 record passes through publication unchanged.
    published = outcome["handoff"]["outputs"]["work.only"]["gaps"][0]
    assert published == unit_result["gaps"][0]
    outcomes = json.loads((root / outcome["handoff"]["outcomes"]["path"]).read_text(encoding="utf-8"))
    assert [gap["code"] for gap in outcomes["gaps"]] == ["truncated"]


@pytest.mark.parametrize(("record_kind", "damage"), [
    ("task", "missing"), ("task", "extra"), ("attempt", "missing"), ("attempt", "status"),
])
def test_root_schema_rejects_malformed_reserved_receipts(tmp_path: Path, record_kind: str, damage: str) -> None:
    _, _, _, outcome, root = publish(tmp_path, lambda unit: {"value": 7})
    attempt = root / "data/jobs/job_fixture/attempts" / outcome["status"]["attempt_id"]
    path = attempt / ("steps/work/tasks/only/status.json" if record_kind == "task" else "status.json")
    record = json.loads(path.read_bytes())
    if damage == "missing":
        del record["unit_id" if record_kind == "task" else "job_id"]
    elif damage == "extra":
        record["arbitrary_permission"] = True
    else:
        record["status"] = "NOT_A_STATUS"
    with pytest.raises(ValidationError):
        Draft202012Validator(SCHEMA).validate(record)


def test_producer_gap_identity_matches_the_runtime_derivation() -> None:
    gap = producer_gap(GapCode.INPUT_UNAVAILABLE, "no catalog", unit_id="load.inputs", scope_id=None, retryable=True)
    assert gap["schema"] == GAP_SCHEMA and gap["code"] == "input_unavailable" and gap["retryable"] is True
    assert gap["gap_id"] == gap_id({"unit_id": "load.inputs", "scope_id": None, "code": "input_unavailable",
                                    "reason": "no catalog"})
    with pytest.raises(ValueError):
        producer_gap("not_a_code", "reason")


@pytest.mark.parametrize("result,message", [
    ({"terminal_status": "NOT_RUN"}, "ProducerStatus"),
    ({"terminal_status": ["SUCCEEDED"]}, "ProducerStatus"),
    ({"dispositions": [{"scope_id": "a", "terminal_status": "REUSED"}]}, "ProducerStatus"),
    ({"dispositions": [{"scope_id": "", "terminal_status": "FAILED"}]}, "scope_id"),
    ({"coverage_disposition": "mostly"}, "CoverageDisposition"),
    ({"gaps": "text"}, "gaps must be an array"),
    ({"gaps": [""]}, "empty text"),
    ({"gaps": [{}]}, "nonempty text or a record"),
    ({"gaps": [{"schema": GAP_SCHEMA, "gap_id": "x"}]}, "producer-gap/1"),
])
def test_unit_output_contract_violations_are_named(result, message) -> None:
    with pytest.raises(UnitOutputContractError, match=message):
        validate_unit_output(result, unit_id="work.only")


def test_strict_gaps_reject_free_text_and_accept_records() -> None:
    validate_unit_output({"gaps": ["free text"]}, unit_id="work.only")
    with pytest.raises(UnitOutputContractError, match="producer-gap/1"):
        validate_unit_output({"gaps": ["free text"]}, unit_id="work.only", strict_gaps=True)
    validate_unit_output({"gaps": [producer_gap("empty_result", "nothing to index")]},
                         unit_id="work.only", strict_gaps=True)


def test_strict_gaps_job_rejects_publication_of_a_free_text_gap(tmp_path: Path) -> None:
    from dataclasses import replace
    config, job, runner = setup(tmp_path, lambda unit: {"terminal_status": "COMPLETED_WITH_GAPS", "gaps": ["free"]})
    strict = replace(job, strict_gaps=True)
    with pytest.raises(ValueError, match="producer-gap/1"):
        runner.run(strict, source_fingerprint="snapshot")
    assert list(config.runtime.runs_dir.glob("*/data/jobs/job_fixture/attempts/*/rejected-handoff.json"))


@pytest.mark.parametrize("fails", (False, True), ids=("success", "failure"))
def test_typed_task_receipts_validate_observed_reads_without_open_fields(tmp_path: Path, fails: bool) -> None:
    from appsec_review.runtime.consume import accepted_upstream
    from tests.test_upstream_consumption import _job, _publish, _runner
    config, runner = _runner(tmp_path, "job_fixture", "job_consumer")
    first = _publish(runner, _job("job_fixture", lambda unit: {"value": 1}))
    root = config.runtime.runs_dir / first["status"]["run_id"]

    def handler(unit):
        assert accepted_upstream(root, "job_fixture").sha256 == first["handoff_sha256"]
        if fails:
            raise RuntimeError("after verified read")
        return {"value": 2}

    job = _job("job_consumer", handler, ("job_fixture",))
    claim = runner.begin_attempt(job, run_id=root.name, source_fingerprint="snapshot")
    if fails:
        with pytest.raises(RuntimeError, match="after verified read"):
            runner.execute_or_reuse_unit(job, claim, "work.only")
    else:
        runner.execute_or_reuse_unit(job, claim, "work.only")
    receipt = json.loads((root / claim["attempt_path"] / "steps/work/tasks/only/status.json").read_bytes())
    _validator("taskReceipt").validate(receipt)
    Draft202012Validator(SCHEMA).validate(receipt)
    reads = receipt["input_consumption"]
    assert reads["citation_observation"] == "not_observed"
    assert reads["reads"][0]["handoff_sha256"] == first["handoff_sha256"]
    assert reads["reads"][0]["read"] is True and reads["reads"][0]["cited"] is None
    with pytest.raises(ValidationError):
        _validator("taskReceipt").validate({**receipt, "arbitrary_permission": True})
    with pytest.raises(ValidationError):
        _validator("inputConsumption").validate({**reads, "permission": "all"})
    with pytest.raises(ValidationError):
        _validator("inputRead").validate({**reads["reads"][0], "cited": True})
