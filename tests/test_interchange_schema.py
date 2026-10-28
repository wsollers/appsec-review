from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import re

import pytest
from jsonschema import Draft202012Validator

from appsec_review.interchange import (
    ArtifactReference, CoverageSummary, NativeResultReference, ObservationMetadata, OUTCOMES_SCHEMA,
    ProducerGap, ResultSelector, UnitOutcome, gap_id,
)
from tests.test_interchange_contract import handoff_fixture


ROOT = Path(__file__).parents[1]
SCHEMA = json.loads((ROOT / "docs" / "schemas" / "job-interchange.schema.json").read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)
REFERENCE = ArtifactReference("data/native.json", "a" * 64, 10)


def test_schema_is_valid_and_offline():
    Draft202012Validator.check_schema(SCHEMA)

    def references(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "$ref":
                    assert child.startswith("#/")
                else:
                    references(child)
        elif isinstance(value, list):
            for child in value:
                references(child)

    references(SCHEMA)


@pytest.mark.parametrize("record", [
    handoff_fixture(),
    NativeResultReference(REFERENCE, ResultSelector("document"), "parser/1").as_dict(),
    NativeResultReference(REFERENCE, ResultSelector("json_pointer", "/runs/0/results/0"), "parser/1").as_dict(),
    NativeResultReference(REFERENCE, ResultSelector("xml_ordinal", {"element": "{urn:scan}Bug", "ordinal": 0}),
                          "parser/1").as_dict(),
    NativeResultReference(REFERENCE, ResultSelector("byte_range", {"start": 0, "end": 10}), "parser/1").as_dict(),
    ProducerGap(gap_id({"unit": "one"}), "provenance_unavailable", "one", None,
                "Original execution receipt unavailable", False, (REFERENCE,)).as_dict(),
    ObservationMetadata("source_sast", "finding", "fixture", "rule/1", {
        "value": "unknown", "native": "UNMAPPED", "basis": "unmapped-native-severity", "rule": "severity/1",
    }, (), (gap_id({"unit": "one"}),), "fixture/1").as_dict(),
    {"schema": OUTCOMES_SCHEMA, "run_id": "run", "job_id": "job_fixture", "attempt_id": "attempt",
     "target_snapshot": "snapshot", "units": [UnitOutcome("one", "SUCCEEDED", "SUCCEEDED", "complete",
                                                        REFERENCE, REFERENCE).as_dict()],
     "gaps": [], "coverage": CoverageSummary("complete", 0, False).as_dict()},
])
def test_schema_accepts_shared_serialized_records(record):
    VALIDATOR.validate(record)


@pytest.mark.parametrize("mutation", [
    {"schema": "appsec-review/job-handoff/1"}, {"execution_status": "FAILED"},
    {"outcomes": None}, {"coverage": {"disposition": "not_affected", "gap_count": 0, "retry_required": False}},
    {"coverage": {"disposition": "complete", "gap_count": 1, "retry_required": False}},
    {"coverage": {"disposition": "complete", "gap_count": 0, "retry_required": True}},
])
def test_schema_rejects_bad_envelope_shape(mutation):
    value = handoff_fixture()
    value.update(mutation)
    assert not VALIDATOR.is_valid(value)


@pytest.mark.parametrize("artifact_mutation", [
    {"path": "../native.json"}, {"path": "C:/native.json"}, {"path": "data\\native.json"},
    {"sha256": "z" * 64}, {"size_bytes": True}, {"size_bytes": -1}, {"unregistered": "value"},
])
def test_schema_rejects_malformed_nested_references(artifact_mutation):
    value = NativeResultReference(REFERENCE, ResultSelector("document"), "parser/1").as_dict()
    value["artifact"].update(artifact_mutation)
    assert not VALIDATOR.is_valid(value)


def test_documented_constructor_examples_remain_executable_and_schema_valid():
    document = (ROOT / "docs" / "architecture" / "job-interchange.md").read_text(encoding="utf-8")
    example = re.search(r"```python\n(.*?)\n```", document, re.DOTALL)
    assert example is not None
    output = StringIO()
    with redirect_stdout(output):
        exec(compile(example.group(1), "job-interchange.md", "exec"), {})
    records = json.loads(output.getvalue())
    assert set(records) == {"diagnostic_handoff", "accepted_handoff", "outcomes", "native_result",
                            "common_observation"}
    for record in records.values():
        VALIDATOR.validate(record)
