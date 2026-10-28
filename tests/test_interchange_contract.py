from __future__ import annotations

import copy
from types import MappingProxyType

import pytest

from appsec_review.interchange import (
    ArtifactReference, CoverageDisposition, CoverageSummary, HANDOFF_SCHEMA, NativeResultReference,
    ObservationMetadata, ResultSelector, artifact_reference_from_mapping, classify_producer_status,
    decode_handoff, gap_id, handoff_input_projection, input_set_sha256,
    native_result_reference_from_mapping, observation_metadata_from_mapping,
)


def handoff_fixture() -> dict:
    artifact = ArtifactReference("data/outcomes.json", "a" * 64, 10).as_dict()
    value = {
        "schema": HANDOFF_SCHEMA, "run_id": "run", "job_id": "job_fixture", "attempt_id": "attempt",
        "status": "ACCEPTED", "completion_status": "SUCCEEDED", "execution_status": "SUCCEEDED",
        "outputs": {}, "artifacts": [artifact], "upstream_handoff_sha256": {},
        "resolved_config_sha256": "b" * 64, "job_config_sha256": "c" * 64,
        "source_fingerprint": "snapshot", "target_snapshot": "snapshot",
        "implementation_identity": "fixture/1", "schema_identity": "fixture/1",
        "validation_identity": "fixture/1", "tool_identity": {"python": "3.14"},
        "input_identity": None, "input_manifest": None, "dataset_contract_sha256": "d" * 64,
        "coverage": CoverageSummary("complete", 0, False).as_dict(), "outcomes": artifact,
        "resolving_paths": {"attempt": "data/attempt", "result": "data/attempt/result.json"},
        "started_at": "2026-10-28T00:00:00+00:00", "completed_at": "2026-10-28T00:00:01+00:00",
    }
    value["input_set_sha256"] = input_set_sha256(handoff_input_projection(value))
    return value


@pytest.mark.parametrize("path", ["../a", "/a", "C:/a", "a\\b", "a//b", "a/./b", "a/../b", "a/"])
def test_artifact_paths_are_canonical_run_relative(path):
    with pytest.raises(ValueError):
        ArtifactReference(path, "a" * 64, 0)


@pytest.mark.parametrize("size", [True, -1, "1", 1.0, None])
def test_artifact_size_is_not_coerced(size):
    with pytest.raises(ValueError):
        ArtifactReference("data/a", "a" * 64, size)


@pytest.mark.parametrize("digest", ["A" * 64, "a" * 63, "a" * 65, "z" * 64, None])
def test_artifact_hash_is_exact(digest):
    with pytest.raises(ValueError):
        ArtifactReference("data/a", digest, 0)


def test_artifact_decoder_rejects_unknown_fields():
    with pytest.raises(ValueError):
        artifact_reference_from_mapping({"path": "data/a", "sha256": "a" * 64, "size_bytes": 0, "raw": "x"})


@pytest.mark.parametrize(("kind", "value"), [
    ("document", None), ("json_pointer", ""), ("json_pointer", "/runs/0/results/1"),
    ("json_pointer", "/files/a~1b~0c"), ("xml_ordinal", {"element": "BugInstance", "ordinal": 0}),
    ("byte_range", {"start": 0, "end": 10}),
])
def test_native_reference_round_trip(kind, value):
    record = NativeResultReference(ArtifactReference("data/report", "a" * 64, 10),
                                   ResultSelector(kind, value), "parser/1")
    assert native_result_reference_from_mapping(record.as_dict()) == record


@pytest.mark.parametrize(("kind", "value"), [
    ("unknown", None), ("document", "/result"), ("json_pointer", "result"),
    ("json_pointer", "/bad~"), ("json_pointer", "/bad~2"),
    ("xml_ordinal", {"element": "Bug", "ordinal": True}),
    ("xml_ordinal", {"element": "Bug", "ordinal": -1}),
    ("byte_range", {"start": 10, "end": 9}),
    ("byte_range", {"start": False, "end": 1}),
])
def test_invalid_result_selector_rejected(kind, value):
    with pytest.raises(ValueError):
        ResultSelector(kind, value)


def test_native_range_cannot_escape_retained_bytes():
    with pytest.raises(ValueError):
        NativeResultReference(ArtifactReference("data/report", "a" * 64, 10),
                              ResultSelector("byte_range", {"start": 0, "end": 11}), "parser/1")


def test_observation_common_metadata_round_trip():
    record = ObservationMetadata(
        "source_sast", "observation", "codeql", "rule/1",
        {"value": "unknown", "native": "UNMAPPED", "basis": "unmapped-native-severity", "rule": "severity/1"},
        (NativeResultReference(ArtifactReference("data/report", "a" * 64, 10),
                               ResultSelector("json_pointer", "/runs/0/results/0"), "parser/1"),),
        (), "codeql-observation/1",
    )
    assert observation_metadata_from_mapping(record.as_dict()) == record
    changed = record.as_dict()
    changed["reported_severity"]["value"] = "not_affected"
    with pytest.raises(ValueError):
        observation_metadata_from_mapping(changed)


@pytest.mark.parametrize(("status", "disposition", "retry"), [
    ("SUCCEEDED", "complete", False), ("FAILED", "unavailable", True),
    ("TIMED_OUT", "unavailable", True), ("BLOCKED_BY_COMPILE", "unavailable", True),
    ("PARTIAL", "partial", False), ("COMPLETED_WITH_GAPS", "partial", False),
    ("NOT_APPLICABLE", "not_applicable", False), ("SKIPPED_POLICY", "skipped_policy", False),
    ("CONFIGURED_DISABLED", "skipped_policy", False), ("unexpected", "unavailable", False),
])
def test_producer_execution_is_not_security_impact(status, disposition, retry):
    result = classify_producer_status(status)
    assert result.disposition == disposition
    assert result.retry_required is retry
    assert "not_affected" not in set(CoverageDisposition)


def test_gapped_success_is_partial_and_false_complete_is_rejected():
    assert classify_producer_status("SUCCEEDED", has_gaps=True).disposition == "partial"
    with pytest.raises(ValueError):
        classify_producer_status("FAILED", coverage_disposition="complete")
    with pytest.raises(ValueError):
        CoverageSummary("complete", 1, False)


def test_input_hash_is_deterministic_and_target_sensitive():
    assert input_set_sha256({"b": 2, "a": 1}) == input_set_sha256({"a": 1, "b": 2})
    assert input_set_sha256({"a": 1}) != input_set_sha256({"a": 2})
    assert gap_id({"unit": "a"}) != gap_id({"unit": "b"})


def test_read_only_mappings_serialize_without_pickle_or_mutation():
    severity = MappingProxyType({"value": "unknown", "native": "UNKNOWN", "basis": "unmapped", "rule": "severity/1"})
    record = ObservationMetadata("other", "observation", "fixture", "rule", severity, (), (), "fixture/1")
    document = record.as_dict()
    assert document["reported_severity"] == dict(severity)
    document["reported_severity"]["value"] = "high"
    assert severity["value"] == "unknown"
    identity = MappingProxyType({"nested": MappingProxyType({"value": (1, 2)})})
    assert input_set_sha256(identity) == input_set_sha256({"nested": {"value": [1, 2]}})


def test_handoff_round_trip_and_identity_checks():
    handoff = handoff_fixture()
    assert decode_handoff(handoff, run_id="run", job_id="job_fixture") == handoff
    for kwargs in ({"run_id": "another"}, {"job_id": "another"}):
        with pytest.raises(ValueError):
            decode_handoff(handoff, **kwargs)


@pytest.mark.parametrize("mutation", [
    {"schema": "appsec-review/job-handoff/1"}, {"execution_status": "FAILED"},
    {"status": "REJECTED"}, {"target_snapshot": "changed"}, {"outcomes": None},
    {"artifacts": []}, {"evidence_target_snapshot": "another"}, {"input_set_sha256": "0" * 64},
])
def test_handoff_rejects_incompatible_or_conflicting_identities(mutation):
    handoff = handoff_fixture()
    handoff.update(mutation)
    with pytest.raises(ValueError):
        decode_handoff(handoff)


def test_rejected_diagnostic_is_explicitly_not_operational_input():
    handoff = handoff_fixture()
    handoff.update(status="REJECTED", execution_status="FAILED")
    assert decode_handoff(handoff, accepted_only=False)["status"] == "REJECTED"
    with pytest.raises(ValueError):
        decode_handoff(handoff)


def test_reference_aliases_cannot_disagree():
    handoff = copy.deepcopy(handoff_fixture())
    handoff["outcomes"] = {**handoff["outcomes"], "size_bytes": handoff["outcomes"]["size_bytes"] + 1}
    with pytest.raises(ValueError):
        decode_handoff(handoff)
