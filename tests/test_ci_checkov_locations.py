"""Checkov line-only ranges bound to real source bytes, without invoking a tool."""
from __future__ import annotations

from copy import deepcopy
import json

import pytest

from appsec_review.jobs.job_ci_configuration_analysis.job import (
    SPECS, _checkov_source_records, _external_records, correlation_key,
)

PATH = "bitbucket-pipelines.yml"
SPEC = next(spec for spec in SPECS if spec.key == "bitbucket_checkov")
SOURCE = (b"image: alpine:latest\n\npipelines:\n  default:\n    - step:\n"
          b"        name: Build\n        script:\n          - echo hi\n          - echo done\n")


def _records(span, **paths):
    item = {
        "check_id": "CKV_BITBUCKETPIPELINES_1", "check_name": "pipeline image version", "severity": "HIGH",
        "file_abs_path": f"/target/{PATH}", "file_path": f"/{PATH}", "file_line_range": span, **paths,
    }
    return _external_records(SPEC, json.dumps({"results": {"failed_checks": [item]}}).encode(), PATH)


@pytest.mark.parametrize("start", [1, 3])
@pytest.mark.parametrize("ending", ["lf", "crlf", "no-final-newline"])
def test_clipped_range_retains_native_provenance_and_verified_byte_coordinates(start, ending) -> None:
    data = SOURCE
    if ending == "crlf":
        data = data.replace(b"\n", b"\r\n")
    elif ending == "no-final-newline":
        data = data.rstrip(b"\n")
    records = _records([start, 11])
    original = deepcopy(records)
    [record] = _checkov_source_records(records, PATH, data)
    lines = data.splitlines(keepends=True)
    assert (record["start_line"], record["end_line"]) == (start, 9)
    assert (record["start_byte"], record["end_byte"]) == (
        sum(len(line) for line in lines[:start - 1]), len(data.rstrip(b"\r\n")))
    assert record["start_column"] == 1 and record["end_column"] == len(lines[-1].rstrip(b"\r\n")) + 1
    assert record["mapping_method"] == "checkov-line-range-clipped"
    assert record["ambiguous"] is True and record["confidence"] == 0.5
    assert record["producer_location"]["file_line_range"] == [start, 11]
    assert record["producer_location"]["source_line_count"] == 9
    assert record["producer_location"]["reason"] == "native_end_line_exceeds_source"
    assert records == original, "native records are not rewritten in place"


def test_five_findings_survive_and_in_bounds_population_is_unchanged() -> None:
    ranges = [[1, 1], [2, 3], [4, 6], [1, 11], [8, 9]]
    records = [record for span in ranges for record in _records(span)]
    bound = _checkov_source_records(records, PATH, SOURCE)
    assert len(bound) == 5
    for before, after in zip(records, bound, strict=True):
        assert after["native_rule_id"] == before["native_rule_id"]
        assert after["message"] == before["message"] and after["severity"] == "high"
        assert after["category"] == before["category"]
        if before["end_line"] <= 9:
            assert after == {key: value for key, value in before.items() if key != "producer_location"}


@pytest.mark.parametrize("span", [None, [], [1], [1, 2, 3], [0, 3], [-1, 3], [True, 3],
                                  ["1", 3], [1.5, 3], [3, 2], [10, 11]],
                         ids=["missing", "empty", "short", "long", "zero", "negative", "boolean",
                              "string", "float", "reversed", "outside-source"])
def test_unusable_native_range_never_becomes_a_line_one_fallback(span) -> None:
    records = _records([1, 1])
    records[0]["producer_location"]["file_line_range"] = span
    with pytest.raises(ValueError, match="Checkov"):
        _checkov_source_records(records, PATH, SOURCE)


@pytest.mark.parametrize(("key", "value"), [
    ("file_abs_path", "/foreign/bitbucket-pipelines.yml"),
    ("file_abs_path", "/target/other.yml"),
    ("file_abs_path", "/target/../bitbucket-pipelines.yml"),
    ("file_path", "/other.yml"),
    ("file_path", "../bitbucket-pipelines.yml"),
], ids=["foreign-absolute", "other-file", "absolute-traversal", "foreign-relative", "relative-traversal"])
def test_foreign_paths_are_not_rebound_to_the_scanned_file(key, value) -> None:
    with pytest.raises(ValueError, match="does not identify"):
        _checkov_source_records(_records([1, 11], **{key: value}), PATH, SOURCE)


def test_empty_source_is_not_a_synthetic_line_one() -> None:
    with pytest.raises(ValueError, match="does not overlap"):
        _checkov_source_records(_records([1, 11]), PATH, b"")
    assert _checkov_source_records([], PATH, b"") == []


def test_clipping_does_not_merge_distinct_native_spans_or_claim_an_exact_match() -> None:
    [one] = _checkov_source_records(_records([1, 11]), PATH, SOURCE)
    [two] = _checkov_source_records(_records([1, 12]), PATH, SOURCE)
    exact = {key: value for key, value in one.items()
             if key not in {"producer_location", "mapping_method", "confidence", "ambiguous"}}
    assert correlation_key(one) != correlation_key(two)
    assert correlation_key(one) != correlation_key(exact)
    assert correlation_key(one) == correlation_key(deepcopy(one))
