"""Native CI decoder units; no tool invocation or target checkout."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_ci_configuration_analysis.job import SPECS, _external_records, _source_location
from tests.ci_support import zizmor_finding

PATH = ".github/workflows/build.yml"
ZIZMOR = next(spec for spec in SPECS if spec.tool_id == "tool-zizmor")


def _decode(findings):
    return _external_records(ZIZMOR, json.dumps(findings).encode(), PATH)


@pytest.mark.parametrize("severity", ["High", "Informational", "Low", "Medium", "Unknown"])
def test_native_rule_message_severity_and_primary_span(severity: str) -> None:
    finding = zizmor_finding()
    finding["determinations"]["severity"] = severity
    span = finding["locations"][0]["concrete"]["location"]
    span["end_point"]["column"] = 33
    span["offset_span"]["end"] = 223
    assert _decode([finding]) == [{
        "provider": "github", "tool_id": "tool-zizmor", "native_rule_id": "artipacked",
        "message": finding["desc"], "severity": severity.lower(),
        "category": "dangerous-defaults-and-uncaught-static-misconfiguration",
        "path": PATH, "start_line": 15, "end_line": 15, "start_column": 9, "end_column": 34,
        "start_byte": 198, "end_byte": 223,
    }]


@pytest.mark.parametrize("primary_index", [0, 1, 2])
def test_primary_not_array_order_selects_location(primary_index: int) -> None:
    finding = zizmor_finding()
    primary = finding["locations"][0]
    secondary = deepcopy(primary)
    secondary["symbolic"]["kind"] = "Related"
    secondary["symbolic"]["key"]["Local"]["verbatim_path"] = "/foreign/related.yml"
    secondary["concrete"] = None
    hidden = deepcopy(secondary)
    hidden["symbolic"]["kind"] = "Hidden"
    finding["locations"] = [secondary, hidden]
    finding["locations"].insert(primary_index, primary)
    [record] = _decode([finding])
    assert record["start_line"] == 15 and record["path"] == PATH and record["start_byte"] == 198


@pytest.mark.parametrize("active", [False, True], ids=["ignored-only", "mixed"])
def test_ignored_findings_are_not_observations(active: bool) -> None:
    ignored = zizmor_finding()
    ignored["ignored"] = True
    findings = [ignored, zizmor_finding()] if active else [ignored]
    assert len(_decode(findings)) == int(active)


def test_relative_local_path_and_zero_based_multiline_span() -> None:
    finding = zizmor_finding(row=0, column=0, offset=0)
    primary = finding["locations"][0]
    primary["symbolic"]["key"]["Local"]["verbatim_path"] = PATH
    primary["concrete"]["location"]["end_point"] = {"row": 2, "column": 0}
    [record] = _decode([finding])
    assert (record["start_line"], record["start_column"], record["start_byte"]) == (1, 1, 0)
    assert (record["end_line"], record["end_column"]) == (3, 1)


@pytest.mark.parametrize("payload", [b"[]", b" \n[]\n"], ids=["empty-array", "surrounding-whitespace"])
def test_native_empty_array_is_clean(payload: bytes) -> None:
    assert _external_records(ZIZMOR, payload, PATH) == []


@pytest.mark.parametrize("payload", [
    b"", b" \n", b"{}", b"null", b"[null]", b"[{}]", b'[{"ignored":"false"}]',
    b"[{}", b"[]\n[]", b"warning\n[]", b'["\xff"]',
], ids=["empty", "whitespace", "object", "null", "null-entry", "empty-entry", "string-ignored",
        "truncated", "json-lines", "mixed-text", "invalid-utf8"])
def test_non_native_or_malformed_output_cannot_look_clean(payload: bytes) -> None:
    with pytest.raises(ValueError, match="Zizmor"):
        _external_records(ZIZMOR, payload, PATH)


@pytest.mark.parametrize(("keys", "value"), [
    (("ignored",), None),
    (("ident",), ""),
    (("desc",), []),
    (("determinations",), None),
    (("determinations", "severity"), 1),
    (("locations",), {}),
    (("locations",), []),
    (("locations", 0), None),
    (("locations", 0, "symbolic", "kind"), "Related"),
    (("locations", 0, "symbolic", "key"), {"Remote": {}}),
    (("locations", 0, "symbolic", "key", "Local", "verbatim_path"), "/foreign/build.yml"),
    (("locations", 0, "symbolic", "key", "Local", "verbatim_path"), "/target/../build.yml"),
    (("locations", 0, "symbolic", "key", "Local", "verbatim_path"), "/target/.github/workflows/other.yml"),
    (("locations", 0, "concrete"), None),
    (("locations", 0, "concrete", "location", "start_point"), {}),
    (("locations", 0, "concrete", "location", "start_point", "row"), -1),
    (("locations", 0, "concrete", "location", "start_point", "row"), True),
    (("locations", 0, "concrete", "location", "start_point", "column"), "8"),
    (("locations", 0, "concrete", "location", "end_point", "row"), 1),
    (("locations", 0, "concrete", "location", "end_point", "column"), 0),
    (("locations", 0, "concrete", "location", "offset_span", "start"), 1.5),
    (("locations", 0, "concrete", "location", "offset_span", "end"), 0),
], ids=["missing-ignored", "empty-rule", "bad-message", "missing-determinations", "bad-severity",
        "bad-locations", "no-primary", "bad-location", "related-only", "remote-primary",
        "foreign-primary", "traversal-primary", "other-definition", "missing-concrete",
        "missing-point", "negative-row", "boolean-row", "string-column", "reversed-rows",
        "reversed-columns", "float-offset", "reversed-offsets"])
def test_malformed_finding_is_explicit_even_alongside_valid_output(keys, value) -> None:
    finding = zizmor_finding()
    current = finding
    for key in keys[:-1]:
        current = current[key]
    current[keys[-1]] = value
    with pytest.raises(ValueError, match="Zizmor finding 1"):
        _decode([zizmor_finding(), finding])


def test_ambiguous_primary_is_not_arbitrarily_bound() -> None:
    finding = zizmor_finding()
    finding["locations"].append(deepcopy(finding["locations"][0]))
    with pytest.raises(ValueError, match="Primary"):
        _decode([finding])


def test_native_message_retains_existing_bound() -> None:
    finding = zizmor_finding()
    finding["desc"] = "x" * 5000
    assert _decode([finding])[0]["message"] == "x" * 4096


def test_zero_byte_span_is_not_replaced_with_a_whole_source_line(tmp_path: Path) -> None:
    source = tmp_path / PATH
    source.parent.mkdir(parents=True)
    source.write_text("name: workflow\n")
    [record] = _decode([zizmor_finding(row=0, column=0, offset=0, feature="")])
    unit = SimpleNamespace(job=SimpleNamespace(target_root=tmp_path, source_fingerprint="a" * 64))
    location = _source_location(unit, record)
    assert location is not None and location.start_byte == location.end_byte == 0
    assert location.start_line == location.end_line == location.start_column == location.end_column == 1


@pytest.mark.parametrize(("tool_id", "payload", "rule", "line"), [
    ("tool-checkov", b'{"results":{"failed_checks":[{"check_id":"CKV_GHA_7","check_name":"check",'
                     b'"file_line_range":[3,4],"severity":"HIGH"}]}}', "CKV_GHA_7", 3),
    ("tool-actionlint", b'[{"kind":"syntax-check","message":"check","line":7,"column":3}]', "syntax-check", 7),
    ("tool-actionlint", b'{"kind":"syntax-check","message":"check","line":7}\n'
                       b'{"kind":"other","message":"next","line":9}', "syntax-check", 7),
], ids=["checkov", "actionlint-array", "actionlint-json-lines"])
def test_other_tools_keep_the_generic_decoder(tool_id: str, payload: bytes, rule: str, line: int) -> None:
    spec = next(spec for spec in SPECS if spec.tool_id == tool_id)
    records = _external_records(spec, payload, PATH)
    record = records[0]
    assert (record["native_rule_id"], record["message"], record["start_line"]) == (rule, "check", line)
    assert record["path"] == PATH
    if tool_id == "tool-checkov":
        assert record["severity"] == "high" and record["end_line"] == 4
    if b"\n" in payload:
        assert len(records) == 2 and records[1]["native_rule_id"] == "other"


@pytest.mark.parametrize("tool_id", ["tool-actionlint", "tool-checkov"])
def test_other_tools_keep_empty_output_compatibility(tool_id: str) -> None:
    spec = next(spec for spec in SPECS if spec.tool_id == tool_id)
    for payload in (b"", b"{}", b"[]"):
        assert _external_records(spec, payload, PATH) == []
