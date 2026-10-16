from __future__ import annotations

from dataclasses import asdict

import pytest

from appsec_review.graph import contract as c
from appsec_review.graph.analyzers import (
    ANALYZER_SINK_RULE, CHECK_SINK_CLASS, METHOD_DIAGNOSTIC_LINE, apply_analyzer_sinks, sink_class_of,
)
from tests.fixtures.graph.secondary.builder import SCOPE, SNAPSHOT, build_secondary

UPSTREAM = [{"index": "observations", "shard_id": "clang-static-proj", "sha256": "a" * 64}]


def _row(fixture, check: str, needle: str, *, scanner: str = "clang-tidy", nth: int = 0, located: bool = True) -> dict:
    location = fixture.location("src/io.c", needle, nth)
    return {"identity": f"asr:tool_observation:{check}:{needle}:{nth}", "name": check,
            "payload": {"scanner": scanner, "native_rule_id": check},
            "location": asdict(location) if located else None}


def _apply(fixture, facts, rows):
    return apply_analyzer_sinks(facts, rows, UPSTREAM, target_snapshot=SNAPSHOT, scope=SCOPE)


def _by(result, producer: str):
    return [fact for fact in result.facts if fact.payload["producer"]["name"] == producer]


def test_the_check_table_maps_only_to_real_sink_classes_and_strips_the_tidy_analyzer_prefix() -> None:
    assert {value.value for value in CHECK_SINK_CLASS.values()} <= {item.value for item in c.SinkClass}
    assert c.SinkClass.UNCLASSIFIED not in CHECK_SINK_CLASS.values()
    assert sink_class_of("clang-analyzer-security.insecureAPI.strcpy") is c.SinkClass.MEMORY_WRITE
    assert sink_class_of("security.insecureAPI.strcpy") is c.SinkClass.MEMORY_WRITE
    assert sink_class_of("unix.cstring.NullArg") is None
    assert sink_class_of("readability-magic-numbers") is None
    assert sink_class_of("") is None


def test_a_mapped_diagnostic_on_a_codeql_sink_line_corroborates_it_without_a_new_fact(tmp_path) -> None:
    fixture = build_secondary(tmp_path)
    sink = fixture.sink("memcpy(out, buf, k)")
    other = fixture.sink("read(0, buf")
    result = _apply(fixture, [sink, other], [_row(fixture, "bugprone-not-null-terminated-result", "memcpy(out, buf, k)")])
    assert len(result.facts) == 2 and result.summary["corroborated"] == 1 and result.summary["analyzer_only"] == 0
    facts = {fact.identity.value: fact for fact in result.facts}
    checked = facts[sink.identity.value]
    cross = checked.payload["cross_check"]
    assert cross["state"] == "agree"
    assert cross["producers"] == [{"name": "clang-static", "state": "agree", "method": METHOD_DIAGNOSTIC_LINE,
                                   "detail": "clang-tidy bugprone-not-null-terminated-result at line "
                                             + str(sink.location.start_line)}]
    assert checked.payload["admissibility"]["direct_eligible"] is True
    assert UPSTREAM[0] in checked.payload["upstream"]
    # A sink the analyzer says nothing about is not covered; silence is never a verdict.
    assert facts[other.identity.value].payload["cross_check"] == other.payload["cross_check"]
    checked.to_entity()


def test_a_mapped_diagnostic_of_another_class_does_not_corroborate_and_becomes_analyzer_only(tmp_path) -> None:
    fixture = build_secondary(tmp_path)
    sink = fixture.sink("memcpy(out, buf, k)")
    result = _apply(fixture, [sink], [_row(fixture, "bugprone-narrowing-conversions", "memcpy(out, buf, k)")])
    assert result.summary["corroborated"] == 0 and result.summary["analyzer_only"] == 1
    assert sink in result.facts   # the CodeQL fact is unchanged
    (added,) = _by(result, "clang-static")
    assert added.payload["result"]["sink_class"] == "integer_conversion"
    assert added.payload["exact"] is False and added.payload["coverage_status"] == "partial"
    assert added.payload["cross_check"]["state"] == "partial"
    assert added.payload["admissibility"]["direct_eligible"] is False
    assert {"inexact_location", "incomplete_coverage", "cross_check_partial"} <= set(
        added.payload["admissibility"]["ineligibility_reasons"])
    assert added.payload["gaps"][0].startswith("analyzer_only:")
    assert added.payload["producer"]["rule_version"] == ANALYZER_SINK_RULE
    assert added.location.ambiguous and added.location.start_byte == added.location.end_byte
    added.to_entity()


def test_an_analyzer_only_sink_groups_checks_at_one_point_and_has_a_stable_identity(tmp_path) -> None:
    fixture = build_secondary(tmp_path)
    rows = [_row(fixture, "security.insecureAPI.strcpy", "int m = n * 2", scanner="clang-static-analyzer"),
            _row(fixture, "bugprone-not-null-terminated-result", "int m = n * 2")]
    first = _apply(fixture, [], rows)
    second = _apply(fixture, [], list(reversed(rows)))
    (fact,) = first.facts
    assert [item.identity for item in first.facts] == [item.identity for item in second.facts]
    assert fact.payload["result"]["checks"] == ["bugprone-not-null-terminated-result", "security.insecureAPI.strcpy"]
    assert fact.payload["result"]["argument_index"] is None


def test_unmapped_and_unlocated_diagnostics_are_named_gaps_not_facts(tmp_path) -> None:
    fixture = build_secondary(tmp_path)
    rows = [_row(fixture, "unix.cstring.NullArg", "memcpy(out, buf, k)", scanner="clang-static-analyzer"),
            _row(fixture, "readability-magic-numbers", "memcpy(out, buf, k)"),
            _row(fixture, "bugprone-not-null-terminated-result", "memcpy(out, buf, k)", located=False),
            {"identity": "x", "name": "other", "payload": {"scanner": "someone-else", "native_rule_id": "cert-env33-c"},
             "location": None}]
    result = _apply(fixture, [], rows)
    assert result.facts == () and result.summary["unmapped_checks"] == {
        "readability-magic-numbers": 1, "unix.cstring.NullArg": 1}
    assert any(gap.startswith("analyzer_checks_unmapped: 2 diagnostic(s) of 2 check(s)") for gap in result.summary["gaps"])
    assert any(gap.startswith("analyzer_diagnostics_unlocated: 1") for gap in result.summary["gaps"])


def test_no_diagnostics_changes_nothing(tmp_path) -> None:
    fixture = build_secondary(tmp_path)
    sink = fixture.sink("memcpy(out, buf, k)")
    result = _apply(fixture, [sink], [])
    assert result.facts == (sink,) and result.summary["gaps"] == []


def test_an_empty_scope_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="scope_id"):
        apply_analyzer_sinks([], [], UPSTREAM, target_snapshot=SNAPSHOT, scope={"scope_id": ""})
