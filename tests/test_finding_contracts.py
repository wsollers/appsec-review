"""The shared finding-metrics contract and the revision-independent fingerprint (T-060)."""
from __future__ import annotations

import pytest

from appsec_review.observability.findings import contracts as c
from appsec_review.observability.findings.identity import fingerprint, match_findings, match_tier, normalize_code

CODE = "void f(char *p) {\n  char b[8];\n  strcpy(b, p); // copy\n}\n"


def finding(finding_id="F1", **changes):
    value = {"finding_id": finding_id, "state": "confirmed", "weakness_cwe": "CWE-121", "severity": "high",
             "lane": "lead", "locations": [{"path": "src/net/parse.c", "start_line": 10, "end_line": 12,
                                            "function": "parse_packet", "code": CODE}]}
    value.update(changes)
    return value


def located(path="src/net/parse.c", line=10, function="parse_packet", code=CODE):
    return [{"path": path, "start_line": line, "end_line": line + 2, "function": function, "code": code}]


def snapshot(findings, **changes):
    arguments = dict(run_id="run-1", target_id="game", source_revision="a" * 40, findings=findings,
                     fingerprint=fingerprint)
    arguments.update(changes)
    return c.build_snapshot(**arguments)


def test_ratio_reports_value_status_and_wilson_interval():
    measured = c.ratio(7, 10, interval=True)
    assert measured["value"] == 0.7 and measured["status"] == "measured" and measured["reason"] is None
    # The published Wilson interval for 7/10 at 95% is (0.3968, 0.8922).
    assert measured["interval"]["low"] == pytest.approx(0.3968, abs=1e-4)
    assert measured["interval"]["high"] == pytest.approx(0.8922, abs=1e-4)
    assert measured["interval"]["level"] == 0.95
    assert c.ratio(0, 7, interval=True)["interval"]["low"] == 0.0
    assert c.ratio(7, 7, interval=True)["interval"]["high"] == 1.0


def test_ratio_never_turns_a_missing_input_into_zero():
    empty = c.ratio(0, 0, interval=True)
    assert (empty["value"], empty["status"], empty["reason"], empty["interval"]) == (
        None, "empty_denominator", "zero_denominator", None)
    missing = c.ratio(None, None, reason="no_prior_run")
    assert (missing["value"], missing["status"], missing["reason"]) == (None, "unavailable", "no_prior_run")


@pytest.mark.parametrize("numerator, denominator", [(-1, 3), (4, 3), (True, 3), (1, -2)], ids=str)
def test_ratio_refuses_impossible_proportions(numerator, denominator):
    with pytest.raises(ValueError):
        c.ratio(numerator, denominator)


def test_unavailable_section_needs_a_named_reason():
    assert c.unavailable("no_answer_key") == {"available": False, "reason": "no_answer_key"}
    with pytest.raises(ValueError):
        c.unavailable("")


def test_counts_are_zero_filled_and_keep_unestablished_values_as_their_own_row():
    table = c.counts(["high", None, "high"], c.SEVERITY_BANDS)
    assert table == {"low": 0, "medium": 0, "high": 2, "critical": 0, "null": 1}
    with pytest.raises(ValueError):
        c.counts(["severe"], c.SEVERITY_BANDS)


@pytest.mark.parametrize("value, expected", [("CWE-120", "CWE-120"), ("cwe-120", "CWE-120"), ("120", "CWE-120"),
                                             (120, "CWE-120"), ("CWE-0120", "CWE-120"), ("buffer", None),
                                             (True, None), (None, None)], ids=str)
def test_normalize_cwe(value, expected):
    assert c.normalize_cwe(value) == expected


def test_weakness_family_groups_related_cwes_and_keeps_unknown_ones_apart():
    assert c.weakness_family("CWE-121") == c.weakness_family("CWE-787") == "memory_safety"
    assert c.weakness_family("CWE-602") == "authorization_and_trust"
    assert c.weakness_family("CWE-9999") == "CWE-9999"
    assert c.weakness_family(None) is None
    members = [number for numbers in c.WEAKNESS_FAMILIES.values() for number in numbers]
    assert len(members) == len(set(members)), "a CWE belongs to exactly one family"


@pytest.mark.parametrize("path", ["/abs/a.c", "a/../../b.c", "C:/a.c", "a\\b.c", "", "..", "a\nb"], ids=repr)
def test_location_paths_must_be_target_relative_posix(path):
    with pytest.raises(ValueError):
        c.normalize_path(path)


def test_normalize_path_collapses_redundant_segments():
    assert c.normalize_path("./src//net/./parse.c") == "src/net/parse.c"


def test_normalize_finding_defaults_unestablished_fields_to_null():
    record = c.normalize_finding(finding())
    assert record["attacker_position"] is None and record["ownership"] is None
    assert record["build_configuration"] is None and record["scanner_backed"] is None
    assert record["actionability"] == {"entry_to_sink_path": None, "preconditions": None, "remediation": None,
                                       "remediation_validated": None}
    assert record["citations"] == {"total": None, "unresolved": None}
    assert record["duplicates_collapsed"] == 0 and record["lead_families"] == []


@pytest.mark.parametrize("change", [
    {"severity": "severe"}, {"lane": "other"}, {"attacker_position": "remote"}, {"ownership": "vendor"},
    {"weakness_cwe": "overflow"}, {"locations": []}, {"finding_id": ""}, {"note": "x"},
    {"citations": {"total": 1, "unresolved": 2}}, {"scanner_backed": "yes"}, {"duplicates_collapsed": -1},
    {"locations": [{"path": "a.c", "start_line": 5, "end_line": 4}]},
    {"actionability": {"exploit": True}},
], ids=lambda change: next(iter(change)))
def test_normalize_finding_refuses_open_vocabularies_and_unknown_fields(change):
    with pytest.raises(ValueError):
        c.normalize_finding(finding(**change))


def test_published_and_actionable_predicates():
    assert c.is_published({"state": "supported"}) and not c.is_published({"state": "contradicted"})
    assert c.is_actionable({"state": "confirmed", "severity": "critical"})
    assert not c.is_actionable({"state": "supported", "severity": "critical"})
    assert not c.is_actionable({"state": "confirmed", "severity": None})


# ------------------------------------------------------------------------------- fingerprint

def test_normalize_code_ignores_comments_and_whitespace_but_keeps_directives():
    assert normalize_code("a  =  b; /* x */\n// gone\n#include <x.h>\n") == "a = b; #include <x.h>"
    assert normalize_code("  /* only */ ") is None and normalize_code(None) is None


def test_fingerprint_ignores_revision_lines_severity_and_prose():
    base = fingerprint(c.normalize_finding(finding()))
    moved_lines = fingerprint(c.normalize_finding(finding(locations=located(line=400))))
    reworded = fingerprint(c.normalize_finding(finding(severity="low", state="supported", finding_id="other")))
    recommented = fingerprint(c.normalize_finding(finding(locations=located(code=CODE.replace("// copy", "")))))
    assert base == moved_lines == reworded == recommented
    assert base["basis"] == "function_and_code" and base["exact"] != base["relocated"]


def test_fingerprint_changes_with_family_function_and_code():
    base = fingerprint(c.normalize_finding(finding()))
    other_family = fingerprint(c.normalize_finding(finding(weakness_cwe="CWE-78")))
    other_function = fingerprint(c.normalize_finding(finding(locations=located(function="parse_header"))))
    other_code = fingerprint(c.normalize_finding(finding(locations=located(code=CODE.replace("b[8]", "b[16]")))))
    assert len({base["exact"], other_family["exact"], other_function["exact"], other_code["exact"]}) == 4
    same_family = fingerprint(c.normalize_finding(finding(weakness_cwe="CWE-787")))
    assert same_family == base, "one root cause named by two CWEs of a family is one finding"


def test_a_moved_file_matches_at_the_relocated_tier_only():
    base = fingerprint(c.normalize_finding(finding()))
    moved = fingerprint(c.normalize_finding(finding(locations=located(path="src/proto/parse.c"))))
    assert match_tier(base, base) is c.MatchTier.EXACT
    assert match_tier(base, moved) is c.MatchTier.RELOCATED
    unrelated = fingerprint(c.normalize_finding(finding(locations=located(function="other", code="x();"))))
    assert match_tier(base, unrelated) is None


def test_a_path_only_finding_cannot_be_recognised_after_a_move():
    here = fingerprint(c.normalize_finding(finding(locations=located(function=None, code=None))))
    there = fingerprint(c.normalize_finding(finding(locations=located(path="b.c", function=None, code=None))))
    assert here["basis"] == "path_only" and here["exact"] == here["relocated"]
    assert match_tier(here, there) is None and match_tier(here, here) is c.MatchTier.EXACT


def test_fingerprints_of_another_version_are_not_comparable():
    base = fingerprint(c.normalize_finding(finding()))
    with pytest.raises(ValueError):
        match_tier({**base, "version": "finding-fingerprint/0"}, base)


def test_match_findings_prefers_exact_matches_and_uses_each_current_finding_once():
    prior = snapshot([finding("P1"), finding("P2", locations=located(path="src/old/parse.c"))])["findings"]
    assert len(prior) == 2
    current = snapshot([finding("C1", locations=located(path="src/new/parse.c")), finding("C2")],
                       run_id="run-2")["findings"]
    matches = match_findings(prior, current)
    assert matches == {"P1": ("C2", c.MatchTier.EXACT), "P2": ("C1", c.MatchTier.RELOCATED)}


# ---------------------------------------------------------------------------------- snapshot

def test_snapshot_collapses_duplicate_root_causes_and_counts_them():
    built = snapshot([finding("B"), finding("A"), finding("C", weakness_cwe="CWE-78")])
    assert [item["finding_id"] for item in built["findings"]] == ["A", "C"]
    assert built["findings"][0]["duplicates_collapsed"] == 1
    assert c.check_snapshot(built) == built


def test_snapshot_is_deterministic_for_any_input_order():
    one = snapshot([finding("A"), finding("C", weakness_cwe="CWE-78")], gaps=["b", "a"])
    two = snapshot([finding("C", weakness_cwe="CWE-78"), finding("A")], gaps=["a", "b", "a"])
    assert c.digest(one) == c.digest(two) and one["gaps"] == ["a", "b"]


def test_snapshot_keeps_unknown_coverage_as_null_not_empty():
    assert snapshot([finding()])["reviewed_units"] is None
    covered = snapshot([finding()], reviewed_units={"./src/net/parse.c": "b" * 64, "src/x.c": None},
                       unreviewed_units={"src/y.c": "not_built"})
    assert covered["reviewed_units"] == {"src/net/parse.c": "b" * 64, "src/x.c": None}
    assert covered["unreviewed_units"] == {"src/y.c": "not_built"}


@pytest.mark.parametrize("change", [{"stage": "final"}, {"configuration_sha256": "abc"}, {"run_id": ""},
                                    {"reviewed_units": {"a.c": "nothex"}}],
                         ids=lambda change: next(iter(change)))
def test_snapshot_refuses_invalid_identity(change):
    with pytest.raises(ValueError):
        snapshot([finding()], **change)


def test_check_snapshot_refuses_foreign_or_tampered_documents():
    built = snapshot([finding()])
    with pytest.raises(ValueError):
        c.check_snapshot({**built, "schema": "appsec-review/finding-snapshot/0"})
    with pytest.raises(ValueError):
        c.check_snapshot({**built, "extra": 1})
    broken = {**built, "findings": [{**built["findings"][0], "fingerprint": {"version": "x"}}]}
    with pytest.raises(ValueError):
        c.check_snapshot(broken)
