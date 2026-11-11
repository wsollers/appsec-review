"""Coverage, the denominator of every finding count, and hunt-lane value (T-068)."""
from __future__ import annotations

import copy

import pytest

from appsec_review.observability.findings import contracts as c
from appsec_review.observability.findings import coverage as cov
from appsec_review.observability.findings.identity import fingerprint


def finding(finding_id="F1", **changes):
    value = {"finding_id": finding_id, "state": "confirmed", "weakness_cwe": "CWE-121", "severity": "high",
             "lane": "hunt", "scanner_backed": False,
             "locations": [{"path": "src/net/parse.c", "start_line": 10, "end_line": 12,
                            "function": f"fn_{finding_id}", "code": "strcpy(b, p);"}]}
    value.update(changes)
    return value


def snapshot(findings, **changes):
    arguments = dict(run_id="run-1", target_id="game", source_revision="a" * 40, findings=findings,
                     fingerprint=fingerprint)
    arguments.update(changes)
    return c.build_snapshot(**arguments)


def entry(entry_id="E1", kind="parser", status="reviewed", reason=None, path="src/net/parse.c"):
    return {"entry_id": entry_id, "kind": kind, "path": path, "status": status, "reason": reason}


# ------------------------------------------------------------------------------ entry points

def test_entry_point_coverage_counts_by_status_kind_and_reason():
    catalogue = [
        entry("p2", "parser", "not_admitted", "budget_exhausted"),
        entry("p1", "parser"),
        entry("n1", "network_handler"),
        entry("n2", "network_handler", "not_built", "platform_excluded"),
        entry("n3", "network_handler", "not_admitted", "budget_exhausted"),
        entry("r1", "rpc_handler", "not_built", "platform_excluded"),
    ]
    before = copy.deepcopy(catalogue)
    result = cov.entry_point_coverage(catalogue)
    assert catalogue == before
    assert result["available"] is True and result["total"] == 6
    assert result["by_status"] == {"reviewed": 2, "not_admitted": 2, "not_built": 2}
    assert result["reviewed_share"] == c.ratio(2, 6) and "interval" not in result["reviewed_share"]
    assert list(result["by_kind"]) == ["file_loader", "network_handler", "parser", "rpc_handler"]
    assert result["by_kind"]["network_handler"] == {
        "total": 3, "by_status": {"reviewed": 1, "not_admitted": 1, "not_built": 1}, "reviewed_share": c.ratio(1, 3)}
    assert result["by_kind"]["file_loader"] == {
        "total": 0, "by_status": {"reviewed": 0, "not_admitted": 0, "not_built": 0}, "reviewed_share": c.ratio(0, 0)}
    assert result["by_kind"]["file_loader"]["reviewed_share"]["status"] == "empty_denominator"
    assert result["by_kind"]["rpc_handler"]["reviewed_share"]["value"] == 0.0
    assert result["uncovered_by_reason"] == {"budget_exhausted": 2, "platform_excluded": 2}
    assert list(result["uncovered_by_reason"]) == ["budget_exhausted", "platform_excluded"]
    assert result["uncovered"] == [
        {"entry_id": "n2", "kind": "network_handler", "status": "not_built", "reason": "platform_excluded"},
        {"entry_id": "n3", "kind": "network_handler", "status": "not_admitted", "reason": "budget_exhausted"},
        {"entry_id": "p2", "kind": "parser", "status": "not_admitted", "reason": "budget_exhausted"},
        {"entry_id": "r1", "kind": "rpc_handler", "status": "not_built", "reason": "platform_excluded"},
    ]
    assert result["uncovered_truncated"] == 0


def test_entry_point_coverage_is_independent_of_input_order():
    catalogue = [entry("b", "parser", "not_built", "x"), entry("a", "file_loader"), entry("c", "parser")]
    assert cov.entry_point_coverage(catalogue) == cov.entry_point_coverage(list(reversed(catalogue)))


def test_a_missing_catalogue_is_unavailable_and_an_empty_one_is_not_zero_coverage():
    assert cov.entry_point_coverage(None) == {"available": False, "reason": "entry_point_catalog_unavailable"}
    empty = cov.entry_point_coverage([])
    assert empty["total"] == 0 and empty["reviewed_share"]["value"] is None
    assert empty["reviewed_share"]["status"] == "empty_denominator"
    assert empty["uncovered"] == [] and empty["uncovered_by_reason"] == {}


def test_a_reviewed_row_may_omit_its_reason():
    row = {"entry_id": "E1", "kind": "parser", "path": "a.c", "status": "reviewed"}
    assert cov.entry_point_coverage([row])["by_status"]["reviewed"] == 1


@pytest.mark.parametrize("catalogue", [
    "not a list",
    ["row"],
    [entry("a"), entry("a")],
    [entry(kind="socket")],
    [entry(status="skipped", reason="x")],
    [entry(reason="because")],
    [entry(status="not_admitted")],
    [entry(status="not_built", reason="")],
    [entry(status="not_built", reason="a\nb")],
    [entry(status="not_built", reason=7)],
    [entry(entry_id="")],
    [entry(entry_id=None)],
    [entry(path="/abs/a.c")],
    [entry(path=None)],
    [{**entry(), "owner": "x"}],
], ids=["not-list", "not-object", "duplicate-id", "kind", "status", "reviewed-with-reason", "missing-reason",
        "empty-reason", "multiline-reason", "reason-type", "empty-id", "null-id", "absolute-path", "null-path",
        "unknown-field"])
def test_entry_point_coverage_refuses_invalid_catalogues(catalogue):
    with pytest.raises(ValueError):
        cov.entry_point_coverage(catalogue)


def test_uncovered_listing_truncates_at_its_exact_bound():
    def catalogue(count):
        return [entry(f"e{index:04d}", status="not_built", reason="platform_excluded") for index in range(count)]

    exact = cov.entry_point_coverage(catalogue(cov.MAX_UNCOVERED_LISTED))
    assert len(exact["uncovered"]) == cov.MAX_UNCOVERED_LISTED and exact["uncovered_truncated"] == 0
    over = cov.entry_point_coverage(catalogue(cov.MAX_UNCOVERED_LISTED + 1))
    assert len(over["uncovered"]) == cov.MAX_UNCOVERED_LISTED and over["uncovered_truncated"] == 1
    assert over["uncovered"][-1]["entry_id"] == "e0199"
    assert over["uncovered_by_reason"] == {"platform_excluded": 201}, "the counts are never truncated"


def test_entry_point_catalogue_bound_is_exact():
    template = entry()
    catalogue = [{**template, "entry_id": str(index)} for index in range(cov.MAX_ENTRY_POINTS)]
    assert cov.entry_point_coverage(catalogue)["total"] == cov.MAX_ENTRY_POINTS
    catalogue.append({**template, "entry_id": "one-more"})
    with pytest.raises(ValueError):
        cov.entry_point_coverage(catalogue)


# ------------------------------------------------------------------------------------- units

def test_unit_coverage_reports_reviewed_share_reasons_and_content_identity():
    built = snapshot([finding()], reviewed_units={"src/a.c": "b" * 64, "src/b.c": None, "src/c.c": "c" * 64},
                     unreviewed_units={"src/y.c": "not_built", "src/x.c": "budget_exhausted", "src/z.c": "not_built"})
    before = copy.deepcopy(built)
    result = cov.unit_coverage(built)
    assert built == before
    assert result == {"available": True, "reviewed": 3, "content_identity_known": 2, "unreviewed": 3,
                      "unreviewed_by_reason": {"budget_exhausted": 1, "not_built": 2},
                      "reviewed_share": c.ratio(3, 6)}
    assert list(result["unreviewed_by_reason"]) == ["budget_exhausted", "not_built"]


def test_unknown_coverage_is_unavailable_never_zero():
    assert cov.unit_coverage(snapshot([finding()])) == {"available": False, "reason": "coverage_unknown"}
    assert cov.unit_coverage(snapshot([finding()], unreviewed_units={"a.c": "not_built"})) == {
        "available": False, "reason": "coverage_unknown"}


def test_unknown_unreviewed_units_leave_the_share_unavailable():
    result = cov.unit_coverage(snapshot([], reviewed_units={"src/a.c": None}))
    assert result["reviewed"] == 1 and result["unreviewed"] is None and result["unreviewed_by_reason"] is None
    assert result["reviewed_share"]["status"] == "unavailable"
    assert result["reviewed_share"]["reason"] == "unreviewed_units_unknown"


def test_known_empty_coverage_is_an_empty_denominator():
    result = cov.unit_coverage(snapshot([], reviewed_units={}, unreviewed_units={}))
    assert result["reviewed"] == 0 and result["unreviewed"] == 0
    assert result["reviewed_share"]["status"] == "empty_denominator"
    full = cov.unit_coverage(snapshot([], reviewed_units={"a.c": None}, unreviewed_units={}))
    assert full["reviewed_share"]["value"] == 1.0


def test_unit_coverage_refuses_a_unit_counted_twice_and_a_foreign_snapshot():
    with pytest.raises(ValueError):
        cov.unit_coverage(snapshot([], reviewed_units={"a.c": None}, unreviewed_units={"a.c": "not_built"}))
    with pytest.raises(ValueError):
        cov.unit_coverage({"schema": "other"})


# ------------------------------------------------------------------------- translation units

def test_translation_units_reports_both_shares_over_the_total():
    result = cov.translation_units(80, 60, 100)
    assert result == {"available": True, "built": 80, "extracted": 60, "total": 100,
                      "built_share": c.ratio(80, 100), "extracted_share": c.ratio(60, 100)}
    assert cov.translation_units(100, 100, 100)["extracted_share"]["value"] == 1.0
    assert cov.translation_units(0, 0, 0)["built_share"]["status"] == "empty_denominator"


@pytest.mark.parametrize("built, extracted, total, built_reason, extracted_reason", [
    (None, 5, 10, "built_count_unavailable", None),
    (None, None, 10, "built_count_unavailable", "extracted_count_unavailable"),
    (None, None, None, "translation_unit_total_unavailable", "translation_unit_total_unavailable"),
    (8, 5, None, "translation_unit_total_unavailable", "translation_unit_total_unavailable"),
    (8, None, 10, None, "extracted_count_unavailable"),
], ids=["no-built", "no-counts", "nothing", "no-total", "no-extracted"])
def test_translation_units_names_each_unavailable_input(built, extracted, total, built_reason, extracted_reason):
    result = cov.translation_units(built, extracted, total)
    for share, reason in ((result["built_share"], built_reason), (result["extracted_share"], extracted_reason)):
        if reason is None:
            assert share["status"] == "measured"
        else:
            assert (share["status"], share["reason"], share["value"]) == ("unavailable", reason, None)
    assert (result["built"], result["extracted"], result["total"]) == (built, extracted, total)


@pytest.mark.parametrize("built, extracted, total", [
    (-1, 0, 10), (1.5, 1, 10), (5, -1, 10), (5, 6, 10), (5, 6, None), (5, True, 10), (5, 1, "10"), (5, 1, -1),
    (11, 5, 10), (None, 11, 10), (True, 0, 10),
], ids=["negative-built", "float-built", "negative-extracted", "extracted-over-built", "extracted-over-built-no-total",
        "bool-extracted", "text-total", "negative-total", "built-over-total", "extracted-over-total", "bool-built"])
def test_translation_units_refuses_impossible_counts(built, extracted, total):
    with pytest.raises(ValueError):
        cov.translation_units(built, extracted, total)


def test_translation_unit_boundaries_are_inclusive():
    assert cov.translation_units(10, 10, 10)["built_share"]["value"] == 1.0
    with pytest.raises(ValueError):
        cov.translation_units(10, 11, 11)
    with pytest.raises(ValueError):
        cov.translation_units(11, 10, 10)


# ---------------------------------------------------------------------------------- hunt lane

def test_hunt_lane_value_counts_only_published_scanner_independent_hunt_findings():
    built = snapshot([
        finding("H1"),
        finding("H2", state="supported", severity="medium", weakness_cwe="CWE-78"),
        finding("H3", scanner_backed=True),
        finding("H4", scanner_backed=None),
        finding("H5", severity=None, weakness_cwe=None),
        finding("L1", lane="lead"),
        finding("N1", lane=None),
        finding("X1", state="contradicted"),
    ])
    before = copy.deepcopy(built)
    result = cov.hunt_lane_value(built)
    assert built == before
    assert result["available"] is True and result["published"] == 7 and result["hunt_published"] == 5
    assert result["scanner_independent"] == {
        "count": 3, "finding_ids": ["H1", "H2", "H5"],
        "by_weakness_family": {"injection": 1, "memory_safety": 1, "null": 1},
        "by_severity": {"low": 0, "medium": 1, "high": 1, "critical": 0, "null": 1},
    }
    assert result["scanner_backed"] == 1 and result["scanner_backing_unknown"] == 1
    assert result["share_of_published"] == c.ratio(3, 7, interval=True)
    assert result["confirmed_actionable_scanner_independent"] == 1


def test_unknown_scanner_backing_is_never_counted_as_independent():
    result = cov.hunt_lane_value(snapshot([finding("A", scanner_backed=None), finding("B", scanner_backed=None)]))
    assert result["scanner_independent"]["count"] == 0 and result["scanner_backing_unknown"] == 2
    assert result["share_of_published"]["value"] == 0.0 and result["share_of_published"]["denominator"] == 2


def test_hunt_lane_value_without_published_findings_has_an_empty_denominator():
    result = cov.hunt_lane_value(snapshot([finding(state="contradicted")]))
    assert result["published"] == 0 and result["scanner_independent"]["finding_ids"] == []
    assert result["scanner_independent"]["by_weakness_family"] == {"null": 0}
    assert result["share_of_published"]["status"] == "empty_denominator"
    assert result["share_of_published"]["value"] is None and result["share_of_published"]["interval"] is None
    with pytest.raises(ValueError):
        cov.hunt_lane_value({"schema": "other"})
