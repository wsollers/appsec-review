"""Reviewed source files and entry points derived from a run's verified documents (T-073).

The documents have the shapes a run records: package ``scope.source_ids`` (``review.packages``), the
projection's cell records (``review.ledger.cell_json``), the manifest's ``units`` rows, accepted
``source_file`` rows with their content hash, and ``tag-assignment/1`` subjects. Reading a real
accepted index set and real package bodies is the integration test's job; here the loader is run
only against runs that cannot give those documents, and is otherwise the injected boundary.
"""
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from appsec_review.observability.findings import coverage, coverage_adapter as adapter
from appsec_review.observability.findings.contracts import build_snapshot
from appsec_review.observability.findings.coverage_adapter import CoverageDocuments, entry_points, reviewed_units
from appsec_review.observability.findings.identity import fingerprint
from tests.test_triage_reduction_metrics import Lead, Scenario, build_run

A, B = "a" * 64, "b" * 64


def source(name):
    return f"asr:source_file:{name}"


def catalog(**files):
    """``name=(path, sha256, built)`` rows of the accepted source catalog."""
    return {source(name): {"path": path, "sha256": content, "built": built}
            for name, (path, content, built) in files.items()}


def package(package_id, *names):
    return {"package_id": package_id, "source_ids": [source(name) for name in names]}


def cells(*rows):
    """``(cell id, package id, role, status)`` terminal records, as the projection keeps them."""
    table: dict[str, list[dict]] = {}
    for cell_id, package_id, role, status in rows:
        table.setdefault(cell_id, []).append(
            {"schema": "appsec-review/review-cell/1", "cell_id": cell_id, "lane": "hunt", "package_id": package_id,
             "role": role, "persona": None, "stack_profile": None, "task": "hunt", "claim_id": None,
             "status": status, "attempts": 1, "gap_ids": [], "receipt_sha256": "9" * 64})
    return table


HUNTER, RED, BLUE = "hypothesis_hunter", "red_team_analyst", "blue_team_refuter"
CATALOG = catalog(parse=("net/parse.c", A, True), rpc=("net/rpc.c", B, True), safe=("net/safe.c", None, True),
                  idle=("net/idle.c", A, True), tool=("tools/gen.c", B, False), lonely=("misc/lonely.c", A, None))
DOCUMENTS = CoverageDocuments(
    catalog=CATALOG,
    packages=[package("hunt-1", "parse", "safe"), package("hunt-2", "rpc"), package("lead-1", "rpc", "parse"),
              package("hunt-3", "idle"), package("hunt-4", "tool", "ghost")],
    cells=cells(("c1", "hunt-1", HUNTER, "succeeded"), ("c2", "hunt-1", HUNTER, "succeeded"),
                ("c3", "hunt-2", HUNTER, "succeeded"), ("c4", "hunt-2", HUNTER, "timed_out"),
                ("c5", "lead-1", RED, "invalid"), ("c6", "hunt-3", HUNTER, "not_launched"),
                ("c7", "hunt-1", BLUE, "failed")),          # only red cells decide whether a package was reviewed
    units=[{"unit_key": "u1", "hunted": True}, {"unit_key": "u2", "hunted": False},
           {"unit_key": "u3", "hunted": False}],
    tags=[])


def test_a_file_is_reviewed_only_when_a_completed_package_contained_it():
    before = copy.deepcopy(DOCUMENTS)

    reviewed, unreviewed, gaps = reviewed_units(DOCUMENTS)

    assert DOCUMENTS == before
    # parse.c is also in the failed lead-1 package: one completed package is enough
    assert reviewed == {"net/parse.c": A, "net/safe.c": None}
    assert unreviewed == {"misc/lonely.c": "not_packaged", "net/idle.c": "not_launched",
                          "net/rpc.c": "cells_incomplete", "tools/gen.c": "not_launched"}
    assert set(unreviewed.values()) <= set(adapter.UNREVIEWED_REASONS)
    assert list(reviewed) == sorted(reviewed) and list(unreviewed) == sorted(unreviewed)
    # the source the catalog does not hold is counted, never listed; un-hunted units explain not_packaged
    assert gaps == ["package_sources_outside_catalog:1", "units_below_hunt_cutoff:2"]
    snapshot = build_snapshot(run_id="r1", target_id="game", source_revision="1" * 40, findings=[],
                              fingerprint=fingerprint, reviewed_units=reviewed, unreviewed_units=unreviewed)
    assert coverage.unit_coverage(snapshot)["reviewed_share"]["numerator"] == 2


@pytest.mark.parametrize(("records", "state"), [
    ([("c1", "p", HUNTER, "succeeded")], "reviewed"),
    ([("c1", "p", RED, "succeeded"), ("c2", "p", RED, "succeeded")], "reviewed"),
    ([("c1", "p", HUNTER, "succeeded"), ("c2", "p", HUNTER, "failed")], "cells_incomplete"),
    ([("c1", "p", HUNTER, "succeeded"), ("c2", "p", HUNTER, "not_launched")], "cells_incomplete"),
    ([("c1", "p", HUNTER, "blocked")], "cells_incomplete"),
    ([("c1", "p", HUNTER, "canceled")], "cells_incomplete"),
    ([("c1", "p", HUNTER, "not_launched")], "not_launched"),
    ([("c1", "p", BLUE, "succeeded")], "not_launched"),
    ([("c1", "other", HUNTER, "succeeded")], "not_launched"),
    ([], "not_launched"),
], ids=["one-red", "all-red", "one-failed", "one-not-launched", "blocked", "canceled", "none-launched", "blue-only",
        "another-package", "no-cells"])
def test_a_package_is_completed_only_when_every_red_cell_succeeded(records, state):
    documents = CoverageDocuments(catalog=catalog(f=("a.c", A, True)), packages=[package("p", "f")],
                                  cells=cells(*records), units=[])
    reviewed, unreviewed, gaps = reviewed_units(documents)
    assert gaps == []
    assert (reviewed, unreviewed) == (({"a.c": A}, {}) if state == "reviewed" else ({}, {"a.c": state}))


@pytest.mark.parametrize(("missing", "gap"), [
    ("catalog", "reviewed_units_not_derived:catalog_unavailable"),
    ("packages", "reviewed_units_not_derived:packages_unavailable"),
    ("cells", "reviewed_units_not_derived:cells_unavailable"),
], ids=["catalog", "packages", "cells"])
def test_a_missing_document_is_null_units_with_a_named_gap_never_empty_units(missing, gap):
    documents = CoverageDocuments(**{**{name: getattr(DOCUMENTS, name) for name in (
        "catalog", "packages", "cells", "units", "tags")}, missing: None})
    assert reviewed_units(documents) == (None, None, [gap])


def test_the_loaders_own_gap_is_kept_as_the_reason():
    documents = CoverageDocuments(gaps=("reviewed_units_not_derived:accepted_index_differs_from_review",))
    assert reviewed_units(documents) == (None, None, ["reviewed_units_not_derived:accepted_index_differs_from_review"])


@pytest.mark.parametrize(("files", "message"), [
    ({"f": ("/abs/a.c", A, True)}, "not target-relative"),
    ({"f": ("../a.c", A, True)}, "escapes the target"),
    ({"f": ("a.c", "not-a-hash", True)}, "not a SHA-256"),
], ids=["absolute", "escaping", "bad-hash"])
def test_an_unusable_catalog_row_is_refused(files, message):
    with pytest.raises(ValueError, match=message):
        reviewed_units(CoverageDocuments(catalog=catalog(**files), packages=[], cells={}))


def test_the_catalog_bound_is_enforced(monkeypatch):
    monkeypatch.setattr(adapter, "MAX_SOURCE_FILES", 1)
    with pytest.raises(ValueError, match="bounded number"):
        reviewed_units(CoverageDocuments(catalog=catalog(a=("a.c", A, True), b=("b.c", A, True)), packages=[],
                                         cells={}))


# ------------------------------------------------------------------------------------ entry points

def tag(term, name, path):
    return {"tag": term, "subject_id": source(name), "path": path}


def test_the_tag_to_kind_table_is_the_taxonomys_entry_group_and_leaves_parser_out():
    assert adapter.ENTRY_KIND_BY_TAG == {
        "surface:entry:remote-input": "network_handler",
        "surface:entry:http-public": "network_handler", "surface:entry:http-internal": "network_handler",
        "surface:entry:message-consumer": "network_handler", "surface:entry:rpc": "rpc_handler",
        "surface:entry:file-input": "file_loader"}
    assert set(adapter.ENTRY_KIND_BY_TAG.values()) <= set(coverage.ENTRY_POINT_KINDS)
    assert adapter.UNMAPPED_ENTRY_KINDS == ("parser",)
    # every mapped term is a term of the pinned vocabulary's ``surface`` namespace
    import json
    vocabulary = json.loads((Path(__file__).parents[1] / "data" / "reference" / "taxonomy" / "vocabulary.json")
                            .read_text(encoding="utf-8"))
    assert set(adapter.ENTRY_KIND_BY_TAG) <= set(vocabulary["namespaces"]["surface"]["terms"])


def test_entry_points_take_the_status_of_their_file():
    documents = CoverageDocuments(
        catalog=DOCUMENTS.catalog, packages=DOCUMENTS.packages, cells=DOCUMENTS.cells, units=DOCUMENTS.units,
        tags=[tag("surface:entry:http-public", "parse", "net/parse.c"),
              tag("surface:entry:http-public", "parse", "net/parse.c"),            # one entry per tag and subject
              tag("surface:entry:http-internal", "safe", "./net/safe.c"),
              tag("surface:entry:message-consumer", "idle", "net/idle.c"),
              tag("surface:entry:rpc", "rpc", "net/rpc.c"),
              tag("surface:entry:file-input", "tool", "tools/gen.c"),
              tag("surface:entry:file-input", "lonely", "misc/lonely.c"),
              tag("surface:entry:rpc", "gone", "net/gone.c"),
              {"tag": "surface:entry:rpc", "subject_id": None, "path": "net/parse.c"},
              tag("surface:entry:cli", "parse", "net/parse.c"), tag("surface:entry:env-config", "parse", "net/parse.c"),
              tag("surface:entry:rpc", "nowhere", None), tag("surface:entry:rpc", "abs", "/etc/passwd")])
    before = copy.deepcopy(documents)
    reviewed, unreviewed, _ = reviewed_units(documents)

    rows, gaps = entry_points(documents, reviewed, unreviewed)

    assert documents == before
    assert [(row["kind"], row["path"], row["status"], row["reason"]) for row in rows] == [
        ("file_loader", "misc/lonely.c", "not_admitted", "not_packaged"),
        ("file_loader", "tools/gen.c", "not_built", "no_build_unit"),
        ("network_handler", "net/safe.c", "reviewed", None),
        ("network_handler", "net/parse.c", "reviewed", None),
        ("network_handler", "net/idle.c", "not_admitted", "not_launched"),
        ("rpc_handler", "net/gone.c", "not_admitted", "not_catalogued"),
        ("rpc_handler", "net/rpc.c", "not_admitted", "cells_incomplete"),
        ("rpc_handler", "net/parse.c", "reviewed", None)]
    assert [row["entry_id"] for row in rows] == sorted(row["entry_id"] for row in rows)
    assert rows[-1]["entry_id"] == "surface:entry:rpc@net/parse.c", "a subject without an identity is named by path"
    assert {row["reason"] for row in rows if row["reason"]} <= set(adapter.ENTRY_REASONS)
    assert gaps == ["entry_point_kind_unmapped:parser", "entry_tags_without_kind:2", "entry_tags_without_path:2"]
    measured = coverage.entry_point_coverage(rows)
    assert measured["by_status"] == {"reviewed": 3, "not_admitted": 4, "not_built": 1}
    assert measured["by_kind"]["parser"]["total"] == 0 and measured["reviewed_share"]["denominator"] == 8


@pytest.mark.parametrize(("tags", "units", "code"), [
    (None, ({}, {}), "security_tags_unavailable"),
    ([tag("surface:entry:rpc", "rpc", "net/rpc.c")], (None, None), "reviewed_units_unavailable"),
    ([], ({}, {}), "no_entry_point_tags"),
    ([tag("surface:entry:cli", "parse", "net/parse.c")], ({}, {}), "no_entry_point_tags"),
], ids=["no-tag-index", "no-units", "no-tags", "only-unmapped-tags"])
def test_an_underivable_catalogue_is_null_with_its_reason_never_an_empty_list(tags, units, code):
    documents = CoverageDocuments(catalog={}, packages=[], cells={}, tags=tags)
    rows, gaps = entry_points(documents, *units)
    assert rows is None and f"entry_points_not_derived:{code}" in gaps
    assert "entry_point_kind_unmapped:parser" in gaps


def test_a_row_that_is_not_an_entry_tag_and_the_bound_are_refused(monkeypatch):
    documents = CoverageDocuments(catalog={}, packages=[], cells={}, tags=[tag("func:net:grpc", "rpc", "net/rpc.c")])
    with pytest.raises(ValueError, match="not an entry-point tag"):
        entry_points(documents, {}, {})
    monkeypatch.setattr(adapter, "MAX_ENTRY_POINTS", 0)
    with pytest.raises(ValueError, match="bounded number"):
        entry_points(documents, {}, {})


# ------------------------------------------------------------------------------------------ loader

def test_the_loader_names_a_run_without_an_accepted_review(tmp_path):
    documents = adapter.load_coverage_documents(tmp_path / "runs" / "absent")
    assert documents == CoverageDocuments(gaps=("reviewed_units_not_derived:review_handoff_unavailable",))
    assert adapter.coverage_from_run(tmp_path / "runs" / "absent") == {
        "reviewed": None, "unreviewed": None,
        "unit_gaps": ["reviewed_units_not_derived:review_handoff_unavailable"], "entry_points": None,
        "entry_gaps": ["entry_point_kind_unmapped:parser", "entry_points_not_derived:security_tags_unavailable",
                       "reviewed_units_not_derived:review_handoff_unavailable"]}


def test_the_loader_refuses_package_bodies_that_name_no_scope_sources(tmp_path):
    # the triage fixture's hash-bound package bodies carry a lead menu and no scope
    run_root = build_run(tmp_path, Scenario(leads=[Lead("L1", outcome="no_proposal")]))
    documents = adapter.load_coverage_documents(run_root)
    assert documents == CoverageDocuments(gaps=("reviewed_units_not_derived:package_unreadable",))


def test_coverage_from_run_uses_the_injected_loader(tmp_path):
    calls = []

    def loader(run_root):
        calls.append(run_root)
        return CoverageDocuments(catalog=CATALOG, packages=DOCUMENTS.packages, cells=DOCUMENTS.cells, units=[],
                                 tags=[tag("surface:entry:rpc", "rpc", "net/rpc.c")])

    derived = adapter.coverage_from_run(tmp_path / "r1", loader=loader)

    assert calls == [tmp_path / "r1"]
    assert derived["reviewed"] == {"net/parse.c": A, "net/safe.c": None}
    assert derived["unit_gaps"] == ["package_sources_outside_catalog:1"]
    assert derived["entry_points"] == [{"entry_id": f"surface:entry:rpc@{source('rpc')}", "kind": "rpc_handler",
                                        "path": "net/rpc.c", "status": "not_admitted", "reason": "cells_incomplete"}]
    assert derived["entry_gaps"] == ["entry_point_kind_unmapped:parser"]
