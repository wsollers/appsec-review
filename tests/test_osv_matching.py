"""OSV version matching against the snapshot's own index (T-013).

The matcher decides one package version against the advisories ``index/osv.sqlite`` lists for that
package. A version it cannot decide is a named gap, never "not affected". Indexes here are built by
the real osv_sync index step from tiny archives; nothing downloads, scans or launches a tool.
"""

from __future__ import annotations

from dataclasses import asdict
import itertools
import json
from pathlib import Path
import sqlite3
import tomllib
from typing import Any
import zipfile

import pytest

from appsec_review import osv_matching
from appsec_review.indexing import products
from appsec_review.indexing.store import ShardSet
from appsec_review.jobs.job_third_party_data_sync.steps.osv_sync import feed as osv_feed
from appsec_review.osv_matching import Bounds, evaluate_record, match_package, match_packages, semver_key
from appsec_review.retrieval import EntityKind, EntityRecord, IndexBuilder, IndexIdentity, LogicalIdentity
from appsec_review.storage import file_sha256


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = "target-sha256:" + "7" * 64


def _events(*pairs: tuple[str, str]) -> list[dict[str, str]]:
    return [{kind: version} for kind, version in pairs]


def _advisory(identifier: str, ecosystem: str, name: str, *, ranges: list[tuple[str, list[dict[str, str]]]] = (),
              versions: list[str] | None = None, withdrawn: str | None = None,
              aliases: list[str] = ()) -> dict[str, Any]:
    entry: dict[str, Any] = {"package": {"ecosystem": ecosystem, "name": name},
                             "ranges": [{"type": kind, "events": events} for kind, events in ranges]}
    if versions is not None:
        entry["versions"] = versions
    document: dict[str, Any] = {"id": identifier, "modified": "2026-01-02T00:00:00Z", "summary": identifier,
                                "aliases": list(aliases), "affected": [entry]}
    if withdrawn:
        document["withdrawn"] = withdrawn
    return document


def _build_index(tmp_path: Path, archives: dict[str, list[dict[str, Any]]]) -> Path:
    """``index/osv.sqlite`` as the real osv_sync index step builds it from per-ecosystem archives."""
    work = tmp_path / "work"
    work.mkdir(parents=True)
    settings = osv_feed.OsvSettings.from_mapping(tmp_path, {"feed_root": str(tmp_path / "feed"),
                                                            "ecosystems": sorted(archives)})
    fetched: dict[str, Any] = {"schema": "appsec-review/osv-fetch/1", "ecosystems": sorted(archives), "archives": {}}
    for ecosystem, records in sorted(archives.items()):
        path = work / f"{ecosystem}.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for record in records:
                archive.writestr(zipfile.ZipInfo(f"{record['id']}.json", date_time=(2026, 1, 1, 0, 0, 0)),
                                 json.dumps(record, sort_keys=True))
        fetched["archives"][ecosystem] = {"path": str(path)}
    indexed = osv_feed.index(settings, fetched, work)
    assert indexed["schema"] == osv_feed.INDEX_SCHEMA == "appsec-review/osv-index/2"
    return Path(indexed["database_path"])


def _open(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)


# --- Semantic Versioning 2.0.0 precedence ------------------------------------------------------------

SEMVER_ASCENDING = ("0.0.0-0", "0.0.0", "0.9.10", "1.0.0-0", "1.0.0-1", "1.0.0-alpha", "1.0.0-alpha.1",
                    "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0",
                    "1.0.1", "1.2.0", "1.10.0", "2.0.0-a-b", "2.0.0", "10.0.0")


def test_semver_precedence_is_a_strict_total_order_over_the_specification_examples() -> None:
    keys = [semver_key(item) for item in SEMVER_ASCENDING]
    assert None not in keys
    for (left, left_key), (right, right_key) in itertools.combinations(zip(SEMVER_ASCENDING, keys), 2):
        assert left_key < right_key, (left, right)
    assert sorted(keys) == keys


@pytest.mark.parametrize("left,right", [("1.0.0", "1.0.0+build.1"), ("1.0.0-rc.1+a", "1.0.0-rc.1+b.2")])
def test_semver_build_metadata_does_not_take_part_in_precedence(left: str, right: str) -> None:
    assert semver_key(left) == semver_key(right) is not None


NOT_SEMVER = ("", "1", "1.0", "1.0.0.0", "01.0.0", "1.00.0", "1.0.0-", "1.0.0-01", "1.0.0-a..b", "1.0.0+", "v1.0.0",
              "=1.0.0", " 1.0.0", "1.0.0 ", "1.0.x", "^1.0.0", ">=1.0.0", "1.0.0-béta", "１.0.0", "1.0.0\n")


@pytest.mark.parametrize("text", NOT_SEMVER, ids=[f"text{index}" for index in range(len(NOT_SEMVER))])
def test_text_that_is_not_strict_semver_has_no_precedence_key(text: str) -> None:
    assert semver_key(text) is None


# --- OSV range and versions semantics ----------------------------------------------------------------

SV, ECO, GIT = "SEMVER", "ECOSYSTEM", "GIT"
ZERO_FIXED = [(SV, _events(("introduced", "0"), ("fixed", "1.2.3")))]
WINDOW = [(SV, _events(("introduced", "1.0.0"), ("fixed", "2.0.0")))]
LAST = [(SV, _events(("introduced", "1.0.0"), ("last_affected", "1.5.0")))]
OPEN = [(SV, _events(("introduced", "1.0.0")))]
TWO_INTERVALS = [(SV, _events(("fixed", "1.1.3"), ("introduced", "1.1.0"), ("fixed", "1.0.5"), ("introduced", "0")))]
TWO_RANGES = [(SV, _events(("introduced", "0"), ("fixed", "1.0.5"))),
              (SV, _events(("introduced", "1.1.0"), ("fixed", "1.1.3")))]
ONE_VERSION = [(SV, _events(("introduced", "1.0.0"), ("last_affected", "1.0.0")))]
ADJACENT = [(SV, _events(("introduced", "0"), ("fixed", "1.2.0"), ("introduced", "1.2.0"), ("fixed", "1.3.0")))]
LIMITED = [(SV, _events(("introduced", "1.0.0"), ("limit", "2.0.0")))]
UNLIMITED = [(SV, _events(("introduced", "1.0.0"), ("limit", "*")))]
ECOSYSTEM_WINDOW = [(ECO, _events(("introduced", "1.0.0"), ("fixed", "2.0.0")))]
GIT_ONLY = [(GIT, _events(("introduced", "0"), ("fixed", "a" * 40)))]

# (id, ecosystem, ranges, versions, queried version, status, gaps)
CASES = [
    ("zero-first", "npm", ZERO_FIXED, None, "0.0.0", "affected", []),
    ("zero-below-fixed", "npm", ZERO_FIXED, None, "1.2.2", "affected", []),
    ("zero-fixed-prerelease", "npm", ZERO_FIXED, None, "1.2.3-rc.1", "affected", []),
    ("zero-at-fixed", "npm", ZERO_FIXED, None, "1.2.3", "not_affected", []),
    ("zero-fixed-build", "npm", ZERO_FIXED, None, "1.2.3+build", "not_affected", []),
    ("zero-above-fixed", "npm", ZERO_FIXED, None, "9.0.0", "not_affected", []),
    ("window-below", "npm", WINDOW, None, "0.9.9", "not_affected", []),
    ("window-introduced-prerelease", "npm", WINDOW, None, "1.0.0-beta", "not_affected", []),
    ("window-at-introduced", "npm", WINDOW, None, "1.0.0", "affected", []),
    ("window-inside", "npm", WINDOW, None, "1.9.9", "affected", []),
    ("window-fixed-prerelease", "npm", WINDOW, None, "2.0.0-alpha", "affected", []),
    ("window-at-fixed", "npm", WINDOW, None, "2.0.0", "not_affected", []),
    ("last-at", "npm", LAST, None, "1.5.0", "affected", []),
    ("last-at-build", "npm", LAST, None, "1.5.0+b", "affected", []),
    ("last-after", "npm", LAST, None, "1.5.1", "not_affected", []),
    ("last-before-introduced", "npm", LAST, None, "0.5.0", "not_affected", []),
    ("open-above", "npm", OPEN, None, "99.0.0", "affected", []),
    ("open-below", "npm", OPEN, None, "0.1.0", "not_affected", []),
    ("intervals-first", "npm", TWO_INTERVALS, None, "1.0.4", "affected", []),
    ("intervals-gap", "npm", TWO_INTERVALS, None, "1.0.7", "not_affected", []),
    ("intervals-second", "npm", TWO_INTERVALS, None, "1.1.0", "affected", []),
    ("intervals-after", "npm", TWO_INTERVALS, None, "1.1.3", "not_affected", []),
    ("ranges-first", "npm", TWO_RANGES, None, "1.0.4", "affected", []),
    ("ranges-gap", "npm", TWO_RANGES, None, "1.0.5", "not_affected", []),
    ("ranges-second", "npm", TWO_RANGES, None, "1.1.2", "affected", []),
    ("one-version-at", "npm", ONE_VERSION, None, "1.0.0", "affected", []),
    ("one-version-after", "npm", ONE_VERSION, None, "1.0.1", "not_affected", []),
    ("adjacent-boundary", "npm", ADJACENT, None, "1.2.0", "affected", []),
    ("adjacent-end", "npm", ADJACENT, None, "1.3.0", "not_affected", []),
    ("limit-inside", "npm", LIMITED, None, "1.5.0", "affected", []),
    ("limit-at", "npm", LIMITED, None, "2.0.0", "not_affected", []),
    ("limit-above", "npm", LIMITED, None, "3.0.0", "not_affected", []),
    ("limit-star", "npm", UNLIMITED, None, "3.0.0", "affected", []),
    ("ecosystem-npm", "npm", ECOSYSTEM_WINDOW, None, "1.5.0", "affected", []),
    ("ecosystem-crates", "crates.io", ECOSYSTEM_WINDOW, None, "2.0.0", "not_affected", []),
    ("ecosystem-go-v", "Go", ECOSYSTEM_WINDOW, None, "v1.5.0", "affected", []),
    ("go-pseudo", "Go", [(SV, _events(("introduced", "0"), ("fixed", "0.0.0-20210101000000-abcdefabcdef")))], None,
     "v0.0.0-20200101000000-abcdef123456", "affected", []),
    ("go-incompatible", "Go", WINDOW, None, "v2.0.0+incompatible", "not_affected", []),
    ("npm-v-prefix", "npm", WINDOW, None, "v1.5.0", "undetermined", ["version_unparseable:npm"]),
    ("ecosystem-pypi", "PyPI", ECOSYSTEM_WINDOW, None, "1.5.0", "undetermined", ["range_ordering_unsupported:PyPI"]),
    ("ecosystem-pypi-outside", "PyPI", ECOSYSTEM_WINDOW, None, "9.0.0", "undetermined",
     ["range_ordering_unsupported:PyPI"]),
    ("ecosystem-maven", "Maven", ECOSYSTEM_WINDOW, None, "1.5.0", "undetermined",
     ["range_ordering_unsupported:Maven"]),
    ("ecosystem-debian-release", "Debian:11", ECOSYSTEM_WINDOW, None, "1.5.0", "undetermined",
     ["range_ordering_unsupported:Debian:11"]),
    ("semver-range-any-ecosystem", "PyPI", WINDOW, None, "1.5.0", "affected", []),
    ("semver-range-any-ecosystem-out", "PyPI", WINDOW, None, "2.0.0", "not_affected", []),
    ("semver-range-odd-version", "PyPI", WINDOW, None, "1.5", "undetermined", ["version_unparseable:PyPI"]),
    ("versions-exact-any-ecosystem", "PyPI", [], ["1.0", "1.5.post1"], "1.5.post1", "affected", []),
    ("versions-miss-unordered", "PyPI", [], ["1.0"], "1.0.0", "undetermined", ["range_ordering_unsupported:PyPI"]),
    ("versions-miss-ordered", "npm", [], ["1.0.0", "1.0.1"], "1.0.2", "not_affected", []),
    ("versions-equal-precedence", "npm", [], ["1.0.0"], "1.0.0+build", "affected", []),
    ("versions-exact-odd-version", "npm", ECOSYSTEM_WINDOW, ["1.5"], "1.5", "affected", []),
    ("versions-miss-odd-version", "npm", [], ["1.0.0"], "1.x", "undetermined", ["version_unparseable:npm"]),
    ("versions-and-range", "npm", WINDOW, ["0.5.0"], "0.5.0", "affected", []),
    ("git-only", "npm", GIT_ONLY, None, "1.0.0", "undetermined", ["range_type_unsupported:GIT"]),
    ("git-with-versions-miss", "npm", GIT_ONLY, ["1.0.0"], "1.0.1", "not_affected", []),
    ("git-with-versions-hit", "npm", GIT_ONLY, ["1.0.0"], "1.0.0", "affected", []),
    ("git-with-range-miss", "npm", [*GIT_ONLY, *WINDOW], None, "2.0.0", "not_affected", []),
    ("git-with-versions-miss-unordered", "PyPI", GIT_ONLY, ["1.0"], "1.1", "undetermined",
     ["range_ordering_unsupported:PyPI"]),
    ("unknown-range-type", "npm", [("CALVER", _events(("introduced", "0")))], None, "1.0.0", "undetermined",
     ["range_type_unsupported:CALVER"]),
    ("event-unparseable", "npm", [(SV, _events(("introduced", "0"), ("fixed", "1.x")))], None, "1.0.0",
     "undetermined", ["range_event_unparseable:npm"]),
    ("event-unparseable-beside-hit", "npm", [(SV, _events(("introduced", "0"), ("fixed", "1.x"))), *WINDOW], None,
     "1.0.0", "affected", []),
    ("no-introduced", "npm", [(SV, _events(("fixed", "1.0.0")))], None, "0.5.0", "undetermined",
     ["malformed_range:no_introduced_event"]),
    ("empty-events", "npm", [(SV, [])], None, "0.5.0", "undetermined", ["malformed_range:events"]),
    ("two-key-event", "npm", [(SV, [{"introduced": "0", "fixed": "1.0.0"}])], None, "0.5.0", "undetermined",
     ["malformed_range:event"]),
    ("unknown-event", "npm", [(SV, _events(("introduced", "0"), ("patched", "1.0.0")))], None, "0.5.0",
     "undetermined", ["malformed_range:event"]),
    ("no-version-data", "npm", [], None, "1.0.0", "undetermined", ["affected_entry_has_no_version_data"]),
    ("empty-versions-list", "npm", [], [], "1.0.0", "undetermined", ["affected_entry_has_no_version_data"]),
]


@pytest.mark.parametrize("ecosystem,ranges,versions,version,status,gaps", [case[1:] for case in CASES],
                         ids=[case[0] for case in CASES])
def test_affected_versions_and_ranges_decide_one_version(ecosystem, ranges, versions, version, status, gaps) -> None:
    document = _advisory("OSV-1", ecosystem, "widget", ranges=ranges, versions=versions)

    verdict = evaluate_record(json.dumps(document), None, ecosystem, "widget", version)

    assert (verdict["status"], verdict["gaps"]) == (status, gaps)
    assert (verdict["evidence"] is not None) == (status == "affected")


def test_matched_range_and_versions_entries_are_returned_as_resolving_evidence() -> None:
    ranged = json.dumps(_advisory("OSV-1", "npm", "widget", ranges=TWO_RANGES))
    assert evaluate_record(ranged, None, "npm", "widget", "1.1.2")["evidence"] == {
        "kind": "range", "range_type": "SEMVER", "ordering": "semver-2.0.0", "introduced": "1.1.0",
        "fixed": "1.1.3", "affected_index": 0, "range_index": 1}
    assert evaluate_record(json.dumps(_advisory("OSV-1", "npm", "widget", ranges=LAST)), None, "npm", "widget",
                           "1.5.0")["evidence"] == {
        "kind": "range", "range_type": "SEMVER", "ordering": "semver-2.0.0", "introduced": "1.0.0",
        "last_affected": "1.5.0", "affected_index": 0, "range_index": 0}
    assert evaluate_record(json.dumps(_advisory("OSV-1", "npm", "widget", ranges=LIMITED)), None, "npm", "widget",
                           "1.5.0")["evidence"]["limits"] == ["2.0.0"]
    listed = json.dumps(_advisory("OSV-1", "PyPI", "widget", versions=["0.9", "1.0"]))
    assert evaluate_record(listed, None, "PyPI", "widget", "1.0")["evidence"] == {
        "kind": "versions", "affected_index": 0, "listed_version": "1.0"}


def test_only_the_queried_package_entries_decide_and_names_compare_without_case() -> None:
    document = _advisory("OSV-1", "npm", "other", ranges=OPEN)
    document["affected"].append(_advisory("x", "npm", "Widget", ranges=ZERO_FIXED)["affected"][0])
    document["affected"].append(_advisory("x", "PyPI", "widget", ranges=OPEN)["affected"][0])
    raw = json.dumps(document)

    assert evaluate_record(raw, None, "npm", "widget", "5.0.0")["status"] == "not_affected"
    assert evaluate_record(raw, None, "npm", "WIDGET", "1.0.0")["evidence"]["affected_index"] == 1
    assert evaluate_record(raw, None, "npm", "absent", "1.0.0")["gaps"] == ["affected_entry_missing"]


def test_several_entries_of_one_package_combine_and_any_undecided_entry_blocks_not_affected() -> None:
    document = _advisory("OSV-1", "npm", "widget", ranges=ZERO_FIXED)
    document["affected"].append(_advisory("x", "npm", "widget", ranges=GIT_ONLY)["affected"][0])
    raw = json.dumps(document)

    assert evaluate_record(raw, None, "npm", "widget", "1.0.0")["status"] == "affected"
    undecided = evaluate_record(raw, None, "npm", "widget", "5.0.0")
    assert (undecided["status"], undecided["gaps"]) == ("undetermined", ["range_type_unsupported:GIT"])


@pytest.mark.parametrize("withdrawn_column,withdrawn_field", [("2026-02-01T00:00:00Z", None),
                                                               (None, "2026-02-01T00:00:00Z")],
                         ids=["index-column", "record-field"])
def test_a_withdrawn_advisory_is_reported_as_withdrawn_not_matched(withdrawn_column, withdrawn_field) -> None:
    document = _advisory("OSV-1", "npm", "widget", ranges=OPEN, withdrawn=withdrawn_field)

    assert evaluate_record(json.dumps(document), withdrawn_column, "npm", "widget", "1.0.0")["status"] == "withdrawn"


@pytest.mark.parametrize("raw,gap", [
    (None, "advisory_record_missing"), ("", "advisory_record_missing"), ("{", "malformed_advisory_record"),
    ("[]", "malformed_advisory_record"), ('{"affected": {}}', "malformed_advisory_record"),
    ('{"affected": ["text"]}', "affected_entry_missing,malformed_affected_entry"),
    ('{"affected": [{"package": {"ecosystem": "npm", "name": "widget"}, "ranges": {}}]}', "malformed_affected_entry"),
    ('{"affected": [{"package": {"ecosystem": "npm", "name": "widget"}, "ranges": ["text"]}]}',
     "malformed_range:not_an_object"),
    ('{"affected": [{"package": {"ecosystem": "npm", "name": "widget"}, "versions": [1]}]}',
     "malformed_affected_entry"),
], ids=["null", "empty", "truncated-json", "not-an-object", "affected-not-a-list", "entry-not-an-object",
        "ranges-not-a-list", "range-not-an-object", "version-not-text"])
def test_a_malformed_stored_record_is_a_named_gap_never_not_affected(raw, gap) -> None:
    verdict = evaluate_record(raw, None, "npm", "widget", "1.0.0")

    assert (verdict["status"], verdict["gaps"]) == ("undetermined", gap.split(","))


@pytest.mark.parametrize("version", ["", None, "1" * 257], ids=["empty", "none", "too-long"])
def test_an_unusable_version_is_a_named_gap(version) -> None:
    raw = json.dumps(_advisory("OSV-1", "npm", "widget", ranges=OPEN))

    assert evaluate_record(raw, None, "npm", "widget", version)["gaps"] == ["version_unusable"]


def test_every_record_bound_is_inclusive_and_one_more_is_a_named_gap() -> None:
    bounds = Bounds(max_events=4, max_ranges=2, max_versions=3, max_affected=2, max_version_length=12)

    def decide(document: dict[str, Any], version: str = "1.5.0", limits: Bounds = bounds) -> tuple[str, list[str]]:
        verdict = evaluate_record(json.dumps(document), None, "npm", "widget", version, bounds=limits)
        return verdict["status"], verdict["gaps"]

    events = _events(("introduced", "0"), ("fixed", "1.0.0"), ("introduced", "1.2.0"), ("fixed", "2.0.0"))
    assert decide(_advisory("A", "npm", "widget", ranges=[(SV, events)])) == ("affected", [])
    assert decide(_advisory("A", "npm", "widget", ranges=[(SV, [*events, {"introduced": "3.0.0"}])])) == (
        "undetermined", ["advisory_bound_exceeded:events"])
    assert decide(_advisory("A", "npm", "widget", ranges=[*GIT_ONLY, *WINDOW])) == ("affected", [])
    assert decide(_advisory("A", "npm", "widget", ranges=[*GIT_ONLY, *GIT_ONLY, *WINDOW])) == (
        "undetermined", ["advisory_bound_exceeded:ranges"])
    assert decide(_advisory("A", "npm", "widget", versions=["1.0.0", "1.1.0", "1.5.0"])) == ("affected", [])
    assert decide(_advisory("A", "npm", "widget", versions=["1.0.0", "1.1.0", "1.2.0", "1.5.0"])) == (
        "undetermined", ["advisory_bound_exceeded:versions"])
    two = _advisory("A", "npm", "other", ranges=OPEN)
    two["affected"].append(_advisory("x", "npm", "widget", ranges=WINDOW)["affected"][0])
    assert decide(two) == ("affected", [])
    two["affected"].append(_advisory("x", "npm", "third", ranges=OPEN)["affected"][0])
    assert decide(two) == ("undetermined", ["advisory_bound_exceeded:affected"])
    assert decide(_advisory("A", "npm", "widget", ranges=WINDOW), "1.5.0-abcdef") == ("affected", [])
    assert decide(_advisory("A", "npm", "widget", ranges=WINDOW), "1.5.0-abcdefg") == (
        "undetermined", ["version_unusable"])
    raw = json.dumps(_advisory("A", "npm", "widget", ranges=WINDOW))
    exact = Bounds(max_raw_bytes=len(raw))
    assert evaluate_record(raw, None, "npm", "widget", "1.5.0", bounds=exact)["status"] == "affected"
    assert evaluate_record(raw + " ", None, "npm", "widget", "1.5.0", bounds=exact)["gaps"] == [
        "advisory_bound_exceeded:raw_bytes"]


@pytest.mark.parametrize("value", [0, -1, True, 1.5, "1"], ids=["zero", "negative", "boolean", "float", "text"])
def test_bounds_must_be_positive_integers(value) -> None:
    with pytest.raises(ValueError, match="max_events"):
        Bounds(max_events=value)


@pytest.mark.parametrize("value", ["enabled", "", None, True, "INDEX"],
                         ids=["other-word", "empty", "none", "boolean", "upper-case"])
def test_the_mode_setting_rejects_anything_but_its_two_values(value) -> None:
    assert [osv_matching.parse_mode(mode, "field") for mode in ("disabled", "index")] == ["disabled", "index"]
    with pytest.raises(ValueError, match="field must be one of disabled, index"):
        osv_matching.parse_mode(value, "field")


def test_the_shipped_configuration_keeps_version_matching_disabled() -> None:
    jobs = tomllib.loads((ROOT / "appsec-review.toml").read_text(encoding="utf-8"))["jobs"]

    assert jobs["job_review_data_indexing"]["settings"]["osv_version_matching"] == "disabled"


def test_only_tested_orderings_are_in_the_ecosystem_table() -> None:
    assert dict(osv_matching.ECOSYSTEM_ORDERINGS) == {"Go": "semver-2.0.0", "crates.io": "semver-2.0.0",
                                                      "npm": "semver-2.0.0"}
    assert osv_matching.ordering_for("PyPI") is None and osv_matching.ordering_for("Go:1") == "semver-2.0.0"


# --- matching against an index built by the real osv_sync index step ---------------------------------

def _archives() -> dict[str, list[dict[str, Any]]]:
    shared = _advisory("GHSA-shared", "npm", "widget", ranges=ZERO_FIXED, aliases=["CVE-2026-0001"])
    shared["affected"].append(_advisory("x", "PyPI", "widget", ranges=ECOSYSTEM_WINDOW)["affected"][0])
    return {
        "npm": [shared,
                _advisory("GHSA-fixed", "npm", "widget", ranges=WINDOW),
                _advisory("GHSA-git", "npm", "widget", ranges=GIT_ONLY),
                _advisory("GHSA-gone", "npm", "widget", ranges=OPEN, withdrawn="2026-03-01T00:00:00Z"),
                _advisory("GHSA-other", "npm", "gadget", ranges=OPEN)],
        "Go": [_advisory("GO-2026-0001", "Go", "example.com/mod", ranges=WINDOW)],
    }


def test_the_index_step_records_its_schema_and_the_ecosystems_indexed_whole(tmp_path: Path) -> None:
    with _open(_build_index(tmp_path, _archives())) as connection:
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
        assert metadata["index_schema"] == "appsec-review/osv-index/2"
        assert json.loads(metadata["ecosystems"]) == ["Go", "npm"]
        assert osv_matching.indexed_ecosystems(connection) == ("Go", "npm")
        # PyPI has package rows from the npm archive's shared advisory, but no archive of its own.
        assert connection.execute("SELECT COUNT(*) FROM package WHERE ecosystem='PyPI'").fetchone()[0] == 1


def test_a_package_version_is_matched_against_only_its_own_advisories(tmp_path: Path) -> None:
    with _open(_build_index(tmp_path, _archives())) as connection:
        result = match_package(connection, "npm", "widget", "1.1.0")
        clean = match_package(connection, "npm", "gadget", "0.1.0")
        unknown = match_package(connection, "npm", "never-published", "1.0.0")
        module = match_package(connection, "Go", "example.com/mod", "v1.4.0")

    assert result["schema"] == "appsec-review/osv-index-match/1"
    assert result["query"] == {"ecosystem": "npm", "name": "widget", "version": "1.1.0"}
    assert [(item["advisory_id"], item["evidence"]["introduced"]) for item in result["matches"]] == [
        ("GHSA-fixed", "1.0.0"), ("GHSA-shared", "0")]
    assert result["undetermined"] == [{"advisory_id": "GHSA-git", "gaps": ["range_type_unsupported:GIT"]}]
    assert (result["withdrawn_count"], result["not_affected_count"], result["advisory_count"]) == (1, 0, 4)
    assert (result["status"], result["gaps"]) == ("partial", ["range_type_unsupported:GIT"])
    assert (clean["status"], clean["matches"], clean["not_affected_count"], clean["gaps"]) == ("complete", [], 1, [])
    assert (unknown["status"], unknown["advisory_count"], unknown["gaps"]) == ("complete", 0, [])
    assert [item["advisory_id"] for item in module["matches"]] == ["GO-2026-0001"]


def test_an_ecosystem_without_its_own_archive_is_never_reported_complete(tmp_path: Path) -> None:
    with _open(_build_index(tmp_path, _archives())) as connection:
        listed = match_package(connection, "PyPI", "widget", "1.5.0")
        absent = match_package(connection, "RubyGems", "rails", "7.0.0")

    assert listed["undetermined"] == [{"advisory_id": "GHSA-shared", "gaps": ["range_ordering_unsupported:PyPI"]}]
    assert listed["gaps"] == ["ecosystem_not_in_snapshot:PyPI", "range_ordering_unsupported:PyPI"]
    assert (absent["status"], absent["matches"], absent["gaps"]) == (
        "partial", [], ["ecosystem_not_in_snapshot:RubyGems"])


def test_an_index_that_does_not_record_its_ecosystems_is_never_reported_complete(tmp_path: Path) -> None:
    path = _build_index(tmp_path, _archives())
    with sqlite3.connect(path) as writable:
        writable.execute("DELETE FROM metadata WHERE key IN ('ecosystems', 'index_schema')")
    with _open(path) as connection:
        result = match_package(connection, "npm", "gadget", "0.1.0")
        assert osv_matching.indexed_ecosystems(connection) is None

    assert (result["status"], result["matches"], result["gaps"]) == ("partial", [], ["snapshot_ecosystems_unrecorded"])


@pytest.mark.parametrize("statement,gap", [
    ("UPDATE advisory SET raw_json='{\"affected\":' WHERE id='GHSA-other'", "malformed_advisory_record"),
    ("DELETE FROM advisory WHERE id='GHSA-other'", "advisory_record_missing"),
    ("UPDATE advisory SET raw_json='{\"id\":\"GHSA-other\",\"affected\":[]}' WHERE id='GHSA-other'",
     "affected_entry_missing"),
], ids=["raw-json-truncated", "advisory-row-missing", "package-row-without-affected-entry"])
def test_a_malformed_index_row_is_a_named_gap_for_that_package(tmp_path: Path, statement: str, gap: str) -> None:
    path = _build_index(tmp_path, _archives())
    with sqlite3.connect(path) as writable:
        writable.execute(statement)
    with _open(path) as connection:
        result = match_package(connection, "npm", "gadget", "0.1.0")

    assert (result["status"], result["matches"], result["gaps"]) == ("partial", [], [gap])
    assert result["undetermined"] == [{"advisory_id": "GHSA-other", "gaps": [gap]}]


@pytest.mark.parametrize("statement,message", [
    ("ALTER TABLE advisory DROP COLUMN raw_json", "advisory lacks column"),
    ("DROP TABLE package", "package lacks column"),
    ("UPDATE metadata SET value='npm' WHERE key='ecosystems'", "'ecosystems' is not JSON"),
    ("UPDATE metadata SET value='{\"npm\":1}' WHERE key='ecosystems'", "'ecosystems' is not a list"),
], ids=["no-raw-json", "no-package-table", "ecosystems-not-json", "ecosystems-not-a-list"])
def test_an_index_of_another_shape_is_an_integrity_error(tmp_path: Path, statement: str, message: str) -> None:
    path = _build_index(tmp_path, _archives())
    with sqlite3.connect(path) as writable:
        writable.execute(statement)
    with _open(path) as connection, pytest.raises(ValueError, match=message):
        match_package(connection, "npm", "widget", "1.0.0")


def test_the_advisory_bound_is_inclusive_and_truncation_is_named(tmp_path: Path) -> None:
    with _open(_build_index(tmp_path, _archives())) as connection:
        exact = match_package(connection, "npm", "widget", "1.1.0", bounds=Bounds(max_advisories_per_package=4))
        short = match_package(connection, "npm", "widget", "1.1.0", bounds=Bounds(max_advisories_per_package=3))

    assert (exact["advisory_count"], "truncated:advisories_per_package" in exact["gaps"]) == (4, False)
    assert (short["advisory_count"], short["status"]) == (3, "partial")
    assert "truncated:advisories_per_package" in short["gaps"]


def test_package_matching_is_the_same_for_every_input_order_and_bounded(tmp_path: Path) -> None:
    packages = [("npm", "widget", "1.1.0"), ("npm", "gadget", "0.1.0"), ("Go", "example.com/mod", "v1.4.0"),
                ("npm", "widget", "9.9.9"), ("npm", "widget", "1.1.0")]
    with _open(_build_index(tmp_path, _archives())) as connection:
        results = [match_packages(connection, order) for order in itertools.permutations(packages)]
        exact = match_packages(connection, packages, bounds=Bounds(max_packages=4))
        short = match_packages(connection, reversed(packages), bounds=Bounds(max_packages=3))

    assert all(json.dumps(result, sort_keys=True) == json.dumps(results[0], sort_keys=True) for result in results)
    assert [item["query"]["name"] + "@" + item["query"]["version"] for item in results[0]["results"]] == [
        "example.com/mod@v1.4.0", "gadget@0.1.0", "widget@1.1.0", "widget@9.9.9"]
    assert (exact["package_count"], exact["unmatched_package_count"]) == (4, 0)
    assert not any(gap.startswith("package_bound_exceeded") for gap in exact["gaps"])
    assert (short["package_count"], short["unmatched_package_count"], short["status"]) == (3, 1, "partial")
    assert short["gaps"][-1] == "package_bound_exceeded: 1 package version(s) were not matched"
    assert [item["query"]["version"] for item in short["results"]] == ["v1.4.0", "0.1.0", "1.1.0"]


# --- the dependency_advisories inventory lookup ------------------------------------------------------

def _dependency(digit: str, name: str, purl: str | None, version: str | None) -> dict[str, Any]:
    return {"identity": "asr:dependency_package:" + digit * 64,
            "payload": {"name": name, "version": version, "purl": purl, "maximal_exposure": "PROD",
                        "resolution_basis": "package_metadata"}}


@pytest.mark.parametrize("purl,version,expected", [
    ("pkg:npm/widget@1.1.0", "1.1.0", ("1.1.0", None)),
    ("pkg:npm/widget@1.1.0", None, ("1.1.0", None)),
    ("pkg:npm/%40scope/widget@2.0.0?arch=x#sub", "2.0.0", ("2.0.0", None)),
    ("pkg:golang/example.com/mod@v1.4.0", "v1.4.0", ("v1.4.0", None)),
    ("pkg:npm/widget@1.0.0%2Bbuild", None, ("1.0.0+build", None)),
    ("pkg:npm/widget", "1.1.0", (None, "version_not_resolved")),
    ("pkg:npm/@scope/widget", "1.1.0", (None, "version_not_resolved")),
    ("pkg:npm/widget@", "1.1.0", (None, "version_not_resolved")),
    (None, "1.1.0", (None, "version_not_resolved")),
    ("pkg:npm/widget@1.1.0", "^1.0.0", (None, "version_identity_conflict")),
], ids=["agree", "purl-only", "scoped-qualified", "golang", "encoded", "no-purl-version", "unencoded-scope",
        "empty-purl-version", "no-purl", "declared-constraint-differs"])
def test_only_the_purl_version_counts_as_the_resolved_version(purl, version, expected) -> None:
    assert products._resolved_version({"purl": purl, "version": version}) == expected


def test_inventory_lookup_with_version_matching_verifies_drops_and_keeps_named_gaps(tmp_path: Path) -> None:
    dependencies = [
        _dependency("1", "widget", "pkg:npm/widget@1.1.0", "1.1.0"),
        _dependency("2", "gadget", "pkg:npm/gadget@0.1.0", "0.1.0"),
        _dependency("3", "widget", "pkg:pypi/widget@1.5.0", "1.5.0"),
        _dependency("4", "widget", "pkg:npm/widget", "^1.0.0"),
        _dependency("5", "native-lib", None, None),
    ]
    with _open(_build_index(tmp_path, _archives())) as connection:
        pairs, coverage, gaps = products._inventory_advisory_pairs(connection, dependencies, max_pairs=100,
                                                                   version_matching=True)
        plain, plain_coverage, plain_gaps = products._inventory_advisory_pairs(connection, dependencies,
                                                                                max_pairs=100)

    found = {(row["dependency_identity"][-1], row["advisory"]): row for row in pairs}
    assert sorted(found) == [("1", "GHSA-fixed"), ("1", "GHSA-git"), ("1", "GHSA-shared"), ("3", "GHSA-shared"),
                             ("4", "GHSA-fixed"), ("4", "GHSA-git"), ("4", "GHSA-gone"), ("4", "GHSA-shared")]
    verified = found[("1", "GHSA-fixed")]
    assert (verified["applicability_verified"], verified["lookup_basis"]) == (
        True, "dependency-inventory-osv-range-match")
    assert verified["version_match"] == {
        "matcher": "appsec-review/osv-index-match/1", "status": "affected", "version": "1.1.0",
        "evidence": {"kind": "range", "range_type": "SEMVER", "ordering": "semver-2.0.0", "introduced": "1.0.0",
                     "fixed": "2.0.0", "affected_index": 0, "range_index": 0}}
    for key, gap in ((("1", "GHSA-git"), "range_type_unsupported:GIT"),
                     (("3", "GHSA-shared"), "range_ordering_unsupported:PyPI"),
                     (("4", "GHSA-gone"), "version_not_resolved")):
        assert (found[key]["applicability_verified"], found[key]["lookup_basis"]) == (
            False, "dependency-inventory-osv-lookup")
        assert found[key]["version_match"]["gaps"] == [gap]
    states = {area.rsplit(":", 1)[-1][-1]: (state, reason) for area, state, reason in coverage}
    assert states["2"] == ("complete", None)
    assert states["1"] == ("partial", "OSV version matching is incomplete: range_type_unsupported:GIT")
    assert states["3"][0] == states["4"][0] == states["5"][0] == "partial"
    assert "ecosystem_not_in_snapshot:PyPI" in states["3"][1]
    assert any(gap.startswith("range_ordering_unsupported:PyPI: asr:dependency_package:" + "3" * 64) for gap in gaps)
    assert any(gap.startswith("version_not_resolved: asr:dependency_package:" + "4" * 64 + ": 4 ") for gap in gaps)
    assert any(gap.startswith("ecosystem_not_in_snapshot:PyPI: 1 dependency(ies)") for gap in gaps)
    # Without the setting nothing is decided: every listed advisory stays an unverified lead.
    assert len(plain) == 4 + 1 + 1 + 4 and not any("version_match" in row for row in plain)
    assert all(row["applicability_verified"] is False for row in plain)
    assert not any("ecosystem_not_in_snapshot" in gap or "range_" in gap for gap in plain_gaps)
    assert {state for _area, state, _reason in plain_coverage} == {"partial"}


def test_inventory_lookup_order_does_not_change_version_matching(tmp_path: Path) -> None:
    dependencies = [_dependency("1", "widget", "pkg:npm/widget@1.1.0", "1.1.0"),
                    _dependency("2", "gadget", "pkg:npm/gadget@5.0.0", "5.0.0"),
                    _dependency("3", "widget", "pkg:pypi/widget@1.5.0", "1.5.0")]
    with _open(_build_index(tmp_path, _archives())) as connection:
        runs = [products._inventory_advisory_pairs(connection, list(order), max_pairs=100, version_matching=True)
                for order in itertools.permutations(dependencies)]

    def canonical(run) -> str:
        pairs, coverage, gaps = run
        return json.dumps([sorted(pairs, key=lambda row: (row["dependency_identity"], row["advisory"])),
                           sorted(coverage, key=str), sorted(gaps)], sort_keys=True)

    assert {canonical(run) for run in runs} == {canonical(runs[0])}


def _advisory_facts(tmp_path: Path, mode: str) -> dict[str, dict[str, Any]]:
    shard_path = tmp_path / "data/indices/inventory/dependencies.sqlite"
    builder = IndexBuilder(shard_path, name="inventory", fingerprint="f" * 64, target_snapshot=SNAPSHOT,
                           shard_id="dependency-intelligence")
    for name, purl, version in (("widget", "pkg:npm/widget@1.1.0", "1.1.0"), ("gadget", "pkg:npm/gadget@0.1.0", "0.1.0")):
        identity = LogicalIdentity.derive(EntityKind.DEPENDENCY_PACKAGE, SNAPSHOT, {"name": name})
        builder.add_entity(EntityRecord(identity, f"dependency-{name}", name, f"dependency {name}",
                                        {"name": name, "version": version, "purl": purl, "maximal_exposure": "PROD",
                                         "resolution_basis": "package_metadata"}))
        builder.add_coverage(f"dependency-{name}", "complete")
    shard = IndexIdentity("inventory", "appsec-review/retrieval-index/2", builder.build(), "f" * 64,
                          shard_path.relative_to(tmp_path).as_posix(), {"job": "job_dependency_intelligence"}, (),
                          "dependency-intelligence")
    feed_database = tmp_path / "feeds/osv/index/osv.sqlite"
    feed_database.parent.mkdir(parents=True)
    feed_database.write_bytes(_build_index(tmp_path / "sync", _archives()).read_bytes())
    feeds = {"osv": {"status": "pinned", "directory": str(tmp_path / "feeds/osv"), "snapshot_id": "osv-fixture",
                     "files": {"index/osv.sqlite": file_sha256(feed_database)}},
             **{name: {"status": "unavailable", "reason": "fixture omits feed"} for name in ("nvd", "kev", "epss")}}
    context = products.ProductContext(tmp_path, SNAPSHOT, ShardSet(tmp_path, (asdict(shard),)), {}, feeds, {}, 100,
                                      "dependency-advisories/test", mode)
    derived = products._build_dependency_advisories(context, (asdict(shard),))
    return {entity.payload["result"]["advisory"]: entity.payload for entity in derived.entities}


def test_version_matching_publishes_verified_facts_with_index_identity_and_matched_range(tmp_path: Path) -> None:
    facts = _advisory_facts(tmp_path, "index")

    assert sorted(facts) == ["GHSA-fixed", "GHSA-git", "GHSA-shared"]
    result = facts["GHSA-fixed"]["result"]
    assert (result["applicability_verified"], result["lookup_bases"]) == (
        True, ["dependency-inventory-osv-range-match"])
    assert not any("applicability_unverified" in gap for gap in facts["GHSA-fixed"]["gaps"])
    assert result["intelligence"]["feed"]["snapshot_id"] == "osv-fixture"
    match, = result["version_matches"]
    assert match == {
        "dependency_identity": result["dependency_inventory"][0]["dependency_identity"],
        "matcher": "appsec-review/osv-index-match/1",
        "index_sha256": file_sha256(tmp_path / "feeds/osv/index/osv.sqlite"), "status": "affected",
        "version": "1.1.0", "kind": "range", "range_type": "SEMVER", "ordering": "semver-2.0.0",
        "introduced": "1.0.0", "fixed": "2.0.0", "affected_index": 0, "range_index": 0}
    undecided = facts["GHSA-git"]
    assert undecided["result"]["applicability_verified"] is False
    assert undecided["result"]["version_matches"][0]["gaps"] == ["range_type_unsupported:GIT"]
    assert any(gap.startswith("applicability_unverified:") and "range_type_unsupported:GIT" in gap
               for gap in undecided["gaps"])


def test_without_the_setting_the_published_facts_carry_no_version_matching(tmp_path: Path) -> None:
    facts = _advisory_facts(tmp_path, "disabled")

    assert sorted(facts) == ["GHSA-fixed", "GHSA-git", "GHSA-gone", "GHSA-other", "GHSA-shared"]
    for payload in facts.values():
        assert payload["result"]["applicability_verified"] is False
        assert "version_matches" not in payload["result"]
        assert any("does not evaluate whether the observed version" in gap for gap in payload["gaps"])
