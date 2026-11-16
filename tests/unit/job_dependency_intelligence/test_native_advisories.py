"""Unit tests for the model-free CPE-range advisory lookup of native components.

The fixture database is a six-row miniature of the cve-bin-tool (NVD) snapshot: the planted zlib,
bzip2 and lz4 rows the smoke target must surface, a fork row (cloudflare/zlib with a dated bound),
a Rust-crate row that shares the bzip2 product name, and cjson rows with one exact-version match
and one exact-version miss. The snapshot verifier is faked; the matcher, the observation shape and
the ``advisory_pairs`` join it feeds are real.
"""
from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace
from typing import Any

import pytest

from appsec_review.indexing.links import advisory_pairs
from appsec_review.indexing.store import ShardSet
from appsec_review.jobs.job_dependency_intelligence import JOB_ID, TOPOLOGY, build_job
from appsec_review.jobs.job_dependency_intelligence import native_advisories as module
from appsec_review.jobs.job_dependency_intelligence.native_advisories import (
    CONFIDENCE_ALTERNATE, CONFIDENCE_CANONICAL, Component, LookupBounds, SCANNER_IDENTITY, TOOL_ID,
    compare_versions, evaluate_row, lookup, observation_records, select_components, snapshot_provenance,
)
from appsec_review.retrieval import EntityKind, IndexIdentity, LogicalIdentity, write_manifest
from appsec_review.runtime import UnitContext
from appsec_review.storage import file_sha256


SNAPSHOT = "f" * 64
BOUNDS = LookupBounds(component_limit=64, rows_per_component=64, match_limit=256)
RANGE_ROWS = [
    # cve, vendor, product, version, startIncl, startExcl, endIncl, endExcl
    ("CVE-2018-25032", "zlib", "zlib", "*", "1.2.2.2", "", "", "1.2.12"),
    ("CVE-2016-9843", "zlib", "zlib", "*", "1.2.0", "", "", "1.2.9"),
    ("CVE-2023-6992", "cloudflare", "zlib", "*", "", "", "", "2023-11-16"),
    ("CVE-2026-27820", "ruby-lang", "zlib", "*", "", "", "", "3.0.1"),
    ("CVE-2019-12900", "bzip", "bzip2", "*", "", "", "1.0.6", ""),
    ("CVE-2016-3189", "bzip", "bzip2", "1.0.6", "", "", "", ""),
    ("CVE-2023-22895", "bzip2_project", "bzip2", "*", "", "", "", "0.4.4"),
    ("CVE-2019-17543", "lz4_project", "lz4", "*", "", "", "", "1.9.2"),
    ("CVE-2014-4715", "yann_collet", "lz4", "*", "", "", "r118", ""),
    ("CVE-2024-31755", "cjson_project", "cjson", "1.7.17", "", "", "", ""),
    ("CVE-2023-50471", "davegamble", "cjson", "1.7.16", "", "", "", ""),
    ("CVE-2025-57052", "davegamble", "cjson", "*", "1.5.0", "", "1.7.18", ""),
]
SEVERITY_ROWS = {
    "CVE-2018-25032": ("HIGH", 7.5, "CVSS:31/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),
    "CVE-2016-9843": ("HIGH", 8.8, "CVSS:31/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"),
    "CVE-2023-6992": ("MEDIUM", 5.5, "CVSS:31/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"),
    "CVE-2026-27820": ("HIGH", 7.5, "CVSS:31/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),
    "CVE-2019-12900": ("CRITICAL", 9.8, "CVSS:31/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CVE-2016-3189": ("MEDIUM", 6.5, "CVSS:30/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"),
    "CVE-2023-22895": ("HIGH", 7.5, "CVSS:31/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),
    "CVE-2019-17543": ("HIGH", 8.1, "CVSS:31/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CVE-2014-4715": ("HIGH", 7.5, "AV:N/AC:L/Au:N/C:P/I:P/A:P"),
    "CVE-2024-31755": ("HIGH", 7.6, "CVSS:31/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H"),
    "CVE-2023-50471": ("MEDIUM", 5.5, "CVSS:31/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"),
    "CVE-2025-57052": ("HIGH", 7.5, "CVSS:31/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"),
}


def _dependency(dependency_id: str, name: str, version: str | None, purl: str | None, **extra: Any) -> dict[str, Any]:
    return {"dependency_id": dependency_id, "name": name, "version": version, "purl": purl,
            "repository": None, "resolution_basis": "linker_evidence", **extra}


DEPENDENCIES = [
    _dependency("dep-zlib", "zlib", "1.2.11", "pkg:generic/zlib@1.2.11"),
    _dependency("dep-zlib-link", "zlib", None, None),            # same component without a version: folds in by name? no: separate key
    _dependency("dep-bzip2", "bzip2", "1.0.6", "pkg:generic/bzip2@1.0.6"),
    _dependency("dep-lz4", "lz4", "1.9.1", "pkg:generic/lz4@1.9.1"),
    _dependency("dep-cjson", "cjson", "1.7.17", "pkg:generic/cjson@1.7.17"),
    _dependency("dep-npm", "left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0"),
    _dependency("dep-libm", "m", None, None),
]


@pytest.fixture
def snapshot(tmp_path: Path) -> dict[str, Any]:
    directory = tmp_path / "feeds" / "cve-bin-tool" / "snapshots" / "sha256-unit"
    directory.mkdir(parents=True)
    database = directory / "cve.db"
    with sqlite3.connect(database) as connection:
        connection.executescript("""
            CREATE TABLE cve_severity (cve_number TEXT, severity TEXT, description TEXT, score INTEGER,
                cvss_version INTEGER, cvss_vector TEXT, data_source TEXT, last_modified TIMESTAMP,
                PRIMARY KEY(cve_number, data_source));
            CREATE TABLE cve_range (cve_number TEXT, vendor TEXT, product TEXT, version TEXT,
                versionStartIncluding TEXT, versionStartExcluding TEXT, versionEndIncluding TEXT,
                versionEndExcluding TEXT, data_source TEXT);
            CREATE TABLE cve_exploited (cve_number TEXT, product TEXT, description TEXT, PRIMARY KEY(cve_number));
            CREATE TABLE purl2cpe (purl TEXT, cpe TEXT, UNIQUE(purl, cpe));
        """)
        connection.executemany("INSERT INTO cve_range VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'NVD')", RANGE_ROWS)
        connection.executemany(
            "INSERT INTO cve_severity VALUES (?, ?, ?, ?, ?, ?, 'NVD', '2026-10-14T07:16:44')",
            [(cve, label, f"{cve} description", score, 3, vector) for cve, (label, score, vector) in SEVERITY_ROWS.items()])
        connection.execute("INSERT INTO cve_exploited VALUES ('CVE-2019-12900', 'bzip2', 'planted')")
    (directory / "manifest.json").write_text(json.dumps({
        "schema": "appsec-review/cve-bin-tool-snapshot/1", "feed_id": "cve-bin-tool", "snapshot_id": "sha256-unit",
        "files": {"cve.db": {"sha256": file_sha256(database), "size_bytes": database.stat().st_size}},
        "nvd_snapshot_id": "sha256-nvd-unit", "tool": {"tool_version": "3.4"}}), encoding="utf-8")
    return {"directory": str(directory), "snapshot_id": "sha256-unit", "manifest_sha256": "e" * 64,
            "nvd_snapshot_id": "sha256-nvd-unit", "nvd_manifest_sha256": "d" * 64, "verified_files": 1,
            "tool": {"tool_version": "3.4"}, "cve_count": len(SEVERITY_ROWS)}


def _connection(snapshot: Mapping[str, Any]) -> sqlite3.Connection:
    return module.open_database(snapshot)


def test_component_selection_takes_generic_and_purl_less_rows_and_names_version_gaps() -> None:
    components, gaps, lookup_gaps = select_components(DEPENDENCIES, BOUNDS)
    assert [(item.name, item.version, item.purl, item.dependency_ids) for item in components] == [
        ("bzip2", "1.0.6", "pkg:generic/bzip2@1.0.6", ("dep-bzip2",)),
        ("cjson", "1.7.17", "pkg:generic/cjson@1.7.17", ("dep-cjson",)),
        ("lz4", "1.9.1", "pkg:generic/lz4@1.9.1", ("dep-lz4",)),
        ("zlib", "1.2.11", "pkg:generic/zlib@1.2.11", ("dep-zlib",)),
    ]
    # The npm row belongs to the package scanners; the two version-less native rows are each a named gap.
    assert {(gap["kind"], gap["component"], gap["dependency_id"]) for gap in gaps} == {
        ("advisory_version_unresolved", "m", "dep-libm"),
        ("advisory_version_unresolved", "zlib", "dep-zlib-link"),
    }
    assert lookup_gaps == []
    limited, _, truncated = select_components(DEPENDENCIES, LookupBounds(2, 64, 256))
    assert [item.name for item in limited] == ["bzip2", "cjson"]
    assert truncated and "component_limit 2" in truncated[0] and "lz4@1.9.1" in truncated[0]


def test_duplicate_rows_fold_into_one_component_keeping_every_dependency_id() -> None:
    rows = [_dependency("a", "ZLib", "1.2.11", "pkg:generic/zlib@1.2.11"),
            _dependency("b", "zlib", "1.2.11", None), _dependency("a", "zlib", "1.2.11", None)]
    components, gaps, _ = select_components(rows, BOUNDS)
    assert components == [Component("zlib", "1.2.11", "pkg:generic/zlib@1.2.11", ("a", "b"))]
    assert gaps == []


@pytest.mark.parametrize(("version", "bound", "expected"), [
    ("1.2.11", "1.2.12", -1), ("1.2.11", "1.2.2.2", 1), ("1.2.11", "1.2.11", 0), ("1.2", "1.2.0", 0),
    ("1.0.6", "1.0.6", 0), ("1.9.1", "1.9.2", -1), ("1.2.11", "2023-11-16", None), ("1.9.1", "r118", None),
    ("1.0.6", "0.9.5a", None), ("1.0.6-r3", "1.0.5", 1), ("1.0.6-r3", "1.0.6", None), ("1.0.6+dfsg", "1.0.7", -1),
    ("abc", "1.0", None), ("1.0", "*", None),
])
def test_version_comparison_is_conservative(version: str, bound: str, expected: int | None) -> None:
    assert compare_versions(version, bound) == expected


def test_row_evaluation_exact_ranges_and_unknowns() -> None:
    row = {"version": "1.7.17", **{column: "" for column in module.RANGE_COLUMNS}}
    assert evaluate_row("1.7.17", row) == ("affected", [])
    assert evaluate_row("1.7.16", row) == ("not_affected", [])
    assert evaluate_row("1.7.17-r1", row) == ("not_affected", [])
    ranged = {"version": "*", "versionStartIncluding": "1.2.2.2", "versionStartExcluding": "",
              "versionEndIncluding": "", "versionEndExcluding": "1.2.12"}
    assert evaluate_row("1.2.11", ranged) == ("affected", [])
    assert evaluate_row("1.2.12", ranged) == ("not_affected", [])
    assert evaluate_row("1.2.2", ranged) == ("not_affected", [])
    dated = {"version": "*", "versionStartIncluding": "", "versionStartExcluding": "",
             "versionEndIncluding": "", "versionEndExcluding": "2023-11-16"}
    status, reasons = evaluate_row("1.2.11", dated)
    assert status == "unknown" and reasons == ["1.2.11 < 2023-11-16 is not comparable"]
    unversioned = {"version": "-", **{column: "" for column in module.RANGE_COLUMNS}}
    assert evaluate_row("1.2.11", unversioned)[0] == "unknown"
    everything = {"version": "*", **{column: "" for column in module.RANGE_COLUMNS}}
    assert evaluate_row("1.2.11", everything) == ("affected", [])
    assert module.confidence_of("zlib", "zlib") == CONFIDENCE_CANONICAL
    assert module.confidence_of("lz4_project", "lz4") == CONFIDENCE_CANONICAL
    assert module.confidence_of("cloudflare", "zlib") == CONFIDENCE_ALTERNATE
    assert module.confidence_of("bzip", "bzip2") == CONFIDENCE_CANONICAL
    assert module.confidence_of("davegamble", "cjson") == CONFIDENCE_ALTERNATE
    assert module.confidence_of("bz", "bzip2") == CONFIDENCE_ALTERNATE


def test_lookup_reports_planted_matches_with_confidence_and_severity(snapshot: dict[str, Any]) -> None:
    components, _, _ = select_components(DEPENDENCIES, BOUNDS)
    with _connection(snapshot) as connection:
        result = lookup(connection, components, BOUNDS)
    found = {(item["name"], item["version"], item["cve_id"]): item for item in result["matches"]}
    assert set(found) == {
        ("zlib", "1.2.11", "CVE-2018-25032"), ("zlib", "1.2.11", "CVE-2026-27820"),
        ("bzip2", "1.0.6", "CVE-2019-12900"), ("bzip2", "1.0.6", "CVE-2016-3189"),
        ("lz4", "1.9.1", "CVE-2019-17543"),
        ("cjson", "1.7.17", "CVE-2024-31755"), ("cjson", "1.7.17", "CVE-2025-57052"),
    }
    zlib = found[("zlib", "1.2.11", "CVE-2018-25032")]
    assert (zlib["confidence"], zlib["severity"], zlib["cvss_score"], zlib["vendor"]) == (
        CONFIDENCE_CANONICAL, "HIGH", 7.5, "zlib")
    assert zlib["matched_row"] == {"version": "*", "versionStartIncluding": "1.2.2.2", "versionStartExcluding": None,
                                   "versionEndIncluding": None, "versionEndExcluding": "1.2.12"}
    assert found[("zlib", "1.2.11", "CVE-2026-27820")]["confidence"] == CONFIDENCE_ALTERNATE   # ruby-lang fork/gem
    bzip2 = found[("bzip2", "1.0.6", "CVE-2019-12900")]
    assert (bzip2["confidence"], bzip2["severity"], bzip2["cvss_score"], bzip2["known_exploited"]) == (
        CONFIDENCE_CANONICAL, "CRITICAL", 9.8, True)
    assert found[("bzip2", "1.0.6", "CVE-2016-3189")]["confidence"] == CONFIDENCE_CANONICAL
    assert found[("lz4", "1.9.1", "CVE-2019-17543")]["severity"] == "HIGH"
    assert found[("cjson", "1.7.17", "CVE-2024-31755")]["confidence"] == CONFIDENCE_CANONICAL
    assert found[("cjson", "1.7.17", "CVE-2025-57052")]["confidence"] == CONFIDENCE_ALTERNATE
    # An exact-version row for another release never matches, nor does a range the version is outside.
    assert ("cjson", "1.7.17", "CVE-2023-50471") not in found
    assert ("zlib", "1.2.11", "CVE-2016-9843") not in found
    assert ("bzip2", "1.0.6", "CVE-2023-22895") not in found
    # Uncomparable bounds are gaps, never matches and never clean.
    assert any("version_uncomparable: zlib@1.2.11: CVE-2023-6992" in gap for gap in result["gaps"])
    assert any("version_uncomparable: lz4@1.9.1: CVE-2014-4715" in gap for gap in result["gaps"])
    by_name = {row["name"]: row for row in result["components"]}
    assert by_name["zlib"]["unknown_advisories"] == ["CVE-2023-6992"]
    assert by_name["lz4"]["status"] == "matched" and by_name["cjson"]["rows_rejected"] == 1
    assert result["query_count"] >= 1 and result["match_count"] == 7


def test_unknown_only_component_is_undetermined_not_clean(snapshot: dict[str, Any]) -> None:
    with _connection(snapshot) as connection:
        result = lookup(connection, [Component("lz4", "2.0.0", None, ("x",))], BOUNDS)
    assert result["matches"] == []
    (component,) = result["components"]
    assert component["status"] == "undetermined" and component["unknown_advisories"] == ["CVE-2014-4715"]
    assert result["gaps"] and result["gaps"][0].startswith("version_uncomparable: lz4@2.0.0: CVE-2014-4715")


def test_bounds_truncate_rows_and_matches_with_named_gaps(snapshot: dict[str, Any]) -> None:
    components, _, _ = select_components(DEPENDENCIES, BOUNDS)
    with _connection(snapshot) as connection:
        # Two rows per component in (cve, vendor) order: bzip2 yields CVE-2016-3189 and CVE-2019-12900 and fills
        # match_limit, so cjson's CVE-2024-31755 is the truncated third match; zlib has more than two rows.
        result = lookup(connection, components, LookupBounds(64, 2, 2))
    assert [(item["name"], item["cve_id"]) for item in result["matches"]] == [
        ("bzip2", "CVE-2016-3189"), ("bzip2", "CVE-2019-12900")]
    assert any(gap.startswith("truncated: ") and "match_limit 2" in gap for gap in result["gaps"])
    assert any(gap.startswith("truncated: zlib@1.2.11: more than 2 CPE rows") for gap in result["gaps"])
    assert {row["name"]: row["rows_truncated"] for row in result["components"]} == {
        "bzip2": True, "cjson": True, "lz4": False, "zlib": True}


def test_observation_records_feed_the_advisory_pairs_join(snapshot: dict[str, Any]) -> None:
    components, _, _ = select_components(DEPENDENCIES, BOUNDS)
    with _connection(snapshot) as connection:
        result = lookup(connection, components, BOUNDS)
    records = observation_records(result, snapshot_provenance(snapshot))
    pairs = [pair for record in records for pair in advisory_pairs({"payload": record["payload"]})]
    assert {(pair["package"], pair["version"], pair["advisory"], pair["severity"], pair["scanner"], pair["purl"])
            for pair in pairs} == {
        ("zlib", "1.2.11", "CVE-2018-25032", "HIGH", SCANNER_IDENTITY, "pkg:generic/zlib@1.2.11"),
        ("zlib", "1.2.11", "CVE-2026-27820", "HIGH", SCANNER_IDENTITY, "pkg:generic/zlib@1.2.11"),
        ("bzip2", "1.0.6", "CVE-2019-12900", "CRITICAL", SCANNER_IDENTITY, "pkg:generic/bzip2@1.0.6"),
        ("bzip2", "1.0.6", "CVE-2016-3189", "MEDIUM", SCANNER_IDENTITY, "pkg:generic/bzip2@1.0.6"),
        ("lz4", "1.9.1", "CVE-2019-17543", "HIGH", SCANNER_IDENTITY, "pkg:generic/lz4@1.9.1"),
        ("cjson", "1.7.17", "CVE-2024-31755", "HIGH", SCANNER_IDENTITY, "pkg:generic/cjson@1.7.17"),
        ("cjson", "1.7.17", "CVE-2025-57052", "HIGH", SCANNER_IDENTITY, "pkg:generic/cjson@1.7.17"),
    }
    findings = [record for record in records if record["payload"]["record_kind"] == "finding"]
    summaries = [record for record in records if record["payload"]["record_kind"] == "scan_summary"]
    assert len(findings) == 7 and len(summaries) == 4
    assert all(not advisory_pairs({"payload": record["payload"]}) for record in summaries)
    finding = findings[0]["payload"]
    assert finding["match_basis"] == "cpe-range" and finding["tool_id"] == TOOL_ID
    assert finding["category"] == "vulnerability_matching" and finding["confidence"] in {"canonical", "alternate_vendor"}
    assert finding["provenance"] == {"feed": "cve-bin-tool", "snapshot_id": "sha256-unit", "manifest_sha256": "e" * 64,
                                     "nvd_snapshot_id": "sha256-nvd-unit", "nvd_manifest_sha256": "d" * 64,
                                     "cve_db_sha256": file_sha256(Path(snapshot["directory"]) / "cve.db"),
                                     "tool_version": "3.4"}
    assert "a lead, not a confirmed vulnerability" in finding["message"]
    assert len({record["native_id"] for record in records}) == len(records)


def test_records_are_dependency_advisory_leads_and_summaries_are_decided_non_leads(snapshot: dict[str, Any]) -> None:
    from appsec_review.review.lead_families import non_lead_key, observation_family, producer_decision
    components, _, _ = select_components(DEPENDENCIES, BOUNDS)
    with _connection(snapshot) as connection:
        result = lookup(connection, components, BOUNDS)
    shard = {"name": "observations", "shard_id": "native-advisory", "producer": {"job": JOB_ID}}
    families = {record["payload"]["record_kind"]: observation_family({"payload": record["payload"]}, shard)
                for record in observation_records(result, snapshot_provenance(snapshot))}
    assert families == {"finding": "dependency_advisory", "scan_summary": None}
    summary = next(record for record in observation_records(result, snapshot_provenance(snapshot))
                   if record["payload"]["record_kind"] == "scan_summary")
    assert non_lead_key({"payload": summary["payload"]}, shard) == "class:diagnostic"
    assert producer_decision(JOB_ID, TOOL_ID).family == "dependency_advisory"
    assert producer_decision(JOB_ID, "native-sbom").family is None


# --- the job unit -------------------------------------------------------------------------------------------

def _unit(tmp_path: Path, *, enabled: bool, resolver, dependencies=DEPENDENCIES) -> tuple[UnitContext, list[dict[str, Any]]]:
    run_root = tmp_path / "runs" / "2026-11-16-0001"
    unit_root = run_root / "data/jobs" / JOB_ID / "attempts/attempt_0001/steps/publication/tasks/native_advisory_lookup"
    unit_root.mkdir(parents=True)
    events: list[dict[str, Any]] = []
    job = SimpleNamespace(
        run_root=run_root, repository_root=tmp_path / "repo", source_fingerprint=SNAPSHOT, run_id=run_root.name,
        attempt_id="attempt_0001", target_root=None,
        config=SimpleNamespace(settings={"native_advisory_lookup": BOUNDS.as_dict()}),
        tools=SimpleNamespace(enable_native_advisory_lookup=enabled),
        events=SimpleNamespace(write=lambda event_type, **details: events.append({"event_type": event_type, **details})))
    unit = UnitContext(job=job, unit_id="publication.native_advisory_lookup", step_id="publication",
                       task_id="native_advisory_lookup", unit_root=unit_root,
                       outputs={"inputs.load_accepted": {"upstream_handoffs": {"job_language_build": "a" * 64}},
                                "resolution.infer_repositories": {"dependencies": list(dependencies)}})
    return unit, events


def _handler(resolver):
    job = build_job(advisory_snapshot=resolver)
    assert "native_advisory_lookup" in TOPOLOGY["publication"]
    return next(unit.handler for unit in job.units if unit.unit_id == "publication.native_advisory_lookup")


def test_unit_is_a_configured_disabled_gap_when_the_tool_flag_is_off(tmp_path: Path, snapshot) -> None:
    unit, events = _unit(tmp_path, enabled=False, resolver=lambda *_: snapshot)
    result = _handler(lambda *_: pytest.fail("the snapshot must not be opened when disabled"))(unit)
    assert result["terminal_status"] == "NOT_APPLICABLE" and result["coverage_disposition"] == "CONFIGURED_DISABLED"
    assert result["gaps"] == ["native advisory lookup was configured disabled by tools.enable_native_advisory_lookup"]
    assert result["index_identity"] is None and result["observation_count"] == 0
    assert [(event["event_type"], event["tool_id"], event["disposition"]) for event in events] == [
        ("TOOL_CONFIGURED_DISABLED", TOOL_ID, "CONFIGURED_DISABLED")]
    document = json.loads((unit.unit_root / "native-advisory-lookup.json").read_text(encoding="utf-8"))
    assert document["coverage_disposition"] == "CONFIGURED_DISABLED"


def test_unit_names_an_unverifiable_snapshot_as_a_gap(tmp_path: Path) -> None:
    def failing(repository_root: Path, run_root: Path) -> Mapping[str, Any]:
        raise ValueError("cve-bin-tool manifest hash mismatch")
    unit, _ = _unit(tmp_path, enabled=True, resolver=failing)
    result = _handler(failing)(unit)
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS" and result["coverage_disposition"] == "unavailable"
    assert result["gaps"][0] == ("verified immutable cve-bin-tool database unavailable: ValueError: "
                                 "cve-bin-tool manifest hash mismatch")
    assert result["index_identity"] is None and result["component_count"] == 4
    # The version-less components are still named, not silenced by the missing feed.
    assert {gap["kind"] for gap in result["gaps"] if isinstance(gap, Mapping)} == {"advisory_version_unresolved"}


def test_unit_builds_an_observations_shard_whose_entities_join_dependency_advisories(tmp_path: Path, snapshot) -> None:
    unit, events = _unit(tmp_path, enabled=True, resolver=lambda *_: snapshot)
    result = _handler(lambda *_: snapshot)(unit)
    assert result["terminal_status"] == "COMPLETED_WITH_GAPS"   # dated/revision bounds and version-less rows
    assert result["coverage_disposition"] == "partial"
    assert (result["component_count"], result["match_count"], result["observation_count"]) == (4, 7, 11)
    identity = IndexIdentity(**{**result["index_identity"], "gaps": tuple(result["index_identity"]["gaps"])})
    assert identity.name == "observations" and identity.shard_id == "native-advisory"
    assert identity.producer == {"job": JOB_ID, "unit": "publication.native_advisory_lookup"}
    assert any("version_uncomparable" in gap for gap in identity.gaps)
    run_root = unit.job.run_root
    assert (run_root / identity.relative_path).is_file()
    manifest_path = run_root / "data/indices/manifests/unit.json"
    write_manifest(manifest_path, run_id=unit.job.run_id, target_snapshot=SNAPSHOT, target_root=tmp_path,
                   indexes=(identity,))
    shards = ShardSet(run_root, json.loads(manifest_path.read_text(encoding="utf-8"))["indexes"])
    selected = shards.select(index="observations", job=JOB_ID)
    assert len(selected) == 1
    rows = list(shards.entities(selected, kinds=("tool_observation",)))
    assert len(rows) == 11
    pairs = {(pair["package"], pair["version"], pair["advisory"], pair["severity"])
             for row in rows for pair in advisory_pairs(row)}
    assert pairs >= {("zlib", "1.2.11", "CVE-2018-25032", "HIGH"), ("bzip2", "1.0.6", "CVE-2019-12900", "CRITICAL"),
                     ("lz4", "1.9.1", "CVE-2019-17543", "HIGH"), ("cjson", "1.7.17", "CVE-2024-31755", "HIGH")}
    assert all(pair[2] != "CVE-2023-50471" for pair in pairs)
    # Each match derives from the dependency row it names, by the same identity publish_context indexes.
    from appsec_review.jobs.job_dependency_intelligence.job import _dependency_identity
    zlib_identity = _dependency_identity(SNAPSHOT, DEPENDENCIES[0]).value
    relations = list(shards.relations(selected, kinds=("DERIVED_FROM",)))
    assert zlib_identity in {relation["target_id"] for relation in relations}
    assert all(LogicalIdentity.parse(relation["source_id"]).kind is EntityKind.TOOL_OBSERVATION for relation in relations)
    coverage = shards.coverage(selected)
    assert [(row["area"], row["status"]) for row in coverage] == [("native-advisory-lookup", "partial")]
    document = json.loads((unit.unit_root / "native-advisory-lookup.json").read_text(encoding="utf-8"))
    assert document["provenance"]["snapshot_id"] == "sha256-unit" and document["match_count"] == 7
    assert events == []
    # The same inputs rebuild the same shard identity.
    unit2, _ = _unit(tmp_path / "again", enabled=True, resolver=lambda *_: snapshot)
    again = _handler(lambda *_: snapshot)(unit2)
    assert again["index_identity"]["fingerprint"] == result["index_identity"]["fingerprint"]
    assert again["index_identity"]["sha256"] == result["index_identity"]["sha256"]
