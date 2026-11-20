"""Unit tests for coverage format detection, path binding, and bounded receipt ingestion."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.jobs.job_test_coverage import (
    CoverageBounds,
    bind_coverage_paths,
    ingest_coverage_artifacts,
    parse_coverage,
)
from appsec_review.jobs.job_test_coverage.job import CoverageIntegrityError, _format, _normalize_report_path
from appsec_review.storage import file_sha256


def _artifact(
    run_root: Path,
    relative: str,
    data: bytes,
    *,
    kind: str = "test-coverage",
    artifact_origin: str = "build-output",
) -> dict[str, object]:
    path = run_root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {
        "path": relative,
        "workspace_path": Path(relative).name,
        "sha256": file_sha256(path),
        "size_bytes": len(data),
        "kind": kind,
        "artifact_origin": artifact_origin,
    }


def test_coverage_bounds_validate_positive_limits_and_mapping_overrides() -> None:
    with pytest.raises(ValueError, match="must be positive"):
        CoverageBounds(max_artifacts=0)
    bounds = CoverageBounds.from_mapping({"max_artifacts": 4, "ignored": 99})
    assert bounds.max_artifacts == 4 and bounds.max_path_candidates == 20


@pytest.mark.parametrize(("label", "payload", "expected"), [
    ("coverage.info", b"anything", "lcov"),
    ("report.txt", b"TN:\nSF:a.c\n", "lcov"),
    ("out.json", b"{not-json", "llvm"),
    ("out.dat", b"{not-json", None),
    ("out.dat", json.dumps({"type": "llvm.coverage.json.export", "data": []}).encode(), "llvm"),
    ("out.json", b'{"hello": 1}', None),
    ("cov.xml", b"<?xml version='1.0'?><coverage/>", "cobertura"),
    ("jacocoTestReport.xml", b"<report name='x'/>", "jacoco"),
    ("other.xml", b"<report name='jacoco'/>", "jacoco"),
    ("unknown.bin", b"\x00\x01\x02", None),
])
def test_format_detection_handles_extensions_and_content_prefixes(
    label: str, payload: bytes, expected: str | None,
) -> None:
    assert _format(label, payload) == expected


def test_normalize_report_path_strips_file_scheme_and_windows_drive() -> None:
    assert _normalize_report_path("C:\\repo\\src\\main.c") == "repo/src/main.c"
    assert _normalize_report_path("file:///repo/src/main.c") == "repo/src/main.c"


def test_path_binding_uses_catalog_hash_and_preserves_unknown_ambiguity_and_truncation() -> None:
    document = parse_coverage(
        b"""SF:/agent/work/src/a.c
DA:1,1
end_of_record
SF:generated/missing.c
DA:1,0
end_of_record
SF:a.c
DA:1,1
end_of_record
""",
        "lcov",
    )
    catalog = {"src/a.c": "1" * 64, "other/a.c": "2" * 64, "third/a.c": "3" * 64}
    rows, gaps = bind_coverage_paths(document, catalog, max_path_candidates=2)
    by_producer = {row["producer_path"]: row for row in rows}
    assert by_producer["/agent/work/src/a.c"]["path"] == "src/a.c"
    assert by_producer["/agent/work/src/a.c"]["binding"] == "unique-suffix"
    assert by_producer["/agent/work/src/a.c"]["file_sha256"] == "1" * 64
    assert by_producer["generated/missing.c"]["binding"] == "unresolved"
    assert by_producer["a.c"]["binding"] == "ambiguous"
    assert by_producer["a.c"]["binding_candidates"] == ["other/a.c", "src/a.c"]
    assert {gap.split(":", 1)[0] for gap in gaps} == {
        "unresolved_source_path",
        "ambiguous_source_path",
        "path_candidate_truncation",
    }


def test_path_binding_resolves_project_root_both_prefixed_and_relative() -> None:
    document = parse_coverage(
        b"SF:src/Main.java\nDA:1,1\nend_of_record\nSF:projects/java/case-016/Local.java\nDA:1,1\nend_of_record\n",
        "lcov",
    )
    catalog = {
        "projects/java/case-016/src/Main.java": "1" * 64,
        "projects/java/case-020/src/Main.java": "2" * 64,
        "Local.java": "3" * 64,
    }
    rows, gaps = bind_coverage_paths(document, catalog, build_root="projects/java/case-016")
    assert gaps == []
    assert [row["path"] for row in rows] == ["Local.java", "projects/java/case-016/src/Main.java"]
    assert all(row["binding"] == "exact" for row in rows)


def test_ingestion_aggregates_bounds_truncation_overlap_and_family_filtering(tmp_path: Path) -> None:
    good_one = _artifact(
        tmp_path,
        "data/build/u/coverage/one.info",
        b"SF:src/a.c\nDA:1,1\nDA:2,0\nSF:dup.c\nDA:1,1\nSF:src/b.c\nDA:1,1\nend_of_record\n",
        artifact_origin="accepted-input",
    )
    overlap = _artifact(
        tmp_path,
        "data/build/u/coverage/two.info",
        b"SF:src/a.c\nDA:1,1\nend_of_record\n",
    )
    malformed = _artifact(tmp_path, "data/build/u/coverage/cobertura.xml", b"<coverage>")
    too_large = _artifact(tmp_path, "data/build/u/coverage/large.lcov", b"SF:a\n" * 30)
    unsupported = _artifact(tmp_path, "data/build/u/coverage/coverage.dat", b"binary-ish")
    extra_truncated = _artifact(tmp_path, "data/build/u/coverage/extra.info", b"SF:src/a.c\nDA:1,1\n")
    non_coverage = _artifact(tmp_path, "data/build/u/bin/app", b"\x7fELF", kind="executable")

    receipts = [
        {
            "build_unit_id": "u",
            "family": "native",
            "root": ".",
            "terminal_status": "SUCCEEDED",
            "artifacts": [good_one, overlap, malformed, too_large, unsupported, extra_truncated, non_coverage],
        },
        {
            "build_unit_id": "empty-applicable",
            "family": "native",
            "root": ".",
            "terminal_status": "COMPLETED_WITH_GAPS",
            "artifacts": [],
        },
        {
            "build_unit_id": "failed-non-applicable",
            "family": "native",
            "root": ".",
            "terminal_status": "FAILED",
            "artifacts": [],
        },
        {
            "build_unit_id": "filtered-family",
            "family": "python",
            "root": ".",
            "terminal_status": "SUCCEEDED",
            "artifacts": [],
        },
    ]
    output = ingest_coverage_artifacts(
        tmp_path,
        receipts,
        {"src/a.c": "a" * 64, "src/b.c": "b" * 64, "x/dup.c": "c" * 64, "y/dup.c": "d" * 64},
        bounds=CoverageBounds(
            max_artifacts=5,
            max_artifact_bytes=120,
            max_rows_per_artifact=20,
            max_files_per_artifact=2,
            max_path_candidates=2,
        ),
        applicable_families=("native",),
    )
    by_unit = {item["build_unit_id"]: item for item in output["units"]}
    assert set(by_unit) == {"empty-applicable", "failed-non-applicable", "u"}
    unit = by_unit["u"]
    assert unit["coverage_state"] == "partial"
    assert unit["totals"]["lines_total"] == 3 and unit["totals"]["lines_covered"] == 2
    assert unit["files"][0]["binding"] == "ambiguous" and unit["files"][0]["file_sha256"] is None
    assert unit["files"][1]["file_sha256"] == "a" * 64
    assert unit["files"][1]["artifact_origin"] == "accepted-input"
    gap_text = "\n".join(unit["gaps"])
    for expected in (
        "artifact_count_truncation",
        "coverage_file_truncation",
        "overlapping_coverage_reports",
        "malformed_coverage",
        "artifact_byte_bound",
        "unsupported_coverage_format",
    ):
        assert expected in gap_text
    assert by_unit["empty-applicable"]["coverage_state"] == "unavailable"
    assert any("missing_applicable_coverage" in gap for gap in by_unit["empty-applicable"]["gaps"])
    assert by_unit["failed-non-applicable"]["gaps"] == []


def test_ingestion_enforces_artifact_origin_and_custody(tmp_path: Path) -> None:
    run_root = tmp_path / "run"
    run_root.mkdir()
    artifact = _artifact(
        run_root,
        "data/build/u/coverage/lcov.info",
        b"SF:src/a.c\nDA:1,1\nend_of_record\n",
    )
    with pytest.raises(CoverageIntegrityError, match="invalid artifact origin"):
        ingest_coverage_artifacts(
            run_root,
            [{
                "build_unit_id": "u",
                "family": "native",
                "root": ".",
                "terminal_status": "SUCCEEDED",
                "artifacts": [{**artifact, "artifact_origin": "untrusted"}],
            }],
            {"src/a.c": "a" * 64},
        )

    outside = tmp_path / "outside.info"
    outside.write_bytes(b"SF:src/a.c\nDA:1,1\nend_of_record\n")
    with pytest.raises(CoverageIntegrityError, match="unavailable or outside the run"):
        ingest_coverage_artifacts(
            run_root,
            [{
                "build_unit_id": "u",
                "family": "native",
                "root": ".",
                "terminal_status": "SUCCEEDED",
                "artifacts": [{**artifact, "path": "../outside.info"}],
            }],
            {"src/a.c": "a" * 64},
        )

    link = run_root / "data/build/u/coverage/link.info"
    link.symlink_to(outside)
    with pytest.raises(CoverageIntegrityError, match="unavailable or outside the run"):
        ingest_coverage_artifacts(
            run_root,
            [{
                "build_unit_id": "u",
                "family": "native",
                "root": ".",
                "terminal_status": "SUCCEEDED",
                "artifacts": [{**artifact, "path": "data/build/u/coverage/link.info"}],
            }],
            {"src/a.c": "a" * 64},
        )

    with pytest.raises(CoverageIntegrityError, match="identity changed"):
        ingest_coverage_artifacts(
            run_root,
            [{
                "build_unit_id": "u",
                "family": "native",
                "root": ".",
                "terminal_status": "SUCCEEDED",
                "artifacts": [{**artifact, "sha256": "0" * 64}],
            }],
            {"src/a.c": "a" * 64},
        )

    clean = ingest_coverage_artifacts(
        run_root,
        [{
            "build_unit_id": "u",
            "family": "native",
            "root": ".",
            "terminal_status": "SUCCEEDED",
            "artifacts": [artifact],
        }],
        {"src/a.c": "a" * 64},
    )
    assert clean["units"][0]["coverage_state"] == "complete"




@pytest.mark.parametrize(("name", "payload"), [
    ("coverage.json", b'{"type":"llvm.coverage.json.export","data":[{"files":[{"filename":"a.c","summary":{"lines":{"count":1e309}}}]}]}'),
    ("coverage.json", b'{"type":"llvm.coverage.json.export","data":[{"files":[{"filename":"a.c","summary":{"lines":{"count":-0.5}}}]}]}'),
    ("coverage.xml", b'<coverage><class filename="a.c"><line number="1" hits="1" branch="true"/></class></coverage>'),
    ("lcov.info", b"FN:1,ghost\nFNDA:1,ghost\nSF:a.c\nDA:1,1\n"),
    ("jacoco.xml", b'<!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd"><report name="jacoco"><package name="p"><sourcefile name="A.java"><counter type="LINE" missed="0" covered="1"/></sourcefile></package></report>'),
], ids=["overflow", "fraction", "unknown-branches", "orphan-function", "jacoco-doctype-policy"])
def test_malformed_report_is_a_gap_not_zero_and_other_reports_survive(
    tmp_path: Path, name: str, payload: bytes,
) -> None:
    bad = _artifact(tmp_path, f"data/bad/{name}", payload)
    receipt = {"build_unit_id": "u1", "family": "native", "terminal_status": "SUCCEEDED",
               "artifacts": [bad]}
    unavailable = ingest_coverage_artifacts(tmp_path, [receipt], {"a.c": "1" * 64})
    unit = unavailable["units"][0]
    assert unit["coverage_state"] == "unavailable"
    assert unit["totals"]["lines_rate"] is None
    assert unit["files"] == []
    assert len(unit["gaps"]) == 1 and unit["gaps"][0].startswith("malformed_coverage:")
    good = _artifact(tmp_path, "data/good/lcov.info", b"SF:a.c\nDA:1,0\nend_of_record\n")
    receipt["artifacts"] = [bad, good]
    partial = ingest_coverage_artifacts(tmp_path, [receipt], {"a.c": "1" * 64})["units"][0]
    assert partial["coverage_state"] == "partial"
    assert partial["totals"]["lines_rate"] == 0.0
    assert len(partial["files"]) == 1
    assert partial["files"][0]["artifact_sha256"] == good["sha256"]
    assert partial["gaps"] == unit["gaps"]
