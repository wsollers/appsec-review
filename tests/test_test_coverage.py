from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.jobs.engineering_contracts import TEST_COVERAGE_HANDOFF_SCHEMA
from appsec_review.jobs.job_test_coverage import (
    CoverageBounds, bind_coverage_paths, ingest_coverage_artifacts, load_accepted_test_coverage,
    parse_coverage,
)
from appsec_review.jobs.job_test_coverage import build_job
from appsec_review.retrieval import IndexBuilder, IndexIdentity, write_manifest
from appsec_review.storage import atomic_json, file_sha256


def _totals(document):
    return document.files[0].totals.as_dict()


def test_parses_lcov_line_branch_and_function_counts() -> None:
    document = parse_coverage(b"""TN:
SF:src/main.c
FN:1,main
FNDA:2,main
DA:1,2
DA:2,0
BRDA:2,0,0,1
BRDA:2,0,1,-
end_of_record
""", "lcov")
    assert document.files[0].source_path == "src/main.c"
    assert _totals(document) == {
        "lines_total": 2, "lines_covered": 1, "branches_total": 2, "branches_covered": 1,
        "functions_total": 1, "functions_covered": 1, "lines_rate": .5,
        "branches_rate": .5, "functions_rate": 1.0,
    }


def test_parses_cobertura_counts() -> None:
    document = parse_coverage(b"""<?xml version="1.0"?>
<coverage><packages><package><classes><class filename="pkg/a.py"><methods>
<method name="f"><lines><line number="1" hits="1"/></lines></method></methods><lines>
<line number="1" hits="1"/><line number="2" hits="0" branch="true"
condition-coverage="50% (1/2)"/></lines></class></classes></package></packages></coverage>""", "cobertura")
    assert document.files[0].source_path == "pkg/a.py"
    assert _totals(document)["lines_covered"] == 1
    assert _totals(document)["branches_total"] == 2
    assert _totals(document)["functions_covered"] == 1


def test_parses_jacoco_counts() -> None:
    document = parse_coverage(b"""<report name="fixture"><package name="org/acme">
<class name="org/acme/A" sourcefilename="A.java"><counter type="METHOD" missed="1" covered="2"/></class>
<sourcefile name="A.java"><counter type="LINE" missed="2" covered="8"/>
<counter type="BRANCH" missed="1" covered="3"/></sourcefile></package></report>""", "jacoco")
    assert document.files[0].source_path == "org/acme/A.java"
    assert _totals(document) == {
        "lines_total": 10, "lines_covered": 8, "branches_total": 4, "branches_covered": 3,
        "functions_total": 3, "functions_covered": 2, "lines_rate": .8,
        "branches_rate": .75, "functions_rate": 0.66666667,
    }


def test_parses_llvm_export_counts() -> None:
    document = parse_coverage(json.dumps({
        "type": "llvm.coverage.json.export", "version": "2.0.1", "data": [{"files": [{
            "filename": "/checkout/src/a.cc", "summary": {
                "lines": {"count": 7, "covered": 5}, "branches": {"count": 6, "covered": 2},
                "functions": {"count": 2, "covered": 1},
            }}]}]}).encode(), "llvm")
    assert document.files[0].source_path == "/checkout/src/a.cc"
    assert _totals(document)["lines_rate"] == pytest.approx(5 / 7)


def test_path_binding_uses_catalog_hash_and_preserves_unknown_and_ambiguity() -> None:
    document = parse_coverage(b"""SF:/agent/work/src/a.c
DA:1,1
end_of_record
SF:generated/missing.c
DA:1,0
end_of_record
SF:a.c
DA:1,1
end_of_record
""", "lcov")
    catalog = {"src/a.c": "1" * 64, "other/a.c": "2" * 64}
    rows, gaps = bind_coverage_paths(document, catalog)
    by_producer = {row["producer_path"]: row for row in rows}
    assert by_producer["/agent/work/src/a.c"]["path"] == "src/a.c"
    assert by_producer["/agent/work/src/a.c"]["file_sha256"] == "1" * 64
    assert by_producer["generated/missing.c"]["binding"] == "unresolved"
    assert by_producer["a.c"]["binding"] == "ambiguous"
    assert by_producer["a.c"]["binding_candidates"] == ["other/a.c", "src/a.c"]
    assert {gap.split(":", 1)[0] for gap in gaps} == {"unresolved_source_path", "ambiguous_source_path"}


def _artifact(run_root: Path, relative: str, data: bytes, *, kind: str = "test-coverage",
              artifact_origin: str = "build-output") -> dict:
    path = run_root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"path": relative, "workspace_path": Path(relative).name, "sha256": file_sha256(path),
            "size_bytes": len(data), "kind": kind, "artifact_origin": artifact_origin}


def test_ingestion_aggregates_and_records_malformed_bounds_and_absence(tmp_path: Path) -> None:
    good = _artifact(tmp_path, "data/build/u/coverage/lcov.info",
                     b"SF:src/a.c\nDA:1,1\nDA:2,0\nend_of_record\n",
                     artifact_origin="accepted-input")
    malformed = _artifact(tmp_path, "data/build/u/coverage/cobertura.xml", b"<coverage>")
    too_large = _artifact(tmp_path, "data/build/u/coverage/large.lcov", b"SF:a\n" * 30)
    unsupported = _artifact(tmp_path, "data/build/u/coverage/coverage.dat", b"binary-ish")
    receipts = [
        {"build_unit_id": "u", "family": "native", "root": ".", "terminal_status": "SUCCEEDED",
         "artifacts": [good, malformed, too_large, unsupported]},
        {"build_unit_id": "empty", "family": "java", "root": ".", "terminal_status": "SUCCEEDED",
         "artifacts": []},
    ]
    output = ingest_coverage_artifacts(
        tmp_path, receipts, {"src/a.c": "a" * 64},
        bounds=CoverageBounds(max_artifact_bytes=64, max_rows_per_artifact=10))
    unit = next(item for item in output["units"] if item["build_unit_id"] == "u")
    assert unit["totals"]["lines_rate"] == .5
    assert unit["files"][0]["file_sha256"] == "a" * 64
    assert unit["files"][0]["artifact_origin"] == "accepted-input"
    assert unit["artifacts"][0]["artifact_origin"] == "accepted-input"
    assert any("malformed_coverage" in gap for gap in output["gaps"])
    assert any("artifact_byte_bound" in gap for gap in output["gaps"])
    assert any("unsupported_coverage_format" in gap for gap in output["gaps"])
    assert any("missing_applicable_coverage" in gap for gap in output["gaps"])


def test_ingestion_rejects_unknown_artifact_origin(tmp_path: Path) -> None:
    artifact = _artifact(tmp_path, "data/build/u/coverage/lcov.info",
                         b"SF:src/a.c\nDA:1,1\nend_of_record\n")
    artifact["artifact_origin"] = "untrusted"
    with pytest.raises(ValueError, match="invalid artifact origin"):
        ingest_coverage_artifacts(tmp_path, [{
            "build_unit_id": "u", "family": "native", "root": ".",
            "terminal_status": "SUCCEEDED", "artifacts": [artifact],
        }], {"src/a.c": "a" * 64})


def test_job_contract_is_generic_and_declares_the_bounded_workflow() -> None:
    job = build_job()
    assert job.job_id == "job_test_coverage" and job.name == "test_coverage"
    assert job.consumes == ("job_target_catalog", "job_language_build", "job_artifact_indexing")
    assert [unit.unit_id for unit in job.units] == [
        "load.accepted_inputs", "normalize.coverage", "index.coverage", "acceptance.publish_handoff"]
    assert {item.output_kind for item in job.datasets} == {"test_coverage", "test_coverage_handoff"}


def test_parser_rejects_unsupported_malformed_and_row_bound() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        parse_coverage(b"x", "gcov")
    with pytest.raises(ValueError, match="malformed"):
        parse_coverage(b"{", "llvm")
    with pytest.raises(ValueError, match="row bound"):
        parse_coverage(b"SF:a.c\nDA:1,1\nend_of_record\n", "lcov", max_rows=2)
    with pytest.raises(ValueError, match="declarations"):
        parse_coverage(b'<!DOCTYPE x [<!ENTITY y "z">]><coverage/>', "cobertura")


def _identity(run_root: Path, path: Path) -> dict:
    return {"path": path.relative_to(run_root).as_posix(), "sha256": file_sha256(path),
            "size_bytes": path.stat().st_size}


def test_accepted_publication_verifies_handoff_artifact_and_manifest(tmp_path: Path) -> None:
    snapshot = "snapshot"
    shard = tmp_path / "data" / "indices" / "analysis" / "coverage.sqlite"
    builder = IndexBuilder(shard, name="analysis", fingerprint="f" * 64,
                           target_snapshot=snapshot, shard_id="test-coverage-u")
    builder.add_coverage("test-coverage:u", "complete")
    index = IndexIdentity("analysis", "appsec-review/retrieval-index/2", builder.build(), "f" * 64,
                          shard.relative_to(tmp_path).as_posix(), {"job": "job_test_coverage"},
                          (), "test-coverage-u")
    manifest = tmp_path / "data" / "indices" / "manifests" / "coverage.json"
    write_manifest(manifest, run_id="run", target_snapshot=snapshot, target_root=tmp_path,
                   indexes=(index,))
    attempt = tmp_path / "data" / "jobs" / "job_test_coverage" / "attempts" / "attempt_0001"
    summary = attempt / "artifacts" / "test-coverage" / "accepted-test-coverage.json"
    summary.parent.mkdir(parents=True)
    atomic_json(summary, {"schema": TEST_COVERAGE_HANDOFF_SCHEMA, "source_fingerprint": snapshot,
                          "build_units": [], "totals": {}, "gaps": [],
                          "index_manifest": _identity(tmp_path, manifest)})
    summary_identity, manifest_identity = _identity(tmp_path, summary), _identity(tmp_path, manifest)
    handoff = attempt / "handoff.json"
    atomic_json(handoff, {"schema": "appsec-review/job-handoff/1", "status": "ACCEPTED",
                          "job_id": "job_test_coverage", "attempt_id": "attempt_0001",
                          "outputs": {"acceptance.publish_handoff": {
                              "artifact": summary_identity, "index_manifest": manifest_identity}},
                          "artifacts": [summary_identity, manifest_identity]})
    latest = tmp_path / "data" / "jobs" / "job_test_coverage" / "latest.json"
    atomic_json(latest, {"handoff_path": handoff.relative_to(tmp_path).as_posix(),
                         "handoff_sha256": file_sha256(handoff)})
    assert load_accepted_test_coverage(tmp_path)["handoff_sha256"] == file_sha256(handoff)
    summary.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="identity changed"):
        load_accepted_test_coverage(tmp_path)
