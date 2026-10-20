from __future__ import annotations

import hashlib
import json
from pathlib import Path

from appsec_review.acceptance.answer_key import Defect, collect_findings, evaluate, load_answer_key
from appsec_review.acceptance.system import (
    LEDGER_JOB, PACKAGE_JOB, final_artifact_problems, run_problems)
from tests.acceptance.test_environment_integrity import JOB, RUN, _run

KEY = """
[corpus]
name = "relay"

[[defect]]
id = "overflow"
cwe = "CWE-121"
path = "src/packet.cpp"
line = 16
summary = "memcpy overflow"
producers = ["codeql", "cppcheck"]

[[defect]]
id = "uaf"
cwe = "CWE-416"
path = "src/session.cpp"
line = 32
producers = ["clang-static-analyzer"]
"""


def _finding(job: str, path: str | None, line: int | None, *, end: int | None = None, unit: str = "codeql:x",
             kind: str = "tool_observation", name: str = "rule") -> dict:
    return {"job_id": job, "unit": unit, "source": "observations", "count": 1,
            "record": {"kind": kind, "name": name, "path": path, "start_line": line, "end_line": end,
                       "text": name}}


def test_the_answer_key_loads_and_rejects_empty_or_repeated_defects(tmp_path: Path) -> None:
    path = tmp_path / "expectations.toml"
    path.write_text(KEY, encoding="utf-8")
    corpus, defects = load_answer_key(path)
    assert corpus["name"] == "relay" and [item.id for item in defects] == ["overflow", "uaf"]
    path.write_text('[corpus]\nname = "x"\n', encoding="utf-8")
    try:
        load_answer_key(path)
    except ValueError as error:
        assert "no defects" in str(error)
    else:
        raise AssertionError("an empty key must be rejected")


def test_found_missed_and_spurious_are_reported_and_only_a_miss_fails() -> None:
    defects = [Defect("overflow", "CWE-121", "src/packet.cpp", 16, "", ("codeql", "cppcheck")),
               Defect("uaf", "CWE-416", "src/session.cpp", 32, "", ("clang-static-analyzer",))]
    findings = [
        _finding("job_codeql_analysis", "<target>/src/packet.cpp", 17, unit="codeql:cpp"),  # within tolerance
        _finding("job_evidence_collection", "src/packet.cpp", 10, end=20, unit="cppcheck_scan"),  # covers the line
        _finding("job_evidence_collection", "src/other.cpp", 3),  # spurious
        _finding("job_evidence_collection", None, None, kind="evidence_artifact"),  # not a finding
    ]
    report = evaluate(defects, findings)

    assert sorted(report.found) == ["overflow"] and report.missed == ["uaf"] and report.spurious == 1
    assert report.failed
    assert report.producers_seen["overflow"] == ["codeql", "cppcheck"] and report.producers_unseen["overflow"] == []

    fixed = evaluate(defects, findings + [_finding("job_clang_static_analysis", "src/session.cpp", 31,
                                                   unit="clang-static-analyzer")])
    assert not fixed.failed and fixed.missed == []


def test_a_finding_on_another_line_or_file_does_not_find_the_defect() -> None:
    defect = Defect("overflow", "CWE-121", "src/packet.cpp", 16, "", ())
    assert evaluate([defect], [_finding("j", "src/packet.cpp", 40)]).missed == ["overflow"]
    assert evaluate([defect], [_finding("j", "src/session.cpp", 16)]).missed == ["overflow"]
    assert evaluate([defect], [_finding("j", "src/packet.cpp", 19)]).missed == ["overflow"]


def test_findings_of_job_outputs_are_tagged_with_their_job() -> None:
    outputs = [{"job_id": "a", "findings": [{"record": {"kind": "tool_observation"}}]}, {"job_id": "b"}]
    assert [item["job_id"] for item in collect_findings(outputs)] == ["a"]


def test_a_run_whose_jobs_are_accepted_and_intact_has_no_problems(tmp_path: Path) -> None:
    run_root, _attempt = _run(tmp_path)
    assert run_problems(run_root, RUN, [JOB]) == []


def test_an_unrun_failed_or_tampered_job_is_reported(tmp_path: Path) -> None:
    run_root, attempt = _run(tmp_path)
    assert [item.path for item in run_problems(run_root, RUN, ["job_never_ran"])] == ["latest"]

    handoff = json.loads((attempt / "handoff.json").read_text(encoding="utf-8"))
    (attempt / "handoff.json").write_text(json.dumps({**handoff, "completion_status": "FAILED"}), encoding="utf-8")
    assert "handoff.status" in {item.path for item in run_problems(run_root, RUN, [JOB])}


def _publish(run_root: Path, job: str, output_name: str, output: dict) -> None:
    attempt = run_root / "data" / "jobs" / job / "attempts" / "attempt_0001"
    attempt.mkdir(parents=True)
    (attempt / "result.json").write_text(json.dumps({"outputs": {output_name: output}}), encoding="utf-8")
    (attempt / "handoff.json").write_text(json.dumps({"status": "ACCEPTED", "completion_status": "SUCCEEDED"}),
                                          encoding="utf-8")
    (attempt.parent.parent / "latest.json").write_text(json.dumps({
        "handoff_path": (attempt / "handoff.json").relative_to(run_root).as_posix()}), encoding="utf-8")


def _final_artifacts(tmp_path: Path) -> Path:
    run_root = tmp_path / "runs" / RUN
    packages = run_root / "data" / "review-packages" / "p1"
    packages.mkdir(parents=True)
    page = packages / "page-0001.json"
    page.write_text('{"items": []}', encoding="utf-8")
    (packages / "manifest.json").write_text(json.dumps({"content_sha256": "c" * 64, "packages": [{"id": 1}]}),
                                            encoding="utf-8")
    _publish(run_root, PACKAGE_JOB, "publication.publish_packages", {
        "package_directory": "data/review-packages/p1", "content_sha256": "c" * 64,
        "artifacts": [{"path": "data/review-packages/p1/page-0001.json",
                       "sha256": hashlib.sha256(page.read_bytes()).hexdigest()}]})
    ledger_digest = "d" * 64
    ledger = run_root / "data" / "document-issues" / ledger_digest / "ledger.json"
    ledger.parent.mkdir(parents=True)
    ledger.write_text(json.dumps({"content_sha256": ledger_digest, "candidates": []}), encoding="utf-8")
    _publish(run_root, LEDGER_JOB, "analysis.map_and_adjudicate", {
        "artifact": {"path": ledger.relative_to(run_root).as_posix()}})
    return run_root


def test_complete_final_artifacts_have_no_problems(tmp_path: Path) -> None:
    assert final_artifact_problems(_final_artifacts(tmp_path), tmp_path) == []


def test_missing_empty_or_changed_final_artifacts_are_reported(tmp_path: Path) -> None:
    run_root = _final_artifacts(tmp_path)
    (run_root / "data/review-packages/p1/page-0001.json").write_text('{"items": [1]}', encoding="utf-8")
    (run_root / "data/review-packages/p1/manifest.json").write_text(
        json.dumps({"content_sha256": "x", "packages": []}), encoding="utf-8")
    ledger = next(run_root.glob("data/document-issues/*/ledger.json"))
    ledger.write_text(json.dumps({"content_sha256": "other"}), encoding="utf-8")
    paths = {item.path for item in final_artifact_problems(run_root, tmp_path)}
    assert {"manifest.packages", "manifest.content_sha256", "artifact data/review-packages/p1/page-0001.json",
            "ledger.content_sha256"} <= paths

    empty = tmp_path / "empty" / "runs" / RUN
    empty.mkdir(parents=True)
    assert {item.job_id for item in final_artifact_problems(empty, tmp_path)} == {PACKAGE_JOB, LEDGER_JOB}
