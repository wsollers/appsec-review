from __future__ import annotations

import hashlib
import json
from pathlib import Path

from appsec_review.acceptance.answer_key import (
    Defect, collect_findings, evaluate, load_answer_key, observations_from_run)
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
        _finding("job_codeql_analysis", "<target>/src/packet.cpp", 16, unit="codeql:cpp"),  # exact line
        _finding("job_evidence_collection", "src/packet.cpp", 10, end=20, unit="cppcheck_scan"),  # covers the line
        _finding("job_evidence_collection", "src/other.cpp", 3),  # spurious
        _finding("job_evidence_collection", None, None, kind="evidence_artifact"),  # not a finding
    ]
    report = evaluate(defects, findings)

    assert sorted(report.found) == ["overflow"] and report.missed == ["uaf"] and report.spurious == 1
    assert report.failed
    assert report.producers_seen["overflow"] == ["codeql", "cppcheck"] and report.producers_unseen["overflow"] == []

    fixed = evaluate(defects, findings + [_finding("job_clang_static_analysis", "src/session.cpp", 32,
                                                   unit="clang-static-analyzer")])
    assert not fixed.failed and fixed.missed == []


def test_a_finding_on_another_line_or_file_does_not_find_the_defect() -> None:
    defect = Defect("overflow", "CWE-121", "src/packet.cpp", 16, "", ())
    assert evaluate([defect], [_finding("j", "src/packet.cpp", 40)]).missed == ["overflow"]
    assert evaluate([defect], [_finding("j", "src/session.cpp", 16)]).missed == ["overflow"]
    assert evaluate([defect], [_finding("j", "src/packet.cpp", 17)]).missed == ["overflow"]  # a neighbour is not a hit
    assert evaluate([defect], [_finding("j", "src/packet.cpp", 17)], tolerance=1).missed == []


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
    (attempt / "handoff.json").write_text(json.dumps({
        "schema": "appsec-review/job-handoff/1", "job_id": job, "status": "ACCEPTED",
        "completion_status": "SUCCEEDED", "outputs": {output_name: output},
        "artifacts": [output["artifact"]] if "artifact" in output else output.get("artifacts", [])}),
        encoding="utf-8")
    (attempt.parent.parent / "latest.json").write_text(json.dumps({
        "handoff_path": (attempt / "handoff.json").relative_to(run_root).as_posix(),
        "handoff_sha256": hashlib.sha256((attempt / "handoff.json").read_bytes()).hexdigest()}), encoding="utf-8")


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
    from appsec_review.retrieval.model import canonical_json as content_json
    from appsec_review.storage import canonical_json
    from appsec_review.storage.shared import put_bytes

    body = {"candidates": []}
    ledger_digest = hashlib.sha256(content_json(body)).hexdigest()
    artifact = put_bytes(run_root, canonical_json({**body, "content_sha256": ledger_digest}))
    _publish(run_root, LEDGER_JOB, "analysis.map_and_adjudicate", {"artifact": artifact})
    return run_root


def test_complete_final_artifacts_have_no_problems(tmp_path: Path) -> None:
    assert final_artifact_problems(_final_artifacts(tmp_path), tmp_path) == []


def test_missing_empty_or_changed_final_artifacts_are_reported(tmp_path: Path) -> None:
    run_root = _final_artifacts(tmp_path)
    (run_root / "data/review-packages/p1/page-0001.json").write_text('{"items": [1]}', encoding="utf-8")
    (run_root / "data/review-packages/p1/manifest.json").write_text(
        json.dumps({"content_sha256": "x", "packages": []}), encoding="utf-8")
    ledger = next(run_root.glob("data/shared/objects/*"))
    ledger.write_text(json.dumps({"content_sha256": "other"}), encoding="utf-8")
    paths = {item.path for item in final_artifact_problems(run_root, tmp_path)}
    assert {"manifest.packages", "manifest.content_sha256", "artifact data/review-packages/p1/page-0001.json",
            "ledger.content_sha256"} <= paths

    empty = tmp_path / "empty" / "runs" / RUN
    empty.mkdir(parents=True)
    assert {item.job_id for item in final_artifact_problems(empty, tmp_path)} == {PACKAGE_JOB, LEDGER_JOB}


def test_observations_are_read_from_the_published_shards(tmp_path: Path) -> None:
    import sqlite3

    shard = tmp_path / "data" / "indices" / "observations" / "clang" / "shard.sqlite"
    shard.parent.mkdir(parents=True)
    database = sqlite3.connect(shard)
    database.execute("CREATE TABLE entities (identity TEXT, kind TEXT, native_id TEXT, name TEXT, text TEXT, payload_json TEXT)")
    database.execute("CREATE TABLE locations (location_id TEXT, entity_id TEXT, path TEXT, start_line INT, end_line INT)")
    database.execute("INSERT INTO entities VALUES ('o1','tool_observation','n','cplusplus.NewDelete','Use of memory after it is freed',"
                     "'{\"scanner\": \"clang-static-analysis\", \"native_rule_id\": \"cplusplus.NewDelete\"}')")
    database.execute("INSERT INTO entities VALUES ('f1','source_file','n','src/session.cpp','','{}')")
    database.execute("INSERT INTO locations VALUES ('l1','o1','src/session.cpp',32,32)")
    database.execute("INSERT INTO locations VALUES ('l2','f1','src/session.cpp',1,50)")
    database.commit()
    database.close()

    findings = observations_from_run(tmp_path)
    assert [(item["record"]["name"], item["record"]["path"], item["record"]["start_line"]) for item in findings] == [
        ("cplusplus.NewDelete", "src/session.cpp", 32)]
    report = evaluate([Defect("uaf", "CWE-416", "src/session.cpp", 32, "", ("clang-static-analysis",))], findings)
    assert report.missed == [] and report.producers_seen["uaf"] == ["clang-static-analysis"]
    assert observations_from_run(tmp_path / "empty") == []


def test_a_defect_spanning_lines_is_found_by_a_finding_on_any_of_them(tmp_path: Path) -> None:
    key = tmp_path / "expectations.toml"
    key.write_text(
        '[corpus]\nname = "x"\n[[defect]]\nid = "wrap"\npath = "src/frame.cpp"\nline = 9\nend_line = 10\n'
        '[[defect]]\nid = "backwards"\npath = "src/a.cpp"\nline = 5\nend_line = 4\n', encoding="utf-8")
    try:
        load_answer_key(key)
    except ValueError as error:
        assert "end_line precedes line" in str(error)
    else:
        raise AssertionError("an end_line before line must be rejected")

    key.write_text('[corpus]\nname = "x"\n[[defect]]\nid = "wrap"\npath = "src/frame.cpp"\nline = 9\nend_line = 10\n',
                   encoding="utf-8")
    _corpus, defects = load_answer_key(key)
    assert (defects[0].line, defects[0].end_line) == (9, 10)
    for line in (9, 10):
        assert evaluate(defects, [_finding("j", "src/frame.cpp", line)]).missed == []
    assert evaluate(defects, [_finding("j", "src/frame.cpp", 8)]).missed == ["wrap"]
    assert evaluate(defects, [_finding("j", "src/frame.cpp", 11)]).missed == ["wrap"]
    assert evaluate(defects, [_finding("j", "src/frame.cpp", 8, end=9)]).missed == []  # a range reaching the defect
