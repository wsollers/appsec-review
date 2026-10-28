"""Outcome acceptance follows accepted current references, never scanner shard discovery."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import sqlite3

import pytest

from appsec_review.acceptance.answer_key import Defect, evaluate, evaluate_current_report, observations_from_run
from appsec_review.acceptance.lanes import LaneWorkspace
from appsec_review.acceptance.system import accepted_final_report
from tests.final_report_support import REPORT, report_job, run_job
from tests.integration.test_authentic_poc_contract import ROOT, acceptance_lane, authentic_chain


@pytest.fixture(scope="module")
def current():
    lane = acceptance_lane("current-report")
    with lane.span("accepted-report"):
        chain = authentic_chain(lane, ci_only=True)
        run_job(chain.config, report_job(), chain.fixture.run_id, chain.upstream("job_final_publication_gate"), chain.env)
        report, _core, _projection = accepted_final_report(chain.run_root, ROOT)
    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    defect = Defect("untrusted-ci", "CWE-829", ".github/workflows/ci.yml", 1, "", (),
                    claim_id=finding["claim_id"], finding_package_id=finding["finding_package_id"])
    lane.emit("ACCEPTANCE_CASE_FINISHED", case="current-positive", findings=len(report["findings"]))
    return lane, chain, defect


def test_current_accepted_identity_state_and_bucket_survive_to_final_report(current):
    lane, chain, defect = current
    with lane.span("answer-key"):
        result = evaluate_current_report([defect], chain.run_root, schema_root=ROOT)
    assert not result.failed, result.as_dict()
    assert defect.finding_package_id in result.found[defect.id][0]
    for changed in (replace(defect, claim_id="claim-" + "0" * 64),
                    replace(defect, finding_package_id="finding-" + "0" * 64),
                    replace(defect, state="supported"), replace(defect, bucket="verification_backlog")):
        assert evaluate_current_report([changed], chain.run_root, schema_root=ROOT).missed == [defect.id]


def test_missing_current_report_is_a_gap_not_scanner_success(current):
    _lane, chain, defect = current
    path = chain.run_root / "data" / "jobs" / REPORT / "latest.json"
    original = path.read_bytes()
    try:
        path.unlink()
        result = evaluate_current_report([defect], chain.run_root, schema_root=ROOT)
        assert result.failed and result.missed == [defect.id] and result.gaps
    finally:
        path.write_bytes(original)


def test_stale_or_orphan_scanner_hit_cannot_satisfy_current_report(current):
    lane, chain, _defect = current
    path = chain.run_root / "data" / "indices" / "observations" / "superseded" / "stale.sqlite"
    path.parent.mkdir(parents=True)
    with sqlite3.connect(path) as database:
        database.execute("CREATE TABLE entities (identity TEXT, kind TEXT, name TEXT, text TEXT, payload_json TEXT)")
        database.execute("CREATE TABLE locations (entity_id TEXT, path TEXT, start_line INT, end_line INT)")
        database.execute("INSERT INTO entities VALUES ('old','tool_observation','old-rule','stale','{}')")
        database.execute("INSERT INTO locations VALUES ('old','stale-only.c',7,7)")
    defect = Defect("stale-only", "", "stale-only.c", 7, "", ())
    assert not evaluate([defect], observations_from_run(chain.run_root)).failed
    with lane.span("stale-only-hit"):
        result = evaluate_current_report([defect], chain.run_root, schema_root=ROOT)
    assert result.failed and result.missed == ["stale-only"] and not result.gaps


@pytest.mark.parametrize("part", ["report", "manifest", "finding", "handoff"])
def test_changed_accepted_bytes_fail_closed(current, part):
    lane, chain, defect = current
    report, core, _projection = accepted_final_report(chain.run_root, ROOT)
    if part == "report":
        path = chain.unit_file(REPORT, "report.assemble", "final-report.json")
    elif part == "manifest":
        pointer = json.loads((chain.run_root / "data" / "indices" / "accepted.json").read_text())
        path = chain.run_root / pointer["manifest_path"]
    elif part == "finding":
        path = chain.run_root / report["findings"][0]["path"]
    else:
        pointer = json.loads((chain.run_root / "data" / "jobs" / REPORT / "latest.json").read_text())
        path = chain.run_root / pointer["handoff_path"]
    original = path.read_bytes()
    try:
        path.write_bytes(original + b" ")
        with lane.span("tamper-" + part):
            result = evaluate_current_report([defect], chain.run_root, schema_root=ROOT)
        assert result.failed and result.gaps and not result.found
    finally:
        path.write_bytes(original)


@pytest.mark.parametrize("blocked", [False, True], ids=["benign", "blocked"])
def test_benign_and_blocked_real_reports_never_promote_scanner_detection(blocked):
    lane = acceptance_lane("current-blocked" if blocked else "current-benign")
    with lane.span("accepted-report"):
        chain = authentic_chain(lane, ci_only=True, benign=not blocked, blocked=blocked)
        run_job(chain.config, report_job(), chain.fixture.run_id, chain.upstream("job_final_publication_gate"), chain.env)
        report, _core, _projection = accepted_final_report(chain.run_root, ROOT)
        assert report["findings"] == [] and report["verification_backlog"] == []
        defect = Defect("untrusted-ci", "CWE-829", ".github/workflows/ci.yml", 1, "", ())
        result = evaluate_current_report([defect], chain.run_root, schema_root=ROOT)
    assert result.failed and result.missed == [defect.id] and not result.gaps
    lane.emit("ACCEPTANCE_CASE_FINISHED", case="blocked" if blocked else "benign")
