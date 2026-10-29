"""Outcome acceptance follows accepted current references, never scanner shard discovery."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import sqlite3

import pytest

from appsec_review.acceptance.answer_key import Defect, evaluate, evaluate_current_report, observations_from_run
from appsec_review.jobs.bound_artifacts import read_bound_json
from appsec_review.storage.validation import validation_scope
from tests.acceptance_review_stages import consumer_chain, fresh_chain
from tests.final_report_support import REPORT, report_job, run_job
from tests.integration.test_authentic_poc_contract import ROOT, acceptance_lane, authentic_chain


@pytest.fixture(scope="module")
def current():
    staged = consumer_chain("ci-positive")
    if staged is None:
        lane = acceptance_lane("current-report")
        with lane.span("accepted-report"):
            chain = authentic_chain(lane, ci_only=True)
            run_job(chain.config, report_job(), chain.fixture.run_id,
                    chain.upstream("job_final_publication_gate"), chain.env)
    else:
        lane, chain = staged
    with validation_scope(chain.run_root):
        report = read_bound_json(
            chain.run_root, chain.handoff(REPORT)["outputs"]["report.assemble"]["artifact"])
    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    defect = Defect("untrusted-ci", "CWE-829", ".github/workflows/ci.yml", 1, "", (),
                    claim_id=finding["claim_id"], finding_package_id=finding["finding_package_id"])
    lane.emit("ACCEPTANCE_CASE_FINISHED", case="current-positive", findings=len(report["findings"]))
    # This producer metadata only locates mutations; each oracle call revalidates the current chain.
    return lane, chain, defect, report


def test_current_accepted_identity_state_and_bucket_survive_to_final_report(current):
    _assert_identity_matrix(current)


def _assert_identity_matrix(current, *, additional=()):
    lane, chain, defect, _report = current
    changed = [
        replace(defect, id="wrong-claim", claim_id="claim-" + "0" * 64),
        replace(defect, id="wrong-finding", finding_package_id="finding-" + "0" * 64),
        replace(defect, id="wrong-state", state="supported"),
        replace(defect, id="wrong-bucket", bucket="verification_backlog"),
    ]
    with lane.span("answer-key"), validation_scope(chain.run_root):
        result = evaluate_current_report([defect, *changed, *additional], chain.run_root, schema_root=ROOT)
    assert not result.gaps, result.as_dict()
    assert set(result.found) == {defect.id}, result.as_dict()
    assert defect.finding_package_id in result.found[defect.id][0]
    assert result.missed == [item.id for item in (*changed, *additional)]
    assert result.spurious == 0


def test_missing_current_report_is_a_gap_not_scanner_success(current):
    lane, chain, defect, _report = current
    chain = fresh_chain(chain, "missing-current-report")
    path = chain.run_root / "data" / "jobs" / REPORT / "latest.json"
    path.unlink()
    with validation_scope(chain.run_root):
        result = evaluate_current_report([defect], chain.run_root, schema_root=ROOT)
    assert result.failed and result.missed == [defect.id] and result.gaps
    lane.emit("ACCEPTANCE_MUTATION_VALIDATED", vector="missing-current",
              run_root=str(chain.run_root), path=path.relative_to(chain.run_root).as_posix(),
              validator="evaluate_current_report", outcome="rejected", gaps=list(result.gaps))


def _orphan_scanner_hit(chain):
    path = chain.run_root / "data" / "indices" / "observations" / "superseded" / "stale.sqlite"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    with sqlite3.connect(path) as database:
        database.execute("CREATE TABLE entities (identity TEXT, kind TEXT, name TEXT, text TEXT, payload_json TEXT)")
        database.execute("CREATE TABLE locations (entity_id TEXT, path TEXT, start_line INT, end_line INT)")
        database.execute("INSERT INTO entities VALUES ('old','tool_observation','old-rule','stale','{}')")
        database.execute("INSERT INTO locations VALUES ('old','stale-only.c',7,7)")
    defect = Defect("stale-only", "", "stale-only.c", 7, "", ())
    assert not evaluate([defect], observations_from_run(chain.run_root)).failed
    return defect


def test_stale_or_orphan_scanner_hit_cannot_satisfy_current_report(current):
    lane, chain, _defect, _report = current
    chain = fresh_chain(chain, "orphan-scanner-hit")
    defect = _orphan_scanner_hit(chain)
    with lane.span("stale-only-hit"), validation_scope(chain.run_root):
        result = evaluate_current_report([defect], chain.run_root, schema_root=ROOT)
    assert result.failed and result.missed == ["stale-only"] and not result.gaps
    lane.emit("ACCEPTANCE_MUTATION_VALIDATED", vector="orphan-hit",
              run_root=str(chain.run_root), validator="evaluate_current_report", outcome="missed-not-gap")


@pytest.mark.parametrize("part", ["report", "manifest", "finding", "handoff", "report-same-size"])
def test_changed_accepted_bytes_fail_closed(current, part):
    lane, chain, defect, report = current
    chain = fresh_chain(chain, "tamper-" + part)
    if part in {"report", "report-same-size"}:
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
    changed = (b"[" + original[1:]) if part == "report-same-size" else original + b" "
    assert changed != original
    if part == "report-same-size":
        assert len(changed) == len(original)
    path.write_bytes(changed)
    with lane.span("tamper-" + part), validation_scope(chain.run_root):
        result = evaluate_current_report([defect], chain.run_root, schema_root=ROOT)
    assert result.failed and result.gaps and not result.found
    lane.emit("ACCEPTANCE_MUTATION_VALIDATED", vector=part, run_root=str(chain.run_root),
              path=path.relative_to(chain.run_root).as_posix(),
              before_sha256=hashlib.sha256(original).hexdigest(),
              after_sha256=hashlib.sha256(changed).hexdigest(), same_size=len(original) == len(changed),
              validator="evaluate_current_report", outcome="rejected", gaps=list(result.gaps))


def test_current_report_quick_contract(current):
    """Positive identity/state/bucket proof plus one independent integrity rejection."""
    _assert_identity_matrix(current)
    test_changed_accepted_bytes_fail_closed(current, "report")
    current[0].emit("ACCEPTANCE_CASE_FINISHED", case="quick-oracle", tamper_vectors=1)


def test_current_report_bound_oracle_matrix(current):
    """Each mutation gets a fresh copy and a validation scope opened after mutation."""
    lane, chain, defect, report = current
    private = fresh_chain(chain, "matrix-orphan")
    orphan = _orphan_scanner_hit(private)
    _assert_identity_matrix((lane, private, defect, report), additional=(orphan,))
    test_missing_current_report_is_a_gap_not_scanner_success(current)
    for part in ("report", "manifest", "finding", "handoff", "report-same-size"):
        test_changed_accepted_bytes_fail_closed(current, part)
    lane.emit("ACCEPTANCE_CASE_FINISHED", case="bound-oracle-matrix", tamper_vectors=5)


@pytest.mark.parametrize("blocked", [False, True], ids=["benign", "blocked"])
def test_benign_and_blocked_real_reports_never_promote_scanner_detection(blocked):
    staged = consumer_chain("ci-blocked" if blocked else "ci-benign")
    if staged is None:
        lane = acceptance_lane("current-blocked" if blocked else "current-benign")
        with lane.span("accepted-report"):
            chain = authentic_chain(lane, ci_only=True, benign=not blocked, blocked=blocked)
            run_job(chain.config, report_job(), chain.fixture.run_id,
                    chain.upstream("job_final_publication_gate"), chain.env)
    else:
        lane, chain = staged
    with lane.span("validate-report"), validation_scope(chain.run_root):
        report = read_bound_json(
            chain.run_root, chain.handoff(REPORT)["outputs"]["report.assemble"]["artifact"])
        assert report["findings"] == [] and report["verification_backlog"] == []
        defect = Defect("untrusted-ci", "CWE-829", ".github/workflows/ci.yml", 1, "", ())
        result = evaluate_current_report([defect], chain.run_root, schema_root=ROOT)
    assert result.failed and result.missed == [defect.id] and not result.gaps
    lane.emit("ACCEPTANCE_CASE_FINISHED", case="blocked" if blocked else "benign")
