"""Manual acceptance of the finding-metrics operator workflow; no live inference, no Docker, no network.

NOT part of unit collection and never an automatic gate. It drives the real entry point in a child
process, the way an operator does, over a disposable store:

    .venv/bin/python -m pytest -q tests/acceptance/test_finding_metrics.py \
        --basetemp=test/tmp/finding-metrics-acceptance

Scenario: one target reviewed at two revisions. Between them one defect is fixed, one file is not
reviewed again, one finding is simply not re-reported, and a new finding appears. Crash exports in
three formats are ingested. The acceptance criteria are what a game team must be able to read off
the page: what is new, what is fixed, what only looks fixed, what the crashes corroborate, and what
was not measured.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from appsec_review.observability.findings import history, lifecycle, recheck
from appsec_review.observability.findings.contracts import METRICS_SCHEMA, build_snapshot
from appsec_review.observability.findings.identity import fingerprint

pytestmark = pytest.mark.time_budget(120, reason="a handful of short child processes over a temporary store")

ROOT = Path(__file__).resolve().parents[2]
CRASH = ROOT / "tests" / "fixtures" / "finding_metrics" / "crash"
ENTRY = [sys.executable, "-m", "appsec_review.observability.findings"]


def run(*arguments: str | Path) -> subprocess.CompletedProcess[str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("APPSEC_")}
    return subprocess.run([*ENTRY, *map(str, arguments)], cwd=ROOT, env=environment, capture_output=True,
                          text=True, timeout=60, check=False)


def finding(finding_id, path, function, cwe, *, severity="high", state="confirmed", lane="lead", code=None):
    return {"finding_id": finding_id, "state": state, "weakness_cwe": cwe, "severity": severity, "lane": lane,
            "bucket": "findings", "ship_block_status": "ship_blocking", "scanner_backed": lane == "lead",
            "locations": [{"path": path, "start_line": 10, "end_line": 12, "function": function,
                           "code": code or f"{function}(input);"}],
            "citations": {"total": 2, "unresolved": 0},
            "actionability": {"entry_to_sink_path": True, "preconditions": True, "remediation": None,
                              "remediation_validated": None}}


def snapshots():
    then = build_snapshot(
        run_id="run-1", target_id="game", source_revision="1" * 40, fingerprint=fingerprint,
        findings=[finding("uaf", "net/parse.c", "parse_packet", "CWE-416", severity="critical"),
                  finding("overflow", "save/load.c", "load_save", "CWE-787"),
                  finding("format", "ui/chat.c", "show_chat", "CWE-134"),
                  finding("skipped", "mods/loader.c", "load_mod", "CWE-22")],
        reviewed_units={"net/parse.c": "a" * 64, "save/load.c": "b" * 64, "ui/chat.c": "c" * 64,
                        "mods/loader.c": "d" * 64},
        unreviewed_units={}, configuration_sha256="1" * 64, guidance_sha256="2" * 64, model_sha256="3" * 64)
    now = build_snapshot(
        run_id="run-2", target_id="game", source_revision="2" * 40, fingerprint=fingerprint,
        findings=[finding("uaf", "net/parse.c", "parse_packet", "CWE-416", severity="critical"),
                  finding("race", "game/score.c", "update_score", "CWE-362", lane="hunt")],
        reviewed_units={"net/parse.c": "a" * 64, "save/load.c": "e" * 64, "ui/chat.c": "c" * 64,
                        "game/score.c": "f" * 64, "net/session.c": "9" * 64},
        unreviewed_units={"mods/loader.c": "not_built"},
        configuration_sha256="1" * 64, guidance_sha256="2" * 64, model_sha256="3" * 64)
    return then, now


@pytest.fixture
def store(tmp_path):
    then, now = snapshots()
    root = tmp_path / "history"
    history.publish_snapshot(root, then)
    history.publish_snapshot(root, now)
    return root


def test_the_page_separates_fixed_from_merely_absent(store, tmp_path):
    result = run("scorecard", "--history", store, "--target-id", "game", "--run-id", "run-2")
    assert result.returncode == 0, result.stderr
    lines = result.stdout.splitlines()
    assert [line for line in lines if line[:1].isdigit()] == [
        "1. For the team", "2. How far to trust it", "3. What triage did", "4. Where it is blind"]
    # Without a targeted re-check nothing is "fixed": the changed file is only a candidate.
    assert "   since run-1: new=1 regressed=0 persisting=1 fixed=0 still_present=0" in lines
    assert "   not progress: fix_candidate=1 not_redetected=1 not_covered=1" in lines
    assert "   confirmed high/critical: 2   supported high/critical (unconfirmed): 0" in lines
    assert any(line.startswith("   - uaf critical CWE-416 net/parse.c ") for line in lines)
    assert "   precision: n/a (no_finding_labels)" in lines, "no label source was supplied; never a zero"
    assert "   found without any scanner: 1 (backing unknown: 0)" in lines


def test_a_targeted_recheck_is_the_only_way_to_a_fix_and_must_cite_changed_code(store):
    then, now = snapshots()
    classified = lifecycle.classify(then, now)
    requests = recheck.build_requests(classified, then)
    assert requests["eligible"] == 2 and requests["truncated"] == 0

    def scripted(request):                                   # stands in for the verifier; an external boundary
        if request["finding_id"] == "overflow":
            return {"finding_id": "overflow", "outcome": "fixed", "reason": "bounds check added",
                    "cited": [{"path": "save/load.c", "start_line": 9, "end_line": 12}]}
        return {"finding_id": request["finding_id"], "outcome": "fixed", "reason": "looks fine",
                "cited": [{"path": "ui/chat.c", "start_line": 10, "end_line": 12}]}     # unchanged file

    outcome = recheck.run_rechecks(requests["requests"], scripted, prior_snapshot=then, current_snapshot=now)
    assert outcome["results"]["overflow"]["outcome"] == "fixed"
    assert outcome["results"]["format"]["outcome"] == "insufficient_evidence"
    assert outcome["results"]["format"]["downgrade_reason"] == "fixed_without_changed_citation"
    states = {row["finding_id"]: row["state"] for row in lifecycle.apply_rechecks(classified, outcome["results"])["prior"]}
    assert states == {"uaf": "persisting", "overflow": "fixed", "format": "not_redetected", "skipped": "not_covered"}


def test_crash_exports_in_three_formats_corroborate_and_expose_what_review_missed(store, tmp_path):
    ingested = run("crash-ingest",
                   "--source", f"sanitizer_report={CRASH / 'sanitizer_wellformed.log'}",
                   "--source", f"stackwalk_json={CRASH / 'stackwalk_wellformed.json'}",
                   "--source", f"sentry_event={CRASH / 'sentry_wellformed.json'}",
                   "--strip-root", "/home/builder/src/", "--output", tmp_path / "crash")
    assert ingested.returncode == 0, ingested.stderr
    receipt = json.loads(ingested.stdout)
    assert receipt["counts"]["failed"] == 0 and receipt["counts"]["parsed"] == 3
    stored = Path(receipt["path"]).read_text(encoding="utf-8")
    for forbidden in ("/home/builder", "ip_address", "breadcrumbs", "server_name"):
        assert forbidden not in stored, f"{forbidden!r} must not survive ingestion"
    again = run("crash-ingest", "--source", f"sanitizer_report={CRASH / 'sanitizer_wellformed.log'}",
                "--source", f"stackwalk_json={CRASH / 'stackwalk_wellformed.json'}",
                "--source", f"sentry_event={CRASH / 'sentry_wellformed.json'}",
                "--strip-root", "/home/builder/src/", "--output", tmp_path / "crash")
    assert json.loads(again.stdout)["status"] == "duplicate", "evidence is content-addressed"

    result = run("scorecard", "--history", store, "--target-id", "game", "--run-id", "run-2",
                 "--crash-evidence", receipt["path"], "--json", "--output", tmp_path / "scorecard.json")
    assert result.returncode == 0, result.stderr
    document = json.loads((tmp_path / "scorecard.json").read_text(encoding="utf-8"))
    assert document["schema"] == METRICS_SCHEMA
    crash = document["crash"]
    assert crash["available"] is True and crash["parse_failures"]["files"] == 0
    assert set(crash["by_adapter"]) == {"sanitizer_report", "sentry_event", "stackwalk_json"}
    assert crash["corroborated_findings"] >= 1, "the use-after-free in parse_packet is on a published finding"
    assert crash["corroborated_share_of_actionable"]["numerator"] >= 1
    assert isinstance(crash["memory_safety_buckets_without_finding"], int)
    assert document["labels"]["available"] is True, "a crash is a label source"


def test_the_audit_sample_is_reproducible_across_processes(tmp_path):
    leads = tmp_path / "leads.json"
    leads.write_text(json.dumps([{"lead_id": f"lead-{index:03d}", "disposition": disposition}
                                 for index, disposition in enumerate(
                                     ["dismissed_by_adjudication", "no_claim_raised", "survived_confirmed"] * 20)]),
                     encoding="utf-8")
    outputs = []
    for name in ("first.json", "second.json"):
        drawn = run("audit-sample", "--leads", leads, "--seed", "audit-2026-11", "--size", "10",
                    "--output", tmp_path / name)
        assert drawn.returncode == 0, drawn.stderr
        outputs.append((tmp_path / name).read_bytes())
    assert outputs[0] == outputs[1]
    sample = json.loads(outputs[0])
    assert sample["eligible"] == 40 and len(sample["sample"]) == 10
    assert all(item["disposition"] != "survived_confirmed" for item in sample["sample"])


def test_unusable_inputs_fail_closed_with_a_named_reason(store, tmp_path):
    missing = run("scorecard", "--history", store, "--target-id", "game", "--run-id", "run-9")
    assert missing.returncode == 2 and "holds 0 published snapshots" in missing.stderr and missing.stdout == ""
    tampered = next((store / "game" / "snapshots").glob("*.json"))
    tampered.write_bytes(tampered.read_bytes().replace(b'"game"', b'"gamf"'))
    refused = run("scorecard", "--history", store, "--target-id", "game", "--run-id", "run-2")
    assert refused.returncode == 2 and refused.stdout == "", "a tampered store is an error, not a smaller history"
