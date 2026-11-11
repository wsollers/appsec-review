"""Manual integration of the finding-metrics domain with a real accepted review chain.

NOT part of unit collection and never an automatic gate. It runs the scripted inference review, the
final publication gate and the final report over the fixture accepted index set (no live model, no
Docker), then reads that run through the real verified readers:

    .venv/bin/python -m pytest -q tests/integration/test_finding_metrics.py \
        --basetemp=test/tmp/finding-metrics-integration

Each test builds its own chain in its own workspace. The chain is the slow part (minutes on a
loaded host), hence the declared budget.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from appsec_review.observability.findings import history, lifecycle, run_adapter, scorecard
from appsec_review.observability.findings.contracts import check_snapshot, digest
from tests.final_report_support import run_review_chain

pytestmark = pytest.mark.time_budget(900, reason="one scripted review, gate and report chain per test")

REVISION_ONE, REVISION_TWO = "1" * 40, "2" * 40


def _chain(tmp_path: Path, name: str):
    return run_review_chain(tmp_path / name / "review", tmp_path / name / "logs")


def test_a_real_accepted_run_yields_a_valid_snapshot_and_scorecard(tmp_path):
    chain = _chain(tmp_path, "one")
    documents = run_adapter.load_run(chain.run_root)
    report_rows = sum(len(documents.report[bucket]) for bucket in ("findings", "verification_backlog", "withheld"))
    assert report_rows > 0, "the fixture chain publishes at least one finding package"
    assert set(documents.located) == {row["finding_package_id"] for bucket in (
        "findings", "verification_backlog", "withheld") for row in documents.report[bucket]}

    snapshot = run_adapter.snapshot_from_run(chain.run_root, target_id="fixture", source_revision=REVISION_ONE)
    assert check_snapshot(snapshot) == snapshot
    assert snapshot["run_id"] == chain.run_root.name
    assert snapshot["configuration_sha256"] is not None, "a run records its frozen configuration identity"
    assert "reviewed_units_not_supplied" in snapshot["gaps"]
    # Every report row either became a finding or is counted in a named gap; nothing vanished.
    unlocated = sum(int(gap.rsplit(":", 1)[1]) for gap in snapshot["gaps"]
                    if gap.startswith("finding_without_resolved_location:"))
    collapsed = sum(item["duplicates_collapsed"] for item in snapshot["findings"])
    assert len(snapshot["findings"]) + unlocated + collapsed >= report_rows
    for item in snapshot["findings"]:
        assert item["citations"]["total"] >= 1 and item["citations"]["unresolved"] == 0
        assert all(location["code"] for location in item["locations"]), "resolved evidence carries its excerpt"

    document = scorecard.build(snapshot)
    assert document["volume"]["findings"] == len(snapshot["findings"])
    assert document["integrity"]["citations"]["failure_rate"]["value"] == 0.0
    lines = scorecard.render_lines(document)
    assert lines[1] == "1. For the team" and any(line.startswith("   not measured: ") for line in lines)
    json.dumps(document)


def test_the_same_review_at_two_revisions_persists_and_is_stored_once(tmp_path):
    first = _chain(tmp_path, "first")
    second = _chain(tmp_path, "second")
    prior = run_adapter.snapshot_from_run(first.run_root, target_id="fixture", source_revision=REVISION_ONE)
    current = run_adapter.snapshot_from_run(second.run_root, target_id="fixture", source_revision=REVISION_TWO)
    if prior["run_id"] == current["run_id"]:
        pytest.skip("the fixture chain reuses one run id; lifecycle needs two distinct runs (coverage gap)")
    # The scripted review is deterministic: the same code yields the same root causes at both revisions.
    assert [item["fingerprint"]["exact"] for item in prior["findings"]] == [
        item["fingerprint"]["exact"] for item in current["findings"]]
    classified = lifecycle.classify(prior, current)
    assert {row["state"] for row in classified["prior"]} <= {"persisting"}
    assert {row["state"] for row in classified["current"]} <= {"persisting"}

    store = tmp_path / "history"
    assert history.publish_snapshot(store, prior)["status"] == "published"
    assert history.publish_snapshot(store, prior)["status"] == "duplicate"
    assert history.publish_snapshot(store, current)["status"] == "published"
    history.publish_lifecycle(store, "fixture", classified)
    loaded = history.load_history(store, "fixture")
    assert [row["run_id"] for row in loaded["snapshots"]] == sorted([prior["run_id"], current["run_id"]])
    assert history.read_snapshot(store, "fixture", digest(prior)) == prior
    document = scorecard.build(current, scorecard.Inputs(lifecycle=classified, ages=history.ages(loaded)))
    assert document["lifecycle"]["available"] is True and document["lifecycle"]["fix_rate"]["value"] == 0.0


def test_a_tampered_run_is_an_error_not_an_empty_snapshot(tmp_path):
    chain = _chain(tmp_path, "tampered")
    pointer = json.loads((chain.run_root / "data/jobs/job_final_report_publication/latest.json").read_text())
    handoff = chain.run_root / pointer["handoff_path"]
    handoff.write_bytes(handoff.read_bytes() + b" ")
    with pytest.raises(Exception) as raised:                      # noqa: PT011 - the reader's own integrity error
        run_adapter.snapshot_from_run(chain.run_root, target_id="fixture", source_revision=REVISION_ONE)
    assert type(raised.value).__name__ in {"IntegrityError", "ValueError", "RetrievalIntegrityError"}
