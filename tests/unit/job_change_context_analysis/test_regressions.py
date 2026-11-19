"""T-5112/T-5113: observed review facts, bounded attribution, and selective priority."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_change_context_analysis import job, metrics
from appsec_review.jobs.job_change_context_analysis.settings import PRIORITY_SIGNALS
from appsec_review.jobs.job_change_context_analysis.sources import REVIEW_EXPORT_SCHEMA, normalize_review_record
from appsec_review.jobs.job_review_prioritization import composite, scoring
from appsec_review.jobs.job_review_prioritization.datasets import CONTRACT as PRIORITY_CONTRACT
from appsec_review.jobs.job_source_history_analysis.sources import GitSource
from appsec_review.runtime.consume import upstream_scope
from appsec_review.storage import atomic_json, file_sha256
from tests.handoff_fixture import write_fixture_handoff
from .support import (
    HEAD, PARENT, PRIOR, SOURCE, T0, artifact, change_entry, context, default_settings,
    document, eligible_entry, handler, write_resolved_config,
)


def _aggregate(records):
    return metrics.aggregate(
        list(records), records, fix_events=None, fix_on_fix_status="unavailable",
        owner=metrics.ownership({}, .5), owner_status="unavailable", organization=None,
        identity_of={}, classification_status="available", settings=default_settings(),
    )


def _records(changes, reviews):
    return metrics.change_records(
        changes, {}, reviews=reviews, deployments=None,
        walked=[item["change_id"] for item in changes], zone=None, roots=[], settings=default_settings(),
    )[0]


@pytest.mark.parametrize("review_source", [None, {}, {HEAD: {"pull_request": 9}}], ids=["unavailable", "missing", "incomplete"])
def test_unobserved_review_metrics_do_not_become_ranked_zeros(review_source):
    reviews = None if review_source is None else {
        key: normalize_review_record(value) for key, value in review_source.items()
    }
    value = _aggregate(_records([change_entry(HEAD, 0, T0, [("src/a.py", 1, 0)])], reviews))
    for signal in metrics.REVIEW_SIGNALS:
        assert value["metrics"][signal] is None
        assert value["availability"][signal] == "unavailable"
    [ranked] = metrics.rank({"src/a.py": value}, dict.fromkeys(metrics.REVIEW_SIGNALS, 1))
    assert ranked["coverage"] == 0
    assert set(ranked["missing_signals"]) == set(metrics.REVIEW_SIGNALS)


def test_review_availability_is_per_metric_and_retains_observed_zero():
    changes = [change_entry(HEAD, 0, T0, [("a.py", 1, 0)]),
               change_entry(PARENT, 1, T0 - 1, [("a.py", 1, 0)])]
    record = normalize_review_record({
        "pull_request": 9, "head_sha": HEAD,
        "approvals": [{"commit_id": HEAD, "submitted_at": None}],
    })
    partial = _aggregate(_records(changes, {HEAD: record}))
    assert partial["metrics"]["fast_review_change_count"] is None
    for signal in ("stale_approval_change_count", "unapproved_mainline_change_count"):
        assert partial["metrics"][signal] == 0
        assert partial["availability"][signal] == "partial"
    assert metrics.rank({"a": partial}, dict.fromkeys(metrics.REVIEW_SIGNALS, 1))[0]["coverage"] == pytest.approx(2 / 3, abs=1e-6)

    measured = _aggregate(_records(changes[:1], {HEAD: record}))
    assert measured["metrics"]["stale_approval_change_count"] == 0
    assert measured["availability"]["stale_approval_change_count"] == "available"
    direct = _aggregate(_records(changes[:1], {HEAD: normalize_review_record({"direct_push": True})}))
    assert [direct["metrics"][key] for key in metrics.REVIEW_SIGNALS] == [0, 0, 1]
    assert all(direct["availability"][key] == "available" for key in metrics.REVIEW_SIGNALS)


@pytest.mark.parametrize("approvals, expected_head", [
    ([{"submitted_at": None, "commit_id": None}], None),
    ([{"submitted_at": "bad", "commit_id": "bad"}], None),
    ([{"submitted_at": None, "commit_id": PARENT}, {"submitted_at": None, "commit_id": None}], None),
    ([{"submitted_at": None, "commit_id": HEAD}, {"submitted_at": None, "commit_id": None}], True),
    ([None], None),
], ids=["absent", "invalid", "mixed-unknown", "observed-head", "rejected"])
def test_incomplete_approvals_do_not_prove_a_stale_or_unapproved_head(approvals, expected_head):
    normalized = normalize_review_record({
        "pull_request": 1, "head_sha": HEAD,
        "created_at": "2023-11-14T20:00:00Z", "merged_at": "2023-11-14T23:00:00Z",
        "approvals": approvals,
    })
    facts = metrics.review_facts(normalized, 300)
    assert normalized["complete"] is False
    assert facts["status"] == "incomplete"
    assert facts["merged_head_approved"] is expected_head
    assert facts["stale_approval"] is (False if expected_head else None)
    assert facts["unapproved_mainline"] is (None if approvals == [None] else False)
    assert facts["fast_approval"] is None


def test_bounded_approval_prefix_cannot_prove_absent_head_or_first_approval():
    old = {"submitted_at": "2023-11-14T22:00:00Z", "commit_id": PARENT}
    normalized = normalize_review_record({
        "pull_request": 1, "head_sha": HEAD, "head_committed_at": "2023-11-14T21:59:00Z",
        "created_at": "2023-11-14T20:00:00Z", "merged_at": "2023-11-14T23:00:00Z",
        "approvals": [old] * 1000 + [{"submitted_at": "2023-11-14T20:01:00Z", "commit_id": HEAD}],
    })
    assert len(normalized["approvals"]) == 1000
    assert "review_approvals_bound_reached" in normalized["gaps"]
    facts = metrics.review_facts(normalized, 300)
    assert facts["status"] == "incomplete"
    assert facts["merged_head_approved"] is None and facts["stale_approval"] is None
    assert facts["creation_to_first_approval_seconds"] is None
    assert facts["fast_approval"] is None


@pytest.mark.parametrize("submitted_at, expected", [
    ("2023-11-14T20:01:00Z", True), ("2023-11-14T22:00:00Z", None),
], ids=["observed-fast", "unknown-head-interval"])
def test_missing_head_time_cannot_prove_review_was_slow(submitted_at, expected):
    normalized = normalize_review_record({
        "pull_request": 1, "head_sha": HEAD,
        "created_at": "2023-11-14T20:00:00Z", "merged_at": "2023-11-14T23:00:00Z",
        "approvals": [{"submitted_at": submitted_at, "commit_id": HEAD}],
    })
    facts = metrics.review_facts(normalized, 300)
    assert facts["fast_approval"] is expected
    result = _aggregate(_records([change_entry(HEAD, 0, T0, [("a.py", 1, 0)])], {HEAD: normalized}))
    assert result["metrics"]["fast_review_change_count"] == (1 if expected else None)


def test_review_unit_churn_and_ambiguity_are_counted_once():
    changes = [
        change_entry(HEAD, 0, T0, [("one/a.py", 30, 0), ("two/a.py", 30, 0)]),
        change_entry(PARENT, 1, T0 - 1, [("tests/test_a.py", 5, 0)]),
        change_entry(PRIOR, 2, T0 - 2, [("one/b.py", 7, 0)]),
    ]
    review = normalize_review_record({"pull_request": 9})
    result = _aggregate(_records(changes, {HEAD: review, PARENT: review}))
    assert result["change_count"] == 3
    assert result["details"]["tests"]["production_churn"] == 67
    assert result["details"]["tests"]["associated_test_churn"] == 5
    assert result["details"]["tests"]["ambiguous_association_count"] == 1


@pytest.mark.parametrize("hunk_count", [200, 201], ids=["at-bound", "over-bound"])
def test_fix_on_fix_reports_the_actual_hunk_bound(tmp_path: Path, monkeypatch, hunk_count):
    unit = context(tmp_path, "attribute.fix_on_fix")
    write_resolved_config(unit.job.run_root)
    changes = [change_entry(HEAD, 0, T0, [("a.py", hunk_count, hunk_count)]),
               change_entry(PRIOR, 1, T0 - 60, [("a.py", 1, 0)])]
    unit.outputs["load.accepted_history"] = {
        "available": True, "eligible": {"a.py": eligible_entry()},
        "changes": artifact(unit, "changes.json", {"changes": changes}),
        "classification": artifact(unit, "classes.json", {
            "classes": {HEAD: {"fix": "heuristic"}, PRIOR: {"fix": "heuristic"}, PARENT: {"fix": None}},
        }),
        "git": GitSource("SUCCEEDED", "resolved", ".git", snapshot_commit=HEAD, head_commit=HEAD).as_dict(),
        "source": {"source_id": ".", "root": "."},
    }
    selected = []

    def run(label, argv):
        if label.startswith("fof-diff"):
            assert argv[-4:] == (PARENT, HEAD, "--", "a.py")
            data = "".join(f"@@ -{i * 2 + 1},1 +{i * 2 + 1},1 @@\n" for i in range(hunk_count)).encode()
        else:
            ranges = [argv[i + 1] for i, value in enumerate(argv) if value == "-L"]
            selected.extend(ranges)
            data = "".join(
                f'{PRIOR if value == f"{hunk_count * 2 - 1},+1" else PARENT} 1 1 1\n\tline\n'
                for value in ranges
            ).encode()
        return SimpleNamespace(stdout=data, exit_code=0, timed_out=False, truncated=False)

    monkeypatch.setattr(job, "GitRunner", lambda *_a, **_kw: SimpleNamespace(run=run))
    result = handler(unit, executor_factory=lambda _: None)(unit)
    stored = document(unit, result)
    assert len(selected) == 200
    assert result["event_count"] == (1 if hunk_count == 200 else 0)
    assert result["status"] == ("available" if hunk_count == 200 else "partial")
    assert result["gaps"] == ([] if hunk_count == 200 else ["fix_on_fix_hunk_bound_reached"])
    assert stored["hunk_count"] == hunk_count
    assert stored["checked_hunks"] == 200
    assert stored["omitted_hunks"] == hunk_count - 200


def _pipeline(tmp_path: Path, raw_reviews, *, with_function=False):
    overrides = {f"priority_weights.{name}": float(name == "unapproved_mainline_change_count")
                 for name in PRIORITY_SIGNALS}
    overrides["ranking_top_files"] = 1
    unit = context(tmp_path, "load.external_sources", overrides=overrides,
                   files={"src/a.py": SOURCE, "other.py": SOURCE})
    changes = [change_entry(HEAD, 0, T0, [("src/a.py", 1, 0), ("other.py", 1, 0)]),
               change_entry(PARENT, 1, T0 - 1, [("other.py", 1, 0)])]
    loaded = {
        "available": True, "source": {"source_id": "repo-one", "root": "."},
        "snapshot_commit": HEAD, "history_handoff_sha256": "history-sha", "history_identity": "history-id",
        "components": [], "classification": None, "classification_gaps": [], "gaps": [],
        "eligible": {path: eligible_entry(SOURCE, path) for path in ("src/a.py", "other.py")},
        "changes": artifact(unit, "changes.json", {"changes": changes, "walked_commits": [HEAD, PARENT]}),
        "review_records": artifact(unit, "reviews.json", {"schema": REVIEW_EXPORT_SCHEMA, "records": raw_reviews}),
        "lifetime": artifact(unit, "lifetime.json", {"files": {}, "components": {}, "identities": {}, "gaps": []}),
    }
    outputs = {"load.accepted_history": loaded,
               "attribute.line_attribution": {"gaps": []}, "attribute.fix_on_fix": {"gaps": []}}
    if with_function:
        function = {
            "key": "src/a.py#1-2:function_definition", "name": "check", "type": "function_definition",
            "start_line": 1, "end_line": 2, "identity": "node-hot",
            "location": {"start_line": 1, "end_line": 2, "start_byte": 0, "end_byte": len(SOURCE)},
            "commits": {HEAD: 2}, "line_authors": {"author-0001": 2},
        }
        outputs["attribute.line_attribution"] = {
            "artifact": artifact(unit, "attribution.json", {
                "files": {"src/a.py": {"functions": [function], "line_authors": {"author-0001": 2}}},
            }), "function_count": 1, "gaps": [],
        }

    def run(unit_id):
        step, task = unit_id.split(".")
        ctx = replace(unit, unit_id=unit_id, step_id=step, task_id=task,
                      unit_root=unit.job.attempt_root / "steps" / step / "tasks" / task, outputs=outputs)
        outputs[unit_id] = handler(ctx)(ctx)
        return ctx

    for unit_id in ("load.external_sources", "analyze.change_signals", "analyze.unit_signals", "analyze.rank"):
        run(unit_id)
    outputs["publish.index_change_context"] = {"manifest": None}
    published = run("publish.publish_handoff")
    return published, outputs


@pytest.mark.parametrize("reviews, expected_gap", [
    ({}, "review_records_missing_for_changes"),
    ({HEAD: {"pull_request": 1}, PARENT: {"pull_request": 2}}, "review_records_incomplete"),
    ({HEAD: {"pull_request": 1, "approvals": [None] * 1001}}, "review_approvals_bound_reached"),
], ids=["missing", "incomplete", "bounded"])
def test_publication_review_coverage_includes_analysis_and_normalization_gaps(tmp_path: Path, reviews, expected_gap):
    unit, outputs = _pipeline(tmp_path, reviews)
    stored = document(unit, outputs["publish.publish_handoff"])
    coverage = next(item for item in stored["coverage"] if item["area"] == "review-records")
    assert coverage["status"] == "partial"
    assert expected_gap in coverage["gap"]
    assert expected_gap in stored["gaps"]
    units = document(unit, outputs["analyze.unit_signals"])
    for value in units["files"].values():
        assert value["metrics"]["unapproved_mainline_change_count"] is None


def test_real_function_priority_publication_boosts_only_the_matching_callable(tmp_path: Path):
    unit, outputs = _pipeline(tmp_path, {HEAD: {"direct_push": True}, PARENT: {"direct_push": True}},
                              with_function=True)
    published = outputs["publish.publish_handoff"]
    stored = document(unit, published)
    [entry] = stored["priority"]["top"]["functions"]
    assert entry["name"] == "check"
    assert (entry["start_line"], entry["end_line"], entry["identity"]) == (1, 2, "node-hot")
    assert entry["file_sha256"] == eligible_entry()["sha256"]
    assert (entry["source_id"], entry["snapshot_commit"]) == ("repo-one", HEAD)
    assert entry["location"]["end_byte"] == len(SOURCE)
    assert [item["path"] for item in stored["priority"]["top"]["files"]] == ["other.py"]
    assert entry["score"] == 1.0

    handoff = unit.job.attempt_root / "handoff.json"
    write_fixture_handoff(unit.job.run_root, handoff, {
        "job_id": job.PRODUCER, "attempt_id": unit.job.attempt_id, "target_snapshot": "snapshot",
        "outputs": {"publish.publish_handoff": published},
    })
    sha = file_sha256(handoff)
    atomic_json(unit.job.run_root / f"data/jobs/{job.PRODUCER}/latest.json", {
        "handoff_path": handoff.relative_to(unit.job.run_root).as_posix(), "handoff_sha256": sha,
    })
    functions = [
        {"item_id": name, "path": path, "name": "check", "start_line": start, "end_line": end,
         "start_byte": offset, "end_byte": len(SOURCE), "features": {"public_api": 1}}
        for name, path, start, end, offset in [
            ("hot", "src/a.py", 1, 2, 0), ("same-name", "src/a.py", 4, 5, 0),
            ("enclosing", "src/a.py", 1, 5, 0), ("other-source", "other/src/a.py", 1, 2, 0),
            ("same-lines", "src/a.py", 1, 2, 4),
        ]
    ]
    settings = {"sources": {name: name == "change_context" for name in (
        "change_context", "test_coverage", "profile_data", "ci_configuration", "artifact_security",
        "dependency_intelligence", "sast_silence_hunt",
    )}}
    ranked_files = scoring.rank(
        [{"item_id": "file-a", "path": "src/a.py", "features": {"public_api": 1}}],
        {"public_api": 1}, ("public_api",), population="all",
    )
    ranked_functions = scoring.rank(functions, {"public_api": 1}, ("public_api",), population="all")
    with upstream_scope(unit.job.run_root, "job_review_prioritization", {job.PRODUCER: sha}, contract=PRIORITY_CONTRACT):
        files, functions, _ = composite.apply_composite_prioritization(
            unit.job.run_root, target_snapshot="snapshot", settings=settings, semantic_doc={},
            ranked_files=ranked_files, ranked_functions=ranked_functions,
        )
    boosts = {item["item_id"]: item["composite_modifiers"]["change_context_boost"] for item in functions}
    assert boosts == {"hot": .15, "same-name": 0, "enclosing": 0, "other-source": 0, "same-lines": 0}
    assert files[0]["composite_modifiers"]["change_context_boost"] == 0
    assert functions[0]["item_id"] == "hot"
    assert functions[0]["score"] == pytest.approx(.65 / 1.15)
