"""Unit tests for every handler and multi-source lane in job_change_context_analysis/job.py."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from zoneinfo import ZoneInfoNotFoundError

import pytest

from appsec_review.jobs.job_change_context_analysis import job
from appsec_review.jobs.job_change_context_analysis.sources import (
    DEPLOYMENT_EXPORT_SCHEMA,
    ORGANIZATION_EXPORT_SCHEMA,
    REVIEW_EXPORT_SCHEMA,
    identity_hash,
)
from appsec_review.jobs.job_source_history_analysis.sources import GitSource
from appsec_review.runtime.consume import upstream_scope
from appsec_review.storage import atomic_json, file_sha256
from .support import (
    DAY,
    HEAD,
    HOUR,
    PARENT,
    PRIOR,
    SOURCE,
    T0,
    artifact,
    change_entry,
    context,
    document,
    eligible_entry,
    handler,
    write_resolved_config,
)


def _git_log_record(commit_sha: str, when: int, email: str, path: str, added: int = 1, deleted: int = 1) -> bytes:
    return (
        f"\x01{commit_sha}\x1f{PARENT}\x1f{when}\x1f{when}\x1f{email}\0"
        f"{added}\t{deleted}\t{path}\0"
    ).encode("utf-8")


def _catalog_stub(components: list[dict[str, str]] | None = None, *, snapshot: str = "snapshot") -> dict[str, Any]:
    return {
        "source_fingerprint": snapshot,
        "catalog_handoff_sha256": "cat-sha",
        "components": components or [{"component_id": "comp-a", "root": "svc"}],
    }


def _fake_git_run(exit_code: int = 0, stdout: bytes = b"", *, timed_out: bool = False, truncated: bool = False):
    return SimpleNamespace(exit_code=exit_code, stdout=stdout, timed_out=timed_out, truncated=truncated)


def test_default_executor_factory_wires_container_executor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[Any, Any]] = []
    monkeypatch.setattr(job, "load_catalog", lambda repo: ("catalog", repo))
    monkeypatch.setattr(job, "ContainerExecutor", lambda cat, run_root: calls.append((cat, run_root)) or "exec-obj")

    unit = context(tmp_path, "attribute.line_attribution", files={"svc/a.py": SOURCE})
    write_resolved_config(unit.job.run_root)
    lifetime_ref = artifact(unit, "lifetime.json", {"identities": {}, "gaps": []})
    signals_ref = artifact(unit, "hist-signals.json", {"files": {"svc/a.py": {"churn_lines": 5}}})
    unit.outputs["load.accepted_history"] = {
        "available": True,
        "eligible": {"svc/a.py": eligible_entry(SOURCE, "svc/a.py")},
        "history_signals": signals_ref,
        "lifetime": lifetime_ref,
        "git": GitSource("SUCCEEDED", "resolved", ".git", snapshot_commit=HEAD, head_commit=HEAD).as_dict(),
        "source": {"root": "."},
    }
    monkeypatch.setattr(job, "_accepted_handoff", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        job, "GitRunner",
        lambda executor, *_args, **_kw: SimpleNamespace(
            executor=executor,
            run=lambda *_r: _fake_git_run(1, b""),
        ),
    )
    out = handler(unit)(unit)
    assert calls == [(("catalog", unit.job.repository_root), unit.job.run_root)]
    assert "line_attribution_execution_failed" in out["gaps"]


def test_load_history_single_and_multi_source_branches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    unit = context(tmp_path, "load.accepted_history")
    write_resolved_config(unit.job.run_root, history_overrides={"bulk_change_file_threshold": 2})

    monkeypatch.setattr(job, "_load_catalog", lambda _root: _catalog_stub(snapshot="other"))
    with pytest.raises(ValueError, match="graph target fingerprint does not match"):
        handler(unit)(unit)

    monkeypatch.setattr(job, "_load_catalog", lambda _root: _catalog_stub())
    monkeypatch.setattr(job, "_accepted_handoff", lambda *_a, **_kw: None)
    missing_out = handler(unit)(unit)
    assert missing_out["available"] is False and missing_out["terminal_status"] == "SKIPPED_NA"

    raw_log = artifact(
        unit,
        "git.log",
        _git_log_record(HEAD, T0, "one@example.test", "svc/a.py")
        + _git_log_record(PARENT, T0 - DAY, "two@example.test", "unmapped.py")
        + _git_log_record(PRIOR, T0 - 2 * DAY, "three@example.test", "svc/a.py"),
    )
    changes_ref = artifact(unit, "changes.json", {"changes": [], "walked_commits": [HEAD]})

    def make_lane_outputs(*, decision: str = "SUCCEEDED", shallow: tuple[str, ...] = ("s1",), walked: int = 2,
                          has_norm_artifact: bool = True, pub_gaps: list[str] | None = None) -> dict[str, Any]:
        git_dict = GitSource(decision, "no_git" if decision != "SUCCEEDED" else "resolved", ".git",
                             snapshot_commit=HEAD, head_commit=HEAD, shallow=shallow).as_dict()
        norm: dict[str, Any] = {"walked_change_count": walked}
        if has_norm_artifact:
            norm["artifact"] = changes_ref
        return {
            "resolve_sources.resolve_history_source": {"git": git_dict, "source": {"source_id": ".", "root": "."}},
            "resolve_sources.bind_snapshot": {
                "eligible": {
                    "svc/a.py": eligible_entry(SOURCE, "svc/a.py"),
                    "unmapped.py": eligible_entry(SOURCE, "unmapped.py"),
                },
            },
            "acquire.git_history": {"raw_log": raw_log},
            "acquire.normalize_changes": norm,
            "acquire.github_enrichment": {"terminal_status": "SKIPPED_NA", "reason": "disabled", "gaps": []},
            "analyze.classify_changes": {"gaps": []},
            "analyze.rank": {},
            "publish.publish_handoff": {"gaps": pub_gaps or []},
        }

    # Unavailable single source with and without upstream source gaps
    for pub_gaps, expected_status in (([], "SKIPPED_NA"), (["upstream_gap"], "PARTIAL")):
        monkeypatch.setattr(job, "_accepted_handoff", lambda *_a, **_kw: ({"handoff": True}, "hist-sha"))
        monkeypatch.setattr(job, "load_accepted_history", lambda _r: {"history_identity": "hist-id"})
        monkeypatch.setattr(
            job, "_accepted_outputs",
            lambda _r, _h, g=pub_gaps: make_lane_outputs(decision="UNAVAILABLE", pub_gaps=g),
        )
        unavail = handler(unit)(unit)
        assert unavail["available"] is False and unavail["terminal_status"] == expected_status

    # SUCCEEDED git decision without normalized artifact -> no_bound_history
    monkeypatch.setattr(job, "_accepted_outputs", lambda _r, _h: make_lane_outputs(has_norm_artifact=False))
    no_bound = handler(unit)(unit)
    assert no_bound["available"] is False and no_bound["reason"] == "no_bound_history"

    # Available single source with bulk change, truncated history, shallow history, and walked==0 variant
    bulk_log = artifact(
        unit,
        "bulk.log",
        _git_log_record(HEAD, T0, "one@example.test", "svc/a.py")
        + (
            f"\x01{PARENT}\x1f\x1f{T0 - DAY}\x1f{T0 - DAY}\x1ftwo@example.test\0"
            f"1\t0\tsvc/a.py\0"
            f"1\t0\tunmapped.py\0"
            f"1\t0\textra.py\0"
        ).encode("utf-8")
        + _git_log_record(PRIOR, T0 - 2 * DAY, "one@example.test", "unmapped.py"),
    )
    lane = make_lane_outputs(walked=2)
    lane["acquire.git_history"]["raw_log"] = bulk_log
    monkeypatch.setattr(job, "_accepted_outputs", lambda _r, _h: lane)
    avail = handler(unit)(unit)
    assert avail["available"] is True
    assert {"lifetime_history_truncated", "lifetime_history_shallow"} <= set(avail["gaps"])
    lifetime_doc = document(unit, avail, "lifetime")
    assert lifetime_doc["files"] == {"svc/a.py": {"author-0001": 1}}
    assert lifetime_doc["components"] == {"comp-a": {"author-0001": 1}}

    lane_zero = make_lane_outputs(walked=0, shallow=())
    monkeypatch.setattr(job, "_accepted_outputs", lambda _r, _h: lane_zero)
    avail_zero = handler(unit)(unit)
    assert document(unit, avail_zero, "lifetime")["first_commit_time"] is None

    # Multi-source by_source with one good lane (len(commits) == walked) and one failing lane
    good_lane = make_lane_outputs(walked=3, shallow=())
    good_lane["resolve_sources.resolve_history_source"]["source"] = {"source_id": "s1", "root": "s1"}
    bad_lane = deepcopy(good_lane)
    bad_lane["resolve_sources.resolve_history_source"]["source"] = {"source_id": "s2", "root": "s2"}
    bad_lane["acquire.git_history"]["raw_log"] = {"path": "missing.log", "sha256": "0" * 64}
    multi_outputs = {
        name: {"by_source": {"s1": good_lane[name], "s2": bad_lane[name]}}
        for name in good_lane
    }
    monkeypatch.setattr(job, "_accepted_outputs", lambda _r, _h: multi_outputs)
    multi = handler(unit)(unit)
    assert set(multi["by_source"]) == {"s1", "s2"}
    assert multi["by_source"]["s1"]["available"] is True
    assert multi["by_source"]["s2"]["available"] is False
    assert "s2:history_source_unavailable:ValueError" in multi["gaps"]


def test_external_sources_covers_all_review_deployment_org_schedule_and_test_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    data_dir = repo / "exports"
    data_dir.mkdir(parents=True)

    rev_good = data_dir / "reviews.json"
    rev_good.write_text(json.dumps({
        "schema": REVIEW_EXPORT_SCHEMA,
        "records": {HEAD: {
            "pull_request": 1, "direct_push": False, "approvals": [], "head_sha": HEAD,
            "created_at": "2023-11-14T20:00:00Z", "merged_at": "2023-11-14T23:00:00Z",
        }},
    }), encoding="utf-8")
    rev_bad = data_dir / "reviews-bad.json"
    rev_bad.write_text('{"schema": "wrong"}', encoding="utf-8")
    dep_good = data_dir / "deployments.json"
    dep_good.write_text(json.dumps({
        "schema": DEPLOYMENT_EXPORT_SCHEMA,
        "coverage": {"start": "2023-11-01T00:00:00Z", "end": "2023-11-30T00:00:00Z"},
        "events": [],
    }), encoding="utf-8")
    org_good = data_dir / "org.json"
    org_good.write_text(json.dumps({
        "schema": ORGANIZATION_EXPORT_SCHEMA,
        "as_of": "2023-11-30T00:00:00Z",
        "members": [{"identity_sha256": identity_hash("one@example.test"), "status": "active"}],
    }), encoding="utf-8")

    # 1. review.source == "none", invalid zone -> ZoneInfoNotFoundError, test_association disabled
    u_none = context(
        tmp_path / "c1", "load.external_sources", repository_root=repo,
        overrides={
            "review.source": "none",
            "schedule.time_zone": "Invalid/NoSuchZone",
            "test_association.enabled": False,
        },
        outputs={"load.accepted_history": {"available": False}},
    )
    monkeypatch.setattr(job, "ZoneInfo", lambda _z: (_ for _ in ()).throw(ZoneInfoNotFoundError("missing")))
    out_none = handler(u_none)(u_none)
    monkeypatch.undo()
    assert {"review_records_disabled", "time_zone_database_unavailable", "test_association_disabled"} <= set(out_none["gaps"])

    # 2. review.source == "export" & deployments enabled with source_count > 1 (ambiguous)
    u_ambig = context(
        tmp_path / "c2", "load.external_sources", repository_root=repo,
        overrides={
            "review.source": "export",
            "review.export_path": "exports/reviews.json",
            "review.export_sha256": file_sha256(rev_good),
            "deployments.enabled": True,
            "deployments.export_path": "exports/deployments.json",
            "deployments.export_sha256": file_sha256(dep_good),
            "schedule.time_zone": "UTC",
        },
        outputs={"load.accepted_history": {"available": True, "source": {"source_count": 2}}},
    )
    out_ambig = handler(u_ambig)(u_ambig)
    assert {"review_export_source_ambiguous", "deployment_export_source_ambiguous"} <= set(out_ambig["gaps"])

    # 3. review.source == "export" with bad schema (document is not None, review_gaps non-empty) and missing file (document is None)
    u_bad_rev = context(
        tmp_path / "c3", "load.external_sources", repository_root=repo,
        overrides={
            "review.source": "export",
            "review.export_path": "exports/reviews-bad.json",
            "review.export_sha256": file_sha256(rev_bad),
        },
        outputs={"load.accepted_history": {"available": True}},
    )
    out_bad_rev = handler(u_bad_rev)(u_bad_rev)
    assert "review_export_invalid" in out_bad_rev["gaps"] and "review" in out_bad_rev["raw_exports"]

    u_miss_rev = context(
        tmp_path / "c3b", "load.external_sources", repository_root=repo,
        overrides={
            "review.source": "export",
            "review.export_path": "exports/missing.json",
            "review.export_sha256": "a" * 64,
        },
        outputs={"load.accepted_history": {"available": True}},
    )
    assert "review_export_missing" in handler(u_miss_rev)(u_miss_rev)["gaps"]

    # 4. review.source == "export", valid review + deployment + organization exports
    u_exports = context(
        tmp_path / "c4", "load.external_sources", repository_root=repo,
        overrides={
            "review.source": "export",
            "review.export_path": "exports/reviews.json",
            "review.export_sha256": file_sha256(rev_good),
            "deployments.enabled": True,
            "deployments.export_path": "exports/deployments.json",
            "deployments.export_sha256": file_sha256(dep_good),
            "organization.enabled": True,
            "organization.export_path": "exports/org.json",
            "organization.export_sha256": file_sha256(org_good),
            "schedule.time_zone": "UTC",
        },
        outputs={"load.accepted_history": {"available": True}},
    )
    out_exports = handler(u_exports)(u_exports)
    assert out_exports["terminal_status"] == "SUCCEEDED" and out_exports["gaps"] == []
    assert document(u_exports, out_exports)["reviews"][HEAD]["complete"] is True
    assert set(out_exports["raw_exports"]) == {"review", "deployment", "organization"}

    # 5. github_enrichment branches: acquired_export, not available, github is None, and valid github facts
    u_acq = context(tmp_path / "c5", "load.external_sources", repository_root=repo)
    acq_ref = artifact(u_acq, "acquired.json", {"schema": REVIEW_EXPORT_SCHEMA, "records": {HEAD: {"direct_push": True}}})
    u_acq.outputs["load.accepted_history"] = {"available": True, "review_records": acq_ref}
    out_acq = handler(u_acq)(u_acq)
    assert out_acq["sources"]["review"]["source"] == "acquired_export"
    assert out_acq["sources"]["review"]["record_count"] == 1

    u_acq_bad = context(tmp_path / "c5b", "load.external_sources", repository_root=repo)
    u_acq_bad.outputs["load.accepted_history"] = {"available": True, "review_records": artifact(u_acq_bad, "bad.json", {"schema": "x"})}
    assert out_acq["sources"]["review"]["status"] == "complete"
    assert handler(u_acq_bad)(u_acq_bad)["sources"]["review"]["status"] == "unavailable"

    u_no_git = context(tmp_path / "c6", "load.external_sources", repository_root=repo,
                       outputs={"load.accepted_history": {"available": False}})
    assert "review_records_unavailable:no_git_history" in handler(u_no_git)(u_no_git)["gaps"]

    u_no_gh = context(tmp_path / "c7", "load.external_sources", repository_root=repo,
                      outputs={"load.accepted_history": {"available": True, "github": None, "github_reason": None}})
    assert "review_records_unavailable:github_enrichment_missing" in handler(u_no_gh)(u_no_gh)["gaps"]

    u_gh = context(tmp_path / "c8", "load.external_sources", repository_root=repo)
    gh_ref = artifact(u_gh, "gh.json", {"facts": {HEAD: {"direct_push": True}}})
    u_gh.outputs["load.accepted_history"] = {"available": True, "github": gh_ref, "github_gaps": ["rate_limited"]}
    out_gh = handler(u_gh)(u_gh)
    assert out_gh["sources"]["review"]["status"] == "partial"
    assert out_gh["sources"]["review"]["gaps"] == ["review_records_partial:rate_limited"]


def test_attribute_lines_and_fix_on_fix_branches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # attribute_lines: unavailable history -> SKIPPED_NA
    u_skip = context(tmp_path / "a0", "attribute.line_attribution",
                     outputs={"load.accepted_history": {"available": False}})
    assert handler(u_skip)(u_skip)["terminal_status"] == "SKIPPED_NA"

    # attribute_lines: limit == 0 with candidate -> bound reached, selected == []
    u_zero = context(
        tmp_path / "a1", "attribute.line_attribution",
        overrides={"ownership.line_attribution_max_files": 0},
        files={"a.py": SOURCE},
    )
    u_zero.outputs["load.accepted_history"] = {
        "available": True,
        "eligible": {"a.py": eligible_entry(SOURCE, "a.py")},
        "history_signals": None,
        "lifetime": artifact(u_zero, "lifetime.json", {"identities": {}, "gaps": []}),
    }
    monkeypatch.setattr(job, "_accepted_handoff", lambda *_a, **_kw: None)
    out_zero = handler(u_zero)(u_zero)
    assert out_zero["attributed_file_count"] == 0
    assert "function_spans_unavailable:tree_sitter_not_accepted" in out_zero["gaps"]

    # attribute_lines: tree-sitter snapshot mismatch -> ValueError
    u_mismatch = context(tmp_path / "a2", "attribute.line_attribution", files={"a.py": SOURCE})
    u_mismatch.outputs["load.accepted_history"] = {
        "available": True,
        "eligible": {"a.py": eligible_entry(SOURCE, "a.py")},
        "history_signals": artifact(u_mismatch, "hs.json", {"files": {"a.py": {"churn_lines": 10}}}),
        "lifetime": artifact(u_mismatch, "lt.json", {"identities": {}, "gaps": []}),
    }
    bad_ts = artifact(u_mismatch, "ts.json", {"schema": "appsec-review/tree-sitter-ast/1", "target_snapshot": "wrong"})
    ts_handoff = {"outputs": {"acceptance.publish_handoff": {"artifact": bad_ts}}}
    monkeypatch.setattr(job, "_accepted_handoff", lambda *_a, **_kw: (ts_handoff, "ts-sha"))
    monkeypatch.setattr("appsec_review.runtime.inputs.observe_output", lambda *_a, **_kw: None)
    with pytest.raises(ValueError, match="Tree-sitter snapshot does not match"):
        handler(u_mismatch)(u_mismatch)

    # attribute_lines: full path with bound reached, reliable + unreliable files, mapped + unmapped authors, outside-span line
    src_a = b"# header\ndef check(user):\n    return bool(user)\n"
    src_b = b"x = 1\n"
    u_attr = context(
        tmp_path / "a3", "attribute.line_attribution",
        overrides={"ownership.line_attribution_max_files": 2},
        files={"a.py": src_a, "b.py": src_b, "c.py": src_b},
    )
    write_resolved_config(u_attr.job.run_root)
    sha_a = hashlib.sha256(src_a).hexdigest()
    shard_lines = [
        json.dumps({
            "identity": "mod:a", "path": "a.py", "file_sha256": sha_a, "grammar_native_type": "module",
            "field": None, "has_error": False, "error": False, "missing": False, "language": "Python",
            "location": {"start_byte": 0, "end_byte": len(src_a), "start_line": 1, "end_line": 3,
                         "start_column": 1, "end_column": 1, "producer_location": {"ordinal_path": []}},
        }),
        json.dumps({
            "identity": "fn:check", "path": "a.py", "file_sha256": sha_a, "grammar_native_type": "function_definition",
            "field": None, "has_error": False, "error": False, "missing": False, "language": "Python",
            "location": {"start_byte": 9, "end_byte": len(src_a), "start_line": 2, "end_line": 3,
                         "start_column": 1, "end_column": 1, "producer_location": {"ordinal_path": [0]}},
        }),
        json.dumps({
            "identity": "id:check", "path": "a.py", "file_sha256": sha_a, "grammar_native_type": "identifier",
            "field": "name", "has_error": False, "error": False, "missing": False, "language": "Python",
            "location": {"start_byte": 13, "end_byte": 18, "start_line": 2, "end_line": 2,
                         "start_column": 5, "end_column": 10, "producer_location": {"ordinal_path": [0, 0]}},
        }),
    ]
    shard_ref = artifact(u_attr, "nodes.jsonl", ("\n".join(shard_lines) + "\n").encode("utf-8"))
    ts_doc_ref = artifact(u_attr, "accepted-ts.json", {
        "schema": "appsec-review/tree-sitter-ast/1",
        "target_snapshot": "snapshot",
        "dispositions": ["skip-str", {"scope_id": "none"}, {"scope_id": "s1", "artifact": shard_ref}],
    })
    monkeypatch.setattr(job, "_accepted_handoff", lambda *_a, **_kw: (
        {"outputs": {"acceptance.publish_handoff": {"artifact": ts_doc_ref}}}, "ts-sha",
    ))
    u_attr.outputs["load.accepted_history"] = {
        "available": True,
        "eligible": {
            "a.py": eligible_entry(src_a, "a.py"),
            "b.py": eligible_entry(src_b, "b.py"),
            "c.py": eligible_entry(src_b, "c.py"),
        },
        "history_signals": artifact(u_attr, "hs.json", {
            "files": {"a.py": {"churn_lines": 30}, "b.py": {"churn_lines": 20}, "c.py": {"churn_lines": 10}},
        }),
        "lifetime": artifact(u_attr, "lt.json", {
            "identities": {"author-0001": identity_hash("known@example.test")}, "gaps": [],
        }),
        "git": GitSource("SUCCEEDED", "resolved", ".git", snapshot_commit=HEAD, head_commit=HEAD).as_dict(),
        "source": {"root": "."},
    }
    porcelain_a = (
        f"{HEAD} 1 1 3\nauthor-mail <known@example.test>\n\t# header\n"
        f"{HEAD} 2 2\n\tdef check(user):\n"
        f"{PARENT} 3 3 1\nauthor-mail <extra@example.test>\n\t    return bool(user)\n"
    ).encode("utf-8")
    porcelain_b = f"{HEAD} 1 1 1\nauthor-mail <extra@example.test>\n\tx = 1\n".encode("utf-8")
    blame_outputs = {"a.py": _fake_git_run(0, porcelain_a), "b.py": _fake_git_run(0, porcelain_b)}
    monkeypatch.setattr(
        job, "GitRunner",
        lambda *_a, **_kw: SimpleNamespace(run=lambda _label, args: blame_outputs[args[-1]]),
    )
    out_attr = handler(u_attr, executor_factory=lambda _u: SimpleNamespace())(u_attr)
    assert {"line_attribution_bound_reached", "function_mapping_unreliable"} <= set(out_attr["gaps"])
    assert out_attr["attributed_file_count"] == 2 and out_attr["function_count"] == 1
    attr_doc = document(u_attr, out_attr)
    assert attr_doc["files"]["a.py"]["functions"][0]["name"] == "check"
    assert attr_doc["files"]["b.py"]["function_mapping"] == "unreliable"
    assert len(attr_doc["unmapped_identities"]) == 1

    # attribute_lines: tree accepted with empty selected ([]), reliable-only selected, blame failure, and missing git guard
    u_ts_empty = context(
        tmp_path / "a4", "attribute.line_attribution",
        overrides={"ownership.line_attribution_max_files": 0},
        files={"a.py": src_a},
    )
    u_ts_empty.outputs["load.accepted_history"] = {
        "available": True,
        "eligible": {},
        "history_signals": None,
        "lifetime": artifact(u_ts_empty, "lt.json", {"identities": {}, "gaps": []}),
    }
    ts_empty_ref = artifact(u_ts_empty, "accepted-ts.json", {"schema": "appsec-review/tree-sitter-ast/1", "target_snapshot": "snapshot", "dispositions": []})
    monkeypatch.setattr(job, "_accepted_handoff", lambda *_a, **_kw: (
        {"outputs": {"acceptance.publish_handoff": {"artifact": ts_empty_ref}}}, "ts-sha",
    ))
    assert handler(u_ts_empty)(u_ts_empty)["gaps"] == []

    u_clean = context(tmp_path / "a5", "attribute.line_attribution", files={"a.py": src_a})
    write_resolved_config(u_clean.job.run_root)
    clean_shard_ref = artifact(u_clean, "nodes.jsonl", ("\n".join(shard_lines) + "\n").encode("utf-8"))
    clean_ts_ref = artifact(u_clean, "accepted-ts.json", {
        "schema": "appsec-review/tree-sitter-ast/1", "target_snapshot": "snapshot",
        "dispositions": [{"scope_id": "s1", "artifact": clean_shard_ref}],
    })
    monkeypatch.setattr(job, "_accepted_handoff", lambda *_a, **_kw: (
        {"outputs": {"acceptance.publish_handoff": {"artifact": clean_ts_ref}}}, "ts-sha",
    ))
    u_clean.outputs["load.accepted_history"] = {
        "available": True,
        "eligible": {"a.py": eligible_entry(src_a, "a.py")},
        "history_signals": artifact(u_clean, "hs.json", {"files": {"a.py": {"churn_lines": 10}}}),
        "lifetime": artifact(u_clean, "lt.json", {"identities": {}, "gaps": []}),
        "git": GitSource("SUCCEEDED", "resolved", ".git", snapshot_commit=HEAD, head_commit=HEAD).as_dict(),
        "source": {"root": "."},
    }
    monkeypatch.setattr(job, "GitRunner", lambda *_a, **_kw: SimpleNamespace(run=lambda _l, _args: _fake_git_run(1, b"")))
    out_clean_fail = handler(u_clean, executor_factory=lambda _u: SimpleNamespace())(u_clean)
    assert out_clean_fail["gaps"] == ["line_attribution_execution_failed"]

    u_no_git_src = context(tmp_path / "a6", "attribute.line_attribution", files={"a.py": src_a})
    monkeypatch.setattr(job, "_accepted_handoff", lambda *_a, **_kw: None)
    u_no_git_src.outputs["load.accepted_history"] = {
        "available": True,
        "eligible": {"a.py": eligible_entry(src_a, "a.py")},
        "history_signals": artifact(u_no_git_src, "hs.json", {"files": {"a.py": {"churn_lines": 10}}}),
        "lifetime": artifact(u_no_git_src, "lt.json", {"identities": {}, "gaps": []}),
        "git": None,
    }
    with pytest.raises(AssertionError):
        handler(u_no_git_src, executor_factory=lambda _u: SimpleNamespace())(u_no_git_src)

    # fix_on_fix: unavailable, disabled policy, and full candidate/diff/blame branches
    u_fof_skip = context(tmp_path / "f0", "attribute.fix_on_fix",
                         outputs={"load.accepted_history": {"available": True, "classification": None}})
    assert handler(u_fof_skip)(u_fof_skip)["terminal_status"] == "SKIPPED_NA"

    u_fof_pol = context(
        tmp_path / "f1", "attribute.fix_on_fix",
        overrides={"repeated_repairs.fix_on_fix_max_checks": 0},
        outputs={"load.accepted_history": {"available": True, "classification": {"path": "x"}}},
    )
    out_pol = handler(u_fof_pol)(u_fof_pol)
    assert out_pol["terminal_status"] == "SKIPPED_POLICY" and out_pol["gaps"] == ["fix_on_fix_disabled"]

    u_fof = context(
        tmp_path / "f2", "attribute.fix_on_fix",
        overrides={"repeated_repairs.fix_on_fix_max_checks": 4},
        files={"a.py": src_a},
    )
    write_resolved_config(u_fof.job.run_root)
    c_unclass = "d" * 40
    c_nonfix = "e" * 40
    c_root_fix = "f" * 40
    changes_list = [
        # Candidate 0: renamed file -> prior fix + unclassified + classified non-fix
        {
            "change_id": HEAD, "position": 0, "parents": [PARENT], "effective_time": T0 + DAY,
            "commit_time": T0 + DAY, "author_time": T0 + DAY, "author": "author-0001", "bulk": False, "file_count": 2,
            "files": [
                {"path": "a.py", "current_path": "a.py", "renamed_from": "old_a.py", "added": 1, "deleted": 2, "binary": False},
                {"path": "bin.dat", "current_path": "bin.dat", "renamed_from": None, "added": 0, "deleted": 1, "binary": True},
            ],
        },
        # Candidate 1: diff fails
        change_entry("1" * 40, 1, T0 + 2 * DAY, [("a.py", 1, 1)]),
        # Candidate 2: diff has no old hunks
        change_entry("2" * 40, 2, T0 + 3 * DAY, [("a.py", 1, 1)]),
        # Candidate 3: blame fails
        change_entry("3" * 40, 3, T0 + 4 * DAY, [("a.py", 1, 1)]),
        # Candidate 4: exceeds limit -> fix_on_fix_bound_reached
        change_entry("4" * 40, 4, T0 + 5 * DAY, [("a.py", 1, 1)]),
        # Prior fix commit
        change_entry(PARENT, 5, T0, [("a.py", 1, 0)]),
        # Non-fix commit (skipped)
        change_entry(c_nonfix, 6, T0 - DAY, [("a.py", 1, 1)]),
        # Root fix without parents (skipped)
        change_entry(c_root_fix, 7, T0 - 2 * DAY, [("a.py", 1, 1)], parents=[]),
    ]
    classes_map = {
        HEAD: {"fix": "heuristic"},
        "1" * 40: {"fix": "heuristic"},
        "2" * 40: {"fix": "heuristic"},
        "3" * 40: {"fix": "heuristic"},
        "4" * 40: {"fix": "heuristic"},
        PARENT: {"fix": "heuristic"},
        c_nonfix: {"fix": None},
        c_root_fix: {"fix": "heuristic"},
    }
    u_fof.outputs["load.accepted_history"] = {
        "available": True,
        "eligible": {"a.py": eligible_entry(src_a, "a.py"), "bin.dat": eligible_entry(b"\x00", "bin.dat")},
        "changes": artifact(u_fof, "changes.json", {"changes": changes_list}),
        "classification": artifact(u_fof, "classes.json", {"classes": classes_map}),
        "git": GitSource("SUCCEEDED", "resolved", ".git", snapshot_commit=HEAD, head_commit=HEAD).as_dict(),
        "source": {"root": "."},
    }

    def fake_fof_git(label: str, _args: tuple[str, ...]):
        if label == "fof-diff-00000":
            return _fake_git_run(0, b"@@ -2,3 +2,1 @@\n")
        if label == "fof-blame-00000":
            return _fake_git_run(
                0,
                f"{PARENT} 2 2 1\n\tline1\n{c_unclass} 3 3 1\n\tline2\n{c_nonfix} 4 4 1\n\tline3\n".encode("utf-8"),
            )
        if label == "fof-diff-00001":
            return _fake_git_run(1, b"")
        if label == "fof-diff-00002":
            return _fake_git_run(0, b"@@ -0,0 +1,2 @@\n")
        if label == "fof-diff-00003":
            return _fake_git_run(0, b"@@ -1,1 +1,1 @@\n")
        if label == "fof-blame-00003":
            return _fake_git_run(0, b"", timed_out=True)
        raise AssertionError(label)

    monkeypatch.setattr(job, "GitRunner", lambda *_a, **_kw: SimpleNamespace(run=fake_fof_git))
    out_fof = handler(u_fof, executor_factory=lambda _u: SimpleNamespace())(u_fof)
    assert {"fix_on_fix_bound_reached", "fix_on_fix_execution_failed"} <= set(out_fof["gaps"])
    fof_doc = document(u_fof, out_fof)
    assert fof_doc["events"] == [{
        "fix_change": HEAD, "prior_fix_change": PARENT, "path": "a.py",
        "line_count": 1, "basis": "exact_line_blame_at_parent",
    }]
    assert fof_doc["prior_lines_outside_window"] == 1

    # Also cover fix_on_fix with 0 eligible candidates (git is None, gaps == [], status == "available")
    u_fof_empty = context(tmp_path / "f3", "attribute.fix_on_fix")
    write_resolved_config(u_fof_empty.job.run_root)
    u_fof_empty.outputs["load.accepted_history"] = {
        "available": True,
        "eligible": {"a.py": eligible_entry(src_a, "a.py")},
        "changes": artifact(u_fof_empty, "changes.json", {"changes": [change_entry(c_nonfix, 0, T0, [("a.py", 1, 0)])]}),
        "classification": artifact(u_fof_empty, "classes.json", {"classes": {c_nonfix: {"fix": None}}}),
    }
    out_fof_empty = handler(u_fof_empty)(u_fof_empty)
    assert out_fof_empty["status"] == "available" and out_fof_empty["gaps"] == []


def test_analyze_index_publish_and_multi_source_pipeline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Unavailable skip paths for change_signals, unit_signals, rank
    u_cs_skip = context(tmp_path / "s0", "analyze.change_signals",
                        outputs={"load.accepted_history": {"available": False}})
    assert handler(u_cs_skip)(u_cs_skip)["terminal_status"] == "SKIPPED_NA"

    u_us_skip = context(tmp_path / "s1", "analyze.unit_signals",
                        outputs={"load.accepted_history": {"available": False}, "analyze.change_signals": {}})
    assert handler(u_us_skip)(u_us_skip)["terminal_status"] == "SKIPPED_NA"

    u_rk_skip = context(tmp_path / "s2", "analyze.rank", outputs={"analyze.unit_signals": {}})
    assert handler(u_rk_skip)(u_rk_skip)["terminal_status"] == "SKIPPED_NA"

    # Full pipeline through change_signals -> unit_signals -> rank -> index -> publish
    files = {"svc/a.py": SOURCE, "unmapped.py": SOURCE}
    base_overrides = {"schedule.time_zone": "UTC", "ranking_top_files": 2, "ranking_top_functions": 2, "ranking_top_components": 2}
    u_cs = context(tmp_path / "full", "analyze.change_signals", overrides=base_overrides, files=files)
    changes_doc = {
        "changes": [
            change_entry(HEAD, 0, T0, [("svc/a.py", 60, 2), ("unmapped.py", 5, 0), ("deleted.py", 2, 0)]),
            change_entry(PARENT, 1, T0 - HOUR, [("svc/a.py", 10, 1)]),
            change_entry(PRIOR, 2, T0 - 2 * HOUR, [("svc/a.py", 4, 0)]),
        ],
        "walked_commits": [HEAD, PARENT, PRIOR],
    }
    rev_record = {
        "pull_request": 9, "direct_push": False, "approved_by_other": False,
        "created_at": T0 - 100, "merged_at": T0, "head_sha": HEAD, "head_committed_at": T0 - 50,
        "approvals": [], "self_merged": True, "complete": True,
    }
    ext_doc = {
        "schema": "appsec-review/change-context-sources/1",
        "sources": {
            "review": {"source": "export", "status": "complete", "gaps": [], "record_count": 1},
            "deployment": {"status": "complete", "gaps": [], "event_count": 1, "environments": ["production"]},
            "organization": {"status": "complete", "gaps": [], "member_count": 1},
            "schedule": {"status": "complete", "gaps": [], "time_zone": "UTC"},
            "test_association": {"status": "complete", "gaps": []},
        },
        "reviews": {HEAD: rev_record},  # PARENT & PRIOR missing -> review_records_missing_for_changes
        "deployments": {
            "coverage": {"start": T0 - 10 * DAY, "end": T0 + 10 * DAY},
            "events": [{"deployment_id": "dep-1", "environment": "production", "deployed_at": T0 + 60, "commit": HEAD}],
        },
        "organization": {"as_of": T0, "members": {identity_hash("one@example.test"): {"status": "departed", "departed_at": T0}}},
    }
    loaded_hist = {
        "available": True,
        "history_handoff_sha256": "hist-sha",
        "history_identity": "hist-id",
        "snapshot_commit": HEAD,
        "source": {"source_id": ".", "root": "."},
        "components": [{"component_id": "comp-svc", "root": "svc"}],
        "eligible": {
            "svc/a.py": eligible_entry(SOURCE, "svc/a.py", exact=True),
            "unmapped.py": eligible_entry(SOURCE, "unmapped.py", exact=False),
        },
        "changes": artifact(u_cs, "changes.json", changes_doc),
        "classification": None,
        "classification_gaps": ["cls_gap"],
        "lifetime": artifact(u_cs, "lifetime.json", {
            "files": {"svc/a.py": {"author-0001": 2}},
            "components": {"comp-svc": {"author-0001": 2}},
            "identities": {"author-0001": identity_hash("one@example.test")},
            "gaps": ["lifetime_history_shallow"],
        }),
        "history_signals": artifact(u_cs, "hist-signals.json", {
            "files": {"svc/a.py": {"churn_lines": 70, "sii": {"rank": 1, "tier": 1, "score": 88.0}}},
            "components": {"comp-svc": {"priority": {"rank": 1, "score": 77.0}}},
            "symbols": {
                "svc/a.py::check": {
                    "path": "svc/a.py", "start_byte": 0, "end_byte": len(SOURCE),
                    "sii": {"rank": 1, "tier": 1, "score": 66.0},
                },
            },
        }),
        "gaps": ["lifetime_history_shallow"],
    }
    ext_out = {
        "artifact": artifact(u_cs, "ext.json", ext_doc),
        "sources": ext_doc["sources"],
        "raw_exports": {},
        "gaps": [],
    }
    u_cs.outputs.update({"load.accepted_history": loaded_hist, "load.external_sources": ext_out})
    cs_out = handler(u_cs)(u_cs)
    assert "review_records_missing_for_changes" in cs_out["gaps"]

    # Patch PARENT to share PR 9 & dep-1, while PRIOR has no review_record and no deployment_id!
    cs_doc = document(u_cs, cs_out)
    cs_doc["changes"][PARENT]["facts"]["review_record"] = rev_record
    cs_doc["changes"][PRIOR]["deployment"] = {"status": "outside_coverage"}
    cs_out["artifact"] = artifact(u_cs, "change-records-patched.json", cs_doc)

    # Also exercise change_signals when schedule is unavailable and reviews is None
    u_cs_norev = context(tmp_path / "cs_norev", "analyze.change_signals", files=files)
    ext_norev = {
        "schema": "appsec-review/change-context-sources/1",
        "sources": {k: {"status": "unavailable", "gaps": []} for k in ("review", "deployment", "organization", "schedule", "test_association")},
        "reviews": None,
        "deployments": None,
        "organization": None,
    }
    u_cs_norev.outputs.update({
        "load.accepted_history": {
            **loaded_hist,
            "changes": artifact(u_cs_norev, "ch.json", changes_doc),
            "classification": artifact(u_cs_norev, "cls.json", {"classes": {HEAD: {"fix": "heuristic"}}}),
        },
        "load.external_sources": {"artifact": artifact(u_cs_norev, "ext.json", ext_norev), "sources": ext_norev["sources"], "raw_exports": {}, "gaps": []},
    })
    assert handler(u_cs_norev)(u_cs_norev)["terminal_status"] == "SUCCEEDED"

    attr_doc = {
        "schema": "appsec-review/change-context-attribution/1",
        "files": {
            "svc/a.py": {
                "line_authors": {"author-0001": 2},
                "functions": [
                    {
                        "key": "svc/a.py#1-2:function_definition",
                        "name": "check",
                        "type": "function_definition",
                        "start_line": 1,
                        "end_line": 2,
                        "identity": "fn:check",
                        "location": {
                            "start_byte": 0, "end_byte": len(SOURCE),
                            "start_line": 1, "end_line": 2, "start_column": 1, "end_column": 1,
                        },
                        "commits": {HEAD: 1, PARENT: 1},
                        "line_authors": {"author-0001": 2},
                    },
                    {
                        "key": "svc/a.py#9-9:function_definition",
                        "name": "untracked",
                        "type": "function_definition",
                        "start_line": 9,
                        "end_line": 9,
                        "identity": "fn:untracked",
                        "location": {
                            "start_byte": 0, "end_byte": 1,
                            "start_line": 9, "end_line": 9, "start_column": 1, "end_column": 1,
                        },
                        "commits": {"9" * 40: 1},
                        "line_authors": {"author-0001": 1},
                    },
                ],
            },
        },
    }
    attr_out = {"artifact": artifact(u_cs, "attr.json", attr_doc), "function_count": 1, "gaps": ["line_attribution_execution_failed"]}
    fof_out = {
        "artifact": artifact(u_cs, "fof.json", {
            "events": [
                {"path": "svc/a.py", "fix_change": HEAD, "prior_fix_change": PARENT, "line_count": 1},
                {"path": "unmapped.py", "fix_change": HEAD, "prior_fix_change": PARENT, "line_count": 1},
            ],
        }),
        "status": "available",
        "gaps": [],
    }

    outputs_so_far = {
        "load.accepted_history": loaded_hist,
        "load.external_sources": ext_out,
        "attribute.line_attribution": attr_out,
        "attribute.fix_on_fix": fof_out,
        "analyze.change_signals": cs_out,
    }
    def step_unit(unit_id: str, outs: dict[str, Any]) -> Any:
        step, task = unit_id.split(".")
        return replace(
            u_cs,
            unit_id=unit_id,
            step_id=step,
            task_id=task,
            unit_root=u_cs.job.attempt_root / "steps" / step / "tasks" / task,
            outputs=dict(outs),
        )

    u_us = step_unit("analyze.unit_signals", outputs_so_far)
    us_out = handler(u_us)(u_us)
    assert us_out["file_count"] == 2 and us_out["function_count"] == 1 and us_out["component_count"] == 1
    units_doc = document(u_us, us_out)
    assert units_doc["files"]["svc/a.py"]["history_hotspot"]["rank"] == 1
    assert units_doc["files"]["unmapped.py"]["binding"] == "divergent"
    assert units_doc["files"]["unmapped.py"]["history_hotspot"] is None
    assert units_doc["functions"]["svc/a.py#1-2:function_definition"]["history_hotspot"]["rank"] == 1
    assert units_doc["components"]["comp-svc"]["history_hotspot"]["rank"] == 1

    # Also exercise unit_signals without attribution artifact / history_signals / fof / gaps in its own unit_root
    u_us_no_attr = replace(
        step_unit("analyze.unit_signals", {
            **outputs_so_far,
            "load.accepted_history": {
                **loaded_hist,
                "classification_gaps": [],
                "history_signals": None,
                "lifetime": artifact(u_cs, "lt-clean.json", {
                    "files": {"svc/a.py": {"author-0001": 2}},
                    "components": {"comp-svc": {"author-0001": 2}},
                    "identities": {"author-0001": identity_hash("one@example.test")},
                    "gaps": [],
                }),
            },
            "attribute.line_attribution": {"gaps": []},
            "attribute.fix_on_fix": {"gaps": []},
        }),
        unit_root=u_cs.job.run_root / "us_no_attr",
    )
    assert handler(u_us_no_attr)(u_us_no_attr)["function_count"] == 0

    outputs_so_far["analyze.unit_signals"] = us_out
    u_rk = step_unit("analyze.rank", outputs_so_far)
    rk_out = handler(u_rk)(u_rk)
    assert rk_out["ranked"] == {"files": 2, "functions": 1, "components": 1}

    # Upstream manifest for index() (empty indexes first, then feed real built shard back on reuse call!)
    upstream_manifest = u_cs.job.run_root / "data/indices/manifests/upstream.json"
    from appsec_review.retrieval import write_manifest
    write_manifest(
        upstream_manifest,
        run_id=u_cs.job.run_id,
        target_snapshot="snapshot",
        target_root=(u_cs.job.target_root or Path()).resolve(),
        indexes=[],
    )
    up_sha = file_sha256(upstream_manifest)
    monkeypatch.setattr(job, "resolve_context_manifest", lambda _ctx: (upstream_manifest, up_sha))
    monkeypatch.setattr("appsec_review.jobs.source_lanes.resolve_context_manifest", lambda _ctx: (upstream_manifest, up_sha))

    outputs_so_far["analyze.rank"] = rk_out
    u_idx = step_unit("publish.index_change_context", outputs_so_far)
    idx_out = handler(u_idx)(u_idx)
    assert idx_out["index_identity"]["shard_id"] == "change-context"
    # Second call reuses existing content-addressed sqlite file AND filters prior PRODUCER entry from upstream manifest
    produced_manifest = u_cs.job.run_root / "data/indices/manifests/upstream2.json"
    produced_manifest.write_bytes((u_cs.job.run_root / idx_out["manifest"]["path"]).read_bytes())
    prod_sha = file_sha256(produced_manifest)
    monkeypatch.setattr(job, "resolve_context_manifest", lambda _ctx: (produced_manifest, prod_sha))
    idx_reused = handler(u_idx)(u_idx)
    assert idx_reused["index_identity"] == idx_out["index_identity"]
    monkeypatch.setattr(job, "resolve_context_manifest", lambda _ctx: (upstream_manifest, up_sha))

    outputs_so_far["publish.index_change_context"] = idx_out
    u_pub = step_unit("publish.publish_handoff", outputs_so_far)
    pub_out = handler(u_pub)(u_pub)
    assert pub_out["terminal_status"] == "PARTIAL"
    assert pub_out["dispositions"] == [{"disposition": "GAP", "reason": "line_attribution_execution_failed"}]

    # Multi-source combine_indexes and publish_sources via per_source
    lane_s1 = deepcopy(loaded_hist)
    lane_s1["source"] = {"source_id": "sub", "root": "sub"}
    multi_outputs: dict[str, Any] = {}
    for key, val in outputs_so_far.items():
        if key != "publish.index_change_context":
            multi_outputs[key] = {"by_source": {"sub": deepcopy(val)}}
    multi_outputs["load.accepted_history"]["by_source"]["sub"] = lane_s1
    u_multi_idx = replace(u_idx, outputs=multi_outputs)
    multi_idx_out = handler(u_multi_idx)(u_multi_idx)
    assert "manifest" in multi_idx_out
    multi_outputs["publish.index_change_context"] = multi_idx_out
    u_multi_pub = replace(u_pub, outputs=multi_outputs)
    multi_pub_out = handler(u_multi_pub)(u_multi_pub)
    multi_doc = document(u_multi_pub, multi_pub_out)
    assert multi_doc["priority"]["scope"] == "per-source"
    assert [s["source_id"] for s in multi_doc["sources"]] == ["sub"]

    # Also exercise coverage_rows / publish when history is unavailable and unit_signals without attribution/history_signals
    unavail_outputs = {
        "load.accepted_history": {"available": False, "reason": "no_git", "history_handoff_sha256": None, "history_identity": None},
        "load.external_sources": {"gaps": ["deployment_disabled"]},
        "attribute.line_attribution": {"gaps": []},
        "attribute.fix_on_fix": {"gaps": [], "reason": "no_bound_history"},
        "analyze.change_signals": {"gaps": []},
        "analyze.rank": {"gaps": []},
        "publish.index_change_context": {"manifest": idx_out["manifest"], "gaps": []},
    }
    u_pub_unavail = replace(u_pub, outputs=unavail_outputs)
    pub_unavail = handler(u_pub_unavail)(u_pub_unavail)
    assert pub_unavail["terminal_status"] == "SKIPPED_NA" and "dispositions" not in pub_unavail

    # _accepted_handoff non-None return via upstream_scope
    ho_path = u_cs.job.run_root / "data/jobs/job_target_catalog/attempts/attempt_0001/handoff.json"
    from tests.handoff_fixture import write_fixture_handoff
    write_fixture_handoff(u_cs.job.run_root, ho_path, {
        "application_run_id": u_cs.job.run_root.name,
        "job_id": "job_target_catalog", "attempt_id": "attempt_0001", "source_fingerprint": "snapshot",
        "status": "ACCEPTED", "outputs": {},
    })
    ho_sha = file_sha256(ho_path)
    atomic_json(u_cs.job.run_root / "data/jobs/job_target_catalog/latest.json", {
        "handoff_path": ho_path.relative_to(u_cs.job.run_root).as_posix(), "handoff_sha256": ho_sha,
    })
    with upstream_scope(u_cs.job.run_root, job.PRODUCER, {"job_target_catalog": ho_sha}, contract=job.CONTRACT):
        got = job._accepted_handoff(u_cs.job.run_root, "job_target_catalog", required=True)
        assert got is not None and got[1] == ho_sha
        assert job._accepted_handoff(u_cs.job.run_root, "job_tree_sitter_ast", required=False) is None
