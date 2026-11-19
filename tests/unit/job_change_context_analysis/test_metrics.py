"""Deterministic metric, review, schedule, deployment, sprawl, test-association, and ranking tests."""
from __future__ import annotations

import json
from zoneinfo import ZoneInfo

import pytest

from appsec_review.jobs.job_change_context_analysis import metrics
from appsec_review.jobs.job_change_context_analysis.sources import (
    deployments_from_export,
    identity_hash,
    normalize_review_record,
    organization_from_export,
    review_records_from_export,
)
from appsec_review.jobs.job_source_history_analysis import signals as history_signals
from appsec_review.jobs.job_source_history_analysis.github import GitHubClient, GitHubSettings, enrich
from .support import DAY, HEAD, HOUR, PARENT, T0, change_entry as change, default_settings


def test_lifetime_normalization_uses_all_walked_commits_without_calendar_underflow() -> None:
    commits = [
        {"commit": HEAD, "parents": [PARENT], "author_time": T0, "commit_time": T0,
         "author_key": "new@example.test", "files": [{"path": "src/a.go", "added": 1, "deleted": 0}]},
        {"commit": PARENT, "parents": [], "author_time": -1, "commit_time": -1,
         "author_key": "old@example.test", "files": [{"path": "src/a.go", "added": 1, "deleted": 0}]},
    ]
    result = history_signals.normalize(
        commits, current_paths=("src/a.go",), shallow=(), window_months=None, max_changes=2, bulk_threshold=500,
    )
    assert [item["change_id"] for item in result["changes"]] == [HEAD, PARENT]


def test_glob_regex_and_path_stems() -> None:
    pat = metrics.glob_regex("**/sub/?_*{.py,.ts}/**")
    assert pat.fullmatch("a/b/sub/x_foo.py/leaf")
    assert pat.fullmatch("sub/y_.ts/")
    with pytest.raises(ValueError, match="unbalanced brace"):
        metrics.glob_regex("tests/{bad")
    assert metrics._stem(".env") == ".env"
    assert metrics._stem("Makefile") == "makefile"
    assert metrics.test_subject("RunnerTest") == "runner"
    assert metrics.test_subject("test_runner") == "runner"


def test_rolling_window_requires_more_than_three_fixes_within_sixty_days() -> None:
    inside = [(T0, "a"), (T0 + 20 * DAY, "b"), (T0 + 40 * DAY, "c"), (T0 + 59 * DAY, "d")]
    window = metrics.peak_window(inside, 60 * DAY)
    assert window["peak"] == 4 and window["changes"] == ["a", "b", "c", "d"]
    boundary = [(T0, "a"), (T0 + 20 * DAY, "b"), (T0 + 40 * DAY, "c"), (T0 + 60 * DAY, "d")]
    assert metrics.peak_window(boundary, 60 * DAY)["peak"] == 3
    spread = [(T0 + day * DAY, str(day)) for day in (0, 30, 59, 61, 95, 125)]
    peak = metrics.peak_window(spread, 60 * DAY)
    assert peak["peak"] == 3 and peak["changes"] == ["0", "30", "59"]
    assert metrics.peak_window([], 60 * DAY)["peak"] == 0


def test_review_speed_distinguishes_final_head_approval_stale_approval_and_direct_push() -> None:
    approved = normalize_review_record({
        "pull_request": 12, "direct_push": False, "created_at": "2023-11-14T22:00:00Z",
        "merged_at": "2023-11-14T23:00:00Z", "head_sha": HEAD, "head_committed_at": "2023-11-14T22:01:00Z",
        "approvals": [{"submitted_at": "2023-11-14T22:03:00Z", "commit_id": HEAD}],
    })
    facts = metrics.review_facts(approved, 300)
    assert facts["status"] == "known" and facts["merged_head_approved"] is True and facts["stale_approval"] is False
    assert facts["creation_to_first_approval_seconds"] == 180
    assert facts["final_head_to_approval_seconds"] == 120 and facts["fast_approval"] is True
    assert facts["unapproved_mainline"] is False and facts["fast_merge"] is False

    stale = normalize_review_record({
        "pull_request": 13, "created_at": "2023-11-14T10:00:00Z", "merged_at": "2023-11-15T10:00:00Z",
        "head_sha": HEAD, "approvals": [{"submitted_at": "2023-11-14T12:00:00-05:00", "commit_id": PARENT}],
    })
    facts = metrics.review_facts(stale, 300)
    assert facts["stale_approval"] is True and facts["merged_head_approved"] is False
    assert facts["final_head_to_approval_seconds"] is None and facts["fast_approval"] is False

    direct = metrics.review_facts(normalize_review_record({"pull_request": None, "direct_push": True}), 300)
    assert direct["direct_push"] is True and direct["unapproved_mainline"] is True

    unapproved = metrics.review_facts(normalize_review_record({
        "pull_request": 14, "created_at": "2023-11-14T10:00:00Z", "merged_at": "2023-11-14T10:02:00Z",
        "head_sha": HEAD, "approvals": [],
    }), 300)
    assert unapproved["unapproved_mainline"] is True and unapproved["fast_merge"] is True
    assert metrics.review_facts(None, 300) == {"status": "missing"}
    incomplete = metrics.review_facts(normalize_review_record({"pull_request": 15}), 300)
    assert incomplete["status"] == "incomplete" and incomplete["stale_approval"] is None
    records, gaps = review_records_from_export({
        "schema": "appsec-review/review-records/1", "records": {HEAD: {"pull_request": 1}, "not-a-sha": {}},
    })
    assert list(records) == [HEAD] and not gaps
    assert review_records_from_export({"schema": "wrong"})[1] == ["review_export_invalid"]


def test_github_enrichment_captures_review_timeline_without_identities() -> None:
    snapshot, merged_head = "c" * 40, "d" * 40
    responses = {
        f"/repos/acme/widget/commits/{snapshot}": (200, {"sha": snapshot}),
        f"/repos/acme/widget/commits/{snapshot}/pulls?per_page=100&page=1": (200, [
            {"number": 3, "merged_at": "2023-11-14T23:00:00Z", "created_at": "2023-11-14T22:00:00Z",
             "merge_commit_sha": snapshot, "user": {"login": "author"}, "head": {"sha": merged_head}}]),
        "/repos/acme/widget/pulls/3": (200, {"merged_by": {"login": "lead"}, "head": {"sha": merged_head}}),
        "/repos/acme/widget/pulls/3/reviews?per_page=100&page=1": (200, [
            {"state": "APPROVED", "user": {"login": "lead"}, "commit_id": merged_head,
             "submitted_at": "2023-11-14T22:04:00Z"},
            {"state": "APPROVED", "user": {"login": "author"}, "commit_id": merged_head,
             "submitted_at": "2023-11-14T22:01:00Z"}]),
        f"/repos/acme/widget/commits/{merged_head}": (200, {"commit": {"committer": {"date": "2023-11-14T22:02:00Z"}}}),
    }

    def transport(url, _headers, _timeout):
        status, body = responses[url.removeprefix("https://api.example.test")]
        return status, {}, json.dumps(body).encode()

    result = enrich(
        GitHubClient(GitHubSettings("https://api.example.test", "acme/widget", None, 50, 5), transport),
        snapshot, [snapshot],
    )
    fact = result["facts"][snapshot]
    assert fact["approvals"] == [{"submitted_at": "2023-11-14T22:04:00Z", "commit_id": merged_head}]
    assert fact["head_committed_at"] == "2023-11-14T22:02:00Z" and "lead" not in json.dumps(result)
    facts = metrics.review_facts(normalize_review_record(fact), 300)
    assert facts["final_head_to_approval_seconds"] == 120 and facts["merged_head_approved"] is True
    assert facts["creation_to_first_approval_seconds"] == 240 and facts["fast_approval"] is True


def test_off_hours_uses_configured_zone_and_deployments_handle_all_coverage_states() -> None:
    settings = default_settings(**{"schedule.time_zone": "America/New_York"})
    zone = ZoneInfo("America/New_York")
    assert metrics.schedule_facts(T0, zone, settings)["off_hours"] is False
    late = metrics.schedule_facts(T0 + 2 * HOUR, zone, settings)
    assert late["off_hours"] is True and late["local_time"].startswith("2023-11-14T19:13:20-05:00")
    summer = 1_689_368_000
    assert metrics.schedule_facts(summer, zone, settings)["off_hours"] is False
    utc = default_settings(**{"schedule.time_zone": "UTC"})
    assert metrics.schedule_facts(summer, ZoneInfo("UTC"), utc)["off_hours"] is True
    saturday = T0 + 4 * DAY - 4 * HOUR
    assert metrics.schedule_facts(saturday, zone, settings)["weekday"] == "saturday"
    assert metrics.schedule_facts(saturday, zone, settings)["off_hours"] is True
    assert metrics.schedule_facts(T0, None, settings) == {"status": "unavailable", "off_hours": None, "local_time": None}

    walked = ["f" * 40, "e" * 40, "d" * 40, "c" * 40, "b" * 40, "a" * 40]
    changes = [
        change(walked[0], 0, T0 + 10 * DAY, [("app.py", 1, 1)]),
        change(walked[1], 1, T0, [("app.py", 1, 1)]),
        change(walked[2], 2, T0 - DAY, [("app.py", 1, 1)]),
        change(walked[3], 3, T0 - 2 * DAY, [("app.py", 1, 1)]),
        change(walked[4], 4, T0, [("app.py", 1, 1)]),
        change(walked[5], 5, T0 - 10 * DAY, [("app.py", 1, 1)]),
    ]
    landed = {item["change_id"]: item["commit_time"] for item in changes}
    document, gaps = deployments_from_export({
        "schema": "appsec-review/deployment-events/1",
        "coverage": {"start": "2023-11-11T00:00:00Z", "end": "2023-11-20T00:00:00Z"},
        "events": [
            {"deployment_id": "d-early", "environment": "production", "status": "success",
             "deployed_at": "2023-11-12T00:00:00Z", "commit": walked[4]},
            {"deployment_id": "d1", "environment": "production", "status": "success",
             "deployed_at": "2023-11-13T23:00:00Z", "commit": walked[2]},
            {"deployment_id": "dx", "environment": "production", "status": "success",
             "deployed_at": "2023-11-15T00:00:00Z", "commit": "9" * 40},
        ],
    }, ("production",))
    assert gaps == [] and document is not None
    result, match_gaps = metrics.deployment_facts(changes, landed, walked, document, 24 * HOUR)
    assert match_gaps == ["deployment_commit_not_in_history"]
    assert result[walked[0]]["status"] == "outside_coverage"
    assert result[walked[1]]["status"] == "not_deployed_in_coverage"
    assert result[walked[2]]["pre_deployment"] is True and result[walked[2]]["deployment_id"] == "d1"
    assert result[walked[3]]["status"] == "shipped" and result[walked[3]]["pre_deployment"] is False
    assert result[walked[4]]["status"] == "timestamp_inconsistent" and result[walked[4]]["pre_deployment"] is None
    assert result[walked[5]]["status"] == "outside_coverage"
    unavailable, clean_gaps = metrics.deployment_facts(changes, landed, walked, None, 24 * HOUR)
    assert clean_gaps == [] and {item["status"] for item in unavailable.values()} == {"unavailable"}

    _, no_unmatched_gaps = metrics.deployment_facts(
        changes[:3], landed, walked, {**document, "events": [document["events"][1]]}, 24 * HOUR,
    )
    assert no_unmatched_gaps == []


def test_scope_sprawl_groups_related_components_and_handles_zero_and_bulk_churn() -> None:
    settings = default_settings()
    roots = [
        ("svc/a/core", "c-core"), ("svc/a", "c-a"), ("svc/b", "c-b"),
        ("lib", "c-lib"), ("ops", "c-ops"), ("ext", "c-ext"), ("docs", "c-docs"), (".", "c-root"),
    ]
    roots = sorted(roots, key=lambda item: (-len(item[0]) if item[0] != "." else 1, item[1]))
    coupled = [
        *[change(f"{index:040x}", index, T0, [("svc/b/x.py", 1, 0), ("lib/y.py", 1, 0)]) for index in range(3)],
        *[change(f"{index + 10:040x}", index + 10, T0, [("lib/y.py", 1, 0), ("ops/z.py", 1, 0)]) for index in range(3)],
        *[change(f"{index + 20:040x}", index + 20, T0, [("ops/z.py", 1, 0), ("ext/e.py", 1, 0)]) for index in range(3)],
        *[change(f"{index + 30:040x}", index + 30, T0, [("svc/b/x.py", 1, 0), ("ext/e.py", 1, 0)]) for index in range(3)],
        change("9" * 40, 40, T0, [("svc/b/x.py", 1, 0), ("docs/w.py", 1, 0)], bulk=True),
    ]
    wide = change("f" * 40, 9, T0, [
        ("svc/a/core/n.py", 100, 0), ("svc/a/m.py", 100, 0),
        ("svc/b/x.py", 100, 0), ("lib/y.py", 100, 0), ("ops/z.py", 100, 0), ("ext/e.py", 100, 0), ("docs/z.py", 200, 0),
    ])
    support = metrics.component_relatedness([*coupled, wide], roots)
    facts = metrics.sprawl_facts(wide, roots, support, settings)
    assert sorted(group["components"] for group in facts["groups"]) == [
        ["c-a", "c-core"], ["c-b", "c-ext", "c-lib", "c-ops"], ["c-docs"],
    ]
    assert facts["unrelated_group_count"] == 3 and facts["sprawling"] is True

    zero_bulk = change("e" * 40, 21, T0, [("unmapped.bin", 0, 0)], bulk=True)
    zero_facts = metrics.sprawl_facts(zero_bulk, [("svc/a", "c-a")], support, settings)
    assert zero_facts["churn_lines"] == 0 and zero_facts["largest_group_churn_share"] is None


def test_test_association_and_change_records_modes() -> None:
    settings = default_settings()
    roles = metrics.PathRoles(settings)
    roots = [("svc", "c-svc"), (".", "c-root")]
    assert [roles.role(p) for p in ("tests/test_auth.py", "src/auth.py", "api/user.proto", "README.md", "Makefile")] == [
        "test", "production", "contract", "other", "other",
    ]
    subject = metrics.test_churn_facts(
        [change(HEAD, 0, T0, [("src/auth.py", 60, 2), ("tests/test_auth.py", 5, 0), ("README.md", 3, 0)])],
        roles, roots, settings,
    )
    assert subject["association_rule_counts"] == {"subject": 1} and subject["untested_production"] is False

    ambiguous = metrics.test_churn_facts(
        [change(PARENT, 0, T0, [("src/auth.py", 60, 0), ("lib/auth.py", 10, 0), ("tests/test_auth.py", 5, 0)])],
        roles, roots, settings,
    )
    assert ambiguous["status"] == "partial" and ambiguous["ambiguous_test_files"] == ["tests/test_auth.py"]

    component = metrics.test_churn_facts(
        [change("c" * 40, 0, T0, [("svc/handler.py", 80, 0), ("root.py", 10, 0), ("svc/tests/test_routes.py", 3, 0)])],
        roles, roots, settings,
    )
    assert component["association_rule_counts"] == {"component": 1}

    unassociated = metrics.test_churn_facts(
        [change("d" * 40, 0, T0, [("svc/handler.py", 80, 0), ("other/test_unrelated.py", 12, 0)])],
        roles, [("svc", "c-svc")], settings,
    )
    assert unassociated["untested_production"] is True and unassociated["unassociated_test_added"] == 12

    disabled_settings = default_settings(**{"test_association.enabled": False})
    recs, gaps = metrics.change_records(
        [change(HEAD, 0, T0, [("src/auth.py", 60, 0)])],
        {HEAD: {"fix": True, "security_fix": False}},
        reviews=None,
        deployments=None,
        walked=[HEAD],
        zone=None,
        roots=roots,
        settings=disabled_settings,
    )
    assert gaps == []
    assert recs[HEAD]["review"] == {"status": "unavailable"}
    assert recs[HEAD]["tests"] == {"status": "unavailable"}
    assert recs[HEAD]["facts"]["landed_at_basis"] == "git_committer_time_claimed"

    pr_reviews = {
        HEAD: normalize_review_record({
            "pull_request": 42, "created_at": "2023-11-14T21:00:00Z", "merged_at": "2023-11-14T22:00:00Z",
            "head_sha": HEAD, "approvals": [],
        }),
    }
    pr_recs, _ = metrics.change_records(
        [change(HEAD, 0, T0, [("src/auth.py", 60, 0)])], {},
        reviews=pr_reviews, deployments=None, walked=[HEAD], zone=ZoneInfo("UTC"), roots=roots, settings=settings,
    )
    assert pr_recs[HEAD]["review_unit"] == "pr:42"
    assert pr_recs[HEAD]["facts"]["landed_at_basis"] == "review_host_merged_at"


def test_ownership_aggregate_and_priority_ranking_branches() -> None:
    settings = default_settings()
    assert metrics._availability([]) == "unavailable"
    assert metrics._availability(["available", "available"]) == "available"
    assert metrics._availability(["available", "partial"]) == "partial"

    owner = metrics.ownership({"author-0001": 7, "author-0002": 2, "author-0003": 1}, 0.5)
    assert owner["bus_factor"] == 1 and owner["principal_author_share"] == 0.7
    assert metrics.ownership({"author-0001": 3, "author-0002": 3, "author-0003": 3}, 0.99)["bus_factor"] == 3
    assert metrics.ownership({"author-0001": 1}, 1.5)["bus_factor"] == 1
    assert metrics.ownership({}, 0.5)["principal_author"] is None

    organization, org_gaps = organization_from_export({
        "schema": "appsec-review/organization-membership/1", "as_of": "2024-01-01T00:00:00Z",
        "members": [
            {"identity_sha256": identity_hash("One@Example.test"), "status": "departed"},
            {"identity_sha256": identity_hash("two@example.test"), "status": "active"},
        ],
    })
    assert org_gaps == [] and organization is not None
    identities = {"author-0001": identity_hash("one@example.test"), "author-0002": identity_hash("two@example.test")}

    known_records = {
        HEAD: {
            "change_id": HEAD, "position": 0, "facts": {"effective_time": T0},
            "classifications": {"fix": "heuristic"},
            "review": {
                "status": "known", "fast_approval": True, "fast_merge": False, "stale_approval": False,
                "unapproved_mainline": False, "direct_push": False, "merged_head_approved": True,
                "creation_to_first_approval_seconds": 100, "final_head_to_approval_seconds": 50,
            },
            "schedule": {"status": "available", "off_hours": True},
            "deployment": {"status": "shipped", "pre_deployment": True},
            "sprawl": {"sprawling": True, "unrelated_group_count": 3, "churn_lines": 500},
            "tests": {"status": "available", "untested_production": True, "untested_contract": False,
                      "ambiguous_association_count": 0, "production_added": 60, "production_deleted": 0,
                      "associated_test_churn": 0},
        },
    }
    full = metrics.aggregate(
        [HEAD], known_records, fix_events=2, fix_on_fix_status="available",
        owner=owner, owner_status="available", organization=organization, identity_of=identities,
        classification_status="available", settings=settings,
    )
    assert full["availability"]["fast_review_change_count"] == "available"
    assert full["details"]["review"]["median_final_head_to_approval_seconds"] == 50
    assert full["metrics"]["fix_on_fix_event_count"] == 2
    assert full["metrics"]["untested_production_change_count"] == 1
    assert full["metrics"]["departed_dominant_owner"] is True

    partial_dep_records = {
        HEAD: {**known_records[HEAD], "review": {"status": "missing"}, "deployment": {"status": "outside_coverage"}},
    }
    partial_agg = metrics.aggregate(
        [HEAD], partial_dep_records, fix_events=None, fix_on_fix_status="unavailable",
        owner=metrics.ownership({"author-0003": 5}, 0.5), owner_status="available",
        organization=organization, identity_of=identities, classification_status="partial", settings=settings,
    )
    assert partial_agg["availability"]["fast_review_change_count"] == "unavailable"
    assert partial_agg["metrics"]["fast_review_change_count"] is None
    assert partial_agg["availability"]["pre_deployment_change_count"] == "partial"
    assert partial_agg["metrics"]["departed_dominant_owner"] is None

    empty_owner_agg = metrics.aggregate(
        [HEAD],
        {
            HEAD: {
                **known_records[HEAD],
                "review": {"status": "unavailable"},
                "schedule": {"status": "unavailable"},
                "deployment": {"status": "unavailable"},
                "tests": {"status": "unavailable"},
            },
        },
        fix_events=None, fix_on_fix_status="unavailable",
        owner=metrics.ownership({}, 0.5), owner_status="available", organization=None, identity_of=identities,
        classification_status="available", settings=settings,
    )
    assert empty_owner_agg["availability"]["lifetime_principal_author_share"] == "unavailable"
    assert empty_owner_agg["availability"]["off_hours_change_count"] == "unavailable"
    assert empty_owner_agg["availability"]["pre_deployment_change_count"] == "unavailable"
    assert empty_owner_agg["availability"]["untested_production_change_count"] == "unavailable"

    weights = {"sprawling_change_count": 2, "unapproved_mainline_change_count": 3, "repeated_repair_peak": 1, "off_hours_change_count": 0}
    records_to_rank = {
        "b.py": {"metrics": {"sprawling_change_count": 1, "unapproved_mainline_change_count": None, "repeated_repair_peak": 2}},
        "a.py": {"metrics": {"sprawling_change_count": 1, "unapproved_mainline_change_count": None, "repeated_repair_peak": 2}},
        "c.py": {"metrics": {"sprawling_change_count": 0, "unapproved_mainline_change_count": 4, "repeated_repair_peak": 0}},
        "d.py": {"metrics": {"sprawling_change_count": 0, "unapproved_mainline_change_count": 0, "repeated_repair_peak": 0}},
    }
    ranked = metrics.rank(records_to_rank, weights)
    assert [item["key"] for item in ranked] == ["a.py", "b.py", "c.py", "d.py"]
    assert ranked[0]["missing_signals"] == ["unapproved_mainline_change_count"] and ranked[0]["coverage"] == 0.5

    all_missing = metrics.rank({"only.py": {"metrics": {}}}, {"sprawling_change_count": 1})
    assert all_missing[0]["score"] == 0.0 and all_missing[0]["coverage"] == 0.0
    zero_weights = metrics.rank({"only.py": {"metrics": {"sprawling_change_count": 1}}}, {})
    assert zero_weights[0]["coverage"] == 0.0
