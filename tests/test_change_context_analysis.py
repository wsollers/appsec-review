from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from zoneinfo import ZoneInfo

import pytest

from appsec_review.config import load_config
from appsec_review.jobs.cataloging import source_fingerprint
from appsec_review.jobs.job_change_context_analysis import build_job as build_change_context
from appsec_review.jobs.job_change_context_analysis import metrics
from appsec_review.jobs.job_change_context_analysis.settings import parse_settings
from appsec_review.jobs.job_change_context_analysis.sources import (
    deployments_from_export, identity_hash, load_export, normalize_review_record, organization_from_export,
    review_records_from_export,
)
from appsec_review.jobs.job_change_context_analysis.settings import ExportSource
from appsec_review.jobs.job_review_intake import build_job as build_intake
from appsec_review.jobs.job_source_history_analysis.github import GitHubClient, GitHubSettings, enrich
from appsec_review.jobs.job_target_catalog import build_job as build_catalog
from appsec_review.retrieval import EntityKind, LogicalIdentity, RetrievalCore
from appsec_review.runtime import GraphRunner, plan_jobs
from appsec_review.storage import atomic_json, file_sha256
from tests.test_source_history_analysis import GIT, ROOT, LocalDocker, commit, configured, git, history_job, write


DAY = 86_400
HOUR = 3_600
T0 = 1_700_000_000  # 2023-11-14T22:13:20Z, 17:13 in America/New_York (EST)
pytestmark = pytest.mark.skipif(GIT is None, reason="host git is required to emulate the tool-git image")


def default_settings(**overrides):
    config = load_config(ROOT / "appsec-review.toml")
    raw = json.loads(json.dumps(dict(config.job("job_change_context_analysis").settings)))
    for dotted, value in overrides.items():
        table = raw
        *parents, leaf = dotted.split(".")
        for key in parents:
            table = table[key]
        table[leaf] = value
    return parse_settings(raw)


def change(change_id: str, position: int, when: int, files, *, author: str = "author-0001", bulk: bool = False):
    return {"change_id": change_id, "position": position, "parents": ["0" * 40], "commit_time": when,
            "effective_time": when, "author_time": when, "author": author, "file_count": len(files), "bulk": bulk,
            "files": [{"path": path, "current_path": path, "renamed_from": None, "added": added, "deleted": deleted,
                       "binary": False} for path, added, deleted in files]}


# ------------------------------------------------------------------------------------------------
# Deterministic metric rules


def test_rolling_window_requires_more_than_three_fixes_within_sixty_days() -> None:
    inside = [(T0, "a"), (T0 + 20 * DAY, "b"), (T0 + 40 * DAY, "c"), (T0 + 59 * DAY, "d")]
    window = metrics.peak_window(inside, 60 * DAY)
    assert window["peak"] == 4 and window["changes"] == ["a", "b", "c", "d"]
    boundary = [(T0, "a"), (T0 + 20 * DAY, "b"), (T0 + 40 * DAY, "c"), (T0 + 60 * DAY, "d")]
    assert metrics.peak_window(boundary, 60 * DAY)["peak"] == 3, "the window is half-open at 60 days"
    spread = [(T0 + day * DAY, str(day)) for day in (0, 30, 59, 61, 95, 125)]
    peak = metrics.peak_window(spread, 60 * DAY)
    assert peak["peak"] == 3 and peak["changes"] == ["0", "30", "59"], "earliest peak wins ties"
    assert metrics.peak_window([], 60 * DAY)["peak"] == 0


def test_review_speed_distinguishes_final_head_approval_stale_approval_and_direct_push() -> None:
    head = "a" * 40
    approved = normalize_review_record({
        "pull_request": 12, "direct_push": False, "created_at": "2023-11-14T22:00:00Z",
        "merged_at": "2023-11-14T23:00:00Z", "head_sha": head, "head_committed_at": "2023-11-14T22:01:00Z",
        "approvals": [{"submitted_at": "2023-11-14T22:03:00Z", "commit_id": head}]})
    facts = metrics.review_facts(approved, 300)
    assert facts["status"] == "known" and facts["merged_head_approved"] is True and facts["stale_approval"] is False
    assert facts["creation_to_first_approval_seconds"] == 180
    assert facts["final_head_to_approval_seconds"] == 120 and facts["fast_approval"] is True
    assert facts["unapproved_mainline"] is False and facts["fast_merge"] is False
    stale = normalize_review_record({
        "pull_request": 13, "created_at": "2023-11-14T10:00:00Z", "merged_at": "2023-11-15T10:00:00Z",
        "head_sha": head, "approvals": [{"submitted_at": "2023-11-14T12:00:00-05:00", "commit_id": "b" * 40}]})
    facts = metrics.review_facts(stale, 300)
    assert facts["stale_approval"] is True and facts["merged_head_approved"] is False
    assert facts["final_head_to_approval_seconds"] is None and facts["fast_approval"] is False
    direct = metrics.review_facts(normalize_review_record({"pull_request": None, "direct_push": True}), 300)
    assert direct["direct_push"] is True and direct["unapproved_mainline"] is True
    unapproved = metrics.review_facts(normalize_review_record({
        "pull_request": 14, "created_at": "2023-11-14T10:00:00Z", "merged_at": "2023-11-14T10:02:00Z",
        "head_sha": head, "approvals": []}), 300)
    assert unapproved["unapproved_mainline"] is True and unapproved["fast_merge"] is True
    assert metrics.review_facts(None, 300) == {"status": "missing"}
    incomplete = metrics.review_facts(normalize_review_record({"pull_request": 15}), 300)
    assert incomplete["status"] == "incomplete" and incomplete["stale_approval"] is None
    records, gaps = review_records_from_export({"schema": "appsec-review/review-records/1",
                                                "records": {head: {"pull_request": 1}, "not-a-sha": {}}})
    assert list(records) == [head] and not gaps
    assert review_records_from_export({"schema": "wrong"})[1] == ["review_export_invalid"]


def test_github_enrichment_captures_review_timeline_without_identities() -> None:
    snapshot, merged_head = "c" * 40, "d" * 40
    responses = {
        f"/repos/acme/widget/commits/{snapshot}": (200, {"sha": snapshot}),
        f"/repos/acme/widget/commits/{snapshot}/pulls?per_page=10": (200, [
            {"number": 3, "merged_at": "2023-11-14T23:00:00Z", "created_at": "2023-11-14T22:00:00Z",
             "merge_commit_sha": snapshot, "user": {"login": "author"}, "head": {"sha": merged_head}}]),
        "/repos/acme/widget/pulls/3": (200, {"merged_by": {"login": "lead"}, "head": {"sha": merged_head}}),
        "/repos/acme/widget/pulls/3/reviews?per_page=100": (200, [
            {"state": "APPROVED", "user": {"login": "lead"}, "commit_id": merged_head,
             "submitted_at": "2023-11-14T22:04:00Z"},
            {"state": "APPROVED", "user": {"login": "author"}, "commit_id": merged_head,
             "submitted_at": "2023-11-14T22:01:00Z"}]),
        f"/repos/acme/widget/commits/{merged_head}": (200, {"commit": {"committer": {"date": "2023-11-14T22:02:00Z"}}}),
    }

    def transport(url, headers, timeout):
        status, body = responses[url.removeprefix("https://api.example.test")]
        return status, {}, json.dumps(body).encode()

    result = enrich(GitHubClient(GitHubSettings("https://api.example.test", "acme/widget", None, 50, 5), transport),
                    snapshot, [snapshot])
    fact = result["facts"][snapshot]
    assert fact["approvals"] == [{"submitted_at": "2023-11-14T22:04:00Z", "commit_id": merged_head}]
    assert fact["head_committed_at"] == "2023-11-14T22:02:00Z" and "lead" not in json.dumps(result)
    facts = metrics.review_facts(normalize_review_record(fact), 300)
    assert facts["final_head_to_approval_seconds"] == 120 and facts["merged_head_approved"] is True
    assert facts["creation_to_first_approval_seconds"] == 240 and facts["fast_approval"] is True


def test_off_hours_uses_the_configured_zone_and_deployments_require_events() -> None:
    settings = default_settings(**{"schedule.time_zone": "America/New_York"})
    zone = ZoneInfo("America/New_York")
    assert metrics.schedule_facts(T0, zone, settings)["off_hours"] is False  # Tue 17:13 EST
    late = metrics.schedule_facts(T0 + 2 * HOUR, zone, settings)
    assert late["off_hours"] is True and late["local_time"].startswith("2023-11-14T19:13:20-05:00")
    summer = 1_689_368_000  # 2023-07-14T20:53:20Z: 16:53 EDT on a Friday, 20:53 in UTC
    assert metrics.schedule_facts(summer, zone, settings)["off_hours"] is False
    utc = default_settings(**{"schedule.time_zone": "UTC"})
    assert metrics.schedule_facts(summer, ZoneInfo("UTC"), utc)["off_hours"] is True
    saturday = T0 + 4 * DAY - 4 * HOUR
    assert metrics.schedule_facts(saturday, zone, settings)["weekday"] == "saturday"
    assert metrics.schedule_facts(saturday, zone, settings)["off_hours"] is True
    assert metrics.schedule_facts(T0, None, settings) == {"status": "unavailable", "off_hours": None, "local_time": None}

    walked = ["e" * 40, "d" * 40, "c" * 40, "b" * 40, "a" * 40]
    changes = [change(walked[index], index, T0 - index * DAY, [("app.py", 1, 1)]) for index in range(5)]
    landed = {item["change_id"]: item["commit_time"] for item in changes}
    document, gaps = deployments_from_export({
        "schema": "appsec-review/deployment-events/1",
        "coverage": {"start": "2023-11-11T00:00:00Z", "end": "2023-11-20T00:00:00Z"},
        "events": [
            {"deployment_id": "d1", "environment": "production", "status": "success",
             "deployed_at": "2023-11-13T23:00:00Z", "commit": walked[1]},
            {"deployment_id": "d0", "environment": "staging", "status": "success",
             "deployed_at": "2023-11-12T00:00:00Z", "commit": walked[3]},
            {"deployment_id": "dx", "environment": "production", "status": "success",
             "deployed_at": "2023-11-15T00:00:00Z", "commit": "f" * 40},
            {"deployment_id": "bad", "environment": "production", "status": "success",
             "deployed_at": "yesterday", "commit": walked[0]},
        ]}, ("production",))
    assert gaps == ["deployment_events_rejected"] and [item["deployment_id"] for item in document["events"]] == ["d1", "dx"]
    result, match_gaps = metrics.deployment_facts(changes, landed, walked, document, 24 * HOUR)
    assert match_gaps == ["deployment_commit_not_in_history"]
    assert result[walked[0]]["status"] == "not_deployed_in_coverage"
    assert result[walked[1]]["pre_deployment"] is True and result[walked[1]]["deployment_id"] == "d1"
    assert result[walked[2]]["status"] == "shipped" and result[walked[2]]["pre_deployment"] is False
    assert result[walked[3]]["deployment_id"] == "d1", "staging is not a configured environment"
    assert result[walked[4]]["status"] == "outside_coverage", "landed before the export's coverage"
    unavailable, _ = metrics.deployment_facts(changes, landed, walked, None, 24 * HOUR)
    assert {item["status"] for item in unavailable.values()} == {"unavailable"}


def test_scope_sprawl_groups_related_components_and_weighs_churn_distribution() -> None:
    settings = default_settings()
    roots = [("svc/a/core", "c-core"), ("svc/a", "c-a"), ("svc/b", "c-b"), ("lib", "c-lib"), ("docs", "c-docs"), (".", "c-root")]
    roots = sorted(roots, key=lambda item: (-len(item[0]) if item[0] != "." else 1, item[1]))
    coupled = [change(f"{index:040x}", index, T0, [("svc/b/x.py", 1, 0), ("lib/y.py", 1, 0)]) for index in range(3)]
    wide = change("f" * 40, 9, T0, [("svc/a/m.py", 150, 0), ("svc/a/core/n.py", 150, 0), ("svc/b/x.py", 150, 0),
                                    ("lib/y.py", 150, 0), ("docs/z.py", 150, 0)])
    support = metrics.component_relatedness([*coupled, wide], roots)
    facts = metrics.sprawl_facts(wide, roots, support, settings)
    assert facts["component_count"] == 5
    assert sorted(group["components"] for group in facts["groups"]) == [["c-a", "c-core"], ["c-b", "c-lib"], ["c-docs"]]
    assert facts["unrelated_group_count"] == 3 and facts["sprawling"] is True and facts["churn_lines"] == 750
    lopsided = change("e" * 40, 10, T0, [("svc/a/m.py", 990, 0), ("svc/b/x.py", 5, 0), ("docs/z.py", 5, 0)])
    lopsided_facts = metrics.sprawl_facts(lopsided, roots, support, settings)
    assert lopsided_facts["unrelated_group_count"] == 3 and lopsided_facts["sprawling"] is False
    assert lopsided_facts["largest_group_churn_share"] == 0.99
    two_support = metrics.component_relatedness([*coupled[:2], wide], roots)
    assert metrics.sprawl_facts(wide, roots, two_support, settings)["unrelated_group_count"] == 4, \
        "the evaluated change never counts toward its own relatedness"


def test_test_association_rules_report_ambiguity_and_untested_churn() -> None:
    settings = default_settings()
    roles = metrics.PathRoles(settings)
    roots = [("svc", "c-svc"), (".", "c-root")]
    assert [roles.role(path) for path in ("tests/test_auth.py", "src/auth.py", "api/user.proto", "README.md",
                                          "web/app.spec.ts", "pkg/server_test.go")] == \
        ["test", "production", "contract", "other", "test", "test"]
    assert metrics.test_subject("tests/test_auth.py") == "auth" and metrics.test_subject("web/app.spec.ts") == "app"
    assert metrics.test_subject("src/AuthTest.java") == "auth"
    subject = metrics.test_churn_facts([change("a" * 40, 0, T0, [("src/auth.py", 60, 2), ("tests/test_auth.py", 5, 0)])],
                                       roles, roots, settings)
    assert subject["association_rule_counts"] == {"subject": 1} and subject["untested_production"] is False
    ambiguous = metrics.test_churn_facts([change("b" * 40, 0, T0, [("src/auth.py", 60, 0), ("lib/auth.py", 10, 0),
                                                                    ("tests/test_auth.py", 5, 0)])], roles, roots, settings)
    assert ambiguous["status"] == "partial" and ambiguous["ambiguous_test_files"] == ["tests/test_auth.py"]
    component = metrics.test_churn_facts([change("c" * 40, 0, T0, [("svc/handler.py", 80, 0),
                                                                    ("svc/tests/test_routes.py", 3, 0)])], roles, roots, settings)
    assert component["association_rule_counts"] == {"component": 1} and component["untested_production"] is False
    untested = metrics.test_churn_facts([change("d" * 40, 0, T0, [("svc/handler.py", 80, 0),
                                                                   ("tests/test_other.py", 30, 0)])],
                                        roles, [("svc", "c-svc"), ("tests", "c-tests")], settings)
    assert untested["untested_production"] is True and untested["unassociated_test_added"] == 30
    contract = metrics.test_churn_facts([change("e" * 40, 0, T0, [("api/user.proto", 4, 1)])], roles, roots, settings)
    assert contract["untested_contract"] is True and contract["untested_production"] is False
    review_unit = metrics.test_churn_facts([change("f" * 40, 0, T0, [("src/auth.py", 60, 0)]),
                                            change("9" * 40, 1, T0, [("tests/test_auth.py", 9, 0)])], roles, roots, settings)
    assert review_unit["untested_production"] is False, "tests in the same review unit count"


def test_lifetime_ownership_concentration_and_departure_come_only_from_organization_data() -> None:
    settings = default_settings()
    owner = metrics.ownership({"author-0001": 7, "author-0002": 2, "author-0003": 1}, 0.5)
    assert owner == {"author_count": 3, "principal_author": "author-0001", "principal_author_share": 0.7,
                     "bus_factor": 1, "weight_total": 10}
    assert metrics.ownership({"author-0001": 3, "author-0002": 3, "author-0003": 4}, 0.8)["bus_factor"] == 3
    assert metrics.ownership({}, 0.5)["principal_author_share"] is None
    organization, gaps = organization_from_export({
        "schema": "appsec-review/organization-membership/1", "as_of": "2024-01-01T00:00:00Z",
        "members": [{"identity_sha256": identity_hash("One@Example.test"), "status": "departed"},
                    {"identity_sha256": identity_hash("two@example.test"), "status": "active"},
                    {"identity_sha256": "not-a-hash", "status": "departed"}]})
    assert gaps == ["organization_members_rejected"]
    records = {"a" * 40: {"change_id": "a" * 40, "position": 0, "facts": {"effective_time": T0},
                          "classifications": {"fix": None}, "review": {"status": "unavailable"},
                          "schedule": {"status": "unavailable"}, "deployment": {"status": "unavailable"},
                          "sprawl": {"sprawling": False, "unrelated_group_count": 1, "churn_lines": 1},
                          "tests": {"status": "unavailable"}}}
    identities = {"author-0001": identity_hash("one@example.test"), "author-0002": identity_hash("two@example.test")}

    def run(owner_counts, org):
        return metrics.aggregate(list(records), records, fix_events=None, fix_on_fix_status="unavailable",
                                 owner=metrics.ownership(owner_counts, 0.5), owner_status="available",
                                 organization=org, identity_of=identities, classification_status="available",
                                 settings=settings)

    departed = run({"author-0001": 3, "author-0002": 1}, organization)
    assert departed["metrics"]["departed_dominant_owner"] is True
    assert departed["metrics"]["lifetime_principal_author_share"] == 0.75
    assert run({"author-0001": 1, "author-0002": 3}, organization)["metrics"]["departed_dominant_owner"] is False
    unknown = run({"author-0003": 5}, organization)
    assert unknown["metrics"]["departed_dominant_owner"] is None
    assert unknown["availability"]["departed_dominant_owner"] == "unavailable"
    absent = run({"author-0001": 5}, None)
    assert absent["metrics"]["departed_dominant_owner"] is None, "inactivity is never departure"
    for signal in ("fast_review_change_count", "off_hours_change_count", "pre_deployment_change_count",
                   "untested_production_change_count", "fix_on_fix_event_count"):
        assert absent["metrics"][signal] is None and absent["availability"][signal] == "unavailable"


def test_priority_ranking_is_deterministic_and_never_zero_fills_missing_signals() -> None:
    weights = {"sprawling_change_count": 2, "unapproved_mainline_change_count": 3, "repeated_repair_peak": 1}

    def record(sprawl, unapproved, peak):
        return {"metrics": {"sprawling_change_count": sprawl, "unapproved_mainline_change_count": unapproved,
                            "repeated_repair_peak": peak}}

    records = {"b.py": record(1, None, 2), "a.py": record(1, None, 2), "c.py": record(0, 4, 0), "d.py": record(0, 0, 0)}
    ranked = metrics.rank(records, weights)
    assert [item["key"] for item in ranked] == ["a.py", "b.py", "c.py", "d.py"]
    assert ranked[0]["missing_signals"] == ["unapproved_mainline_change_count"] and ranked[0]["coverage"] == 0.5
    assert ranked[0]["score"] == 1.0 and ranked[2]["score"] == 0.5 and ranked[3]["score"] == 0.0
    assert ranked == metrics.rank(dict(reversed(list(records.items()))), weights)


def test_settings_and_exports_fail_closed(tmp_path: Path) -> None:
    raw = json.loads(json.dumps(dict(load_config(ROOT / "appsec-review.toml").job("job_change_context_analysis").settings)))
    for mutate, message in (
        (lambda value: value.update(extra=1), "keys are invalid"),
        (lambda value: value["schedule"].update(time_zone="../etc/passwd"), "schedule.time_zone"),
        (lambda value: value["priority_weights"].update(churn_lines=1), "unknown change context priority signal"),
        (lambda value: value["deployments"].update(enabled=True), "enabled without export_path"),
        (lambda value: value["schedule"].update(business_hours_start="19:00"), "start before"),
    ):
        candidate = json.loads(json.dumps(raw))
        mutate(candidate)
        with pytest.raises(ValueError, match=message):
            parse_settings(candidate)
    target = tmp_path / "target"
    target.mkdir()
    (tmp_path / "data").mkdir()
    export = tmp_path / "data" / "deploy.json"
    export.write_text('{"schema": "x"}', encoding="utf-8")
    digest = file_sha256(export)
    assert load_export(tmp_path, target, ExportSource(False, "data/deploy.json", digest), "deployment")[2] == ["deployment_disabled"]
    assert load_export(tmp_path, target, ExportSource(True, "data/deploy.json", ""), "deployment")[2] == ["deployment_export_unpinned"]
    assert load_export(tmp_path, target, ExportSource(True, "data/deploy.json", "0" * 64), "deployment")[2] == \
        ["deployment_export_hash_mismatch"]
    assert load_export(tmp_path, target, ExportSource(True, "../deploy.json", digest), "deployment")[2] == \
        ["deployment_export_outside_repository"]
    (target / "deploy.json").write_bytes(export.read_bytes())
    assert load_export(tmp_path, target, ExportSource(True, "target/deploy.json", digest), "deployment")[2] == \
        ["deployment_export_inside_target"]
    document, data, gaps = load_export(tmp_path, target, ExportSource(True, "data/deploy.json", digest), "deployment")
    assert document == {"schema": "x"} and data == export.read_bytes() and not gaps
    assert deployments_from_export(document, ("production",)) == (None, ["deployment_export_invalid"])


# ------------------------------------------------------------------------------------------------
# End-to-end job behavior


def build_target(target: Path) -> dict[str, str]:
    target.mkdir(parents=True)
    git(target, "init", "-q", "-b", "main")
    write(target, "pyproject.toml", "[project]\nname = 'fixture'\n")
    for name in ("lib", "svc_a", "svc_b"):
        write(target, f"{name}/pyproject.toml", f"[project]\nname = '{name}'\n")
    write(target, "lib/core.py", "VALUE = 0\n")
    write(target, "svc_a/api.py", "def route():\n    return 0\n")
    write(target, "svc_b/db.py", "def query():\n    return 0\n")
    ids = {"init": commit(target, "initial import", T0 - 400 * DAY)}
    write(target, "app/auth.py", "def check(user):\n    return True\n\n\ndef audit(user):\n    return None\n")
    write(target, "app/util.py", "def helper():\n    return 1\n")
    ids["c1"] = commit(target, "add app", T0)
    write(target, "app/auth.py", "def check(user):\n    return user.ok\n\n\ndef audit(user):\n    return None\n")
    ids["c2"] = commit(target, "fix: auth bypass", T0 + DAY)
    write(target, "app/auth.py", "def check(user):\n    return bool(user.ok)\n\n\ndef audit(user):\n    return None\n")
    ids["c3"] = commit(target, "refactor", T0 + 2 * DAY, author="two@example.test")
    write(target, "app/auth.py", "def check(user):\n    return bool(user and user.ok)\n\n\ndef audit(user):\n    return None\n")
    ids["c4"] = commit(target, "fix: null user", T0 + 10 * DAY + 3 * HOUR)
    write(target, "app/auth.py", "def check(user):\n    return bool(user and user.ok and user.active)\n\n\n"
                                 "def audit(user):\n    return None\n")
    ids["c5"] = commit(target, "fix crash on inactive user", T0 + 20 * DAY)
    git(target, "revert", "--no-edit", ids["c5"], when=T0 + 30 * DAY)
    ids["c6"] = git(target, "rev-parse", "HEAD")
    big = "".join(f"LINE_{index} = {index}\n" for index in range(130))
    write(target, "app/auth.py", "def check(user):\n    return bool(user and user.ok)\n\n\ndef audit(user):\n"
                                 "    return None\n" + big)
    write(target, "lib/core.py", "VALUE = 0\n" + big)
    write(target, "svc_a/api.py", "def route():\n    return 0\n" + big)
    write(target, "svc_b/db.py", "def query():\n    return 0\n" + big)
    ids["c7"] = commit(target, "rename constants everywhere", T0 + 40 * DAY)
    write(target, "app/util.py", "def helper():\n    return 1\n" + "".join(f"X{index} = {index}\n" for index in range(60)))
    ids["c8"] = commit(target, "extend helper", T0 + 45 * DAY)
    write(target, "app/auth.py", (target / "app/auth.py").read_text(encoding="utf-8").replace(
        "def audit(user):\n    return None\n", "def audit(user):\n    return user.id\n"))
    write(target, "tests/test_auth.py", "def test_audit():\n    assert True\n")
    ids["c9"] = commit(target, "audit returns id", T0 + 46 * DAY)
    return ids


def fake_tree_sitter(run_root: Path, target: Path, snapshot: str, paths: list[str]) -> None:
    """Publish an accepted Tree-sitter handoff whose nodes mirror Python ``def`` blocks."""
    lines: list[str] = []
    for path in paths:
        data = (target / path).read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        text = data.decode()
        rows = text.splitlines(keepends=True)
        offsets = [0]
        for row in rows:
            offsets.append(offsets[-1] + len(row.encode()))

        def node(ordinal, kind, start_line, end_line, start_byte, end_byte, field=None):
            identity = "asr:ast_node:" + hashlib.sha256(f"{path}{ordinal}".encode()).hexdigest()
            return json.dumps({"identity": identity, "path": path, "file_sha256": sha, "grammar_native_type": kind,
                               "field": field, "has_error": False, "error": False, "missing": False, "language": "Python",
                               "location": {"start_byte": start_byte, "end_byte": end_byte, "start_line": start_line,
                                            "end_line": end_line, "start_column": 1, "end_column": 1,
                                            "producer_location": {"ordinal_path": ordinal}}}, sort_keys=True)

        lines.append(node([], "module", 1, len(rows), 0, len(data)))
        starts = [index for index, row in enumerate(rows) if row.startswith("def ")]
        for number, start in enumerate(starts):
            end = next((index for index in range(start + 1, len(rows)) if rows[index] and not rows[index][0].isspace()
                        and rows[index].strip()), len(rows)) - 1
            while end > start and not rows[end].strip():
                end -= 1
            lines.append(node([number], "function_definition", start + 1, end + 1, offsets[start], offsets[end + 1]))
            name = re.match(r"def (\w+)", rows[start]).group(1)
            lines.append(node([number, 0], "identifier", start + 1, start + 1, offsets[start] + 4,
                              offsets[start] + 4 + len(name), field="name"))
    root = run_root / "data" / "jobs" / "job_tree_sitter_ast" / "attempts" / "fake"
    shard = root / "nodes.jsonl"
    shard.parent.mkdir(parents=True, exist_ok=True)
    shard.write_text("\n".join(sorted(lines)) + "\n", encoding="utf-8")
    accepted = root / "accepted-tree-sitter-ast.json"
    atomic_json(accepted, {"schema": "appsec-review/tree-sitter-ast/1", "target_snapshot": snapshot, "dispositions": [
        {"scope_id": "fake", "artifact": {"path": shard.relative_to(run_root).as_posix(), "sha256": file_sha256(shard)}}]})
    handoff = root / "handoff.json"
    atomic_json(handoff, {"schema": "appsec-review/job-handoff/1", "status": "ACCEPTED", "outputs": {
        "acceptance.publish_handoff": {"artifact": {"path": accepted.relative_to(run_root).as_posix(),
                                                    "sha256": file_sha256(accepted)}}}})
    atomic_json(root.parent.parent / "latest.json", {"handoff_path": handoff.relative_to(run_root).as_posix(),
                                                     "handoff_sha256": file_sha256(handoff)})


def change_context_job(docker: LocalDocker):
    from appsec_review.container_runtime import ContainerExecutor, load_catalog
    return build_change_context(executor_factory=lambda unit: ContainerExecutor(
        load_catalog(unit.job.repository_root), unit.job.run_root, runner=docker))


def run_review(config, target: Path, docker: LocalDocker, *, tree_sitter: bool = False):
    upstream = (build_intake(), build_catalog(), history_job(docker))
    fingerprint = source_fingerprint(target)
    first = GraphRunner(config, upstream).run(target_root=target, source_fingerprint=fingerprint)
    run_root = config.runtime.runs_dir / first["run_id"]
    if tree_sitter:
        fake_tree_sitter(run_root, target, fingerprint, sorted(
            path.relative_to(target).as_posix() for path in target.rglob("*.py") if ".git" not in path.parts))
    outcome = GraphRunner(config, (*upstream, change_context_job(docker))).run(
        target_root=target, source_fingerprint=fingerprint, run_id=first["run_id"])
    return outcome, run_root


def produced(outcome) -> dict:
    return outcome["jobs"]["job_change_context_analysis"]["result"]["outputs"]


def signals(run_root: Path, outcome) -> dict:
    return json.loads((run_root / produced(outcome)["analyze.rank"]["artifact"]["path"]).read_text(encoding="utf-8"))


def coverage(core: RetrievalCore) -> dict[str, dict]:
    rows = [row for item in core.coverage(indexes=("history",))["results"] for row in item["coverage"]]
    return {row["area"]: row for row in rows if row["area"] in {
        "git-change-context", "review-records", "deployment-events", "off-hours-schedule", "test-association",
        "organization-membership", "function-attribution", "fix-on-fix"}}


def test_git_only_run_publishes_git_signals_and_names_every_missing_source(tmp_path: Path) -> None:
    config = configured(tmp_path)
    target = tmp_path / "target"
    ids = build_target(target)
    outcome, run_root = run_review(config, target, LocalDocker())
    assert {item["job_id"]: item["action"] for item in outcome["decisions"]}["job_change_context_analysis"] == "RUN"
    result = signals(run_root, outcome)
    auth = result["files"]["app/auth.py"]
    assert auth["metrics"]["repeated_repair_peak"] == 4
    assert auth["details"]["repeated_repairs"]["flagged"] is True
    assert auth["details"]["repeated_repairs"]["changes"] == [ids["c2"], ids["c4"], ids["c5"], ids["c6"]]
    assert set(auth["details"]["repeated_repairs"]["classification_basis"]) == {"heuristic"}
    assert auth["metrics"]["fix_on_fix_event_count"] >= 1, "the revert fixes lines a prior fix introduced"
    events = json.loads((run_root / produced(outcome)["attribute.fix_on_fix"]["artifact"]["path"]).read_text())["events"]
    assert {"fix_change": ids["c6"], "prior_fix_change": ids["c5"], "path": "app/auth.py"}.items() <= next(
        event for event in events if event["fix_change"] == ids["c6"]).items()
    assert auth["metrics"]["sprawling_change_count"] == 1 and auth["details"]["sprawl"]["sprawling_changes"] == [ids["c7"]]
    changes = json.loads((run_root / produced(outcome)["analyze.change_signals"]["artifact"]["path"]).read_text())["changes"]
    assert changes[ids["c7"]]["sprawl"]["unrelated_group_count"] == 4
    assert changes[ids["c8"]]["tests"]["untested_production"] is True
    assert changes[ids["c9"]]["tests"]["association_rule_counts"] == {"subject": 1}
    assert changes[ids["c9"]]["tests"]["untested_production"] is False
    assert auth["metrics"]["lifetime_principal_author_share"] == 0.875
    assert auth["details"]["ownership"]["bus_factor"] == 1
    for signal in ("fast_review_change_count", "stale_approval_change_count", "unapproved_mainline_change_count",
                   "off_hours_change_count", "pre_deployment_change_count", "departed_dominant_owner"):
        assert auth["metrics"][signal] is None and auth["availability"][signal] == "unavailable", signal
    assert result["functions"] == {}
    assert produced(outcome)["publish.publish_handoff"]["terminal_status"] == "PARTIAL"
    gaps = set(produced(outcome)["publish.publish_handoff"]["gaps"])
    assert {"review_records_unavailable:github_enrichment_disabled", "deployment_disabled", "organization_disabled",
            "time_zone_not_configured", "function_spans_unavailable:tree_sitter_not_accepted"} <= gaps

    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    rows = coverage(core)
    assert rows["git-change-context"]["status"] == "complete"
    assert rows["review-records"] == {"area": "review-records", "status": "unavailable",
                                      "gap": "review_records_unavailable:github_enrichment_disabled"}
    assert rows["deployment-events"]["status"] == "unavailable" and rows["organization-membership"]["status"] == "unavailable"
    assert rows["off-hours-schedule"]["gap"] == "time_zone_not_configured"
    assert rows["function-attribution"]["status"] == "unavailable"
    top = core.query_change_context(scope="file", limit=5)
    assert [item["payload"]["rank"] for item in top["results"]] == sorted(item["payload"]["rank"] for item in top["results"])
    assert top["results"][0]["location"]["path"] == "app/auth.py"
    assert any("review-records: unavailable" in gap for gap in top["coverage_gaps"])
    sprawling = core.query_change_context(signal="sprawling_change_count", scope="component", limit=10)
    assert len(sprawling["results"]) == 4
    traced = core.trace(identity=top["results"][0]["identity"], relations=("DERIVED_FROM",), depth=1, limit=50)
    c7 = LogicalIdentity.derive(EntityKind.CHANGE, source_fingerprint(target), {"vcs": "git", "change_id": ids["c7"]})
    assert c7.value in {item["target_id"] for item in traced["results"]}
    assert core.find(identity=c7.value, indexes=("history",))["results"][0]["payload"]["sprawl"]["sprawling"] is True
    history_rows = [row for item in core.coverage(indexes=("history",))["results"] for row in item["coverage"]]
    assert {"area": "git-history", "status": "complete", "gap": None} in history_rows, "history shard stays composed"
    assert "one@example.test" not in json.dumps(top) and identity_hash("one@example.test") not in json.dumps(top)

    fresh, fresh_root = run_review(config, target, LocalDocker())
    assert (fresh_root / produced(fresh)["analyze.rank"]["artifact"]["path"]).read_bytes() == \
        (run_root / produced(outcome)["analyze.rank"]["artifact"]["path"]).read_bytes()


def test_external_sources_drive_review_deployment_schedule_ownership_and_function_signals(tmp_path: Path) -> None:
    target = tmp_path / "target"
    ids = build_target(target)
    data = tmp_path / "data" / "change-context"
    data.mkdir(parents=True)
    head = "9" * 40
    reviews = {"schema": "appsec-review/review-records/1", "records": {
        ids["c2"]: {"pull_request": 1, "created_at": "2023-11-15T22:00:00Z", "merged_at": "2023-11-15T22:13:20Z",
                    "head_sha": head, "head_committed_at": "2023-11-15T21:59:00Z",
                    "approvals": [{"submitted_at": "2023-11-15T22:02:00Z", "commit_id": head}]},
        ids["c3"]: {"pull_request": 2, "created_at": "2023-11-15T10:00:00Z", "merged_at": "2023-11-16T22:13:20Z",
                    "head_sha": head, "approvals": [{"submitted_at": "2023-11-16T09:00:00Z", "commit_id": "8" * 40}]},
        ids["c4"]: {"pull_request": None, "direct_push": True},
    }}
    deployments = {"schema": "appsec-review/deployment-events/1",
                   "coverage": {"start": "2023-11-01T00:00:00Z", "end": "2024-02-01T00:00:00Z"},
                   "events": [{"deployment_id": "rel-1", "environment": "production", "status": "success",
                               "deployed_at": "2023-11-25T03:00:00Z", "commit": ids["c4"]}]}
    organization = {"schema": "appsec-review/organization-membership/1", "as_of": "2024-02-01T00:00:00Z",
                    "members": [{"identity_sha256": identity_hash("one@example.test"), "status": "departed"}]}
    digests = {}
    for name, value in (("reviews", reviews), ("deployments", deployments), ("organization", organization)):
        (data / f"{name}.json").write_text(json.dumps(value), encoding="utf-8")
        digests[name] = file_sha256(data / f"{name}.json")
    config = configured(tmp_path)
    text = (tmp_path / "appsec-review.toml").read_text(encoding="utf-8")
    replacements = (
        ('source = "github_enrichment"\nexport_path = ""\nexport_sha256 = ""',
         f'source = "export"\nexport_path = "data/change-context/reviews.json"\nexport_sha256 = "{digests["reviews"]}"'),
        ('time_zone = ""', 'time_zone = "America/New_York"'),
        ('enabled = false\nexport_path = ""\nexport_sha256 = ""\nenvironments',
         f'enabled = true\nexport_path = "data/change-context/deployments.json"\n'
         f'export_sha256 = "{digests["deployments"]}"\nenvironments'),
        ('[jobs.job_change_context_analysis.settings.organization]\n'
         '# Departure comes only from an appsec-review/organization-membership/1 export, never Git inactivity.\n'
         'enabled = false\nexport_path = ""\nexport_sha256 = ""',
         '[jobs.job_change_context_analysis.settings.organization]\nenabled = true\n'
         f'export_path = "data/change-context/organization.json"\nexport_sha256 = "{digests["organization"]}"'),
    )
    for old, new in replacements:
        assert old in text, old
        text = text.replace(old, new)
    (tmp_path / "appsec-review.toml").write_text(text, encoding="utf-8")
    config = load_config(tmp_path / "appsec-review.toml")
    outcome, run_root = run_review(config, target, LocalDocker(), tree_sitter=True)
    changes = json.loads((run_root / produced(outcome)["analyze.change_signals"]["artifact"]["path"]).read_text())["changes"]
    assert changes[ids["c2"]]["review"]["fast_approval"] is True
    assert changes[ids["c2"]]["review"]["merged_head_approved"] is True
    assert changes[ids["c2"]]["facts"]["landed_at_basis"] == "review_host_merged_at"
    assert changes[ids["c3"]]["review"]["stale_approval"] is True
    assert changes[ids["c4"]]["review"]["unapproved_mainline"] is True and changes[ids["c4"]]["review"]["direct_push"]
    assert changes[ids["c5"]]["review"]["status"] == "missing"
    assert changes[ids["c4"]]["schedule"]["off_hours"] is True, "20:13 local time is outside business hours"
    assert changes[ids["c1"]]["schedule"]["off_hours"] is False
    assert changes[ids["c4"]]["deployment"]["pre_deployment"] is True
    assert changes[ids["c2"]]["deployment"]["status"] == "shipped" and changes[ids["c2"]]["deployment"]["pre_deployment"] is False
    assert changes[ids["c9"]]["deployment"]["status"] == "not_deployed_in_coverage"
    result = signals(run_root, outcome)
    auth = result["files"]["app/auth.py"]
    assert auth["metrics"]["fast_review_change_count"] == 1 and auth["metrics"]["stale_approval_change_count"] == 1
    assert auth["metrics"]["unapproved_mainline_change_count"] == 1
    assert auth["availability"]["fast_review_change_count"] == "partial", "uncovered changes are partial, not clean"
    assert changes[ids["c7"]]["schedule"]["weekday"] == "sunday" and changes[ids["c9"]]["schedule"]["weekday"] == "saturday"
    assert auth["metrics"]["off_hours_change_count"] == 3 and auth["metrics"]["pre_deployment_change_count"] == 1
    assert auth["metrics"]["departed_dominant_owner"] is True
    check = next(value for value in result["functions"].values() if value["function"]["name"] == "check")
    audit = next(value for value in result["functions"].values() if value["function"]["name"] == "audit")
    assert check["attribution"] == "surviving-line" and check["location"]["start_line"] == 1
    assert ids["c6"] in check["supporting_changes"] and ids["c9"] not in check["supporting_changes"]
    assert audit["supporting_changes"] == [ids["c9"], ids["c1"]], "only changes with surviving lines in the span"
    assert check["availability"]["fix_on_fix_event_count"] == "unavailable"
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    rows = coverage(core)
    assert rows["review-records"]["status"] == "complete" and rows["deployment-events"]["status"] == "complete"
    assert rows["organization-membership"]["status"] == "complete"
    assert rows["function-attribution"]["status"] == "complete"
    functions = core.query_change_context(scope="function", path="app/auth.py", limit=10)
    assert {item["name"] for item in functions["results"]} == {"check", "audit"}
    assert all(item["location"]["mapping_method"] == "tree-sitter-span+git-blame" for item in functions["results"])
    stale = core.query_change_context(signal="stale_approval_change_count", scope="file", limit=10)
    assert [item["location"]["path"] for item in stale["results"]] == ["app/auth.py"]
    found = core.find(kind="deployment_event", indexes=("history",))
    assert [item["native_id"] for item in found["results"]] == ["rel-1"]
    accepted = json.loads((run_root / produced(outcome)["publish.publish_handoff"]["artifact"]["path"]).read_text())
    assert accepted["authority"].startswith("change-context priorities order review work")
    assert set(accepted["raw_exports"]) == {"review", "deployment", "organization"}

    (data / "deployments.json").write_text(json.dumps({**deployments, "events": []}), encoding="utf-8")
    tampered, _ = run_review(config, target, LocalDocker())
    assert "deployment_export_hash_mismatch" in produced(tampered)["publish.publish_handoff"]["gaps"]
    tampered_auth = signals(config.runtime.runs_dir / tampered["run_id"], tampered)["files"]["app/auth.py"]
    assert tampered_auth["metrics"]["pre_deployment_change_count"] is None


def test_missing_history_publishes_unavailable_coverage(tmp_path: Path) -> None:
    config = configured(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    write(target, "main.py", "print('ok')\n")
    outcome, _ = run_review(config, target, LocalDocker())
    assert produced(outcome)["publish.publish_handoff"]["terminal_status"] == "SKIPPED_NA"
    core = RetrievalCore(config.runtime.runs_dir, outcome["run_id"])
    rows = coverage(core)
    assert rows["git-change-context"] == {"area": "git-change-context", "status": "unavailable", "gap": "no_git_metadata"}
    assert {row["status"] for row in rows.values()} == {"unavailable"}
    assert core.query_change_context()["results"] == []


def test_dag_shape() -> None:
    plan = plan_jobs((build_change_context(),))
    assert plan.node("job_change_context_analysis.analyze.unit_signals").dependencies == (
        "job_change_context_analysis.analyze.change_signals", "job_change_context_analysis.attribute.line_attribution",
        "job_change_context_analysis.attribute.fix_on_fix")
