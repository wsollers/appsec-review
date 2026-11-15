"""Exhaustive validation and normalization tests for settings.py and sources.py."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from appsec_review.jobs.job_change_context_analysis import sources
from appsec_review.jobs.job_change_context_analysis.settings import ExportSource, parse_settings
from appsec_review.jobs.job_change_context_analysis.sources import (
    DEPLOYMENT_EXPORT_SCHEMA,
    ORGANIZATION_EXPORT_SCHEMA,
    REVIEW_EXPORT_SCHEMA,
    deployments_from_export,
    identity_hash,
    load_export,
    normalize_review_record,
    organization_from_export,
    parse_timestamp,
    review_records_from_export,
)
from appsec_review.storage import file_sha256
from .support import HEAD, PARENT, raw_settings


def test_parse_settings_valid_and_closed_validation() -> None:
    parsed = parse_settings(raw_settings())
    assert parsed.ranking_top_files >= 1
    assert parsed.schedule.business_start_minute < parsed.schedule.business_end_minute
    assert all(ext.islower() for ext in parsed.test_association.production_extensions)

    with pytest.raises(ValueError, match="must be a table: settings"):
        parse_settings([])  # type: ignore[arg-type]

    invalid_cases = [
        (lambda r: r.update(extra=1), "keys are invalid"),
        (lambda r: r.update(ranking_top_files=True), "settings.ranking_top_files"),
        (lambda r: r.update(ranking_top_files=0), "settings.ranking_top_files"),
        (lambda r: r["review"].update(source="gitlab"), "review.source"),
        (lambda r: r["review"].update(export_path=123), "review.export_path"),
        (lambda r: r["review"].update(export_path="a\x00b"), "review.export_path"),
        (lambda r: r["review"].update(export_sha256="not-hex"), "review.export_sha256"),
        (lambda r: r["review"].update(source="export", export_path=""), "review is enabled without export_path"),
        (lambda r: r["schedule"].update(time_zone=123), "schedule.time_zone"),
        (lambda r: r["schedule"].update(time_zone="../etc/passwd"), "schedule.time_zone"),
        (lambda r: r["schedule"].update(time_zone="123/Invalid"), "schedule.time_zone"),
        (lambda r: r["schedule"].update(business_hours_start=900), "schedule.business_hours_start"),
        (lambda r: r["schedule"].update(business_hours_start="25:00"), "schedule.business_hours_start"),
        (lambda r: r["schedule"].update(business_hours_start="19:00"), "start before they end"),
        (lambda r: r["schedule"].update(weekend_days="saturday"), "schedule.weekend_days"),
        (lambda r: r["schedule"].update(weekend_days=["saturday", "saturday"]), "schedule.weekend_days"),
        (lambda r: r["schedule"].update(weekend_days=["funday"]), "schedule.weekend_days"),
        (
            lambda r: r["schedule"].update(
                weekend_days=["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"],
            ),
            "schedule.weekend_days",
        ),
        (lambda r: r["deployments"].update(enabled=1), "deployments.enabled"),
        (lambda r: r["deployments"].update(enabled=True, export_path=""), "deployments is enabled without export_path"),
        (lambda r: r["deployments"].update(environments=[]), "deployments.environments"),
        (lambda r: r["deployments"].update(environments=["prod", "prod"]), "deployments.environments"),
        (lambda r: r["scope_sprawl"].update(min_group_entropy=True), "scope_sprawl.min_group_entropy"),
        (lambda r: r["scope_sprawl"].update(min_group_entropy=1.5), "scope_sprawl.min_group_entropy"),
        (lambda r: r["test_association"].update(enabled="yes"), "test_association.enabled"),
        (lambda r: r["ownership"].update(dominant_owner_share=0.0), "ownership.dominant_owner_share"),
        (lambda r: r["organization"].update(enabled=0), "organization.enabled"),
        (lambda r: r.update(priority_weights={}), "priority weights are required"),
        (lambda r: r["priority_weights"].update(churn_lines=1), "unknown change context priority signal"),
        (lambda r: r["priority_weights"].update(sprawling_change_count=True), "priority weight is invalid"),
        (lambda r: r["priority_weights"].update(sprawling_change_count=-1), "priority weight is invalid"),
        (
            lambda r: r.update(priority_weights={k: 0 for k in r["priority_weights"]}),
            "at least one positive weight",
        ),
    ]
    for mutate, expected in invalid_cases:
        candidate = raw_settings()
        mutate(candidate)
        with pytest.raises(ValueError, match=expected):
            parse_settings(candidate)

    zero_entropy = parse_settings(raw_settings(**{"scope_sprawl.min_group_entropy": 0.0, "test_association.contract_patterns": []}))
    assert zero_entropy.scope_sprawl.min_group_entropy == 0.0
    assert zero_entropy.test_association.contract_patterns == ()


def test_parse_timestamp_and_identity_hash() -> None:
    assert parse_timestamp(None) is None
    assert parse_timestamp("2023-11-14 22:13:20") is None
    assert parse_timestamp("2023-11-14T22:13:20Z") == 1_700_000_000
    assert parse_timestamp("2023-11-14T17:13:20.123456789-05:00") == 1_700_000_000
    assert parse_timestamp("2023-02-29T12:00:00Z") is None
    assert identity_hash("  Alice@Example.TEST ") == hashlib.sha256(b"alice@example.test").hexdigest()


def test_load_export_enforces_custody_bounds_and_hash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    target = repo / "target"
    data_dir = repo / "data"
    target.mkdir(parents=True)
    data_dir.mkdir(parents=True)
    export = data_dir / "deploy.json"
    export.write_text('{"schema": "x"}', encoding="utf-8")
    digest = file_sha256(export)

    assert load_export(repo, target, ExportSource(False, "data/deploy.json", digest), "deployment") == (
        None, None, ["deployment_disabled"],
    )
    assert load_export(repo, target, ExportSource(True, "data/deploy.json", ""), "deployment") == (
        None, None, ["deployment_export_unpinned"],
    )
    assert load_export(repo, target, ExportSource(True, "/abs/deploy.json", digest), "deployment") == (
        None, None, ["deployment_export_outside_repository"],
    )
    assert load_export(repo, target, ExportSource(True, "../outside.json", digest), "deployment") == (
        None, None, ["deployment_export_outside_repository"],
    )
    (target / "deploy.json").write_bytes(export.read_bytes())
    assert load_export(repo, target, ExportSource(True, "target/deploy.json", digest), "deployment") == (
        None, None, ["deployment_export_inside_target"],
    )
    assert load_export(repo, target, ExportSource(True, "target", digest), "deployment") == (
        None, None, ["deployment_export_inside_target"],
    )
    assert load_export(repo, None, ExportSource(True, "data/missing.json", digest), "deployment") == (
        None, None, ["deployment_export_missing"],
    )

    link = data_dir / "link.json"
    link.symlink_to(data_dir / "dangling-target.json")
    assert load_export(repo, None, ExportSource(True, "data/link.json", digest), "deployment") == (
        None, None, ["deployment_export_missing"],
    )

    monkeypatch.setattr(sources, "MAX_EXPORT_BYTES", 4)
    assert load_export(repo, None, ExportSource(True, "data/deploy.json", digest), "deployment") == (
        None, None, ["deployment_export_too_large"],
    )
    monkeypatch.undo()

    assert load_export(repo, target, ExportSource(True, "data/deploy.json", "0" * 64), "deployment") == (
        None, None, ["deployment_export_hash_mismatch"],
    )

    bad_utf8 = data_dir / "bad.bin"
    bad_utf8.write_bytes(b"\xff\xfe")
    assert load_export(repo, target, ExportSource(True, "data/bad.bin", file_sha256(bad_utf8)), "review") == (
        None, None, ["review_export_invalid"],
    )

    bad_json = data_dir / "bad.json"
    bad_json.write_text("{not-json", encoding="utf-8")
    assert load_export(repo, target, ExportSource(True, "data/bad.json", file_sha256(bad_json)), "review") == (
        None, None, ["review_export_invalid"],
    )

    doc, raw, gaps = load_export(repo, target, ExportSource(True, "data/deploy.json", digest), "deployment")
    assert doc == {"schema": "x"} and raw == export.read_bytes() and gaps == []


def test_review_deployment_and_organization_export_normalizers() -> None:
    norm = normalize_review_record({
        "pull_request": True,
        "direct_push": False,
        "approved_by_other": "unknown",
        "approvals": [
            "skip-non-mapping",
            {"submitted_at": None, "commit_id": "bad"},
            {"submitted_at": "2023-11-14T22:00:00Z", "commit_id": HEAD},
        ],
        "head_sha": "not-sha",
        "self_merged": True,
    })
    assert norm["pull_request"] is None
    assert norm["approved_by_other"] is True
    assert norm["self_merged"] is True
    assert norm["complete"] is False
    assert [a["commit_id"] for a in norm["approvals"]] == [HEAD, None]

    no_approvals = normalize_review_record({"pull_request": 7, "approved_by_other": True})
    assert no_approvals["approvals"] is None and no_approvals["approved_by_other"] is True

    assert review_records_from_export("not-a-dict") == ({}, ["review_export_invalid"])
    assert review_records_from_export({"schema": REVIEW_EXPORT_SCHEMA, "records": []}) == ({}, ["review_export_invalid"])
    records, gaps = review_records_from_export({
        "schema": REVIEW_EXPORT_SCHEMA,
        "records": {HEAD: {"pull_request": 2, "direct_push": True}, "bad-key": {}, PARENT: "not-mapping"},
    })
    assert list(records) == [HEAD] and records[HEAD]["direct_push"] is False and gaps == []

    assert deployments_from_export([], ("production",)) == (None, ["deployment_export_invalid"])
    assert deployments_from_export({
        "schema": DEPLOYMENT_EXPORT_SCHEMA,
        "coverage": {"start": "2023-11-20T00:00:00Z", "end": "2023-11-10T00:00:00Z"},
        "events": [],
    }, ("production",)) == (None, ["deployment_export_invalid"])

    dep_doc, dep_gaps = deployments_from_export({
        "schema": DEPLOYMENT_EXPORT_SCHEMA,
        "coverage": {"start": "2023-11-10T00:00:00Z", "end": "2023-11-20T00:00:00Z"},
        "events": [
            "not-a-mapping",
            {"deployment_id": "bad id!", "environment": "production", "status": "success",
             "deployed_at": "2023-11-12T00:00:00Z", "commit": HEAD},
            {"deployment_id": "d-fail", "environment": "production", "status": "failure",
             "deployed_at": "2023-11-12T00:00:00Z", "commit": HEAD},
            {"deployment_id": "d-ok", "environment": "production", "status": "success",
             "deployed_at": "2023-11-13T00:00:00Z", "commit": HEAD},
        ],
    }, ("production",))
    assert dep_gaps == ["deployment_events_rejected"]
    assert dep_doc is not None and dep_doc["rejected_count"] == 2
    assert [e["deployment_id"] for e in dep_doc["events"]] == ["d-ok"]

    dep_clean, dep_clean_gaps = deployments_from_export({
        "schema": DEPLOYMENT_EXPORT_SCHEMA,
        "coverage": {"start": "2023-11-10T00:00:00Z", "end": "2023-11-20T00:00:00Z"},
        "events": [{
            "deployment_id": "d-ok", "environment": "production", "status": "success",
            "deployed_at": "2023-11-13T00:00:00Z", "commit": HEAD,
        }],
    }, ("production",))
    assert dep_clean_gaps == [] and dep_clean is not None and dep_clean["rejected_count"] == 0

    assert organization_from_export({"schema": ORGANIZATION_EXPORT_SCHEMA, "members": [], "as_of": "bad"}) == (
        None, ["organization_export_invalid"],
    )
    h1 = identity_hash("one@example.test")
    org_doc, org_gaps = organization_from_export({
        "schema": ORGANIZATION_EXPORT_SCHEMA,
        "as_of": "2024-01-01T00:00:00Z",
        "members": [
            "not-a-dict",
            {"identity_sha256": h1, "status": "departed", "departed_at": "2023-12-01T00:00:00Z"},
            {"identity_sha256": h1, "status": "active"},
        ],
    })
    assert org_gaps == ["organization_members_rejected"]
    assert org_doc is not None and org_doc["rejected_count"] == 2
    assert org_doc["members"][h1]["status"] == "departed"

    org_clean, org_clean_gaps = organization_from_export({
        "schema": ORGANIZATION_EXPORT_SCHEMA,
        "as_of": "2024-01-01T00:00:00Z",
        "members": [{"identity_sha256": h1, "status": "active"}],
    })
    assert org_clean_gaps == [] and org_clean is not None and org_clean["rejected_count"] == 0
    _ = SimpleNamespace(json=json)
