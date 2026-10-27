from pathlib import Path

import pytest

from appsec_review.config.assurance import (
    AssuranceMode, ComponentReleases, ResourceBudget, parse_review_policy,
)


def test_default_policy_excludes_platform_in_strict_mode():
    policy = parse_review_policy({})
    assert policy.mode is AssuranceMode.STRICT
    assert policy.view()["platform_payload_verification"] == "excluded"
    assert policy.releases.require("platform") == (False, "missing_release_identity")


@pytest.mark.parametrize("settings", [
    {"mode": "trusted"},
    {"mode": "first_party_managed"},
    {"mode": "first_party_managed", "project_id": "customer"},
    {"platform_payload_verification": "strict"},
    {"approved_first_party_projects": "project"},
    {"resources": {"cpu": True}},
    {"resources": {"io_slots": 0}},
    {"resources": {"memory_mb": 1}},
    {"releases": {"codeql": ""}},
    {"releases": {"codeql": 123}},
])
def test_reject_invalid_or_unapproved_policy(settings):
    with pytest.raises(ValueError):
        parse_review_policy(settings)


def test_managed_target_is_operator_bound(tmp_path: Path):
    policy = parse_review_policy({
        "mode": "first_party_managed", "project_id": "first-party",
        "approved_first_party_projects": ["first-party"],
        "target_root": str(tmp_path), "custody": "application_private_v1",
    })
    policy.check_target(tmp_path)
    assert policy.view()["platform_payload_verification"] == "excluded"
    with pytest.raises(ValueError, match="operator-approved"):
        policy.check_target(tmp_path / "different-project")


def test_release_declarations_are_frozen_not_measured():
    declarations = {"platform": "release-1"}
    releases = ComponentReleases(declarations)
    declarations["platform"] = "release-2"
    assert releases.view() == {"platform": "release-1"}
    assert releases.require("platform") == (True, None)
    with pytest.raises(TypeError):
        releases.values["platform"] = "changed"


def test_resource_budget_counts_host_staging():
    assert ResourceBudget(memory_mb=10240, staging_memory_mb=512).view()["memory_mb"] == 10240
    with pytest.raises(ValueError, match="staging"):
        ResourceBudget(memory_mb=512, staging_memory_mb=512)
