from __future__ import annotations

from pathlib import Path

from appsec_review.jobs.job_language_build import php


def test_php_policy_allows_manifest_only_dependency_resolution(tmp_path: Path) -> None:
    assert php.policy_argv(("composer", "archive"), {
        "composer_plugins": "disabled", "composer_scripts": "disabled"})[-3:] == (
            "--no-plugins", "--no-scripts", "--no-interaction")
    dispatch = {"build_system": "composer", "recipe": {
        "dependency_files": ["composer.json"], "network_required": True}}
    assert php.validate_php_dispatch(dispatch) == []
