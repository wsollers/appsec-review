from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy" / "dagster" / "bin"))
from host import deployment_profile, provider_overlay, project_name, reject_other_deployments, validate_workspace  # noqa: E402


@pytest.mark.parametrize("profile", ["copilot-dev", "copilot-prod"])
def test_copilot_overlay_and_environment_precedence(tmp_path, monkeypatch, profile):
    environment = tmp_path / ".env"
    environment.write_text(f"APPSEC_REVIEW_PROFILE={profile}\n")
    monkeypatch.delenv("APPSEC_REVIEW_PROFILE", raising=False)
    assert deployment_profile(environment) == profile
    for platform in ("wsl", "linux", "windows"):
        assert provider_overlay(platform, profile) == "compose.copilot.yaml"
    monkeypatch.setenv("APPSEC_REVIEW_PROFILE", "dev")
    assert deployment_profile(environment) == "dev"
    monkeypatch.setenv("APPSEC_REVIEW_PROFILE", "invalid")
    with pytest.raises(RuntimeError, match="unknown runtime profile"):
        deployment_profile(environment)


def test_projects_have_separate_names() -> None:
    assert project_name("windows") != project_name("wsl")
    assert project_name("wsl") != project_name("linux")


def test_wsl_checkout_must_be_under_home(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    (tmp_path / "home" / "repo").mkdir(parents=True)
    validate_workspace(tmp_path / "home" / "repo", "wsl")
    with pytest.raises(RuntimeError, match="WSL home"):
        validate_workspace(tmp_path / "mounted" / "repo", "wsl")


def test_start_rejects_other_stack(monkeypatch) -> None:
    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess([], 0, "appsec-review-dagster-windows\nunrelated-project\n", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="appsec-review-dagster-windows"):
        reject_other_deployments("wsl")
    reject_other_deployments("windows")
