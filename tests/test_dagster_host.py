from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tomllib

import pytest
import yaml


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy" / "dagster" / "bin"))
from host import deployment_profile, provider_overlay, project_name, reject_other_deployments, validate_workspace  # noqa: E402


def test_application_codeql_runner_has_exact_readonly_host_backing():
    root = Path(__file__).resolve().parents[1]
    compose = yaml.safe_load((root / "deploy/dagster/compose.yaml").read_text())
    mounts = compose["services"]["code-location"]["volumes"]
    asset = "containers/tools/codeql/codeql_runner.py"
    matching = [mount for mount in mounts if f":/opt/app/{asset}" in mount]
    assert matching == [f"../../{asset}:/opt/app/{asset}:ro"]
    assert (root / asset).is_file() and not (root / asset).is_symlink()


def test_review_host_preinstalled_runtime_bindings_use_declared_application_runner():
    root = Path(__file__).resolve().parents[1]
    config = tomllib.loads((root / "appsec-review.toml").read_text())
    settings = config["jobs"]["job_codeql_analysis"]["settings"]
    mappings = settings["preinstalled_runtimes"]
    releases = config["review_policy"]["releases"]
    cpp = config["jobs"]["job_project_build"]["settings"]["profiles"]["native"]
    assert settings["preinstalled_undeclared"] == "derive"
    build_images = {entry["build_image_id"] for entry in mappings}
    assert {settings["source_image_id"], cpp["image_id"]} <= build_images
    assert len(build_images) == len(mappings)
    for entry in mappings:
        assert entry["source_image_id"] == settings["source_image_id"]
        assert entry["runtime_user"] == "1000:1000"
        assert entry["runner_source"] == "application"
        assert entry["codeql_release_id"] == releases["codeql"]
        assert entry["runner_release_id"] == releases["codeql_runner"]


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


def test_native_markers_refuse_compose_lifecycle_and_ops(monkeypatch, capsys) -> None:
    import lifecycle
    import ops

    monkeypatch.setenv("APPSEC_NATIVE_DEPLOYMENT_ID", "fixture")

    def forbidden(*_args, **_kwargs):
        pytest.fail("prepared native configuration reached a Compose subprocess")

    monkeypatch.setattr(subprocess, "run", forbidden)
    with pytest.raises(RuntimeError, match="ambient engine fallback is prohibited"):
        lifecycle.main()
    assert ops.main(["stack-status"]) == ops.REFUSED
    assert "ambient engine fallback is prohibited" in capsys.readouterr().err
