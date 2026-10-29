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


def test_github_token_reaches_only_the_code_location_from_the_operator_shell():
    root = Path(__file__).resolve().parents[1]
    compose = yaml.safe_load((root / "deploy/dagster/compose.yaml").read_text())
    config = tomllib.loads((root / "appsec-review.toml").read_text())
    token_env = config["jobs"]["job_source_history_analysis"]["settings"]["github"]["token_env"]
    services = compose["services"]
    assert services["code-location"]["environment"][token_env] == f"${{{token_env}:-}}"
    assert all(token_env not in (services[name].get("environment") or {})
               for name in services if name != "code-location")
    example = (root / "deploy/dagster/.env.example").read_text()
    assert not any(line.lstrip("# ").startswith(f"{token_env}=") for line in example.splitlines())


def test_review_host_preinstalled_runtime_bindings_use_declared_application_runner():
    root = Path(__file__).resolve().parents[1]
    config = tomllib.loads((root / "appsec-review.toml").read_text())
    settings = config["jobs"]["job_codeql_analysis"]["settings"]
    mappings = settings["preinstalled_runtimes"]
    releases = config["review_policy"]["releases"]
    cpp = config["jobs"]["job_project_build"]["settings"]["profiles"]["native"]
    assert {entry["build_image_id"] for entry in mappings} == {
        settings["source_image_id"], cpp["image_id"]}
    assert len(mappings) == 2
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


def test_compose_environment_takes_github_token_from_the_stored_gh_login(monkeypatch, capsys):
    import host

    calls = []

    def fake_gh(argv, *, env, **_kwargs):
        calls.append((argv, env))
        return subprocess.CompletedProcess(argv, 0, "gho_stored-login\n", "")

    monkeypatch.setattr(host.shutil, "which", lambda name: "/usr/bin/gh" if name == "gh" else None)
    monkeypatch.setattr(host.subprocess, "run", fake_gh)
    environment = host.compose_environment({"PATH": "/usr/bin", "GH_TOKEN": "work-account"})
    assert environment["GITHUB_TOKEN"] == "gho_stored-login" and environment["GH_TOKEN"] == "work-account"
    [(argv, lookup)] = calls
    assert argv == ["/usr/bin/gh", "auth", "token", "--hostname", "github.com"] and "GH_TOKEN" not in lookup
    assert "gho_stored-login" not in capsys.readouterr().err


@pytest.mark.parametrize("explicit", ["operator-token", ""])
def test_compose_environment_keeps_an_explicit_github_token_or_opt_out(monkeypatch, explicit):
    import host

    monkeypatch.setattr(host.subprocess, "run", lambda *_a, **_k: pytest.fail("gh consulted despite GITHUB_TOKEN"))
    assert host.compose_environment({"GITHUB_TOKEN": explicit})["GITHUB_TOKEN"] == explicit


def test_compose_environment_without_gh_login_leaves_github_token_unset(monkeypatch, capsys):
    import host

    monkeypatch.setattr(host.shutil, "which", lambda name: "/usr/bin/gh")
    monkeypatch.setattr(host.subprocess, "run",
                        lambda argv, **_k: subprocess.CompletedProcess(argv, 1, "", "not logged in"))
    assert "GITHUB_TOKEN" not in host.compose_environment({"PATH": "/usr/bin"})
    assert "github_credentials_missing" in capsys.readouterr().err


@pytest.mark.parametrize(("action", "supplied"), [("start", True), ("reload", True), ("stop", False), ("build", False)])
def test_lifecycle_supplies_github_token_only_when_creating_containers(monkeypatch, action, supplied):
    import lifecycle

    seen = {}
    monkeypatch.delenv("APPSEC_NATIVE_DEPLOYMENT_ID", raising=False)
    monkeypatch.setattr(lifecycle, "validate_deployment", lambda *_a: None)
    monkeypatch.setattr(lifecycle, "reject_other_deployments", lambda *_a: None)
    monkeypatch.setattr(lifecycle, "compose_environment", lambda: {"GITHUB_TOKEN": "from-gh"})
    monkeypatch.setattr(lifecycle.subprocess, "run",
                        lambda argv, **kwargs: seen.update(kwargs) or subprocess.CompletedProcess(argv, 0))
    monkeypatch.setattr(sys, "argv", ["lifecycle.py", action])
    assert lifecycle.main() == 0
    assert seen["env"] == ({"GITHUB_TOKEN": "from-gh"} if supplied else None)


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
